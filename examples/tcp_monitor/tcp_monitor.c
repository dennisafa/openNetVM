/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * monitor.c - an example using onvm. Print a message each p package received
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/wait.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_load_balance.h"

#define NF_TAG "TCP Load Balancer"
//#define SCALED_TAG "Simple Forward Network Function";
char *scale_tag;

struct chain_meta {
        int num_connections;
        int chain_id[10]; // should be an array of ints
        pid_t pid_list[10]; // array of the spawned nf's pids to kill
        int dest_id;
        int scaled_nfs; // will represent size of chain_id array
        int num_packets;
};

// Trying to use flow specific

static struct flow_meta *global_flow_meta[MAX_FLOWS];

int default_service_chain_id[MAX_CHAINS];
int chain_length = 1;
int next_service_id = 4;

// Used for flow hashing
#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00


/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t total_packets = 0;
static uint64_t last_cycle;
static uint64_t cur_cycles;

int create_rtehashmap(const char *name, int entries, size_t key_len);
static struct rte_hash *flow_map;

/* shared data structure containing host port info */
extern struct port_info *ports;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                RTE_LOG(INFO, APP, "print_delay = %d\n", print_delay);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t pkt_process = 0;
        struct ipv4_hdr *ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("Hash : %u\n", pkt->hash.rss);
        printf("N°   : %"
        PRIu64
        "\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        cur_cycles = rte_get_tsc_cycles();

        if (((cur_cycles - last_cycle) / rte_get_timer_hz()) > 5) {
                printf("Total packets received: %"
                PRIu32
                "\n", total_packets);
                last_cycle = cur_cycles;
        }

        return 0;
}


static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        struct chain_meta *lkup_chain_meta;
        int fd_ret;
        int dest;
        int num_duplicated;
        int dup_index;

        struct onvm_flow_entry *flow_entry = NULL;
        struct onvm_service_chain *sc;
        struct tcp_hdr *tcp_hdr;

        uint16_t flags = 0;
        static uint32_t counter = 0;

        struct onvm_nf *nf;
        int next_dest_id;


        if (!onvm_pkt_is_tcp(pkt) || !onvm_pkt_is_ipv4(pkt)) {
                printf("Packet isn't TCP/IPv4");
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = 2;
                return 0;
        }

        tcp_hdr = onvm_pkt_tcp_hdr(pkt);
        flags = ((tcp_hdr->data_off << 8) | tcp_hdr->tcp_flags) & 0b111111111;

        fd_ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (fd_ret < 0 && (flags >> 1) & 0x1) {
                //printf("New flow\n");
                onvm_flow_dir_add_pkt(pkt, &flow_entry);
                memset(flow_entry, 0, sizeof(struct onvm_flow_entry));
                flow_entry->sc = onvm_sc_create();
                sc = flow_entry->sc;

                for (int i = 1; i < chain_length + 1; i++) {
                        next_dest_id = default_service_chain_id[i-1];
                        nf = &nfs[next_dest_id];
                        if (nf->resource_usage.cpu_time_proportion > 0.3) {
//                                printf("Nf is overflowing, CPU\n");
//                                printf("NF: %s\n", nf->tag);
                                switch (nf->state)
                                {
                                        case ONVM_NF_STATEFUL:
                                                printf("Stateful NF balancing\n");
                                                break;
                                        default:
                                                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, default_service_chain_id[i-1]);
                                                printf("Neither stateful nor stateless\n");
                                                break;
                                }
                                //onvm_nflib_fork(nf->tag, 2, next_id);

                        } else {
                                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, default_service_chain_id[i-1]);
                        }
                }
                dest = default_service_chain_id[0];
        }
        else {
                //printf("Flow found\n");
                sc = flow_entry->sc;
        }

        for (int i = 1; i < chain_length + 1; i++) {
                dest = sc->sc[i].destination;
                nf = &nfs[dest];
                if (nf->resource_usage.cpu_time_proportion > 0.3) {
                        switch (nf->state)
                        {
                                case ONVM_NF_STATELESS:
//                                        printf("Stateless NF balancing\n");
                                        num_duplicated = nf->num_duplicated;

                                        if (num_duplicated > 1) { // If the flow is coming in and the original is overloaded, spread across dups
                                                for (int j = 0; j < num_duplicated; j++) {
                                                        sc->sc[i].destination_dup[j] = nf->destination_dup[j];
                                                }
                                                sc->sc[i].is_duplicated = 1;
                                                sc->sc[i].num_duplicated = num_duplicated;
                                                //printf("Num duplicated: %d\n", num_duplicated);
                                        }

                                        // But if it's been more than 5 secs and the duplicates arent taking the load off
                                        // then spawn another one and add it

                                        // Copy nf dup array into current duplicated service chain array
                                        if ((rte_get_tsc_cycles() - nf->time_since_scale) * TIME_TTL_MULTIPLIER /
                                                                     rte_get_timer_hz() < 5) {
                                                //printf("Time to live exceeded, shutting down\n");
                                                break;
                                        }

                                        if (num_duplicated == ONVM_MAX_CHAIN_LENGTH) {
                                                //printf("Maximum duplications\n");
                                                break;
                                        }

                                        onvm_nflib_fork(nf->tag, 2, next_service_id);
                                        nf->time_since_scale = rte_get_tsc_cycles();
                                        sc->sc[i].is_duplicated = 1;
                                        nf->num_duplicated++;
                                        nf->destination_dup[nf->num_duplicated - 1] = next_service_id; // 4 is the id of the new duplicated NF
                                        next_service_id++;

                                        for (int j = 0; j < nf->num_duplicated; j++) {
                                                sc->sc[i].destination_dup[j] = nf->destination_dup[j];
                                        }

                                        sc->sc[i].num_duplicated = nf->num_duplicated;
                                        break;
                                case ONVM_NF_STATEFUL:
                                        printf("Stateful NF balancing\n");
                                        break;
                                default:
                                        //onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, default_service_chain_id[i-1]);
                                        printf("Neither stateful nor stateless: %s\n", nf->tag);
                                        break;
                        }
                }
        }

        sc->sc[1].num_packets++;
        if (sc->sc[1].is_duplicated == 1) {
                //printf("Num dup: %d\n", sc->sc[1].num_duplicated);
                dup_index = sc->sc[1].num_packets % sc->sc[1].num_duplicated;
                //printf("Num_duplicated %d\n", sc->sc[1].num_duplicated);
                //printf("Num_packets %ld\n", sc->sc[1].num_packets);
                dest = sc->sc[1].destination_dup[dup_index];

        } else {
                dest = sc->sc[1].destination;
        }
        nf = &nfs[default_service_chain_id[0]];
        if ((flags >> 1) & 0x1) { // SYN so add connection count to service chain
                nf->num_flows++;
                printf("Number of flows: %d\n", nf->num_flows);
        }

        // TODO subtract and add flows from all NF's
        if (flags & 0x1) { // SYN so add connection count to service chain
                nf->num_flows--;
                printf("Number of flows: %d\n", nf->num_flows);
        }

        // If the nf is stateless, and if the CPU usage is above certain percentage, make it alternate sending across
        // different NF's


//        if (flags & 0x1) { // FIN
//                printf("FIN, killing %d\n", to_kill);
//        }

        //printf("Destination = %d\n", dest);
        meta->action = ONVM_NF_ACTION_TONF; // otherwise we have a scaled nf so send it to that
        meta->destination = dest;

        return 0;

        //nf = default_service_chain[0];

        // To dealloc- if there are no more flows going to that NF

        // Check if this IP is attached to service chain
        // If new IP comes in, map to service chain with least amount of connections. First one is default to 3
//        if (rte_hash_lookup_data(ip_chain, &ip_addr_long, &chain_meta_data) < 0) {
//                //new_chain_meta = rte_malloc(NULL, sizeof(struct chain_meta), 0);
//                printf("Attaching IP to chain with least connections\n");
//                index = 0;
//                min = chain_meta_list[index]->num_connections;
//                for (i = index + 1; i < tcp_lb_hash_maps->list_size; i++) {
//                        if (chain_meta_list[i]->num_connections < min) {
//                                index = i;
//                                min = chain_meta_list[i]->num_connections;
//                        }
//                }
//
//                lkup_chain_meta = (struct chain_meta *) chain_meta_list[index];
//                lkup_chain_meta->num_packets = 0;
//                rte_hash_add_key_data(ip_chain, &ip_addr_long, (void *) lkup_chain_meta);
//        } else {
//                lkup_chain_meta = (struct chain_meta *) chain_meta_data;
//                min = lkup_chain_meta->num_connections / lkup_chain_meta->scaled_nfs;
//                printf("Min: %d\n", min);
//                printf("Num connections: %d scaled nfs: %d\n", lkup_chain_meta->num_connections,
//                       lkup_chain_meta->scaled_nfs);
//                if (min >= MAX_CONNECTIONS) {
//                        printf("Hit the maximum amount of connections, scaling\n");
//                        lkup_chain_meta->scaled_nfs++;
//                        next_id = ++tcp_lb_hash_maps->total_connections;
//                        pid_t saved_pid = onvm_nflib_fork("simple_forward", 2, next_id);
//                        //lkup_chain_meta->scaled_nfs
//                        // TODO: Scale here
//                        /* Each IP gets meta_chain index in bucket, each IP gets list of NF's it may scale to.
//                         I.E 4 connections from one IP, max connections is 2.
//                         2 of the connections get sent to chain ID 1, the other two get sent to chain ID 2.
//                         We need to spawn the new chain and put the ID into the array
//                         This could be a message sent to other process that scales for us
//                         */
//
//                        scaled_nfs = lkup_chain_meta->scaled_nfs; // place holder
//                        printf("Scaled nfs val: %d\n", scaled_nfs);
//                        lkup_chain_meta->chain_id[scaled_nfs - 1] =
//                                next_id; // first two are mtcp and balancer
//                        lkup_chain_meta->pid_list[0] = saved_pid;
//
//                        printf("Meta dest ID %d\n", lkup_chain_meta->dest_id);
//                        printf("Meta dest ID %d\n", lkup_chain_meta->dest_id);
//                }
//
//        }



        total_packets++;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        lkup_chain_meta->num_packets++;
        lkup_chain_meta->dest_id = lkup_chain_meta->chain_id[lkup_chain_meta->num_packets %
                                                             lkup_chain_meta->scaled_nfs];
        meta->action = ONVM_NF_ACTION_TONF; // otherwise we have a scaled nf so send it to that
        meta->destination = lkup_chain_meta->dest_id;
        usleep(1);

        return 0;
}

int
create_rtehashmap(const char *name, int entries, size_t key_len) {
        struct rte_hash_parameters *ipv4_hash_params;

        ipv4_hash_params = (struct rte_hash_parameters *) rte_malloc(NULL, sizeof(struct rte_hash_parameters), 0);
        if (!ipv4_hash_params) {
                return -1;
        }

        char *tbl_name = rte_malloc(NULL, sizeof(name) + 1, 0);
        /* create ipv4 hash table. use core number and cycle counter to get a unique name. */
        ipv4_hash_params->entries = entries;
        ipv4_hash_params->key_len = key_len;
        ipv4_hash_params->hash_func = rte_jhash;
        ipv4_hash_params->name = tbl_name;
        ipv4_hash_params->socket_id = rte_socket_id();
        ipv4_hash_params->extra_flag = 0;
        snprintf(tbl_name, sizeof(name) + 1, "%s", name);
        printf("Name: %s\n", tbl_name);


        return onvm_nflib_request_ft(ipv4_hash_params);
}

static int init_lb_maps(struct onvm_nf *nf) {
        struct tcp_lb_maps *tcp_lb_hash_maps;
        int i, j;
        //struct chain_meta *start_chain;

        scale_tag = rte_malloc(NULL, 20, 0);
        strncpy(scale_tag, scale_tag_cpy, 20);

        for (i = 0; i < MAX_FLOWS; i++) {
                global_flow_meta[i] = (struct flow_meta *) rte_malloc(NULL, sizeof(struct flow_meta), 0);
                global_flow_meta[i]->service_chain = (struct onvm_nf **) rte_malloc(NULL,
                                                                                    sizeof(struct onvm_nf *) * MAX_CHAINS, 0);
                for (j = 0; j < MAX_CHAINS; j++) {
                        global_flow_meta[i]->service_chain[j] = (struct onvm_nf *) rte_malloc(NULL, sizeof(struct onvm_nf), 0);
                }
                global_flow_meta[i]->global_flow_id = -1;
        }

        default_service_chain = (struct onvm_nf **) rte_malloc(NULL,
                                                               sizeof(struct onvm_nf *) * MAX_CHAINS, 0);

        for (j = 0; j < MAX_CHAINS; j++) {
                default_service_chain[j] = (struct onvm_nf *) rte_malloc(NULL,
                                                                          sizeof(struct onvm_nf), 0);
        }

        //global_flow_meta[i]->service_chain[0] = NULL;

        tcp_lb_hash_maps = rte_malloc(NULL, sizeof(struct tcp_lb_maps), 0);
        tcp_lb_hash_maps->total_connections = 0;

        int ret = create_rtehashmap(flow_map_name, 10, sizeof(union ipv4_5tuple_host));
        if (ret < 0) {
                printf("Creating hashmap failed\n");
                exit(0);
        }

//        flow_table = onvm_ft_create(256, sizeof(struct flow_meta));
        printf("%p\n", sdn_ft);

        union ipv4_5tuple_host newkey;
        void *lkup;

        newkey.ip_dst = 500;
        newkey.ip_src = 500;
        newkey.port_dst = 11;
        newkey.port_src = 10;
//
        flow_map = rte_hash_find_existing(flow_map_name);
        printf("Did flow_map lookup\n");
        if (flow_map == NULL) {
                printf("Could not find map\n");
                //exit(0);
        }
        else {
                printf("FM addr: %p\n", flow_map);
        }
//
        rte_hash_lookup_data(flow_map, (void *) &newkey, &lkup);

        tcp_lb_hash_maps->global_flow_meta_freelist = rte_ring_create(global_flow_meta_freelist, MAX_FLOWS,
                rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (tcp_lb_hash_maps->global_flow_meta_freelist == NULL) {
                printf("Could not create ring\n");
                exit(0);
        }

        // TODO: allow user to input this next step it should be a loop in which the static chain is constructured

        default_service_chain[0] = &nfs[3]; // ID 3 is
        default_service_chain_id[0] = 3;

        printf("We are here\n");

        for (i = 0; i < MAX_FLOWS; i++) {
                for (j = 0; j < MAX_CHAINS; j++) {
                        global_flow_meta[i]->service_chain[j] = default_service_chain[j];
                }
        }


        for (i = 0; i < MAX_FLOWS; i++) {
                rte_ring_enqueue(tcp_lb_hash_maps->global_flow_meta_freelist, (void *) global_flow_meta[i]);
        }

        nf->data = (void *) tcp_lb_hash_maps;
        return 0;
}

int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->user_actions = &callback_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        cur_cycles = rte_get_tsc_cycles();
        last_cycle = rte_get_tsc_cycles();
        init_lb_maps(nf_local_ctx->nf);

        onvm_flow_dir_nf_init();

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
