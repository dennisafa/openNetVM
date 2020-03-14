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
#include<sys/wait.h> 

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "TCP Load Balancer"
#define MAX_CHAINS 10
#define MAX_CONNECTIONS 1
//#define SCALED_TAG "Simple Forward Network Function";
char *scale_tag;

struct tcp_lb_maps {
        struct rte_hash *ip_chain; // Int to int
        struct rte_hash *chain_connections; // Int to int
        struct chain_meta **chain_meta_list;
        int list_size;
	int total_connections;
};

struct chain_meta {
        int num_connections;
        int chain_id[10]; // should be an array of ints
        pid_t pid_list[10]; // array of the spawned nf's pids to kill
        int dest_id;
        int scaled_nfs; // will represent size of chain_id array
        int num_packets;
};


/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t total_packets = 0;
static uint64_t last_cycle;
static uint64_t cur_cycles;

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
        printf("N°   : %" PRIu64 "\n", pkt_process);
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
                printf("Total packets received: %" PRIu32 "\n", total_packets);
                last_cycle = cur_cycles;
        }

        return 0;
}



static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, struct onvm_nf_local_ctx *nf_local_ctx) {
        struct tcp_lb_maps *tcp_lb_hash_maps;
        struct rte_hash *ip_chain;
        struct chain_meta **chain_meta_list;
        void *chain_meta_data;
        //struct onvm_nf *nf;

        struct chain_meta *lkup_chain_meta;
        int min, i, index, to_kill;
        long ip_addr_long;
        int scaled_nfs, next_id;

        struct tcp_hdr *tcp_hdr;
        struct ipv4_hdr *ip_hdr;
        uint16_t flags = 0;
        static uint32_t counter = 0;

        if (!onvm_pkt_is_tcp(pkt) && !onvm_pkt_is_ipv4(pkt)) {
                printf("Packet isn't TCP/IPv4");
                meta->action = ONVM_NF_ACTION_OUT;
                meta->destination = 0;
                return 0;
        }
        tcp_lb_hash_maps = nf_local_ctx->nf->data;
        chain_meta_list = tcp_lb_hash_maps->chain_meta_list;
        ip_chain = tcp_lb_hash_maps->ip_chain;
        tcp_hdr = onvm_pkt_tcp_hdr(pkt);
        ip_hdr = onvm_pkt_ipv4_hdr(pkt);
        //onvm_pkt_print_ipv4(ip_hdr);
        ip_addr_long = (long) ip_hdr->src_addr;
        // Check if this IP is attached to service chain
        // If new IP comes in, map to service chain with least amount of connections. First one is default to 3
        if (rte_hash_lookup_data(ip_chain, &ip_addr_long, &chain_meta_data) < 0) {
                //new_chain_meta = rte_malloc(NULL, sizeof(struct chain_meta), 0);
                printf("Attaching IP to chain with least connections\n");
                index = 0;
                min = chain_meta_list[index]->num_connections;
                for (i = index + 1; i < tcp_lb_hash_maps->list_size; i++) {
                        if (chain_meta_list[i]->num_connections < min) {
                                index = i;
                                min = chain_meta_list[i]->num_connections;
                        }
                }

                lkup_chain_meta = (struct chain_meta *) chain_meta_list[index];
                lkup_chain_meta->num_packets = 0;
                rte_hash_add_key_data(ip_chain, &ip_addr_long, (void *) lkup_chain_meta);
        } else {
                lkup_chain_meta = (struct chain_meta *) chain_meta_data;
                min = lkup_chain_meta->num_connections / lkup_chain_meta->scaled_nfs;
                printf("Min: %d\n", min);
                printf("Num connections: %d scaled nfs: %d\n", lkup_chain_meta->num_connections, lkup_chain_meta->scaled_nfs); 
                if (min >= MAX_CONNECTIONS) {
                        printf("Hit the maximum amount of connections, scaling\n");
                        lkup_chain_meta->scaled_nfs++;
			            next_id = ++tcp_lb_hash_maps->total_connections;
	            		pid_t saved_pid = onvm_nflib_fork("simple_forward", 2, next_id);  
                        //lkup_chain_meta->scaled_nfs
                        // TODO: Scale here
                        /* Each IP gets meta_chain index in bucket, each IP gets list of NF's it may scale to.
                         I.E 4 connections from one IP, max connections is 2.
                         2 of the connections get sent to chain ID 1, the other two get sent to chain ID 2.
                         We need to spawn the new chain and put the ID into the array
                         This could be a message sent to other process that scales for us
                         */

                        scaled_nfs = lkup_chain_meta->scaled_nfs; // place holder
                        printf("Scaled nfs val: %d\n", scaled_nfs);
                        lkup_chain_meta->chain_id[scaled_nfs - 1] =
                                next_id; // first two are mtcp and balancer
                        lkup_chain_meta->pid_list[0] = saved_pid; 

                        printf("Meta dest ID %d\n", lkup_chain_meta->dest_id);
                        printf("Meta dest ID %d\n", lkup_chain_meta->dest_id);
                }

        }


        flags = ((tcp_hdr->data_off << 8) | tcp_hdr->tcp_flags) & 0b111111111;

        if ((flags >> 1) & 0x1) { // SYN so add connection count to service chain
                printf("SYN,\n");
                lkup_chain_meta->num_connections++;
                printf("Num connections after syn: %d\n", lkup_chain_meta->num_connections);
        }


        if (flags & 0x1) { // FIN
                scaled_nfs = lkup_chain_meta->scaled_nfs;
                to_kill = lkup_chain_meta->chain_id[scaled_nfs - 1];
                printf("FIN, killing %d\n", to_kill);
                lkup_chain_meta->num_connections--;
                lkup_chain_meta->scaled_nfs--;
                if (onvm_nflib_send_kill_msg(to_kill) != 0) {
                    printf("Couldn't kill %d\n", to_kill);
                }
        }


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

static struct rte_hash *
create_rtehashmap(const char *name, int entries) {
        struct rte_hash_parameters hash_map_params;
        printf("%s\n", name);

        hash_map_params.name = name;
        hash_map_params.entries = entries;
        hash_map_params.reserved = 0;
        hash_map_params.key_len = sizeof(int); // Default is an int key
        hash_map_params.hash_func = rte_jhash; // Default is the jhash method, this can be changed if needed
        hash_map_params.socket_id = rte_socket_id();
        hash_map_params.extra_flag = 0;

        return rte_hash_create(&hash_map_params);
}

static int init_lb_maps(struct onvm_nf *nf) {
        struct tcp_lb_maps *tcp_lb_hash_maps;
        int i;
        //struct chain_meta *start_chain;

        const char *ip_map = "IP to service chain";
        const char *chain_to_connections = "Service chain to connections";
        const char *scale_tag_cpy = "Simple Forward";
        scale_tag = rte_malloc(NULL, 20, 0);
        strncpy(scale_tag, scale_tag_cpy, 20);

        tcp_lb_hash_maps = rte_malloc(NULL, sizeof(struct tcp_lb_maps), 0);
     	tcp_lb_hash_maps->total_connections = 3; 
        tcp_lb_hash_maps->chain_connections = create_rtehashmap(chain_to_connections,
                                                                MAX_CHAINS); // 10 service chains (for now)
        tcp_lb_hash_maps->ip_chain = create_rtehashmap(ip_map, 1000); // 1000 different IP addresses

        tcp_lb_hash_maps->chain_meta_list = rte_malloc(NULL, sizeof(struct chain_meta *) * MAX_CHAINS, 0);
        tcp_lb_hash_maps->chain_meta_list[0] = rte_malloc(NULL, sizeof(struct chain_meta), 0);
        tcp_lb_hash_maps->chain_meta_list[0]->chain_id[0] = 3; // First entry in scaled NF's array
        tcp_lb_hash_maps->chain_meta_list[0]->num_connections = 0; // Number of TCP connections
        tcp_lb_hash_maps->chain_meta_list[0]->scaled_nfs = 1; // Starting off with 1 spawned NF
        tcp_lb_hash_maps->list_size = MAX_CHAINS;
        for (i = 1; i < MAX_CHAINS; i++) {
                tcp_lb_hash_maps->chain_meta_list[i] = rte_malloc(NULL, sizeof(struct chain_meta), 0);
                tcp_lb_hash_maps->chain_meta_list[i]->scaled_nfs = 0;
                tcp_lb_hash_maps->chain_meta_list[i]->num_packets = 0;
                tcp_lb_hash_maps->chain_meta_list[i]->num_connections = 0;
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

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
