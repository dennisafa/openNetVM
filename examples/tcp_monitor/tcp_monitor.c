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
#include "onvm_common.h"

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_load_balance.h"

#define NF_TAG "TCP Load Balancer"

int load_balance_flow(struct onvm_nf *nf, struct onvm_service_chain *service_chain_flow_map, int index);
int pick_initial_dest(struct onvm_service_chain *service_chain);

// Trying to use flow specific

int default_service_chain_id[MAX_CHAINS];
int next_service_id = 0;

#define CPU_MAX 0.30

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
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        int fd_ret;
        int dest;
        int num_duplicated;
        int dups_killed;
        int spawned_nf_id;
        struct onvm_flow_entry *flow_entry = NULL;
        struct onvm_service_chain *sc;
        struct tcp_hdr *tcp_hdr;
        uint16_t flags = 0;
        dups_killed = 0;
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
        if (fd_ret >= 0) {
                sc = flow_entry->sc;
        } else {
                //flow_entry = (struct onvm_flow_entry *) rte_malloc(NULL, sizeof(struct onvm_flow_entry), 0);
                onvm_flow_dir_add_pkt(pkt, &flow_entry);
                memset(flow_entry, 0, sizeof(struct onvm_flow_entry));
                flow_entry->sc = onvm_sc_create();
                sc = flow_entry->sc;

                for (int i = 1; i < CHAIN_LENGTH; i++) {
                        next_dest_id = default_service_chain_id[i - 1];
                        nf = &nfs[next_dest_id];
                        if (nf->resource_usage.cpu_time_proportion > CPU_MAX) {
                                switch (nf->state) {
                                        case ONVM_NF_STATEFUL:
                                                spawned_nf_id = load_balance_flow(nf, sc, i);
                                                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF,
                                                                     spawned_nf_id);
                                                break;
                                        default:
                                                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF,
                                                                     default_service_chain_id[i - 1]);
                                                break;
                                }

                        } else {
                                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF,
                                                     default_service_chain_id[i - 1]);
                        }
                }
        }

        for (int i = 1; i < CHAIN_LENGTH; i++) {
                dest = sc->sc[i].destination;
                dest = onvm_sc_service_to_nf_map(
                        dest, pkt);
                nf = &nfs[dest];
                if (nf->resource_usage.cpu_time_proportion > CPU_MAX) {
                        switch (nf->state) {
                                case ONVM_NF_STATELESS:
                                        load_balance_flow(nf, sc, i);
                                        break;
                                default:
                                        break;
                        }
                }
        }

        dest = pick_initial_dest(sc);

        nf = nf_local_ctx->nf;
        if ((flags >> 1) & 0x1) { // SYN so add connection count to service chain
                nf->num_flows++;
                printf("Number of flows: %ld\n", nf->num_flows);
        }

        if (flags & 0x1) { // FIN so add connection count to service chain
                if (nf->num_flows > 0) {
                        nf->num_flows--;
                }

                if (nf->num_flows == 0) {
                        printf("Killing NF's\n");
                        for (int i = 1; i < CHAIN_LENGTH; i++) {
                                nf = &nfs[default_service_chain_id[i-1]];
                                if (sc->sc[i].is_duplicated == 1) {
                                        num_duplicated = sc->sc[i].num_duplicated;
                                        sc->sc[i].destination_dup[0] = 0;
                                        for (int j = 1; j < num_duplicated; j++) {
                                                int dst_instance_id = onvm_sc_service_to_nf_map(
                                                        sc->sc[i].destination_dup[j], pkt);
                                                onvm_nflib_send_kill_msg(dst_instance_id);
                                                printf("Killing %d\n", sc->sc[i].destination_dup[j]);
                                                sc->sc[i].num_duplicated--;
                                                nf->num_duplicated--; // heres the problem - nf should be changed too
                                                sc->sc[i].destination_dup[j] = 0;
                                                next_service_id--;
                                        }
                                        sc->sc[i].is_duplicated = 0;
                                }
                                dups_killed = 1;
                        }
                }
                printf("Number of flows: %ld\n", nf->num_flows);
        }

        if (dups_killed == 1) {
                dest = sc->sc[1].destination;
                printf("Dups killed, sending to %d\n", dest);
        }

        meta->action = ONVM_NF_ACTION_TONF; // otherwise we have a scaled nf so send it to that
        meta->destination = dest;

        return 0;
}

int
load_balance_flow(struct onvm_nf *nf, struct onvm_service_chain *service_chain_flow_map, int index) {
        int num_duplicated;
        int nf_id;

        num_duplicated = nf->num_duplicated;

        if (num_duplicated > 1 && nf->state ==
                                  ONVM_NF_STATELESS) { // If the flow is coming in and the original is overloaded, spread across dups
                for (int j = 0; j < num_duplicated; j++) {
                        service_chain_flow_map->sc[index].destination_dup[j] = nf->destination_dup[j];
                }
                service_chain_flow_map->sc[index].is_duplicated = 1;
                service_chain_flow_map->sc[index].num_duplicated = num_duplicated;
                //printf("Num duplicated: %d\n", num_duplicated);
        }

        // But if it's been more than 5 secs and the duplicates arent taking the load off
        // then spawn another one and add it

        // Copy nf dup array into current duplicated service chain array
        if ((rte_get_tsc_cycles() - nf->time_since_scale) * TIME_TTL_MULTIPLIER /
            rte_get_timer_hz() < 10) {
                return -1;
        }

        if (num_duplicated == ONVM_MAX_CHAIN_LENGTH - 1) {
                return -1;
        }

        onvm_nflib_fork(nf->tag, 2, next_service_id);
        nf->time_since_scale = rte_get_tsc_cycles();
        service_chain_flow_map->sc[index].is_duplicated = 1;
        nf->num_duplicated++;
        nf->destination_dup[nf->num_duplicated - 1] = next_service_id; // 4 is the id of the new duplicated NF
        nf_id = next_service_id;
        next_service_id++;

        for (int j = 0; j < nf->num_duplicated; j++) {
                service_chain_flow_map->sc[index].destination_dup[j] = nf->destination_dup[j];
        }

        service_chain_flow_map->sc[index].num_duplicated = nf->num_duplicated;

        return nf_id;
}

int
pick_initial_dest(struct onvm_service_chain *service_chain) {
        int dup_index;
        int dest;

        service_chain->sc[1].num_packets++;
        if (service_chain->sc[1].is_duplicated == 1) {
                dup_index = service_chain->sc[1].num_packets % service_chain->sc[1].num_duplicated;
                dest = service_chain->sc[1].destination_dup[dup_index];
        } else {
                dest = service_chain->sc[1].destination;
        }

        return dest;
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
        next_service_id = CHAIN_LENGTH + 2;

        default_service_chain_id[0] = 3;
        default_service_chain_id[1] = 4;

        onvm_flow_dir_nf_init();

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
