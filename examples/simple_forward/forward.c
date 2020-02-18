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
 * forward.c - an example using onvm. Forwards packets to a DST NF.
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

#include <rte_malloc.h>
#include <rte_hash.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_load_balance.h"

#define NF_TAG "simple_forward"

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t destination;

struct rte_hash *flow_map_obj;
struct packet_tuple {
        uint32_t ip_src;
        uint32_t ip_dst;
};


/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d <dst>`: destination service ID to foward to\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'p')
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

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
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
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

#ifdef LOAD_BALANCE_LOOKUP
        int fd_ret;
        struct onvm_flow_entry *flow_entry = NULL;
        struct onvm_service_chain *service_chain = NULL;
        int index, dup_index;
        //struct onvm_service_chain *sc;
        fd_ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (fd_ret < 0) {
                printf("No flow lookup for this packet\n");
                goto normal_send;
        } else {
                service_chain = flow_entry->sc;
        }
        for (int i = 0; i < CHAIN_LENGTH; i++) {
                if (service_chain->sc[i].destination == nf_local_ctx->nf->service_id) {
                        index = i + 1;
                        if (service_chain->sc[index].destination == 0) {
                                destination = ONVM_MTCP_ID;
                                printf("We're done!\n");
                        }
                        else {
                                //printf("Found next service_chain entry");
                                if (service_chain->sc[index].is_duplicated == 1) {
                                        dup_index = service_chain->sc[index].num_packets % service_chain->sc[index].num_duplicated;
                                        destination = service_chain->sc[index].destination_dup[dup_index];
                                }
                                else {
                                        destination = service_chain->sc[index].destination;
                                }
                                //printf("destination: %d\n", destination);
                        }
                }

        }
#endif


//
//        union ipv4_5tuple_host newkey;
//        struct tcp_hdr *tcp_hdr;
//        struct ipv4_hdr *ipv4_hdr;
//        void *flow_meta_value;
//        struct flow_meta *flow_meta_lkup;
//
//        ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
//        tcp_hdr = onvm_pkt_tcp_hdr(pkt);
//
//        newkey.ip_dst = rte_cpu_to_be_32(ipv4_hdr->dst_addr);
//        newkey.ip_src = rte_cpu_to_be_32(ipv4_hdr->src_addr);
//        newkey.port_dst = rte_cpu_to_be_16(tcp_hdr->dst_port);
//        newkey.port_src = rte_cpu_to_be_16(tcp_hdr->src_port);
//        int hash_ret = rte_hash_lookup_data(flow_map_obj, (void *) &newkey, &flow_meta_value);
//        flow_meta_lkup = (struct flow_meta *) flow_meta_value;
//        if (hash_ret < 0) {
//                printf("Could not find hash\n");
//        }
//        printf("Flow lkup: %s\n", flow_meta_lkup->service_chain[0]->tag);

        normal_send:
        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
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

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }
        nf_local_ctx->nf->state = ONVM_NF_STATELESS;

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        destination = ONVM_MTCP_ID;
        onvm_flow_dir_nf_init();

        onvm_nflib_run(nf_local_ctx);
        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
