/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
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

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_cycles.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "basic_monitor"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t total_packets = 0;
static uint64_t last_cycle;
static uint64_t cur_cycles;
static void do_stats_display();


static uint8_t measure_latency = 0;
static uint32_t latency_packets = 0;
static uint64_t total_latency = 0;
/* shared data structure containing host port info */
extern struct port_info *ports;


struct onvm_nf *nf;

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

static int
callback_handler(__attribute__((unused)) struct onvm_nf_info *nf_info) {
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
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info) {
        static uint32_t counter = 0;
        total_packets++;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        meta->action = ONVM_NF_ACTION_OUT;
        meta->destination = pkt->port;
//	meta->destination = 0;

        if (onvm_pkt_swap_src_mac_addr(pkt, meta->destination, ports) != 0) {
                RTE_LOG(INFO, APP, "ERROR: Failed to swap src mac with dst mac!\n");
        }
        return 0;
}

static void
do_stats_display() {
        static uint64_t last_cycles;
        static uint64_t cur_pkts = 0;
        static uint64_t last_pkts = 0;
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

        uint64_t cur_cycles = rte_get_tsc_cycles();
        cur_pkts += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("Total packets: %9"PRIu64" \n", cur_pkts);
        printf("TX pkts per second: %9"PRIu64" \n", (cur_pkts - last_pkts)
                                                    * rte_get_timer_hz() / (cur_cycles - last_cycles));
        if (measure_latency && latency_packets > 0)
                printf("Avg latency nanoseconds: %6"PRIu64" \n", total_latency/(latency_packets)
                                                                 * 1000000000 / rte_get_timer_hz());

        total_latency = 0;
        latency_packets = 0;

        last_pkts = cur_pkts;
        last_cycles = cur_cycles;

        printf("\n\n");
}


void
monitor(struct onvm_nf_info *nf_info, struct queue_mgr *tx_mgr) {
        uint16_t i, port_id, j;
        uint16_t rx_count, tx_count;
        //struct rte_ring *rx_ring;
        //struct rte_ring *tx_ring;
        //volatile struct onvm_nf *nf;
        struct rte_mbuf *pkts[PACKET_READ_SIZE];
        struct onvm_pkt_meta *meta;

        printf("NF with instance id %d is running without RX/TX thread", nf_info->instance_id);

        //nf = onvm_nflib_get_nf(nf_info->instance_id);
        //rx_ring = nf->rx_q;
        //tx_ring = nf->tx_q;
        //for (i=0; i<PACKET_READ_SIZE; i++){
        //      pkts[i] = rte_pktmbuf_alloc(nf->nf_pool);
        //}
        port_id = (nf_info->instance_id - 1) % 4;
        static uint32_t counter = 0;

        for (;;) {
                rx_count = rte_eth_rx_burst(port_id, 0, pkts, PACKET_READ_SIZE);

                if (rx_count > 0) {

                        for (j = 0; j < rx_count; j++) {

                                onvm_pkt_enqueue_nf(tx_mgr, 2, pkts[j], nf);

                                if (counter++ == print_delay) {
                                        do_stats_display();
                                        counter = 0;
                                }

                                //printf("Sent");
                        }

                }
                //tx_count = rte_eth_tx_burst(port_id, 0, pkts, rx_count);

                //onvm_pkt_process_tx_batch(tx_mgr, pkts, tx_count, nf);
        }
}


int main(int argc, char *argv[]) {
        int arg_offset;
        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, &nf_info)) < 0)
                return -1;

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        cur_cycles = rte_get_tsc_cycles();
        last_cycle = rte_get_tsc_cycles();

        struct queue_mgr *tx_mgr = calloc(1, sizeof(struct queue_mgr));
        tx_mgr->mgr_type_t = MGR;
        tx_mgr->id = 0;
        tx_mgr->tx_thread_info = calloc(1, sizeof(struct tx_thread_info));
        tx_mgr->tx_thread_info->port_tx_bufs = calloc(RTE_MAX_ETHPORTS, sizeof(struct packet_buf));
        tx_mgr->nf_rx_bufs = calloc(MAX_NFS, sizeof(struct packet_buf));
        tx_mgr->tx_thread_info->first_nf = 1;
        tx_mgr->tx_thread_info->last_nf = 2;

        nf = &nfs[1];

        //onvm_nflib_run_callback(nf_info, &packet_handler, &callback_handler);
        monitor(nf_info, tx_mgr);
        printf("If we reach here, program is ending\n");
        return 0;
}
