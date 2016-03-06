/*********************************************************************
 *                     openNetVM
 *       https://github.com/sdnfv/openNetVM
 *
 *  Copyright 2015 George Washington University
 *            2015 University of California Riverside
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * flow_table.c - a simple flow table NF
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
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "flow_table.h"
#include "sdn.h"
//#include "onvm_flow_table.h"

#define NF_TAG "flow_table"

extern struct onvm_ft *sdn_ft;

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

struct rte_ring* ring_to_sdn;
struct rte_ring* ring_from_sdn;
#define SDN_RING_SIZE 65536

/* number of package between each print */
static uint32_t print_delay = 10000;

uint16_t def_destination;
static uint32_t total_flows;

/* Setup rings to hold buffered packets destined for SDN controller */
static void
setup_rings(void) {
        ring_to_sdn = rte_ring_create("ring_to_sdn", SDN_RING_SIZE,
                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        ring_from_sdn = rte_ring_create("ring_from_sdn", SDN_RING_SIZE,
                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if(ring_to_sdn == NULL || ring_from_sdn == NULL) {
                rte_exit(EXIT_FAILURE, "Unable to create SDN rings\n");
        }
}

/* Clear out rings on exit. Requires DPDK v2.2.0+ */
static void
cleanup(void) {
        printf("Freeing memory for SDN rings.\n");
        rte_ring_free(ring_to_sdn);
        rte_ring_free(ring_from_sdn);
        printf("Freeing memory for hash table.\n");
        rte_hash_free(sdn_ft->hash);
}

static int
parse_app_args(int argc, char *argv[]) {
        const char *progname = argv[0];
        int c;

        opterr = 0;

        while ((c = getopt (argc, argv, "p:")) != -1)
                switch (c) {
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'p')
                                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                        else
                                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        return -1;
                }
        return optind;
}

static void
do_stats_display(struct rte_mbuf* pkt, int32_t tbl_index) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static int total_pkts = 0;
        /* Fix unused variable warnings: */
        (void)pkt;


        struct onvm_flow_entry *flow_entry = (struct onvm_flow_entry *)onvm_ft_get_data(sdn_ft, tbl_index);
        total_pkts += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("FLOW TABLE NF\n");
        printf("-----\n");
        printf("Total pkts   : %d\n", total_pkts);
        printf("Total flows  : %d\n", total_flows);
        printf("Flow ID      : %d\n", tbl_index);
        printf("Flow pkts    : %"PRIu64"\n", flow_entry->packet_count);
       // printf("Flow Action  : %d\n", flow_entry->action);
       // printf("Flow Dest    : %d\n", flow_entry->destination);
        printf("\n\n");

        #ifdef DEBUG_PRINT
                struct ipv4_hdr* ip;
                ip = onvm_pkt_ipv4_hdr(pkt);
                if (ip != NULL) {
                        onvm_pkt_print(pkt);
                } else {
                        printf("Not an IP4 packet\n");
                }
        #endif
}

static int
flow_table_hit(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta,
               union ipv4_5tuple_host *key, int32_t tbl_index) {
        (void)pkt;
        (void)key;
	(void)meta;
        #ifdef DEBUG_PRINT
        printf("Found existing flow %d\n", tbl_index);
        #endif
      //  meta->action = sdn_ft->data[tbl_index]->scaction;
      //  meta->destination = flow_table[tbl_index].destination;
	struct onvm_flow_entry *flow_entry;
	flow_entry = (struct onvm_flow_entry *)onvm_ft_get_data(sdn_ft, tbl_index);
        flow_entry->packet_count++;
        return 0;
}

static int
flow_table_miss(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta,
                union ipv4_5tuple_host *key) {
        // int32_t tbl_index;
        (void)pkt;
        (void)key;
        int ret;

        #ifdef DEBUG_PRINT
        printf("Unkown flow\n");
        #endif

        // This will go in the SDN thread
        // tbl_index = rte_hash_add_key(flow_table_hash, (const void *)key);
        // #ifdef DEBUG_PRINT
        // printf("New flow %d\n", tbl_index);
        // #endif
        // if(tbl_index < 0) {
        //         onvm_pkt_print(pkt);
        //         rte_exit(EXIT_FAILURE, "Unable to add flow entry\n");
        // }
        // total_flows++;
        // flow_table[tbl_index].count = 1;
        // flow_table[tbl_index].action = ONVM_NF_ACTION_TONF;
        // flow_table[tbl_index].destination = def_destination;

        /* Buffer new flows until we get response from SDN controller. */
        ret = rte_ring_enqueue(ring_to_sdn, pkt);
        if(ret != 0) {
                printf("ERROR enqueing to SDN ring\n");
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }

        return 1;
}

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
        static uint32_t counter = 0;

        //struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ipv4_hdr;
        struct tcp_hdr *tcp_hdr;
        int32_t tbl_index;
        union ipv4_5tuple_host key;
        int action;

        if(!onvm_pkt_is_ipv4(pkt)) {
                printf("Non-ipv4 packet\n");
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = def_destination;
                return 0;
        }

        /* Make a key to do flow table lookup */
        ipv4_hdr = onvm_pkt_ipv4_hdr(pkt);
        tcp_hdr = onvm_pkt_tcp_hdr(pkt);
        memset(&key, 0, sizeof(key));
        key.proto = ipv4_hdr->type_of_service;
        key.virt_port = meta->src;
        key.ip_src = ipv4_hdr->src_addr;
        key.ip_dst = ipv4_hdr->dst_addr;
        /* FIXME: The L3 fwd example gets all of
         * this information by using some mask functions that I don't really
         * understand.  Perhaps we should do the same.
         */
        if(tcp_hdr != NULL) {
                key.port_src = tcp_hdr->src_port;
                key.port_dst = tcp_hdr->dst_port;
        }
        else {
                key.port_src = 0;
                key.port_dst = 0;
        }

        tbl_index = rte_hash_lookup(sdn_ft->hash, (const void *)&key);
        if(tbl_index >= 0) {
                /* Existing flow */
                action = flow_table_hit(pkt, meta, &key, tbl_index);
        }
        else if (tbl_index == -ENOENT) {
                /* New flow */
                action = flow_table_miss(pkt, meta, &key);
        }
        else {
                #ifdef DEBUG_PRINT
                printf("Error in flow lookup: %d (ENOENT=%d, EINVAL=%d)\n", tbl_index, ENOENT, EINVAL);
                onvm_pkt_print(pkt);
                #endif
                rte_exit(EXIT_FAILURE, "Error in flow lookup\n");
        }

        if (++counter == print_delay && print_delay != 0) {
                do_stats_display(pkt, tbl_index);
                counter = 0;
        }

        return action;
}


int main(int argc, char *argv[]) {
        int retval;
        unsigned sdn_core = 0;

        if ((retval = onvm_nf_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= retval;
        argv += retval;
        if (parse_app_args(argc, argv) < 0) {
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        printf("Flow table running on %d\n", rte_lcore_id());

        def_destination = nf_info->client_id + 1;
        printf("Setting up hash table with default destination: %d\n", def_destination);
        total_flows = 0;

        /* Setup the SDN connection thread */
        printf("Setting up SDN rings and thread.\n");
        setup_rings();
        sdn_core = rte_lcore_id();
        sdn_core = rte_get_next_lcore(sdn_core, 1, 1);
        rte_eal_remote_launch(setup_securechannel, NULL, sdn_core);

        printf("Starting packet handler.\n");
        onvm_nf_run(nf_info, &packet_handler);
        printf("NF exiting...");
        cleanup();
        return 0;
}
