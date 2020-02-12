//
// Created by Dennis Afanasev on 2020-02-11.
//

#ifndef SD_ONVM_LOAD_BALANCE_H
#define SD_ONVM_LOAD_BALANCE_H

/* Load balancing info */
#define LOAD_BALANCE_ENABLED 1
#define MAX_CHAINS 16
#define MAX_CONNECTIONS 1
#define MAX_FLOWS 1024
#define TCP_LB_ID 1

const char *ip_map = "IP to service chain";
const char *chain_to_connections = "Service chain to connections";
const char *scale_tag_cpy = "Simple Forward";
const char *flow_map_name = "Flow_map";
const char *global_flow_meta_freelist = "Flow_meta freelist";
struct onvm_nf **default_service_chain;

struct flow_meta {
        struct onvm_nf **service_chain; // Service chain pattern
        int global_flow_id; // Flow information is allocated from global_flow_meta
};

struct tcp_lb_maps {
        struct rte_hash *ip_chain; // Int to int
        struct rte_hash *chain_connections; // Int to int
        struct rte_ring *global_flow_meta_freelist;
        struct chain_meta **chain_meta_list;
        int list_size;
        int total_connections;
};

#endif //SD_ONVM_LOAD_BALANCE_H
