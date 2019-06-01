//
// Created by Dennis Afanasev on 2019-05-31.
//

#ifndef _ONVM_MTCP_COMMON_H
#define _ONVM_MTCP_COMMON_H

typedef union mtcp_epoll_data
{
        void *ptr;
        int sockid;
        uint32_t u32;
        uint64_t u64;
} mtcp_epoll_data_t;
/*----------------------------------------------------------------------------*/
struct mtcp_epoll_event
{
        uint32_t events;
        mtcp_epoll_data_t data;
};


#endif
