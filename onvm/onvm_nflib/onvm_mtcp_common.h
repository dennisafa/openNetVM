//
// Created by Dennis Afanasev on 2019-05-31.
//

#ifndef _ONVM_MTCP_COMMON_H
#define _ONVM_MTCP_COMMON_H

#define MTCP_EPOLLNONE      0x000
#define MTCP_EPOLLIN        0x001
#define MTCP_EPOLLPRI       0x002
#define MTCP_EPOLLOUT       0x004
#define MTCP_EPOLLRDNORM    0x040
#define MTCP_EPOLLRDBAND    0x080
#define MTCP_EPOLLWRNORM    0x100
#define MTCP_EPOLLWRBAND    0x200
#define MTCP_EPOLLMSG       0x400
#define MTCP_EPOLLERR       0x008
#define MTCP_EPOLLHUP       0x010
#define MTCP_EPOLLRDHUP     0x2000
#define MTCP_EPOLLONESHOT   (1 << 30)
#define MTCP_EPOLLET        (1 << 31)

#define HTTP_HEADER_LEN 1024
#define NAME_LIMIT 256
#define URL_LEN 128

typedef union mtcp_epoll_data {
        void *ptr;
        int sockid;
        uint32_t u32;
        uint64_t u64;
} mtcp_epoll_data_t;
/*----------------------------------------------------------------------------*/
struct mtcp_epoll_event {
        uint32_t events;
        mtcp_epoll_data_t data;
};

struct nf_files {
        struct server_vars *sv;
        struct mtcp_epoll_event *ev;
        int file_sent;
        char *file_buffer;
        char *response;
};

struct server_vars
{
        char request[HTTP_HEADER_LEN];
        int recv_len;
        int request_len;
        long int total_read, total_sent;
        uint8_t done;
        uint8_t rspheader_sent;
        uint8_t keep_alive;

        int fidx;						// file cache index
        char fname[NAME_LIMIT];				// file name
        long int fsize;					// file size
};

#endif
