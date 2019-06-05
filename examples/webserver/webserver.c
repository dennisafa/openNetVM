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
#include <sys/types.h>
#include <dirent.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_mtcp_common.h"
#include "/local/onvm/mtcp/util/include/http_parsing.h"

#define NF_TAG "webserver"
#define MIN(a,b) (((a)<(b))?(a):(b))

#define NAME_LIMIT 256
#define FULLNAME_LIMIT 512
#define MAX_FILES 30

struct file_cache
{
        char name[NAME_LIMIT];
        char fullname[FULLNAME_LIMIT];
        uint64_t size;
        char *file;
};

const char *www_main = NULL;
DIR *dir;
int nfiles;
static int read_file (struct nf_files *files, char *file_name);
static void cache_files(void);
static struct file_cache fcache[MAX_FILES];

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
        int c, dir_flag = 1;

        while ((c = getopt(argc, argv, "p:")) != -1) {
                switch (c) {
                        case 'p':
                                www_main = optarg;
                                dir = opendir(www_main);
                                if (dir == NULL) {
                                        dir_flag = 0;
                                }
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

        if (!dir_flag) {
                RTE_LOG(INFO, APP, "Directory must be specified\n");
                return -1;
        }

        return optind;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        meta->action = ONVM_NF_ACTION_DROP;
        return 0;
}

static void
msg_handler(void *msg, struct onvm_nf_local_ctx *nf_local_ctx) {
        struct nf_files *mtcp_files;
        struct mtcp_epoll_event *even;
        char *filename;
        struct server_vars *serv;
        int success;

        mtcp_files = (struct nf_files *) msg;
        even = mtcp_files->ev;
        serv = mtcp_files->sv;
        filename = serv->fname;

        printf("Event: %d\n", even->events);

        if (even == NULL || serv == NULL || filename == NULL) {
                printf("Invalid mTCP message\n");
                return;
        }

        switch (even->events) {
                case MTCP_EPOLLIN:
                        success = read_file(mtcp_files, filename);
                        if (success) {
                                printf("File transmitted to main mTCP nf successfully\n\n");
                        }
                        break;
                case MTCP_EPOLLOUT:
                default:
                        printf("Unknown mTCP message\n");
                        break;
        }
}

static int
read_file (struct nf_files *mtcp_files, char *mtcp_filename) {
        struct server_vars *sv;
        char keepalive_str[128];
        //char response[HTTP_HEADER_LEN];
        char t_str[128];
        int i, scode;
        time_t t_now;

        sv = mtcp_files->sv;

        //printf("mTCP main NF requests file: %s\n", mtcp_filename);
        RTE_LOG(INFO, APP, "mTCP main NF requests file: %s\n", mtcp_filename);
        mtcp_files->file_sent = 0;
        for (i = 0; i < nfiles; i++) {
                if (strcmp(fcache[i].name, mtcp_filename) == 0) {
                        mtcp_files->file_buffer = (char *) rte_zmalloc("char_buffer", fcache[i].size, 0);
                        mtcp_files->response = (char *) rte_zmalloc("response_buffer", HTTP_HEADER_LEN, 0);
                        snprintf(mtcp_files->file_buffer, fcache[i].size, "%s", fcache[i].file);
                        sv->fsize = fcache[i].size;
                        scode = 200; // File found
                        mtcp_files->file_sent = 1;
                        RTE_LOG(INFO, APP, "Found file %s\n", mtcp_filename);
                        break;
                }
        }
        if (!mtcp_files->file_sent) {
                RTE_LOG(INFO, APP, "Requested file not found\n");
                mtcp_files->file_sent = 2; // Error, file wasn't found
                return 0;
        }

        // Creating response header

        sv->keep_alive = 0;
        if (http_header_str_val(sv->request, "Connection: ", strlen("Connection: "), keepalive_str, 128)) {
                if (strstr(keepalive_str, "Keep-Alive")) {
                        sv->keep_alive = 1;
                } else if (strstr(keepalive_str, "Close")) {
                        sv->keep_alive = 0;
                }
        }

        time(&t_now);
        strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));

        if (sv->keep_alive) {
                sprintf(keepalive_str, "Keep-Alive");
        } else {
                sprintf(keepalive_str, "Close");
        }

        sprintf(mtcp_files->response, "HTTP/1.1 %d OK\r\n"
                          "Date: %s\r\n"
                          "Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
                          "Content-Length: %ld\r\n"
                          "Connection: %s\r\n\r\n",
                scode, t_str, sv->fsize, keepalive_str);

        RTE_LOG(INFO, APP, "Sending file to mTCP main NF\n");
        onvm_nflib_send_msg_to_nf(1, (void*) mtcp_files);

        return 1;
}


static void
cache_files (void) {
        struct dirent *ent;
        uint32_t total_read;
        int fd, ret, i;

        nfiles = 0;
        while ((ent = readdir(dir)) != NULL) { // Storing the files
                if (strcmp(ent->d_name, ".") == 0)
                        continue;
                else if (strcmp(ent->d_name, "..") == 0)
                        continue;

                snprintf(fcache[nfiles].name, NAME_LIMIT, "%s", ent->d_name);
                snprintf(fcache[nfiles].fullname, FULLNAME_LIMIT, "%s/%s",
                         www_main, ent->d_name);
                fd = open(fcache[nfiles].fullname, O_RDONLY);
                if (fd < 0) {
                        perror("open");
                        continue;
                } else {
                        fcache[nfiles].size = lseek64(fd, 0, SEEK_END);
                        lseek64(fd, 0, SEEK_SET);
                }

                fcache[nfiles].file = (char *)malloc(fcache[nfiles].size);
                if (!fcache[nfiles].file) {
                        perror("malloc");
                        continue;
                }

                total_read = 0;
                while (1) {
                        ret = read(fd, fcache[nfiles].file + total_read,
                                   fcache[nfiles].size - total_read);
                        if (ret < 0) {
                                break;
                        } else if (ret == 0) {
                                break;
                        }
                        total_read += ret;
                }
                if (total_read < fcache[nfiles].size) {
                        free(fcache[nfiles].file);
                        continue;
                }
                close(fd);
                nfiles++;

                if (nfiles >= MAX_FILES)
                        break;
        }

        if (nfiles == 0) {
                RTE_LOG(INFO, APP, "No files stored in cache\n");
                return;
        }

        for (i = 0; i < nfiles; i++) {
                printf("%d:%s\n", i, fcache[i].name);
        }


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
        nf_function_table->msg_handler = &msg_handler;
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

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        cache_files();

        onvm_nflib_run(nf_local_ctx);
        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
