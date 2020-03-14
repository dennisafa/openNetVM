#include "onvm_rusage.h"

extern struct onvm_nf *nfs;

void onvm_update_rusage(void) {
        for (int i = 0; i < MAX_NFS; i++)
                core_rusage[i] = 0.0;

        static unsigned long int last_update_time = 0;

        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
                // TODO Error getting time.
        }

        // Calculate how many ticks have passed since the last update.
        unsigned long int now_time = (now.tv_sec + now.tv_nsec / 1e9) * sysconf(_SC_CLK_TCK);
        unsigned long int last_update_delta = now_time - last_update_time;

        for (int i = 0; i < MAX_NFS; i++) {
                if (!onvm_nf_is_valid(&nfs[i]))
                        continue;

                char proc_file_path[24];
                if (snprintf(proc_file_path, 24, "/proc/%d/stat", nfs[i].pid) > 24) {
                        // TODO Filepath too long.
                }

                FILE *proc_file = fopen(proc_file_path, "r");
                // TODO Error check proc_file.

                unsigned long int ctime, stime;
                if (fscanf(proc_file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &ctime, &stime)
                                != 2) {
                        // TODO Report fscanf error.
                }
                unsigned long int nf_usage = ctime + stime;

                // Calculate the NF's CPU usage by dividing the time spent on this NF by the total time passed.
                nfs[i].resource_usage.cpu_time_proportion = 
                        (double)(nf_usage - nfs[i].resource_usage.last_usage) / (double)last_update_delta;

                nfs[i].resource_usage.last_usage = nf_usage;

                core_rusage[nfs[i].thread_info.core] += nfs[i].resource_usage.cpu_time_proportion;
        }

        last_update_time = now_time;
}
