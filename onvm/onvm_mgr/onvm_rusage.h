#ifndef _ONVM_RUSAGE_H_
#define _ONVM_RUSAGE_H_

#include <stdio.h>
#include <time.h>

#include "onvm_nf.h"
#include "onvm_mgr.h"

#define RUSAGE_UPDATE_INTERVAL_MS 100

void onvm_update_rusage(void);

double core_rusage[MAX_NFS];

#endif
