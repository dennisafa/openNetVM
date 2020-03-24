#ifndef _ONVM_RUSAGE_H_
#define _ONVM_RUSAGE_H_

#include "onvm_common.h"
#include <math.h>
#include <sys/time.h>
#include <sys/resource.h>

#define RUSAGE_UPDATE_INTERVAL 2

/* Update the NF's rusage if the interval has been passed. */
void onvm_rusage_update(struct onvm_nf *nf);

#endif
