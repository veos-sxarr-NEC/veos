/**
 * @file psm_main.h
 * @brief PSM API
 */
#ifndef __PSM_MAIN_H
#define __PSM_MAIN_H

#include <pthread.h>
#include "libved.h"

#define MAX_PSM_PSEUDO_MSG_LEN	256
#define THREAD_WAIT_FOR_USE	0
#define THREAD_IN_USE		1
#define VE_PROC_PRIORITY_MAX		0
#define VE_PROC_PRIORITY_MIN		0

/**
 * @brief PSM Scheduling parameters
 */
struct psm_param {
	int priority; /*!< if priority based scheduling */
	int pid; /*!< required when sending reply */
	int timeslice; /*!< time slice */
};

/**
 * @brief PSM communication command struct
 */
struct psm_cmd {
	int cmd; /*!< command */
	union {
		struct psm_param param; /*!< command parameters */
	} param;
};
#endif
