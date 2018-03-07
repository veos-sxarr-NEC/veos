#ifndef __AMM_PSM_IF_H
#define __AMM_PSM_IF_H

#include <pthread.h>
#include "veos_list.h"
#include "ve_hw.h"
#include "psm_task_mgmt.h"

#define REQUEST_FOR_PROCESS_SHARED     1
#define REQUEST_FOR_PROCESS_PRIVATE    2

/*
 * Data Structures
 */

struct mm_thread_descriptor {
	/* Thread ID */
	uint64_t tid;
	/* Head to maintain list of mm_thread_descriptor */
	struct list_head mm_thread_head;
};

struct ve_mm_struct {
	/* Process ID */
	uint64_t pid;
	/* ATB structure*/
	atb_reg_t atb;
	/* Mutex lock */
	pthread_mutex_t mm_lock;
	pthread_mutex_t shm_lock;
	/* Count for number of threads that are sharing this mm_struct */
	int ref_count;
	/* SHM/LHM area address */
	uint64_t shm_lhm_addr;
	/* Info regarding threads under process */
	struct mm_thread_descriptor mm_td;
	/*List of shm segments attached in Process Virtual Address Space*/
	struct list_head shm_head;

	/* TODO: Need to add handling for populating
	 * below mentioned data structures.
	 */
	uint64_t start_code, end_code,
		start_data, end_data,
		start_brk, brk,
		start_stack, arg_start,
		arg_end, env_start,
		env_end;

};


/* <------ AMM Interfaces ------> */

extern int amm_alloc_mm_struct(struct ve_mm_struct **);
extern int amm_copy_mm_struct(struct ve_mm_struct *,
				struct ve_mm_struct **, int, int);
extern int amm_update_atb(struct ve_task_struct *, uint64_t);
extern int amm_update_dmaatb(struct ve_task_struct *, uint64_t);
extern int amm_update_atb_all(struct ve_task_struct *);
extern int amm_del_mm_struct(struct ve_mm_struct **, int);
extern int64_t amm_addr_translation(char *, atb_reg_t *);
uint64_t amm_get_rss_in_kb(struct ve_mm_struct *);
#endif
