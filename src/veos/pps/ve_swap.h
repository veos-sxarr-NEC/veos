/*
 * Copyright (C) 2019-2020 NEC Corporation
 * This file is part of the VEOS.
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file ve_swap.h
 * @brief Data structures and prototype declarations for Partial Process
 * Swapping
 */
#ifndef __VE_SWAP_H
#define __VE_SWAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ve_list.h"
#include "mm_type.h"
#include "task_mgmt.h"
#include "ve_hw.h"
#include "locking_handler.h"

extern log4c_category_t *cat_os_pps;

#define PPS_CRIT(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_CRIT, fmt, ## __VA_ARGS__)
#define PPS_ERROR(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define PPS_WARN(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)
#define PPS_NOTICE(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_NOTICE, fmt, ## __VA_ARGS__)
#define PPS_INFO(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)
#define PPS_DEBUG(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define PPS_TRACE(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_TRACE, fmt, ## __VA_ARGS__)

#define PPS_VIRT_ATB		1
#define PPS_VIRT_DMAATB		2
#define PPS_BUFFPAGE_SIZE	2 /* Size of buffer page in MB */
/* Size of buffer page in Byte */
#define PPS_BUFFPAGE_SIZE_BYTE	(PPS_BUFFPAGE_SIZE * 1024 * 1024)

#define PPS_INTER_SWAPIN	1
#define PPS_INTER_TERM		2
#define PPS_DIR_INVALID		3
#define PPS_ALLOC_RETRY		4
#define NO_PPS_BUFF		5
#define PPS_END_OF_PIDS		-1
#define PPS_FILE_OFF            -1
#define PPS_SKIP_PID            0

#define PPS_MEM_MODE   1
#define PPS_FILE_MODE  2
#define PPS_MIX_MODE   3
#define PPS_TRANSFER_BUFFER_SIZE 64 
#define PPS_TRANSFER_BUFFER_SIZE_BYTE (PPS_TRANSFER_BUFFER_SIZE * 1024 * 1024)
#define PPS_PAGE_SIZE_64MB	(64 * 1024 * 1024)

/**
 * This structure contains information about Swapped-out ATB or
 * Swapped-out DMAATB per ATB entry or DMAATB entry.
 */
struct ve_swapped_virtual {
	struct list_head pages;
	int dir; /* !< Directory number in which Swapped-out page was */
	int ent; /* !< Entry number in which Swapped-out page was */
	struct ve_swapped_physical *phy; /* !< Information about Swapped-out
					  *  VE page */
	int kind; /* !< PPS_VIRT_ATB or PPS_VIRT_DMAATB */
};

/**
 * This structure contains information about Swapped-out VE page.
 */
struct ve_swapped_physical {
	void *buf_page; /* !< Buffer pages */
	off_t file_offset; /* !< File offsets */
	uint64_t perm;    /* !< Permission of Swapped-out page. */
	size_t pgsz;      /* !< Page size of Swapped-out VE page. */
	uint64_t flag;    /* !< Flag of Swapped-out VE page. */
	pgno_t pno;       /* !< VE physical page number which is corresponding
			   *    to this information.*/
	int numa_node;    /* !< Numa node of Swapped-out page. */
	void *private_data; /* !< Private data of Swapped-out VE page. */
	uint64_t ref_cnt;
};

enum swap_progress {
	NOT_SWAPPED, /* !< Not swap-out */
	SWAPPING,    /* !< Swap-out gose on */
	SWAPPED      /* !< Swap-out completes  */
};

/**
  * This structure manages rwlock for exclusive control between IPC and
  * Swap-out/in.
  */
struct ve_ipc_sync {
	pthread_mutex_t ref_lock; /* Lock to protect ref_count and exit_status */
	int ref_count;            /* Reference counter */
	pthread_mutex_t swap_exclusion_lock; /* Lock to protect handling_request and swapping */
	int handling_request;     /* The number of threads handling requests */
	pthread_cond_t handling_request_cond; /* Condition variable to wait handling_request becomes 0 */
	int swapping; /* The flag which is 1 while process is swapped by pps */
	pthread_cond_t swapping_cond; /* Condition variable to wait swapping becomes 0 */
};

int veos_alloc_ppsbuf(size_t, size_t);
int veos_pps_log4c_init(void);
void *ve_swap_thread(void *);
int ve_do_swapout(struct ve_task_struct *);
int ve_do_swapin(struct ve_task_struct *);
void veos_pps_free_buf_page(void *, size_t, int);
void veos_pps_free_file_offset(void *, size_t, int);
int get_task_exit_status(struct ve_task_struct *);
void veos_update_substatus(struct ve_task_struct *, enum swap_status);
int veos_check_substatus(struct ve_task_struct *, enum swap_status);
int veos_pps_save_memory_content(pgno_t);
int del_swapped_pages(struct ve_task_struct *);
void veos_operate_all_ve_task_lock(struct ve_task_struct *, lock_unlock_t);
void veos_free_ppsbuf(void);
bool is_process_veos_terminate(struct ve_task_struct *, char *);
int veos_ve_swapin_req(pid_t *pids);
struct ve_ipc_sync *ve_get_ipc_sync (struct ve_task_struct *);
int ve_put_ipc_sync (struct ve_ipc_sync *);
int ve_set_state_ipc_sync (struct ve_ipc_sync *);
int ve_mark_ipc_sync(struct ve_task_struct *);
int ve_unlock_swapped_proc_lock(struct ve_task_struct *);
struct ve_ipc_sync *ve_alloc_ipc_sync(void);
int is_ve_page_swappable(pgno_t pgno, struct ve_node_struct *vnode);
int is_ve_page_swappable_core(uint64_t, uint64_t, uint64_t, pgno_t,
						struct ve_task_struct *);
void del_doing_swap_request(struct veos_swap_request_info *request);
bool veos_check_pps_enable(void);
void ve_swap_out_start(struct ve_ipc_sync *);
void ve_swap_in_finish(struct ve_ipc_sync *);
int veos_init_pps_file_info(char *, size_t, char *);
int veos_open_pps_file(struct ve_node_struct *);
void veos_del_pps_file(struct ve_node_struct *);
int print_pps_mode_info(char, size_t, bool, bool);
int check_swap_out_in_process(int);
bool check_swap_in_need_wait(struct ve_node_struct *);
int64_t veos_pps_get_cns(struct ve_task_struct *, pid_t);
#endif
