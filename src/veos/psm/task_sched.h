/**
* Copyright (C) 2017-2018 NEC Corporation
* This file is part of the VEOS.
*
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
 * @file task_sched.h
 * @brief VE scheduler
 */

#ifndef __PSM_SCHED_H
#define __PSM_SCHED_H

#include <stdio.h>
#include <stdbool.h>
#include "ve_hw.h"
#include "dmaatb_api.h"
#include "task_signal.h"
#include "task_mgmt.h"

#define ASSIGN_RETRY_CNT	8
#define ASSIGN_RETRY_DELAY	1
#define VE_UDMA_OFFSET_OF_DMACTL(i) (offsetof(core_system_reg_t, dmactl[(i)]))
#define VE_UDMA_OFFSET_OF_DMADESC(i) (offsetof(core_system_reg_t, dmades[(i)]))
#define VE_CORE_OFFSET_OF_JIDR (offsetof(core_system_reg_t, JIDR))
#define VE_CORE_OFFSET_OF_DIDR (offsetof(core_system_reg_t, DIDR))

#define VE_UDMA_CTL_STATUS_HALT	(2)
#define VE_UDMA_CTL_PERM_START	(1)
#define VE_UDMA_CTL_PERM_STOP	(0)
#define VE_UDMA_EENTRY		(1)
#define VE_UDMA_HENTRY		(0)
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))
#define CLEAR_BIT(bitmap, bit) (bitmap &= ~(1 << bit))

#define HALT_CORE_MAX_TIME	30
#define START_CORE_MAX_TIME	1

#define NANO_SECONDS 1
#define MILLI_SECONDS (1000 * NANO_SECONDS)
#define MICRO_SECONDS (1000 * 1000 * NANO_SECONDS)

#define PSM_CTXSW_CREG_VERAA(phys_core_num) (\
	PCI_BAR2_CREG_SIZE * phys_core_num)

#define PSM_CTXSW_CREG_SIZE (\
	offsetof(core_user_reg_t, VR) +\
	sizeof(((core_user_reg_t *)NULL)->VR))

#define SECONDS 1
#define DIR_CNT 32
/* "PSM_TIMER_INTERVAL_SECS" timer interval in which
 * scheduling decision can occur */
#define PSM_TIMER_INTERVAL_SECS 0
#define PSM_TIMER_INTERVAL_NSECS 100*1000*1000
#define PSM_TIMER_INTERVAL_MIN_MLSECS 1
#define PSM_TIMER_INTERVAL_MAX_MLSECS 60000
/* "PSM_TIME_SLICE_SECS" per process time slice of VE process.
 * */
#define PSM_TIME_SLICE_SECS 1
#define PSM_TIME_SLICE_NSECS 0
#define PSM_TIME_SLICE_MIN_MLSECS 1
#define PSM_TIME_SLICE_MAX_MLSECS 60000

typedef enum {
	_DMAATB = 0,
	_ATB,
	_CRD,
	REG_INVAL = -1
}regs_t;
/* "veos_timer_interval" Timer interval, in nano seconds. */
extern int64_t veos_timer_interval;
/* "veos_time_slice" Time slice, in micro seconds. */
extern int64_t veos_time_slice;

int psm_alloc_udma_context_region(struct ve_task_struct *);
int psm_free_udma_context_region(struct ve_task_struct *);
bool psm_compare_jid(struct ve_task_struct *, struct ve_task_struct *);
bool psm_check_sched_jid_core(uint64_t *, struct ve_task_struct *, regs_t, reg_t *);
bool psm_check_udma_desc(struct ve_task_struct *);
int psm_stop_udma(int, uint8_t);
int psm_save_udma_context(struct ve_task_struct *, int);
int psm_restore_udma_context(struct ve_task_struct *ve_task, int);
int __psm_restore_udma_context(struct ve_task_struct *, int, bool);
int psm_start_udma(int, uint8_t);
void psm_wake_up_scheduler(struct ve_core_struct *, bool);
int psm_set_jdid(struct ve_task_struct *);
int psm_halt_ve_core(int, int, reg_t *, bool);
int psm_start_ve_core(int, int);
void psm_sched_interval_handler(union sigval);
int psm_udma_no_migration(struct ve_task_struct *);
int psm_udma_do_migration(struct ve_task_struct *, uint64_t);
int psm_process_dma_migration(struct ve_task_struct*);
void psm_save_current_user_context(struct ve_task_struct *);
struct ve_task_struct* psm_find_next_task_to_schedule(
		struct ve_core_struct *);
int veos_scheduler_timer(struct ve_node_struct *);
int veos_remove_timer(struct ve_node_struct *);
int psm_restore_context_for_new_thread(struct ve_task_struct *);
int schedule_task_on_ve_node_ve_core(struct ve_task_struct *,
		struct ve_task_struct *,
		bool, bool);
int veos_update_atb(uint64_t, void *, int, int, struct ve_task_struct *);
int veos_update_dmaatb(uint64_t, void *, int, int, struct ve_task_struct *, reg_t *);
int psm_sync_hw_regs(struct ve_task_struct *, regs_t, void *, bool, int, int);
void psm_find_sched_new_task_on_core(struct ve_core_struct *, bool, bool);
void psm_rebalance_task_to_core(struct ve_core_struct *);
void psm_unassign_migrate_task(struct ve_task_struct *);
int psm_calc_task_exec_time(struct ve_task_struct *);
bool psm_unassign_task(struct ve_task_struct *);
bool psm_unassign_assign_task(struct ve_task_struct *, bool);
struct ve_task_struct *find_and_remove_task_to_rebalance(int, int);
void insert_and_update_task_to_rebalance(int, int, struct ve_task_struct *);
#endif
