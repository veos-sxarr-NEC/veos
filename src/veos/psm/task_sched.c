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
 * @file  task_sched.c
 * @brief Scheduler functionality.
 *
 * This file contains the functions which are responsible for carrying out
 * scheduling of VE processes on VE core
 *
 * @author PSMG / Scheduling and context switch
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <veos_arch_defs.h>
#include "dmaatb_api.h"
#include "mm_common.h"
#include "task_sched.h"
#include "velayout.h"
#include "task_mgmt.h"
#include "task_signal.h"
#include "cr_api.h"
#include "locking_handler.h"
#include "vesync.h"
#include "ve_shm.h"

#include <sys/syscall.h>
#include <sys/syslog.h>

/* To record the first power throttling event occured in any VE core */
bool first_power_throttling_occured = false;

/**
* @brief Function handles the failure of assigning task on core
* while context switch decision is ongoing.
*
* @param curr_ve_task Pointer to current task on core
* @param task_to_schedule Pointer to new task getting scheduled on core
* @param schedule_current Flag indicating current and new task are same
*/
void psm_handle_assign_failure(struct ve_task_struct *curr_ve_task,
		struct ve_task_struct *task_to_schedule,
		bool schedule_current)
{
	VEOS_TRACE("Entering");

	/* If "schedule_current" is set then following needs to be done
	 * before making current task on core as NULL
	 * - Decrement thread_sched_count
	 * - Save current task context
	 * */
	if (schedule_current && curr_ve_task) {
		*(curr_ve_task->thread_sched_count) -= 1;
		CLEAR_BIT(*(curr_ve_task->thread_sched_bitmap),
				curr_ve_task->core_id);
		VEOS_DEBUG("DECREMENT THREAD_SCHED_COUNT %d PID %d",
				*(curr_ve_task->thread_sched_count),
				curr_ve_task->pid);
		psm_save_current_user_context(curr_ve_task);
		VEOS_DEBUG("Saved current user context from core"
				"for PID %d", curr_ve_task->pid);
		curr_ve_task->reg_dirty = false;
	}

	/* If current and task to schedule are from same group then
	 * migration decision is to be made as assign to task failed
	 * */
	if ((curr_ve_task) &&
			(curr_ve_task->group_leader
			 == task_to_schedule->group_leader)) {
		VEOS_DEBUG("Current task %d and task to schedule %d"
				" do not belong to same thread group",
				curr_ve_task->pid, task_to_schedule->pid);

		/* Check whether DMA needs to be migrated*/
		(*_veos_arch_ops->arch_psm_process_dma_resource)(curr_ve_task);
	}

	if (curr_ve_task) {
		curr_ve_task->p_ve_core->curr_ve_task = NULL;
	}

	VEOS_TRACE("Exiting");
}

/**
 * @brief Unassign and assign task on core
 *
 * @param tsk Pointer to VE task struct
 * @param retry_assign true, when retry mechanism is added
 * 			to assign task on core (when get register
 * 			request is received), else false
 *
 * @return true when unassign and assign is successful else false
 */
bool psm_unassign_assign_task(struct ve_task_struct *tsk, bool retry_assign)
{
	bool ret = false;
	int retval = -1;
	int retry = 0;
	struct timespec retry_delay = {};

	VEOS_TRACE("Entering");

	/* check whether psm_unassign_assign_task() has already been invoked prior
	 * to this point during handling of VLFA wait while halting the core.
	 * if yes (for VE3 arch only) then return*/
	if((*_veos_arch_ops->arch_psm_get_vlfa_wait)(tsk))
		return true;

	if (retry_assign)  {
		retry = ASSIGN_RETRY_CNT;	/* number of retries when EAGAIN */
		retry_delay.tv_sec = 0;		/* start delay, doubles every retry */
	        retry_delay.tv_nsec = ASSIGN_RETRY_DELAY;
	}

	/* Unassign task from core */
	ret = psm_unassign_task(tsk);
	if (ret == false) {
		/* In reference to #587
		 * As task is already unassiged from core
		 * before invocation of above psm_unassign_task() API,
		 * we will rely on scheduler to assign
		 * task on core.
		 * */
		VEOS_DEBUG("Not assigning task %d on core", tsk->pid);
		return ret;
	}

	/* Assign task on core */
	VEOS_DEBUG("Assigning task with pid: %d", tsk->pid);
	do {
		retval = vedl_assign_ve_task(VE_HANDLE(tsk->node_id),
				tsk->p_ve_core->phys_core_num, tsk->pid);
		if (retval == 0)
			break;
		if (EAGAIN == errno) {
			if (retry && retry_assign) {
				retry--;
				nanosleep(&retry_delay, NULL);
				retry_delay.tv_nsec *= 2;
				continue;
			}
			VEOS_ERROR("Assign failed even after %d retries, "
					"exception not served yet PID %d",
					ASSIGN_RETRY_CNT, tsk->pid);
			return false;
		}
		/* errno is other than EAGAIN then there is
		 * a bug/race in veos which is not handled
		 * */
		VEOS_ERROR("Failed (%s) to assign PID %d",
						strerror(errno), tsk->pid);
		veos_abort("Failed to assign task on core");
	} while(1);

	tsk->assign_task_flag = TSK_ASSIGN;
	VEOS_TRACE("Exiting");
	return true;
}

/**
* @brief Unassign task from VE core
* Function retries if unassign fails with EAGAIN errno.
*
* @param tsk Pointer to VE task struct
*
* @return false if task was already unassigned and
* true if task is unassigned now.
*/
bool psm_unassign_task(struct ve_task_struct *tsk)
{
	int ret = -1;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("Unassigning PID %d from VE Core",
			tsk->pid);

	if (tsk->assign_task_flag == TSK_UNASSIGN) {
		VEOS_DEBUG("PID already unassigned %d from VE Core",
				tsk->pid);
		return false;
	}

	do {
		ret = vedl_unassign_ve_task(VE_HANDLE(0),
				tsk->pid);
		if (ret < 0) {
			if (EAGAIN == errno) {
				VEOS_DEBUG("Delayed interrupt pending %d",
						tsk->pid);
				continue;
			} else {
				/* errno is other than EAGAIN then there is
				 * a bug/race in veos which is not handled
				 * */
				veos_abort("Failed (%s) to unassign PID %d",
						strerror(errno),
						tsk->pid);
			}
		} else {
			break;
		}
	} while(1);
	tsk->assign_task_flag = TSK_UNASSIGN;

	VEOS_TRACE("Exiting");
	return true;
}

/**
* @brief unassign task from core and take migration decision if needed
*
* This function is invoked when a VE task is undergoing deletion.
* Function removes the task from VE core if the task is currently
* scheduled on core.
* Function processes migration of DMA descriptor table
*
* @param del_task_struct Pointer to ve task struct
*/
void psm_unassign_migrate_task(struct ve_task_struct *del_task_struct)
{
	int node_id = del_task_struct->node_id;
	int core_id = del_task_struct->core_id;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");

	/* Acquire thread group lock */
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->
			thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	psm_halt_ve_core(node_id, core_id, &regdata, false, true);

	/* Unassign task from core */
	psm_unassign_task(del_task_struct);

	/* Decrement thread sched count */
	if (del_task_struct->reg_dirty == true) {
		*(del_task_struct->thread_sched_count) -= 1;
		CLEAR_BIT(*(del_task_struct->thread_sched_bitmap),
				del_task_struct->core_id);
		VEOS_DEBUG("DECREMENT THREAD_SCHED_COUNT %d PID %d",
				*(del_task_struct->thread_sched_count),
				del_task_struct->pid);
	}
	(*_veos_arch_ops->arch_psm_process_dma_resource)(del_task_struct);

	/* release thread group lock */
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->
			thread_group_mm_lock, UNLOCK,
			"Failed to release thread group lock");

	VE_CORE(node_id, core_id)->curr_ve_task = NULL;
	VEOS_TRACE("Exiting");
}

/**
* @brief Marks the CRD as "dirty" for all the threads of thread group
*
* Function marks the CRD as "dirty" i.e. the local copy of CRD register
* for VE process as updated. Scheduler when scheduling any thread of the VE
* process on core checks if CRD is marked as dirty, if yes it will updates
* core's ATB register with local copy of CRD register placed in VE task struct
*
* @param[in] task Pointer to VE process task struct.
*/
static void update_crd_dirty(struct ve_task_struct *task)
{
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VEOS_TRACE("Entering");

	/* Mark CRD as dirty for all threads of thread group */
	VEOS_DEBUG("Marking CR DIRTY for thread group PID : %d",
			task->pid);
	group_leader = task->group_leader;
	group_leader->crd_dirty = true;

	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
				tmp->crd_dirty = true;
		}
	}
	VEOS_TRACE("Exiting");
}
/**
* @brief Set bitmap of the ATB directories as "dirty" for all the threads of
* thread group
*
* Function set bitmap of the ATB directories  as "dirty" i.e. the local copy of
* ATB register for VE process as updated. Scheduler when scheduling any
* thread of the VE process on core checks if the bit of ATB directory is set
* as dirty, if yes it will updates core's ATB register with local copy of ATB
* register placed in VE task struct
*
* @param[in] task Pointer to VE process task struct.
* @param[in] bmap bitmap of dirty directories of ATB.
*/
static void update_atb_dirty(struct ve_task_struct *task, uint64_t bmap)
{
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VEOS_TRACE("Entering");

	/* Mark ATB as dirty for all threads of thread group */
	VEOS_DEBUG("Marking ATB DIRTY for thread group PID : %d, bmap %lu",
			task->pid, bmap);
	group_leader = task->group_leader;
	group_leader->atb_dirty |= bmap;

	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
			tmp->atb_dirty |= bmap;
		}
	}
	VEOS_TRACE("Exiting");
}

/**
* @brief Frees the udma context
*
* @param[in] tsk Pointer to VE task
*
* @return 0 on success
*/
int psm_free_udma_context_region(struct ve_task_struct *tsk)
{
	VEOS_TRACE("Entering");

	(*_veos_arch_ops->arch_psm_free_udma_context)(tsk->udma_context);
	tsk->udma_context = NULL;

	VEOS_TRACE("Exiting");

	return 0;
}

/**
 * @brief Allocates user DMA descriptor and control register context
 * region in ve_task_struct structure.
 *
 * @param[in] ve_task Pointer of VE process leaders ve_task_structure
 *
 * @return 0 on success, -1 or -errno on failure.
 */
int psm_alloc_udma_context_region(struct ve_task_struct *ve_task)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	/* Allocate memory for udma context */
	ve_task->udma_context = (*_veos_arch_ops->
					arch_psm_alloc_udma_context)();
	if (!(ve_task->udma_context)) {
		retval = -errno;
		VEOS_CRIT("Internal Memory allocation failed");
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Check and set the bit in core bitmap if some other thread of same
* thread group as of the current task is scheduling on other core
*
* Function traverse all the VE core and checks if some thread of same
* thread group as of current task is executing on core, if yes the its
* core is stopped.
*
* @param[in] core_set core bitmap
* @param[in] ve_task pointer to ve task struct
* @param[in] reg_type enum denoting register type ATB/DMAATB/CRD
*
* @return 0 on success, 1 on failure.
*/
bool psm_check_sched_jid_core(uint64_t *core_set,
		struct ve_task_struct *ve_task,
		regs_t reg_type, ve_reg_t *arr_exs)
{
	bool retval = false;
	int core_loop = 0;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		p_ve_core = VE_CORE(0, core_loop);
		/* Check scheduling status of bit set in thread_sched_bitmap */
		if (CHECK_BIT(*(ve_task->thread_sched_bitmap), core_loop)) {
			/* Halt the core */
			psm_halt_ve_core(0, core_loop, (arr_exs + core_loop), false, true);

			if (!(*(arr_exs + core_loop) & VE_EXCEPTION) || reg_type == _DMAATB) {
				if (psm_unassign_assign_task(p_ve_core->curr_ve_task,
							true)) {
					*core_set |= 1 << core_loop;
					/* Set core state to HALT so that it cannot be
					 * started until syncing finish */
					VEOS_DEBUG("Thread of same thread group at core %d "
						"Setting core state to HALT", core_loop);
					SET_CORE_STATE(p_ve_core->ve_core_state,
							HALT);
					retval = true;
				} else {
					VEOS_DEBUG("Assigning task %d failed",
							p_ve_core->curr_ve_task->pid);
				}
			} else {
				VEOS_DEBUG("Exception has occurred on core");
			}
		}
	}
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Checks if core's user DMA descriptor is in use
*
* @param[in] ve_task Pointer to VE task struct
*
* @return true if core DMA descriptor in use else false is returned
*/
bool psm_check_udma_desc(struct ve_task_struct *ve_task)
{
	bool retval = false;
	VEOS_TRACE("Entering");
	/* Compare the "core_dma_desc" field of thread group
	 * leader with core id */
	if (*(ve_task->core_dma_desc) == ve_task->core_id) {
		VEOS_DEBUG("Core DMA descriptor in use");
		retval = true;
	} else {
		VEOS_DEBUG("Core DMA descriptor not in use");
	}
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Change the core state to HALT by setting EXS register as EXS_STOP.
 *
 * Function waits for 30 second for EXS_STOP bit to get updated in core
 * register. If EXS_STOP bit is not updated in 30 seconds then veos_abort
 * is invoked.
 * Function also calculate/update process time slice, core busy time.
 * Function checks if VE process time slice is exhausted (when core
 * halt request is made upon scheduler timer has expired).
 *
 * @param[in] node_id VE Node Id of core to Stop
 * @param[in] core_id VE Core Id of core to Stop
 * @param[Out] regdata to get user register
 * @param[in] scheduler_expiry Halt core request is made from
 * schedule timer expiry or not
 *
 * @return 0 on Success and aborts if core does not halts
 * -1 is returned when core halt request is made by schedule
 *  timer expiry  and current task's time slice is not exhausted.
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
int psm_halt_ve_core(int node_id, int core_id, ve_reg_t *regdata,
		bool scheduler_expiry, bool should_vlfa_wait)
{
	int retval = -1;
	struct timeval now = {0};
	struct ve_core_struct *p_ve_core = NULL;
	time_t endwait = 0;
	int wait_time = HALT_CORE_MAX_TIME;
	struct ve_task_struct *curr_ve_task = NULL;

	VEOS_TRACE("Entering");

	p_ve_core = VE_CORE(node_id, core_id);
	curr_ve_task = p_ve_core->curr_ve_task;

	/*
	 * When halt core request is made while initialising core's,
	 * simply halt the core.
	 * */
	if (!p_ve_core->core_stime.tv_sec &&
			!p_ve_core->core_stime.tv_usec)
		goto halt_core;

	/* If core state is already stopped, just fetch
	 * content of EXS register
	 * */
	if (p_ve_core->ve_core_state != EXECUTING) {
		if ((*_veos_arch_ops->arch_psm_get_core_execution_status)(
					core_id, regdata)) {
			VEOS_ERROR("Getting user registers failed "
					"on core %d",
					core_id);
			goto hndl_return;
		}
		VEOS_DEBUG("Core: %d already stopped EXS: %lx", core_id, *regdata);
		retval = 0;
		goto hndl_return1;
	}

	/* Update VE core busy time and VE process execution time and  */
	gettimeofday(&now, NULL);
	if (true == p_ve_core->core_running) {
		p_ve_core->busy_time +=
			timeval_diff(now, p_ve_core->core_stime);
		p_ve_core->core_running = false;
		if (curr_ve_task) {
			curr_ve_task->time_slice -=
				timeval_diff(now, curr_ve_task->stime);
			psm_calc_task_exec_time(curr_ve_task);
		}
	}

	/* a. If core halt request is due to schedule timer expiry,
	 * then verify whether time slice of current process
	 * is exhausted or not
	 * b. Also if current task state is set to WAIT, then do not
	 * skip scheduling
	 * */
	if (scheduler_expiry) {
		if (curr_ve_task && (curr_ve_task->time_slice >= 0) &&
				(curr_ve_task->ve_task_state == RUNNING)) {
			if (curr_ve_task->ve_sched_state == VE_THREAD_STOPPING) {
				VEOS_DEBUG("pid %d change ve_sched_state from STOPPING"
					 " to STOPPED", curr_ve_task->pid);
				curr_ve_task->ve_sched_state = VE_THREAD_STOPPED;
			} else {
				VEOS_DEBUG("Time slice remaining %ld",
						curr_ve_task->time_slice);
				p_ve_core->core_running = true;
				gettimeofday(&(curr_ve_task->stime), NULL);
				gettimeofday(&(p_ve_core->core_stime), NULL);
				return -1;
			}
		} else {
			VEOS_DEBUG("Process time slice exhausted"
					" or task state is WAIT");
		}
	}

	/* Set the EXS_STOP bit in EXS register as
	 * all other bits are protected by VE HW
	 * */
halt_core:
	retval = (*_veos_arch_ops->arch_psm_request_core_to_stop)(core_id);
	if (0 > retval) {
		VEOS_ERROR("Setting user register failed"
				" for core %d", core_id);
		goto hndl_return;
	}

	/* Wait for EXS_STOP to get updated in core register.
	 * We wait for 30 seconds
	 * */
	endwait = time(NULL) + wait_time;
	do {
		retval = (*_veos_arch_ops->arch_psm_get_core_execution_status)(
						core_id, regdata);
		if (0 > retval) {
			VEOS_ERROR("Getting user registers failed"
					" for core %d.", core_id);
			goto hndl_return;
		}

		if ((*_veos_arch_ops->arch_psm_check_core_status_is_stopped)(
					*regdata))
			break;

		if (time(NULL) >= endwait)
			break;
	} while (1);

	/* Invoke veos_abort */
	if (!(*_veos_arch_ops->arch_psm_check_core_status_is_stopped)(
					*regdata)) {
		/* Core did not stop, abort veos... */
		VEOS_DEBUG("Core %d did not stop", core_id);
		goto hndl_return;
	}

	/* Set VE core state to STOP */
	SET_CORE_STATE(p_ve_core->ve_core_state, STOPPED);

	(*_veos_arch_ops->arch_psm_wait_for_delayed_VLFA_exception)(
						should_vlfa_wait, curr_ve_task);

	retval = 0;
	VEOS_DEBUG("Core: %d EXS: %lx stopped", core_id, *regdata);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
hndl_return:
	veos_abort("Stopping core %d was not successful",
			core_id);
}

/**
 * @brief Change the core state to EXECUTING
 *
 * Function sets the EXS_RUN bit of EXS register.
 * If VE process is getting traced then EXS_HW_DEBUG_BIT
 * is also set.
 *
 * Function waits for 1sec for the bits to get updated.
 * If EXS is not updated till in 1 second then veos_abort
 * is invoked.
 *
 * @param[in] node_id VE Node Id of core to Start
 * @param[in] core_id VE Core Id of core to Start
 *
 * @return 0 on Success, -1 on failure.
 */
int psm_start_ve_core(int node_id, int core_id)
{
	int retval;
	struct ve_core_struct *p_ve_core = NULL;
	p_ve_core = VE_CORE(node_id, core_id);
	time_t endwait = 0;
	int wait_time = START_CORE_MAX_TIME;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("Initiated Syncing Operation");
	veos_sync_w_bar2();

	VEOS_DEBUG("Setting EXS_RUN bit");

	retval = (*_veos_arch_ops->arch_psm_request_core_to_start)(core_id);
	if (0 > retval) {
		VEOS_ERROR("Setting user registers failed for core %d",
				core_id);
		goto hndl_return;
	}

	endwait = time(NULL) + wait_time;
	do {
		retval = (*_veos_arch_ops->arch_psm_get_core_execution_status)(
						core_id, &regdata);
		if (0 > retval) {
			VEOS_ERROR("Getting user registers failed"
					" for core %d.", core_id);
			goto hndl_return;
		}
		if ((*_veos_arch_ops->arch_psm_check_core_status_is_running)(
						regdata))
			break;
		if (time(NULL) >= endwait)
			break;
	} while (1);

	if (!(*_veos_arch_ops->arch_psm_check_core_status_is_running)(
				regdata)) {
		/* Core did not start, abort veos... */
		VEOS_ERROR("Core %d did not start",
				core_id);
		goto hndl_return;
	}

	/* Set core state to EXECUTING */
	SET_CORE_STATE(p_ve_core->ve_core_state, EXECUTING);

	p_ve_core->core_running = true;
	gettimeofday(&(p_ve_core->core_stime), NULL);
	gettimeofday(&(p_ve_core->curr_ve_task->stime), NULL);

	(*_veos_arch_ops->arch_psm_clear_vlfa_wait)(p_ve_core->curr_ve_task);
	retval = 0;
	VEOS_DEBUG("Core: %d EXS: %lx", core_id, regdata);
	VEOS_TRACE("Exiting");
	return retval;

hndl_return:
	veos_abort("Starting core %d was not successful", core_id);
}

/**
* @brief Calculate VE task execution time on core.
*
* @param curr_ve_tas Pointer to ve_task _struct
*
* @return 0 on success and -1 when execution time
* exceeds hard limit for RLIMIT_CPU.
*/
int psm_calc_task_exec_time(struct ve_task_struct *curr_ve_task)
{
	struct timeval now_time = {0};
	int retval = 0;
	double exec_time_ticks = 0, size = 0;
        uint64_t uss = 0, pss = 0, exec_time = 0;
	uint64_t total_time = 0;
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL, *group_leader = NULL;

	VEOS_TRACE("Entering");
	gettimeofday(&now_time, NULL);
	exec_time = timeval_diff(now_time, (curr_ve_task->stime));
	curr_ve_task->exec_time += exec_time;
	group_leader = curr_ve_task->group_leader;

	VEOS_DEBUG("Core %d PID %d Exec Time %ld",
			curr_ve_task->p_ve_core->core_num,
			curr_ve_task->pid, curr_ve_task->exec_time);

	/*1679 ac_total_mem in each context switch*/
	uss = get_uss(curr_ve_task->p_ve_mm, NULL);
	pss = get_pss(curr_ve_task->p_ve_mm, NULL);
	exec_time_ticks = (exec_time) / ((double)(USECOND / AHZ));
	size = ((uss + pss) / (double)1024) * exec_time_ticks;
	update_accounting_data(curr_ve_task, ACCT_TOTAL_MEM, size);

	/* Check the RLIMIT_CPU resource limit of current
	 * VE task.
	 *
	 * If limit exceeds the soft limit then SIGXCPU signal
	 * is send to VE process, if exceeds the hard limit
	 * then SIGKILL is send.
	 */
	total_time = group_leader->exec_time + group_leader->sighand->utime;
	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
				VEOS_DEBUG("Thread with PID %d execution time %lu",
						tmp->pid, tmp->exec_time);
				total_time += tmp->exec_time;
		}
	}
	if ((total_time/(double)MICRO_SECONDS) >
			curr_ve_task->sighand->rlim[RLIMIT_CPU]
			.rlim_max) {
		VEOS_INFO("CPU Hard limit exceeded, "
				"Sending Signal SIGKILL to pid %d",
				curr_ve_task->pid);
		kill(curr_ve_task->pid, SIGKILL);
		retval = -1;
		goto ret;
	}
	if (!curr_ve_task->cpu_lim_exceed) {
		if ((total_time/(double)MICRO_SECONDS) >
				curr_ve_task->sighand->rlim[RLIMIT_CPU]
				.rlim_cur) {
			VEOS_INFO("CPU Soft limit exceeded, "
					"Sending Signal SIGXCPU to PID %d",
					curr_ve_task->pid);
			VEOS_DEBUG("CPU Soft limit exceeded, "
					"Sending Signal SIGXCPU to PID %d"
					" rlim_cur :-> %lu"
					" exec_time :-> %lu",
					curr_ve_task->pid,
					curr_ve_task->sighand->
					rlim[RLIMIT_CPU].rlim_cur,
					curr_ve_task->exec_time);
			kill(curr_ve_task->pid, SIGXCPU);
			curr_ve_task->cpu_lim_exceed = true;
		}
	}
ret:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Save current task user context
*
* Function saves the current task user context from core and maintains its
* software copy. Function also checks whether Scalar registers or
* PSW/PMMR/PMCR/PMC registers are updated while task was executing on core.
*
* @param curr_ve_task Pointer to VE task struct
*
* @internal
* @note Invoked by other modules i.e. PTRACE
*/
void psm_save_current_user_context(struct ve_task_struct *curr_ve_task)
{
	ve_reg_t sr_tmp[64] = {0};
	ve_reg_t pmr_tmp[64] = {0};
	int core_id = -1;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	ve_dma_status_t dmast = 0;
	pid_t pid = getpid();

	core_id = curr_ve_task->core_id;
	p_ve_node = VE_NODE(0);
	p_ve_core = VE_CORE(0, core_id);

	VEOS_TRACE("Entering");
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock), LOCK,
		"Failed to acquire task lock");

	/* No need to fetch context from VE core
	 * - If task is getting scheduled after sigreturn() request
	 * - If user registers are modified by PTRACE request
	 * */
	if (curr_ve_task->usr_reg_dirty) {
		pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
				UNLOCK,
				"Failed to release task lock");
		VEOS_DEBUG("usr_reg_dirty is true for %d", curr_ve_task->pid);
		goto success;
	}

	/* store SR registers */
	if (curr_ve_task->sr_context_bitmap)
		psm_st_rst_context(curr_ve_task, sr_tmp, NULL, true);

	/* store PSW PMMR PMCR PMC registers */
	if (curr_ve_task->pmr_context_bitmap)
		psm_st_rst_context(curr_ve_task, NULL, pmr_tmp, true);

	/* Copy context from hardware registers
	 * to software for curr_ve_task */
	dmast = (*_veos_arch_ops->arch_psm_save_context_from_core_reg)(
			p_ve_node->dh, p_ve_core->phys_core_num, pid,
			curr_ve_task->p_ve_thread->arch_user_regs);
	if (dmast != VE_DMA_STATUS_OK) {
		pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
			UNLOCK,
			"Failed to release task lock");
		pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
				thread_group_mm_lock, UNLOCK,
			"Failed to release thread group lock");
		VEOS_ERROR("Failed to get user registers "
				" for PID %d", curr_ve_task->pid);
		veos_abort("Getting user context failed");
	}
	if ((*_veos_arch_ops->arch_psm_get_core_execution_status)(
		p_ve_core->core_num, &curr_ve_task->p_ve_thread->EXS)) {
		pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
			UNLOCK,
			"Failed to release task lock");
		pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
				thread_group_mm_lock, UNLOCK,
			"Failed to release thread group lock");
		VEOS_ERROR("Failed to get user registers "
				" for PID %d", curr_ve_task->pid);
		veos_abort("Getting EXS failed");
	}

	VEOS_DEBUG("Getting VE registers done for PID %d",
			curr_ve_task->pid);

	/* restore SR register context */
	if (curr_ve_task->sr_context_bitmap)
		psm_st_rst_context(curr_ve_task, sr_tmp, NULL, false);

	/* restore PSW PMMR PMCR PMC registers context */
	if (curr_ve_task->pmr_context_bitmap)
		psm_st_rst_context(curr_ve_task, NULL, pmr_tmp, false);

#if 0
	VEOS_DEBUG("Current PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0 : %lx SR1 : %lx SR2 : %lx EXS: %lx",
			curr_ve_task->pid,
			curr_ve_task->p_ve_thread->user_regs.IC,
			curr_ve_task->p_ve_thread->user_regs.SR[10],
			curr_ve_task->p_ve_thread->user_regs.SR[11],
			curr_ve_task->p_ve_thread->user_regs.SR[12],
			curr_ve_task->p_ve_thread->user_regs.SR[00],
			curr_ve_task->p_ve_thread->user_regs.SR[01],
			curr_ve_task->p_ve_thread->user_regs.SR[02],
			curr_ve_task->p_ve_thread->EXS);
#else
	VEOS_DEBUG("Current PID : %d IC: %lx EXS: %lx", curr_ve_task->pid,
		(*_veos_arch_ops->
			arch_psm_get_program_counter_from_thread_struct)(
				curr_ve_task->p_ve_thread->arch_user_regs),
				curr_ve_task->p_ve_thread->EXS);
#endif
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock), UNLOCK,
		"Failed to release task lock");
	size_t ctx_size = (*_veos_arch_ops->arch_psm_get_context_size)();
	update_accounting_data(curr_ve_task, ACCT_TRANSDATA,
			ctx_size / (double)1024);
success:
	VEOS_TRACE("Exiting");
}

/**
* @brief Find the next eligible task which can be scheduled
* by traversing the core list
*
* @param p_ve_core Pointer to core struct
*
* @return Pointer to schedulable task on success else
* NULL is returned,
*/
struct ve_task_struct* psm_find_next_task_to_schedule(
		struct ve_core_struct *p_ve_core)
{
	struct ve_task_struct *first_task = NULL;
	struct ve_task_struct *task_to_return = NULL;
	struct ve_task_struct *curr_ve_task = NULL;
	struct ve_task_struct *temp = NULL;
	struct ve_task_struct *temp_worker = NULL;
	int worker_found = 0;

	VEOS_TRACE("Entering");
	curr_ve_task = p_ve_core->curr_ve_task;

	/* Finds the most eligible VE process to be
	 * scheduled on this VE core
	 * */
	if (NULL != curr_ve_task) {
		first_task = curr_ve_task->next;
	} else {
		first_task = p_ve_core->ve_task_list;
	}

	temp = first_task;
	do {
		worker_found = 0;
		VEOS_DEBUG("Core: %d Check scheduling for PID: %d State: %d",
				p_ve_core->core_num,
				temp->pid,
				temp->ve_task_state);
		if((RUNNING == temp->ve_task_state)){
			temp_worker = temp->next;
			while(temp_worker != temp){
				if((RUNNING == temp_worker->ve_task_state) &&
					((temp_worker->ve_task_worker_belongs != NULL) ||
					(temp_worker->ve_task_worker_belongs_chg)) &&
					(temp_worker->tgid == temp->tgid)){
					VEOS_DEBUG("Core: %d skip for PID: %d",
							p_ve_core->core_num,temp->pid);
					worker_found = 1;
					break;
				}
				temp_worker = temp_worker->next;
			}

			if (temp->ve_sched_state == VE_THREAD_STOPPING) {
				VEOS_DEBUG("pid %d change ve_sched_state from STOPPING"
						" to STOPPED", temp->pid);
				temp->ve_sched_state = VE_THREAD_STOPPED;
			}

			if (worker_found == 0) {
				if (temp->ve_sched_state == VE_THREAD_STARTED) {
					VEOS_DEBUG("Ready task found with PID : %d",
						 temp->pid);
					task_to_return = temp;
					break;
				}
			}
		}
		VEOS_DEBUG("Skipping task with PID : %d",
				temp->pid);
		temp = temp->next;
	} while(temp != first_task);

	VEOS_TRACE("Exiting");
	return task_to_return;
}

/**
* @brief Restore CR pages, DMAATB, user DMA context for VE process
*
* Function allocates a CR page and restore it
* Function allocates a DMAATB dir entry.
* Function chooses the current core for DMA descriptor
* Function pdates DMAATB entries to map DMA descriptor table and
* control register of the chosen core
* Function restore DMA descriptor table and start DMA
*
* @param tts Pointer to VE process task struct which is getting
* scheduled on VE core
*
* @return -1 on failure and 0 on success
*/
int psm_restore_context_for_new_thread(struct ve_task_struct *tts)
{
	return (*_veos_arch_ops->arch_psm_restore_context_for_new_thread)(tts);
}

/**
 * @brief Stop User level DMA
 *
 * Function stops the operation status of DMA descriptor table H and E
 * depending on the argument "udma_desc_bmap" received
 *
 * @param[in] core_id VE core ID
 * @param[in] udma_desc_bmap Specifies DMA corresponding to which DMA
 * descriptor table needs to be stopped
 *
 * @return 0 on success and -1 on failure
 */
int psm_stop_udma(int core_id, uint8_t udma_desc_bmap)
{
	return (*_veos_arch_ops->arch_psm_stop_udma)(core_id, udma_desc_bmap);
}

/**
* @brief Start user level DMA
*
* Function sets the permission bit of DMA control register
*
* @param[in] core_id VE core ID
* @param[in] udma_desc_bmap Specifies DMA corresponding to which DMA
* descriptor table needs to be started
*
* @return 0 on success and -1 on failure.
*/
int psm_start_udma(int core_id, uint8_t udma_desc_bmap)
{
	return (*_veos_arch_ops->arch_psm_start_udma)(core_id, udma_desc_bmap);
}

/**
* @brief Saves core's user DMA descriptor tables and DMA control register
* corresponding to H and E.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
*
* @return 0 on success and -1 on failure.
*/
int psm_save_udma_context(struct ve_task_struct *ve_task, int core_id)
{
	int retval = -1;
	VEOS_TRACE("Entering");

	/* If the bit corresponding to DMA descriptor table E is set in the
	 * bitmap then save the udma context corresponding to DMA decriptor
	 * table E */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_E) {
		VEOS_DEBUG("Saving UDMA context corresponding to E");
		if ((*_veos_arch_ops->arch__psm_save_udma_context)(ve_task,
					core_id, VE_UDMA_EENTRY)) {
			VEOS_ERROR("Failed to Save UDMA context corresponding to E");
			goto save_udma_fail;
		}
	}

	/* If the bit corresponding to DMA descriptor table H is set in the
	 * bitmap then save the udma context corresponding to DMA decriptor
	 * table H */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("Saving UDMA context corresponding to H");
		if((*_veos_arch_ops->arch__psm_save_udma_context)(ve_task,
					core_id, VE_UDMA_HENTRY)) {
			VEOS_ERROR("Failed to Save UDMA context corresponding to H");
			goto save_udma_fail;
		}
	}

	VEOS_DEBUG("Successfully saved DMA descriptors/control reg");
	retval = 0;
save_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Restores user DMA descriptor tables and control register
* corresponding to H and E entry which are saved in ve_task_struct
* to specified core's register.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
*
* @return 0 on success and -1 on failure.
*/
int psm_restore_udma_context(struct ve_task_struct *ve_task, int core_id)
{
	int retval = -1;
	VEOS_TRACE("Entering");

	/* If the bit corresponding to DMA descriptor table E is set in the
	 * bitmap then restore the udma context corresponding to DMA decriptor
	 * table E */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_E) {
		VEOS_DEBUG("Restore UDMA context corresponding to E");
		if ((*_veos_arch_ops->arch__psm_restore_udma_context)(ve_task,
					core_id, VE_UDMA_EENTRY))
			goto restore_dma_fail;
	}

	/* If the bit corresponding to DMA descriptor table H is set in the
	 * bitmap then restore the udma context corresponding to DMA decriptor
	 * table H */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("Restore UDMA context corresponding to H");
		if((*_veos_arch_ops->arch__psm_restore_udma_context)(ve_task,
					core_id, VE_UDMA_HENTRY))
			goto restore_dma_fail;
	}

	VEOS_DEBUG("Successfully restored DMA descriptors/control registers");
	retval = 0;
restore_dma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Schedule the provided task on a VE core.
 *
 * @param[in,out] curr_ve_task Pointer to current VE task of the core
 * @param task_to_schedule Pointer to VE task to be scheduled on the core
 * @param scheduler_expiry Is scheduler expired
 * @param schedule_current Is current task to be schedule.
 *
 * @return 0 on success, -1 on failure.
 */
int schedule_task_on_ve_node_ve_core(struct ve_task_struct *curr_ve_task,
		struct ve_task_struct *task_to_schedule,
		bool scheduler_expiry,
		bool schedule_current)
{
	int node_id = -1;
	int core_id = -1;
	int ret = -1;
	struct ve_core_struct *p_ve_core = NULL;
	pid_t pid = getpid();

	VEOS_TRACE("Entering");
	if (!task_to_schedule)
		goto hndl_return;

	node_id = task_to_schedule->node_id;
	core_id = task_to_schedule->core_id;
	p_ve_core = VE_CORE(node_id, core_id);

	if (curr_ve_task && curr_ve_task != task_to_schedule) {
		/* Number of voluntary or involuntary context switches count
		 * of VE process/thread is updated based on the flag.
		 */
		if (true == scheduler_expiry)
			curr_ve_task->nivcsw++;
		else
			curr_ve_task->nvcsw++;

		/* Context switch count of core is incremented.
		*/
		VE_CORE(node_id, core_id)->nr_switches++;
	}

	/* Unassign the currently scheduled task from VE core */
	if (curr_ve_task && (curr_ve_task->assign_task_flag == TSK_ASSIGN)) {
		if ((curr_ve_task != task_to_schedule) ||
				task_to_schedule->sigpending) {
			psm_unassign_task(curr_ve_task);
		}
	}

	if ((curr_ve_task == NULL) || (curr_ve_task &&
				(curr_ve_task->group_leader !=
				 task_to_schedule->group_leader))) {
		if (curr_ve_task) {
			curr_ve_task->p_ve_core->curr_ve_task = NULL;

			/* Release thread group lock of curr_ve_task */
			VEOS_DEBUG("Release thread group lock PID %d",
					curr_ve_task->pid);
			pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
		}

		/* Acquire thread group lock of task_to_schedule */
		VEOS_DEBUG("Acquire thread group lock PID %d",
				task_to_schedule->pid);
		pthread_mutex_lock_unlock(&task_to_schedule->p_ve_mm->
				thread_group_mm_lock, LOCK,
				"Failed to acquire thread-group-mm-lock");
	}

	/* Assign the to_be_scheduled task on the VE core */
	if ((task_to_schedule->assign_task_flag == TSK_UNASSIGN)
			|| (task_to_schedule->sigpending)) {
		VEOS_DEBUG("Assigning task with pid: %d",
				task_to_schedule->pid);
		ret = vedl_assign_ve_task(VE_HANDLE(node_id),
				task_to_schedule->p_ve_core->phys_core_num,
				task_to_schedule->pid);
		if (ret) {
			if (EAGAIN == errno) {
				VEOS_ERROR("Assign failed exception"
						" not served PID %d",
						task_to_schedule->pid);
				psm_handle_assign_failure(curr_ve_task,
						task_to_schedule,
						schedule_current);
				goto hndl_return1;
			} else {
				/* errno is other than EAGAIN then there is
				 * a bug/race in veos which is not handled
				 * */
				VEOS_ERROR("Failed (%s) to assign PID %d",
						strerror(errno),
						task_to_schedule->pid);
				goto abort;
			}
		}
		/*
		* Do not invalidate ranch history if task to schedule is the
		* current task on core and branch history has been invalidated
		* already
		*/
		if ((curr_ve_task != task_to_schedule) &&
				task_to_schedule->invalidate_branch_history) {
			/* invalidate branch history as new task is assigned on core
			 */
			VEOS_DEBUG("Invoked veos_invalidate_branch_history"
					" for tsk(%d) on core(%d)",
					task_to_schedule->pid,
					task_to_schedule->core_id);
			ret = veos_invalidate_branch_history(
						task_to_schedule->core_id);
			if (ret) {
				VEOS_ERROR("Error while invalidating the"
							" branch history");
				veos_abort("Failed to invalidate the"
							" branch history");
			}

			task_to_schedule->invalidate_branch_history = false;
		}
		/* Update core->curr_ve_task */
		task_to_schedule->p_ve_core->curr_ve_task = task_to_schedule;
		task_to_schedule->assign_task_flag = TSK_ASSIGN;
	}

	if (1 == task_to_schedule->sigpending) {
		/* Signal is generated for this process.
		 * Set the signal handler context and save the
		 * current process context on stack
		 * */
		VEOS_DEBUG("Sigpending Flag set.");
		ret = psm_do_signal_ve(task_to_schedule);
		if (-1 == ret)
			goto hndl_return1;
		task_to_schedule->usr_reg_dirty = true;
	}

	/* Check if current task and next task belongs to
	 * different thread group
	 * a. Set Job ID Debug ID
	 * b. Set ATB dir and ATB image
	 * c. Restore UDMA and DMAATB context
	 * */
	if (!curr_ve_task || (curr_ve_task && (curr_ve_task->group_leader
					!= task_to_schedule->group_leader))) {
		/* Set Job ID Debug ID */
		VEOS_DEBUG("Set JIDR and DIDR on core %d",
				core_id);
		ret = (*_veos_arch_ops->arch_psm_set_jdid_from_task_to_core)
						(task_to_schedule);
		if (ret){
			VEOS_ERROR("Set JDID failed");
			goto abort;
		}

		/* Set ATB and ATB image */
		VEOS_DEBUG("Set ATB context");
		task_to_schedule->atb_dirty = 0xffffffff;
		/* psm_sync_hw_regs_atb() update ATB based on atb_dirty
		   in task_to_schedule if halt_all is false. So, bmap
		   set 0. */
		ret = psm_sync_hw_regs_atb(task_to_schedule,
				       false, 0, DIR_CNT, 0);
		if (0 > ret) {
			VEOS_ERROR("Set atb context failed");
			goto abort;
		}

		VEOS_DEBUG("THREAD_SCHED_COUNT %d PID %d",
				*(task_to_schedule->thread_sched_count),
				task_to_schedule->pid);

		/* Restore DMA DMAATB context on core if no other thread
		 * of next task is executing on core
		 * */
		if (*(task_to_schedule->core_dma_desc) == -1) {
			VEOS_DEBUG("Core DMA descriptor set to -1 for PID %d",
					task_to_schedule->pid);
			ret = psm_restore_context_for_new_thread(task_to_schedule);
			if (ret) {
				VEOS_ERROR("Setting DMA and DMAATB context failed");
				goto abort;
			}
		} else {
			VEOS_DEBUG("Some other threads of PID %d are executing."
				" No need to restore DMAATB/UDMA context",
				task_to_schedule->pid);
		}
		VEOS_DEBUG("Setting CRD context");
		veos_set_crd_context(task_to_schedule);
	}

	/* If current task on core and next task to schedule on core
	 * belong to same thread group and DMA descriptor is not mapped to any
	 * core then restore context
	 * */
	if ((-1 == *(task_to_schedule->core_dma_desc)) && (curr_ve_task &&
			(curr_ve_task->group_leader ==
			 task_to_schedule->group_leader))) {
		VEOS_DEBUG("Restore context for new thread");
		ret = psm_restore_context_for_new_thread(task_to_schedule);
		if (ret) {
			VEOS_ERROR("Setting DMA and DMAATB context failed");
			goto abort;
		}
	} else {
		VEOS_DEBUG("No need to restore context");
	}


	/* If local ATB is updated, then set ATB register of core */
	if (task_to_schedule->atb_dirty) {
		VEOS_DEBUG("Set ATB context");
		/* bmap that is 5th argument is ignored if halt_all
		   is false. So, this is set 0. */
		ret = psm_sync_hw_regs_atb(task_to_schedule,
				       false, 0, DIR_CNT, 0);
		if (-1 == ret) {
			VEOS_ERROR("Setting ATB context failed");
			goto abort;
		}
	}

	VEOS_DEBUG("Setting CRD context");
	veos_set_crd_context(task_to_schedule);

	(*_veos_arch_ops->arch_psm_clear_execution_status_on_thread_struct)(
				task_to_schedule->p_ve_thread);

	if (schedule_current && task_to_schedule->usr_reg_dirty == false) {
		/* Update the bit which are set in sr_context_bitmap
		 * and pmr_context_bitmap on core h/w regs
		 * */
		(*_veos_arch_ops->arch_psm_set_context_from_task_to_core)(
					task_to_schedule);
	} else {
		VEOS_DEBUG("Setting all user registers");
		/* Load the VE process context */
		if ((*_veos_arch_ops->
			arch_psm_restore_all_context_to_core_regs)(
				p_ve_core, pid,
				task_to_schedule->p_ve_thread) != 0) {
			VEOS_DEBUG("Setting all user registers failed");
			goto abort;
		} else {
			size_t ctx_size = (*_veos_arch_ops
						->arch_psm_get_context_size)();
			update_accounting_data(task_to_schedule, ACCT_TRANSDATA,
						ctx_size / (double)1024);
		}
		task_to_schedule->usr_reg_dirty = false;
	}
	VEOS_DEBUG("Scheduling PID : %d IC: %lx", task_to_schedule->pid,
		(*_veos_arch_ops->
			arch_psm_get_program_counter_from_thread_struct)(
				task_to_schedule->p_ve_thread->arch_user_regs));

	if (!schedule_current) {
		/* Set thread_sched_bitmap and increament thread_sched_count*/
		*(task_to_schedule->thread_sched_count) += 1;
		*(task_to_schedule->thread_sched_bitmap) |=
			(1 << task_to_schedule->core_id);
		*(task_to_schedule->thread_core_bitmap) |=
				(1 << task_to_schedule->core_id);

		VEOS_DEBUG("INCREMENTED THREAD_SCHED_COUNT"
				" %d and THREAD_CORE_BITMAP %ld for PID %d",
				*(task_to_schedule->thread_sched_count),
				*(task_to_schedule->thread_core_bitmap),
				task_to_schedule->pid);
	}

	/* this process will run on core then it's register will get
	 * updated.
	 */
	task_to_schedule->reg_dirty = true;
	task_to_schedule->invalidate_branch_history = true;
	task_to_schedule->sr_context_bitmap = 0;
	task_to_schedule->pmr_context_bitmap = 0;

	/* Reset the block_status flag for VE process
	 * to handle scenario "When monc is encountered on VE and
	 * schedule timer expires before the Block request is
	 * served by veos." when this VE process will be
	 * scheduled next time.
	 * */
	task_to_schedule->block_status = BLOCK_RECVD;

	if (!schedule_current) {
		/* Reset VE task time slice */
		VEOS_DEBUG("Reset VE task time slice");
		task_to_schedule->time_slice = VE_ATOMIC_GET(uint64_t,
							&veos_time_slice);
	} else if (task_to_schedule->time_slice <= 0) {
		/* When scheduling is invoked from non-blocking
		 * syscall then VE task time slice is reset only when
		 * it is exhausted
		 * */
		VEOS_DEBUG("Reset VE task time slice");
		task_to_schedule->time_slice = VE_ATOMIC_GET(uint64_t,
							&veos_time_slice);
	}
	VEOS_DEBUG("Remaining time slice %ld",
			task_to_schedule->time_slice);

	/* Start VE core */
	VEOS_DEBUG("Setting the start bit");
	psm_start_ve_core(node_id, core_id);

	pthread_mutex_lock_unlock(&task_to_schedule->p_ve_mm->
			thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	ret = 0;
	VEOS_TRACE("Exiting");
	return ret;
hndl_return1:
	/* RELEASE THREAD GROUP LOCK */
	pthread_mutex_lock_unlock(&task_to_schedule->p_ve_mm->
			thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
hndl_return:
	VEOS_TRACE("Exiting");
	return ret;
abort:
	/* RELEASE THREAD GROUP LOCK */
	pthread_mutex_lock_unlock(&task_to_schedule->p_ve_mm->
			thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	veos_abort("Scheduling of next task on core %d failed", core_id);
}

/**
* @brief Update CR directory for all the threads of current task thread
* group which are executing on VE core
*
* @param core_set Bitmap maintaining core where CR register is to be updated
* @param reg_sw Address of local copy of CRD register of VE process task struct
* @param dir_num Directory Number
* @param count Number of Directories which are to be updated
* @param tsk Pointer to VE task struct
*
* @return 0 on success and -1 on failure
*/
int veos_update_crd(uint64_t core_set, void *reg_sw, int dir_num,
		int count, struct ve_task_struct *tsk)
{
	int retval = -1;
	int core_loop = 0;
	struct ve_task_struct *curr_ve_task = NULL;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Directory num: %d Count: %d",
			dir_num, count);

	/* Update CRD on all the cores */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			VEOS_DEBUG("Update CRD for Core %d",
					core_loop);
			/* Update CRD */
			if (amm_set_crd((crd_t *)reg_sw, dir_num, core_loop,
						sizeof(ve_reg_t)*count)) {
				VEOS_ERROR("Setting CRD failed in AMM");
				retval = -1;
				goto veos_update_crd_fail;
			}
			VE_CORE(0, core_loop)->curr_ve_task->crd_dirty = false;
		}
	}

	/* Start all core */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			curr_ve_task = VE_CORE(0, core_loop)->curr_ve_task;
			if (curr_ve_task != tsk) {
				if (curr_ve_task && curr_ve_task->atb_dirty){
					VEOS_DEBUG("ATB is dirty, so the core "
						"won't start:%d,%d,0x%lx,%s",
						core_loop, curr_ve_task->pid,
						curr_ve_task->atb_dirty,__func__);
					SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state, STOPPED);
				}else{
					psm_start_ve_core(0, core_loop);
				}
			} else {
				SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state,
						STOPPED);
			}
		}
	}

	retval = 0;

veos_update_crd_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Update ATB directory for all the threads of current task thread
* group which are executing on VE core
*
* @param core_set Bitmap maintaining core where ATB register is to be updated
* @param reg_sw Address of local copy of ATB register of VE process task struct
* @param dir_num Start Directory number of ATB
* @param count Number of directories to be updated
* @param tsk Pointer to ve task struct
*
* @return -1 on success and 0 on failure.
*/
int veos_update_atb(uint64_t core_set, int16_t *dir_num,
		int count, struct ve_task_struct *tsk)
{
	int loop_cnt = 0;
	int retval = -1;
	int core_loop = 0;
	struct ve_task_struct *curr_ve_tsk = NULL;

	VEOS_TRACE("Entering");

	/* Update ATB on all the cores */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			VEOS_DEBUG("Update ATB for Core %d",
					core_loop);
			curr_ve_tsk = VE_CORE(0, core_loop)->curr_ve_task;
			for (loop_cnt = 0; loop_cnt < count; loop_cnt++) {
				VEOS_DEBUG("Directory num: %d", dir_num[loop_cnt]);
				if (amm_update_atb_dir(VE_HANDLE(0),
								core_loop,
								tsk,
								dir_num[loop_cnt])) {
					VEOS_ERROR("Updating ATB directory failed in driver");
					retval = -1;
					goto veos_update_atb_fail;
				}
				curr_ve_tsk->atb_dirty &= ~(1UL << dir_num[loop_cnt]);
			}
			if (curr_ve_tsk->invalidate_branch_history) {
				/* invalidate branch history here as task is
				 * assigned on core*/
				VEOS_DEBUG("Invoked veos invalidate"
					" branch history for tsk(%d) on core(%d)",
					curr_ve_tsk->pid, core_loop);
				retval = veos_invalidate_branch_history(
								core_loop);
				if (retval) {
					VEOS_ERROR("Error while invalidating"
							" the branch history");
					goto veos_update_atb_fail;
				}
				curr_ve_tsk->invalidate_branch_history = false;
			}
		}
	}

	/* Start all core */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			curr_ve_tsk = VE_CORE(0, core_loop)->curr_ve_task;
			if (curr_ve_tsk != tsk) {
				VEOS_DEBUG("Start core id : %d",
						core_loop);
				if (curr_ve_tsk && curr_ve_tsk->atb_dirty){
					VEOS_DEBUG("ATB is dirty, so the core "
						"won't start:%d,%d,0x%lx,%s",
						core_loop, curr_ve_tsk->pid,
						curr_ve_tsk->atb_dirty,__func__);
					SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state, STOPPED);
				}else{
					curr_ve_tsk->invalidate_branch_history = true;
					psm_start_ve_core(0, core_loop);
				}
			} else {
				SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state,
						STOPPED);
			}
		}
	}
	retval = 0;

veos_update_atb_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief  Update DMAATB for VE node
*
* Function stops udma of all the cores where threads in thread group
* of current task are executing.
* Function updates the DMAATB of the node
* Function then starts udma of all the cores where threads in thread group
* of current task are executing.
*
* @param core_set Bitmap maintaining core id's where UDMA is to be started/stopped
* @param reg_sw Address of local copy of DMAATB register
* @param dir_num Start Directory number of DMAATB
* @param count Number of directories to be updated
* @param ve_task Pointer to VE task struct
*
* @return Returns -1 on failure and 0 on success
*/
int veos_update_dmaatb(uint64_t core_set, veos_dmaatb_reg_t *reg_sw, int dir_num,
		int count, struct ve_task_struct *ve_task, ve_reg_t *arr_exs)
{
	int retval = -1;
	int ret;
	int loop_cnt = 0;
	int core_loop = 0;
	struct ve_task_struct *curr_ve_task = NULL;

	VEOS_TRACE("Entering");
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			/* Stop UDMA */
			if (*(ve_task->core_dma_desc) == core_loop)
				psm_stop_udma(core_loop,
						ve_task->p_ve_mm->udma_desc_bmap);
			VEOS_DEBUG("Update DMAATB for Core %d",
					core_loop);
			for (loop_cnt = dir_num; loop_cnt < dir_num + count ; loop_cnt++) {
				ret = (*_veos_arch_ops->
						arch_psm_update_dmaatb_dir)(
							VE_NODE_CNT_REG(0),
							reg_sw, loop_cnt);
				if (ret) {
					VEOS_ERROR("Update ATB directory at driver failed");
					VEOS_DEBUG("ret = %d, loop_cnt = %d, count = %d",
							ret, loop_cnt, count);
					retval = -1;
					goto veos_update_dmaatb_fail;
				}
			}
		}
	}

	/* Start all core */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			curr_ve_task = VE_CORE(0, core_loop)->curr_ve_task;
			/* Start UDMA */
			if (*(ve_task->core_dma_desc) == core_loop)
				psm_start_udma(core_loop,
						curr_ve_task->p_ve_mm->udma_desc_bmap);

			if (curr_ve_task && curr_ve_task->ve_task_state ==
					RUNNING &&
					!(*(arr_exs + core_loop) & VE_EXCEPTION)) {
				VEOS_DEBUG("Start core id : %d",
						core_loop);
				if (curr_ve_task->atb_dirty){
					VEOS_DEBUG("ATB is dirty, so the core "
						"won't start:%d,%d,0x%lx,%s",
					       core_loop, curr_ve_task->pid,
						curr_ve_task->atb_dirty,__func__);
					SET_CORE_STATE(VE_CORE(0, core_loop)
							->ve_core_state, STOPPED);
				}else{
					psm_start_ve_core(0, core_loop);
				}
			} else {
				VEOS_DEBUG("Not starting Core %d EXS : %lx",
						core_loop, *(arr_exs + core_loop));
				SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state,
						STOPPED);
			}
		}
	}
	retval = 0;
veos_update_dmaatb_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Sync the software image of register on VE core/node h/w
*
* Based upon the type of register(ATB/DMAATB/CRD), function will provide the
* synchronization (halting/restarting the core) while updating the software
* image in VE core/node
*
* @param ve_task Pointer to VE task structure
* @param reg_type enum denoting register type ATB/DMAATB/CRD
* @param halt_all Flag which denotes syncing will be done for thread group
*		or only thread
* @param dir_num Directory number
* @param count Number of directories that needs to be updated
*
* @return positive integer on success and -1 in failure.
*/
int psm_sync_hw_regs(struct ve_task_struct *ve_task,
		regs_t reg_type,
		bool halt_all,
		int dir_num,
		int count)
{
	uint64_t core_set = 0;
	int loop_cnt = 0;
	int retval = 0;
	ve_reg_t *exception_arr = NULL;
	struct ve_mm_struct *mm = ve_task->p_ve_mm;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Entering");

	VEOS_DEBUG("PID %d dir_num %d count %d reg_typ %d",
			ve_task->pid, dir_num, count, reg_type);

	exception_arr = malloc(VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));
	if (!exception_arr) {
		VEOS_CRIT("Internal Memory allocation failed");
		goto hndl_failure;
	}

	memset(exception_arr, 0, VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));
	switch(reg_type) {
	case _DMAATB:
		VEOS_DEBUG("Update DMAATB");

		if (halt_all) {

			if (psm_check_sched_jid_core(&core_set,
						ve_task, reg_type, exception_arr)) {
				/* Update DMAATB on all core in core set */
				retval = veos_update_dmaatb(core_set,
						vnode->dmaatb,
						dir_num, count, ve_task, exception_arr);
				if (-1 == retval) {
					VEOS_ERROR("Update DMAATB failed in VEOS");
					goto hndl_failure;
				}
			} else {
				VEOS_DEBUG("Task %d is scheduled out from core,"
						" so directly updating DMAATB",
						ve_task->pid);
				goto directly_update_dmaatb;
			}
		} else {
directly_update_dmaatb:
			/* Update DMAATB */
			for (loop_cnt = dir_num; loop_cnt < dir_num + count
					; loop_cnt++) {
				retval = (*_veos_arch_ops->
					arch_psm_update_dmaatb_dir)(
						VE_NODE_CNT_REG(0),
						vnode->dmaatb, loop_cnt);
				if (0 > retval) {
					VEOS_ERROR("Update DMAATB failed in driver");
						goto hndl_failure;
				}
			}
		}
		break;
	case _CRD:
		VEOS_DEBUG("Update CRD");
		if (halt_all) {
			/* Halt all the threads of thread group
			 * and update CRD */
			VEOS_DEBUG("Mark CRD DIRTY for thread group");
			update_crd_dirty(ve_task);
			if (psm_check_sched_jid_core(&core_set,
						ve_task, reg_type, exception_arr)) {
				VEOS_DEBUG("Core set %ld", core_set);
				VEOS_DEBUG("Syncing CRD");
				/* Update ATB on all core in core set */
				retval = veos_update_crd(core_set,
						mm->crd,
						dir_num, count,
						ve_task);
				if (-1 == retval) {
					VEOS_ERROR("Update CRD failed");
					goto hndl_failure;
				}
			}
		} else {
			/* Update CRD */
			retval = amm_set_crd(mm->crd, dir_num, ve_task->core_id,
					sizeof(ve_reg_t) * count);
			if (-1 == retval) {
				VEOS_ERROR("Setting CRD failed");
				goto hndl_failure;
			}
			ve_task->crd_dirty = false;
		}
		break;
	default:
		VEOS_ERROR("Default case should never hit");
		retval = -1;
		break;
	}

	free(exception_arr);
	VEOS_TRACE("Exiting");
	return retval;

hndl_failure:
	free(exception_arr);
	veos_abort("Syncing HW registers failed");
}

/**
* @brief Sync the ATB software image of register on VE core/node h/w
*
* This function will provide the synchronization (halting/restarting
* the core) while updating the software image in VE core/node
*
* @param ve_task Pointer to VE task structure
* @param halt_all Flag which denotes syncing will be done for thread group
*		or only thread
* @param dir_num Directory number
* @param count Number of directories that needs to be updated
* @param bmap bitmap of dirty directories of ATB. If halt_all is false,
* 		this is ignored because this function will update based
* 		on ve_task->atb_dirty. This is used only if halt_all is true.
*
* @return positive integer on success and -1 in failure.
*/
int psm_sync_hw_regs_atb(struct ve_task_struct *ve_task,
		bool halt_all,
		int dir_num,
		int count,
		uint64_t bmap)
{
	uint64_t core_set = 0;
	int loop_cnt = 0;
	int retval = 0;
	ve_reg_t *exception_arr = NULL;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("PID %d dir_num %d count %d ATB",
			ve_task->pid, dir_num, count);

	exception_arr = malloc(VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));
	if (!exception_arr) {
		VEOS_CRIT("Internal Memory allocation failed");
		goto hndl_failure;
	}

	memset(exception_arr, 0, VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));
	VEOS_DEBUG("Update ATB");
	if (halt_all) {
		/* Halt all the threads of thread group
		 * and update ATB*/
		VEOS_DEBUG("ATB update for whole thread group");
		VEOS_DEBUG("Mark ATB DIRTY for thread group");
		update_atb_dirty(ve_task, bmap);

		/* Reset the core_set before getting the list of the core to be halted*/
		ve_task->core_set = 0;
		if (psm_check_sched_jid_core(&(ve_task->core_set),
					     ve_task, _ATB, exception_arr)) {
			VEOS_DEBUG("Core set %ld", core_set);
		}
		else
			retval = -1;
	} else {
		for (loop_cnt = dir_num; loop_cnt < dir_num + count
			     ; loop_cnt++) {
			if ( ve_task->atb_dirty & (1UL << loop_cnt) ) {
				retval = amm_update_atb_dir(VE_HANDLE(0),
							    ve_task->core_id,
							    ve_task,
							    loop_cnt);
				if (0 > retval) {
					VEOS_ERROR("Update ATB failed in driver");
					goto hndl_failure;
				}
				ve_task->atb_dirty &= ~(1UL << loop_cnt);
			}
		}
		if (ve_task->invalidate_branch_history) {
			/* invalidate branch history here as
			 * ATB register has changed
			 */
			VEOS_DEBUG("Invoked veos invalidate"
				   " branch_history for tsk(%d) on core(%d)",
				   ve_task->pid, ve_task->core_id);
			retval = veos_invalidate_branch_history(
								ve_task->core_id);
			if (retval) {
				VEOS_ERROR("Error while invalidating"
					   " the branch history");
				veos_abort("Failed to invalidate"
					   " the branch history");
			}

			ve_task->invalidate_branch_history = false;
		}
	}

	free(exception_arr);
	VEOS_TRACE("Exiting");
	return retval;

hndl_failure:
	free(exception_arr);
	veos_abort("Syncing HW registers failed");
}

/**
 * @brief Start VEOS scheduler timer and register the scheduler
 * timer handler function.
 *
 * @param[in] p_ve_node Pointer to node for which timer is created
 *
 * @return 0 on success, -1 on failure.
 */
int veos_scheduler_timer(struct ve_node_struct *p_ve_node)
{
	/* for timer create */
	clockid_t psm_sched_clock_id = -1;
	struct sigevent psm_sched_clock_sig_event = { {0} };

	/* for timer settime */
	struct itimerspec psm_new_timer_value = { {0} };
	struct itimerspec psm_old_timer_value = { {0} };
	int psm_interval_flags = 0;
	int psm_sched_retval = -1;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");
	if (!p_ve_node)
		goto hndl_return;

	VEOS_DEBUG("Starting PSM scheduler timer");
	/* Setting clock id */
	psm_sched_clock_id = CLOCK_MONOTONIC;

	/* Setting up sig event notify functions */
	psm_sched_clock_sig_event.sigev_notify = SIGEV_THREAD;
	psm_sched_clock_sig_event.sigev_notify_function
		= psm_sched_interval_handler;
	psm_sched_clock_sig_event.sigev_notify_attributes = NULL;

	psm_sched_retval = timer_create(psm_sched_clock_id,
			&psm_sched_clock_sig_event,
			&(p_ve_node->psm_sched_timer_id));
	if (-1 == psm_sched_retval) {
		VEOS_DEBUG("timer_create failed: %s",
				strerror(errno));
		goto hndl_return;
	}

	/* setting timer interval values */
	psm_new_timer_value.it_interval.tv_sec =
				veos_timer_interval / (1000 * 1000 * 1000);
	psm_new_timer_value.it_interval.tv_nsec =
				veos_timer_interval % (1000 * 1000 * 1000);

	/* setting timer initial expiration values */
	psm_new_timer_value.it_value.tv_sec =
				veos_timer_interval / (1000 * 1000 * 1000);
	psm_new_timer_value.it_value.tv_nsec =
				veos_timer_interval % (1000 * 1000 * 1000);

	/* read the core's initial power throttling count, if any */
	for (int core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
								core_loop++) {
		p_ve_core = VE_CORE(VE_NODE_ID(0), core_loop);
		psm_sched_retval
			= vedl_get_usr_reg(VE_CORE_USR_REG(0, core_loop),
					VE_USR_PMC14, &p_ve_core->previous_PMC14);
		if (psm_sched_retval != 0) {
			VEOS_DEBUG("Failed to get register PMC14, returned %d",
							psm_sched_retval);
			goto hndl_return;
		}
	}
	/* create timer */
	psm_sched_retval = timer_settime(p_ve_node->psm_sched_timer_id,
			psm_interval_flags, &psm_new_timer_value,
			&psm_old_timer_value);

	if (-1 == psm_sched_retval)
		VEOS_ERROR("timer_settime failed: %s",
				strerror(errno));
	else
		VEOS_DEBUG("Started PSM scheduler timer"
				"with interval SECS: %d N_SECS: %d",
				(int)psm_new_timer_value.it_interval.tv_sec,
				(int)psm_new_timer_value.it_interval.tv_nsec);
hndl_return:
	VEOS_TRACE("Exiting");
	return psm_sched_retval;
}

/**
 * @brief Stop the veos scheduler timer.
 *
 * @param[in] p_ve_node Pointer of Node for which scheduler timer is to remove
 *
 * @return 0 on success, -1 on failure.
 */
int veos_remove_timer(struct ve_node_struct *p_ve_node)
{
	int psm_sched_retval = -1;
	VEOS_TRACE("Entering");

	if (!p_ve_node)
		goto hndl_return;

	if (p_ve_node->psm_sched_timer_id) {
		psm_sched_retval = timer_delete(p_ve_node->psm_sched_timer_id);
		if (-1 == psm_sched_retval) {
			VEOS_ERROR("Failed to delete scheduler timer: %s",
					strerror(errno));
			goto hndl_return;
		}
		VEOS_DEBUG("Deleted Scheduler Timer for Node : %d",
				p_ve_node->node_num);
		psm_sched_retval = 0;
	}
hndl_return:
	VEOS_TRACE("Exiting");
	return psm_sched_retval;
}

/**
 * @brief Handles interrupt coming from interrupt generator for PSM scheduling.
 *
 * @detail Interrupt generator generates an interrupt after every "TIME_SLICE"
 * Function handles the interrupt and updates data structure and takes
 * rescheduling decision on all the VE cores.
 * This function also schedules the very next task in the VE core task list.
 *
 * @param[in] psm_sigval sigval coming from start timer function
 */
void psm_sched_interval_handler(union sigval psm_sigval)
{
	int ret = -1;
	int ovfl_ret = 0;
	int svpmc_ret = 0;
	int node_loop = 0, core_loop = 0;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;
	struct list_head get_task_list;
	struct task_entry *task_entry;
	struct task_entry *task_entry_n = NULL;

	static struct timeval now_tv = {0}, prev_check_tv = {0};
	static struct timeval prev_check_tv_pmc = {0};
	bool log_power_throttling = false;
	bool pmc_overflow_check = false;
	uint64_t diff_time;
	uint64_t diff_time_pmc;

	VEOS_TRACE("Entering");
	p_ve_node = VE_NODE(VE_NODE_ID(node_loop));

	if (NULL == p_ve_node) {
		VEOS_ERROR("BUG Node ID: %d struct is NULL",
				VE_NODE_ID(node_loop));
		goto hndl_return;
	}

	/* acquire the handling_request_lock used for IPC communication
	 * in order to make sure veos termination is not initialized while
	 * scheduling is in progress
	 **/
	ret = pthread_rwlock_tryrdlock(&handling_request_lock);
	if (ret) {
		VEOS_ERROR("Scheduler failed in acquiring "
				"try read lock");
		if (ret == EBUSY)
			goto terminate;
		else
			goto abort;
	}
	if (terminate_flag) {
		pthread_rwlock_lock_unlock(&handling_request_lock, UNLOCK,
				"Failed to release handling request lock");
		goto terminate;
	}
	/* acquiring semaphore for node */
	if (-1 == sem_trywait(&p_ve_node->node_sem)) {
		VEOS_DEBUG("Node %d semaphore try lock failed with errno: %d",
				p_ve_node->node_num, errno);
		goto release_handling_request_lock;
	}

	if (ONGOING == p_ve_node->scheduling_status) {
		VEOS_DEBUG("Scheduling ongoing for Node %d",
				VE_NODE_ID(node_loop));
		sem_post(&p_ve_node->node_sem);
		goto release_handling_request_lock;
	}

	VEOS_TRACE("Setting ongoing for Node %d", VE_NODE_ID(node_loop));
	SET_SCHED_STATE(p_ve_node->scheduling_status, ONGOING);

	/* check if logging interval time is over or not after first
	 * occurance of power throttling event */
	gettimeofday(&now_tv, NULL);
	if (first_power_throttling_occured == true) {
		diff_time  = timeval_diff(now_tv, prev_check_tv);
		diff_time  = diff_time / (1000 * 1000);
		if(diff_time >= power_throttle_log_interval) {
			log_power_throttling = true;
			prev_check_tv = now_tv;
		}
	} else
		prev_check_tv = now_tv;

	diff_time_pmc  = timeval_diff(now_tv, prev_check_tv_pmc);
	diff_time_pmc  = diff_time_pmc / (1000 * 1000);
	if(diff_time_pmc >= ONE_HOUR_INTERVAL) {
		pmc_overflow_check = true;
		prev_check_tv_pmc  = now_tv;
	}
	pthread_rwlock_lock_unlock(&(veos_scheduler_lock),RDLOCK,
			"Failed to acquire scheduler read lock");
	/* core loop */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
							 core_loop++) {
		p_ve_core = VE_CORE(VE_NODE_ID(node_loop), core_loop);
		if (NULL == p_ve_core) {
			VEOS_ERROR("BUG Core ID: %d struct is NULL",
							core_loop);
			continue;
		}
		(*_veos_arch_ops->arch_psm_log_pwr_throttle)
				(p_ve_core->core_num, log_power_throttling);
		psm_find_change_parent_of_worker(p_ve_core);
		/* Rebalance task */
		psm_rebalance_task_to_core(p_ve_core);
		psm_find_sched_new_task_on_core(p_ve_core,
						true, false);
		if(pmc_overflow_check == true) {
			INIT_LIST_HEAD(&get_task_list);

			VEOS_TRACE("PMC Checking Initiated");
			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
					"Failed to aquire ve core lock");
			if(p_ve_core->ve_task_list == NULL) {
				pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
					"Failed to release ve core lock");
				continue;
			}
			ve_task_list_head = p_ve_core->ve_task_list;
			temp = ve_task_list_head;
			do {
				if(temp->exec_time > 0) {
					task_entry = malloc(sizeof(struct task_entry));
					if(task_entry == NULL){
						VEOS_ERROR("failed to alloc for task entry");
					}else{
						if(!get_ve_task_struct(temp)){
							task_entry->task = temp;
							list_add(&task_entry->list, &get_task_list);
							svpmc_ret = (*_veos_arch_ops->arch_psm_save_performance_registers)
								(temp);
							if(svpmc_ret){
								VEOS_ERROR("Failed to save the PMC value in %s", __func__);
								syslog(LOG_INFO, "Failed to save the PMC value while checking at hourly intervals");
							}

							ovfl_ret = (*_veos_arch_ops->arch_psm_update_pmc_check_overflow)
								(temp);
							if(ovfl_ret){
								VEOS_ERROR("The PMC value has become abnormal in %s", __func__);
								syslog(LOG_INFO, "The PMC value has become abnormal while checking at hourly intervals");
							}
						}
					}
				}
				temp = temp->next;
			} while (temp != ve_task_list_head);
			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
					"Failed to release ve core lock");
			list_for_each_entry_safe(task_entry, task_entry_n, &get_task_list, list) {
				put_ve_task_struct(task_entry->task);
				list_del(&task_entry->list);
				free(task_entry);
			}
		}
	}
	pthread_rwlock_lock_unlock(&(veos_scheduler_lock),UNLOCK,
			"Failed to release scheduler read lock");

	/* Caluculate the system load on every scheduler timer
	 * expiry.
	 */
	calc_sys_load_per_sched_interval(p_ve_node);

	VEOS_TRACE("Scheduling Completed for Node %d",
			VE_NODE_ID(node_loop));
	SET_SCHED_STATE(p_ve_node->scheduling_status, COMPLETED);
	sem_post(&p_ve_node->node_sem);
release_handling_request_lock:
	pthread_rwlock_lock_unlock(&handling_request_lock,UNLOCK,
		"Failed to release handling request lock");
hndl_return:
	VEOS_TRACE("Exiting");
	return;
terminate:
	VEOS_DEBUG("Termination flag SET,"
			" VEOS SCHEDULER thread exiting");
	return;
abort:
	veos_abort("VEOS scheduler thread failed");
	return;
}

/**
* @brief Find a task which can be relocated to core which
* is idle to rebalance VE tasks among VE cores
*
* Function traverses core list of all the available core. If a core
* have two or more than two tasks in its core list, then a task apart
* from current task on core is selected which can be relocated on the
* idle core.
*
* @param ve_node_id VE node number
* @param ve_core_id VE core number for core having no task
*
* @return Pointer to VE task struct of task which is to be relocated,
* else NULL is returned.
*/
struct ve_task_struct *find_and_remove_task_to_rebalance(
	int ve_node_id, int ve_core_id)
{
	struct ve_task_struct *task_to_rebalance = NULL;
	struct ve_task_struct *loop_start = NULL;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;
	int core_loop, state, active_cnt;
	int is_rebalance = 1;
	int rebalance_flag = 0;
	struct ve_core_struct *p_another_core;
	struct ve_core_struct *p_given_core;

	struct list_head get_task_list;
	struct task_entry *task_entry;
	struct task_entry *task_entry_n = NULL;

	VEOS_TRACE("Entering");

	p_given_core = VE_CORE(ve_node_id, ve_core_id);
	pthread_rwlock_lock_unlock(&(p_given_core->ve_core_lock), RDLOCK,
					"Failed to acquire Core %d read lock",
					p_given_core->core_num);
	if (!psm_check_rebalance_condition(p_given_core, 1)) {
		is_rebalance = 0;
	}
	pthread_rwlock_lock_unlock(&(p_given_core->ve_core_lock), UNLOCK,
					"Failed to release core's write lock");
	if (!is_rebalance) {
		VEOS_DEBUG("Active VE Tasks exist on core %d"
			   " rebalance is canceled", p_given_core->core_num);
		return NULL;
	}


	INIT_LIST_HEAD(&get_task_list);

	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
			core_loop++) {
		if (core_loop == ve_core_id)
			continue;
		p_another_core = VE_CORE(ve_node_id, core_loop);
		if (NULL == p_another_core) {
			VEOS_ERROR("BUG Core ID: %d struct is NULL",
					core_loop);
			continue;
		}

		pthread_rwlock_lock_unlock(&(p_another_core->ve_core_lock),
				WRLOCK,
				"Failed to acquire Core %d read lock",
				p_another_core->core_num);

		if((NULL == p_another_core->ve_task_list) ||
				(p_another_core->numa_node
				 != p_given_core->numa_node)) {
			pthread_rwlock_lock_unlock(
					&(p_another_core->ve_core_lock),
					UNLOCK,
					"Failed to release core's write lock");
			continue;
		}

		if (p_another_core->curr_ve_task) {
			pthread_mutex_lock_unlock(&p_another_core->curr_ve_task->ve_task_lock,
					LOCK, "Failed to acquire ve_task_lock");
			if((p_another_core->curr_ve_task->ve_task_worker_belongs
					!= NULL) ||
				(p_another_core->curr_ve_task->ve_task_worker_belongs_chg)){
				pthread_mutex_lock_unlock(
					&p_another_core->curr_ve_task->ve_task_lock, UNLOCK,
					"Failed to release ve_task_lock");
				VEOS_DEBUG("Current task on core is worker, "
					"so skip [%d]", p_another_core->curr_ve_task->pid);
				pthread_rwlock_lock_unlock(
					&(p_another_core->ve_core_lock),
					UNLOCK,
					"Failed to release core's write lock");
				continue;  // if current is worker,skip
			}
			task_to_rebalance = p_another_core->curr_ve_task->next;
			loop_start = p_another_core->curr_ve_task;
			pthread_mutex_lock_unlock(&p_another_core->curr_ve_task->ve_task_lock,
					UNLOCK, "Failed to release ve_task_lock");
		} else {
			VEOS_DEBUG("Current task on core is [%p]",
						p_another_core->curr_ve_task);
			task_to_rebalance = p_another_core->ve_task_list->next;
			loop_start = p_another_core->ve_task_list;
		}

		active_cnt = 0;
		temp = loop_start;
		do {
			pthread_mutex_lock_unlock(&temp->ve_task_lock, LOCK,
					"Failed to acquire ve_task_lock");
			if (((temp->ve_task_state == WAIT) ||
					(temp->ve_task_state == RUNNING)) &&
						((temp->ve_task_worker_belongs == NULL) &&
						!(temp->ve_task_worker_belongs_chg))) {
				active_cnt++;
			}
			pthread_mutex_lock_unlock(&temp->ve_task_lock, UNLOCK,
					"Failed to release ve_task_lock");
		} while ((loop_start != temp->next) && (temp = temp->next));
		if (active_cnt < 2) {
			VEOS_DEBUG("Core[%d] has no excess tasks",
						p_another_core->core_num);
			task_to_rebalance = NULL;
			pthread_rwlock_lock_unlock(
					&(p_another_core->ve_core_lock),
					UNLOCK,
					"Failed to release core's write lock");
			continue;
		}

		ve_task_list_head = p_another_core->ve_task_list;

		/* Check wether curr_ve_task->next should be rabalanced. */
		while (task_to_rebalance != loop_start) {
			task_entry = malloc(sizeof(struct task_entry));
			if(task_entry == NULL){
				VEOS_ERROR("failed to alloc for task entry");
			}else{
				if (CPU_ISSET(ve_core_id,
					&(task_to_rebalance->cpus_allowed)) &&
					!(get_ve_task_struct(task_to_rebalance))) {
					pthread_mutex_lock_unlock(
						&task_to_rebalance->ve_task_lock, LOCK,
						"Failed to acquire ve_task_lock");
					state = task_to_rebalance->ve_task_state;
					if (((state == WAIT) ||
						(state == RUNNING)) &&
						((task_to_rebalance->ve_task_worker_belongs == NULL) &&
						!(task_to_rebalance->ve_task_worker_belongs_chg))) {
						rebalance_flag = 1;
						pthread_mutex_lock_unlock(
							&task_to_rebalance->ve_task_lock, UNLOCK,
							"Failed to release ve_task_lock");
						free(task_entry);
						break;
					} else {
						pthread_mutex_lock_unlock(
							&task_to_rebalance->ve_task_lock, UNLOCK,
							"Failed to release ve_task_lock");
						task_entry->task = task_to_rebalance;
						list_add(&task_entry->list, &get_task_list);
					}
				}else{
					free(task_entry);
				}
			}
			task_to_rebalance = task_to_rebalance->next;
		}
		if (rebalance_flag) {
			VEOS_DEBUG("Found task to rebalance %d",
					task_to_rebalance->pid);
			temp = task_to_rebalance;
			while (temp->next != task_to_rebalance)
				temp = temp->next;

			temp->next = task_to_rebalance->next;
			if (task_to_rebalance == ve_task_list_head) {
				p_another_core->ve_task_list =
						ve_task_list_head->next;
				VEOS_DEBUG("Now Head is %p",
						ve_task_list_head);
			}

			task_to_rebalance->next = NULL;

			if (RUNNING == task_to_rebalance->ve_task_state) {
				ve_atomic_dec(&(p_another_core->nr_active));
				VEOS_DEBUG("Core[%d] nr_active: [%d]",
					p_another_core->core_num,
					p_another_core->nr_active);
			}

			(*_veos_arch_ops->arch_decrement_num_ve_proc)();
			ve_atomic_dec(&(VE_NODE(ve_node_id)->
					numa[p_another_core->numa_node].num_ve_proc));
			ve_atomic_dec(&(p_another_core->num_ve_proc));

			pthread_rwlock_lock_unlock(
					&(p_another_core->ve_core_lock),
					UNLOCK,
					"Failed to release core's write lock");
			break;
		}
		task_to_rebalance = NULL;
		pthread_rwlock_lock_unlock(&(p_another_core->ve_core_lock),
				UNLOCK, "Failed to release core's write lock");
	}
	list_for_each_entry_safe(task_entry, task_entry_n, &get_task_list, list) {
		put_ve_task_struct(task_entry->task);
		list_del(&task_entry->list);
		free(task_entry);
	}
	/* if task_to_rebalance is not NULL, ve_task_lock is still acquired */
	VEOS_TRACE("Exiting");
	return task_to_rebalance;
}

/**
* @brief Inserts the "task_to_rebalance" in core list of core
* which is idle.
*
* @param ve_node_id VE node number
* @param ve_core_id VE core number of idle core
* @param task_to_rebalance Pointer to task struture which
* is to be relocated
*/
void insert_and_update_task_to_rebalance(
	int ve_node_id, int ve_core_id,
	struct ve_task_struct *task_to_rebalance)
{
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("Node %d Core %d Core Pointer %p", ve_node_id, ve_core_id,
			VE_CORE(ve_node_id, ve_core_id));

	/* take lock before Updating Core task list */
	pthread_rwlock_lock_unlock(
			&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
			WRLOCK, "Failed to acquire ve core write lock");

	/* Core data structure should not be NULL*/
	ve_task_list_head = VE_CORE(ve_node_id, ve_core_id)->ve_task_list;

	VEOS_DEBUG("ve_task_list_head : %p", ve_task_list_head);

	/* Create HEAD node*/
	if (NULL == ve_task_list_head) {
		VEOS_DEBUG(":%d:%d VE task list INIT", ve_node_id, ve_core_id);
		ve_task_list_head = task_to_rebalance;
		ve_task_list_head->next = ve_task_list_head;
	} else{
		/* Insert the node at the last */
		temp = ve_task_list_head->next;
		while (temp->next != ve_task_list_head)
			temp = temp->next;

		task_to_rebalance->next = temp->next;
		temp->next = task_to_rebalance;
	}

	/* Update HEAD of the Core list */
	VE_CORE(ve_node_id, ve_core_id)->ve_task_list = ve_task_list_head;
	/*Protected using relocate lock*/
	ve_atomic_inc(&(VE_CORE(ve_node_id, ve_core_id)->num_ve_proc));

	(*_veos_arch_ops->arch_increment_num_ve_proc)();
	ve_atomic_inc(&(VE_NODE(ve_node_id)->
		numa[task_to_rebalance->numa_node].num_ve_proc));
	if (RUNNING == task_to_rebalance->ve_task_state) {
		ve_atomic_inc(&(VE_CORE(ve_node_id, ve_core_id)->nr_active));
		VEOS_DEBUG("Core[%d] active task[%d]",
			task_to_rebalance->p_ve_core->core_num,
			task_to_rebalance->p_ve_core->nr_active);
	}


	/* update task fields */
	task_to_rebalance->node_id = ve_node_id;
	task_to_rebalance->core_id = ve_core_id;
	task_to_rebalance->p_ve_core = VE_CORE(ve_node_id, ve_core_id);

	/* relaese lock for Core task list */
	pthread_rwlock_lock_unlock(
			&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
			UNLOCK, "Failed to release ve core lock");

	VEOS_DEBUG("Now Head for Core %d is %p Inserted PID %d head IC %lx",
		ve_core_id, ve_task_list_head, task_to_rebalance->pid,
		(*_veos_arch_ops->
			arch_psm_get_program_counter_from_thread_struct)(
				task_to_rebalance->p_ve_thread->
					arch_user_regs));

	put_ve_task_struct(task_to_rebalance);
	VEOS_TRACE("Exiting");
}

/**
 * @brief Check that specified VE core meets rebalancing condition.
 *        "Rebalancing condition" is as follows.
 *        When VE core meets one of the following condition, Rebalancing will be done.
 *        - No VE task is on the VE core.
 *        - Only VE tasks by which state is STOP, ZOMBIE, or EXIT_DEAD
 *          are on the VE core.
 *
 * @param[in] p_ve_core Pointer to core structure of core which is idle.
 * @param[in] strictly Do check strictly if '1' is specified.
 *
 * @return If specified VE core meets rebalancing condition, return 1,
 *         if not, return 0.
 *
 * @note Caller should ensure that p_ve_core is not NULL.
 *       Caller should ensure that p_ve_core->ve_core_lock is acquired.
 */
int psm_check_rebalance_condition(struct ve_core_struct *p_ve_core,
				  int strictly)
{
	int do_rebalance = 0;
	struct ve_task_struct *curr_ve_task;

	VEOS_TRACE("Entering");

	/* No VE task is on the VE core. */
	if (NULL == p_ve_core->ve_task_list) {
		do_rebalance = 1;
		goto hdnl_return;
	}

	/* Only VE tasks by which state is STOP, ZOMBIE, or EXIT_DEAD
	 * are on the VE core */
	if (strictly != 1) {
		//Simple Check
		curr_ve_task = p_ve_core->curr_ve_task;
		if (NULL == curr_ve_task) {
			do_rebalance = 1;
			goto hdnl_return;
		}
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, LOCK,
					"Failed to acquire ve_task_lock");
		if ((curr_ve_task->ve_task_state == STOP) ||
		    (curr_ve_task->ve_task_state == ZOMBIE) ||
		    (curr_ve_task->ve_task_state == EXIT_DEAD))
			do_rebalance = 1;
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, UNLOCK,
					"Failed to release ve_task_lock");
	} else {
		//Strictly Check
		curr_ve_task = p_ve_core->ve_task_list;
		do_rebalance = 1;
		do {
			pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock,
					LOCK, "Failed to acquire ve_task_lock");
			if ((curr_ve_task->ve_task_state == WAIT) ||
			    (curr_ve_task->ve_task_state == RUNNING))
				do_rebalance = 0;
			pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock,
				UNLOCK, "Failed to release ve_task_lock");
		} while ((p_ve_core->ve_task_list != curr_ve_task->next) &&
					(do_rebalance == 1) &&
					(curr_ve_task = curr_ve_task->next));
	}

hdnl_return:
	VEOS_TRACE("Exiting(%d)", do_rebalance);
	return do_rebalance;
}

/**
* @brief Performs rebalancing on VE core if it does not have any
* task in its core list.
*
* @param p_ve_core Pointer to core structure of core which is idle.
*/
void psm_rebalance_task_to_core(struct ve_core_struct *p_ve_core)
{
	struct ve_task_struct *task_to_rebalance = NULL;

	VEOS_TRACE("Entering");

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), RDLOCK,
			"Failed to acquire Core %d read lock",
			p_ve_core->core_num);
	if (psm_check_rebalance_condition(p_ve_core, 0)) {
		pthread_rwlock_lock_unlock(
				&(p_ve_core->ve_core_lock), UNLOCK,
				"Failed to release Core %d read lock",
				p_ve_core->core_num);

		pthread_rwlock_lock_unlock(
				&(VE_NODE(0)->ve_relocate_lock), WRLOCK,
				"Failed to acquire ve_relocate_lock read lock");
		/* Find task which can be rebalanced on p_ve_core */
		task_to_rebalance = find_and_remove_task_to_rebalance(
				p_ve_core->node_num, p_ve_core->core_num);
		if (task_to_rebalance) {
			VEOS_DEBUG("Task to rebalance = %d",
					task_to_rebalance->pid);
			/* Insert "task_to_rebalance" in "p_ve_core"
			 * to rebalance */
			insert_and_update_task_to_rebalance(
					p_ve_core->node_num, p_ve_core->core_num,
					task_to_rebalance);
			pthread_mutex_lock_unlock(&task_to_rebalance->ve_task_lock,
					LOCK, "Failed to acquire task lock");
			if(task_to_rebalance->ve_task_have_worker == true){
				struct ve_task_struct *temp = NULL;
				temp = task_to_rebalance->ve_worker_thread;
				pthread_mutex_lock_unlock(&task_to_rebalance->ve_task_lock,
					UNLOCK, "Failed to release task lock");

				if (temp){
					if(p_ve_core->core_num != temp->core_id){
						pthread_rwlock_lock_unlock(
							&(VE_CORE(0, temp->core_id)->ve_core_lock),
							RDLOCK,
							"Failed to acquire Core %d read lock",
							temp->core_id);
						if(!get_ve_task_struct(temp)){
							pthread_rwlock_lock_unlock(
								&(VE_CORE(0, temp->core_id)->ve_core_lock),
								UNLOCK,
								"Failed to release Core %d read lock",
								temp->core_id);
							psm_relocate_ve_task(temp->node_id, temp->core_id,
								p_ve_core->node_num, p_ve_core->core_num, temp);
							put_ve_task_struct(temp);
						}else{
							pthread_rwlock_lock_unlock(
								&(VE_CORE(0, temp->core_id)->ve_core_lock),
								UNLOCK,
								"Failed to release Core %d read lock",
								temp->core_id);
						}
					}
				}
			}else{
				pthread_mutex_lock_unlock(&task_to_rebalance->ve_task_lock,
					UNLOCK, "Failed to release task lock");
			}
		}
		pthread_rwlock_lock_unlock(
				&(VE_NODE(0)->ve_relocate_lock), UNLOCK,
				"Failed to release ve_relocate_lock writelock");
	} else {
		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
				"Failed to release Core %d read lock",
				p_ve_core->core_num);
	}

	VEOS_TRACE("Exiting");
	return;
}

/**
* @brief Performs change parent of worker thread on VE core.
*
* @param src Pointer to task of worker thread
* @param dest Pointer to task of parent of worker thread
*/
void psm_change_parent_ve_worker(struct ve_task_struct *src,
	struct ve_task_struct *dest)
{
	VEOS_TRACE("Entering");

	VEOS_DEBUG("Change parent of a worker:%d to %d",src->pid,dest->pid);
	pthread_mutex_lock_unlock(&(dest->ve_task_lock),LOCK,
		"Failed to release task lock");
	dest->ve_task_have_worker = true;
	dest->ve_worker_thread = src;
	pthread_mutex_lock_unlock(&(dest->ve_task_lock),UNLOCK,
		"Failed to release task lock");

	pthread_mutex_lock_unlock(&(src->ve_task_lock),LOCK,
		"Failed to acquire task lock");
	src->ve_task_worker_belongs= dest;
	src->ve_task_worker_belongs_chg= false;
	pthread_mutex_lock_unlock(&(src->ve_task_lock), UNLOCK,
		"Failed to release task lock");

	if(src->core_id != dest->core_id){
		pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock),WRLOCK,
				"Failed to acquire ve_relocate_lock read lock");
		psm_relocate_ve_task( src->node_id,
			src->core_id, dest->node_id,
			dest->core_id, src);
		pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock),UNLOCK,
				"Failed to release ve_relocate_lock writelock");
	}
	VEOS_TRACE("Exiting");
}

/**
* @brief Performs change parent of worker thread on VE core.
*
* @param src Pointer to task of worker thread
* @param dest Pointer to task of parent of worker thread
*/
void psm_find_parent_of_ve_worker(struct ve_task_struct *mv_task)
{
	struct ve_task_struct *mv_to = NULL;
        struct list_head *p, *n;
        struct ve_task_struct *group_leader = NULL;

	VEOS_TRACE("Entering");
	group_leader = mv_task->group_leader;
	pthread_mutex_lock_unlock(
		&group_leader->p_ve_mm->thread_group_mm_lock,
		LOCK, "Failed to acquire thread-group-mm-lock");
	if (!thread_group_empty(mv_task)) {
		list_for_each_safe(p, n, &mv_task->thread_group) {
			mv_to = list_entry(p, struct ve_task_struct, thread_group);
			if (mv_to->pid == mv_task->pid) {
				continue;
			}
			pthread_mutex_lock_unlock(
				&(mv_to->ve_task_lock), LOCK,
				"Failed to acquire task lock");
			if(((mv_to->ve_task_worker_belongs == NULL) &&
				!(mv_to->ve_task_worker_belongs_chg)) &&
				(mv_to->ve_task_state != ZOMBIE)){
				pthread_mutex_lock_unlock(
					&(mv_to->ve_task_lock),UNLOCK,
					"Failed to release task lock");
				if(!(get_ve_task_struct(mv_to))){
					pthread_mutex_lock_unlock(
						&group_leader->p_ve_mm->
						thread_group_mm_lock,UNLOCK,
						"Failed to release thread-group-mm-lock");
					psm_change_parent_ve_worker(mv_task,mv_to);

					put_ve_task_struct(mv_to);
					goto hndl_return;
				}
				pthread_mutex_lock_unlock(
					&group_leader->p_ve_mm->
					thread_group_mm_lock,UNLOCK,
					"Failed to release thread-group-mm-lock");
				goto hndl_return;
			}
			pthread_mutex_lock_unlock(
				&(mv_to->ve_task_lock),
				UNLOCK, "Failed to release task lock");
		}
	}
	/* There is no thread which assigne to parent of worker
	 * thread. So Send SIGKILL to worker thread.
	 */
	pthread_mutex_lock_unlock(
		&group_leader->p_ve_mm->thread_group_mm_lock,
		UNLOCK, "Failed to release thread-group-mm-lock");
	VEOS_DEBUG("No thread assigne to parent of worker");
	syscall(SYS_tkill,mv_task->pid,SIGKILL);
hndl_return:

	VEOS_TRACE("Exiting");
	return;
}
/**
* @brief Performs change parent of worker thread on VE core.
*
* @param p_ve_core Pointer to core structure of core which is idle.
*/
void psm_find_change_parent_of_worker (struct ve_core_struct *p_ve_core)
{
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;

	VEOS_TRACE("Entering");

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), RDLOCK,
			"Failed to acquire Core %d read lock",
			p_ve_core->core_num);

	ve_task_list_head = VE_CORE(p_ve_core->node_num, p_ve_core->core_num)->ve_task_list;
	if(ve_task_list_head != NULL){
		temp = ve_task_list_head;
		do {
			pthread_mutex_lock_unlock( &(temp->ve_task_lock), LOCK,
				"Failed to acquire task lock");
			if((temp->ve_task_worker_belongs_chg == true)){
				pthread_mutex_lock_unlock(&(temp->ve_task_lock),
					UNLOCK, "Failed to release task lock");
				if(!(get_ve_task_struct(temp))){
					pthread_rwlock_lock_unlock(
						&(p_ve_core->ve_core_lock), UNLOCK,
						"Failed to release Core %d read lock",
						p_ve_core->core_num);
					psm_find_parent_of_ve_worker(temp);
					put_ve_task_struct(temp);
					goto hndl_return;
				}
			}else{
				pthread_mutex_lock_unlock(&(temp->ve_task_lock),
					UNLOCK, "Failed to release task lock");
			}
			temp = temp->next;
		} while (temp != ve_task_list_head);
	}
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to acquire Core %d read lock",
			p_ve_core->core_num);
hndl_return:

	VEOS_TRACE("Exiting");
	return;
}
/**
 * @brief Finds and schedules the most eligible task on core
 *
 * Function skips scheduling if no eligible task exist i.e.
 * no task exist whose task state is RUNNING
 *
 * Function skips context-switch if current task on core is
 * only eligible task and no exception has occured for it.
 *
 * Function skips context-switch if time slice of current task
 * on core has not exhausted
 *
 * Function also updates the VE core busy time and VE task execution time.
 *
 * Function find next eligible task to be scheduled on VE core,
 * save/migarte current VE task context, restore new VE task context
 * on core and start VE core.
 *
 * @param[in] p_ve_core Core on which new task is to be scheduled
 * @param[in] scheduler_expiry Is scheduler expired
 * @param[in] schedule_current Is current task to be schedule
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
void psm_find_sched_new_task_on_core(struct ve_core_struct *p_ve_core,
		bool scheduler_expiry,
		bool schedule_current)
{
	ve_reg_t regdata = 0;
	struct ve_task_struct *task_to_schedule = NULL;
	struct ve_task_struct *curr_ve_task = NULL;
	struct timeval now_time = {0};
	bool tsd_update = false;

	VEOS_TRACE("Entering");

	if (!p_ve_core)
		goto hndl_return1;

	if (!schedule_current) {
		/* acquiring semaphore for core*/
		if (-1 == sem_trywait(&p_ve_core->core_sem)) {
			VEOS_DEBUG("Core %d semaphore try lock"
					" failed with errno: %d",
					p_ve_core->core_num, errno);
			goto hndl_return1;
		}
	}
	/* Check if scheduling is already ongoing or core state is halt */
	if ((ONGOING == p_ve_core->scheduling_status) ||
			(p_ve_core->ve_core_state == HALT)) {
		VEOS_DEBUG("Core[%d] state is either HALT"
				" or scheduling is ongoing on this core,"
				" core state : %d,"
				" scheduling status : %d",
				p_ve_core->core_num,
				p_ve_core->ve_core_state,
				p_ve_core->scheduling_status);
		sem_post(&p_ve_core->core_sem);
		goto hndl_return1;
	}
	p_ve_core->scheduling_status = ONGOING;

	/* Acquire core lock */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
			"Failed to acquire Core %d read lock",
			p_ve_core->core_num);
	curr_ve_task = p_ve_core->curr_ve_task;

	/* Skip scheduling as no task exists in core list */
	if (NULL == p_ve_core->ve_task_list) {
		VEOS_TRACE("No task on Core %d",
				p_ve_core->core_num);
		goto hndl_return;
	}

	/* Only task on core doing no exception, therefore
	 * skip context switch
	 * */
	gettimeofday(&now_time, NULL);
	if (curr_ve_task && (curr_ve_task->sigpending == 0)
			&& scheduler_expiry
			&& (p_ve_core->nr_active == 1)
			&& (curr_ve_task->ve_task_state == RUNNING)
			&& (p_ve_core->ve_core_state == EXECUTING)
			&& (curr_ve_task->ve_sched_state == VE_THREAD_STARTED)) {

		/* Update core busy time */
		p_ve_core->busy_time +=
			timeval_diff(now_time, p_ve_core->core_stime);
		p_ve_core->core_stime = now_time;

		pthread_mutex_lock_unlock(
				&(curr_ve_task->p_ve_mm->thread_group_mm_lock),
				LOCK,
				"Failed to acquire thread-group-mm-lock");
		/* Update VE task execution time */
		psm_calc_task_exec_time(curr_ve_task);

		pthread_mutex_lock_unlock(
				&(curr_ve_task->p_ve_mm->thread_group_mm_lock),
				UNLOCK,
				"Failed to release thread-group-mm-lock");
		/* Update time quantum of VE task
		 * As this is the only eligible VE task on VE core, therefore
		 * re-assign time quantum even if it is exhausted
		 * */
		VEOS_DEBUG("Core %d No exception for pid %d No scheduling",
				p_ve_core->core_num,
				curr_ve_task->pid);
		curr_ve_task->time_slice -=
				timeval_diff(now_time, curr_ve_task->stime);
		if (curr_ve_task->time_slice <= 0) {
			VEOS_DEBUG("Reset time slice for PID %d on Core %d",
					curr_ve_task->pid, curr_ve_task->core_id);
			curr_ve_task->time_slice =
				VE_ATOMIC_GET(uint64_t, &veos_time_slice);
		}
		curr_ve_task->stime = now_time;
		goto hndl_return;
	}

	/* TAKE THREAD GROUP LOCK */
	if (curr_ve_task) {
		VEOS_DEBUG("Acquire thread group lock PID %d CORE %d",
				curr_ve_task->pid, curr_ve_task->core_id);
		pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
				thread_group_mm_lock, LOCK,
				"Failed to acquire thread-group-mm-lock");
	}

	/* STOP the VE core */
	if (psm_halt_ve_core(p_ve_core->node_num, p_ve_core->core_num, &regdata,
						scheduler_expiry, true)) {
		if (curr_ve_task) {
			VEOS_DEBUG("Process %d time slice not exhausted,"
					" Skip Scheduling for core %d",
					curr_ve_task->pid,
					curr_ve_task->core_id);
			pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
		}
		goto hndl_return;
	}

	/* Skip scheduling if there is no eligible task
	 * to be scheduled on core
	 * */
	if (p_ve_core->nr_active == 0) {
		VEOS_DEBUG("Skip scheduling as no active task on core %d",
				p_ve_core->core_num);
		if (curr_ve_task)
			pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
		goto hndl_return;
	}

	/* Handling scenario:
	 * When monc or any other h/w exception like ILSA/ILPV/ILOP etc
	 * is encountered on VE and schedule timer expires before the
	 * Block request is served by veos.
	 * */
	if (NULL != curr_ve_task) {
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, LOCK,
						"Failed to acquire task lock");
		if ((regdata & VE_EXCEPTION)
			&& (curr_ve_task->ve_task_state == RUNNING)
			&& (curr_ve_task->block_status == BLOCK_RECVD)) {
			VEOS_DEBUG("Scheduler setting task state to WAIT for"
					" PID : %d CORE ID: %d",
					curr_ve_task->pid,
					p_ve_core->core_num);
			psm_set_task_state(curr_ve_task, WAIT);
			if (scheduler_expiry) {
				VEOS_DEBUG("Returning from scheduler");
				pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock,
					UNLOCK, "Failed to release task lock");
				pthread_mutex_lock_unlock(&curr_ve_task->
						p_ve_mm->thread_group_mm_lock,
						UNLOCK,
						"Failed to release thread-group-mm-lock");
				goto hndl_return;
			}
		}
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, UNLOCK,
						"Failed to release task lock");
	}

	if (schedule_current && curr_ve_task) {
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, LOCK,
						"Failed to acquire task lock");
		if ((curr_ve_task->ve_task_state == RUNNING)
				&& (curr_ve_task->time_slice > 0)
				&& (curr_ve_task->sigpending == 0)
				&& curr_ve_task->ve_sched_state == VE_THREAD_STARTED) {

			pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, UNLOCK,
							"Failed to release task lock");
			/* Finally, schedule VE process on VE core */
			VEOS_DEBUG("Scheduling Current Task with PID : %d",
					curr_ve_task->pid);
			schedule_task_on_ve_node_ve_core(
					curr_ve_task,
					curr_ve_task,
					scheduler_expiry,
					schedule_current);
			goto hndl_return;
		}
		pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock, UNLOCK,
						"Failed to release task lock");
	}

	schedule_current = false;

	/* a. Decrement thread_sched_count and unset its entry from
	 * thread_sched_bitmap
	 * b. Save user registers of core into current task local copy
	 * */
	if (curr_ve_task && curr_ve_task->reg_dirty == true) {
		*(curr_ve_task->thread_sched_count) -= 1;
		CLEAR_BIT(*(curr_ve_task->thread_sched_bitmap),
				curr_ve_task->core_id);
		VEOS_DEBUG("DECREMENT THREAD_SCHED_COUNT %d PID %d",
				*(curr_ve_task->thread_sched_count),
				curr_ve_task->pid);
		tsd_update = true;

		VEOS_DEBUG("Saving current user context from core");
		psm_save_current_user_context(curr_ve_task);
		VEOS_DEBUG("Setting reg_dirty to false for %d",
					curr_ve_task->pid);
		curr_ve_task->reg_dirty = false;
	}

	/* Find next eligible task to schedule by traversing core list */
	VEOS_DEBUG("Finding next eligible task from core to schedule");
	task_to_schedule = psm_find_next_task_to_schedule(p_ve_core);

	if (task_to_schedule) {
		VEOS_DEBUG("Task to schedule is %d",
				task_to_schedule->pid);

		/* Check if current task and task to schedule
		 * belong to different thread group */
		if ((curr_ve_task) &&
				(curr_ve_task->group_leader
				 != task_to_schedule->group_leader)) {
			VEOS_DEBUG("Current task %d and task to schedule %d"
					" do not belong to same thread group",
					curr_ve_task->pid, task_to_schedule->pid);

			/* Check whether DMA needs to be migrated*/
			(*_veos_arch_ops->arch_psm_process_dma_resource)(
								curr_ve_task);
		}

		/* Schedule task on core */
		VEOS_DEBUG("Initiate scheduling for %d",
				task_to_schedule->pid);
		(*_veos_arch_ops->arch_psm_update_pwr_throttle)
						(p_ve_core->core_num, false);
		schedule_task_on_ve_node_ve_core(
				curr_ve_task, task_to_schedule,
				scheduler_expiry,
				schedule_current);
		(*_veos_arch_ops->arch_psm_update_pwr_throttle)
						(p_ve_core->core_num, true);

	} else if (curr_ve_task) {
		VEOS_DEBUG("No task to schedule");
		VEOS_DEBUG("Release thread group lock"
				" PID %d CORE %d",
				curr_ve_task->pid, curr_ve_task->core_id);

		/* "tsd_update" variable maintained to ensure that
		 * thread_sched_count is updated only when a different
		 * VE task is getting scheduled on core
		 * */
		if (tsd_update) {
			*(curr_ve_task->thread_sched_count) += 1;
			SET_BIT(*(curr_ve_task->thread_sched_bitmap),
					curr_ve_task->core_id);
			if (!(GET_BIT(*(curr_ve_task->thread_core_bitmap),
                                        curr_ve_task->core_id))) {
				SET_BIT(*(curr_ve_task->thread_core_bitmap),
					curr_ve_task->core_id);
				VEOS_DEBUG("THREAD_CORE_BITMAP %ld PID %d",
					*(curr_ve_task->thread_core_bitmap),
						curr_ve_task->pid);
			}
			curr_ve_task->reg_dirty = true;
			VEOS_DEBUG("INCREMENT THREAD_SCHED_COUNT %d PID %d",
					*(curr_ve_task->thread_sched_count),
					curr_ve_task->pid);
		}
		pthread_mutex_lock_unlock(&curr_ve_task->p_ve_mm->
				thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
	}
hndl_return:
	SET_SCHED_STATE(p_ve_core->scheduling_status, COMPLETED);
	sem_post(&p_ve_core->core_sem);
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release core read lock");
hndl_return1:
	VEOS_TRACE("Exiting");
}

/**
 *
 * @return 0 on success, -1 on Failure.
 *
 * @note Invoked by other modules i.e. PPS
 */
int veos_stop_udma(struct ve_task_struct *tsk)
{
	int retval = -1;
	int ret, core_num;
	bool dma_migration_occured = true;
	struct ve_core_struct *p_ve_core;

	VEOS_TRACE("Entering");

	if (tsk == NULL) {
		VEOS_DEBUG("task structure is NULL");
		goto hndl_return;
	}

	do {
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			LOCK, "Failed to acquire thread-group-mm-lock");
		if (tsk->core_dma_desc == NULL || *(tsk->core_dma_desc) == -1) {
			VEOS_DEBUG("%d is not executing User Mode DMA",
							tsk->group_leader->pid);
			pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to acquire thread-group-mm-lock");
			retval = 0;
			goto hndl_return;
		}
		core_num = *(tsk->core_dma_desc);
		p_ve_core = VE_CORE(0, core_num);
		VEOS_DEBUG("tsk %d is executing User Mode DMA on %d",
						tsk->pid, p_ve_core->core_num);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to acquire thread-group-mm-lock");

		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
					"Failed to acquire Core %d read lock",
					p_ve_core->core_num);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			LOCK, "Failed to acquire thread-group-mm-lock");

		/* Check DMA migration, or Rebalancing VE task */
		if (core_num != *(tsk->core_dma_desc)) {
			VEOS_DEBUG("DMA migration or Rebalancing VE task occured");
			pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to acquire thread-group-mm-lock");
			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
				UNLOCK, "Failed to acquire Core %d read lock",
				p_ve_core->core_num);
		} else {
			dma_migration_occured = false;
		}
	}while (dma_migration_occured);

	VEOS_DEBUG("Reset Core DMA descriptor flag");
	*(tsk->core_dma_desc) = -1;

	ret = psm_stop_udma(core_num, tsk->p_ve_mm->udma_desc_bmap);
	if (ret != 0) {
		VEOS_ERROR("Stopping user DMA failed");
		goto hndl_unlock;
	}

	ret = psm_save_udma_context(tsk, core_num);
	if (ret != 0) {
		VEOS_ERROR("Saving user DMA context failed");
		goto hndl_unlock;
	}

	(*_veos_arch_ops->arch_veos_clear_udma)(core_num);

	ret = veos_scheduleout_dmaatb(tsk);
	if (ret != 0) {
		VEOS_ERROR("Scheduling out DMAATB failed due to %s",
								strerror(ret));
		goto hndl_unlock;
	}

	retval = 0;
hndl_unlock:
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
				"Failed to acquire thread-group-mm-lock");
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
					"Failed to acquire Core %d read lock",
					p_ve_core->core_num);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
