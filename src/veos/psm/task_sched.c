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
#include "task_sched.h"
#include "velayout.h"
#include "task_mgmt.h"
#include "cr_api.h"
#include "locking_handler.h"
#include "vesync.h"

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
		psm_process_dma_migration(curr_ve_task);
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
 *
 * @return true when unassign and assign is successful else false
 */
bool psm_unassign_assign_task(struct ve_task_struct *tsk)
{
	bool ret = false;
	int retval = -1;

	VEOS_TRACE("Entering");

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
	VEOS_DEBUG("Assigning task with pid: %d",
			tsk->pid);
	retval = vedl_assign_ve_task(VE_HANDLE(tsk->node_id),
			tsk->p_ve_core->phys_core_num,
			tsk->pid);
	if (retval) {
		if (EAGAIN == errno) {
			VEOS_ERROR("Assign failed exception"
					" not served PID %d",
					tsk->pid);
			ret = false;
			goto hndl_ret;
		} else {
			/* errno is other than EAGAIN then there is
			 * a bug/race in veos which is not handled
			 * */
			VEOS_DEBUG("Failed (%s) to assign PID %d",
					strerror(errno),
					tsk->pid);
			veos_abort("Failed to assign task on core");
		}
	}
	tsk->assign_task_flag = TSK_ASSIGN;
	ret = true;
hndl_ret:
	VEOS_TRACE("Exiting");
	return ret;
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
	reg_t regdata = 0;

	VEOS_TRACE("Entering");

	/* Acquire thread group lock */
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->
			thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	psm_halt_ve_core(node_id, core_id, &regdata, false);

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
	psm_process_dma_migration(del_task_struct);

	/* release thread group lock */
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->
			thread_group_mm_lock, UNLOCK,
			"Failed to release thread group lock");

	VE_CORE(node_id, core_id)->curr_ve_task = NULL;
	VEOS_TRACE("Exiting");
}

/*
* @brief Function sets the updated register value on core
*
* @param task Pointer to VE task struct
*/
void psm_set_context(struct ve_task_struct *task)
{
	int i = 0;
	int ret = -1;

	VEOS_TRACE("Entering");
	if (task->sr_context_bitmap) {
		for (i = 0; i < 64; i++) {
			if (GET_BIT(task->sr_context_bitmap, i)) {
				/* Invoke VEDL API */
				ret = vedl_set_usr_reg(VE_HANDLE(0),
						VE_CORE_USR_REG_ADDR(0,
							task->core_id),
						(SR00 + i),
						task->p_ve_thread->SR[i]);
				if (ret) {
					VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
					goto abort;
				}
				VEOS_DEBUG("Set SR[%d]: 0x%lx in tmp",
						i, task->p_ve_thread->SR[i]);
			}
		}
	}
	if (task->pmr_context_bitmap) {
		for (i = 0; i < 22; i++) {
			if (GET_BIT(task->pmr_context_bitmap, i)) {
				if (i == 0) {
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(VE_HANDLE(0),
							VE_CORE_USR_REG_ADDR(0,
								task->core_id),
							PSW, task->p_ve_thread->PSW);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
								ret, task->pid);
						goto abort;
					}
				}

				if (i == 1) {
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(VE_HANDLE(0),
							VE_CORE_USR_REG_ADDR(0,
								task->core_id),
							PMMR,
							task->p_ve_thread->PMMR);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
								ret, task->pid);
						goto abort;
					}
				}

				if ((i >= 2) && (i <= 5)) {
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(VE_HANDLE(0),
							VE_CORE_USR_REG_ADDR(0,
								task->core_id),
							PMCR00 + (i-2),
							task->p_ve_thread->PMCR[i-2]);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
								ret, task->pid);
						goto abort;
					}
				}
				if (i >= 6) {
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(VE_HANDLE(0),
							VE_CORE_USR_REG_ADDR(0,
								task->core_id),
							PMC00 + (i-6),
							task->p_ve_thread->PMC[i-6]);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
								ret, task->pid);
						goto abort;
					}
				}
			}
		}
	}
	VEOS_TRACE("Exiting");
	return;
abort:
	pthread_mutex_lock_unlock(&task->p_ve_mm->thread_group_mm_lock,
			UNLOCK,	"Failed to release thread group lock");
	veos_abort("Setting context failed");
}

/**
* @brief Marks the ATB/CRD as "dirty" for all the threads of thread group
*
* Function marks the ATB/CRD as "dirty" i.e. the local copy of ATB/CRD register
* for VE process as updated. Scheduler when scheduling any thread of the VE
* process on core checks if ATB/CRD is marked as dirty, if yes it will updates
* core's ATB register with local copy of ATB/CRD register placed in VE task struct
*
* @param[in] task Pointer to VE process task struct.
* @param[in] reg_type.
*/
static void update_atb_crd_dirty(struct ve_task_struct *task, regs_t reg_type)
{
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Register Type is %d", reg_type);

	/* Mark ATB as dirty for all threads of thread group */
	VEOS_DEBUG("Marking ATB/CR DIRTY for thread group PID : %d",
			task->pid);
	group_leader = task->group_leader;
	if (reg_type == _ATB)
		group_leader->atb_dirty = true;
	else
		group_leader->crd_dirty = true;

	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
			if (reg_type == _ATB)
				tmp->atb_dirty = true;
			else
				tmp->crd_dirty = true;
		}
	}
	VEOS_TRACE("Exiting");
}

/**
* @brief Set the JID and DID of VE process on VE core JIDR and
* DIDR registers of VE core
*
* @param tsk Pointer to VE task struct
*
* @return 0 on success and -1 on failure.
*/
int psm_set_jdid(struct ve_task_struct *tsk)
{
	int retval = -1;

	VEOS_TRACE("Entering");
	/* Set JIDR register */
	VEOS_DEBUG("Set JID %u to core %d",
			tsk->jid, tsk->core_id);
	retval = vedl_set_sys_reg_words(VE_HANDLE(0),
			VE_CORE_SYS_REG_ADDR(0, tsk->core_id),
			VE_CORE_OFFSET_OF_JIDR,
			&(tsk->jid), sizeof(reg_t));
	if (0 > retval) {
		VEOS_ERROR("Setting JID %d failed for task %d",
				tsk->jid, tsk->pid);
		retval = -1;
		goto set_jdid_fail;
	}

	/* Set DIDR register */
	VEOS_DEBUG("Set DID %ld to core %d",
			tsk->did, tsk->core_id);
	retval = vedl_set_sys_reg_words(VE_HANDLE(0),
			VE_CORE_SYS_REG_ADDR(0, tsk->core_id),
			VE_CORE_OFFSET_OF_DIDR,
			&(tsk->did), sizeof(reg_t));
	if (0 > retval) {
		VEOS_ERROR("Setting DID failed");
		retval = -1;
		goto set_jdid_fail;
	}
	retval = 0;
set_jdid_fail:
	VEOS_TRACE("Exiting");
	return retval;
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

	free(tsk->udma_context);
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
	ve_task->udma_context =
		(struct ve_udma *)malloc(sizeof(struct ve_udma));
	if (!(ve_task->udma_context)) {
		retval = -errno;
		VEOS_CRIT("Internal Memory allocation failed");
		goto hndl_return;
	}
	memset(ve_task->udma_context, 0, sizeof(struct ve_udma));
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
		regs_t reg_type, reg_t *arr_exs)
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
			psm_halt_ve_core(0, core_loop, (arr_exs + core_loop), false);

			if (!(*(arr_exs + core_loop) & VE_EXCEPTION) || reg_type == _DMAATB) {
				if (psm_unassign_assign_task(p_ve_core->curr_ve_task)) {
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
int psm_halt_ve_core(int node_id, int core_id, reg_t *regdata,
		bool scheduler_expiry)
{
	int retval = -1;
	struct timeval now = {0};
	struct ve_core_struct *p_ve_core = NULL;
	time_t endwait = 0;
	reg_t temp_reg = 0x0;
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
		if (vedl_get_usr_reg(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id, core_id),
				EXS, regdata)) {
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
			VEOS_DEBUG("Time slice remaining %ld",
					curr_ve_task->time_slice);
			p_ve_core->core_running = true;
			gettimeofday(&(curr_ve_task->stime), NULL);
			gettimeofday(&(p_ve_core->core_stime), NULL);
			return -1;
		} else {
			VEOS_DEBUG("Process time slice exhausted"
					" or task state is WAIT");
		}
	}

	/* Set the EXS_STOP bit in EXS register as
	 * all other bits are protected by VE HW
	 * */
halt_core:
	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id, core_id),
			EXS, EXS_STOP);
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
		retval = vedl_get_usr_reg(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id,
					core_id), EXS, regdata);
		if (0 > retval) {
			VEOS_ERROR("Getting user registers failed"
					" for core %d.", core_id);
			goto hndl_return;
		}

		temp_reg = *regdata & EXS_STOPPING;

		if(temp_reg == 1)
			break;

		if (time(NULL) >= endwait)
			break;
	} while (1);

	/* Invoke veos_abort */
	if (temp_reg >> 1) {
		/* Core did not stop, abort veos... */
		VEOS_DEBUG("Core %d did not stop", core_id);
		goto hndl_return;
	}

	/* Set VE core state to STOP */
	SET_CORE_STATE(p_ve_core->ve_core_state, STOPPED);

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
	reg_t regdata = 0;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("Initiated Syncing Operation");
	veos_sync_w_bar2();

	VEOS_DEBUG("Setting EXS_RUN bit");

	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id,
				core_id),
			EXS,
			EXS_RUN);
	if (0 > retval) {
		VEOS_ERROR("Setting user registers failed for core %d",
				core_id);
		goto hndl_return;
	}

	endwait = time(NULL) + wait_time;
	do {
		retval = vedl_get_usr_reg(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id,
					core_id),
				EXS,
				&regdata);
		if (0 > retval) {
			VEOS_ERROR("Getting user registers failed"
					" for core %d.", core_id);
			goto hndl_return;
		}
		if (regdata & EXS_RUN)
			break;
		if (time(NULL) >= endwait)
			break;
	} while (1);

	if (!(regdata & EXS_RUN)) {
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
	retval = 0;
	VEOS_DEBUG("Core: %d EXS: %lx", core_id, regdata);
	VEOS_TRACE("Exiting");
	return retval;

hndl_return:
	veos_abort("Starting core %d was not successful", core_id);
}

/**
* @brief Check core's DMA is mapped to VEHVA and save DMA context
*
* Function check if core's DMA is mapped to VEHVA. If DMA is mapped then
* DMA is halted and DMA descriptor table is saved.
*
* @param curr_ve_task Pointer to current VE task struct
*
* @return 0 on success and -1 on failure
*/
int psm_udma_no_migration(struct ve_task_struct *curr_ve_task)
{
	int retval = -1;

	VEOS_TRACE("Entering");
	/* Check if core's DMA is mapped to VEHVA */
	if (psm_check_udma_desc(curr_ve_task)) {
		/* core_dma_desc reset */
		VEOS_DEBUG("Reset Core DMA descriptor flag");
		*(curr_ve_task->core_dma_desc) = -1;

		/* Stop udma */
		if (psm_stop_udma(curr_ve_task->core_id,
					curr_ve_task->p_ve_mm->udma_desc_bmap)) {
			VEOS_ERROR("Stopping user DMA failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("User DMA Halted");

		/* Save UDMA context */
		if (psm_save_udma_context(curr_ve_task,
					curr_ve_task->core_id)) {
			VEOS_ERROR("Saving user DMA context failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("UDMA saved successfully");

		/* AMM free DMAATB dir entry */
		if (veos_scheduleout_dmaatb(curr_ve_task)) {
			VEOS_ERROR("Scheduling out DMAATB failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("Freed DMAATB dir entry successfully");
	}

	/* AMM save CR page and free it */
	if (veos_save_cr(curr_ve_task)) {
		VEOS_ERROR("Saving CR page failed");
		goto save_context_fail;
	}
	VEOS_DEBUG("Saved CR page");
	retval = 0;

save_context_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Find core for DMA migration and perform DMA migration.
*
* Function finds the eligible core from core bitmap where DMA
* can be migrated.
* Function stops the DMA on current core, saves DMA descriptor table.
* Functions set the DMA and restore the DMA descriptor table entry
* on new core
*
* @param curr_ve_task Pointer to current VE task struct
* @param core_bitmap_set Bitmap representing core executing threads
* of same thread group
*
* @return 0 on success and -1 on failure
*/
int psm_udma_do_migration(struct ve_task_struct *curr_ve_task,
		uint64_t core_bitmap_set)
{
	int migrate_core_id = -1;
	int core_loop = 0;
	int retval = -1;

	VEOS_TRACE("Entering");
	/* Find migrate core id*/
	migrate_core_id = ffsl(core_bitmap_set) - 1;

	VEOS_DEBUG("Migrate core ID %d",
			migrate_core_id);
	/* Stop udma on current core*/
	if (psm_stop_udma(curr_ve_task->core_id,
				curr_ve_task->p_ve_mm->udma_desc_bmap)) {
		VEOS_ERROR("Stopping UDMA failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA halted");

	/* Save UDMA context */
	if (psm_save_udma_context(curr_ve_task,
				curr_ve_task->core_id)) {
		VEOS_ERROR("Saving UDMA context failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA saved successfully");

	/* Update core_dma_desc to migrated core id */
	*(curr_ve_task->core_dma_desc) = migrate_core_id;
	VEOS_DEBUG("Core DMA descriptor set to %d",
			*(curr_ve_task->core_dma_desc));

	VEOS_DEBUG("Invoking veos_update_dmaatb_context()");
	if (veos_update_dmaatb_context(curr_ve_task, migrate_core_id)) {
		VEOS_ERROR("Updating DMA context failed");
		goto udma_migration_fail;
	}

	/* Migrate DMA on new core ID */
	if (psm_restore_udma_context(curr_ve_task, migrate_core_id)) {
		VEOS_ERROR("Restoring DMA context failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA restored successfully on new core");

	if (psm_start_udma(migrate_core_id,
				curr_ve_task->p_ve_mm->udma_desc_bmap)) {
		VEOS_ERROR("Start UDMA failed");
		goto udma_migration_fail;
	}

	/* Start all core of core_set */
	for (; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_bitmap_set, core_loop)) {
			psm_start_ve_core(0, core_loop);
			SET_SCHED_STATE(VE_CORE(0, core_loop)->scheduling_status,
					COMPLETED);
		}
	}
	retval = 0;
udma_migration_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Check and performs DMA migration if required.
*
* Function checks if the current task cores DMA descriptor table is mapped
* to VEHVA
* If core DMA descriptor is mapped then function checks if any thread of
* current VE task is executingon any other VE core.
* If some other thread of same thread group is running then DMA
* migration is performed, else DMA is halted and context is saved.
*
* @param curr_ve_task Pointer to current VE task struct
*
* @return 0 on success, abort veos on failure.
*/
int psm_process_dma_migration(struct ve_task_struct* curr_ve_task)
{
	int tsd = -1;
	int retval = -1;
	uint64_t core_set = 0;
	reg_t *exception_arr = NULL;

	VEOS_TRACE("Entering");

	/* Check the whether other thread of same thread group is executing */
	tsd = *(curr_ve_task->thread_sched_count);

	exception_arr = (reg_t *)malloc(
			VE_NODE(0)->nr_avail_cores * sizeof(reg_t));
	if (!exception_arr) {
		VEOS_CRIT("Internal Memory allocation failed");
		goto dma_migration_fail;
	}

	memset(exception_arr, 0, VE_NODE(0)->nr_avail_cores * sizeof(reg_t));

	VEOS_DEBUG("THREAD_SCHED_COUNT %d PID %d",
			tsd, curr_ve_task->pid);

	if (tsd == 0) {
		/* No other thread of thread group is executing */
		VEOS_DEBUG("No other thread of PID %d is running",
				curr_ve_task->pid);
		if (psm_udma_no_migration(curr_ve_task)) {
			VEOS_ERROR("No DMA migration failed");
			goto dma_migration_fail;
		}
	} else if (tsd > 0) {
		/* Other thread of thread group are executing */
		VEOS_DEBUG("Some other threads of PID %d are executing",
				curr_ve_task->pid);
		if (psm_check_udma_desc(curr_ve_task)) {
			/* Core DMA desc is mapped to VEHVA */
			if (psm_check_sched_jid_core(&core_set,
						curr_ve_task, REG_INVAL, exception_arr)) {
				VEOS_DEBUG("Initiate DMA migration");
				if (psm_udma_do_migration(curr_ve_task, core_set)) {
					VEOS_DEBUG("UDMA migration failed");
					goto dma_migration_fail;
				}
			} else {
				VEOS_DEBUG("No DMA migration, Save context");
				if (psm_udma_no_migration(curr_ve_task)) {
					VEOS_DEBUG("No DMA migration failed");
					goto dma_migration_fail;
				}
			}
		}
	} else {
		/* Normally this should never happen. If this happens then
		 * there is inconsistency while updating "thread_sched_count".
		 */
		VEOS_DEBUG("THREAD_SCHED_COUNT is %d for PID %d",
				tsd, curr_ve_task->pid);
		goto dma_migration_fail;
	}

	retval = 0;
	free(exception_arr);
	VEOS_TRACE("Exiting");
	return retval;
dma_migration_fail:
	veos_abort("VEOS aborting due to failure of DMA migration");
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

	VEOS_TRACE("Entering");
	gettimeofday(&now_time, NULL);
	curr_ve_task->exec_time += timeval_diff(now_time,
			(curr_ve_task->stime));

	VEOS_DEBUG("Core %d PID %d Exec Time %ld",
			curr_ve_task->p_ve_core->core_num,
			curr_ve_task->pid, curr_ve_task->exec_time);

	/* Check the RLIMIT_CPU resource limit of current
	 * VE task.
	 *
	 * If limit exceeds the soft limit then SIGXCPU signal
	 * is send to VE process, if exceeds the hard limit
	 * then SIGKILL is send.
	 */
	if (((curr_ve_task->exec_time)/(double)MICRO_SECONDS) >
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
		if (((curr_ve_task->exec_time)/(double)MICRO_SECONDS) >
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
	reg_t sr_tmp[64] = {0};
	reg_t pmr_tmp[64] = {0};
	int node_id = -1, core_id = -1;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	ve_dma_status_t dmast = 0;
	pid_t pid = getpid();

	node_id = curr_ve_task->node_id;
	core_id = curr_ve_task->core_id;
	p_ve_node = VE_NODE(node_id);
	p_ve_core = VE_CORE(node_id, core_id);

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
	dmast = ve_dma_xfer_p_va(p_ve_node->dh, VE_DMA_VERAA, pid,
			PSM_CTXSW_CREG_VERAA(p_ve_core->phys_core_num),
			VE_DMA_VHVA, pid, (uint64_t)curr_ve_task->p_ve_thread,
			PSM_CTXSW_CREG_SIZE);
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

	VEOS_DEBUG("Getting VE registers done for PID %d",
			curr_ve_task->pid);

	/* restore SR register context */
	if (curr_ve_task->sr_context_bitmap)
		psm_st_rst_context(curr_ve_task, sr_tmp, NULL, false);

	/* restore PSW PMMR PMCR PMC registers context */
	if (curr_ve_task->pmr_context_bitmap)
		psm_st_rst_context(curr_ve_task, NULL, pmr_tmp, false);

	VEOS_DEBUG("Current PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0 : %lx SR1 : %lx SR2 : %lx EXS: %lx",
			curr_ve_task->pid,
			curr_ve_task->p_ve_thread->IC,
			curr_ve_task->p_ve_thread->SR[10],
			curr_ve_task->p_ve_thread->SR[11],
			curr_ve_task->p_ve_thread->SR[12],
			curr_ve_task->p_ve_thread->SR[00],
			curr_ve_task->p_ve_thread->SR[01],
			curr_ve_task->p_ve_thread->SR[02],
			curr_ve_task->p_ve_thread->EXS);
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock), UNLOCK,
		"Failed to release task lock");

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
	struct ve_task_struct *loop_cntr = NULL;
	struct ve_task_struct *task_to_schedule = NULL;
	struct ve_task_struct *task_to_return = NULL;
	struct ve_task_struct *curr_ve_task = NULL;

	VEOS_TRACE("Entering");
	curr_ve_task = p_ve_core->curr_ve_task;

	/* Finds the most eligible VE process to be
	 * scheduled on this VE core
	 * */
	if (NULL != curr_ve_task) {
		loop_cntr = curr_ve_task;
		task_to_schedule = curr_ve_task->next;
	} else {
		loop_cntr = task_to_schedule = p_ve_core->ve_task_list;
	}
	do {
		VEOS_DEBUG("Core: %d Check scheduling for PID: %d State: %d",
				p_ve_core->core_num,
				task_to_schedule->pid,
				task_to_schedule->ve_task_state);

		if ((RUNNING == task_to_schedule->ve_task_state)) {
			VEOS_DEBUG("Ready task found with PID : %d",
					task_to_schedule->pid);
			task_to_return = task_to_schedule;
			break;
		} else {
			VEOS_DEBUG("Skipping task with PID : %d",
					task_to_schedule->pid);
			task_to_schedule = task_to_schedule->next;
		}

		if (loop_cntr == task_to_schedule) {
			if ((RUNNING == task_to_schedule->ve_task_state)) {
				/* Finally, schedule VE process on VE core */
				VEOS_DEBUG("Ready Task found with PID : %d",
						task_to_schedule->pid);
				task_to_return = task_to_schedule;
			}
			break;
		}
	} while (1);
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
	int retval = -1;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Restore CR");

	retval = veos_restore_cr(tts);
	if (0 > retval) {
		VEOS_ERROR("Restoring CR failed");
		goto restore_context_failed;
	}
	/* Schedule in DMAATB */
	VEOS_DEBUG("Schedule in DMAATB");
	if (veos_schedulein_dmaatb(tts)) {
		VEOS_ERROR("Schedule in DMAATB failed");
		retval = -1;
		goto restore_context_failed;
	}

	VEOS_DEBUG("Set DMAATB context");
	if (veos_update_dmaatb_context(tts, tts->core_id)) {
		VEOS_ERROR("Update DMAATB context failed in VEOS");
		retval = -1;
		goto restore_context_failed;
	}

	*(tts->core_dma_desc) = tts->core_id;
	VEOS_DEBUG("Core DMA descriptor set to %d",
			*(tts->core_dma_desc));

	/* Restore UDMA */
	VEOS_DEBUG("Restore udma context");
	retval = psm_restore_udma_context(tts, tts->core_id);
	if (retval) {
		VEOS_ERROR("Restoring UDMA context failed");
		goto restore_context_failed;
	}

	/* Start UDMA */
	VEOS_DEBUG("Start UDMA");
	retval = psm_start_udma(tts->core_id,
			tts->p_ve_mm->udma_desc_bmap);
	if (retval) {
		VEOS_DEBUG("Start UDMA failed");
		goto restore_context_failed;
	}
	retval = 0;
restore_context_failed:
	VEOS_TRACE("Exiting");
	return retval;
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
	int retval = -1;
	reg_t regdata = 0;

	VEOS_TRACE("Entering");

	regdata = VE_UDMA_CTL_PERM_STOP;

	if (udma_desc_bmap & DMA_DESC_H) {
		/* Stop DMA operation on DMA decriptor H */
		VEOS_DEBUG("Unset H DMACTL permission bit");
		retval = vedl_set_sys_reg_words(VE_HANDLE(0),
				VE_CORE_SYS_REG_ADDR(0, core_id),
				VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_HENTRY),
				&regdata, sizeof(reg_t));
		if (0 > retval) {
			VEOS_ERROR("Unsetting H DMACTL permission bit failed");
			goto stop_udma_fail;
		}
	}

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Stop DMA operation on DMA decriptor E */
		VEOS_DEBUG("Unset E DMACTL permission bit");
		retval = vedl_set_sys_reg_words(VE_HANDLE(0),
				VE_CORE_SYS_REG_ADDR(0, core_id),
				VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_EENTRY),
				&regdata, sizeof(reg_t));
		if (0 > retval) {
			VEOS_ERROR("Unsetting permission bit failed");
			goto stop_udma_fail;
		}
	}

	regdata = 0;

	if (udma_desc_bmap & DMA_DESC_H) {
		/* Wait for raising halt bit of DMA control reg
		 * corresponding to DMA descriptor table H
		 * */
		do {
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_H");
			retval = vedl_get_sys_reg_words(VE_HANDLE(0),
					VE_CORE_SYS_REG_ADDR(0, core_id),
					VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_HENTRY),
					&regdata, sizeof(reg_t));
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for Core %d", core_id);
				goto stop_udma_fail;
			}
		} while (!(regdata & 0x2));
	}

	regdata = 0;

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Wait for raising halt bit of DMA control reg
		 * corresponding to DMA descriptor table E
		 * */
		do {
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_E");
			retval = vedl_get_sys_reg_words(VE_HANDLE(0),
					VE_CORE_SYS_REG_ADDR(0, core_id),
					VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_EENTRY),
					&regdata, sizeof(reg_t));
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for Core %d", core_id);
				goto stop_udma_fail;
			}
		} while (!(regdata & 0x2));
	}

	retval = 0;
	VEOS_DEBUG("UDMA stopped for core %d", core_id);
stop_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
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
	int retval = -1;
	reg_t regdata = 0;

	VEOS_TRACE("Entering");
	regdata = VE_UDMA_CTL_PERM_START;

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Set permission bit to start operation on
		 * DMA descriptor table E */
		if (vedl_set_sys_reg_words(VE_HANDLE(0),
					VE_CORE_SYS_REG_ADDR(0, core_id),
					VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_EENTRY),
					&regdata, sizeof(reg_t))) {
			VEOS_ERROR("Setting permission bit failed for E entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for E entry");
		}
	}
	if (udma_desc_bmap & DMA_DESC_H) {
		/* Set permission bit to start operation on
		 * DMA descriptor table H */
		if (vedl_set_sys_reg_words(VE_HANDLE(0),
					VE_CORE_SYS_REG_ADDR(0, core_id),
					VE_UDMA_OFFSET_OF_DMACTL(VE_UDMA_HENTRY),
					&regdata, sizeof(reg_t))) {
			VEOS_ERROR("Setting permission bit failed for H entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for H entry");
		}
	}
	retval = 0;
start_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Saves core's user DMA descriptor tables and DMA control register
* corresponding to H or E depending upon the argument received.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
* @param[in] dma_entry_type Identifier for type of DMA descriptor table
*
* @return 0 on sucess and -1 on failure
*/
int __psm_save_udma_context(struct ve_task_struct *ve_task,
		int core_id, bool dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");

	/* Save DMA descriptor table */
	if (vedl_get_sys_reg_words(VE_HANDLE(ve_task->node_id),
			VE_CORE_SYS_REG_ADDR(ve_task->node_id, core_id),
			VE_UDMA_OFFSET_OF_DMADESC(dma_entry_type),
			&(ve_task->udma_context->dmades[dma_entry_type]),
			sizeof(dma_desc_t)*DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Saving DMA descriptor table failed");
		goto __save_udma_fail;
	}

	/* Save DMA control register */
	if (vedl_get_sys_reg_words(VE_HANDLE(0),
			VE_CORE_SYS_REG_ADDR(0, core_id),
			VE_UDMA_OFFSET_OF_DMACTL(dma_entry_type),
			&(ve_task->udma_context->dmactl[dma_entry_type]),
			sizeof(dma_control_t))) {
		VEOS_ERROR("Saving DMA control register failed");
		goto __save_udma_fail;
	}
	retval = 0;
__save_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
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
		if (__psm_save_udma_context(ve_task, core_id, VE_UDMA_EENTRY)) {
			VEOS_ERROR("Failed to Save UDMA context corresponding to E");
			goto save_udma_fail;
		}
	}

	/* If the bit corresponding to DMA descriptor table H is set in the
	 * bitmap then save the udma context corresponding to DMA decriptor
	 * table H */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("Saving UDMA context corresponding to H");
		if(__psm_save_udma_context(ve_task, core_id, VE_UDMA_HENTRY)) {
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
* saved in ve_task_struct to specified core's register.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
* @param[in] dma_entry_type Identifier for type of DMA descriptor table
*
* @return 0 on success and -1 on failure
*/
int __psm_restore_udma_context(struct ve_task_struct *ve_task,
		int core_id, bool dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");
	/* Set the UDMA descriptors table to core */
	if (vedl_set_sys_reg_words(VE_HANDLE(0),
				VE_CORE_SYS_REG_ADDR(0, core_id),
				VE_UDMA_OFFSET_OF_DMADESC(dma_entry_type),
				&(ve_task->udma_context->dmades[dma_entry_type]),
				sizeof(dma_desc_t)*DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Restoring DMA descriptor table failed");
		goto __restore_dma_fail;
	}

	/* Set the UDMA control register to core */
	if (vedl_set_sys_reg_words(VE_HANDLE(0),
				VE_CORE_SYS_REG_ADDR(0, core_id),
				VE_UDMA_OFFSET_OF_DMACTL(dma_entry_type),
				&(ve_task->udma_context->dmactl[dma_entry_type]),
				sizeof(dma_control_t))) {
		VEOS_ERROR("Restoring DMA control registers failed");
		goto __restore_dma_fail;
	}
	VEOS_DEBUG("Successfully restored DMA descriptors/control registers");
	retval = 0;
__restore_dma_fail:
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
		if (__psm_restore_udma_context(ve_task, core_id, VE_UDMA_EENTRY))
			goto restore_dma_fail;
	}

	/* If the bit corresponding to DMA descriptor table H is set in the
	 * bitmap then restore the udma context corresponding to DMA decriptor
	 * table H */
	if (ve_task->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("Restore UDMA context corresponding to H");
		if(__psm_restore_udma_context(ve_task, core_id, VE_UDMA_HENTRY))
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
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	ve_dma_status_t dmast = 0;
	pid_t pid = getpid();

	VEOS_TRACE("Entering");
	if (!task_to_schedule)
		goto hndl_return;

	node_id = task_to_schedule->node_id;
	core_id = task_to_schedule->core_id;
	p_ve_node = VE_NODE(node_id);
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
		ret = psm_set_jdid(task_to_schedule);
		if (ret){
			VEOS_ERROR("Set JDID failed");
			goto abort;
		}

		/* Set ATB and ATB image */
		VEOS_DEBUG("Set ATB context");
		ret = psm_sync_hw_regs(task_to_schedule, _ATB,
				&task_to_schedule->p_ve_mm->atb,
				false, 0, DIR_CNT);
		if (0 > ret) {
			VEOS_ERROR("Set atb context failed");
			goto abort;
		}

		VEOS_DEBUG("THREAD_SCHED_COUNT %d PID %d",
				*(task_to_schedule->thread_sched_count),
				task_to_schedule->pid);

		/* Restore DMA DMAATB context on core if no other thread
		 * of next task is exedcuting on core
		 * */
		if (*(task_to_schedule->core_dma_desc) == -1) {
			VEOS_DEBUG("Core DMA descriptor set to -1 for PID %d",
					task_to_schedule->pid);
			ret = psm_restore_context_for_new_thread(task_to_schedule);
			if (ret) {
				VEOS_ERROR("Setting DMA and DMAATB context failed");
				goto abort;
			}
		}

		VEOS_DEBUG("Setting CRD context");
		veos_set_crd_context(task_to_schedule);
	}

	/* If current task on core and next task to schedule on core
	 * belong to same thread group and DMA descriptor is not mapped to any
	 * core then restore context
	 * */
	if ((-1 == *(task_to_schedule->core_dma_desc)) &&
			(curr_ve_task->group_leader ==
			 task_to_schedule->group_leader)) {
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
		ret = psm_sync_hw_regs(task_to_schedule, _ATB,
				&task_to_schedule->p_ve_mm->atb,
				false, 0, 32);
		if (-1 == ret) {
			VEOS_ERROR("Setting ATB context failed");
			goto abort;
		}
	}

	VEOS_DEBUG("Setting CRD context");
	veos_set_crd_context(task_to_schedule);

	task_to_schedule->p_ve_thread->EXS = EXS_NOML;

	if (schedule_current && task_to_schedule->usr_reg_dirty == false) {
		/* Update the bit which are set in sr_context_bitmap
		 * and pmr_context_bitmap on core h/w regs
		 * */
		psm_set_context(task_to_schedule);
	} else {
		VEOS_DEBUG("Setting all user registers");
		/* Load the VE process context */
		dmast = ve_dma_xfer_p_va(p_ve_node->dh,	VE_DMA_VHVA, pid,
				(uint64_t)task_to_schedule->p_ve_thread,
				VE_DMA_VERAA, pid,
				PSM_CTXSW_CREG_VERAA(p_ve_core->phys_core_num),
				PSM_CTXSW_CREG_SIZE);
		if (dmast != VE_DMA_STATUS_OK) {
			VEOS_DEBUG("Setting all user registers failed");
			goto abort;
		}
		task_to_schedule->usr_reg_dirty = false;
	}

	VEOS_DEBUG("Scheduling PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0 : %lx SR1 : %lx SR2 : %lx",
			task_to_schedule->pid,
			task_to_schedule->p_ve_thread->IC,
			task_to_schedule->p_ve_thread->SR[10],
			task_to_schedule->p_ve_thread->SR[11],
			task_to_schedule->p_ve_thread->SR[12],
			task_to_schedule->p_ve_thread->SR[00],
			task_to_schedule->p_ve_thread->SR[01],
			task_to_schedule->p_ve_thread->SR[02]);

	if (!schedule_current) {
		/* Set thread_sched_bitmap and increament thread_sched_count*/
		*(task_to_schedule->thread_sched_count) += 1;
		*(task_to_schedule->thread_sched_bitmap) |=
			(1 << task_to_schedule->core_id);
		VEOS_DEBUG("INCREMENTED THREAD_SCHED_COUNT"
				" %d for PID %d",
				*(task_to_schedule->thread_sched_count),
				task_to_schedule->pid);
	}

	/* this process will run on core then it's register will get
	 * updated.
	 */
	task_to_schedule->reg_dirty = true;
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
		task_to_schedule->time_slice = veos_time_slice;
	} else if (task_to_schedule->time_slice <= 0) {
		/* When scheduling is invoked from non-blocking
		 * syscall then VE task time slice is reset only when
		 * it is exhausted
		 * */
		VEOS_DEBUG("Reset VE task time slice");
		task_to_schedule->time_slice = veos_time_slice;
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
						sizeof(reg_t)*count)) {
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
			if (VE_CORE(0, core_loop)->curr_ve_task != tsk) {
				psm_start_ve_core(0, core_loop);
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
int veos_update_atb(uint64_t core_set, void *reg_sw, int dir_num,
		int count, struct ve_task_struct *tsk)
{
	int loop_cnt = 0;
	int retval = -1;
	int core_loop = 0;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Directory num: %d Count: %d",
			dir_num, count);

	/* Update ATB on all the cores */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			VEOS_DEBUG("Update ATB for Core %d",
					core_loop);
			for (loop_cnt = dir_num; loop_cnt < dir_num + count; loop_cnt++) {
				if (vedl_update_atb_dir(VE_HANDLE(0),
							VE_CORE_SYS_REG_ADDR(0,
								core_loop),
							(atb_reg_t *)reg_sw,
							loop_cnt)) {
					VEOS_ERROR("Updating ATB directory failed in driver");
					retval = -1;
					goto veos_update_atb_fail;
				}
			}
			VE_CORE(0, core_loop)->curr_ve_task->atb_dirty = false;
		}
	}

	/* Start all core */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_set, core_loop)) {
			if (VE_CORE(0, core_loop)->curr_ve_task != tsk) {
				VEOS_DEBUG("Start core id : %d",
						core_loop);
				psm_start_ve_core(0, core_loop);
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
int veos_update_dmaatb(uint64_t core_set, void *reg_sw, int dir_num,
		int count, struct ve_task_struct *ve_task, reg_t *arr_exs)
{
	int retval = -1;
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
				if (vedl_update_dmaatb_dir(VE_HANDLE(0),
							VE_CORE_CNT_REG_ADDR(0),
							(dmaatb_reg_t *)reg_sw,
							loop_cnt)) {
					VEOS_ERROR("Update ATB directory at driver failed");
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
				psm_start_ve_core(0, core_loop);
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
* @param reg_sw Pointer containing the address of software image of register
* @param halt_all Flag which denotes syncing will be done for thread group
*		or only thread
* @param dir_num Directory number
* @param count Number of directories that needs to be updated
*
* @return positive integer on success and -1 in failure.
*/
int psm_sync_hw_regs(struct ve_task_struct *ve_task,
		regs_t reg_type,
		void *reg_sw,
		bool halt_all,
		int dir_num,
		int count)
{
	uint64_t core_set = 0;
	int loop_cnt = 0;
	int retval = 0;
	reg_t *exception_arr = NULL;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("PID %d dir_num %d count %d reg_typ %d",
			ve_task->pid, dir_num, count, reg_type);
	exception_arr = (reg_t *)malloc(
			VE_NODE(0)->nr_avail_cores * sizeof(reg_t));
	if (!exception_arr) {
		VEOS_CRIT("Internal Memory allocation failed");
		goto hndl_failure;
	}

	memset(exception_arr, 0, VE_NODE(0)->nr_avail_cores * sizeof(reg_t));
	switch(reg_type) {
	case _ATB:
		VEOS_DEBUG("Update ATB");
		if (halt_all) {
			/* Halt all the threads of thread group
			 * and update ATB*/
			VEOS_DEBUG("ATB update for whole thread group");
			VEOS_DEBUG("Mark ATB DIRTY for thread group");
			update_atb_crd_dirty(ve_task, reg_type);

			if (psm_check_sched_jid_core(&core_set,
						ve_task, reg_type, exception_arr)) {
				VEOS_DEBUG("Core set %ld", core_set);
				VEOS_DEBUG("Syncing ATB");
				/* Update ATB on all core in core set */
				retval = veos_update_atb(core_set, reg_sw,
						dir_num, count,
						ve_task);
				if (-1 == retval) {
					VEOS_ERROR("Updating ATB failed");
					goto hndl_failure;
				}
			}
		} else {
			for (loop_cnt = dir_num; loop_cnt < dir_num + count
					; loop_cnt++) {
				retval = vedl_update_atb_dir(VE_HANDLE(0),
						VE_CORE_SYS_REG_ADDR(0,
							ve_task->core_id),
						(atb_reg_t *)reg_sw,
						loop_cnt);
				if (0 > retval) {
					VEOS_ERROR("Update ATB failed in driver");
					goto hndl_failure;
				}
			}
			ve_task->atb_dirty = false;
		}
		break;
	case _DMAATB:
		VEOS_DEBUG("Update DMAATB");

		if (halt_all) {

			if (psm_check_sched_jid_core(&core_set,
						ve_task, reg_type, exception_arr)) {
				/* Update DMAATB on all core in core set */
				retval = veos_update_dmaatb(core_set, reg_sw,
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
				retval = vedl_update_dmaatb_dir(VE_HANDLE(0),
						VE_CORE_CNT_REG_ADDR(0),
						(dmaatb_reg_t *)reg_sw,
						loop_cnt);
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
			update_atb_crd_dirty(ve_task, reg_type);
			if (psm_check_sched_jid_core(&core_set, ve_task, reg_type, exception_arr)) {
				VEOS_DEBUG("Core set %ld", core_set);
				VEOS_DEBUG("Syncing CRD");
				/* Update ATB on all core in core set */
				retval = veos_update_crd(core_set, reg_sw,
						dir_num, count,
						ve_task);
				if (-1 == retval) {
					VEOS_ERROR("Update CRD failed");
					goto hndl_failure;
				}
			}
		} else {
			/* Update CRD */
			retval = amm_set_crd((crd_t *)reg_sw, dir_num, ve_task->core_id,
					sizeof(reg_t) * count);
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
	int node_loop = 0, core_loop = 0;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");
	p_ve_node = VE_NODE(VE_NODE_ID(node_loop));

	if (NULL == p_ve_node) {
		VEOS_ERROR("BUG Node ID: %d struct is NULL",
				VE_NODE_ID(node_loop));
		goto hndl_return;
	}

	/* acquiring semaphore for node */
	if (-1 == sem_trywait(&p_ve_node->node_sem)) {
		VEOS_DEBUG("Node %d semaphore try lock failed with errno: %d",
				p_ve_node->node_num, errno);
		goto hndl_return;
	}

	if (ONGOING == p_ve_node->scheduling_status) {
		VEOS_DEBUG("Scheduling ongoing for Node %d",
				VE_NODE_ID(node_loop));
		sem_post(&p_ve_node->node_sem);
		goto hndl_return;
	}

	VEOS_TRACE("Setting ongoing for Node %d",
			VE_NODE_ID(node_loop));
	SET_SCHED_STATE(p_ve_node->scheduling_status, ONGOING);

	/* core loop */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		p_ve_core = VE_CORE(VE_NODE_ID(node_loop), core_loop);
		if (NULL == p_ve_core) {
			VEOS_ERROR("BUG Core ID: %d struct is NULL",
					core_loop);
			continue;
		}

		if (!terminate_flag) {
			ret = pthread_rwlock_tryrdlock
				(&handling_request_lock);
			if (ret) {
				VEOS_ERROR("Scheduler failed in acquiring "
						"try read lock");
				if (ret == EBUSY)
					goto terminate;
				else
					goto abort;
			}
			/* Rebalance task */
			psm_rebalance_task_to_core(p_ve_core);
			psm_find_sched_new_task_on_core(p_ve_core,
					true, false);
			pthread_rwlock_lock_unlock(&handling_request_lock,
					UNLOCK,
					"Failed to release handling request lock");
		} else {
			goto terminate;
		}
	}

	/* Caluculate the system load on every scheduler timer
	 * expiry.
	 */
	calc_sys_load_per_sched_interval(p_ve_node);

	VEOS_TRACE("Scheduling Completed for Node %d",
			VE_NODE_ID(node_loop));
	SET_SCHED_STATE(p_ve_node->scheduling_status, COMPLETED);
	sem_post(&p_ve_node->node_sem);
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
	int core_loop;
	int rebalance_flag = 0;
	struct ve_core_struct *p_another_core;

	VEOS_TRACE("Entering");

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

		if(NULL == p_another_core->ve_task_list) {
			pthread_rwlock_lock_unlock(
					&(p_another_core->ve_core_lock),
					UNLOCK,
					"Failed to release core's write lock");
			continue;
		}
		if (p_another_core->curr_ve_task) {
			task_to_rebalance = p_another_core->curr_ve_task->next;
			loop_start = p_another_core->curr_ve_task;
		} else {
			VEOS_DEBUG("Current task on core is [%p]",
						p_another_core->curr_ve_task);
			task_to_rebalance = p_another_core->ve_task_list->next;
			loop_start = p_another_core->ve_task_list;
		}

		ve_task_list_head = p_another_core->ve_task_list;

		/* Check wether curr_ve_task->next should be rabalanced. */
		while (task_to_rebalance != loop_start) {
			if (CPU_ISSET(ve_core_id,
					&(task_to_rebalance->cpus_allowed)) &&
				!(get_ve_task_struct(task_to_rebalance))) {
				rebalance_flag = 1;
				break;
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

			ve_atomic_dec(&(VE_NODE(ve_node_id)->num_ve_proc));
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

	ve_atomic_inc(&(VE_NODE(ve_node_id)->num_ve_proc));
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
			task_to_rebalance->p_ve_thread->IC);

	put_ve_task_struct(task_to_rebalance);
	VEOS_TRACE("Exiting");
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
	if (NULL == p_ve_core->ve_task_list) {
		pthread_rwlock_lock_unlock(
				&(p_ve_core->ve_core_lock), UNLOCK,
				"Failed to acquire Core %d read lock",
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
		}
		pthread_rwlock_lock_unlock(
				&(VE_NODE(0)->ve_relocate_lock), UNLOCK,
				"Failed to release ve_relocate_lock writelock");
	} else {
		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
				"Failed to acquire Core %d read lock",
				p_ve_core->core_num);
	}

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
	reg_t regdata = 0;
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
			&& p_ve_core->ve_core_state == EXECUTING) {
		/* Update core busy time */
		p_ve_core->busy_time +=
			timeval_diff(now_time, p_ve_core->core_stime);
		p_ve_core->core_stime = now_time;

		/* Update VE task execution time */
		psm_calc_task_exec_time(curr_ve_task);

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
			curr_ve_task->time_slice = veos_time_slice;
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
	if (psm_halt_ve_core(p_ve_core->node_num,
			p_ve_core->core_num, &regdata,
			scheduler_expiry)) {
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
	if (NULL != curr_ve_task && ((curr_ve_task->ve_task_state == RUNNING))) {
		if ((regdata & VE_EXCEPTION)
				&&
				(curr_ve_task->block_status == BLOCK_RECVD)) {
			pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock,
					LOCK, "Failed to acquire task lock");
			VEOS_DEBUG("Scheduler setting task state to WAIT for"
					" PID : %d CORE ID: %d",
					curr_ve_task->pid,
					p_ve_core->core_num);
			psm_set_task_state(curr_ve_task, WAIT);
			pthread_mutex_lock_unlock(&curr_ve_task->ve_task_lock,
					UNLOCK, "Failed to release task lock");
			if (scheduler_expiry) {
				VEOS_DEBUG("Returning from scheduler");
				pthread_mutex_lock_unlock(&curr_ve_task->
						p_ve_mm->thread_group_mm_lock,
						UNLOCK,
						"Failed to release thread-group-mm-lock");
				goto hndl_return;
			}
		}
	}

	if ((schedule_current) && (curr_ve_task)
			&& (curr_ve_task->ve_task_state == RUNNING)
			&& (curr_ve_task->time_slice > 0)
			&& curr_ve_task->sigpending == 0) {
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
			psm_process_dma_migration(curr_ve_task);
		}

		/* Schedule task on core */
		VEOS_DEBUG("Initiate scheduling for %d",
				task_to_schedule->pid);
		schedule_task_on_ve_node_ve_core(
				curr_ve_task, task_to_schedule,
				scheduler_expiry,
				schedule_current);
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
