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
 * @file  task_mgmt.c
 * @brief Handles VE task management activities
 *
 * This contains the functions that are used to handle VE task
 * creation, deletion and scheduling.
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <mqueue.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "task_mgmt.h"
#include "mm_common.h"
#include "ve_mem.h"
#include "mm_stat.h"
#include "cr_api.h"
#include "veos.h"
#include "task_sched.h"
#include "dmaatb_api.h"
#include "task_signal.h"
#include "proto_buff_schema.pb-c.h"
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include "velayout.h"
#include "libved.h"
#include "veos_ived.h"
#include "ptrace_req.h"
#include "locking_handler.h"
#include "psm_stat.h"

/**
* @brief Get the content of register value of the VE process.
*
* @param[in] pid Pid of VE process
* @param[in] numregs Number of registers whose data needs to
* 	be fetched form VEOS
* @param[in] regids Array of Register ID whose data is needed
* @param[out] data Data corresponding to Register ID needs to
* be populated in it
*
* @return 0 in case of success and negative value in case of failure
*/
int psm_get_regval(struct ve_task_struct *tsk,
		int numregs, int *regids, uint64_t *data)
{
	int i, regid;
	int retval = -1;
	int node_id = -1, core_id = -1;
	struct ve_task_struct *curr_ve_task = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	bool should_stop_core = false, core_stopped = false;
	reg_t exception_reg = 0;

	VEOS_TRACE("Entering");

	node_id = tsk->node_id;
	core_id = tsk->core_id;
	p_ve_core = tsk->p_ve_core;
	curr_ve_task = p_ve_core->curr_ve_task;

	for (i = 0; i < numregs; i++) {
		regid = regids[i];
		if (regid < USRCC || regid > SR63) {
			retval = -EINVAL;
			VEOS_DEBUG("Illegal regid %d", regid);
			goto hndl_return;
		}
		/* Check if Register ID array contains any register for
		 * which core is needed to be stopped if task
		 * is current task on core */
		if (!((USRCC <= regid && regid <= PMC15) || (regid == EXS)
					|| (SAR <= regid && regid <= PMCR03)))
			should_stop_core = true;
	}

	/* Acquire core lock */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
			"Failed to acquire Core %d write lock",
			p_ve_core->core_num);

	if (curr_ve_task == tsk && should_stop_core) {
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->
				thread_group_mm_lock, LOCK,
				"Failed to acquire thread-group-mm-lock");
		psm_halt_ve_core(0, core_id, &exception_reg, false);

		if (!(exception_reg & VE_EXCEPTION))
			psm_unassign_assign_task(p_ve_core->curr_ve_task);

		core_stopped = true;
	}

	for (i = 0; i < numregs; i++) {
		regid = regids[i];
		if (tsk == p_ve_core->curr_ve_task &&
				!(regid >= SAR && regid <= PMCR03)) {
			VEOS_DEBUG("Getting reg[%d] on core[%d]",
				   regid, core_id);
			retval = vedl_get_usr_reg(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id, core_id),
						  regid,
						  &data[i]);
			if (0 != retval) {
				VEOS_ERROR("Failed to get user registers "
					"for core[%d]", core_id);
				retval = -EFAULT;
				goto hndl_return2;
			}
		} else {
			retval = psm_ptrace_peekuser(tsk, regid,
						     (void *)&data[i]);
			if (0 != retval) {
				VEOS_ERROR("Failed to read the content of"
					"given VE register Process for core"
					"[%d]", core_id);
				retval = -EFAULT;
				goto hndl_return2;
			}
		}
		VEOS_DEBUG("Register %d: %lx of Pid: %d", regid,
			   data[i], tsk->pid);
	}
	retval = 0;
hndl_return2:
	if (core_stopped) {
		/* Start VE core if no exception is pending */
		if (!(exception_reg & VE_EXCEPTION))
			psm_start_ve_core(0, core_id);

		pthread_mutex_lock_unlock(&tsk->p_ve_mm->
				thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
	}
	/* Release core lock */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release Core %d read lock",
			p_ve_core->core_num);
hndl_return:
	put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sets task's state according to current_state and new_state.
 * Also increments/decrements nr_active if required.
 *
 * @param[in] task_struct Pointer to VE task struct
 * @param[in] new_state target state to be set of the task
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 * @note Invoked by other modules i.e. PTRACE
 */
void psm_set_task_state(struct ve_task_struct *task_struct,
		enum proc_state new_state) {

	enum proc_state curr_state = P_INVAL;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");

	/* Added to handle functionality when Parent exits before a
	 * VFORKED child */
	if (task_struct->pid == 1){
		VEOS_DEBUG("Parent is INIT. No need to set task state");
		goto hndl_return;
	}

	curr_state = task_struct->ve_task_state;
	p_ve_core = task_struct->p_ve_core;

	if (NULL == p_ve_core) {
		VEOS_ERROR("VE Core struct is NULL");
		veos_abort("Core struct is NULL");
	}

	VEOS_DEBUG("Core:%d nr_active:%d PID : %d"
			" Current task state: %d, state to set: %d",
			p_ve_core->core_num,
			p_ve_core->nr_active,
			task_struct->pid,
			curr_state,
			new_state);

	/* Checking for following:
	 * 1. if new state is same as current state, no change needed
	 * 2. if current state is EXIT_DEAD, it cannot be changed
	 *    to any other state, hence return
	 * 3. return in case of P_INVAL*/
	if (new_state == curr_state || curr_state == EXIT_DEAD
			|| new_state == P_INVAL || curr_state == P_INVAL)
		goto hndl_return1;

	if (curr_state == ZOMBIE) {
		if (new_state == EXIT_DEAD)
			task_struct->ve_task_state = new_state;
		goto hndl_return1;
	}

	/* If state is changing from RUNNING to any other */
	if (curr_state == RUNNING) {
		task_struct->ve_task_state = new_state;
		ve_atomic_dec(&(p_ve_core->nr_active));
		goto hndl_return1;
	}
	/* If state is changing from any other to RUNNING */
	if (new_state == RUNNING) {
		task_struct->ve_task_state = new_state;
		ve_atomic_inc(&(p_ve_core->nr_active));
		goto hndl_return1;
	}

	task_struct->ve_task_state = new_state;

hndl_return1:
	VEOS_DEBUG("Core:%d nr_active:%d Task state for PID: %d set to %d",
						p_ve_core->core_num,
						p_ve_core->nr_active,
						task_struct->pid,
						task_struct->ve_task_state);
hndl_return:
	VEOS_TRACE("Exiting");
	return;
}
/**
 * @brief Calculate the total number of context switches across all
 * VE cores of given node.
 *
 * @param[in] p_ve_node Pointer to VE Node struct
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
unsigned long psm_calc_nr_context_switches(struct ve_node_struct *p_ve_node)
{
	unsigned long retval = -1;
	unsigned long sum = 0;
	int core_loop = 0;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");
	if (!p_ve_node)
		goto hndl_return;

	for (; core_loop < p_ve_node->nr_avail_cores; core_loop++) {
		p_ve_core = VE_CORE(p_ve_node->node_num, core_loop);
		if (NULL == p_ve_core) {
			VEOS_ERROR("BUG Core ID: %d struct is NULL",
					core_loop);
			continue;
		}
		sum += p_ve_core->nr_switches;
	}
	retval = sum;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Calculate the VE system last 1min, 5min, 15min load
 *
 * @param[in] p_ve_node Pointer to struct VE Node
 * @param[out] sys_load_1 Last 1min VE system load
 * @param[out] sys_load_5 Last 5min VE system load
 * @param[out] sys_load_15 Last 15min VE system load
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int calc_last_1_5_15_load(struct ve_node_struct *p_ve_node,
		double *sys_load_1, double *sys_load_5, double *sys_load_15)
{
	int retval = -1;
	struct ve_sys_load *tmp = NULL;
	struct list_head *p;
	double load_1 = 0;
	double load_5 = 0;
	double load_15 = 0;
	uint64_t time = 0;
	int itr_1 = 0;
	int itr_5 = 0;
	int itr_15 = 0;
	VEOS_TRACE("Entering");
	if (!p_ve_node || !sys_load_1 || !sys_load_5 || !sys_load_15){
		goto hndl_return;
	}
	/* To avoid deadlock due to sequence node_sem -> ve_relocate_lock */
	pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock), UNLOCK,
				"Failed to release ve_relocate_lock release lock");
	/* acquiring semaphore for node */
	if (-1 == sem_wait(&p_ve_node->node_sem)) {
		VEOS_DEBUG("Node %d semaphore lock failed with errno: %d",
				p_ve_node->node_num, errno);
		goto hndl_error;
	}
	pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock), RDLOCK,
				"Failed to acquire ve_relocate_lock read lock");
	list_for_each_prev(p, &(p_ve_node->ve_sys_load_head)) {
		tmp = list_entry(p, struct ve_sys_load, list);
		if (time < (ONE_MIN * MICRO_SECONDS)) {
			load_1 += tmp->sys_load;
			itr_1++;
		}

		if (time < (FIVE_MIN * MICRO_SECONDS)) {
			load_5 += tmp->sys_load;
			itr_5++;
		}
		load_15 += tmp->sys_load;
		itr_15++;
		time += tmp->time_slice;
	}
	sem_post(&p_ve_node->node_sem);

	/* calculate last 1 min load */
	if (itr_1)
		*sys_load_1 = load_1/(double)itr_1;
	else
		*sys_load_1 = 0;

	/* calculate last 5 min load */
	if (itr_5)
		*sys_load_5 = load_5/(double)itr_5;
	else
		*sys_load_5 = 0;

	/* calculate last 15 min load */
	if (itr_15)
		*sys_load_15 = load_15/(double)itr_15;
	else
		*sys_load_15 = 0;

	VEOS_DEBUG("Load in last (1min %f itr %d) (5min %f itr %d)"
			" (15min %f itr %d)",
			*sys_load_1, itr_1,
			*sys_load_5, itr_5,
			*sys_load_5, itr_15);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
hndl_error:
	veos_abort("Failed to acquire VE node semaphore for system load calculation");
}

/**
 * @brief It populates the list of VE system load for last 15min maximum
 * in the Node struct.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 * @param[in] load Load on system at every scheduler interval
 * @param[in] time Time slice for that scheduler interval
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
void populate_1_5_15_sys_load(struct ve_node_struct *p_ve_node,
		double load, uint64_t time)
{
	struct ve_sys_load *ve_load = NULL;
	struct ve_sys_load *tmp = NULL;
	struct list_head *p;

	VEOS_TRACE("Entering");
	if (!p_ve_node)
		goto hndl_return;

	/* Maximum last 15min load of VE system is maintained
	 * when system load time increases from 15min entries from
	 * the list are removed.
	 */
	while (p_ve_node->total_sys_load_time > (FIFTEEN_MIN * MICRO_SECONDS)) {
		/* Removing the first element of the list */
		p = p_ve_node->ve_sys_load_head.next;
		tmp = list_entry(p, struct ve_sys_load, list);
		p_ve_node->total_sys_load_time -= tmp->time_slice;
		list_del(p);
		free(tmp);
	}

	ve_load = malloc(sizeof(struct ve_sys_load));
	if (NULL == ve_load) {
		VEOS_CRIT("Internal memory allocation failed");
		VEOS_DEBUG("Malloc failed due to: %s", strerror(errno));
		goto hndl_return;
	}
	/*MEMSET*/
	memset(ve_load, '\0', sizeof(struct ve_sys_load));
	ve_load->sys_load = load;
	ve_load->time_slice = time;
	p_ve_node->total_sys_load_time += time;
	list_add_tail(&(ve_load->list), &(p_ve_node->ve_sys_load_head));
hndl_return:
	VEOS_TRACE("Exiting");
}

/**
 * @brief Calculate the system load on every scheduler expiry.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
void calc_sys_load_per_sched_interval(struct ve_node_struct *p_ve_node)
{
	struct ve_core_struct *p_ve_core = NULL;
	int core_loop = 0;
	double per_core_load;
	double per_node_load = 0;
	struct timeval now;
	uint64_t time_slice = 0;
	uint64_t nr_active = 0;

	VEOS_TRACE("Entering");
	if (!p_ve_node)
		goto hndl_return;

	gettimeofday(&now, NULL);
	time_slice = timeval_diff(now, p_ve_node->sched_stime);
	p_ve_node->sched_stime = now;
	for (; core_loop < p_ve_node->nr_avail_cores; core_loop++) {
		p_ve_core = VE_CORE(p_ve_node->node_num, core_loop);
		if (NULL == p_ve_core) {
			VEOS_ERROR("BUG Core ID: %d struct is NULL",
					core_loop);
			continue;
		}

		per_core_load = (double)((p_ve_core->busy_time -
				p_ve_core->busy_time_prev) / (double)time_slice);
		nr_active += p_ve_core->nr_active;
		VEOS_TRACE("Load On Core %d (In %.2f Sec) is %.2f%%",
				core_loop,
				(double)(time_slice/(double)MICRO_SECONDS),
				(per_core_load * 100));
		p_ve_core->busy_time_prev = p_ve_core->busy_time;
		per_node_load += per_core_load;
	}

	/* Average load on a NODE */
	per_node_load = per_node_load/(p_ve_node->nr_avail_cores);

	VEOS_TRACE("VE System Load (In %.2f Sec): %.4f, Active Task: %lu",
			(double)(time_slice/(double)MICRO_SECONDS),
			per_node_load * p_ve_node->nr_active,
			p_ve_node->nr_active);

	/* Populate the load in list maintained to calculate system
	 * load in last 1min, 5min, 15min.
	 */
	populate_1_5_15_sys_load(p_ve_node,
			per_node_load * p_ve_node->nr_active,
			time_slice);

	p_ve_node->nr_active = nr_active;
hndl_return:
	VEOS_TRACE("Exiting");
}

/**
 * @brief Calculates the time difference between two given timestamp.
 *
 * @param[in] end_time End time
 * @param[in] start_time Start time
 *
 * @return time difference between two timestamp
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
long long timeval_diff(struct timeval end_time, struct timeval start_time)
{
	VEOS_TRACE("Entering");
	struct timeval difference = {0};

	difference.tv_sec = end_time.tv_sec - start_time.tv_sec;
	difference.tv_usec = end_time.tv_usec - start_time.tv_usec;

	while (difference.tv_usec < 0) {
		difference.tv_usec += USECOND;
		difference.tv_sec -= SECOND;
	}
	VEOS_TRACE("Exiting");
	return USECOND*difference.tv_sec + difference.tv_usec;
}

/**
 * @brief This function temporarly store/restore the s/w
 * context of user registers of processes.
 *
 * @param[in] task current ve task
 * @param[in] sr_temp pointer to buffer used to store/restore
 * value of sr context registers
 * @param[in] pmr_temp pointer to buffer used to store/restore
 * value of pmr context registers
 * @param[in] st_flag flag to tell whether to store or restore
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
void psm_st_rst_context(struct ve_task_struct *task, reg_t *sr_temp,
		reg_t *pmr_temp, bool st_flag)
{
	int i = 0;
	VEOS_TRACE("Entering");
	if (sr_temp) {
		for (i = 0; i < MAX_SR; i++) {
			if (GET_BIT(task->sr_context_bitmap, i)) {
				if (st_flag)
					sr_temp[i] = task->p_ve_thread->SR[i];
				else
					task->p_ve_thread->SR[i] = sr_temp[i];
					VEOS_DEBUG("Storing SR[%d]: 0x%lx in tmp",
						i, sr_temp[i]);
			}
		}
	}

	if (pmr_temp) {
		for (i = PMR_CONTEXT_PSW; i < PMR_CONTEXT_LOOP; i++) {
			if (GET_BIT(task->pmr_context_bitmap, i)) {
				if (i == PMR_CONTEXT_PSW) {
					if (st_flag)
						pmr_temp[i] = task->p_ve_thread->PSW;
					else
						task->p_ve_thread->PSW = pmr_temp[i];

					VEOS_DEBUG("Storing PSW: 0x%lx in tmp",
							pmr_temp[i]);
				}
				if (i == PMR_CONTEXT_PMRR) {
					if (st_flag)
						pmr_temp[i] = task->p_ve_thread->PMMR;
					else
						task->p_ve_thread->PMMR = pmr_temp[i];

					VEOS_DEBUG("Storing PMMR: 0x%lx in tmp",
							pmr_temp[i]);
				}
				if ((i >= PMR_CONTEXT_PMCR0) && (i <= PMR_CONTEXT_PMCR3)) {
					if (st_flag)
						pmr_temp[i] = task->p_ve_thread->PMCR[i - PMR_CONTEXT_PMCR0];
					else
						task->p_ve_thread->PMCR[i - PMR_CONTEXT_PMCR0] = pmr_temp[i];

					VEOS_DEBUG("Storing PMCR[%d]: 0x%lx in tmp",
							i - PMR_CONTEXT_PMCR0, pmr_temp[i]);
				}
				if (i >= PMR_CONTEXT_PMCR4) {
					if (st_flag)
						pmr_temp[i] = task->p_ve_thread->PMC[i - PMR_CONTEXT_PMCR4];
					else
						task->p_ve_thread->PMC[i - PMR_CONTEXT_PMCR4] = pmr_temp[i];

					VEOS_DEBUG("Storing PMC[%d]: 0x%lx in tmp",
							i - PMR_CONTEXT_PMCR4, pmr_temp[i]);
				}
			}
		}
	}
	VEOS_TRACE("Exiting");
}

/**
 * @brief This function is invoked by veos_termination() to handle shutdown of veos.
 *
 * This function will halt all VE cores and user mode DMA, delete all VE
 * processes and kill all pseudo processes. It will then requests VE driver to
 * remove tasks corresponding to VE processes. Requests internal VESHM module
 * to notify erasing VE process with IVED.
 *
 * This function psm_terminate_all() can fail due to various reason and this
 * function is invoked during shutdown of veos, so if some failure occurred, we
 * just log the error message and call veos_abort().
 *
 * @return : Always returns success.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_terminate_all(int node_id)
{
	int retval = -1;
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_node_struct *p_ve_node = NULL;
	int core_id = 0;
	pid_t tmp_pid = -1;
	reg_t regdata = 0;

	VEOS_TRACE("Entering");

	p_ve_node = VE_NODE(node_id);

	for (; core_id < p_ve_node->nr_avail_cores; core_id++) {

		p_ve_core = VE_CORE(node_id, core_id);
		if (NULL == p_ve_core) {
			VEOS_DEBUG("BUG Core ID: %d struct is NULL",
					core_id);
			goto err_handle;
		}
		/* Taking VE core lock before setting EXS_STOP so that
		 *                  * some other thread excuting in schedule_timer_expiry
		 *                                   * cannot set core state back to EXS_RUN.
		 *                                                    * */
		retval = pthread_rwlock_trywrlock(&(p_ve_core->ve_core_lock));
		if (0 != retval) {
			VEOS_ERROR("Acquiring read write try lock"
					" failed for Core: %d",
					core_id);
			goto err_handle;
		}

		retval = psm_halt_ve_core(node_id, core_id, &regdata, false);
		if (retval < 0) {
			VEOS_ERROR("Halting VE Core failed for core: %d",
					core_id);
			goto err_handle;
		}
		retval = pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
		if (0 != retval) {
			VEOS_ERROR("Releasing try lock"
					" failed for Core: %d",
					core_id);
			goto err_handle;
		}

		retval = psm_stop_udma(core_id, DMA_DESC_E_H);
		if (0 != retval) {
			VEOS_ERROR("Stopping UDMA failed for core : %d",
					core_id);
			goto err_handle;
		}

	}
	/* 1. Traverse the INIT task list.
	 * 2. For every VE process,
	 *      a. Send SIGKILL to pseudo process
	 *      corresponding to this VE process.
	 *      b. Invoke psm_handle_delete_ve_process()
	 * to VE process.
	 */
        VEOS_DEBUG("Delete VE processes and free their resources");
        if (!list_empty(&ve_init_task.tasks)) {
                list_for_each_safe(p, n, &ve_init_task.tasks) {
                        tmp = list_entry(p, struct ve_task_struct, tasks);
                        tmp_pid = tmp->pid;
			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), LOCK,
					"Failed to acquire task lock [PID = %d]",
					tmp->pid);
			tmp->exit_code = SIGKILL;
			tmp->exit_code_set = true;
			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), UNLOCK,
					"Failed to release task lock [PID = %d]",
					tmp->pid);
                        VEOS_DEBUG("Deleting PID : %d. "
					"Getting reference for group leader",
                                        tmp_pid);
			get_ve_task_struct(tmp);
			psm_do_process_cleanup(tmp, tmp, EXIT_EXECVE_VH);
                        VEOS_INFO("Sending SIGKILL to PID: %d",
                                        tmp_pid);
                        kill(tmp_pid, SIGKILL);
                }
        } else {
                VEOS_DEBUG("No VE process exist");
        }

	VEOS_TRACE("Exiting");
	return retval;

err_handle:
	veos_abort("Terminating all tasks failed");
}

/**
 * @brief Allocates memory for ve_thread_struct
 *
 * @return pointer to VE thread struct on success, NULL on failure
 * 	and errno is set to indicate the error value.
 *
 * @internal
 * @author PSMG / Process management
 */
core_user_reg_t *alloc_ve_thread_struct_node()
{
	int retval = -1;
	core_user_reg_t *p = NULL;
	VEOS_TRACE("Entering");

	p = (core_user_reg_t *)malloc(sizeof(core_user_reg_t));
	if (!p) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for user register "
				"structure, return value %s", strerror(errno));
		errno = -retval;
		goto hndl_return;
	}

	memset(p, 0, sizeof(core_user_reg_t));

hndl_return:
	VEOS_TRACE("Exiting");
	return p;
}

/**
 * @brief Allocate memory for VE task structure.
 *
 * @return pointer to VE task struct on success, NULL on failure
 * 	and errno is set to indicate the error value.
 *
 * @internal
 * @author PSMG / Process management
 */
struct ve_task_struct *alloc_ve_task_struct_node(void)
{
	int retval = -1;
	struct ve_task_struct *p = NULL;

	VEOS_TRACE("Entering");

	p = (struct ve_task_struct *)malloc(sizeof(struct ve_task_struct));
	if (!p) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for task structure, "
				"return value %s", strerror(errno));
		errno = -retval;
		goto hndl_return;
	}
	memset(p, 0, sizeof(struct ve_task_struct));

hndl_return:
	VEOS_TRACE("Exiting");
	return p;
}

/**
 * @brief Allocate memory for udma_context, core_dma_desc, cr data,
 * and jid data structures of thread group leader task
 * structure
 *
 * @param[in] tsk Pointer of VE process leaders ve_task_structure
 *
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int alloc_ve_task_data(struct ve_task_struct *tsk)
{
	int64_t retval = -1;

	VEOS_TRACE("Entering");

	/* Allocate JID to VE task */
	retval = veos_get_jid(tsk);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get jid");
		VEOS_DEBUG("Failed to allocate memory, return value %ld,"
				" mapped value %d", retval, -EAGAIN);
		retval = -EAGAIN;
		goto hndl_return;
	}
	tsk->jid = retval;
	/* DID is same as JID */
	tsk->did = tsk->jid;

	/* Allocate udma context */
	retval = psm_alloc_udma_context_region(tsk);
	if (retval < 0) {
		VEOS_ERROR("Failed to allocate udma context");
		goto free_jid;
	}

	/* Allocate data for core_dma_desc and initialize it with the core
	 * ID in which the process is going to be scheduled
	 * */
	tsk->core_dma_desc = (int32_t *)malloc(sizeof(int32_t));
	if (!tsk->core_dma_desc) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for DMA descriptor, "
				"return value %d", errno);
		goto free_udma_context;
	}
	memset(tsk->core_dma_desc, -1, sizeof(int32_t));

	/* Initialize ived-poperty */
	tsk->ived_resource = NULL;
	if (veos_init_ived_proc_property(tsk) != 0) {
		VEOS_ERROR("Failed to initialize ived property");
		retval = -EFAULT;
		goto free_core_dma_desc;
	}

	/* Allocated thread_sched_count for thread group */
	tsk->thread_sched_count = (int *)malloc(sizeof(int));
	if (!tsk->thread_sched_count) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for thread scheduling "
				"count, return value %s", strerror(errno));
		goto free_ived;
	}
	memset(tsk->thread_sched_count, 0, sizeof(int));

	/* Allocated thread_sched_bitmap for thread group */
	tsk->thread_sched_bitmap = (uint64_t *)malloc(sizeof(uint64_t));
	if (!tsk->thread_sched_bitmap) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for thread scheduling "
				"bitmap, return value %s", strerror(errno));
		goto free_sched_count;
	}
	memset(tsk->thread_sched_bitmap, 0, sizeof(uint64_t));


	retval = 0;
	goto hndl_return;

free_sched_count:
	free(tsk->thread_sched_count);
	tsk->thread_sched_count = NULL;
free_ived:
	if (veos_clean_ived_proc_property(tsk) != 0) {
		VEOS_ERROR("Failed to claen ived property");
		retval = -EFAULT;
	}
free_core_dma_desc:
	free(tsk->core_dma_desc);
	tsk->core_dma_desc = NULL;
free_udma_context:
	psm_free_udma_context_region(tsk);
free_jid:
	veos_free_jid(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Allocate memory for VE sighand structure.
 *
 * @return pointer to VE sighand structure on success, NULL on failure.
 */
struct sighand_struct *alloc_ve_sighand_struct_node()
{
	int retval = -1;
	struct sighand_struct *p = NULL;

	VEOS_TRACE("Entering");

	p = (struct sighand_struct *)malloc(sizeof(struct sighand_struct));
	if (!p) {
		retval = -errno;
		VEOS_CRIT("Failed to allocate memory for sighand structure "
				"return value %s", strerror(errno));
		errno = -retval;
		goto hndl_return;
	}

	memset(p, '\0', sizeof(struct sighand_struct));
	if (pthread_mutex_init(&(p->siglock), NULL) != 0) {
		VEOS_ERROR("Failed to initialize siglock");
		errno = ENOMEM;
		free(p);
		p = NULL;
		goto hndl_return;
	}

	if (pthread_mutex_init(&(p->del_lock), NULL) != 0) {
		VEOS_ERROR("Failed to initialize thread group delete lock");
		retval = pthread_mutex_destroy(&(p->siglock));
		if (retval != 0) {
			VEOS_ERROR("Failed to destroy siglock,"
					" return value %d", retval);
		}
		errno = ENOMEM;
		free(p);
		p = NULL;
		goto hndl_return;
	}

	p->ref_count = 1;

hndl_return:
	VEOS_TRACE("Exiting");
	return p;
}

/**
 * @brief Handles re-scheduling from one VE Node and Core to another
 * VE node and core.
 *
 * @param[in] old_node_id VE task old Node ID
 * @param[in] old_core_id VE task Old Core ID
 * @param[in] new_node_id VE task new Node ID
 * @param[in] new_core_id VE task new Core ID
 * @param[in] p_ve_task Pointer to VE task to be relocated
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_relocate_ve_task(int old_node_id, int old_core_id,
		int new_node_id, int new_core_id,
		struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	struct ve_core_struct *p_ve_core = NULL;
	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	p_ve_core = p_ve_task->p_ve_core;

	/* Set the task state to WAITING
	* Acquire core lock as we can update number of active task on core */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			WRLOCK, "Failed to acquire core's write lock");
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	if (RUNNING == p_ve_task->ve_task_state) {
		psm_set_task_state(p_ve_task, WAIT);
	}

	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's write lock");

	/* Schedule out the current task from the core */
	if (p_ve_core->curr_ve_task == p_ve_task) {
		VEOS_DEBUG("Scheduling out the "
				"current task from Core %d",
				p_ve_core->core_num);
		psm_find_sched_new_task_on_core(p_ve_core, false,
				false);
	}

	/* If still the relocating task is the current task of the
	 * core, then we need to perform following steps:-
	 * 1. Update current task of core to NULL.
	 * 2. Unassign the task from core.
	 * 3. Perform DMA migration if required .
	 */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
			"Failed to acquire ve core write lock");
	if (p_ve_core->curr_ve_task == p_ve_task) {

		VEOS_DEBUG("Invoke psm_unassign_migrate_task");
		psm_unassign_migrate_task(p_ve_task);

		if (p_ve_task->reg_dirty) {
			VEOS_DEBUG("Get process context");
			psm_save_current_user_context(p_ve_task);
		}
	}
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release ve core lock");

	VEOS_DEBUG("Relocating PID %d from %d:%d to %d:%d",
			p_ve_task->pid,
			old_node_id, old_core_id,
			new_node_id, new_core_id);

	/* Delete VE task from old core/node. Delete first so that PSM does
	 * not have two processes with similar PID at a time.
	 */
	retval = remove_task_from_core_list(old_node_id,
			old_core_id, p_ve_task);
	if (-1 == retval) {
		VEOS_ERROR("Failed to remove PID %d from Core %d",
				p_ve_task->pid, old_core_id);
		goto hndl_return;
	}

	/* Insert task in to the new Node/Core */
	insert_ve_task(new_node_id, new_core_id, p_ve_task);

	/* Update the neccesary fields in VE task struct */
	p_ve_task->node_id = new_node_id;
	p_ve_task->core_id = new_core_id;
	p_ve_task->p_ve_core = VE_CORE(new_node_id, new_core_id);
	p_ve_core = p_ve_task->p_ve_core;

	/* Set the state of task to RUNNING if no exception is
	 * pending for the task or,
	 * the task was to be set RUNNING due to its unblock */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
			"Failed to acquire ve core write lock");
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	if (p_ve_task->ve_task_state != STOP &&
			(p_ve_task->block_status == UNBLOCK_SERVED ||
			 !(p_ve_task->p_ve_thread->EXS & VE_EXCEPTION))
			 && !p_ve_task->rpm_create_task) {
		VEOS_DEBUG("Change state of VE process to RUNNING "
				"after affinity system call");
		psm_set_task_state(p_ve_task, RUNNING);
	} else {
		VEOS_DEBUG("EXS: %d, Task state: %d, p_ve_task->block_status %d",
				(int) p_ve_task->p_ve_thread->EXS,
				p_ve_task->ve_task_state,
				p_ve_task->block_status);

	}
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release ve core lock");
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Finds and print least loaded Node and Core information.
 *
 * @return 0 always success.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_least_loaded_node_n_core(void)
{
	int ve_core_id = -1 , ve_node_id = -1;

	VEOS_TRACE("Entering");
	get_ve_core_n_node_new_ve_proc(&ve_init_task, &ve_node_id, &ve_core_id);
	VEOS_DEBUG("Least Loaded Node: %d Core: %d",
			ve_node_id, ve_core_id);
	VEOS_TRACE("Exiting");
	return 0;
}

/**
 * @brief Searches for the appropriate VE Node and Core for the new VE process.
 *
 * @param[in] p_ve_task Pointer to struct ve_task_struct of VE process
 * @param[in,out] ve_node_id Obtain the appropriate VE node ID
 * @param[in,out] ve_core_id Obtain the appropriate VE core ID
 *
 * @return 0 on success, negative error number on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int get_ve_core_n_node_new_ve_proc(struct ve_task_struct *p_ve_task,
		int *ve_node_id, int *ve_core_id)
{
	int retval = -1;
	/* Per Node */
	int min_proc_num_node = -1;
	int num_proc_node = -1;
	int num_proc_node_min = MAX_TASKS_PER_NODE;

	/* Per Core */
	int min_proc_num_core = -1;
	int num_proc_core = -1;
	int num_proc_core_min = MAX_TASKS_PER_CORE;

	int node_loop = 0, core_loop = 0;

	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");

	if (!p_ve_task || !ve_node_id || !ve_core_id) {
		VEOS_ERROR("Invalid (NULL) argument received");
		goto hndl_return;
	}

	/* node loop
	 * Find Node with Minimum Processes */
	for (; node_loop < MAX_VE_NODE_PER_VH; node_loop++) {
		p_ve_node = VE_NODE(VE_NODE_ID(node_loop));
		if (NULL == p_ve_node) {
			VEOS_ERROR("Node %d struct NULL", node_loop);
			retval = -EFAULT;
			continue;
		}
		VEOS_DEBUG("Number of processes on node %d is %d",
				VE_NODE_ID(node_loop), p_ve_node->num_ve_proc);
		num_proc_node = p_ve_node->num_ve_proc;
		if (num_proc_node < num_proc_node_min) {
			num_proc_node_min = num_proc_node;
			min_proc_num_node = node_loop;
		}
	}

	if (-1 == min_proc_num_node) {
		VEOS_ERROR("All VE resources are busy,"
				" unable to accept new request");
		*ve_node_id = min_proc_num_node;
		*ve_core_id = min_proc_num_core;
		retval = -ENOMEM;
		goto hndl_return;
	}
	*ve_node_id = VE_NODE_ID(min_proc_num_node);
	p_ve_node = VE_NODE(*ve_node_id);
	VEOS_DEBUG("Number of processes on node %d is %d",
			*ve_node_id, p_ve_node->num_ve_proc);

	if ((-1 < *ve_core_id) && (*ve_core_id < p_ve_node->nr_avail_cores)) {
		CPU_ZERO(&(p_ve_task->cpus_allowed));
		CPU_SET(*ve_core_id, &(p_ve_task->cpus_allowed));
		goto skip_get_core_num;
	} else if ((*ve_core_id >= p_ve_node->nr_avail_cores)) {
		VEOS_DEBUG("Invalid core id: %d", *ve_core_id);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* core loop
	 * Find Core with Minimum Processes */
	for (; core_loop < p_ve_node->nr_avail_cores; core_loop++) {
		p_ve_core = VE_CORE(*ve_node_id, core_loop);
		if ((NULL == p_ve_core) ||
				!(CPU_ISSET(core_loop, &(p_ve_task->cpus_allowed)))) {
			VEOS_DEBUG("Core %d not allowed or Core struct is NULL",
					core_loop);
			continue;
		}
		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), RDLOCK,
			"Failed to acquire ve core read lock");
		num_proc_core = p_ve_core->num_ve_proc;
		if (num_proc_core < num_proc_core_min) {
			num_proc_core_min = num_proc_core;
			min_proc_num_core = core_loop;
		}
		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release ve core lock");
	}

	*ve_core_id = min_proc_num_core;
	if (-1 == min_proc_num_core) {
		VEOS_ERROR("All VE resources are busy,"
				" unable to accept new request");
		*ve_node_id = -1;
		retval = -ENOMEM;
		goto hndl_return;
	}

skip_get_core_num:
	retval = 0;
	VEOS_DEBUG("Selected Node %d Core %d",
			*ve_node_id,
			*ve_core_id);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the state of the task as EXITING for process termination.
 *
 * @param[in] task VE task which is to be terminated
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
void set_state(struct ve_task_struct *task)
{
	VEOS_TRACE("Entering");
	if (task == NULL) {
		VEOS_ERROR("Invalid argument received");
		return;
	}
	VEOS_DEBUG("setting exit status of pid %d as %d",
				task->pid, EXITING);
	pthread_mutex_lock_unlock(&task->ref_lock, LOCK,
		"Failed to acquire task reference lock");
	task->exit_status = EXITING;
	pthread_mutex_lock_unlock(&task->ref_lock, UNLOCK,
		"Failed to acquire task reference lock");
	VEOS_TRACE("Exiting");
}

/**
 * @brief Get VE task reference.
 *
 * @param[in] task VE task whose reference count is to be incremented
 *
 * @internal
 * @author PSMG / MP-MT
 */
int get_ve_task_struct(struct ve_task_struct *task)
{
	int retval = -1;
	VEOS_TRACE("Entering");
	if (task == NULL) {
		VEOS_ERROR("Invalid argument received");
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&task->ref_lock, LOCK,
			"Failed to acquire task reference lock");

	if (task->ref_count == -1)
		goto err_handle;
	if (task->exit_status != 0  && task->ve_task_state != ZOMBIE) {
		pthread_mutex_lock_unlock(&task->ref_lock, UNLOCK,
				"Failed to release task reference lock");
		goto hndl_return;
	}
	task->ref_count++;

	pthread_mutex_lock_unlock(&task->ref_lock, UNLOCK,
			"Failed to release task reference lock");

	VEOS_DEBUG("PID:%d :: ref_count(after increment):%d :: exiting flag:%d",
			task->pid, task->ref_count, task->exit_status);
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
err_handle:
	VEOS_FATAL("veos terminating abnormally");
	veos_abort("process %d in inconsistent state", task->pid);
}

/**
 * @brief Put VE task reference.
 *
 *	Function internally invokes cleanup of the task if the exit status
 *	of the process has been marked as EXITING and there is no active
 *	reference corrensponding to it
 *
 * @param[in] task VE task whose reference count is to be decremented
 *
 * @internal
 * @author PSMG / MP-MT
 * @note Invoked by other modules i.e. PTRACE
 */
void put_ve_task_struct(struct ve_task_struct *task)
{
	bool deleting_flag = false;
	VEOS_TRACE("Entering");
	if (task == NULL) {
		VEOS_ERROR("Invalid argument received");
		return;
	}
	if (task->ref_count == 0)
		goto err_handle;
	pthread_mutex_lock_unlock(&task->ref_lock, LOCK,
		"Failed to acquire task reference lock");
	task->ref_count--;
	if (task->ref_count == 0 && task->exit_status == EXITING){
		VEOS_DEBUG("setting exit status of pid %d as %d",
				task->pid, DELETING);
		task->exit_status = DELETING;
		deleting_flag = true;
	}
	VEOS_DEBUG("PID:%d :: ref_count(after decrement):%d :: exiting flag:%d",
			task->pid, task->ref_count, task->exit_status);
	if ((task->ref_count == 1) &&
			(pthread_cond_signal(&task->ref_lock_signal))) {
		veos_abort("pthread_cond_signal failed: %s",
				strerror(errno));
	}
	pthread_mutex_lock_unlock(&task->ref_lock, UNLOCK,
		"Failed to acquire task reference lock");

	if (deleting_flag && task->exit_status == DELETING) {
		if (0 > psm_handle_delete_ve_process(task)) {
			VEOS_DEBUG("Terminating process failed");
		}
	}

	VEOS_TRACE("Exiting");
	return;
err_handle:
	VEOS_FATAL("veos terminating abnormally");
	veos_abort("process %d in inconsistent state", task->pid);
}

/**
 * @brief Finds VE task struct based on input PID and Node/Core values.
 *
 * @param[in] min_node Min Node to start searching from
 * @param[in] max_node Max Node to search till
 * @param[in] min_core Min Core to start searching from
 * @param[in] max_core Max Core to search till
 * @param[in] pid PID of the process to find VE task struct for
 *
 * @return pointer to VE task struct on Success, NULL if VE task is not found.
 *
 * @internal
 * @author PSMG / MP-MT
 * @note Invoked by other modules i.e. PTRACE
 */
struct ve_task_struct *find_ve_task_struct(int pid)
{
	int retval = -1;
	int node_loop = 0, core_loop = 0, max_core = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_task_struct *ve_task_ret = NULL;

	VEOS_TRACE("Entering");
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
	max_core = VE_NODE(0)->nr_avail_cores;

		/* Core loop */
		for (; core_loop < max_core; core_loop++) {
			VEOS_TRACE("Core loop: %d", core_loop);
			p_ve_core = VE_CORE(VE_NODE_ID(node_loop), core_loop);
			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
					RDLOCK,
					"Failed to acquire ve core read lock");
			ve_task_list_head = p_ve_core->ve_task_list;

			ve_task_curr = ve_task_list_head;

			if (NULL == ve_task_curr) {
				VEOS_DEBUG("No task in the list "
						"for Node %d Core %d",
						VE_NODE_ID(node_loop), core_loop);
				pthread_rwlock_lock_unlock(
						&(p_ve_core->ve_core_lock),
						UNLOCK,
						"Failed to release ve core lock");
				continue;
			}
			VEOS_TRACE("Node %d: Core %d "
					"Head is %p "
					"PID(C) = %d "
					"PID(s) = %d",
					VE_NODE_ID(node_loop),
					core_loop,
					ve_task_list_head,
					ve_task_curr->pid,
					pid);
			do {
				if (ve_task_curr->pid == pid) {
					VEOS_DEBUG("FOUND NODE: %d"
							" CORE : %d"
							" TASK : %p"
							" TASK PID : %d",
							VE_NODE_ID(node_loop),
							core_loop,
							ve_task_curr,
							ve_task_curr->pid);

					retval = get_ve_task_struct(ve_task_curr);
					pthread_rwlock_lock_unlock(
						&(p_ve_core->ve_core_lock),
						UNLOCK,
						"Failed to release ve core lock");
					if (0 > retval) {
						VEOS_ERROR("failed to get "
								"task reference: %d",
							pid);
						ve_task_ret = NULL;
						goto hndl_return;
					}
					ve_task_ret = ve_task_curr;
					goto hndl_return;
				}
			} while ((ve_task_list_head != ve_task_curr->next)
					&& (ve_task_curr = ve_task_curr->next));

			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
					UNLOCK,
					"Failed to release ve core lock");
		}
		VEOS_DEBUG("Task with PID : %d not found in Node %d",
							pid,
							VE_NODE_ID(node_loop));

hndl_return:
	VEOS_TRACE("Exiting");
	return ve_task_ret;
}

/**
 * @brief Will set the tid address of the process identified by
 * the pid passed to it.
 *
 * @param[in] pid pid of the process whose tid address is to be set
 * @param[in] tid_addr tid address to be set
 *
 * @return task ID of calling task on success and
 * 		negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t psm_handle_set_tid_addr(pid_t pid, uint64_t tid_addr)
{
	int64_t retval = -1;

	/* find the ve_task_struct for process (pid) */
	struct ve_task_struct *ve_task_curr = NULL;

	VEOS_TRACE("Entering");

	ve_task_curr = find_ve_task_struct(pid);
	if (!ve_task_curr) {
		VEOS_ERROR("Failed to find task structure for PID: %d ", pid);
		retval = -ESRCH;
		goto hndl_return;
	}
	ve_task_curr->clear_child_tid = (int *)tid_addr;

	retval = ve_task_curr->pid;

	put_ve_task_struct(ve_task_curr);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Change the state of the VE process state to RUNNING.
 *
 * @param[in] pid pid of the process whose state is to be changed
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t psm_handle_schedule_ve_process(pid_t pid)
{
	bool invoke_scheduler = false;
	struct ve_task_struct *tsk = NULL;
	int retval = -1;

	VEOS_TRACE("Entering");
	tsk = find_ve_task_struct(pid);

	if (!tsk) {
		VEOS_ERROR("PID %d not found. "
				"SCHEDULE REQ failed", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	pthread_rwlock_lock_unlock(&(tsk->p_ve_core->ve_core_lock),
			WRLOCK,	"Failed to acquire core lock");
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	/* Start time of new VE process/thread is maintained */
	gettimeofday(&(tsk->start_time), NULL);

	if (tsk->parent->ptraced == true &&
			tsk->group_leader == tsk &&
			(tsk->parent->p_ve_ptrace->ptrace_options &
			 (PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK))) {
		tsk->ve_task_state = STOP;
		VEOS_DEBUG("Set state STOP for pid: %d, tracer will"
				" start this process", tsk->pid);
	} else if (tsk->group_leader != tsk &&
			tsk->group_leader->ptraced == true &&
			(tsk->group_leader->p_ve_ptrace->ptrace_options &
			 PTRACE_O_TRACECLONE)) {
		tsk->ve_task_state = STOP;
		VEOS_DEBUG("Set state STOP for pid: %d, tracer will"
				" start this thread", tsk->pid);
	} else {
		if (tsk->ve_task_state == STOP) {
			VEOS_DEBUG("Task: %d state is STOP,"
			" No scheduling", tsk->pid);
		} else {
			psm_set_task_state(tsk, RUNNING);
			if (tsk->p_ve_core->nr_active == 1)
				invoke_scheduler = true;
		}
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(tsk->p_ve_core->ve_core_lock),
				UNLOCK,	"Failed to release core lock");

	if (invoke_scheduler)
		psm_find_sched_new_task_on_core(tsk->p_ve_core,
				false, false);

	put_ve_task_struct(tsk);
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Releases all the resources allocated to a VE process and
 * task struct is not deleted.
 *
 * @param[in] del_task_struct VE process to be release
 *
 * @internal
 * @author PSMG / MP-MT
 */
void clear_ve_task_struct(struct ve_task_struct *del_task_struct)
{
	int node_id = -1, core_id = -1;
	int sig = 1;

	VEOS_TRACE("Entering");
	if (!del_task_struct)
		goto hndl_return;

	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	struct ve_task_struct *del_task_real_parent = NULL;

	node_id = del_task_struct->node_id;
	core_id = del_task_struct->core_id;

	/* During execve(), Change the signal disposition
	 * to default if not ignored.
	 * */
	pthread_mutex_lock_unlock(&(del_task_struct->sighand->siglock), LOCK,
			"failed to acquire signal lock");
	for (; sig <= _NSIG; sig++) {
		if (del_task_struct->sighand->action[sig-1].sa_handler
				!= SIG_IGN)
			del_task_struct->sighand->action[sig - 1].sa_handler
				= SIG_DFL;
	}

	/* execve() removes any existing alternate signal stack
	 * */
	del_task_struct->sas_ss_sp = 0;
	del_task_struct->sas_ss_size = 0;
	pthread_mutex_lock_unlock(&(del_task_struct->sighand->siglock), UNLOCK,
			"failed to release signal lock");

	/* Clean and Re-initialise ived proc property */
	veos_clean_ived_proc_property(del_task_struct);

	del_task_struct->execed_proc = true;

	/* task exit status is set to 0 so that it does not invoke delete
	 * in put_ve_task_struct()
	 */
	del_task_struct->exit_status = 0;

	pthread_rwlock_lock_unlock(&(del_task_struct->p_ve_core->ve_core_lock),
			WRLOCK,	"Failed to acquire core lock");
	/* If state is RUNNING, decrement nr_active */
	if (del_task_struct->ve_task_state == RUNNING)
		ve_atomic_dec(&(del_task_struct->p_ve_core->nr_active));
	del_task_struct->ve_task_state =  WAIT;
	pthread_rwlock_lock_unlock(&(del_task_struct->p_ve_core->ve_core_lock),
			UNLOCK,	"Failed to release core lock");
	/* Acquiring tasklist_lock so that children list of del_task_struct
	 * isn't modified. Could have been done by del_task_struct task lock,
	 * but then Hierarchy would become parent_lock -> child_lock which is
	 * opposite of what we have taken when vforked child wakes up its parent.,
	 * Hierarchy: tasklist_lock -> task_lock
	 */
	VEOS_DEBUG("Acquiring tasklist_lock in PID %d", del_task_struct->pid);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	/* task is execve()-ing, we don't want its vforked child to change state */
	if (!list_empty(&(del_task_struct->children))) {
		list_for_each_safe(p, n, &(del_task_struct->children)) {
			tmp = list_entry(p, struct ve_task_struct,
					siblings);
			VEOS_DEBUG("Found child PID %d", tmp->pid);
			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), LOCK,
					"Failed to acquire task lock");

			VEOS_DEBUG("Acquired task lock for PID %d", tmp->pid);
			if (tmp->ve_task_state == ZOMBIE) {
				pthread_mutex_lock_unlock(
						&(tmp->ve_task_lock), UNLOCK,
						"Failed to release task lock");
				continue;
			}
			if (tmp->real_parent == del_task_struct
					&& tmp->vforked_proc) {
				VEOS_DEBUG("Setting wake_up_parent in child %d false",
						tmp->pid);
				tmp->wake_up_parent = false;
			}

			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), UNLOCK,
					"Failed to release task lock");
		}
	}

	/* If task is vforked child and its parent exists, then wake up
	 * parent. There is no point in waking up exiting parent
	 * As we have acquired task list lock so we can freely access
	 * real parent.
	 */
	if (true == del_task_struct->vforked_proc
			&& del_task_struct->wake_up_parent == true) {
		del_task_real_parent = del_task_struct->real_parent;
		pthread_mutex_lock_unlock(&del_task_real_parent->ref_lock,
				LOCK, "Failed to acquire task reference lock");
		if (del_task_real_parent->exit_status == EXITING
				|| del_task_real_parent->exit_status == DELETING) {
			pthread_mutex_lock_unlock(
					&del_task_real_parent->ref_lock,
					UNLOCK, "Failed to acquire task reference lock");
			VEOS_DEBUG("No need to wake up exiting/deleting parent");
			goto skip_wakeup;
		}
		pthread_mutex_lock_unlock(
				&del_task_real_parent->ref_lock,
				UNLOCK, "Failed to acquire task reference lock");

		VEOS_DEBUG("vforked process execution completed");
		if (del_task_real_parent->core_id != del_task_struct->core_id)
			pthread_rwlock_lock_unlock(
				&(del_task_real_parent->p_ve_core->ve_core_lock),
					WRLOCK,	"Failed to acquire core lock");

		/* If parent process has not served UNBLOCK yet then
		 * do not change task state here let, UNBLOCK request
		 * make the decision.
		 */
		pthread_mutex_lock_unlock(
				&(del_task_real_parent->ve_task_lock), LOCK,
				"Failed to acquire task lock");
		if (del_task_real_parent->ve_task_state != STOP &&
				del_task_real_parent->block_status
					== UNBLOCK_SERVED) {
			VEOS_DEBUG("vforked process waking up parent");
			psm_set_task_state(del_task_real_parent, RUNNING);
		}
		del_task_real_parent->vfork_state = VFORK_COMPLETED;

		pthread_mutex_lock_unlock(
				&(del_task_real_parent->ve_task_lock), UNLOCK,
				"failed to release task lock");
		if (del_task_real_parent->core_id != del_task_struct->core_id)
		pthread_rwlock_lock_unlock(
				&(del_task_real_parent->p_ve_core->ve_core_lock),
				UNLOCK,	"Failed to release core lock");
	}
skip_wakeup:
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist_lock lock");
	pthread_mutex_lock_unlock(&(del_task_struct->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	/* resetting vfork related states */
	del_task_struct->vfork_state = VFORK_C_INVAL;
	del_task_struct->vforked_proc = false;
	del_task_struct->wake_up_parent = false;

	pthread_mutex_lock_unlock(&(del_task_struct->ve_task_lock), UNLOCK,
			"Failed to acquire task lock");

	/* If Task to be deleted is current task, mark the curr_task
	 * as NULL
	 */
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			WRLOCK, "Failed to acquire ve core write lock");
	if (del_task_struct == VE_CORE(node_id, core_id)->curr_ve_task) {
		if (del_task_struct->reg_dirty) {
			VEOS_DEBUG("Get process context");
			psm_save_current_user_context(del_task_struct);
		}

		VEOS_DEBUG("Invoking psm_unassign_migrate_task");
		psm_unassign_migrate_task(del_task_struct);
		del_task_struct->reg_dirty = false;
	}
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			UNLOCK,	"Failed to release ve core lock");

	/* freeing cr data*/
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->thread_group_mm_lock,
		LOCK, "Failed to acquire mm-thread-group-lock");
	__amm_del_mm_struct(del_task_struct);

	/* allocate the new memory structure */
	__amm_alloc_mm_struct(&(del_task_struct->p_ve_mm));
	pthread_mutex_lock_unlock(&del_task_struct->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release mm-thread-group-lock");
	veos_init_ived_proc_property(del_task_struct);

	/* Re-initialise udma_context */
	memset(del_task_struct->udma_context, 0, sizeof(struct ve_udma));

	/* Free the LHM/SHM area */
	shmdt((void *)del_task_struct->sighand->lshm_addr);

hndl_return:
	VEOS_TRACE("Exiting");
}

/**
 * @brief Convert long value to comp_t.
 *
 * @param[in] val Long value to convert
 *
 * @internal
 * @author PSMG / Process management
 */
static comp_t veos_encode_comp_t(unsigned long val)
{
	comp_t exp, rnd;

	exp = rnd = 0;
	while (val > MAXFRACT) {
		rnd = val & (1 << (EXPSIZE - 1));     /* Round up? */
		val >>= EXPSIZE;      /* Base 8 exponent == 3 bit shift. */
		exp++;
	}

	/* If we need to round up, do it (and handle overflow correctly).
	*/
	if (rnd && (++val > MAXFRACT)) {
		val >>= EXPSIZE;
		exp++;
	}

	exp <<= MANTSIZE;	/* Shift the exponent into place */
	exp += val;		/* and add on the mantissa. */
	return exp;
}

/**
 * @brief Dump the accounting information of struct ve_acct in a
 * accounting file.
 *
 * @param[in] tsk Pointer to VE task struct
 *
 * @internal
 * @author PSMG / Process management
 */
void veos_acct_ve_proc(struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct = NULL;
	struct ve_acct acct_info = {0};
	struct timeval now = {0};
	int retval = -1;

	VEOS_TRACE("Entering");
	if (!tsk)
		goto hndl_return;

	pacct = &(tsk->sighand->pacct);
	memset(&acct_info, 0, sizeof(struct ve_acct));

	acct_info.ac_flag = (char)(pacct->ac_flag);

	/* Always set to VE_ACCT_VERSION | ACCT_BYTEORDER */
	acct_info.ac_version = VE_ACCT_VERSION | ACCT_BYTEORDER;

	/* task exit code passed to the exit system call */
	acct_info.ac_exitcode = pacct->ac_exitcode;

	/* Real user ID */
	acct_info.ac_uid = tsk->uid;

	/*Real group ID*/
	acct_info.ac_gid = tsk->gid;

	/*Process ID*/
	acct_info.ac_pid = tsk->pid;

	/* Parent process ID*/
	acct_info.ac_ppid = tsk->parent->pid;

	/* process creation time */
	acct_info.ac_btime = tsk->start_time.tv_sec +
			tsk->start_time.tv_usec/MICRO_SECONDS;

	/* elapsed time from process creation to termination */
	gettimeofday(&now, NULL);
	acct_info.ac_etime = (timeval_diff(now, tsk->start_time))/USECOND;

	/* In VE stime of process would be zero */
	acct_info.ac_stime = 0;

	/* Time spend by the process while scheduled on VE core */
	acct_info.ac_utime = veos_encode_comp_t(pacct->ac_utime/USECOND);

	/* Average memory usage (kB) */
	acct_info.ac_mem = veos_encode_comp_t(pacct->ac_mem);

	/* Command name of the program */
	strncpy(acct_info.ac_comm, tsk->ve_comm, sizeof(tsk->ve_comm));

	/* Write struct ve_acct to file */
	retval = write(veos_acct.fd, (char *)&acct_info,
			sizeof(struct ve_acct));
	if (-1 == retval) {
		VEOS_ERROR("Failed to write in accounting file");
		VEOS_DEBUG("Writing in accounting file failed due to: %s",
				strerror(errno));
	}

	VEOS_DEBUG("Data is successfully dumped in accounting file: %s",
			veos_acct.file);
hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Collect accounting information into pacct_struct.
 *
 * @param[in] exit_code task exit code
 * @param[in] tsk Pointer to VE task struct
 *
 * @internal
 * @author PSMG / Process management
 */
void psm_acct_collect(int exit_code, struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct = NULL;
	VEOS_TRACE("Entering");
	if (!tsk)
		goto hndl_return;

	pacct = &(tsk->sighand->pacct);

	/* status of the process when it terminated */
	if (tsk->flags & PF_FORKNOEXEC)
		pacct->ac_flag |= AFORK;
	if (tsk->flags & PF_SIGNALED)
		pacct->ac_flag |= AXSIG;
	if (tsk->flags & PF_DUMPCORE)
		pacct->ac_flag |= ACORE;

	/* Time spend by the process while scheduled on VE core */
	pacct->ac_utime += tsk->exec_time;

	/* In case of thread group */
	if (tsk->group_leader == tsk) {
		pacct->ac_mem += amm_get_rss_in_kb(tsk->p_ve_mm);
		pacct->ac_exitcode = exit_code;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Handle's NEW VE PROC request from pseudo process such request is
 * sent from pseudo process in case pseudo invoked ve_exec
 *
 * @param[in] pti Pointer to thread arg for Worker Thread
 * @param[in] ve_core_id VE Core Id recevied from Pseudo
 * @param[in] ve_node_id VE Node Id recevied from Pseudo
 * @param[in] pid PID of the Pseudo Process
 * @param[in] exe_name VE process exe command name
 * @param[in] traced VE process traced flag
 * @param[in] tracer_pid VE process tracer pid
 * @param[in] vaddr VE process shared memory address
 * @param[in] shmid VE process shared memory identifier
 * @param[in] ve_lim VE rlimit structure address recieved
 * from pseudo
 * @param[in] gid VE GID recieved from pseudo
 * @param[in] uid VE UID recieved from pseudo
 * @param[in] rpm_task_create flag of rpm task
 * @param[in] exe_path path of pseudo process
 *
 * @return 0 on success , negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_exec_ve_process(struct veos_thread_arg *pti,
				int *ve_core_id,
				int *ve_node_id,
				int pid,
				char *exe_name,
				bool traced,
				pid_t tracer_pid,
				uint64_t vaddr,
				int shmid,
				struct rlimit *velim,
				uint64_t gid,
				uint64_t uid,
				bool rpm_task_create,
				char *exe_path)
{
	int retval = -1, ret = -1;
	int core_loop = 0;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");

	if (!pti || !ve_core_id || !ve_node_id) {
		retval = -EINVAL;
		VEOS_ERROR("Invalid (NULL) argument received");
		goto hndl_return;
	}

	/* Allocate memory for VE task structure */
	tsk = alloc_ve_task_struct_node();
	if (!tsk) {
		retval = -errno;
		VEOS_ERROR("Failed to allocate memory for Task Structure");
		goto hndl_return;
	}

	/* Allocate memory for VE thread structure */
	tsk->p_ve_thread = alloc_ve_thread_struct_node();
	if (!tsk->p_ve_thread) {
		retval = -errno;
		VEOS_ERROR("Failed to allocate memory for Thread Structure");
		goto free_tsk;
	}

	tsk->group_leader = tsk;

	/* Allocate memory for VE MM structure */
	retval = amm_alloc_mm_struct(&(tsk->p_ve_mm));
	if (0 > retval) {
		VEOS_ERROR("Failed to allocate memory for mm structure");
		goto free_thread;
	}
	/* Allocate memory for VE sighand structure */
	tsk->sighand = alloc_ve_sighand_struct_node();
	if (!tsk->sighand) {
		retval = -errno;
		VEOS_ERROR("Failed to allocate sighand structure");
		VEOS_DEBUG("Failed to allocate sighand structure, return "
				"value %d", retval);
		goto free_mm;
	}

	/* Initialize CPU MASK of the task */
	for (; core_loop < VE_NODE(0)->nr_avail_cores ; core_loop++) {
		CPU_SET(core_loop, &(tsk->cpus_allowed));
	}

	/* Populate ve_task_struct */
	strncpy(tsk->ve_comm, exe_name, ACCT_COMM);
	strncpy(tsk->ve_exec_path, exe_path, PATH_MAX);
	tsk->pid = pid;
	tsk->priority = VE_DEF_SCHED_PRIORITY;
	tsk->sched_class = 0;
	tsk->ve_task_state = WAIT;
	tsk->exit_signal = 0;
	tsk->tgid = tsk->pid;
	tsk->sas_ss_sp = 0;
	tsk->sas_ss_size = 0;
	tsk->syncsignal = 0;
	tsk->policy = SCHED_OTHER;
	tsk->rt_priority = 0;
	tsk->flags = 0;
	tsk->ptraced = traced;
	tsk->p_ve_ptrace = NULL;
	tsk->atb_dirty = false;
	tsk->crd_dirty = false;
	tsk->reg_dirty = false;
	tsk->usr_reg_dirty = false;
	tsk->gid = gid;
	tsk->uid = uid;
	tsk->is_crt_drv = false;
	tsk->is_dlt_drv = false;
	tsk->cpu_lim_exceed = false;
	tsk->ref_count = 0;
	tsk->exit_status = 0;
	tsk->exit_code = 0;
	tsk->exit_code_set = false;
	tsk->thread_execed = false;
	tsk->assign_task_flag = TSK_UNASSIGN;
	/* Allocate time slice to VE task, however when scheduled
	 * this value will be initialised again. We are initializing it
	 * so that it does not contain any junk value. */
	tsk->time_slice = veos_time_slice;

	if (!rpm_task_create)
		memcpy(tsk->sighand->rlim, velim, sizeof(tsk->sighand->rlim));

	/* Parent of VE pocess created from
	 * "ve_exec" is INIT ve task */
	tsk->parent = &ve_init_task;

	tsk->offset = 0;
	tsk->sr_context_bitmap = 0;
	tsk->exec_time = 0;
	tsk->execed_proc = false;
	tsk->rpm_preserve_task = 0;
	tsk->rpm_create_task = rpm_task_create;
	sprintf(tsk->p_ve_mm->dma_dump_file, "/tmp/dma_dump_file%d", pid);

	/* Initialize children/sibling/tasks list */
	INIT_LIST_HEAD(&tsk->children);
	INIT_LIST_HEAD(&tsk->siblings);
	INIT_LIST_HEAD(&tsk->thread_group);
	INIT_LIST_HEAD(&tsk->tasks);
	ve_init_sigpending(&tsk->pending);
	sigemptyset(&tsk->blocked);

	/* Every VE process is thread group leader */
	tsk->group_leader = tsk;

	/* Flag to handle vforked VE process */
	tsk->vfork_state = VFORK_C_INVAL;
	tsk->vforked_proc = false;
	tsk->wake_up_parent = false;

	/* Initialize block_status with BLOCK_RECVD, so that
	 * this process can be scheduled successfully after it
	 * is scheduled for the  first time by the scheduler.
	 * */
	tsk->block_status = BLOCK_RECVD;

	/*CR dump file name*/
	sprintf(tsk->p_ve_mm->cr_dump_fname,
			"/tmp/cr_dump_task_%d", tsk->pid);

	if (0 != pthread_mutex_init(&(tsk->ve_task_lock), NULL)) {
		VEOS_ERROR("Intialising task lock failed");
		retval = -ENOMEM;
		goto free_cr_data;
	}

	if (0 != pthread_mutex_init(&(tsk->ref_lock), NULL)) {
		VEOS_ERROR("Intialising lock failed");
		retval = -ENOMEM;
		goto destroy_mutex_1;
	}

	/* Allocate memory for VE task data */
	retval = alloc_ve_task_data(tsk);
	if (0 > retval) {
		VEOS_ERROR("Failed to allocate memory for task data");
		goto destroy_mutex_2;
	}

	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), LOCK,
			"Failed to acquire VE node mutex lock");

	retval = get_ve_core_n_node_new_ve_proc(tsk, ve_node_id, ve_core_id);
	if (retval < 0) {
		VEOS_ERROR("Searching for Node/Core for task failed");
		pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), UNLOCK,
				"Failed to release VE node mutex lock");
		goto free_dma_data;
	}

	/* Insert VE task list for Node and Core task list */
	insert_ve_task(*ve_node_id, *ve_core_id, tsk);

	tsk->node_id = *ve_node_id;
	tsk->core_id = *ve_core_id;
	tsk->p_ve_core = VE_CORE(*ve_node_id, *ve_core_id);

	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), UNLOCK,
			"Failed to release VE node mutex lock");

	VEOS_DEBUG("Creating NEW VE Process on NODE : %d"
			"CORE : %d for PID : %d",
			*ve_node_id, *ve_core_id, pid);

	/* Create VE process structure at driver server */
	if (0 > vedl_create_ve_task(VE_NODE(0)->handle, pid)) {
		VEOS_ERROR("Failed to create task in driver");
		VEOS_DEBUG("Failed to create task in driver, return value "
				"%d, mapped value %d", -errno, -ENOMEM);
		retval = -ENOMEM;
		goto remove_from_core;
	}

	/* task created on driver, set flag to true */
	tsk->is_crt_drv = true;

	/* Insert the task in it's parent's children list */
	VEOS_DEBUG("Acquiring tasklist_lock in PID %d", tsk->pid);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	list_add_tail(&tsk->siblings, &tsk->parent->children);

	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist_lock lock");

	VEOS_DEBUG("Inserting pid: %d of core: %d to init list",
				pid, *ve_core_id);
	/* Insert an entry for this task in INIT tasks list */
	pthread_rwlock_lock_unlock(&init_task_lock, WRLOCK,
			"Failed to acquire init_task write lock");
	list_add_tail(&tsk->tasks, &ve_init_task.tasks);
	pthread_rwlock_lock_unlock(&init_task_lock, UNLOCK,
		"Failed to release init_task lock");

	/* Get SHM/LHM area */
	if (!rpm_task_create) {
		tsk->sighand->lshm_addr = (uint64_t)shmat(shmid, NULL, 0);
		if ((void *)-1 == (void *)tsk->sighand->lshm_addr) {
			VEOS_ERROR("Failed to attach shared memory");
			VEOS_DEBUG("Failed to attach shared memory, return "
					"value %d, mapped value %d",
					-errno, -EFAULT);
			retval = -EFAULT;
			goto delete_ve_task;
		}

		/* Saving shmid in task struct to be used by vforked child */
		tsk->lshmid = shmid;

		/* Store the SHM/LHM address of pseudo process
		 * in mm_struct.
		 */
		tsk->p_ve_mm->shm_lhm_addr = vaddr;
		VEOS_DEBUG("SHM/LHM address %lx of pid %d",
				vaddr, tsk->pid);

		tsk->p_ve_mm->shm_lhm_addr_vhsaa = vedl_get_dma_address(VE_HANDLE(0),
				(void *)(tsk->p_ve_mm->shm_lhm_addr),
				tsk->pid, 1, 0, 0);
		if ((uint64_t)-1 == (tsk->p_ve_mm->shm_lhm_addr_vhsaa)) {
			VEOS_ERROR("VHVA->VHSAA conversion failed for %p",
					(void *)vaddr);
			retval = -EFAULT;
			goto delete_ve_task;
		}
		VEOS_DEBUG("Virtual address: %lx Physical address: %lx",
				tsk->p_ve_mm->shm_lhm_addr,
				tsk->p_ve_mm->shm_lhm_addr_vhsaa);
	}

	if (0 != pthread_mutex_init(&(tsk->ptrace_lock), NULL)) {
		VEOS_ERROR("Failed to initialise ptrace lock");
		retval = -EFAULT;
		goto delete_ve_task;
	}

	/* Setup VE process tracing information */
	if (traced == true) {
		retval = psm_attach_ve_process(tsk, tracer_pid,
				pti->cred.uid, pti->cred.gid, false);
		if (0 > retval) {
			VEOS_ERROR("Failed to ATTACH process with pid: %d",
					tsk->pid);
			VEOS_DEBUG("Failed to ATTACH process, return value %d, "
					"mapped value %d", retval , -EFAULT);
			retval = -EFAULT;
			goto delete_ve_task;
		}
		VEOS_DEBUG("PID: %d is now attached", tsk->pid);
	}
        /* Initialize conditional signal lock */
        retval = pthread_cond_init(&(tsk->ref_lock_signal), NULL);
        if (retval != 0) {
		VEOS_ERROR("Initialising conditional signal failed %s",
				strerror(retval));
		retval = -EFAULT;
		goto delete_ve_task;
        }

	VE_NODE(*ve_node_id)->total_forks++;
	retval = 0;
	goto hndl_return;

remove_from_core:
	remove_task_from_core_list(tsk->node_id, tsk->core_id,
			tsk);
free_dma_data:
	if (veos_clean_ived_proc_property(tsk) != 0)
		VEOS_ERROR("Failed to clean ived property");
	free(tsk->core_dma_desc);
	psm_free_udma_context_region(tsk);
	veos_free_jid(tsk);
destroy_mutex_2:
       ret = pthread_mutex_destroy(&(tsk->ref_lock));
       if (ret != 0) {
               VEOS_ERROR("Failed to destroy ref lock");
               VEOS_DEBUG("Failed to destroy ref lock, return value "
                               "%d", -ret);
       }
destroy_mutex_1:
	ret = pthread_mutex_destroy(&(tsk->ve_task_lock));
	if (ret != 0) {
		VEOS_ERROR("Failed to destroy task lock");
		VEOS_DEBUG("Failed to destroy task lock, return value "
				"%d", -ret);
	}
free_cr_data:
	amm_free_cr_data(tsk->p_ve_mm);
	free(tsk->sighand);
free_mm:
	free(tsk->p_ve_mm);
free_thread:
	free(tsk->p_ve_thread);
free_tsk:
	free(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
delete_ve_task:
	if (0 > psm_handle_delete_ve_process(tsk))
		VEOS_ERROR("Failed to delete new task");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles START VE request from Pseudo Process.
 *
 * @param[in] pti Pointer to thread arg for Worker Thread
 * @param[in] pid PID of the VE process
 *
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_start_ve_request(struct veos_thread_arg *pti, int pid)
{
	int retval = -1;
	struct ve_start_ve_req_cmd start_ve_req = { {0} };
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		retval = -EINVAL;
		goto hndl_return;
	}

	memcpy(&start_ve_req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			sizeof(struct ve_start_ve_req_cmd));

	VEOS_DEBUG("IC:%lx\tSP:%lx\tSZ:%lx",
			start_ve_req.context_info.IC,
			start_ve_req.context_info.SP,
			start_ve_req.context_info.SZ);

	/* Fetch the respective task_struct from the list */
	tsk = find_ve_task_struct(pid);
	if (!tsk) {
		VEOS_ERROR("Failed to fetch the task structure");
		VEOS_DEBUG("Failed to fetch task structure for PID: %d", pid);
		retval = -EINVAL;
		goto hndl_return;
	} else {
		/* update thread struct */
		if (update_ve_thread_node(&start_ve_req.context_info,
				tsk->p_ve_thread) != 0) {
			VEOS_ERROR("Failed to update thread structure");
			retval = -EINVAL;
			put_ve_task_struct(tsk);
			goto hndl_return;
		}
	}

	tsk->p_ve_mm->start_brk = start_ve_req.ve_info.heap_start;
	tsk->p_ve_mm->brk = start_ve_req.ve_info.heap_top;
	tsk->p_ve_mm->start_code = start_ve_req.start_code;
	tsk->p_ve_mm->end_code = start_ve_req.end_code;
	tsk->p_ve_mm->start_data = start_ve_req.start_data;
	tsk->p_ve_mm->end_data = start_ve_req.end_data;
	tsk->p_ve_mm->start_stack = start_ve_req.ve_info.stack_bottom;
	tsk->p_ve_mm->argc = start_ve_req.argc;
	tsk->p_ve_mm->argv_addr = start_ve_req.argv_addr;
	tsk->p_ve_mm->argv_size = start_ve_req.argv_size;
	tsk->p_ve_mm->auxv_addr = start_ve_req.auxv_addr;
	tsk->p_ve_mm->auxv_size = start_ve_req.auxv_size;
	tsk->p_ve_mm->pgsz = start_ve_req.pgsz;

	pthread_rwlock_lock_unlock
		(&(tsk->p_ve_core->ve_core_lock), WRLOCK,
		"Failed to acquire core lock");
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
		"Failed to acquire task lock");

	/* Start time of new VE process is maintained */
	retval = gettimeofday(&(tsk->start_time), NULL);
	if (0 != retval) {
		retval = -errno;
		VEOS_ERROR("Failed to get the time");
		goto hndl_return1;
	}

	if (tsk->ptraced == true) {
		tsk->ve_task_state = STOP;
		VEOS_DEBUG("Set state STOP for pid: %d, tracer will"
				" start this process", tsk->pid);
	} else
		psm_set_task_state(tsk, RUNNING);

hndl_return1:
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");
	pthread_rwlock_lock_unlock
			(&(tsk->p_ve_core->ve_core_lock),
			UNLOCK,	"Failed to release core lock");

	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Removes the task from the core list.
 *
 * @param[in] ve_node_id Node ID of the task
 * @param[in] ve_core_id Core ID of the task
 * @param[in] p_rm_task Pointer to ve_task_struct of VE process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int remove_task_from_core_list(int ve_node_id, int ve_core_id,
		struct ve_task_struct *p_rm_task)
{
	int retval = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;
	VEOS_TRACE("Entering");

	/* take lock before Updating Core task list */
	pthread_rwlock_lock_unlock(
			&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
			WRLOCK,
			"Failed to acquire ve core write lock");

	if (NULL == p_rm_task) {
		VEOS_ERROR("Task to be removed is NULL");
		goto hndl_return;
	}

	VEOS_DEBUG("Remove task %d from Node %d Core %d"
			"Core Pointer %p",
			p_rm_task->pid,
			ve_node_id,
			ve_core_id,
			VE_CORE(ve_node_id, ve_core_id));

	/* Core data structure should not be NULL*/
	ve_task_list_head = VE_CORE(ve_node_id, ve_core_id)->ve_task_list;

	if (NULL == ve_task_list_head) {
		VEOS_ERROR("Head task of Core "
				"is NULL, Task to be removed 0x%p",
				p_rm_task);
		goto hndl_return;
	}

	if (p_rm_task == ve_task_list_head &&
			ve_task_list_head->next == ve_task_list_head) {
		VE_CORE(ve_node_id, ve_core_id)->ve_task_list = NULL;
		goto hndl_return1;
	}

	temp = p_rm_task->next;
	while (temp->next != p_rm_task)
		temp = temp->next;

	temp->next = p_rm_task->next;
	if (p_rm_task == ve_task_list_head) {
		VE_CORE(ve_node_id, ve_core_id)->ve_task_list =
			ve_task_list_head->next;
		VEOS_DEBUG("Now Head is %p", ve_task_list_head);
	}

hndl_return1:
	p_rm_task->next = NULL;
	ve_atomic_dec(&(VE_NODE(ve_node_id)->num_ve_proc));
	ve_atomic_dec(&(VE_CORE(ve_node_id, ve_core_id)->num_ve_proc));
	retval = 0;
hndl_return:
	/* release lock for Core task list */
	pthread_rwlock_lock_unlock(
			&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
			UNLOCK,
			"Failed to release ve core lock");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Inserts VE task to the VE node and VE core list.
 *
 * @param[in] ve_node_id VE Node ID for the task
 * @param[in] ve_core_id VE Core ID for the task
 * @param[in] p_ve_task Pointer to VE task structure
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int insert_ve_task(int ve_node_id, int ve_core_id,
		struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;

	VEOS_TRACE("Entering");

	if (!p_ve_task) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	VEOS_DEBUG("Node %d Core %d Core Pointer %p",
			ve_node_id,
			ve_core_id,
			VE_CORE(ve_node_id, ve_core_id));

	/* take lock before Updating Core task list */
	pthread_rwlock_lock_unlock(
		&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
		WRLOCK,
		"Failed to acquire ve core write lock");

	/* Core data structure should not be NULL*/
	ve_task_list_head = VE_CORE(ve_node_id, ve_core_id)->ve_task_list;

	VEOS_DEBUG("ve_task_list_head : %p", ve_task_list_head);

	/* Create HEAD node*/
	if (NULL == ve_task_list_head) {
		VEOS_DEBUG(":%d:%d VE task list INIT",
				ve_node_id, ve_core_id);
		ve_task_list_head = p_ve_task;
		ve_task_list_head->next = ve_task_list_head;
	} else if (ve_task_list_head->next == ve_task_list_head) {
		/* Create second node */
		ve_task_list_head->next = p_ve_task;
		p_ve_task->next = ve_task_list_head;
	} else {
		/* Insert the node at the last */
		temp = ve_task_list_head->next;
		while (temp->next != ve_task_list_head)
			temp = temp->next;

		p_ve_task->next = temp->next;
		temp->next = p_ve_task;
	}

	/* Update HEAD of the Core list */
	VE_CORE(ve_node_id, ve_core_id)->ve_task_list = ve_task_list_head;
	ve_atomic_inc(&(VE_CORE(ve_node_id, ve_core_id)->num_ve_proc));

	pthread_mutex_lock_unlock(&VE_NODE(ve_node_id)->stop_mtx, LOCK,
		"Failed to acquire VE node stop mutex lock");

	ve_atomic_inc(&(VE_NODE(ve_node_id)->num_ve_proc));

	/* wake up the thread which handles SIGSTOP signal */
	VEOS_DEBUG("Signal wake up of stopping thread");
	if (VE_NODE(ve_node_id)->num_ve_proc == 1)
		if (pthread_cond_signal(&VE_NODE(ve_node_id)->stop_cond)) {
			VEOS_ERROR("Failed to signal on condition variable");
			goto abort;
		}

	pthread_mutex_lock_unlock(&VE_NODE(ve_node_id)->stop_mtx, UNLOCK,
		"Failed to release VE node stop mutex lock");

	/* relaese lock for Core task list */
	pthread_rwlock_lock_unlock(
		&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock),
		UNLOCK,
		"Failed to release ve core lock");

	VEOS_DEBUG("Now Head for Core %d is %p Inserted PID %d",
			ve_core_id,
			ve_task_list_head,
			p_ve_task->pid);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
abort:
	veos_abort("Failed to wake up stopping thread");
}

/**
 * @brief List over all the Nodes and Core to print all task
 * currently with veos.
 *
 * @internal
 * @author PSMG / Process management
 */
void list_ve_proc(void)
{
	int core_loop = 0;
	int node_loop = 0;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_task_struct *p_ve_task = NULL;
	struct ve_task_struct *temp = NULL;

	VEOS_TRACE("Entering");
	for (; node_loop < MAX_VE_NODE_PER_VH; node_loop++) {
		p_ve_node = VE_NODE(VE_NODE_ID(node_loop));
		if (NULL == p_ve_node) {
			VEOS_ERROR("BUG Node ID %d struct is NULL",
					VE_NODE_ID(node_loop));
			continue;
		}
		VEOS_DEBUG("L:Number of processes on Core %d is %d",
				VE_NODE_ID(node_loop), p_ve_node->num_ve_proc);
		if (0 == p_ve_node->num_ve_proc)
			continue;
		for (; core_loop < p_ve_node->nr_avail_cores; core_loop++) {
			p_ve_core = p_ve_node->p_ve_core[core_loop];
			if (NULL == p_ve_core) {
				VEOS_ERROR("BUG core_id %d struct is NULL",
						core_loop);
				continue;
			}
			VEOS_DEBUG("Number of Processes on Core %d is %d",
					core_loop, p_ve_core->num_ve_proc);
			pthread_rwlock_lock_unlock(
					&(VE_CORE(VE_NODE_ID(node_loop),
							core_loop)->ve_core_lock),
					RDLOCK,
					"Failed to acquire ve core read lock");
			p_ve_task = p_ve_core->ve_task_list;
			if (NULL == p_ve_task) {
				VEOS_DEBUG("LIST : No TASK for Node %d Core %d",
						VE_NODE_ID(node_loop), core_loop);
				pthread_rwlock_lock_unlock(
						&(VE_CORE(VE_NODE_ID(node_loop),
								core_loop)->ve_core_lock),
						UNLOCK,
						"Failed to release ve core lock");
				continue;
			} else if (p_ve_task->next == p_ve_task) {
				VEOS_DEBUG("LIST:%d:%d, HEAD = %p, PID = %d, STATE = %d"
						, VE_NODE_ID(node_loop), core_loop
						, p_ve_task, p_ve_task->pid
						, p_ve_task->ve_task_state);

			} else {
				VEOS_DEBUG("LIST:%d:%d, HEAD = %p, PID = %d, STATE = %d"
						, VE_NODE_ID(node_loop), core_loop
						, p_ve_task, p_ve_task->pid
						, p_ve_task->ve_task_state);

				temp = p_ve_task->next;
				while (temp != p_ve_task) {
					VEOS_DEBUG("LIST:%d:%d, NODE = %p, "
							"PID = %d, STATE = %d"
							, VE_NODE_ID(node_loop)
							, core_loop
							, temp, temp->pid
							, temp->ve_task_state);
					temp = temp->next;
				}
				VEOS_DEBUG("LIST : END for "
						"Node %d Core %d",
						VE_NODE_ID(node_loop),
						core_loop);
			}
			pthread_rwlock_lock_unlock(
					&(VE_CORE(VE_NODE_ID(node_loop),
							core_loop)->ve_core_lock),
					UNLOCK,
					"Failed to release ve core lock");
		}
		core_loop = 0;
	}
	VEOS_TRACE("Entering");
}

/**
 * @brief Handles BLOCK request for a VE Process when it's corresponding
 * Pseudo Process is about to execute a blocking system call on VH Host.
 *
 * @param[in] pid PID of the process requesting BLOCK
 *
 * @return 0 on success, -1 or -errno on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_handle_block_request(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	reg_t regdata = 0;
	int retval = 0;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Handling BLOCK REQ for PID %d", pid);

	tsk = find_ve_task_struct(pid);
	if (!tsk) {
		VEOS_ERROR("Task with PID %d not found"
				"while handling block request",
				pid);
		retval = -ESRCH;
		goto hndl_return;
	}
	p_ve_core = VE_CORE(tsk->node_id, tsk->core_id);

	/* Set the task state to WAITING */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			WRLOCK, "Failed to acquire core's write lock");
	VEOS_DEBUG("Acquired core's write lock");
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	VEOS_DEBUG("Acquired task lock for PID %d", tsk->pid);

	tsk->block_status = BLOCK_RECVD;
	if (STOP == tsk->ve_task_state) {
		/* We can't change the task state to WAIT as some STOPPING
		 * SIGNAL has changed the task state to STOP */
		VEOS_DEBUG("VE process state set to STOP,"
				"task state cannot be set to WAIT");
	} else {
		psm_set_task_state(tsk, WAIT);
		VEOS_DEBUG("State set to WAIT for pid %d", pid);
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	/* #1084: If "tsk" is current task on core then invoke psm_halt_ve_core(),
	 * this will set software state of core to STOP forcefully
	 * This has been added to ensure that core's software and hardware
	 * state are in sync
	 * */
	if (p_ve_core->nr_active == 0 || (p_ve_core->curr_ve_task == tsk)) {
		/* Halt core specially added for correct
		 * CPU busy time update */
		psm_halt_ve_core(0, p_ve_core->core_num, &regdata, false);

		if (p_ve_core->nr_active == 0) {
			pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
				UNLOCK, "Failed to release ve core lock");
			goto hndl_return1;
		}
	}

	/* Skip scheduling if current task on core is not
	 * same as the task serving the block request
	 * */
	if (p_ve_core->curr_ve_task != tsk) {
		VEOS_DEBUG("Skip Scheduling from BLOCK");
		pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
				"Failed to release ve core lock");
		goto hndl_return1;
	}

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release ve core lock");

	/* Scheduling a new VE process on VE core as current
	 * VE process has generated MONC */
	VEOS_DEBUG("SCHEDULING NEW PROCESS"
			" after block on Core %d",
			p_ve_core->core_num);
	psm_find_sched_new_task_on_core(p_ve_core, false, false);

hndl_return1:
	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles UN BLOCK request for a VE Process when it has executed
 * its blocking system call on VH Host.
 *
 * @param[in] pid PID of the process requesting UNBLOCK
 * @param[in] is_blk Determine unblock from blocking/non-blocking call
 * @param[in] sys_trace Determine start process or not at unblock
 *
 * @return 0 on success, -1 or -errno on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_handle_un_block_request(struct ve_task_struct *tsk,
					bool is_blk, bool sys_trace)
{
	struct ve_core_struct *p_ve_core = NULL;
	bool schedule_current = false;
	int retval = 0;
	pid_t pid = -1;

	VEOS_TRACE("Entering");
	if (!tsk) {
		VEOS_ERROR("Task not found while handling unblock request");
		retval = -ESRCH;
		goto hndl_return;
	}

	pid = tsk->pid;

	VEOS_DEBUG("Handling UNBLOCK REQ for PID %d", pid);

	p_ve_core = tsk->p_ve_core;

	/* sem_wait on core semaphor to ensure that VE task is scheduled
	 * from unblock request
	 * */
	do {
		if (-1 == sem_wait(&p_ve_core->core_sem)) {
			if (errno == EINTR) {
				VEOS_DEBUG("Failed to acquire core lock");
				continue;
			} else {
				VEOS_DEBUG("Core %d semaphore try lock"
						" failed with errno: %d",
						p_ve_core->core_num, errno);
				VEOS_ERROR("Failed to acquire core lock");
				retval = -ESRCH;
				goto hndl_return;
			}
		} else {
			break;
		}
	} while(1);

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			WRLOCK, "Failed to acquire core's write lock");
	VEOS_DEBUG("Acquired core's write lock");
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	if (VFORK_ONGOING == tsk->vfork_state) {
		VEOS_DEBUG("vforked child is executing, "
				"task state not changed");
	} else if (sys_trace && tsk->ptraced && tsk->p_ve_ptrace &&
			tsk->p_ve_ptrace->syscall_trace) {
		VEOS_DEBUG("Syscall tracing is enabled, tracer will"
				" start this process");
	} else if (STOP == tsk->ve_task_state) {
		/* As task state is STOP therefore even if system call request
		 * is served VE task state cannot be switched to RUNNING
		 * */
		tsk->block_status = UNBLOCK_SERVED;
		VEOS_DEBUG("VE process state set to STOP,"
				"task state cannot be set to RUNNING");
	} else if (is_blk == false) {
		/* As UNBLOCK REQUEST for non-blocking system call is
		 * arrived therfore "schedule_current" flag for scheduler
		 * invocation is set to true.
		 * Also VE task state will be set to RUNNING
		 * */
		schedule_current = true;
		VEOS_DEBUG("Set task state to "
				"RUNNING for pid %d", pid);
		psm_set_task_state(tsk, RUNNING);
	} else if (WAIT == tsk->ve_task_state) {
		VEOS_DEBUG("Set task state to "
				"RUNNING for pid %d", pid);
		psm_set_task_state(tsk, RUNNING);
	}

	tsk->block_status = UNBLOCK_SERVED;

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	if (p_ve_core->nr_active == 1)
		schedule_current = true;

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
			"Failed to release ve core lock");

	/* Scheduling a new VE process on VE core as current
	 * VE process have generated MONC
	 * */
	if (schedule_current && p_ve_core->curr_ve_task == tsk) {
		VEOS_DEBUG("Scheduling Current Process"
				" after unblock on Core %d",
				p_ve_core->core_num);
		psm_find_sched_new_task_on_core(p_ve_core, false,
				schedule_current);
	} else {
		/* Release semaphor lock */
		sem_post(&p_ve_core->core_sem);
	}
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Prints the PID of all the VE processes starting
 * from the veos INIT VE process.
 *
 * @param[in] ve_tsk INIT's ve_task_struct
 *
 * @internal
 * @author PSMG / Process management
 */
void print_process_tree(struct ve_task_struct *ve_tsk)
{
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	static int cnt;
	int cnt2;

	if (!ve_tsk)
		return;

	cnt2 = cnt;
	while (cnt2) {
		fprintf(stdout, "\t");
		cnt2--;
	}

	fprintf(stdout, "PID %d\n", ve_tsk->pid);
	if (list_empty(&ve_tsk->children))
		return;

	list_for_each_safe(p, n, &ve_tsk->children) {
		tmp = list_entry(p,
				struct ve_task_struct,
				siblings);
		cnt++;
		print_process_tree(tmp);
		cnt--;
	}
}

/**
 * @brief Traverse INIT task list.
 *
 * @internal
 * @author PSMG / Process management
 */
void list_init_tasks(void)
{
	struct list_head *p, *n;

	fprintf(stdout, "PID : %d\n", ve_init_task.pid);
	list_for_each_safe(p, n, &ve_init_task.tasks) {
		struct ve_task_struct *tmp =
			list_entry(p,
					struct ve_task_struct,
					tasks);
		fprintf(stdout, "PID : %d\n", tmp->pid);

	}
}

/**
 * @brief Calucates the total time that VE process exectued on VE core,
 * flag determines 0 for perticular thread and 1 for process group.
 *
 * @param[in] tsk Pointer to struct ve_task_struct
 * @param[in] flag flag detemines for thread or thread group
 *
 * @return execution time of VE process on success, 0 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
uint64_t get_ve_proc_exec_time(struct ve_task_struct *tsk, int flag)
{
	uint64_t total_time = 0;
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	struct ve_task_struct *group_leader = NULL;

	VEOS_TRACE("Entering");
	if (!tsk)
		goto hndl_return;

	group_leader = tsk->group_leader;

	VEOS_DEBUG("Acquiring thread_group_mm_lock lock");
	pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");

	if (flag) {
		VEOS_DEBUG("Process with PID %d execution time(microsec) %lu",
				group_leader->pid, group_leader->exec_time);
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
		} else {
			VEOS_DEBUG("No running threads exist");
		}
	} else {
		total_time = tsk->exec_time;
	}

	pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to released thread-group-mm-lock");

hndl_return:
	VEOS_TRACE("Exiting");
	return total_time;
}

/**
 * @brief Calculates the total time taken by VE process/thread on VE core.
 *
 * @param[in] tsk Pointer to struct ve_task_struct
 * @param[in] flag Flag determines process or thread
 *		0 for thread
 *		1 for process
 * @param[out] tp Pointer to struct timespec contain time to fill
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_clk_cputime_request(struct ve_task_struct *tsk,
		int flag, struct timespec *tp)
{
	int retval = -1;
	uint64_t total_time = 0;
	VEOS_TRACE("Entering");

	if (!tsk || !tp) {
		VEOS_ERROR("NULL argument recieved");
		retval = -EFAULT;
		goto hndl_return;
	}

	memset(tp, 0, sizeof(struct timespec));

	total_time = get_ve_proc_exec_time(tsk, flag);

	/* Converting to nanoseconds */
	total_time *= 1000;

	tp->tv_sec = total_time/SECS_TO_NANOSECONDS;
	tp->tv_nsec = total_time%SECS_TO_NANOSECONDS;

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the specefied resource limit of the VE process.
 *
 * @param[in] caller_pid Pid of caller process
 * @param[in] tsk Pointer to VE task struct
 * @param[in] resource Resource information to get
 * @param[out] rlim Pointer to struct rlim to fill resource value
 * @param[in] caller_uid uid of caller process
 * @param[in] caller_gid gid of caller process
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_rlimit_request(int caller_pid,
		struct ve_task_struct *tsk,
		int resource, struct rlimit *rlim,
		uid_t caller_uid, gid_t caller_gid)
{
	int retval = -1;
	struct rlimit *proc_rlim = NULL;
	proc_t ve_proc_info = {0};

	VEOS_TRACE("Entering");
	if (!tsk || !rlim) {
		VEOS_ERROR("NULL argument received");
		retval = -EFAULT;
		goto hndl_return;
	}

	if (caller_pid == tsk->pid) {
		VEOS_DEBUG("Caller: %d, getting capability for: %d",
				caller_pid, tsk->pid);
		goto get_resource;
	}
	/* Get the information of /proc/## for the given pid */
	retval = psm_get_ve_proc_info(tsk->pid, &ve_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* UID/GID checking of caller and VE process:
	 * Check if caller pid and ve pid are from same user, if so, directly
	 * get the rlimit.
	 */
	if (caller_uid == ve_proc_info.euid &&
			caller_uid == ve_proc_info.suid &&
			caller_uid == ve_proc_info.ruid &&
			caller_gid == ve_proc_info.egid &&
			caller_gid == ve_proc_info.sgid &&
			caller_gid == ve_proc_info.rgid) {
		VEOS_DEBUG("Caller process: %d and Current process: "
				"%d belongs to same user",
				caller_pid, tsk->pid);
		goto get_resource;
	}

       if (!check_ve_proc_capability(caller_pid, CAP_SYS_RESOURCE)) {
	       retval = -EPERM;
	       goto hndl_return;
       }

get_resource:
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
		"Failed to acquire task lock");
	proc_rlim = tsk->sighand->rlim + resource;
	*rlim = *proc_rlim;
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");

	VEOS_DEBUG("Get Resource: %d, rlim_cur: %ld, rlim_max: %ld",
			resource, rlim->rlim_cur, rlim->rlim_max);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the specefied resource limit of the VE process.
 *
 * @param[in] caller_pid Pid of caller process
 * @param[in] tsk Pointer to VE task struct
 * @param[in] resource Resource information to set
 * @param[in] rlim VE process resource value to update with
 * @param[in] caller_uid uid of caller process
 * @param[in] caller_gid gid of caller process
 *
 * @return 0 on success, negative value on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_set_rlimit_request(int caller_pid,
		struct ve_task_struct *tsk, int resource,
		struct rlimit rlim, uid_t caller_uid, gid_t caller_gid)
{
	int retval = -1;
	struct rlimit *proc_rlim = NULL;
	proc_t ve_proc_info = {0};

	VEOS_TRACE("Entering");

	if (!tsk) {
		VEOS_ERROR("NULL argument recieved");
		retval = -EFAULT;
		goto hndl_return;
	}

	if (rlim.rlim_cur > rlim.rlim_max) {
		retval = -EINVAL;
		VEOS_ERROR("soft limit is greater than hard limit");
		goto hndl_return;
	}

	if (resource >= RLIM_NLIMITS) {
		retval = -EINVAL;
		VEOS_ERROR("Invalid resource");
		goto hndl_return;
	}
	/* Get the information of /proc/## for the given pid */
	retval = psm_get_ve_proc_info(tsk->pid, &ve_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		retval = -EFAULT;
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(tsk->sighand->siglock), LOCK,
		"Failed to acquire task sighand lock");
	proc_rlim = tsk->sighand->rlim + resource;


	if (rlim.rlim_max > proc_rlim->rlim_max)
		goto check_capability;
	/* UID/GID checking of caller and VE process:
	 * Check if caller pid and ve pid are from same user, if so, directly
	 * update the rlimit.
	 */
	if (caller_uid == ve_proc_info.euid &&
			caller_uid == ve_proc_info.suid &&
			caller_uid == ve_proc_info.ruid &&
			caller_gid == ve_proc_info.egid &&
			caller_gid == ve_proc_info.sgid &&
			caller_gid == ve_proc_info.rgid) {
		VEOS_DEBUG("Caller process: %d and Current process: "
				"%d belongs to same user",
				caller_pid, tsk->pid);
		goto update_rlim;
	}

	if (caller_pid != tsk->pid) {
		VEOS_DEBUG("Caller: %d, setting capability for: %d",
				caller_pid, tsk->pid);
		goto check_capability;
	}

check_capability:
	/*
	 * checking does caller having a CAP_SYS_RESOURCE
	 * capability.
	 */
	if (!check_ve_proc_capability(caller_pid, CAP_SYS_RESOURCE)) {
		retval = -EPERM;
		pthread_mutex_lock_unlock(&(tsk->sighand->siglock), UNLOCK,
				"Failed to release task sighand lock");
		goto hndl_return;
	}
update_rlim:
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
		"Failed to acquire task lock");
	*proc_rlim = rlim;
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");

	pthread_mutex_lock_unlock(&(tsk->sighand->siglock), UNLOCK,
			"Failed to release task sighand lock");
	VEOS_DEBUG("Set Resource :%d rlim_cur:%ld rlim_max:%ld",
			resource, proc_rlim->rlim_cur, proc_rlim->rlim_max);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Provide the CPU affinity value for the VE process.
 *
 * @param[in] pid PID of the VE process
 * @param[in] cpusetsize Size of cpu mask
 *
 * @return affinity mask of VE process on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t psm_handle_getaffinity_request(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
{
	int64_t retval = -1;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Handling getaffinity request for PID %d", pid);

	if ((cpusetsize * BITS_PER_BYTE) < VE_NODE(0)->nr_avail_cores) {
		retval = -EINVAL;
		goto hndl_return;
	}

	if (cpusetsize & (sizeof(unsigned long)-1)) {
		retval = -EINVAL;
		goto hndl_return;
	}
	tsk = find_ve_task_struct(pid);
	if (!tsk) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
		"Failed to acquire task lock");
	memcpy(mask, &(tsk->cpus_allowed), cpusetsize);
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");

	put_ve_task_struct(tsk);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sets the CPU affinity value for the VE process.
 *
 * @param[in] caller PID of the caller process
 * @param[in] pid PID of the VE process
 * @param[in] mask cpu mask to set
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t psm_handle_setaffinity_request(pid_t caller, pid_t pid, cpu_set_t mask)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_task_struct *caller_tsk = NULL;
	int core_id = -1;
	int node_id = -1;
	int64_t retval = -1;
	proc_t ve_proc_info = {0};
	proc_t caller_proc_info = {0};
	cpu_set_t old_mask;
	CPU_ZERO(&old_mask);

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Handling set affinity request for PID %d", pid);

	tsk = find_ve_task_struct(pid);
	if (!tsk) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto hndl_return;
	}
	memset(&ve_proc_info, 0, sizeof(proc_t));
	retval = psm_get_ve_proc_info(pid, &ve_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				pid);
		retval = -EFAULT;
		goto hndl_return1;
	}
	memset(&caller_proc_info, 0, sizeof(proc_t));
	retval = psm_get_ve_proc_info(caller, &caller_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for Caller pid: %d",
				caller);
		retval = -EFAULT;
		goto hndl_return1;
	}
	/* Check if caller pid and ve pid are from same user, if so, directly
	 * update the affinity.
	 */
	if (caller_proc_info.euid  == ve_proc_info.euid ||
			caller_proc_info.euid == ve_proc_info.ruid) {
		VEOS_DEBUG("Caller process: %d and Current process: "
				"%d belongs to same user",
				caller, pid);
		goto set_affinity;
	}

	caller_tsk = find_ve_task_struct(caller);
	/* RPM commands can also set affinity, so the caller may or may not
	 * be the VE process.
	 *
	 * If caller is not the VE process then we need to check CAP_SYS_NICE
	 * capability.
	 */
	if (!caller_tsk) {
		VEOS_ERROR("Task of Caller PID %d not found", caller);
	}

	/* VEOS allows a VE thread to set affinity of a thread of
	 * the same process.
	 */
	if (caller_tsk && caller_tsk->group_leader == tsk->group_leader) {
		VEOS_DEBUG("PID: %d and PID: %d belongs to same thread group",
				caller_tsk->pid, tsk->pid);
		goto set_affinity;
	}

	/* checking does caller having a CAP_SYS_NICE
	 * capability.
	 */
	if (!check_ve_proc_capability(caller, CAP_SYS_NICE)) {
		retval = -EPERM;
		goto hndl_return1;
	}

set_affinity:
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	old_mask = tsk->cpus_allowed;
	tsk->cpus_allowed = mask;
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	/* check that after updating the affinity VE process
	 * need to relocate or not.
	 */
	if (!(CPU_ISSET(tsk->core_id, &(tsk->cpus_allowed)))) {
		retval = get_ve_core_n_node_new_ve_proc(tsk, &node_id,
				&core_id);
		if (retval < 0) {
			VEOS_ERROR("Failed to get Core/Node id");
			VEOS_DEBUG("Getting VE Node and Core returned %ld", retval);
			retval = -EINVAL;
			pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
					"Failed to acquire task lock");
			tsk->cpus_allowed = old_mask;
			pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
					"Failed to release task lock");
			goto hndl_return1;
		}
		psm_relocate_ve_task(tsk->node_id, tsk->core_id, node_id,
			core_id, tsk);
	}
	retval = 0;

hndl_return1:
	if (caller != pid && caller_tsk)
		put_ve_task_struct(caller_tsk);
	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Obtains and fills the VE process resource usage in struct ve_rusage.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[in] who resource usage measures for who
 * @param[out] ve_r Pointer to struct ve_rusage to fill
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_rusage_request(struct ve_task_struct *tsk,
		int who, struct ve_rusage *ve_r)
{
	int retval = -1;
	uint64_t total_time;

	VEOS_TRACE("Entering");

	if (!tsk || !ve_r)
		goto hndl_return;

	if (who == RUSAGE_SELF) {
		total_time = get_ve_proc_exec_time(tsk, 1);
		ve_r->ru_utime.tv_sec = total_time/1000000;
		ve_r->ru_utime.tv_usec = total_time%1000000;
	} else if (who == RUSAGE_THREAD) {
		total_time = get_ve_proc_exec_time(tsk, 0);
		ve_r->ru_utime.tv_sec = total_time/1000000;
		ve_r->ru_utime.tv_usec = total_time%1000000;
	} else if (who == RUSAGE_CHILDREN) {
		total_time = tsk->sighand->cexec_time;
		ve_r->ru_utime.tv_sec = total_time/1000000;
		ve_r->ru_utime.tv_usec = total_time%1000000;
	} else
		goto hndl_return;

	/*
	 * For RUSAGE_CHILDREN, RSS of the largest child,
	 * not the maximum resident set size of the process tree.
	 */
	retval = veos_getrusage(who, ve_r, tsk);
	if (retval < 0) {
		VEOS_ERROR("rusage request failed");
		goto hndl_return;
	}

	ve_r->nvcsw = tsk->nvcsw;
	ve_r->nivcsw = tsk->nivcsw;

	VEOS_DEBUG("Max RSS: %ld CPU time (%ld sec %ld microsec)"
			"ru_nvcsw %ld ru_nivcsw %ld",
			ve_r->ru_maxrss,
			ve_r->ru_utime.tv_sec,
			ve_r->ru_utime.tv_usec,
			ve_r->nvcsw,
			ve_r->nivcsw);
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Populate the values in struct sysinfo maintained in VEOS.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[out] ve_sysinfo Pointer to struct sysinfo to populate
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_sysinfo_request(struct ve_task_struct *tsk,
		struct sysinfo *ve_sysinfo)
{
	int retval = -1;
	struct timeval now = {0};
	double av_1 = 0, av_5 = 0, av_15 = 0;
	struct ve_node_struct *p_ve_node = NULL;

	VEOS_TRACE("Entering");
	if (!tsk || !ve_sysinfo) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	p_ve_node = VE_NODE(tsk->node_id);

	retval = calc_last_1_5_15_load(p_ve_node, &av_1, &av_5, &av_15);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get load on VE");
		goto hndl_return;
	}

	gettimeofday(&now, NULL);
	/* VE node boot time */
	ve_sysinfo->uptime = ((now.tv_sec * MICRO_SECONDS) + now.tv_usec) -
		p_ve_node->node_boot_time;

	/* Convert micro seconds to seconds */
	ve_sysinfo->uptime /= MICRO_SECONDS;

	/* Number of current processes*/
	ve_sysinfo->procs = p_ve_node->num_ve_proc;

	VEOS_DEBUG("uptime: %lu procs: %d",
			ve_sysinfo->uptime,
			ve_sysinfo->procs);

	ve_sysinfo->loads[0] =
		(unsigned long)(av_1 * (float)(1 << SI_LOAD_SHIFT));
	ve_sysinfo->loads[1] =
		(unsigned long)(av_5 * (float)(1 << SI_LOAD_SHIFT));
	ve_sysinfo->loads[2] =
		(unsigned long)(av_15 * (float)(1 << SI_LOAD_SHIFT));

	VEOS_DEBUG("Load 1min: %lu, 5min: %lu, 15min: %lu",
			ve_sysinfo->loads[0],
			ve_sysinfo->loads[1],
			ve_sysinfo->loads[2]);
	veos_sysinfo(tsk->node_id, ve_sysinfo);

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Enable/disable process accounting.
 *
 * @param[in] file_name Filename to append accouting detail
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_do_acct_ve(char *file_name)
{
	int retval = -1;
	int fd = -1;

	VEOS_TRACE("Entering");
	/* Disable previous accounting */
	pthread_mutex_lock_unlock(&(veos_acct.ve_acct_lock), LOCK,
		"Failed to acquire task accounting lock");
	veos_acct.active = false;
	if (NULL != veos_acct.file) {
		free(veos_acct.file);
		veos_acct.file = NULL;
	}
	if (0 < veos_acct.fd) {
		close(veos_acct.fd);
		veos_acct.fd = -1;
	}

	/* Case to disable accounting */
	if (NULL == file_name) {
		retval = 0;
		goto hndl_return;
	}

	/* Enable accounting */
	fd = open(file_name, O_WRONLY|O_APPEND|O_LARGEFILE, 0);
	if (-1 == fd) {
		retval = -errno;
		VEOS_ERROR("VEOS failed to open accounting file: %s",
				file_name);
		goto hndl_return;
	}

	veos_acct.active = true;
	veos_acct.fd = fd;
	veos_acct.file = file_name;
	VEOS_DEBUG("VE Accounting File: %s", veos_acct.file);

	retval = 0;
hndl_return:
	pthread_mutex_lock_unlock(&(veos_acct.ve_acct_lock), UNLOCK,
		"Failed to release task accounting lock");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief set value to s/w user registers and update bitmap
 * register value.
 *
 * @param[in] tsk pointer to current task struct
 * @param[in] regid register ID
 * @param[in] regval register value to be set
 * @param[in] mask Bit mask for updating register.
 *
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 * @note Invoked by other modules i.e. PTRACE
 */
int psm_handle_set_reg_req(struct ve_task_struct *tsk, usr_reg_name_t regid,
				reg_t regval, int64_t mask)
{
	int retval = -1;
	reg_t old_regval = 0;
	int node_id = -1, core_id = -1;
	struct ve_core_struct *p_ve_core = NULL;
	bool sync_reg = false;

	VEOS_TRACE("Entering");

	node_id = tsk->node_id;
	core_id = tsk->core_id;
	p_ve_core = VE_CORE(node_id, core_id);

	VEOS_DEBUG("Reg: %d New Regval: %lx Mask: %lx",
			regid, regval, mask);

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			RDLOCK, "Failed to acquire core's read lock");
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	/* Current task on core latest register value is required */
	if (p_ve_core->curr_ve_task == tsk &&
			tsk->reg_dirty &&
			mask != USER_REG_MASK)
		sync_reg = true;

	if (regid == PSW) {
		if (sync_reg && !GET_BIT(tsk->pmr_context_bitmap, 0)) {
			VEOS_DEBUG("Getting PSW from Core: %d", core_id);
			retval = vedl_get_usr_reg(VE_HANDLE(node_id),
					VE_CORE_USR_REG_ADDR(node_id, core_id),
					PSW,
					&(tsk->p_ve_thread->PSW));
			if (retval) {
				VEOS_ERROR("Failed to get user registers");
				VEOS_DEBUG("Failed to get user registers, "
						"return value %d, mapped "
						"value %d", -retval, -EFAULT);
				retval = -EFAULT;
				goto hndl_ret;
			}
		}
		old_regval = tsk->p_ve_thread->PSW;
		regval = (old_regval & (~mask)) | (regval & mask);
		tsk->p_ve_thread->PSW = regval;
		SET_BIT(tsk->pmr_context_bitmap, 0);
		retval = 0;
		goto hndl_ret;
	}
	if (regid == PMMR) {
		if (sync_reg && !GET_BIT(tsk->pmr_context_bitmap, 1)) {
			VEOS_DEBUG("Getting PMMR from Core: %d", core_id);
			retval = vedl_get_usr_reg(VE_HANDLE(node_id),
					VE_CORE_USR_REG_ADDR(node_id, core_id),
					PMMR,
					&(tsk->p_ve_thread->PMMR));
			if (retval) {
				VEOS_ERROR("Failed to get user registers, "
						"return value %d", retval);
				VEOS_DEBUG("Failed to get user registers, "
						"return value %d, mapped "
						"value %d", -retval, -EFAULT);
				retval = -EFAULT;
				goto hndl_ret;
			}
		}
		old_regval = tsk->p_ve_thread->PMMR;
		regval = (old_regval & (~mask)) | (regval & mask);
		tsk->p_ve_thread->PMMR = regval;
		SET_BIT(tsk->pmr_context_bitmap, 1);
		retval = 0;
		goto hndl_ret;
	}
	if ((regid >= SR00) && (regid <= SR63)) {
		/* In scaler register mask will be always USER_REG_MASK,
		 * so we dont need the latest register value from core.
		 */
		old_regval = tsk->p_ve_thread->SR[regid - SR00];
		regval = (old_regval & (~mask)) | (regval & mask);
		tsk->p_ve_thread->SR[regid - SR00] = regval;
		SET_BIT(tsk->sr_context_bitmap, (regid - SR00));
		retval = 0;
		goto hndl_ret;
	}
	if ((regid >= PMCR00) &&  (regid <= PMCR03)) {
		if (sync_reg && !GET_BIT(tsk->pmr_context_bitmap,
					((regid - PMCR00) + 2))) {
			VEOS_DEBUG("Getting PMCR0%d from Core: %d",
					regid - PMCR00, core_id);
			retval = vedl_get_usr_reg(VE_HANDLE(node_id),
					VE_CORE_USR_REG_ADDR(node_id, core_id),
					regid,
					&(tsk->p_ve_thread->PMCR[regid - PMCR00]));
			if (retval) {
				VEOS_ERROR("Failed to get user registers "
						"return value %d", retval);
				VEOS_DEBUG("Failed to get user registers, "
						"return value %d, mapped "
						"value %d", -retval, -EFAULT);
				retval = -EFAULT;
				goto hndl_ret;
			}
		}
		old_regval = tsk->p_ve_thread->PMCR[regid - PMCR00];
		regval = (old_regval & (~mask)) | (regval & mask);
		tsk->p_ve_thread->PMCR[regid - PMCR00] = regval;
		SET_BIT(tsk->pmr_context_bitmap, ((regid - PMCR00) + 2));
		retval = 0;
		goto hndl_ret;
	}
	if ((regid >= PMC00) && (regid <= PMC15)) {
		if (sync_reg && !GET_BIT(tsk->pmr_context_bitmap,
					((regid - PMC00) + 6))) {
			VEOS_DEBUG("Getting PMC%d from Core: %d",
					regid - PMC00, core_id);
			retval = vedl_get_usr_reg(VE_HANDLE(node_id),
					VE_CORE_USR_REG_ADDR(node_id, core_id),
					regid,
					&(tsk->p_ve_thread->PMC[regid - PMC00]));
			if (retval) {
				VEOS_ERROR("Failed to get user registers "
						"return value %d", retval);
				VEOS_DEBUG("Failed to get user registers, "
						"return value %d, mapped "
						"value %d", -retval, -EFAULT);
				retval = -EFAULT;
				goto hndl_ret;
			}
		}
		old_regval = tsk->p_ve_thread->PMC[regid - PMC00];
		regval = (old_regval & (~mask)) | (regval & mask);
		tsk->p_ve_thread->PMC[regid - PMC00] = regval;
		SET_BIT(tsk->pmr_context_bitmap, ((regid - PMC00) + 6));
		retval = 0;
		goto hndl_ret;
	}
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's read lock");

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");

	VEOS_ERROR("Failed to handle pseudo process request: "
			"unmatched register");
	return retval;
hndl_ret:
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's read lock");

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
		"Failed to release task lock");
	VEOS_TRACE("Exiting");
	return retval;
}
