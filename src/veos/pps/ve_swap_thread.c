/**
 * Copyright (C) 2019-2020 NEC Corporation
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
 * @file ve_swap_thread.c
 * @brief PPS swap-thread functions in VEOS
 */

#include <stdio.h>
#include <stdlib.h>
#include <log4c.h>
#include <pthread.h>
#include "ve_swap.h"
#include "veos.h"
#include "locking_handler.h"
#include "mm_common.h"
#include "task_mgmt.h"
#include "task_signal.h"
#include "buddy.h"

/**
 * @brief Get status and sub-status of threads
 *
 * If the status and sub-status of child threads are the same as leader thread,
 * returen the status and sub-status, else return -1
 *
 * @param [in] ve_task Pointer to the task structure
 * @param [out] state Pointer to the status
 * @param [out] sstatus Pointer to the sub-status
 *
 * @retval None
 */
static void
get_all_threads_status_substatus(struct ve_task_struct *ve_task,
					int *state, int *sstatus)
{
	struct list_head *p = NULL, *n = NULL;
	struct ve_task_struct *group_leader = NULL, *tmp = NULL;
	int leader_state = 0;
	int leader_sstatus = 0;
	int ret_state = 0;
	int ret_sstatus = 0;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	group_leader = ve_task->group_leader;

	/* Get status and sub-status of leader thread */
	leader_state = group_leader->ve_task_state;
	leader_sstatus = group_leader->sstatus;

	/* Get status and sub-status of child threads */
	list_for_each_safe(p, n, &group_leader->thread_group) {
		tmp = list_entry(p, struct ve_task_struct, thread_group);
		/* ZOMBIE is allowed as child thread's state, */
		if ((tmp->ve_task_state == STOP) &&
					(leader_state == ZOMBIE)) {
			ret_state = tmp->ve_task_state;
			ret_sstatus = tmp->sstatus;
			goto hndl_return;
		} else if ((tmp->ve_task_state != leader_state) &&
					(tmp->ve_task_state != ZOMBIE)) {
			ret_state = P_INVAL;
			goto hndl_return;
		} else if (tmp->sstatus != leader_sstatus) {
			ret_sstatus = -1;
			goto hndl_return;
		}
	}

	ret_state = leader_state;
	ret_sstatus = leader_sstatus;

hndl_return:
	*state = ret_state;
	*sstatus = ret_sstatus;

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Delete all swap request information within swap request queue
 * @param [in] vnode Pointer to the node structure
 *
 * @retval None
 */
static void
del_all_swap_request_information(struct ve_node_struct *vnode)
{
	struct list_head *p = NULL, *n = NULL;
	struct veos_swap_request_info *tmp = NULL;
	struct ve_task_struct *ve_task = NULL;
	struct ve_ipc_sync *ipc_sync;
	int i;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	list_for_each_safe(p, n, &vnode->swap_request_pids_queue) {
		tmp = list_entry(p, struct veos_swap_request_info, swap_info);
		for (i = 0; tmp->pid_array[i] != PPS_END_OF_PIDS; i++) {
			ve_task = find_ve_task_struct(tmp->pid_array[i]);
			ipc_sync = tmp->ipc_sync_array[i];
			if (ve_task == NULL) {
				PPS_DEBUG(cat_os_pps,
					"VE task with %d not found",
					tmp->pid_array[i]);
				continue;
			};
			ve_swap_in_finish(ipc_sync);
			ve_put_ipc_sync(ipc_sync);
			put_ve_task_struct(ve_task);
		}
		list_del(p);
		free(p);
	}
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Delete the swap request which is handling
 * @param [in] request Pointer to the swap request
 * @param [in] num number of handling pid within swap request
 *
 * @retval None
 */
void
del_doing_swap_request(struct veos_swap_request_info *request)
{
	int i;
	struct ve_task_struct *ve_task = NULL;
	struct ve_ipc_sync *ipc_sync = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	for (i = 0; request->pid_array[i] != PPS_END_OF_PIDS; i++) {
		ve_task = find_ve_task_struct(request->pid_array[i]);
		ipc_sync = request->ipc_sync_array[i];
		if (ve_task == NULL) {
			PPS_DEBUG(cat_os_pps, "VE task with %d not found",
					request->pid_array[i]);
			continue;
		}

		ve_swap_in_finish(ipc_sync);
		put_ve_task_struct(ve_task);
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}


/**
 * @brief check swapin or swapout requeset in swap_request_pids_queue
 *
 * @param [in] Which process(swapin or swapout) want to check
 * @retval 0 swapin or swapout request is exist
 * @retval -1  swapin or swapout request is none exist
 */
int 
check_swap_out_in_process(int swap_status)
{
	int i;
	pid_t pid;
	int status, sub_status;
	struct list_head *p = NULL, *n = NULL;
	struct veos_swap_request_info *tmp = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_task_struct *ve_task = NULL;
	int ret = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	list_for_each_safe(p, n, &vnode->swap_request_pids_queue) {
		tmp = list_entry(p, struct veos_swap_request_info, swap_info);
		for (i = 0; (tmp->pid_array[i] != PPS_END_OF_PIDS)
					&& (tmp->pid_array[i] != 0); i++) {
			pid = tmp->pid_array[i];
			ve_task = find_ve_task_struct(pid);
			if (ve_task == NULL) {
				PPS_DEBUG(cat_os_pps, "VE task with %d not found", pid);
				continue;
			}
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			veos_operate_all_ve_task_lock(ve_task->group_leader,
							LOCK);
			get_all_threads_status_substatus(ve_task,
							&status, &sub_status);
			veos_operate_all_ve_task_lock(
					ve_task->group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				UNLOCK, "Failed to release thread_group_mm_lock");
			if (sub_status == swap_status) {
				ret = 0;
				put_ve_task_struct(ve_task);
				goto hndl_return;
			}
			put_ve_task_struct(ve_task);
		}
	}
hndl_return :
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return ret;
}

/**
 * @brief ve_swap_thread of process exit
 * @param[in] ipc_sync Pointer to ve_ipc_sync structure related to process
 *                     which is going to be swapped-out.
 *                     Caller must ensure that this argument isn't NULL.
 *
 * @param[in] task VE task whose reference count is to be decremented
 * @retval None
 */
static void
ve_swap_thread_process_exit(struct ve_ipc_sync *ipc_sync,
				struct ve_task_struct *ve_task)
{
	
	PPS_TRACE(cat_os_pps, "In %s", __func__);
	ve_swap_in_finish(ipc_sync);
	ve_put_ipc_sync(ipc_sync);

	if(ve_task != NULL)
		put_ve_task_struct(ve_task);

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Start_routine of "swap_thread"
 * @param [in] arg Not used
 *
 * @retval None
 */
void
*ve_swap_thread(void *arg)
{
	int i, k;
	int ret = -1;
	int status, sub_status;
	int swapin_pids_idx[MAX_SWAP_PROCESS];
	int swapin_pids_num = 0;
	pid_t pid;
	struct list_head *p = NULL, *n = NULL;
	struct veos_swap_request_info *tmp = NULL;
	struct ve_task_struct *ve_task = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_ipc_sync *ipc_sync;
	bool swapin_retry_flag = false;
	bool swapout_retry_flag = false;
	bool swapin_interrupt = false;
	bool is_need_tail = false;
	bool need_unlock_request = true;
	int swapin_flag = 0;
	size_t node_swapped_sz = 0;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

hndl_start:
	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
			LOCK, "Failed to aqcuire swap_request lock");
	/* Check whether VEOS is terminating */
	if (terminate_flag == REQUIRED)
		goto hndl_exit;

	node_swapped_sz = 0;
	if (list_empty(&vnode->swap_request_pids_queue)) {
		if (vnode->pps_file.is_opened) {
			pthread_mutex_lock_unlock(&(vnode->pps_file_lock), LOCK,
					"Failed to aqcuire pps_file_lock");
			if (vnode->pps_buf_size > 0) {
				pthread_mutex_lock_unlock(
					&(vnode->pps_mp->buddy_mempool_lock),
					LOCK,
					"Failed to acquire PPS buddy lock");
			}
			pthread_mutex_lock_unlock(
				&(vnode->pps_file_offset->buddy_mempool_lock),
				LOCK,
				"Failed to acquire PPS file buddy lock");
			for (i = 0; i < vnode->numa_count; i++) {
				node_swapped_sz += vnode->pps_mp_used[i];
				node_swapped_sz += vnode->pps_file_used[i];
			}
			if ((node_swapped_sz == 0)) {
				vnode->pps_file.not_del_after_swapin = false;
				/* Release the lock so that the VEOS command works 
				 * even if it stops at the file closing process. */
				pthread_mutex_lock_unlock(
					&(vnode->pps_file_offset->buddy_mempool_lock),
					UNLOCK,
					"Failed to release PPS file buddy lock");
				if (vnode->pps_buf_size > 0) {
					pthread_mutex_lock_unlock(
					&(vnode->pps_mp->buddy_mempool_lock),
					UNLOCK,
					"Failed to release PPS buddy lock");
				}
				pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
					UNLOCK,
					"Failed to release swap_request lock");
				veos_del_pps_file(vnode);
				pthread_mutex_lock_unlock(&(vnode->pps_file_lock), UNLOCK,
					"Failed to release pps_file_lock");
				/* After closing processing, execute swap thread processing
				 * again. Because pthread_cond_broadcase() may have been 
				 * issued by unlocking. */
				goto hndl_start;
			}
			pthread_mutex_lock_unlock(
				&(vnode->pps_file_offset->buddy_mempool_lock),
				UNLOCK,
				"Failed to release PPS file buddy lock");
			if (vnode->pps_buf_size > 0) {
				pthread_mutex_lock_unlock(
					&(vnode->pps_mp->buddy_mempool_lock),
					UNLOCK,
					"Failed to release PPS buddy lock");
			}
			pthread_mutex_lock_unlock(&(vnode->pps_file_lock), UNLOCK,
					"Failed to release pps_file_lock");
		}

		pthread_cond_wait(&(vnode->swap_request_pids_cond),
					&(vnode->swap_request_pids_lock));
	} 

	/* Check whether VEOS is terminating */
	if (terminate_flag == REQUIRED)
		goto hndl_exit;

	list_for_each_safe(p, n, &vnode->swap_request_pids_queue) {
		swapin_pids_num = 0;
		swapin_retry_flag = false;
		swapout_retry_flag = false;
		swapin_interrupt = false;
		is_need_tail = false;
		/* Pick up one "swap request information" */
		PPS_DEBUG(cat_os_pps, "Pick up one swap request information");
		tmp = list_entry(p, struct veos_swap_request_info, swap_info);
		/* Delete "swap request information" from list */
		list_del(p);
		pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
					UNLOCK,
					"Failed to release swap_request lock");
		/* Pick up one process */
		PPS_DEBUG(cat_os_pps, "Pick up one process");
		/* Do swap-out/in with each process */
		for (i = 0; tmp->pid_array[i] != PPS_END_OF_PIDS; i++) {
			/* Check whether VEOS is terminating */
			if (terminate_flag == REQUIRED) {
				del_doing_swap_request(tmp);
				free(tmp);
				need_unlock_request = false;
				goto hndl_exit;
			}

			pid = tmp->pid_array[i];
			if (pid == PPS_SKIP_PID) {
				PPS_DEBUG(cat_os_pps, "%dth pid %d is swapped "
							"before", i+1, pid);
				continue;
			}
			ipc_sync = tmp->ipc_sync_array[i];
			PPS_DEBUG(cat_os_pps, "%dth pid is %d", i+1, pid);
			ve_task = find_ve_task_struct(pid);
			if (ve_task == NULL) {
				PPS_DEBUG(cat_os_pps, "VE task with %d not found", pid);
				ve_swap_thread_process_exit(ipc_sync, NULL);
				continue;
			}

			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			veos_operate_all_ve_task_lock(ve_task->group_leader,
							LOCK);
			get_all_threads_status_substatus(ve_task,
							&status, &sub_status);
			if (((status != STOP) && (status != ZOMBIE)) ||
				(!((sub_status == SWAPPING_OUT) ||
				(sub_status == SWAPPING_IN)))) {
				PPS_DEBUG(cat_os_pps, "Status or Sub-status are invalid,"
					"Status:%d, Sub-status:%d",
					status, sub_status);
				veos_operate_all_ve_task_lock(
						ve_task->group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_swap_thread_process_exit(ipc_sync, ve_task);
				continue;
			}

			if (sub_status == SWAPPING_OUT) {
				/* Check whether process is core dumping */
				if (is_dumping_core(ve_task)) {
					PPS_DEBUG(cat_os_pps,
						"%d is core dump ongoing", pid);
					veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
					pthread_mutex_lock_unlock(&(ve_task->
						p_ve_mm->thread_group_mm_lock),
						UNLOCK,
						"Failed to release "
						"thread_group_mm_lock");
					ve_swap_thread_process_exit(ipc_sync, ve_task);
					continue;
				}
				veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");

				ret = ve_do_swapout(ve_task);
				if (ret == NO_PPS_BUFF) {
					pthread_mutex_lock_unlock(&(vnode->
						swap_request_pids_lock),
						LOCK,
						"Failed to aqcuire swap_request lock");
					swapin_flag = check_swap_out_in_process(SWAPPING_IN);
					pthread_mutex_lock_unlock(&(vnode->
						swap_request_pids_lock),
						UNLOCK,
						"Failed to release swap_request lock");
					if (swapin_flag == 0) {
						PPS_DEBUG(cat_os_pps, "Swap-out against retry");
						swapout_retry_flag = true;
						is_need_tail = true;
					} else {
						PPS_DEBUG(cat_os_pps, "Swap-out not retry");
						pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
							thread_group_mm_lock),LOCK,
							"Failed to acquire thread_group_mm_lock");
						veos_operate_all_ve_task_lock(ve_task->group_leader, LOCK);
						if (veos_check_substatus(ve_task->group_leader,SWAPPING_OUT) == 0) 
							veos_update_substatus(ve_task->group_leader,
										SWAPPED_OUT);
						veos_operate_all_ve_task_lock(ve_task->group_leader, UNLOCK);
						pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
							thread_group_mm_lock),UNLOCK,
							"Failed to release thread_group_mm_lock");
					}
				} else if (ret < 0) {
					/* if swap out error, pid skip*/
					tmp->pid_array[i]  = PPS_SKIP_PID;
					ve_swap_thread_process_exit(ipc_sync, ve_task);
					continue;
				} else if (ret == PPS_INTER_SWAPIN) {
					PPS_DEBUG(cat_os_pps,
						"swapin interrupt of PID:%d",
						ve_task->group_leader->pid);
					swapin_interrupt = true;
					goto hndl_swapin;
				} else {
					/* if swap out success, pid skip*/
					tmp->pid_array[i]  = PPS_SKIP_PID;
				}
			} else if (sub_status == SWAPPING_IN) {
				veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
hndl_swapin:
				ret = ve_do_swapin(ve_task);
				if (ret == -PPS_ALLOC_RETRY) {
					PPS_DEBUG(cat_os_pps, "Swap-in against retry");
					swapin_retry_flag = true;
					is_need_tail = true;
					pthread_mutex_lock_unlock(&(vnode->
						swap_request_pids_lock),
						LOCK,
						"Failed to aqcuire swap_request lock");
					if((!vnode->resource_freed) &&
					(check_swap_in_need_wait(vnode))) {
						PPS_DEBUG(cat_os_pps, "wait for resource");
						pthread_cond_wait(&(vnode->
							swap_request_pids_cond),
							&(vnode->
							swap_request_pids_lock));
						vnode->resource_freed = false;
					}
					pthread_mutex_lock_unlock(&(vnode->
						swap_request_pids_lock),
						UNLOCK,
						"Failed to release swap_request lock");
				} else if ((ret != 0 ) && (swapin_interrupt)) {
					PPS_DEBUG(cat_os_pps,
						"Failed swapin interrupt of PID:%d",
						ve_task->group_leader->pid);
					kill(ve_task->group_leader->pid, SIGKILL);
					ve_swap_thread_process_exit(ipc_sync, ve_task);
					tmp->pid_array[i]  = PPS_SKIP_PID;
					continue;
				} else if (ret < 0) {
					kill(ve_task->pid, SIGKILL);
					ve_swap_thread_process_exit(ipc_sync, ve_task);
					tmp->pid_array[i]  = PPS_SKIP_PID;
					continue;
				} else {
					swapin_pids_idx[swapin_pids_num] = i;
					swapin_pids_num++;
					PPS_DEBUG(cat_os_pps, "Set pid %d to 0",
						tmp->pid_array[i]);
					tmp->pid_array[i]  = PPS_SKIP_PID;
				}
			}
			/* if need, add request to tail of queue */
			if ((is_need_tail)
				&& (tmp->pid_array[i+1] == PPS_END_OF_PIDS)){
				pthread_mutex_lock_unlock(
					&(vnode->swap_request_pids_lock),
					LOCK,
					"Failed to acquire swap_request lock");
				PPS_DEBUG(cat_os_pps,
					"Add request to tail of queue");
				list_add_tail(&(tmp->swap_info),
					&(vnode->swap_request_pids_queue));
				pthread_mutex_lock_unlock(
					&(vnode->swap_request_pids_lock),
					UNLOCK,
					"Failed to release swap_request lock");
			}
			put_ve_task_struct(ve_task);
		}
		for (k = 0; k < swapin_pids_num; k++) {
			ipc_sync = tmp->ipc_sync_array[swapin_pids_idx[k]];
			ve_swap_thread_process_exit(ipc_sync, NULL);
		}
		if((!swapin_retry_flag) && (!swapout_retry_flag))
			free(tmp);
		tmp = NULL;
		pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock), LOCK,
					"Failed to aqcuire swap_request lock");
	}
	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
				UNLOCK,
				"Failed to release swap_request lock");
	goto hndl_start;

hndl_exit:
	PPS_INFO(cat_os_pps,
			"VEOS is terminating, so Swap thread terminates");
	vnode->swap_request_pids_enable = false;
	del_all_swap_request_information(vnode);
	if (need_unlock_request) {
		pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
			UNLOCK, "Failed to release swap_request lock");
	}
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return NULL;
}
