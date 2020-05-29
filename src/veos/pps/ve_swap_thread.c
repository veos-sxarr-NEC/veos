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
		/* ZOMBIE is allowed as child thread's state, but
		 * not allowed as main thread's state */
		if ((tmp->ve_task_state != leader_state) &&
					(tmp->ve_task_state != ZOMBIE)) {
			ret_state = -1;
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

	PPS_TRACE(cat_os_pps, "In %s", __func__);

hndl_start:
	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
			LOCK, "Failed to aqcuire swap_request lock");
	/* Check whether VEOS is terminating */
	if (terminate_flag == REQUIRED)
		goto hndl_exit;

	if (list_empty(&vnode->swap_request_pids_queue)) {
		pthread_cond_wait(&(vnode->swap_request_pids_cond),
					&(vnode->swap_request_pids_lock));
	}

	/* Check whether VEOS is terminating */
	if (terminate_flag == REQUIRED)
		goto hndl_exit;

	list_for_each_safe(p, n, &vnode->swap_request_pids_queue) {
		swapin_pids_num = 0;
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
				goto hndl_exit;
			}

			pid = tmp->pid_array[i];
			ipc_sync = tmp->ipc_sync_array[i];
			PPS_DEBUG(cat_os_pps, "%dth pid is %d", i+1, pid);
			ve_task = find_ve_task_struct(pid);
			if (ve_task == NULL) {
				PPS_DEBUG(cat_os_pps, "VE task with %d not found", pid);
				ve_swap_in_finish(ipc_sync);
				ve_put_ipc_sync(ipc_sync);
				continue;
			}

			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			veos_operate_all_ve_task_lock(ve_task->group_leader,
							LOCK);
			get_all_threads_status_substatus(ve_task,
							&status, &sub_status);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				UNLOCK, "Failed to release thread_group_mm_lock");
			if ((status != STOP) ||
				(!((sub_status == SWAPPING_OUT) ||
				(sub_status == SWAPPING_IN)))) {
				PPS_DEBUG(cat_os_pps, "Status or Sub-status are invalid,"
					"Status:%d, Sub-status:%d",
					status, sub_status);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), LOCK,
					"Failed to acquire thread_group_mm_lock");
				veos_operate_all_ve_task_lock(
						ve_task->group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_swap_in_finish(ipc_sync);
				ve_put_ipc_sync(ipc_sync);

				put_ve_task_struct(ve_task);
				continue;
			}

			if (sub_status == SWAPPING_OUT) {
				/* Check whether process is core dumping */
				if (is_dumping_core(ve_task)) {
					PPS_DEBUG(cat_os_pps,
						"%d is core dump ongoing", pid);
					pthread_mutex_lock_unlock(&(ve_task->
						p_ve_mm->thread_group_mm_lock),
						LOCK,
						"Failed to acquire "
						"thread_group_mm_lock");
					veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
					pthread_mutex_lock_unlock(&(ve_task->
						p_ve_mm->thread_group_mm_lock),
						UNLOCK,
						"Failed to release "
						"thread_group_mm_lock");
					ve_swap_in_finish(ipc_sync);
					ve_put_ipc_sync(ipc_sync);
					put_ve_task_struct(ve_task);
					continue;
				}
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), LOCK,
					"Failed to acquire thread_group_mm_lock");
				veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");

				ret = ve_do_swapout(ve_task);
				if (ret < 0) {
					ve_swap_in_finish(ipc_sync);
					ve_put_ipc_sync(ipc_sync);
					put_ve_task_struct(ve_task);
					continue;
				} else if (ret == PPS_INTER_SWAPIN) {
					swapin_pids_idx[swapin_pids_num] = i;
					swapin_pids_num++;
				}
			} else if (sub_status == SWAPPING_IN) {
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), LOCK,
					"Failed to acquire thread_group_mm_lock");
				veos_operate_all_ve_task_lock(ve_task->
							group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");

				ret = ve_do_swapin(ve_task);
				if (ret < 0) {
					ve_swap_in_finish(ipc_sync);
					ve_put_ipc_sync(ipc_sync);
					kill(ve_task->pid, SIGKILL);
					put_ve_task_struct(ve_task);
					continue;
				}
				swapin_pids_idx[swapin_pids_num] = i;
				swapin_pids_num++;
			}
			put_ve_task_struct(ve_task);
		}
		for (k = 0; k < swapin_pids_num; k++) {
			pid = tmp->pid_array[swapin_pids_idx[k]];
			ipc_sync = tmp->ipc_sync_array[swapin_pids_idx[k]];
			ve_swap_in_finish(ipc_sync);
			ve_put_ipc_sync(ipc_sync);
		}
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
	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
			UNLOCK, "Failed to release swap_request lock");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return NULL;
}
