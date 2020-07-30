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
 * @file ve_swap_out.c
 * @brief PPS swap-out functions in VEOS
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <log4c.h>
#include <pthread.h>
#include "velayout.h"
#include "ve_swap.h"
#include "ve_list.h"
#include "veos.h"
#include "veos_ived.h"
#include "locking_handler.h"
#include "task_mgmt.h"
#include "task_sched.h"
#include "ve_hw.h"
#include "ve_mem.h"
#include "buddy.h"
#include "dma.h"
#include "ve_shm.h"

/**
 * @brief Check whether PPS is enabled or not.
 *
 * @return true on PPS is enabled, false on not.
 */
bool
veos_check_pps_enable(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	bool pps_enable;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock), LOCK,
					"Failed to aqcuire swap_request lock");
	pps_enable = vnode->swap_request_pids_enable;
	pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock), UNLOCK,
					"Failed to release swap_request lock");

	PPS_TRACE(cat_os_pps, "Out %s", __func__);

	return pps_enable;
}

/**
 * @brief Get PPS mode 
 *
 * @retval mode on success
 * @retval -1 on Failure.
 *
 * @note Acquire ve_page_node_lock before invoking this.
 */
static int veos_get_swapout_mode(void) 
{
	int mode = -1;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (vnode->pps_buf_size > 0) {
		if (vnode->pps_file.is_opened) {
			mode = PPS_MIX_MODE;
			PPS_DEBUG(cat_os_pps, "PPS mode is PPS_MIX_MODE");
			goto hndl_return;
		}
		mode = PPS_MEM_MODE;
		PPS_DEBUG(cat_os_pps, "PPS mode is PPS_MEM_MODE");
		goto hndl_return;
	}
	if (vnode->pps_file.is_opened) {
		mode = PPS_FILE_MODE;
		PPS_DEBUG(cat_os_pps, "PPS mode is PPS_FILE_MODE");
	}
hndl_return:
	PPS_TRACE(cat_os_pps, "In %s", __func__);
	return mode;
}

/**
 * @brief Allocate struct ve_ipc_sync and initialize it.
 *
 * @return Pointer to allocated ve_ipc_sync on success, NULL on Failure.
 */
struct ve_ipc_sync
*ve_alloc_ipc_sync(void)
{
	struct ve_ipc_sync *ret_ptr = NULL;
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret_ptr = (struct ve_ipc_sync *)malloc(sizeof(struct ve_ipc_sync));
	if (ret_ptr == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to allocate ve_ipc_sync "
						"due to %s", strerror(errno));
		goto hndl_return;
	}

	/* Initial value '1' means reference from ve_task_struct.
	 * So, it will be decremented when ve_task_struct is freed.
	 */
	ret_ptr->ref_count = 1;
	ret_ptr->handling_request = 0;
	ret_ptr->swapping = 0;

	ret = pthread_mutex_init(&(ret_ptr->ref_lock), NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Initialising ve_ipc_sync->ref_lock"
						" due to %s", strerror(ret));
		goto hndl_free_return;
	}

	ret = pthread_mutex_init(&(ret_ptr->swap_exclusion_lock), NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to init "
				"ve_ipc_sync->swap_exclusion_lock due to %s",
				strerror(ret));
		goto hndl_free_return;
	}

	ret = pthread_cond_init(&(ret_ptr->handling_request_cond), NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to init "
				"ve_ipc_sync->handling_request_cond due to %s",
				strerror(ret));
		goto hndl_free_return;
	}

	ret = pthread_cond_init(&(ret_ptr->swapping_cond), NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to init "
					"ve_ipc_sync->swapping_cond due to %s",
					strerror(ret));
		goto hndl_free_return;
	}

	PPS_DEBUG(cat_os_pps, "ipc_sync allocated : %p", ret_ptr);
	goto hndl_return;

hndl_free_return:
	free(ret_ptr);
	ret_ptr = NULL;

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return ret_ptr;
}

/**
 * @brief Set 0 to ve_ipc_sync->swapping, if its process is going to be deleted.
 *
 * @param[in] tsk ve_task_struct of process which is going to be deleted.
 *
 * @return 0 on success, -1 on Failure.
 *
 * @note Acquire ve_task_lock before invoking this.
 */
int
ve_unlock_swapped_proc_lock(struct ve_task_struct *tsk)
{
	int retval = -1;
	struct ve_ipc_sync *ipc_sync;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL) {
		PPS_ERROR(cat_os_pps,
			"Failed to resume IPC request due to %s",
			strerror(EINVAL));
		goto hndl_return;
	}

	/* T(s) Process's group_leader doesn't match following conditions. */
	if ((tsk->group_leader != tsk) ||
		((tsk->ve_task_state != STOP) &&
		(tsk->ve_task_state != ZOMBIE)) ||
		(tsk->sstatus != SWAPPED_OUT)) {
		retval = 0;
		goto hndl_return;
	}

	ipc_sync = ve_get_ipc_sync(tsk);
	if (ipc_sync == NULL)
		goto hndl_return;

	ve_swap_in_finish(ipc_sync);

	ve_put_ipc_sync(ipc_sync);
	/* Decrement a ref_cnt because this is kept up until finishing Swap-in.
	 */
	ve_put_ipc_sync(ipc_sync);

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Return ve_ipc_sync which is contained in specefied ve_task_struct,
 * after incrementing its reference counter.
 *
 * @param[in] tsk ve_task_struct which contains ve_ipc_sync.
 *
 * @return Pointer to ve_ipc_sync on success, NULL on Failure.
 */
struct ve_ipc_sync
*ve_get_ipc_sync (struct ve_task_struct *tsk)
{
	struct ve_ipc_sync *ret_ptr = NULL;
	struct ve_ipc_sync *tmp;
	int prev;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL) {
		PPS_DEBUG(cat_os_pps, "Failed to get ipc_sync");
		goto hndl_return;
	}

	tmp = tsk->ipc_sync;
	PPS_DEBUG(cat_os_pps, "getting ipc_sync : %p", tmp);
	if (tmp == NULL)
		veos_abort("VEOS internal info(ipc_sync) is missing");

	pthread_mutex_lock_unlock(&(tmp->ref_lock), LOCK,
					"Failed to acquire ipc_sync ref lock");
	if (tmp->ref_count < 0) {
		PPS_ERROR(cat_os_pps, "Failed to get ipc_sync");
		goto hndl_unlock;
	}
	prev = tmp->ref_count;
	if (prev == INT_MAX) {
		PPS_ERROR(cat_os_pps, "Error at ref_count of ipc_sync"
						" : %s", strerror(ERANGE));
		goto hndl_unlock;
	}
	tmp->ref_count++;
	PPS_DEBUG(cat_os_pps, "Increment ipc_sync->ref_count, before %d, "
					"after %d", prev, tmp->ref_count);

	ret_ptr = tsk->ipc_sync;
hndl_unlock:
	pthread_mutex_lock_unlock(&(tmp->ref_lock), UNLOCK,
					"Failed to release ipc_sync ref lock");

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return ret_ptr;

}

/**
 * @brief Decrement specified ve_ipc_sync's reference counter.
 *
 * @param[in] ipc_sync ve_ipc_sync by which reference counter is decremented.
 *
 * @return 0 on success, -1 on Failure.
 */
int
ve_put_ipc_sync (struct ve_ipc_sync *ipc_sync)
{
	int prev;
	int retval = -1;
	bool deleting_flag = false;
	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (ipc_sync == NULL) {
		PPS_ERROR(cat_os_pps,
				"Failed to put of ipc_sync");
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(ipc_sync->ref_lock), LOCK,
					"Failed to acquire ipc_sync ref lock");
	prev = ipc_sync->ref_count;
	ipc_sync->ref_count--;
	PPS_DEBUG(cat_os_pps, "Decrement ipc_sync->ref_count, before %d, "
					"after %d", prev, ipc_sync->ref_count);
	if (ipc_sync->ref_count == 0) {
		PPS_DEBUG(cat_os_pps, "Deleting ve_ipc_sync(%p)", ipc_sync);
		deleting_flag = true;
	}
	pthread_mutex_lock_unlock(&(ipc_sync->ref_lock), UNLOCK,
					"Failed to release ipc_sync ref lock");

	if (deleting_flag) {
		PPS_DEBUG(cat_os_pps, "Freeing ipc_sync(%p)", ipc_sync);
		pthread_cond_destroy(&(ipc_sync->handling_request_cond));
		pthread_cond_destroy(&(ipc_sync->swapping_cond));
		free(ipc_sync);
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Stop IPC request e.g. system call request, to start swap-out.
 *
 * @param[in] ipc_sync Pointer to ve_ipc_sync structure related to process
 *                     which is going to be swapped-out.
 *                     Caller must ensure that this argument isn't NULL.
 */
void
ve_swap_out_start(struct ve_ipc_sync *ipc_sync)
{
	PPS_TRACE(cat_os_pps, "In %s", __func__);
	pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock), LOCK,
				"Failed to aqcuire swap_exclusion_lock");

	while(ipc_sync->handling_request != 0) {
		pthread_cond_wait(&(ipc_sync->handling_request_cond),
					&(ipc_sync->swap_exclusion_lock));
	}
	ipc_sync->swapping = 1;

	pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock), UNLOCK,
				"Failed to release swap_exclusion_lock");
	PPS_DEBUG(cat_os_pps, "Stop IPC request handle to start Swap-out");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Resume IPC request e.g. system call request, after Swap-in finishs.
 *
 * @param[in] ipc_sync Pointer to ve_ipc_sync structure related to process
 *                     which is going to be swapped-out.
 *                     Caller must ensure that this argument isn't NULL.
 */

void
ve_swap_in_finish(struct ve_ipc_sync *ipc_sync)
{
	PPS_TRACE(cat_os_pps, "In %s", __func__);
	pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock), LOCK,
				  "Failed to aqcuire swap_exclusion_lock");

	ipc_sync->swapping = 0;
	pthread_cond_broadcast(&(ipc_sync->swapping_cond));

	pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock), UNLOCK,
				"Failed to release swap_exclusion_lock");
	PPS_DEBUG(cat_os_pps, "Resume IPC request handling because Swap-in"
								"finishs");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}
/**
 * @brief Check whether all thread's sub-status is expected or not.
 *
 * @param[in] group_leader Group leader's ve_task_struct
 * @param[in] expected Expected sub-status.
 *
 * @retval 0 on all sub-states are expected
 * @retval -1 on not all sub-states are expected
 *
 * @note Acquire ve_task_lock before invoking this.
 */
 int
veos_check_substatus(struct ve_task_struct *group_leader,
						enum swap_status expected)
{
	struct ve_task_struct *tmp;
	int retval = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	if (group_leader->sstatus != expected) {
		PPS_TRACE(cat_os_pps,
			"Expected sub-status of group_leader(%d) is %d, but %d",
			group_leader->pid, expected, group_leader->sstatus);
		goto hndl_return;
	}

	list_for_each_entry(tmp, &(group_leader->thread_group), thread_group) {
		if (tmp->sstatus != expected) {
			PPS_TRACE(cat_os_pps,
				"Expected sub-status of %d is %d, but %d",
				tmp->pid, expected, tmp->sstatus);
			goto hndl_return;
		}
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Check whether Swap-in is requested against specified process or not.
 *
 * @param[in] group_leader Group leader's ve_task_struct of specified process.
 *
 * @retval 0 on Success,
 * @retval SWAPIN_INTER on Swap-in Interrupts,
 * @retval -1 on Failure.
 *
 * @note Acquire all thread's ve_task_lock of group_leader before invoking this.
 */
static int
veos_check_swapin_interruption(struct ve_task_struct *group_leader)
{
	int retval, ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = veos_check_substatus(group_leader, SWAPPING_IN);
	if (ret == 0) {
		PPS_INFO(cat_os_pps, "Swap-in Interrupts");
		retval = PPS_INTER_SWAPIN;
		goto hndl_return;
	}
	ret = veos_check_substatus(group_leader, SWAPPING_OUT);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Unexpected sub-status");
		retval = -1;
	} else {
		retval = 0;
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Delete information about Swapped-out ATB, DMAATB and VE page
 * corresponding to exited process.
 *
 * @param[in] tsk ve_task_struct of exited process.
 *
 * @retval 0 on success
 * @retval -errno on Failure.
 *
 * @note Acquire thread_group_mm_lock before invoking this.
 */
int
del_swapped_pages(struct ve_task_struct *tsk)
{
	int retval, ret;
	struct ve_task_struct *group_leader;
	struct ve_swapped_virtual *vrt, *tmp;
	struct ve_node_struct *vnode = VE_NODE(0);
	pgno_t pno;
	bool free_private_needed;
	void *private_data;
	uint64_t flag, perm;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL) {
		retval = -EINVAL;
		goto hndl_return;
	}
	group_leader = tsk->group_leader;

	list_for_each_entry_safe(vrt, tmp,
			&(group_leader->p_ve_mm->swapped_pages), pages) {
		PPS_DEBUG(cat_os_pps, "Swap-info is remained, cleanup");
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");
		PPS_DEBUG(cat_os_pps, "vrt->kind : %d", vrt->kind);
		PPS_DEBUG(cat_os_pps, "vrt->dir : %d", vrt->dir);
		PPS_DEBUG(cat_os_pps, "vrt->ent : %d", vrt->ent);
		PPS_DEBUG(cat_os_pps, "vrt->phy : %p", vrt->phy);
		pno = vrt->phy->pno;
		vrt->phy->ref_cnt--;
		if (vrt->phy->ref_cnt != 0) {
			list_del(&(vrt->pages));
			free(vrt);
			pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
					UNLOCK,
					"Failed to release ve_pages_node_lock");
			continue;
		}

		free_private_needed = false;
		if (pno == -1) {
			free_private_needed = true;
			private_data = vrt->phy->private_data;
			flag = vrt->phy->flag;
			perm = vrt->phy->perm;
			if (vrt->phy->file_offset == PPS_FILE_OFF) {
				veos_pps_free_buf_page(vrt->phy->buf_page,
					vrt->phy->pgsz, vrt->phy->numa_node);
			} else {
				veos_pps_free_file_offset((void *)vrt->phy->file_offset,
					vrt->phy->pgsz, vrt->phy->numa_node);
			}
		} else {
			VE_PAGE(vnode, pno)->swapped_info = NULL;
		}
		free(vrt->phy);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		if (free_private_needed) {
			ret = amm_free_private_data(
						private_data, flag, perm);
			if (ret != 0)
				PPS_DEBUG(cat_os_pps, "amm_free_private_data "
							"returned %d", ret);
		}
		list_del(&(vrt->pages));
		free(vrt);
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Dump ATB of specified process.
 *
 * @param[in] tsk Pointer to ve_task_struct.
 * The caller must ensure that this argument is not NULL.
 *
 * @retval None
 */
void
dump_process_atb(struct ve_task_struct *tsk)
{
	int dir, ent;
	pgno_t pgno;

	if (!log4c_category_is_priority_enabled(cat_os_pps,
							LOG4C_PRIORITY_DEBUG))
		return;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	PPS_DEBUG(cat_os_pps, "Dump %d atb", tsk->pid);

	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire hread_group_mm_lock");

	for (dir = 0; dir < ATB_DIR_NUM; dir++) {
		if (!ps_isvalid(&(tsk->p_ve_mm->atb[0].dir[dir])))
			continue;
		PPS_DEBUG(cat_os_pps, "DIR[%d] : 0x%lx", dir,
					tsk->p_ve_mm->atb[0].dir[dir].data);
		for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
			pgno = pg_getpb(&(tsk->p_ve_mm->atb[0].entry[dir][ent]),
									PG_2M);
			if ((pgno == PG_BUS) || (pgno == 0))
				continue;
			PPS_DEBUG(cat_os_pps, "ENT[%d][%d] : 0x%lx", dir, ent,
				tsk->p_ve_mm->atb[0].entry[dir][ent].data);
		}
	}

	PPS_DEBUG(cat_os_pps, "Dump %d atb Done", tsk->pid);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release hread_group_mm_lock");

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Allocate information about Swapping-out ATB or Swapping-out DMAATB
 * per ATB entry or per DMAATB entry and corresponding information about
 * Swapped-out VE page.
 *
 * @param[in] pgno VE page number corresponding to Swapping-out ATB or
 * Swapping-out DMAATB
 * @param[in] vnode vnode VE node structure.
 * @param[out] vrt A Pointer to which allocated information about
 * Swapping-out ATB or Swapping-out DMAATB is set.
 * @param[in] dir Directory number corresponding to Swapping-out ATB or
 * Swapping-out DMAATB.
 * @param[in] ent Entry number corresponding to Swapping-out ATB or
 * Swapping-out DMAATB.
 * @param[in] kind ATB or DMAATB
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Acquire thread_group_mm_lock and ve_pages_node_lock before invoking
 * this.
 */
static int
allocate_swap_info(pgno_t pgno, struct ve_node_struct *vnode,
					struct ve_swapped_virtual **vrt,
					int dir, int ent, int kind)
{
	int retval = -1;
	struct ve_page *page = VE_PAGE(vnode, pgno);
	struct ve_swapped_physical *phy;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (page->swapped_info != NULL) {
		PPS_DEBUG(cat_os_pps, "%ld has swapped_info", pgno);
		phy = page->swapped_info;
	} else {

		phy = (struct ve_swapped_physical *)malloc(
					sizeof(struct ve_swapped_physical));
		if (phy == NULL) {
			PPS_ERROR(cat_os_pps, "Failed to allocate Swap-out"
					"physical memory info due to %s",
					strerror(errno));
			goto hndl_return;
		}
		phy->buf_page = NULL;
		phy->file_offset = PPS_FILE_OFF;
		phy->perm = 0;
		phy->pgsz = page->pgsz;
		phy->flag = 0;
		phy->pno = pgno;
		phy->numa_node = -1;
		phy->ref_cnt = 0;
		phy->private_data = NULL;
		page->swapped_info = phy;
	}

	*vrt = (struct ve_swapped_virtual *)malloc(
					sizeof(struct ve_swapped_virtual));
	if (*vrt == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to allocate Swap-out ATB entry "
						"due to %s", strerror(errno));
		goto hndl_free_phy;
	}
	(*vrt)->dir = dir;
	(*vrt)->ent = ent;
	(*vrt)->phy = phy;
	(*vrt)->kind = kind;
	phy->ref_cnt++;

	retval = 0;
	goto hndl_return;

hndl_free_phy:
	if (phy->ref_cnt == 0) {
		page->swapped_info = NULL;
		free(phy);
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Check whether specified VE page is capable of Swap-out or not.
 *
 * @param[in] pgno VE page number
 * @param[in] vnode vnode VE node structure.
 *
 * @retval 0 on swappable
 * @retval -1 on not swappable.
 *
 * @note Acquire ve_page_node_lock before invoking this.
 */
int
is_ve_page_swappable(pgno_t pgno, struct ve_node_struct *vnode)
{
	int retval = -1;
	struct ve_page *page = VE_PAGE(vnode, pgno);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (page->pci_count > 0) {
		PPS_DEBUG(cat_os_pps, "%ld is registerer with PCIATB", pgno);
		goto hndl_return;
	}

	if (page->flag & MAP_VDSO) {
		PPS_DEBUG(cat_os_pps, "%ld is VDSO", pgno);
		goto hndl_return;
	}

	if ((page->flag & PG_SHM) || (page->flag & MAP_SHARED)) {
		PPS_DEBUG(cat_os_pps, "%ld is shared", pgno);
		goto hndl_return;
	}

	if (page->flag & PG_PTRACE) {
		PPS_DEBUG(cat_os_pps, "%ld is traced", pgno);
		goto hndl_return;
	}

	if (!(page->flag & MAP_ANON) &&
		!((page->flag & MAP_PRIVATE) && (page->perm & PROT_WRITE))) {
		PPS_DEBUG(cat_os_pps,
			"%ld is not anonymous or read-only fileback memory",
			pgno);
		goto hndl_return;
	}

	if (page->owner != NULL) {
		PPS_DEBUG(cat_os_pps, "%ld has owner", pgno);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Do Swap-out a DMAATB entry
 *
 * @param[in] tsk ve_task_struct of Swapping-out process
 * @param[in] dir Directory number corresponding to Swapping-out DMAATB
 * @param[in] ent Entry number corresponding to Swapping-out DMAATB
 * @param[in] sync_copy Copy of DMAATB process soft copy of Swapping-out process
 *
 * @retval 0 on success,
 * @retval DIR_INVALID on DMAATB dir is invalid,
 * @retval NO_PPS_BUFF on PPS buffer or PPS file is full
 * @retval  -1 on Failure.
 *
 * @note Acquire thread_group_mm_lock before invoking this.
 */
static int
veos_do_swap_out_dmaatb(struct ve_task_struct *tsk, int dir, int ent,
							dmaatb_reg_t *sync_copy)
{
	int retval = 0;
	int ret;
	pgno_t pgno = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_swapped_virtual *vrt = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (!ps_isvalid(&(sync_copy->dir[dir]))) {
		PPS_DEBUG(cat_os_pps, "DMAATB dir %d is invalid", dir);
		retval = PPS_DIR_INVALID;
		goto hndl_return;
	} else if (ent == (DMAATB_ENTRY_MAX_SIZE - 1)) {
		ps_clrdir(&(sync_copy->dir[dir]));
		ps_invalid(&(sync_copy->dir[dir]));
	}

	if (pg_gettype(&(sync_copy->entry[dir][ent])) != VE_ADDR_VEMAA) {
		PPS_DEBUG(cat_os_pps, "DMAATB dir %d ent %d does not contain"
						" VE_ADDR_VEMAA", dir, ent);
		goto hndl_free;
	}
	pgno = pg_getpb(&(sync_copy->entry[dir][ent]), PG_2M);
	PPS_DEBUG(cat_os_pps, "page number = %ld", pgno);
	if (pgno == PG_BUS) {
		PPS_DEBUG(cat_os_pps, "invalid page num");
		goto hndl_free;
	}
	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");

	ret = is_ve_page_swappable(pgno, vnode);
	if (ret != 0) {
		PPS_DEBUG(cat_os_pps,
				"page %ld is not capable of Swap-out", pgno);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		goto hndl_free;
	}

	ret = allocate_swap_info(pgno, vnode, &vrt, dir, ent, PPS_VIRT_DMAATB);
	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "dir %d, ent %d : "
					  "cannot create swap info", dir, ent);
		retval = -1;
		goto hndl_return;
	}

	list_add(&(vrt->pages), &(tsk->p_ve_mm->swapped_pages));
	pg_setpb(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]), PG_BUS, PG_2M);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
	ret = amm_do_put_page(pgno * PAGE_SIZE_2MB, true);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	if (ret != 0) {
		list_del(&(vrt->pages));
		pg_clearpfn(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]));
		pg_setpb(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]), pgno, PG_2M);
		/* clear virt, because it will not be used */
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to lock ve_pages_node_lock");
		VE_PAGE(vnode, pgno)->swapped_info->ref_cnt--;
		if (VE_PAGE(vnode, pgno)->swapped_info->ref_cnt == 0) {
			free(VE_PAGE(vnode, pgno)->swapped_info);
			VE_PAGE(vnode, pgno)->swapped_info = NULL;
		}
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		if(ret == NO_PPS_BUFF) {
			retval= NO_PPS_BUFF;
		}
		PPS_DEBUG(cat_os_pps, "Failed to deallocate memory,"
							" but free DMAATB");
		free(vrt);
	}

hndl_free:
	pg_unsetro(&(sync_copy->entry[dir][ent]));
	pg_unsetido(&(sync_copy->entry[dir][ent]));
	pg_unsettype(&(sync_copy->entry[dir][ent]));
	pg_clearpfn(&(sync_copy->entry[dir][ent]));
	pg_invalid(&(sync_copy->entry[dir][ent]));
	pg_unsetprot(&(sync_copy->entry[dir][ent]));

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Acquire or release all ve_task_lock of specfied process.
 *
 * @param[in] group_leader ve_task_struct of group loader of specfied process.
 * The caller must ensure that this argument is not NULL.
 * @param[in] operate LOCK or UNLOCK
 *
 * @retval None
 */
void
veos_operate_all_ve_task_lock(struct ve_task_struct *group_leader,
							lock_unlock_t operate)
{
	struct ve_task_struct *tmp;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	if (operate == LOCK) {
		pthread_mutex_lock_unlock(&(group_leader->ve_task_lock), LOCK,
					"Failed to acquire leader's ve_task_lock");
		list_for_each_entry(tmp, &(group_leader->thread_group),
								thread_group) {
			pthread_mutex_lock_unlock(&(tmp->ve_task_lock), LOCK,
					"Failed to acquire ve_task_lock");
		}
	} else if (operate == UNLOCK) {
		list_for_each_entry(tmp, &(group_leader->thread_group),
								thread_group) {
			pthread_mutex_lock_unlock(&(tmp->ve_task_lock), UNLOCK,
					"Failed to release ve_task_lock");
		}
		pthread_mutex_lock_unlock(&(group_leader->ve_task_lock), UNLOCK,
				"Failed to release leader's ve_task_lock");
	} else {
		veos_abort("Invalid lock operation");
	}
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Get exit_status of specified process.
 *
 * @param[in] group_leader ve_task_struct of group loader of specfied process.
 * The caller must ensure that this argument is not NULL.
 *
 * @return group_leader->exit_status
 *
 */
int
get_task_exit_status(struct ve_task_struct *group_leader)
{
	int ret_exit_status;
	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&group_leader->ref_lock, LOCK,
				  "Failed to acquire task reference lock");
	ret_exit_status = group_leader->exit_status;
	PPS_DEBUG(cat_os_pps, "ret_exit_status = %d",ret_exit_status);
	pthread_mutex_lock_unlock(&group_leader->ref_lock, UNLOCK,
				  "Failed to releasse task reference lock");

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return ret_exit_status;
}

/**
 * @brief Swap out (free) the DMAATB of specified process.
 *
 * @param[in] tsk ve_task_struct of specfied process
 *
 * @retval 0 on Success,
 * @retval SWAPIN_INTER on Swap-in Interrupts,
 * @retval TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval NO_PPS_BUFF on PPS buffer or PPS file is full
 * @retval -1 on Failure.
 */
static int
veos_swap_out_dmaatb(struct ve_task_struct *tsk)
{
	int retval = 0;
	int dir, ent, ret;
	uint64_t sync_dir_bitmap = 0;
	dmaatb_reg_t *sync_copy;
	struct ve_mm_struct mm = {};
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_task_struct *group_leader = tsk->group_leader;

	bool is_no_buffer = false;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			LOCK, "Failed to acquire thread_group_mm_lock");
	if (tsk->p_ve_mm->dmaatb_progress == SWAPPED) {
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");
		goto hndl_return;
	}
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");

	for (dir = vnode->nr_avail_cores; dir < DMAATB_DIR_NUM; dir++) {
		for (ent = 0; ent < DMAATB_ENTRY_MAX_SIZE; ent++) {
			pthread_mutex_lock_unlock(
				&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			if ((dir == vnode->nr_avail_cores) && (ent == 0)) {
				memcpy(&mm, tsk->p_ve_mm,
						sizeof(struct ve_mm_struct));
				sync_copy = &(mm.dmaatb);
				tsk->p_ve_mm->dmaatb_progress = SWAPPING;
			}

			ret = veos_do_swap_out_dmaatb(tsk, dir, ent, sync_copy);
			pthread_mutex_lock_unlock(
				&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			if (ret == PPS_DIR_INVALID) {
				break;
			} else if (ret == NO_PPS_BUFF) {
				is_no_buffer = true;
			} else if (ret != 0) {
				/* Error occur during Swap-out of DMAATB
				 * Terminate process.
				 * process soft copy -> Set PG_BUS to released memory
				 * node soft copy -> Not changed
				 * */
				retval = -1;
				goto hndl_return;
			}
			sync_dir_bitmap |= (1ULL << dir);
			pthread_mutex_lock_unlock(
				&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			veos_operate_all_ve_task_lock(group_leader, LOCK);
			ret = veos_check_swapin_interruption(group_leader);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(
				&(tsk->p_ve_mm->thread_group_mm_lock),
				UNLOCK,
				"Failed to release thread_group_mm_lock");
			if (ret == PPS_INTER_SWAPIN) {
				retval = PPS_INTER_SWAPIN;
				goto hndl_return;
			} else if (ret != 0) {
				retval = -1;
				goto hndl_return;
			}

			if (is_process_veos_terminate(
						group_leader, "Swap-out")) {
				retval = PPS_INTER_TERM;
				goto hndl_return;
			}
		}
	}

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
					"Failed to acquire node dmaatb lock");
	for (dir = vnode->nr_avail_cores; dir < DMAATB_DIR_NUM; dir++) {
		if (!(sync_dir_bitmap & (1ULL << dir)))
			continue;
		PPS_DEBUG(cat_os_pps, "Syncing DMAATB Dir %d", dir);
		memcpy(&(vnode->dmaatb.dir[dir]), &(sync_copy->dir[dir]),
							sizeof(uint64_t));
		memcpy(vnode->dmaatb.entry[dir], sync_copy->entry[dir],
				sizeof(uint64_t) * DMAATB_ENTRY_MAX_SIZE);
		/* All entry are freed. */
		hw_dma_map[dir].count = 0;
		/* if this function fails, veos aborts. */
		psm_sync_hw_regs(tsk, _DMAATB, true, dir, 1);
	}

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");

	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	tsk->p_ve_mm->dmaatb_progress = SWAPPED;
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");

	if (is_no_buffer) {
		retval = NO_PPS_BUFF;
	}
hndl_return:
	PPS_DEBUG(cat_os_pps, "Dumping DMAATB in %s", __func__);
	amm_dump_dmaatb(tsk, true);
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Free PPS buffer pages.
 *
 * @param[in] buf_page Pointer to PPS buffer pages.
 * @param[in] pgsz Page size of VE page which used freeing PPS buffer pages.
 * @param[in] numa_node NUMA node number to which VE page
 * which used freeing PPS buffer page belonged.
 *
 * @retval None
 */
void
veos_pps_free_buf_page(void *buf_page, size_t pgsz, int numa_node)
{
	int j;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct block *pps_block = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock), LOCK,
					"Failed to acquire PPS buddy lock");

	PPS_DEBUG(cat_os_pps, "Freeing PPS buff page %p", buf_page);
	pps_block = (struct block *)calloc(1, sizeof(struct block));
	if (pps_block == NULL) {
		PPS_CRIT(cat_os_pps, "Failed to allocate pps_block"
						" due to %s", strerror(errno));
		veos_abort("pps buddy mempool inconsistent due to "
							"calloc failure");
	}
	pps_block->start = (uint64_t)buf_page;
	pps_block->order = size_to_order(pgsz);
	buddy_free(vnode->pps_mp, pps_block);
	for (j = 0; j < vnode->numa_count; j++) {
		PPS_DEBUG(cat_os_pps, "Before :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_mp_used[%d] : 0x%lx",
						j, vnode->pps_mp_used[j]);
	}
	vnode->pps_mp_used[numa_node] -= pgsz;
	for (j = 0; j < vnode->numa_count; j++) {
		PPS_DEBUG(cat_os_pps, "After :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_mp_used[%d] : 0x%lx",
						j, vnode->pps_mp_used[j]);
	}

	pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock), UNLOCK,
					"Failed to release PPS buddy lock");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Free PPS file offset.
 *
 * @param[in] offset Offset of PPS file.
 * @param[in] pgsz Page size of VE page which used freeing PPS buffer pages.
 * @param[in] numa_node NUMA node number to which VE page
 * which used freeing PPS buffer page belonged.
 *
 * @retval None
 */
void
veos_pps_free_file_offset(void *offset, size_t pgsz, int numa_node)
{
	int j;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct block *pps_block = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(vnode->pps_file_offset->buddy_mempool_lock),
			LOCK, "Failed to acquire PPS file offset buddy lock");

	PPS_DEBUG(cat_os_pps, "Freeing PPS file offset %p", offset);
	pps_block = (struct block *)calloc(1, sizeof(struct block));
	if (pps_block == NULL) {
		PPS_CRIT(cat_os_pps, "Failed to allocate pps_block"
						" due to %s", strerror(errno));
		veos_abort("pps buddy mempool inconsistent due to "
							"calloc failure");
	}
	pps_block->start = (uint64_t)offset;
	pps_block->order = size_to_order(pgsz);
	buddy_free(vnode->pps_file_offset, pps_block);
	for (j = 0; j < vnode->numa_count; j++) {
		PPS_DEBUG(cat_os_pps, "Before :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_file_used[%d] : 0x%lx",
						j, vnode->pps_file_used[j]);
	}
	vnode->pps_file_used[numa_node] -= pgsz;
	for (j = 0; j < vnode->numa_count; j++) {
		PPS_DEBUG(cat_os_pps, "After :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_file_used[%d] : 0x%lx",
						j, vnode->pps_file_used[j]);
	}

	pthread_mutex_lock_unlock(&(vnode->pps_file_offset->buddy_mempool_lock),
				UNLOCK,
				"Failed to release PPS file offset buddy lock");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Update sub-status of specified process's all thread.
 *
 * @param[in] group_leader ve_task_struct of specfied process
 * The caller must ensure that this argument is not NULL.
 * @param[in] sstatus New sub-status
 *
 * @retval None
 *
 * @note Acquire ve_task_lock before invoking this.
 */
void
veos_update_substatus(struct ve_task_struct *group_leader,
						enum swap_status sstatus)
{
	struct ve_task_struct *tmp;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	PPS_DEBUG(cat_os_pps, "Update sstatus to %d", sstatus);

	group_leader->sstatus = sstatus;
	list_for_each_entry(tmp, &(group_leader->thread_group), thread_group) {
		tmp->sstatus = sstatus;
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Allocates PPS buffer pages
 *
 * @param[in] pgnum VE page number which is going to be freed.
 * @param[out] numa_node NUMA node number which VE page belongs to.
 *
 * @note Acquire ve_page_node_lock before invoking this.
 */
static void
*veos_pps_alloc_buf_page(pgno_t pgnum, int *numa_node)
{
	int i;
	int mem_numa = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t pps_buff_size;
	void *buff_page = NULL;
	void *retval = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if ((VE_PAGE(vnode, pgnum)->pgsz != PAGE_SIZE_2MB) &&
			(VE_PAGE(vnode, pgnum)->pgsz != PAGE_SIZE_64MB)) {
		PPS_ERROR(cat_os_pps, "Freeing VE page(%ld) size is invalid"
				" 0x%lx", pgnum, VE_PAGE(vnode, pgnum)->pgsz);
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock), LOCK,
					"Failed to acquire PPS buddy lock");

	if (vnode->partitioning_mode)
		mem_numa = (int)paddr2mpnum(pbaddr(pgnum, PG_2M),
						numa_sys_info.numa_mem_blk_sz,
						numa_sys_info.first_mem_node);
	*numa_node = mem_numa;
	pps_buff_size = vnode->pps_buf_size;
	if ((pps_buff_size / vnode->numa_count)
		< vnode->pps_mp_used[mem_numa] + VE_PAGE(vnode, pgnum)->pgsz) {
		PPS_DEBUG(cat_os_pps, "Cannot Swap out page(%ld)"
				"due to limitaion for each NUMA node", pgnum);
		PPS_DEBUG(cat_os_pps,
			"pps_buff_size : 0x%lx, vnode->numa_count : %d, "
			"Memory NUMA node : %d, pps_mp_used[%d] : 0x%lx,"
			" pgsz 0x%lx", pps_buff_size, vnode->numa_count,
			mem_numa, mem_numa, vnode->pps_mp_used[mem_numa],
			VE_PAGE(vnode, pgnum)->pgsz);
			buff_page = ((void *)NO_PPS_BUFF);
		retval = buff_page;
		goto hndl_unlock;
	}

	buff_page = buddy_alloc(vnode->pps_mp,
				size_to_order(VE_PAGE(vnode, pgnum)->pgsz));
	if (buff_page == BUDDY_FAILED) {
		PPS_ERROR(cat_os_pps, "Failed to allocate PPS buff page");
		goto hndl_unlock;
	}
	PPS_DEBUG(cat_os_pps, "allocated %p", buff_page);

	for (i = 0; i < vnode->numa_count; i++) {
		PPS_DEBUG(cat_os_pps, "Before :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_mp_used[%d] : 0x%lx",
						i, vnode->pps_mp_used[i]);
	}
	vnode->pps_mp_used[mem_numa] += VE_PAGE(vnode, pgnum)->pgsz;
	for (i = 0; i < vnode->numa_count; i++) {
		PPS_DEBUG(cat_os_pps, "After :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_mp_used[%d] : 0x%lx",
						i, vnode->pps_mp_used[i]);
	}
	retval = buff_page;

hndl_unlock:
	pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock), UNLOCK,
					"Failed to release PPS buddy lock");
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Allocates PPS file offsets
 *
 * @param[in] pgnum VE page number which is going to be freed.
 * @param[out] numa_node NUMA node number which VE page belongs to.
 *
 * @note Acquire ve_page_node_lock before invoking this.
 */
static void
*veos_pps_alloc_file_offset(pgno_t pgnum, int *numa_node)
{
	int i;
	int mem_numa = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t pps_file_size;
	void *file_offset = NULL;
	void *retval = (void *)-1;
	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if ((VE_PAGE(vnode, pgnum)->pgsz != PAGE_SIZE_2MB) &&
			(VE_PAGE(vnode, pgnum)->pgsz != PAGE_SIZE_64MB)) {
		PPS_ERROR(cat_os_pps, "VE page(%ld) size is invalid"
				" 0x%lx", pgnum, VE_PAGE(vnode, pgnum)->pgsz);
		goto hndl_return;
	}
	pthread_mutex_lock_unlock(&(vnode->pps_file_offset->buddy_mempool_lock),
				LOCK, "Failed to acquire PPS file buddy lock");
	if (vnode->partitioning_mode)
		mem_numa = (int)paddr2mpnum(pbaddr(pgnum, PG_2M),
						numa_sys_info.numa_mem_blk_sz,
						numa_sys_info.first_mem_node);
	*numa_node = mem_numa;
	pps_file_size = vnode->pps_file.size;
	if ((pps_file_size/ vnode->numa_count)
		< vnode->pps_file_used[mem_numa] + VE_PAGE(vnode, pgnum)->pgsz) {
		PPS_DEBUG(cat_os_pps, "Cannot Swap out page(%ld)"
				"due to limitaion for each NUMA node", pgnum);
		PPS_DEBUG(cat_os_pps,
			"pps_file_size : 0x%lx, vnode->numa_count : %d, "
			"Memory NUMA node : %d, pps_file_used[%d] : 0x%lx,"
			" pgsz 0x%lx", pps_file_size, vnode->numa_count,
			mem_numa, mem_numa, vnode->pps_file_used[mem_numa],
			VE_PAGE(vnode, pgnum)->pgsz);
			file_offset = ((void *)NO_PPS_BUFF);
		retval = file_offset;
		goto hndl_unlock;
	}
	file_offset = buddy_alloc(vnode->pps_file_offset,
				size_to_order(VE_PAGE(vnode, pgnum)->pgsz));
	if (file_offset == BUDDY_FAILED) {
		PPS_ERROR(cat_os_pps, "Failed to allocate PPS file offset");
		goto hndl_unlock;
	}
	PPS_DEBUG(cat_os_pps, "allocated %p", file_offset);

	for (i = 0; i < vnode->numa_count; i++) {
		PPS_DEBUG(cat_os_pps, "Before :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_file_used[%d] : 0x%lx",
						i, vnode->pps_file_used[i]);
	}
	vnode->pps_file_used[mem_numa] += VE_PAGE(vnode, pgnum)->pgsz;
	for (i = 0; i < vnode->numa_count; i++) {
		PPS_DEBUG(cat_os_pps, "After :");
		PPS_DEBUG(cat_os_pps, "vnode->pps_file_used[%d] : 0x%lx",
						i, vnode->pps_file_used[i]);
	}
	retval = file_offset;

hndl_unlock:
	pthread_mutex_lock_unlock(&(vnode->pps_file_offset->buddy_mempool_lock),
					UNLOCK,
					"Failed to release PPS file buddy lock");
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Transfer content of VE page which is going to be freed,
 * to PPS buffer pages
 *
 * @param[in] page_start Start address of VE page which is going to be freed
 * @param[in] pgsz Page size of VE page which is going to be freed
 * @param[in] buf_page Pointer to PPS buffer pages
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Don't acquire ve_page_node_lock before invoking this.
 */
static int
veos_pps_do_save_memory_content(uint64_t page_start,
						size_t pgsz, void *buf_page)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ve_dma_hdl *dh = vnode->dh;
	ve_dma_status_t dma_status = 0;
	int retval = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	dma_status = ve_dma_xfer_p_va(dh,
				VE_DMA_VEMAA, 0, page_start,
				VE_DMA_VHVA, getpid(), (uint64_t)buf_page,
				pgsz);
	if (dma_status != VE_DMA_STATUS_OK) {
		PPS_WARN(cat_os_pps, "Failed to save VE memory(0x%lx)"
				" content to PPS buffer(0x%lx) due to %d",
				page_start, (uint64_t)buf_page, dma_status);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Transfer content of VE page which is going to be freed,
 * to PPS buffer pages
 *
 * @param[in] page_start Start address of VE page which is going to be freed
 * @param[in] pgsz Page size of VE page which is going to be freed
 * @param[in] offset Offset of PPS file
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Don't acquire ve_page_node_lock before invoking this.
 */
static int
veos_pps_do_save_file_content(uint64_t page_start, size_t pgsz,
							void *buf, off_t offset)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ve_dma_hdl *dh = vnode->dh;
	ve_dma_status_t dma_status = 0;
	size_t write_ret = 0;
	int retval = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	PPS_DEBUG(cat_os_pps, "page_start : %ld", page_start);
	PPS_DEBUG(cat_os_pps, "pgsz : %ld", pgsz);
	PPS_DEBUG(cat_os_pps, "transfer buff : %p", buf);
	PPS_DEBUG(cat_os_pps, "offset : 0x%lx", offset);

	dma_status = ve_dma_xfer_p_va(dh,
				VE_DMA_VEMAA, 0, page_start,
				VE_DMA_VHVA, getpid(), (uint64_t)buf,
				pgsz);
	if (dma_status != VE_DMA_STATUS_OK) {
		PPS_WARN(cat_os_pps, "Failed to save VE memory(0x%lx)"
				" content to transfer buffer(0x%lx) due to %d",
				page_start, (uint64_t)buf, dma_status);
		goto hndl_return;
	}

	write_ret = pwrite(vnode->pps_file.fd, buf, pgsz, offset);
	if (write_ret != pgsz) {
		PPS_ERROR(cat_os_pps,
		"Failed to write data to PPS file due to %s", strerror(errno));
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Save content of VE page which is going to be freed, to PPS buffer pages
 *
 * @param[in] pgnum Page number of VE page which is going to be freed
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Acquire ve_page_node_lock before invoking this.
 */
int
veos_pps_save_memory_content(pgno_t pgnum)
{
	void *swap_to = NULL;
	uint64_t page_start;
	size_t pgsz;
	int ret, numa_node;
	int pps_mode = -1;
	int retval = -1;
	bool is_to_file = false;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pps_mode = veos_get_swapout_mode();
	PPS_DEBUG(cat_os_pps, "PPS mode is %d", pps_mode);
	if (pps_mode == PPS_MEM_MODE) {
		swap_to = veos_pps_alloc_buf_page(pgnum, &numa_node);
		if (swap_to == NULL) {
			goto func_return;
		} else if (swap_to == (void*)NO_PPS_BUFF) {
			goto func_no_pps_buff;
		}
	} else if (pps_mode == PPS_MIX_MODE)  {
		swap_to = veos_pps_alloc_buf_page(pgnum, &numa_node);
		if ((swap_to == NULL) || (swap_to == (void*)NO_PPS_BUFF)){
			swap_to = veos_pps_alloc_file_offset(pgnum, &numa_node);
			if (swap_to == (void *)-1) {
				goto func_return;
			} else if (swap_to == (void*)NO_PPS_BUFF) {
				goto func_no_pps_buff;
			}
			is_to_file = true;
		}
	} else if (pps_mode == PPS_FILE_MODE) {
        	swap_to = veos_pps_alloc_file_offset(pgnum, &numa_node);
	        if (swap_to == (void *)-1) {
        	        goto func_return;
		} else if (swap_to == (void*)NO_PPS_BUFF) {
			goto func_no_pps_buff;
		}
		is_to_file = true;
	} else {
		PPS_ERROR(cat_os_pps, "PPS mode is invalid");
		goto func_return;
	}
	page_start = VE_PAGE(vnode, pgnum)->page_start;
	pgsz = VE_PAGE(vnode, pgnum)->pgsz;
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
						"Fail to release ve page lock");
	if (!is_to_file) {
		ret = veos_pps_do_save_memory_content(page_start, pgsz, swap_to);
	} else {
		ret = veos_pps_do_save_file_content(page_start, pgsz,
			vnode->pps_file_transfer_buffer, (off_t)swap_to);
	}
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
						"Fail to acquire ve page lock");
	if (ret != 0) {
		if (is_to_file) {
			veos_pps_free_file_offset(swap_to, pgsz, numa_node);
		} else {
			veos_pps_free_buf_page(swap_to, pgsz, numa_node);
		}	
		goto func_return;
	}

	if (!((VE_PAGE(vnode, pgnum)->ref_count == 1) &&
				(VE_PAGE(vnode, pgnum)->dma_ref_count == 0))) {
		PPS_DEBUG(cat_os_pps, "Memory refcnt is incremented"
					" during saving memory content");
		if (is_to_file) {
			veos_pps_free_file_offset(swap_to, pgsz, numa_node);
		} else {
			veos_pps_free_buf_page(swap_to, pgsz, numa_node);
		}
	} else {
		PPS_DEBUG(cat_os_pps, "Memory refcnt is not changed");
		if (is_to_file) {
			VE_PAGE(vnode, pgnum)->swapped_info->file_offset =
								(off_t)swap_to;
		} else {
			VE_PAGE(vnode, pgnum)->swapped_info->buf_page =	swap_to;
		}
		VE_PAGE(vnode, pgnum)->swapped_info->pno = -1;
		VE_PAGE(vnode, pgnum)->swapped_info->perm =
						VE_PAGE(vnode, pgnum)->perm;
		VE_PAGE(vnode, pgnum)->swapped_info->pgsz =
						VE_PAGE(vnode, pgnum)->pgsz;
		VE_PAGE(vnode, pgnum)->swapped_info->flag =
						VE_PAGE(vnode, pgnum)->flag;
		VE_PAGE(vnode, pgnum)->swapped_info->numa_node = numa_node;
		VE_PAGE(vnode, pgnum)->swapped_info->private_data =
					VE_PAGE(vnode, pgnum)->private_data;
	}
	retval = 0;

func_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;

func_no_pps_buff:
	retval = NO_PPS_BUFF;
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/*
 * @brief Do Swap-out a ATB entry
 *
 * @param[in] group_leader ve_task_struct of group leader of Swapping-out process
 * @param[in] dir Directory number corresponding to Swapping-out ATB
 * @param[in] ent Entry number corresponding to Swapping-out DMAATB
 *
 * @retval 0 on Success,
 * @retval DIR_INVALID on Directory is invalid
 * @retval -1 on Failure.
 */
static int
veos_do_swap_out_atb(struct ve_task_struct *group_leader, int dir, int ent,
								size_t pgsize)
{
	pgno_t pgno;
	int retval = 0;
	int ret, i;
	struct ve_mm_struct *mm = group_leader->p_ve_mm;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_swapped_virtual *vrt = NULL;
	atb_reg_t *atb = &(mm->atb[0]);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	if (!ps_isvalid(&(atb->dir[dir]))) {
		retval = PPS_DIR_INVALID;
		goto hndl_return;
	}

	pgno = pg_getpb(&(atb->entry[dir][ent]), PG_2M);
	if ((pgno == PG_BUS) || (pgno == 0)) {
		PPS_TRACE(cat_os_pps, "dir %d, ent %d : "
						"PG_BUS or cleared", dir, ent);
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");

	if (VE_PAGE(vnode, pgno)->pgsz != pgsize) {
		PPS_DEBUG(cat_os_pps, "dir %d, ent %d : page num %ld "
			 "not do swap-out now due to page size is not %ld",
			dir, ent, pgno, pgsize);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		goto hndl_return;
	}

	ret = is_ve_page_swappable(pgno, vnode);
	if (ret != 0) {
		PPS_DEBUG(cat_os_pps, "dir %d, ent %d : "
					  "not capable of Swap-out", dir, ent);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		goto hndl_return;
	}

	ret = allocate_swap_info(pgno, vnode, &vrt, dir, ent, PPS_VIRT_ATB);
	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
	if (ret != 0) {
		PPS_DEBUG(cat_os_pps, "dir %d, ent %d : "
					  "cannot create swap info", dir, ent);
		retval = -1;
		goto hndl_return;
	}

	list_add(&(vrt->pages), &(group_leader->p_ve_mm->swapped_pages));
	for (i = 0; i < vnode->numa_count; i++) {
		pg_setpb(&(mm->atb[i].entry[dir][ent]), PG_BUS, PG_2M);
	}
	pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock), UNLOCK,
				"Failed to release hread_group_mm_lock");

	ret = amm_do_put_page(pgno * PAGE_SIZE_2MB, true);
	pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	if (ret != 0) {
		PPS_DEBUG(cat_os_pps, "VE page(%ld) is not freed due to %s",
							pgno, strerror(-ret));
		list_del(&(vrt->pages));
		for (i = 0; i < vnode->numa_count; i++) {
			pg_clearpfn(&(mm->atb[i].entry[dir][ent]));
			pg_setpb(&(mm->atb[i].entry[dir][ent]), pgno, PG_2M);
		}
		/* clear virt, because it will not be used */
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");
		VE_PAGE(vnode, pgno)->swapped_info->ref_cnt--;
		if (VE_PAGE(vnode, pgno)->swapped_info->ref_cnt == 0) {
			free(VE_PAGE(vnode, pgno)->swapped_info);
			VE_PAGE(vnode, pgno)->swapped_info = NULL;
		}
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to lock e_pages_node_lock");
		if(ret == NO_PPS_BUFF) {
			retval= NO_PPS_BUFF;
		}
		free(vrt);
		goto hndl_return;
	}


hndl_return:
	pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock), UNLOCK,
				"Failed to release hread_group_mm_lock");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Swap out the ATB of specified process.
 *
 * @param[in] group_leader ve_task_struct of group leader of Swapping-out process
 *
 * @retval 0 on Success,
 * @retval SWAPIN_INTER on Swap-in Interrupts,
 * @retval TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval -1 on Failure.
 * */
static int
veos_swap_out_atb(struct ve_task_struct *group_leader, size_t pgsize)
{
	int retval = -1;
	int dir, ent, ret;
	bool is_no_buffer = false;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	for (dir = 0; dir < ATB_DIR_NUM; dir++) {
		for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
			pthread_mutex_lock_unlock(&(group_leader->p_ve_mm->
				thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			veos_operate_all_ve_task_lock(group_leader, LOCK);
			ret = veos_check_swapin_interruption(group_leader);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(group_leader->p_ve_mm->
				thread_group_mm_lock),
				UNLOCK,
				"Failed to release thread_group_mm_lock");
			if (ret == PPS_INTER_SWAPIN) {
				retval = PPS_INTER_SWAPIN;
				goto hndl_return;
			} else if (ret != 0) {
				kill(group_leader->pid, SIGKILL);
				goto hndl_return;
			}

			if (is_process_veos_terminate(
						group_leader, "Swap-out")) {
				retval = PPS_INTER_TERM;
				goto hndl_return;
			}

			ret = veos_do_swap_out_atb(group_leader, dir, ent,
								pgsize);
			if (ret == PPS_DIR_INVALID) {
				break;
			} else if (ret == NO_PPS_BUFF) {
				/* PPS buffer or PPS file is full */
				is_no_buffer = true;
			} else if (ret != 0) {
				/* Swap-out fail, but process can continue */
				retval = 0;
				goto hndl_return;
			}
		}
	}

	if (is_no_buffer) {
		retval = NO_PPS_BUFF;
	} else {
		retval = 0;
	}
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Swap out the ATB and DMAATB of specified process.
 *
 * @param[in] tsk ve_task_struct of Swapping-out process
 * The caller must ensure that this argument is not NULL.
 *
 * @retval 0 on Success,
 * @retval 1 on Swap-in Interrupts,
 * @retval NO_PPS_BUFF on PPS buffer or PPS file is full
 * @retval -1 on Failure.
 */
int
ve_do_swapout(struct ve_task_struct *tsk)
{
	int retval = -1;
	int ret;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_task_struct *group_leader = tsk->group_leader;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	PPS_DEBUG(cat_os_pps, "Start Swap-out against %d", group_leader->pid);
	dump_process_atb(tsk);

	/* Set flag to false,
	 * file can be deleted after swap in when no resource is swapped out
	 * */
	pthread_mutex_lock_unlock(&(vnode->pps_file_lock), LOCK,
					"Failed to aqcuire pps_file_lock");
	vnode->pps_file.not_del_after_swapin = false;
	pthread_mutex_lock_unlock(&(vnode->pps_file_lock), UNLOCK,
					"Failed to release pps_file_lock");

	veos_veshm_update_is_swap_out(tsk, true);
	veos_veshm_test_paddr_array_all(tsk);

	ret = veos_stop_udma(tsk);
	if (ret != 0) {
		/* If stopping Uesr mode DMA, VEOS cannot release DMAATB.
		 * User cannot check usage of DMAATB, so user might be confused
		 * if swap-out succeeds in this condition.
		 * */
		PPS_ERROR(cat_os_pps, "Failed to stop Uesr mode DMA, kill %d",
							group_leader->pid);
		kill(group_leader->pid, SIGKILL);
		goto hndl_return;
	} else {
		ret = veos_swap_out_dmaatb(tsk);
		if (ret == PPS_INTER_SWAPIN) {
			/* Swap-in Interrupts */
			goto hndl_swapin;
		} else if (ret == PPS_INTER_TERM) {
			/* Process termination or VEOS termination Interrupt */
			goto hndl_return;
		} else if (ret == NO_PPS_BUFF) {
			/* PPS buffer or PPS file is full */
			goto hndl_no_pps_buff;
		} else if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to release DMAATB, "
						"kill %d", group_leader->pid);
			kill(group_leader->pid, SIGKILL);
			goto hndl_return;
		}
	}

	dump_process_atb(tsk);

	ret = veos_swap_out_atb(group_leader, PAGE_SIZE_64MB);
	if (ret == PPS_INTER_SWAPIN) {
		/* Swap-in Interrupts */
		goto hndl_swapin;
	} else if (ret == PPS_INTER_TERM) {
		/* Process termination or VEOS termination Interrupt */
		goto hndl_return;
	} else if (ret == NO_PPS_BUFF) {
		/* PPS buffer or PPS file is full */
		goto hndl_no_pps_buff;
	} else if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Swap-out 64MB memory failed due to"
							" internal errnor");
		goto hndl_return;
	}

	ret = veos_swap_out_atb(group_leader, PAGE_SIZE_2MB);
	if (ret == PPS_INTER_SWAPIN) {
		/* Swap-in Interrupts */
		goto hndl_swapin;
	} else if (ret == PPS_INTER_TERM) {
		/* Process termination or VEOS termination Interrupt */
		goto hndl_return;
	} else if (ret == NO_PPS_BUFF) {
		/* PPS buffer or PPS file is full */
		goto hndl_no_pps_buff;
	} else if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Swap-out 2MB memory failed due to"
							" internal errnor");
		goto hndl_return;
	}

hndl_swapin:
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	veos_operate_all_ve_task_lock(group_leader, LOCK);
	ret = veos_check_swapin_interruption(group_leader);
	if (ret == PPS_INTER_SWAPIN) {
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");
		retval = PPS_INTER_SWAPIN;
		goto hndl_return;
	} else if ((ret != 0) ||
			is_process_veos_terminate(group_leader, "Swap-out")) {
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");
		if (ret != 0)
			kill(group_leader->pid, SIGKILL);
		goto hndl_return;
	}
	veos_update_substatus(group_leader, SWAPPED_OUT);
	veos_operate_all_ve_task_lock(group_leader, UNLOCK);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");
	PPS_DEBUG(cat_os_pps, "Swap-out against %d finishes",
							group_leader->pid);
	dump_process_atb(tsk);

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
hndl_no_pps_buff:
	retval = ret;
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}
