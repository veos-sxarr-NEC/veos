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

#include "ived_ipc.h"
#include "ived.pb-c.h"
#include "veos_veshm_ipc.h"

#include "velayout.h"
#include "ve_swap.h"
#include "ve_list.h"
#include "veos.h"
#include "veos_ived.h"
#include "locking_handler.h"
#include "task_mgmt.h"
#include "task_sched.h"
#include "ve_mem.h"
#include "buddy.h"
#include "dma.h"
#include "ve_shm.h"
#include "ve_memory.h"
#include "mman_ve.h"
#include "ve_memory_def.h"
#include <veos_arch_defs.h>
#include "veos_veshm_core.h"
#include "ived_common.h"
#include "veos_ived_private.h"

#define INVALID_VESHM		0xFFFFFFFFFFFFFFFFll

/**
 * @brief Return current non-swappable memory size of a specified process.
 *
 * @param[in] tsk Pointer to ve_task_struct of specified process.
 * @param[in] pid PID of specified process.
 *
 * @return Current non-swappable memory size on Success, -errno on failure.
 */
int64_t
veos_pps_get_cns(struct ve_task_struct *tsk, pid_t pid)
{
	int64_t cns = 0;
	uint64_t uss_cns, pss_cns;
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *tmp;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL) {
		PPS_ERROR(cat_os_pps, "specified ve_task_struct is null");
		return -ECANCELED;
	}

	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), LOCK,
				  "Failed to acquire thread_group_mm_lock");
	group_leader = tsk->group_leader;
	veos_operate_all_ve_task_lock(group_leader, LOCK);
	if (tsk->group_leader->pid != tsk->pid) {
		PPS_DEBUG(cat_os_pps, "%d is child thread", pid);
		cns = -ESRCH;
	} else if (group_leader->ptraced) {
		PPS_DEBUG(cat_os_pps, "%d is traced", pid);
		cns = -EPERM;
	} else {
		list_for_each_entry(
			tmp, &(group_leader->thread_group), thread_group) {
			if (tmp->ptraced) {
				PPS_DEBUG(cat_os_pps, "%d is traced", pid);
				cns = -EPERM;
			}
		}
	}
	veos_operate_all_ve_task_lock(group_leader, UNLOCK);
	if (cns == 0) {
		get_uss(tsk->p_ve_mm, &uss_cns);
		get_pss(tsk->p_ve_mm, &pss_cns);
		cns = uss_cns + pss_cns;
		PPS_DEBUG(cat_os_pps, "PID %d, cns : %ld", pid, cns);
	}
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
				  "Failed to release thread_group_mm_lock");
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return cns;
}

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
int
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
 * @brief Delete and free information about Swapped-out VESHM owned list
 *
 * @param[in] tsk ve_task_struct of exited process.
 */
void
del_swapped_owned_veshm_list(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry_copy = NULL;
	struct list_head *list_p, *list_n;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}

	if (tsk->group_leader != tsk){
		PPS_ERROR(cat_os_pps, "Not group leader");
		goto hndl_return;
	}

	resource = tsk->ived_resource;
	if (resource == NULL){
		PPS_ERROR(cat_os_pps, "ived_resource is NULL");
		goto hndl_return;
	}

	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_p = resource->swapped_owned_veshm_list.next;
	/* Loop swapped VESHM owned information*/
	list_for_each_safe(list_p, list_n, &resource->swapped_owned_veshm_list) {
		entry_copy = list_entry(list_p, struct owned_veshm_info, list);
		if (entry_copy == NULL){
			PPS_ERROR(cat_os_pps, "entry_copy of swapped_owned_veshm_list is NULL");
			continue;
		}
		list_del(&entry_copy->list);
		free(entry_copy);
	}
	pthread_rwlock_unlock(&resource->ived_resource_lock);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Delete and free information about Swapped-out veshm attach list
 *
 * @param[in] tsk ve_task_struct of exited process.
 */
void
del_swapped_attach_veshm_list(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct attaching_veshm_info *entry_copy=NULL;
	struct list_head *list_p, *list_n;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}

	if (tsk->group_leader != tsk){
		PPS_ERROR(cat_os_pps, "Not group leader");
		goto hndl_return;
	}

	resource = tsk->ived_resource;
	if (resource == NULL){
		PPS_ERROR(cat_os_pps, "ived_resource is NULL");
		goto hndl_return;
	}
	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_p = resource->swapped_attach_veshm_list.next;
	/* Loop swapped VESHM attached information*/
	list_for_each_safe(list_p, list_n, &resource->swapped_attach_veshm_list) {
		entry_copy = list_entry(list_p, struct attaching_veshm_info, list);
		if (entry_copy == NULL){
			PPS_ERROR(cat_os_pps, "entry_copy of swapped_attach_veshm_list is NULL");
			continue;
		}
		list_del(&entry_copy->list);
		free(entry_copy);
	}
	pthread_rwlock_unlock(&resource->ived_resource_lock);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
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
			for ( ; vrt->phy->remained_page_ref_count > 0;
					vrt->phy->remained_page_ref_count--) {
				amm_do_put_page_no_lock(pno * PAGE_SIZE_2MB, true);
			}
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

	for (dir = 0; dir < VEOS_ATB_DIR_NUM; dir++) {
		if (!ps_isvalid(&(tsk->p_ve_mm->atb[0].dir[dir])))
			continue;
		PPS_DEBUG(cat_os_pps, "DIR[%d] : 0x%lx", dir,
					tsk->p_ve_mm->atb[0].dir[dir].data);
		for (ent = 0; ent < VEOS_ATB_ENTRY_MAX_SIZE; ent++) {
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
int
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
		phy->remained_page_ref_count = 0;
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

	if (page == NULL)
		return retval;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	retval = is_ve_page_swappable_core(
		page->pci_ns_count, page->flag, page->perm, pgno, page->owner);
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 *
 * @brief Check whether specified VE page is capable of Swap-out or not.
 *        This function can be used in memory allocation procedure.
 *
 * @param[in] pci_ns_count Number indicates how many times page was registered with pciatb.
 * @param[in] flag Flag of VE page.
 * @param[in] perm Permission of VE page.
 * @param[in] pgno VE page number.
 * @param[in] owner Owner of VE page.
 *
 * @retval 0 on swappable
 * @retval -1 on not swappable.
 *
 * @note Acquire ve_page_node_lock before invoking this. */
int
is_ve_page_swappable_core(
		uint64_t pci_ns_count, uint64_t flag,
		uint64_t perm, pgno_t pgno, struct ve_task_struct *owner)
{
	int retval = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	assert(pthread_mutex_trylock(&(VE_NODE(0)->ve_pages_node_lock))
								== EBUSY);

	PPS_DEBUG(cat_os_pps, "pgno : %ld, flag : 0x%lx, perm : %ld",
							pgno, flag, perm);

	if (flag & MAP_VDSO) {
		PPS_DEBUG(cat_os_pps, "%ld is VDSO", pgno);
		goto hndl_return;
	}

	if ((flag & PG_SHM) || (flag & MAP_SHARED)) {
		PPS_DEBUG(cat_os_pps, "%ld is shared", pgno);
		goto hndl_return;
	}

	if (flag & PG_PTRACE) {
		PPS_DEBUG(cat_os_pps, "%ld is traced", pgno);
		goto hndl_return;
	}

	if (!(flag & MAP_ANON) &&
		!((flag & MAP_PRIVATE) && (perm & PROT_WRITE))) {
		PPS_DEBUG(cat_os_pps,
			"%ld is not anonymous or read-only fileback memory",
			pgno);
		goto hndl_return;
	}

	if (pci_ns_count > 0) {
		PPS_DEBUG(cat_os_pps, "%ld is registered with PCIATB and without"
			" VESWAPPABLE", pgno);
		goto hndl_return;
	}

	if (owner != NULL) {
		PPS_DEBUG(cat_os_pps, "%ld has owner", pgno);
		goto hndl_return;
	}

	retval = 0;
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
	return (*_veos_arch_ops->arch_pps_veos_swap_out_dmaatb)(tsk);
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
 * @brief This function send data between VEOS and PPS file handler process
 *
 * @param[in] sockfd File descriptor of socket
 * @param[in] communication data of send
 *
 * @retval >0 on Success,
 * @retval -1 on Failure.
 *
 */

int send_pps_file_handler_comm(int sockfd, struct ve_swap_file_hdr_comm message)
{
	struct msghdr msg;
	char buf[CMSG_SPACE(sizeof(int))];
	int status = 0;
	struct iovec iov;
	struct cmsghdr *cmsg;
	int *ppsffd;
	ssize_t size;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	int pps_f_fd = -1;
	memset(&msg, '\0', sizeof(struct msghdr));
	memset(buf, '\0', sizeof(buf));
	memset(&iov, '\0', sizeof(struct iovec));

	/* Transmit at least 1 byte of real data in order to send ancillary
	 * data */
	iov.iov_base = &message;
	iov.iov_len = sizeof(struct ve_swap_file_hdr_comm);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if((message.kind == PPS_F_HDR_OPEN_FD_RET) && !(message.int_ret < 0)){
		/* Only when sending valid file descriptor */
		pps_f_fd = message.int_ret;
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		/* Set message header to describe ancillary data that we want
		 * to send */
		cmsg = CMSG_FIRSTHDR(&msg);
		if (NULL == cmsg) {
			PPS_ERROR(cat_os_pps,"control data err in file handler"
				" comm. errno: %d",errno);
			status = -1;
			goto hndl_return;
		}

		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(pps_f_fd));
		ppsffd = (int *) CMSG_DATA(cmsg);
		memcpy(ppsffd, &pps_f_fd, sizeof(int));
	}

	/* Do the actual send */
	size = sendmsg(sockfd, &msg, 0);
	if (size != sizeof(struct ve_swap_file_hdr_comm)) {
		PPS_ERROR(cat_os_pps, "sendmsg err in file handler comm. "
				" %s(%d)", strerror(errno),errno);
		status = -1;
		goto hndl_return;
	}
	status = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return status;
}

/**
 * @brief This function recieve data between VEOS and PPS file handler process
 *
 * @param[in] sockfd socket descriptor
 * @param[out] communication data of recieve
 *
 * @retval 0 on Success
 * @retval -1 on Failure
 */
int recv_pps_file_handler_comm(int sockfd, struct ve_swap_file_hdr_comm *message)
{
	struct msghdr msgh;
	ssize_t size;
	int status = 0;
	struct iovec iov;
	struct cmsghdr *cmsg;
	unsigned char *data;
	union {
		struct cmsghdr cmh;
		char c_buffer[CMSG_SPACE(sizeof(int))];
	} control_un;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	memset(&msgh, '\0', sizeof(struct msghdr));
	memset(&iov, '\0', sizeof(struct iovec));

	/* Set 'control_un' to dsescribe ancillary data that we want to
	 * receive */
	control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
	control_un.cmh.cmsg_level = SOL_SOCKET;
	control_un.cmh.cmsg_type = SCM_RIGHTS;

	/* Set 'msg' fields to describe 'control_un' */
	msgh.msg_control = control_un.c_buffer;
	msgh.msg_controllen = sizeof(control_un.c_buffer);

	/* Set fields of 'msgh' to point to buffer used to receive(real)
	 * data read by recvmsg() */
	iov.iov_base = message;
	iov.iov_len = sizeof(struct ve_swap_file_hdr_comm);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	/* Receive real plus ancillary data */
	size = recvmsg(sockfd, &msgh, MSG_WAITALL);
	if (size != sizeof(struct ve_swap_file_hdr_comm)){
		if (size < 0){
			PPS_ERROR(cat_os_pps,"recvmsg err in file handler comm."
				" size:%ld error:%s(%d)",size,strerror(errno),
					errno);
			status = -1;
		}else{
			PPS_ERROR(cat_os_pps,"recvmsg message shortage in file "
			 "handler comm. size:%ld error:%s(%d)",size,
				strerror(errno),errno);
			status = -1;
		}
		goto hndl_return;
	}

	if((message->kind == PPS_F_HDR_OPEN_FD_RET) && !(message->int_ret < 0)){
		/* when valid file descriptor return,
		 * Get the received file descriptor (which is typically a 
		 * different file descriptor number that was used in the sending
		 * process) */
		cmsg = CMSG_FIRSTHDR(&msgh);
		if ((NULL==cmsg) || (cmsg->cmsg_len != CMSG_LEN(sizeof(int)))) {
			PPS_ERROR(cat_os_pps,"Bad cmsg header / message length");
			status = -1;
			goto hndl_return;
		}

		if ((cmsg->cmsg_level != SOL_SOCKET) ||
			(cmsg->cmsg_type != SCM_RIGHTS)) {
			PPS_ERROR(cat_os_pps,"Bad access rights received from "
					"sender process");
			status = -1;
			goto hndl_return;
		}

		data = CMSG_DATA(cmsg);
		message->int_ret = *(int *)data;
	}
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return status;
}


/**
 * @brief This function request to write PPS file to PPS file handler
 *
 * @param[in] sockfd File descriptor of socket
 * @param[in] pgsz Page size of VE page which is going to be freed
 * @param[in] offset Offset of PPS file
 *
 * @retval write size,
 * @retval -1 on Failure. 
 *
 */
ssize_t 
write_pps_file_handler(int sockfd, size_t pgsz, off_t offset)
{
	int retval = -1;
	ssize_t write_sz = -1;
	struct ve_swap_file_hdr_comm msg;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
	msg.kind = PPS_F_HDR_WRITE_REQ;
	msg.cnt = pgsz;
	msg.off = offset;
	retval = send_pps_file_handler_comm(sockfd, msg);
	if(retval < 0){
		PPS_ERROR(cat_os_pps,
		"Failed to send data from file handler");
		write_sz = -1;
		goto hndl_return;
	}
	memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
	retval = recv_pps_file_handler_comm(sockfd, &msg);
	if(retval < 0){
		PPS_ERROR(cat_os_pps,
		"Failed to recv data from file handler");
		write_sz = -1;
		goto hndl_return;
	}
	if (msg.ssize_ret < 0){
		errno = msg.r_errno;
	}
	write_sz = msg.ssize_ret;

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return write_sz;
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

	if(vnode->pps_file.is_created_by_root){
		write_ret = pwrite(vnode->pps_file.fd, buf, pgsz, offset);
		if (write_ret != pgsz) {
			if(write_ret == -1){
				PPS_ERROR(cat_os_pps,
				"Failed to write data to PPS file due to %s",
							strerror(errno));
			}else{
				PPS_ERROR(cat_os_pps,
				"Failed to write data to PPS file %ld %ld %ld", 
							write_ret, pgsz, offset);
			}
			goto hndl_return;
		}
	}else{
		write_ret = write_pps_file_handler(vnode->pps_file.sockfd, pgsz, 
								offset);
		if (write_ret != pgsz) {
			if(write_ret == -1){
				PPS_ERROR(cat_os_pps,
				"Failed to write data to PPS file due to %s", 
							strerror(errno));
			}else{
				PPS_ERROR(cat_os_pps,
				"Failed to write data to PPS file %ld %ld", 
							write_ret, pgsz);
			}
			goto hndl_return;
		}
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
		pthread_mutex_lock_unlock(&vnode->pps_file_buffer_lock, LOCK,
							"Fail to acquire pps file buffer lock");
		ret = veos_pps_do_save_file_content(page_start, pgsz,
			vnode->pps_file_transfer_buffer, (off_t)swap_to);
		pthread_mutex_lock_unlock(&vnode->pps_file_buffer_lock, UNLOCK,
							"Fail to release pps file buffer lock");
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
		if ((ret == NO_PPS_BUFF) || (ret == -EBUSY))
			VE_PAGE(vnode, pgno)->swapped_info->remained_page_ref_count--;
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

	for (dir = 0; dir < VEOS_ATB_DIR_NUM; dir++) {
		for (ent = 0; ent < VEOS_ATB_ENTRY_MAX_SIZE; ent++) {
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
 * @brief Check a VESHM owner information is need copy or not.
 *
 * @param[in] veshm VESHM owner information struct.
 *
 * @retval 0 on not need copy
 * @retval 1 on need copy
 */
static int
is_need_copy_owned_info(struct owned_veshm_info *veshm)
{
	int i;
	int ret = 0;
	pgno_t pgno;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	PPS_DEBUG(cat_os_pps, "veshm->pciatb_entries: %d", veshm->pciatb_entries);
	if ((veshm->pciatb_entries != 0)
		&& (veshm->register_cnt_proc_swappable > 0)) {
		PPS_DEBUG(cat_os_pps, "veshm->physical_pages: %ld", veshm->physical_pages);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");
		for (i = 0; i < veshm->physical_pages; i++) {
			if (veshm->paddr_array[i] == INVALID_VESHM) {
				break;
			}
			pgno = pfnum((veshm->paddr_array[i]), PG_2M);
			PPS_DEBUG(cat_os_pps, "pgno: %ld", pgno);
			if ((is_ve_page_swappable(pgno, vnode) == 0)) {
				PPS_DEBUG(cat_os_pps, "Get swappable page");
				ret = 1;
				break;
			}
		}
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
	}
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return ret;
}

/**
 * @brief Close VESHMs when swap-out
 *
 * @param[in] tsk of Swapping-out process
 *
 * @retval 0 on Success,
 * @retval SWAPIN_INTER on Swap-in Interrupts,
 * @retval TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval NO_PPS_BUFF on PPS buffer or PPS file is full
 * @retval -1 on Failure
 */
static int
veos_swap_out_close_veshm(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry = NULL, *entry_copy=NULL;
	struct list_head *list_p, *list_n;
	struct ve_task_struct *group_leader = NULL;
	int retval = -1;
	int ret = -1;
	int unlocked = 0;
	int i;
	int close_cnt = 0;
	RpcVeshmSubClose request_close;
	IvedReturn reply;
	RpcVeshmReturn veshm_ret;
	ProtobufCBinaryData uuid1, uuid2;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}
	group_leader = tsk->group_leader;
	resource = tsk->ived_resource;

	list_p = resource->owned_veshm_list.next;
	/* loop VESHM owned information */
	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_for_each_safe(list_p, list_n, &resource->owned_veshm_list) {
		PPS_DEBUG(cat_os_pps, "Pickup a member of owned_veshm_list ");
		veos_operate_all_ve_task_lock(group_leader, LOCK);
		ret = veos_check_swapin_interruption(group_leader);
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		if (ret == PPS_INTER_SWAPIN) {
			retval = PPS_INTER_SWAPIN;
			PPS_DEBUG(cat_os_pps, "PPS INTER SWAPIN");
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		} else if (ret != 0) {
			kill(group_leader->pid, SIGKILL);
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		}

		if (is_process_veos_terminate(group_leader, "Swap-out")) {
			retval = PPS_INTER_TERM;
			PPS_DEBUG(cat_os_pps, "PPS INTER TERM");
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		}
		/* get owned VESHM information */
		PPS_DEBUG(cat_os_pps, "Get an owned VESHM information");
		entry = list_entry(list_p, struct owned_veshm_info, list);
		if (is_need_copy_owned_info(entry)) {
			if (isset_flag(entry->status_flag, IVED_PROC_EXIT)) {
				continue;
			}

			PPS_DEBUG(cat_os_pps, "Copy owned_veshm_info");
			/* copy owned_veshm_info */
			entry_copy = (struct owned_veshm_info *)malloc
				(sizeof (struct owned_veshm_info));
			if (entry_copy == NULL) {
				PPS_ERROR(cat_os_pps, "Failed to create owned_veshm_info"
					" entory");
				pthread_rwlock_unlock(&resource->ived_resource_lock);
				goto hndl_return;
			}

			memcpy(entry_copy, entry, sizeof (struct owned_veshm_info));
			/* We don't know whether all the close processes are successful
			 * at here, so set register_cnt_proc_swappable to 0 */
			close_cnt = entry_copy->register_cnt_proc_swappable;
			entry_copy->register_cnt_proc_swappable = 0;
			entry_copy->pciatb_slot = NULL;
			entry_copy->paddr_array = NULL;

			/* close veshm */
			PPS_DEBUG(cat_os_pps, "Make an info for closing VESHM");
			rpc_veshm_sub_close__init(&request_close);
			ived_return__init(&reply);
			rpc_veshm_return__init(&veshm_ret);
			reply.veshm_ret = &veshm_ret;

			request_close.owner_pid = resource->pid;
			set_flag(request_close.mode_flag, VE_SWAPPABLE); 
			set_flag(request_close.mode_flag, VE_REQ_PROC);

			uuid1.len                     = sizeof(uuid_t);
			uuid1.data                   = (uint8_t *)entry_copy->uuid_veshm;
			request_close.has_uuid_veshm = 1;
			request_close.uuid_veshm     = uuid1;

			uuid2.len                     = sizeof(uuid_t);
			uuid2.data                   = (uint8_t *)entry_copy->uuid_proc;
			request_close.has_uuid_proc  = 1;
			request_close.uuid_proc      = uuid2;

			pthread_rwlock_unlock(&resource->ived_resource_lock);
			unlocked = 1;

			dump_uuid("close all proc", entry_copy->uuid_proc);
			dump_uuid("close all veshm", entry_copy->uuid_veshm);

			for (i = close_cnt; i > 0; i--) {
				PPS_DEBUG(cat_os_pps, "Invoke do veos_veshm_close_common to"
					" close VESHM %dth in %d",
					i, entry->register_cnt_proc_swappable);
				ret = veos_veshm_close_common(&request_close, &reply, NULL, NULL);
				PPS_DEBUG(cat_os_pps,
					"ret:%d, reply.ret_val:%"PRIx64", reply.error:%d",
					ret, reply.retval, reply.error);
				if (reply.error == -NO_PPS_BUFF) {
					retval = NO_PPS_BUFF;
					PPS_DEBUG(cat_os_pps, "PPS NO_PPS_BUFF");
					break;
				} else if ((ret != 0) || (reply.error != 0)) {
					PPS_ERROR(cat_os_pps, "Close VESHM is failed, "
						"errno=%d", reply.error);
					break;
				} else {
					entry_copy->register_cnt_proc_swappable++;
				}
			}
			/* And add to list */
			PPS_DEBUG(cat_os_pps, "Add to swapped_owned_veshm_list");
			pthread_rwlock_wrlock(&resource->ived_resource_lock);
			unlocked = 0;
			list_add(&entry_copy->list, &resource->swapped_owned_veshm_list);
		}
		if (unlocked) {
			pthread_rwlock_wrlock(&resource->ived_resource_lock);
			unlocked = 0;
		}
	}
	if (!unlocked)
		pthread_rwlock_unlock(&resource->ived_resource_lock);
	retval = 0;

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Detach VESHMs when swap-out
 *
 * @param[in] tsk of Swapping-out process
 *
 * @retval 0 on Success,
 * @retval SWAPIN_INTER on Swap-in Interrupts,
 * @retval TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval -1 on Failure
 */
static int
veos_swap_out_detach_veshm(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct attaching_veshm_info *entry = NULL, *entry_copy=NULL;
	struct list_head *list_p, *list_n;
	struct ve_task_struct *group_leader = NULL;
	int retval = -1;
	int ret = -1;
	int unlocked = 0;
	int i = 0;

	RpcVeshmSubDetach request_detach = RPC_VESHM_SUB_DETACH__INIT;
	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}
	group_leader = tsk->group_leader;
	resource = tsk->ived_resource;

	list_p = resource->attach_veshm_list.next;
	/* loop VESHM attach information*/
	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_for_each_safe(list_p, list_n, &resource->attach_veshm_list) {
		PPS_DEBUG(cat_os_pps, "Pickup a member of attach_veshm_list");
		veos_operate_all_ve_task_lock(group_leader, LOCK);
		ret = veos_check_swapin_interruption(group_leader);
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		if (ret == PPS_INTER_SWAPIN) {
			retval = PPS_INTER_SWAPIN;
			PPS_DEBUG(cat_os_pps, "PPS INTER SWAPIN");
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		} else if (ret != 0) {
			kill(group_leader->pid, SIGKILL);
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		}

		if (is_process_veos_terminate(group_leader, "Swap-out")) {
			retval = PPS_INTER_TERM;
			PPS_DEBUG(cat_os_pps, "PPS INTER TERM");
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		}
		/* Get a VESHM attach information */
		PPS_DEBUG(cat_os_pps, "Get a VESHM attach information");
		entry = list_entry(list_p, struct attaching_veshm_info, list);
		if (isset_flag(entry->req_mode_flag, VE_SWAPPABLE) &&
				(isset_flag(entry->req_mode_flag, VE_REGISTER_VEHVA))) {
			PPS_DEBUG(cat_os_pps, "VE_SWAPPABLE is set");
			/* Copy attaching_veshm_info */
			PPS_DEBUG(cat_os_pps, "Copy attaching_veshm_info");
			entry_copy = (struct attaching_veshm_info *)malloc
				(sizeof (struct attaching_veshm_info));
			if (entry_copy == NULL) {
				PPS_ERROR(cat_os_pps, "Failed to create attaching_veshm_info"
					" entory");
				pthread_rwlock_unlock(&resource->ived_resource_lock);
				goto hndl_return;
			}
			memcpy(entry_copy, entry, sizeof (struct attaching_veshm_info));
			/* We don't know whether all the detach processes are successful
			 * at here, so set ref_cnt_vehva to 0 */
			entry_copy->ref_cnt_vehva = 0;
			/* Detach VESHM */
			PPS_DEBUG(cat_os_pps, "Make an info for detaching VESHM");
			ived_return__init(&reply);
			rpc_veshm_return__init(&veshm_ret);
			reply.veshm_ret = &veshm_ret;

			request_detach.user_uid   = tsk->uid;
			request_detach.user_pid   = tsk->tgid;
			request_detach.address    = entry->vehva;
			request_detach.mode_flag  = entry->req_mode_flag &
				(VE_REGISTER_VEHVA | VE_REGISTER_VEMVA | VE_MEM_LOCAL);

			pthread_rwlock_unlock(&resource->ived_resource_lock);
			unlocked = 1;

			set_flag(request_detach.mode_flag, VE_REQ_PROC);

			PPS_DEBUG(cat_os_pps, "Do veos_veshm_detach_common to detach"
				" VESHM");
			for (i = entry->ref_cnt_vehva; i > 0 ; i--) {
				ret = veos_veshm_detach_common(&request_detach, &reply);
				PPS_DEBUG(cat_os_pps, "ret:%d, reply.ret_val:%"PRIx64"",
					ret, reply.retval);
				if ((ret != 0) || (reply.error != 0)) {
					PPS_ERROR(cat_os_pps, "Detach VESHM is failed, "
						"errno=%d", reply.error);
					break;
				} else {
					entry_copy->ref_cnt_vehva++;
				}
			}
			/* And add to list */
			PPS_DEBUG(cat_os_pps, "Add info to swapped_attach_veshm_list");
			pthread_rwlock_wrlock(&resource->ived_resource_lock);
			unlocked = 0;
			list_add(&entry_copy->list, &resource->swapped_attach_veshm_list);
		}
		if (unlocked) {
			pthread_rwlock_wrlock(&resource->ived_resource_lock);
			unlocked = 0;
		}
	}
	if (!unlocked)
		pthread_rwlock_unlock(&resource->ived_resource_lock);

	retval = 0;

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
	int dma_size = 8;
	ve_dma_status_t dmast = 0;
	int already_swapped_out = 0;

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

	already_swapped_out = veos_veshm_update_is_swap_out(tsk, true);
	if (!already_swapped_out)
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
		/* Copy 8 byte from ve zero page to ve zero page.
		 * To prevent the "posted write" from overtaking the "read".
		 */
		dmast = ve_dma_xfer_p_va(vnode->dh, VE_DMA_VEMAA, 0,
					vnode->zeroed_page_address,VE_DMA_VEMAA, 0,
					(vnode->zeroed_page_address + dma_size), dma_size);
		if (dmast != VE_DMA_STATUS_OK) {
			PPS_WARN(cat_os_pps, "Failed to copy ve zero page due to %d",
						dmast);
		}

		ret = veos_swap_out_detach_veshm(tsk);
		if (ret == PPS_INTER_SWAPIN) {
			/* Swap-in Interrupts */
			goto hndl_swapin;
		} else if (ret == PPS_INTER_TERM) {
			/* Process termination or VEOS termination Interrupt */
			goto hndl_return;
		} else if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Detach VESHM failed due to internal errnor");
			/* Even if detach VESHM is failed, swap-out is successful,
			 * because the memory has not been corrupted */
		}

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

	ret = veos_swap_out_close_veshm(tsk);
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
		PPS_ERROR(cat_os_pps, "Close VESHM failed due to internal errnor");
		/* Even if close VESHM is failed, swap-out is successful,
		 * because the memory has not been corrupted */
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
