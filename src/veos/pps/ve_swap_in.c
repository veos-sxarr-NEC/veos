
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
 * @file ve_swap_in.c
 * @brief PPS swap-in functions in VEOS
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
#include "ve_memory_def.h"
#include <veos_arch_defs.h>
#include "dmaatb_api.h"
#include "veos_veshm_core.h"
#include "ived_common.h"
#include "vehva_mgmt.h"
#include "veos_ived_private.h"

extern void dump_process_atb(struct ve_task_struct *);

/**
 * @brief Set true to atb_dirty flag of all threads.
 *
 * @param[in] group_leader ve_task_struct of thread group leader of Swapping-in
 * process.
 *
 * @retval None
 *
 * @note Acquire ve_task_lock before invoking this.
 */

static void
veos_set_atb_dirty(struct ve_task_struct *group_leader)
{
	struct ve_task_struct *tmp;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	group_leader->atb_dirty = 0xffffffff;
	list_for_each_entry(tmp, &(group_leader->thread_group), thread_group) {
		tmp->atb_dirty = 0xffffffff;
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Transfer saved content of VE page to new VE page.
 *
 * @param[in] page_start Start address of new VE page
 * @param[in] pgsz Page size of new VE page
 * @param[in] buf_page Pointer to PPS buffer pages which stores saved content
 * of VE page
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Don't acquire ve_page_node_lock before invoking this.
 */
int
veos_pps_do_restore_memory_content(uint64_t page_start,
						size_t pgsz, void *buf_page)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ve_dma_hdl *dh = vnode->dh;
	ve_dma_status_t dma_status = 0;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	dma_status = ve_dma_xfer_p_va(dh,
				VE_DMA_VHVA, getpid(), (uint64_t)buf_page,
				VE_DMA_VEMAA, 0, page_start, pgsz);
	if (dma_status != VE_DMA_STATUS_OK) {
		PPS_ERROR(cat_os_pps, "Failed to restore VE memory(0x%lx)"
				" content from buffer(0x%lx) due to %d",
				page_start, (uint64_t)buf_page, dma_status);
		PPS_TRACE(cat_os_pps, "Out %s", __func__);
		return -1;
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return 0;
}

/**
 * @brief Transfer saved content of VE page to new VE page.
 *
 * @param[in] page_start Start address of new VE page
 * @param[in] pgsz Page size of new VE page
 * @param[in] buf_page Pointer to PPS buffer pages which stores saved content
 * of VE page
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 *
 * @note Don't acquire ve_page_node_lock before invoking this.
 */
static int
veos_pps_do_restore_file_content(uint64_t page_start, size_t pgsz, void *buf,
								off_t offset)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int read_ret = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	read_ret = pread(vnode->pps_file.fd, buf, pgsz, offset);
	if (read_ret != pgsz) {
		PPS_ERROR(cat_os_pps,
		"Failed to read data from PPS file due to %s", strerror(errno));
		return -1;
	}

	if (veos_pps_do_restore_memory_content(page_start, pgsz, buf) != 0)
		return -1;

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return 0;
}


/**
 * @brief This function allocates a new VE page in Swap-in.
 *
 * @param[in] count Number of free pages.
 * @param[out] map Holds page number that is allocated.
 * @param[in] pgmod page mode for the memory allocation.
 * @param[in] mempolicy Memory policy for partitioning mode.
 * @param[in] numa_node NUMA node number of the VE process
 * requires memories is running on.
 * @param[out] from_node A pointer to a variable that holds
 * which node the memory was allocated from.
 * @param[in] group_leader ve_task_struct of thread group leader of Swapping-in
 * process
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval -ALLOC_RETRY on Retry due to lack of VE memory.
 *
 * @note Acquire thread_group_mm_lock before invoking this.
 */
static int
allocate_new_ve_page(uint64_t count, pgno_t *map, int pgmod,
				int mempolicy, int numa_node, int *from_node,
				struct ve_task_struct *group_leader)
{
	int retval = -1;
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = alloc_ve_pages(1, map, pgmod, mempolicy, numa_node, from_node);
	if (ret == -ENOMEM) {
		if (is_process_veos_terminate(group_leader, "Swap-in")) {
			retval = -PPS_INTER_TERM;
			goto hndl_return;
		}
		PPS_DEBUG(cat_os_pps, "Retry memory allocation");
		retval = -PPS_ALLOC_RETRY;
		goto hndl_return;
	} else if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to allocate new ve memory"
			  " due to %s", strerror(-ret));
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Restore ATB or DMAATB in Swap-in. This function allocates physical
 * VE page for deallocated all entries of ATB or DMAATB.
 *
 * @param[in] group_leader ve_task_struct of thread group leader of Swapping-in
 * process
 * @param[in] vrt A Pointer to Swapping-out ATB or Swapping-out DMAATB.
 * @param[in] pgsize Page size of Memory which is restored in Swap-in
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt,
 * @retval -ALLOC_RETRY on Retry due to lack of VE memory.
 * @note Acquire thread_group_mm_lock before invoking this.
 */
int
veos_restore_registered_memory(struct ve_task_struct *group_leader,
				struct ve_swapped_virtual *vrt, size_t pgsize)
{
	int retval = 0;
	int pgmod, from_node, numa_node, ret, i;
	void *buf_page;
	off_t offset;
	uint64_t page_start;
	pgno_t pno;
	size_t pgsz;
	struct ve_node_struct *vnode = VE_NODE(0);
	bool is_new_mem_alloc = false;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	//Following procedure might be merge into ve_restore_swapped_pages()
	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
			LOCK, "Failed to lock ve_pages_node_lock");

	if (vrt->phy->pgsz != pgsize) {
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
		goto hndl_return;
	}

	if (vrt->phy->pgsz == PAGE_SIZE_2MB) {
		pgmod = PG_2M;
	} else {
		pgmod = PG_HP;
	}

	pno = vrt->phy->pno;
	if (pno == -1) {
		buf_page = vrt->phy->buf_page;
		offset = vrt->phy->file_offset;
		pgsz = vrt->phy->pgsz;
		numa_node = vrt->phy->numa_node;

		/*
		 * In this case, vrt->phy is not changed, because Swap-in
		 * is not handled in parallel.
		 */
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");

		retval = allocate_new_ve_page(1, &pno, pgmod,
					group_leader->p_ve_mm->mem_policy,
					numa_node, &from_node, group_leader);
		if (retval != 0)
			goto hndl_return;
		page_start = pbaddr(pno, PG_2M);
		PPS_DEBUG(cat_os_pps, "page %ld is allocated fom numa %d",
								pno, from_node);

		pthread_mutex_lock_unlock(&(group_leader->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");

		if (offset != -1) {
 			PPS_DEBUG(cat_os_pps, "swap in from file, offset is %ld",
									offset);
			pthread_mutex_lock_unlock(&vnode->pps_file_buffer_lock, LOCK,
					"Fail to acquire pps file buffer lock");
			retval = veos_pps_do_restore_file_content(page_start,
				pgsz, vnode->pps_file_transfer_buffer, offset);
			pthread_mutex_lock_unlock(&vnode->pps_file_buffer_lock, UNLOCK,
					"Fail to release pps file buffer lock");
		} else {
			PPS_DEBUG(cat_os_pps, "swap in from PPS buffer");
			retval = veos_pps_do_restore_memory_content(page_start,
								pgsz, buf_page);
		}
		pthread_mutex_lock_unlock(&(group_leader->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");
		pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
						"Fail to acquire ve page lock");
		if (retval != 0) {
			veos_free_page(pno);
			pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
			goto hndl_return;
		}
		VE_PAGE(vnode, pno)->perm = vrt->phy->perm;
		VE_PAGE(vnode, pno)->flag = vrt->phy->flag;
		VE_PAGE(vnode, pno)->private_data = vrt->phy->private_data;

		vrt->phy->pno = pno;
		vrt->phy->perm = 0;
		vrt->phy->pgsz = VE_PAGE(vnode, pno)->pgsz;
		vrt->phy->flag = 0;
		vrt->phy->buf_page = NULL;
		vrt->phy->file_offset = -1;
		if(buf_page != NULL)
			veos_pps_free_buf_page(buf_page, pgsz, vrt->phy->numa_node);
		if(offset != -1)
			veos_pps_free_file_offset((void *)offset, pgsz,
							vrt->phy->numa_node);
		vrt->phy->numa_node = -1;
		VE_PAGE(vnode, pno)->swapped_info = vrt->phy;
		is_new_mem_alloc = true;
	}
	/* Increment ref_cnt of VE page */
	if (VE_PAGE(vnode, pno)->swapped_info->remained_page_ref_count > 0) {
		PPS_DEBUG(cat_os_pps, "Not increment ref_count");
		VE_PAGE(vnode, pno)->swapped_info->remained_page_ref_count--;
	} else{
		__sync_fetch_and_add(&vnode->ve_pages[pno]->ref_count, 1);
	}
	VE_PAGE(vnode, pno)->swapped_info->ref_cnt--;
	if (VE_PAGE(vnode, pno)->swapped_info->ref_cnt == 0) {
		free(VE_PAGE(vnode, pno)->swapped_info);
		VE_PAGE(vnode, pno)->swapped_info = NULL;
	}
	if (vnode->partitioning_mode == 1) {
		numa_node = (int)paddr2mpnum(pbaddr(pno, PG_2M),
					numa_sys_info.numa_mem_blk_sz,
					numa_sys_info.first_mem_node);
	} else {
		numa_node = 0;
	}
	pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				UNLOCK, "Failed to release ve_pages_node_lock");
	if (is_new_mem_alloc) {
		ret = amm_update_rss_swapin(VE_PAGE(vnode, pno));
		if (ret != 0)
			PPS_DEBUG(cat_os_pps, "Failed to amm_update_rss_swapin"
						" due to %s", strerror(-ret));
	}
	if (vrt->kind == PPS_VIRT_DMAATB) {
		(*_veos_arch_ops->arch_pps_veos_restore_registered_memory)(group_leader,vrt,pno);
	} else {
		PPS_DEBUG(cat_os_pps, "ATB[%d][%d] for Page %ld",
						vrt->dir, vrt->ent, pno);
		PPS_DEBUG(cat_os_pps, "numa_count = %d", vnode->numa_count);
		for (i = 0; i < vnode->numa_count; i++) {
			pg_clearpfn(&(group_leader->p_ve_mm->
				atb[i].entry[vrt->dir][vrt->ent]));
			pg_setpb(&(group_leader->p_ve_mm->
				atb[i].entry[vrt->dir][vrt->ent]), pno, PG_2M);
			if ((vnode->partitioning_mode == 1) &&
							(numa_node == i)) {
				pg_unsetbypass(&(group_leader->p_ve_mm->
					atb[i].entry[vrt->dir][vrt->ent]));
			} else if ((vnode->partitioning_mode == 1) &&
							(numa_node != i)) {
				pg_setbypass(&(group_leader->p_ve_mm->
					atb[i].entry[vrt->dir][vrt->ent]));
			}
			/* Don't Update cache baypass bit when Normal mode */
		}
	}
	list_del(&(vrt->pages));
	free(vrt);
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function allocates a new DMAATB dir in Swap-in.
 *
 * @param[in] vehva a VEHVA which uses DMAATB dir.
 * @param[in] ve_task_struct of Swapping-in process.
 *
 * @retval New DMAATB dir number on success
 * @retval -1 on Failure,
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt.
 * @retval -ALLOC_RETRY on Retry due to lack of VE memory.
 *
 * @note Acquire thread_group_mm_lock and dmaatb_node_lock before invoking this.
 */
int
get_new_dimatb_dir(uint64_t vehva, struct ve_task_struct *tsk)
{
	int newdir;
	struct ve_task_struct *group_leader = tsk->group_leader;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	newdir = get_dmapgd(vehva, tsk);
	if (newdir == -1) {
		PPS_DEBUG(cat_os_pps, "Cannot allocate new DMAATB");
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
		if (is_process_veos_terminate(group_leader, "Swap-in")) {
			newdir = -PPS_INTER_TERM;
			goto hndl_return;
		}
		PPS_DEBUG(cat_os_pps, "Retry DMAATB allocation");
		newdir = -PPS_ALLOC_RETRY;
		goto hndl_return;
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return newdir;
}

/**
 * @brief Swap-in memory and ATB.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process
 * @param[in] pgsize Page size of Memory which is restored in Swap-in
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt,
 * */
static int
veos_swap_in_atb(struct ve_task_struct *tsk, size_t pgsize)
{
	int retval = -1;
	int ret;
	struct list_head *p = NULL, *n = NULL;
	struct ve_swapped_virtual *tmp = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	PPS_DEBUG(cat_os_pps, "Swapping-in ATB");

	pthread_mutex_lock_unlock(&(tsk->group_leader->p_ve_mm->
			thread_group_mm_lock), LOCK,
			"Failed to aqcuire hread_group_mm_lock");

	/* Pick one information */
	list_for_each_safe(p, n, &(tsk->p_ve_mm->swapped_pages)) {
		PPS_DEBUG(cat_os_pps, "Pick up one info");
		tmp = list_entry(p, struct ve_swapped_virtual, pages);
		/* Check information type */
		if (tmp->kind == PPS_VIRT_ATB) {
			PPS_DEBUG(cat_os_pps, "Kind is ATB");
			ret = veos_restore_registered_memory(tsk->group_leader,
								tmp, pgsize);
			if (ret != 0) {
				pthread_mutex_lock_unlock(
					&(tsk->group_leader->p_ve_mm->
						thread_group_mm_lock), UNLOCK,
					"Failed to release "
					"thread_group_mm_lock");
				if (ret == -PPS_ALLOC_RETRY) {
					PPS_DEBUG(cat_os_pps,
						"Retry to restore memory");
					retval = -PPS_ALLOC_RETRY;
					goto hndl_return;
				}
				PPS_DEBUG(cat_os_pps,
					"Failed to restore memory and ATB");
				retval = -1;
				goto hndl_return;
			}
		}
		pthread_mutex_lock_unlock(&(tsk->group_leader->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");

		/* Check veos and process */
		if (is_process_veos_terminate(tsk->group_leader, "Swap-in")) {
			retval = -PPS_INTER_TERM;
			goto hndl_return;
		}
		pthread_mutex_lock_unlock(&(tsk->group_leader->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");
	}
	pthread_mutex_lock_unlock(&(tsk->group_leader->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release hread_group_mm_lock");
	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Swap-in DMAATB.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt,
 * */
static int
veos_swap_in_dmaatb(struct ve_task_struct *tsk)
{
	int retval, i;
	int pasizea[] = {PAGE_SIZE_64MB, PAGE_SIZE_2MB, -1};
	struct ve_task_struct *group_leader = tsk->group_leader;
	struct ve_swapped_virtual *vrt, *tmp;
	struct ve_mm_struct *mm = group_leader->p_ve_mm;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	PPS_DEBUG(cat_os_pps, "Swapping-in DMAATB");

	/* Update Process soft copy.
	 * VE memory which are registered with DMAATB may be changed after
	 * Swap-in.
	 * So, at the first, update entry of Process soft copy corresponding
	 * to such memory.
	 */
	for (i = 0; pasizea[i] != -1; i++) {
		pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");
		list_for_each_entry_safe(vrt, tmp,
			&(group_leader->p_ve_mm->swapped_pages), pages) {
			retval = veos_restore_registered_memory(
						group_leader, vrt, pasizea[i]);
			pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock),
				UNLOCK,
				"Failed to release thread_group_mm_lock");
			if (retval != 0) {
				goto hndl_return;
			}
			if (is_process_veos_terminate(
						group_leader, "Swap-in")) {
				retval = -PPS_INTER_TERM;
				goto hndl_return;
			}
			pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
		}
		pthread_mutex_lock_unlock(&(mm->thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
	}

	/*
	 * At second step, updated Process soft copy is synchronized to Node
	 * soft copy.
	 * But, original directory number of Process soft copy may be used
	 * by other Process.
	 * So, new direcotry number is allocated, update Process soft copy,
	 * and it is synchronized to Node soft copy.
	 */
	retval = (*_veos_arch_ops->arch_pps_allocate_new_dmaatb_dir)(tsk);
	PPS_DEBUG(cat_os_pps, "Swapped-in DMAATB done");
	amm_dump_dmaatb(tsk, true);
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}


/**
 * @brief Check whether process termination or VEOS termination Interrupt.
 *
 * @param[in] tsk Pointer to the task structure.
 * The caller must ensure that this argument is not NULL.
 *
 * @return false, if termination interrupted return ture.
 */
bool
is_process_veos_terminate(struct ve_task_struct *tsk, char *kind)
{
	bool retval = false;
	int exit_status;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	/* Check process */
	exit_status = get_task_exit_status(tsk);
	if (exit_status == EXITING) {
		PPS_INFO(cat_os_pps,
			"Process is terminating, so %s is canceled", kind);
		retval = true;
		goto hndl_return;
	}

	/* Check VEOS */
	if (terminate_flag == REQUIRED) {
		PPS_INFO(cat_os_pps,
			"VEOS is terminating, so %s is canceled", kind);
		retval = true;
		goto hndl_return;
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Re-open VESHM.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -PPS_INTER_TERM on Process termination or VEOS termination Interrupt,
 * */
static int
veos_swap_in_open_veshm(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry_copy = NULL;
	struct list_head *list_p, *list_n;
	int vemva_pg_mode = 0;
	int retval = -1;
	int ret = -1;
	int i;
	int failed = 0;

	RpcVeshmSubOpen request_open = RPC_VESHM_SUB_OPEN__INIT;

	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}

	resource = tsk->ived_resource;
	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_p = resource->swapped_owned_veshm_list.next;
	/* Loop swapped VESHM owned information*/
	list_for_each_safe(list_p, list_n, &resource->swapped_owned_veshm_list) {
		/* Check veos and process */
		if (is_process_veos_terminate(tsk->group_leader, "Swap-in")) {
			retval = -PPS_INTER_TERM;
			pthread_rwlock_unlock(&resource->ived_resource_lock);
			goto hndl_return;
		}

		/* Get owned VESHM information */
		entry_copy = list_entry(list_p, struct owned_veshm_info, list);

		if (isset_flag(entry_copy->status_flag, VESHM_MODE_INVALID)) {
			PPS_DEBUG(cat_os_pps, " VESHM_MODE_INVALID is set, skip it");
			list_del(list_p);
			free(entry_copy);
			continue;
		}

		/* Make an open request */
		request_open.uid	 = tsk->uid;
		/* tsk->tgid is the process id */
		request_open.pid_of_owner	 = tsk->tgid;
		request_open.vemva	 = entry_copy->vemva;
		request_open.size	 = entry_copy->size;
		request_open.syncnum	 = entry_copy->pcisync_num;
		request_open.mode_flag	 =
			entry_copy->status_flag & ~(VESHM_MODE_INVALID | VESHM_MODE_CLOSE);

		pthread_rwlock_unlock(&resource->ived_resource_lock);

		set_flag(request_open.mode_flag, VE_REQ_PROC);
		set_flag(request_open.mode_flag, VE_SWAPPABLE);
		reply.veshm_ret = &veshm_ret;
		vemva_pg_mode = pgsz_to_pgmod(entry_copy->physical_pgsize);
		for (i = entry_copy->register_cnt_proc_swappable; i > 0; i--) {
			PPS_DEBUG(cat_os_pps, "Invoke do veos_veshm_open_common to"
			" re-open VESHM %dth in %d",
			i, entry_copy->register_cnt_proc_swappable);
			ret = veos_veshm_open_common(&request_open, &reply, vemva_pg_mode);
			PPS_DEBUG(cat_os_pps,
				"ret:%d, reply.ret_val:%"PRIx64", reply.error:%d",
				ret, reply.retval, reply.error);
			if ((ret != 0) || (reply.error != 0)) {
				PPS_ERROR(cat_os_pps, "Re-open VESHM is failed");
				failed = 1;
				break;
			}
		}
		pthread_rwlock_wrlock(&resource->ived_resource_lock);
		list_del(list_p);
		free(entry_copy);
	}
	pthread_rwlock_unlock(&resource->ived_resource_lock);
	if (!failed)
		retval = 0;

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Re-attach VESHM.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * */
int veos_swap_in_user_veshm_pciatb_re_attach(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct attaching_veshm_info *entry_copy=NULL;
	struct list_head *list_p, *list_n;
	uint64_t invalid_veshm_flag = 0;
	int retval = -1;
	int ret = -1;
	int i = 0;
	int failed = 0;

	RpcVeshmSubAttach request_attach = RPC_VESHM_SUB_ATTACH__INIT;
	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}
	resource = tsk->ived_resource;
	pthread_mutex_lock_unlock(&resource->re_attach_veshm_lock, LOCK,
			"Failed to acquire re-attach veshm lock");
	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	if (list_empty(&resource->swapped_attach_veshm_list)) {
		PPS_DEBUG(cat_os_pps, "List is empty");
		/* It is not a swapped-out user process of VESHM */
		pthread_rwlock_unlock(&resource->ived_resource_lock);
		pthread_mutex_lock_unlock(&resource->re_attach_veshm_lock, UNLOCK,
				"Failed to release re-attach veshm lock");
		retval = 0;
		goto hndl_return;
	}

	list_p = resource->swapped_attach_veshm_list.next;
	/* Loop swapped-out VESHM attach information*/
	list_for_each_safe(list_p, list_n, &resource->swapped_attach_veshm_list) {

		/* Get VESHM attach information */
		entry_copy = list_entry(list_p, struct attaching_veshm_info, list);

		/* Re-attach veshm */

		invalid_veshm_flag  = entry_copy->mode_flag & VESHM_MODE_INVALID;

		request_attach.user_uid		 = tsk->uid;
		/* tsk->tgid is the process id */
		request_attach.user_pid		 = tsk->tgid;
		request_attach.user_vemva	 = entry_copy->vemva;
		request_attach.owner_pid	 = entry_copy->target_pid;
		request_attach.vemva		 = entry_copy->target_vemva;
		request_attach.size			 = entry_copy->size;
		request_attach.syncnum		 = entry_copy->pcisync_num;
		request_attach.mode_flag	 =
			(entry_copy->req_mode_flag & ~VE_REQ_NON_OWNER_INFO)
			| invalid_veshm_flag;

		set_flag(request_attach.mode_flag, VE_REQ_PPS);
		set_flag(request_attach.mode_flag, VE_REQ_PROC);

		reply.veshm_ret = &veshm_ret;

		list_del(list_p);
		pthread_rwlock_unlock(&resource->ived_resource_lock);

		for (i = entry_copy->ref_cnt_vehva; i > 0 ; i--) {
			PPS_DEBUG(cat_os_pps, "Invoke %dth veos_veshm_attach_common()", i);
			ret = veos_veshm_attach_common(&request_attach, &reply,
				entry_copy->vehva);
			if ((ret != 0) || (reply.error != 0)) {
				PPS_ERROR(cat_os_pps, "Re-attach VESHM is failed");
				failed = 1;
				break;
			}
		}
		pthread_rwlock_wrlock(&resource->ived_resource_lock);
		free(entry_copy);
	}

	if (!failed)
		retval = 0;

	pthread_rwlock_unlock(&resource->ived_resource_lock);
	pthread_mutex_lock_unlock(&resource->re_attach_veshm_lock, UNLOCK,
			"Failed to release re-attach veshm lock");

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}


/**
 * @brief This function handles a Swap-in request.
 *
 * @param[in] tsk Pointer to the task structure which is corresponding to
 * VE process against which Swap-in is required.
 * The caller must ensure that this argument is not NULL.
 *
 * @retval 0 on success,
 * @retval -1 on failure.
 */
int
ve_do_swapin(struct ve_task_struct *tsk)
{
	int retval = -1;
	int ret;
	pid_t pid;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	dump_process_atb(tsk);

	pid = tsk->pid;

	/* Swap in memory and ATB.
	 * To avoid memory fragmentation, Swap-in 64MB memory before 2MB memory.
	 * */
	ret = veos_swap_in_atb(tsk, PAGE_SIZE_64MB);
	if (ret == -PPS_INTER_TERM) {
		goto hndl_return;
	} else if (ret == -PPS_ALLOC_RETRY) {
		goto hndl_retry;
	} else if  (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to restore 64MB memory and ATB, "
					"kill %d", tsk->group_leader->pid);
		goto hndl_return;
	}
	ret = veos_swap_in_atb(tsk, PAGE_SIZE_2MB);
	if (ret == -PPS_INTER_TERM) {
		goto hndl_return;
	} else if (ret == -PPS_ALLOC_RETRY) {
		goto hndl_retry;
	} else if  (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to restore 2MB memory and ATB, "
					"kill %d", tsk->group_leader->pid);
		goto hndl_return;
	}

	dump_process_atb(tsk);

	/* Swap in DMAATB */
	ret = veos_swap_in_dmaatb(tsk);
	if (ret == -PPS_INTER_TERM) {
		/*
		 * Process termination or VEOS termination Interrupt
		 */
		goto hndl_return;
	} else if (ret == -PPS_ALLOC_RETRY) {
		goto hndl_retry;
	} else if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to restore DMAATB, "
					"kill %d", tsk->group_leader->pid);
		goto hndl_return;
	}

	/* Update list of physical address of owne VESHM */
	veos_veshm_update_paddr_array_all(tsk);
	veos_veshm_update_is_swap_out(tsk, false);

	dump_process_atb(tsk);

	/* Re-open VESHM */
	ret = veos_swap_in_open_veshm(tsk);
	if (ret == -PPS_INTER_TERM) {
		goto hndl_return;
	} else if  (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to re-open VESHM, kill %d",
			tsk->group_leader->pid);
		goto hndl_return;
	}

	/* Re-servate dmaatb dir for VESHM */
	ret = (*_veos_arch_ops->arch_veos_swap_in_user_veshm)(tsk);
	if (ret == -PPS_INTER_TERM) {
		goto hndl_return;
	} else if (ret == -PPS_ALLOC_RETRY) {
		goto hndl_retry;
	} else if  (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to re-servate dmaatb dir for VESHM,"
			" kill %d", tsk->group_leader->pid);
		goto hndl_return;
	}

	/* Change sub-status */
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			LOCK, "Failed to acquire thread_group_mm_lock");
	veos_operate_all_ve_task_lock(tsk->group_leader, LOCK);
	veos_update_substatus(tsk->group_leader, ACTIVE);
	veos_set_atb_dirty(tsk->group_leader);
	veos_operate_all_ve_task_lock(tsk->group_leader, UNLOCK);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");

	retval = 0;

hndl_return:
	PPS_DEBUG(cat_os_pps, "Swap-in against %d finishes retval is %d", pid,
			retval);
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;

hndl_retry:
	retval = ret;
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Notifies "swap thread" to perform Swap-in to the process specified by
 * the argument pids.
 *
 * @param[in] pids Array of Process ID by which VE process. This array must be
 * terminate with -1
 *
 * @retval 0 on success,
 * @retval -errno on failure.
 */
int
veos_ve_swapin_req(pid_t *pids)
{
	int retval = -EPERM;
	int i;
	int all_ok_flag = 1;
	int add_to_info_flag = 1;
	int valid_pid_num = 0;
	int to_next_pid = 0;
	pid_t pid = 0;
	struct veos_swap_request_info *request_info = NULL;
	struct ve_task_struct *ve_task = NULL;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_task_struct *group_leader = NULL, *tmp = NULL;
	struct ve_ipc_sync *ipc_sync = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	request_info = (struct veos_swap_request_info *)malloc(
					sizeof(struct veos_swap_request_info));
	if (request_info == NULL) {
		retval = -errno;
		PPS_ERROR(cat_os_pps, "Failed to create Swap request due to %s",
							strerror(errno));
		goto hndl_return;
	}

	p_ve_node = VE_NODE(0);
	for (i = 0; -1 != pids[i]; i++) {
		pid = pids[i];
		PPS_DEBUG(cat_os_pps, "Pick up one pid %d", pid);
		add_to_info_flag = 1;

		if (!veos_check_pps_enable()) {
			PPS_DEBUG(cat_os_pps,
					"Partial process swapping is disabled");
			goto hndl_free_req;
		}

		ve_task = find_ve_task_struct(pid);
		if (ve_task == NULL) {
			PPS_DEBUG(cat_os_pps, "VE task with pid %d not found",
				pid);
			all_ok_flag = 0;
			continue;
		}
		ipc_sync = ve_get_ipc_sync(ve_task);
		if (ipc_sync == NULL) {
			put_ve_task_struct(ve_task);
			all_ok_flag = 0;
			continue;
		}
		group_leader = ve_task->group_leader;
		pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
		veos_operate_all_ve_task_lock(group_leader, LOCK);
		list_for_each_entry(tmp, &group_leader->thread_group,
					thread_group) {
			/* Check status and sub-status */
			if (!(((tmp->ve_task_state == STOP) ||
				(tmp->ve_task_state == ZOMBIE)) &&
				((tmp->sstatus == SWAPPING_OUT) ||
				(tmp->sstatus == SWAPPED_OUT)))) {
				PPS_DEBUG(cat_os_pps, "Checking status and "
					"sub-status of child thread "
					"failed, status:%d, "
					"sub-status:%d",
					tmp->ve_task_state,
					tmp->sstatus);
				all_ok_flag = 0;
				veos_operate_all_ve_task_lock(group_leader,
								UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				to_next_pid = 1;
				break;
			}
			/* Change sub-status with main thread together*/
		}

		if (!to_next_pid) {
			/* Check status and sub-status */
			if (((group_leader->ve_task_state != ZOMBIE) &&
				(group_leader->ve_task_state != STOP)) ||
				((group_leader->sstatus != SWAPPING_OUT) &&
				(group_leader->sstatus != SWAPPED_OUT))) {
				PPS_DEBUG(cat_os_pps,
					"Checking status and sub-status of "
					"leader thread failed, status:%d, "
					"sub-status:%d",
					group_leader->ve_task_state,
					group_leader->sstatus);
				all_ok_flag = 0;
				veos_operate_all_ve_task_lock(group_leader,
					UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				continue;
			}

			if (group_leader->sstatus != SWAPPED_OUT) {
				add_to_info_flag = 0;
			}
			/* Change sub-status */
			veos_update_substatus(group_leader, SWAPPING_IN);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			if (add_to_info_flag) {
				request_info->pid_array[valid_pid_num] = pid;
				request_info->ipc_sync_array[valid_pid_num]
								= ipc_sync;
				valid_pid_num++;
			}
			ve_put_ipc_sync(ipc_sync);
			put_ve_task_struct(ve_task);
		}
	}
	request_info->pid_array[valid_pid_num] = PPS_END_OF_PIDS;
	request_info->pid_number = valid_pid_num;

	/* Check whether VEOS is terminating */
	pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock),
			LOCK, "Failed to aqcuire swap_request lock");
	if (!p_ve_node->swap_request_pids_enable) {
		PPS_INFO(cat_os_pps,
			"VEOS is terminating, so Swap thread is canceled");
		pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock),
			UNLOCK,	"Failed to release swap_request lock");
		goto hndl_free_req;
	}

	list_add_tail(&(request_info->swap_info),
			&(p_ve_node->swap_request_pids_queue));

	/* wake up thread */
	PPS_DEBUG(cat_os_pps, "Wake up thread");
	pthread_cond_broadcast(&(p_ve_node->swap_request_pids_cond));
	pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock), UNLOCK,
					"Failed to release swap_request lock");

	if (all_ok_flag) {
		retval = 0;
	}
	goto hndl_return;

hndl_free_req:
	retval = -ENOTSUP;
	request_info->pid_array[valid_pid_num] = PPS_END_OF_PIDS;
	request_info->pid_number = valid_pid_num;
	del_doing_swap_request(request_info);
	free(request_info);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}
