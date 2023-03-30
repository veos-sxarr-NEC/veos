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
#include "ve_mem.h"
#include "buddy.h"
#include "dma.h"
#include "ve_shm.h"
#include "ve_memory.h"
#include "mman_ve.h"
#include "ve_hw.h"
#include <veos_ve1.h>
#include <ve_mem_ve1.h>
#include <ve_memory_ve1.h>
#include <veos_arch_defs.h>
#include <dmaatb_api.h>


/**
 * @brief Do Swap-out a DMAATB entry
 *
 * @param[in] tsk ve_task_struct of Swapping-out process
 * @param[in] dir Directory number corresponding to Swapping-out DMAATB
 * @param[in] ent Entry number corresponding to Swapping-out DMAATB
 * @param[in] sync_copy_d Copy of DMAATB process soft copy of Swapping-out process
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
						veos_dmaatb_reg_t *sync_copy_d)
{
	int retval = 0;
	int ret;
	pgno_t pgno = 0;
	ve1_veos_dmaatb_reg_t *ve1_veos_dmaatb_reg = (ve1_veos_dmaatb_reg_t *)sync_copy_d;
	ve1_dmaatb_reg_t *sync_copy = &ve1_veos_dmaatb_reg->dmaatb_reg;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_swapped_virtual *vrt = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (!ps_isvalid(&(sync_copy->dir[dir]))) {
		PPS_DEBUG(cat_os_pps, "DMAATB dir %d is invalid", dir);
		retval = PPS_DIR_INVALID;
		goto hndl_return;
	} else if (ent == (VE1_DMAATB_ENTRY_MAX_SIZE - 1)) {
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
	ve1_dmaatb_reg_t *tsk_p_ve_mm_dmaatb = &((ve1_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg;
	//pg_setpb(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]), PG_BUS, PG_2M);
	pg_setpb(&(tsk_p_ve_mm_dmaatb->entry[dir][ent]), PG_BUS, PG_2M);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
	ret = amm_do_put_page(pgno * PAGE_SIZE_2MB, true);
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
	if (ret != 0) {
		list_del(&(vrt->pages));
		//pg_clearpfn(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]));
		pg_clearpfn(&(tsk_p_ve_mm_dmaatb->entry[dir][ent]));
		pg_setpb(&(tsk_p_ve_mm_dmaatb->entry[dir][ent]), pgno, PG_2M);
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
int ve1_pps_veos_swap_out_dmaatb(struct ve_task_struct *tsk)
{
	int retval = 0;
	int dir, ent, ret;
	uint64_t sync_dir_bitmap = 0;
	veos_dmaatb_reg_t *sync_copy = NULL;
	ve1_dmaatb_reg_t mm_dmaatb = {};
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

	for (dir = vnode->nr_avail_cores; dir < VE1_DMAATB_DIR_NUM; dir++) {
		for (ent = 0; ent < VE1_DMAATB_ENTRY_MAX_SIZE; ent++) {
			pthread_mutex_lock_unlock(
				&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
			if ((dir == vnode->nr_avail_cores) && (ent == 0)) {
				memcpy(&mm_dmaatb, tsk->p_ve_mm->dmaatb,
						sizeof(ve1_dmaatb_reg_t));
				sync_copy = (veos_dmaatb_reg_t *)&mm_dmaatb;
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
	ve1_dmaatb_reg_t *vnode_dmaatb = &((ve1_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;
	for (dir = vnode->nr_avail_cores; dir < VE1_DMAATB_DIR_NUM; dir++) {
		if (!(sync_dir_bitmap & (1ULL << dir)))
			continue;
		PPS_DEBUG(cat_os_pps, "Syncing DMAATB Dir %d", dir);
		ve1_veos_dmaatb_reg_t *ve1_veos_dmaatb_reg = (ve1_veos_dmaatb_reg_t *)sync_copy;
		ve1_dmaatb_reg_t *sync_copy_dmaatb = &ve1_veos_dmaatb_reg->dmaatb_reg;
		memcpy(&(vnode_dmaatb->dir[dir]), &(sync_copy_dmaatb->dir[dir]),
							sizeof(uint64_t));
		memcpy(vnode_dmaatb->entry[dir], sync_copy_dmaatb->entry[dir],
				sizeof(uint64_t) * VE1_DMAATB_ENTRY_MAX_SIZE);
		/* All entry are freed. */
		VE1_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir].count = 0;
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
VEOS_ARCH_DEP_FUNC(ve1, arch_pps_veos_swap_out_dmaatb, ve1_pps_veos_swap_out_dmaatb)
