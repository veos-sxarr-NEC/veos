
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
#include <veos_ve3.h>
#include <ve_mem_ve3.h>
#include <ve_memory_ve3.h>
#include <vehva_mgmt_ve3.h>
#include <veos_arch_defs.h>
#include <dmaatb_api.h>
#include <veos_veshm_core.h>
#include "veos_ived_private.h"


/**
 * @brief Restore DMAATB in Swap-in. This function allocates physical
 * VE page for deallocated all entries of ATB or DMAATB.
 *
 * @param[in] group_leader ve_task_struct of thread group leader of Swapping-in
 * process
 * @param[in] vrt A Pointer to Swapping-out ATB or Swapping-out DMAATB.
 * @param[in] pgsize Page size of Memory which is restored in Swap-in
 *
 * @note Acquire thread_group_mm_lock before invoking this.
 */
void
ve3_pps_veos_restore_registered_memory(struct ve_task_struct *group_leader,
				struct ve_swapped_virtual *vrt, pgno_t pno)
{
		ve3_dmaatb_reg_t *group_leader_p_ve_mm_dmaatb = &((ve3_veos_dmaatb_reg_t *)group_leader->p_ve_mm->dmaatb)->dmaatb_reg;
		pg_clearpfn(&(group_leader_p_ve_mm_dmaatb->entry[vrt->dir][vrt->ent]));
		pg_setpb(&(group_leader_p_ve_mm_dmaatb->entry[vrt->dir][vrt->ent]), pno, PG_2M);

}
VEOS_ARCH_DEP_FUNC(ve3, arch_pps_veos_restore_registered_memory, ve3_pps_veos_restore_registered_memory)


/**
 * @brief When VEOS termination, or Process termination interrupts Swap-in,
 * or when Swap-in failed, this function frees DMAATB dirs which were allocated
 * in Swap-in procedure.
 *
 * @param[in] new_allocate_dirs Bits which indicates allocated DMAATB dirs.
 *
 * @retval None
 */
static void
cleanup_allocate_dirs(uint64_t new_allocate_dirs[])
{
	int dir, ent;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ve3_dmaatb_reg_t *vnode_dmaatb = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;
	for (dir = vnode->nr_avail_cores; dir < VE3_DMAATB_DIR_NUM; dir++) {
		if (!(new_allocate_dirs[dir/64] & (1ULL << (dir - (dir/64)*64))))
			continue;
		PPS_DEBUG(cat_os_pps, "Cleanup dir %d", dir);
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
					"Failed to acquire node dmaatb lock");
		ps_clrdir(&(vnode_dmaatb->dir[dir]));
		ps_invalid(&(vnode_dmaatb->dir[dir]));;
		for (ent = 0; ent < VE3_DMAATB_ENTRY_MAX_SIZE; ent++) {
			pg_unsetro(&(vnode_dmaatb->entry[dir][ent]));
			pg_unsetido(&(vnode_dmaatb->entry[dir][ent]));
			pg_invalid(&(vnode_dmaatb->entry[dir][ent]));
			pg_unsetprot(&(vnode_dmaatb->entry[dir][ent]));
			pg_unsettype(&(vnode_dmaatb->entry[dir][ent]));
			pg_clearpfn(&(vnode_dmaatb->entry[dir][ent]));
		}
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief This function allocates new DMAATB dir, update Process soft copy
 * of DMAATB to use it, and synchronize Process soft copy to Node soft copy.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process.
 *
 * @retval 0 on success,
 * @retval -1 on Failure.
 * @retval -TERM_INTER on Process termination or VEOS termination Interrupt,
 */
int
ve3_pps_allocate_new_dmaatb_dir(struct ve_task_struct *tsk)
{
	int retval;
	int new_dir, old_dir, ent, pgmod, ret, valid_ent;
	uint64_t ps, vehva;
	uint64_t new_allocate_dirs[VE3_DMAATB_DIR_NUM/64] = {};
	veos_dmaatb_reg_t *new_process_soft_copy;
	ve3_veos_dmaatb_reg_t ve3_new_process_soft_copy;
	new_process_soft_copy = (veos_dmaatb_reg_t *)&ve3_new_process_soft_copy;
	ve3_dmaatb_reg_t *ve3_new_process_soft_copy_dmaatb = &ve3_new_process_soft_copy.dmaatb_reg;

	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	/* If Swap-in interrupted Swap-out of DMAATB, all dir are not changed.
	 * If not, dir may not be changed.
	 */
	invalidate_dmaatb(new_process_soft_copy);
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");
	ve3_dmaatb_reg_t *tsk_p_ve_mm_dmaatb = &((ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg;
	ve3_dmaatb_reg_t *vnode_dmaatb = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;

	for(old_dir = vnode->nr_avail_cores; old_dir < VE3_DMAATB_DIR_NUM;
								old_dir++) {
		if (!ps_isvalid(&(tsk_p_ve_mm_dmaatb->dir[old_dir])))
			continue;

		for (ent = 0; ent < VE3_DMAATB_ENTRY_MAX_SIZE; ent++) {
			if (pg_isvalid(
				&(tsk_p_ve_mm_dmaatb->entry[old_dir][ent]))) {
				break;
			}
		}
		pgmod = ps_getpgsz(&(tsk_p_ve_mm_dmaatb->dir[old_dir]));
		ps = ps_getps(&(tsk_p_ve_mm_dmaatb->dir[old_dir]), pgmod);
		if (pgmod == PG_2M) {
			vehva = (ps << ps_shft) | (pbaddr_l(ent));
		} else if (pgmod == PG_HP) {
			vehva = (ps << ps_shft_h) | (pbaddr_h(ent));
		} else {
			vehva = (ps << ps_shft_sh) | (pbaddr_sh(ent));
		}
		PPS_DEBUG(cat_os_pps, "Picked VEHVA : 0x%lx", vehva);
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
					"Failed to acquire node dmaatb lock");
		/* If dir are not changed, same dir is allocated. */
		retval = get_new_dimatb_dir(vehva, tsk);
		if (retval < 0) {
			/* In thias case, get_new_dimatb_dir() Released
			 * dmaatb_node_lock and thread_group_mm_lock */
			cleanup_allocate_dirs(new_allocate_dirs);
			goto hndl_return;
		}
		new_dir = retval;
		PPS_DEBUG(cat_os_pps, "new_dir %d is allocated "
					"for old_dir %d", new_dir, old_dir);
		if (!ps_isvalid(&(vnode_dmaatb->dir[new_dir]))) {
			validate_dmapgd(new_process_soft_copy,
						new_dir, ps, tsk->jid, pgmod);
			new_allocate_dirs[new_dir/64] |= (1ULL << (new_dir - (new_dir/64)*64));
		}

		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock,
				UNLOCK, "Failed to release node dmaatb lock");

		memcpy(&(ve3_new_process_soft_copy_dmaatb->dir[new_dir]),
			&(tsk_p_ve_mm_dmaatb->dir[old_dir]), sizeof(uint64_t));
		memcpy(ve3_new_process_soft_copy_dmaatb->entry[new_dir],
				tsk_p_ve_mm_dmaatb->entry[old_dir],
				sizeof(uint64_t) * VE3_DMAATB_ENTRY_MAX_SIZE);
	}

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
				LOCK, "Failed to acquire node dmaatb lock");
	for (new_dir = vnode->nr_avail_cores; new_dir < VE3_DMAATB_DIR_NUM;
								new_dir++) {
		memcpy(&(tsk_p_ve_mm_dmaatb->dir[new_dir]),
			&(ve3_new_process_soft_copy_dmaatb->dir[new_dir]),
			sizeof(uint64_t));
		memcpy(tsk_p_ve_mm_dmaatb->entry[new_dir],
			ve3_new_process_soft_copy_dmaatb->entry[new_dir],
			sizeof(uint64_t) * VE3_DMAATB_ENTRY_MAX_SIZE);

	}
	for (new_dir = vnode->nr_avail_cores; new_dir < VE3_DMAATB_DIR_NUM;
								new_dir++) {
		if (!ps_isvalid(&(tsk_p_ve_mm_dmaatb->dir[new_dir])))
			continue;
		valid_ent = 0;
		for (ent = 0; ent < VE3_DMAATB_ENTRY_MAX_SIZE; ent++) {
			if (pg_isvalid(
				&(tsk_p_ve_mm_dmaatb->entry[new_dir][ent]))) {
				valid_ent++;
			}
		}
		VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[new_dir].count = valid_ent;
		ret = sync_node_dmaatb_dir(0, tsk->p_ve_mm, new_dir, tsk->jid);
		if (ret != new_dir) {
			PPS_ERROR(cat_os_pps,
				"Failed to sync DMAATB dir %d between process"
				" %d(%d) and node due to %s",
				new_dir, tsk->pid, tsk->jid, strerror(-ret));
			veos_abort("Failed to sync DMAATB soft copy");
		}
		/* if this function fails, veos aborts. */
		psm_sync_hw_regs(tsk, _DMAATB, true, new_dir, 1);
	}

	tsk->p_ve_mm->dmaatb_progress = NOT_SWAPPED;
	retval = 0;
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pps_allocate_new_dmaatb_dir, ve3_pps_allocate_new_dmaatb_dir)

/**
 * @brief Return page mode from VEHVA.
 *
 * @param[in] vehva Adress of VEHVA
 *
 * @retval pgmod on success
 * @retval -EINVAL on Failure
 * */
int
ve3_veos_get_pgmod_by_vehva(uint64_t vehva)
{
	int pgmod = 0;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if ((vehva >= VEHVA_4K_START) &&
			(vehva <= VEHVA_4K_END)) {
		PPS_DEBUG(cat_os_pps, "VEHVA_4K Region");
		pgmod = PG_4K;
	} else if ((vehva >= VEHVA_2M_START) &&
			(vehva <= VEHVA_2M_END)) {
		PPS_DEBUG(cat_os_pps, "VEHVA_2M Region");
		pgmod = PG_2M;
	} else if ((vehva >= VEHVA_64M_START) &&
			(vehva <= VEHVA_64M_END)) {
		PPS_DEBUG(cat_os_pps, "VEHVA_64M Region");
		pgmod = PG_HP;
	} else if ((vehva >= VEHVA_256M_START) &&
			(vehva <= VEHVA_256M_END)) {
		PPS_DEBUG(cat_os_pps, "VEHVA_256M Region");
		pgmod = PG_SHP;
	} else {
		pgmod = -EINVAL;
		PPS_DEBUG(cat_os_pps, "Inval Region");
	}
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return pgmod;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_get_pgmod_by_vehva, ve3_veos_get_pgmod_by_vehva)

/**
 * @brief Reserve a dmaatb dir when swap-in.
 * @note Re-attach VESHM when SIGCONT.
 * @param[in] tsk ve_task_struct of Swapping-in process
 * @param[in] vehva requested vehva
 * @param[in] pgmod DMA mode
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -PPS_INTER_TERM on Process termination or VEOS termination Interrupt.
 * @retval -PPS_ALLOC_RETRY on Retry due to lack of VE memory.
 * */
static int
ve3_veos_reserve_dmaatb_dir(struct ve_task_struct *tsk, uint64_t vehva, int pgmod)
{
	int new_dir;
	int retval = -1;
	int ret = -1;
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t ps;
	uint64_t new_allocate_dirs[VE3_DMAATB_DIR_NUM/64] = {};
	veos_dmaatb_reg_t *new_process_soft_copy;
	ve3_veos_dmaatb_reg_t ve3_new_process_soft_copy;
	new_process_soft_copy = (veos_dmaatb_reg_t *)&ve3_new_process_soft_copy;
	ve3_dmaatb_reg_t *ve3_new_process_soft_copy_dmaatb = &ve3_new_process_soft_copy.dmaatb_reg;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	PPS_DEBUG(cat_os_pps, "Reserve dmaatb dir for vehva: %#lx (pgmod: %d)", vehva, pgmod);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}

	invalidate_dmaatb(new_process_soft_copy);
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
				"Failed to acquire node dmaatb lock");

	ve3_dmaatb_reg_t *tsk_p_ve_mm_dmaatb = &((ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg;
	ve3_dmaatb_reg_t *vnode_dmaatb = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;

	/* If dir are not changed, same dir is allocated. */
	retval = get_new_dimatb_dir(vehva, tsk);
	if (retval < 0) {
		/* In thias case, get_new_dimatb_dir() Released
		 * dmaatb_node_lock and thread_group_mm_lock */
		cleanup_allocate_dirs(new_allocate_dirs);
		goto hndl_return;
	}
	new_dir = retval;
	if (!ps_isvalid(&(vnode_dmaatb->dir[new_dir]))) {
		ps = psnum(vehva, pgmod);
		PPS_DEBUG(cat_os_pps,
			"validate dmaatb dir, new_dir:%d, ps:%ld, tsk->jid:%d, pgmod:%d",
			new_dir, ps, tsk->jid, pgmod);
		validate_dmapgd(new_process_soft_copy, new_dir, ps, tsk->jid, pgmod);
		memcpy(&(tsk_p_ve_mm_dmaatb->dir[new_dir]),
			&(ve3_new_process_soft_copy_dmaatb->dir[new_dir]), sizeof(uint64_t));
	}

	PPS_DEBUG(cat_os_pps, "new_dir %d is allocated", new_dir);

	ret = sync_node_dmaatb_dir(vehva, tsk->p_ve_mm, new_dir, tsk->jid);
	if (ret != new_dir) {
		PPS_ERROR(cat_os_pps,
		"Failed to sync DMAATB dir %d between process %d(%d) and node due "
		"to %s", new_dir, tsk->pid, tsk->jid, strerror(-ret));
		veos_abort("Failed to sync DMAATB soft copy");
	}
	/* if this function fails, veos aborts. */
	psm_sync_hw_regs(tsk, _DMAATB, true, new_dir, 1);

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Invoke veos_reserve_dmaatb_dir() to reserve a dmaatb dir.
 *
 * @param[in] tsk ve_task_struct of Swapping-in process
 *
 * @retval 0 on success
 * @retval -1 on Failure.
 * @retval -PPS_INTER_TERM on Process termination or VEOS termination Interrupt.
 * @retval -PPS_ALLOC_RETRY on Retry due to lack of VE memory.
 * */
int
ve3_veos_swap_in_user_veshm(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct attaching_veshm_info *entry_copy=NULL;
	struct list_head *list_p, *list_n;
	struct ve_task_struct *group_leader = NULL;
	int retval = -1;
	uint64_t vehva, vehva_new_dir;
	int pgmod;
	size_t pgsz, dma_dir_max_size;
	int new_dir = -1;
	int i;
	int count = 0;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (tsk == NULL){
		PPS_ERROR(cat_os_pps, "Argument is NULL");
		goto hndl_return;
	}
	group_leader = tsk->group_leader;
	resource = tsk->ived_resource;

	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	list_p = resource->swapped_attach_veshm_list.next;
	/* Loop VESHM attach information*/
	list_for_each_safe(list_p, list_n, &resource->swapped_attach_veshm_list) {
		if (is_process_veos_terminate(group_leader, "Swap-in")) {
			retval = -PPS_INTER_TERM;
			PPS_DEBUG(cat_os_pps, "PPS INTER TERM");
			goto hndl_free_return;
		}

		/* get VESHM attach information */
		entry_copy = list_entry(list_p, struct attaching_veshm_info, list);
		/* reserve dmaatb dir for re-attach */
		vehva = entry_copy->vehva;
		pgmod = ve3_veos_get_pgmod_by_vehva(vehva);

		pgsz = (size_t)pgmod_to_pgsz(pgmod);
		PPS_DEBUG(cat_os_pps, "vehva: %#lx, pgsz: %ld, pgmod : %d", vehva, pgsz, pgmod);
		dma_dir_max_size = pgsz * VE3_DMAATB_ENTRY_MAX_SIZE;
		PPS_DEBUG(cat_os_pps, "Total size of one DMAATB dir: %ld",
			dma_dir_max_size);
		count = (entry_copy->size -1) / dma_dir_max_size + 1;
		vehva_new_dir = vehva;
		for (i = 0; i < count; i++) {
			if (i > 0) {
				vehva_new_dir = ALIGN(vehva + (dma_dir_max_size * i),
									dma_dir_max_size);
			}
			new_dir = ve3_veos_reserve_dmaatb_dir(tsk, vehva_new_dir, pgmod);
			PPS_DEBUG(cat_os_pps, "reserved dmaatb dir: %d for vehva: %#lx", new_dir, vehva_new_dir);
			if (new_dir < 0) {
				retval = new_dir;
				PPS_DEBUG(cat_os_pps, "Failed to reserve dmaatb dir");
				goto hndl_free_return;
			}
		}
	}
	retval = 0;

hndl_free_return:
	pthread_rwlock_unlock(&resource->ived_resource_lock);
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_swap_in_user_veshm, ve3_veos_swap_in_user_veshm)
