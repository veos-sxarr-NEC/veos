/*
 * Copyright (C) 2020 NEC Corporation
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
 * @file dmaatb_api.c
 * @brief VE3 dependent part of DMAATB realated functions
 */
#include <libved.h>
#include <ve_hw.h>
#include <libved_ve3.h>
#include <ve_drv.h>
#include <sys/mman.h>
#include <mman_ve.h>

#include <veos_arch_defs.h>

#include <task_mgmt.h>
#include <task_sched.h>
#include <ve_memory.h>
#include <ve_memory_ve3.h>
#include <dmaatb_api.h>
#include <vehva_mgmt.h>
#include <vehva_mgmt_ve3.h>
#include <veos.h>

#include <ve_mem.h>
#include <ve_mem_ve3.h>
#include <udma_ve3.h>
#include <task_sched_ve3.h>
#include <veos_ve3.h>
#include "vehva_mgmt_ve3.h"

int64_t ve3_amm_alloc_dmaatb_for_sysregs(struct ve_task_struct *tsk)
{
	veraa_t veraa_paddr[3] = {
		SYSCOM_NONPRE_ADD +
			offsetof(ve3_system_common_reg_nonpre_t, STM),
		SYSCOM_NONPRE_ADD +
			offsetof(ve3_system_common_reg_nonpre_t, CPMMR),
		0,
	};
	return veos_alloc_dmaatb_entry_for_aa_tsk(tsk, veraa_paddr,
			PROT_READ, VE_ADDR_VERAA_NONPRE,
			VEHVA_SYSCOM_REG | VEHVA_4K, false);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_map_dma_area_to_system_registers, ve3_amm_alloc_dmaatb_for_sysregs)

int ve3_amm_dma_syscall_region_is_mapped(const struct ve_mm_struct *mm)
{
	const ve3_veos_dmaatb_reg_t *dmaatb = (const ve3_veos_dmaatb_reg_t *)mm->dmaatb;
	return ps_isvalid(&dmaatb->dmaatb_reg.dir[0]);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_dma_syscall_region_is_mapped, ve3_amm_dma_syscall_region_is_mapped)

static int ve3_find_aa_in_dmaatb_entries(ve3_dmaatb_entry_t *e, uint64_t paddr,
						uint64_t pagesize, int type)
{
	for (int pg_entry = 0; pg_entry < VE3_DMAATB_ENTRY_MAX_SIZE;
			++pg_entry) {
		uint64_t data = e[pg_entry].data;
		VEOS_DEBUG("Entry %d: PB Address %p", pg_entry, (void *)paddr);
		uint64_t pgmask = ~(pagesize - 1);
		if ((data & pgmask) == paddr
			&& ((data >> type_shft) & PG_TYP_MSK) == type)
			return pg_entry;
	}
	return -1;
}

/* dmaatb_node_lock is held on call */
int64_t ve3_amm__aa_to_vehva(const struct ve_mm_struct *mm, uint64_t paddr,
				int type)
{
	ve3_dmaatb_reg_t dmaatb;

	memcpy(&dmaatb,
		&((const ve3_veos_dmaatb_reg_t *)mm->dmaatb)->dmaatb_reg,
		sizeof(ve3_dmaatb_reg_t));

	ve3_dmaatb_dir_t *atbp = dmaatb.dir;
	int pg_entry = -1;
	uint64_t psnum_dir = 0;
	uint64_t pagesize = 0;
	for (int ps_entry = 0; ps_entry < VE3_DMAATB_DIR_NUM; ++ps_entry) {
		/* Is atbp valid ? */
		if (ps_isvalid(atbp)) {
			VEOS_DEBUG("Directory %d", ps_entry);
			/* pgmode */
			uint8_t pgmode_dir = ps_getpgsz(atbp);
			if (pgmode_dir == PG_2M) {
				pagesize = (2 << 20);
			} else if (pgmode_dir == PG_4K) {
				pagesize = (4 << 10);
			} else {
				pagesize = (64 << 20);
			}
			pg_entry = ve3_find_aa_in_dmaatb_entries(dmaatb.entry[ps_entry],
					paddr, pagesize, type);
			if (pg_entry >= 0) {
				psnum_dir = ps_getps(atbp, pgmode_dir);
				goto done;
			}
		}
		++atbp;
	}
	VEOS_DEBUG("ve3_amm__aa_to_vehva fails");
	return -EFAULT;
done:
	return  psnum_dir + (pg_entry * pagesize);

}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__aa_to_vehva, ve3_amm__aa_to_vehva)

void ve3_amm_free_dmaatb(veos_dmaatb_reg_t *d,
				enum swap_progress dmaatb_progress)
{
	int dir, ent, pg_type, ret;
	ve3_veos_dmaatb_reg_t *ve3_veos_dmaatb_reg = (ve3_veos_dmaatb_reg_t *)d;
	ve3_dmaatb_reg_t *dmaatb = &ve3_veos_dmaatb_reg->dmaatb_reg;
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	struct ve_node_struct *vnode = VE_NODE(0);

	for (dir = vnode->nr_avail_cores; dir < VE3_DMAATB_DIR_NUM; ++dir) {
		if (!ps_isvalid(&dmaatb->dir[dir]))
			continue;

		/* Clear registered memory with DMAATB
		 * along process soft copy */
		VEOS_DEBUG("Clear DMAATB dir %d", dir);
		ps_clrdir(&dmaatb->dir[dir]);
		ps_invalid(&dmaatb->dir[dir]);
		for (ent = 0; ent < VE3_DMAATB_ENTRY_MAX_SIZE; ent++) {
			while (pg_isvalid(&(dmaatb->entry[dir][ent]))) {
				pg_type = pg_gettype(
						&(dmaatb->entry[dir][ent]));
				if (pg_type != VE_ADDR_VEMAA)
					break;

				pgno_t pb = pg_getpb(
					&(dmaatb->entry[dir][ent]), PG_2M);
				if (pb == PG_BUS)
					break;
				vemaa_t vemaa = pbaddr(pb, PG_2M);
				VEOS_DEBUG("free registered memory 0x%lx",
						vemaa);
				amm_put_page(vemaa);
				break;
			}
			pg_unsetro(&(dmaatb->entry[dir][ent]));
			pg_unsetido(&(dmaatb->entry[dir][ent]));
			pg_invalid(&(dmaatb->entry[dir][ent]));
			pg_unsetprot(&(dmaatb->entry[dir][ent]));
			pg_unsettype(&(dmaatb->entry[dir][ent]));
			pg_clearpfn(&(dmaatb->entry[dir][ent]));
		}

		/* If dmaatb_progress is 'SWAPPED', all directories and entries
		 * of node soft copy already have been freed.
		 */
		if (dmaatb_progress == SWAPPED)
			continue;

		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
					"Failed to acquire node dmaatb lock");
		VEOS_DEBUG("Clear node's DMAATB dir %d", dir);
		ve3_dmaatb_reg_t *node_dmaatb = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;
		ps_clrdir(&node_dmaatb->dir[dir]);
		ps_invalid(&node_dmaatb->dir[dir]);

		for (ent = 0; ent < VE3_DMAATB_ENTRY_MAX_SIZE; ent++) {
			pg_unsetro(&node_dmaatb->entry[dir][ent]);
			pg_unsetido(&node_dmaatb->entry[dir][ent]);
			pg_invalid(&node_dmaatb->entry[dir][ent]);
			pg_unsetprot(&node_dmaatb->entry[dir][ent]);
			pg_unsettype(&node_dmaatb->entry[dir][ent]);
			pg_clearpfn(&node_dmaatb->entry[dir][ent]);
		}
		VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir].count = 0;
		ret = vedl_ve3_update_dmaatb_dir(cnt_regs, node_dmaatb, dir);
		if (ret < 0) {
			VEOS_ERROR("vedl_update_dmaatb_dir failed (%d)", ret);
			veos_abort("failed to sync dmaatb");
		}
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
					"Failed to release node dmaatb lock");

		if (terminate_flag == NOT_REQUIRED) {
			pthread_mutex_lock_unlock(&(vnode->
				swap_request_pids_lock),
 				LOCK, "Failed to aqcuire swap_request lock");
			vnode->resource_freed = true;
			pthread_cond_broadcast(
					&(vnode->swap_request_pids_cond));
			pthread_mutex_lock_unlock(&(vnode->
				swap_request_pids_lock),
				UNLOCK, "Failed to release swap_request lock");
                }
	}
#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from veos_free_dmaatb");
	amm_dump_dmaatb(NULL, 0);
#endif
	VEOS_TRACE("returned");
	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_free_dmaatb, ve3_amm_free_dmaatb)

int64_t ve3_amm_update_dmaatb_context(struct ve_task_struct *tsk, int udma_desc_id)
{
	int64_t ret = 0, err_ret = 0;
	veraa_t paddr[2] = {0, 0};

	VEOS_TRACE("Invoked");

	if (!tsk || (-1 == udma_desc_id))
		return -1;

	VEOS_DEBUG("update_dmaatb_context for pid %d on"
			" udma descriptor id %d",
			tsk->pid, udma_desc_id);
	/* DMACTL */
	paddr[0] = SYSCOM_NONPRE_ADD + VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id, 0);

	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ, VE_ADDR_VERAA_NONPRE,
			VEHVA_DMA_CNT_REG|VEHVA_4K|VEHVA_MAP_FIXED, false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		return ret;
	}
	amm_dump_dmaatb(tsk, true);

	/* DMA Descriptor table E */
	paddr[0] = SYSCOM_NONPRE_ADD +
			VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, VE_UDMA_EENTRY);
	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE, VE_ADDR_VERAA_NONPRE,
			VEHVA_DMA_DESC_E_REG|VEHVA_4K|VEHVA_MAP_FIXED, false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		err_ret = ret;
		goto hndl_err;
	}
	amm_dump_dmaatb(tsk, true);

	/* DMA Descriptor table H */
	/* If DMA Descriptor table H is enabled, allocate dmaatb entry. */
	if (!(tsk->p_ve_mm->udma_desc_bmap & DMA_DESC_H))
		goto done;

	paddr[0] = SYSCOM_NONPRE_ADD +
			VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, VE_UDMA_HENTRY);
	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE, VE_ADDR_VERAA_NONPRE,
			VEHVA_DMA_DESC_H_REG|VEHVA_4K|VEHVA_MAP_FIXED, false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		err_ret = ret;
		goto hndl_err1;
	}
	amm_dump_dmaatb(tsk, true);
done:
	VEOS_DEBUG("updated dmaatb context for pid %d on"
			" udma descriptor id %d",
			tsk->pid, udma_desc_id);
	ret = 0;
	VEOS_TRACE("returned");
	return ret;

hndl_err1:
	paddr[0] = SYSCOM_NONPRE_ADD +
			VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, VE_UDMA_EENTRY);
	ret = veos_free_dmaatb_entry_tsk(tsk, paddr[0], VEHVA_4K);
	if (0 > ret)
		VEOS_DEBUG("veos_free_dmaatb failed");
hndl_err:
	paddr[0] = SYSCOM_NONPRE_ADD +
			VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id, 0);
	ret = veos_free_dmaatb_entry_tsk(tsk, paddr[0], VEHVA_4K);
	if (0 > ret)
		VEOS_DEBUG("veos_free_dmaatb failed");

	VEOS_DEBUG("returned with 0x%lx", err_ret);
	VEOS_TRACE("returned");
	return err_ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_update_dmaatb_context, ve3_amm_update_dmaatb_context)

int ve3_amm_release_dmaatb_entry(struct ve_task_struct *tsk)
{
	int ps_entry = 0;
	ve3_dmaatb_reg_t *dmaatb = &((ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg;
	struct ve_node_struct *vnode = VE_NODE(0);
	ve3_dmaatb_reg_t *node_dmaatb = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;

	VEOS_TRACE("Invoked ve3_amm_release_dmaatb_entry for pid: %d",
			tsk->pid);

	dir_t dir_num = ve3_amm__get_dma_pgd(tsk->p_ve_mm->shm_lhm_vehva,
					tsk->jid, false);
	if (0 > dir_num) {
		VEOS_DEBUG("DMAATB Directory not available for vehva");
		return -EFAULT;
	}

	ps_clrdir(&(node_dmaatb->dir[dir_num]));
	ps_invalid(&(node_dmaatb->dir[dir_num]));

	for (ps_entry = 0; ps_entry < VE3_ATB_ENTRY_MAX_SIZE;
			ps_entry++) {
		pg_unsetro(&(node_dmaatb->entry[dir_num][ps_entry]));
		pg_unsetido(&(node_dmaatb->entry[dir_num][ps_entry]));
		pg_unsetprot(&(node_dmaatb->entry[dir_num][ps_entry]));
		pg_unsettype(&(node_dmaatb->entry[dir_num][ps_entry]));
		pg_clearpfn(&(node_dmaatb->entry[dir_num][ps_entry]));
		pg_invalid(&(node_dmaatb->entry[dir_num][ps_entry]));
	}

	for (ps_entry = 3; ps_entry < 6; ps_entry++) {
		pg_unsetro(&(dmaatb->entry[0][ps_entry]));
		pg_unsetido(&(dmaatb->entry[0][ps_entry]));
		pg_unsetprot(&(dmaatb->entry[0][ps_entry]));
		pg_unsettype(&(dmaatb->entry[0][ps_entry]));
		pg_clearpfn(&(dmaatb->entry[0][ps_entry]));
		pg_invalid(&(dmaatb->entry[0][ps_entry]));
	}

	VEOS_TRACE("returned with 0x%x", dir_num);
	return dir_num;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_release_dmaatb_entry, ve3_amm_release_dmaatb_entry)

int ve3_amm_sync_node_dmaatb_dir(vehva_t vehva, struct ve_mm_struct *mm,
				dir_t dir_idx, jid_t jid)
{
	ve3_dmaatb_dir_t *pgd = NULL;
	ve3_dmaatb_entry_t *pte = NULL;
	dir_t dir_num = 0;
	ve3_dmaatb_reg_t *dmaatb, *dmaatb_node;
	struct ve_node_struct *vnode = VE_NODE(0);
	dmaatb = &((ve3_veos_dmaatb_reg_t *)mm->dmaatb)->dmaatb_reg;
	dmaatb_node = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg;
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("vehva %lx dmaatb %p dir_idx %d jid %d",
			vehva, dmaatb, dir_idx, jid);

	if (PG_4K == ps_getpgsz(&dmaatb->dir[dir_idx])) {
		dir_num = ve3_amm__get_dma_pgd(vehva, jid, true);
		if (0 > dir_num && mm->is_sched) {
			dir_num = -EINVAL;
			VEOS_DEBUG("Error (%s) while getting directory for VEHVA %p",
					strerror(-dir_num), (void *)vehva);
			return dir_num;
		} else if (!mm->is_sched) {
			VEOS_DEBUG("process is scheduleout and \
				requested for syscall directiory entry");
			return DIR_MAX;
		}
	} else {
		dir_num = dir_idx;
	}

	ps_clrjid(&dmaatb->dir[dir_idx], jid);
	ps_setjid(&dmaatb->dir[dir_idx], jid);
	pgd = &dmaatb_node->dir[dir_num];
	pte = dmaatb_node->entry[dir_num];

	memcpy(&pgd->data, &dmaatb->dir[dir_idx].data, sizeof(ve_reg_t));
	memcpy(pte, dmaatb->entry[dir_idx],
		sizeof(ve_reg_t) * VE3_DMAATB_ENTRY_MAX_SIZE);

	return dir_num;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_sync_node_dma_page_dir, ve3_amm_sync_node_dmaatb_dir)

int ve3_amm__map_dmades(struct ve_task_struct *tsk,
			uint64_t *vehva_dmades, uint64_t *vehva_dmactl)
{
	bool set_permission_bit = true;
	int udma_desc_id = -1;

	VEOS_TRACE("Entering");

	/* thread_group_mm_lock is held here */
	/* Check if DMA descriptor table H is already enabled or not */
	if (tsk->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("DMAATB for DMA descriptor table H"
				" is already allocated of PID: %d", tsk->pid);
		return -EBUSY;
	}

	/* Currently VE task is not scheduled on any of the core.
	 * So we will just update the field "DMA_DESC_H" and
	 * during scheduling DMAATB entry will get allocated.
	 */
	if (-1 == *tsk->core_dma_desc || false == tsk->p_ve_mm->is_sched) {
		VEOS_DEBUG("PID: %d is not scheduled.", tsk->pid);

		/* Currently task is scheduled out so there is no need
		 * to set the permission bit of DMA control register H. */
		set_permission_bit = false;
		goto update_field;
	}

	udma_desc_id = *(tsk->core_dma_desc);
	VEOS_DEBUG("PID %d DMA DESC id %d logical core %d", tsk->pid,
					*tsk->core_dma_desc,  tsk->core_id);

	veraa_t paddr[2] = {
		SYSCOM_NONPRE_ADD +
			VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, VE_UDMA_HENTRY),
		0,
	};
	amm_dump_dmaatb(tsk, true);
	int retval = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE, VE_ADDR_VERAA_NONPRE,
			VEHVA_DMA_DESC_H_REG|VEHVA_4K|VEHVA_MAP_FIXED, true);
	if (0 > retval) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		return retval;
	}

        amm_dump_dmaatb(tsk, true);

update_field:
	/* Zero-clear DMA descriptor table H and DMA control register
	 * corresponding to DMA descriptor table H. */
	memset(&TO_VE3_UDMA(tsk->udma_context)->dmades[VE_UDMA_HENTRY], 0,
		sizeof(ve3_dma_desc_t) * VE3_DMA_DSCR_ENTRY_SIZE);
	memset(&TO_VE3_UDMA(tsk->udma_context)->dmactl[VE_UDMA_HENTRY], 0,
		sizeof(ve3_dma_control_t));

	/* If any threads of the process are running on VE cores, then sync the
	 * soft copy of DMA descriptor table H and DMA control register
	 * corresponding to DMA descriptor table H to actual registers, and set
	 * permission bit in the DMA control register of H.
	 */

	if (set_permission_bit) {
		VEOS_DEBUG("Restore UDMA context corresponding to H");
		if (ve3__psm_restore_udma_context(tsk, *(tsk->core_dma_desc),
				VE_UDMA_HENTRY))
			veos_abort("Fail to Restore DMA H context of core: %d",
					*tsk->core_dma_desc);

		if (psm_start_udma(*(tsk->core_dma_desc), DMA_DESC_H))
			veos_abort("Fail to START DMA H of core: %d",
					*tsk->core_dma_desc);

	}
	*vehva_dmades = DMA_DESC_H_START;
	*vehva_dmactl = DMA_CNT_START;
	tsk->p_ve_mm->udma_desc_bmap = DMA_DESC_E_H;
	VEOS_DEBUG("DMA descriptor table H is now enabled of PID: %d",
			tsk->pid);
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__map_dmades, ve3_amm__map_dmades)

int64_t ve3_amm_free_dmaatb_entry_tsk(struct ve_task_struct *req_tsk,
		vehva_t vehva, size_t size)
{
	int64_t ret = -1;
	dir_t dir_num = -1;
	dir_t prv_dir = -1;
	vehva_t tmp_vehva = 0;
	uint64_t count = 0;
	int pgmod = 0, i = 0, noc = 0, start = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t pgsz;
	dir_t *dirs = NULL;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked(ve3) with pid:%d vehva:%ld size:%ld",
			req_tsk->pid, vehva, size);

	noc = vnode->nr_avail_cores;
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	amm_dump_dmaatb(req_tsk, true);
	/*
	 * Use veos_get_pgmod instead of returning pgmod from veos_vehva_free*/
	pgmod = veos_vehva_free(vehva, size, req_tsk);
	if (0 > pgmod) {
		ret = pgmod;
		VEOS_DEBUG("Error (%s) while freeing vehva",
				strerror(-ret));
		goto err_handle;
	}

	pgsz = (uint64_t)((pgmod == PG_4K) ? PAGE_SIZE_4KB :
		(pgmod == PG_2M) ? PAGE_SIZE_2MB :
		(pgmod == PG_HP) ? PAGE_SIZE_64MB :
		PAGE_SIZE_256MB);

	count = size/pgsz;
	dirs = (dir_t *)malloc((count + 1) * sizeof(dir_t));
	if (dirs == NULL) {
		ret = -ENOMEM;
		VEOS_DEBUG("Error (%s) while freeing vehva", strerror(-ret));
		goto err_handle;
	}
	memset(dirs, -1, sizeof(dir_t) * (count + 1));

	tmp_vehva = vehva;

	for (i = 0; i < count; i++) {
		dir_num = invalidate_vehva(tmp_vehva + (i*pgsz),
				req_tsk->p_ve_mm, req_tsk->jid);
		if (0 > dir_num) {
			ret = -EFAULT;
			VEOS_DEBUG("Error (%s) while unsetting dmaatb",
					strerror(-ret));
			goto err_handle;
		}
		/* Check for node DMAATB for jid & VEHVA  with false
		 * if dir is -1 then do nothing and if any directory
		 * then invalidate correspodning entry
		 * */
		if (prv_dir == -1 || (prv_dir != dir_num))
			dirs[start++] = dir_num;

		prv_dir = dir_num;
	}
	i = 0;

	while (0 <= dirs[i]) {
		if ((dirs[i] >= noc) || (req_tsk->p_ve_mm->is_sched == true)) {
			VEOS_DEBUG("dirs[%d] = %d\n", i, dirs[i]);
			psm_sync_hw_regs(req_tsk, _DMAATB,
					true, dirs[i++], 1);
		} else
			i++;
	}
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	amm_dump_dmaatb(req_tsk, true);
	if (dir_num >= noc) {
		pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
				LOCK, "Failed to aqcuire swap_request lock");
		vnode->resource_freed = true;
		pthread_cond_broadcast(&(vnode->swap_request_pids_cond));
		pthread_mutex_lock_unlock(&(vnode->swap_request_pids_lock),
				UNLOCK, "Failed to release swap_request lock");
	}
	free(dirs);
#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from free_dmaatb_entry");
	amm_dump_dmaatb(NULL, 0);
#endif

	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	return 0;
err_handle:
	free(dirs);
	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_free_dmaatb_entry_tsk, ve3_amm_free_dmaatb_entry_tsk)

int64_t ve3_amm_alloc_dmaatb_entry_by_vehva_tsk(struct ve_task_struct *tsk,
		vhsaa_t *addr, int permission, int addr_flag,
		uint64_t vehva_flag, bool halt_all, uint64_t vehva)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ssize_t i = 0, ret = -1;
	size_t pgsize = 0;
	int dma_pgmod = 0;
	uint64_t *bmap = NULL;
	int64_t entry = -1;
	size_t size = 0;
	dir_t prv_dir = -1;
	dir_t dir_num = -1;
	dir_t dirs[VE3_DMAATB_DIR_NUM] = {0};
	int prot = 0, cnt = 0;
	int64_t count = 0;
	int offset = 0;
	pthread_mutex_t *vehva_lock = NULL; /*!< mutex lock*/
	ve3_dmaatb_reg_t tsk_cp = { { { {0} } } } ,node_cp = { { { {0} } } };

	memset(dirs, -1, sizeof(dirs));

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid = %d, permission = %d, addr_flag = %d"
		"vehva_flag = %ld halt_all = %d vehva = %#08lx",
		tsk->pid, permission, addr_flag, vehva_flag, halt_all, vehva);

	VEOS_DEBUG("Dump dmaatb before alloc entry by vehva");
	amm_dump_dmaatb(tsk, true);

	pgsize = (size_t)((vehva_flag & VEHVA_4K) ? PAGE_SIZE_4KB :
		(vehva_flag & VEHVA_2MB) ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB);
	dma_pgmod = (vehva_flag & VEHVA_4K) ? PG_4K :
		(vehva_flag & VEHVA_2MB) ? PG_2M :
		(vehva_flag & VEHVA_64MB) ? PG_HP :
		PG_SHP;

	offset = (vehva_flag & VEHVA_256MB) ? 4 : 1;
	for (i = 0; addr[i]; i++) {
		VEOS_DEBUG("addr[%ld]:%lx", i, addr[i]);
		size += pgsize;
		count = i + 1;
	}
	count = count / offset;

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	if (vehva_flag & VEHVA_2MB) {
		VEOS_DEBUG("VEHVA request type VESHM_2MB");
		bmap = tsk->p_ve_mm->vehva_header.bmap_2m;
		entry = (vehva - VEHVA_2M_START)/PAGE_SIZE_2MB;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_2m_lock;
	} else if (vehva_flag & VEHVA_64MB) {
		VEOS_DEBUG("VEHVA request type VESHM_64MB");
		bmap = tsk->p_ve_mm->vehva_header.bmap_64m;
		entry = (vehva - VEHVA_64M_START)/PAGE_SIZE_64MB;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_64m_lock;
	} else if (vehva_flag & VEHVA_4K) {
		VEOS_DEBUG("VEHVA request type VESHM_4KB");
		bmap = tsk->p_ve_mm->vehva_header.bmap_4k;
		entry = (vehva - VEHVA_4K_START)/PAGE_SIZE_4KB;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_4k_lock;
	} else if (vehva_flag & VEHVA_256MB) {
		VEOS_DEBUG("VEHVA request type VESHM_256MB");
		bmap = tsk->p_ve_mm->vehva_header.bmap_256m;
		entry = (vehva - VEHVA_256M_START)/(PAGE_SIZE_256MB);
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_256m_lock;
	} else {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) for VESHM vehva", strerror(-ret));
		goto err_handle;
	}

	VEOS_DEBUG("vehva:%ld count:%ld entry:%ld dma pgmod:%d",
			vehva, count, entry, dma_pgmod);
	pthread_mutex_lock_unlock(vehva_lock, LOCK,
			"Failed to acquire VEHVA VESHM lock");
	if (check_bits(bmap, entry, count, MARK_UNUSED)) {
		mark_bits(bmap, entry, count, MARK_USED);
		pthread_mutex_lock_unlock(vehva_lock, UNLOCK,
			"Failed to release VEHVA VESHM lock");
	} else {
		pthread_mutex_lock_unlock(vehva_lock, UNLOCK,
			"Failed to release VEHVA VESHM lock");
		VEOS_ERROR("Used bit is already set");
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) for VESHM vehva", strerror(-ret));
		goto err_handle;
	}
	memset(&tsk_cp, 0, sizeof(ve3_dmaatb_reg_t));
	memset(&node_cp, 0, sizeof(ve3_dmaatb_reg_t));
	/* Here we save the content of node_dmaatb and task_dmaatb.
	 * so in case of failure we can do proper cleanup.
	 */
	memcpy(&tsk_cp, &((ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg, sizeof(ve3_dmaatb_reg_t));
	memcpy(&node_cp, &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg, sizeof(ve3_dmaatb_reg_t));

	prot = (permission & PROT_WRITE) ? 1 : 0;

	/* Allocate DMAATB entry for the absolute address */
	for (i = 0; addr[i]; i = i + offset) {
		dir_num = validate_vehva(vehva+(i*pgsize), prot,
				pfnum(addr[i], dma_pgmod),
				tsk->p_ve_mm,
				dma_pgmod, addr_flag, tsk->jid, vehva_flag,
				tsk->numa_node);
		if (0 > dir_num) {
				ret = -ENOMEM;
			VEOS_DEBUG("Error (%s) while setting vehva 0x%lx",
					strerror(-ret), vehva);
			goto clean_up;
		}
		if (prv_dir == -1 || (prv_dir != dir_num)) {
			if (VE3_DMAATB_DIR_NUM == dir_num)
				continue;
			dirs[cnt++] = dir_num;
			prv_dir = dir_num;
		}
	}

	i = 0;
	while (0 <= dirs[i]) {
		/* Syncing DMAATB with h/w */
		dir_num = dirs[i++];
		if (VE3_DMAATB_DIR_NUM == dir_num)
			continue;
		psm_sync_hw_regs(tsk, _DMAATB, halt_all, dir_num, 1);
	}

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");

	ret = vehva;
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");

	VEOS_DEBUG("Dump dmaatb after alloc entry by vehva");
	amm_dump_dmaatb(tsk, true);

	return ret;
clean_up:
	memcpy(&((ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb)->dmaatb_reg, &tsk_cp, sizeof(ve3_dmaatb_reg_t));
	memcpy(&((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg, &node_cp, sizeof(ve3_dmaatb_reg_t));
	if(0 > veos_vehva_free(vehva, size, tsk)) {
		VEOS_DEBUG("Error (%s) while freeing vehva",
				strerror(-ret));
	}

err_handle:
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_alloc_dmaatb_entry_by_vehva_tsk, ve3_amm_alloc_dmaatb_entry_by_vehva_tsk)
