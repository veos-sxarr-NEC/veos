/*
 * Copyright (C) 2017-2019 NEC Corporation
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
 * @file pgtbl.c
 * @brief AMM core functions which manages the VE memory.
 *
 * @internal
 * @author AMM
 */
#include <unistd.h>
#include <sys/mman.h>
#include "ve_shm.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "task_signal.h"
#include "dmaatb_api.h"
#include "vehva_mgmt.h"
#include "veos_ived.h"


/**
* @brief Dump the information present in page table(ATB).
*
* @param tsk process task struct.
*/
void amm_dump_atb(struct ve_task_struct *tsk)
{
	int entry_cntr = -1, dir_cntr = -1;

	VEOS_DEBUG("Dumping atb for pid %d", tsk->pid);
	atb_reg_t *atb = &tsk->p_ve_mm->atb[0];

	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			VEOS_DEBUG("%d : Partial Space Offset %p PGMOD %s",
					dir_cntr,
					(void *)atb->dir[dir_cntr].data,
					pgmod_to_pgstr(ps_getpgsz(&(atb->dir[dir_cntr]))));
			for (entry_cntr = 0; entry_cntr < ATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(atb->entry[dir_cntr][entry_cntr]))) {
					VEOS_DEBUG("%d : %d :PB  Address %p",
							dir_cntr, entry_cntr, (void *)
							atb->entry[dir_cntr][entry_cntr].data);
				}
			} /* end entry loop */
		} /* end*/
	} /* end dir loop */
}

/**
* @brief Dump the information present in page table(DMAATB).
*
* @param tsk process task struct.
* @param node node id.
*/
void amm_dump_dmaatb(struct ve_task_struct *tsk, bool node)
{
	struct ve_node_struct *vnode_info = VE_NODE(0);
	FILE *fd  = stdout;

	if (!log4c_category_is_priority_enabled(CAT_OS_CORE,
							LOG4C_PRIORITY_DEBUG))
		return;

	VEOS_DEBUG("Dumping DMAATB");

#ifdef DEBUG
	char *filename = tsk->p_ve_mm->dma_dump_file;
	fd = fopen(filename, "a+");
	if (NULL == fd) {
		VEOS_DEBUG("Error (%s) to open new file : %s",
				strerror(str), filename);
		return;
	}
#endif
	if (tsk) {
		VEOS_DEBUG("Dumping DMAATB for pid %d", tsk->pid);
#ifdef DEBUG
		fprintf(fd, "                TASK(%d)\n",
				tsk->pid);
#endif
		__dump_dmaatb(fd, &tsk->p_ve_mm->dmaatb);
	}
	if (node) {
#ifdef DEBUG
		fprintf(fd, "                NODE\n");
#endif
		VEOS_DEBUG("Dumping DMAATB of Node");
		__dump_dmaatb(fd, &vnode_info->dmaatb);
	}
}

/**
 * @brief Dump data of DMAATB
 *
 * @param[in] fd Pointer to FILE
 * @param[in] dmaatb Pointer to DMAATB
 */
void __dump_dmaatb(FILE *fd, dmaatb_reg_t *dmaatb)
{
	int dir_cntr = 0;
	int entry_cntr = 0;

#ifdef DEBUG
	fprintf(fd,
			"\n-------------------------------------------------------\n");
	fprintf(fd,
			"DMAATBDIRNO    PSNUM\n");
	fprintf(fd,
			"\n-------------------------------------------------------\n");
#endif

	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < DMAATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(dmaatb->dir[dir_cntr]))) {
#ifdef DEBUG
			fprintf(fd, "%5d%10lx\n", dir_cntr,
					dmaatb->dir[dir_cntr].data
					& 0xFFFFFFF00000);
#endif
			VEOS_DEBUG("%d : Partial Space Offset %p JID: %ld",
					dir_cntr,
					(void *)dmaatb->dir[dir_cntr].data,
					ps_getjid(&(dmaatb->dir[dir_cntr])));
			for (entry_cntr = 0; entry_cntr < DMAATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
#ifdef DEBUG
				fprintf(fd, "page_no \n");
				fprintf(fd, "%d\n", entry_cntr);
#endif
				/* Check if page entries is valid */
				if (pg_isvalid(&(dmaatb->entry[dir_cntr][entry_cntr]))) {
					VEOS_DEBUG("%d : %d :PB Address %p",
							dir_cntr, entry_cntr, (void *)
							dmaatb->entry[dir_cntr][entry_cntr].data);
				}
			} /* end entry loop */
		} else {
			VEOS_TRACE("DMAATB DIR:%d Invalid", dir_cntr);
		}
	}
}
/**
* @brief This function will validate the given directory(ATB/DMAATB).
*
* @param[out] dt pointer to the directory table which is to be updated.
* @param[in] dir directory number.
* @param[in] psnum  partial space number i.e entry within the directory table.
* @param[in] jid JID in partial space directory.
* @param[in] pgmod page mode to be set.
*/
void __validate_pgd(void *dt, dir_t dir, int psnum, int jid, int pgmod)
{
	int ps_entry = 0;
	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;
	VEOS_TRACE("invoked");

	VEOS_TRACE("dt(%p), dir(%d), psnum(%d), jid(%d), pgmod(%s)",
			dt, dir, psnum, jid, pgmod_to_pgstr(pgmod));

	if (jid < 0) {
		pgd = &((atb_reg_t *)dt)->dir[dir];
		pte = ((atb_reg_t *)dt)->entry[dir];

		/* partial space directory */
		ps_setpsnum(pgd, psnum, pgmod);
		ps_setpgsz(pgd, pgmod);
		ps_valid(pgd);

		/* partial space page table (PSPT) */
		for (ps_entry = 0; ps_entry <
			     ATB_ENTRY_MAX_SIZE; ps_entry++)
			pg_invalid(&pte[ps_entry]);
	} else {
		pgd = &((dmaatb_reg_t *)dt)->dir[dir];
		pte = ((dmaatb_reg_t *)dt)->entry[dir];

		/* partial space directory */
		ps_setpsnum(pgd, psnum, pgmod);
		ps_setjid(pgd, jid);
		ps_setpgsz(pgd, pgmod);
		ps_valid(pgd);

		/*For dmaatb only*/
		if (pgmod != PG_4K) {
			/*Will be used in case of DMAATB only*/
			atb_dir_t *pgd_node = NULL;
			/*Will be used in case of DMAATB only*/
			atb_entry_t *pte_node = NULL;
			struct ve_node_struct *vnode = VE_NODE(0);

			/* partial space directory */
			pgd_node = &vnode->dmaatb.dir[dir];
			pte_node = vnode->dmaatb.entry[dir];

			ps_setpsnum(pgd_node, psnum, pgmod);
			ps_setjid(pgd_node, jid);
			ps_setpgsz(pgd_node, pgmod);
			ps_valid(pgd_node);

			for (ps_entry = 0; ps_entry <
					ATB_ENTRY_MAX_SIZE; ps_entry++)
				pg_invalid(&pte_node[ps_entry]);
		}

		/* partial space page table (PSPT) */
		for (ps_entry = 0; ps_entry <
				ATB_ENTRY_MAX_SIZE; ps_entry++)
			pg_invalid(&pte[ps_entry]);
	}
	VEOS_TRACE("returned");

	return;
}

/**
* @brief Initialize partial space directory.
*
* @param[in] vaddr address of vemva to whom new directory is to be allocated.
* @param[in] pgmod page mode to be set for allocated ATB directory.
* @param[in] tsk process tast struct.
*
* @return On success it returns 0 and -1 on failure.
*/
int amm_do_vemva_init_atb(vemva_t vaddr, int pgmod,
	struct ve_task_struct *tsk)
{
	ret_t ret = 0;
	uint64_t psoff = 0;
	dir_t dir_num = 0;
	atb_reg_t temp_atb[VE_MAX_NUMA_NODE] = {
			  { { { {0} } } },
			  { { { {0} } } } };
	struct ve_node_struct *vnode = VE_NODE(0);
	int index = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("%s vemva 0x%lx init for pid %d",
		pgmod_to_pgstr(pgmod), vaddr, tsk->pid);

	struct ve_mm_struct *mm = tsk->p_ve_mm;

	psoff = psnum(vaddr, pgmod);

	/*Get the local copy of ATB*/
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	for (index = 0; index < vnode->numa_count; index++)
		memcpy(&temp_atb[index], &(mm->atb[index]), sizeof(atb_reg_t));

	/* search whether directory is alloacted or not
	 * if not then allocate new directory for new chunk
	 * */
	dir_num = __get_pgd((vemva_t)vaddr, &temp_atb[0], -1, true);
	if (0 > dir_num) {
		VEOS_DEBUG("tsk:pid(%d) vemva 0x%lx not valid",
				tsk->pid, vaddr);
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		ret = -EINVAL;
		goto hndl_return;
	}

	VEOS_DEBUG("vemva 0x%lx mapped to pgd[%d]", vaddr, dir_num);

	/*
	 * Now set all newly allocated ATB directory Entries
	 */
	if (!ps_isvalid(&(temp_atb[0].dir[dir_num]))) {
		VEOS_DEBUG("validate pgd[%d] for vemva 0x%lx",
				dir_num, vaddr);
		for (index = 0; index < vnode->numa_count; index++)
			validate_pgd(&temp_atb[index], dir_num, psoff, pgmod);
	}

	/*Upadate ATB with new entry*/
	for (index = 0; index < vnode->numa_count; index++)
		memcpy(&(mm->atb[index]), &temp_atb[index], sizeof(atb_reg_t));

	if( 0 == psm_sync_hw_regs(tsk, _ATB, true, -1, 1))
        {
                VEOS_DEBUG("Syncing ATB");
                ret = veos_update_atb(tsk->core_set, &dir_num, 1, tsk);
                if(-1 == ret)
                {
                        VEOS_ERROR("Updating ATB failed");
                        veos_abort("Syncing ATB registers failed");
                }
        }
	/* Reset the core_set as all the cores are restarted*/
	tsk->core_set = 0;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
hndl_return:
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function will find ATB/DMAATB directory for given VE virtual address.
 *	 ATB [0] and ATB[1] are the same except for cache bypass bit.
 *	 so only check ATB[0] directory number.
 *
 * @param[in] vaddr VE virtual address.
 * @param[in] dt reference to directory table.
 * @param[in] jid jid of the process which uses the vaddr.
 * @param[in] inval if true then return new ATB/DMAATB directory to be allocated.
 *              if false then return ATB/DMAATB directory which is allocated.
 * @return 0 ATB/DMAATB directory number on success and -1 on failure.
 */
dir_t __get_pgd(vemva_t vaddr, void *dt, int jid, bool inval)
{
	dir_t ps_entry = 0;
	int atb_num = 0;
	int psnum = 0;		/* partial space # generated from vaddr */
	int psnum_dir = 0;	/* partial space # generated from dir[] entry */
	int pgmod = 0;		/* Page size flag from dir[] entry */
	atb_dir_t *atbp = NULL;
	int unused = -1;	/* unused partial space # */
	struct ve_node_struct *vnode = VE_NODE(0);
	int noc = -1;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("%lx vemva for jid %d", vaddr, jid);
	noc = vnode->nr_avail_cores;

	VEOS_DEBUG("%d number of cores available", noc);

	ps_entry = (0 > jid) ? 0 :
			(((uint64_t)vaddr < VEHVA_DIR0_END) ? 0 :
			 noc);

	atb_num = (0 > jid) ? ATB_DIR_NUM : ((uint64_t)vaddr <
			VEHVA_DIR0_END) ? noc : DMAATB_DIR_NUM;

	atbp = (0 > jid) ? &((atb_reg_t *)dt)->dir[ps_entry] :
		&vnode->dmaatb.dir[ps_entry];

	VEOS_DEBUG("vemva(%lx), dt(%p)", vaddr, atbp);
	VEOS_TRACE("iterating page tables");
	for (; ps_entry < atb_num; ps_entry++) {
		/* Is atbp valid? */
		if (ps_isvalid(atbp)) {
			/* If atbp is DMAATB, check JID. */
			VEOS_TRACE("pgd[%p] is valid", atbp);
			if (!(0 > jid)) {
				VEOS_TRACE("match job id of pgd");
				if (ps_getjid(atbp) != jid) {
					atbp++;
					continue;
				}
			}

			pgmod = ps_getpgsz(atbp);
			psnum = psnum(vaddr, pgmod);
			/* psnum check */
			psnum_dir = ps_getps(atbp, pgmod);
			if (psnum_dir == psnum) {
				VEOS_TRACE("returned %d", ps_entry);
				return ps_entry;
			}
		} else if (inval) {
			if (0 > unused)
				unused = ps_entry;
		}
		atbp++;
	}
	VEOS_TRACE("page table iteration ends");
	VEOS_TRACE("returned %d", unused);
	return unused;
}

/**
* @brief Search a ATB partial space directory of specified VE virtual address.
*
* @param[in] vaddr VE virtual address.
* @param[in] tsk process task structure.
*
* @return 0 ATB/DMAATB directory number on success and -1 on failure.
*/
dir_t get_pgd(vemva_t vaddr, struct ve_task_struct *tsk)
{
	return __get_pgd(vaddr, &tsk->p_ve_mm->atb[0], -1, true);
}

/**
* @brief Search a DMAATB partial space directory of specified VE virtual address.
*
* @param[in] vaddr VE virtual address.
* @param[in] tsk process task structure.
*
* @return 0 ATB/DMAATB directory number on success and -1 on failure.
*/
dir_t get_dmapgd(vehva_t vehva, struct ve_task_struct *tsk)
{
	return __get_pgd(vehva, NULL, tsk->jid, true);
}

/**
* @brief This routine invalidate the ATB page table
*	for newly created ve_mm_struct.
*
* @param[in] atb reference to the page table(ATB).
*/
void invalidate_atb(atb_reg_t *atb)
{
	dir_t dirno = 0;
	ent_t entry = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("atb(%p)", atb);
	memset(atb, 0, sizeof(atb_reg_t));
	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		ps_invalid(&(atb->dir[dirno]));
		for (entry = 0; entry < ATB_ENTRY_MAX_SIZE; entry++)
			pg_invalid(&(atb->entry[dirno][entry]));
	}
	VEOS_TRACE("returning");
	return;
}

/**
* @brief This routine invalidate the DMAATB page table
*	for newly created ve_mm_struct.
*
* @param[in] dmaatb reference to the page table(DMAATB).
*/
void invalidate_dmaatb(dmaatb_reg_t *dmaatb)
{
	dir_t dirno = 0;
	ent_t entry = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("dmaatb(%p)", dmaatb);
	/*
	 * Initialize the DMAATB structure for new allocation
	 */
	memset(dmaatb, 0, sizeof(dmaatb_reg_t));

	VEOS_TRACE("iterate dma page tables");
	for (dirno = 0; dirno < DMAATB_DIR_NUM; dirno++) {
		ps_invalid(&(dmaatb->dir[dirno]));
		for (entry = 0; entry < DMAATB_ENTRY_MAX_SIZE; entry++) {
			pg_invalid(&(dmaatb->entry[dirno][entry]));
			VEOS_TRACE("dma pgd[%d] and value(0x%lx)",
				dirno, dmaatb->dir[dirno].data);
			VEOS_TRACE("dma pte[%d][%d] and value(%lx)",
				dirno, entry,
				dmaatb->entry[dirno][entry].data);
		}
	}
	VEOS_TRACE("iteration ends");
	VEOS_TRACE("returning");
	return;
}

/**
* @brief This routine will invalidate atb entries which are allocated to VESHM.
*
* @param[in] new_atb reference to the page table(ATB).
* @param[in] veshm veshm related information(directory base address and veshm bitmap).
*
*/
void invalidate_veshm_pte(atb_reg_t *new_atb, struct veshm_struct *veshm)
{
	int word = 0;
	int bit = 0;
	int dir_count = 0;
	int8_t dir_num = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("atb(%p) and veshm map(%p)",
		new_atb, veshm);
	VEOS_TRACE("page table itertaion starts");
	for (dir_count = 0; dir_count < ATB_DIR_NUM; dir_count++) {
		dir_num = __get_pgd(veshm[dir_count].vemva_base,
				new_atb, -1, false);
		if (0 > dir_num)
			continue;
		for (word = 0; word < 4; word++) {
			for (bit = 0; bit < 64; bit++) {
				if (!(veshm[dir_count].bitmap[word] &
							((uint64_t)1 << bit))) {
					VEOS_TRACE("Invalidate pte[%d][%d] mapped with VESHM",
							dir_num, ((word*64) + bit));
					/*unset destination type*/
					pg_unsettype(&(new_atb->entry[dir_num][((word*64) + bit)]));
					/*set pgno to zero in atb*/
					pg_clearpfn(&(new_atb->entry[dir_num][((word*64) + bit)]));
					/*unset the permission*/
					pg_unsetprot(&(new_atb->entry[dir_num][((word*64) + bit)]));
					/*unset the bypass*/
					pg_unsetbypass(&(new_atb->entry[dir_num][((word*64) + bit)]));
					/*Mark entry as invalid*/
					pg_invalid(&(new_atb->entry[dir_num][((word*64) + bit)]));

				}
			}
		}
	}
	VEOS_TRACE("page table iteration ends");
	VEOS_TRACE("returned");
}

/**
* @brief This routine copy old atb entries to new atb with same physical page.
*
* @param[in] old_atb reference to the old page table.
* @param[out] new_atb reference to the new page table.
* @param[in] veshm related information(directory base address and veshm bitmap).
* @param[in] numa_node NUMA node number of the VE process requires memories
*	     is running on.
*
* @return On success return 0 and negative of errno on failure.
*/
int amm_copy_atb_private(struct ve_mm_struct *mm_old, struct ve_mm_struct *mm,
				int numa_node)
{
	atb_reg_t *old_atb = mm_old->atb, *new_atb = mm->atb;
	struct veshm_struct *veshm = mm->veshm;
	int mempolicy = mm_old->mem_policy;
	int dirno = 0, ent = 0;
	int pgmod = 0;
	int ret = 0;
	int i = 0;
	atb_entry_t *new_pte[VE_MAX_NUMA_NODE];
	atb_entry_t *old_pte[VE_MAX_NUMA_NODE];
	struct ve_node_struct *vnode = VE_NODE(0);
	int mp_num = 0;
	pgno_t pgno = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("old atb(%p), new atb(%p) and veshm map(%p)",
		&old_atb[0], &new_atb[0], veshm);

	for (i = 0; i < vnode->numa_count; i++) {
		memcpy(&new_atb[i], &old_atb[i], sizeof(atb_reg_t));
		invalidate_veshm_pte(&new_atb[i], veshm);
	}

	VEOS_TRACE("iterate and copy pte's");
	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		if (ps_isvalid(&(new_atb[0].dir[dirno]))) {
			pgmod = ps_getpgsz(&(new_atb[0].dir[dirno]));
			for (i = 0; i < vnode->numa_count; i++) {
				new_pte[i] = new_atb[i].entry[dirno];
				old_pte[i] = old_atb[i].entry[dirno];
			}
			for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
				VEOS_TRACE("valid old pte[%d][%d] with val %lx",
					dirno, ent, old_pte[0][ent].data);
				VEOS_TRACE("valid new pte[%d][%d] with val %lx",
					dirno, ent, new_pte[0][ent].data);
				/**
				 * If ATB enrty is not valid it will check,
				 * whether any valid page number is there or not.
				 * In case of PROT_NONE memory ATB entry is invalid
				 * but it is having valid page number.
				 */
				if (!(pg_isvalid(&new_pte[0][ent]) ||
					pg_getpb(&new_pte[0][ent], PG_2M)))
					continue;
				ret = copy_entry(&new_pte[0][ent],
						&old_pte[0][ent], pgmod,
						mempolicy, numa_node, mm);
				if (0 > ret) {
					VEOS_DEBUG("Error (%s) while copying pte",
							strerror(-ret));
					amm_atb_cleanup(&new_atb[0], dirno, ent);
					return ret;
				}
				/* Apply update of atb[0] by copy_entry() to atb[1]. */
				for (i = 1; i < vnode->numa_count; i++) {
					pg_clearpfn(&new_pte[i][ent]);
					pg_setpb(&new_pte[i][ent],
							pg_getpb(&new_pte[0][ent], PG_2M),
							PG_2M);
					if (vnode->partitioning_mode != 1)
						continue;
					pgno = pg_getpb(&new_pte[i][ent], PG_2M);
					mp_num = (int)paddr2mpnum(pbaddr(pgno, PG_2M),
							numa_sys_info.numa_mem_blk_sz,
							numa_sys_info.first_mem_node);
					if (i != mp_num)
						pg_setbypass(&new_pte[i][ent]);
					else
						pg_unsetbypass(&new_pte[i][ent]);
				}
			}
		}
	}
	VEOS_TRACE("iteration ends");
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will release half allocated memory in case process creation
*
* @param[in] new_atb reference to newly allocated atb structure.
* @param[in] dirno directory number
* @param[in] ent entry number.
*/
void amm_atb_cleanup(atb_reg_t *new_atb, int dirno, int ent)
{
	int dir_idx = 0;
	int ent_idx = 0;
	int ent_loop = ATB_ENTRY_MAX_SIZE;
	atb_entry_t *new_pte = NULL;
	pgno_t pgno = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("Cleanup from directory(%d) and ATB entry(%d)", dirno, ent);

	for (dir_idx = 0; dir_idx <= dirno; dir_idx++) {
		if (ps_isvalid(&(new_atb->dir[dir_idx]))) {
			new_pte = new_atb->entry[dir_idx];
			/*If last directory then go till allocated entry only*/
			if (dir_idx == dirno)
				ent_loop = ent;
			for (ent_idx = 0; ent_idx < ent_loop; ent_idx++) {
				VEOS_TRACE("valid new pte[%d][%d] with val %lx",
						dir_idx, ent_idx, new_pte[ent_idx].data);
				if (pg_isvalid(&new_pte[ent_idx]) ||
						pg_getpb(&new_pte[ent_idx], PG_2M)) {
					pgno = pg_getpb(&new_pte[ent_idx], PG_2M);
					VEOS_DEBUG("FORK (Error) Freeing page[%ld]", pgno);

					if (pgno != PG_BUS)
						amm_put_page(pbaddr(pgno, PG_2M));
				}
			}
		}
	}

	VEOS_TRACE("returned");
}


/**
* @brief This function will copy the atb entry from ATB copy of parent to
*        the newly allocated mm struct of vfoked child.
*
* @param[in] old_atb reference to the old page table.
* @param[in] new_atb reference to the new page table
* @param[in] veshm veshm related information(directory base address and veshm bitmap).
*/
void amm_copy_atb_vfork(atb_reg_t *old_atb,
			atb_reg_t *new_atb, struct veshm_struct *veshm)
{
	int dirno = 0, ent = 0;
	atb_entry_t *new_pte[VE_MAX_NUMA_NODE];
	int i = 0;
	uint64_t op_flg = 0;
	pgno_t pgno = 0;
	vemaa_t pb[2] = {0};
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");
	for (i = 0; i < vnode->numa_count; i++) {
		memcpy(&new_atb[i], &old_atb[i], sizeof(atb_reg_t));
		/*Invalidating entry which are allocated for VESHM*/
		invalidate_veshm_pte(&new_atb[i], veshm);
	}

	/* copy all entries as it is and then increase
	 * the ref count of all pages*/
	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		if (ps_isvalid(&(new_atb[0].dir[dirno]))) {
			new_pte[0] = new_atb[0].entry[dirno];
			for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
				VEOS_TRACE("valid new pte[%d][%d] with val %lx",
					dirno, ent, new_pte[0][ent].data);
				/**
				 * If ATB enrty is not valid it will check,
				 * whether any valid page number is there or not.
				 * In case of PROT_NONE memory ATB entry is invalid
				 * but it is having valid page number
				 * refs count up only once. So only node is 0.
				 **/
				if (pg_isvalid(&new_pte[0][ent]) ||
					 pg_getpb(&new_pte[0][ent], PG_2M)) {

					/*Get page number from new ATB entry*/
					pgno = pg_getpb(&new_pte[0][ent], PG_2M);

					if (pgno == PG_BUS)
						continue;
					op_flg = VE_PAGE(vnode, pgno)->flag;
					if (op_flg & PG_SHM) {
						VEOS_DEBUG("copying page of shared memory segment");
						pthread_mutex_lock_unlock(&(((struct shm *)(VE_PAGE(vnode, pgno)->
							private_data))->shm_lock), LOCK, "Failed to acquire shm_lock");
						((struct shm *)(VE_PAGE(vnode, pgno)->
							private_data))->nattch++;
						pthread_mutex_lock_unlock(&(((struct shm *)(VE_PAGE(vnode, pgno)->
							private_data))->shm_lock), UNLOCK, "Failed to acquire shm_lock");
					}
					/*Increament the refs count of all pages*/
					pb[0] = (pgno  * PAGE_SIZE_2MB);
					pb[1] = '\0';
					VEOS_DEBUG("increamenting the ref count of"
						"VE page(0x%lx)", pb[0]);
					amm_get_page(pb);
				}
			}
		}
	}
	VEOS_TRACE("returned");
}

/**
* @brief This routine copy old atb entries to new atb and also depending
*	on flag it will allocate new VE page.
*
* @param[in] new_atb reference to the old page table.
* @param[in] old_atb reference to the new page table.
* @param[in] page mode page mode of the given page table entry.
* @param[in] mempolicy Memory policy for partitioning mode.
* @param[in] numa_node NUMA node number of the VE process requires memories
*	     is running on.
*
* @return On success return 0 and negative of errno on failure.
*/
int copy_entry(atb_entry_t *new_pte, atb_entry_t *old_pte,
		int pgmod, int mempolicy, int numa_node,
		struct ve_mm_struct *mm)
{
	pgno_t pgno_dst = 0;
	pgno_t pgno_src = 0;
	vemaa_t src_addr = 0, dest_addr = 0;
	size_t pgsz = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	vemaa_t pb[2] = {0};
	uint64_t op_flg = 0;
	int op_perm, ret = 0;
	int mp_num = 0;
	struct mmap_mem *mmap_mem = NULL, *mmap_tmp = NULL, *mmap_n = NULL;
	struct mmap_desc *mmap_desc = NULL, *mmap_d_tmp = NULL;
	bool found = false;

	VEOS_TRACE("invoked");

	pgno_src = pg_getpb(old_pte, PG_2M);
	pgno_dst = pg_getpb(new_pte, PG_2M);

	VEOS_DEBUG("copy pte from(%p) to(%p) with %s",
		old_pte, new_pte, pgmod_to_pgstr(pgmod));

	VEOS_DEBUG("copy VE page from pgno [(%ld) to (%ld)",
		pgno_src, pgno_dst);
	if ((pgno_src == PG_BUS) || (pgno_dst == PG_BUS))
		return 0;

	op_flg = VE_PAGE(vnode, pgno_src)->flag;
	op_perm = VE_PAGE(vnode, pgno_src)->perm;

	pgsz = (size_t)pgmod_to_pgsz(pgmod);

	/* Below condition is for allocating new page in child
	 * When flags are as follows:
	 * MAP_PRIVATE | PROT_READ not allocating new
	 * MAP_PRIVATE |PROT_WRITE allocate new
	 * MAP_VDSO : No new allocation
	 * MAP_SHARED: no new allocation
	 * If is followed with not operation
	 */
	if (!((op_flg & MAP_SHARED) || (op_flg & PG_SHM) ||
			(op_flg & MAP_VDSO) || !(op_perm & PROT_WRITE))) {
		ret = alloc_ve_pages(1, &pgno_dst, pgmod,
				mempolicy, numa_node, NULL);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while allocating VE page",
				strerror(-ret));
			goto alloc_error;
		}

		/*Update perm*/
		VE_PAGE(vnode, pgno_dst)->perm = (uint64_t)op_perm;

		/*Update flag*/
		VE_PAGE(vnode, pgno_dst)->flag = op_flg;

		VEOS_DEBUG("dst page %ld configured with 0x%lx and %s",
			pgno_dst, op_flg,
			perm_to_str(op_perm));

		pg_clearpfn(new_pte);
		pg_setpb(new_pte, pgno_dst, PG_2M);

		list_for_each_entry(mmap_tmp, &(mm->mmap_page_priv), 
							list_mmap_pages) {
			mmap_d_tmp = mmap_tmp->mmap_descripter;
			if (mmap_d_tmp->pgsz == pgsz) {
				mmap_d_tmp->in_mem_pages++;
				mmap_d_tmp->reference_count++;
				mmap_d_tmp->sum_virt_pages++;
				mmap_tmp->virt_page++;
				VE_PAGE(vnode, pgno_dst)->private_data =
								mmap_d_tmp;
				found = true;
				break;
			}
		}

		if (found == false) {
			mmap_desc = init_mmap_desc();
			if (NULL == mmap_desc) {
				ret = -errno;
				VEOS_CRIT("Failed to allocate memory for mmap_desc");
				goto error;
			}
			mmap_desc->pgsz = pgsz;
			mmap_desc->in_mem_pages = 1;
			mmap_desc->reference_count = 1;
			mmap_desc->sum_virt_pages = 1;
			mmap_mem = init_mmap_mem();
			if (NULL == mmap_mem) {
				ret = -errno;
				VEOS_CRIT("Failed to allocate memory for mmap_mem");
				pthread_mutex_destroy(&mmap_desc->mmap_desc_lock);
				free(mmap_desc);
				goto error;
			}
			mmap_mem->mmap_descripter = mmap_desc;
			mmap_mem->virt_page = 1;
			list_add_tail(&mmap_mem->list_mmap_pages, &mm->mmap_page_priv);
			VE_PAGE(vnode, pgno_dst)->private_data = mmap_desc;
		}

		/* copy_entry handling only atb soft image of numa node 0 */
		if (vnode->partitioning_mode == 1) {
			mp_num = (int)paddr2mpnum(pbaddr(pgno_dst, PG_2M),
					numa_sys_info.numa_mem_blk_sz,
					numa_sys_info.first_mem_node);
			if (mp_num != 0)
				pg_setbypass(new_pte);
			else
				pg_unsetbypass(new_pte);
		}

		src_addr = pgaddr(old_pte);
		dest_addr = pgaddr(new_pte);

		VEOS_DEBUG("src page base(%lx) and dst page base(%lx)",
			src_addr, dest_addr);

		ret = memcpy_petoe(src_addr, dest_addr, pgsz);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while copying page contents",
				strerror(-ret));
			goto error;
		}

		pgno_src = pgno_dst;
	} else {
		if (op_flg & PG_SHM) {
			VEOS_DEBUG("copying page of shared memorys segment");
			pthread_mutex_lock_unlock(&((struct shm *)(VE_PAGE(vnode, pgno_src)->
				private_data))->shm_lock, LOCK,
				"Fail to get shm_lock lock");

			((struct shm *)(VE_PAGE(vnode, pgno_src)->private_data))->nattch++;

			pthread_mutex_lock_unlock(&((struct shm *)(VE_PAGE(vnode, pgno_src)->
				private_data))->shm_lock, UNLOCK,
				"Fail to release shm_lock lock");
		}
	}
	/*Increament the ref
	 * count of allocated pages*/
	pb[0] = (pgno_src  * PAGE_SIZE_2MB);
	pb[1] = '\0';
	VEOS_DEBUG("copied page address(%lx)",
		pb[0]);
	amm_get_page(pb);

	VEOS_TRACE("returned");
	return ret;
error:
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Fail to get ve page lock");
	veos_free_page(pgno_dst);
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release ve page lock");
alloc_error:
	list_for_each_entry_safe(mmap_tmp, mmap_n, &(mm->mmap_page_priv),
							list_mmap_pages) {
		/*after that, amm_put_page is called in amm_atb_cleanup()
		 *so, don't free mmap_desc */
		list_del(&(mmap_tmp->list_mmap_pages));
		free(mmap_tmp);
	}
	return ret;
}

/**
* @brief This function will set page table entry(ATB/DMAATB) for
*	 given VE virtual address.
*
* @param[in] vaddr VE virtual address.
* @param[in] rw memory protection to be set.
* @param[in] pgno VE physical page.
* @param[in] pdt  Page Descriptor Table.
* @param[in] pgmod VE physical page mode.
*
* @return on success it will return directory number and
*	  negative of errno on failure.
*/
dir_t validate_vemva(vemva_t vaddr, int rw, pgno_t pgno,
		void *pdt, int pgmod)
{
	ret_t ret = 0;
	uint64_t  psoff = 0;
	uint64_t pgoff = 0;
	dir_t dir_num = -1;

	uint8_t type = VE_ADDR_VEMAA;
	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;

	struct ve_node_struct *vnode = VE_NODE(0);
	int i = 0;
	int mp_num = 0;

	psoff = psnum(vaddr, pgmod);

	VEOS_TRACE("invoked");
	/*
	 * Check for node structure to find Directory
	 * w.r.t vemva.
	 */
	dir_num =  __get_pgd(vaddr, &((atb_reg_t *)pdt)[0], -1, true);
	if (dir_num < 0) {
		VEOS_DEBUG("no page directory for vemva %lx", vaddr);
		ret = -EINVAL;
		goto error;
	}


	pgoff = pgentry(vaddr, pgmod);

	VEOS_DEBUG("psoff %lx pgoff %lx pgmod = %d type %d",
		psoff, pgoff, pgmod, type);

	for (i = 0; i < vnode->numa_count; i++) {
		pgd = &((atb_reg_t *)pdt)[i].dir[dir_num];
		pte = ((atb_reg_t *)pdt)[i].entry[dir_num];

		if (!ps_isvalid(pgd)) {
			VEOS_DEBUG("pgd[%d] is invalid",
					dir_num);
			__validate_pgd(&((atb_reg_t *)pdt)[i],
					dir_num, psoff, -1, pgmod);
		} else {
			VEOS_DEBUG("pgd[%d] is valid", dir_num);
		}

		if (pg_isvalid(&pte[pgoff])) {
			VEOS_DEBUG("pte[%ld] is valid for addr(%lx)"
					"with fixed map",
					pgoff, vaddr);
			ret =  -ENOMEM;
			goto error;
		}

		VEOS_DEBUG("validate atb pte[%ld] with pgnum %ld",
				pgoff, pgno);
		pg_setpb(&pte[pgoff], pgno, PG_2M);

		pg_valid(&pte[pgoff]);

		if (rw == 0)
			pg_setprot(&pte[pgoff]);
		else if (-1 == rw)
			pg_invalid(&pte[pgoff]);

		pg_settype(&pte[pgoff], type);

		if (vnode->partitioning_mode == 1) {
			mp_num = (int)paddr2mpnum(pbaddr(pgno, PG_2M),
						numa_sys_info.numa_mem_blk_sz,
						numa_sys_info.first_mem_node);
			if (i != mp_num)
				pg_setbypass(&pte[pgoff]);
			else
				pg_unsetbypass(&pte[pgoff]);
		}
	}
	ret = dir_num;

error:
	return ret;
}

/**
 * @brief This function will set page table entry(DMAATB) for
 *	 given VE virtual address.
 *
 * @param[in] vaddr VE virtual address.
 * @param[in] rw memory protection to be set.
 * @param[in] pgno VE physical page.
 * @param[in] pdt  Page Descriptor Table.
 * @param[in] pgmod VE physical page mode.
 * @param[in] type VE physical page type to be set.
 * @param[in] jid jid of given process.
 * @param[in] vehva_flag VH virtual memory flag.
 * @param[in] numa_node NUMA node number of the VE process requires memories
 *	     is running on.
 *
 * @return on success it will return directory number and
 *	   negative of errno on failure.
 */
dir_t validate_vehva(vemva_t vaddr, int rw, pgno_t pgno,
		void *pdt, int pgmod, uint8_t type,
		jid_t jid, uint16_t vehva_flag,
		int numa_node)
{
	ret_t ret = 0;
	uint64_t  psoff = 0;
	uint64_t pgoff = 0;
	dir_t dir_num = -1;
	struct ve_mm_struct *mm = NULL;

	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;

	psoff = psnum(vaddr, pgmod);

	if (jid < 0) {
		VEOS_ERROR("Invalid jid %d", jid);
		ret = -EINVAL;
		goto error;
	}
	/*
	 * Check for node structure to find Directory
	 * w.r.t vehva.
	 */
	if (pgmod == PG_4K) {
		dir_num = 0; /*syscall Dir*/
	} else {
		dir_num =  __get_pgd(vaddr, pdt, jid, true);
		if (dir_num < 0) {
			VEOS_DEBUG("no page directory for vehva %lx", vaddr);
			ret = -EINVAL;
			goto error;
		}
	}
	/*
	 * Setting DMAATB Directory entries
	 */
	pgoff = pgentry(vaddr, pgmod);

	VEOS_DEBUG("psoff %lx pgoff %lx pgmod = %d type %d",
		psoff, pgoff, pgmod, type);
	pgd = &((dmaatb_reg_t *)pdt)->dir[dir_num];
	pte = ((dmaatb_reg_t *)pdt)->entry[dir_num];

	if (!ps_isvalid(pgd)) {
		VEOS_DEBUG("pgd[%d] is invalid",
				dir_num);
		__validate_pgd(pdt, dir_num, psoff, jid, pgmod);
	} else {
		VEOS_DEBUG("pgd[%d] is valid", dir_num);
	}

	if (pg_isvalid(&pte[pgoff])) {
		if (vehva_flag & VEHVA_MAP_FIXED) {
			pg_unsetro(&pte[pgoff]);
			pg_unsetido(&pte[pgoff]);
			pg_unsetprot(&pte[pgoff]);
			pg_unsettype(&pte[pgoff]);
			pg_clearpfn(&pte[pgoff]);
			pg_invalid(&pte[pgoff]);
		} else {
			VEOS_DEBUG("pte[%ld] is valid for addr(%lx)"
					"with fixed map",
					pgoff, vaddr);
			ret =  -ENOMEM;
			goto error;
		}
	}

	VEOS_DEBUG("validate dma pte[%ld] with pgnum %ld", pgoff, pgno);
	pg_setpb(&pte[pgoff], pgno, pgmod);
	if (!((vaddr >= VEHVA_4K_START) &&
				(vaddr < VEHVA_4K_END)))
		hw_dma_map[dir_num].count++;
	VEOS_DEBUG("dma map pgd[%d] count is %lu",
			dir_num, hw_dma_map[dir_num].count);

	pg_valid(&pte[pgoff]);

	/* DMAATB use LCC. So bypass bit setting unnecessary. */
	if (rw == 0)
		pg_setprot(&pte[pgoff]);
	else if (-1 == rw)
		pg_invalid(&pte[pgoff]);

	pg_setro(&pte[pgoff]);
	pg_setido(&pte[pgoff]);
	pg_settype(&pte[pgoff], type);

	mm = (struct ve_mm_struct *)container_of(pdt,
			struct ve_mm_struct, dmaatb);
	dir_num = sync_node_dmaatb_dir(vaddr, mm, dir_num, jid);
	if (0 > dir_num) {
		VEOS_DEBUG("no page directory for vehva %lx", vaddr);
		ret = dir_num;
		goto error;
	}
	ret = dir_num;
error:
	return ret;
}
/**
* @brief This function translate's the VE Virtual address
*        to Physical address based on the ATB.
*
* @param[in] vaddr VE Virtual address.
* @param[in] atb ATB of the VE process.
*
* @return On Success, it returns the Physical address or
*	  negative of errno on failure.
*/
vemaa_t __veos_virt_to_phy(vemva_t vaddr, atb_reg_t *atb,
		int *prot, int *pgmod)
{
	int pgmod_dir = 0;
	dir_t dir_num = 0;
	uint64_t pgoff = 0;
	ent_t pgent = 0;
	int lprot = 0;
	ret_t ret = 0;

	VEOS_TRACE("invoked");
	dir_num = __get_pgd(vaddr, atb, -1, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("__veos_virt_to_phy Error (%s) in getting pgd for vemva %lx",
			strerror(-ret), vaddr);
		return ret;
	}
	pgmod_dir = ps_getpgsz(&atb->dir[dir_num]);

	if (pgmod)
		*pgmod = pgmod_dir;

	pgent = pgentry(vaddr, pgmod_dir);
	pgoff = (reg_t)vaddr & ((pgmod_dir == PG_2M) ?
			POFFMASK : POFFMASK_H);

	if (!pg_isvalid(&(atb->entry[dir_num][pgent]))) {
		if (!pg_getpb(&(atb->entry[dir_num][pgent]), PG_2M)) {
			VEOS_DEBUG("pte not valid for vemva %lx",
					vaddr);
			ret = -EINVAL;
			return ret;
		}
		lprot = PROT_NONE;
	} else if (pg_isprot(&atb->entry[dir_num][pgent]))
		lprot = PROT_READ;
	else
		lprot = PROT_WRITE;

	if (prot)
		*prot = lprot;

	VEOS_DEBUG("vemva 0x%lx mapped to pte[%d][%d] and val 0x%lx",
		vaddr, dir_num, pgent, atb->entry[dir_num][pgent].data);

	ret = pg_getpb(&(atb->entry[dir_num][pgent]), PG_2M);
	if (ret == PG_BUS) {
		VEOS_DEBUG("vemva 0x%lx mapped to bus error", vaddr);
		return -EINVAL;
	}

	ret = (ret * PAGE_SIZE_2MB) | pgoff;

	VEOS_DEBUG("%s vemva 0x%lx mapped with vemaa 0x%lx"
		"pgoff(0x%lx) and prot(%0xlx)",
		pgmod_to_pgstr(pgmod_dir), vaddr, ret, pgoff, lprot);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This is generic handler to check rw permission on given iovec.
 *
 * @param[in] tsk Pointer of ve_task_struct of the VE process.
 * @param[in] rw_agrs  Contaion information to check  the permission.
 *
 * @return On success return 0 and negative of errno on failure.
 */
int amm_rw_check_permission(struct ve_task_struct *tsk,
		struct ve_rw_check_iovec rw_args)
{
	ret_t ret = 0;
	int prot = 0;
	ssize_t pg_size = 0;
	int64_t pages = 0, i = 0;
	vemva_t va_addr = 0;
	pg_size = PAGE_SIZE_2MB;
	pages = (rw_args.len/pg_size);
	va_addr = rw_args.vaddr;
	VEOS_TRACE("invoked");

	do {
		if (rw_args.type) {
			ret = check_write_permisssion(va_addr,
					rw_args.pid);
			if (0 > ret) {
				VEOS_DEBUG("%lx is write protected", va_addr);
				return ret;
			}
		} else {
			ret = veos_virt_to_phy(va_addr, rw_args.pid, 0, &prot);
			if (0 > ret) {
				VEOS_DEBUG("%lx is not allocated", va_addr);
				return ret;
			} else if (prot == PROT_NONE) {
				VEOS_DEBUG("Addr is PROT_NONE");
				return -EINVAL;
			}
		}
		i++;
		va_addr += pg_size;
	} while (i < pages);

	VEOS_TRACE("returned");
	return 0;
}

/**
* @brief This function will invalidate the page table entry
*   which allocated to given VE virtual address.
*
* @param[in] vaddr VE virtual address.
* @param[in] pdt reference to the page table.
*
* @return On success it will return ATB directory number
*	and negative of errno on failure.
*/
dir_t invalidate_vemva(vemva_t vaddr, void *pdt)
{
	uint64_t pgoff = 0;
	dir_t dir_tsk = 0, dir_num = 0;
	int pgmod = 0;
	atb_entry_t *pte;
	struct ve_node_struct *vnode = VE_NODE(0);
	int i = 0;

	VEOS_TRACE("invoked");
	VEOS_TRACE("vemva  %lx for pdt %p",
			vaddr, pdt);

	dir_num =  __get_pgd(vaddr, &((atb_reg_t *)pdt)[0], -1, false);
	if (dir_num < 0) {
		dir_num = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for vemva %lx",
				strerror(dir_num), vaddr);
		return dir_num;
	} else {
		dir_tsk = dir_num;
	}

	pgmod = ps_getpgsz(&((atb_reg_t *)pdt)[0].dir[dir_tsk]);
	pgoff = pgentry(vaddr, pgmod);

	VEOS_DEBUG("%s VEMVA  0x%lx is mapped to pgoff %lx",
			pgmod_to_pgstr(pgmod), vaddr, pgoff);

	for (i = 0; i < vnode->numa_count; i++) {
		pte = ((atb_reg_t *)pdt)[i].entry[dir_tsk];
		if ((!pg_isvalid(&pte[pgoff]))
			&& (!pg_getpb(&pte[pgoff], PG_2M))) {
			VEOS_DEBUG("Invalid pte %ld associated with vemva %lx",
					pgoff, vaddr);
			dir_num = -EINVAL;
			goto out;
		}
	}
	for (i = 0; i < vnode->numa_count; i++) {
		pte = ((atb_reg_t *)pdt)[i].entry[dir_tsk];

		pg_unsettype(&pte[pgoff]);
		pg_clearpfn(&pte[pgoff]);
		pg_invalid(&pte[pgoff]);
		pg_unsetprot(&pte[pgoff]);
		pg_unsetbypass(&pte[pgoff]);

		invalidate_pgd(&((atb_reg_t *)pdt)[i], dir_tsk);
	}
out:
	VEOS_TRACE("returned");
	return dir_num;
}
/**
* @brief This function will invalidate the page table entry
*   which allocated to given VE virtual address.
*
* @param[in] vaddr VE virtual address.
* @param[in] pdt reference to the page table.
* @param[in] jid jid of given process.
*
* @return On success it will return (DMATAB) directory number
*	and negative of errno on failure.
*/
dir_t invalidate_vehva(vemva_t vaddr, void *pdt, jid_t jid)
{
	uint64_t pgoff = 0;
	pgno_t pb = 0;
	int pg_type = 0;
	vemaa_t vemaa = 0;
	dir_t dir_tsk = 0, dir_num = 0;
	int pgmod = 0;
	atb_dir_t *pgd = NULL, *node_pgd = NULL;
	atb_entry_t *pte, *node_pte = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");
	VEOS_TRACE("vehva %lx for pdt %p",
			vaddr, pdt);

	if (jid < 0) {
		VEOS_ERROR("Invalid jid %d", jid);
		dir_num = -EINVAL;
		return dir_num;
	}

	dir_num =  __get_pgd(vaddr, pdt, jid, false);
	if ((dir_num < 0) && !((vaddr >= VEHVA_4K_START) &&
					(vaddr < VEHVA_4K_END))) {
		dir_num = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for vehva %lx",
				strerror(dir_num), vaddr);
		return dir_num;
	} else if ((dir_num < 0)) {
		dir_tsk = dir_num = 0;
	} else {
		if ((vaddr >= VEHVA_4K_START) &&
				(vaddr < VEHVA_4K_END))
			dir_tsk = 0;
		else
			dir_tsk = dir_num;
		node_pgd = &vnode->dmaatb.dir[dir_num];
		node_pte = vnode->dmaatb.entry[dir_num];
	}

	pgmod = ps_getpgsz(&((dmaatb_reg_t *)pdt)->dir[dir_tsk]);
	pgoff = pgentry(vaddr, pgmod);

	VEOS_DEBUG("%s VEHVA 0x%lx is mapped to pgoff %lx",
			pgmod_to_pgstr(pgmod), vaddr, pgoff);

	pgd = &((dmaatb_reg_t *)pdt)->dir[dir_tsk];
	pte = ((dmaatb_reg_t *)pdt)->entry[dir_tsk];

	if (!pg_isvalid(&pte[pgoff])) {
		VEOS_DEBUG("Invalid pte %ld associated with vemva %lx",
			pgoff, vaddr);
		dir_num = -EINVAL;
		goto out;
	}

	/* DMAATB use LCC. So bypass bit unsetting unnecessary. */
	pg_unsetro(&pte[pgoff]);
	pg_unsetido(&pte[pgoff]);
	pg_unsettype(&pte[pgoff]);
	pg_clearpfn(&pte[pgoff]);
	pg_invalid(&pte[pgoff]);
	pg_unsetprot(&pte[pgoff]);

	if (node_pgd) {
		pg_type = pg_gettype(&node_pte[pgoff]);
		if (pg_type == VE_ADDR_VEMAA) {
			VEOS_DEBUG("Decrementing pages ref count");
			pb = pg_getpb(&node_pte[pgoff], pgmod);
			vemaa = pbaddr(pb, pgmod);
			VEOS_DEBUG("vemaa = 0x%lx", vemaa);
			if (amm_put_page(vemaa)) {
				dir_num = -EINVAL;
				goto out;
			}
		}

		pg_unsetro(&node_pte[pgoff]);
		pg_unsetido(&node_pte[pgoff]);
		pg_invalid(&node_pte[pgoff]);
		pg_unsetprot(&node_pte[pgoff]);
		pg_unsettype(&node_pte[pgoff]);
		pg_clearpfn(&node_pte[pgoff]);

		if (!((vaddr >= VEHVA_4K_START) &&
					(vaddr < VEHVA_4K_END))) {
			hw_dma_map[dir_num].count--;
			if (!hw_dma_map[dir_num].count) {
				ps_clrdir(pgd);
				ps_invalid(pgd);
				ps_clrdir(node_pgd);
				ps_invalid(node_pgd);
			}
		}
	}
out:
	VEOS_TRACE("returned");
	return dir_num;
}

/**
 * @brief Realease the ATB directory.
 *
 * @param[in] atb reference to the page table(ATB).
 * @param[in] dir_num (ATB/DMAATB)directory number to release.
 */
void invalidate_pgd(atb_reg_t *atb, dir_t dir_num)
{
	int ent = 0;
	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;

	VEOS_TRACE("invoked");
	VEOS_TRACE("invalidate pgd %d for atb(%p)", dir_num, atb);

	pgd = &atb->dir[dir_num];
	pte = atb->entry[dir_num];

	if (ps_isvalid(pgd)) {
		for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
			/* Check if page entries is valid */
			if (pg_isvalid(&pte[ent]) ||
					pg_getpb(&pte[ent], PG_2M))
				return;
		}
	} else {
		VEOS_DEBUG("page directory %d is invalid", dir_num);
		return;
	}

	VEOS_DEBUG("Invalidating page directory %d", dir_num);
	ps_clrdir(pgd);
	ps_invalid(pgd);
	/* partial space directory */
	VEOS_TRACE("returned");
}

/**
 * @brief Replace the physical page number correponding to given
 *        VEMVA of a VE process.
 *
 * @param[in] vemva Virtual address of VE process.
 * @param[in] tsk Pointer to VE task struct.
 *
 * @return On sucess return new page number and negative of errno on failure.
 */
int64_t replace_page(vemva_t vemva, struct ve_task_struct *tsk)
{
	atb_reg_t *pdt = NULL;
	dir_t dir_num = -1;
	int64_t new_pg = 0;
	int pgmod_dir = 0, pgoff = 0;
	int64_t ret = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_page *new_ve_page = NULL;

	int i = 0;
	int mp_num = 0;

	pdt = &tsk->p_ve_mm->atb[0];
	dir_num = __get_pgd(vemva, pdt, -1, false);
	if (0 > dir_num) {
		VEOS_DEBUG("tsk:pid(%d) vemva 0x%lx not valid",
				tsk->pid, vemva);
		ret = -EINVAL;
		return ret;
	}
	pgmod_dir = ps_getpgsz(&pdt->dir[dir_num]);
	pgoff = pgentry(vemva, pgmod_dir);

	pdt = &tsk->p_ve_mm->atb[0];

	ret = __replace_page(&pdt->entry[dir_num][pgoff], tsk->p_ve_mm,
							tsk->numa_node);
	if (0 > ret) {
		VEOS_DEBUG("tsk:pid(%d) vemva 0x%lx not valid",
			   tsk->pid, vemva);
		return ret;
	}

	new_pg = ret;
	new_ve_page = VE_PAGE(vnode, new_pg);
	new_ve_page->owner = tsk->group_leader;

	for (i = 0; i < vnode->numa_count; i++) {
		if (vnode->partitioning_mode == 1) {
			pdt = &tsk->p_ve_mm->atb[i];
			if (i > 0) {
				/* Apply update of atb[0] by __replace_page() to atb[1]. */
				pg_clearpfn(&(pdt->entry[dir_num][pgoff]));
				pg_setpb(&(pdt->entry[dir_num][pgoff]), new_pg, PG_2M);
			}
			mp_num = (int)paddr2mpnum(pbaddr(new_pg, PG_2M),
						numa_sys_info.numa_mem_blk_sz,
						numa_sys_info.first_mem_node);
			if (i != mp_num)
				pg_setbypass(&(pdt->entry[dir_num][pgoff]));
			else
				pg_unsetbypass(&(pdt->entry[dir_num][pgoff]));
		}

	}
	if(0 == psm_sync_hw_regs(tsk, _ATB, true, -1, 1))
        {
                VEOS_DEBUG("Syncing ATB");
                if(-1 == veos_update_atb(tsk->core_set, &dir_num, 1, tsk))
                {
                        VEOS_ERROR("Updating ATB failed");
                        veos_abort("Syncing ATB registers failed");
                }
        }
	/* Reset the core_set as all the cores are restarted*/
        tsk->core_set = 0;

	return ret;
}

/**
* @brief Initialize partial space directory within the page table(ATB).
*
* @param[in] atb reference to the page table.
* @param[in] dir ATB directory number to be validate.
* @param[in] psnum partial space number whithin corrosponding ATB directory.
* @param[in] pgmod
*/
void validate_pgd(atb_reg_t *atb, dir_t dir, int psnum, int pgmod)
{
	__validate_pgd((void *)atb, dir, psnum, -1, pgmod);
	return;
}

/**
* @brief Initialize partial space directory within the page table(DMAATB).
*
* @param[in] dmaatb reference to the page table.
* @param[in] dir_num DMAATB directory number to be validate
* @param[in] psnum psnum partial space number i.e entry number within directory.
* @param[in] jid JID of VE process.
* @param[in] pgmod page mode.
*/
void validate_dmapgd(dmaatb_reg_t *dmaatb,
		dir_t dir_num, int psnum, int jid, int pgmod)
{
	__validate_pgd((void *)dmaatb, dir_num, psnum, jid, pgmod);
	return;
}

/**
* @brief This function returns the page size corresponding
*	to the flag provided by the user.
*
* @param[in] type specifying for which type page size to be calculate.
* @param[in] tsk pointer to VE task struct.
* @param[in] vaddr VE virtual address.
*
* @return on success returns page size and negative of errno on failure.
*/
int __veos_get_pgmode(uint8_t type, struct ve_task_struct *tsk, uint64_t vaddr)
{
	int ret = 0;
	dir_t dir_num = 0;
	uint64_t pgoff = 0;
	atb_entry_t *pte = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("invoked to get tsk:pid(%d) addr %lx with type %x",
			tsk->pid, vaddr, type);

	void *dt = (type == VE_ADDR_VEMVA) ? (void *)&tsk->p_ve_mm->atb[0] :
		(void *)&tsk->p_ve_mm->dmaatb;
	int jid = (type == VE_ADDR_VEMVA) ?  -1 : tsk->jid;

	dir_num = __get_pgd(vaddr, dt, jid, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for vemva %lx",
			strerror(-ret), vaddr);
		goto out;
	}

	ret = (type == VE_ADDR_VEMVA) ? ps_getpgsz(&((atb_reg_t *)dt)->
			dir[dir_num]) : ps_getpgsz(&((dmaatb_reg_t *)dt)->
				dir[dir_num]);
	pte = (0 > jid) ? ((atb_reg_t *)dt)->entry[dir_num] :
		((dmaatb_reg_t *)dt)->entry[dir_num];

	pgoff = pgentry(vaddr, ret);

	if (!pg_isvalid(&pte[pgoff])) {
		if ((0 > jid) && pg_getpb(&pte[pgoff], PG_2M)) {
			goto out;
		} else {
			VEOS_DEBUG("Invalid pte %ld associated with vemva %lx",
					pgoff, vaddr);
			ret = -EINVAL;
		}
	}

out:
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function returns the page size corresponding
*	to the flag provided by the user.
*
* @param[in] type specifying for which type page size to be calculate.
* @param[in] pid process identifier.
* @param[in] vaddr VE virtual address.
*
* @return on success returns page size and negative of errno on failure.
*/
int veos_get_pgmode(uint8_t type, pid_t pid, uint64_t vaddr)
{
	struct ve_task_struct *tsk = NULL;
	int ret = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("invoked to get tsk:pid(%d) addr %lx with type %x",
			pid, vaddr, type);

	/* Get ve task struct */
	if (type == VE_ADDR_PCI) {
		/* Added by NEC. Please update. */
		int pgsz;
		pgsz = veos_ived_get_pciatb_pgmode(pid);
		if (pgsz == PAGE_SIZE_2MB)
			return PG_2M; /* 2MB flag */
		else if (pgsz == PAGE_SIZE_64MB)
			return PG_HP; /* 64MB flag */
		else
			return -errno;
	}
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting tsk for pid %d",
				strerror(-ret), pid);
		return ret;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	ret = __veos_get_pgmode(type, tsk, vaddr);
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");

	put_ve_task_struct(tsk);
	VEOS_TRACE("exiting");
	return ret;
}

/**
* @brief This function will allocate new VE page.
*
* @param[in] pte reference to the page table.
* @param[in] mempolicy Memory policy for partitioning mode.
* @param[in] numa_node NUMA node number of the VE process requires memories
*	     is running on.
*
* @return on success return new page number and negative of errno on failure.
*/
pgno_t __replace_page(atb_entry_t *pte, struct ve_mm_struct *mm, int numa_node)
{
	int mempolicy = mm->mem_policy;
	ret_t ret = 0, shmrm = 0, found = 0;
	pgno_t old_pgno = 0, new_pgno = 0;
	ssize_t pgsz = 0;
	vemaa_t pb[2] = {0};
	struct shm *seg = NULL, *shm_ent = NULL;
	struct shm_map *shm_map_tmp = NULL, *shm_map_n = NULL;
	struct ve_page *old_ve_page = NULL, *new_ve_page = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	int mp_num = 0;
	struct mapping_desc *old_file_mem = NULL;
	struct file_desc *old_file_desc = NULL;
	struct mmap_desc *new_mmap_desc = NULL, *old_mmap_desc = NULL;
	struct mmap_mem *mmap_m = NULL;
	flag_t old_flag = 0;
	prot_t old_perm = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("replace VE page for pte %p", pte);

	old_pgno = pg_getpb(pte, PG_2M);
	if (PG_BUS == old_pgno) {
		VEOS_DEBUG("pte is mapped to PG_BUS page");
		return -1;
	}

	old_ve_page = VE_PAGE(vnode, old_pgno);
	pgsz = old_ve_page->pgsz;
	old_flag = old_ve_page->flag;
	old_perm = old_ve_page->perm;

	if (old_flag & MAP_VDSO) {
		VEOS_DEBUG("MAP_VDSO.");
		return -1;
	}

	ret = alloc_ve_pages(1, &new_pgno, pgsz_to_pgmod(pgsz),
			mempolicy, numa_node, NULL);
	if (0 > ret) {
		VEOS_TRACE("returned, Error (%s) in allocating VE Page",
				strerror(-ret));
		return ret;	
	}

	/*First clear page base bits*/
	pg_clearpfn(pte);

	/*Then update page base bits with new pgno*/
	pg_setpb(pte, new_pgno, PG_2M);

	pb[0] = pbaddr(new_pgno, PG_2M);
	pb[1] = 0;

	if (vnode->partitioning_mode == 1) {
		/*bypassbit setting*/
		mp_num = (int)paddr2mpnum(pb[0],
					numa_sys_info.numa_mem_blk_sz,
					numa_sys_info.first_mem_node);
		if (mp_num != 0)
			pg_setbypass(pte);
		else
			pg_unsetbypass(pte);
	}

	/*Increament ref count*/
	amm_get_page(pb);

	/*
	 * copy physical page before doing put page.
	 */
	ret = memcpy_petoe(pbaddr(old_pgno, PG_2M),
					pbaddr(new_pgno, PG_2M), pgsz);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in page copy from src %lx to dst %lx",
				strerror(-ret), old_pgno, new_pgno);
		goto error_memcpy;
	}

	new_ve_page = VE_PAGE(vnode, new_pgno);

	/* Set PG_PTRACE only to keep track of
	 * VE traced pages
	 */
	new_ve_page->perm = old_perm;
	new_ve_page->flag = old_flag;
	new_ve_page->flag |= PG_PTRACE;
	new_ve_page->private_data = NULL;
	new_ve_page->buddy_order = old_ve_page->buddy_order;

	if (!old_ve_page->private_data){
		goto no_private_data;
	} else if ((old_flag & PG_SHM) && !(old_flag & PG_PTRACE)) {
		new_ve_page->flag &= ~PG_SHM;
		/*
		 * Page belong to shared memory segment
		 */
		VEOS_DEBUG("Old VE page %ld of SHM", old_pgno);
		seg = old_ve_page->private_data;
		
		list_for_each_entry_safe(shm_map_tmp, shm_map_n, &(mm->shm_head), shm_list) {
			if (shm_map_tmp->shm_segment == seg) {
				VEOS_DEBUG("shm mapping is found in shm list");
				found = 1;
				break;
			}
		}
		if (found) {
			VEOS_DEBUG("delete shm_map from ve_mm_struct's shm list");
			list_del(&(shm_map_tmp->shm_list));
			free(shm_map_tmp);
			found = 0;
		}
		
		pthread_mutex_lock_unlock(&seg->shm_lock, LOCK,
				"Failed to acquire shm lock");
		seg->nattch--;
		if (!seg->nattch)
			shmrm = 1;
		pthread_mutex_lock_unlock(&seg->shm_lock, UNLOCK,
				"Failed to release shm lock");
		if (shmrm) {
			pthread_mutex_lock_unlock(&vnode->shm_node_lock,
					LOCK, "Failed to acquire node lock");
			list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
				if (shm_ent == seg) {
					VEOS_DEBUG("Shared memory segment(%p) for shmid(%d) found",
							shm_ent, shm_ent->shmid);
					found = 1;
					break;
				}
			}
			if (found) {
				if ((seg->ipc_stat.shm_perm.mode & SHM_DEST) && (seg->nattch == 0))
					amm_release_shm_segment(seg);
			}
			pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
					"Failed to release node shm lock");
		}
	} else if (FILE_DESC(old_flag, old_perm)) {
		/*copy data file_desc to mmap_desc*/
		VEOS_DEBUG("Old VE page %ld", old_pgno);
		new_mmap_desc = init_mmap_desc();
		if (!new_mmap_desc) {
			VEOS_DEBUG("Error init_mmap_desc in fdesc to mdesc");
			goto error_memcpy;
		}
		old_file_mem = (struct mapping_desc *)(old_ve_page->private_data);
		old_file_desc = (struct file_desc *)(old_file_mem->file_desc);
		pthread_mutex_lock_unlock(&old_file_desc->f_desc_lock, LOCK,
					"Failed to acquire file desc lock");
		new_mmap_desc->pgsz = old_file_desc->pgsz;
		pthread_mutex_lock_unlock(&old_file_desc->f_desc_lock, UNLOCK,
					"Failed to release file desc lock");
		new_mmap_desc->in_mem_pages = 1;
		new_mmap_desc->reference_count = 1;
		new_mmap_desc->sum_virt_pages = 1;
		new_mmap_desc->ns_pages = 1;
		new_ve_page->private_data = (void *)new_mmap_desc;
	} else if (MMAP_DESC_PRIVATE(old_flag, old_perm)) {
		/*Use existing structure mmap_mem and mmap_desc*/
		VEOS_DEBUG("Old VE page %ld", old_pgno);
		old_mmap_desc = (struct mmap_desc *)old_ve_page->private_data;
		old_mmap_desc->in_mem_pages += 1;
		old_mmap_desc->reference_count += 1;
		old_mmap_desc->ns_pages += 1;
		new_ve_page->private_data = (void *)old_mmap_desc;
	} else if (MMAP_DESC(old_flag, old_perm)) {
		/*copy data mmap_desc to mmap_desc*/
		VEOS_DEBUG("Old VE page %ld", old_pgno);
		new_mmap_desc = init_mmap_desc();
		if (!new_mmap_desc) {
			VEOS_DEBUG("Error init_mmap_desc in mdesc to mdesc");
			goto error_memcpy;
		}
		old_mmap_desc = (struct mmap_desc *)old_ve_page->private_data;
		pthread_mutex_lock_unlock(&old_mmap_desc->mmap_desc_lock, LOCK,
					"Failed to acquire mmap desc lock");
		new_mmap_desc->pgsz = old_mmap_desc->pgsz;
		new_mmap_desc->in_mem_pages = 1;
		new_mmap_desc->reference_count = 1;
		new_mmap_desc->ns_pages = 1;
		new_mmap_desc->sum_virt_pages = 1;
		pthread_mutex_lock_unlock(&old_mmap_desc->mmap_desc_lock, UNLOCK,
					"Failed to release file desc lock");
		new_ve_page->private_data = (void *)new_mmap_desc;
	}

	if (!(MMAP_DESC_PRIVATE(old_flag, old_perm)) && !(old_flag & PG_SHM)) {
		/*if use existing structure mmap_mem and mmap_desc,
		 * decrement old virt page and increment new virt page
		 * is needless*/
		/*increment new virt page*/
		mmap_m = init_mmap_mem();
		if(!mmap_m){
			goto error_init_mmem;
		}
		pthread_mutex_lock_unlock(&((struct mmap_desc *)(new_ve_page->
				private_data))->mmap_desc_lock, LOCK,
				"Failed to acquire mmap desc lock");
		mmap_m->mmap_descripter =
				(struct mmap_desc *)new_ve_page->private_data;
		list_add_tail(&(mmap_m->list_mmap_pages), &(mm->list_mmap_mem));
		mmap_m->virt_page += 1;
		pthread_mutex_lock_unlock(&((struct mmap_desc *)(new_ve_page->
				private_data))->mmap_desc_lock, UNLOCK,
				"Failed to release mmap desc lock");
		/*decrement old virt page*/
		ret = decrement_virt_page(old_ve_page, mm);
		if (ret < 0)
			goto error_dec_virt;
	}

no_private_data:
	/*Decrement ref count*/
	ret = amm_put_page(pbaddr(old_pgno, PG_2M));

	VEOS_TRACE("returned with new page %lx", new_pgno);
	return new_pgno;

error_dec_virt:
	list_del(&mmap_m->list_mmap_pages);
	free(mmap_m);
error_init_mmem:
	new_ve_page->private_data = NULL;
	if(new_mmap_desc){
		pthread_mutex_destroy(&new_mmap_desc->mmap_desc_lock);
		free(new_mmap_desc);
	}
error_memcpy:
	pg_clearpfn(pte);
	pg_setpb(pte, old_pgno, PG_2M);
	if (amm_put_page(pb[0]))
		VEOS_DEBUG("Error while freeing new page 0x%lx", new_pgno);

	if (vnode->partitioning_mode == 1) {
		mp_num = (int)paddr2mpnum(pbaddr(old_pgno, PG_2M),
				numa_sys_info.numa_mem_blk_sz,
				numa_sys_info.first_mem_node);
		if (mp_num != 0)
			pg_setbypass(pte);
		else
			pg_unsetbypass(pte);
	}
	return ret;
}
