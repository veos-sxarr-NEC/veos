/*
 * Copyright (C) 2020 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file pgtbl.c
 * @brief VE3 dependent part of page table structure
 *
 */
#include <libved.h>
#include <ve_hw.h>

#include <veos.h>
#include <mm_common.h>
#include <vehva_mgmt.h>

#include <veos_arch_defs.h>

#include <ve_memory.h>

#include <veos_ve3.h>
#include "ve_mem_ve3.h"
#include "vehva_mgmt_ve3.h"
#include "ve_memory_ve3.h"

extern int opt_rordering;

static void ve3__dump_dmaatb(FILE *fp, const ve3_dmaatb_reg_t *dmaatb)
{
	int dir_cntr = 0;
	int entry_cntr = 0;

#ifdef DEBUG
	fprintf(fp, "\n-------------------------------------------------------\n");
	fprintf(fp, "DMAATBDIRNO    PSNUM\n");
	fprintf(fp, "\n-------------------------------------------------------\n");
#endif

	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < VE3_DMAATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(dmaatb->dir[dir_cntr]))) {
#ifdef DEBUG
			fprintf(fd, "%5d%10lx\n", dir_cntr,
				dmaatb->dir[dir_cntr].data & 0xFFFFFFF00000);
#endif
			VEOS_DEBUG("%d : Partial Space Offset %p JID: %ld",
				dir_cntr, (void *)dmaatb->dir[dir_cntr].data,
				ps_getjid(&(dmaatb->dir[dir_cntr])));
			VEOS_DEBUG("pgsize of dir[%d] is %ld",
				dir_cntr, ps_getpgsz(&(dmaatb->dir[dir_cntr])));

			for (entry_cntr = 0;
				entry_cntr < VE3_DMAATB_ENTRY_MAX_SIZE;
				entry_cntr++) {
#ifdef DEBUG
				fprintf(fd, "page_no \n%d\n", entry_cntr);
#endif
				/* Check if page entries is valid */
				if (pg_isvalid(&(dmaatb->entry[dir_cntr][entry_cntr]))) {
					VEOS_DEBUG("%d : %d :PB Address %p",
						dir_cntr, entry_cntr,
						(void *)dmaatb->entry[dir_cntr][entry_cntr].data);
				}
			} /* end entry loop */
		} else {
			VEOS_TRACE("DMAATB DIR:%d Invalid", dir_cntr);
		}
	}
}

void ve3_amm__dump_dmaatb(FILE *fp, const veos_dmaatb_reg_t *ptbl)
{
	const ve3_veos_dmaatb_reg_t *ptr = (const ve3_veos_dmaatb_reg_t *)ptbl;
	ve3__dump_dmaatb(fp, &ptr->dmaatb_reg);
	
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__dump_dmaatb, ve3_amm__dump_dmaatb)

static void ve3__validate_dma_pgd(ve3_dmaatb_reg_t *dmaatb, dir_t dir,
				int psnum, int jid, int pgmod)
{
	ve3_dmaatb_dir_t *pgd = &dmaatb->dir[dir];
	ve3_dmaatb_entry_t *pte = dmaatb->entry[dir];

	VEOS_TRACE("invoked");
	VEOS_DEBUG("pgmod is %d, psnum is %d, jid is %d", pgmod, psnum, jid);

	/* partial space directory */
	ps_setpsnum(pgd, psnum, pgmod);
	ps_setjid(pgd, jid);
	ps_setpgsz(pgd, pgmod);
	ps_valid(pgd);

	/*For dmaatb only*/
	if (pgmod != PG_4K) {
		/*Will be used in case of DMAATB only*/
		ve3_dmaatb_dir_t *pgd_node = NULL;
		/*Will be used in case of DMAATB only*/
		ve3_dmaatb_entry_t *pte_node = NULL;
		struct ve_node_struct *vnode = VE_NODE(0);

		/* partial space directory */
		pgd_node = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg.dir[dir];
		pte_node = ((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg.entry[dir];

		ps_setpsnum(pgd_node, psnum, pgmod);
		ps_setjid(pgd_node, jid);
		ps_setpgsz(pgd_node, pgmod);
		ps_valid(pgd_node);

		for (int ps_entry = 0; ps_entry < VE3_DMAATB_ENTRY_MAX_SIZE;
			ps_entry++)
			pg_invalid(&pte_node[ps_entry]);
	}

                /* partial space page table (PSPT) */
                for (int ps_entry = 0; ps_entry <
                                VE3_ATB_ENTRY_MAX_SIZE; ps_entry++)
                        pg_invalid(&pte[ps_entry]);
}

void ve3_amm__validate_dma_pgd(veos_dmaatb_reg_t *dmaatb, dir_t dir,
				int psnum, int jid, int pgmod)
{
	ve3_veos_dmaatb_reg_t *ptr = (ve3_veos_dmaatb_reg_t *)dmaatb;
	ve3__validate_dma_pgd(&ptr->dmaatb_reg, dir, psnum, jid, pgmod);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__validate_dma_pgd, ve3_amm__validate_dma_pgd)

dir_t ve3_amm__get_dma_pgd(vehva_t vaddr, int jid, bool inval)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int noc = vnode->nr_avail_cores;
	dir_t ps_entry = vaddr < VEHVA_DIR0_END ? 0 : noc;
	int atb_num = vaddr < VEHVA_DIR0_END ? noc : VE3_DMAATB_DIR_NUM;
	ve3_dmaatb_dir_t *atbp = &((ve3_veos_dmaatb_reg_t *)vnode->dmaatb)->dmaatb_reg.dir[ps_entry];
	int unused = -1;

	VEOS_DEBUG("vehva(0x%lx), directory table (%p)", vaddr, atbp);
	VEOS_TRACE("invoked");
	VEOS_TRACE("iterating page table");
	for (; ps_entry < atb_num; ++ps_entry) {
		if (ps_isvalid(atbp)) {
			VEOS_TRACE("pgd[%p] is valid", atbp);
			if (ps_getjid(atbp) != jid) {
				++atbp;
				continue;
			}
			/* JID matches to that of page directory */
			int pgmod = ps_getpgsz(atbp);
			int psnum = psnum(vaddr, pgmod);
			/* check psnum */
			int psnum_dir = ps_getps(atbp, pgmod);
			if (psnum_dir == psnum) {
				VEOS_TRACE("returned %d\n", ps_entry);
				return ps_entry;
			}
		} else if (inval) {
			if (0 > unused)
				unused = ps_entry;
		}
		++atbp;
	}
	VEOS_TRACE("DMA page table iteration ends");
	VEOS_TRACE("returned %d", unused);
	return unused;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__get_dma_pgd, ve3_amm__get_dma_pgd)

void ve3_amm_invalidate_dmaatb(veos_dmaatb_reg_t *veos_dmaatb)
{
	dir_t dirno = 0;
	ent_t entry = 0;
	ve3_dmaatb_reg_t *dmaatb = &((ve3_veos_dmaatb_reg_t *)veos_dmaatb)->dmaatb_reg;
	VEOS_TRACE("invoked");
	VEOS_DEBUG("dmaatb(%p)", dmaatb);
        /*
         * Initialize the DMAATB structure for new allocation
         */
        memset(dmaatb, 0, sizeof(ve3_dmaatb_reg_t));

        VEOS_TRACE("iterate dma page tables");
        for (dirno = 0; dirno < VE3_DMAATB_DIR_NUM; dirno++) {
                ps_invalid(&(dmaatb->dir[dirno]));
                for (entry = 0; entry < VE3_DMAATB_ENTRY_MAX_SIZE; entry++) {
                        pg_invalid(&(dmaatb->entry[dirno][entry]));
                        VEOS_TRACE("dma pgd[%d] and value(0x%lx)",
                                dirno, dmaatb->dir[dirno].data);
                        VEOS_TRACE("dma pte[%d][%d] and value(%lx)",
                                dirno, entry,
                                dmaatb->entry[dirno][entry].data);
                }
        }
        VEOS_TRACE("iteration ends");
        VEOS_TRACE("returned");
        return;

}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_invalidate_dmaatb, ve3_amm_invalidate_dmaatb)

dir_t ve3_amm_validate_vehva(vehva_t vaddr, int rw, pgno_t pgno,
		struct ve_mm_struct *mm, int pgmod, uint8_t type,
		jid_t jid, uint16_t vehva_flag,
		int numa_node)
{
	ret_t ret = 0;
	uint64_t  psoff = 0;
	uint64_t pgoff = 0;
	dir_t dir_num = -1;

	ve3_dmaatb_dir_t *pgd = NULL;
	ve3_dmaatb_entry_t *pte = NULL;

	VEOS_TRACE("invoked");

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
		dir_num =  ve3_amm__get_dma_pgd(vaddr, jid, true);
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
	ve3_veos_dmaatb_reg_t *pdt= (ve3_veos_dmaatb_reg_t *)mm->dmaatb;
	
	pgd = &pdt->dmaatb_reg.dir[dir_num];
	pte = pdt->dmaatb_reg.entry[dir_num];

	if (!ps_isvalid(pgd)) {
		VEOS_DEBUG("pgd[%d] is invalid", dir_num);
		ve3__validate_dma_pgd(&pdt->dmaatb_reg,
					dir_num, psoff, jid, pgmod);
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
					"with fixed map", pgoff, vaddr);
			ret =  -ENOMEM;
			goto error;
		}
	}

	VEOS_DEBUG("validate dma pte[%ld] with pgnum %ld", pgoff, pgno);
	pg_setpb(&pte[pgoff], pgno, pgmod);
	if (!((vaddr >= VEHVA_4K_START) && (vaddr < VEHVA_4K_END)))
		VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir_num].count++;
	VEOS_DEBUG("dma map pgd[%d] count is %lu",
		dir_num, VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir_num].count);

	pg_valid(&pte[pgoff]);

	/* DMAATB use LLC. So bypass bit setting unnecessary. */
	if (rw == 0)
		pg_setprot(&pte[pgoff]);
	else if (-1 == rw)
		pg_invalid(&pte[pgoff]);

	if (opt_rordering)
	  pg_setro(&pte[pgoff]);
	pg_setido(&pte[pgoff]);
	pg_settype(&pte[pgoff], type);

	dir_num = ve3_amm_sync_node_dmaatb_dir(vaddr, mm, dir_num, jid);
	if (0 > dir_num) {
		VEOS_DEBUG("no page directory for vehva %lx", vaddr);
		ret = dir_num;
		goto error;
	}
	ret = dir_num;

error:
	VEOS_TRACE("returned");
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_validate_vehva, ve3_amm_validate_vehva)

dir_t ve3_amm_invalidate_vehva(vehva_t vaddr, struct ve_mm_struct *mm,
				jid_t jid)
{
        uint64_t pgoff = 0;
        pgno_t pb = 0;
        int pg_type = 0;
        vemaa_t vemaa = 0;
        dir_t dir_tsk = 0, dir_num = 0;
        int pgmod = 0;
        ve3_dmaatb_dir_t *pgd = NULL, *node_pgd = NULL;
        ve3_dmaatb_entry_t *pte, *node_pte = NULL;
        struct ve_node_struct *vnode = VE_NODE(0);
	ve3_veos_dmaatb_reg_t *node_dmaatb = (ve3_veos_dmaatb_reg_t *)vnode->dmaatb;
        int ret;
        
        VEOS_TRACE("invoked");
        VEOS_TRACE("vehva %lx for mm %p",
                        vaddr, mm);

        if (jid < 0) {
                VEOS_ERROR("Invalid jid %d", jid);
                dir_num = -EINVAL;
                return dir_num;
        }

        dir_num =  ve3_amm__get_dma_pgd(vaddr, jid, false);
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
                node_pgd = &node_dmaatb->dmaatb_reg.dir[dir_num];
                node_pte = node_dmaatb->dmaatb_reg.entry[dir_num];
        }

	ve3_veos_dmaatb_reg_t *tsk_dmaatb = (ve3_veos_dmaatb_reg_t *)mm->dmaatb;
	pgmod = ps_getpgsz(&((ve3_veos_dmaatb_reg_t *)mm->dmaatb)->dmaatb_reg.dir[dir_tsk]);
        pgoff = pgentry(vaddr, pgmod);

        VEOS_DEBUG("%s VEHVA 0x%lx is mapped to pgoff %lx, pgmod is %d, dir_tsk is %d",
                        pgmod_to_pgstr(pgmod), vaddr, pgoff, pgmod, dir_tsk);

        pgd = &tsk_dmaatb->dmaatb_reg.dir[dir_tsk];
        pte = tsk_dmaatb->dmaatb_reg.entry[dir_tsk];

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
						ret = amm_put_page(vemaa);
                        if ((ret < 0) && (ret != -EBUSY)) {
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
                        VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir_num].count--;
                        if (!VE3_NODE_ARCH_DEP(VE_NODE(0))->hw_dma_map[dir_num].count) {
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
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_invalidate_vehva, ve3_amm_invalidate_vehva)

int ve3_amm_veos_get_pgmode_vehva(struct ve_task_struct *tsk, uint64_t vaddr)
{
	int ret = 0;
	dir_t dir_num = 0;
	uint64_t pgoff = 0;
	ve3_dmaatb_entry_t *pte = NULL;

	ve3_veos_dmaatb_reg_t *dt = (ve3_veos_dmaatb_reg_t *)tsk->p_ve_mm->dmaatb;
	int jid = tsk->jid;

	VEOS_TRACE("invoked");

	dir_num = __get_pgd(vaddr, dt, jid, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for vehva %lx",
			strerror(-ret), vaddr);
		goto out;
	}

	ret = ps_getpgsz(&dt->dmaatb_reg.dir[dir_num]);
	pte = dt->dmaatb_reg.entry[dir_num];

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
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_veos_get_pgmode_vehva, ve3_amm_veos_get_pgmode_vehva)

