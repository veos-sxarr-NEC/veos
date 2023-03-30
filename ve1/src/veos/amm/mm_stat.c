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
 * @file mm_stat.c
 * @brief VE1 dependent part of command handlers
 *
 * @internal
 * @author AMM
 */
#include <stdlib.h>
#include <ve_hw.h>
#include <errno.h>

#include <veos.h>

#include <veos_arch_defs.h>

#include <ve_memory.h>
#include <ve_mem.h>

#include "ve_mem_ve1.h"
#include "ve_memory_ve1.h"

int ve1_amm_get_VEHVA_swappable_size(veos_dmaatb_reg_t *reg,
				unsigned long *swappable_size_p)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ve1_dmaatb_reg_t *dmaatb = &((ve1_veos_dmaatb_reg_t *)reg)->dmaatb_reg;
	size_t tmp_swapped_size = 0;

	for (int dir = vnode->nr_avail_cores; dir < VE1_DMAATB_DIR_NUM; ++dir) {
		VEOS_DEBUG("DIR[%d]: 0x%lx", dir, dmaatb->dir[dir].data);
		for (int ent = 0; ent < VE1_DMAATB_ENTRY_MAX_SIZE; ++ent) {
			if (pg_gettype(&dmaatb->entry[dir][ent])
				!= VE_ADDR_VEMAA)
				continue;
			int pgno = pg_getpb(&dmaatb->entry[dir][ent], PG_2M);

			if ((pgno == PG_BUS) || (pgno == 0))
				continue;

			int ret = is_ve_page_swappable(pgno, vnode);
			if (ret != 0)
				continue;

			VEOS_DEBUG("ENT[%d][%d] : 0x%lx ", dir, ent,
					VE_PAGE(vnode, pgno)->pgsz);

			int refcount;
			if (VE_PAGE(vnode, pgno)->swapped_info != NULL) {
				refcount = VE_PAGE(vnode, pgno)->ref_count +
					VE_PAGE(vnode, pgno)->swapped_info->ref_cnt;
			} else {
				refcount = VE_PAGE(vnode, pgno)->ref_count;
			}
			if (refcount != 0) {
				tmp_swapped_size +=
					VE_PAGE(vnode, pgno)->pgsz / refcount;
				refcount = 0;
			}
		}
	}
	*swappable_size_p = tmp_swapped_size;
	VEOS_DEBUG("swappable size: %lu", *swappable_size_p);
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_get_dma_space_swappable_size, ve1_amm_get_VEHVA_swappable_size)
