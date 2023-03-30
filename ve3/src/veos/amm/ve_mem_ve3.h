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
 * @file ve_mem_ve3.h
 * @brieaf VE3-dependent part of header for memory management core
 *
 * @internal
 * @author AMM
 */
#ifndef VEOS_VE3_AMM_VE_MEM_VE3_H
#define VEOS_VE3_AMM_VE_MEM_VE3_H

#include <ve_hw.h>
#include <ve_drv.h>

#define SYSCOM_PRE_ADD VEDRV_VE3_PCI_BAR2_SCR_OFFSET
#define SYSCOM_NONPRE_ADD VEDRV_VE3_PCI_BAR4_SCR_OFFSET

#define VE3_UDMA_OFFSET_OF_DMACTL(c, i) \
	(offsetof(ve3_system_common_reg_nonpre_t, DMACTL_PACK[c].DMACTL[(i)]))
#define VE3_UDMA_OFFSET_OF_DMADESC(c, i) \
	(offsetof(ve3_system_common_reg_nonpre_t, DMADES[2 * (c) + (i)]))

struct ve3_hw_dma_map {
	uint64_t count;
};
struct ve3_veos_dmaatb_reg {
	ve3_dmaatb_reg_t dmaatb_reg;
};
typedef struct ve3_veos_dmaatb_reg ve3_veos_dmaatb_reg_t;

dir_t ve3_amm__get_dma_pgd(vehva_t, int, bool);

int ve3_amm_sync_node_dmaatb_dir(vehva_t, struct ve_mm_struct *, dir_t, jid_t);
#endif
