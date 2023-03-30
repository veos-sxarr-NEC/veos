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
 * @file ve_mem_ve1.h
 * @brieaf VE1-dependent part of header for memory management core
 *
 * @internal
 * @author AMM
 */
#ifndef VEOS_VE1_AMM_VE_MEM_VE1_H
#define VEOS_VE1_AMM_VE_MEM_VE1_H

#include <ve_hw.h>
#include <ve_drv.h>

#define SYSCOM_ADD VEDRV_VE1_PCI_BAR2_SCR_OFFSET
#define VE1_CORE_SYS_OFFSET(c) (VEDRV_VE1_PCI_BAR2_CREG_SIZE * (c) + \
		VEDRV_VE1_PCI_BAR2_SREG_OFFSET)

#define VE1_UDMA_OFFSET_OF_DMACTL(i) (offsetof(ve1_core_system_reg_t, dmactl[(i)]))
#define VE1_UDMA_OFFSET_OF_DMADESC(i) (offsetof(ve1_core_system_reg_t, dmades[(i)]))

struct ve1_hw_dma_map {
	uint64_t count;
};
struct ve1_veos_dmaatb_reg {
	ve1_dmaatb_reg_t dmaatb_reg;
};
typedef struct ve1_veos_dmaatb_reg ve1_veos_dmaatb_reg_t;

dir_t ve1_amm__get_dma_pgd(vehva_t, int, bool);

int ve1_amm_sync_node_dmaatb_dir(vehva_t, struct ve_mm_struct *, dir_t, jid_t);
#endif
