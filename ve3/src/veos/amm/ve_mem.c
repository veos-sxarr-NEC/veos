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
 * @file ve_mem.c
 * @brief VE3 dependent part of updating page table
 *
 */
#include <libved.h>
#include <ve_hw.h>
#include <libved_ve3.h>

#include <veos.h>
#include <mm_common.h>

#include <veos_arch_defs.h>

#include <ve_memory.h>

int ve3_amm_update_all_dmaatb(const veos_dmaatb_reg_t *dmapgtbl)
{
	const ve3_dmaatb_reg_t *reg = (const ve3_dmaatb_reg_t *)dmapgtbl;
	return vedl_ve3_update_dmaatb_all(VE_NODE_CNT_REG(0), reg);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_update_dma_all_pgtable, ve3_amm_update_all_dmaatb)

int ve3_amm_update_atb_dir(int core, const atb_reg_t *pgtbl, int dir)
{
	ve3_atb_reg_t *reg = (ve3_atb_reg_t *)pgtbl;
	/*
	 * the current implementation depends on architecture-independent
	 * page table structure same as VE1 and VE3 ATB
	 */
	return vedl_ve3_update_atb_dir(VE_CORE_SYS_REG(0, core), reg, dir);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_update_pg_dir, ve3_amm_update_atb_dir)

void ve3_free_veos_vehva_header_bmap(vehva_header_t v)
{
	free(v.bmap_4k);
	free(v.bmap_64m);
	free(v.bmap_2m);
	free(v.bmap_256m);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_free_veos_vehva_header_bmap, ve3_free_veos_vehva_header_bmap)

void ve3_destroy_veos_vehva_header_vehva_lock(vehva_header_t v)
{
	pthread_mutex_destroy(&v.vehva_4k_lock);
	pthread_mutex_destroy(&v.vehva_2m_lock);
	pthread_mutex_destroy(&v.vehva_64m_lock);
	pthread_mutex_destroy(&v.vehva_256m_lock);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_destroy_veos_vehva_header_vehva_lock, ve3_destroy_veos_vehva_header_vehva_lock)

