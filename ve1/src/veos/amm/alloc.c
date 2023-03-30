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
 * @file alloc.h
 * @brief Allocation and deallocation of VE1-dependent PCIATB and DMAATB
 *
 * @internal
 * @author AMM
 */
#include <stdlib.h>
#include <string.h>
#include <ve_hw.h>
#include <errno.h>

#include <veos_arch_defs.h>

#include "ve_mem_ve1.h"

veos_dmaatb_reg_t *ve1_alloc_veos_dmaatb_reg(void)
{
	return calloc(1, sizeof(ve1_veos_dmaatb_reg_t));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_alloc_veos_dma_pgtable, ve1_alloc_veos_dmaatb_reg)


int ve1_alloc_veos_pciatb_dmaatb(veos_pciatb_entry_t **pp,
				veos_dmaatb_reg_t **dp)
{
	*pp = calloc(VE1_PCIATB_VLD_SIZE, sizeof(ve1_pciatb_entry_t));
	if (*pp == NULL) {
		*dp = NULL;
		goto fail_alloc_pciatb;
	}
	*dp = calloc(1, sizeof(ve1_veos_dmaatb_reg_t));
	if (*dp == NULL)
		goto fail_alloc_dmaatb;
	return 0;

fail_alloc_dmaatb:
	free(*pp);
	*pp = NULL;
fail_alloc_pciatb:
	return -ENOMEM;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_alloc_veos_pci_dma_pgtables, ve1_alloc_veos_pciatb_dmaatb)

void ve1_free_veos_pciatb_dmaatb(veos_pciatb_entry_t *p, veos_dmaatb_reg_t *d)
{
	free(p);
	free(d);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_free_veos_pci_dma_pgtables, ve1_free_veos_pciatb_dmaatb)

veos_dmaatb_reg_t *ve1_amm_dup_veos_dmaatb_reg(const veos_dmaatb_reg_t *from)
{
	veos_dmaatb_reg_t *to = ve1_alloc_veos_dmaatb_reg();
	if (to == NULL)
		return to;
	memcpy(to, from, sizeof(ve1_veos_dmaatb_reg_t));
	return to;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_dup_veos_dma_pgtable, ve1_amm_dup_veos_dmaatb_reg)

void ve1_amm_copy_dmaatb_reg(veos_dmaatb_reg_t *dst,
				const veos_dmaatb_reg_t *src)
{
	ve1_dmaatb_reg_t *to = &((ve1_veos_dmaatb_reg_t *)dst)->dmaatb_reg;
	const ve1_dmaatb_reg_t *from = &((const ve1_veos_dmaatb_reg_t *)src)->dmaatb_reg;
	memcpy(to, from, sizeof(ve1_dmaatb_reg_t));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_copy_veos_dma_pgtable, ve1_amm_copy_dmaatb_reg)
