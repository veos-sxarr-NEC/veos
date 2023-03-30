/**
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
 * @file udma.c
 * @brief user DMA resource for VE1
 */
#include <stdlib.h>

#include <veos_arch_defs.h>

#include "task_mgmt.h"

#include "udma_ve1.h"

void ve1_psm_clear_udma_context(struct ve_udma *p)
{
	struct ve1_udma *udma = TO_VE1_UDMA(p);
	memset(udma, 0, sizeof(*udma));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_clear_udma_context, ve1_psm_clear_udma_context)

struct ve_udma *ve1_psm_alloc_udma_context(void)
{
	struct ve1_udma *udma = calloc(1, sizeof(*udma));
	return (struct ve_udma *)udma;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_alloc_udma_context, ve1_psm_alloc_udma_context)

void ve1_psm_free_udma_context(struct ve_udma *p)
{
	free(p);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_free_udma_context, ve1_psm_free_udma_context)
