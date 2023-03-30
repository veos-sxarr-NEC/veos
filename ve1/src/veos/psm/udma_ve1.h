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
 * @file udma_ve1.h
 * @brief user DMA resource for VE1
 */
#ifndef VEOS_VE1_PSM_UDMA_VE1_H
#define VEOS_VE1_PSM_UDMA_VE1_H
#include <libved.h>
#include <ve_hw.h>

struct ve1_udma {
	ve1_dma_desc_t dmades[2][VE1_DMA_DSCR_ENTRY_SIZE];
	ve1_dma_control_t dmactl[2];
};

static inline struct ve1_udma *TO_VE1_UDMA(struct ve_udma *p)
{
	return (struct ve1_udma *)p;
}

#endif
