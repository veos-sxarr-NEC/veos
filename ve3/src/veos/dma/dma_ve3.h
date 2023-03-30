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
 * @file dma_ve3.h
 * @brief VE3-dependent part of DMA API header
 */
#ifndef VEOS_VE3_DMA_VE3_H
#define VEOS_VE3_DMA_VE3_H
/* VE3 dependent adddress space type */
#define VE3_DMA_VERAA_NON_PREFETCHABLE (4) /*!< VERAA (physical address space on VE registers) in BAR4, non-prefetchable, area */
#define VE3_DMA_VERAA_PREFETCHABLE (6) /*!< VERAA in BAR23, prefetchable, area */
#endif
