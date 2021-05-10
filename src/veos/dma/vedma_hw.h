/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file vedma_hw.h
 * @brief Definitions of parameters for DMA engine
 */
#ifndef VE_VEOS_VEDMA_HW_H
#define VE_VEOS_VEDMA_HW_H

/* DMA engine control register */
#define VE_DMA_OFFSET_OF_DMACTL (offsetof(system_common_reg_t, dmactl))
#define VE_DMA_OFFSET_OF_WORD_READPTR (VE_DMA_OFFSET_OF_DMACTL + 8)
/* word 0 */
#define VE_DMA_CTL_STATUS_MASK (3)
#define VE_DMA_CTL_STATUS_HALT (2)
#define VE_DMA_CTL_PERM_START (1)

/* word 1 */
#define VE_DMA_CTL_EXCEPTION_MASK (1UL << 63)
#define VE_DMA_CTL_READ_PTR_MASK (0x7f)

/* DMA descriptor */
#define VE_DMA_OFFSET_OF_DMADESC(i) (offsetof(system_common_reg_t, dmadesc[(i)]))
/* word 0 */
#define VE_DMA_DESC_EXCEPTION_MASK (0xffffUL << 48)
#define VE_DMA_DESC_STATUS_MASK (0xfUL)
#define VE_DMA_DESC_STATUS_STARTED (8UL)
#define VE_DMA_DESC_STATUS_EARLY (4UL)
#define VE_DMA_DESC_STATUS_COMPLETED (2UL)
#define VE_DMA_DESC_STATUS_PREPARED (1UL)

/* word 1 */
#define VE_DMA_DESC_ADDR_VEMAA (6UL)
#define VE_DMA_DESC_ADDR_VERAA (4UL)
#define VE_DMA_DESC_ADDR_VHSAA (2UL)
#define VE_DMA_DESC_ADDR_SRC(type) (((uint64_t)(type)) << 40)
#define VE_DMA_DESC_ADDR_DST(type) (((uint64_t)(type)) << 36)

#define VE_DMA_DESC_LEN_MAX (64 * 1024 * 1024)
#define VE_DMA_DESC_REQUEST_ALIGN (8)

#define VE_DMA_DESC_CTL_MASK (0xfUL << 32)
#define VE_DMA_DESC_CTL_SYNC (8UL << 32)
#define VE_DMA_DESC_CTL_INTR_ERR (4UL << 32)
#define VE_DMA_DESC_CTL_INTR_EARLY (2UL << 32)
#define VE_DMA_DESC_CTL_INTR_COMPLETION (1UL << 32)

#define VE_DMA_DESC_CTL_PCI_RO (4UL << 44)
#define VE_DMA_DESC_CTL_PCI_IDO (2UL << 44)

#define VE_DMA_NUM_DESC (128)

#endif
