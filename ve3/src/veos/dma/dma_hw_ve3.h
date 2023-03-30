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
 * @file dma_hw_ve3.h
 * @brief VE3-dependent part of dma_hw.c
 */
#ifndef VEOS_VE3_DMA_HW_VE3_H
#define VEOS_VE3_DMA_HW_VE3_H
int ve3_dma_hw_get_readptr(vedl_handle *, vedl_common_reg_handle *);
uint64_t ve3_dma_hw_desc_status(vedl_handle *, vedl_common_reg_handle *, int);
void ve3_dma_hw_nullify_dma(vedl_handle *, vedl_common_reg_handle *, int);
int ve3_dma_hw_post_dma(vedl_handle *, vedl_common_reg_handle *, int, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t, int, int, int);
uint64_t ve3_dma_hw_get_ctlword1(vedl_handle *, vedl_common_reg_handle *);
uint32_t ve3_dma_hw_get_ctlstatus(vedl_handle *, vedl_common_reg_handle *);
int ve3_dma_hw_set_readptr(vedl_handle *, vedl_common_reg_handle *, int);
#endif
