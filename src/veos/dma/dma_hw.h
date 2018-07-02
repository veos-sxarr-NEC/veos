/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file dma_hw.h
 * @brief declaration of functions in dma_hw.c
 */
#ifndef VE_VEOS_DMA_HW_H
#define VE_VEOS_DMA_HW_H

#include <libved.h>

int ve_dma_hw_get_readptr(vedl_handle *, system_common_reg_t *);
uint64_t ve_dma_hw_get_ctlword1(vedl_handle *, system_common_reg_t *);
uint32_t ve_dma_hw_get_ctlstatus(vedl_handle *, system_common_reg_t *);
int ve_dma_hw_post_dma(vedl_handle *, system_common_reg_t *, int, uint64_t,
		       uint64_t, uint64_t, uint64_t, uint32_t, int);
void ve_dma_hw_start(vedl_handle *, system_common_reg_t *);
void ve_dma_hw_post_stop(vedl_handle *, system_common_reg_t *);
uint64_t ve_dma_hw_desc_status(vedl_handle *, system_common_reg_t *, int);
void ve_dma_hw_nullify_dma(vedl_handle *, system_common_reg_t *, int);
int ve_dma_hw_clear_dma(vedl_handle *, system_common_reg_t *, int);
int ve_dma_hw_set_readptr(vedl_handle *, system_common_reg_t *, int);
#endif
