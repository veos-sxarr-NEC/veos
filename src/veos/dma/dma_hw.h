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
 * @file dma_hw.h
 * @brief declaration of functions in dma_hw.c
 */
#ifndef VE_VEOS_DMA_HW_H
#define VE_VEOS_DMA_HW_H

#include <veos_arch_defs.h>

#include <libved.h>
struct ve_dma_engine_usage;

void ve_dma_hw_start(vedl_common_reg_handle *);
void ve_dma_hw_post_stop(vedl_common_reg_handle *);
int ve_dma_hw_clear_all_dma(vedl_handle *, vedl_common_reg_handle *);
int ve_dma_hw_engine_is_halt(vedl_handle *, vedl_common_reg_handle *);
#endif
