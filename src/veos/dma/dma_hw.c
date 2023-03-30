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
 * @file dma_hw.c
 * @brief functions to control DMA engine execution
 */
#include <unistd.h>
#include <errno.h>
#include <libved.h>
#include <stddef.h>
#include "dma_hw.h"
#include "dma_log.h"

/**
 * @brief Start DMA transfer, with permission bit enabled.
 *
 * @param[in,out] creg pointer to node control register area
 */
void ve_dma_hw_start(vedl_common_reg_handle *creg)
{
	(*_veos_arch_ops->arch_dma_hw_start)(creg);
}

/**
 * @brief Post DMA stop request, with halt bit enabled.
 *
 *        only write the halt bit, returning without waiting for stop.
 *
 * @param[in,out] creg pointer to node control register area
 */
void ve_dma_hw_post_stop(vedl_common_reg_handle *creg)
{
	(*_veos_arch_ops->arch_dma_hw_post_stop)(creg);
}

int ve_dma_hw_clear_all_dma(vedl_handle *h, vedl_common_reg_handle *creg)
{
	return (*_veos_arch_ops->arch_dma_hw_clear_all_dma)(h, creg);
}
int ve_dma_hw_engine_is_halt(vedl_handle *h, vedl_common_reg_handle *creg)
{
	return (*_veos_arch_ops->arch_dma_hw_engine_is_halt)(h, creg);
}
