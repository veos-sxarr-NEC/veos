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
 * @brief private data structure in VE3-dependent part of DMA API header
 */
#ifndef VEOS_VE3_DMA_VE3_PRIVATE_H
#define VEOS_VE3_DMA_VE3_PRIVATE_H

#include "ve3dma_hw.h"

struct ve3_dma_engine_usage {
	int desc_used_begin;
	int desc_num_used;
	struct ve_dma_reqlist_entry *req_entry[VE3_DMA_NUM_DESC];
};

#define VE3_DMA_HDL_USAGE(hdl_) ((struct ve3_dma_engine_usage *)hdl_->dma_engine_usage)
#endif
