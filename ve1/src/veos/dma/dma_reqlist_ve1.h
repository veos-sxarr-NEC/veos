/*
 * Copyright (C) 2017-2019 NEC Corporation
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
 * @file dma_reqlist_ve1.h
 * @brief Header for VE1 dependent part of dma_reqlist.c
 */
#ifndef VE_VEOS_VE1_DMA_REQLIST_VE1_H
#define VE_VEOS_VE1_DMA_REQLIST_VE1_H
#include <libved.h>

struct ve_dma_reqlist_entry;
typedef struct ve_dma_reqlist_entry ve_dma_reqlist_entry;

void ve1_dma_free_used_desc(ve_dma_hdl *, int);
void ve1_dma_finish_reqlist_entry(ve_dma_reqlist_entry *, uint64_t, int);
#endif
