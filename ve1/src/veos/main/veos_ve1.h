/*
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
 * @file veos_ve1.h
 * @brieaf VE1-dependent part of VEOS data structure
 */
#ifndef VEOS_VE1_VEOS_VE1_H
#define VEOS_VE1_VEOS_VE1_H
#include <ve_hw.h>
#include <ve_mem_ve1.h>
struct ve1_node_arch_dep_data {
	struct ve1_hw_dma_map hw_dma_map[VE1_DMAATB_DIR_NUM];
};

#define VE1_NODE_ARCH_DEP(nodep_) \
	((struct ve1_node_arch_dep_data *)(nodep_)->arch_dep_data)
#endif
