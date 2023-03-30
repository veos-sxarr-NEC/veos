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
 * @file veos_ve3.h
 * @brieaf VE3-dependent part of VEOS data structure
 */
#ifndef VEOS_VE3_VEOS_VE3_H
#define VEOS_VE3_VEOS_VE3_H
#include <ve_hw.h>
#include <ve_mem_ve3.h>
struct ve3_node_arch_dep_data {
	struct ve3_hw_dma_map hw_dma_map[VE3_DMAATB_DIR_NUM];
	int type;
};

#define VE3_NODE_ARCH_DEP(nodep_) \
	((struct ve3_node_arch_dep_data *)(nodep_)->arch_dep_data)
#endif
