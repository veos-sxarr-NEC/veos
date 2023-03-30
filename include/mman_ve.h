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
 * @file mman_ve.h
 * @brieaf Mapping control flags
 *
 * @internal
 * @author AMM
 */
#ifndef VEOS_INCLUDE_MMAN_VE_H_
#define VEOS_INCLUDE_MMAN_VE_H_

#define MAP_VESHM               ((uint64_t)1<<21)
#define MAP_2MB                 ((uint64_t)1<<22)
#define MAP_64MB                ((uint64_t)1<<23)
#define MAP_ADDR_64GB_FIXED     ((uint64_t)1<<36)
#define MAP_ADDR_64GB_SPACE     ((uint64_t)1<<35)
#define MAP_ADDR_SPACE          ((uint64_t)1<<34)
#define MAP_VDSO                ((uint64_t)1<<32)

#endif
