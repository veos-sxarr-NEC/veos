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
 * @file vemva_layout.h
 * @brief Header file containing definitions about VE memory virtual address
 *        layout.
 */
#ifndef __VEMVA_LAYOUT_H
#define __VEMVA_LAYOUT_H

/**
 * @brief These macro are related to mapping that comes under first 64GB
 *        of process address space.
 */
#define HEAP_START                      0x601000000000
#define ADDR_SPACE_2MB_START            0x600000000000
#define ADDR_SPACE_64MB_START           0x600000000000
#define ADDR_SPACE_2MB_END              0x600400000000
#define ADDR_SPACE_64MB_END             0x600c00000000
#define TRAMP_2MB                       0x6003ffe00000
#define TRAMP_64MB                      0x600fffe00000

/**
 * @brief These macro are related to VE Memory management region.
 */
#define VEMMR_START			0x600000000000ULL
#define VEMMR_SIZE                      0x100000000000ULL
#define VEMMR_NONFIXED_OFFSET		 0x10000000000ULL
#define VEMMR_64MB_OFFSET		VEMMR_NONFIXED_OFFSET
#define VEMMR_2MB_OFFSET		 0xf0000000000ULL
#define VEMMR_BOTTOM			(VEMMR_START + VEMMR_SIZE)

/**
 * @brief These macro are related to RDMA virtual region.
 */
#define RVR_SIZE			VEMMR_SIZE
#define RVR_LOWER_LIMIT			0x100000000000ULL
#define RVR_UPPER_LIMIT			0x500000000000ULL
#endif
