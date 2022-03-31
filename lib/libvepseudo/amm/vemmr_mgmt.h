/*
 * Copyright (C) 2021 NEC Corporation
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
 * @file vemmr_mgmt.h
 * @brief Header file for "vemmr_mgmt.c".
 */
#ifndef __VEMMR_MGMT_H
#define __VEMMR_MGMT_H

#include "stdint.h"
#include "vemva_layout.h"

struct vemmr_usage {
	uint64_t blocks_16GB; /*!< bitmap of usages of 64 blocks */
	uint32_t blocks_512MB[sizeof(uint64_t) * 8]; /*!< bitmap of usages 32 blocks per 16GB blocks*/
};

/**
 * @brief This contains last allocated VEMMR block info.
 */
struct vemmr_index {
	int64_t idx_16GB;  /*!< Last allocated 16GB block */
	int64_t idx_512MB; /*!< Last allocated 512MB block */
};

int ve_init_vemmr(void);
uint64_t allocate_chunk(uint64_t, uint64_t, uint64_t);
int free_chunk(uint8_t, void *);
int free_chunks(uint64_t, uint64_t, uint64_t);
int ve_init_rvr(veos_handle *, uint64_t);
int ve_sys_get_vemva_region(veos_handle *, uint64_t, uint64_t, uint64_t);
#endif
