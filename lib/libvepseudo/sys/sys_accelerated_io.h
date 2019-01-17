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
 * @file sys_accelerated_io.h
 * @brief Header file for "sys_accelerated_io.c" file.
 */

#ifndef __SYS_ACCELERATED_IO_H
#define __SYS_ACCELERATED_IO_H

#include "libved.h"

#define VESHM_MAX_ARGS  5

#define VE_ACCELERATED_IO_ADDR_MASK 0x3fffffffffffffff 

#define SIZE_2MB        (2*1024*1024)
#define SIZE_8MB        (8*1024*1024)
#define SIZE_64MB       (64*1024*1024)

#define CHANGE_MASK_2MB   0xFFFFFFFFFFE00000ULL
#define CHANGE_MASK_64MB  0xFFFFFFFFFC000000ULL

int sys_accelerated_io_init(veos_handle *, void **, uint64_t *, void *,
				uint64_t *, int);
int sys_accelerated_io_register_dmaatb(veos_handle *, void *, uint64_t *,
				void *, uint64_t *, int);
void sys_accelerated_unregister_ve_buf_vehva(veos_handle *);
void sys_accelerated_free_vh_buf(void);
#endif
