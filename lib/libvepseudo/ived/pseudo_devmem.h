/*
 * Copyright (C) 2017-2022 NEC Corporation
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
 * @file pseudo_devmem.h
 * @brief Header for VE-GPU data transfer functions (Pseudo process side)
 *
 * @internal
 * @author VE-GPU
 */

#ifndef __PSEUDO_DEVMEM_H
#define __PSEUDO_DEVMEM_H

#include <stdint.h>
#include "sys_common.h"
#include "handle.h"
#include "list.h"

/* Function prototypes */
ret_t sys_dev_mem(veos_handle *, uint64_t *);
int64_t sys_attach_dev_mem(veos_handle *, int);
int sys_detach_dev_mem(veos_handle *, const uint64_t);
#endif
