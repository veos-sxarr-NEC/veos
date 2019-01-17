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
 * @file pseudo_vhshm.h
 * @brief Header for VH-VE shared memory functions (Pseudo process side)
 *
 * @internal
 * @author VHSHM
 */

#ifndef __PSEUDO_VHSHM_H
#define __PSEUDO_VHSHM_H

#include <stdint.h>
#include "sys_common.h"
#include "handle.h"
#include "list.h"

#define CHILD_PROCESS 0

/* Function prototypes */
ret_t sys_vhshm(veos_handle *, uint64_t *);
int sys_vh_shmget(veos_handle *, key_t, size_t, int);
int64_t sys_vh_shmat(veos_handle *, int, const void *, int, void **);
int sys_vh_shmdt(veos_handle *, const void *);
void sys_prepar_clear_all_vhshm_resource(void);
void sys_clear_all_vhshm_resource(pid_t);
int64_t sys_vhshm_exchange_attach_request(veos_handle *,void *, size_t, int);
int sys_vhshm_exchange_detach_request(veos_handle *, int64_t);
#endif
