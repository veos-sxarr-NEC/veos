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
 * @file sys_shm.h
 * @brief Header file for "sys_shm.c".
 *
 * @internal
 * @author AMM
 */
#ifndef __SYS_SHM_H
#define __SYS_SHM_H

#include <sys/mman.h>
#include <inttypes.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include "vemva_mgmt.h"
#include "mm_type.h"
#include "libved.h"
#include "comm_request.h"

#define SHM_2MB		((uint32_t)1 << 22)
#define SHM_64MB       ((uint32_t)1 << 23)

#define CHUNK_512GB     0x8000000000
#define CHUNK_512MB     0x20000000
#define CHUNK_16GB      0x400000000
#define PG_4K   0
#define PG_2M   1
#define PG_HP   2

#define BUF_SIZ 8192
#define SYSVIPC_FILE "/proc/sysvipc/shm"

int get_shm_stat_proc(int shmid, key_t key, struct shmid_ds *buf);
ret_t ve_shmat(int syscall_num, char *syscall_name, veos_handle *handle);
ret_t ve_shmctl(int syscall_num, char *syscall_name,
			veos_handle *handle);
ret_t ve_shmdt(int syscall_num, char *syscall_name, veos_handle *handle);

vemva_t *__ve_shmat(veos_handle *, int64_t, vemva_t, int, uint64_t);
int64_t __ve_shmctl(veos_handle *, int64_t, int64_t, uint64_t);
int64_t __ve_shmdt(veos_handle *, vemva_t);

int64_t amm_request_shmat(veos_handle *, int64_t, vemva_t,
	uint64_t, int64_t);
struct shm_seginfo *amm_request_shmget(veos_handle *, key_t, int64_t,
		uint64_t, int);
struct shm_seginfo *ve_get_shm_seg_pgmode(veos_handle *, int64_t);
int64_t amm_request_shmctl_rmid(veos_handle *, int64_t);
int ve_shm_request(struct ve_shm_cmd *, int, int,
				struct shm_seginfo *);
#endif
