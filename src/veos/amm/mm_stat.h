/*
 * Copyright (C) 2017-2018 NEC Corporation
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
/*
 * @file mm_stat.h
 * @brief Header file for mm_stat.c
 *
 * @internal
 * @author AMM
 */
#ifndef __MM_STAT_H
#define __MM_STAT_H

#include "rpm_comm.h"
#include "ve_mem.h"
#include "ve_shm.h"
#include<sys/mman.h>

void veos_sysinfo(int node_id, struct sysinfo *val);
int veos_pidstat_info(int, struct velib_pidstat *);
int veos_pidstatm_info(int, struct velib_pidstatm *);
int veos_meminfo(struct velib_meminfo *);
int veos_getrusage(int who, struct ve_rusage *ve_r,
		struct ve_task_struct *tsk);
int veos_pmap(int pid, uid_t, uid_t, struct ve_mapheader *);
uint64_t get_vm_size(struct ve_mm_struct *);
size_t get_map_attr(vemva_t, size_t, struct ve_mm_struct *, char *);
void parse_vmflags(char *, char *);
bool check_flag(vemva_t, uint64_t, struct ve_mm_struct *);
int veos_numa_meminfo(struct velib_meminfo *, size_t);
int veos_get_mempolicy(struct ve_task_struct *);
int veos_set_mempolicy(struct ve_task_struct *, int);
int veos_get_dma_space_swappable_size(struct ve_task_struct *, unsigned long *);
#endif
