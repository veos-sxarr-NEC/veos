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
/**
 * @file dmaatb_api.h
 * @brief Header file for dmaatb_api.c
 *
 * @internal
 * @author AMM
 */
#ifndef __DMAATB_H
#define __DMAATB_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "ve_list.h"
#include "libved.h"
#include "mm_common.h"
#include "ve_mem.h"
#include "ve_swap.h"

#define PG_TYP_MSK (uint64_t)0x7

struct hw_dmaaatb_map {
	uint64_t count;
}hw_dma_map[DMAATB_DIR_NUM];

/* DMAATB  Handling related API's*/
int64_t veos_set_dmaatb(uint64_t, int, int, dmaatb_reg_t *, int, int);
struct vehva_map *vehva_to_vehva_map(uint64_t ,struct ve_mm_struct *);
void amm_dump_vehva(struct ve_mm_struct *);
int64_t del_vehva(vehva_t, size_t, struct ve_task_struct *);
int veos_release_dmaatb_entry(struct ve_task_struct *);
int amm_acquire_dmaatb(struct ve_task_struct *);
int veos_schedulein_dmaatb(struct ve_task_struct *tsk);
int veos_scheduleout_dmaatb(struct ve_task_struct *tsk);

void veos_free_dmaatb(dmaatb_reg_t *, enum swap_progress);
int64_t veos_free_dmaatb_entry(pid_t, vehva_t, size_t);
int64_t veos_free_dmaatb_entry_tsk(struct ve_task_struct *, vehva_t, size_t);

int64_t veos_update_dmaatb_context(struct ve_task_struct *, int);
int64_t veos_alloc_dmaatb_entry_for_syscall(struct ve_task_struct *, vehva_t, vhsaa_t);
int64_t veos_alloc_dmaatb_entry_for_vemva(pid_t, pid_t, vemva_t, size_t,
		int, bool);

int64_t veos_alloc_dmaatb_entry_for_aa(pid_t, uint64_t *, int, int, uint64_t);
int64_t veos_alloc_dmaatb_entry_for_aa_tsk(struct ve_task_struct *, int64_t *,
		int, int, uint64_t, bool);
int8_t amm_set_dmaatb(uint64_t, int, uint64_t, struct ve_task_struct *, int,
		uint8_t, uint8_t, uint16_t);
int8_t amm_unset_dmaatb(uint64_t, struct ve_task_struct *, uint64_t, uint8_t);
void amm_dump_dmaatb(struct ve_task_struct *, bool);
void __dump_dmaatb(FILE*, dmaatb_reg_t *);
int64_t veos_aa_to_vehva(pid_t, vemaa_t, int);
int sync_node_dmaatb_dir(vehva_t, struct ve_mm_struct *, dir_t, jid_t);
int veos_map_dmades(pid_t, uint64_t *, uint64_t *);
int veos_unmap_dmades(pid_t, uint64_t);
#endif
