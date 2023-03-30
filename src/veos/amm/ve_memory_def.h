/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file ve_memory_def.h
 * @brieaf Header file for "ve_memory.c".
 *
 * @internal
 * @author AMM
 */

#ifndef VEOS_AMM_MEMORY_H
#define VEOS_AMM_MEMORY_H
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>

#include <mman_ve.h>
#include <mm_type.h>

#include <veos_arch_defs.h>

int pg_getpb(veos_atb_entry_t *, int);

void pg_setpb(veos_atb_entry_t *, pgno_t, int);

void ps_setpsnum(veos_atb_dir_t *, pgno_t, int);

int ps_getps(veos_atb_dir_t *, int);

int64_t psnum(int64_t, int);

int64_t pgentry(int64_t, int);

int64_t psnum_to_vaddr(uint64_t, int, int);

pgno_t pfnum(int64_t, int);

uint64_t pbaddr(pgno_t, int);

#endif
