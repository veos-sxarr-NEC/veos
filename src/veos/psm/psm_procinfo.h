/*
 * Copyright (C) 2025 NEC Corporation
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
 * @file psm_procinfo.h
 * @brief Header file for "psm_procinfo.c" file.
 *
 * @internal
 * @author PSMG
 */
#ifndef __PSM_PROCINFO_H
#define __PSM_PROCINFO_H

#ifdef USE_OPENPROC
#include <proc/readproc.h>
#else
#include <libproc2/pids.h>
#include "libproc_readproc.h"
#endif /* USE_OPENPROC */

#include <stdbool.h>
#include <pthread.h>
#include "task_mgmt.h"

int psm_get_ve_proc_info(pid_t, proc_t *);
bool check_for_zombie_deletion(struct ve_task_struct *);
bool is_pseudo_stop(pid_t);

#endif /* __PSM_PROCINFO_H */
