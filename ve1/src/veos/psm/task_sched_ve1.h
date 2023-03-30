/**
 * Copyright (C) 2020 NEC Corporation
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
 * @file task_sched_ve1.h
 * @brief VE1-dependent part of task_sched.c
 */
#ifndef VEOS_VE1_PSM_TASK_SCHED_VE1_H
#define VEOS_VE1_PSM_TASK_SCHED_VE1_H
#include <libved.h>
#include <task_sched.h>
int ve1__psm_restore_udma_context(struct ve_task_struct *, int, int);

#endif
