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
 * @file veos_cr.h
 * @brief CR related data structure and function
 *
 * @internal
 * @author CR
 */
#ifndef __VEOS_CR_H
#define __VEOS_CR_H

#include <inttypes.h>

/**
 * @brief CR page data for process.
 */
struct proc_cr_page {
	uint64_t mode_flag;
	uint64_t cr_page_num;
};

struct RpcCrArg;
typedef struct _RpcCrArg RpcCrArg;
struct ived_shared_resource_data;
struct ve_task_struct;

int veos_cr_init_resource(struct ived_shared_resource_data *);
int veos_cr_discard_all(struct ve_task_struct *);
int veos_cr_rpc_from_ived(int, RpcCrArg *);

#endif
