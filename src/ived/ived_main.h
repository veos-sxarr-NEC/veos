/**
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
 * @file ived_main.h  
 * @brief Header for IVED  main 
 *
 * @internal
 * @author IVED
 */


#ifndef __IVED_MAIN_H
#define __IVED_MAIN_H

#include <uuid/uuid.h>
#include "ived.pb-c.h"

#define  VEOS_SELF_SHUTDOWN	1

struct veos_info;
struct process_info;
struct ived_thread_arg;
typedef struct ived_thread_arg ived_thread_arg_t;

int test_os_state(struct veos_info *);

struct veos_info *get_osinfo_struct(pid_t);
int search_node_proc_info(int, uuid_t, struct veos_info ** ,
			  struct process_info **);
struct process_info *get_procinfo_struct(struct veos_info *, int, 
					 uuid_t, int);

int ived_register_osdata(ived_thread_arg_t *, RpcIvedArg *);
int ived_erase_osdata(ived_thread_arg_t *, RpcIvedArg *);

int ived_register_procdata(ived_thread_arg_t *, RpcIvedArg *);
int ived_erase_procdata(ived_thread_arg_t *, RpcIvedArg *);
int try_erase_procinfo(struct process_info *);
int try_clear_osinfo(struct veos_info *, int);

#endif
