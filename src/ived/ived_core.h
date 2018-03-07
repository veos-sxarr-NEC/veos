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
 * @file ived_common.h  
 * @brief Header for IVED common functions
 *
 * @internal
 * @author VESHM
 */


#ifndef __IVED_CORE_H
#define __IVED_CORE_H

#include "ve_list.h"
#include "ived.h"

struct ived_resource_user *
search_ived_resource_user(struct list_head *, pthread_mutex_t *, int);

struct ived_resource_user *
create_ived_resource_user(struct list_head *, pthread_mutex_t *, 
			  pid_t, uuid_t);

int erase_ived_resource_user(struct ived_resource_user *, 
			     struct list_head *, pthread_mutex_t *);

/* test */
int dump_os_info(struct veos_info *);
int dump_proc_info(struct process_info *);
int dump_resource_user_info(struct ived_resource_user *);

#endif
