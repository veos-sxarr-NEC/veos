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
 * @file veshm_core.h  
 * @brief Header for VESHM core functionality
 *
 * @internal
 * @author VESHM
 */

#ifndef __VESHM_CORE_H
#define __VESHM_CORE_H

#include <uuid/uuid.h>
#include "ve_list.h"
#include "ived.h"
#include "ived_veshm_core.h"


int ived_veshm_discard_all(struct veos_info *, struct process_info *,
			   uint64_t, struct list_head *);

struct ived_resource_user *
search_veshm_attach_proc(struct veshm_memory_info *, int);

struct ived_resource_user *
create_veshm_attach_proc(struct veshm_memory_info *, pid_t, uuid_t);

int 
erase_veshm_attach_proc(struct veshm_memory_info *,
			struct ived_resource_user *);

struct veshm_info_tracker *
create_attaching_veshm_tracker(struct process_info *); 

struct veshm_info_tracker *
search_veshm_tracker_uuid(struct list_head *, struct process_info *, 
			  uuid_t);
int
erase_veshm_tracker(struct veshm_info_tracker *, int *);

struct veshm_info_tracker *
search_veshm_tracker(struct list_head *, struct process_info *,
		     int, uint64_t, uint64_t, int, uint64_t, uint64_t);
struct veshm_info_tracker *
create_having_veshm_tracker(struct process_info *);

int
erase_having_veshm_tracker(struct process_info *, struct veshm_info_tracker *);

struct veshm_memory_info *create_veshm_info(struct veos_info *);

struct veshm_memory_info * 
search_veshm_info(struct process_info *, uint64_t, uint64_t, int, uint64_t,
		  uint64_t);

int 
erase_veshm_info(struct veos_info *, struct veshm_memory_info *);


/* Test for VESHM */
int dump_veshm_info(struct veshm_memory_info *);
int dump_tracker(struct veshm_info_tracker *);
int dump_attach_proc_info(struct ived_resource_user *);

#endif
