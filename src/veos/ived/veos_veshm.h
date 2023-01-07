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
 * @file veos_veshm.h  
 * @brief VESHM functions in VEOS
 *
 * @internal
 * @author VESHM
 */

#ifndef __VEOS_VESHM_H
#define __VEOS_VESHM_H

#include <unistd.h>
#include <inttypes.h>
#include <uuid/uuid.h>
#include "ve_list.h"
#include "task_mgmt.h"
#include "veos_ived.h"
#include "veos_veshm_core.h"


/*
 * Data structures 
 */

/* Functions */
int check_mem_pgmode(int, int64_t, int64_t);
int check_mem_perm(int, int64_t, int64_t, int);
int create_veshm_paddr_array(pid_t, uint64_t, int64_t, uint64_t, uint64_t *);
int check_veshm_paddr(uint64_t *, uint64_t, uint64_t, pid_t, uint64_t, 
		      uint64_t);

int conv_pcislot_to_pciaddr(int, int *, uint64_t *);

extern uint64_t veshm_open_internal(int, int, uint64_t, uint64_t, int, 
				    uint64_t, uuid_t *, uint64_t **);
extern int veshm_close_internal(uuid_t , int);

extern int veos_veshm_discard_all(struct ve_task_struct *);

extern struct owned_veshm_info *
pickup_owned_veshm_addr(struct ived_shared_resource_data *, uint64_t, uint64_t, int,
			uint64_t);
extern struct owned_veshm_info *
pickup_owned_veshm_uuid(struct list_head *, uuid_t);

struct owned_veshm_info *search_all_owned_veshm_uuid
(uuid_t, struct ived_shared_resource_data *);

extern int delete_owned_veshm_info(struct list_head *, int *,
				   struct owned_veshm_info *);


extern struct attaching_veshm_info *
pickup_attaching_veshm(struct ived_shared_resource_data *, int, uint64_t, 
		       uint64_t, int, uint64_t, uint64_t);
extern struct attaching_veshm_info *
pickup_attaching_veshm_kind(struct ived_shared_resource_data *, 
			    uint64_t, uint64_t);

extern int delete_attaching_veshm_info(struct ived_shared_resource_data *, 
				       struct attaching_veshm_info *);


#endif
