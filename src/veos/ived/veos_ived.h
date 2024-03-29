/**
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
 * @file veos_ived.h  
 * @brief IVED header in VEOS
 *
 * @internal
 * @author VESHM
 */

#ifndef __VEOS_IVED_H
#define __VEOS_IVED_H

#include <stdbool.h>
#include <sys/socket.h>
#include <pthread.h>
#include <uuid/uuid.h>
#include <log4c.h>
#include "ve_list.h"

/* List of ived_shared_resource_data */
extern struct list_head ived_task_list;
/* Protect list in ived_shared_resource_data */
extern pthread_mutex_t ived_task_list_lock;

extern struct ve_node_struct *current_node;
extern log4c_category_t *log4cat_veos_ived;

extern struct ve_node_struct *current_node;
extern uuid_t null_id;
extern int ived_linkage;
extern pthread_rwlock_t ived_requesting_lock;
#define IVED_LINKAGE_OFF	(ived_linkage == 0)
#define IVED_LINKAGE_ON		(ived_linkage == 1)	/* for debug */

/**
 * @brief VESHM, CR management data linked from ve_task_struct.
 *
 * It is used by all threads in common.
 *
 * NOTE: owned_veshm and ataching veshm are managed by lists, so
 * owned_veshm_num and attach_veshm_num are not necessary. 
 * owned_veshm_num and attach_veshm_num counts length of each list entries
 * for the purpose of debuging. Don't divert them.
 */
struct ived_shared_resource_data;
struct ve_task_struct;

extern int veos_ived_register_osdata();
extern int veos_ived_erase_osdata();
extern int veos_init_ived_proc_property(struct ve_task_struct *);
extern int veos_clean_ived_proc_property(struct ve_task_struct *);
extern int veos_ived_get_pciatb_pgmode(int);
extern int veos_veshm_update_is_swap_out(struct ve_task_struct *, bool);

extern int veos_veshm_test_paddr_array_all(struct ve_task_struct *);
extern void veos_veshm_update_paddr_array_all(struct ve_task_struct *);
#endif
