/**
 * Copyright (C) 2022 NEC Corporation
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
 * @file veos_devmem.h
 * @brief Header for VE-GPU data transfer functions (VEOS side)
 *
 * @internal
 * @author VE-GPU
 */

#ifndef __VEOS_DEVMEM_H
#define __VEOS_DEVMEM_H

#include <pthread.h>
#include <stdint.h>
#include <libved.h>
#include "ve_list.h"
#include "comm_request.h"

#define HUGE_PAGE_SIZE_4KB (4 * 1024)
#define HUGE_PAGE_SIZE_2MB (2 * 1024 * 1024)
#define HUGE_PAGE_SIZE_64MB (64 * 1024 * 1024)
#define DMAATB_PAGE_SIZE_FOR_DEVMEM HUGE_PAGE_SIZE_64MB
#define KPAGEFLAG          "/proc/kpageflags"
#define HUGE_BIT           0x20000

/* Function prototypes */
int veos_initialize_devmem_resource(struct ived_shared_resource_data *);
int veos_dev_mem(veos_thread_arg_t *);
int veos_delete_devmem_resource(struct ve_task_struct *);
int64_t veos_map_dev_mem_paddr_to_vehva(int,
					struct ve_task_struct *);
int64_t veos_unmap_dev_mem_paddr_from_vehva(uint64_t,
					struct ve_task_struct *);
int veos_devmem_init(struct ve_node_struct *);

/* Structures */

/* For resource information list and lock */
struct veos_dev_mem {
	struct list_head res; /* List for devmem resources */
	pthread_mutex_t veos_dev_mem_lock; /* lock hierarchy is node_devmem_id_list.devmem_id_list_lock > veos_dev_mem_lock*/
};

struct veos_dev_mem_resources {
	struct list_head list; /* List for next resource */
	uint64_t vehva;
	uint64_t *paddr; /* array of GPU physical address. End of this array must be NULL */
	uint64_t page_num; /* Number of pindowned pages. */
	uint32_t id;
};

#endif
