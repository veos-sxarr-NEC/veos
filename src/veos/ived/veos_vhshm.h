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
 * @file veos_vhshm.h
 * @brief Header for VH-VE shared memory functions (VEOS side)
 *
 * @internal
 * @author VHSHM
 */

#ifndef __VEOS_VHSHM_H
#define __VEOS_VHSHM_H

#include <pthread.h>
#include <stdint.h>
#include <libved.h>
#include "ve_list.h"
#include "comm_request.h"

#define HUGE_PAGE_SIZE_2MB (2 * 1024 * 1024)
#define KPAGEFLAG          "/proc/kpageflags"
#define HUGE_BIT           0x20000

/* Function prototypes */
int veos_initialize_vhshm_resource(struct ived_shared_resource_data *);
int veos_vhshm(veos_thread_arg_t *);
int veos_delete_vhshm_resource(struct ived_shared_resource_data *);
int64_t veos_map_vhva_to_vehva(pid_t, uint64_t, size_t, int,
						struct ve_task_struct *);
int64_t veos_unmap_vhva_from_vehva(pid_t, uint64_t, struct ve_task_struct *);

/* Structures */

/* For resource information list and lock */
struct veos_vhshm {
	struct list_head res; /* List for vhshm resources */
	pthread_mutex_t veos_vhshm_lock;
};

struct veos_vhshm_resouces {
	struct list_head list; /* List for next resource */
	int64_t vehva;
	uint64_t *vhsaas; /* array of vhsaa. End of this array must be NULL */
	uint64_t page_num; /* Number of pindowned pages. */
};
#endif
