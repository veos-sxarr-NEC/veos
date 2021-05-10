/*
 * Copyright (C) 2020-2021 NEC Corporation
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
 * @file  vhve_common.h
 * @brief Header file for "vhve_common.c" file.
 *
 * @internal
 * @author VHVE
 */
#ifndef __VHVE_COMMON_H
#define __VHVE_COMMON_H

#include <sys/types.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include "velayout.h"
#include "list.h"
#include "vhve_request.h"

#define IS_ALIGNED(x, a)    (((x) & ((typeof(x))(a) - 1)) == 0)
#define VE_DMA_MAX_LENGTH 0x7FFFFFFFFFFFFFF8UL

/* Used for log4c logging in veos module */
extern log4c_category_t *cat_vhve_core;
extern const log4c_location_info_t locinfo;

/* data structure for ext_data in veos_handle */
struct vhve_veos_handle_struct {
	char *veos_sock_name;
	int veos_sock_fd;
	/* lock for veos_handle */
	pthread_mutex_t hndl_lock;
	struct list_head list;
};

typedef struct vhve_veos_handle_struct vhve_veos_handle;

/* list of vhve_veos_handle */
struct list_head veos_hndl_list;
/* A lock for veos_hndl_list  */
pthread_mutex_t vhve_veos_hndl_list_lock;

#define CAT_VHVE_CORE cat_vhve_core
#define VHVE_ERROR(fmt, ...) \
	VE_LOG(CAT_VHVE_CORE, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define VHVE_DEBUG(fmt, ...) \
	VE_LOG(CAT_VHVE_CORE, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define VHVE_TRACE(fmt, ...) \
	VE_LOG(CAT_VHVE_CORE, LOG4C_PRIORITY_TRACE, fmt, ## __VA_ARGS__)
#define VHVE_WARN(fmt, ...) \
	VE_LOG(CAT_VHVE_CORE, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)
#define VHVE_INFO(fmt, ...) \
	VE_LOG(CAT_VHVE_CORE, LOG4C_PRIORITY_INFO, fmt " %s()", ## __VA_ARGS__, __func__)

vhve_veos_handle * vhve_veos_handle_alloc(char *);
void vhve_veos_handle_free(vhve_veos_handle *);
int vhve_request_to_veos(vhve_veos_handle *, void *, size_t, struct vhve_result *);
int vhve_dma_check_args(uint64_t, uint64_t, uint64_t);

#endif
