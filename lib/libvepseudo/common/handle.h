/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file handle.h
 * @brief Header file for VEOS handle.
 */

#ifndef __HANDLE_H
#define __HANDLE_H

#include "libved.h"

struct veos_handle_struct {
	vedl_handle *ve_handle;
	char *device_name;
	char *veos_sock_name;
	int veos_sock_fd;
	void *ext_data;/* for VEO or other extensions */
};

typedef struct veos_handle_struct veos_handle;

extern __thread veos_handle *g_handle;

veos_handle *veos_handle_create(char *, char *, veos_handle *, int);
void veos_handle_free(veos_handle *);
void pseudo_abort();
#endif
