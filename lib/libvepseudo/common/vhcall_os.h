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
 * @file vhcall_os.h
 * @brief declation of functions for sysve() handler.
 */
#ifndef __VE_VHCALL_OS_H
#define __VE_VHCALL_OS_H

#include "sys_common.h"

vhcall_handle sys_vhcall_install(veos_handle *, uintptr_t);
int64_t sys_vhcall_find(veos_handle *, vhcall_handle, uintptr_t);
long sys_vhcall_invoke(veos_handle *, int64_t, uintptr_t, size_t, uintptr_t,
		       size_t);
int sys_vhcall_uninstall(veos_handle *, vhcall_handle);
int sys_system(veos_handle *, uintptr_t, size_t);
#endif

/* Used for log4c logging in veos module */

#define CAT_PSEUDO_CORE cat_pseudo_core
extern log4c_category_t *cat_pseudo_core;
extern const log4c_location_info_t locinfo;
