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
 * @file veos_veshm_ipc.h  
 * @brief Header for VESHM IPC functions
 *
 * @internal
 * @author VESHM
 */


#ifndef __VEOS_VESHM_IPC_H
#define __VEOS_VESHM_IPC_H

#include <uuid/uuid.h>
#include "ived.pb-c.h"

struct owned_veshm_info;
struct ve_task_struct;

int veos_veshm_open_common(RpcVeshmSubOpen *, IvedReturn *);
int veos_veshm_attach_common(RpcVeshmSubAttach *, IvedReturn *);
int veos_veshm_detach_common(RpcVeshmSubDetach *, IvedReturn *);
int veos_veshm_close_common(RpcVeshmSubClose *, IvedReturn *, 
			    struct ve_task_struct *, struct owned_veshm_info *);
int veos_veshm_erase_area(size_t, uint64_t *);

#endif
