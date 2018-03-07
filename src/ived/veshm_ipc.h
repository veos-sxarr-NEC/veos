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
 * @file veshm_ipc.h  
 * @brief Header for VESHM IPC
 *
 * @internal
 * @author VESHM
 */


#ifndef __VESHM_IPC_H
#define __VESHM_IPC_H

#include "ived.h"
#include "ived_veshm_core.h"
#include "ve_list.h"

int ived_veshm_kill_remote_process(struct veos_info *);
int erase_veshm_info_batch(struct veos_info *, struct list_head *);

int ived_veshm_close_common(struct veos_info *, struct process_info *, 
			    struct veshm_info_tracker *, uint64_t,
			    int64_t *, int *, int *);

int ived_handle_veshm_request(ived_thread_arg_t *);

#endif
