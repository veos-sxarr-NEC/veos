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
 * @file cr_ipc.h  
 * @brief Header for CR IPC of IVED
 *
 * @internal
 * @author CR
 */

#include "ived.h"

#ifndef _CR_IPC_H
#define _CR_IPC_H

int ived_cr_kill_remote_process(struct veos_info *);
int put_cr_reference(struct veos_info *, int);
int ived_handle_cr_request(ived_thread_arg_t *);

#endif
