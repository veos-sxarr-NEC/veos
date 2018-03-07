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
 * @file ived_ipc_func.h  
 * @brief Header for IVED common IPC functions
 *
 * @internal
 * @author IVED
 */


#ifndef __IVED_IPC_FUNC_H
#define __IVED_IPC_FUNC_H

struct ived_thread_arg;
typedef struct ived_thread_arg ived_thread_arg_t;

int ived_handle_daemon_request(ived_thread_arg_t *);

#endif
