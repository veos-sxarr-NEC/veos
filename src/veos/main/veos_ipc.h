/*
 * Copyright (C) 2021-2022 NEC Corporation
 * This file is part of the VEOS.
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
 * @file veos_ipc.h
 * @brief Data structures and prototype declarations for 
 * Handling IPC requests
 */

#ifndef __VEOS_IPC_H
#define __VEOS_IPC_H

#include "task_mgmt.h"

/**
  * This structure manages rwlock for exclusive control between IPC and
  * Swap-out/in.
  */
struct ve_ipc_sync {
        pthread_mutex_t ref_lock; /* Lock to protect ref_count and exit_status */
        int ref_count;            /* Reference counter */
        pthread_mutex_t swap_exclusion_lock; /* Lock to protect handling_request and swapping */
        int handling_request;     /* The number of threads handling requests */
        pthread_cond_t handling_request_cond; /* Condition variable to wait handling_request becomes 0 */
        int swapping; /* The flag which is 1 while process is swapped by pps */
        pthread_cond_t swapping_cond; /* Condition variable to wait swapping becomes 0 */
};

struct ve_ipc_sync *ve_get_ipc_sync (struct ve_task_struct *);
int ve_put_ipc_sync (struct ve_ipc_sync *);
int ve_set_state_ipc_sync (struct ve_ipc_sync *);
int ve_mark_ipc_sync(struct ve_task_struct *);
struct ve_ipc_sync *ve_alloc_ipc_sync(void);

#endif
