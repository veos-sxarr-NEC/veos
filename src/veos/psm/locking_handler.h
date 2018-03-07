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
 * @file  locking_handler.h
 * @brief
 * This file contains the functions which are responsible for
 * mutex lock/unlock
 *
 * @author PSMG / MPMT
 */
#ifndef __PSM_LOCKING_HANDLER_H
#define __PSM_LOCKING_HANDLER_H

#include <pthread.h>

typedef enum {
	LOCK,
	UNLOCK,
	RDLOCK,
	WRLOCK
} lock_unlock_t;

#define VEOS_ABORT_MESSAGE_BUF_SIZE 512

void pthread_mutex_lock_unlock(pthread_mutex_t *lock,
		lock_unlock_t flag, const char *message, ...);
void pthread_rwlock_lock_unlock(pthread_rwlock_t *lock,
		lock_unlock_t flag, const char *message, ...);
#endif
