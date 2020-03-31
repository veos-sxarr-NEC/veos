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
 * @file  locking_handler.c
 * @brief
 * This file contains the functions which are responsible for
 * mutex lock/unlock
 *
 * @author PSMG / MPMT
 */
#include "locking_handler.h"
#include "velayout.h"
#include "veos.h"


/**
* @brief Handles mutex lock/unlock functionality
*
* @param[in] lock Lock variable
* @param[in] flag Specifies lock/unlock
* @param[in] message String which is printed when lock/unlock fails
* @param[in] ... Any extra arguments if required
*
* @internal
* @note Invoked by other modules i.e. PTRACE
*/
void pthread_mutex_lock_unlock(pthread_mutex_t *lock,
				lock_unlock_t flag, const char *message, ...)
{
	int retval = -1;
	va_list ap;
	char message_str[VEOS_ABORT_MESSAGE_BUF_SIZE] = {0};

	va_start(ap, message);
	vsnprintf(message_str, VEOS_ABORT_MESSAGE_BUF_SIZE, message, ap);
	va_end(ap);

	switch (flag) {
	case LOCK:
		retval = pthread_mutex_lock(lock);
		if (retval != 0) {
			VEOS_DEBUG(message_str, "return value %s",
					strerror(retval));
			VEOS_DEBUG("return value %s", strerror(retval));
			goto abort;
		}
		break;
	case UNLOCK:
		retval = pthread_mutex_unlock(lock);
		if (retval != 0) {
			VEOS_DEBUG(message_str, "return value %s",
					strerror(retval));
			goto abort;
		}
		break;
	default:
		VEOS_ERROR("Invalid lock operation");
	}
	return;
abort:
	veos_abort(message_str);
}

/**
* @brief Handles read-write lock/unlock funcionality
*
* @param[in] lock Lock variable to lock/unlock
* @param[in] flag Specifies lock/unlock
* @param[in] message String which is printed when lock/unlock fails
* @param[in] ... Any extra arguments if required
*/
void pthread_rwlock_lock_unlock(pthread_rwlock_t *lock,
				lock_unlock_t flag, const char *message, ...)
{
	int retval = -1;
	va_list ap;
	char message_str[VEOS_ABORT_MESSAGE_BUF_SIZE] = {0};

	va_start(ap, message);
	vsnprintf(message_str, VEOS_ABORT_MESSAGE_BUF_SIZE, message, ap);
	va_end(ap);

	switch (flag) {
	case RDLOCK:
		retval = pthread_rwlock_rdlock(lock);
		if (retval != 0) {
			VEOS_DEBUG(message_str, "return value %s",
					strerror(retval));
			goto abort;
		}
		break;
	case UNLOCK:
		retval = pthread_rwlock_unlock(lock);
		if (retval != 0) {
			VEOS_DEBUG(message_str, "return value %s",
					strerror(retval));
			goto abort;
		}
		break;
	case WRLOCK:
		retval = pthread_rwlock_wrlock(lock);
		if (retval != 0) {
			VEOS_DEBUG(message_str, "return value %s",
					strerror(retval));
			goto abort;
		}
		break;
	default:
		VEOS_ERROR("Invalid lock operation");
	}
	return;
abort:
	veos_abort(message_str);
}
