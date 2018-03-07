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
 * @file  ived_misc.c
 * @brief Miscellaneous functions for IVED components.
 *
 * @internal
 * @author VESHM
 */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <log4c.h>
#include "ve_memory.h"
#include "ived_common.h"
#include "ived_ipc.h"

log4c_category_t *log4cat_lib;

/**
 * @brief Check locking 
 * If mutex is locked by a caller thread, this function returns 0.
 *
 * @param [in] mutex Checked lock (Must be error checking type)
 *
 * @return 0 on success, -1  on failure
 */
int
ived_check_mutex_locked(pthread_mutex_t *mutex)
{
	int ret;
	struct timespec timeout;

	ret = clock_gettime(CLOCK_REALTIME, &timeout);
	if (ret != 0){
		IVED_ERROR(log4cat_lib, "%s", strerror(errno));
		return(-ret);
	}
	timeout.tv_sec += LOCK_CHK_TIMEOUT;
	ret = pthread_mutex_timedlock(mutex, &timeout);

	if (ret == 0){
		pthread_mutex_unlock(mutex);
		IVED_ERROR(log4cat_lib, "Need to aqcuire a target lock.");
		return (-1);
	}
	if (ret == EDEADLK){
		return (0);
	}
	IVED_ERROR(log4cat_lib, "Check locking: %s", strerror(ret));
	return (-1);
}


/**
 * @brief Convert Page size in byte to flag (bit pattern)
 *
 * @param [in] size size in byte
 * @param [in] mode flag mode VE_ADDR_VEMVA/VE_ADDR_VEHVA/VE_ADDR_PCI
 *
 * @return bit pattern of size on success, -1 on failure
 */
int
ived_pgsize_byte2flag(int64_t size, int mode)
{
	if (mode == VE_ADDR_PCI){
		if (size == PGSIZE_64M)
			return (PGMODE_FLAG_64M);
		else if (size == PGSIZE_2M)
			return (PGMODE_FLAG_2M);
	} else {
		if (size == PGSIZE_64M)
			return (PG_HP);
		else if (size == PGSIZE_2M)
			return (PG_2M);
		else if (size == PGSIZE_4K)
			return (PG_4K);
	}

	IVED_ERROR(log4cat_lib, "Invalid pagesize: %#"PRIx64"", size);
	return (-1);
}

/**
 * @brief Convert flag (bit pattern) to page size in byte
 *
 * @param flag flag of PCIATB page size (value is the same in PCIATBA)
 *
 * @return size in byte on success, -1 on failure
 */
int
ived_pci_pgsize_flag2byte(int flag)
{
	if (flag == PGMODE_FLAG_64M)
		return (PGSIZE_64M);
	else if (flag == PGMODE_FLAG_2M)
		return (PGSIZE_2M);

	IVED_ERROR(log4cat_lib, "Invalid flag: %d", flag);
	return (-1);
}


/**
 * @brief dump uuid 
 */
int
dump_uuid(char *str, uuid_t data)
{
	char str_uuid[64];

	uuid_unparse(data, str_uuid);

	IVED_DEBUG(log4cat_lib, "%s uuid:%s", str, str_uuid);
	return(0);
}

