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
/*
 * @file mm_type.h
 * @brief It contains data types related to AMM
 *
 * @internal
 * @author AMM
 */
#include "velayout.h"
#include <stdint.h>

typedef int64_t vemva_t;
typedef int64_t vhva_t;
typedef int64_t vehva_t;
typedef int64_t veraa_t;
typedef int64_t vemaa_t;
typedef int64_t vhsaa_t;
typedef int64_t pgno_t;
typedef int64_t ret_t;
typedef int16_t dir_t;
typedef int16_t jid_t;
typedef int16_t ent_t;
typedef uint64_t flag_t;
typedef uint64_t prot_t;

#define VE_MMAP_FAILED ((void *)-1)

#define pgmod_to_pgstr(p) ((p == PG_2M) ? "large page" : ((p == PG_HP) ? "huge page" : "small page"))
#define pgsz_to_pgstr(p) ((p == PAGE_SIZE_2MB) ? "large page" : ((p == PAGE_SIZE_64MB) ? "huge page" : "small page"))
#define pgmod_to_pgsz(p) ((p == PG_2M) ? PAGE_SIZE_2MB : ((p == PG_HP) ? PAGE_SIZE_64MB : PAGE_SIZE_4KB))
#define pgsz_to_pgmod(p) ((p == PAGE_SIZE_2MB) ? PG_2M : PG_HP)
#define perm_to_shmstr(p) ((p & SHM_RDONLY) ? "SHM_RDONLY" : "PROT_READ and PROT_WRITE")
#define chsz_to_chstr(p) ((p == CHUNK_512GB) ? "CHUNK_512GB" :\
	((p == CHUNK_512MB) ? "CHUNK_512MB" : "CHUNK_16GB"))
#define perm_to_str(perm)      (perm == PROT_READ) ? "PROT_READ" :\
                              ((perm == PROT_WRITE) ? "PROT_WRITE" :\
                               ((perm == (PROT_READ | PROT_WRITE))\
                               ? "PROT_RDWR" : "PROT_NONE"))


#define AMM_TRACE(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "%s " fmt, __func__, ## __VA_ARGS__)
#define AMM_INFO(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)
#define AMM_ERR(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define AMM_DEBUG(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define AMM_DBG(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define AMM_CRIT(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_CRIT, fmt, ## __VA_ARGS__)
#define AMM_ALERT(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ALERT, fmt, ## __VA_ARGS__)
