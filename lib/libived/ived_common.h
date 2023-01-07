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
 * @file   ived_common.h
 * @brief  Header file for VESHM/CR module
 *
 * @internal
 * @author VESHM
 */

#ifndef _IVED_LIB_COMMON_H
#define _IVED_LIB_COMMON_H

#include <uuid/uuid.h>
#include "velayout.h"
#include "veshm_defs.h"
#include "vecr_defs.h"
#include "ived_misc.h"

#define UNUSED	-1

#define LOCK_CHK_TIMEOUT   1	/* seconds. Wait time for lock checking. */

extern uuid_t null_id;

/*
 * Macro
 */

enum veshm_memory_mode_flag{
	VESHM_MODE_RO		= VE_SHM_RO,	        /* 0x1 */
	VESHM_MODE_SYNC		= VE_PCISYNC,           /* 0x2 */
	VESHM_MODE_PCIATB	= VE_REGISTER_PCI,      /* 0x4 */
	VESHM_MODE_SWAPPABLE	= VE_SWAPPABLE,			/* 0x20 */
	VESHM_MODE_CLOSE	= 0x0000000000000008LL,	/* VESHM is closed */
};


/* VE_CR_* is defined in veos_defs.h */
enum veshm_cr_mode_flag{
	CR_MODE_INIT		= 0x0000000000000000LL,	/* Initialised   */
	CR_MODE_CLEAR		= 0x0000000100000000LL,	/* CR is erasing */
};

#define set_flag(var, flag)	(var |= flag)
#define unset_flag(var, flag)	(var &= ~flag)
#define isset_flag(var, flag)	(var & flag)
#define issame_flag(var1, var2, flag)	((var1 & flag) == (var2 & flag))

/* Memory Size */
#define PGMODE_FLAG_2M		0ULL    /* page size mode flag */
#define PGMODE_FLAG_64M		1ULL
#define PGSIZE_4K	 4*1024
#define PGSIZE_2M	 2*1024*1024
#define PGSIZE_64M	64*1024*1024
#define SHFT_2M		21
#define SHFT_64M	26
#define SIZE_MB		1024*1024	


/* 
 * Logging 
 */

extern log4c_category_t *log4cat_lib;

#define IVED_FATAL(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_FATAL, fmt, ## __VA_ARGS__)

#define IVED_CRIT(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_CRIT, fmt, ## __VA_ARGS__)

#define IVED_ERROR(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)

/* A program is running, but a problem occurred. */
#define IVED_WARN(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)

#define IVED_INFO(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)

/* #ifdef DEBUG */
#define IVED_DEBUG(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)

#define IVED_TRACE(category, fmt, ...) \
	VE_LOG(category, LOG4C_PRIORITY_TRACE, fmt, ## __VA_ARGS__)

#endif
