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
 * @file veos_veshm_core.h  
 * @brief IVED internal header in VEOS
 *
 * @internal
 * @author VESHM
 */


#ifndef __VEOS_VESHM_CORE_H
#define __VEOS_VESHM_CORE_H

#include <inttypes.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "ve_list.h"

extern struct list_head veshm_remains_list;
extern pthread_mutex_t veshm_remains_lock;

/*
 * Data structures 
 */


/* The following struct represents a VESHM area owned by a process */
struct owned_veshm_info{
	struct list_head list;
	uuid_t  uuid_veshm;		/*!< UUID of a VESHM area */
	uuid_t  uuid_proc;		/*!< UUID of a process */
	uint64_t vemva;			/*!< Address of a target memory */
	uint64_t size;			/*!< Size of a target memory */
	int	pcisync_num;		/*!< PCISYAR/MR tuple number */
	int	*pciatb_slot;		/*!< Array of pciatb slots, -1 terminated */
	int	pciatb_entries;		/*!< Number of pciatb_slot (incluing -1 entry) */
	/* pciatb_entries is ( the number of pciatb_slot entries) - 1. */
	uint64_t status_flag;		/*!< How to allocate PCIATB and status */

	/* For physical address check of VESHM memory */
	uint64_t *paddr_array;		/*!< Array of physical pages */
	uint64_t physical_pages;	/*!< The number of physical pages */
	uint64_t physical_pgsize;	/*!< Physical page size of a page */

	int	register_cnt_proc_swappable;	/*!< Open counter from ve processes and with VE_SWAPPABLE */
};


/* The following struct represents an attaching VESHM by a process */
struct attaching_veshm_info{
	struct list_head list;
	pid_t		target_pid;	/*!< Pid of owner process of a VESHM */
	uint64_t	target_vemva;	/*!< Address in the owner process */
	uint64_t	size;		/*!< Size of a target memory */
	int		pcisync_num;	/* PCISYAR/MR tuple number */
	uint64_t	mode_flag;
	uint64_t	req_mode_flag;	/*!< mode_flag for attaching request */
	uint64_t	vemva;		/*!< Address in a user process */
	int		ref_cnt_vemva;  /*!< Reference counter (VEMVA) */
	uint64_t	vehva;		/*!< Address in a user process */
	int		ref_cnt_vehva;  /*!< Reference counter (VEHVA) */
	uuid_t		uuid_proc;	/*!< UUID of a target proces*/
	uuid_t		uuid_veshm;	/*!< UUID of a target VESHM area */
};

#endif /* __VEOS_VESHM_CORE_H */
