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
 * @file   ived_cr_core.h
 * @brief  Header file for CR manager
 *
 * @internal
 * @author CR
 */

#ifndef _IVED_CR_CORE_H
#define _IVED_CR_CORE_H

#include "inttypes.h"
#include "ived.h"

/*
 * Macro
 */

#define NODE_CR_PAGE_NUM	32
#define CRD_ENTRY		4

/*
 * Data structures
 */

struct cr_page_info{			/*!< Array of CR pages in a node */
	struct list_head erase_list;	/*!< Used for CR batch release */
	pthread_mutex_t cr_lock;	/*!< lock for cr_page_info */
	struct veos_info *os_info;	/*!< CR page exists on the OS */

	int	cr_page_num;		/*!< CR page numbeer (Equal to index) */
	uid_t	uid;			/*!< CR user's UID */
	uint64_t mode_flag;		/*!< Mode flag of CR */
	int	reference_cnt;		/*!< Reference counter 
					  (# of cr_info_tracker )*/
	struct list_head cr_users_list;	/* List head of cr_remote_proc_info */
} ;

/**
 * @brief Using CR tracker per process
 */
struct cr_info_tracker{
	struct list_head list;
	struct cr_page_info *cr_info;	/*!< Corresponding CR page */

	/* A data can hold crd or vehva. Don't set both. */
	int crd;			/* CRD number of a user process */
	uint64_t vehva;			/* VEHVA  of a user process */
};

#endif
