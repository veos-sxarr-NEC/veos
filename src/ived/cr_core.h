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
 * @file cr_core.h  
 * @brief Header for CR core functions
 *
 * @internal
 * @author CR
 */

#ifndef __CR_CORE_H
#define __CR_CORE_H

#include "ived.h"
#include "ived_cr_core.h"

int try_clear_cr_page_info(struct cr_page_info *);
struct cr_info_tracker * search_using_cr_info(struct process_info *, 
					      int , uint64_t );
struct cr_info_tracker * search_using_cr_info_halfway(struct process_info *, 
						      struct cr_page_info *);
struct cr_info_tracker * create_using_cr_info(struct process_info *, 
					      struct cr_page_info *);
int erase_using_cr_info(struct process_info *, struct cr_info_tracker *);
struct ived_resource_user * search_cr_user_info(struct cr_page_info *, int );
struct ived_resource_user * create_cr_user_info(struct cr_page_info *, pid_t );
int try_erase_cr_user_info(struct cr_page_info *, struct ived_resource_user *,
			   uint64_t);
int all_cr_release_remote(struct veos_info *, struct process_info *, 
			  struct list_head *);
int all_cr_release_local(struct veos_info *, struct process_info *);
int ived_cr_discard_all(struct veos_info *, struct process_info *, uint64_t,
			struct list_head *);
int erase_cr_info_batch(struct list_head *);

/* Debug message */
int dump_cr_page_info(struct cr_page_info *);
int dump_cr_info_tracker(struct cr_info_tracker *);

#endif

