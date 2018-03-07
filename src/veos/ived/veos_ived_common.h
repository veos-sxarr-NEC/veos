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
 * @file veos_ived_common.h  
 * @brief IVED related common functions at VEOS side.
 *
 * @internal
 * @author VESHM
 */

#ifndef __VEOS_IVED_COMMON_H
#define __VEOS_IVED_COMMON_H

#include <sys/types.h>
#include <uuid/uuid.h>
#include "comm_request.h"
#include "ived_request.h"

extern int veos_ived_log4c_init(void);
extern int veos_ived_reply(int64_t, struct ived_sub_reply *, 
			   veos_thread_arg_t *);
struct ived_shared_resource_data *search_ived_resource_data(pid_t);

#endif
