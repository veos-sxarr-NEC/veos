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
 * @file veos_ived_misc.c  
 * @brief IVED/VESHM/CR functions in VEOS (helper functions)
 *
 * @internal
 * @author VESHM
 */

#include <stdio.h>
#include <uuid/uuid.h>
#include <inttypes.h>

#include "ve_mem.h"
#include "comm_request.h"

#include "ived_request.h"
#include "ived_common.h"
#include "veos_ived.h"
#include "veos_ived_common.h"
#include "veos_veshm_core.h"
#include "veos_ived_private.h"

int
dump_ived_shared_resource_data(struct ived_shared_resource_data *info)
{
	char str_uuid[64];

	IVED_DEBUG(log4cat_veos_ived,"Dump ived_shared_resource_data: %p",
		   info);
	if (info == NULL)
		return(0);

	uuid_unparse(info->uuid_proc, str_uuid);

	IVED_DEBUG(log4cat_veos_ived,
		   "\tpid:%d, uuid_proc:%s",
		   info->pid, str_uuid);

	IVED_DEBUG(log4cat_veos_ived,
		   "\tSKIP CR data. Add it later, if needed.");

	IVED_DEBUG(log4cat_veos_ived,
		   "\tNum of owned veshm:%d, Num of owned veshm:%d",
		   info->owned_veshm_num,
		   info->attach_veshm_num);
	return(0);
}


int
dump_own_veshm(struct owned_veshm_info *info)
{
	char str_uuid[64];

	IVED_DEBUG(log4cat_veos_ived,"Dump owned_veshm_info: %p", info);
	if (info == NULL)
		return(0);

	uuid_unparse(info->uuid_veshm, str_uuid);

	IVED_DEBUG(log4cat_veos_ived,
		   "\tvemva:0x%"PRIx64", size:0x%"PRIx64
		   ", pciatb slot:%p & num:%d",
		   info->vemva,
		   info->size,
		   info->pciatb_slot,
		   info->pciatb_entries);
	IVED_DEBUG(log4cat_veos_ived,
		   "\tstat:0x%"PRIx64"",
		   info->status_flag);
	IVED_DEBUG(log4cat_veos_ived,
		   "\tpcisync_num:%d, uuid_veshm:%s", 
		   info->pcisync_num,
		   str_uuid);
	dump_uuid("\tuuid_proc", info->uuid_proc);
	return(0);
}

int
dump_attach_veshm(struct attaching_veshm_info *info)
{
	IVED_DEBUG(log4cat_veos_ived,"Dump attaching_veshm_info : %p", info);
	if (info == NULL)
		return(0);

	IVED_DEBUG(log4cat_veos_ived,
		   "\ttarget_pid: %d, target_vemva:0x%"PRIx64", size:0x%"PRIx64"",
		   info->target_pid,
		   info->target_vemva,
		   info->size);
	IVED_DEBUG(log4cat_veos_ived,
		   "\tvemva:0x%"PRIx64", count:%d, vehva:0x%"PRIx64", count:%d",
		   info->vemva,
		   info->ref_cnt_vemva,
		   info->vehva,
		   info->ref_cnt_vehva);
	dump_uuid("\tuuid_proc ", info->uuid_proc);
	dump_uuid("\tuuid_veshm ", info->uuid_veshm);

	return(0);
}


