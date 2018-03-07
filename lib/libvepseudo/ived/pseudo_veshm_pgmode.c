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
 * @file pseudo_veshm_pgmode.c  
 * @brief ve_get_pgmode
 *
 * @internal
 * @author VESHM
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stddef.h>

#include "pseudo_veshm_pgmode.h"
#include "libved.h"
#include "ve_hw.h"
#include "proto_buff_schema.pb-c.h"
#include "handle.h"
#include "comm_request.h"
#include "ived_request.h"
#include "ived_common.h"
#include "ived_ipc.h"
#include "pseudo_ived_common.h"

/**
 * @brief Get pgmode 
 *
 * @return page size in byte on success, -errono on failure
 */
int
pseudo_veshm_get_pgmode(veos_handle *handle, 
			uint8_t mode, pid_t pid, uint64_t address)
{
	int retval;
	uint64_t args[4];

	args[0] = 0;
	args[1] = (uint64_t)mode;
	args[2] = (uint64_t)pid;
	args[3] = address;

	retval = pseudo_get_pgsize(args, handle);

	return(retval);
}


/**
 * @brief Get page size of a specified address.
 *
 * @param [in]     args  Arguments of the system call
 * @param [in]     handle veos_handle
 *
 * @return Page size or -errno on failure
 * @retval 0x200000 (2MB)
 * @retval 0x4000000 (64MB)
 */
int
pseudo_get_pgsize(uint64_t *args, veos_handle *handle)
{
	int ret, retval = -EINVAL;
	struct veshm_args veshm_param;
	PseudoVeosMessage *ret_msg = NULL;
	PseudoVeosMessage ve_veshm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_veshm_req_msg;

	IVED_TRACE(log4cat_pseudo_ived, "PASS");

	if (args == NULL || handle == NULL){
		IVED_CRIT(log4cat_pseudo_ived, 
			  "Internal error: Argument is NULL");
		return(-ECANCELED);
	}

	/* Generate IPC Command */
	veshm_param.subcmd = VESHM_PGSIZE;
	veshm_param.arg.args_veshm_pgsize.mode_flag = args[1];
	veshm_param.arg.args_veshm_pgsize.pid       = args[2];
	veshm_param.arg.args_veshm_pgsize.address   = args[3];

	ve_veshm_req_msg.len = sizeof(struct veshm_args);
	ve_veshm_req_msg.data = (uint8_t *)&veshm_param;	

	ve_veshm_req.pseudo_veos_cmd_id = CMD_VESHM;
	ve_veshm_req.has_pseudo_pid = 1;
	ve_veshm_req.pseudo_pid = syscall(SYS_gettid);
	ve_veshm_req.has_pseudo_msg = 1;
	ve_veshm_req.pseudo_msg = ve_veshm_req_msg;

	ret = exchange_request(handle, &ve_veshm_req, &ret_msg);
	if (ret != 0 ){
		IVED_ERROR(log4cat_pseudo_ived, 
			   "Failed to communicate with VEOS");
		fprintf(stderr, "Failed to communicate with VEOS\n");
		pseudo_abort();
	} 
	
	if (ret_msg->syscall_retval == 2 /* PG_HP */)
		retval = PGSIZE_64M;
	else if (ret_msg->syscall_retval == 1 /* PG_2M */)
		retval = PGSIZE_2M;
	else if (ret_msg->syscall_retval == 0 /* PG_4K */)
		retval = PGSIZE_4K;
	else
		retval = ret_msg->syscall_retval;

	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	return(retval);
}

