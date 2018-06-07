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
 * @file ived_ipc_func.c  
 * @brief IPC functions in IVED
 *
 * @internal
 * @author VESHM
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <uuid/uuid.h>
#include "ived.h"
#include "libved.h"
#include "ived_main.h"
#include "ived_common.h"
#include "ived_ipc.h"
#include "ived.pb-c.h"


/**
 * @brief Entry point of IVED common functions
 *
 * It unpacks payload which is packed by protocol buffer, and call 
 * a function specified by sub command in the payload.
 *
 * @param [in]  pti Thread argument
 *
 * @return 0 on success, -1 on failure
 */
int 
ived_handle_daemon_request(ived_thread_arg_t *pti) 
{
	int ret;
	int retval = 0;
	RpcIvedArg	*request;
	struct veos_info *os_info = NULL;

	int rpc_retval = 0;	/* Return value of RPC message */
	int rpc_reterr = 0;	/* Return error of RPC message */

	IVED_TRACE(log4cat_main, "PASS");

	if (pti == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return (-1);
	}

	if (pti->request == NULL || pti->request->ived == NULL){
		IVED_CRIT(log4cat_main, "No ived argument from OS:%d",
			  pti->cred.pid);
		rpc_retval = IVED_REQ_NG;
		rpc_reterr = -ECANCELED;
		retval = -1;
		goto err_ret;
	}

	request = pti->request->ived;

	IVED_DEBUG(log4cat_main, "New request pid:%d, subcmd:%#x",
		   pti->cred.pid, request->subcmd);

	/* Check whether a requester is a valid user. It should be 
	 * registered veos_info[]. */
	os_info = get_osinfo_struct(pti->cred.pid);
	if ( os_info == NULL ){
		if (request->subcmd != IVED_OS_REG){
			rpc_retval = IVED_REQ_NG;
			rpc_reterr = -ECANCELED;
			retval = -1;
			goto err_ret;
		}
	} else {
		/* A requester has been registered. */
		pthread_mutex_unlock(&os_info->os_lock);
	}

	switch(request->subcmd){
	case IVED_OS_REG:
		ret = ived_register_osdata(pti, request);
		if (ret == 0){
			pti->socket_not_close = 1;
		}
		break;

	case IVED_OS_STOP:
		ived_erase_osdata(pti, request);
		break;

	case IVED_PROC_REG:
		ived_register_procdata(pti, request);
		break;

	case IVED_PROC_ERASE:
		ived_erase_procdata(pti, request);
		break;

	default:
		IVED_ERROR(log4cat_main, "Invalid command");
		rpc_retval = IVED_REQ_NG;
		rpc_reterr = -EINVAL;
		retval = -1;
		goto err_ret;
	}

err_ret:
	if (retval == -1){
		IVED_DEBUG(log4cat_main, "Send error");
		ived_send_int64(pti->socket_descriptor, 
				rpc_retval, rpc_reterr);
	}
	IVED_DEBUG(log4cat_main, "TID[%u] A request finished. retval: %d", 
		   (uint)pthread_self(), retval);
	return (retval);
}
