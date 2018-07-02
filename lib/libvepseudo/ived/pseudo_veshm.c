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
 * @file pseudo_veshm.c  
 * @brief VESHM functions (Pseudo process)
 *
 * @internal
 * @author VESHM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <sys/types.h>

#include "pseudo_veshm.h"
#include "libved.h"
#include "mm_transfer.h"
#include "syscall.h"
#include "sys_mm.h"
#include "ived_common.h"
#include "veos_defs.h"
#include "comm_request.h"
#include "ived_request.h"
#include "handle.h"
#include "proto_buff_schema.pb-c.h"
#include "ve_socket.h"
#include "pseudo_ived_common.h"
#include "vemva_mgmt.h"
#include "pseudo_veshm_pgmode.h"

#define	VESHM_MAX_ARGS	5

int veshm_test = 0;

/**
 * @brief System call function for VESHM open.
 *
 * @param [in]     args  Arguments of the system call
 * @param [in]     handle veos_handle
 */
int 
pseudo_veshm_open(uint64_t *args, veos_handle *handle)
{

	/* Use ve_shm_request() as a reference for 
	 * exchanging messages.
	 */

	int ret, retval = 0;

	/* request */
	struct veshm_args veshm_param;
	PseudoVeosMessage ve_veshm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_veshm_req_msg;

	/* reply */
	PseudoVeosMessage *ret_msg = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "PASS");

	if (args == NULL || handle == NULL){
		IVED_CRIT(log4cat_pseudo_ived, 
			  "Internal error: Argument is NULL");
		return(-ECANCELED);
	}

	/* Generate IPC Command */
	veshm_param.subcmd    = VESHM_OPEN;
	veshm_param.arg.args_veshm_sub_open.vemva     = args[1];
	veshm_param.arg.args_veshm_sub_open.size      = args[2];
	veshm_param.arg.args_veshm_sub_open.syncnum   = args[3];
	veshm_param.arg.args_veshm_sub_open.mode_flag = args[4];

	ve_veshm_req_msg.len = sizeof(struct veshm_args);
	ve_veshm_req_msg.data = (uint8_t *)&veshm_param;	

	ve_veshm_req.pseudo_veos_cmd_id = CMD_VESHM;
	ve_veshm_req.has_pseudo_pid = true;
	ve_veshm_req.pseudo_pid = syscall(SYS_gettid);
	ve_veshm_req.has_pseudo_msg = true;
	ve_veshm_req.pseudo_msg = ve_veshm_req_msg;

	ret = exchange_request(handle, &ve_veshm_req, &ret_msg);
	if (ret != 0 ){
		IVED_ERROR(log4cat_pseudo_ived, 
			   "Failed to send VESHM request. (%d)", ret);
		fprintf(stderr, "Failed to send VESHM request to VEOS.\n");
		pseudo_abort();
	} else {
		retval = ret_msg->syscall_retval;
	}
	if (retval == -ESRCH)
		retval = -ECANCELED;

	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	if (retval < 0)
		IVED_INFO(log4cat_pseudo_ived, 
			  "VESHM registration request failed (err:%d)", 
			  -retval);
	return(retval);
}

/**
 * @brief System call function for VESHM attach
 *
 * @param [in]     args  Arguments of the system call
 * @param [in]     handle veos_handle
 */
int64_t
pseudo_veshm_attach(uint64_t *args, veos_handle *handle)
{
	int ret;
	int64_t retval = -ECANCELED;
	uint64_t mode_flag;
	uint64_t size; 
	int64_t attached_vemva = (int64_t)NULL;
	int64_t local_pgsize;
	uint64_t flag;
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

	/* Generate IPC Command #1 */
	veshm_param.subcmd    = VESHM_ATTACH;
	veshm_param.arg.args_veshm_sub_attach.owner_pid = (uint32_t)args[1];
	veshm_param.arg.args_veshm_sub_attach.vemva     = args[2];
	veshm_param.arg.args_veshm_sub_attach.size      = args[3];
	veshm_param.arg.args_veshm_sub_attach.syncnum   = (uint32_t)args[4];
	veshm_param.arg.args_veshm_sub_attach.mode_flag = args[5];

	/* If VE_REGISTER_VEMVA, get vemva for a VESHM user */
	mode_flag = veshm_param.arg.args_veshm_sub_attach.mode_flag;
	size      = veshm_param.arg.args_veshm_sub_attach.size;
	if (isset_flag(mode_flag, VE_REGISTER_VEMVA)){
		local_pgsize = pseudo_veshm_get_pgmode /* ve_get_pgmode */
			(handle, (uint8_t)VE_ADDR_VEMVA, 
			 veshm_param.arg.args_veshm_sub_attach.owner_pid,
			 veshm_param.arg.args_veshm_sub_attach.vemva);
		if (local_pgsize < 0){
			retval = -EINVAL;
			goto err_ret;
		} else if (local_pgsize == PGSIZE_2M){
			flag = MAP_2MB;
		} else {
			flag = MAP_64MB;
		}
		flag |= MAP_PRIVATE | MAP_ANON | MAP_VESHM;

		attached_vemva = (int64_t)ve_get_vemva
			(handle, (uint64_t)NULL, size, flag, 
			 PROT_READ|PROT_WRITE, -1, 0);
		if (attached_vemva < 0){
			retval = -ENOMEM;
			goto err_ret;
		}
		veshm_param.arg.args_veshm_sub_attach.user_vemva 
			= attached_vemva;
	} else {
		veshm_param.arg.args_veshm_sub_attach.user_vemva = -1;
	}


	/* Generate IPC Command #2 */
	ve_veshm_req_msg.len = sizeof(struct veshm_args);
	ve_veshm_req_msg.data = (uint8_t *)&veshm_param;	

	ve_veshm_req.pseudo_veos_cmd_id = CMD_VESHM;
	ve_veshm_req.has_pseudo_pid = true;
	ve_veshm_req.pseudo_pid = syscall(SYS_gettid);
	ve_veshm_req.has_pseudo_msg = true;
	ve_veshm_req.pseudo_msg = ve_veshm_req_msg;

	ret = exchange_request(handle, &ve_veshm_req, &ret_msg);
	if (ret != 0 ){
		IVED_ERROR(log4cat_pseudo_ived, 
			   "Failed to send VESHM request. (%d)", ret);
		fprintf(stderr, "Failed to send VESHM request to VEOS.\n");
		pseudo_abort();
	} else {
		retval = ret_msg->syscall_retval;
	}

	if (isset_flag(mode_flag, VE_REGISTER_VEMVA)){
		if (retval != attached_vemva){
			IVED_DEBUG(log4cat_pseudo_ived, 
				   "The VESHM has been attached.");
			/* Free unnecessary VEMVA */
			ve_free_vemva((void *)attached_vemva, size);
		}
	}

	pseudo_veos_message__free_unpacked(ret_msg, NULL);

err_ret:
	if (retval < 0)
		IVED_INFO(log4cat_pseudo_ived, 
			  "VESHM attaching request failed (err:%d)", 
			  (int)-retval);
	return(retval);
}


/**
 * @brief System call function for VESHM detach
 *
 * @param [in]     args  Arguments of the system call
 * @param [in]     handle veos_handle
 *
 * @retval 0 on success, -errno on failure.
 */
int 
pseudo_veshm_detach(uint64_t *args, veos_handle *handle)
{
	int ret, retval;
	uint64_t size, address, mode_flag;

	/* request */
	struct veshm_args veshm_param;
	PseudoVeosMessage ve_veshm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_veshm_req_msg;
	/* reply */
	PseudoVeosMessage *ret_msg = NULL;
	struct ived_sub_reply reply_msg;

	IVED_TRACE(log4cat_pseudo_ived, "PASS");

	if (args == NULL || handle == NULL){
		IVED_CRIT(log4cat_pseudo_ived, 
			  "Internal error: Argument is NULL");
		return(-ECANCELED);
	}

	/* Generate IPC Command */
	address = args[1];
	mode_flag = args[2];

	veshm_param.subcmd    = VESHM_DETACH;
	veshm_param.arg.args_veshm_sub_detach.address   = args[1];
	veshm_param.arg.args_veshm_sub_detach.mode_flag = args[2];

	ve_veshm_req_msg.len = sizeof(struct veshm_args);
	ve_veshm_req_msg.data = (uint8_t *)&veshm_param;	

	ve_veshm_req.pseudo_veos_cmd_id = CMD_VESHM;
	ve_veshm_req.has_pseudo_pid = true;
	ve_veshm_req.pseudo_pid = syscall(SYS_gettid);
	ve_veshm_req.has_pseudo_msg = true;
	ve_veshm_req.pseudo_msg = ve_veshm_req_msg;

	ret = exchange_request(handle, &ve_veshm_req, &ret_msg);
	if (ret != 0 ){
		IVED_ERROR(log4cat_pseudo_ived, 
			   "Failed to send VESHM request. (%d)", ret);
		fprintf(stderr, "Failed to send VESHM request to VEOS.\n");
		pseudo_abort();
	}
	retval = ret_msg->syscall_retval;

	/* If VE_REGISTER_VEMVA, free vemva for a VESHM user */
	memcpy(&reply_msg, ret_msg->pseudo_msg.data, ret_msg->pseudo_msg.len);

	if (isset_flag(mode_flag, VE_REGISTER_VEMVA)){
		if ((reply_msg.num == 0)
		    && reply_msg.size != 0){
			size = reply_msg.size;
			ve_free_vemva((void *)address, size);
		}
	}

	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	if (retval == -ECANCELED){
		/* Even though IVED or VEOS fails an IPC request, a detach 
		 * request returns succecss. */
		retval = 0;
	} else if (retval == -ESRCH){
		retval = -ECANCELED;
	}

	if (retval < 0)
		IVED_INFO(log4cat_pseudo_ived, 
			  "VESHM detaching request failed (err:%d)", 
			  -retval);
	return(retval);
}


/**
 * @brief System call function for VESHM close
 *
 * @param [in]     args  Arguments of the system call
 * @param [in]     handle veos_handle
 *
 * @retval 0 on success, -errno on failure.
 */
int 
pseudo_veshm_close(uint64_t *args, veos_handle *handle)
{
	int ret, retval = -ECANCELED;
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
	veshm_param.subcmd = VESHM_CLOSE;
	veshm_param.arg.args_veshm_sub_close.vemva   = args[1];
	veshm_param.arg.args_veshm_sub_close.size    = args[2];
	veshm_param.arg.args_veshm_sub_close.syncnum = args[3];
	veshm_param.arg.args_veshm_sub_close.mode_flag = args[4];

	ve_veshm_req_msg.len = sizeof(struct veshm_args);
	ve_veshm_req_msg.data = (uint8_t *)&veshm_param;	

	ve_veshm_req.pseudo_veos_cmd_id = CMD_VESHM;
	ve_veshm_req.has_pseudo_pid = true;
	ve_veshm_req.pseudo_pid = syscall(SYS_gettid);
	ve_veshm_req.has_pseudo_msg = true;
	ve_veshm_req.pseudo_msg = ve_veshm_req_msg;

	ret = exchange_request(handle, &ve_veshm_req, &ret_msg);
	if (ret != 0 ){
		IVED_ERROR(log4cat_pseudo_ived, 
			   "Failed to send VESHM request. (%d)", ret);
		fprintf(stderr, "Failed to send VESHM request to VEOS.\n");
		pseudo_abort();
	} else {
		retval = ret_msg->syscall_retval;
	}
	if (retval == -ESRCH)
		retval = -ECANCELED;

	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	if (retval < 0)
		IVED_INFO(log4cat_pseudo_ived, 
			  "VESHM erasing request failed (err:%d)", 
			  -retval);
	return(retval);
}


/**
 * @brief The common entry function for VESHM 
 *
 * It checks subcmd and invokes a specific function.
 *
 * @param [in]     handle veos_handle
 * @param [in]     args		Array of system call arguments
 *
 * @return return value of each request
 */
ret_t /* uint64_t */
ve_veshm(veos_handle *handle, uint64_t *args)
{
	int ret;
	int subcmd;
	/* uint64_t *args; */
	int64_t retval;	/* return value of system call */
	uint64_t veshm_args[VESHM_MAX_ARGS+1];

	if (args == NULL || handle == NULL){
		IVED_CRIT(log4cat_pseudo_ived, 
			  "Internal error: Argument is NULL");
		return(-ECANCELED);
	}

	/* Read system call arguments (index: 0-4) */
	subcmd  = (int) args[0];

	IVED_DEBUG(log4cat_pseudo_ived, "subcmd:%d", subcmd);

	/* VESHM is available only a 64MB binary at the
	 * first version. */
	if ((default_page_size == PGSIZE_2M) 
	    && (veshm_test == 0) ){
		switch(subcmd){
		case VESHM_OPEN:
		case VESHM_ATTACH:
		case VESHM_DETACH:
		case VESHM_CLOSE:
			IVED_ERROR(log4cat_pseudo_ived, 
				   "VESHM for 2MB binary is not available.");
			return(-ENOTSUP);
		}
	}

	switch(subcmd){
	case VESHM_OPEN:
		retval = pseudo_veshm_open(args, handle);
		break;

	case VESHM_ATTACH:
		veshm_args[0] = args[0];
		ret = ve_recv_data(handle, args[1],
				   sizeof(uint64_t)*VESHM_MAX_ARGS,
				   &veshm_args[1]);
		if (ret != 0){
			IVED_ERROR(log4cat_pseudo_ived, 
				   "Load arguments failed:%"PRIx64"\n", 
				   args[2]);
			retval = -EINVAL;
			break;
		}

		retval = pseudo_veshm_attach(veshm_args, handle);
		break;

	case VESHM_DETACH:
		retval = pseudo_veshm_detach(args, handle);
		break;

	case VESHM_CLOSE:
		retval = pseudo_veshm_close(args, handle);
		break;

	case VESHM_PGSIZE: 
		retval = pseudo_get_pgsize(args, handle);
		break;

	default:
		IVED_ERROR(log4cat_pseudo_ived,
			   "Invalid command: %#x", subcmd);
		retval = -EINVAL;
		break;
	}

	IVED_DEBUG(log4cat_pseudo_ived,"retval=%"PRIx64"",retval);

	/* Return a value by sysve(). */
	return (retval);

}
