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
 * @file veos_veshm_interface.c  
 * @brief VESHM interfaces in VEOS
 *
 * @internal
 * @author VESHM
 */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <pthread.h>
#include <errno.h>

#include <veos_arch_defs.h>

#include "libved.h"
#include "comm_request.h"
#include "proto_buff_schema.pb-c.h"
#include "ve_memory.h"
#include "vehva_mgmt.h"

#include "veos_veshm.h"
#include "veos_veshm_core.h"
#include "veos_ived.h"
#include "veos_ived_common.h"
#include "veos_ived_misc.h"
#include "ived_ipc.h"
#include "ived.pb-c.h"
#include "ived_common.h"
#include "veos_veshm_ipc.h"
#include "veshm_defs.h"

#define REPLY_OK	0
#define REPLY_NG	-ECANCELED

#define LOCK_TIMEOUT 10      /* seconds */
#define INVALID_VEHVA	0xFFFFFFFFFFFFFFFFll

/**
 * @brief VESHM open for VE program
 *
 * Register a user memory as VESHM.
 *
 * @param [in]    pti  Containing REQ info
 *
 * @return 0 on success, -1 and set errno on failure
 */
static int
veos_veshm_open(veos_thread_arg_t *pti, struct veshm_args *subcmd,
		struct ucred *cred)
{
	int ret = -1;
	int rpc_retval = -ECANCELED;
	int open_2_steps = 0;
	uint64_t mode_flag_ro = 0;

	RpcVeshmSubOpen request_open = RPC_VESHM_SUB_OPEN__INIT;

	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	assert(pti    !=  NULL);
	assert(subcmd !=  NULL);
	assert(cred   !=  NULL);

	if (pti == NULL || subcmd == NULL || cred == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		rpc_retval = -ECANCELED;
		goto err_ret;
	}

	request_open.uid	 = cred->uid;
	request_open.pid_of_owner= cred->pid;
	request_open.vemva	 = subcmd->arg.args_veshm_sub_open.vemva;
	request_open.size	 = subcmd->arg.args_veshm_sub_open.size;
	request_open.syncnum     = subcmd->arg.args_veshm_sub_open.syncnum;
	request_open.mode_flag	 = subcmd->arg.args_veshm_sub_open.mode_flag;

	if (isset_flag(request_open.mode_flag, VE_SYS_FLAG_MASK)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM registration: %s",
			   strerror(EINVAL));
		rpc_retval = -EINVAL;
		goto err_ret;
	}

	/* For MPI, when mode_flag is VE_REGISTER_PCI | VE_SWAPPABLE,
	 * set open_2_steps = 1, invoke veos_veshm_open_common() 2 times,
	 * 1st, with VE_REGISTER_PCI | VE_SWAPPABLE,
	 * 2nd, with VE_REGISTER_NONE
	 */
	if (isset_flag(request_open.mode_flag, VE_REGISTER_PCI)
		&& isset_flag(request_open.mode_flag, VE_SWAPPABLE)) {
		open_2_steps = 1;

		if (isset_flag(request_open.mode_flag, VE_SHM_RO))
			mode_flag_ro = mode_flag_ro | VE_SHM_RO;
	}

	set_flag(request_open.mode_flag, VE_REQ_PROC);

	reply.veshm_ret = &veshm_ret;

	ret = veos_veshm_open_common(&request_open, &reply, 0);
	if (ret != 0){
		/* Function failed or IVED returns an error. */
		rpc_retval = reply.error;
		ret = -1;
	} else {
		rpc_retval = reply.retval;
	}

	if((ret == 0) && (open_2_steps == 1)) {
		request_open.mode_flag = mode_flag_ro | VE_REGISTER_NONE | VE_REQ_PROC;
		ret = veos_veshm_open_common(&request_open, &reply, 0);
		if (ret != 0){
			/* Function failed or IVED returns an error. */
			rpc_retval = reply.error;
			ret = -1;
		} else {
			rpc_retval = reply.retval;
		}
	}

err_ret:
	/*  NOTE: A data structure "reply" has VHSAA (for _internal),
	 *  so DON'T return  the data structure "reply". */
	if (pti != NULL)
		veos_ived_reply(rpc_retval, NULL, pti);

	IVED_DEBUG(log4cat_veos_ived, "VESHM registration finished");

	return(ret);
}

/**
 * @brief VESHM open for VEOS component (VE Memory mapping)
 *
 * NOTE: Always VESHM open for VEOS component creates
 * a PCI addresses array of a requested VESHM.
 * A caller must manage (or clear) the memory every invoking.
 *
 * @param [in]     uid		UID of PCIATB user
 * @param [in]     pid		PID of PCIATB user
 * @param [in]     vemva	VEMVA of "pid" process
 * @param [in]     size		Memory size 
 * @param [in]     syncnum	PCISYNC pair number
 * @param [in]     mode_flag	Mode flag
 * @param [out]    uuid_veshm   stored address for uuid
 * @param [out]    pci_address  Pointer of allocated PCI addresses array (-1 terminated)
 *
 * @return number of pci_address entries on success, -1 on failure
 */
uint64_t
veshm_open_internal(int uid, int pid, uint64_t vemva, uint64_t size, 
		    int syncnum, uint64_t mode_flag, uuid_t *uuid_veshm,
		    uint64_t **pci_address)
{
	uint64_t ret = IVED_REQ_NG;
	RpcVeshmSubOpen request_open = RPC_VESHM_SUB_OPEN__INIT;

	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	if (IVED_LINKAGE_OFF){
		IVED_DEBUG(log4cat_veos_ived,"IVED is unavailable.");
		errno = ENOTSUP;
		goto err_ret;
	}

	if (uuid_veshm == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		errno = ECANCELED;
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veos_ived, "New request from pid: %d subcmd:%#x",
		   pid, VESHM_OPEN);

	request_open.uid	  = uid;
	request_open.pid_of_owner = pid;
	request_open.vemva	  = vemva;
	request_open.size	  = size;
	request_open.syncnum      = syncnum;
	request_open.mode_flag	  = mode_flag;

	if (isset_flag(request_open.mode_flag, VE_SYS_FLAG_MASK)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM registration: %s",
			   strerror(EINVAL));
		errno = EINVAL;
		goto err_ret;
	}
	set_flag(request_open.mode_flag, VE_REQ_DEV);

	reply.veshm_ret = &veshm_ret;

	ret = veos_veshm_open_common(&request_open, &reply, 0);

	if (ret != 0){
		errno = -reply.error;
		ret = -1;
	} else {
		ret	     = veshm_ret.n_pci_address; 
		*pci_address = veshm_ret.pci_address;
		memcpy(uuid_veshm, veshm_ret.uuid_veshm.data, 
		       sizeof(uuid_t));
		dump_uuid("veshm", *uuid_veshm);
	}

err_ret:
	return (ret);
}

/*
 * @brief VESHM attach for VE program
 *
 * Attach a target VESHM to the requester's VEHVA space 
 *
 * @param [in]    pti  Containing REQ info
 *
 * @return 0 on success, -errno on failure
 */
static int
veos_veshm_attach(veos_thread_arg_t *pti, struct veshm_args *subcmd,
		  struct ucred *cred)
{
	int ret;
	uint64_t rpc_retval = -ECANCELED;
	uint64_t mode_flag_ro = 0;

	/* To IVED */
	RpcVeshmSubAttach request_attach = RPC_VESHM_SUB_ATTACH__INIT;

	/* To pseudo process */
	IvedReturn reply = IVED_RETURN__INIT;	
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	IVED_TRACE(log4cat_veos_ived, "PASS");
	assert(pti    !=  NULL);
	assert(subcmd !=  NULL);
	assert(cred   !=  NULL);

	if (pti == NULL || subcmd == NULL || cred == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		rpc_retval = -ECANCELED;
		goto err_ret;
	}

	request_attach.user_uid  = (uint32_t)cred->uid;
	request_attach.user_pid  = (uint32_t)cred->pid;
	request_attach.user_vemva= (uint64_t)
		subcmd->arg.args_veshm_sub_attach.user_vemva;

	/* Convert owner pid which specified by an API argument. */
	request_attach.owner_pid = (uint32_t)
		vedl_host_pid(VE_HANDLE(0), cred->pid,
			      subcmd->arg.args_veshm_sub_attach.owner_pid);

	request_attach.vemva	 = (uint64_t)
		subcmd->arg.args_veshm_sub_attach.vemva;
	request_attach.size	 = (uint64_t)
		subcmd->arg.args_veshm_sub_attach.size;
	request_attach.syncnum   = (uint32_t)
		subcmd->arg.args_veshm_sub_attach.syncnum;
	request_attach.mode_flag = (uint64_t)
		subcmd->arg.args_veshm_sub_attach.mode_flag;

	if (isset_flag(request_attach.mode_flag, VE_SYS_FLAG_MASK)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM attaching: %s",
			   strerror(EINVAL));
		rpc_retval = -EINVAL;
		goto err_ret;
	}

	/* For MPI, when mode_flag is
	 * VE_REGISTER_PCI | VE_SWAPPABLE | VE_REGISTER_VEMVA
	 * change mode_flag to VE_REGISTER_NONE | VE_REGISTER_VEMVA
	 */
	if (isset_flag(request_attach.mode_flag, VE_REGISTER_PCI)
			&& isset_flag(request_attach.mode_flag, VE_SWAPPABLE)
			&& isset_flag(request_attach.mode_flag, VE_REGISTER_VEMVA)) {
		if (isset_flag(request_attach.mode_flag, VE_SHM_RO))
			mode_flag_ro = mode_flag_ro | VE_SHM_RO;

		request_attach.mode_flag = mode_flag_ro
			| VE_REGISTER_NONE | VE_REGISTER_VEMVA;
	}

	set_flag(request_attach.mode_flag, VE_REQ_PROC);

	reply.veshm_ret = &veshm_ret;

	IVED_DEBUG(log4cat_veos_ived,
		   "VESHM attaching request for pid:%d (host pid:%d)",
		   subcmd->arg.args_veshm_sub_attach.owner_pid,
		   request_attach.owner_pid);

	ret = veos_veshm_attach_common(&request_attach, &reply, INVALID_VEHVA);
	if (ret != 0){
		/* Function failed or IVED returns an error. */
		rpc_retval = (uint64_t)reply.error;
	} else {
		rpc_retval = veshm_ret.address;
	}

err_ret:
	IVED_DEBUG(log4cat_veos_ived, "VESHM attaching finished"); 

	if (pti != NULL)
		veos_ived_reply(rpc_retval, NULL, pti);
	return(rpc_retval);
}


/*
 * @brief VESHM detach for VE program
 *
 * Detach a target VESHM to the requester's VEHVA space 
 *
 * @param [in]    pti  Containing REQ info
 *
 * @return 0 on success, -1 on failure
 */
static int
veos_veshm_detach(veos_thread_arg_t *pti, struct veshm_args *subcmd,
		  struct ucred *cred)
{
	int ret = -1;
	int rpc_retval = -ECANCELED;
	struct ived_sub_reply retval_st; 

	/* To IVED */
	RpcVeshmSubDetach request_detach = RPC_VESHM_SUB_DETACH__INIT;

	/* To pseudo process */
	IvedReturn reply = IVED_RETURN__INIT;	
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;

	assert(pti    !=  NULL);
	assert(subcmd !=  NULL);
	assert(cred   !=  NULL);

	if (pti == NULL || subcmd == NULL || cred == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		rpc_retval = -ECANCELED;
		goto err_ret;
	}

	request_detach.user_uid   = cred->uid;
	request_detach.user_pid   = cred->pid;
	request_detach.address    = subcmd->arg.args_veshm_sub_detach.address;
	request_detach.mode_flag  = subcmd->arg.args_veshm_sub_detach.mode_flag;

	if (isset_flag(request_detach.mode_flag, VE_SYS_FLAG_MASK)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM detaching: %s",
			   strerror(EINVAL));
		rpc_retval = -EINVAL;
		goto err_ret;
	}
	set_flag(request_detach.mode_flag, VE_REQ_PROC);

	reply.veshm_ret = &veshm_ret;

	ret = veos_veshm_detach_common(&request_detach, &reply);
	if (ret != 0){
		/* Function failed */
		rpc_retval = reply.error;
		retval_st.size = 0;
		retval_st.num  = (uint32_t)-1;
		ret = -1;
	} else {
		rpc_retval = reply.retval;
		retval_st.size = veshm_ret.size;
		retval_st.num  = veshm_ret.counts;
	}

err_ret:
	if (pti != NULL)
		veos_ived_reply(rpc_retval, &retval_st, pti);
	IVED_DEBUG(log4cat_veos_ived, "VESHM detaching finished"); 

	return(ret);
}


/*
 * @brief VESHM close for VE program
 *
 * Close a target VESHM to the requester's VEHVA space 
 *
 * @param [in]    pti  Containing REQ info
 *
 * @return 0 on success, -1 on failure
 */
static int
veos_veshm_close(veos_thread_arg_t *pti, struct veshm_args *subcmd,
		 struct ucred *cred)
{
	int ret = -1;
	int rpc_retval = -ECANCELED;
	int ret_2 = -1;
	int rpc_retval_2 = -ECANCELED;
	ProtobufCBinaryData uuid_data1;
	int close_2_steps = 0;
	uint64_t mode_flag_ro = 0;

	RpcVeshmSubClose request_close = RPC_VESHM_SUB_CLOSE__INIT;
	IvedReturn reply = IVED_RETURN__INIT;
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;
	reply.veshm_ret = &veshm_ret;

	assert(pti    !=  NULL);
	assert(subcmd !=  NULL);
	assert(cred   !=  NULL);

	if (pti == NULL || subcmd == NULL || cred == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		rpc_retval = -ECANCELED;
		goto err_ret;
	}

	request_close.owner_uid  = cred->uid;
	request_close.owner_pid  = cred->pid;
	request_close.vemva      = subcmd->arg.args_veshm_sub_close.vemva;
	request_close.size	 = subcmd->arg.args_veshm_sub_close.size;
	request_close.syncnum    = subcmd->arg.args_veshm_sub_close.syncnum;
	request_close.mode_flag	 = subcmd->arg.args_veshm_sub_close.mode_flag;

	/* VE_MAP_256MB is specified, but not VE3 */
	if ( (isset_flag(request_close.mode_flag, VE_MAP_256MB))
		&& (VE_NODE(0)->ve_type != VE_TYPE_VE3)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM closing: %s",
			strerror(EINVAL));
		rpc_retval = -EINVAL;
		goto err_ret;
	}

	/* invalid flag */
	if (isset_flag(request_close.mode_flag, VE_SYS_FLAG_MASK)){
		IVED_DEBUG(log4cat_veos_ived, "VESHM closing: %s",
			   strerror(EINVAL));
		rpc_retval = -EINVAL;
		goto err_ret;
	}
	if ( isset_flag(request_close.mode_flag,
			~(VE_SHM_RO | VE_PCISYNC 
			  | VE_REGISTER_PCI | VE_REGISTER_NONE
			  | VE_MAP_256MB | VE_SWAPPABLE))){
		rpc_retval = -EINVAL;
		goto err_ret;
	}

	/* If VE_SWAPPABLE is specified. VE_REGISTER_PCI must be specified.*/
	if ( isset_flag(request_close.mode_flag, VE_SWAPPABLE)
		&& !(isset_flag(request_close.mode_flag, VE_REGISTER_PCI)) ){
		rpc_retval = -EINVAL;
		goto err_ret;
	}

	/* For MPI, when mode_flag is VE_REGISTER_PCI | VE_SWAPPABLE,
	 * set close_2_steps = 1, invoke veos_veshm_close_common() 2 times,
	 * 1st, with VE_REGISTER_PCI | VE_SWAPPABLE,
	 * 2nd, with VE_REGISTER_NONE
	 */
	if (isset_flag(request_close.mode_flag, VE_SWAPPABLE)
		&& (isset_flag(request_close.mode_flag, VE_REGISTER_PCI)) ){
		close_2_steps = 1;

		if (isset_flag(request_close.mode_flag, VE_SHM_RO))
			mode_flag_ro = mode_flag_ro | VE_SHM_RO;
	}

	set_flag(request_close.mode_flag, VE_REQ_PROC);

	uuid_data1.len             = sizeof(uuid_t);
	uuid_data1.data            = (uint8_t *)null_id;
	request_close.has_uuid_veshm  = 1;
	request_close.uuid_veshm      = uuid_data1;

	ret = veos_veshm_close_common(&request_close, &reply, NULL, NULL);
	if (ret != 0){
		rpc_retval = reply.error;
		ret = -1;
	} else {
		rpc_retval = 0;
	}

	if (close_2_steps == 1) {
		request_close.has_uuid_veshm  = 1;
		request_close.uuid_veshm      = uuid_data1;
		request_close.mode_flag = mode_flag_ro | VE_REGISTER_NONE | VE_REQ_PROC;
		ret_2 = veos_veshm_close_common(&request_close, &reply, NULL, NULL);
		if (ret_2 != 0){
			rpc_retval_2 = reply.error;
			ret_2 = -1;
			if (ret == 0){
				ret = ret_2;
				rpc_retval = rpc_retval_2;
			}
		} else {
			rpc_retval_2 = 0;
		}
	}
err_ret:
	if (pti != NULL)
		veos_ived_reply(rpc_retval, NULL, pti);
	IVED_DEBUG(log4cat_veos_ived, "VESHM closing finished"); 

	return(ret);
}


/**
 * @brief VESHM close for VEOS component (VE Memory mapping)
 *
 * @param [in]     uid		UID of a requester
 * @param [in]     pid		PID of the owner process
 * @param [in]     vemva	VEMVA of "pid" process
 * @param [in]     size		Memory size 
 *
 * @return 0 on success, -1 and set errno on failure
 */
int 
veshm_close_internal(uuid_t uuid_veshm, int owner_pid) 
{ 
	int ret = IVED_REQ_NG;
	/* To IVED */
	RpcVeshmSubClose request_close = RPC_VESHM_SUB_CLOSE__INIT;
	ProtobufCBinaryData uuid;

	/* Store a result of a request (but not used) */
	IvedReturn reply = IVED_RETURN__INIT;	
	RpcVeshmReturn veshm_ret = RPC_VESHM_RETURN__INIT;
	reply.veshm_ret = &veshm_ret;

	if (IVED_LINKAGE_OFF){
		IVED_DEBUG(log4cat_veos_ived,"IVED is unavailable.");
		errno = ENOTSUP;
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veos_ived, "New request from pid: %d subcmd:%#x",
		   owner_pid, VESHM_CLOSE);

	request_close.owner_uid     = 0;
	request_close.owner_pid     = owner_pid;
	request_close.vemva	    = 0;
	request_close.size	    = 0;
	request_close.syncnum	    = 0;
	set_flag(request_close.mode_flag, VE_REQ_DEV);

	uuid.len		    = sizeof(uuid_t);
	uuid.data                   = (uint8_t *)uuid_veshm;
	request_close.has_uuid_veshm = true;
	request_close.uuid_veshm     = uuid;

	ret = veos_veshm_close_common(&request_close, &reply, NULL, NULL);

	IVED_DEBUG(log4cat_veos_ived, "ret:%d, reply.ret_val:%"PRIx64"", 
		   ret, reply.retval);
	if (ret != 0)
		errno = -reply.error;

err_ret:
	return(ret);
}


/**
 * @brief Interface for get_pgmode system call 
 *
 * @param [in]    pti    Containing REQ info
 * @param [in]    subcmd Request
 *
 * @return 0 on success, -1 on failure
 *
 */
static int 
get_pgmode_syscall(veos_thread_arg_t *pti, struct veshm_args *subcmd)
{
	int ret = -1;
	int rpc_reterr = 0;
	int8_t page_mode = 0;
	uint64_t mode_flag;
	pid_t host_pid;

	if (pti == NULL || subcmd == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	mode_flag = subcmd->arg.args_veshm_pgsize.mode_flag;
	
	ret = 0;
	if ( isset_flag(mode_flag, VE_ADDR_VEMVA) )
		ret++;
	if ( isset_flag(mode_flag, VE_ADDR_VEHVA) )
		ret++;
	if ( isset_flag(mode_flag, VE_ADDR_PCI) )
		ret++;
	if (ret != 1){
		rpc_reterr = -EINVAL;
		goto err_ret_invalid_arg;
	}

	host_pid = vedl_host_pid(VE_HANDLE(0),
				 pti->cred.pid,
				 (pid_t)subcmd->arg.args_veshm_pgsize.pid);

	page_mode = veos_get_pgmode
		((uint8_t)subcmd->arg.args_veshm_pgsize.mode_flag,
		 host_pid,
		 (uint64_t)subcmd->arg.args_veshm_pgsize.address);
	if (page_mode < 0){
		rpc_reterr = page_mode;	/* negative of errno */
		goto err_ret_invalid_arg;
	}

	veos_ived_reply((uint64_t)page_mode, NULL, pti);
	IVED_DEBUG(log4cat_veos_ived, "pid:%d(host pid:%d) rpc_retval:%d", 
		   (pid_t)subcmd->arg.args_veshm_pgsize.pid, host_pid,
		   page_mode);

	return(0); 

err_ret_invalid_arg:
err_ret:
	if (pti != NULL)
		veos_ived_reply(rpc_reterr, NULL, pti);
	return(-1); 
}



/**
 * @brief Common function for VESHM in VEOS.
 *
 * @param [in]    pti  Containing REQ info
 *
 * @return: On Success return 0 and -1 on function's failure
 */
int veos_veshm_veshmctl(veos_thread_arg_t *pti)
{
	/* "CMD_VESHM" */

	int ret, retval = 0;
	struct ucred cred;
	int ucred_size = sizeof(struct ucred);
	struct veshm_args request_msg;
	ProtobufCBinaryData *pseudo_cmd;


	if(IVED_LINKAGE_OFF){
		IVED_DEBUG(log4cat_veos_ived,"IVED is unavailable.");
		veos_ived_reply(-ENOTSUP, NULL, pti);
		retval = -1;
		goto err_ret;
	}

	if (pti ==  NULL){
		IVED_CRIT(log4cat_veos_ived,"Argument is null.");
		retval = -1;
		goto err_ret;
	}

	ret = getsockopt(pti->socket_descriptor,
			 SOL_SOCKET, SO_PEERCRED, &cred,
			 (socklen_t *)&ucred_size);
	if (ret!=0){
		IVED_ERROR(log4cat_veos_ived, "Getting credential failed.(%s)",
			   strerror(errno));
		veos_ived_reply(-ECANCELED, NULL, pti);
		retval = -1;
		goto err_ret;
	}

	pseudo_cmd = (ProtobufCBinaryData *)
		(&(((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg));

	if (pseudo_cmd->len <= 0){
		IVED_DEBUG(log4cat_veos_ived,"Invalid message length: %d", 
			   (int)pseudo_cmd->len);
		veos_ived_reply(-EAGAIN, NULL, pti);
		retval = -1;
		goto err_ret;
	}
	memcpy(&request_msg, pseudo_cmd->data, pseudo_cmd->len);


	IVED_DEBUG(log4cat_veos_ived, "New request from pid: %d subcmd:%#x",
		   cred.pid, request_msg.subcmd);

	switch (request_msg.subcmd){
	case VESHM_OPEN:
		veos_veshm_open(pti, &request_msg, &cred);
		break;
	case VESHM_ATTACH:
		veos_veshm_attach(pti, &request_msg, &cred);
		break;
	case VESHM_DETACH:
		veos_veshm_detach(pti, &request_msg, &cred);
		break;
	case VESHM_CLOSE:
		veos_veshm_close(pti, &request_msg, &cred);
		break;
	case VESHM_PGSIZE:
		get_pgmode_syscall(pti, &request_msg);
		break;

	default:
		IVED_ERROR(log4cat_veos_ived,
			   "Invalid request type. (%d)",
			   request_msg.subcmd);
		veos_ived_reply(-EINVAL, NULL, pti);
		retval = -1;
		break;
	}

err_ret:
	IVED_DEBUG(log4cat_veos_ived, "Request finished");
	return (retval);
}


