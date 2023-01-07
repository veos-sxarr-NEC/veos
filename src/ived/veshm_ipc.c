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
 * @file  veshm_interface.c
 * @brief Interface functions of VESHM 
 *
 * @internal
 * @author VESHM
 */
#define __USE_GNU
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <inttypes.h>
#include <uuid/uuid.h>
#include <signal.h>
#include "veshm_ipc.h"
#include "ve_list.h"
#include "ived_common.h"
#include "ived.pb-c.h"
#include "ived.h"
#include "ived_ipc.h"
#include "ived_core.h"
#include "veshm_core.h"
#include "ived_veshm_core.h"
#include "ived_main.h"

#define RETRY		3	/* Retry of a request */

/**
 * @brief Send SIGKILL to processes which use the booting VE node.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * os_lock
 *
 * @param [in] os_info   OS on which a target process exists
 *
 * @return 0 on success, -1 on failure
 */
int
ived_veshm_kill_remote_process(struct veos_info *os_info)
{
	int ret, retval = -1;
	int send_signal = 0;
	struct list_head *veshm_list_p, *proc_list_p = NULL;
	struct veshm_memory_info *entry_veshm = NULL;
	struct ived_resource_user *attach_proc = NULL;

	IVED_TRACE(log4cat_veshm, "PASS");

	if (os_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		assert(os_info == 0);
		return (-1);
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0){
		assert(ret == 0);
		return(retval);
	}

	/* Kill processes which use VESHM of a terminated VE node */
	list_for_each(veshm_list_p, &(os_info->veshm_mem_info_list)){
		entry_veshm = list_entry(veshm_list_p, 
					 struct veshm_memory_info, list);

		/* Get each VESHM attaching process and send SIGKILL */
		list_for_each(proc_list_p, &(entry_veshm->attach_proc_list)){
			attach_proc = list_entry(proc_list_p, 
						 struct ived_resource_user, 
						 list);
			send_signal = 1;
			kill(attach_proc->pid, SIGKILL);
		}
	}

	if (send_signal != 0){
		IVED_INFO(log4cat_veshm, "Terminate processes using VESHM on %s",
			  os_info->drv_socket_name);
	}
	return(0);
}


/**
 * @brief Main function of VESHM open
 *
 * @param [in]		tsk	Task structure
 * @param [in]		request	VESHM arguments of open request
 *
 * @return 0 on success, -1 on failure
 */
int 
ived_veshm_open(ived_thread_arg_t *pti, RpcVeshmArg *request)
{
	int ret, retval = -1;
	uint64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;
	uid_t req_uid;
	pid_t req_pid;
	uint64_t req_vemva, req_mode_flag, req_size;
	int req_syncnum;
	size_t req_n_pci_address;	/* # of allocated PCIATBs + 1 */
	uint64_t *req_pci_address;	/* -1 terminated array */

	uint64_t *pci_address = NULL;
	int os_pid;
	int *register_cnt;

	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	struct veshm_info_tracker *having_veshm = NULL;
	struct veshm_memory_info  *veshm_info = NULL;

	uint64_t checking_mask = (VESHM_MODE_SYNC | VESHM_MODE_PCIATB
				  | VESHM_MODE_RO);

	if (pti == NULL || request == NULL || request->open_arg == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	os_pid        = pti->cred.pid;
	req_uid       = request->open_arg->uid;
	req_pid       = request->open_arg->pid_of_owner;
	req_vemva     = request->open_arg->vemva;
	req_size      = request->open_arg->size;
	req_n_pci_address  = request->open_arg->n_pci_address;
	req_pci_address    = request->open_arg->pci_address;
	req_syncnum        = request->open_arg->syncnum;
	req_mode_flag      = request->open_arg->mode_flag;
	/* copying uuid_veshm and uuid_proc are done later. */

	IVED_DEBUG(log4cat_veshm, 
		   "requester pid: %d, mode_flag: %#"PRIx64"",
		   req_pid, req_mode_flag);

	if ( ((req_n_pci_address > 0) && (req_pci_address == NULL))
	     || ((req_n_pci_address == 0) && (req_pci_address != NULL)) ){
		rpc_reterr = -ECANCELED;
		IVED_ERROR(log4cat_veshm, 
			   "Received PCI data is invalid: num:%zu", 
			   req_n_pci_address);
		goto err_ret_nolock;
	}

	/* VEOS must not send the following flags as an open request */
	ret = 0;
	if (isset_flag(req_mode_flag, VESHM_MODE_CLOSE))
		ret++;
	if (isset_flag(req_mode_flag, VESHM_MODE_INVALID))
		ret++;
	if (ret != 0){
		rpc_reterr = -ECANCELED;
		IVED_DEBUG(log4cat_veshm, "Mode flag is invalid");
		assert(0);
		goto err_ret_nolock;
	}

	/* Get process info */
	search_node_proc_info(req_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_veshm, 
			   "VESHM registration: pid=%d data is not found", 
			   req_pid);
		goto err_ret_nolock;
	}

	if (os_info->os_pid != os_pid){
		test_os_state(os_info);
		rpc_reterr = -EACCES;
		IVED_ERROR(log4cat_veshm, "Invalid request from pid:%d",
			   pti->cred.pid);
		goto err_ret_unlock;
	}

	/* Pick up veshm info */
	having_veshm = search_veshm_tracker(&proc_info->having_veshm_info,
					    proc_info,
					    req_pid, req_vemva, req_size,
					    req_syncnum, req_mode_flag,
					    checking_mask);

	/* If VE_MEM_RENEW exists, old veshm_info is invalidated */
	if (having_veshm != NULL){
		ret = pthread_mutex_lock(&having_veshm->veshm_info->veshm_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
				   strerror(ret));
		}

		if (isset_flag(having_veshm->veshm_info->mode_flag,
			       VESHM_MODE_CLOSE)
		    || (isset_flag(req_mode_flag, VE_MEM_RENEW))){

			set_flag(having_veshm->veshm_info->mode_flag,
				 VESHM_MODE_INVALID);
			IVED_DEBUG(log4cat_veshm, "VESHM Renewal");
			dump_veshm_info(having_veshm->veshm_info);

			pthread_mutex_unlock
				(&having_veshm->veshm_info->veshm_lock);

			/* Set NULL */
			having_veshm = NULL;
		} else {
			pthread_mutex_unlock
				(&having_veshm->veshm_info->veshm_lock);
		}
	}

	if (having_veshm == NULL){
		/*  It is enough to cehck os_info->veshm_mem_num for
		 *  the maximum VESHM number. 
		 *  It is because always proc_info->own_veshm_num is less than 
		 *  os_info->veshm_mem_num. */
		if ((unsigned int)os_info->veshm_mem_num + 1 > INT_MAX){
			IVED_ERROR(log4cat_veshm, "Too many VESHM (%s)",
				   os_info->drv_socket_name);
			rpc_reterr = -ENOMEM;
			goto err_ret_unlock;
		}

		if (req_pci_address != NULL){
			pci_address = (uint64_t *) malloc (sizeof (uint64_t) *
							   req_n_pci_address);
			if (pci_address == NULL){
				IVED_CRIT(log4cat_veshm, 
					  "VESHM data area (PCI) allocation failed");
				rpc_reterr = -ENOMEM;
				goto err_ret_unlock;
			}
			memcpy(pci_address, req_pci_address, 
			       sizeof(uint64_t) * req_n_pci_address);
		}
		having_veshm = create_having_veshm_tracker(proc_info);
	}
	IVED_DEBUG(log4cat_veshm, "[%u] having_veshm = %p", (uint)pthread_self(),
		   having_veshm);

	/* Chack again */
	if (having_veshm == NULL){
		rpc_reterr = -ENOMEM;
		goto err_ret_unlock;
	}
	veshm_info = having_veshm->veshm_info;
	ret = pthread_mutex_lock(&veshm_info->veshm_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
			   strerror(ret));
	}

	if ( veshm_info->start_vemva == UNUSED){
		/* Fill members by the request data and etc. */
		/* veshm_info->(counters) are set as 0 when it created. */

		uuid_copy(veshm_info->uuid_veshm,
			  request->open_arg->uuid_veshm.data);
		uuid_copy(veshm_info->uuid_owner_proc,
			  proc_info->uuid_proc);
		veshm_info->uid_of_owner   = req_uid;
		veshm_info->pid_of_owner   = req_pid;
		veshm_info->start_vemva    = req_vemva;
		veshm_info->size           = req_size;
		veshm_info->pcisync_num    = req_syncnum;

		veshm_info->mode_flag      = req_mode_flag &
			(VESHM_MODE_RO | VESHM_MODE_SYNC | VESHM_MODE_PCIATB);

		/* pci_address is NULL or valid address */
		/* req_n_pci_address is 0 or positive value */
		veshm_info->pci_address   = pci_address;
		veshm_info->n_pci_address = req_n_pci_address; 

		veshm_info->os_info	   = os_info;
	}

	if ( isset_flag(req_mode_flag, VE_REQ_DEV )){
		register_cnt = &veshm_info->register_cnt_dev;
	} else {
		register_cnt = &veshm_info->register_cnt_proc;
	}
	if ((unsigned int)(*register_cnt) + 1 > INT_MAX){
		IVED_ERROR(log4cat_veshm, 
			   "Too many multiple registration (pid:%d)",
			   req_pid);
		rpc_reterr = -ENOMEM;
		goto err_ret_unlock_veshm;
	}
	(*register_cnt)++;

	dump_tracker(having_veshm);
	dump_veshm_info(veshm_info);

	pthread_mutex_unlock(&veshm_info->veshm_lock);
	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

	ret = ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);
	if (ret != 0){
		IVED_INFO(log4cat_veshm, "Sending a reply failed");
	}
	return (IVED_REQ_OK);

err_ret_unlock_veshm:
	pthread_mutex_unlock(&veshm_info->veshm_lock);
err_ret_unlock:
	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

	if (pci_address != NULL){
		free(pci_address);
	}

err_ret_nolock:
	if (pti != NULL){
		ret = ived_send_int64(pti->socket_descriptor, 
				      rpc_retval, rpc_reterr);
		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Sending a reply failed");
		}
	}

	return (retval);
}
/**
 * @brief Main function for VESHM attach
 *
 * @param [in]  pti	Thread argument
 * @param [in]  request Request from a client
 *
 * @return 0 on success, -1 on failure
 */
int
ived_veshm_attach(ived_thread_arg_t *pti, RpcVeshmArg *request)
{ 
	int ret, retval = -1;
	int rpc_retval = IVED_REQ_NG, rpc_reterr = 0;

	uid_t req_user_uid;
	pid_t req_user_pid, req_owner_pid;
	uint64_t req_vemva, req_mode_flag, req_size;
	int req_syncnum;
	int same_node = 0;

	int locked_owner = 0;
	int locked_user  = 0;
	int locked_veshm = 0;
	int change_refcnt = 0;
	int change_attach_proc = 0;

	uint64_t owner_os_pci_pgsize;
	struct veos_info *owner_os_info = NULL;
	struct veos_info *user_os_info = NULL;
	struct process_info *owner_proc_info = NULL, *user_proc_info = NULL;
	struct veshm_info_tracker *attach_veshm = NULL;
	struct ived_resource_user *attach_proc = NULL;

	struct veshm_memory_info  *veshm_info = NULL;

	IvedReturn reply_msg = IVED_RETURN__INIT;
	RpcVeshmReturn reply_veshm = RPC_VESHM_RETURN__INIT;
	ProtobufCBinaryData uuid_data1, uuid_data2;

	uint64_t checking_mask = VESHM_MODE_SYNC | VESHM_MODE_PCIATB |
		VESHM_MODE_RO;

	if (pti == NULL || request == NULL || request->attach_arg == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	req_user_uid	= (request->attach_arg)->user_uid;
	req_user_pid	= (request->attach_arg)->user_pid;
	req_owner_pid	= (request->attach_arg)->owner_pid;
	req_vemva	= (request->attach_arg)->vemva;
	req_size	= (request->attach_arg)->size;
	req_syncnum     = (request->attach_arg)->syncnum;
	req_mode_flag	= (request->attach_arg)->mode_flag;

	IVED_DEBUG(log4cat_veshm, 
		   "requester pid: %d, mode_flag: %#"PRIx64"",
		   req_user_pid, req_mode_flag);
	dump_uuid("requester uuid", (request->attach_arg)->uuid_proc.data);

	/* Check arguments */
	if (isset_flag(req_mode_flag, VE_REGISTER_VEHVA)
	    && isset_flag(req_mode_flag, VE_REGISTER_VEMVA)){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	if (isset_flag(req_mode_flag, VE_MEM_LOCAL) 
	    || (req_user_pid == req_owner_pid)){
		/* VE_MEM_LOCAL request doesn't need to access IVED. */
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	if ( ! isset_flag(req_mode_flag, 
			  (VE_REGISTER_VEHVA | VE_REGISTER_VEMVA))){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* Search the target (owner) process data */
	search_node_proc_info(req_owner_pid, null_id, &owner_os_info, 
			      &owner_proc_info);
	if (owner_os_info == NULL || owner_proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_DEBUG(log4cat_veshm,
			   "VESHM attach: owner(pid=%d) data is not found", 
			   req_owner_pid);
		goto err_ret_nolock;
	}
	locked_owner = 1;

	/* Check OS status */
	test_os_state(owner_os_info);
	if ( owner_os_info->node_stat != VE_STAT_RUNNING ){
		rpc_reterr = -EINVAL;
		goto err_ret_lock1;
	}

	/* Check nodes and VESHM_MODE_PCIATB flag in a request */
	if ( ! isset_flag(req_mode_flag, VESHM_MODE_PCIATB) ){
		if (owner_os_info->os_pid != pti->cred.pid){
			/* It means that a target VESHM is not registered 
			 * to PCIATB, but a requester process want to 
			 * attach it. */
			rpc_reterr = -EINVAL;
			goto err_ret_lock1;
		}
	}

	owner_os_pci_pgsize = owner_os_info->pciatb_pgsize;

	/* pti->cred.pid is pid of user's node os */
	if (pti->cred.pid == owner_os_info->os_pid)
		same_node = 1;

	/* Search a valid target veshm info (data structure) and aquire veshm_lock */
	veshm_info = search_veshm_info(owner_proc_info, req_vemva, req_size,
				       req_syncnum, req_mode_flag, 
				       checking_mask);
	if (veshm_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_lock1;
	}
	locked_veshm = 1;

	if (isset_flag(veshm_info->mode_flag, VESHM_MODE_CLOSE)){
		IVED_DEBUG(log4cat_veshm, "%s", strerror(EINVAL));
		rpc_reterr = -EINVAL;
		goto err_ret_lock_veshm;
	}
	if (veshm_info->uid_of_owner != req_user_uid){
		IVED_DEBUG(log4cat_veshm, "%s", strerror(EACCES));
		rpc_reterr = -EACCES;
		goto err_ret_lock_veshm;
	}

	/* Check whether data had been registered */
	attach_proc = search_veshm_attach_proc(veshm_info, req_user_pid);

	if (attach_proc == NULL){
		/* Increment reference count so that veshm_info is not deleted. */
		veshm_info->reference_cnt++;
		change_refcnt = 1;

		/* Create an attaching process information to VESHM mem info */
		attach_proc = create_veshm_attach_proc
			(veshm_info, req_user_pid, 
			 (request->attach_arg)->uuid_proc.data);
		if (attach_proc == NULL){
			rpc_reterr = -ENOMEM;
			goto err_ret_revert;
		}
		change_attach_proc = 1;

		IVED_DEBUG(log4cat_veshm, "Add VESHM user data");
		dump_attach_proc_info(attach_proc);
	} else {
		IVED_DEBUG(log4cat_veshm, "Use attached VESHM");
		change_refcnt = 0;
	}

	/* Finish using owner_os_info, owner_proc_info */
	pthread_mutex_unlock(&owner_proc_info->proc_lock);
	pthread_mutex_unlock(&owner_os_info->os_lock);
	locked_owner = 0;

	if (change_refcnt == 0){
		/* VESHM is not renewed, so not need to create
		 * a new attaching_veshm_info */
		goto ret_registered;
	} else {
		/* Finish using veshm_info */
		pthread_mutex_unlock(&veshm_info->veshm_lock);
		locked_veshm = 0;
	}

	/* Search the user process data */
	search_node_proc_info(req_user_pid, null_id,
			      &user_os_info, &user_proc_info);
	if (user_os_info == NULL || user_proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_veshm, "%s (pid=%d)", 
			   strerror(ESRCH), req_user_pid);
		user_proc_info = NULL;
		goto err_ret_revert;
	}
	locked_user = 1;

	if ( user_os_info->os_pid != pti->cred.pid ){
		IVED_ERROR(log4cat_veshm, "Invalid request from pid:%d",
			   pti->cred.pid);
		rpc_reterr = -EACCES;
		goto err_ret;
	}

	pthread_mutex_lock(&veshm_info->veshm_lock);
	locked_veshm = 1;

	/* Get an attaching VESHM information to the user process info.
	 * If data is created, it has set veshm_info. */
	attach_veshm = search_veshm_tracker
		(&user_proc_info->attaching_veshm_info, 
		 user_proc_info, req_owner_pid, req_vemva, req_size, 
		 req_syncnum, req_mode_flag, checking_mask);

	if ( attach_veshm != NULL ){
		IVED_ERROR(log4cat_veshm, 
			   "Multiple attaching request from VEOS.");
		rpc_reterr = -EINVAL;
		goto err_ret;
	}

	if ((unsigned int)user_proc_info->attach_veshm_num + 1 > INT_MAX){
		IVED_ERROR(log4cat_veshm, "Too many VESHM attachment (pid:%d)",
			   user_proc_info->pid);
		rpc_reterr = -ENOMEM;
		goto err_ret;
	}

	attach_veshm = create_attaching_veshm_tracker(user_proc_info);
	if (attach_veshm == NULL){
		rpc_reterr = -ENOMEM;
		goto err_ret;
	}
	attach_veshm->veshm_info = veshm_info;

	dump_tracker(attach_veshm);
	dump_proc_info(user_proc_info);

ret_registered:
	dump_veshm_info(veshm_info);

	/* Fill the reply message (1) */
	reply_veshm.has_flag	= 1;
	reply_veshm.flag	= veshm_info->mode_flag & VESHM_MODE_RO;

	reply_veshm.has_pagesize = 1;

	if (same_node == 0){
		/* If owner and user exist on the same node, DMAATB should not
		 * set VHSAA to DMAATB entries. (Limitation of PCIe) */
		reply_veshm.n_pci_address = veshm_info->n_pci_address;
		reply_veshm.pci_address   = veshm_info->pci_address;
		reply_veshm.pagesize   = owner_os_pci_pgsize;
	} else {
		reply_veshm.n_pci_address = 0;
		reply_veshm.pci_address   = NULL;
		reply_veshm.pagesize   = -1;
	}

	uuid_data1.len		   = sizeof(uuid_t);
	uuid_data1.data		   = (uint8_t *)veshm_info->uuid_owner_proc;
	reply_veshm.has_uuid_proc  = 1;
	reply_veshm.uuid_proc	   = uuid_data1;
	dump_uuid("target(owner) proc", uuid_data1.data);

	uuid_data2.len		   = sizeof(uuid_t);
	uuid_data2.data		   = (uint8_t *)veshm_info->uuid_veshm;
	reply_veshm.has_uuid_veshm = 1;
	reply_veshm.uuid_veshm     = uuid_data2;
	dump_uuid("target veshm", uuid_data2.data);

	reply_msg.veshm_ret	= &reply_veshm;

	rpc_retval = IVED_REQ_OK;
	retval = 0;

	/* Don't clear created data on success */
	change_attach_proc = 0;
	change_refcnt = 0;


err_ret:
	if (locked_user == 1){
		pthread_mutex_unlock(&user_proc_info->proc_lock);
		pthread_mutex_unlock(&user_os_info->os_lock);
		locked_user = 0;
	}
err_ret_revert:
	if (locked_veshm == 0){
		ret = pthread_mutex_lock(&veshm_info->veshm_lock);
		IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
			   strerror(ret));
		locked_veshm = 1;
	}
	if (change_attach_proc == 1){
		erase_veshm_attach_proc(veshm_info, attach_proc);
		change_attach_proc = 0;
	}
	if (change_refcnt == 1){
		veshm_info->reference_cnt--;
		change_refcnt = 0;
	}
err_ret_lock_veshm:
	if (locked_veshm == 1){
		pthread_mutex_unlock(&veshm_info->veshm_lock);
		locked_veshm = 0;
	}
err_ret_lock1:
	if (locked_owner == 1){
		pthread_mutex_unlock(&owner_os_info->os_lock);
		pthread_mutex_unlock(&owner_proc_info->proc_lock);
		locked_owner = 0;
	}

err_ret_nolock:

	/* Fill the reply message (2) */
	reply_msg.retval	= rpc_retval;
	reply_msg.error		= rpc_reterr;

	if (pti != NULL){
		ret = ived_send_reply_msg(pti->socket_descriptor, &reply_msg);
		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Sending a reply failed");
		}
	}

	/* Check conditions of changes */
	ret = locked_owner + locked_user + locked_veshm 
		+ change_refcnt + change_refcnt;
	assert (ret == 0);

	return (retval); 
}

/**
 * @brief Send a request of release the VESHM area to VEOS
 *
 * NOTE: request_detach uses veshm_info->pci_address. Don't free 
 * veshm_info before send IPC.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * veshm_info
 *
 * @param [in] owner_os_info	OS information of VESHM owner 
 * @param [in] request_detach	Request of VESHM detach
 *
 * @return 0 on success, -1 on failure
 */
int
send_erase_veshm_req(int veos_sock,
		     RpcVeshmSubDetach *request_detach)
{
	int ret;
	int retval = 0;
	int retry = RETRY;
	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	IvedReturn *reply = NULL;

	if (request_detach == NULL || veos_sock < 0){
		IVED_CRIT(log4cat_veshm, "%s", strerror(EINVAL));
		return(-1);
	}

	/* Create a request */
	request.detach_arg  = request_detach;
	request.subcmd      = VESHM_DETACH_AREA;

	while (retry > 0){
		ret = ived_exchange_veshm_msg(veos_sock,
					      &request, &reply);
		if (ret != 0 || reply == NULL){
			IVED_WARN(log4cat_veshm, 
				  "Sending VESHM release request failed");
			goto err_ret;
		} else if (reply->error == -EAGAIN){
			sleep(3);
			retry--;
			continue;
		} else {
			break;
		}
	}
	/* Don't care a result of the request */

err_ret:
	if (reply != NULL)
		ived_return__free_unpacked(reply, NULL);
	return(retval);
}


/**
 * @brief Erase VESHM memory used by detach functions
 *    If registration counters and reference counter are all 0,
 *    send a request of release the VESHM area, and erase 
 *    VESHM info.
 *    This function unlocks veshm_lock regardless of the result.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * owner_os_info, owner_proc_info, veshm_info
 *
 * NOTE: Before entering this function, unlink veshm_info from erase_veshm_list.
 *
 * @param [in]  user_proc_info Detach VESHM of this process
 * @param [in]  owner_proc_inf Target VESHM's owner
 * @param [in]  attaching_info Tracker of the VESHM
 *
 * @return Result of erasing VESHM info
 * @retval 0 if erase a veshm info
 * @retval 1 if not erase
 * @retval -1 on error (set reterr)
 */
int
erase_veshm_info_by_detach( struct veos_info *owner_os_info,
			    struct process_info *owner_proc_info,
			    struct veshm_memory_info *veshm_info)
{
	int ret, retval = -1;
	struct veshm_info_tracker *having_veshm = NULL;
	RpcVeshmSubDetach request_detach_area = RPC_VESHM_SUB_DETACH__INIT;
	ProtobufCBinaryData uuid_data;
	ProtobufCBinaryData uuid_data2;

	/* Before invoking this function, get locks of 
	 * owner's os_info/proc_info, veshm_info. */

	IVED_TRACE(log4cat_veshm, "PASS");

	assert(owner_os_info   != NULL);
	assert(owner_proc_info != NULL);
	assert(veshm_info      != NULL);

	if (owner_os_info == NULL || owner_proc_info == NULL 
	    || veshm_info == NULL ){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		goto err_ret;
	}

	dump_veshm_info(veshm_info);

	/* Erase_list is initialized whether the data is cleared or not. */
	INIT_LIST_HEAD(&veshm_info->erase_list);

	/* Sum of registration counters and reference counter is 0,
	 * release the target VESHM */
	if (veshm_info->reference_cnt != 0
	    || veshm_info->register_cnt_dev != 0
	    || veshm_info->register_cnt_proc != 0){
		IVED_DEBUG(log4cat_veshm, "The VESHM is used.");
		retval = 1;
		pthread_mutex_unlock(&veshm_info->veshm_lock);
		goto ret_using;
	}

	request_detach_area.n_pci_address = veshm_info->n_pci_address;
	request_detach_area.pci_address	  = veshm_info->pci_address;

	uuid_data.len = sizeof(uuid_t);
	uuid_data.data = (uint8_t *)veshm_info->uuid_veshm;
	request_detach_area.has_uuid_veshm = 1;
	request_detach_area.uuid_veshm = uuid_data;

	uuid_data2.len = sizeof(uuid_t);
	uuid_data2.data = (uint8_t *)veshm_info->uuid_owner_proc;
	request_detach_area.has_uuid_proc = 1;
	request_detach_area.uuid_proc = uuid_data2;

	test_os_state(owner_os_info);
	if (owner_os_info->node_stat == VE_STAT_RUNNING
	    && request_detach_area.n_pci_address != 0){
		pthread_mutex_lock(&owner_os_info->veos_sock_lock);
		ret = send_erase_veshm_req(owner_os_info->veos_sock, 
					   &request_detach_area);
		pthread_mutex_unlock(&owner_os_info->veos_sock_lock);

		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Erase request failed");
		}
	}

	having_veshm = search_veshm_tracker_uuid
		(&owner_proc_info->having_veshm_info,
		 owner_proc_info, veshm_info->uuid_veshm);
	if (having_veshm == NULL){
		pthread_mutex_unlock(&veshm_info->veshm_lock);
		IVED_ERROR(log4cat_veshm, 
			  "VESHM tracker is not found. VESHM is not cleared");
		goto err_ret;
	}

	/* Erase Having VESHM tracker */
	erase_having_veshm_tracker(owner_proc_info, having_veshm);

	/* Erase VESHM information (Unlock veshm_lock)*/
	erase_veshm_info(veshm_info->os_info, veshm_info);

	retval = 0;

ret_using:
err_ret:
	IVED_DEBUG(log4cat_veshm, "retval:%d", retval);
	return(retval);
}

/**
 * @brief Erase VESHM memory collectively
 * Mainly it is used by erasing a process or OS cleanup.
 * erase_veshm_list is created in ived_veshm_detach_all().
 *
 * NOTE: Don't acquire a lock of cur_os_info before entering 
 * this function.
 *
 * All veshm_info which are linked to erase_veshm_list have
 * be locked before entering this function.
 *
 * @param [in]  cur_os_info       VEOS on which a erased process exists
 * @param [in]  erase_veshm_list  Erased VESHM memory infomation list
 *
 * @return 0 on success, -1 on failure
 */
int
erase_veshm_info_batch(struct veos_info *cur_os_info,
		       struct list_head *erase_veshm_list)
{
	int  ret;
	struct list_head *list_p, *list_n;
	struct veshm_memory_info *veshm_info = NULL;

	struct veos_info *owner_os_info = NULL;
	struct process_info *owner_proc_info = NULL;
	RpcVeshmSubDetach request_detach;
	ProtobufCBinaryData uuid_data;
	ProtobufCBinaryData uuid_data2;

	assert(cur_os_info      != NULL);
	assert(erase_veshm_list != NULL);
	if (cur_os_info == NULL || erase_veshm_list == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return (-1);
	}

	IVED_TRACE(log4cat_veshm, "PASS");

	list_for_each_safe(list_p, list_n, erase_veshm_list){

		veshm_info = list_entry(list_p, struct veshm_memory_info, 
					erase_list);
		/* Initialize erase_list in erase_veshm_info_by_detach() */
		list_del(list_p);
		INIT_LIST_HEAD(&veshm_info->erase_list);

		search_node_proc_info(-1, veshm_info->uuid_owner_proc,
				      &owner_os_info, &owner_proc_info);
		if (owner_os_info == NULL || owner_proc_info == NULL){
			IVED_ERROR(log4cat_veshm, 
				   "Owner process is not found. (Skip clearing %p)",
				   veshm_info);
			continue;
		}

		ret = pthread_mutex_lock(&veshm_info->veshm_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
				   strerror(ret));
		}

		/* This request is sent to a VEOS of an attached VESHM. */
		rpc_veshm_sub_detach__init(&request_detach);

		uuid_data.len = sizeof(uuid_t);
		uuid_data.data = (uint8_t *)veshm_info->uuid_veshm;
		request_detach.has_uuid_veshm = 1;
		request_detach.uuid_veshm = uuid_data;

		uuid_data2.len = sizeof(uuid_t);
		uuid_data2.data = (uint8_t *)veshm_info->uuid_owner_proc;
		request_detach.has_uuid_proc = 1;
		request_detach.uuid_proc = uuid_data2;

		dump_uuid("Erase veshm by detach", uuid_data.data);
		dump_uuid("Erased veshm of owner", uuid_data2.data);

		erase_veshm_info_by_detach(owner_os_info, owner_proc_info,
					   veshm_info);

		/* proc_lock will be unlocked. */
		try_erase_procinfo(owner_proc_info);

		/* try_clear_osinfo doesn't unlock os_lock */
		if (owner_os_info != cur_os_info){
			/* Note: In case of veos exiting or clean up,
			 * try_clear_osinfo() later */
			try_clear_osinfo(owner_os_info, 0);
		}
		pthread_mutex_unlock(&owner_os_info->os_lock);
	}
	return(0);
}


/**
 * @brief Main function for VESHM delete
 *
 * 1. Search a process info
 * 2. Search a VESHM info
 * 3  Call a common function for detach
 *
 * @param [in]  pti     Thread arguments
 * @param [in]  request Request from a client
 *
 * @return 0 on success, IVED_FUNC_ERR on failure
 */
int 
ived_veshm_detach(ived_thread_arg_t *pti, RpcVeshmArg *request)
{
	int ret, retval;
	int rpc_reterr;
	int same_node = 0;

	pid_t req_user_pid;
	uint64_t req_mode_flag;
	uuid_t req_uuid_veshm, req_uuid_proc;

	struct veos_info *owner_os_info = NULL;
	struct veos_info *user_os_info = NULL;
	struct process_info *owner_proc_info = NULL, *user_proc_info = NULL;
	struct veshm_info_tracker *attaching_info = NULL;
	struct ived_resource_user *attaching_proc = NULL;
	struct veshm_memory_info *veshm_info = NULL;

	retval = -1;
	rpc_reterr = 0;

	if (pti == NULL || request == NULL || request->detach_arg == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	req_user_pid	= (request->detach_arg)->user_pid;
	req_mode_flag	= (request->detach_arg)->mode_flag;

	IVED_DEBUG(log4cat_veshm, 
		   "requester pid: %d, mode_flag: %#"PRIx64"",
		   req_user_pid, req_mode_flag);

	/* req_uuid_proc and req_uuid_veshm are owner's id */
	uuid_copy(req_uuid_proc, request->detach_arg->uuid_proc.data);
	uuid_copy(req_uuid_veshm, request->detach_arg->uuid_veshm.data);

	/* Check a request */
	if (isset_flag(req_mode_flag, VE_REGISTER_VEHVA)
	    && isset_flag(req_mode_flag, VE_REGISTER_VEMVA)){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	if (isset_flag(req_mode_flag, VE_MEM_LOCAL)){ 
		/* VE_MEM_LOCAL request doesn't need to access IVED. */
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	dump_uuid("detach_req: proc", req_uuid_proc);
	dump_uuid("detach_req: veshm", req_uuid_veshm);


	/* Search the user process data */
	search_node_proc_info(req_user_pid, null_id, 
			      &user_os_info, &user_proc_info);
	if (user_os_info == NULL || user_proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_veshm, "%s (pid=%d)", 
			   strerror(ESRCH), req_user_pid);
		goto err_ret_nolock;
	}

	if ( user_os_info->os_pid != pti->cred.pid ){
		IVED_ERROR(log4cat_veshm, "Invalid request from pid:%d",
			   pti->cred.pid);
		rpc_reterr = -EACCES;
		goto err_ret_lock1;
	}

	attaching_info = search_veshm_tracker_uuid
		(&user_proc_info->attaching_veshm_info,
		 user_proc_info, req_uuid_veshm);
	if (attaching_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_lock1;
	}

	if (user_os_info == attaching_info->veshm_info->os_info)
		same_node = 1;

	veshm_info = attaching_info->veshm_info;

	/* Delete attaching veshm_info tracker */
	erase_veshm_tracker(attaching_info, &user_proc_info->attach_veshm_num);

	if (same_node == 1){
		owner_os_info = user_os_info;
	} else {
		owner_os_info = veshm_info->os_info;

		/* Finish using user os data */
		pthread_mutex_unlock(&user_os_info->os_lock);
		user_os_info = NULL;
	}

	/* Finish using user process data */
	pthread_mutex_unlock(&user_proc_info->proc_lock);
	user_proc_info = NULL;

	/* Erase veshm info if possible */
	/* Search the target process data by uuid */
	if (same_node != 1){
		pthread_mutex_lock(&owner_os_info->os_lock);
	}
	owner_proc_info = get_procinfo_struct(owner_os_info, -1, 
					      req_uuid_proc, 0);
	if (owner_proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_veshm, 
			   "VESHM detach: Owner process data is not found");
		goto err_ret_lock2;
	}

	ret = pthread_mutex_lock(&veshm_info->veshm_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
			   strerror(ret));
	}

	/* Delete attaching processes infomation and tracker */
	attaching_proc = search_veshm_attach_proc(veshm_info, req_user_pid);
	if (attaching_proc == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_lock_veshm;
	}

	veshm_info->reference_cnt--;
	erase_veshm_attach_proc(veshm_info, attaching_proc);

	/* veshm_lock will be unlocked in the function. */
	erase_veshm_info_by_detach(owner_os_info, owner_proc_info, veshm_info);

	/* proc_lock will be unlocked in the function. */
	try_erase_procinfo(owner_proc_info);

	if (same_node != 1){
		/* If same_node == 1, veos is running. try_clear_osinfo()
		 * sets node_stat to VE_STAT_STOP. */

		/* try_clear_osinfo doen't unlock os_lock */
		try_clear_osinfo(owner_os_info, 0);
	}
	pthread_mutex_unlock(&owner_os_info->os_lock);

	retval = IVED_REQ_OK;

	ret = ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);
	if (ret != 0){
		IVED_WARN(log4cat_veshm, "Sending a reply failed");
	}
	return (retval); 


err_ret_lock_veshm:
	pthread_mutex_unlock(&veshm_info->veshm_lock);

err_ret_lock2:
	if (owner_os_info != NULL)
		pthread_mutex_unlock(&owner_os_info->os_lock);
	if (owner_proc_info != NULL)
		pthread_mutex_unlock(&owner_proc_info->proc_lock);

err_ret_lock1:
	if (user_os_info != NULL){
		pthread_mutex_unlock(&user_os_info->os_lock);

	}
	if (user_proc_info != NULL){
		pthread_mutex_unlock(&user_proc_info->proc_lock);
	}

err_ret_nolock:

	if (pti != NULL){
		ret = ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				      rpc_reterr);
		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Sending a reply failed");
		}
	}
	return (retval); 

}

/**
 * @brief Main function for VESHM close 
 *
 * 1. Erase Attaching VESHM information
 * 2. Erase attaching processes infomation
 * 3. If registration counters and reference counter are all 0,
 *    send a request of release the VESHM area, and erase 
 *    VESHM info.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * NOTE: This function may erase owner_proc_info, if possible.
 *
 * @param [in]  os_info      Target OS
 * @param [in]  proc_info    Target process
 * @param [in]  having_veshm Tracker data of a terget VESHM
 * @param [in]  mode_flag    Mode flag
 * @param [out] rpc_retval   Return value
 * @param [out] reterr       Return error
 *
 * @return retval on success, -1 on error
 */
int
ived_veshm_close_common(struct veos_info *os_info, 
			struct process_info *proc_info,
			struct veshm_info_tracker *having_veshm,
			uint64_t req_mode_flag, 
			int64_t *rpc_retval, int *reterr, int *rpc_ret_refcnt)
{
	int ret;
	int retval = -1;
	struct veshm_memory_info *veshm_info = NULL;

	assert(os_info      != NULL);
	assert(proc_info    != NULL);
	assert(having_veshm != NULL);
	assert(rpc_retval   != NULL);
	assert(rpc_ret_refcnt != NULL);
	assert(reterr       != NULL);

	if (os_info == NULL || proc_info == NULL || having_veshm == NULL
	    || rpc_retval == NULL || reterr == NULL || rpc_ret_refcnt == NULL){ 
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		if (rpc_retval != NULL)
			*rpc_retval = IVED_REQ_NG;
		if (reterr != NULL)
			*reterr = -ECANCELED;
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veshm, 
		   "requester pid: %d, mode_flag: %#"PRIx64"",
		   proc_info->pid, req_mode_flag);


	*rpc_retval = IVED_REQ_NG;

	if ( (req_mode_flag & (VE_REQ_DEV | VE_REQ_PROC
			       | IVED_PROC_EXIT | IVED_VEOS_EXIT)) == 0){
		IVED_CRIT(log4cat_veshm, "Unexpected case");
		*reterr = -ECANCELED;
		assert(0);
		goto err_ret;
	}

	veshm_info = having_veshm->veshm_info;
	if (veshm_info == NULL){
		IVED_ERROR(log4cat_veshm, "Closing VESHM failed");
		*reterr = -EINVAL;
		goto err_ret;
	}

	ret = pthread_mutex_lock(&veshm_info->veshm_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
			   strerror(ret));
	}

	/* Update registration count */
	/* IVED_VEOS_EXIT is a exclusive flag.
	 *
	 * VE_REQ_PROC and VE_REQ_DEV are exclusive.
	 * VE_REQ_PROC and IVED_PROC_EXIT are exclusive.
	 *
	 * VE_REQ_DEV and IVED_PROC_EXIT can be ORed value.
	 *
	 */

	if ( isset_flag(req_mode_flag, IVED_VEOS_EXIT) ){
		 /* If a VESHM closed and it was attached, the VESHM
		  * should be linked to erase_veshm_list, and
		  * is detached (and freed) in erase_veshm_info_batch().
		  * So, this function can return here.
		  */
		if ((veshm_info->register_cnt_proc == 0)
		    && (veshm_info->register_cnt_dev == 0)){
			IVED_DEBUG(log4cat_veshm,
				   "Already closed. veshm_info:%p", veshm_info);
			*rpc_retval = 0;
			*rpc_ret_refcnt = veshm_info->reference_cnt;
			pthread_mutex_unlock(&veshm_info->veshm_lock);
			retval = 0;
			goto already_closed;
		}
		veshm_info->register_cnt_proc = 0;
		veshm_info->register_cnt_dev = 0;
	} else {
		if ( isset_flag(req_mode_flag, VE_REQ_DEV) ){
			if (veshm_info->register_cnt_dev == 0){
				pthread_mutex_unlock(&veshm_info->veshm_lock);
				IVED_ERROR(log4cat_veshm, 
					   "Invalid VESHM (device) closing from pid:%d",
					   proc_info->pid);
				*reterr = -EINVAL;
				goto err_ret;
			}
			veshm_info->register_cnt_dev--;

		} else if ( isset_flag(req_mode_flag, VE_REQ_PROC)){
			if (veshm_info->register_cnt_proc == 0){
				pthread_mutex_unlock(&veshm_info->veshm_lock);
				IVED_ERROR(log4cat_veshm, 
					   "Invalid VESHM (process) closing from pid:%d",
					   proc_info->pid);
				*reterr = -EINVAL;
				goto err_ret;
			}
			veshm_info->register_cnt_proc--;
		}

		if ( isset_flag(req_mode_flag, IVED_PROC_EXIT) ){
			veshm_info->register_cnt_proc = 0;
		}
	}


	if ((veshm_info->register_cnt_proc == 0)
	    && (veshm_info->register_cnt_dev == 0)){
		set_flag(veshm_info->mode_flag, VESHM_MODE_CLOSE);
	}

	if ((veshm_info->register_cnt_proc == 0)
	    && (veshm_info->register_cnt_dev == 0)
	    && (veshm_info->reference_cnt == 0)){

		/* NOTE: Even though register_cnt_* are 0, VESHM may shared. 
		 * (reference_cnt > 0) Delete it later in detach function. */

		/* Erase Having VESHM tracker */
		erase_having_veshm_tracker(proc_info, having_veshm);
	}
	/* Try erasing VESHM information */
	/* Unlock veshm_lock whether it erases veshm_info or not.*/
	ret = erase_veshm_info(os_info, veshm_info);
	if (ret == 0){
		*rpc_retval = 0;
		*rpc_ret_refcnt = 0;
	} else {
		*rpc_retval = (long long)veshm_info->register_cnt_proc 
			+ veshm_info->register_cnt_dev;
		*rpc_ret_refcnt = veshm_info->reference_cnt;
	}

	retval = 0;

already_closed:
	IVED_DEBUG(log4cat_veshm, 
		   "registration count:%d, reference count:%d",
		   (int)*rpc_retval, *rpc_ret_refcnt);
err_ret:
	return(retval);
}

/**
 * @brief Main function for VESHM close
 * Return value of VESHM close is the summention of registration counters.
 * It is called by MPI/IB/OS(process termination). An owner process may
 * be terminated.
 *
 * @param [in]  pti     Thread arguments
 * @param [in]  request Request from a client
 *
 * @return 0 on success, IVED_FUNC_ERR on failure
 */
int 
ived_veshm_close(ived_thread_arg_t *pti, RpcVeshmArg *request)
{
	int ret, retval = -1;
	int64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;
	int rpc_ret_refcnt= 0;

	uid_t req_pid;
	uint64_t req_mode_flag;
	uuid_t req_uuid_veshm, req_uuid_proc;

	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	struct veshm_info_tracker *having_veshm = NULL;

	IvedReturn reply_msg = IVED_RETURN__INIT;
	RpcVeshmReturn reply_veshm = RPC_VESHM_RETURN__INIT;

	if (pti == NULL || request == NULL || request->close_arg == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	req_pid		= (request->close_arg)->owner_pid;
	req_mode_flag   = (request->close_arg)->mode_flag;

	uuid_copy(req_uuid_proc, request->close_arg->uuid_proc.data);
	uuid_copy(req_uuid_veshm, request->close_arg->uuid_veshm.data);

	dump_uuid("close proc", req_uuid_proc);
	dump_uuid("close veshm", req_uuid_veshm);

	/* Get process info */
	search_node_proc_info(-1, req_uuid_proc, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_veshm, 
			   "VESHM close: process data is not found"); 
		goto err_ret_nolock;
	}

	/* Pick up veshm info */
	having_veshm = search_veshm_tracker_uuid(&proc_info->having_veshm_info,
						 proc_info, req_uuid_veshm);
	IVED_DEBUG(log4cat_veshm, "[%u] having_veshm = %p", (uint)pthread_self(),
		   having_veshm);
	if (having_veshm == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret;
	}

	if (req_pid != having_veshm->veshm_info->pid_of_owner){
		IVED_DEBUG(log4cat_veshm, "Invalid close request: %s", 
			   strerror(EACCES));
		rpc_reterr = -EACCES;
		goto err_ret;
	}

	ived_veshm_close_common(os_info, proc_info, having_veshm, 
				req_mode_flag, &rpc_retval, &rpc_reterr,
				&rpc_ret_refcnt);

	if ( rpc_reterr != 0 ){
		goto err_ret;
	}

	/* registration count */
	reply_msg.retval	 = rpc_retval;
	reply_msg.error		 = rpc_reterr;
	/* reference count */
	reply_veshm.has_counts   = 1;
	reply_veshm.counts	 = rpc_ret_refcnt;
	reply_msg.veshm_ret	 = &reply_veshm;

	retval = 0;

	/* proc_lock will be unlocked. */
	try_erase_procinfo(proc_info);
	pthread_mutex_unlock(&os_info->os_lock);
	ret = ived_send_reply_msg(pti->socket_descriptor, &reply_msg);
	if (ret != 0){
		IVED_INFO(log4cat_veshm, "Sending a reply failed");
	}

	return (retval); 

err_ret:
	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

err_ret_nolock:

	if (pti != NULL){
		ret = ived_send_int64(pti->socket_descriptor, 
				      IVED_REQ_NG, rpc_reterr);
		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Sending a reply failed");
		}
	}

	return (retval); 
}


/**
 * @brief Reply PCIATB page size on which a specified process exists
 *
 * @param [in]  pti	Thread argument
 * @param [in]  request Request from a client
 *
 * @return 0 on success, -1 on failure
 */
int 
ived_get_pciatb_pgmode(ived_thread_arg_t *pti, RpcVeshmArg *request)
{
	int ret;
	int rpc_reterr = 0;
	pid_t req_pid;
	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;

	IvedReturn reply_msg = IVED_RETURN__INIT;
	RpcVeshmReturn reply_veshm = RPC_VESHM_RETURN__INIT;

	if (pti == NULL || request == NULL || request->pgsize_arg == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	req_pid		= request->pgsize_arg->pid;

	/* Search a process data */
	search_node_proc_info(req_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_DEBUG(log4cat_veshm, "pid=%d data is not found", 
			   req_pid);
		goto err_ret_nolock;
	}

	if (os_info->node_stat != VE_STAT_RUNNING){
		rpc_reterr = -ESRCH;
		IVED_DEBUG(log4cat_veshm, "%s (pid=%d)", 
			   strerror(ESRCH), req_pid);
		goto err_ret;
	}
	reply_veshm.has_pagesize = 1;
	reply_veshm.pagesize	 = os_info->pciatb_pgsize;

	reply_msg.veshm_ret	 = &reply_veshm;
	reply_msg.retval	 = IVED_REQ_OK;
	reply_msg.error		 = rpc_reterr;

	IVED_DEBUG(log4cat_veshm, "PCI pgsize of %s: %#"PRIx64"", 
		   os_info->drv_socket_name, reply_veshm.pagesize);

	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

	ret = ived_send_reply_msg(pti->socket_descriptor, &reply_msg);
	if ( ret != 0 ){
		IVED_INFO(log4cat_veshm, "Sending a reply failed");
	}

	return (IVED_REQ_OK); 

err_ret:
	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

err_ret_nolock:
	reply_veshm.has_pagesize = 1;
	reply_veshm.pagesize	 = 0;
	reply_msg.veshm_ret	 = &reply_veshm;
	reply_msg.retval	 = IVED_REQ_NG;
	reply_msg.error		 = rpc_reterr;


	if (pti != NULL){
		ret = ived_send_reply_msg(pti->socket_descriptor, &reply_msg);
		if (ret != 0){
			IVED_WARN(log4cat_veshm, "Sending a reply failed");
		}
	}

	return (-1); 
}

/**
 * @brief Entry point of VESHM manager functions
 *
 * It unpacks payload which is packed by protocol buffer, and call 
 * a function specified by sub command in the payload.
 *
 * @param [in]  pti Thread argument
 *
 * @return 0 on success, 1 on failure
 */
int 
ived_handle_veshm_request(ived_thread_arg_t *pti)
{
	int retval = -1;
	RpcVeshmArg	*request = NULL;
	struct veos_info *os_info = NULL;

	int rpc_retval = IVED_REQ_NG;	/* Return value of RPC message */
	int rpc_reterr = 0;		/* Return error of RPC message */

	IVED_TRACE(log4cat_veshm, "PASS");

	assert(pti != NULL);
	assert(pti->request != NULL);
	if (pti == NULL || pti->request == NULL || pti->request->veshm == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	/* Check whether a requester is a valid user. It should be 
	 * registered veos_info[]. */
	os_info = get_osinfo_struct(pti->cred.pid);
	if ( os_info == NULL ){
		rpc_reterr = -ECANCELED;
		goto err_ret;
	} else {
		pthread_mutex_unlock(&os_info->os_lock);
	}

	request = pti->request->veshm;
	IVED_DEBUG(log4cat_veshm, "New request pid:%d, subcmd:%#x",
		   pti->cred.pid, request->subcmd);

	switch(request->subcmd){

	case VESHM_OPEN:
		ived_veshm_open(pti, request);
		break;
	case VESHM_ATTACH:
		ived_veshm_attach(pti, request);
		break;
	case VESHM_DETACH:
		ived_veshm_detach(pti, request);
		break;
	case VESHM_CLOSE:
		ived_veshm_close(pti, request);
		break;
	case VESHM_PGSIZE:
		ived_get_pciatb_pgmode(pti, request);
		break;
	default:
		IVED_ERROR(log4cat_veshm, "Invalid VESHM command");
		rpc_reterr = -EINVAL;
		retval = -1;
		goto err_ret;
	}
	rpc_retval = IVED_REQ_OK;
	retval = 0;

err_ret:
	if (retval == -1 && pti != NULL){
		IVED_DEBUG(log4cat_veshm, "Invalid IPC message error");
		ived_send_int64(pti->socket_descriptor, 
				rpc_retval, rpc_reterr);
	}
	IVED_DEBUG(log4cat_veshm, "A request finished. retval: %d", retval);
	return (retval);
}


