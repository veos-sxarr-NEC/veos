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
 * @file  cr_ipc.c
 * @brief IPC functions for CR
 *
 * @internal
 * @author CR
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
#include <signal.h>
#include <log4c.h>
#include "ve_list.h"
#include "cr_ipc.h"
#include "ived_common.h"
#include "ived.h"
#include "ived.pb-c.h"
#include "ived_ipc.h"
#include "ived_cr_core.h"
#include "ived_main.h"
#include "ived_core.h"
#include "cr_core.h"
/**
 * @brief Send a request of release a CR page to VEOS
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * os_lock
 *
 * @param [in] owner_os_info	OS information of VESHM owner 
 * @param [in] page_num		Releasing CR page number
 *
 * @return  0 on success, -1 on failure
 */
int
put_cr_reference(struct veos_info *owner_os_info, int page_num)
{
	int ret;
	int retval = -1;
	RpcCrArg request = RPC_CR_ARG__INIT;
	RpcCrSubNotReferenced request_not_refs =
		RPC_CR_SUB_NOT_REFERENCED__INIT;
	IvedReturn *reply = NULL;

	IVED_TRACE(log4cat_cr, "PASS");
	assert(owner_os_info != NULL);

	if (owner_os_info == NULL){
		IVED_CRIT(log4cat_cr, "Argument is NULL");
		return(retval);
	}

	test_os_state(owner_os_info);
	if (owner_os_info->node_stat != VE_STAT_RUNNING){
		try_clear_osinfo(owner_os_info, 0);
		retval = 0;
		goto not_send_req;
	}

	/* Create a request */
	request_not_refs.cr_page = page_num;
	request.not_referenced   = &request_not_refs;
	request.subcmd           = CR_NOT_REFERENCED;

	pthread_mutex_lock(&owner_os_info->veos_sock_lock);

	ret = ived_exchange_cr_msg(owner_os_info->veos_sock,
				   &request, &reply);
	if (ret != 0 || reply == NULL){
		IVED_ERROR(log4cat_cr, "IPC of releasing CR failed");
		goto err_ret;
	}
	if (reply->retval == IVED_REQ_NG){
		IVED_WARN(log4cat_cr,
			  "Releasing a CR page failed on the node of %s"
			  "(err:%d).",
			  owner_os_info->drv_socket_name, -reply->error);
		goto err_ret;
	}
	retval = 0;

not_send_req:
err_ret:
	if (reply != NULL)
		ived_return__free_unpacked(reply, NULL);
	pthread_mutex_unlock(&owner_os_info->veos_sock_lock);
	IVED_DEBUG(log4cat_cr, "retval:%d", retval);
	return(retval);
}

/**
 * @brief Send SIGKILL to remote processes which use the booting VE node.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * os_lock
 *
 * @param [in] os_info   OS on which a target process exists
 *
 * @return 0 on success, -1 on failure
 */
int
ived_cr_kill_remote_process(struct veos_info *os_info)
{
	int i;
	int ret, retval = -1;
	int send_signal = 0;
	struct list_head *list_p, *list_n;
	struct cr_page_info *cr_info = NULL;
	struct ived_resource_user *cr_user = NULL;

	IVED_TRACE(log4cat_cr, "PASS");

	if (os_info == NULL){
		IVED_CRIT(log4cat_cr, "Argument is null.");
		assert(os_info == 0);
		return (-1);
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0){
		assert(ret == 0);
		return(retval);
	}

	for (i=0; i < NODE_CR_PAGE_NUM; i++){
		cr_info = &os_info->cr_page_info[i];

		list_for_each_safe(list_p, list_n, &cr_info->cr_users_list){
			cr_user = list_entry(list_p, struct ived_resource_user,
					     list);
			kill(cr_user->pid, SIGKILL);
			send_signal = 1;
		}
	}

	if (send_signal != 0){
		IVED_INFO(log4cat_cr, "Terminate processes using CR on %s",
			  os_info->drv_socket_name);
	}
	return(0);
}


/**
 * @brief Main function of CR alloc
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_alloc(ived_thread_arg_t *pti, RpcCrSubAlloc *request)
{
	int ret, retval = -1;
	int rpc_reterr = 0;
	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;
	struct ived_resource_user *cr_user = NULL;

	uint	 my_pid;
	uint	 my_uid;
	uint64_t my_crd_number;
	uint64_t req_cr_page;
	uint64_t req_mode_flag;

	assert(pti     != NULL);
	assert(request != NULL);

	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid        = request->my_pid;
	my_uid        = request->my_uid;
	my_crd_number = request->my_crd_number;
	req_cr_page   = request->cr_page;
	req_mode_flag = request->mode_flag;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d, mode_flag: %#"PRIx64", cr page:%d",
		   my_pid, req_mode_flag, (int)req_cr_page);

	/* Check arguments and a request */
	if ( (! isset_flag(req_mode_flag, VE_CR_MPI))
	     || (isset_flag(req_mode_flag, VE_CR_THREAD)) ){
		/* VE_CR_MPI is not set or VE_CR_THREAD is set */
		IVED_CRIT(log4cat_cr, "Invalid flags");
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	if (req_cr_page >= NODE_CR_PAGE_NUM){
		IVED_DEBUG(log4cat_cr, "Invalid CR page number: %d.", 
			   (int)req_cr_page);
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	if(my_crd_number >= CRD_ENTRY){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)my_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	cr_info = &os_info->cr_page_info[(int)req_cr_page];
	ret = pthread_mutex_lock(&cr_info->cr_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_cr, "Acquire CR: %s", strerror(ret));
	}
	if (cr_info->uid != UNUSED 
	    || isset_flag(cr_info->mode_flag, CR_MODE_CLEAR)){
		IVED_DEBUG(log4cat_cr, "Invalid arguments");
		rpc_reterr = -EINVAL;
		goto err_ret;
	}

	/* Add using_cr_info */
	using_cr_info = create_using_cr_info(proc_info, cr_info);
	if (using_cr_info == NULL){
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}
	using_cr_info->crd = (int)my_crd_number;

	cr_info->uid       = (int)my_uid;
	cr_info->mode_flag = req_mode_flag;
	cr_info->reference_cnt++;

	/* Add cr_user_info */
	cr_user = create_cr_user_info(cr_info, my_pid);
	if (cr_user == NULL){
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	proc_info->local_crd[my_crd_number] = cr_info;

	IVED_DEBUG(log4cat_cr, "Allocated CR[%d] on %s", 
		   cr_info->cr_page_num, os_info->drv_socket_name);

	pthread_mutex_unlock(&cr_info->cr_lock);
	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

	ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	dump_resource_user_info(cr_user);
	return(0);

err_ret:
	if (using_cr_info != NULL){
		using_cr_info->cr_info->reference_cnt--;
		erase_using_cr_info(proc_info, using_cr_info);
	}

	/* This function unlock cr_lock. */
	try_clear_cr_page_info(cr_info);

	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&os_info->os_lock);

err_ret_nolock:
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "CR allocation failed. error:%d.", rpc_reterr);
	return (retval);
}

/**
 * @brief Main function of CR attach
 *
 * This function creates cr_info_tracker and incremetns reference_cnt
 * of CR page information. However cr_info_tracker.crd and .vehva are
 * set UNUSED. (One of them is set in ived_cr_attached.)
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_attach(ived_thread_arg_t *pti, RpcCrSubAttach *request)
{
	int ret;
	uint64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;

	int target_os_pid = 0;
	uint64_t target_bar_cr = 0;

	struct veos_info *os_info = NULL;		/* My OS */
	struct veos_info *t_os_info = NULL;		/* Target OS */
	struct process_info *proc_info = NULL;		/* My process */
	struct process_info *t_proc_info = NULL;	/* Target process */
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;

	uint	 my_pid;
	uint	 my_uid;
	uint	 t_pid;
	uint64_t t_crd_number;

	IVED_TRACE(log4cat_cr, "[%u] PASS", (uint)pthread_self());
	assert(pti     != NULL);
	assert(request != NULL);

	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid       = request->my_pid;
	my_uid       = request->my_uid;
	t_pid        = request->pid;
	t_crd_number = request->crd_number;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d, target pid:%d & cr:%d",
		   my_pid, t_pid, (int)t_crd_number);

	if (t_crd_number >= CRD_ENTRY){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)t_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* Get target process info & CR info */
	search_node_proc_info(t_pid, null_id, &t_os_info, &t_proc_info);
	if (t_os_info == NULL || t_proc_info == NULL){
		rpc_reterr = -ESRCH;
		goto err_ret_nolock;
	}

	/* Check OS status */
	test_os_state(t_os_info);
	if ( t_os_info->node_stat != VE_STAT_RUNNING ){
		rpc_reterr = -EINVAL;
		goto err_ret_t_lock;
	}

	target_os_pid = t_os_info->os_pid;
	target_bar_cr = t_os_info->bar_cr_paddr;

	cr_info = t_proc_info->local_crd[t_crd_number];
	if (cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)t_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_t_lock;
	}

	ret = pthread_mutex_lock(&cr_info->cr_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_cr, "Acquire CR: %s", strerror(ret));
	}

	pthread_mutex_unlock(&t_os_info->os_lock);
	pthread_mutex_unlock(&t_proc_info->proc_lock);
	t_os_info = NULL;
	t_proc_info = NULL;

	if (isset_flag(cr_info->mode_flag, CR_MODE_CLEAR)){
		IVED_DEBUG(log4cat_cr, "CR page [%d] is released",
			   cr_info->cr_page_num);
		rpc_reterr = -EINVAL;
		goto err_ret_cr_lock;
	}

	if (cr_info->uid != my_uid){
		IVED_DEBUG(log4cat_cr, "%s", strerror(EACCES));
		rpc_reterr = -EACCES;
		goto err_ret_cr_lock;
	}

	if ((unsigned int)cr_info->reference_cnt + 1 > INT_MAX){
		IVED_ERROR(log4cat_cr, "Too many CR page [%d] attachment(veos:%d)",
			   cr_info->cr_page_num, target_os_pid);
		rpc_reterr = -ENOMEM;
		goto err_ret_cr_lock;
	}

	cr_info->reference_cnt++;
	pthread_mutex_unlock(&cr_info->cr_lock);

	/* Get own process info */
	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_decrement;
	}

	if (os_info->os_pid == target_os_pid){
		/* Local */
		rpc_retval = 0;
	} else {
		/* Remote (VHSAA) */
		/* A CR page is mapped 2 pages. */
		rpc_retval = target_bar_cr + 
			((uint64_t)PGSIZE_4K * 2 * cr_info->cr_page_num);
	}

	pthread_mutex_unlock(&os_info->os_lock);
	os_info = NULL;

	/* Add cr_info_tracker */
	using_cr_info = create_using_cr_info(proc_info, cr_info);
	if (using_cr_info == NULL){
		rpc_reterr = -ENOMEM;
		IVED_ERROR(log4cat_cr, "CR query failed : %s",
			   strerror(rpc_reterr));
		goto err_ret_decrement;
	}

	pthread_mutex_unlock(&proc_info->proc_lock);

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);

	ived_send_int64(pti->socket_descriptor, rpc_retval, rpc_reterr);
	IVED_DEBUG(log4cat_cr, "CR query finished");
	return (0);

err_ret_decrement:
	pthread_mutex_lock(&cr_info->cr_lock);
	cr_info->reference_cnt--;
	pthread_mutex_unlock(&cr_info->cr_lock);

	if (proc_info != NULL)
		pthread_mutex_unlock(&proc_info->proc_lock);

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, rpc_reterr);
	IVED_DEBUG(log4cat_cr, "CR query failed. error:%d.", rpc_reterr);
	return (-1);

err_ret_cr_lock:
	pthread_mutex_unlock(&cr_info->cr_lock);
err_ret_t_lock:
	if (t_os_info != NULL)
		pthread_mutex_unlock(&t_os_info->os_lock);
	if (t_proc_info != NULL)
		pthread_mutex_unlock(&t_proc_info->proc_lock);
err_ret_nolock:
	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "CR query failed. error:%d.", rpc_reterr);
	return (-1);
}

/**
 * @brief Main function of CR attached
 *
 * VEOS informs CR manager of attached place (CRD or DMAATB).
 * This function sets cr_info_tracker.crd or cr_info_tracker.vehva.
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_attached(ived_thread_arg_t *pti, RpcCrSubAttached *request)
{
	int ret;
	int rpc_reterr = 0;

	struct veos_info *os_info = NULL;		/* My OS */
	struct veos_info *t_os_info = NULL;		/* Target OS */
	struct process_info *proc_info = NULL;		/* My process */
	struct process_info *t_proc_info = NULL;	/* Target process */
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;
	struct ived_resource_user *cr_user = NULL;

	uint	 my_pid;
	int64_t  my_crd_number;
	int64_t  my_vehva;
	uint	 t_pid;
	uint64_t t_crd_number;

	int target_os_pid = 0;

	IVED_TRACE(log4cat_cr, "[%u] PASS", (uint)pthread_self());
	assert(pti     != NULL);
	assert(request != NULL);

	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid        = request->my_pid;
	my_crd_number = (int64_t)request->my_crd_number;
	my_vehva      = (int64_t)request->my_vehva;
	t_pid         = request->pid;
	t_crd_number  = request->crd_number;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d, target pid:%d & cr:%d",
		   my_pid, t_pid, (int)t_crd_number);

	if (request->has_my_crd_number == request->has_my_vehva){
		IVED_DEBUG(log4cat_cr, "CRD and VEHVA in IPC are specified");
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	if (request->has_my_crd_number){
		if ((my_crd_number < 0) || (my_crd_number >= CRD_ENTRY)){
			IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
			IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)my_crd_number);
			rpc_reterr = -EINVAL;
			goto err_ret_nolock;
		}
	} else {
		if (my_vehva < 0){
			IVED_DEBUG(log4cat_cr, "Invalid VEHVA"); 
			rpc_reterr = -EINVAL;
			goto err_ret_nolock;
		}
	}

	if (t_crd_number >= CRD_ENTRY){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)t_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* Get target process info & CR info */
	search_node_proc_info(t_pid, null_id, &t_os_info, &t_proc_info);
	if (t_os_info == NULL || t_proc_info == NULL){
		rpc_reterr = -ESRCH;
		goto err_ret_nolock;
	}

	/* Check OS status */
	test_os_state(t_os_info);
	if ( t_os_info->node_stat != VE_STAT_RUNNING ){
		rpc_reterr = -EINVAL;
		/* Unfilled using_cr_info remains, but it will be cleared
		 * when the os reboots. */
		goto err_ret_t_lock; 
	}

	cr_info = t_proc_info->local_crd[t_crd_number];
	if (cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)t_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_t_lock;
	}
	target_os_pid = t_os_info->os_pid;

	pthread_mutex_unlock(&t_os_info->os_lock);
	pthread_mutex_unlock(&t_proc_info->proc_lock);

	/* Get own process info */
	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	pthread_mutex_unlock(&os_info->os_lock);

	if ((cr_info->os_info == proc_info->os_info)
	    && (request->has_my_vehva == 1)){
		/* Target CR is a local CR but a request is for remote CR.*/
		IVED_DEBUG(log4cat_cr, "Can't attach a Local CR to VEHVA.");
		rpc_reterr = -EINVAL;
		goto err_ret_my_proc;
	}

	ret = pthread_mutex_lock(&cr_info->cr_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_cr, "Acquire CR: %s", strerror(ret));
	}

	/* Get using CR info and update */
	using_cr_info = search_using_cr_info_halfway(proc_info, cr_info); 
	if (using_cr_info == NULL){
		IVED_ERROR(log4cat_cr, "CR intermediate data is not found");
		rpc_reterr = -EINVAL;
		goto err_ret_cr_lock;
	}

	if (request->has_my_crd_number){
		proc_info->local_crd[my_crd_number] = cr_info;
		using_cr_info->crd = (int)my_crd_number;
	} else {
		using_cr_info->vehva = my_vehva;
	}

	cr_user = search_cr_user_info(cr_info, my_pid);
	if (cr_user == NULL){
		IVED_DEBUG(log4cat_cr, "Add CR user data to CR:%p", cr_info);
		cr_user = create_cr_user_info(cr_info, my_pid);
		if (cr_user == NULL){
			IVED_ERROR(log4cat_cr, "Add CR user data failed");
			rpc_reterr = -ECANCELED;
			goto cancel_attached;
		}
	} else {
		if ((unsigned int)cr_user->reference_cnt_cr  + 1 > INT_MAX){
			IVED_ERROR(log4cat_cr, "Too many CR page [%d] attachment(pid:%d)",
				   cr_info->cr_page_num, target_os_pid);
			rpc_reterr = -ENOMEM;
			goto cancel_attached;
		}
		cr_user->reference_cnt_cr++;
	}

	pthread_mutex_unlock(&proc_info->proc_lock);
	pthread_mutex_unlock(&cr_info->cr_lock);

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	dump_resource_user_info(cr_user);
	ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);
	IVED_DEBUG(log4cat_cr, "CR attached");
	return (0);

cancel_attached:
	if (request->has_my_crd_number){
		proc_info->local_crd[my_crd_number] = NULL;
	}
	using_cr_info->crd = UNUSED;
	using_cr_info->vehva = UNUSED;

err_ret_cr_lock:
	pthread_mutex_unlock(&cr_info->cr_lock);
err_ret_my_proc:
	pthread_mutex_unlock(&proc_info->proc_lock);
err_ret_t_lock:
	if (t_os_info != NULL)
		pthread_mutex_unlock(&t_os_info->os_lock);
	if (t_proc_info != NULL)
		pthread_mutex_unlock(&t_proc_info->proc_lock);
err_ret_nolock:
	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	dump_resource_user_info(cr_user);
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "CR attaching failed. error:%d.", rpc_reterr);
	return (-1);
}

/**
 * @brief Main function of cancel CR attaching
 *
 * Attaching CR failed after CR_ATTACH request, VEOS sends
 * CR_CANCEL_ATTACH request.
 * This function erases using_cr_info which is added by ived_cr_attach.
 *
 * NOTE: Even if IVED replied success for CR_ATTACHED request, VEOS may
 * send CR_CANCEL_ATTACH request. In the such case, this function do nothing
 * because intermediate data of cr_info_tracker is not found.
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_cancel_attach(ived_thread_arg_t *pti, RpcCrSubCancelAttach *request)
{
	int ret;
	int rpc_reterr = 0;

	struct veos_info *os_info = NULL;		/* My OS */
	struct veos_info *t_os_info = NULL;		/* Target OS */
	struct process_info *proc_info = NULL;		/* My process */
	struct process_info *t_proc_info = NULL;	/* Target process */
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;

	uint	 my_pid;
	uint	 t_pid;
	uint64_t t_crd_number;

	assert(pti     != NULL);
	assert(request != NULL);

	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid        = request->my_pid;
	t_pid         = request->pid;
	t_crd_number  = request->crd_number;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d, target pid:%d & cr:%d",
		   my_pid, t_pid, (int)t_crd_number);

	if (t_crd_number >= CRD_ENTRY){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* Get target process info & CR info */
	search_node_proc_info(t_pid, null_id, &t_os_info, &t_proc_info);
	if (t_os_info == NULL || t_proc_info == NULL){
		rpc_reterr = -ESRCH;
		goto err_ret_nolock;
	}

	cr_info = t_proc_info->local_crd[t_crd_number];

	pthread_mutex_unlock(&t_os_info->os_lock);
	pthread_mutex_unlock(&t_proc_info->proc_lock);

	if (cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		IVED_DEBUG(log4cat_cr, "CRD: %d.", (int)t_crd_number);
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* Get own process info */
	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}
	pthread_mutex_unlock(&os_info->os_lock);

	ret = pthread_mutex_lock(&cr_info->cr_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_cr, "Acquire CR: %s", strerror(ret));
	}

	/* Get using CR info and update */
	using_cr_info = search_using_cr_info_halfway(proc_info, cr_info);
	if (using_cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "There are no intermediate CR data");
		pthread_mutex_unlock(&cr_info->cr_lock);
		goto ret_no_intermediate_data;
	}

	dump_proc_info(proc_info);
	dump_cr_info_tracker(using_cr_info);

	using_cr_info->cr_info->reference_cnt--;
	erase_using_cr_info(proc_info, using_cr_info);

	/* This function unlock cr_lock. */
	try_clear_cr_page_info(cr_info);

ret_no_intermediate_data:
	pthread_mutex_unlock(&proc_info->proc_lock);

	ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);
	IVED_DEBUG(log4cat_cr, "Cancellation of attaching CR finished");
	return (0);

err_ret_nolock:
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "Cancellation of attaching CR failed. error:%d", 
		   rpc_reterr);
	return (-1);
}

/**
 * @brief Main function of local CR releasing
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_release_local(ived_thread_arg_t *pti, RpcCrSubReleaseLocal *request)
{
	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;
	struct ived_resource_user *cr_user = NULL;

	uint64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;

	uint	 my_pid;
	uint64_t my_crd_number;

	assert(pti     != NULL);
	assert(request != NULL);
	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid        = request->my_pid;
	my_crd_number = request->my_crd_number;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d", my_pid);

	if (my_crd_number >= CRD_ENTRY){
		IVED_DEBUG(log4cat_cr, "Invalid CR directory number"); 
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	/* It acquires cr_info->cr_lock. */
	using_cr_info = search_using_cr_info(proc_info, my_crd_number, UNUSED);
	if (using_cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "Invalid arguments");
		rpc_reterr = -EINVAL;
		goto err_ret_proc_unlock;
	}

	cr_info = using_cr_info->cr_info;
	proc_info->local_crd[my_crd_number] = NULL;

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);

	erase_using_cr_info(proc_info, using_cr_info);
	using_cr_info = NULL;

	pthread_mutex_unlock(&proc_info->proc_lock);

	/* Erase CR user information */
	cr_user = search_cr_user_info(cr_info, my_pid);
	if (cr_user != NULL){
		if (try_erase_cr_user_info(cr_info, cr_user, 0) == 0){
			cr_user = NULL;
		}
	}
	dump_resource_user_info(cr_user);

	if (cr_info->reference_cnt > 0){
		cr_info->reference_cnt--;
	} else {
		IVED_WARN(log4cat_cr, 
			  "Reference count of CR info is invalid");
		assert(0);
		cr_info->reference_cnt = 0;
	}

	rpc_retval = (uint64_t)cr_info->reference_cnt;

	/* Release CR information. It unlocks cr_lock. */
	try_clear_cr_page_info(cr_info);

	pthread_mutex_unlock(&os_info->os_lock);

	ived_send_int64(pti->socket_descriptor, rpc_retval, rpc_reterr);
	IVED_DEBUG(log4cat_cr, "Releasing local CR finished");
	return (0);

err_ret_proc_unlock:
	pthread_mutex_unlock(&os_info->os_lock);
	pthread_mutex_unlock(&proc_info->proc_lock);
err_ret_nolock:
	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	dump_resource_user_info(cr_user);
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "Releasing local CR failed. error:%d.",
		   rpc_reterr);
	return (-1);
}

/**
 * @brief Main function of remote CR releasing
 *
 * @param [in]		pti	Data of a thread
 * @param [in]		request	CR arguments
 *
 * @return 0 on success, -1 on failure
 */
static int 
ived_cr_release_remote(ived_thread_arg_t *pti, RpcCrSubReleaseRemote *request)
{
	uint64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;

	struct veos_info *os_info = NULL;		/* My OS */
	struct process_info *proc_info = NULL;		/* My process */
	struct cr_page_info *cr_info = NULL;
	struct cr_info_tracker *using_cr_info = NULL;
	struct ived_resource_user *cr_user = NULL;

	uint	 my_pid;
	uint64_t my_vehva;

	assert(pti     != NULL);
	assert(request != NULL);

	if ((pti == NULL) || (request == NULL)){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
		goto err_ret_nolock;
	}

	my_pid   = request->my_pid;
	my_vehva = request->my_vehva;

	IVED_DEBUG(log4cat_cr, 
		   "requester pid: %d", my_pid);

	search_node_proc_info(my_pid, null_id, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -EINVAL;
		goto err_ret_nolock;
	}

	pthread_mutex_unlock(&os_info->os_lock);

	/* It acquires cr_info->cr_lock. */
	using_cr_info = search_using_cr_info(proc_info, UNUSED, my_vehva);
	if (using_cr_info == NULL){
		IVED_DEBUG(log4cat_cr, "Invalid arguments");
		rpc_reterr = -EINVAL;
		goto err_ret_my_proc;
	}

	cr_info = using_cr_info->cr_info;

	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);

	erase_using_cr_info(proc_info, using_cr_info);
	using_cr_info = NULL;

	pthread_mutex_unlock(&proc_info->proc_lock);


	/* Erase CR user information */
	cr_user = search_cr_user_info(cr_info, my_pid);
	if (cr_user != NULL){
		if (try_erase_cr_user_info(cr_info, cr_user, 0) == 0){
			cr_user = NULL;
		}
	} else {
		IVED_ERROR(log4cat_cr, "Requester is not found in users list.");
	}
	dump_resource_user_info(cr_user);

	if (cr_info->reference_cnt > 0){
		cr_info->reference_cnt--;
	} else {
		IVED_WARN(log4cat_cr, 
			  "Reference count of CR info is invalid");
		assert(0);
		cr_info->reference_cnt = 0;
	}

	rpc_retval = (uint64_t)cr_info->reference_cnt;

	/* Put remote CR page and Delete CR page information */
	if (cr_info->reference_cnt == 0){
		IVED_DEBUG(log4cat_cr, "Put CR page [%d] of %s",
			   cr_info->cr_page_num, 
			   cr_info->os_info->drv_socket_name);
		dump_cr_page_info(cr_info);
		/* Send put CR page request */
		try_clear_cr_page_info(cr_info);
		/* cr_info->os_info, cr_info->cr_page_num are never changed */
		pthread_mutex_lock(&cr_info->os_info->os_lock);
		put_cr_reference(cr_info->os_info, cr_info->cr_page_num);
		pthread_mutex_unlock(&cr_info->os_info->os_lock);
	} else {
		pthread_mutex_unlock(&cr_info->cr_lock);
	}

	ived_send_int64(pti->socket_descriptor, rpc_retval, rpc_reterr);
	IVED_DEBUG(log4cat_cr, "Releasing remote CR finished");
	return (0);

err_ret_my_proc:
	pthread_mutex_unlock(&proc_info->proc_lock);
err_ret_nolock:
	dump_proc_info(proc_info);
	dump_cr_page_info(cr_info);
	dump_cr_info_tracker(using_cr_info);
	dump_resource_user_info(cr_user);
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_DEBUG(log4cat_cr, "Releasing remote CR failed. error:%d.", 
		   rpc_reterr);
	return (-1);
}

/**
 * @brief Entry point of CR manager functions
 *
 * It unpacks payload which is packed by protocol buffer, and call 
 * a function specified by sub command in the payload.
 *
 * @param [in]  pti Thread argument
 *
 * @return 0 on success, -1 on failure
 */
int 
ived_handle_cr_request(ived_thread_arg_t *pti)
{
	int retval = -1;
	RpcCrArg *request;
	pthread_t tid = pthread_self();
	struct veos_info *os_info = NULL;

	int rpc_reterr = 0;		/* Return error of RPC message */

	if (pti == NULL || pti->request == NULL){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_cr, "Argument is null.");
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

	request = pti->request->cr;
	if (request == NULL){
		IVED_ERROR(log4cat_cr, "No CR argument");
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}
	IVED_DEBUG(log4cat_cr, "TID[%u] New request pid:%d, subcmd:%#x",
		   (unsigned int)tid, pti->cred.pid, request->subcmd);

	switch(request->subcmd){

	case CR_ALLOC:
		ived_cr_alloc(pti, request->alloc);
		break;
	case CR_ATTACH:
		ived_cr_attach(pti, request->attach);
		break;
	case CR_ATTACHED:
		ived_cr_attached(pti, request->attached);
		break;
	case CR_CANCEL_ATTACH:
		ived_cr_cancel_attach(pti, request->cancel);
		break;
	case CR_RELEASE_LOCAL:
		ived_cr_release_local(pti, request->release_local);
		break;
	case CR_RELEASE_REMOTE:
		ived_cr_release_remote(pti, request->release_remote);
		break;
	default:
		IVED_ERROR(log4cat_cr, "Invalid CR command");
		rpc_reterr = -EINVAL;
		retval = -1;
		goto err_ret;
	}
	retval = 0;

err_ret:
	if (retval == -1){
		IVED_DEBUG(log4cat_cr, "CR message error");
		if (pti != NULL)
			ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
					rpc_reterr);
	}
	IVED_DEBUG(log4cat_cr, "TID[%u] A request finished. retval: %d", 
		   (uint)pthread_self(), retval);
	return (retval);
}


