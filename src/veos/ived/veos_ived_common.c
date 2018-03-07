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
 * @file veos_ived_common.c  
 * @brief IVED related common functions at VEOS side.
 *
 * @internal
 * @author VESHM
 */

#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>

#include "proto_buff_schema.pb-c.h"
#include "comm_request.h"
#include "ived_request.h"

#include "task_mgmt.h"
#include "psm_comm.h"

#include "ived_common.h"
#include "veos_ived.h"
#include "ived_ipc.h"

/**
 * @brief Initialize log4cat_pseudo_ived.
 *
 * @return 0 on success, -1 on failure
 */
int
veos_ived_log4c_init(void)
{
	/* log4c categories */
	log4cat_veos_ived = log4c_category_get("veos.os_module.ived");
	if (log4cat_veos_ived == NULL) {
		return -1;
	}
	log4cat_lib = log4c_category_get("veos.os_module.ived");
	if (log4cat_lib == NULL) {
		return -1;
	}
	IVED_DEBUG(log4cat_veos_ived, "Initialized log4c.");
	return 0;
}

/**
 * @brief Send a ACK/NACK to a clinet
 *
 * @param [in]   result		Return value or -errno
 *                              (will be return to VE program)
 * @param [in]   reply		Return value  (It can be NULL.)
 * @param [in]   pti		veos_thread_arg_t
 *
 * @return 0 on success,  -1 on failure
 */

int
veos_ived_reply(int64_t result, struct ived_sub_reply *reply,
		veos_thread_arg_t *pti)
{
	int ret, retval = -1;
	int sd;
	ssize_t msg_len;
	uint8_t *payload_buf = NULL;    /* store a packed request */
	PseudoVeosMessage reply_msg = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData reply_data;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	reply_msg.has_syscall_retval = 1;
	reply_msg.syscall_retval = result;

	if (pti == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret_nofree;
	}
	sd = pti->socket_descriptor;

	if (reply != NULL){
		reply_data.len =  sizeof(struct ived_sub_reply);
		reply_data.data = (uint8_t *)reply;
		reply_msg.has_pseudo_msg = 1;
		reply_msg.pseudo_msg = reply_data;
	}

	msg_len = pseudo_veos_message__get_packed_size(&reply_msg);

	if (get_rpc_buf(&payload_buf, msg_len) ){
		goto err_ret_nofree;
	}
	ret = pseudo_veos_message__pack(&reply_msg, payload_buf);
	if (ret != msg_len){
		goto err_ret;
	}
	ret = psm_pseudo_send_cmd(sd, payload_buf, msg_len);
	if (ret < 0) {
		IVED_DEBUG(log4cat_veos_ived, 
			   "Sending reply failed");
		goto err_ret;
	}
	retval = 0;
err_ret:
	free(payload_buf);

err_ret_nofree:
	IVED_DEBUG(log4cat_veos_ived, "PASS retval:%d", retval);
	return (retval);
}


/**
 * @brief Search ived_shared_resource_data from ived_task_list
 * by pid.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * ived_task_list_lock
 *
 * NOTE: This function acquires entry->ived_resource_lock.
 *
 * @param [in] pid PID of a target process
 *
 * @return Address of the target on success, NULL on failure
 */
struct ived_shared_resource_data *
search_ived_resource_data(pid_t pid){

	struct list_head *list_p;
	struct ived_shared_resource_data *entry = NULL;
	int found = 0;

	list_for_each(list_p, &ived_task_list){
		entry = list_entry(list_p, struct ived_shared_resource_data,
				   list);
		if ( entry->pid == pid ){
			found = 1;
			break;
		}
	}
	if ( found == 0 ){
		entry = NULL;
	} else {
		pthread_rwlock_wrlock(&entry->ived_resource_lock);
	}

	IVED_DEBUG(log4cat_veos_ived, "IVED data is %s",
		   (entry == NULL)? "not found.": "found.");
	return(entry);
}

