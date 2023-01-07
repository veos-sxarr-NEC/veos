/**
 * Copyright (C) 2020 NEC Corporation
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
 * @file ve_swap_sysve.c
 * @brief PPS sysve systemcall functions in VEOS
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <log4c.h>
#include "rpm_comm.h"
#include "task_mgmt.h"
#include "ve_swap.h"
#include "ve_swap_request.h"
#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"
#include "mm_common.h"
#include "ve_shm.h"

/**
 * @brief Send responce to Pseudo process
 *
 * @param[in] pseudo_sock_fd Descriptor used to communicate with VEOS.
 * @param[in] p_retval Return value of handled system call request.
 * @param[in] responce Responce which is returned to Pseudo process
 * @param[in] size Size of responce.
 *
 * @return 0 on Success, -1 on Failure.
 */
static int
veos_pps_return_responce(int pseudo_sock_fd, int p_retval,
						void *responce, size_t size)
{
	int retval = -1;
	int ret;
	void *msg_buff = NULL;
	ssize_t msg_len = 0;
	ProtobufCBinaryData data;
	PseudoVeosMessage ack = PSEUDO_VEOS_MESSAGE__INIT;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ack.has_syscall_retval = true;
	ack.syscall_retval = p_retval;
	if (responce == NULL) {
		ack.has_pseudo_msg = false;
	} else {
		ack.has_pseudo_msg = true;
		data.data = (uint8_t *)responce;
		data.len = size;
		ack.pseudo_msg = data;
	}

	msg_len = pseudo_veos_message__get_packed_size(&ack);
	msg_buff = malloc(msg_len);
	if (msg_buff == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to alloc PPS sysve msg_buff %s",
							strerror(errno));
		goto hndl_return;
	}
	memset(msg_buff, '\0', msg_len);

	if (msg_len != pseudo_veos_message__pack(&ack, msg_buff)) {
		PPS_ERROR(cat_os_pps, "Failed to pack PPS sysve msg");
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(pseudo_sock_fd, msg_buff, msg_len);
	if (ret < msg_len) {
		PPS_ERROR(cat_os_pps, "Failed to send ack for PPS sysve msg");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	free(msg_buff);
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Return maximun non-swappable memory of specified process.
 *
 * @param[in] pti Pointer to the thread argument structure containing IPC data.
 *
 * @return  0 on Success, -1 value on Failure.
 */
int
veos_handle_get_mns(veos_thread_arg_t *pti)
{
	int w_retval = 0;
	int p_retval = 0;
	pid_t requester;
	struct ve_task_struct *tsk = NULL;
	struct ve_ns_info_proc *ns_info = NULL;
	PseudoVeosMessage *request = NULL;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	request = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	if (request == NULL) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS request : %p", request);
		w_retval = -1;
		goto hndl_return;
	}
	if (!(request->has_pseudo_msg)) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS has no message");
		p_retval = -ECANCELED;
		goto hndl_responce;
	} else if (request->pseudo_msg.data == NULL) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS has invalid message");
		p_retval = -ECANCELED;
		goto hndl_responce;
	} else if (request->pseudo_msg.len != sizeof(pid_t)) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS has wrong size message");
		p_retval = -ECANCELED;
		goto hndl_responce;
	}
	requester = vedl_host_pid(VE_HANDLE(0), pti->cred.pid,
		*(pid_t *)request->pseudo_msg.data);

	tsk = find_ve_task_struct(requester);
	if (tsk == NULL) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS : requester(%d) %s",
						requester, strerror(ESRCH));
		p_retval = -ECANCELED;
		goto hndl_responce;
	}

	ns_info = (struct ve_ns_info_proc *)calloc(1,
						sizeof(struct ve_ns_info_proc));
	if (ns_info == NULL) {
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS : failed to alloc buff %s",
							strerror(errno));
		p_retval = -ECANCELED;
		goto hndl_responce;
	}
	ns_info->pid = requester;
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), LOCK,
		"CMD_GET_MNS : Failed to acquire thread_group_mm_lock(%d)",
		requester);
	ns_info->ns = tsk->p_ve_mm->mns;
	pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock), UNLOCK,
		"CMD_GET_MNS : Failed to release thread_group_mm_lock(%d)",
		requester);
	PPS_DEBUG(cat_os_pps, "CMD_GET_MNS : requester = %d, msn = 0x%lx ",
						ns_info->pid, ns_info->ns);

hndl_responce:
	if (tsk != NULL)
		put_ve_task_struct(tsk);
	w_retval = veos_pps_return_responce(pti->socket_descriptor,
			p_retval, ns_info, sizeof(struct ve_ns_info_proc));
	if (w_retval != 0)
		PPS_ERROR(cat_os_pps, "CMD_GET_MNS : failed to send responce");
	free(ns_info);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return w_retval;
}
