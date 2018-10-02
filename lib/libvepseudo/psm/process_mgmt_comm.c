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
* @file process_mgmt_comm.c
* @brief These file contains IPC handling make from PSEUDO
* to VEOS
*
* @internal
* @author PSMG
*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "libved.h"
#include "ve_socket.h"
#include "process_mgmt_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "pseudo_ptrace.h"

/**
 * @brief This function sends new VE process intimation to PSM.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] ve_proc new VE process creation information
 *
 * @return On failure, returns negative errno and on success, returns any
 * positive value
 *
 * @internal
 * @author PSMG / MP-MT
 */
int pseudo_psm_send_new_ve_process(int veos_sock_fd, struct new_ve_proc ve_proc)
{
	ssize_t retval = -1;
	PseudoVeosMessage new_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData new_ve_proc_msg = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	PSEUDO_TRACE("Entering");

	new_ve_proc.pseudo_veos_cmd_id = NEW_VE_PROC;

	new_ve_proc.has_pseudo_pid = true;
	new_ve_proc.pseudo_pid = syscall(SYS_gettid);

	new_ve_proc_msg.len = sizeof(struct new_ve_proc);
	new_ve_proc_msg.data = (uint8_t *)&ve_proc;

	new_ve_proc.has_pseudo_msg = true;
	new_ve_proc.pseudo_msg = new_ve_proc_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&new_ve_proc);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer "
				"return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&new_ve_proc, buf);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected length: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -EFAULT;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Request veos to schedule VE process.
 *
 * This function will prepare request to be sent to PSM to schedule
 * the VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 *
 * @return Returns negative errno on failure and any positive value on success.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_send_schedule_req(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_schedule_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf = NULL;
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	PSEUDO_TRACE("Entering");

	if (veos_sock_fd < 0) {
		PSEUDO_ERROR("Invalid(NULL) argument received");
		PSEUDO_DEBUG("Invalid veos_sock_fd argument received");
		goto malloc_error;
	}

	/* prepare request to be sent to PSM */
	ve_schedule_req.pseudo_veos_cmd_id = SCHEDULE;

	ve_schedule_req.has_pseudo_pid = true;
	ve_schedule_req.pseudo_pid = syscall(SYS_gettid);

	/* Pack ve_schedule_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_schedule_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer, "
				"return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_schedule_req, buf);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -EFAULT;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for acknowledgment of "SCHEDULE" request from veos.
 *
 * This function will wait for the acknowledgment from PSM which will
 * ensure that PSM has changed the state of VE process from RUNNING to
 * WAITING so that it can be scheduled.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 *
 * @return Returns negative errno on failure and a positive value on success.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_recv_schedule_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage *ve_schedule_ack = NULL;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Exiting");

	if (veos_sock_fd < 0) {
		PSEUDO_ERROR("Invalid(NULL) argument received");
		PSEUDO_DEBUG("Invalid veos_sock_fd argument received");
		retval = -EINVAL;
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive schedule acknowledgment "
				"from VEOS");
		retval = -EFAULT;
	} else {
		/* Unpack the structure */
		ve_schedule_ack = pseudo_veos_message__unpack(NULL, retval,
						      (const uint8_t *)(buf));
		if (NULL == ve_schedule_ack) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		/* Check message for SCHEDULE failure */
		if (ve_schedule_ack->has_syscall_retval) {
			if (-1 == ve_schedule_ack->syscall_retval) {
				PSEUDO_ERROR("Received negative acknowledgement"
						" for scheduling,"
						" return value %ld",
					ve_schedule_ack->syscall_retval);
				retval = ve_schedule_ack->syscall_retval;
			} else {
				PSEUDO_DEBUG("PSEUDO received SCHEDULE ACK");
				retval = ve_schedule_ack->syscall_retval;
			}
		}
		pseudo_veos_message__free_unpacked(ve_schedule_ack, NULL);
	}

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function sends Blocking System Call request to VEOS.
 *
 *	Function internally invokes pseudo_veos_send_cmd() to send the
 *	Blocking system call request to VEOS.
 *
 * @param[in] veos_sock_fd Socket descriptor for communication with VEOS.
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t pseudo_psm_block_syscall_req(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_block_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

       /* prepare request to be sent to PSM */
	ve_block_req.pseudo_veos_cmd_id = BLOCK;

	ve_block_req.has_pseudo_pid = true;
	ve_block_req.pseudo_pid = syscall(SYS_gettid);

	PSEUDO_DEBUG("Sending block for pid: %d",
			ve_block_req.pseudo_pid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_block_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_block_req,
							buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("failed to communicate with veos");
		PSEUDO_DEBUG("failed to send request to veos, "
				"transferred %ld bytes",
				retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function receives Blocking System Call ACK from VEOS.
 *
 *	Function internally invokes pseudo_veos_recv_cmd() to receive the
 *	Blocking system call ACK from VEOS.
 *
 * @param[in] veos_sock_fd Socket descriptor for communication with VEOS.
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t pseudo_psm_recv_block_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("failed to receive acknowledgement from"
				" veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}

	/* Check message for PSM GET BLOCK ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("received failure acknowledgement for"
				" block request, return value %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("veos performed syscall preprocessing"
					" for pid %ld", syscall(SYS_gettid));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * pseudo_psm_unblock_and_set_regval_req: Sends request to veos to set the
 *	system call return value and to set ve_process state unblock.
 *
 * @param veos_sock_fd: Descriptor used for commnication with veos.
 * @param sys_info: structure contains info about register no. and
 *		blocking_flag.
 * @param syscall_ret: Contains the return value of system call.
 *
 * @return: On failure, returns -1 and on success, returns any positive value.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int pseudo_psm_unblock_and_set_regval_req(int veos_sock_fd,
		struct ve_sys_info *sys_info, ret_t syscall_ret)
{
	ssize_t retval = -1;
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	ProtobufCBinaryData pseudo_info = {0};
	PseudoVeosMessage un_blk_n_set_reg = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("Entering");

	/* prepare request to be sent to PSM */
	un_blk_n_set_reg.pseudo_veos_cmd_id = UNBLOCK_AND_SET_REGVAL;

	un_blk_n_set_reg.has_pseudo_pid = true;
	un_blk_n_set_reg.pseudo_pid = syscall(SYS_gettid);

	un_blk_n_set_reg.has_syscall_retval = 1;
	un_blk_n_set_reg.syscall_retval = syscall_ret;

	pseudo_info.data = (uint8_t *)sys_info;
	pseudo_info.len = sizeof(struct ve_sys_info);

	un_blk_n_set_reg.has_pseudo_msg = true;
	un_blk_n_set_reg.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&un_blk_n_set_reg);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		PSEUDO_ERROR("malloc for message buffer failed. %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&un_blk_n_set_reg,
							buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("failed to send request to veos,"
				" transferred %ld bytes",
				retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function receives Unblock and retval ACK from VEOS.
 *
 *       Function internally invokes pseudo_veos_recv_cmd() to receive the
 *       Unblock system call ACK from VEOS.
 *
 * @param[in] veos_sock_fd Socket Descriptor used for commnication with VEOS.
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t pseudo_psm_recv_un_block_and_retval_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("failed to receive unblock acknowledgement"
				" from veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error\n");
		pseudo_abort();
	}

	/* Check message for GET UNBLOCK ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("received failure acknowledgement for"
				" unblock request, return value %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("received acknowledgement for syscall"
				" post-processing for pid %ld",
					syscall(SYS_gettid));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function communicates with VEOS for notifying the unblock and
 * set regval call request.
 *
 *       Function internally invokes "pseudo_psm_un_block_and_set_regval_req"
 *       request for communication with VEOS.
 *       Function receives the Unblock system call acknowledgement from VEOS by
 *       invoking "pseudo_psm_recv_un_block_ack".
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t un_block_and_retval_req(veos_handle *handle, int syscall_num,
		ret_t syscall_ret, bool blocking_flag)
{
	ssize_t retval = -1;
	struct ve_sys_info sys_info = {0};

	PSEUDO_TRACE("Entering");

	sys_info.is_blk = blocking_flag;
	sys_info.reg_num = SR00;
	sys_info.set_reg = true;
	sys_info.sys_trace_stop = sys_enter_trap;

	if (syscall_num == 315)
		sys_info.reg_num = SR08;

	/* In case of rt_sigreturn() system call return value
	 * is not updated.
	 */
	if (syscall_num == SYS_rt_sigreturn)
		sys_info.set_reg = false;

	/* In case of correctable h/w exception occured on a traced
	 * VE process we need to start the VE process.
	 */
	if (syscall_num == PTRACE_UNBLOCK_REQ)
		sys_info.set_reg = false;

	retval = pseudo_psm_unblock_and_set_regval_req(handle->veos_sock_fd,
			&sys_info, syscall_ret);
	if (retval < 0) {
		PSEUDO_ERROR("failed to notify veos for syscall post-processing");
		fprintf(stderr, "failed to notify veos for syscall"
				" post-processing\n");
		pseudo_abort();
	}
	retval = pseudo_psm_recv_un_block_and_retval_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos failed to perform syscall post-processing");
		fprintf(stderr, "veos failed to perform syscall"
			" post-processing\n");
		pseudo_abort();
	}

	PSEUDO_TRACE("Entering");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to set
 * value to user register.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] regid register ID
 * @param[in] value register value to be set
 * @param[in] Bit mask for updating register.
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
int ve_set_user_reg_req(int veos_sock_fd, int regid, uint64_t value,
						int64_t mask)
{
	ssize_t retval = -1;
	void *msg_buff = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	ProtobufCBinaryData set_usr_reg_msg = {0};
	PseudoVeosMessage set_usr_reg_req = PSEUDO_VEOS_MESSAGE__INIT;
	struct reg_data rd = {0};

	PSEUDO_TRACE("Entering");

	rd.reg = regid;
	rd.regval = value;
	rd.mask = mask;

	/* prepare request to be sent to PSM */
	set_usr_reg_req.pseudo_veos_cmd_id = SET_USR_REG;

	set_usr_reg_req.has_pseudo_pid = true;
	set_usr_reg_req.pseudo_pid = syscall(SYS_gettid);

	set_usr_reg_msg.len = sizeof(struct reg_data);
	set_usr_reg_msg.data = (uint8_t *)&rd;

	set_usr_reg_req.has_pseudo_msg = true;
	set_usr_reg_req.pseudo_msg = set_usr_reg_msg;

	/* Pack set_usr_reg_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&set_usr_reg_req);
	msg_buff = malloc(pseudo_msg_len);
	if (NULL == msg_buff) {
		PSEUDO_ERROR("Failed to allocate memory for message buffer, "
				"return value %s", strerror(errno));
		goto hndl_return;
	}
	memset(msg_buff, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&set_usr_reg_req, msg_buff);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}
	retval = pseudo_veos_send_cmd(veos_sock_fd, msg_buff, pseudo_msg_len);
	if (retval < msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
		goto hndl_return;
	}

	retval = 0;

hndl_return:
	if (msg_buff)
		free(msg_buff);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function waits for acknowledgment from PSM
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On success 0, on failure negative errno
 *
 * @internal
 * @author PSMG / Process management
 */
int recv_ve_set_user_reg_ack(int veos_sock_fd)
{
	int64_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive SCHEDULE acknowledgment "
				"from VEOS");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* Check message for SET user register ACK*/
	if (pseudo_msg->has_syscall_retval)
		retval = pseudo_msg->syscall_retval;

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
/**
 * @brief This function sends request to VEOS to set value
 * to the user registers.
 *
 * @param[in] handle VEOS handle
 * @param[in] regid register id to which value need to set
 * @param[in] regval value to which register will be set
 * @param[in] mask Bit mask for updating register.
 *
 * @return: 0 on success, negative errno on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int ve_set_user_reg(veos_handle *handle, int regid, uint64_t regval,
					int64_t mask)
{
	ssize_t retval = -1;

	PSEUDO_TRACE("Entering");

	retval = ve_set_user_reg_req(handle->veos_sock_fd, regid, regval,
						mask);
	if (0 > retval)
		PSEUDO_ERROR("Failed to send request to set user register"
					"VEOS");
	else {
		/* Waiting for ACK from PSM */
		retval = recv_ve_set_user_reg_ack(handle->veos_sock_fd);
		if (0 > retval)
			PSEUDO_ERROR("Failed to receive acknowledgement"
				"for user register");
		else
			PSEUDO_DEBUG("PSEUDO received SET USER REGISTER ACK");
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to set tid
 *	 address for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] set_tid_addr address to be set in clear_child_tid for the process
 *			invoking set_tid_address
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_send_set_tidaddr_req(int veos_sock_fd,
		uint64_t set_tid_addr)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_set_tid_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData set_tid_ve_proc_msg = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

	/* prepare request to be sent to PSM */
	ve_set_tid_req.pseudo_veos_cmd_id = SET_TID_ADDR;

	ve_set_tid_req.has_pseudo_pid = true;
	ve_set_tid_req.pseudo_pid = syscall(SYS_gettid);

	set_tid_ve_proc_msg.len = sizeof(set_tid_addr);
	set_tid_ve_proc_msg.data = (uint8_t *)&set_tid_addr;

	ve_set_tid_req.has_pseudo_msg = true;
	ve_set_tid_req.pseudo_msg = set_tid_ve_proc_msg;

	/* Pack ve_set_tid_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_set_tid_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer, "
				"return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_set_tid_req, buf);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM which will
 * ensure that PSM has set the clear_child_tid for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_recv_set_tidaddr_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage *ve_set_tid_ack = NULL;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)buf,
			MAX_PROTO_MSG_SIZE);
	if (-1 == retval)
		PSEUDO_ERROR("Failed to receive SET TID ADDRESS "
				"acknowledgement from veos");
	else {
		/* Unpack the structure */
		ve_set_tid_ack = pseudo_veos_message__unpack(NULL, retval,
				(const uint8_t *)(buf));
		if (NULL == ve_set_tid_ack) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		/* Check message for SET TID ADDR ACK */
		if (ve_set_tid_ack->has_syscall_retval) {
			if (ve_set_tid_ack->syscall_retval < 0) {
				PSEUDO_ERROR("Received negative acknowledgement"
						" for SET TID ADDRESS, "
						"return value %ld",
						ve_set_tid_ack->syscall_retval);
				retval = ve_set_tid_ack->syscall_retval;
			} else {
				retval = ve_set_tid_ack->syscall_retval;
				PSEUDO_DEBUG("PSEUDO received SET TID ADDRESS "
						"acknowledgement");
			}
		}
		pseudo_veos_message__free_unpacked(ve_set_tid_ack, NULL);
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Request veos to handle clone system call.
 *
 *	This function will prepare request to be sent to PSM to perform
 *	cloning for VE side.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 * @param[in] ve_clone_info Contains the clone arguments and child tid to be sent
 *		to PSM.
 * @param[in] parent_pid Contains the pid of the parent process.
 *
 * @return On failure, returns negative errno and on success,
 * 		returns a positive value.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_send_clone_req(int veos_sock_fd,
		struct pseudo_ve_clone_info ve_clone_info,
		pid_t parent_pid) {
	ssize_t retval = -1;
	PseudoVeosMessage ve_clone_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData clone_ve_proc_msg = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

	if (veos_sock_fd < 0) {
		PSEUDO_ERROR("Invalid(NULL) argument received");
		PSEUDO_DEBUG("Invalid veos_sock_fd argument received");
		goto malloc_error;
	}

	if (parent_pid < 0) {
		PSEUDO_ERROR("Invalid(NULL) argument received");
		PSEUDO_DEBUG("Invalid parent_pid argument received");
		goto malloc_error;
	}

	/* prepare request to be sent to PSM */
	ve_clone_req.pseudo_veos_cmd_id = CLONE_VE_PROC;

	ve_clone_req.has_pseudo_pid = true;
	ve_clone_req.pseudo_pid = parent_pid;

	ve_clone_req.has_pseudo_msg = true;
	clone_ve_proc_msg.len = sizeof(ve_clone_info);
	clone_ve_proc_msg.data = (uint8_t *)&ve_clone_info;
	ve_clone_req.pseudo_msg = clone_ve_proc_msg;

	/* Pack ve_clone_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_clone_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer, "
				"return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_clone_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -ENOMEM;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function sends fork() request to PSM
 *
 * @param[in] syscall_name syscall call name
 * @param[in] fork_info fork information of the VE process
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns negative errno
 * 		and on success, any positive value
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t pseudo_psm_send_fork_req(char *syscall_name,
		struct pseudo_ve_clone_info fork_info,
		int veos_sock_fd)
{

	ret_t retval = -1;
	PseudoVeosMessage ve_fork_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData fork_ve_proc_msg = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("Populating Request message for fork");
	/* Populate Pseudo<->PSM fork() request information
	 * structure
	 */
	ve_fork_req.pseudo_veos_cmd_id = FORK_VE_PROC;

	ve_fork_req.has_pseudo_pid = true;
	ve_fork_req.pseudo_pid = syscall(SYS_gettid);

	fork_ve_proc_msg.len = sizeof(struct pseudo_ve_clone_info);
	fork_ve_proc_msg.data = (uint8_t *)&fork_info;

	ve_fork_req.has_pseudo_msg = true;
	ve_fork_req.pseudo_msg = fork_ve_proc_msg;

	/* Pack ve_fork_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_fork_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval  = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer "
				"return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_fork_req, buf);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -ENOMEM;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Send delete request to PSM
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] clean_all_threads 0 for exit and 1 for exit_group system call
 * @param[in] exit_code VE process exit code
 *
 * @return On success, returns any positive value, -1 on failure
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t pseudo_psm_send_delete_ve_proc_req(int veos_sock_fd,
					int clean_all_threads,
					int exit_code,
					int pseudo_vefd)
{
	ret_t retval = -1;
	PseudoVeosMessage delete_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData delete_ve_proc_msg = {0};
	struct ve_exit_req exit_req = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1;

	PSEUDO_TRACE("Entering");

	/* Popuate DELETE VE process message */
	delete_ve_proc.pseudo_veos_cmd_id = DEL_VE_PROC;

	delete_ve_proc.has_pseudo_pid = true;
	delete_ve_proc.pseudo_pid = syscall(SYS_gettid);


	exit_req.clean_all_thread = clean_all_threads;
	exit_req.exit_code = exit_code;
	exit_req.pseudo_vefd = pseudo_vefd;

	delete_ve_proc_msg.len = sizeof(struct ve_exit_req);
	delete_ve_proc_msg.data = (uint8_t *)&exit_req;

	delete_ve_proc.has_pseudo_msg = true;
	delete_ve_proc.pseudo_msg = delete_ve_proc_msg;

	/* Pack delete_ve_proc before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&delete_ve_proc);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
                PSEUDO_ERROR("Failed to allocate memory for message buffer, "
                                "return value %d", -errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&delete_ve_proc,
							buf)) {
		PSEUDO_ERROR("Packing message protocol buffer error");
                PSEUDO_DEBUG("Expected length: %ld", pseudo_msg_len);
                fprintf(stderr, "Internal message protocol buffer error\n");
                /* FATAL ERROR: abort current process */
                pseudo_abort();
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
                PSEUDO_ERROR("Failed to send request to VEOS");
                PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
                                pseudo_msg_len, retval);
                retval = -ENOMEM;
	}

hndl_return:
	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM
 * it will ensure that PSM has done deletion of task for VE side.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 *
 * @return On failure, returns -1 and on success, returns the following values
 *		0 (for threads other than main thread),
 *		1 (for process, for non-Zombie main thread,for last thread in
 *		   thread group whose main thread is Zombie, for exit_group
 *				 case),
 *		2 (for Zombie thread)
 *
 * @internal
 * @author PSMG / MP-MT
 */
int pseudo_psm_recv_delete_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage *delete_ack = NULL;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive delete acknowledgment from"
				" VEOS");
	} else {
		PSEUDO_DEBUG("delete acknowledgment received");

		/* Unpack the structure */
		delete_ack = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(buf));
		if (NULL == delete_ack) {
                        PSEUDO_ERROR("Unpacking message protocol buffer error");
                        fprintf(stderr, "Internal message protocol "
                                        "buffer error\n");
                        /* FATAL ERROR: abort current process */
                        pseudo_abort();
		}

		/* Check message for DELETE ACK */
		if (delete_ack->has_syscall_retval) {
			if (delete_ack->syscall_retval >= 0) {
				PSEUDO_DEBUG("PSEUDO received "
						"DEL_VE_PROC ACK");
			} else {
				PSEUDO_ERROR("Received negative acknowledgement "
						" for exit, return value %ld",
						delete_ack->syscall_retval);
			}
			retval = delete_ack->syscall_retval;
		}
		pseudo_veos_message__free_unpacked(delete_ack, NULL);
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* pseudo_psm_send_start_ve_proc_req: This function sends start ve request
* to PSM. PSM will schedule the VE process after this.
*
* @param context_info: Context information of the VE process
* @param veos_sock_fd: Descriptor used to communicate with PSM
*
* @return:  On failure, returns negative errno and on success, returns any positive value
*/
int pseudo_psm_send_start_ve_proc_req(struct  ve_start_ve_req_cmd *start_ve_req,
		int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage start_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData start_ve_proc_msg = {0};
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

	/* Popuate START VE process message */
	start_ve_proc.pseudo_veos_cmd_id = START_VE_REQ;

	start_ve_proc.has_pseudo_pid = true;
	start_ve_proc.pseudo_pid = getpid();

	start_ve_proc_msg.len = sizeof(struct ve_start_ve_req_cmd);
	start_ve_proc_msg.data = (uint8_t *)start_ve_req;

	start_ve_proc.has_pseudo_msg = true;
	start_ve_proc.pseudo_msg = start_ve_proc_msg;

	/* Pack start_ve_proc before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&start_ve_proc);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for message buffer "
				"return value %d", errno);
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&start_ve_proc, buf);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* Send Start VE Process Request */
	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to VEOS");
		PSEUDO_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -EFAULT;
	}

	free(buf);

malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Waits for acknowledgment of "CLONE_VE_PROC" request from veos.
*
*	This function will wait for the acknowledgment from PSM which will
*	ensure that PSM has completed the clone functinality for a new
*	VE thread/process.
*
* @param[in] veos_sock_fd Descriptor used to communicate with PSM.
* @param[out] clone_response_rcvd clone acknowledgment structure received
*		from PSM.
*
* @return Value greater than or equal to 0 on success, negative errno on failure.
*/
int pseudo_psm_recv_start_ve_proc(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage *pseudo_msg = NULL;
	char buff[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd, buff,
					MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive START VE PROC "
				"acknowledgement from VEOS");
		retval = -EFAULT;
	} else {
		/* Unpack the structure */
		pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
				(const uint8_t *)(&buff));
		if (NULL == pseudo_msg) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}
		/* Check message for START VE PROC*/
		if (pseudo_msg->has_syscall_retval) {
			if (pseudo_msg->syscall_retval < 0) {
				PSEUDO_ERROR("Failure acknowledgement received "
						"for START VE PROC, "
						"return value %ld",
						pseudo_msg->syscall_retval);
				retval = pseudo_msg->syscall_retval;
			} else {
				PSEUDO_DEBUG("PSEUDO received START VE PROC "
						"acknowledgement");
				retval = pseudo_msg->syscall_retval;
			}
			pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
		}
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * pseudo_psm_recv_clone_ack: This function will wait for the acknowledgement
 * from PSM which will ensure that PSM has done the cloning work for VE side.
 *
 * @param veos_sock_fd: Descriptor used to communicate with PSM.
 * @param clone_response_rcvd: structure containing core_id, node_id and return
 *				value to be returned
 *
 * @return On failure, returns negative errno and on success,
 * 		returns a positive value.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int64_t pseudo_psm_recv_clone_ack(int veos_sock_fd,
		struct clone_response *clone_response_rcvd)
{
	ssize_t retval = -ENOMEM;
	PseudoVeosMessage *clone_ack = NULL;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	struct ve_proc_info *clone_proc_info = NULL;

	PSEUDO_TRACE("Entering");

	if (veos_sock_fd < 0) {
		PSEUDO_ERROR("Invalid argument");
		PSEUDO_DEBUG("Invalid veos_sock_fd argument received");
		goto hndl_return;
	}

	if (NULL == clone_response_rcvd) {
		PSEUDO_ERROR("Invalid argument");
		PSEUDO_DEBUG("Invalid clone_response_rcvd argument received");
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive CLONE acknowledgement "
				"from VEOS");
		retval = -ENOMEM;
	} else {
		/* Unpack the structure */
		clone_ack = pseudo_veos_message__unpack(NULL, retval,
							(const uint8_t *)(buf));
		if (NULL == clone_ack) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		clone_proc_info = (struct ve_proc_info *)
			((clone_ack->pseudo_msg).data);
		/* Check message for CLONE ACK */
		if (clone_ack->has_syscall_retval) {
			if (clone_ack->syscall_retval >= 0) {
				PSEUDO_DEBUG("PSEUDO received CLONE ACK");
				clone_response_rcvd->core_id = clone_proc_info->core_id;
				clone_response_rcvd->node_id = clone_proc_info->node_id;
				clone_response_rcvd->offset = clone_proc_info->offset;
				retval = clone_ack->syscall_retval;
			} else {
				PSEUDO_ERROR("Received negative acknowledgement"
						" for CLONE, return value %ld",
						clone_ack->syscall_retval);
				retval = clone_ack->syscall_retval;
			}
			pseudo_veos_message__free_unpacked(clone_ack, NULL);
		}
	}

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM
 * which will ensure that PSM has successfully created child VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns negative errno and on success, returns core num of the
 *		core on which child VE process will be scheduled.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int pseudo_psm_recv_fork_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage *fork_ack = NULL;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive FORK acknowledgement "
					"from VEOS");
		retval = -ENOMEM;
	} else {
		/* Unpack the structure */
		fork_ack = pseudo_veos_message__unpack(NULL, retval,
						       (const uint8_t *)(buf));
		if (NULL == fork_ack) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		/* Check message for FORK ACK */
		if (fork_ack->has_syscall_retval) {
			if (0 <= fork_ack->syscall_retval) {
				PSEUDO_DEBUG("PSEUDO received FORK "
						"acknowledgement");
				/* syscall_retval contains the child_core_id */
				retval = fork_ack->syscall_retval;
			} else {
				PSEUDO_ERROR("Recieved negative acknowledgement"
						" for FORK, return value %ld",
						fork_ack->syscall_retval);
				retval = fork_ack->syscall_retval;
			}
			pseudo_veos_message__free_unpacked(fork_ack, NULL);
		}
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * pseudo_psm_recv_load_binary_req: This function waits for the request
 * of load VE binary from PSM.
 *
 * @param veos_sock_fd: Descriptor used to communicate with PSM
 * @param ve_core_id: Core num on which the VE process is to be scheduled
 * @param ve_node_id: Node num on which the VE process is to be scheduled
 *
 * @return:  On failure, returns negative errno and on success, returns any
 * positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_recv_load_binary_req(int veos_sock_fd,
		int *ve_core_id,
		int *ve_node_id)
{
	ssize_t retval = -1;
	PseudoVeosMessage *ld_binary_req = NULL;
	struct new_proc_info new_ve_proc = {0};
	char buff[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd, buff,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive load binary acknowledgement"
				" from VEOS");
		retval = -EFAULT;
	} else {
		/* Unpack the structure */
		ld_binary_req = pseudo_veos_message__unpack(NULL, retval,
						    (const uint8_t *)(&buff));
		if (NULL == ld_binary_req) {
			PSEUDO_ERROR("Unpacking message protocol buffer error");
			fprintf(stderr, "Internal message protocol "
					"buffer error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		if (ld_binary_req->has_syscall_retval) {
			if (0 <= ld_binary_req->syscall_retval) {
				PSEUDO_DEBUG("PSEUDO received load binary "
						"acknowledgement");
				retval = ld_binary_req->syscall_retval;
				memcpy(&new_ve_proc,
						((PseudoVeosMessage *)
					 (ld_binary_req->pseudo_msg).data),
					(ld_binary_req->pseudo_msg).len);
				*ve_core_id = new_ve_proc.core_id;
				*ve_node_id = new_ve_proc.node_id;
			} else {
				PSEUDO_ERROR("Received negative acknowledgement"
						" for LOAD BINARY, "
						"return value %ld",
						ld_binary_req->syscall_retval);
				retval = ld_binary_req->syscall_retval;
			}
		}
			pseudo_veos_message__free_unpacked(ld_binary_req, NULL);
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function communicates with VEOS for notifying the blocking system
 * call request.
 *
 *	Function internally invokes "pseudo_psm_block_syscall_req" request for
 *	communication with VEOS.
 *	Function receives the blocking system call acknowledgement from VEOS by
 *	invoking "pseudo_psm_recv_block_ack".
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int64_t block_syscall_req_ve_os(veos_handle *handle)
{
	ssize_t retval = -1;

	PSEUDO_TRACE("Entering");

	/* Send BLOCKING system call to veos */
	retval = pseudo_psm_block_syscall_req(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("failed to notify veos for syscall"
				" pre-processing");
	} else {
		/* Wait for BLOCK ACK from veos */
		retval = pseudo_psm_recv_block_ack(handle->veos_sock_fd);
		if (0 > retval) {
			PSEUDO_ERROR("veos failed to perform syscall"
				" pre-processing");
		}
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}


/**
 * @brief This function will send request to veos for getting the CPU and NUMA
 * node.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_send_getcpu_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;

	PSEUDO_TRACE("Entering");

	ve_proc_req.pseudo_veos_cmd_id = GET_CPU_REQ;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_proc_req, buf);

	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief This function will wait for acknowledgement from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[out] cpu_info Structure contain information for code id and node id
 *
 * @return On failure, returns -1 and on success, returns positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_recv_getcpu_ack(int veos_sock_fd, struct ve_cpu_info *cpu_info)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;
	PSEUDO_TRACE("Entering");

	if (!cpu_info)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive getcpu"
				" acknowledgement from veos");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	memcpy(cpu_info, pseudo_msg->pseudo_msg.data,
			pseudo_msg->pseudo_msg.len);
	/* Check message for GET CPU ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received "
					"for getcpu");
			PSEUDO_DEBUG("Failure acknowledgement received "
					"for getcpu, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("PSEUDO recieved GET CPU ACK");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will send request to veos for getting the SCHED_RR
 *	 interval for the named process
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] ve_pid PID of VE process
 *
 * @return On failure, returns -1 and on success, returns positive value
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_send_get_inr_req(int veos_sock_fd, pid_t ve_pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	ProtobufCBinaryData pseudo_info = {0};

	PSEUDO_TRACE("Entering");

	ve_proc_req.pseudo_veos_cmd_id = GET_SCHED_INTRVL;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.data = (uint8_t *)&ve_pid;
	pseudo_info.len = sizeof(pid_t);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_proc_req, buf);

	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief This function will wait for SCHED_RR interval ack.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[out] tp_info Contains time related paramters populated by veos
 *
 * @return On failure, returns -errno and on success, returns positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_recv_get_inr_ack(int veos_sock_fd, struct timespec *tp_info)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;
	PSEUDO_TRACE("Entering");

	if (!tp_info) {
		PSEUDO_ERROR("NULL argument recieved");
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to communicate to veos");
		PSEUDO_DEBUG("Failed to receive sched_rr_get_interval"
				" acknowledgement from veos");
		retval = -EFAULT;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	memcpy(tp_info, pseudo_msg->pseudo_msg.data,
			pseudo_msg->pseudo_msg.len);

	/* Check message for GET INR ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Received failure acknowledgement");
			PSEUDO_DEBUG("Failure acknowledgement received "
					"for sched_rr_get_interval, "
					"return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("PSEUDO received "
					"GET SCHED INTRVL ACK");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to get clock
r*	 cputime of VE process.
 *
 * @param[in] veos_sock_fd: Descriptor used to communicate with PSM
 * @param[in] type Determine process or thread
 *			0 for thread
 *			1 for process
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_send_clk_cputime_req(int veos_sock_fd,
		struct ve_clockinfo clockinfo)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_clk_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	ProtobufCBinaryData cputime = {0};

	PSEUDO_TRACE("Entering");

	/* prepare request to be sent to PSM */
	ve_clk_req.pseudo_veos_cmd_id = CLK_CPUTIME;

	ve_clk_req.has_pseudo_pid = true;
	ve_clk_req.pseudo_pid = syscall(SYS_gettid);

	cputime.len = sizeof(clockinfo);
	cputime.data = (uint8_t *)&clockinfo;

	ve_clk_req.has_pseudo_msg = true;
	ve_clk_req.pseudo_msg = cputime;
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_clk_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_clk_req, buf);

	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief This function will wait for the acknowledgement from PSM and the
 *	   clock cputime for VE process or thread.
 *
 * @param[in] veos_sock_fd: Descriptor used to communicate with PSM
 * @param[out] tp Pointer to struct timespec
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_recv_clk_cputime_ack(int veos_sock_fd, struct timespec *tp)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	if (!tp) {
		PSEUDO_ERROR("NULL argument recieved");
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive clock cputime"
				" acknowledgement from veos");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for PSM clk_cputime ack  */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received "
					"for clock cputime");
			PSEUDO_DEBUG("Failure acknowledgement received "
					"for clock cputime, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(tp,
			       (pseudo_msg->pseudo_msg.data),
			       (pseudo_msg->pseudo_msg.len));
			PSEUDO_DEBUG("PSEUDO received clk_cputime ack");
		}
	}
		pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
/**
 * @brief This function will prepare request to be sent to PSM to get rlimit
 *		of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] resource Resource to get
 * @param[in] resource PID of VE process
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_send_get_rlimit_req(int veos_sock_fd,
		int resource, pid_t pid)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_rlimit_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	struct rlimit_info rlimit = {0};
	ProtobufCBinaryData pseudo_info = {0};

	PSEUDO_TRACE("Entering");

	ve_rlimit_req.pseudo_veos_cmd_id = GET_RLIMIT;

	ve_rlimit_req.has_pseudo_pid = true;
	ve_rlimit_req.pseudo_pid = syscall(SYS_gettid);

	rlimit.pid = pid;
	rlimit.resource = resource;

	pseudo_info.len = sizeof(struct rlimit_info);
	pseudo_info.data = (uint8_t *)&rlimit;

	ve_rlimit_req.has_pseudo_msg = true;
	ve_rlimit_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rlimit_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_rlimit_req, buf);

	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief This function will wait for the acknowledgement from PSM and
 *	 the resource limit for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[out] rlim Pointer to struct rlimit
 *
 * @return On failure, returns -errno and on success, returns any positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_recv_get_rlimit_ack(int veos_sock_fd, struct rlimit *rlim)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	if (!rlim) {
		PSEUDO_ERROR("NULL argument recieved");
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive getrlimit"
				" acknowledgement from veos");
		retval = -EFAULT;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received "
					"for getrlimit");
			PSEUDO_DEBUG("Failure acknowledgement received "
					"for getrlimit, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved GET RLIMIT ACK");
			retval = pseudo_msg->syscall_retval;
			memcpy(rlim, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("EXITING");
	return retval;
}


/**
 * @brief This function will prepare request to be sent to PSM to set rlimit of
 *	 VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] resource Resource to get
 * @param[in] rlim Resource limit to set
 * @param[in] pid PID of VE process
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_send_set_rlimit_req(int veos_sock_fd,
		int resource, struct rlimit rlim, pid_t pid)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_rlimit_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	struct rlimit_info rlim_info = {0};
	ProtobufCBinaryData pseudo_info = {0};

	PSEUDO_TRACE("Entering");

	ve_rlimit_req.pseudo_veos_cmd_id = SET_RLIMIT;

	ve_rlimit_req.has_pseudo_pid = true;
	ve_rlimit_req.pseudo_pid = syscall(SYS_gettid);

	rlim_info.pid = pid;
	rlim_info.resource = resource;
	rlim_info.rlim = rlim;

	pseudo_info.data = (uint8_t *)&rlim_info;
	pseudo_info.len = sizeof(rlim_info);

	ve_rlimit_req.has_pseudo_msg = true;
	ve_rlimit_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rlimit_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_rlimit_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("EXITING");
	return retval;

}

/**
 * @brief This function will wait for the acknowledgement from PSM for VE
 *	 process
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1, -2, -3 and on success, returns
 *			any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_recv_set_rlimit_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;
	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive setrlimit"
				" acknowledgement from veos");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	/* Check ack value fom veos */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received "
					"for setrlimit");
			PSEUDO_DEBUG("Failure acknowledgement received "
					"for setrlimit, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved SET RLIMIT ACK");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to get affinity
 * of VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 * @param[in] pid PID of VE process
 * @param[in] cpusetsize Size of cpu mask
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_send_getaffinity_req(int ve_sock_fd,
		pid_t pid, size_t cpusetsize)
{
	ret_t retval = -1;
	struct ve_setaffinity_req ve_req = {0};
	PseudoVeosMessage getaffinity_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	ProtobufCBinaryData pseudo_info = {0};

	PSEUDO_TRACE("Entering");

	getaffinity_req.pseudo_veos_cmd_id = GET_AFFINITY;

	getaffinity_req.has_pseudo_pid = true;
	getaffinity_req.pseudo_pid = syscall(SYS_gettid);

	ve_req.pid = pid;
	ve_req.cpusetsize = cpusetsize;

	pseudo_info.len = sizeof(ve_req);
	pseudo_info.data = (uint8_t *)&ve_req;

	getaffinity_req.has_pseudo_msg = true;
	getaffinity_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&getaffinity_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&getaffinity_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(ve_sock_fd, buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}
/**
 * @brief This function will wait for the acknowledgement from PSM and
 * the return value for VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 * @param[out] mask CPU mask
 *
 * @return On failure, returns -errno and on success,returns retval for
 * VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_recv_getaffinity_ack(int ve_sock_fd, cpu_set_t *mask)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	if (!mask) {
		PSEUDO_ERROR("NULL argument recieved");
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(ve_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (retval <= 0) {
		PSEUDO_ERROR("Failed to receive getrlimit"
				" acknowledgement from veos");
		retval = -EFAULT;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	/* Check ack value fom veos */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received"
					" for getrlimit");
			PSEUDO_DEBUG("Failure acknowledgement received"
					" for getrlimit, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved GET AFFINITY ACK");
			retval = pseudo_msg->syscall_retval;
			memcpy(mask, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}


/**
 * @brief This function will prepare request to be sent to PSM to set affinity
 * of VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 * @param[in] pid PID of VE process
 * @param[in] mask CPU mask
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_send_setaffinity_req(int ve_sock_fd, pid_t pid, cpu_set_t mask)
{
	ret_t retval = -1;
	struct ve_setaffinity_req ve_req = {0};
	PseudoVeosMessage setaffinity_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;
	ProtobufCBinaryData pseudo_info = {0};

	PSEUDO_TRACE("Entering");

	/* Populate the information in struct ve_setaffinity_req */
	ve_req.pid = pid;
	ve_req.mask = mask;

	setaffinity_req.pseudo_veos_cmd_id = SET_AFFINITY;

	setaffinity_req.has_pseudo_pid = true;
	setaffinity_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.len = sizeof(struct ve_setaffinity_req);
	pseudo_info.data = (uint8_t *)&ve_req;

	setaffinity_req.has_pseudo_msg = true;
	setaffinity_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&setaffinity_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&setaffinity_req, buf);

	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(ve_sock_fd, buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM and
 * the return value for VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -errno and on success,returns 0 for
 * VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_recv_setaffinity_ack(int ve_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(ve_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (retval <= 0) {
		retval = -EFAULT;
		PSEUDO_ERROR("Failed to receive setaffinity"
				" acknowledgement from veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	/* Check ACK for GETAFFINITY*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received"
					" for setaffinity");
			PSEUDO_DEBUG("Failure acknowledgement received"
					" for setaffinity, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("PSEUDO recieved SET AFFINITY ACK");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to get
 * rusage of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] who resource usage measures for who
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_send_get_rusage_req(int veos_sock_fd,
		struct ve_rusage_info rusage_task)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_rusage_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info = {0};
	ssize_t pseudo_msg_len = -1 , msg_len = -1;
	void *buf = NULL;

	PSEUDO_TRACE("Entering");

	ve_rusage_req.pseudo_veos_cmd_id = GET_RUSAGE;

	ve_rusage_req.has_pseudo_pid = true;
	ve_rusage_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.len  = sizeof(rusage_task);
	pseudo_info.data = (uint8_t *)&rusage_task;

	ve_rusage_req.has_pseudo_msg = true;
	ve_rusage_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rusage_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&ve_rusage_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM and
 *	 the resource usage for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[out] ve_r Pointer to struct ve_rusage
 *
 * @return On failure, returns -1 or -errno  and on success, returns 0
 *
 * @internal
 * @author PSMG / Process management
 */
int64_t pseudo_psm_recv_get_rusage_ack(int veos_sock_fd, struct ve_rusage *ve_r)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");
	if (!ve_r)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive rusage"
				" acknowledgement from veos");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure acknowledgement received"
					" for rusage");
			PSEUDO_DEBUG("Failure acknowledgement received"
					" for rusage, return value %ld",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved RUSAGE ACK");
			retval = pseudo_msg->syscall_retval;
			memcpy(ve_r, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will send request to veos for getting information on
 * overall system statistics.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_send_sysinfo_req(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage sysinfo_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;

	PSEUDO_TRACE("Entering");

	sysinfo_req.pseudo_veos_cmd_id = SYSINFO_REQ;

	sysinfo_req.has_pseudo_pid = true;
	sysinfo_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sysinfo_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len = pseudo_veos_message__pack(&sysinfo_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Wait for acknowledgement from VEOS for SYSINFO_REQ.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 * @param[in] vh_sysinfo pointer to struct sysinfo that will be filled by VEOS
 *
 * @return 0 value on success, -1 on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_recv_sysinfo_ack(int veos_sock_fd, struct sysinfo *vh_sysinfo)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");
	if (!vh_sysinfo)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive sysinfo"
				" acknowledgement from veos");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_DEBUG("Failure acknowledgement received"
					" for sysinfo, return value %ld",
					pseudo_msg->syscall_retval);
			PSEUDO_ERROR("Failure acknowledgement received"
					"sysinfo");
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved SYSINFO ACK");
			retval = pseudo_msg->syscall_retval;
			memcpy(vh_sysinfo, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will send request to veos for enabling/disabling
 * the accounting.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] path_buff Pointer to filename will be use for accounting
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_send_acct_req(int veos_sock_fd, char *path_buff)
{
	ssize_t retval = -1;
	PseudoVeosMessage acct_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;

	PSEUDO_TRACE("Entering");

	acct_req.pseudo_veos_cmd_id = ACCT_REQ;

	acct_req.has_pseudo_pid = true;
	acct_req.pseudo_pid = syscall(SYS_gettid);

	if (NULL != path_buff) {
		pseudo_info.len  = strlen(path_buff) + 1;
		pseudo_info.data = (uint8_t *)path_buff;
		acct_req.has_pseudo_msg = true;
		acct_req.pseudo_msg = pseudo_info;
	}

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&acct_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -EFAULT;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&acct_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for acknowledgement from VEOS for ACCT_REQ
 * command.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_recv_acct_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive acct"
				" acknowledgement from veos");
		retval = -EFAULT;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_DEBUG("Failure acknowledgement received"
					" for acct, return value %ld",
					pseudo_msg->syscall_retval);
			PSEUDO_ERROR("Failure acknowledgement received"
					" for acct");
			retval = pseudo_msg->syscall_retval;
		} else {
			PSEUDO_DEBUG("PSEUDO recieved ACCT ACK");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function check vefd status.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ret_t pseudo_psm_send_vefd_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage vefd_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf = NULL;
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PSEUDO_TRACE("Entering");

	vefd_req.pseudo_veos_cmd_id = VEFD_REQ;

	vefd_req.has_pseudo_pid = true;
	vefd_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vefd_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed.");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);
	msg_len =  pseudo_veos_message__pack(&vefd_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM for
 *	vefd status request.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -2 and on success, returns status of vefd
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t pseudo_psm_recv_vefd_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = {0};

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive vefd"
				" acknowledgement from veos");
		retval = -2;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval)
		retval = pseudo_msg->syscall_retval;
	else
		retval = -2;

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will send request to veos for updated GID/UID
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos.
 * @param[in] gid_uid updated GID or UID value.
 * @param[in] flag to ensure updated value is GID or UID.
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_send_setuidgid_req(int veos_sock_fd, uint64_t gid_uid, bool flag)
{
	ssize_t retval = -1;
	PseudoVeosMessage gid_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info = {0};
	struct giduid_info id_info = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	void *buf = NULL;

	PSEUDO_TRACE("Entering");
	gid_req.pseudo_veos_cmd_id = GIDUID_REQ;

	gid_req.has_pseudo_pid = true;
	gid_req.pseudo_pid = syscall(SYS_gettid);

	id_info.data = gid_uid;
	id_info.info_flag = flag;
	pseudo_info.len = sizeof(struct giduid_info);
	pseudo_info.data = (uint8_t *)&id_info;
	gid_req.has_pseudo_msg = true;
	gid_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&gid_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_ERROR("malloc for message buffer failed.");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&gid_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_ERROR("Internal message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_ERROR("Failed to send request to veos");
		PSEUDO_DEBUG("Expected bytes: %ld, transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function receives GID and UID System Call ACK from VEOS.
 *
 *	Function internally invokes pseudo_veos_recv_cmd() to receive the
 *	GID and UID system call ACK from VEOS.
 *
 * @param[in] veos_sock_fd Socket descriptor for communication with VEOS.
 *
 * @return -1 on FAILURE , non-negative integer on SUCCESS.
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_psm_recv_setuidgid_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("failed to receive setuidgid"
				" acknowledgement from veos");
		retval = -EFAULT;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error\n");
		pseudo_abort();
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval)
		retval = pseudo_msg->syscall_retval;
	else
		retval = -1;

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
