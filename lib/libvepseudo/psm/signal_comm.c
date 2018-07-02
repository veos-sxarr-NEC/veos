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
/*
 * @file signal_comm.c
 * @brief Handles signal related ipc to and from veos.
 *
 *	This file contain functions which are used to communicate to and from
 *	veos for signal related requests.
 *
 * @internal
 * @author Signal Handling
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include <errno.h>
#include "libved.h"
#include "sys_common.h"
#include "ve_socket.h"
#include "signal_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"

/**
 * @brief This function will send signal request to veos
 *
 * @param[in] signal_info Signal information of VE process
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return: On failure, returns -1 and on success, returns positive value
 */
int pseudo_psm_send_signal_req(struct ve_signal_info *signal_info,
				int veos_sock_fd)
{
	ssize_t retval = -1;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;
	PseudoVeosMessage ve_signal_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_signal_req_msg = {0};

	ve_signal_req.pseudo_veos_cmd_id = VE_SIGNAL_REQ;

	ve_signal_req.has_pseudo_pid = true;
	ve_signal_req.pseudo_pid = syscall(SYS_gettid);

	ve_signal_req_msg.len = sizeof(struct ve_signal_info);
	ve_signal_req_msg.data = (uint8_t *)signal_info;

	ve_signal_req.has_pseudo_msg = true;
	ve_signal_req.pseudo_msg = ve_signal_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_signal_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_signal_req,
							buf);
	if (pseudo_msg_len != msg_len) {
		WRITE(2, "internal message protocol buffer error\n", 40);
		pseudo_abort();
	}

	retval = pseudo_veos_send_signal_req(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len)
		retval = -EFAULT;

	free(buf);
malloc_error:
	return retval;
}

/**
 * @brief Waits for acknowledgment of "VE_SIGNAL_REQ" request from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_signal_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg;

	retval = pseudo_veos_recv_signal_ack(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (0 > retval) {
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		WRITE(2, "internal message protocol buffer error\n", 40);
		pseudo_abort();
	}
	/* Check for VE_SIGNAL_REQ ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0)
			retval = pseudo_msg->syscall_retval;
		else
			retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	return retval;
}

/**
 * @brief Sends "SIGRETURN REQ" to veos
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns a positive value.
 */
int pseudo_psm_send_sigreturn_req(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigret_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;

	PSEUDO_TRACE("Entering");

	ve_sigret_req.pseudo_veos_cmd_id = SIGRETURN_REQ;

	ve_sigret_req.has_pseudo_pid = true;
	ve_sigret_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_sigret_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_sigret_req,
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
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends "SIGACTION REQ" to veos
 *
 * @param[in] sigaction_info Structure containing sigaction parameters
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value.
 */
int pseudo_psm_send_sigaction_req(struct ve_sigaction_info *sigaction_info,
					int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigaction_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_sigaction_req_msg = {0};
	void *buf;
	ssize_t pseudo_msg_len, msg_len;

	PSEUDO_TRACE("Entering");

	ve_sigaction_req.pseudo_veos_cmd_id = SIGACTION_REQ;

	ve_sigaction_req.has_pseudo_pid = true;
	ve_sigaction_req.pseudo_pid = syscall(SYS_gettid);

	ve_sigaction_req_msg.len = sizeof(struct ve_sigaction_info);
	ve_sigaction_req_msg.data = (uint8_t *)sigaction_info;

	ve_sigaction_req.has_pseudo_msg = true;
	ve_sigaction_req.pseudo_msg = ve_sigaction_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size
		(&ve_sigaction_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_sigaction_req,
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
	if (retval != pseudo_msg_len) {
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for the acknowledgment of "SIGACTION REQ" from veos
 *	which will ensure that veos has set the action for the signal.
 *
 * @param[out] old_act Stores the old action os the signal received from veos
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1/-errno and on success, returns any positive value.
 */
int pseudo_psm_recv_sigaction_ack(struct sigaction *old_act, int veos_sock_fd)
{
	ssize_t retval = -1;
	char buff[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buff, MAX_PROTO_MSG_SIZE);
	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
		goto hndl_error;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
						 retval,
						 (const uint8_t *)buff);
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}

	/* Check message for SIGACTION ACK*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Receiving acknowledgement from veos"
					" failed");
			PSEUDO_DEBUG("sigaction acknowledgement request returned %d",
					(int)retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("Received acknowledgement for"
					" sigaction, syscall return"
					" value %ld", retval);
			memcpy(old_act, pseudo_msg->pseudo_msg.data,
			       pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for "SIGRETURN REQ" acknowledgment from veos which
 *	will ensure that veos has restored the hardware context of VE
 *	process after handling signal
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 */
int pseudo_psm_recv_sigreturn_ack(int veos_sock_fd, sigset_t *curr_mask)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}

	/* Check message for SIGRETURN ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Received failure acknowledgement for"
					" sigreturn request, return"
					" value %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(curr_mask, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
			PSEUDO_DEBUG("Received acknowledgement for"
					" sigreturn request, return"
					" value %ld", retval);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Request VEOS to set new signal alternate stack
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] sigalt_req New signal stack information
 *
 * @return: On failure, returns -1 and on success, returns any positive value
 */
int pseudo_psm_send_setnew_sas(int veos_sock_fd,
		struct ve_sigalt_info *sigalt_req)
{
	ssize_t retval = -1;
	PseudoVeosMessage new_sas_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	size_t pseudo_msg_len, msg_len;
	ProtobufCBinaryData ve_new_sas_msg;

	PSEUDO_TRACE("Entering");

	new_sas_req.pseudo_veos_cmd_id = SET_NEW_SAS;

	new_sas_req.has_pseudo_pid = true;
	new_sas_req.pseudo_pid = syscall(SYS_gettid);

	ve_new_sas_msg.len = sizeof(struct ve_sigalt_info);
	ve_new_sas_msg.data = (uint8_t *)sigalt_req;

	new_sas_req.has_pseudo_msg = true;
	new_sas_req.pseudo_msg = ve_new_sas_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&new_sas_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&new_sas_req,
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
	if (retval < (ssize_t)pseudo_msg_len) {
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for acknowledgment for "SET NEW SAS" request
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[out] sigalt_ack Stores the old alternate stack information
 *	as received from veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_setnew_sas_ack(int veos_sock_fd,
		struct ve_sigalt_info *sigalt_ack)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval
			, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}
	/* Check message for NEW SAS ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Receiving acknowledgement from veos"
					" failed");
			PSEUDO_DEBUG("acknowledgement from veos for new_sas request"
					" returned %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(sigalt_ack, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
			PSEUDO_DEBUG("Received acknowledgement for"
					"  new_sas request, return"
					" value %ld", retval);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief Request veos to set new signal blocking mask
 *
 * @param[in] newset New signal blocking mask
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return: On failure, returns -1 and on success, returns any positive value
 */
int pseudo_psm_send_sigprocmask_req(struct ve_signal_mask *ve_mask,
		int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage sigprocmask_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;
	ProtobufCBinaryData pseudo_info;

	PSEUDO_TRACE("Entering");

	sigprocmask_req.pseudo_veos_cmd_id = SIGPROCMASK_REQ;

	sigprocmask_req.has_pseudo_pid = true;
	sigprocmask_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.data = (uint8_t *)ve_mask;
	pseudo_info.len = sizeof(struct ve_signal_mask);

	sigprocmask_req.has_pseudo_msg = true;
	sigprocmask_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigprocmask_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&sigprocmask_req,
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
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief Waits for acknowledgment of "SIGPROCMASK REQ" request.
 *	It also retrieves the old signal mask stored at veos.
 *
 * @param[out] oldset Stores the retrieved old signal mask
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_sigprocmask_ack(struct ve_signal_mask *recv_mask, int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			buf, MAX_PROTO_MSG_SIZE);
	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)buf);
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}

	/* Check for SIGPROCMASK  ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Received Failure acknowledgement for"
					" sigprocmask request, return"
					" value %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			if (pseudo_msg->has_pseudo_msg)
				memcpy(recv_mask, pseudo_msg->pseudo_msg.data,
						pseudo_msg->pseudo_msg.len);
			PSEUDO_DEBUG("Received acknowledgement for"
					" sigprocmask request, return"
					" value %ld", retval);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Request veos to handle hardware exception
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] ve_siginfo Hardware exception mapped signal's information
 *
 * @return -1 on failure and positive value on success
 */
ret_t pseudo_psm_send_exception_req(int veos_sock_fd, siginfo_t *ve_siginfo)
{
	ret_t retval = 0;
	PseudoVeosMessage hndl_excep_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;
	ProtobufCBinaryData pseudo_info;

	hndl_excep_req.pseudo_veos_cmd_id = HW_EXP_REQ;

	hndl_excep_req.has_pseudo_pid = true;
	hndl_excep_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.data = (uint8_t *)ve_siginfo;
	pseudo_info.len = sizeof(siginfo_t);

	hndl_excep_req.has_pseudo_msg = true;
	hndl_excep_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&hndl_excep_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&hndl_excep_req,
							buf);
	if (pseudo_msg_len != msg_len) {
		WRITE(2, "internal message protocol buffer error\n", 40);
		pseudo_abort();
	}
	retval = pseudo_veos_send_signal_req(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len)
			retval = -EFAULT;

	free(buf);

malloc_error:
	return retval;
}

/**
 * @brief Waits for acknowledgment of "HW_EXP_REQ" request from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_hw_exp_ack(int veos_sock_fd)
{
	int retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	retval = pseudo_veos_recv_signal_ack(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (0 > retval)
		goto hndl_return;

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		WRITE(2, "internal message protocol buffer error\n", 40);
		pseudo_abort();
	}

	/* Check for HW_EXP_REQ ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0)
			retval = pseudo_msg->syscall_retval;
		else
			retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	return retval;
}


/**
 * @brief Request veos to send signal request to veos.
 *
 *	This function packs the signal related information and then
 *	sends signal request to veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos.
 *
 * @return: On failure, returns -1 and on success, returns any positive value
 */
int pseudo_psm_send_sigpending_req(int veos_sock_fd)
{
	ssize_t retval = -1;
	PseudoVeosMessage sigpending_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;

	PSEUDO_TRACE("Entering");

	sigpending_req.pseudo_veos_cmd_id = SIGPENDING_REQ;

	sigpending_req.has_pseudo_pid = true;
	sigpending_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigpending_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&sigpending_req,
							buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "internal message protocol buffer error\n");
		PSEUDO_ERROR("internal message protocol buffer error");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;

}

/**
 * @brief Waits for acknowledgment of "SIGPENDING REQ" request from veos.
 *
 * @param[out] veos_set Stores the set of pending signal information
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_sigpending_ack(sigset_t *veos_set, int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}

	/* Check for SIGPENDING  ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Receiving acknowledgement failed for"
					" sigpending request");
			PSEUDO_DEBUG("sigepnding request acknowledgement returned %d",
					(int)retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(veos_set, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
			PSEUDO_DEBUG("Received acknowledgement for"
					" sigpending request, return"
					" value %ld", retval);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Waits for the acknowledgment of "SIGSUSPEND_REQ" from veos
* which will ensure that veos has set the sigsuspend mask.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos
*
* @return On failure, return either -1 or failure retval received
* from veos and on success, returns 0.
*/
int pseudo_psm_recv_sigsuspend_ack(int veos_sock_fd)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (0 > retval) {
		PSEUDO_ERROR("failed to communicate with veos");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		pseudo_abort();
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_ERROR("Receiving acknowledgement from VEOS failed");
			PSEUDO_DEBUG("sigsuspend request, return"
					" value %ld", retval);
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("Received acknowledgement for"
					" sigsuspend request, return"
					" value %ld", retval);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Sends "SIGSUSPEND_REQ" to veos
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos
* @param[in] sigmask Signal mask.
*
* @return On failure, returns -1 and on success, returns positive value.
*/
int pseudo_psm_send_sigsuspend_req(int veos_sock_fd, sigset_t *sigmask)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigsuspend_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_sigsuspend_req_msg;
	void *buf;
	ssize_t pseudo_msg_len, msg_len;

	PSEUDO_TRACE("Entering");

	ve_sigsuspend_req.pseudo_veos_cmd_id = SIGSUSPEND_REQ;

	ve_sigsuspend_req.has_pseudo_pid = true;
	ve_sigsuspend_req.pseudo_pid = syscall(SYS_gettid);

	ve_sigsuspend_req_msg.len = sizeof(sigset_t);
	ve_sigsuspend_req_msg.data = (uint8_t *)sigmask;

	ve_sigsuspend_req.has_pseudo_msg = true;
	ve_sigsuspend_req.pseudo_msg = ve_sigsuspend_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size
		(&ve_sigsuspend_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		retval = -errno;
		PSEUDO_ERROR("malloc for message buffer failed: %s"
				, strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&ve_sigsuspend_req,
							buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "internal message protocol buffer error\n");
		PSEUDO_ERROR("internal message protocol buffer error");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %ld bytes", retval);
		PSEUDO_ERROR("failed to communicate with veos");
		retval = -EFAULT;
	}

	free(buf);
malloc_error:
	PSEUDO_TRACE("Exiting");
	return retval;
}
