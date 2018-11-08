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
 * @file pseudo_ptrace.c
 * @brief Handlers for special handling to de done in pseudo for the
 * support of ve_ptrace() system call
 *
 * @internal
 * @author PTRACE
 */

#include "sys_common.h"
#include "pseudo_ptrace.h"
#include "ve_socket.h"
#include "comm_request.h"
#include "ve_signal.h"
#include "proto_buff_schema.pb-c.h"

__thread bool sys_enter_trap = false;

/**
 * @brief Function will send the requested signal to itself with the
 * provided signal information(siginfo_t).
 *
 * @param[in] signo Signal number to deliver
 * @param[in] sicode Signal code to send
 * @param[in] siaddr Memory location which caused fault
 *
 */
void send_sig_to_itself(int signo, int sicode, void *siaddr)
{
	int retval = -1;
	siginfo_t siginfo;
	sigset_t sigset;
	pid_t tid = syscall(SYS_gettid);
	bool sig_unblock = false;

	PSEUDO_TRACE("Entering");

	memset(&siginfo, 0, sizeof(siginfo_t));
	siginfo.si_signo = signo;
	siginfo.si_pid = getpid();
	siginfo.si_code = sicode;
	siginfo.si_addr = siaddr;

	/* Get the current signal mask */
	sigemptyset(&sigset);
	pthread_sigmask(0, NULL, &sigset);

	PSEUDO_INFO("Sending Signal %d to TID: %d", signo, tid);
	/* Check if SIGTRAP is blocked, then we need to
	 * unblock SIGTRAP signal.
	 */
	if (sigismember(&sigset, SIGTRAP)) {
		/* Unblock SIGTRAP signal */
		sigemptyset(&sigset);
		PSEUDO_DEBUG("Unblocking SIGTRAP signal");
		sigaddset(&sigset, SIGTRAP);
		pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
		sig_unblock = true;
	}

	/* rt_tgsigqueueinfo() system call is invoked to send signal */
	retval = syscall(SYS_rt_tgsigqueueinfo, getpid(), tid,
			siginfo.si_signo, &siginfo);
	/* Check if SIGTRAP is blocked for ve process, then we
	 * need to block again SIGTRAP signal.
	 */
	if (sig_unblock) {
		/* Block SIGTRAP signal */
		pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	}
	if (-1 == retval) {
		PSEUDO_DEBUG("rt_tgsigqueueinfo syscall failed: %s",
				strerror(errno));
		PSEUDO_ERROR("Failed to generate SIGTRAP signal");
		fprintf(stderr, "Failed to generate SIGTRAP signal\n");
		pseudo_abort();
	}

	PSEUDO_TRACE("Exiting");
}

/**
 * @brief This function will send the SIGTRAP to itself if
 * VE process is traced and system call tracing is enabled.
 *
 * @param[in] handle VEOS handle
 * @param[in] in True while entering and false while exiting system call
 */
void ve_syscall_trace(veos_handle *handle, bool in)
{
	int trace = 0;

	PSEUDO_TRACE("Entering");

	/* Check whether VE process/thread is traced or not */
	if (IS_VE_TRACED(handle->ve_handle)) {
		PSEUDO_DEBUG("VE process is traced");
	} else {
		PSEUDO_DEBUG("VE process is not traced");
		goto hndl_return;
	}

	/* Check system call tracing is enabled or not */
	if (!IS_SYSCALL_TRACED(handle->ve_handle)) {
		PSEUDO_DEBUG("System call Tracing is Disabled");
		goto hndl_return;
	}

	/* Syscall tracing is disabled for grow syscall, so SIGTRAP signal
	 * is not generated when ve_grow() syscall is invoked.
	 */
	if (315 == vedl_get_syscall_num(handle->ve_handle)) {
		PSEUDO_DEBUG("grow() is invoked so not tracing it");
		goto hndl_return;
	}

	/* If SIGTRAP is not generated while entering system call, then
	 * SIGTRAP is not generated send while exiting system call even
	 * if SYSTEM CALL Trace is enabled.
	 */
	if (in == false && sys_enter_trap == false) {
		PSEUDO_DEBUG("SIGTRAP will not be generated while exiting syscall");
		goto hndl_return;
	}

	PSEUDO_DEBUG("System Call Tracing is enabled, Sending SIGTRAP to itself");

	sys_enter_trap = in;

	/* If PTRACE_O_TRACESYSGOOD option is set then SICODE would be
	 * SIGTRAP|0x80.
	 */
	if (VE_PTRACE_OPTION(handle->ve_handle) &
			PTRACE_O_TRACESYSGOOD) {
		trace = SIGTRAP|0x80;
		PSEUDO_DEBUG("PTRACE_O_TRACESYSGOOD is Set");
	}

	send_sig_to_itself(SIGTRAP, trace, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return;
}

/**
 * @brief This function will send request to veos to set the ptrace event
 * message of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] event Ptrace event message
 *
 * @return positive value on success, -1 on failure
 */
int pseudo_psm_send_ptrace_event_req(int veos_sock_fd, uint64_t event)
{
	int retval = -1;
	void *buf = NULL;
	ProtobufCBinaryData pseudo_info = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	PseudoVeosMessage req = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("Entering");

	req.pseudo_veos_cmd_id = PTRACE_EVENT_MSG;

	req.has_pseudo_pid = true;
	req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.data = (uint8_t *)&event;
	pseudo_info.len = sizeof(uint64_t);

	req.has_pseudo_msg = true;
	req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_DEBUG("malloc for structure packing failed");
		PSEUDO_ERROR("Internal Memory Allocation Failed");
		fprintf(stderr, "Internal Memory Allocation Failed\n");
		pseudo_abort();
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("pack failed returned len: %ld expected: %ld",
			msg_len, pseudo_msg_len);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_DEBUG("wrote %d bytes, expected: %ld bytes",
				retval, pseudo_msg_len);
		PSEUDO_ERROR("Failed to send message to VEOS");
		retval = -1;
	}

	free(buf);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for the acknowledgment of "PTRACE_EVENT_MSG" from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return 0 on success and -1 on failure
 */
int pseudo_psm_recv_ptrace_event_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive acknowledgment from VEOS");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_DEBUG("pseudo_veos_message__unpack failed read len :%ld",
			  retval);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0)
			PSEUDO_ERROR("Failure received from VEOS: %ld",
				pseudo_msg->syscall_retval);
		else
			PSEUDO_DEBUG("PTRACE_EVENT_MSG Success ");
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepare and send the ptrace event message information to veos.
 *
 * @param[in] handle veos handle
 * @param[in] event Ptrace event message
 *
 * @return 0 on success, -1 on failure.
 */
int ptrace_event_notify(veos_handle *handle, uint64_t event)
{
	int retval = -1;

	PSEUDO_TRACE("Entering");

	retval = pseudo_psm_send_ptrace_event_req(handle->veos_sock_fd, event);
	if (0 > retval) {
		PSEUDO_DEBUG("Fail to send PTRACE_EVENT_MSG req to PSM");
		goto hndl_return;
	}

	retval = pseudo_psm_recv_ptrace_event_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_DEBUG("Fail to recv PTRACE_EVENT_MSG ACK from PSM");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will send request to veos to get value of
 * ICE register
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return positive value on success, -1 on failure
 */
int pseudo_psm_send_get_regval_req(int veos_sock_fd)
{
	int retval = -1;
	void *buf = NULL;
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	PseudoVeosMessage regval_req = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("Entering");

	regval_req.pseudo_veos_cmd_id = GET_REGVAL_REQ;

	regval_req.has_pseudo_pid = true;
	regval_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&regval_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_DEBUG("malloc for structure packing failed");
		PSEUDO_ERROR("Internal Memory Allocation Failed");
		fprintf(stderr, "Internal Memory Allocation Failed\n");
		pseudo_abort();
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&regval_req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("pack failed returned len: %ld expected: %ld",
			msg_len, pseudo_msg_len);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_DEBUG("wrote %d bytes, expected: %ld bytes",
				retval, pseudo_msg_len);
		PSEUDO_ERROR("Failed to send message to VEOS");
		retval = -1;
	}

	free(buf);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for the acknowledgment of "GET_REGVAL_REQ" from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[out] ice Content of ICE regval
 *
 * @return 0 on success and -1 on failure
 */
int pseudo_psm_recv_get_regval_ack(int veos_sock_fd, uint64_t *ice)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive acknowledgment from VEOS");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_DEBUG("pseudo_veos_message__unpack failed read len :%ld",
			  retval);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			PSEUDO_ERROR("Failure received from VEOS: %ld",
				pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			PSEUDO_DEBUG("Received success ack for GET_REGVAL_REQ");
			memcpy(ice, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepare and send signal to itself for traced VE
 * process/thread.
 *
 * @param[in] hw_siginfo Siginfo structure to send
 * @param[in] handle veos handle
 *
 * @return 0 on success, -1 on failure.
 */
int prepare_and_send_signal(siginfo_t hw_siginfo, veos_handle *handle)
{
	int retval = -1;
	uint64_t ice = 0;

	PSEUDO_TRACE("Entering");

	retval = pseudo_psm_send_get_regval_req(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_DEBUG("Failed to send GET_REGVAL request to PSM");
		goto hndl_return;
	}

	retval = pseudo_psm_recv_get_regval_ack(handle->veos_sock_fd, &ice);
	if (0 > retval) {
		PSEUDO_DEBUG("Fail to recv GET_REGVAL ACK from PSM");
		goto hndl_return;
	}

	hw_siginfo.si_addr = (void *)ice;

	/* Send h/w exception signal to itself */
	send_sig_to_itself(hw_siginfo.si_signo,
			hw_siginfo.si_code, hw_siginfo.si_addr);

	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the ve process ptrace traceme request.
 *
 * @param[in] handle veos handle
 *
 * @return 0 on success, -1 on failure.
 */
int pseudo_handle_traceme(veos_handle *handle)
{
	int retval = -1;

	PSEUDO_TRACE("Entering");

	/* Invoking host ptrace() system call with PTRACE_TRACEME */
	retval = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	if (-1 == retval) {
		PSEUDO_ERROR("VH ptrace(PTRACE_TRACEME) fails: %s",
				strerror(errno));
		goto hndl_return;
	}

	PSEUDO_DEBUG("VH ptrace(PTRACE_TRACEME) Done");

	/* Send SIGTRAP signal to itself */
	send_sig_to_itself(SIGTRAP, 0, NULL);
	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will send request to veos to set the
 * ve process state as STOP.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return positive value on success, -1 on failure
 */
int pseudo_psm_send_ve_stop_req(int veos_sock_fd)
{
	int retval = -1;
	void *buf = NULL;
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	PseudoVeosMessage req = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("Entering");

	req.pseudo_veos_cmd_id = VE_STOP_PROC;

	req.has_pseudo_pid = true;
	req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		PSEUDO_DEBUG("malloc for structure packing failed");
		PSEUDO_ERROR("Internal Memory Allocation Failed");
		fprintf(stderr, "Internal Memory Allocation Failed\n");
		pseudo_abort();
	}
	memset(buf, '\0', pseudo_msg_len);

	msg_len = pseudo_veos_message__pack(&req, buf);
	if (pseudo_msg_len != msg_len) {
		PSEUDO_DEBUG("pack failed returned len: %ld expected: %ld",
			msg_len, pseudo_msg_len);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		PSEUDO_DEBUG("wrote %d bytes, expected: %ld bytes",
				retval, pseudo_msg_len);
		PSEUDO_ERROR("Failed to send message to VEOS");
		retval = -1;
	}

	free(buf);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Waits for the acknowledgment of "VE_STOP_PROC" from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return 0 on success and -1 on failure
 */
int pseudo_psm_recv_ve_stop_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *pseudo_msg = NULL;

	PSEUDO_TRACE("Entering");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		PSEUDO_ERROR("Failed to receive acknowledgment from VEOS");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		PSEUDO_DEBUG("pseudo_veos_message__unpack failed read len :%ld",
			  retval);
		PSEUDO_ERROR("Protocol Buffers Internal Error");
		fprintf(stderr, "Protocol Buffers Internal Error\n");
		pseudo_abort();
	}

	/* Check message for PSM */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0)
			PSEUDO_ERROR("Failure received from VEOS: %ld",
				pseudo_msg->syscall_retval);
		else
			PSEUDO_DEBUG("VE_STOP_PROC Success");
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will communicate with veos and mark the
 * VE process state as STOP.
 *
 * @param[in] handle veos handle
 *
 * @return 0 on success, -1 on failure.
 */
int pseudo_stop_ve_process(veos_handle *handle)
{
	int retval = -1;

	PSEUDO_TRACE("Entering");

	retval = pseudo_psm_send_ve_stop_req(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_DEBUG("Fail to send VE_STOP_PROC req to PSM");
		goto hndl_return;
	}

	retval = pseudo_psm_recv_ve_stop_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_DEBUG("Fail to recv VE_STOP_PROC ACK from PSM");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
