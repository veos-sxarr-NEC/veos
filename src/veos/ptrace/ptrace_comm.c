/*
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
 * @file ptrace_comm.c
 * @brief VEOS interfaces regarding ptrace system call handling in VEOS.
 *
 * @internal
 * @author PTRACE
 */

#include <unistd.h>
#include <search.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ptrace_comm.h"
#include "ptrace_req.h"
#include "proto_buff_schema.pb-c.h"
#include "locking_handler.h"
#include "velayout.h"

/**
 * @brief Write the buffer on the file descriptor.
 *
 * @param[in] socket_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to buffer to send
 * @param[in] max_len Size of buffer
 *
 * @return positive value on success, -1 on failure.
 */
ssize_t veos_ptrace_write_buf(int socket_fd, void *buf, ssize_t max_len)
{
	ssize_t transferred = 0;
	ssize_t write_byte = 0;

	VEOS_TRACE("Entering");

	if (!buf) {
		transferred = -1;
		goto hndl_return;
	}

	while ((write_byte =
		send(socket_fd, buf + transferred,
		      max_len - transferred, MSG_NOSIGNAL)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VEOS_ERROR("Sending message to"
						" libveptrace failed: %s",
						strerror(errno));
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;

		VEOS_DEBUG("transferred = %ld, write_byte = %ld",
			  transferred, write_byte);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return transferred;
}

/**
 * @brief Sends the success/failure response from VEOS back to libveptrace.
 *
 * @param[in] veos_soc_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to populated structure by VEOS
 * @param[in] len Size of populated structure
 * @param[in] ack_ret Return value send to libveptrace
 */
void veos_ptrace_send_cmd_response(int veos_soc_fd, uint8_t *buf,
		int64_t len, int64_t ack_ret)
{
	ssize_t retval = -1;
	ssize_t pack_msg_len = 0, pack_len = 0;
	void *pack_buf = NULL;
	PseudoVeosMessage ptrace_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ptrace_data = {0};

	VEOS_TRACE("Entering");

	/* Initializing message and populating return value */
	ptrace_ack.has_syscall_retval = true;
	ptrace_ack.syscall_retval = ack_ret;

	VEOS_DEBUG("Sending return value: %ld", ack_ret);

	if (NULL != buf) {
		VEOS_DEBUG("Structure to send of size: %ld", len);
		ptrace_ack.has_pseudo_msg = true;
		ptrace_data.data = buf;
		ptrace_data.len = len;
		ptrace_ack.pseudo_msg = ptrace_data;
	}

	pack_msg_len = pseudo_veos_message__get_packed_size(&ptrace_ack);
	pack_buf = malloc(pack_msg_len);
	if (NULL == pack_buf) {
		VEOS_CRIT("Internal memory allocation failed: %s",
				strerror(errno));
		goto hndl_return;
	}

	memset(pack_buf, '\0', pack_msg_len);

	/* Pack the message */
	pack_len = pseudo_veos_message__pack(&ptrace_ack, pack_buf);
	if (pack_len != pack_msg_len) {
		VEOS_DEBUG("pseudo_veos_message__pack fail "
				"returns: %ld, but required %ld",
				pack_len, pack_msg_len);
		VEOS_ERROR("Protocol Buffers Internal Error");
		goto hndl_return1;
	}

	/* Write the buffer to socket descriptor */
	retval = veos_ptrace_write_buf(veos_soc_fd, pack_buf, pack_msg_len);
	if (retval < pack_msg_len) {
		VEOS_DEBUG("written:%ld bytes of total:%ld bytes",
				retval, pack_msg_len);
		goto hndl_return1;
	}

hndl_return1:
	free(pack_buf);
hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Handles the VE_STOP_PROCESS request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] seized_stop Determines the stop of seized process or not
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_stop_process(struct veos_thread_arg *pti,
		pid_t pid, bool seized_stop)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied VE_STOP_PROCESS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check whether stop request from PTRACE_INTERRUPT and process
	 * is not attached using PTRACE_SEIZE.
	 */
	if (false == p_ve_task->p_ve_ptrace->is_seized &&
		true == seized_stop) {
		VEOS_ERROR("PID: %d is not seized attached process", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	/* Change the VE process state to STOP */
	psm_ve_stop_process(p_ve_task);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "START_PROCESS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_start_process(struct veos_thread_arg *pti, pid_t pid)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied START_PROCESS request for pid: %d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Change the VE process state */
	psm_ve_start_process(p_ve_task);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "ATTACH" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_attach(struct veos_thread_arg *pti, pid_t pid)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied VE_ATTACH request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Locking is taken to prevent parallel attach request from
	 * tracer.
	 */
	pthread_mutex_lock_unlock(&(p_ve_task->ptrace_lock), LOCK,
			"Failed to acquire ptrace mutex lock");

	/* Check if this VE task already traced or not */
	if (p_ve_task->ptraced && p_ve_task->p_ve_ptrace != NULL) {
		VEOS_ERROR("VE task: %d is already traced by: %d",
				pid,
				p_ve_task->p_ve_ptrace->tracer_pid);
		retval = -EPERM;
		goto hndl_return1;
	}

	/* Change the VE process state to STOP */
	psm_ve_stop_process(p_ve_task);

	/* Attach the VE process for tracing */
	retval = psm_attach_ve_process(p_ve_task, tracer_pid, pti->cred.uid,
			pti->cred.gid, false);
	if (-1 == retval) {
		VEOS_ERROR("Ptrace attach failed for pid: %d", pid);

		/* Change the VE process state */
		psm_ve_start_process(p_ve_task);
		retval = -EPERM;
		goto hndl_return1;
	}

	VEOS_INFO("Pid: %d is now attached", pid);

	retval = 0;
hndl_return1:
	pthread_mutex_lock_unlock(&(p_ve_task->ptrace_lock), UNLOCK,
			"Failed to release ptrace mutex lock");
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "CHECK_PID" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_check_pid(struct veos_thread_arg *pti, pid_t pid)
{
	int retval = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	VEOS_DEBUG("Recevied CHECK_PID request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	VEOS_DEBUG("Pid: %d found on core: %d", pid, p_ve_task->core_id);

	put_ve_task_struct(p_ve_task);
	retval = 0;
hndl_return1:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "PEEKDATA" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] addr VEMVA of tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_peekdata(struct veos_thread_arg *pti, pid_t pid, uint64_t addr)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	ptrace_req pt_req = {0};
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied PEEKDATA request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Get the content from the VE memory of the given address */
	retval = psm_ptrace_peekdata(p_ve_task, addr, &(pt_req.data));
	if (-1 == retval) {
		VEOS_ERROR("PEEKDATA failed for pid: %d", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d VEMVA: %lx DATA: %lx", pid, addr, pt_req.data);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor,
			(uint8_t *)(&pt_req), sizeof(pt_req), retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "POKEDATA" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] addr VEMVA of tracee process
 * @param[in] data Data to store on VEMVA
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_pokedata(struct veos_thread_arg *pti, pid_t pid,
		uint64_t addr, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied POKEDATA request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d VEMVA: %lx DATA: %lx", pid, addr, data);

	/* Write the content to VE memory of the given address */
	retval = psm_ptrace_pokedata(p_ve_task, addr, data);
	if (-1 == retval) {
		VEOS_ERROR("POKEDATA failed for pid: %d", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "PEEKUSER" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] addr VE user register of tracee
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_peekuser(struct veos_thread_arg *pti, pid_t pid, uint64_t addr)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	ptrace_req pt_req = {0};
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied PEEKUSER request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Get the content from the given VE user register
	 * of the tracee process */
	retval = psm_ptrace_peekuser(p_ve_task, addr, &(pt_req.data));
	if (-1 == retval) {
		VEOS_ERROR("PEEKUSER failed for pid: %d", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d REGISTER: %lx DATA: %lx", pid, addr, pt_req.data);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor,
			(uint8_t *)(&pt_req), sizeof(pt_req), retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "POKEUSER" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] addr VE user register of tracee
 * @param[in] data Content of VE user register
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_pokeuser(struct veos_thread_arg *pti, pid_t pid,
		uint64_t addr, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied POKEUSER request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Set the content to the given VE user register
	 * of the tracee process */
	retval = psm_ptrace_pokeuser(p_ve_task, addr, data);
	if (-1 == retval) {
		VEOS_ERROR("POKEUSER failed for pid: %d", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d REGISTER: %lx DATA: %lx", pid, addr, data);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "GETREGS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data VHVA of tracer to store register set
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_getregs(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied GETREGS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Get the content of VE user register set
	 * of the tracee process */
	retval = psm_ptrace_getregs(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("GETREGS failed for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d GETREGS SUCCESS", pid);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SETREGS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data VHVA of tracer to get the register set
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_setregs(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SETREGS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Set the content of VE user register set of the
	 * tracee process provided by it's tracer.
	 */
	retval = psm_ptrace_setregs(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("SETREGS failed for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d SETREGS SUCCESS", pid);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "GETVREGS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data VHVA of tracer to store register set
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_getvregs(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied GETVREGS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Get the content of VE vector register set
	 * of the tracee process */
	retval = psm_ptrace_getvregs(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("GETFPREGS failed for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d GETVREGS SUCCESS", pid);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SETVREGS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data VHVA of tracer to get the register set
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_setvregs(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SETVREGS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Set the content of VE vector register set of the
	 * tracee process provided by it's tracer.
	 */
	retval = psm_ptrace_setvregs(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("SETFPREGS failed for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("PID: %d SETVREGS SUCCESS", pid);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "DETACH" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_detach(struct veos_thread_arg *pti, pid_t pid)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied DETACH request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Detach the VE process */
	retval = psm_ptrace_detach(p_ve_task);
	if (-1 == retval) {
		VEOS_ERROR("PTRACE_DETACH failed for pid: %d", pid);
		retval = -EIO;
		goto hndl_return1;
	}

	/* On a safe side after detaching VE process SINGLESTEP interrupt
	 * bit needs to cleared from PSW register.
	 */
	psm_handle_set_reg_req(p_ve_task, PSW, ~PSW_SINGLESTEP, PSW_SINGLESTEP);

	/* Change the VE process state */
	psm_ve_start_process(p_ve_task);

	VEOS_DEBUG("PID: %d DETACH SUCCESS", pid);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SEIZE" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data Ptrace options to activate
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_seize(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SEIZE request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Locking is taken to prevent parallel attach request from
	 * tracer.
	 */
	pthread_mutex_lock_unlock(&(p_ve_task->ptrace_lock), LOCK,
			"Failed to acquire ptrace mutex lock");

	/* Check if this VE task already traced or not */
	if (p_ve_task->ptraced && p_ve_task->p_ve_ptrace != NULL) {
		VEOS_ERROR("VE task: %d is already traced by: %d",
				pid,
				p_ve_task->p_ve_ptrace->tracer_pid);
		retval = -EPERM;
		goto hndl_return1;
	}

	/* Attach(SEIZE) the VE process for tracing */
	retval = psm_attach_ve_process(p_ve_task, tracer_pid, pti->cred.uid,
			pti->cred.gid, true);
	if (-1 == retval) {
		VEOS_ERROR("PTRACE_SEIZE failed for pid: %d", pid);
		retval = -EPERM;
		goto hndl_return1;
	}

	/* Set the ptrace options provided while attaching through
	 * PTRACE_SEIZE.
	 */
	retval = psm_ptrace_setoptions(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("PTRACE_SETOPTIONS from SEIZE failed for pid: %d", pid);

		/* In case of failure detach the VE process,
		 * that was just attached.
		 */
		psm_ptrace_detach(p_ve_task);
		retval = -EIO;
		goto hndl_return1;
	}

	VEOS_INFO("Pid: %d is now attached(SEIZE)", pid);

	retval = 0;
hndl_return1:
	pthread_mutex_lock_unlock(&(p_ve_task->ptrace_lock), UNLOCK,
			"Failed to release ptrace mutex lock");
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SYSCALL" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] bool Enable/disable system call tracing
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_syscall(struct veos_thread_arg *pti, pid_t pid, bool on)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SYSCALL request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Enable/Disable VE process system call tracing */
	retval = psm_ptrace_syscall(p_ve_task, on);
	if (-1 == retval) {
		VEOS_ERROR("PTRACE_SYSCALL failed for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("Pid: %d SYSCALL tracing now: %s", pid,
			(char *)((on)?"Enabled":"Disabled"));

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SINGLESTEP" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] bool Enable/disable singlestep tracing
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_singlestep(struct veos_thread_arg *pti, pid_t pid, bool on)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SINGLESTEP request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Enable/Disable VE process singlestep tracing */
	psm_handle_set_reg_req(p_ve_task, PSW,
			(on)?(PSW_SINGLESTEP):(~PSW_SINGLESTEP), PSW_SINGLESTEP);

	VEOS_DEBUG("Pid: %d SINGLESTEP tracing now: %s", pid,
			(char *)((on)?"Enabled":"Disabled"));

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "SETOPTIONS" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 * @param[in] data Ptrace options to activate
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_setoptions(struct veos_thread_arg *pti, pid_t pid, uint64_t data)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied SETOPTIONS request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Set the ptrace options for VE process */
	retval = psm_ptrace_setoptions(p_ve_task, data);
	if (-1 == retval) {
		VEOS_ERROR("PTRACE_SETOPTIONS failed for pid: %d", pid);
		retval = -EINVAL;
		goto hndl_return1;
	}

	VEOS_DEBUG("Pid: %d Ptrace options now: %lx", pid, data);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the "GETEVENTMSG" ptrace request for the given pid.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 * @param[in] pid Pid of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int veos_ptrace_geteventmsg(struct veos_thread_arg *pti, pid_t pid)
{
	int retval = -1;
	pid_t tracer_pid = -1;
	ptrace_req pt_req;
	struct ve_task_struct *p_ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	tracer_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Recevied GETEVENTMSG request for pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return2;
	}

	/* Check VE process is traced/attached or not */
	if (false == p_ve_task->ptraced) {
		VEOS_ERROR("VE Process: %d is not traced/attached", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Check that PTRACE request from valid VE tracer or not */
	if (tracer_pid != p_ve_task->p_ve_ptrace->tracer_pid) {
		VEOS_DEBUG("VE Process(%d)->Tracer(%d) Not: %d",
				pid, p_ve_task->p_ve_ptrace->tracer_pid,
				tracer_pid);
		VEOS_ERROR("Request from unknown tracer received");
		retval = -ESRCH;
		goto hndl_return1;
	}

	memset(&pt_req, 0, sizeof(pt_req));

	/* Get the ptrace event message that just happened from
	 * VE task struct.
	 */
	pt_req.data = p_ve_task->p_ve_ptrace->ptrace_message;

	VEOS_DEBUG("Pid: %d Ptrace GETEVENTMSG: %ld", pid, pt_req.data);

	retval = 0;
hndl_return1:
	put_ve_task_struct(p_ve_task);
hndl_return2:
	veos_ptrace_send_cmd_response(pti->socket_descriptor,
			(uint8_t *)(&pt_req), sizeof(pt_req), retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the PTRACE Request received form VE Ptrace Library.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 *
 * @return 0 on success, -1 on failure.
 */
int veos_handle_ptrace_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	ptrace_req pt_req = {0};
	ProtobufCBinaryData proto_msg;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	proto_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	memcpy(&pt_req, proto_msg.data, proto_msg.len);

	VEOS_DEBUG("Recevied PTRACE request:%d for pid :%d",
			pt_req.ptrace_cmd,
			pt_req.pid);

	/* Identify the ptrace request received and invoke the
	 * corresponding handler to the request.
	 */
	switch(pt_req.ptrace_cmd) {
	case STOP_PROCESS:
		retval = veos_ptrace_stop_process(pti, pt_req.pid,
				(bool)pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("STOP_PROCESS fails for PID: %d",
					pt_req.pid);
		break;
	case START_PROCESS:
		retval = veos_ptrace_start_process(pti, pt_req.pid);
		if (0 > retval)
			VEOS_DEBUG("START_PROCESS fails for PID: %d",
					pt_req.pid);
		break;
	case ATTACH:
		retval = veos_ptrace_attach(pti, pt_req.pid);
		if (0 > retval)
			VEOS_DEBUG("ATTACH fails for PID: %d", pt_req.pid);
		break;
	case CHECK_PID:
		retval = veos_ptrace_check_pid(pti, pt_req.pid);
		if (0 > retval)
			VEOS_DEBUG("PID: %d not found", pt_req.pid);
		break;
	case PEEKDATA:
		retval = veos_ptrace_peekdata(pti, pt_req.pid, pt_req.addr);
		if (0 > retval)
			VEOS_DEBUG("PEEKDATA fails for PID: %d ADDR: %lx",
					pt_req.pid, pt_req.addr);
		break;
	case POKEDATA:
		retval = veos_ptrace_pokedata(pti, pt_req.pid,
				pt_req.addr, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("POKEDATA fails for PID: %d ADDR: %lx",
					pt_req.pid, pt_req.addr);
		break;
	case PEEKUSER:
		retval = veos_ptrace_peekuser(pti, pt_req.pid, pt_req.addr);
		if (0 > retval)
			VEOS_DEBUG("PEEKUSER fails for PID: %d Register: %lx",
					pt_req.pid, pt_req.addr);
		break;
	case POKEUSER:
		retval = veos_ptrace_pokeuser(pti, pt_req.pid,
				pt_req.addr, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("POKEUSER fails for PID: %d Register: %lx",
					pt_req.pid, pt_req.addr);
		break;
	case GETREGS:
		retval = veos_ptrace_getregs(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("GETREGS fails for PID: %d ", pt_req.pid);
		break;
	case SETREGS:
		retval = veos_ptrace_setregs(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SETREGS fails for PID: %d", pt_req.pid);
		break;
	case GETVREGS:
		retval = veos_ptrace_getvregs(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("GETVREGS fails for PID: %d", pt_req.pid);
		break;
	case SETVREGS:
		retval = veos_ptrace_setvregs(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SETVREGS fails for PID: %d", pt_req.pid);
		break;
	case DETACH:
		retval = veos_ptrace_detach(pti, pt_req.pid);
		if (0 > retval)
			VEOS_DEBUG("DETACH fails for PID: %d", pt_req.pid);
		break;
	case SEIZE:
		retval = veos_ptrace_seize(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SEIZE fails for PID: %d", pt_req.pid);
		break;
	case SYSCALL:
		retval = veos_ptrace_syscall(pti, pt_req.pid,
				(bool)pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SYSCALL fails for PID: %d", pt_req.pid);
		break;
	case SINGLESTEP:
		retval = veos_ptrace_singlestep(pti, pt_req.pid,
				(bool)pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SINGLESTEP fails for PID: %d", pt_req.pid);
		break;
	case SETOPTIONS:
		retval = veos_ptrace_setoptions(pti, pt_req.pid, pt_req.data);
		if (0 > retval)
			VEOS_DEBUG("SETOPTIONS fails for PID: %d", pt_req.pid);
		break;
	case GETEVENTMSG:
		retval = veos_ptrace_geteventmsg(pti, pt_req.pid);
		if (0 > retval)
			VEOS_DEBUG("GETEVENTMSG fails for PID: %d", pt_req.pid);
		break;
	case PTRACE_INVAL:
		VEOS_ERROR("Invalid Ptrace request received");
		retval = -EINVAL;

		/* Send the failure response back to libveptrace */
		veos_ptrace_send_cmd_response(pti->socket_descriptor,
				NULL, 0, retval);
		break;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the PTRACE_EVENT_MSG Request received form
 * pseudo process.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 *
 * @return 0 on success, -1 on failure.
 */
int veos_handle_ptrace_event_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	uint64_t event = 0;
	struct ve_task_struct *p_ve_task = NULL;
	pid_t pid = 0;
	ProtobufCBinaryData proto_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	proto_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	memcpy(&event, proto_msg.data, proto_msg.len);

	VEOS_DEBUG("Recevied PTRACE_EVENT_MSG from pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Set the ptrace event message given by pseudo process */
	p_ve_task->p_ve_ptrace->ptrace_message = event;

	VEOS_DEBUG("Pid: %d Event message now: %ld", pid, event);
	retval = 0;
	put_ve_task_struct(p_ve_task);
hndl_return1:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_STOP_PROC Request received form
 * pseudo process.
 *
 * @param[in] pti Pointer to veos_thread_arg for communication
 *
 * @return 0 on success, -1 on failure.
 */
int veos_handle_stop_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *p_ve_task = NULL;
	pid_t pid = 0;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Recevied VE_STOP_PROC from pid :%d", pid);

	/* Find the VE task struct corresponding to given pid */
	p_ve_task = find_ve_task_struct(pid);
	if (NULL == p_ve_task) {
		VEOS_ERROR("Pid: %d is not found", pid);
		retval = -ESRCH;
		goto hndl_return1;
	}

	/* Change the VE process state to STOP */
	psm_ve_stop_process(p_ve_task);

	retval = 0;
	put_ve_task_struct(p_ve_task);
hndl_return1:
	veos_ptrace_send_cmd_response(pti->socket_descriptor, NULL, 0, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
