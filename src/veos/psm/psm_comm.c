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
 * @file  psm_comm.c
 * @brief Handles commands sent from PSEUDO PROCESS
 *
 * This contains the handler functions that are invoked based
 * on the request from the pseudo process.
 */

#include <unistd.h>
#include <search.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include "ve_hw.h"
#include "task_mgmt.h"
#include "ve_clone.h"
#include "veos_handler.h"
#include "psm_comm.h"
#include "mm_common.h"
#include "task_signal.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "ptrace_req.h"
#include "ve_mem.h"
#include "locking_handler.h"
#include "task_mgmt.h"
#include "psm_stat.h"

/**
 * @brief This Function is used to communicate with PSM
 *
 * @param socket_fd Descriptor used to communicate with PSM
 * @param buff contain req info to be sent to PSM
 * @param max_len size of packed structure
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @author PSMG / Process management
 */
ssize_t psm_pseudo_send_cmd(int socket_fd, void *buff, ssize_t max_len)
{
	ssize_t transferred = 0;
	ssize_t sent_byte = 0;

	VEOS_TRACE("Entering");

	if (!buff) {
		transferred = -1;
		goto send_error;
	}

	while ((sent_byte =
		send(socket_fd, buff + transferred,
		      max_len - transferred, MSG_NOSIGNAL)) != 0) {
		if (sent_byte == -1) {
			if (EINTR == errno|| EAGAIN == errno) {
				continue;
			} else if (EPIPE == errno) {
				VEOS_ERROR("IPC failed, Pseudo process "
						"terminated");
				transferred = -1;
				break;
			} else {
				VEOS_ERROR("Sending Command from PSM"
						"to pseudo failed %s",
						strerror(errno));
				transferred = -1;
				break;
			}
		}
		transferred += sent_byte;
		if (transferred == max_len)
			break;
		VEOS_DEBUG("transferred = %ld, sent_byte = %ld",
				transferred, sent_byte);
	}

send_error:
	VEOS_TRACE("Exiting");
	return transferred;
}

/**
 * @brief Sends request to pseudo process about success/failure creation of
 * exec VE process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 * @param[in] pid PID of the VE process created
 * @param[in] syscall_ret Value to be returned to the pseudo side
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_start_ve(struct veos_thread_arg *pti,
		pid_t pid, int64_t syscall_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage start_ve_req = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t psm_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	start_ve_req.has_pseudo_pid = true;
	start_ve_req.pseudo_pid = pid;

	start_ve_req.has_syscall_retval = true;
	start_ve_req.syscall_retval = syscall_ret;

	/* Pack start_ve_req before sending */
	psm_msg_len = pseudo_veos_message__get_packed_size(&start_ve_req);

	msg_len = pseudo_veos_message__pack(&start_ve_req, (uint8_t *)buf);
	if (msg_len != psm_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				psm_msg_len, msg_len);
		goto hndl_return;
	}

	/* Send ACK to Pseudo Process */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor, buf,
							psm_msg_len);
	if (retval < psm_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				psm_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends request to pseudo process to load the VE process binary.
 *
 * @param[in] pti Contains the request message received from pseudo process
 * @param[in] ve_core_id VE proces core id
 * @param[in] ve_node_id VE process node id
 * @param[in] ack_ret Command ack to send
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_pseudo_send_load_binary_req(struct veos_thread_arg *pti,
		int ve_core_id,
		int ve_node_id, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ld_binary_req = PSEUDO_VEOS_MESSAGE__INIT;
	struct new_proc_info new_ve_proc = {0};
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData new_ve_proc_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* Popuate request message */
	new_ve_proc.core_id = ve_core_id;
	new_ve_proc.node_id = ve_node_id;

	ld_binary_req.has_syscall_retval = true;
	ld_binary_req.syscall_retval = ack_ret;

	/* Send info for PSEUDO */
	ld_binary_req.has_pseudo_msg = true;
	new_ve_proc_msg.len = sizeof(new_ve_proc);
	new_ve_proc_msg.data = (uint8_t *)&(new_ve_proc);
	ld_binary_req.pseudo_msg = new_ve_proc_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ld_binary_req);

	msg_len = pseudo_veos_message__pack(&ld_binary_req, (uint8_t *)buf);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending LOAD BINARY Request");
	/* Send LOAD BINARY REQ to pseudo process */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles START VE request from Pseudo Process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_recv_start_ve_request(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"pseudo process");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Recevied START VE REQ from"
			"Pseudo with PID : %d", pid);

	retval = psm_handle_start_ve_request(pti, pid);
	if (0 > retval)
		VEOS_ERROR("Failed to handle START VE process request");

	/* Send start VE ack */
	retval = psm_pseudo_send_start_ve(pti, pid, retval);
	if (0 > retval)
		VEOS_ERROR("Failed to send START VE acknowledgement "
				"to pseudo process");

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends an acknowledgment to the pseudo process about the creation
 * of child process when fork() is invoked.
 *
 * @param[in] pti Contains the request message received from pseudo process
 * @param[in] child_core_id Core id of the child process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_pseudo_send_fork_ack(struct veos_thread_arg *pti, int child_core_id)
{
	ssize_t retval = -1;
	PseudoVeosMessage fork_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument(pti) received from "
				"pseudo process");
		goto hndl_return;
	}

	/* Popuate FORK ACK process message */
	fork_ack.has_syscall_retval = true;
	fork_ack.syscall_retval = child_core_id;

	/* Pack fork_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&fork_ack);

	msg_len = pseudo_veos_message__pack(&fork_ack, (uint8_t *)buf);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing message protocl buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending FORK Acknowledgement");
	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function sends set user register acknowledgment to
 * pseudo process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 * @param[in] ack_ret Command ack to send
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_set_user_reg_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	PseudoVeosMessage set_usr_reg_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* Popuate SET RETURN ACK process return value */
	set_usr_reg_ack.has_syscall_retval = true;
	set_usr_reg_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&set_usr_reg_ack);

	msg_len = pseudo_veos_message__pack(&set_usr_reg_ack, (uint8_t *)buf);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending SET USER REGISTER ACK");
	/* send SET USER REGISTER ACK */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Receives request from pseudo process and updates user register
 * value in core user register struct.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_set_regval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *tsk = NULL;
	PseudoVeosMessage *request = NULL;
	struct reg_data rd = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	request = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = request->pseudo_pid;
	memcpy(&rd, request->pseudo_msg.data, request->pseudo_msg.len);

	tsk = find_ve_task_struct(pid);
	if (tsk == NULL) {
		VEOS_ERROR("Failed to find task structure");
		VEOS_DEBUG("Failed to fetch task structure for PID %d", pid);
		retval = -ESRCH;
	} else {
		retval = psm_handle_set_reg_req(tsk, rd.reg, rd.regval, rd.mask);
		put_ve_task_struct(tsk);
		if (0 > retval)
			VEOS_ERROR("Failed to set user register value");
	}

	retval = psm_pseudo_send_set_user_reg_ack(pti, retval);
	if (retval == -1)
		VEOS_ERROR("Failed to send SET USER REG acknowledgement to "
				"pseudo process");

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepare the acknowledgment/response that is to be sent to
 * pseudo process.
 *
 * @param[in] pti Contains the message received from pseudo process
 * @param[in] syscall_ret Value to be returned to the pseudo side
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_pseudo_send_set_tidaddr_ack(struct veos_thread_arg *pti,
					int64_t syscall_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_set_tid_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* prepare the response */
	ve_set_tid_ack.has_syscall_retval = true;
	ve_set_tid_ack.syscall_retval = syscall_ret;

	/* Pack ve_set_tid_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_set_tid_ack);

	msg_len = pseudo_veos_message__pack(&ve_set_tid_ack, (uint8_t *)buf);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing protocol message buf error");
		VEOS_DEBUG("Expected length: %ld, Returned length %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending SET_TID_ADDR acknowledgement");
	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles set_tid_address() system call functionality for VE side.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_set_tid_addr_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	uint64_t tid_addr = 0;
	int length = 0;
	int32_t pid = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"pseudo process");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&tid_addr,
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.data,
		length);

	retval = psm_handle_set_tid_addr(pid, tid_addr);
	if (0 > retval)
		VEOS_ERROR("Failed to set tid address");

	/* SEND SET TID ADDR ACK */
	retval = psm_pseudo_send_set_tidaddr_ack(pti, retval);
	if (0 > retval)
		VEOS_ERROR("Failed to send SET TID ADDR acknowledgement to "
				"pseudo process");

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepare the schedule acknowledgment/response that is to be
 * sent to pseudo process.
 *
 * @param[in] pti Contains the message received from pseudo process
 * @param[in] syscall_ret Contains the value to be returned to pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_pseudo_send_schedule_ack(struct veos_thread_arg *pti,
				int64_t syscall_ret)
{
	ssize_t retval = -1;
	ssize_t msg_pack_len = 0, pseudo_msg_len = 0;
	PseudoVeosMessage ve_schedule_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument pti");
		goto hndl_return;
	}

	/* prepare SCHEDULE_ACK response */
	ve_schedule_ack.has_syscall_retval = true;
	ve_schedule_ack.syscall_retval = syscall_ret;

	/* Pack ve_schedule_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_schedule_ack);
	msg_pack_len = pseudo_veos_message__pack(&ve_schedule_ack, (uint8_t *)buf);

	if (pseudo_msg_len != msg_pack_len) {
		VEOS_ERROR("Ack from PSM to PSEUDO failed");
		VEOS_DEBUG("Message pack length: %ld", msg_pack_len);
		goto hndl_return;
	}

	/* Send ACK to the pseudo side */
	VEOS_DEBUG("Sending schedule ack");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			(void *)buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Sending schedule ack failed");
		VEOS_DEBUG("PSM Send command wrote %ld bytes",
				retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Changes the state of the VE process from RUNNING to WAITING
 * so that it can be scheduled.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_handle_schedule_req(struct veos_thread_arg *pti)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument pti");
		goto hndl_return;
	}

	/* Immediately send ack to pseudo */
	retval = psm_pseudo_send_schedule_ack(pti, 0);
	if (0 > retval) {
		VEOS_ERROR("Failed to send schedule acknowledgement");
		goto hndl_return;
	}
	retval = psm_handle_schedule_ve_process(((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_pid);
hndl_return:
	if (0 > retval) {
		VEOS_ERROR("State of VE process not changed by PSM");
		VEOS_DEBUG("PSM schedule VE process returned %d", retval);
	}

	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the request of creation of a new VE process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_exec_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	int core_id = -1;
	int node_id = -1;
	uint64_t gid = -1;
	uint64_t uid = -1;
	struct new_ve_proc ve_proc;
	struct ve_task_struct *tsk = NULL;
	int length = -1;
	char exe_name[ACCT_COMM+1] = {0};
	char exe_path[PATH_MAX] = {0};

	VEOS_TRACE("Entering");

	if (VE_NODE(0)->num_ve_proc >= MAX_TASKS_PER_NODE) {
		VEOS_ERROR("Reached maximum(%d) VEOS tasks limit",
				MAX_TASKS_PER_NODE);
		retval = -EAGAIN;
		goto hndl_return;
	}

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"pseudo process");
		goto hndl_return1;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VEOS_ERROR("Failed to recieve message from pseudo process"
				"message length %d", length);
		goto hndl_return;
	}

	memset(&ve_proc, '\0', sizeof(struct new_ve_proc));
	memcpy(&ve_proc, (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
				pseudo_msg).data, length);
	core_id = ve_proc.core_id;
	gid = ve_proc.gid;
	uid = ve_proc.uid;

	retval = amm_dma_xfer(VE_DMA_VHVA, ve_proc.exec_path, pid, VE_DMA_VHVA,
				(uint64_t)exe_path, getpid(), PATH_MAX, 0);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get path of new VE process binary");
		goto hndl_return;
	}

	strncpy(exe_name, ve_proc.exe_name, sizeof(ve_proc.exe_name));

	VEOS_DEBUG("VE Executable name: %s,"
			" ve_exec path: %s,"
			" PID of the new VE process : %d",
			exe_name, exe_path, pid);

	/* Fetch the respective task_struct from the list */
	tsk = find_ve_task_struct(pid);
	if (tsk && tsk->execed_proc) {
		VEOS_DEBUG("PID %d already exists", pid);
		tsk->gid = gid;
		tsk->uid = uid;
		strncpy(tsk->ve_exec_path, exe_path, PATH_MAX);

		/* Populate the resource limit if task created through RPM */
		if (tsk->rpm_create_task) {
			if (tsk->rpm_preserve_task != 2)
				memcpy(tsk->sighand->rlim , ve_proc.lim,
						sizeof(ve_proc.lim));
			tsk->rpm_create_task = false;
		}

		tsk->atb_dirty = 0;
		tsk->crd_dirty = 0;
		tsk->exit_code = 0;
		tsk->exit_status = 0;
		tsk->exit_code_set = 0;
		tsk->block_status = BLOCK_RECVD;

		pthread_rwlock_lock_unlock(&(tsk->p_ve_core->ve_core_lock), WRLOCK,
				"Failed to acquire execve task's core write lock");
		psm_set_task_state(tsk, WAIT);
		pthread_rwlock_lock_unlock(&(tsk->p_ve_core->ve_core_lock), UNLOCK,
				"Failed to release execve task's core write lock");

		tsk->ptraced = ve_proc.traced_proc;
		strncpy(tsk->ve_comm, exe_name, ACCT_COMM);
		tsk->sighand->lshm_addr = (uint64_t)shmat(ve_proc.shmid, NULL, 0);

		if ((void *)-1 == (void *)tsk->sighand->lshm_addr) {
			VEOS_ERROR("Failed to attach shared memory");
			VEOS_DEBUG("Failed to attach shared memory return value "
					"%d, mapped value %d",
					-errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}

		/* Saving shmid in task struct to be used by vforked child */
		tsk->lshmid = ve_proc.shmid;

		/* Store the SHM/LHM address of pseudo process
		 * in mm_struct.
		 */
		tsk->p_ve_mm->shm_lhm_addr = ve_proc.shm_lhm_addr;
		VEOS_DEBUG("SHM/LHM address %lx of pid %d",
				ve_proc.shm_lhm_addr, tsk->pid);

                tsk->p_ve_mm->shm_lhm_addr_vhsaa = vedl_get_dma_address(VE_HANDLE(0),
                                (void *)(tsk->p_ve_mm->shm_lhm_addr),
                                tsk->pid, 1, 0, 0);
		if ((uint64_t)-1 == tsk->p_ve_mm->shm_lhm_addr_vhsaa) {
			VEOS_ERROR("Failed to convert the address");
			VEOS_DEBUG("Failed to convert the address(VHVA->VHSAA),"
					"return value %d, mapped value %d",
					-errno, -EFAULT);
			retval = -EFAULT;
                        goto hndl_return;
                }

		VEOS_DEBUG("Virtual address: %lx Physical address: %lx",
				tsk->p_ve_mm->shm_lhm_addr,
				tsk->p_ve_mm->shm_lhm_addr_vhsaa);

		/* Reviving task state at VE driver as it can be marked DELETED
		 * (as discussed in #789)
		 * */
		if (vedl_revive_ve_task(VE_NODE(0)->handle, tsk->pid)) {
			VEOS_ERROR("Reviving task state at Driver failed");
			VEOS_DEBUG("Failed to revive state of %d at Driver"
					"Retval: %d", tsk->pid, -errno);
			retval = -EFAULT;
                        goto hndl_return;
		}
		tsk->is_dlt_drv = false;
		tsk->is_crt_drv = true;

		retval = 0;
		goto hndl_return;

	} else if (tsk) {
		/* PID conflict occurs at VEOS. This a race scenario wherein VEOS
		 * contains entry for VE task but correponding pseudo task does
		 * not exist.
		 * */
		VEOS_ERROR("Failed to find task structure");
		VEOS_DEBUG("PID conflict occurs at VEOS");
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Invoke EXEC VE handler */
	retval = psm_handle_exec_ve_process(pti,
			&core_id, &node_id, pid, exe_name,
			ve_proc.traced_proc, ve_proc.tracer_pid,
			ve_proc.shm_lhm_addr,
			ve_proc.shmid,
			ve_proc.lim, gid, uid, false, exe_path);
	if (0 > retval) {
		VEOS_ERROR("Failed to create new process");
		VEOS_DEBUG("Creation of new process(PID: %d) failed", pid);
	}

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	retval = psm_pseudo_send_load_binary_req(pti,
			core_id,
			node_id, retval);
	if (retval > 0)
		VEOS_DEBUG("Successfully sent Load Binary Req");
	else
		VEOS_DEBUG("Sending Load Binary Req failed");
	/* Added for debugging to list all the VE process
	 * in PSM at this time
	 * */
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the request of VE process deletion.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_delete_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_exit_req exit_req = {0};
	int32_t pid = -1;
	ProtobufCBinaryData *pseudo_del_msg = NULL;
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	pseudo_del_msg = (ProtobufCBinaryData *)(&(((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg));
	memcpy(&exit_req,
			(void *)(pseudo_del_msg->data), pseudo_del_msg->len);

	VEOS_DEBUG("Delete request for VE process with PID %d", pid);

	ve_task_curr = find_ve_task_struct(pid);
	if (NULL == ve_task_curr) {
                VEOS_ERROR("Failed to find task structure");
                VEOS_DEBUG("Failed to fetch task structure for PID %d", pid);
                retval = -ESRCH;
		goto hndl_return1;
	}
	group_leader = ve_task_curr->group_leader;

	if (exit_req.pseudo_vefd > 0) {
		group_leader->pseudo_vefd = exit_req.pseudo_vefd;
	}

	VEOS_DEBUG("exit_req.clean_all_thread %d", exit_req.clean_all_thread);

	switch (exit_req.clean_all_thread) {
	case EXIT_THREAD:
		/* ve_exit() has been invoked */
		pthread_mutex_lock_unlock(&(ve_task_curr->ve_task_lock), LOCK,
				"Failed to acquire task lock [PID = %d]", pid);
		ve_task_curr->exit_code = exit_req.exit_code;
		ve_task_curr->exit_code_set = true;
		pthread_mutex_lock_unlock(&(ve_task_curr->ve_task_lock), UNLOCK,
				"Failed to acquire task lock [PID = %d]", pid);
		set_state(ve_task_curr);
		put_ve_task_struct(ve_task_curr);
		break;
	case EXIT_PROCESS:
		/* ve_exit_group() has been invoked
		 * - When exit_group() is invoked then, set the exit code
		 *   using this request
		 * - However cleanup will be performed by polling thread
		 */
		pthread_mutex_lock_unlock(
				&(group_leader->ve_task_lock), LOCK,
				"Failed to acquire task lock [PID = %d]",
				group_leader->pid);
		group_leader->exit_code = exit_req.exit_code;
		VEOS_DEBUG("Exit code for PID: %d %d", group_leader->pid,
				group_leader->exit_code);
		group_leader->exit_code_set = true;
		pthread_mutex_lock_unlock(
				&(group_leader->ve_task_lock), UNLOCK,
				"Failed to release task lock [PID = %d]",
				group_leader->pid);

		VEOS_DEBUG("Acquiring thread group lock");
		pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");

		/* Traverse thread_group list and remove all the thread entry */
		if (!list_empty(&group_leader->thread_group)) {
			list_for_each_safe(p, n, &group_leader->thread_group) {
				tmp = list_entry(p, struct ve_task_struct,
						thread_group);
				pthread_mutex_lock_unlock(
						&(tmp->ve_task_lock), LOCK,
						"Failed to acquire task lock [PID = %d]",
						tmp->pid);
				tmp->exit_code = exit_req.exit_code;
				tmp->exit_code_set = true;
				pthread_mutex_lock_unlock(
						&(tmp->ve_task_lock), UNLOCK,
						"Failed to release task lock [PID = %d]",
						tmp->pid);
			}
		} else {
			VEOS_DEBUG("thread group list is empty");
		}
		pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release thread-group-mm-lock");

		put_ve_task_struct(ve_task_curr);
		break;
	case EXIT_EXECVE_VH:
	case EXIT_EXECVE_VE:
		if (group_leader != ve_task_curr) {
			VEOS_DEBUG("Getting reference for group leader");
			group_leader = find_ve_task_struct(group_leader->pid);
		}
		/* We have taken reference for group_leader
		 * and ve_task_curr */
		psm_do_process_cleanup(group_leader,
				ve_task_curr,
				exit_req.clean_all_thread);
		break;
	}
	retval = 0;
#ifdef VE_OS_DEBUG
	/* Added for debugging to list all the VE process
	 * in PSM at this time
	 */
	list_ve_proc();
#endif
hndl_return1:
	/* SEND DELETE ACK */
	retval = psm_pseudo_send_delete_ack(pti, retval, pid);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepares the acknowledgment/response that is to be
 * sent to pseudo process.
 *
 * @param[in] pti Contains the message received from pseudo process
 * @param[in] cleanup_flag Cleanup needs to be done at pseudo side
 * @param[in] pid PID of VE process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_pseudo_send_delete_ack(struct veos_thread_arg *pti,
		int cleanup_flag, int pid)
{
	ssize_t retval = -1;
	PseudoVeosMessage delete_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, pack_msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument pti");
		goto hndl_return;
	}
	/* prepare DELETE ACK response */
		VEOS_DEBUG("Sending DELETE_ACK for PID %d", pid);
	delete_ack.has_syscall_retval = true;
	delete_ack.syscall_retval = cleanup_flag;

	/* Pack delete_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&delete_ack);
	pack_msg_len = pseudo_veos_message__pack(&delete_ack, (uint8_t *)buf);
	if (pseudo_msg_len != pack_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, pack_msg_len);
		retval = -1;
		goto hndl_return;
	}

	/* Send ACK to the pseudo side */
	VEOS_DEBUG("Sending delete acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Sending command to Pseudo failed");
		VEOS_ERROR("Send command wrote %ld bytes",
				retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Prepares the clone acknowledgment/response that is to be
 * sent to pseudo process.
 *
 * @param[in] pti Contains the message received from pseudo process
 * @param[in] syscall_ret Contains the value to be sent to pseudo process
 * @param[in] fork_info Contains updated offset of the newly created thread
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_pseudo_send_clone_ack(struct veos_thread_arg *pti,
		int64_t syscall_ret, struct ve_fork_info *fork_info)
{
	ssize_t retval = -1;
	PseudoVeosMessage clone_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData clone_ack_msg = {0};
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	struct ve_proc_info clone_proc_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument(pti) received "
				"from pseudo process");
		goto hndl_return;
	}

	if (!fork_info) {
		VEOS_ERROR("Invalid(NULL) argument(fork_info) received "
				"from pseudo process");
		goto hndl_return;
	}

	/* Populate core_id and node_id to be sent to pseudo process */
	clone_proc_info.core_id = fork_info->core_id;
	clone_proc_info.node_id = fork_info->node_id;
	clone_proc_info.offset = fork_info->offset;

	/* prepare CLONE ACK response */
	clone_ack.has_syscall_retval = true;
	clone_ack.syscall_retval = syscall_ret;

	clone_ack.has_pseudo_msg = true;
	clone_ack_msg.len = sizeof(struct ve_proc_info);
	clone_ack_msg.data = (uint8_t *)&clone_proc_info;
	clone_ack.pseudo_msg = clone_ack_msg;

	/* Pack clone_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&clone_ack);

	msg_len = pseudo_veos_message__pack(&clone_ack, (uint8_t *)buf);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending CLONE acknowledgement");
	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor, buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles clone() request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_clone_ve_proc_req(veos_thread_arg_t *pti)
{
	int retval = -1;
	ProtobufCBinaryData pseudo_clone_msg = {0};
	struct pseudo_ve_clone_info ve_clone_info = {0};
	struct ve_fork_info fork_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"pseudo process");
		goto hndl_return;
	}

	pseudo_clone_msg =
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	memcpy(&ve_clone_info, pseudo_clone_msg.data, pseudo_clone_msg.len);

	VEOS_DEBUG("Received CLONE request from PARENT: %d for CHILD: %d",
			((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid,
			ve_clone_info.child_pid);

	fork_info.parent_pid = ((PseudoVeosMessage *)pti->
			pseudo_proc_msg)->pseudo_pid;
	fork_info.child_pid = ve_clone_info.child_pid;

	/* Main fork-routine which duplicates the process(or)thread */
	retval = do_ve_fork(ve_clone_info.flags, ve_clone_info.stack_ptr, 0,
			(int *)ve_clone_info.ptid,
			(int *)ve_clone_info.ctid, &fork_info);
	if (0 > retval)
		VEOS_ERROR("Failed to duplicate the thread");

	/* SEND CLONE ACK */
	retval = psm_pseudo_send_clone_ack(pti, retval, &fork_info);
	if (0 > retval)
		VEOS_ERROR("Failed to send CLONE acknowledgement to "
				"pseudo process");

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles fork() request from pseudo process.
 *
 * @param[in] pti Contains the request message received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int psm_handle_fork_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct pseudo_ve_clone_info ve_fork_info = {0};
	struct ve_fork_info fork_info = {0};
	ProtobufCBinaryData pseudo_fork_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument(pti) received from "
				"pseudo process");
		goto hndl_return;
	}

	pseudo_fork_msg = ((PseudoVeosMessage *)pti->
			pseudo_proc_msg)->pseudo_msg;
	memcpy(&ve_fork_info, pseudo_fork_msg.data, pseudo_fork_msg.len);

	fork_info.child_pid =
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	fork_info.parent_pid = ve_fork_info.parent_pid;
	fork_info.shm_lhm_addr = ve_fork_info.shm_lhm_addr;
	fork_info.shmid = ve_fork_info.shmid;
	fork_info.veshm = ve_fork_info.veshm_dir;

	VEOS_DEBUG("Received FORK request from PARENT: %d for CHILD: %d",
			fork_info.parent_pid,
			fork_info.child_pid);

	/* Main fork-routine which duplicates the process(or)thread */
	retval = do_ve_fork(ve_fork_info.flags, ve_fork_info.stack_ptr, 0,
				(int *)ve_fork_info.ptid,
				(int *)ve_fork_info.ctid, &fork_info);
	if (0 > retval)
		VEOS_ERROR("Failed to duplicate the process");

	/*SEND FORK ACK*/
	retval = psm_pseudo_send_fork_ack(pti, retval);
	if (0 > retval)
		VEOS_ERROR("Failed to send FORK acknowledgement "
				"to pseudo process");

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends ACK for BLOCK request from Pseudo Process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_pseudo_send_block_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage block_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t msg_pack_len = 0, pseudo_msg_len = 0;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument received");
		goto hndl_return;
	}
	/*Populating BLOCK ACK*/
	block_ack.has_syscall_retval = true;
	block_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&block_ack);
	msg_pack_len = pseudo_veos_message__pack(&block_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_pack_len) {
		VEOS_ERROR("Acknowledgement from PSM to PSEUDO failed");
		VEOS_DEBUG("Expected Length: %d, Returned Length Message: %ld",
				(int)pseudo_msg_len, msg_pack_len);
		goto hndl_return;
	}

	VEOS_DEBUG("Sending BLOCK ACK");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("PSM failed in sending acknowledgement");
		VEOS_DEBUG("Send command wrote %ld bytes",
				retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Changes the state of the VE process from WAITING to RUNNING
 * so that it can be scheduled.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_handle_block_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t ve_pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument pti");
		goto hndl_return;
	}

	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	retval = psm_handle_block_request(ve_pid);
	if (0 > retval) {
		VEOS_ERROR("State of VE process not changed by PSM");
		retval = psm_pseudo_send_block_ack(pti, retval);
	} else
		/* Send BLOCK_ACK */
		retval = psm_pseudo_send_block_ack(pti, retval);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowledgment for UNLOCK request received from Pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_pseudo_send_unblock_and_setregval_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	ssize_t msg_pack_len = 0, pseudo_msg_len = 0;
	PseudoVeosMessage unblock_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	/* Popuate UNBLOCK ACK message */
	unblock_ack.has_syscall_retval = true;
	unblock_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&unblock_ack);
	msg_pack_len = pseudo_veos_message__pack(&unblock_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_pack_len) {
		VEOS_ERROR("PSM failed in sending acknowledgement to PSEUDO");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				msg_pack_len, pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending UNBLOCK ACK");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("PSM send block ack failed");
		VEOS_DEBUG("Send command wrote %ld bytes",
				retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Changes the state of the VE process from RUNNING to WAITING
 * so that it can be schedule and set the return value of system call
 * recieve from pseudo into SR00 register.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 or -errno on failure.
 *
 * @internal
 * @author PSMG / Scheduling and context switch
 */
int psm_handle_unblock_setregval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	int len = -1;
	struct ve_task_struct *tsk = NULL;
	PseudoVeosMessage *pseudo_req = {0};
	struct ve_sys_info sys_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid argument pti");
		goto send_failure_ack;
	}

	pseudo_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = pseudo_req->pseudo_pid;
	len = pseudo_req->pseudo_msg.len;
	if (len <= 0) {
		VEOS_ERROR("Failed to receive message from PSEUDO");
		VEOS_DEBUG("Failure: UNBLOCK_AND_SET_REGVAL "
				"message length: %d", len);
		goto send_failure_ack;
	}

	memcpy(&sys_info, pseudo_req->pseudo_msg.data, len);

	tsk = find_ve_task_struct(pid);
	if (!tsk) {
		VEOS_ERROR("Task with PID %d not found", pid);
		goto send_failure_ack;
	}

	if (true == sys_info.set_reg) {
		retval = psm_handle_set_reg_req(tsk, sys_info.reg_num,
				pseudo_req->syscall_retval, USER_REG_MASK);
		if (retval == -1) {
			VEOS_ERROR("PSM set register request failed");
			goto send_failure_ack;
		}
	} else {
		VEOS_DEBUG("System call return value not set for PID: %d",
				pid);
	}

	/* Send ACK to pseudo after updating register content */
	retval = psm_pseudo_send_unblock_and_setregval_ack(pti, 0);
	if (0 > retval) {
		VEOS_ERROR("Failed to send unblock and set regval ack");
		goto hndl_return;
	}

	retval = psm_handle_un_block_request(tsk, sys_info.is_blk,
			sys_info.sys_trace_stop);
	if (retval < 0) {
		VEOS_ERROR("Unblock request failed");
		VEOS_DEBUG("PSM Unblock request returned %d", retval);
	}
	goto hndl_return;

send_failure_ack:
	/* Send failure ACK to pseudo */
	retval = psm_pseudo_send_unblock_and_setregval_ack(pti, 0);
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Entering");
	return retval;
}


/**
* @brief Sends acknowledgment for SIGRETURN REQ request received from
*	pseudo process
*
* @param[in] pti Pointer to veos_thread_arg containing PSM socket file
*	for communication with pseudo process
* @param[in] message Acknowledgment message to be send to pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*
* @internal
* @author Signal Handling
*/
int psm_pseudo_send_sigreturn_ack(struct veos_thread_arg *pti,
		int syscall_ret, sigset_t *curr_mask)
{
	ssize_t retval = -1;
	PseudoVeosMessage sigreturn_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char cmd_buff[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;
	ProtobufCBinaryData sigreturn_ack_msg;

	VEOS_TRACE("Entering");

	VEOS_DEBUG("VEOS sending sigreturn acknowledgement to pseudo");

	/* Populating Retval value to be send to Pseudo process */
	sigreturn_ack.has_syscall_retval = true;
	sigreturn_ack.syscall_retval = syscall_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	sigreturn_ack.has_pseudo_msg = true;
	sigreturn_ack_msg.len = sizeof(sigset_t);
	sigreturn_ack_msg.data = (uint8_t *)curr_mask;
	sigreturn_ack.pseudo_msg = sigreturn_ack_msg;
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigreturn_ack);

	msg_len = pseudo_veos_message__pack(&
				sigreturn_ack, (uint8_t *)cmd_buff);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		retval = -1;
		goto hndl_return;
	}

	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			cmd_buff, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo");
		VEOS_DEBUG("Sending acknowledgement to VEOS returned %ld bytes",
				retval);
		retval = -1;
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Sends acknowledgment for SIGACTION REQ request received from
*	pseudo process
*
* @param[in] old_act Stores the current signal action
* @param[in] pti Pointer to veos_thread_arg containing PSM socket file for
*	communication with pseudo process
* @param[in] message Acknowledgment message to be send to pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
* @internal
* @author Signal Handling
*/
int psm_pseudo_send_sigaction_ack(struct sigaction *old_act,
		struct veos_thread_arg *pti,
		int syscall_ret)
{
	int retval = -1;
	char cmd_buff[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	PseudoVeosMessage sigaction_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData sigaction_ack_msg;

	VEOS_TRACE("Entering");

	/* Populating Retval value to be send to Pseudo process */
	sigaction_ack.has_syscall_retval = true;
	sigaction_ack.syscall_retval = syscall_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	sigaction_ack.has_pseudo_msg = true;
	sigaction_ack_msg.len = sizeof(struct sigaction);
	sigaction_ack_msg.data = (uint8_t *)old_act;
	sigaction_ack.pseudo_msg = sigaction_ack_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigaction_ack);

	msg_len = pseudo_veos_message__pack(&
				sigaction_ack, (uint8_t *)cmd_buff);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("internal message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		retval = -EFAULT;
		goto hndl_return1;
	}

	VEOS_DEBUG("VEOS sending sigaction acknowledgement to pseudo");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			cmd_buff, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo");
		VEOS_DEBUG("failed to send acknowledgement to pseudo "
				"transferred %d bytes", retval);
		retval = -EPIPE;
	}

hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}
/**
* @brief Handles the "VE SIGNAL REQ" from pseudo process
*
*	This function checks if the synchronous fatal signal is pending
*	for the process, if yes then requested Signal will not be
*	delivered to VE process.
*
* @param[in] pti Pointer to structure containing the request received from
* the pseudo process
*
* @return: On failure, returns -1 or -errno and on success, returns a
* positive value
* @internal
* @author Signal Handling
*/
int psm_handle_signal_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_signal_info signal_info = {0};
	struct ve_task_struct *ve_task_curr = NULL;
	PseudoVeosMessage *pseudo_req;
	size_t length = 0;
	pid_t pid = -1, caller_pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto signal_error;
	}

	/* Immediately send ack to pseudo */
	retval = psm_pseudo_send_signal_ack(pti, 0);
	if (0 > retval) {
		VEOS_ERROR("failed to send signal acknowledgement");
		goto signal_error;
	}

	pseudo_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	caller_pid = pseudo_req->pseudo_pid;
	length = pseudo_req->pseudo_msg.len;
	if (length == 0) {
		retval = -1;
		VEOS_ERROR("%d request message length is invalid", caller_pid);
		VEOS_DEBUG("Failed to received message"
				" for command SIGNAL_REQ %zu", length);
		goto signal_error;
	}

	memcpy((char *)&signal_info, pseudo_req->pseudo_msg.data,
			length);

	pid = signal_info.tid;

	VEOS_DEBUG("Caller PID %d Callee PID %d", caller_pid, pid);

	ve_task_curr = find_ve_task_struct(pid);
	if (NULL != ve_task_curr) {
		VEOS_DEBUG("Signal %d task :%d",
				signal_info.signum, pid);
		if (pid != caller_pid) {
			VEOS_DEBUG("Permission check for signal request"
					" from %d to %d",
					caller_pid, pid);
			retval = check_kill_permission(caller_pid, ve_task_curr,
					pti->cred.uid, signal_info.signum);
			if (retval) {
				VEOS_ERROR("%d is not permitted"
						" to send signal to %d",
						caller_pid, pid);
				goto signal_error;
			}
		}

		/* Check whether a synchronous fatal signal is pending
		 * */
		psm_send_ve_signal(ve_task_curr,
				&(signal_info.ve_siginfo),
				signal_info.signum, 0);
	} else {
		VEOS_ERROR("Task %d not found", pid);
		retval = -ESRCH;
	}

signal_error:
	if (ve_task_curr)
		put_ve_task_struct(ve_task_curr);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief  Sends acknowledgment for signal/HW exception request received
 * from pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 or errno on failure.
 */
int psm_pseudo_send_signal_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);

	msg_len = pseudo_veos_message__pack(&ve_getprio_req
				, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		retval = -EFAULT;
		goto hndl_return;
	}

	VEOS_DEBUG("VEOS sending signal/hw exp acknowledgement to pseudo");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo, "
			"transferred %ld bytes", retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Sends acknowledgment for get interval request from
 * pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 * @param[in] cpu_info Structure contains the info of core and node id
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_get_cpu_ack(struct veos_thread_arg *pti,
		int ack_ret, struct ve_cpu_info *cpu_info)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_getproc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info = {0};
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populating Retval value to be send to Pseudo process */
	ve_getproc_req.has_syscall_retval = true;
	ve_getproc_req.syscall_retval = ack_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	if (cpu_info != NULL) {
		ve_getproc_req.has_pseudo_msg = true;
		veos_info.data = (uint8_t *)cpu_info;
		veos_info.len =  sizeof(struct ve_cpu_info);
		ve_getproc_req.pseudo_msg = veos_info;
	}

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getproc_req);
	msg_len = pseudo_veos_message__pack(&ve_getproc_req, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending getcpu acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			(uint8_t *)buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowledgment for get interval request from pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 * @param[in] tp Structure contains the info of time interval for current policy
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_get_interval_ack(struct veos_thread_arg *pti,
		int ack_ret, struct timespec *tp)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_getproc_req = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData veos_info = {0};

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populating retval to be send to pseudo process */
	ve_getproc_req.has_syscall_retval = true;
	ve_getproc_req.syscall_retval = ack_ret;

	/* Populating pseudo_msg to be send to pseudo process */
	if (tp != NULL) {
		ve_getproc_req.has_pseudo_msg = true;
		veos_info.data = (uint8_t *)tp;
		veos_info.len = sizeof(struct timespec);
		ve_getproc_req.pseudo_msg = veos_info;
	}

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getproc_req);
	msg_len = pseudo_veos_message__pack(&ve_getproc_req, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending sched_rr_get_interval acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the SIGRETURN REQ request from pseudo process.
*
* This function restores the VE process context from handler context.
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
*
* @return: On failure, returns -1 or -errno on success, returns a positive
* value
*
* @internal
* @author Signal Handling
*/
int psm_handle_sigreturn_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	int pid = -1;
	sigset_t ve_curr_mask = { {0} };
	struct ve_task_struct *ve_task_curr = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			"received from pseudo process");
		retval = -EINVAL;
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Received SIGRETURN request %d", pid);

	ve_task_curr = find_ve_task_struct(pid);

	if (NULL != ve_task_curr) {
		VEOS_DEBUG("restoring ve process context");
		retval = psm_restore_ve_context(ve_task_curr);
		sigemptyset(&ve_curr_mask);
		memcpy(&ve_curr_mask, &(ve_task_curr->blocked), sizeof(sigset_t));
		put_ve_task_struct(ve_task_curr);
	} else {
		VEOS_ERROR("No task with pid as: %d", pid);
		retval = -ESRCH;
	}
	retval = psm_pseudo_send_sigreturn_ack(pti, retval, &ve_curr_mask);
ret:
	VEOS_TRACE("Exiting");
	return retval;
}
/**
* @brief Handles the SIGACTION REQ request from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
*
* @return: On failure, returns -1 or -errno on success, returns a positive
* value
*
* @internal
* @author Signal Handling
*/
int psm_handle_sigaction_req(struct veos_thread_arg *pti)
{
	ssize_t retval = -1;
	int pid = -1;
	size_t length = 0;
	struct ve_sigaction_info sigaction_info = {0};
	struct ve_task_struct *ve_task_curr = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EAGAIN;
		goto signal_error;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Received sigaction request from "
			"Pseudo with pid :%d", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length == 0) {
		VEOS_ERROR("%d request message length is invalid", pid);
		VEOS_DEBUG("Failed to received message for"
				" command SIGACTION_REQ %zu", length);
		retval = -EFAULT;
		goto signal_error;
	}

	memcpy((char *)&sigaction_info,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	ve_task_curr = find_ve_task_struct(pid);

	if (NULL != ve_task_curr) {
		psm_do_sigaction_ve(ve_task_curr, &sigaction_info);
		put_ve_task_struct(ve_task_curr);
		retval = 0;
		retval = psm_pseudo_send_sigaction_ack(
				&(sigaction_info.old_ve_sigaction),
				pti,
				retval);
	} else {
		VEOS_DEBUG("No task with pid as: %d", pid);
		retval = -ESRCH;
		retval = psm_pseudo_send_sigaction_ack(&
				(sigaction_info.old_ve_sigaction),
				pti,
				retval);
	}
signal_error:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Acknowledgment for SIGSUSPEND_REQ request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value.
*
* @internal
* @author Signal Handling
*/
int psm_pseudo_send_sigsuspend_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigsuspend_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto handle_error;
	}

	/* Populating Retval value to be send to Pseudo process */
	ve_sigsuspend_ack.has_syscall_retval = true;
	ve_sigsuspend_ack.syscall_retval = ack_ret;

	pseudo_msg_len =
		pseudo_veos_message__get_packed_size(&ve_sigsuspend_ack);

	msg_len = pseudo_veos_message__pack(&
				ve_sigsuspend_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		retval = -EFAULT;
		goto handle_error;
	}

	VEOS_DEBUG("VEOS Sending sigsuspend acknowledgment to pseudo");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo "
			"transferred %ld bytes", retval);
		retval = -EFAULT;
	}

handle_error:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the "SIGSUSPEND_REQ" request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process.
*
* @return: On failure, returns -1 or -errno and on success, returns 0
*
* @internal
* @author Signal Handling
*/
int psm_handle_sigsuspend_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	size_t length = 0;
	sigset_t mask_set;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Recevied SIGSUSPEND request from "
			"Pseudo with pid :%d", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length == 0) {
		VEOS_ERROR("request message length is invalid");
		VEOS_DEBUG("Failed to received message for"
				" command SIGSUSPEND_REQ %zu", length);
		retval = -EFAULT;
		goto send_ack;
	}


	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("Task[%d] not found", pid);
		retval = -ESRCH;
		goto send_ack;
	}

	sigemptyset(&mask_set);
	memcpy(&mask_set, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			((PseudoVeosMessage *)pti->
			 pseudo_proc_msg)->pseudo_msg.len);
	psm_do_sigsuspend(tsk, &mask_set);
	retval = 0;
	put_ve_task_struct(tsk);
send_ack:
	retval = psm_pseudo_send_sigsuspend_ack(pti, retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Acknowledgment for SET NEW SAS request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
* @param[in] sigalt_ack Stores the information related to alternate stack.
*
* @return: On failure, returns -1 and on success, returns a positive value.
*
* @internal
* @author Signal Handling
*/
int psm_setnew_sas_ack(struct veos_thread_arg *pti,
		struct ve_sigalt_info *sigalt_ack)
{
	ssize_t retval = -1;
	PseudoVeosMessage new_sas_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	VEOS_TRACE("Entering");

	if (!pti || !sigalt_ack) {
		VEOS_ERROR("invalid(NULL) argument received");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* Populating Retval for sending to pseudo process */
	new_sas_ack.has_syscall_retval = true;
	if (sigalt_ack->retval)
		new_sas_ack.syscall_retval = sigalt_ack->retval;
	else
		new_sas_ack.syscall_retval = 0;

	/* Populating pseudo_msg for sending to pseudo process */
	new_sas_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)sigalt_ack;
	veos_info.len = sizeof(struct ve_sigalt_info);
	new_sas_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&new_sas_ack);

	msg_len =
		pseudo_veos_message__pack(&new_sas_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		retval = -EFAULT;
		goto hndl_return;
	}

	VEOS_DEBUG("VEOS sending set new sas acknowledgement to veos");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo "
			"transferred %ld bytes", retval);
		retval = -EFAULT;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles SET NEW SAS request from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
*	pseudo process
*
* @return: On failure, returns -1 or -errno and on success, returns a
* positive value
*
* @internal
* @author Signal Handling
*/
int psm_handle_setnew_sas_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	int pid = -1;
	size_t length = 0;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_sigalt_info sigalt_req = {0};
	struct ve_sigalt_info sigalt_ack = {0};

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Received NEW SAS request from Pseudo with pid :%d", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length == 0) {
		VEOS_ERROR("[%d] request message length is invalid", pid);
		VEOS_DEBUG("Failed to received message for"
				" command SET_NEW_SAS %zu", length);
		retval = -EFAULT;
		goto ret;
	}

	memcpy(&sigalt_req, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			((PseudoVeosMessage *)pti->pseudo_proc_msg)->
			pseudo_msg.len);

	ve_task_curr = find_ve_task_struct(pid);

	if (NULL != ve_task_curr) {
		if (sigalt_req.old_sas_flag) {
			psm_getold_sas(ve_task_curr, &(sigalt_ack.old_sas));
		}

		if (sigalt_req.new_sas_flag) {
			sigalt_ack.retval = psm_setnew_sas(ve_task_curr,
					&(sigalt_req.new_sas));
		}

		put_ve_task_struct(ve_task_curr);
		retval = psm_setnew_sas_ack(pti, &sigalt_ack);
	} else {
		VEOS_DEBUG("Task %d not found", pid);
		sigalt_ack.retval = -ESRCH;
		retval = psm_setnew_sas_ack(pti, &sigalt_ack);
	}

ret:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles SIGPROCMASK REQ request from pseudo process.
*
* @param[in] oldset Stores old signal mask
*
* @param[in] pti Pointer to structure containing the request received from
*	pseudo process
*
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return: On failure, returns -1 or -errno and on success, returns a
* positive value
*
* @internal
* @author Signal Handling
*/
int psm_pseudo_send_sigprocmask_ack(struct ve_signal_mask *curr_mask,
		struct veos_thread_arg *pti,
		int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigprocmask_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	VEOS_TRACE("Entering");

	if (!pti || !curr_mask) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* Populating Retval for sending to pseudo process */
	ve_sigprocmask_ack.has_syscall_retval = true;
	ve_sigprocmask_ack.syscall_retval = ack_ret;

	/* Populating pseudo_msg for sending to pseudo process */
	ve_sigprocmask_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)curr_mask;
	veos_info.len = sizeof(struct ve_signal_mask);
	ve_sigprocmask_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_sigprocmask_ack);

	msg_len = pseudo_veos_message__pack(&
				ve_sigprocmask_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		goto hndl_return;
	}

	VEOS_DEBUG("VEOS sending sigprocmask acknowledgement to pseudo");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo "
				"transferred %ld bytes", retval);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles "SIGPROCMASK REQ" from pseudo process.
 *
 * @param pti Pointer to structure containing the request received from
 *       pseudo process
 *
 * @return On failure, returns -1 or negative errno and on success,
 *        returns a positive value.
 *
 * @internal
 * @author Signal Handling
 */
int psm_handle_sigprocmask_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	size_t length = 0;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_signal_mask ve_mask;

	VEOS_TRACE("Entering");

	sigemptyset(&ve_mask.newset);
	sigemptyset(&ve_mask.oldset);
	sigemptyset(&ve_mask.ve_curr_mask);

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("VEOS recevied sigprocmask request from "
			"Pseudo with pid :%d", pid);
	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length == 0) {
		VEOS_ERROR("[%d] request message length is invalid", pid);
		VEOS_DEBUG("Failed to received message for"
				" command SIGPROCMASK_REQ %zu", length);
		retval = -EFAULT;
		goto ret;
	}

	ve_task_curr = find_ve_task_struct(pid);

	if (NULL != ve_task_curr) {
		memcpy(&ve_mask, ((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.data,
				((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.len);

		VEOS_DEBUG("New signal mask : %lx",
				ve_mask.newset.__val[0]);

		/* Set new signal mask and fetch old signal mask
		 * */
		psm_do_sigprocmask(ve_task_curr, &ve_mask);
		memcpy(&(ve_mask.ve_curr_mask), &(ve_task_curr->blocked),
				sizeof(sigset_t));

		put_ve_task_struct(ve_task_curr);
		retval = 0;
		retval = psm_pseudo_send_sigprocmask_ack(&ve_mask,
				pti,
				retval);
	} else {
		VEOS_ERROR("No task with pid as: %d", pid);
		retval = -ESRCH;
		retval = psm_pseudo_send_sigprocmask_ack(&ve_mask,
				pti,
				retval);
	}

ret:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handle "HANDLE EXCEPTION" request from pseudo process.
 *
 * @param[in] pti Pointer to structure containing the request received from
 *	pseudo process
 *
 * @return: On failure, returns -1 or -errno and on success, returns a
 * 	positive value.
 *
 * @internal
 * @author Signal Handling
 */
int psm_handle_exception_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	size_t length = 0;
	struct ve_task_struct *ve_task_curr = NULL;
	siginfo_t ve_siginfo;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto ret;
	}

	/* Immediately send ack to pseudo */
	retval = psm_pseudo_send_signal_ack(pti, 0);
	if (0 > retval) {
		VEOS_DEBUG("Fail to send signal acknowledgment");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg)
		.len;
	if (length == 0) {
		retval = -1;
		VEOS_DEBUG("Failed to received message"
				" for command HW_EXP_REQ %zu", length);
		VEOS_ERROR("[%d] request message length is invalid", pid);
		goto ret;
	}
	VEOS_DEBUG("Received handle exception request from "
			"Pseudo with pid :%d", pid);

	ve_task_curr = find_ve_task_struct(pid);
	memset(&ve_siginfo, 0, sizeof(siginfo_t));

	if (NULL != ve_task_curr) {
		memcpy(&ve_siginfo, ((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.data,
				((PseudoVeosMessage *)pti->pseudo_proc_msg)->
				pseudo_msg.len);

		VEOS_DEBUG("signal %d due to exception, task %d",
				ve_siginfo.si_signo, pid);

		psm_handle_hw_exception(ve_task_curr,
				&ve_siginfo,
				ve_siginfo.si_signo);
		put_ve_task_struct(ve_task_curr);
		retval = 0;
	} else {
		VEOS_ERROR("Handling exception failed for pid %d", pid);
		retval = -ESRCH;
	}

ret:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
* @brief Sends acknowledgment for "SIGPENDING REQ" from pseudo process
*
* @param[in] veos_set mask of blocked pending signals
* @param[in] pti Pointer to structure containing the request received from
* pseudo_process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*
* @internal
* @author Signal Handling
*/
int psm_pseudo_send_sigpending_ack(sigset_t *veos_set,
		struct veos_thread_arg *pti,
		int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage ve_sigpending_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len, msg_len;

	VEOS_TRACE("Entering");

	if (!pti || !veos_set) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received");
		retval = -EINVAL;
		goto hndl_return;
	}

	VEOS_DEBUG("blocked pending signal mask: %lx"
			, veos_set->__val[0]);

	/* Populating Retval for sending to pseudo process */
	ve_sigpending_ack.has_syscall_retval = true;
	ve_sigpending_ack.syscall_retval = ack_ret;

	/* Populating pseudo_msg for sending to pseudo process */
	ve_sigpending_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)veos_set;
	veos_info.len = sizeof(sigset_t);
	ve_sigpending_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_sigpending_ack);

	msg_len = pseudo_veos_message__pack(&
				ve_sigpending_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
		                                pseudo_msg_len, msg_len);
		VEOS_ERROR("internal message protocol buffer error");
		retval = -EFAULT;
		goto hndl_return;
	}

	VEOS_DEBUG("VEOS sending sigpending acknowledgement to pseudo");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("failed to send acknowledgement to pseudo "
				"transferred %ld bytes", retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handle "SIGPENDING REQ" request from pseudo process
 *
 * @param[in] pti Pointer to structure containing the request received from
 * 	pseudo process
 *
 * @return: On failure, returns -1 or -errno and on success, returns a
 * 	positive value
 *
 * @internal
 * @author Signal Handling
 */
int psm_handle_sigpending_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	sigset_t veos_set;

	sigemptyset(&veos_set);

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument"
			" received from pseudo process");
		retval = -EINVAL;
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VEOS_DEBUG("Received sigpending request from "
			"Pseudo with pid :%d", pid);

	ve_task_curr = find_ve_task_struct(pid);

	if (NULL != ve_task_curr) {
		retval = 0;
		psm_do_sigpending(ve_task_curr, &veos_set);

		put_ve_task_struct(ve_task_curr);
		retval = psm_pseudo_send_sigpending_ack(&veos_set,
				pti,
				retval);
	} else {
		VEOS_ERROR("No task with pid as: %d", pid);
		retval = -ESRCH;
		retval = psm_pseudo_send_sigpending_ack(&veos_set,
				pti,
				retval);
	}

ret:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the CLOCK CPUTIME request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_clk_cputime_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int clk_type = -1;
	PseudoVeosMessage *clk_cputime_req = NULL;
	struct ve_task_struct *tsk = NULL;
	struct ve_task_struct *current = NULL;
	struct timespec tp = {0};
	struct ve_clockinfo clockinfo = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from Pseudo");
		goto hndl_return;
	}

	clk_cputime_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	memcpy(&clockinfo, (clk_cputime_req->pseudo_msg.data),
			clk_cputime_req->pseudo_msg.len);

	VEOS_DEBUG("Clock id: %d, PID : %d",
			clockinfo.clockid, clockinfo.pid);

	tsk = find_ve_task_struct(clockinfo.pid);

	if (NULL == tsk) {
		VEOS_ERROR("Failed to find task %d", clockinfo.pid);
		retval = -ESRCH;
		goto send_ack1;
	}

	if (clockinfo.pid_flag == 0) {
		clk_type = ((clockinfo.clockid & CLOCKFD_MASK) == 2) ? 1 : 0;
		retval = psm_handle_clk_cputime_request
			(tsk, clk_type, &tp);
	} else {
		current = find_ve_task_struct(clockinfo.current);
		if (NULL == current) {
			VEOS_ERROR("Failed to find current task");
			retval = -ESRCH;
			goto send_ack1;
		}

		/* third bit checks process or thread
		 * rest two bits checks for clock validity
		 */
		if (CPUCLOCK_PERTHREAD(clockinfo.clockid)) {
			if (current->sighand == tsk->sighand)
				clk_type = 0;
		} else {
			if (tsk == current || thread_group_leader(tsk))
				clk_type = 1;
		}
		if (clk_type == -1) {
			VEOS_ERROR("Invalid clock_gettime() request\n");
			retval = -EINVAL;
			goto send_ack;
		}
		VEOS_DEBUG("clock type: %d", clk_type);
		switch (CPUCLOCK_WHICH(clockinfo.clockid)) {
			default:
				VEOS_ERROR("Invalid clock %d",
						clockinfo.clockid);
				retval = -EINVAL;
				break;
			case 0:
			case 1:
			case 2:
				retval = psm_handle_clk_cputime_request
					(tsk, clk_type, &tp);
				break;
		}
	}
send_ack:
	if (clockinfo.pid_flag)
		put_ve_task_struct(current);
send_ack1:
	if (tsk)
		put_ve_task_struct(tsk);
	retval = psm_pseudo_clk_cputime_ack(pti, retval, tp);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for CLK_CPUTIME request received from
 * pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Acknowledgment return value  to be send to pseudo process
 * @param[in] tp struct timespec contains the time of process/thread on CPU
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_clk_cputime_ack(struct veos_thread_arg *pti,
		int ack_ret, struct timespec tp)
{
	ssize_t retval = -1;
	PseudoVeosMessage clk_cputime_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ProtobufCBinaryData veos_info = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populating Retval for sending to pseudo process */
	clk_cputime_ack.has_syscall_retval = true;
	clk_cputime_ack.syscall_retval = ack_ret;

	/* Populating pseudo_msg for sending to pseudo process */
	clk_cputime_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&tp;
	veos_info.len = sizeof(struct timespec);
	clk_cputime_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&clk_cputime_ack);

	msg_len = pseudo_veos_message__pack(&clk_cputime_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending clock cputime acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the getcpu request from pseudo process
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 or -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_getcpu_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_cpu_info cpu_info = {0};
	int pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"pseudo process");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Received getcpu request from "
			"Pseudo with pid :%d", pid);

	ve_task_curr = find_ve_task_struct(pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		cpu_info.cpu = ve_task_curr->core_id;
		cpu_info.node = ve_task_curr->node_id;
		put_ve_task_struct(ve_task_curr);
		retval = psm_pseudo_send_get_cpu_ack(pti,
				retval, &cpu_info);
	} else {
		retval = -ESRCH;
		VEOS_ERROR("Failed to find task structure");
		retval = psm_pseudo_send_get_cpu_ack(pti, retval, NULL);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
/**
 * @brief Handles the get interval request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_interval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct timespec tp = {0};
	pid_t pid = -1;
	pid_t ve_pid = -1;
	int length = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from "
				"Pseudo process");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Received get interval request from "
			"Pseudo with pid :%d", pid);

	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&ve_pid, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(ve_pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		tp.tv_sec = veos_time_slice / (1000 * 1000);
		tp.tv_nsec = (veos_time_slice % (1000 * 1000)) * 1000;
		put_ve_task_struct(ve_task_curr);
		retval = psm_pseudo_send_get_interval_ack(pti,
				retval, &tp);
	} else {
		VEOS_ERROR("Failed to find task structure");
		VEOS_DEBUG("Task with PID %d not found", ve_pid);
		retval = -ESRCH;
		retval = psm_pseudo_send_get_interval_ack(pti, retval, NULL);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the GET RLIMIT request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_rlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rlimit_req = NULL;
	struct ve_task_struct *tsk = NULL;
	struct rlimit rlim = {0};
	struct rlimit_info rlimit = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from pseudo side");
		goto hndl_return;
	}

	rlimit_req = (PseudoVeosMessage  *)pti->
		pseudo_proc_msg;

	memcpy(&rlimit, rlimit_req->pseudo_msg.data,
			rlimit_req->pseudo_msg.len);

	VEOS_DEBUG("Resource : %d, pid : %d",
			rlimit.resource, rlimit.pid);

	tsk = find_ve_task_struct(rlimit.pid);
	if (NULL == tsk) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto send_ack;
	}

	retval = psm_handle_get_rlimit_request(rlimit_req->pseudo_pid,
			tsk, rlimit.resource, &rlim, pti->cred.uid, pti->cred.gid);

	put_ve_task_struct(tsk);
send_ack:
	retval = psm_pseudo_get_rlimit_ack(pti, retval, rlim);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Sends acknowlegdment for GET RLIMIT request received
* from pseudo process.
*
* @param[in] pti Contains the request received from the pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
* @param[in] rlim rlim struct rlimt contains the resource limit
*
* @return positive value on success, -1 on failure.
*/
int psm_pseudo_get_rlimit_ack(struct veos_thread_arg *pti,
		int ack_ret, struct rlimit rlim)
{
	ssize_t retval = -1;
	PseudoVeosMessage rlimit_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData veos_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	rlimit_ack.has_syscall_retval = true;
	rlimit_ack.syscall_retval = ack_ret;

	rlimit_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&rlim;
	veos_info.len =  sizeof(struct rlimit);
	rlimit_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rlimit_ack);
	msg_len = pseudo_veos_message__pack(&rlimit_ack, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending getrlimit acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the SET RLIMIT request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_set_rlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rlimit_req = NULL;
	struct ve_task_struct *tsk = NULL;
	struct rlimit rlim = {0};
	struct rlimit_info *rlimit_msg = NULL;
	int resource = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	rlimit_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;
	rlimit_msg = (struct rlimit_info *)(rlimit_req->pseudo_msg.data);

	memcpy(&resource, &(rlimit_msg->resource),
			sizeof(resource));
	memcpy(&rlim, &(rlimit_msg->rlim),
			sizeof(rlim));

	VEOS_DEBUG("Resource : %d, pid : %d",
			resource, rlimit_msg->pid);

	VEOS_DEBUG("rlim_cur: %ld rlim_max: %ld",
			rlim.rlim_cur, rlim.rlim_max);

	tsk = find_ve_task_struct(rlimit_msg->pid);
	if (NULL == tsk) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto send_ack;
	}

	retval = psm_handle_set_rlimit_request(rlimit_req->pseudo_pid,
			tsk, resource, rlim, pti->cred.uid, pti->cred.gid);
	put_ve_task_struct(tsk);

send_ack:
	retval = psm_pseudo_set_rlimit_ack(pti, retval);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for SET RLIMIT request received
 * from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_set_rlimit_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage rlimit_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	rlimit_ack.has_syscall_retval = true;
	rlimit_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rlimit_ack);
	msg_len =  pseudo_veos_message__pack(&rlimit_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending setrlimit acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for GET AFFINITY request received
 * from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Return value send to VE process
 * @param[in] mask CPU set mask to send
 * @param[in] cpusetsize CPU set mask size
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_getaffinity_ack(struct veos_thread_arg *pti,
		int64_t ack_ret, cpu_set_t mask, size_t cpusetsize)
{
	ssize_t ret = -1;
	PseudoVeosMessage getaffinity_resp = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData veos_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Use retval field to send CPU affinity value */
	getaffinity_resp.has_syscall_retval = true;
	getaffinity_resp.syscall_retval = ack_ret;

	/*Populate acknowledgement message*/
	getaffinity_resp.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&mask;
	veos_info.len =  cpusetsize;
	getaffinity_resp.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			getaffinity_resp);
	msg_len = pseudo_veos_message__pack(&getaffinity_resp, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending getaffinity acknowledgement");
	ret = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handles the GET AFFINITY request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_getaffinity_req(struct veos_thread_arg *pti)
{
	int64_t retval = -1;
	struct ve_setaffinity_req ve_req = {0};
	PseudoVeosMessage *getaffinity_req = NULL;
	pid_t caller_pid = 0;
	cpu_set_t mask;

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Received getaffinity request from"
			"Pseudo with PID : %d", caller_pid);

	getaffinity_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	memcpy(&ve_req, getaffinity_req->pseudo_msg.data,
			getaffinity_req->pseudo_msg.len);

	retval = psm_handle_getaffinity_request(ve_req.pid, ve_req.cpusetsize, &mask);
	if (retval < 0)
		VEOS_ERROR("Failed to handle getaffinity request");

hndl_return:
	VEOS_DEBUG("PID : %d GET AFFINITY return: %ld",
			ve_req.pid, retval);
	/* Send ACK */
	retval = psm_pseudo_send_getaffinity_ack(pti, retval, mask,
			ve_req.cpusetsize);
	if (retval < 0)
		VEOS_ERROR("Failed to send getaffinity acknowledgement");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the SET AFFINITY request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_setaffinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_setaffinity_req ve_req = {0};
	PseudoVeosMessage *setaffinity_req = NULL;
	pid_t caller_pid = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VEOS_DEBUG("Received setaffinity request from"
			"Pseudo with PID : %d", caller_pid);

	setaffinity_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;

	memcpy(&ve_req, setaffinity_req->pseudo_msg.data,
			setaffinity_req->pseudo_msg.len);

	/* Releasing ipc read lock and acquiring write lock */
	pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock), UNLOCK,
			"Failed to release ve_relocate_lock release lock");
	pthread_rwlock_lock_unlock(&(VE_NODE(0)->ve_relocate_lock), WRLOCK,
			"Failed to acquire ve_relocate_lock write lock");

	retval = psm_handle_setaffinity_request(caller_pid,
			ve_req.pid, ve_req.mask);
hndl_return:
	VEOS_DEBUG("PID : %d SET AFFINITY returns %d",
			caller_pid, retval);
	/* Send ACK */
	retval = psm_pseudo_send_setaffinity_ack(pti, retval);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for SET AFFINITY request received
 * from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_setaffinity_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage setaffinity_resp = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}
	/* Use retval field to syscall retval value */
	setaffinity_resp.has_syscall_retval = true;
	setaffinity_resp.syscall_retval = ack_ret;

	/*Populate acknowledgement message*/
	setaffinity_resp.has_pseudo_msg = false;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(
			&setaffinity_resp);
	msg_len =  pseudo_veos_message__pack(&setaffinity_resp, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending setaffinity acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the GET RUSAGE request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_rusage_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rusage_req = NULL;
	struct ve_task_struct *tsk = NULL, *group_leader = NULL;
	struct ve_rusage ve_r = {{0}};
	struct ve_rusage_info rusage_task = {0};
	uint64_t max_rss = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	rusage_req = (PseudoVeosMessage *)pti->
					pseudo_proc_msg;

	memcpy(&rusage_task, rusage_req->pseudo_msg.data,
		rusage_req->pseudo_msg.len);

	VEOS_DEBUG("who : %d, pid : %d",
			rusage_task.who, rusage_task.pid);

	tsk = find_ve_task_struct(rusage_task.pid);

	if (NULL == tsk) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto send_ack1;
	}

	retval = psm_handle_get_rusage_request(tsk, rusage_task.who, &ve_r);
	if (retval < 0) {
		VEOS_ERROR("Failed to handle rusage request");
		retval = -EINVAL;
		goto send_ack;
	}

	group_leader = tsk->group_leader;

	if (rusage_task.cleanup) {

		VEOS_DEBUG("Parent acquiring del_lock for PID %d",
				group_leader->pid);
		pthread_mutex_lock_unlock(&(group_leader->sighand->del_lock), LOCK,
				"Failed to acquire thread group delete lock");

		/* populating cexec_time field in parent as it waits for child */
		group_leader->parent->sighand->cexec_time =
				group_leader->sighand->cexec_time +
				get_ve_proc_exec_time(group_leader, 1);

		if (group_leader->p_ve_mm->crss_max > group_leader->p_ve_mm->rss_max)
			max_rss = group_leader->p_ve_mm->crss_max;
		else
			max_rss = group_leader->p_ve_mm->rss_max;

		VEOS_DEBUG("max_rss %ld", max_rss);

		if (group_leader->parent->p_ve_mm->crss_max < max_rss) {
			group_leader->parent->p_ve_mm->crss_max = max_rss;
			VEOS_DEBUG("Pid: %d crss_max: %ld",
					group_leader->parent->pid, max_rss);
		}

		pthread_mutex_lock_unlock(&(group_leader->ve_task_lock), LOCK,
				"Failed to acquire task lock");

		VEOS_DEBUG("Parent %d invoking cleanup of Child: %d",
				tsk->parent->pid, tsk->pid);
		group_leader->ve_task_state = EXIT_DEAD;

		pthread_mutex_lock_unlock(&(group_leader->ve_task_lock), UNLOCK,
				"Failed to release task lock");
		pthread_mutex_lock_unlock(&group_leader->ref_lock, LOCK,
				"Failed to acquire task reference lock");
		VEOS_DEBUG("Acquired ref_lock, waiting for conditional signal");
		if (!(group_leader->ref_count == 1) &&
				pthread_cond_wait(&group_leader->ref_lock_signal,
					&group_leader->ref_lock)) {
			veos_abort("pthread_cond_signal failed %s",
					strerror(errno));
		}
		pthread_mutex_lock_unlock(&group_leader->ref_lock, UNLOCK,
				"Failed to release task reference lock");

		delete_entries(group_leader);
		retval = 0;
		goto send_ack1;

	}
	retval = 0;
send_ack:
	if (tsk)
		put_ve_task_struct(tsk);
send_ack1:
	retval = psm_pseudo_get_rusage_ack(pti, retval, ve_r);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for GET rusage request received
 * from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 * @param[in] ve_r struct ve_rusage to fill VE process resource usage
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_get_rusage_ack(struct veos_thread_arg *pti,
		int ack_ret, struct ve_rusage ve_r)
{
	ssize_t retval = -1;
	PseudoVeosMessage rusage_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData veos_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	rusage_ack.has_syscall_retval = true;
	rusage_ack.syscall_retval = ack_ret;

	rusage_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&ve_r;
	veos_info.len = sizeof(struct ve_rusage);
	rusage_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rusage_ack);
	msg_len = pseudo_veos_message__pack(&rusage_ack, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}


	VEOS_DEBUG("Sending rusage acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}


/**
 * @brief Sends acknowlegdment for SYSINFO_REQ request received from
 * pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 * @param[in] ve_sysinfo system information populated in strcuture sysinfo
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_sysinfo_ack(struct veos_thread_arg *pti,
		int ack_ret, struct sysinfo *ve_sysinfo)
{
	ssize_t retval = -1;
	PseudoVeosMessage sysinfo_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	ProtobufCBinaryData veos_info = {0};

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	sysinfo_ack.has_syscall_retval = true;
	sysinfo_ack.syscall_retval = ack_ret;

	sysinfo_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)ve_sysinfo;
	veos_info.len = sizeof(struct sysinfo);
	sysinfo_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sysinfo_ack);
	msg_len = pseudo_veos_message__pack(&sysinfo_ack, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending sysinfo acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			(uint8_t *)buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the SYSINFO_REQ from pseudo process
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return postive value on success, -1 on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_sysinfo_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *sysinfo_req = NULL;
	struct ve_task_struct *ve_task_curr = NULL;
	struct sysinfo ve_sysinfo = {0};
	int pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	sysinfo_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = sysinfo_req->pseudo_pid;

	VEOS_DEBUG("Recevied sysinfo request from "
			"Pseudo with pid :%d", pid);

	ve_task_curr  = find_ve_task_struct(pid);
	if (NULL == ve_task_curr) {
		VEOS_ERROR("Failed to find task structure");
		retval = -ESRCH;
		goto hndl_return;
	}
	retval = psm_handle_sysinfo_request(ve_task_curr, &ve_sysinfo);
	put_ve_task_struct(ve_task_curr);
hndl_return:
	if (-1 == retval) {
		retval = -EFAULT;
		VEOS_ERROR("Failed to handle sysinfo request");
	}

	/* Send the response back to pseudo process */
	retval = psm_pseudo_send_sysinfo_ack(pti, retval, &ve_sysinfo);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for ACCT_REQ request received from
 * pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_acct_ack(struct veos_thread_arg *pti, int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage acct_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	acct_ack.has_syscall_retval = true;
	acct_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&acct_ack);
	msg_len = pseudo_veos_message__pack(&acct_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending ACCT_REQ acknowledgement");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the ACCT_REQ from pseudo process
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return postive value on success, -1 or -errno on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_acct_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	char *acct_file = NULL;
	PseudoVeosMessage *acct_req = NULL;
	int pid = -1;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	acct_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = acct_req->pseudo_pid;

	VEOS_DEBUG("Received acct request from Pseudo with pid :%d",
			pid);
	/*
	 * Checking does the VE process having a permit
	 * to enable/disable the accounting by using capget system call
	 */
	if (!check_ve_proc_capability(pid, CAP_SYS_PACCT)) {
		retval = -EPERM;
		goto hndl_return;
	}

	if (acct_req->has_pseudo_msg) {
		/* Case when accounting is enabled */
		VEOS_DEBUG("Accounting is enabled by pid: %d",
				pid);
		acct_file = malloc(acct_req->pseudo_msg.len);
		if (NULL == acct_file) {
			retval = -errno;
			VEOS_CRIT("fail to allocate memory: %s",
					strerror(errno));
			goto hndl_return;
		}
		memset(acct_file, '\0', acct_req->pseudo_msg.len);
		memcpy(acct_file, acct_req->pseudo_msg.data,
				acct_req->pseudo_msg.len);
	} else
		/* Case when accounting is disabled */
		VEOS_DEBUG("Accounting is disabled by pid: %d",
				pid);

	retval = psm_handle_do_acct_ve(acct_file);
hndl_return:
	if (0 > retval)
		VEOS_ERROR("VEOS fails to update Accounting");

	/* Send the response back to pseudo process */
	retval = psm_pseudo_send_acct_ack(pti, retval);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief prepare the acknowledgement and send the existing fd to pseudo process
 *
 * @param[in] pti contains the request message received from pseudo process
 * @param[in] pseudo_vefd value at vedriver fd
 *
 * @return positive value on success, -1 on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_send_pseudo_vefd_ack(struct veos_thread_arg *pti,
		int pseudo_vefd)
{

	ssize_t retval = -1;
	PseudoVeosMessage vefd_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Popuate FORK ACK process message */
	vefd_ack.has_syscall_retval = true;
	vefd_ack.syscall_retval = pseudo_vefd;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vefd_ack);
	msg_len = pseudo_veos_message__pack(&vefd_ack, (uint8_t *)buf);

	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		retval = -1;
		goto hndl_return;
	}

	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the request of fetching newfd for pseudo process
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_pseudo_vefd_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	int pseudo_vefd = -1;
	struct ve_task_struct *tsk = NULL;
	struct ve_task_struct *group_leader = NULL;

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	tsk  = find_ve_task_struct(pid);
	if (tsk) {
		VEOS_DEBUG("VE process with PID %d"
				" is executed by execve", pid);
		group_leader = tsk->group_leader;
		pseudo_vefd = group_leader->pseudo_vefd;
		put_ve_task_struct(tsk);

	} else {
		VEOS_DEBUG("VE process with PID %d"
				" is executed by ve_exec", pid);
	}

	retval = psm_handle_send_pseudo_vefd_ack(pti, pseudo_vefd);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends acknowlegdment for GET_REGVAL_REQ request received from
 * pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 * @param[in] ice Value of ice user register
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_pseudo_send_get_regval_ack(struct veos_thread_arg *pti,
		int ack_ret, uint64_t ice)
{
	ssize_t retval = -1;
	PseudoVeosMessage regval_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info = {0};
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, pack_msg_len = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Populate acknowledgment message */
	regval_ack.has_syscall_retval = true;
	regval_ack.syscall_retval = ack_ret;

	regval_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&ice;
	veos_info.len = sizeof(ice);
	regval_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&regval_ack);
	pack_msg_len = pseudo_veos_message__pack(&regval_ack, (uint8_t *)buf);
	if (pseudo_msg_len != pack_msg_len) {
		VEOS_ERROR("Packing message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, pack_msg_len);
		retval = -1;
		goto hndl_return;
	}

	VEOS_DEBUG("Sending GET_REGVAL_REQ Acknowledgment");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Send command failed");
		VEOS_DEBUG("PSM Pseudo send command wrote %ld bytes",
				retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the GET_REGVAL_REQ from pseudo process
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return postive value on success, -1 on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_get_regval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	uint64_t ice = 0;
	PseudoVeosMessage *regval_req = NULL;
	int pid = -1;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	regval_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = regval_req->pseudo_pid;

	VEOS_DEBUG("Received GET_REGVAL_REQ from Pseudo with PID :%d",
			pid);

	retval = psm_get_ice_regval(pid, &ice);
	if (0 > retval)
		VEOS_ERROR("PSM failed in getting ice value");

	/* Send the response back to pseudo process */
	retval = psm_pseudo_send_get_regval_ack(pti, retval, ice);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the request of fetching giduid for pseudo process
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_giduid_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct giduid_info id_info = {0};
	int pid = -1;
	int length = -1;
	struct ve_task_struct *ve_task = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument received from Pseudo");
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&id_info,
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.data,
		length);

	ve_task  = find_ve_task_struct(pid);
	if (NULL == ve_task) {
		VEOS_ERROR("Failed to find task structure");
		VEOS_DEBUG("PID %d does not exists", pid);
		retval = -1;
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(ve_task->ve_task_lock), LOCK,
		"Failed to acquire task lock [PID = %d]", pid);

	if (id_info.info_flag == true)
		ve_task->gid = id_info.data;
	else
		ve_task->uid = id_info.data;

	pthread_mutex_lock_unlock(&(ve_task->ve_task_lock), UNLOCK,
		 "Failed to release task lock [PID = %d]", pid);
	retval = 0;

	put_ve_task_struct(ve_task);
hndl_return:
	retval = psm_handle_send_pseudo_giduid_ack(pti, retval);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Sends an acknowledgment to the pseudo process that the system
 * call return value has been updated in VE process thread struct.
 *
 * @param[in] pti Contains the request message received from pseudo process
 * @param[in] ack_ret Command ack to send
 *
 * @return positive value on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
int psm_handle_send_pseudo_giduid_ack(struct veos_thread_arg *pti,
		int ack_ret)
{
	ssize_t retval = -1;
	PseudoVeosMessage giduid_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	char buf[MAX_PROTO_MSG_SIZE] = {0};

	VEOS_TRACE("Entering");
	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* Popuate GIDUID ACK process message */
	giduid_ack.has_syscall_retval = true;
	giduid_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&giduid_ack);
	msg_len = pseudo_veos_message__pack(&giduid_ack, (uint8_t *)buf);
	if (pseudo_msg_len != msg_len) {
		VEOS_ERROR("Internal message protocol error");
		VEOS_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);

		retval = -1;
		goto hndl_return;
	}

	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld, Transferred bytes: %ld",
				pseudo_msg_len, retval);
		retval = -1;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
