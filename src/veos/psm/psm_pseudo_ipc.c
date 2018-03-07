/**
 * @file  psm_pseudo_ipc.c
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
#include "ve_hw.h"
#include "psm_main.h"
#include "psm_task_mgmt.h"
#include "psm_clone.h"
#include "veos_ipc.h"
#include "psm_pseudo_ipc.h"
#include "amm_psm_if.h"
#include "psm_signal_handler.h"
#include "pseudo_veos.pb-c.h"
#include "velayout.h"

/**
* @brief This Function is used to communicate with PSM
*
* @param socket_fd Descriptor used to communicate with PSM
* @param buff contain req info to be sent to PSM
* @param max_len size of packed structure
*
* @return On failure, returns -1 and on success, returns any positive value
*/
ssize_t psm_pseudo_send_cmd(int socket_fd, void *buff, int max_len)
{
	ssize_t transferred = 0;
	ssize_t write_byte;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!buff)
		goto send_error;

	while ((write_byte =
		write(socket_fd, buff + transferred,
		      max_len - transferred)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Sending Command from Pseudo"
						"to PSM failed %s\n",
						strerror(write_byte));
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			  "transferred = %ld, write_byte = %ld\n",
			  transferred, write_byte);
	}

send_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_start_ve(struct veos_thread_arg *pti,
		pid_t pid, int64_t syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage start_ve_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t psm_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	start_ve_req.has_pseudo_pid = true;
	start_ve_req.pseudo_pid = pid;

	start_ve_req.has_syscall_retval = true;
	start_ve_req.syscall_retval = syscall_ret;

	/* Pack start_ve_req before sending */
	psm_msg_len = pseudo_veos_message__get_packed_size(&start_ve_req);
	buf = malloc(psm_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', psm_msg_len);

	if (psm_msg_len != pseudo_veos_message__pack(&start_ve_req, buf)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"start_ve_req pack failed\n");
			retval = -1;
			goto hndl_return1;
	}

	/* Send ACK to Pseudo Process */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor, buf,
							psm_msg_len);
	if (retval < psm_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_load_binary_req(struct veos_thread_arg *pti,
		int ve_core_id,
		int ve_node_id, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ld_binary_req = PSEUDO_VEOS_MESSAGE__INIT;
	struct new_proc_info new_ve_proc;
	void *cmd_buff;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData new_ve_proc_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

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
	cmd_buff = malloc(pseudo_msg_len);
	if (NULL == cmd_buff) {
		retval = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(cmd_buff, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ld_binary_req, cmd_buff)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ld_binary_req pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			cmd_buff, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(cmd_buff);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles START VE request from Pseudo Process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_recv_start_ve_request(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Recevied START VE REQ from"
					"Pseudo with PID : %d\n", pid);

	retval = psm_handle_start_ve_request(pti, pid);
	if (-1 == retval) {
		/* TODO: Need to decide the value to be returned to pseudo */
		psm_pseudo_send_start_ve(pti, pid, -EFAULT);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID : %d not started by PSM", pid);
	} else
		/* Send start VE ack */
		retval = psm_pseudo_send_start_ve(pti, pid, 0);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_fork_ack(struct veos_thread_arg *pti, int child_core_id)
{
	int retval = -1;
	PseudoVeosMessage fork_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Popuate FORK ACK process message */
	fork_ack.has_syscall_retval = true;
	fork_ack.syscall_retval = child_core_id;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending FORK_VE_PROC\n");

	/* Pack fork_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&fork_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fail %s\n", strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&fork_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"fork_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_syscall_ret_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage syscall_ret_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Popuate SET RETURN ACK process return value */
	syscall_ret_ack.has_syscall_retval = true;
	syscall_ret_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&syscall_ret_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&syscall_ret_ack,
				buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"syscall_ret_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SYSCALL RET ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Receives request from pseudo process and updates register value
 * in VE process thread struct.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_set_regval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *ve_set_syscall_reg_req;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	ve_set_syscall_reg_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Set regval 0x%lx for regid  %d PID %d\n",
			ve_set_syscall_reg_req->syscall_retval,
			*(ve_set_syscall_reg_req->pseudo_msg.data),
			ve_set_syscall_reg_req->pseudo_pid);

	/* TODO: Need to remove this */
	if (SR00 == *(ve_set_syscall_reg_req->pseudo_msg.data)) {
		retval = psm_handle_set_syscall_return_req(
				ve_set_syscall_reg_req->pseudo_pid,
				ve_set_syscall_reg_req->syscall_retval);
	} else {
		retval = psm_handle_set_reg_req(
				ve_set_syscall_reg_req->pseudo_pid,
				*(ve_set_syscall_reg_req->pseudo_msg.data),
				ve_set_syscall_reg_req->syscall_retval);
	}

	if (-1 == retval) {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN,
				"Fail to set Reg : %sd by PSM\n",
				ve_set_syscall_reg_req->pseudo_msg.data);
		psm_pseudo_send_syscall_ret_ack(pti, retval);
	} else
		retval = 0;

		/* Send SET REG ACK */
	retval = psm_pseudo_send_syscall_ret_ack(pti, retval);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_set_tidaddr_ack(struct veos_thread_arg *pti,
					int64_t syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_set_tid_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* prepare the response */
	ve_set_tid_ack.has_syscall_retval = true;
	ve_set_tid_ack.syscall_retval = syscall_ret;

	/* Pack ve_set_tid_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_set_tid_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails: %s\n", strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_set_tid_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ve_set_tid_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	/* Send ACK to the pseudo side */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Sending SET_TID_ADDR ACK Packet size: %ld\n",
			pseudo_msg_len);
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles set_tid_address() system call functionality for VE side.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_set_tid_addr_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	uint64_t tid_addr;
	int length;
	int32_t pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&tid_addr,
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.data,
		length);

	retval = psm_handle_set_tid_addr(pid, tid_addr);
	if (-1 == retval) {
		retval = -EFAULT;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"clear_child_tid not set by PSM\n");
		psm_pseudo_send_set_tidaddr_ack(pti, retval);
	} else {
		retval = 0;
		/* SEND SET_TID_ADDR_ACK */
		retval = psm_pseudo_send_set_tidaddr_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_schedule_ack(struct veos_thread_arg *pti,
				int64_t syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_schedule_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* prepare SCHEDULE_ACK response */
	ve_schedule_ack.has_syscall_retval = true;
	ve_schedule_ack.syscall_retval = syscall_ret;

	/* Pack ve_schedule_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_schedule_ack);
	buf = malloc(pseudo_msg_len);

	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails: %s\n", strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_schedule_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ve_schedule_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	/* Send ACK to the pseudo side */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending schedule_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			(void *)buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Changes the state of the VE process from RUNNING to WAITING
 * so that it can be scheduled.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_schedule_req(struct veos_thread_arg *pti)
{
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	retval = psm_handle_schedule_ve_process(((PseudoVeosMessage *)pti->
						pseudo_proc_msg)->pseudo_pid);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN,
				"state of VE process not changed by PSM\n");
		psm_pseudo_send_schedule_ack(pti, retval);
	} else
		/* Send SUCCESS ACK */
		retval = psm_pseudo_send_schedule_ack(pti, retval);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the request of creation of a new VE process.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_exec_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	int core_id = -1;
	int node_id = -1;
	struct new_ve_proc ve_proc;
	struct ve_task_struct *tsk = NULL;
	int length;
	char exe_name[ACCT_COMM+1];

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to recieved message for"
				"command NEW_VE_PROC:%d\n", length);
		goto hndl_return;
	}

	memcpy(&ve_proc,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data, length);

	core_id = ve_proc.core_id;
	strcpy(exe_name, ve_proc.exe_name);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"VE Executable name: %s\n", exe_name);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"PID of the new VE process : %d\n", pid);

	/* Fetch the respective task_struct from the list */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (tsk && tsk->execed_proc) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID %d already exists.\n", pid);
		node_id = tsk->node_id;
		core_id = tsk->core_id;

		/* Create VE process structure at driver server */
		retval = vedl_create_ve_process(VE_NODE(node_id)->handle
				, pid);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_create_ve_process failed.\n");
			goto hndl_return;
		}
	} else if (tsk) {
		/* Perform cleanup of existing VE task */
		psm_handle_delete_ve_process(tsk->pid, 1, 0);
	}

	/* Invoke EXEC VE handler */
	retval = psm_handle_exec_ve_process(pti,
			&core_id, &node_id, pid, exe_name,
			ve_proc.traced_proc, ve_proc.shm_lhm_addr,
			ve_proc.shmid);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID : %d not created by PSM", pid);
		goto hndl_return;
	}

hndl_return:
	retval = psm_pseudo_send_load_binary_req(pti,
			core_id,
			node_id, retval);
	if (retval > 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Successfully sent"
				"Load Binary Req\n");
	else
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending Load Binary"
				"Req failed\n");
	/* Added for debugging to list all the VE process
	 * in PSM at this time
	 * */
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the request of VE process deletion.
 *
 * @param[in] pti Contains the request message received from pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_delete_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_exit_req exit_req;
	int32_t pid;
	ProtobufCBinaryData *pseudo_del_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	pseudo_del_msg = (ProtobufCBinaryData *)(&(((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg));
	memcpy(&exit_req,
			(void *)(pseudo_del_msg->data), pseudo_del_msg->len);


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Delete request for VE process with PID %d\n",
				pid);

	retval = psm_handle_delete_ve_process(pid,
			exit_req.clean_all_thread,
			exit_req.exit_code);

	/* Added for debugging to list all the VE process
	 * in PSM at this time
	 */
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
	/* SEND DELETE ACK */
	retval = psm_pseudo_send_delete_ack(pti, retval, pid);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_delete_ack(struct veos_thread_arg *pti,
		int cleanup_flag, int pid)
{
	int retval = -1;
	PseudoVeosMessage delete_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* prepare DELETE ACK response */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Sending DELETE_ACK for %d\n", pid);
	delete_ack.has_syscall_retval = true;
	delete_ack.syscall_retval = cleanup_flag;

	/* Pack delete_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&delete_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails: %s\n", strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&delete_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"delete_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	/* Send ACK to the pseudo side */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending Delete Ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_clone_ack(struct veos_thread_arg *pti,
		int64_t syscall_ret, struct ve_fork_info *fork_info)
{
	int retval = -1;
	PseudoVeosMessage clone_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData clone_ack_msg;
	void *buf = NULL;
	ssize_t pseudo_msg_len;
	struct ve_proc_info *clone_proc_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti || !fork_info)
		goto hndl_return;

	/* Populate core_id and node_id to be sent to pseudo process */
	clone_proc_info = (struct ve_proc_info *)malloc(
			sizeof(struct ve_proc_info));
	if (NULL == clone_proc_info) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for ve_proc_info failed.\n");
		retval = -1;
		goto hndl_return;
	}
	clone_proc_info->core_id = fork_info->core_id;
	clone_proc_info->node_id = fork_info->node_id;
	clone_proc_info->offset = fork_info->offset;

	/* prepare CLONE ACK response */
	clone_ack.has_syscall_retval = true;
	clone_ack.syscall_retval = syscall_ret;

	clone_ack.has_pseudo_msg = true;
	clone_ack_msg.len = sizeof(struct ve_proc_info);
	clone_ack_msg.data = (uint8_t *)clone_proc_info;
	clone_ack.pseudo_msg = clone_ack_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Sending CLONE_VE_PROC\n");

	/* Pack clone_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&clone_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails: %s\n", strerror(errno));
		retval = -1;
		goto hndl_return1;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&clone_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"clone_ack pack failed\n");
		retval = -1;
		goto hndl_return2;
	}

	/* Send ACK to the pseudo side */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending %ld for %d\n",
			syscall_ret,
			fork_info->child_pid);
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return2:
	free(buf);
hndl_return1:
	free(clone_proc_info);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles clone() request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_clone_ve_proc_req(veos_thread_arg_t *pti)
{
	int retval = -1;
	ProtobufCBinaryData pseudo_clone_msg;
	struct pseudo_ve_clone_info ve_clone_info;
	struct ve_fork_info fork_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pseudo_clone_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)
							->pseudo_msg;
	memcpy(&ve_clone_info, pseudo_clone_msg.data, pseudo_clone_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "CLONE_REQ from %d for %d\n",
			((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid,
			ve_clone_info.child_pid);
	fork_info.parent_pid = ((PseudoVeosMessage *)pti->
			pseudo_proc_msg)->pseudo_pid;
	fork_info.child_pid = ve_clone_info.child_pid;

	fork_info.offset = -1;

	retval = do_ve_fork(ve_clone_info.flags, ve_clone_info.stack_ptr, 0,
				(int *)ve_clone_info.ptid,
				(int *)ve_clone_info.ctid, &fork_info);
	if (-1 == retval) {
		retval = psm_pseudo_send_clone_ack(pti, retval, &fork_info);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID %u not created by PSM\n",
				ve_clone_info.child_pid);
	} else
		/* SEND CLONE ACK */
		retval = psm_pseudo_send_clone_ack(pti,
				retval, &fork_info);

	/* TODO : retval for psm_pseudo_send_clone_ack has not been handled.
	 *	Need to decide which retval is to be returned : either retval
	 *	of psm_pseudo_send_clone_ack is to be returned or retval of
	 *	do_ve_fork is to be returned.
	 */
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles fork() request from pseudo process.
 *
 * @param[in] pti Contains the request message received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_fork_ve_proc_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct pseudo_ve_clone_info ve_fork_info;
	struct ve_fork_info fork_info;
	ProtobufCBinaryData pseudo_fork_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pseudo_fork_msg = ((PseudoVeosMessage *)pti->
			pseudo_proc_msg)->pseudo_msg;
	memcpy(&ve_fork_info, pseudo_fork_msg.data, pseudo_fork_msg.len);

	fork_info.parent_pid =
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	fork_info.child_pid = ve_fork_info.child_pid;
	fork_info.shm_lhm_addr = ve_fork_info.shm_lhm_addr;
	fork_info.shmid = ve_fork_info.shmid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Received FORK request from PARENT : %d"
			" for CHILD : %d\n",
			fork_info.parent_pid,
			fork_info.child_pid);

	/* Invoke fork handler */
	retval = do_ve_fork(ve_fork_info.flags, ve_fork_info.stack_ptr, 0,
				(int *)ve_fork_info.ptid,
				(int *)ve_fork_info.ctid, &fork_info);

	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID %d not created by PSM\n",
				fork_info.child_pid);
		psm_pseudo_send_fork_ack(pti, retval);
	} else {
		/*SEND FORK ACK*/
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PID %d created by PSM\n",
				fork_info.child_pid);
		retval = psm_pseudo_send_fork_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sends ACK for BLOCK request from Pseudo Process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_send_block_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage block_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/*Populating BLOCK ACK*/
	block_ack.has_syscall_retval = true;
	block_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&block_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&block_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"block_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending BLOCK ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sends acknowledgment for UNLOCK request received from Pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_send_un_block_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage unblock_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Popuate UNBLOCK ACK message */
	unblock_ack.has_syscall_retval = true;
	unblock_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&unblock_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&unblock_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"unblock_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending UNBLOCK ACK");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Changes the state of the VE process from WAITING to RUNNING
 * so that it can be scheduled.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_block_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t ve_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	retval = psm_handle_block_request(ve_pid);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN,
				"state of VE process not changed by PSM\n");
		/*TODO:
		 * Add acknowledgment message for block request failure
		 *                                   */
		psm_pseudo_send_block_ack(pti, retval);
	} else
		/* Send BLOCK_ACK */
		retval = psm_pseudo_send_block_ack(pti, retval);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Changes the state of the VE process from RUNNING to WAITING
 * so that it can be scheduled.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_un_block_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t ve_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;
	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	retval = psm_handle_un_block_request(ve_pid);

	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN,
				"state of VE process not changed by PSM\n");
		/*TODO:
		 * Add acknowledgment message for un-block request failure
		 */
		psm_pseudo_send_un_block_ack(pti, retval);
	} else
		/* Send UNBLOCK ACK */
		retval = psm_pseudo_send_un_block_ack(pti, retval);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the CORE HALT request from pseudo process.
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 *
 * @return On failure, returns -1 and on success, returns a positive value
 */
int psm_handle_halt_core_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	PseudoVeosMessage *halt_core_req = NULL;
	ProtobufCBinaryData pseudo_halt_msg;
	struct ve_task_struct *tsk = NULL;
	struct halt_ve_cores_info ve_core_info = {0};

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	halt_core_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pseudo_halt_msg = halt_core_req->pseudo_msg;

	memcpy(&ve_core_info.flag, pseudo_halt_msg.data,
			pseudo_halt_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "flag : %d, pid : %d\n",
			ve_core_info.flag, halt_core_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, halt_core_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_halt_core_req failed\n");
		retval = -1;
		goto send_ack;
	}

	if (1 == ve_core_info.flag) {
		ve_core_info.start_core_id = tsk->core_id;
		ve_core_info.stop_core_id = tsk->core_id;
	} else {
		ve_core_info.start_core_id = 0;
		ve_core_info.stop_core_id = MAX_VE_CORE_PER_VE_NODE - 1;
	}

	ve_core_info.task = tsk;
	ve_core_info.pid = halt_core_req->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"start_core_id :%d stop_core_id :%d\n",
			ve_core_info.start_core_id,
			ve_core_info.stop_core_id);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "pid : %d and flags : %d\n",
			ve_core_info.pid,
			ve_core_info.flag);

	retval = psm_handle_halt_core_request(&ve_core_info);

send_ack:
	if (0 == retval) {
		psm_pseudo_core_halted_ack(pti, retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to halt core\n");
		psm_pseudo_core_halted_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends acknowlegdment for the CORE HALT
* request received from pseudo process.
*
* @param[in] pti contains the request received from the pseudo process
* @param[in] syscall_ret contains return value of halt_core_request
*
* @return On failure, returns -1 and on success, returns a positive value
*/
int psm_pseudo_core_halted_ack(struct veos_thread_arg *pti, int64_t syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage core_halt_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	core_halt_ack.has_syscall_retval = true;
	core_halt_ack.syscall_retval = syscall_ret;

	/* Pack core_halt_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&core_halt_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);
	if (pseudo_msg_len != pseudo_veos_message__pack(&core_halt_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"core_halt_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief psm_handle_start_core_req: Handles the START CORE request from pseudo process.
*
* @param[in] pti contains the request received from the pseudo process
*
* @return On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_start_core_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	PseudoVeosMessage *start_core_req = NULL;
	ProtobufCBinaryData pseudo_start_core_msg;
	struct halt_ve_cores_info ve_core_info = {0};
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	start_core_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pseudo_start_core_msg = start_core_req->pseudo_msg;

	memcpy(&ve_core_info.flag, pseudo_start_core_msg.data,
			pseudo_start_core_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "flag : %d, pid : %d\n",
			ve_core_info.flag, start_core_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, start_core_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_start_core_req failed\n");
		retval = -1;
		goto send_ack;
	}

	if (1 == ve_core_info.flag) {
		ve_core_info.start_core_id = tsk->core_id;
		ve_core_info.stop_core_id = tsk->core_id;
	} else {
		ve_core_info.start_core_id = 0;
		ve_core_info.stop_core_id = MAX_VE_CORE_PER_VE_NODE - 1;
	}

	ve_core_info.task = tsk;
	ve_core_info.pid = start_core_req->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"start_core_id :%d stop_core_id :%d\n",
			ve_core_info.start_core_id,
			ve_core_info.stop_core_id);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "pid : %d and flags : %d\n",
			ve_core_info.pid,
			ve_core_info.flag);

	retval = psm_handle_start_core_request(&ve_core_info);

send_ack:
	if (0 == retval) {
		psm_pseudo_core_started_ack(pti, retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to start core\n");
		psm_pseudo_core_started_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends acknowlegdment for START CORE
*               request received from pseudo process.
*
* @param[in] pti contains the request received from the pseudo process
* @param[in] syscall_ret contains return value of halt_core_request
*
* @return On failure, returns -1 and on success, returns a positive value
*/
int psm_pseudo_core_started_ack(struct veos_thread_arg *pti,
		int64_t syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage core_started_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	core_started_ack.has_syscall_retval = true;
	core_started_ack.syscall_retval = syscall_ret;

	/* Pack core_started_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(
			&core_started_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				core_started_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"core_started_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	/* Send ACK to the pseudo side */
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_pseudo_send_sigreturn_ack(struct veos_thread_arg *pti, int syscall_ret)
{
	int retval = -1;
	PseudoVeosMessage sigreturn_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *cmd_buff;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Populating Retval value to be send to Pseudo process */
	sigreturn_ack.has_syscall_retval = true;
	sigreturn_ack.syscall_retval = syscall_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigreturn_ack);
	cmd_buff = malloc(pseudo_msg_len);
	if (NULL == cmd_buff) {
		retval = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(cmd_buff, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				sigreturn_ack, cmd_buff)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigreturn_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending sigreturn_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			cmd_buff, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(cmd_buff);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_pseudo_send_sigaction_ack(struct sigaction *old_act,
		struct veos_thread_arg *pti,
		int syscall_ret)
{
	int retval = -1;
	void *cmd_buff;
	ssize_t pseudo_msg_len;

	PseudoVeosMessage sigaction_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData sigaction_ack_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Populating Retval value to be send to Pseudo process */
	sigaction_ack.has_syscall_retval = true;
	sigaction_ack.syscall_retval = syscall_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	sigaction_ack.has_pseudo_msg = true;
	sigaction_ack_msg.len = sizeof(struct sigaction);
	sigaction_ack_msg.data = (uint8_t *)old_act;
	sigaction_ack.pseudo_msg = sigaction_ack_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigaction_ack);

	cmd_buff = malloc(pseudo_msg_len);
	if (NULL == cmd_buff) {
		retval = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(cmd_buff, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				sigaction_ack, cmd_buff)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigaction_ack pack failed\n");
		goto hndl_return1;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending sigaction_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			cmd_buff, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(cmd_buff);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles the "VE SIGNAL REQ" from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* the pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_signal_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_signal_info signal_info = {0};
	struct ve_task_struct *ve_task_curr = NULL;
	int length = -1;
	pid_t pid = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		retval = -EFAULT;
		goto signal_error;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Signal handler Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg)
		.len;
	if (length <= 0) {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to received message"
				"for command SIGNAL_REQ %d\n", length);
		goto signal_error;
	}
	memcpy((char *)&signal_info,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL != ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Recevied SIGNAL %d from Pseudo with pid :%d\n",
				signal_info.signum, pid);
		/* Check whether a synchronous fatal signal is pending
		 * */
		retval = psm_check_sync_signal_pending(ve_task_curr,
				signal_info.signum);
		if (0 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Signal %d will be served\n",
					signal_info.signum);
			psm_send_ve_signal(ve_task_curr,
					&(signal_info.ve_siginfo),
					signal_info.signum, 0);
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Synchronous fatal signal is pending"
					" Signal will not be served\n");
		}
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n", pid);
		retval = -1;
	}

signal_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Acknowledgment for getpriority request received from pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] priority Priority read from ve_task struct
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_send_getpriority_ack(struct veos_thread_arg *pti,
		int priority, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	ve_getprio_req.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&priority;
	veos_info.len = sizeof(priority);
	ve_getprio_req.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET_PRIO_REQ pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending GET_PRIO_REQ ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends acknowledgment for getscheduler request received
* from pseudo process.
*
* @param[in] pti Descriptor used to communication with pseudo process
* @param[in] policy policy read from ve_stak_struct
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return positive value on success, -1 on failure.
*/
int psm_pseudo_send_getscheduler_ack(struct veos_thread_arg *pti,
		int policy, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	/* Populating pseudo_msg */
	ve_getprio_req.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&policy;
	veos_info.len = sizeof(policy);
	ve_getprio_req.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
	ve_getprio_req);

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET_SCHED_REQ pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending GET_SCHED_REQ\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief  Sends acknowledgment for setscheduler request received
* from pseudo process.
*
* @param[in] pti Descriptor used to communication with pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return positive value on success, -1 on failure.
*/
int psm_pseudo_send_setscheduler_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET_SCHED_REQ pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET_SCHED_REQ\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sends acknowledgment for sched_getparam request received
 * from pseudo process.
 *
 * @param[in] pti Descriptor used to communication with pseudo process
 * @param[in] rt_priority Realtime priority read from ve_task_struct
 * @param[in] ack_ret Acknowledgment to be send to pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_send_sched_getparam_ack(struct veos_thread_arg *pti,
		int rt_priority, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&rt_priority;
	veos_info.len = sizeof(rt_priority);
	ve_getprio_req.pseudo_msg = veos_info;

	/* Populating pseudo_msg to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET_PARAM_REQ pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending GET PARAM REQ ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends acknowledgment for sched_setparam request received
* from pseudo process.
*
* @param[in] pti Descriptor used to communication with pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return positive value on success, -1 on failure.
*/
int psm_pseudo_send_sched_setparam_ack(struct veos_thread_arg *pti,
		int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET PARAM REQ  pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET PARAM REQ\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_get_cpu_ack(struct veos_thread_arg *pti,
		int ack_ret, struct ve_cpu_info *cpu_info)
{
	int retval = -1;
	PseudoVeosMessage ve_getproc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populating Retval value to be send to Pseudo process */
	ve_getproc_req.has_syscall_retval = true;
	ve_getproc_req.syscall_retval = ack_ret;

	/* Populating pseudo_msg to be send to Pseudo process */
	if (cpu_info != NULL) {
		ve_getproc_req.has_pseudo_msg = true;
		veos_info.data = (uint8_t *)&cpu_info;
		veos_info.len =  sizeof(struct ve_cpu_info);
		ve_getproc_req.pseudo_msg = veos_info;
	}

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getproc_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_getproc_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"get_cpu pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending get cpu ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_get_interval_ack(struct veos_thread_arg *pti,
		int ack_ret, struct timespec *tp)
{
	int retval = -1;
	PseudoVeosMessage ve_getproc_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

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
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);
	if ( pseudo_msg_len != pseudo_veos_message__pack(
				&ve_getproc_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET_SCHED_INTRVL pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending GET_INR_REQ\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles the SIGRETURN REQ request from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_sigreturn_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"IN PSM SIGRETURN HANDLER %d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RESTORING VE PROCESS CONTEXT\n");
		retval = psm_restore_ve_context(ve_task_curr);
		psm_pseudo_send_sigreturn_ack(pti, retval);
	} else {
		retval = -1;
		psm_pseudo_send_sigreturn_ack(pti, retval);
	}
ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
* @brief Handles the "SIGACTION REQ" request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process.
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_sigaction_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	int length = -1;
	struct ve_sigaction_info sigaction_info = {0};
	struct ve_task_struct *ve_task_curr = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto signal_error;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm sigaction handler\n"
			"\t\tRecevied sigaction request from "
			"Pseudo with pid :%d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to received message for"
				"command SIGACTION_REQ %d\n", length);
		goto signal_error;
	}

	memcpy((char *)&sigaction_info,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		psm_do_sigaction_ve(ve_task_curr, &sigaction_info);
		psm_pseudo_send_sigaction_ack(
				&(sigaction_info.old_ve_sigaction),
				pti,
				0);
	} else
		psm_pseudo_send_sigaction_ack(&
				(sigaction_info.old_ve_sigaction),
				pti,
				-1);
signal_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_pseudo_send_sigsuspend_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_sigsuspend_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	size_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				" NULL argument received\n");
		goto handle_error;
	}

	/* Populating Retval value to be send to Pseudo process */
	ve_sigsuspend_ack.has_syscall_retval = true;
	ve_sigsuspend_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_sigsuspend_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n",
				strerror(errno));
		goto handle_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_sigsuspend_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sigsuspend ack packing failed\n");
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Sending SIGSUSPEND_REQ acknowledgment\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
handle_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles the "SIGSUSPEND_REQ" request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process.
*
* @return: On failure, returns -1 or -errno and on success, returns 0
*/
int psm_handle_sigsuspend_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	sigset_t mask_set;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		retval = -1;
		goto hndl_return;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Recevied sigsuspend request from "
			"Pseudo with pid :%d\n", pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task not found. sigsuspend_req  failed\n");
		retval = -ESRCH;
		goto send_ack;
	}

	memcpy(&mask_set, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			((PseudoVeosMessage *)pti->
			 pseudo_proc_msg)->pseudo_msg.len);
	psm_do_sigsuspend(tsk, &mask_set);
	retval = 0;
send_ack:
	if (0 == retval) {
		psm_pseudo_send_sigsuspend_ack(pti, retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to serve sigsuspend req\n");
		psm_pseudo_send_sigsuspend_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_setnew_sas_ack(struct veos_thread_arg *pti,
		struct ve_sigalt_info *sigalt_ack)
{
	int retval = -1;
	PseudoVeosMessage new_sas_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti || !sigalt_ack) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto hndl_return;
	}

	/* Populating Retval for sending to pseudo process */
	new_sas_ack.has_syscall_retval = true;
	if (sigalt_ack->retval)
		new_sas_ack.syscall_retval = -1;
	else
		new_sas_ack.syscall_retval = 0;

	/* Populating pseudo_msg for sending to pseudo process */
	new_sas_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)sigalt_ack;
	veos_info.len = sizeof(struct ve_sigalt_info);
	new_sas_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&new_sas_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&new_sas_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET NEW SAS pack failed\n");
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET NEW SAS ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles SET NEW SAS request from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
*	pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_setnew_sas_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_sigalt_info sigalt_req = {0};
	struct ve_sigalt_info sigalt_ack = {0};

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	memcpy(&sigalt_req, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			((PseudoVeosMessage *)pti->pseudo_proc_msg)->
			pseudo_msg.len);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		if (sigalt_req.old_sas_flag) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Getting OLD_SAS\n");
			psm_getold_sas(ve_task_curr, &(sigalt_ack.old_sas));
		}

		if (sigalt_req.new_sas_flag) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Setting NEW SAS\n");
			sigalt_ack.retval = psm_setnew_sas(ve_task_curr,
					&(sigalt_req.new_sas));
		}

		psm_setnew_sas_ack(pti, &sigalt_ack);
	} else {
		sigalt_ack.retval = -1;
		psm_setnew_sas_ack(pti, &sigalt_ack);
		retval = -1;
	}

ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Out Func\n");
	return retval;
}

/**
* @brief Acknowledgment for "SIGPROCMASK REQ" request from pseudo process.
*
* @param[in] oldset Stores old signal mask
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value.
*/
int psm_pseudo_send_sigprocmask_ack(sigset_t *oldset,
		struct veos_thread_arg *pti,
		int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_sigprocmask_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti || !oldset) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"OLDSET : %ld\n", oldset->__val[0]);

	/* Populating Retval for sending to pseudo process */
	ve_sigprocmask_ack.has_syscall_retval = true;
	ve_sigprocmask_ack.syscall_retval = ack_ret;

	/* Populating pseudo_msg for sending to pseudo process */
	ve_sigprocmask_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)oldset;
	veos_info.len = sizeof(sigset_t);
	ve_sigprocmask_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_sigprocmask_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_sigprocmask_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigprocmask_ack pack failed\n");
		goto ret;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending sigprocmask_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

ret:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles "SIGPROCMASK REQ" from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
*	pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value.
*/
int psm_handle_sigprocmask_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	sigset_t newset, oldset;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm sigprocmask handler\n"
			"\t\tRecevied sigprocmask request from "
			"Pseudo with pid :%d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		memcpy(&newset, ((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.data,
				((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.len);

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"New signal mask : %ld\n",
				newset.__val[0]);

		sigemptyset(&oldset);
		/* Set new signal mask and fetch old signal mask
		 * */
		psm_do_sigprocmask(ve_task_curr, &newset, &oldset);

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"OLDSET : %ld\n", oldset.__val[0]);
		retval = 0;
		psm_pseudo_send_sigprocmask_ack(&oldset,
				pti,
				retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigpromask fail for pid %d\n", pid);
		psm_pseudo_send_sigprocmask_ack(&oldset,
				pti,
				retval);
	}

ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handle "HANDLE EXCEPTION" request from pseudo process.
*
* @param[in] pti Pointer to structure containing the request received from
*	pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value.
*/
int psm_handle_exception_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	siginfo_t ve_siginfo;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Received handle exception request from "
			"Pseudo with pid :%d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		memcpy(&ve_siginfo, ((PseudoVeosMessage *)pti->
					pseudo_proc_msg)->pseudo_msg.data,
				((PseudoVeosMessage *)pti->pseudo_proc_msg)->
				pseudo_msg.len);

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Handle exception mapped to signal %d\n",
				ve_siginfo.si_signo);

		psm_handle_hw_exception(ve_task_curr,
				&ve_siginfo,
				ve_siginfo.si_signo);
		retval = 0;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"handle exception fail for pid %d\n", pid);
		retval = -1;
	}

ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the get priority max request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_get_priority_max_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int prior_max = VE_PROC_PRIORITY_MAX;
	PseudoVeosMessage prior_max_ack = PSEUDO_VEOS_MESSAGE__INIT;
	pid_t ve_pid;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	ProtobufCBinaryData veos_info;

	if (!pti)
		goto hndl_return;

	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"IN PSM GET_PRIORITY_MAX HANDLER %d\n",
			ve_pid);

	/* Populating Retval for sending to pseudo process */
	prior_max_ack.has_syscall_retval = true;
	prior_max_ack.has_syscall_retval = 0;

	/* Populating pseudo_msg for sending to pseudo process */
	prior_max_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&prior_max;
	veos_info.len = sizeof(prior_max);
	prior_max_ack.pseudo_msg = veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending ..%d\n",
			prior_max_ack.has_syscall_retval);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&prior_max_ack);

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				prior_max_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"prior_max_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the get priority min request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_get_priority_min_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int prior_min = VE_PROC_PRIORITY_MIN;
	PseudoVeosMessage prior_min_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	pid_t ve_pid;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;


	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"IN PSM GET_PRIORITY_MIN HANDLER %d\n",
			ve_pid);

	/* Populating Retval for sending to pseudo process */
	prior_min_ack.has_syscall_retval = true;
	prior_min_ack.has_syscall_retval = 0;

	/* Populating Retval for sending to pseudo process */
	prior_min_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&prior_min;
	veos_info.len = sizeof(int);
	prior_min_ack.pseudo_msg = veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending ..%d\n",
			prior_min_ack.has_syscall_retval);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&prior_min_ack);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				prior_min_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"prior_min_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the getpriority request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_getpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int priority = -1;
	int pid;
	pid_t ve_pid;
	struct ve_task_struct *ve_task_curr = NULL;
	int length;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm getpriority handler\n"
			"\t\tRecevied getpriority request from "
			"Pseudo with pid :%d\n", pid);
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&ve_pid, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);
	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, ve_pid);
	if (NULL != ve_task_curr) {
		priority = ve_task_curr->priority;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"priority get from veos %d\n", priority);
		retval = 0;
		retval = psm_pseudo_send_getpriority_ack(pti,
				priority, retval);
	} else {
		retval = -1;
		psm_pseudo_send_getpriority_ack(pti, priority, retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n", ve_pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends acknowledgment for setpriority request received
* from pseudo process.
*
* @param[in] pti Descriptor used to communication with pseudo process
* @param[in] ack_ret Acknowledgment to be send to pseudo process
*
* @return positive value on success, -1 on failure.
*/
int psm_pseudo_send_setpriority_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_getprio_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populating Retval for sending to pseudo process */
	ve_getprio_req.has_syscall_retval = true;
	ve_getprio_req.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_getprio_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_getprio_req, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"setpriority_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET PRIO REQ ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the setpriority min request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_setpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_prio_info prio_info = {0};
	int pid;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm setpriority handler\n"
			"\t\tRecevied setpriority request from "
			"Pseudo with pid :%d\n", pid);
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&prio_info, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, prio_info.pid);

	if (NULL != ve_task_curr) {
		retval = 0;
		pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
		ve_task_curr->priority = prio_info.prio;
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		retval = psm_pseudo_send_setpriority_ack(pti, retval);
	} else {
		retval = -1;
		psm_pseudo_send_setpriority_ack(pti, retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				prio_info.pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the get schedular request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_getscheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int policy = -1;
	int pid;
	pid_t ve_pid;
	struct ve_task_struct *ve_task_curr = NULL;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm getscheduler handler\n"
			"\t\tRecevied getscheduler request from "
			"Pseudo with pid :%d\n", pid);
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&ve_pid, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, ve_pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		policy = ve_task_curr->policy;
		retval = psm_pseudo_send_getscheduler_ack(pti,
				policy, retval);
	} else {
		retval = -1;
		psm_pseudo_send_getscheduler_ack(pti, policy, retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				ve_pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the get setscheduler request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_setscheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_sched_info sched_info = {0};
	int pid;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"In psm sched_setscheduler handler\n"
			"\t\tRecevied sched_setscheduler request from "
			"Pseudo with pid :%d\n", pid);
	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&sched_info, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, sched_info.pid);

	if (NULL != ve_task_curr) {
		retval = 0;
		pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
		ve_task_curr->priority = sched_info.prio;
		ve_task_curr->policy = sched_info.policy;
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		retval = psm_pseudo_send_setscheduler_ack(pti, retval);
	} else {
		psm_pseudo_send_setscheduler_ack(pti, retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				sched_info.pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the sched_get_param request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_sched_getparam_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_sched_info sched_info = {0};
	int pid;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm getparam handler\n"
			"\t\tRecevied getparam request from "
			"Pseudo with pid :%d\n", pid);

	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&sched_info, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, sched_info.pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		sched_info.prio = ve_task_curr->rt_priority;
		retval = psm_pseudo_send_sched_getparam_ack(pti,
				sched_info.prio,
				retval);
	} else {
		retval = -1;
		psm_pseudo_send_sched_getparam_ack(pti, sched_info.prio,
				retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				sched_info.pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the sched_setparam request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_sched_setparam_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_sched_info sched_info = {0};
	int pid;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm setparam handler\n"
			"\t\tRecevied setparam request from "
			"Pseudo with pid :%d\n", pid);

	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&sched_info, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, sched_info.pid);

	if (NULL != ve_task_curr) {
		retval = 0;
		pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
		ve_task_curr->rt_priority = sched_info.prio;
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		retval = psm_pseudo_send_sched_setparam_ack(pti,
				retval);
	} else {
		retval = -1;
		psm_pseudo_send_sched_setparam_ack(pti, retval);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				sched_info.pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_pseudo_send_sigpending_ack(sigset_t *veos_set,
		struct veos_thread_arg *pti,
		int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage ve_sigpending_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData veos_info;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti || !veos_set) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"VEOS_SET : %ld\n", veos_set->__val[0]);

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

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_sigpending_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigpending_ack pack failed\n");
		goto ret;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending sigpending_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

ret:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handle "SIGPENDING REQ" request from pseudo process
*
* @param[in] pti Pointer to structure containing the request received from
* pseudo process
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
int psm_handle_sigpending_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	sigset_t veos_set;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		goto ret;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm sigpending handler\n"
			"\t\tRecevied sigpending request from "
			"Pseudo with pid :%d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);

	if (NULL != ve_task_curr) {
		retval = 0;
		sigemptyset(&veos_set);
		psm_do_sigpending(ve_task_curr, &veos_set);

		psm_pseudo_send_sigpending_ack(&veos_set,
				pti,
				retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sigpending fail for pid %d\n", pid);
		psm_pseudo_send_sigpending_ack(&veos_set,
				pti,
				retval);
	}

ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the CLOCK CPUTIME request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_clk_cputime_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *clk_cputime_req;
	struct ve_task_struct *tsk = NULL;
	struct timespec tp;
	int type;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	clk_cputime_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	memcpy(&type, (clk_cputime_req->pseudo_msg.data),
			clk_cputime_req->pseudo_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Type : %d, pid : %d\n",
			type, clk_cputime_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, clk_cputime_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_clk_cputime_req failed\n");
		retval = -1;
		goto send_ack;
	}

	retval = psm_handle_clk_cputime_request(tsk, type, &tp);

send_ack:
	if (0 == retval) {
		psm_pseudo_clk_cputime_ack(pti, retval, tp);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to get clock cputime\n");
		psm_pseudo_clk_cputime_ack(pti, retval, tp);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int psm_pseudo_clk_cputime_ack(struct veos_thread_arg *pti,
		int ack_ret, struct timespec tp)
{
	int retval = -1;
	PseudoVeosMessage clk_cputime_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ProtobufCBinaryData veos_info;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Populating Retval for sending to pseudo process */
	clk_cputime_ack.has_syscall_retval = true;
	clk_cputime_ack.syscall_retval = ack_ret;

	/* Populating pseudo_msg for sending to pseudo process */
	clk_cputime_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&tp;
	veos_info.len = sizeof(struct timespec);
	clk_cputime_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&clk_cputime_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&clk_cputime_ack,
				buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"clk_cputime_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending clk_cputime_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the getcpu request from pseudo process
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_getcpu_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_cpu_info cpu_info = {0};
	int pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm getcpu handler\n"
			"\t\tRecevied getcpu request from "
			"Pseudo with pid :%d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		cpu_info.cpu = ve_task_curr->core_id;
		cpu_info.node = ve_task_curr->node_id;
		retval = psm_pseudo_send_get_cpu_ack(pti,
				retval, &cpu_info);
	} else {
		retval = -1;
		psm_pseudo_send_get_cpu_ack(pti, retval, NULL);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief Handles the get interval request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_get_interval_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *ve_task_curr = NULL;
	struct timespec tp;
	pid_t  pid;
	pid_t ve_pid;
	int length;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm get interval handler\n"
			"\t\tRecevied get interval request from "
			"Pseudo with pid :%d\n", pid);

	length = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg.len;
	memcpy(&ve_pid, ((PseudoVeosMessage *)pti->
				pseudo_proc_msg)->pseudo_msg.data,
			length);
	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, ve_pid);
	if (NULL != ve_task_curr) {
		retval = 0;
		tp.tv_sec = PSM_TIMER_INTERVAL_SECS;
		tp.tv_nsec = PSM_TIMER_INTERVAL_NSECS;
		retval = psm_pseudo_send_get_interval_ack(pti,
				retval, &tp);
	} else {
		retval = -1;
		psm_pseudo_send_get_interval_ack(pti, retval, NULL);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				ve_pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the GET RLIMIT request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_get_rlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rlimit_req;
	struct ve_task_struct *tsk = NULL;
	struct rlimit rlim;
	int resource;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	rlimit_req = (PseudoVeosMessage  *)pti->
		pseudo_proc_msg;

	memcpy(&resource, rlimit_req->pseudo_msg.data,
			rlimit_req->pseudo_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Resource : %d, pid : %d\n",
			resource, rlimit_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, rlimit_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_get_rlimit_req failed\n");
		retval = -1;
		goto send_ack;
	}

	retval = psm_handle_get_rlimit_request(tsk, resource, &rlim);

send_ack:
	if (0 == retval) {
		psm_pseudo_get_rlimit_ack(pti, retval, rlim);
	} else {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to get rlimit\n");
		psm_pseudo_get_rlimit_ack(pti, retval, rlim);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
	int retval = -1;
	PseudoVeosMessage rlimit_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	rlimit_ack.has_syscall_retval = true;
	rlimit_ack.syscall_retval = ack_ret;

	rlimit_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&rlim;
	veos_info.len =  sizeof(struct rlimit);
	rlimit_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rlimit_ack);

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&rlimit_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET RLIMIT ACK  pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending GET RLIMIT ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Handles the SET RLIMIT request from pseudo process.
*
* @param[in] pti Contains the request received from the pseudo process
*
* @return 0 on success, -1 or -2 on failure.
*/
int psm_handle_set_rlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rlimit_req;
	struct ve_task_struct *tsk = NULL;
	struct rlimit rlim;
	struct rlimit_info *rlimit_msg;
	int resource;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	rlimit_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;
	rlimit_msg = (struct rlimit_info *)(rlimit_req->pseudo_msg.data);

	memcpy(&resource, &(rlimit_msg->resource),
			sizeof(resource));
	memcpy(&rlim, &(rlimit_msg->rlim),
			sizeof(rlim));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Resource : %d, pid : %d\n",
			resource, rlimit_req->pseudo_pid);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"rlim_cur: %ld rlim_max: %ld\n",
			rlim.rlim_cur, rlim.rlim_max);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, rlimit_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_set_rlimit_req failed\n");
		retval = -1;
		goto send_ack;
	}

	retval = psm_handle_set_rlimit_request(tsk, resource, rlim);

send_ack:
	if (0 == retval) {
		psm_pseudo_set_rlimit_ack(pti, retval);
	} else if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to set rlimit\n");
		psm_pseudo_set_rlimit_ack(pti, retval);
	} else if (-2 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Pseudo don't have permission\n");
		psm_pseudo_set_rlimit_ack(pti, retval);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_set_rlimit_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage rlimit_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	rlimit_ack.has_syscall_retval = true;
	rlimit_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rlimit_ack);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails:%s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);
	if (pseudo_msg_len != pseudo_veos_message__pack(&rlimit_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET RLIMIT ACK pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET RLIMIT ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sends acknowlegdment for GET AFFINITY request received
 * from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 * @param[in] ack_ret Return value send to VE process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_send_getaffinity_ack(struct veos_thread_arg *pti,
		int64_t ack_ret)
{
	int ret = -1;
	PseudoVeosMessage getaffinity_resp = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Use retval field to send CPU affinity value */
	getaffinity_resp.has_syscall_retval = true;
	getaffinity_resp.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			getaffinity_resp);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails:%s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				getaffinity_resp, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"getaffinity pack failed\n");
		ret = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending  GET AFFINITY ACK\n");
	ret = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				ret);
		ret = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}
/**
 * @brief Handles the GET AFFINITY request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 or -2 on failure.
 */
int psm_handle_getaffinity_req(struct veos_thread_arg *pti)
{
	uint64_t retval = -1;
	PseudoVeosMessage *getaffinity_req;
	int pid = -1;
	ssize_t cpusetsize;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Received GET AFFINITY from"
			"Pseudo with PID : %d\n", pid);

	getaffinity_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	memcpy(&cpusetsize, getaffinity_req->pseudo_msg.data,
			getaffinity_req->pseudo_msg.len);

	retval = psm_handle_getaffinity_request(pid, cpusetsize);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"PID : %d GET AFFINITY return: %ld",
			pid, retval);
	/* Send ACK */
	psm_pseudo_send_getaffinity_ack(pti, retval);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the SET AFFINITY request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 or -2 on failure.
 */
int psm_handle_setaffinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *setaffinity_req;
	int pid = -1;
	uint64_t mask;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Received SET AFFINITY from"
			"Pseudo with PID : %d\n", pid);

	setaffinity_req = (PseudoVeosMessage *)pti->
					pseudo_proc_msg;

	memcpy(&mask, setaffinity_req->pseudo_msg.data,
			setaffinity_req->pseudo_msg.len);

	retval = psm_handle_setaffinity_request(pid, mask);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"PID : %d SET AFFINITY returns %d",
			pid, retval);
	/* Send ACK */
	psm_pseudo_send_setaffinity_ack(pti, retval);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_setaffinity_ack(struct veos_thread_arg *pti,
		int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage setaffinity_resp = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Use retval field to send CPU affinity value */
	setaffinity_resp.has_syscall_retval = true;
	setaffinity_resp.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(
			&setaffinity_resp);

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails:%s\n",
				strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				setaffinity_resp, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET AFFINITY pack failed\n");
		retval = -1;
		goto hndl_return1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SET AFFINITY ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the SCHED YIELD request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_sched_yield_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Received SET AFFINITY req from"
			" Pseudo process with PID : %d\n", pid);

	retval = psm_handle_sched_yield_request(pid);
	if (-1 == retval)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID : %d SCHED YIELD FAIL", pid);
	else
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID : %d SCHED YIELD SUCCESS", pid);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the GET RUSAGE request from pseudo process.
 *
 * @param[in] pti Contains the request received from the pseudo process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_get_rusage_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *rusage_req;
	struct ve_task_struct *tsk = NULL;
	struct ve_rusage ve_r;
	int who;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	rusage_req = (PseudoVeosMessage *)pti->
					pseudo_proc_msg;

	memcpy(&who, rusage_req->pseudo_msg.data,
			rusage_req->pseudo_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Who : %d, pid : %d\n",
			who, rusage_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, rusage_req->pseudo_pid);

	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_get_rusage_req failed\n");
		retval = -1;
		goto send_ack;
	}

	retval = psm_handle_get_rusage_request(tsk, who, &ve_r);

send_ack:
	if (0 == retval) {
		psm_pseudo_get_rusage_ack(pti, retval, ve_r);
	} else {
		retval = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to get rusage\n");
		psm_pseudo_get_rusage_ack(pti, retval, ve_r);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_get_rusage_ack(struct veos_thread_arg *pti,
		int ack_ret, struct ve_rusage ve_r)
{
	int retval = -1;
	PseudoVeosMessage rusage_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* Populate acknowledgment message */
	rusage_ack.has_syscall_retval = true;
	rusage_ack.syscall_retval = ack_ret;

	rusage_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)&ve_r;
	veos_info.len = sizeof(struct ve_rusage);
	rusage_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&rusage_ack);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto hndl_return;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&rusage_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"get_rusage_ack pack failed\n");
		retval = -1;
		goto hndl_return1;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending get_rusage_ack\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the PR SET MM request from pseudo process.
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return positive value on success, -1 on failure.
 */
int psm_handle_pr_set_mm_req(struct veos_thread_arg *pti)
{
	int retval = 0;
	PseudoVeosMessage *pr_req;
	struct prlimit_mm pr_mm;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pr_req = (PseudoVeosMessage *)pti->
		pseudo_proc_msg;

	memcpy(&pr_mm, pr_req->pseudo_msg.data,
			pr_req->pseudo_msg.len);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Option: %lu value: %lu, pid : %d\n",
			pr_mm.option, pr_mm.value, pr_req->pseudo_pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pr_req->pseudo_pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "PID: %d not found\n",
				pr_req->pseudo_pid);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_pr_set_mm_req failed\n");
		retval = -1;
		goto send_ack;
	}

	retval = psm_handle_pr_set_mm_request(tsk, pr_mm.option, pr_mm.value);

send_ack:
	if (0 == retval) {
		psm_pseudo_pr_set_mm_ack(pti, retval);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM failed to set prctl memory map\n");
		psm_pseudo_pr_set_mm_ack(pti, retval);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sends acknowlegdment for PR SET MM request received
 * from pseudo process.
 *
 * @param[in] pti contains the request received from the pseudo process
 * @param ack_ret
 *
 * @return positive value on success, -1 on failure.
 */
int psm_pseudo_pr_set_mm_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage pr_mm_resp = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	size_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto malloc_error;

	/* Use retval field to send CPU affinity value */
	pr_mm_resp.has_syscall_retval = true;
	pr_mm_resp.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(
			&pr_mm_resp);

	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Malloc fails:%s\n",
				strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				pr_mm_resp, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PR_SET_MM ack msg pack failed\n");
		retval = -1;
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending PR_SET_MM ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_sysinfo_ack(struct veos_thread_arg *pti,
		int ack_ret, struct sysinfo *ve_sysinfo)
{
	int retval = -1;
	PseudoVeosMessage sysinfo_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	size_t pseudo_msg_len;
	ProtobufCBinaryData veos_info;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto malloc_error;

	/* Populate acknowledgment message */
	sysinfo_ack.has_syscall_retval = true;
	sysinfo_ack.syscall_retval = ack_ret;

	sysinfo_ack.has_pseudo_msg = true;
	veos_info.data = (uint8_t *)ve_sysinfo;
	veos_info.len = sizeof(struct sysinfo);
	sysinfo_ack.pseudo_msg = veos_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sysinfo_ack);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&sysinfo_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SYSINFO_REQ ACK pack failed\n");
		retval = -1;
		goto hndl_return;
	}


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending SYSINFO_REQ ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the SYSINFO_REQ from pseudo process
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return postive value on success, -1 on failure
 */
int psm_handle_sysinfo_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	PseudoVeosMessage *sysinfo_req;
	struct ve_task_struct *ve_task_curr = NULL;
	struct sysinfo ve_sysinfo = {0};
	int pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	sysinfo_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = sysinfo_req->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In psm sysinfo handler\n"
			"\t\tRecevied sysinfo request from "
			"Pseudo with pid :%d\n", pid);

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				pid);
		goto hndl_return;
	}

	retval = psm_handle_sysinfo_request(ve_task_curr, &ve_sysinfo);
hndl_return:
	if (-1 == retval)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEOS fails to provide SYSINFO\n");

	/* Send the response back to pseudo process */
	psm_pseudo_send_sysinfo_ack(pti, retval, &ve_sysinfo);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int psm_pseudo_send_acct_ack(struct veos_thread_arg *pti, int ack_ret)
{
	int retval = -1;
	PseudoVeosMessage acct_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	size_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto malloc_error;

	/* Populate acknowledgment message */
	acct_ack.has_syscall_retval = true;
	acct_ack.syscall_retval = ack_ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&acct_ack);
	buf = malloc(pseudo_msg_len);

	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&acct_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ACCT_REQ ACK pack failed\n");
		retval = -1;
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Sending ACCT_REQ ACK\n");
	retval = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the ACCT_REQ from pseudo process
 *
 * @param[in] pti contains the request received from the pseudo process
 *
 * @return postive value on success, -1 on failure
 */
int psm_handle_acct_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	char *acct_file = NULL;
	PseudoVeosMessage *acct_req;
	int pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	acct_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = acct_req->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Recevied ACCT_REQ request from Pseudo with pid :%d\n",
			pid);

	if (acct_req->has_pseudo_msg) {
		/* Case when accounting is enabled */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Accounting is enabled by pid: %d\n",
				pid);
		acct_file = malloc(acct_req->pseudo_msg.len);
		if (NULL == acct_file) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"malloc fails: %s\n",
					strerror(errno));
			retval = -errno;
			goto hndl_return;
		}
		memcpy(acct_file, acct_req->pseudo_msg.data,
				acct_req->pseudo_msg.len);
	} else
		/* Case when accounting is disabled */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Accounting is disabled by pid: %d\n",
				pid);

	retval = psm_handle_do_acct_ve(acct_file);
hndl_return:
	if (0 > retval)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEOS fails to update Accounting\n");

	/* Send the response back to pseudo process */
	psm_pseudo_send_acct_ack(pti, retval);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
