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
 * @file  rpm_comm.c
 * @brief This file contains the functions which are responsible for
 * handling RPM request
 *
 * @author PSMG
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <proc/readproc.h>
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include "libved.h"
#include "task_mgmt.h"
#include "psm_stat.h"
#include "mm_stat.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "ptrace_req.h"
#include "ve_shm.h"
#include "buddy.h"
#include "ve_swap.h"
#include "ve_swap_request.h"
#include "psm_comm.h"

/**
 * @brief Write the buffer on the file descriptor.
 *
 * @param[in] socket_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to buffer to send
 * @param[in] max_len Size of buffer
 *
 * @return positive value on success, -1 on failure.
 */
int veos_write_buf(int socket_fd, void *buf, int max_len)
{
	ssize_t transferred = 0;
	ssize_t write_byte = 0;

	VEOS_TRACE("Entering");
	if (!buf)
		goto send_error;

	while ((write_byte = write(socket_fd, buf + transferred,
					max_len - transferred)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VEOS_ERROR("Sending command from VEOS failed");
				VEOS_DEBUG("Writing to socket failed: %s",
						strerror(errno));
				transferred = -1;
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;
		VEOS_DEBUG("Transferred = %d, Written = %d",
				(int)transferred, (int)write_byte);
	}
send_error:
	VEOS_TRACE("Exiting");
	return transferred;
}

/**
 * @brief Sends the success/failure response from VEOS back to RPM command.
 *
 * @param[in] veos_soc_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to populated structure by VEOS
 * @param[in] len Size of populated structure
 * @param[in] ack_ret Return value send to RPM command
 *
 * @return positive value on success, -1 on failure.
 */
int veos_rpm_send_cmd_ack(int veos_soc_fd, uint8_t *buf,
		int64_t len, int64_t ack_ret)
{
	int retval = -1;
	int pack_msg_len = -1;
	int msg_pack_len = -1;
	char pack_buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage rpm_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData rpm_data = {0};
	ProtobufCBinaryData ve_version = {0};

	VEOS_TRACE("Entering");
	/* Initializing message and populating return value */
	rpm_ack.has_syscall_retval = true;
	rpm_ack.syscall_retval = ack_ret;

	if (NULL != buf) {
		VEOS_DEBUG("Structure to send of size: %ld",
				len);
		rpm_ack.has_pseudo_msg = true;
		rpm_data.data = buf;
		rpm_data.len = len;
		rpm_ack.pseudo_msg = rpm_data;
	}

	rpm_ack.has_veos_version = true;
	ve_version.data = (uint8_t *)VERSION_STRING;
	ve_version.len = strlen(VERSION_STRING) + 1;
	rpm_ack.veos_version = ve_version;

	pack_msg_len = pseudo_veos_message__get_packed_size(&rpm_ack);
	msg_pack_len = pseudo_veos_message__pack(&rpm_ack, (uint8_t *)pack_buf);
	if (pack_msg_len != msg_pack_len) {
		VEOS_ERROR("Acknowledgment from VEOS to RPM failed");
		VEOS_DEBUG("Expected length: %d, Received length: %d",
				pack_msg_len, msg_pack_len);
		goto hndl_return;
	}

	retval = veos_write_buf(veos_soc_fd, pack_buf, pack_msg_len);
	if (retval < pack_msg_len) {
		VEOS_ERROR("Written: %d bytes of total: %d bytes",
				retval, pack_msg_len);
		retval = -1;
		goto hndl_return;
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_VEOSCTL_SET_PARAM request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_veosctl_set_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_veosctl_stat sched_param = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_veosctl_stat from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
								pseudo_msg;
	if (sizeof(sched_param) != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_param, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_param, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_rpm_handle_veosctl_set_req(sched_param);
	if (0 > retval) {
		VEOS_ERROR("Failed to set scheduler parameters using "
						"veosctl command");
		VEOS_DEBUG("veosctl command failed to set scheduler "
				"parameters returned %d", retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
								0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_VEOSCTL_GET_PARAM request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_veosctl_get_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_veosctl_stat sched_param = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	retval = psm_rpm_handle_veosctl_get_req(&(sched_param));
	if (0 > retval) {
		VEOS_ERROR("Failed to get scheduler parameters using "
							"veosctl command");
		VEOS_DEBUG("veosctl command failed to get scheduler "
					"parameters returned %d", retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
			(uint8_t *)&sched_param,
			sizeof(struct ve_veosctl_stat),retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE process getpriority request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_getpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_priorityinfo prio_req = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	pid_t host_pid = -1;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priorityinfo from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof prio_req != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof prio_req, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	/* Convert namespace pid to host pid */
	host_pid = vedl_host_pid(VE_HANDLE(0), pti->cred.pid, prio_req.who);
	if (host_pid <= 0) {
		VEOS_DEBUG("PID conversion failed, host: %d"
				" namespace: %d"
				" error: %s",
				pti->cred.pid,
				prio_req.who,
				strerror(errno));
		retval = -errno;
		goto hndl_return;
	}
	prio_req.who = host_pid;

	retval = psm_rpm_handle_getpriority_req(&prio_req);
	if (0 > retval) {
		VEOS_ERROR("Get priority request failed");
		VEOS_DEBUG("PSM get priority request returned %d", retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&prio_req,
			sizeof(struct ve_priorityinfo), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE process setpriority request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_setpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_priorityinfo prio_req = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	pid_t host_pid = -1;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priorityinfo from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof prio_req != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof prio_req, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	/* Convert namespace pid to host pid */
	host_pid = vedl_host_pid(VE_HANDLE(0), pti->cred.pid, prio_req.who);
	if (host_pid <= 0) {
		VEOS_DEBUG("PID conversion failed, host: %d"
				" namespace: %d"
				" error: %s",
				pti->cred.pid,
				prio_req.who,
				strerror(errno));
		retval = -errno;
		goto hndl_return;
	}
	prio_req.who = host_pid;

	retval = psm_rpm_handle_setpriority_req(&prio_req);
	if (0 > retval) {
		VEOS_ERROR("Set prioriy req failed");
		VEOS_DEBUG("PSM set priority req returned %d", retval);
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_CHECKPID request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_checkpid_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;

	VEOS_TRACE("Entering");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Check VE pid exists or not */
	retval = psm_rpm_handle_check_pid(pid);
	if (0 > retval) {
		VEOS_DEBUG("PSM check PID returned %d", retval);
	}
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_MEM_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_mem_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct velib_meminfo mem_info = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	retval = veos_meminfo(&mem_info);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed");
		VEOS_DEBUG("AMM populate meminfo struct returned %d",
				retval);
		goto hndl_return1;
	}

	retval = 0;
hndl_return1:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&mem_info,
			sizeof(struct velib_meminfo), retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_MAP_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_map_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	pid_t caller_pid = -1;
	proc_t ve_proc_info = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	struct ve_mapheader header = {0};

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;
	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof header != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof header, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&header, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_get_ve_proc_info(pid, &ve_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for pid: %d", pid);
		retval = -EFAULT;
		goto hndl_return;
	}

	if ((pti->cred.uid == ve_proc_info.euid &&
			pti->cred.uid == ve_proc_info.suid &&
			pti->cred.uid == ve_proc_info.ruid &&
			pti->cred.gid == ve_proc_info.egid &&
			pti->cred.gid == ve_proc_info.sgid &&
			pti->cred.gid == ve_proc_info.rgid) || !(pti->cred.uid)) {
		VEOS_DEBUG("Caller process: %d and Current process: "
				"%d belongs to same user",
				caller_pid, pid);
		goto get_pmap;
	} else {
		VEOS_DEBUG("Caller process :%d is not have "
			"permission to get pmap of process %d",
				 caller_pid, pid);
		retval = 0;
		goto hndl_return;
	}

get_pmap:
	retval = veos_pmap(pid, pti->cred.gid, pti->cred.uid, &header);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed for PID: %d",
				pid);
		VEOS_DEBUG("VEOS populate mapheader struct returned %d", retval);
	}
hndl_return:
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&header,
			sizeof(struct ve_mapheader), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_PIDSTAT_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_pidstat_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct velib_pidstat pidstat = {0};
	pid_t namespace_pid = -1;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	namespace_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	if (((PseudoVeosMessage *)pti->pseudo_proc_msg)->has_ve_pid &&
			namespace_pid > 0) {
		pid = vedl_host_pid(VE_HANDLE(0),
				pti->cred.pid, namespace_pid);
		if (pid <= 0) {
			VEOS_ERROR("Conversion of namespace to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" namespace: %d"
					" error: %s",
					pti->cred.pid,
					namespace_pid,
					strerror(errno));
			retval = -errno;

			/* Send the failure response back to RPM command */
			retval = veos_rpm_send_cmd_ack(
					pti->socket_descriptor,
					NULL, 0, retval);
			goto hndl_return1;
		}
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid = pid;
	}

	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof pidstat != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof pidstat, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&pidstat, rpm_pseudo_msg.data, rpm_pseudo_msg.len);
	pidstat.tgid = namespace_pid;

	/* PSM will populate its corresponding fields of
	 * struct velib_pidstat.
	 */
	retval = psm_rpm_handle_pidstat_req(pid, &pidstat);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed for PID: %d",
				pid);
		VEOS_DEBUG("PSM populate pidstat struct returned %d", retval);
		goto hndl_return;
	}

	/*
	 * AMM interface to populate rest of the field of
	 * struct velib_pidstat.
	 */
	retval = veos_pidstat_info(pid, &pidstat);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed for PID: %d",
				pid);
		VEOS_DEBUG("AMM populate pidstat struct returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&pidstat,
			sizeof(struct velib_pidstat), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_GET_REGVALS request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_get_regvals_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *tsk = NULL;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	int numregs = 0;
	int regids[VE_MAX_REGVALS] = {0};
	uint64_t regvals[VE_MAX_REGVALS] = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* allow only root or own user to retrieve registers
	 * task struct is retrieved once again later, but this
	 * seems still the cheapest way to restrict access
	 */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("VE task with pid %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}
	if (tsk->uid != pti->cred.uid && pti->cred.uid != 0) {
		VEOS_DEBUG("VE regvals access not permitted");
		put_ve_task_struct(tsk);
		retval = -EPERM;
		goto hndl_return;
	}

	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	numregs = rpm_pseudo_msg.len / sizeof(int);
	if (numregs < 1 || numregs > VE_MAX_REGVALS) {
		VEOS_ERROR("illegal value for numregs: %d", numregs);
		retval = -EINVAL;
		numregs = 0;
		goto hndl_return;
	}

	memcpy(&regids[0], rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	/* PSM will populate regvals */
	retval = psm_get_regval(tsk, numregs, regids, regvals);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed for PID: %d",
				pid);
		VEOS_DEBUG("PSM populate regvals returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */

	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				       (uint8_t *)&regvals,
				       sizeof(uint64_t) * numregs,
				       retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_PIDSTATM_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_pidstatm_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_pidstatm pidstatm = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	pid = ((PseudoVeosMessage *) pti->pseudo_proc_msg)->ve_pid;

	retval = veos_pidstatm_info(pid, &pidstatm);
	if (0 > retval) {
		VEOS_ERROR("Failed in populating pidstatm struct for pid: %d",
				pid);
		VEOS_DEBUG("Populating pidstatm struct returned %d", retval);
		goto hndl_return1;
	}
	retval = 0;
hndl_return1:
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *) &pidstatm,
			sizeof(struct velib_pidstatm), retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_PIDSTATUS_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_pidstatus_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_pidstatus pidstatus = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Populate struct velib_pidstatus */
	retval = psm_rpm_handle_pidstatus(pid, &pidstatus);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed");
		VEOS_DEBUG("PSM populate pidstatus struct returned %d",
				retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&pidstatus,
			sizeof(struct velib_pidstatus), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_LOAD_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_load_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_loadavg ve_load = {0};
	struct ve_node_struct *p_ve_node = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	p_ve_node = VE_NODE(0);

	/* Populating values in struct ve_loadavg */
	retval = calc_last_1_5_15_load(p_ve_node,
			&(ve_load.av_1),
			&(ve_load.av_5),
			&(ve_load.av_15));
	if (-1 == retval) {
		VEOS_ERROR("Failed to calculate VE node load");
		retval = -EFAULT;
		goto hndl_return;
	}

	ve_load.runnable = p_ve_node->nr_active;
	ve_load.total_proc = p_ve_node->num_ve_proc;
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&ve_load,
			sizeof(struct ve_loadavg), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_STAT_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_stat_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct velib_statinfo statinfo = { {0} };
	struct ve_node_struct *p_ve_node = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	p_ve_node = VE_NODE(0);

	/* PSM will populate the struct velib_statinfo */
	retval = psm_rpm_handle_stat_req(p_ve_node, &statinfo);
	if (-1 == retval) {
		VEOS_ERROR("Populating information failed");
		VEOS_DEBUG("PSM populate statinfo struct returned %d",
				retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&statinfo,
			sizeof(struct velib_statinfo), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_GET_RUSAGE request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_get_rusage_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_get_rusage_info ve_ru = { {0} };

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	retval = psm_rpm_handle_get_rusage_req(pid, &ve_ru);
	if (0 > retval) {
		VEOS_ERROR("Failed to get resource usage for PID: %d", pid);
		VEOS_DEBUG("Getting rusage req returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&ve_ru,
			sizeof(struct velib_get_rusage_info), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_GET_SCHEDULER request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_sched_get_scheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_setscheduler sched_param = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Populate the struct velib_setscheduler */
	retval = psm_rpm_handle_sched_get_scheduler(pid, &sched_param);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed");
		VEOS_DEBUG("PSM populate scheduler struct returned %d",
				retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_param,
			sizeof(struct velib_setscheduler), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_SET_SCHEDULER request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_sched_set_scheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_setscheduler sched_param = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct velib_setscheduler from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof sched_param != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_param, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_param, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	retval = psm_rpm_handle_sched_set_scheduler(pid, sched_param);
	if (0 > retval) {
		VEOS_ERROR("Setting scheduling parameter and "
				"policy failed for PID %d", pid);
		VEOS_DEBUG("Setting sched_param request returned %d", retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_GET_PARAM request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_sched_get_param_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct sched_param sp = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Populate the struct velib_setscheduler */
	retval = psm_rpm_handle_sched_get_param(pid, &sp);
	if (0 > retval) {
		VEOS_ERROR("Getting scheduling parameter and "
				"policy failed for PID %d", pid);
		VEOS_DEBUG("Getting sched_param request returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sp,
			sizeof(struct sched_param), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_GET_PRIORITY_MAX request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_get_priority_max_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_sched_limit_request sched_limit = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_sched_limit_request from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof sched_limit != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_limit, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_limit, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	/* VE only supports SCHED_OTHER scheduling policy */
	if (sched_limit.policy == SCHED_OTHER) {
		sched_limit.retval = VE_PROC_PRIORITY_MAX;
		retval = 0;
	} else {
		VEOS_ERROR("Invalid policy received: %d",
				sched_limit.policy);
		retval = -EINVAL;
	}

	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_limit,
			sizeof(struct ve_sched_limit_request), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_GET_PRIORITY_MIN request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_get_priority_min_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_sched_limit_request sched_limit = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_sched_limit_request from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof sched_limit != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_limit, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_limit, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	/* VE only supports SCHED_OTHER scheduling policy */
	if (sched_limit.policy == SCHED_OTHER) {
		sched_limit.retval = VE_PROC_PRIORITY_MIN;
		retval = 0;
	} else {
		VEOS_ERROR("Invalid policy received: %d",
				sched_limit.policy);
		retval = -EINVAL;
	}

	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_limit,
			sizeof(struct ve_sched_limit_request), retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_SET_AFFINITY request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_set_affinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int caller_pid = -1, ve_pid = -1;
	struct velib_affinity sched_affinity = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	ve_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Fetch the struct velib_affinity from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof sched_affinity != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_affinity, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_affinity, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_handle_setaffinity_request(caller_pid, ve_pid,
			sched_affinity.mask);
	if (0 > retval) {
		VEOS_ERROR("Set affinity failed for VE PID: %d"
				" and caller PID: %d",
				ve_pid,
				caller_pid);
		VEOS_DEBUG("SET AFFINITY REQ returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_GET_AFFINITY request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_get_affinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	struct velib_affinity sched_affinity = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Fetch the struct velib_affinity from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof sched_affinity != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof sched_affinity, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&sched_affinity, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_handle_getaffinity_request(pid, sched_affinity.cpusetsize,
			&(sched_affinity.mask));
	if (0 > retval) {
		VEOS_ERROR("Getting affinity failed for PID: %d", pid);
		VEOS_DEBUG("GET AFFINITY REQ returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
			(uint8_t *)&sched_affinity,
			sizeof(struct velib_affinity),
			retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_PRLIMIT request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_prlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1, caller_pid = -1;
	struct velib_prlimit prlimit = {0};
	ProtobufCBinaryData rpm_pseudo_msg = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;
	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Fetch the struct velib_prlimit from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof prlimit != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof prlimit, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&prlimit, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_rpm_handle_prlimit(caller_pid, pid, &prlimit, pti);
	if (0 > retval) {
		VEOS_ERROR("Populating prlimit struct failed");
		VEOS_DEBUG("PSM populate prlimit struct returned %d",
				retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&prlimit,
			sizeof(struct velib_prlimit), retval);
hndl_return1:
	VEOS_TRACE("Entering");
	return retval;
}

/**
 * @brief Handles the VE_ACCTINFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_acctinfo_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	char *acct_file = NULL;
	PseudoVeosMessage *acct_req = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	acct_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = acct_req->pseudo_pid;

	VEOS_DEBUG("Received ACCT REQ from "
			"RPM command for PID: %d", pid);

	if (acct_req->has_pseudo_msg) {
		/* Case when accounting is enabled */
		VEOS_DEBUG("Accounting is enabled by PID: %d",
				pid);
		acct_file = malloc(acct_req->pseudo_msg.len + 1);
		if (NULL == acct_file) {
			retval = -errno;
			VEOS_CRIT("Internal Memory allocation failed");
			VEOS_DEBUG("Malloc failed: %s",
					strerror(errno));
			goto hndl_return;
		}
		memset(acct_file, '\0', acct_req->pseudo_msg.len + 1);
		memcpy(acct_file, acct_req->pseudo_msg.data,
				acct_req->pseudo_msg.len);
	} else
		/* Case when accounting is disabled */
		VEOS_DEBUG("Accounting is disabled by PID: %d",
				pid);

	retval = psm_rpm_handle_acct(pid, acct_file);
	if (0 > retval) {
		if (acct_file)
			free(acct_file);
		VEOS_ERROR("Accounting failed");
		VEOS_DEBUG("PSM acct handling failed returned %d", retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_CREATE_PROCESS request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return PID on success, -1 on failure.
 */
int rpm_handle_create_process_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	int node_id = -1, core_id = -1, numa_node = -1;
	struct ve_task_struct *tsk = NULL;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct velib_create_process create_proc = {0};
	struct ve_core_struct *p_ve_core = NULL;
	cpu_set_t cpu_mask;
	int core_loop = 0;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Fetch the flag rpm_preserve_task data from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	if (sizeof create_proc != rpm_pseudo_msg.len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof create_proc, rpm_pseudo_msg.len);
		goto hndl_return1;
	}
	memcpy(&create_proc, rpm_pseudo_msg.data, rpm_pseudo_msg.len);
	numa_node = create_proc.numa_num;
	cpu_mask = create_proc.mask;


	if (!((numa_node >= -1) &&
				(numa_node < VE_NODE(0)->numa_count))) {
		VEOS_DEBUG("PID : %d Numa node id :"
				" %d", pid, numa_node);
		retval = -VE_EINVAL_NUMAID;
		goto hndl_return;
	}

	if (create_proc.taskset_flag == false)
		goto skip_affinity_mask_check;

	for (; core_loop < VE_NODE(0)->nr_avail_cores;
			core_loop++) {
		if (!CPU_ISSET(core_loop, &cpu_mask))
			continue;
		p_ve_core = VE_CORE(0, core_loop);
		if (numa_node == -1)
			numa_node = p_ve_core->numa_node;

		if (numa_node != p_ve_core->numa_node) {
			VEOS_DEBUG("CPU %d mask belongs "
					"to another NUMA node",
					core_loop);
			retval = -VE_EINVAL_COREID;
			goto hndl_return;
		}
		if (core_id == -1)
			core_id = core_loop;
	}

	if (core_id == -1) {
		VEOS_DEBUG("Invalid CPU");
		retval = -VE_EINVAL_COREID;
		goto hndl_return;
	}

	/* AS numa_node and core_id can't send together,
	 * we are updating numa node with -1*/
	numa_node = -1;

skip_affinity_mask_check:
	retval = psm_handle_exec_ve_process(pti, &core_id, &node_id,
			pid, 0, "Dummy_task", false, 0, (uint64_t)0,
			NULL, NULL, 0, 0, true, "Dummy path", &numa_node,
			create_proc.policy_flag, create_proc.ppid, pid);
	if (0 > retval) {
		VEOS_ERROR("Creating VE process failed");
		VEOS_DEBUG("Creating VE process from RPM command returned: %d",
				retval);
		goto hndl_return;
	}

	/* Fetch the respective task_struct from the list */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID %d does not exist", pid);
		retval = -ESRCH;
		goto hndl_return;
	}
	memcpy(tsk->sighand->rlim , create_proc.ve_rlim,
			sizeof(create_proc.ve_rlim));

	tsk->execed_proc = true;
	tsk->rpm_preserve_task = create_proc.flag;
	tsk->pseudo_vefd = create_proc.vedl_fd;
	if (create_proc.taskset_flag == true)
		tsk->cpus_allowed = cpu_mask;
	retval = pid;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, retval);
	if (tsk)
		put_ve_task_struct(tsk);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}
/**
 * @brief Handles the VE_SHM_RMLS request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ipc_rmls_req(struct veos_thread_arg *pti)
{
	int ret = 0;
	bool key_id_valid = false;
	struct ve_shm_info shm_info = {0};
	struct ve_mapheader header = {0};
	struct shm_summary s_summary = {0};
	proc_t proc_info = {0};
	sdata_t shm_id_info = {0};
	size_t len = 0;
	bool if_yes = false;

	VEOS_TRACE("Entering");

	if (!pti) {
		ret = -1;
		goto hndl_return;
	}

	pid_t pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	len = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg).len;

	if (sizeof shm_info != len) {
		VEOS_ERROR("Expected request message len: [%lu] Got: [%lu]",
			sizeof shm_info, len);
		ret = -1;
		goto hndl_return;
	}
	memcpy(&shm_info, (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
				pseudo_msg).data, len);

	/*Get proc info for given pid*/
	if (0 > psm_get_ve_proc_info(pid, &proc_info)) {
		ret = -EFAULT;
		VEOS_DEBUG("pid(%d) error unable to get proc info", pid);
		veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, ret);
		goto hndl_return;
	}

	switch (shm_info.mode) {
	case SHMKEY:
		if_yes =  true;
	case SHMID:
		VEOS_DEBUG("PID[%d] Request for IPCRM -m/IPCRM -M SHMID[%d]",
				pid, shm_info.key_id);
		ret = is_capable(&proc_info, &shm_info.key_id, if_yes);
		if (ret < 0) {
			VEOS_DEBUG("Caller: %d doesnot have access to "
					"remove segment : %d",
					pid, shm_info.key_id);
			ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
					(uint8_t *)&shm_info,
					sizeof(struct ve_shm_info), ret);
			goto hndl_return;
		}

		/* Deleting segment from VE*/
		ret = amm_do_shmctl(shm_info.key_id, proc_info.ns[IPCNS]);
		if (ret < 0)
			VEOS_DEBUG("error while deleting shm segment with %s : %d",
					(shm_info.mode == SHMKEY) ?
					"SHMKEY" : "SHMID",
					shm_info.key_id);

		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&shm_info,
				sizeof(struct ve_shm_info), ret);
		break;
	case SHM_LS:
		if_yes =  true;
	case SHM_ALL:
		header.node_id = shm_info.node_id;
		VEOS_DEBUG("PID[%d] Request for IPCRM -a/IPCS", pid);
		ret = rm_or_ls_segment(&proc_info, if_yes, &header);
		if (ret < 0) {
			VEOS_DEBUG("pid(%d) error(%s) %s", pid, strerror(-ret),
					if_yes ? "ipcs" : "ipcrm -a");
			VEOS_DEBUG("error while %s all shm segments from veos",
			(shm_info.mode == SHM_ALL) ? "deleting" : "listing");
		}

		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&header,
				sizeof(struct ve_mapheader), ret);
		break;
	case SHMID_INFO:
		VEOS_DEBUG("PID[%d] Request for IPCS -i SHMID[%d]",
				shm_info.key_id, pid);
		ret = get_shm_info(shm_info.key_id, &shm_id_info,
				proc_info.ns[IPCNS]);
		if (ret < 0)
			VEOS_DEBUG("error(%s) while getting info for shmid(%d)",
					strerror(-ret), shm_info.key_id);

		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&shm_id_info,
				sizeof(sdata_t), ret);
		break;
	case SHM_SUMMARY:
		VEOS_DEBUG("PID[%d] Request for IPCS -u", pid);
		ve_shm_summary(&s_summary, proc_info.ns[IPCNS]);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&s_summary,
				sizeof(struct shm_summary), ret);
		break;
	case SHMID_QUERY:
		VEOS_DEBUG("shmid(%d) query", shm_info.key_id);
		veos_key_id_query(shm_info.key_id,
				&key_id_valid, false, proc_info.ns[IPCNS]);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&key_id_valid,
				sizeof(key_id_valid), ret);
		break;
	case SHMKEY_QUERY:
		VEOS_DEBUG("shmkey(%d) query", shm_info.key_id);
		veos_key_id_query(shm_info.key_id,
				&key_id_valid, true, proc_info.ns[IPCNS]);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				(uint8_t *)&key_id_valid,
				sizeof(key_id_valid), ret);
		break;
	default:
		ret = -EINVAL;
		VEOS_DEBUG("No such option for ipcs/ipcrm");
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, ret);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handles the VE_DEL_DUMMY_TASK request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_delete_dummy_task_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	pid_t pid = -1;
	struct ve_task_struct *del_dummy_tsk = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return1;
	}

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;
	del_dummy_tsk = find_ve_task_struct(pid);
	if (del_dummy_tsk == NULL) {
		VEOS_ERROR("Failed to find task structure");
		VEOS_DEBUG("Failed to fetch task structure for PID %d", pid);
		retval = -ESRCH;
		goto hndl_return;
	}
	/* Set "dummy_task" flag in VE task struct so that accounting
	 * information is not dumped while VE task cleanup
	 * */
	set_state(del_dummy_tsk);
	put_ve_task_struct(del_dummy_tsk);

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0,
			retval);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the VE_NUMA_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_numa_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int core_loop = 0, numa_loop = 0, core_list = 0;
	struct ve_numa_stat ve_numa = {0};
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct velib_meminfo mem_info[VE_MAX_NUMA_NODE] = { {0} };
	size_t size = 0;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Invalid(NULL) argument "
				"received from pseudo process");
		goto hndl_return1;
	}

	size = (sizeof(struct velib_meminfo) * vnode->numa_count);

	if (VE_NODE(0)->partitioning_mode) {
		retval = veos_numa_meminfo(mem_info, size);
		if (0 > retval) {
			VEOS_ERROR("veos_numa_meminfo request failed");
			goto hndl_return;
		}

		ve_numa.tot_numa_nodes = vnode->numa_count;
		for (; numa_loop < vnode->numa_count; numa_loop++) {
			core_list = 0;
			for (core_loop = 0; core_loop < vnode->nr_avail_cores;
					core_loop++) {
				p_ve_core = VE_CORE(0, core_loop);
				if (p_ve_core->numa_node == numa_loop)
					core_list |= (1 << core_loop);
			}
			sprintf(ve_numa.ve_cores[numa_loop], "%x", core_list);
			ve_numa.mem_size[numa_loop] =
				(uint64_t)mem_info[numa_loop].kb_main_total;
			ve_numa.mem_free[numa_loop] =
				(uint64_t)mem_info[numa_loop].kb_main_free;

		}
	} else {
		retval = veos_meminfo(mem_info);
		if (0 > retval) {
			VEOS_ERROR("veos_meminfo request failed");
			goto hndl_return;
		}
		for (; core_loop < vnode->nr_avail_cores; core_loop++)
			core_list |= (1 << core_loop);

		ve_numa.tot_numa_nodes = vnode->numa_count;
		sprintf(ve_numa.ve_cores[0], "%x", core_list);
		ve_numa.mem_size[0] = (uint64_t)mem_info[0].kb_main_total;
		ve_numa.mem_free[0] = (uint64_t)mem_info[0].kb_main_free;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
			(uint8_t *)&ve_numa,
			sizeof(struct ve_numa_stat),
			retval);
hndl_return1:
	VEOS_TRACE("Entering");
	return retval;
}

/**
 * @brief Check pid is tid of child thread or not.
 *
 * @param[in] ve_task Pointer of source VE task struct
 *
 * @return false, if pid is tid of child thread return ture.
 */
static bool is_child_tid(struct ve_task_struct *ve_task)
{
	bool retval = false;

	VEOS_TRACE("In %s", __func__);

	if (ve_task->group_leader->pid != ve_task->pid) {
		retval = true;
	}

	VEOS_TRACE("Out %s", __func__);

	return retval;
}

/**
 * @brief pids check of PPS.
 *
 * @param[in] pids structure of ve_swap_pid
 *
 * @return 0 on success, -EINVAL on failure.
 */
static int swap_pid_check(struct ve_swap_pids pids)
{
	int retval = 0;

	VEOS_TRACE("In %s", __func__);

	if (pids.process_num < 0) {
		VEOS_ERROR("Data which veswap sent contains less data"
							" than expected");
		retval = -EINVAL;
		goto hndl_return;
	} else if (pids.process_num > MAX_SWAP_PROCESS) {
		VEOS_ERROR("Data which veswap sent contains more data"
							" than expected");
		retval = -EINVAL;
		goto hndl_return;
	}
	if (pids.pid[pids.process_num] != PPS_END_OF_PIDS) {
		VEOS_ERROR("Data which veswap sent has contradiction");
		retval = -EINVAL;
		goto hndl_return;
	}

hndl_return:
	VEOS_TRACE("Out %s", __func__);
	return retval;
}

/**
 * @brief Check whether specified process can execute swap handling.
 *
 * @param[in] pti Contains the request message received from RPM command
 * @param[in] ve_task Pointer of source VE task struct
 *
 * @return 0 on success, -errno on failure.
 */
static int check_process_for_swap(struct veos_thread_arg *pti,
			struct ve_task_struct *tsk)
{
	int retval = -1;
	int ret = -1;
	pid_t pid = 0;
	proc_t ve_proc_info = {0};
	proc_t ve_caller_proc_info = {0};
	pid_t caller_pid = 0;

	int errno_re = 0;
	pid = tsk->pid;

	VEOS_TRACE("In %s", __func__);

	/* Check security */
	ret = psm_get_ve_proc_info(pid, &ve_proc_info);
	if (ret == -1) {
		VEOS_ERROR("Failed to get proc information for pid: %d", pid);
		errno_re = EPERM;
		goto hndl_return;
	}
	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	ret = psm_get_ve_proc_info(caller_pid, &ve_caller_proc_info);
	if (ret == -1) {
		VEOS_ERROR("Failed to get proc information for caller pid: %d",
				caller_pid);
		errno_re = EPERM;
		goto hndl_return;
	}

	if (!(pti->cred.uid) ||
		(pti->cred.uid == ve_proc_info.euid &&
		pti->cred.uid == ve_proc_info.suid &&
		pti->cred.uid == ve_proc_info.ruid &&
		pti->cred.gid == ve_proc_info.egid &&
		pti->cred.gid == ve_proc_info.sgid &&
		pti->cred.gid == ve_proc_info.rgid)) {

		VEOS_DEBUG("Caller process: %d and swap process: "
				"%d belongs to same user",
				caller_pid, pid);
	} else {
		VEOS_DEBUG("Caller process :%d is not have "
		"permission to handle swap request of process %d",
				 caller_pid, pid);
		errno_re = EPERM;
		goto hndl_return;
	}

hndl_return:
	retval = -errno_re;
	VEOS_TRACE("Out %s", __func__);
	return retval;
}

/**
 * @brief Handles the VE_SWAP_OUT request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ve_swapout_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int retval_to_cmd = -errno;
	struct ve_node_struct *p_ve_node = NULL;
	struct ve_task_struct *ve_task = NULL;
	struct veos_swap_request_info *request_info;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct ve_swap_pids target_pids = {};
	struct ve_task_struct *group_leader = NULL, *tmp = NULL;
	struct ve_ipc_sync *ipc_sync = NULL;
	pid_t pid = 0;
	int i;
	int pid_num = 0;
	int valid_pid_num = 0;
	int to_next_pid = 0;
	bool retval_to_cmd_eio = false;

	VEOS_TRACE("In %s", __func__);

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		retval = -1;
		goto hndl_return;
	}

	request_info = (struct veos_swap_request_info *)malloc(
					sizeof(struct veos_swap_request_info));
	if (request_info == NULL) {
		retval_to_cmd = -ECANCELED;
		VEOS_ERROR("Failed to create Swap request due to %s",
							strerror(errno));
		goto hndl_sendmgs;
	}

	p_ve_node = VE_NODE(0);
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	if (rpm_pseudo_msg.len != sizeof(struct ve_swap_pids)) {
		VEOS_ERROR("Data which veswap sent is invalid");
		retval_to_cmd = -ECANCELED;
		free(request_info);
		goto hndl_sendmgs;
	}
	memcpy(&target_pids, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = swap_pid_check(target_pids);
	if (retval != 0) {
		retval_to_cmd = -ECANCELED;
		free(request_info);
		goto hndl_sendmgs;
	}

	pid_num = target_pids.process_num;
	for (i = 0; i < pid_num; i++) {
		to_next_pid = 0;
		pid = vedl_host_pid(VE_HANDLE(0),
				pti->cred.pid, target_pids.pid[i]);
		if (pid <= 0) {
			VEOS_ERROR("Conversion of target_pid to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" target pid: %d"
					" error: %s",
					pti->cred.pid,
					target_pids.pid[i],
					strerror(errno));
			continue;
		}
		VEOS_DEBUG("swapout target pid is %d", pid);

		/* Check whether VEOS is terminating */
		if (!veos_check_pps_enable()) {
			VEOS_DEBUG("Partial process swapping is disabled");
			goto hndl_free_req;
		}

		ve_task = find_ve_task_struct(pid);
		if (ve_task == NULL) {
			VEOS_DEBUG("VE task with pid %d not found", pid);
			continue;
		}
		/* Check whether process is core dumping */
		if (is_dumping_core(ve_task)) {
			VEOS_DEBUG("%d is core dumping", pid);
			put_ve_task_struct(ve_task);
			continue;
		}

		ipc_sync = ve_get_ipc_sync(ve_task);
		if (ve_task->group_leader->sstatus == SWAPPED_OUT)
			ve_put_ipc_sync(ipc_sync);

		if (ipc_sync == NULL) {
			put_ve_task_struct(ve_task);
			continue;
		}

		pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");

		group_leader = ve_task->group_leader;
		veos_operate_all_ve_task_lock(group_leader, LOCK);

		/* Check whether pid is tid of child thread */
		if (is_child_tid(ve_task)) {
			VEOS_DEBUG("%d is child tid", pid);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			ve_put_ipc_sync(ipc_sync);
			put_ve_task_struct(ve_task);
			continue;
		}

		/* Check process */
		retval = check_process_for_swap(pti, ve_task);
		if (retval != 0) {
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			ve_put_ipc_sync(ipc_sync);
			put_ve_task_struct(ve_task);
			continue;
		}

		list_for_each_entry(tmp, &(group_leader->thread_group),
							thread_group) {
			if (tmp->ptraced) {
				VEOS_DEBUG("%d is ptraced", pid);
				veos_operate_all_ve_task_lock(
					group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				to_next_pid = 1;
				break;
			}

			/* Check status and sub-status */
			if (((tmp->ve_task_state == ZOMBIE) ||
				(tmp->ve_task_state == STOP)) &&
				((tmp->sstatus == ACTIVE) || 
				(tmp->sstatus == SWAPPED_OUT))) {
				VEOS_DEBUG("child thread %d,"
					" status:%d, sub-status:%d", tmp->pid,
					tmp->ve_task_state, tmp->sstatus);
			} else {
				VEOS_DEBUG("Checking status and "
					"sub-status of child thread "
					"failed, status:%d, sub-status:%d",
					tmp->ve_task_state,
					tmp->sstatus);
				veos_operate_all_ve_task_lock(
					group_leader, UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				to_next_pid = 1;
				break;
			}
			/* Change sub-status with main thread together*/
		}

		if (!to_next_pid) {
			if (group_leader->ptraced) {
				VEOS_DEBUG("%d is ptraced", pid);
				veos_operate_all_ve_task_lock(group_leader,
					UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				continue;
			}
			/* Check status and sub-status */
			/* Swap-out against ZOMBIE group_leader is not allowed. */
			if (((group_leader->ve_task_state != STOP) &&
				(group_leader->ve_task_state != ZOMBIE)) ||
				((group_leader->sstatus != ACTIVE) &&
				(group_leader->sstatus != SWAPPED_OUT))) {
				VEOS_DEBUG("Checking status and sub-status of "
					"leader thread failed, status:%d, "
					"sub-status:%d",
					group_leader->ve_task_state,
					group_leader->sstatus);
				veos_operate_all_ve_task_lock(group_leader,
					UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to acquire thread_group_mm_lock");
				ve_put_ipc_sync(ipc_sync);
				put_ve_task_struct(ve_task);
				continue;
			}
			/* Change sub-status */
			veos_update_substatus(group_leader, SWAPPING_OUT);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release hread_group_mm_lock");
			/* To delete ve_task_struct in  psm_do_execve_wait()
			 * when VH binary is executed via evecve(),
			 * Swap-out procedure must set 1 to ve_ipc_sync->swapping
			 * without incrementing ref_cnt of ve_task_struct.
			 * Swap-thread must set 0 to ve_ipc_sync->swapping,
			 * and must free ipc_sync, even if ve_task_struct
			 * corresponding to process id wihch is in request
			 * information, is not found.
			 */
			put_ve_task_struct(ve_task);
			ve_swap_out_start(ipc_sync);
			request_info->ipc_sync_array[valid_pid_num] = ipc_sync;
			request_info->pid_array[valid_pid_num] = pid;
			valid_pid_num++;
		}
	}
	request_info->pid_array[valid_pid_num] = PPS_END_OF_PIDS;
	request_info->pid_number = valid_pid_num;

	pthread_rwlock_lock_unlock(
			&(p_ve_node->ve_relocate_lock), UNLOCK,
			"Failed to release ve_relocate_lock lock");

	retval = veos_open_pps_file(p_ve_node);
	if (retval != 0) {
		if(p_ve_node->pps_buf_size > 0) {
			retval_to_cmd_eio = true;
		} else {
			pthread_rwlock_lock_unlock(
				&(p_ve_node->ve_relocate_lock), RDLOCK,
				"Failed to acquire ve_relocate_lock read lock");
			/* Change sub-status back */
			for (i = 0; i < request_info->pid_number; i++) {
				pid = request_info->pid_array[i];
				ve_task = find_ve_task_struct(pid);
				if (ve_task == NULL) {
					VEOS_DEBUG("VE task with pid %d not "
								"found", pid);
					continue;
				}

				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), LOCK,
					"Failed to acquire "
					"thread_group_mm_lock");

				group_leader = ve_task->group_leader;
				veos_operate_all_ve_task_lock(group_leader,
									LOCK);
				/* The original sub-status is not needed to
				 * change back when original sub-status is not
				 * ACTIVE, because open pps file is done only
				 * the first time */
				veos_update_substatus(group_leader, ACTIVE);
				veos_operate_all_ve_task_lock(group_leader,
									UNLOCK);
				pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
					thread_group_mm_lock), UNLOCK,
					"Failed to release "
					"thread_group_mm_lock");
				put_ve_task_struct(ve_task);
			}
			retval_to_cmd = -EFAULT;
			goto hndl_open_fail_req;
		}
	}

	/* Check whether VEOS is terminating */
	pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock), LOCK,
		"Failed to aqcuire swap_request lock");
	if (!p_ve_node->swap_request_pids_enable) {
		VEOS_DEBUG("VEOS is terminating");
		pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock),
			UNLOCK, "Failed to release swap_request lock");
		pthread_rwlock_lock_unlock(&(p_ve_node->ve_relocate_lock),
			RDLOCK, "Failed to acquire ve_relocate_lock read lock");
		goto hndl_free_req;
	}

	list_add_tail(&(request_info->swap_info),
			&(p_ve_node->swap_request_pids_queue));

	/* Wake up thread */
	VEOS_DEBUG("Wake up thread");
	pthread_cond_broadcast(&(p_ve_node->swap_request_pids_cond));
	pthread_mutex_lock_unlock(&(p_ve_node->swap_request_pids_lock), UNLOCK,
					"Failed to release swap_request lock");

	pthread_rwlock_lock_unlock(
				&(p_ve_node->ve_relocate_lock), RDLOCK,
				"Failed to acquire ve_relocate_lock read lock");

	if (valid_pid_num == pid_num) {
		if (retval_to_cmd_eio) {
			retval_to_cmd = -EIO;
		} else {
			retval_to_cmd = 0;
		}
	} else {
		retval_to_cmd = -EPERM;
	}
	goto hndl_sendmgs;

hndl_free_req:
	retval_to_cmd = -ENOTSUP;
hndl_open_fail_req:
	request_info->pid_array[valid_pid_num] = PPS_END_OF_PIDS;
	request_info->pid_number = valid_pid_num;
	del_doing_swap_request(request_info);
	for (i = 0; request_info->pid_array[i] != PPS_END_OF_PIDS; i++) {
		ve_put_ipc_sync(request_info->ipc_sync_array[i]);
	}
	free(request_info);

hndl_sendmgs:
	retval = 0;
	/* Send the response back to RPM command */
	VEOS_DEBUG("Send the response back %d to RPM command", retval_to_cmd);
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0,
					retval_to_cmd);
	if (retval == -1) {
		VEOS_ERROR("Failed send the response back to RPM command");
	}

hndl_return:
	VEOS_TRACE("Out %s", __func__);
	return retval;
}

/**
 * @brief Handles the VE_SWAP_IN request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ve_swapin_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int retval_to_cmd = -errno;
	struct ve_task_struct *ve_task = NULL;
	struct ve_task_struct *group_leader = NULL;
	struct veos_swap_request_info *request_info = NULL;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct ve_swap_pids target_pids = {};
	pid_t pid = 0;
	int i;
	int pid_num = 0;
	int valid_pid_num = 0;

	VEOS_TRACE("In %s", __func__);

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		retval = -1;
		goto hndl_return1;
	}

	request_info = (struct veos_swap_request_info *)malloc(
					sizeof(struct veos_swap_request_info));
	if (request_info == NULL) {
		retval_to_cmd = -ECANCELED;
		VEOS_ERROR("Failed to create Swap request due to %s",
							strerror(errno));
		goto hndl_return;
	}

	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	if (rpm_pseudo_msg.len != sizeof(struct ve_swap_pids)) {
		VEOS_ERROR("Data which veswap sent is invalid");
		retval_to_cmd = -ECANCELED;
		free(request_info);
		goto hndl_return;
	}
	memcpy(&target_pids, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = swap_pid_check(target_pids);
	if (retval != 0) {
		retval_to_cmd = -ECANCELED;
		free(request_info);
		goto hndl_return;
	}

	pid_num = target_pids.process_num;
	for (i = 0; i < pid_num; i++) {
		pid = vedl_host_pid(VE_HANDLE(0),
				pti->cred.pid, target_pids.pid[i]);
		if (pid <= 0) {
			VEOS_ERROR("Conversion of target_pid to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" target pid: %d"
					" error: %s",
					pti->cred.pid,
					target_pids.pid[i],
					strerror(errno));
			continue;
		}
		ve_task = find_ve_task_struct(pid);
		if (ve_task == NULL) {
			VEOS_DEBUG("VE task with pid %d not found", pid);
			continue;
		}

		group_leader = ve_task->group_leader;
		pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");
		veos_operate_all_ve_task_lock(group_leader, LOCK);
		/* Check whether ptraced is true */
		if (ve_task->ptraced) {
			VEOS_DEBUG("ptraced is true, pid is %d", pid);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			put_ve_task_struct(ve_task);
			continue;
		}

		/* Check process */
		retval = check_process_for_swap(pti, ve_task);
		if (retval != 0) {
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
			put_ve_task_struct(ve_task);
			continue;
		}

		request_info->pid_array[valid_pid_num] = pid;
		valid_pid_num++;
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		pthread_mutex_lock_unlock(&(ve_task->p_ve_mm->
			thread_group_mm_lock), UNLOCK,
			"Failed to release thread_group_mm_lock");
		put_ve_task_struct(ve_task);
	}
	request_info->pid_array[valid_pid_num] = PPS_END_OF_PIDS;

	retval_to_cmd = veos_ve_swapin_req(request_info->pid_array);

	free(request_info);
hndl_return:

	/* Send the response back to RPM command */
	VEOS_DEBUG("Send the response back %d to RPM command", retval_to_cmd);
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0,
					retval_to_cmd);
	if (retval == -1) {
		VEOS_ERROR("Failed send the response back to RPM command");
	}
hndl_return1:
	VEOS_TRACE("Out %s", __func__);
	return retval;
}

/**
 * @brief Handles the VE_SWAP_STATUSINFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @note If Request is invalid, return value for veswap command is -errno, and
 *       ve_swap_status_info doesn't have ANY VALID DATA.
 *       If Request is valid, and a VE process is invalid, return value for
 *       veswap command is 0, and corresponding ve_swap_status_struct has
 *       + pid           : PID from request.
 *       + proc_state    : -1
 *       + proc_substate : -errno
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ve_swapstatusinfo_req(struct veos_thread_arg *pti)
{
	int worker_retval, i, ret;
	int command_retval = 0;
	ProtobufCBinaryData rpm_pseudo_msg = {};
	struct ve_swap_pids pids;
	struct ve_task_struct *tsk, *tmp;
	struct ve_task_struct *group_leader = NULL;
	struct ve_swap_status_info swap_stat_array = {};
	struct ve_swap_status_struct *swap_status;

	VEOS_TRACE("In %s", __func__);

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		worker_retval = -1;
		goto hndl_return1;
	}
	rpm_pseudo_msg = (((PseudoVeosMessage *)
					(pti->pseudo_proc_msg))->pseudo_msg);
	if (rpm_pseudo_msg.len != sizeof(struct ve_swap_pids)) {
		VEOS_ERROR("Data which veswap sent is invalid");
		command_retval = -ECANCELED;
		goto hndl_return;
	}
	memcpy(&pids, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	ret = swap_pid_check(pids);
	if (ret != 0) {
		command_retval = -ECANCELED;
		goto hndl_return;
	}
	VEOS_DEBUG("VE_SWAP_STATUSINFO request for %d processes is received",
							pids.process_num);

	swap_stat_array.len = pids.process_num;
	for (i = 0; i < pids.process_num; i++) {
		swap_status = &(swap_stat_array.ve_swap_status[i]);
		swap_status->pid = vedl_host_pid(VE_HANDLE(0),
					pti->cred.pid, pids.pid[i]);
		if (swap_status->pid <= 0) {
			VEOS_ERROR("Conversion of target_pid to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" pids.pid[%d]: %d"
					" error: %s",
					pti->cred.pid,
					i, pids.pid[i],
					strerror(errno));
			swap_status->proc_state = -1;
			swap_status->proc_substate = -errno;
			continue;
		}
		pids.pid[i] = swap_status->pid;
		tsk = find_ve_task_struct(pids.pid[i]);
		if (tsk == NULL) {
			VEOS_ERROR("tsk %d is not found",
					pids.pid[pids.process_num - 1]);
			swap_status->proc_state = P_INVAL;
			swap_status->proc_substate = -ESRCH;
			continue;
		}
		/* Check whether process is core dumping */
		if (is_dumping_core(tsk)) {
			swap_status->proc_state = P_INVAL;
			swap_status->proc_substate = -EPERM;
			put_ve_task_struct(tsk);
			continue;
		}
		ret = check_process_for_swap(pti, tsk);
		if (ret != 0) {
			swap_status->proc_state = P_INVAL;
			swap_status->proc_substate = ret;
			put_ve_task_struct(tsk);
			continue;
		}

		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");

		group_leader = tsk->group_leader;
		veos_operate_all_ve_task_lock(group_leader, LOCK);

		/* Check whether pid is tid of child thread */
		if (is_child_tid(tsk)) {
			VEOS_DEBUG("%d is child tid", pids.pid[i]);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
						thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
			swap_status->proc_state = P_INVAL;
			swap_status->proc_substate = -ESRCH;
			put_ve_task_struct(tsk);
			continue;
		}

		swap_status->proc_state = group_leader->ve_task_state;
		swap_status->proc_substate = group_leader->sstatus;
		if (group_leader->ptraced) {
			swap_status->proc_state = P_INVAL;
			swap_status->proc_substate = -EPERM;
		} else {
			list_for_each_entry(tmp, &(group_leader->thread_group),
								thread_group) {
				if (tmp->ptraced) {
					swap_status->proc_state = P_INVAL;
					swap_status->proc_substate = -EPERM;
				} else if (tmp->sstatus == INVALID) {
					swap_status->proc_substate = INVALID;
				}
			}
		}
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");
		put_ve_task_struct(tsk);
	}

hndl_return:
	worker_retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
					(uint8_t *)&swap_stat_array,
					sizeof(struct ve_swap_status_info),
					command_retval);
hndl_return1:
	VEOS_TRACE("Out %s", __func__);
	return worker_retval;
}

/**
 * @brief Handles the VE_SWAP_NODEINFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ve_swapnodeinfo_req(struct veos_thread_arg *pti)
{
	int worker_retval, i;
	int command_retval = 0;
	struct ve_swap_node_info swap_node_info = {0};
	struct ve_node_struct *vnode = VE_NODE(0);
	unsigned long long node_swap_sz = 0;
	bool is_file_flag = true;
	bool is_mem_flag = true;

	VEOS_TRACE("In %s", __func__);

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		worker_retval = -1;
		goto hndl_return1;
	}
	VEOS_DEBUG("VE_SWAP_NODEINFO request received");

	swap_node_info.node_num = vnode->node_num;
	if (!veos_check_pps_enable()) {
		command_retval = -ENOTSUP;
		goto hndl_return;
	}

	if (vnode->pps_mp == NULL) {
		VEOS_DEBUG("PPS mem mode is off");
		is_mem_flag = false;
	}

	if (vnode->pps_file_offset == NULL) {
		VEOS_DEBUG("PPS file mode is off");
		is_file_flag = false;
	}

	/* calculate swapped memory */
	if (is_mem_flag) {
		pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock),
					LOCK,
					"Failed to acquire PPS buddy lock");
	}

	if (is_file_flag) {
		pthread_mutex_lock_unlock(
				&(vnode->pps_file_offset->buddy_mempool_lock),
				LOCK,
				"Failed to acquire PPS file buddy lock");
	}
	for (i = 0; i < vnode->numa_count; i++) {
		if (is_mem_flag)
			node_swap_sz += vnode->pps_mp_used[i];
		if (is_file_flag)
			node_swap_sz += vnode->pps_file_used[i];
	}
	if (is_file_flag) {
		pthread_mutex_lock_unlock(
				&(vnode->pps_file_offset->buddy_mempool_lock),
				UNLOCK,
				"Failed to release PPS file buddy lock");
	}
	if (is_mem_flag) {
		pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock),
					UNLOCK,
					"Failed to release PPS buddy lock");
	}
	VEOS_DEBUG("node_num : %d, node_swap_sz : %llu",
			swap_node_info.node_num, node_swap_sz);
	swap_node_info.node_swapped_sz = node_swap_sz;

hndl_return:
	worker_retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
					(uint8_t *)&swap_node_info,
					sizeof(struct ve_swap_node_info),
					command_retval);
hndl_return1:
	VEOS_TRACE("Out %s", __func__);
	return worker_retval;
}

/**
 * @brief get the swapped memory size of VE process.
 *
 * @param[in] tsk Pointer of source VE task struct
 * @param[out] swapped_sz Pointer to contain the swapped memory size
 *		of VE process
 *
 * @return None.
 *
 * @note Acquire thread_group_mm_lock before invoking this.
 */
static void veos_get_swapped_size(struct ve_task_struct *tsk,
				unsigned long long *swapped_sz)
{
	struct list_head *p = NULL, *n = NULL;
	struct ve_swapped_virtual *tmp = NULL;
	size_t tmp_swapped_sz = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	int refcount = 0;
	struct ve_page **ve_pages = vnode->ve_pages;

	VEOS_TRACE("In %s", __func__);
	list_for_each_safe(p, n, &(tsk->p_ve_mm->swapped_pages)) {

		tmp = list_entry(p, struct ve_swapped_virtual, pages);
		if ((tmp->kind == PPS_VIRT_ATB) || (tmp->kind == PPS_VIRT_DMAATB)) {
			if (tmp->phy->pno != -1) {
				refcount = tmp->phy->ref_cnt
					 + ve_pages[tmp->phy->pno]->ref_count;
			} else {
				refcount = tmp->phy->ref_cnt;
			}

			tmp_swapped_sz += tmp->phy->pgsz/refcount;
			VEOS_DEBUG("count swapped_sz (%ld), kind (%d)",
					tmp->phy->pgsz/tmp->phy->ref_cnt, tmp->kind);
		} else {
			VEOS_ERROR("page kind is (%d) not DMAATB or ATB",tmp->kind);
		}
	}

	*swapped_sz = tmp_swapped_sz;
	VEOS_DEBUG("swapped_sz is %llu", *swapped_sz);

	VEOS_TRACE("Out %s", __func__);
}
/**
 * @brief get the swapped memory size of VE process..
 * @note The ve_task_lock of struct ve_task_struct is acquired in advance.
 *
 * @param[in] tsk Pointer of source VE task struct
 * @param[out] swapped_sz Pointer to contain the swapped memory size
 *		of VE process
 *
 * @return 0 on success, -errno on failure.
 */
static int veos_get_swappable_size(struct ve_task_struct *tsk,
				unsigned long long *swappable_sz)
{
	pgno_t pgno;
	int dir = 0, ent = 0;
	int retval = 0, ret = 0;
	size_t tmp_swapped_sz = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	int refcount = 0;

	VEOS_TRACE("In %s", __func__);

	/*  dmaatb calculate */
	for (dir = vnode->nr_avail_cores; dir < DMAATB_DIR_NUM; dir++) {
		if (!ps_isvalid(&(tsk->p_ve_mm->dmaatb.dir[dir])))
			continue;

		VEOS_DEBUG("DIR[%d] : 0x%lx", dir,
				tsk->p_ve_mm->dmaatb.dir[dir].data);
		for (ent = 0; ent < DMAATB_ENTRY_MAX_SIZE; ent++) {
			if (pg_gettype(&(tsk->p_ve_mm->
				dmaatb.entry[dir][ent])) != VE_ADDR_VEMAA)
				continue;

			pgno = pg_getpb(&(tsk->p_ve_mm->dmaatb.entry[dir][ent]),
									PG_2M);
			if ((pgno == PG_BUS) || (pgno == 0))
				continue;

			ret = is_ve_page_swappable(pgno, vnode);
			if (ret != 0)
				continue;

			VEOS_DEBUG("ENT[%d][%d] : 0x%lx ", dir, ent,
						VE_PAGE(vnode, pgno)->pgsz);
			if (VE_PAGE(vnode, pgno)->swapped_info != NULL) {
				refcount = VE_PAGE(vnode, pgno)->ref_count
					 + VE_PAGE(vnode, pgno)->swapped_info->ref_cnt;
			} else {
				refcount = VE_PAGE(vnode, pgno)->ref_count;
			}
			if (refcount != 0) {
				tmp_swapped_sz +=
					(VE_PAGE(vnode, pgno)->pgsz) / refcount;
				refcount = 0;
			}
		}
	}

	/*  atb calculate */
	for (dir = 0; dir < ATB_DIR_NUM; dir++) {
		if (!ps_isvalid(&(tsk->p_ve_mm->atb[0].dir[dir])))
			continue;

		VEOS_DEBUG("DIR[%d] : 0x%lx", dir,
				tsk->p_ve_mm->atb[0].dir[dir].data);
		for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
			pgno = pg_getpb(&(tsk->p_ve_mm->atb[0].entry[dir][ent]),
									PG_2M);
			if ((pgno == PG_BUS) || (pgno == 0))
				continue;

			ret = is_ve_page_swappable(pgno, vnode);
			if (ret != 0)
				continue;

			VEOS_DEBUG("ENT[%d][%d] : 0x%lx ", dir, ent,
						VE_PAGE(vnode, pgno)->pgsz);
			if (VE_PAGE(vnode, pgno)->swapped_info != NULL) {
				refcount = VE_PAGE(vnode, pgno)->ref_count
					 + VE_PAGE(vnode, pgno)->swapped_info->ref_cnt;
			} else {
				refcount = VE_PAGE(vnode, pgno)->ref_count;
			}
			if (refcount != 0) {
				tmp_swapped_sz +=
					(VE_PAGE(vnode, pgno)->pgsz) / refcount;
				refcount = 0;
			}
		}
	}
	*swappable_sz = tmp_swapped_sz;
	VEOS_DEBUG("swappable_sz : %llu ", *swappable_sz);

	VEOS_TRACE("Out %s", __func__);
	return retval;
}
/**
 * @brief Handles the VE_SWAP_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_ve_swapinfo_req(struct veos_thread_arg *pti)
{
	int worker_retval, i, ret;
	int command_retval = 0;
	ProtobufCBinaryData rpm_pseudo_msg = {};
	struct ve_swap_pids pids;
	struct ve_task_struct *tsk, *tmp;
	struct ve_task_struct *group_leader = NULL;
	struct ve_swap_info swap_info = {};
	struct ve_swap_struct *swap_status;
	unsigned long long *p_swapped_sz, *p_swappable_sz;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("In %s", __func__);

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		worker_retval = -1;
		goto hndl_return1;
	}
	rpm_pseudo_msg = (((PseudoVeosMessage *)
					(pti->pseudo_proc_msg))->pseudo_msg);
	if (rpm_pseudo_msg.len != sizeof(struct ve_swap_pids)) {
		VEOS_ERROR("Data which veswap sent is invalid");
		command_retval = -ECANCELED;
		goto hndl_return;
	}
	memcpy(&pids, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	ret = swap_pid_check(pids);
	if (ret != 0) {
		command_retval = -ECANCELED;
		goto hndl_return;
	}
	VEOS_DEBUG("VE_SWAP_INFO request for %d processes is received",
							pids.process_num);

	swap_info.len = pids.process_num;
	for (i = 0; i < pids.process_num; i++) {
		swap_status = &(swap_info.ve_swap[i]);
		swap_status->pid = vedl_host_pid(VE_HANDLE(0),
					pti->cred.pid, pids.pid[i]);
		if (swap_status->pid <= 0) {
			VEOS_ERROR("Conversion of target_pid to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" pids.pid[%d]: %d"
					" error: %s",
					pti->cred.pid,
					i, pids.pid[i],
					strerror(errno));
			swap_status->proc_state = -1;
			swap_status->proc_substate = -errno;
			continue;
		}
		pids.pid[i] = swap_status->pid;
		tsk = find_ve_task_struct(pids.pid[i]);
		if (tsk == NULL) {
			VEOS_ERROR("tsk %d is not found",
						pids.pid[i]);
			swap_status->proc_state = -1;
			swap_status->proc_substate = -ESRCH;
			continue;
		}
		/* Check whether process is core dumping */
		if (is_dumping_core(tsk)) {
			swap_status->proc_state = -1;
			swap_status->proc_substate = -EPERM;
			put_ve_task_struct(tsk);
			continue;
		}
		ret = check_process_for_swap(pti, tsk);
		if (ret != 0) {
			swap_status->proc_state = -1;
			swap_status->proc_substate = ret;
			put_ve_task_struct(tsk);
			continue;
		}

		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), LOCK,
				"Failed to acquire thread_group_mm_lock");

		group_leader = tsk->group_leader;
		veos_operate_all_ve_task_lock(group_leader, LOCK);

		/* Check whether pid is tid of child thread */
		if (is_child_tid(tsk)) {
			VEOS_DEBUG("%d is child tid", pids.pid[i]);
			veos_operate_all_ve_task_lock(group_leader, UNLOCK);
			pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
						thread_group_mm_lock), UNLOCK,
					"Failed to release thread_group_mm_lock");
			swap_status->proc_state = -1;
			swap_status->proc_substate = -ESRCH;
			put_ve_task_struct(tsk);
			continue;
		}
		swap_status->proc_state = group_leader->ve_task_state;
		swap_status->proc_substate = group_leader->sstatus;
		if (group_leader->ptraced) {
			swap_status->proc_state = -1;
			swap_status->proc_substate = -EPERM;
		} else {
			list_for_each_entry(tmp, &(group_leader->thread_group),
								thread_group) {
				if (tmp->ptraced) {
					swap_status->proc_state = -1;
					swap_status->proc_substate = -EPERM;
				} else if (tmp->sstatus == INVALID) {
					swap_status->proc_substate = INVALID;
				}
			}
		}
		veos_operate_all_ve_task_lock(group_leader, UNLOCK);
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->
				thread_group_mm_lock), UNLOCK,
				"Failed to release thread_group_mm_lock");

		p_swapped_sz = &(swap_status->swapped_sz);
		p_swappable_sz = &(swap_status->swappable_sz);

		/* get swapped memory size*/
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
				LOCK, "Failed to acquire thread_group_mm_lock");
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
				LOCK, "Failed to acquire ve_pages_node_lock");
		veos_get_swapped_size(tsk, p_swapped_sz);

		VEOS_DEBUG("swapped_sz is %llu", swap_status->swapped_sz);

		/* get swappable memory size*/
		ret = veos_get_swappable_size(tsk, p_swappable_sz);
		pthread_mutex_lock_unlock(&(vnode->ve_pages_node_lock),
			UNLOCK, "Failed to release  ve_pages_node_lock");
		pthread_mutex_lock_unlock(&(tsk->p_ve_mm->thread_group_mm_lock),
			UNLOCK, "Failed to release thread_group_mm_lock");
		if (ret != 0) {
			VEOS_ERROR("tsk %d is can't get swappable_sz",
						pids.pid[i]);
		}
		VEOS_DEBUG("swappable_sz is %llu", swap_status->swappable_sz);
		put_ve_task_struct(tsk);
	}

hndl_return:
	worker_retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
					(uint8_t *)&swap_info,
					sizeof(struct ve_swap_info),
					command_retval);
hndl_return1:
	VEOS_TRACE("Out %s", __func__);
	return worker_retval;
}

/**
 * @brief Handler of 'veswap -n'.
 *        This function tells current non-swappable memory size of specified
 *        processes to 'veswap -n'.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return Positive value on Success, -1 on failure.
 */
int
rpm_handle_ve_get_cns_req(struct veos_thread_arg *pti)
{
	int worker_retval, i, ret;
	int command_retval = 0;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct ve_swap_pids pids;
	struct ve_task_struct *tsk;
	struct ve_cns_info cns_info;
	pid_t pid;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("Data which veswap sent is not found");
		worker_retval = -1;
		goto hndl_return;
	}
	rpm_pseudo_msg = (((PseudoVeosMessage *)
					(pti->pseudo_proc_msg))->pseudo_msg);
	if (rpm_pseudo_msg.len != sizeof(struct ve_swap_pids)) {
		VEOS_ERROR("Data which veswap sent is invalid");
		command_retval = -ECANCELED;
		goto hndl_send_ack;
	}
	memcpy(&pids, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	ret = swap_pid_check(pids);
	if (ret != 0) {
		command_retval = -ECANCELED;
		goto hndl_send_ack;
	}
	memset(&cns_info, 0, sizeof(struct ve_cns_info));
	VEOS_DEBUG("VE_SWAP_GET_CNS request for %d processes is received",
							pids.process_num);

	for (i = 0; i < pids.process_num; i++) {
		pid = vedl_host_pid(VE_HANDLE(0), pti->cred.pid, pids.pid[i]);
		if (pid <= 0) {
			cns_info.info[i].ns = -errno;
			cns_info.info[i].pid = pids.pid[i];
			VEOS_DEBUG("PID conversion failed, host: %d"
				"pids.pid[%d]: %d error: %s",
				pti->cred.pid, i, pids.pid[i], strerror(errno));
			continue;
		}
		cns_info.info[i].pid = pid;
		VEOS_DEBUG("VE_SWAP_GET_CNS, pid : %d -vedl_host_pid()-> %d",
							pids.pid[i], pid);
		tsk = find_ve_task_struct(pid);
		if (tsk == NULL) {
			VEOS_ERROR("VE_SWAP_GET_CNS : tsk %d is not found", pid);
			cns_info.info[i].ns = -ESRCH;
			continue;
		} else if (is_dumping_core(tsk)) {
			VEOS_ERROR("VE_SWAP_GET_CNS : tsk %d is dumping", pid);
			cns_info.info[i].ns = -EPERM;
		} else if ((ret = check_process_for_swap(pti, tsk)) != 0) {
			VEOS_ERROR("VE_SWAP_GET_CNS : tsk %d is invalid", pid);
			cns_info.info[i].ns = ret;
		} else {
			cns_info.info[i].ns = veos_pps_get_cns(tsk, pid);
			VEOS_DEBUG("pid : %d, ns : %ld",
				   cns_info.info[i].pid, cns_info.info[i].ns);
		}
		put_ve_task_struct(tsk);
	}

hndl_send_ack:
	worker_retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
						(uint8_t *)&cns_info,
						sizeof(struct ve_cns_info),
						command_retval);
hndl_return:
	VEOS_TRACE("Exiting");
	return worker_retval;
}

/**
 * @brief Handles "RPM_QUERY" request from RPM commmand.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return negative value on failure.
 */
int veos_rpm_hndl_old_cmd_req(struct veos_thread_arg *pti)
{
	int retval = -EINVAL;

	VEOS_TRACE("Entering");
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, retval);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles "RPM_QUERY_COMPT" request from RPM commmand.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int veos_rpm_hndl_cmd_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int rpm_subcmd = -1;
	pid_t host_pid = -1, namespace_pid = -1;
	char *version = NULL;
	PseudoVeosMessage *req_msg = NULL;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	/* Fetch the RPM sub command ID */
	rpm_subcmd = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		veos_sub_cmd_id;
	req_msg = (PseudoVeosMessage *)pti->pseudo_proc_msg;

	if (rpm_subcmd == -1) {
		version = malloc(req_msg->veos_version.len + 1);
		if (!version) {
			retval = -errno;
			VEOS_CRIT("Internal Memory allocation failed");
			VEOS_DEBUG("Malloc failed: %s",	strerror(errno));
			/* Send the failure response back to RPM command */
			retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
					NULL, 0, retval);
			goto hndl_return;
		}
		memset(version, '\0', req_msg->veos_version.len + 1);
		memcpy(version, req_msg->veos_version.data,
				req_msg->veos_version.len);
		retval = version_compare(VERSION_STRING, version);
		VEOS_DEBUG("VEOS version: %s, Received version: %s",
				VERSION_STRING, version);
		if (retval == -1) {
			VEOS_ERROR("Version compatibility error");
			retval = -EINVAL;
		}
		/* Send the failure response back to RPM command */
		retval = veos_rpm_send_cmd_ack(pti->socket_descriptor,
				NULL, 0, retval);
		goto hndl_return;
	}

	namespace_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Convert namespace pid to host pid */
	if ((rpm_subcmd != VE_GET_RUSAGE) &&
		(rpm_subcmd != VE_PIDSTAT_INFO) &&
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->has_ve_pid &&
		namespace_pid > 0) {
		host_pid = vedl_host_pid(VE_HANDLE(0),
				pti->cred.pid, namespace_pid);
		if (host_pid <= 0) {
			VEOS_ERROR("Conversion of namespace to host"
					" pid fails");
			VEOS_DEBUG("PID conversion failed, host: %d"
					" namespace: %d"
					" error: %s",
					pti->cred.pid,
					namespace_pid,
					strerror(errno));
			retval = -errno;

			/* Send the failure response back to RPM command */
			retval = veos_rpm_send_cmd_ack(
					pti->socket_descriptor,
					NULL, 0, retval);
			goto hndl_return;
		}
		((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid = host_pid;
	}

	/* Invoke the command specific function */
	VEOS_DEBUG("rpm_subcmd is %d", rpm_subcmd);
	switch (rpm_subcmd) {
	case VE_GETPRIORITY:
		VEOS_DEBUG("RPM request: GETPRIORITY");
		retval = rpm_handle_getpriority_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SETPRIORITY:
		VEOS_DEBUG("RPM request: SETPRIORITY");
		retval = rpm_handle_setpriority_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_CHECKPID:
		VEOS_DEBUG("RPM request: CHECKPID");
		retval = rpm_handle_checkpid_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_MEM_INFO:
		VEOS_DEBUG("RPM request: MEM_INFO");
		retval = rpm_handle_mem_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_MAP_INFO:
		VEOS_DEBUG("RPM request: MAP_INFO");
		retval = rpm_handle_map_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_PIDSTAT_INFO:
		VEOS_DEBUG("RPM request: PIDSTAT_INFO");
		retval = rpm_handle_pidstat_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_PIDSTATM_INFO:
		VEOS_DEBUG("RPM request: PIDSTATM_INFO");
		retval = rpm_handle_pidstatm_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_PIDSTATUS_INFO:
		VEOS_DEBUG("RPM request: PIDSTATUS_INFO");
		retval = rpm_handle_pidstatus_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_LOAD_INFO:
		VEOS_DEBUG("RPM request: LOAD_INFO");
		retval = rpm_handle_load_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_STAT_INFO:
		VEOS_DEBUG("RPM request: VE_STAT_INFO");
		retval = rpm_handle_stat_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_GET_RUSAGE:
		VEOS_DEBUG("RPM request: GET_RUSAGE");
		retval = rpm_handle_get_rusage_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SCHED_GET_SCHEDULER:
		VEOS_DEBUG("RPM request: SCHED_GET_SCHEDULER");
		retval = rpm_handle_sched_get_scheduler_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SCHED_SET_SCHEDULER:
		VEOS_DEBUG("RPM request: SCHED_SET_SCHEDULER");
		retval = rpm_handle_sched_set_scheduler_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SCHED_GET_PARAM:
		VEOS_DEBUG("RPM request: SCHED_GET_PARAM");
		retval = rpm_handle_sched_get_param_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_GET_PRIORITY_MAX:
		VEOS_DEBUG("RPM request: GET_PRIORITY_MAX");
		retval = rpm_handle_get_priority_max_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_GET_PRIORITY_MIN:
		VEOS_DEBUG("RPM request: GET_PRIORITY_MIN");
		retval = rpm_handle_get_priority_min_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SET_AFFINITY:
		VEOS_DEBUG("RPM request: SET_AFFINITY");
		retval = rpm_handle_set_affinity_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_GET_AFFINITY:
		VEOS_DEBUG("RPM request: GET_AFFINITY");
		retval = rpm_handle_get_affinity_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_PRLIMIT:
		VEOS_DEBUG("RPM request: PRLIMIT");
		retval = rpm_handle_prlimit_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_ACCTINFO:
		VEOS_DEBUG("RPM request: ACCTINFO");
		retval = rpm_handle_acctinfo_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_CREATE_PROCESS:
		VEOS_DEBUG("RPM request: CREATE_PROCESS");
		retval = rpm_handle_create_process_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SHM_RMLS:
		VEOS_DEBUG("RPM request : IPCS/IPCRM");
		retval = rpm_handle_ipc_rmls_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_GET_REGVALS:
		VEOS_DEBUG("RPM request : GET_REGVALS");
		retval = rpm_handle_get_regvals_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_NUMA_INFO:
		VEOS_DEBUG("RPM request : VE_NUMA_INFO");
		retval = rpm_handle_numa_info_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_DEL_DUMMY_TASK:
		VEOS_DEBUG("RPM request : VE_DEL_DUMMY_TASK");
		retval = rpm_handle_delete_dummy_task_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_OUT:
		VEOS_DEBUG("RPM request : VE_SWAP_OUT");
		retval = rpm_handle_ve_swapout_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_IN:
		VEOS_DEBUG("RPM request : VE_SWAP_IN");
		retval = rpm_handle_ve_swapin_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_STATUSINFO:
		VEOS_DEBUG("RPM request : VE_SWAP_STATUSINFO");
		retval = rpm_handle_ve_swapstatusinfo_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_NODEINFO:
		VEOS_DEBUG("RPM request : VE_SWAP_NODEINFO");
		retval = rpm_handle_ve_swapnodeinfo_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_INFO:
		VEOS_DEBUG("RPM request : VE_SWAP_INFO");
		retval = rpm_handle_ve_swapinfo_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_SWAP_GET_CNS:
		VEOS_DEBUG("RPM request : VE_SWAP_GET_CNS");
		retval = rpm_handle_ve_get_cns_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_VEOSCTL_GET_PARAM:
		VEOS_DEBUG("RPM request: VE_VEOSCTL_GET_PARAM");
		retval = rpm_handle_veosctl_get_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_VEOSCTL_SET_PARAM:
		VEOS_DEBUG("RPM request: VE_VEOSCTL_SET_PARAM");
		retval = rpm_handle_veosctl_set_req(pti);
		if (0 > retval) {
			VEOS_ERROR("Query request failed");
			goto hndl_return;
		}
		break;
	case VE_RPM_INVALID:
		VEOS_ERROR("Invalid query request failed");
		retval = -1;

		/* Send the failure response back to RPM command */
		retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
				0, retval);
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	if(version)
		free(version);
	VEOS_TRACE("Exiting");
	return retval;
}

