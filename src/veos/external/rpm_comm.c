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

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priorityinfo from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

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

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priorityinfo from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

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
		VEOS_DEBUG("Failed in checking if PID exists");
		VEOS_DEBUG("PSM check PID returned %d", retval);
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

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	struct ve_mapheader header = {0};

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;
	caller_pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

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
	retval = veos_pmap(pid, &header);
	if (0 > retval) {
		VEOS_ERROR("Populating information failed for PID: %d",
				pid);
		VEOS_DEBUG("VEOS populate mapheader struct returned %d", retval);
	} else {
		/*Change the owner of shared memory segment*/
		if (header.shmid) {
			retval = change_owner_shm(pti->cred.uid, header.shmid);
			if (retval < 0) {
				header.shmid = 0;
				VEOS_DEBUG("can't change shm segment owner");
			}
		}
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

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&pidstat, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

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
 * @return 0 on success, -1 on failure.
 */
int rpm_handle_create_process_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid = -1;
	int node_id = -1, core_id = -1;
	struct ve_task_struct *tsk = NULL;
	ProtobufCBinaryData rpm_pseudo_msg = {0};
	struct velib_create_process create_proc = {0};

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->ve_pid;

	/* Fetch the flag rpm_preserve_task data from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&create_proc, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_handle_exec_ve_process(pti, &core_id, &node_id,
			pid, "Dummy_task", false, 0, (uint64_t)0,
			0, NULL, 0, 0, true, "Dummy path");
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
	if (create_proc.flag == 2) {
		memcpy(tsk->sighand->rlim , create_proc.ve_rlim,
				sizeof(create_proc.ve_rlim));
	}

	tsk->execed_proc = true;
	tsk->rpm_preserve_task = create_proc.flag;
	tsk->pseudo_vefd = create_proc.vedl_fd;
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	retval = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, retval);
hndl_return1:
	if (tsk)
		put_ve_task_struct(tsk);
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
	size_t len = 0;

	pid_t pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	len = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg).len;

	memcpy(&shm_info, (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
				pseudo_msg).data, len);

	switch (shm_info.mode) {
	case SHMKEY:
	case SHMID:
		ret = veos_ipc_op(pid, &shm_info, NULL, NULL);
		if (ret < 0) {
			VEOS_ERROR("error while deleting shm segment with %s : %d",
					(shm_info.mode == SHMKEY) ? "SHMKEY" : "SHMID",
					shm_info.key_id);

			VEOS_DEBUG("error while deleting shm segment with %s : %d",
					(shm_info.mode == SHMKEY) ? "SHMKEY" : "SHMID",
					shm_info.key_id);
		}
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&shm_info,
			sizeof(struct ve_shm_info), ret);
		break;
	case SHM_ALL:
	case SHM_LS:
		ret = veos_ipc_op(pid, &shm_info, &header, NULL);
		if (ret < 0) {
			VEOS_ERROR("error while %s all shm segments from veos",
			(shm_info.mode == SHM_ALL) ? "deleting" : "listing");
			VEOS_DEBUG("error while %s all shm segments from veos",
			(shm_info.mode == SHM_ALL) ? "deleting" : "listing");
		} else {
			if (header.shmid) {
				ret = change_owner_shm(pti->cred.uid, header.shmid);
				if (ret < 0) {
					header.shmid = 0;
					VEOS_DEBUG("can't change owner of shm segment");
				}
			}
		}
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&header,
			sizeof(struct ve_mapheader), ret);
		break;
	case SHMID_INFO:
		ret = veos_ipc_op(pid, &shm_info, &header, NULL);
		if (ret < 0) {
			VEOS_ERROR("error while %s getting info for shm segments shmid(%d)",
				strerror(-ret), shm_info.key_id);
			VEOS_DEBUG("error while %s getting info for shm segments shmid(%d)",
				strerror(-ret), shm_info.key_id);
		} else {
			if (header.shmid) {
				ret = change_owner_shm(pti->cred.uid, header.shmid);
				if (ret < 0) {
					header.shmid = 0;
					VEOS_DEBUG("can't change owner of shm segment");
				}
			}
		}
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&header,
			sizeof(struct ve_mapheader), ret);
		break;
	case SHM_SUMMARY:
		veos_ipc_op(pid, &shm_info, NULL, &s_summary);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&s_summary,
			sizeof(struct shm_summary), ret);
		break;
	case SHMID_QUERY:
		VEOS_DEBUG("shmid(%d) query", shm_info.key_id);
		veos_key_id_query(shm_info.key_id, &key_id_valid, false);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&key_id_valid,
			sizeof(key_id_valid), ret);
		break;
	case SHMKEY_QUERY:
		VEOS_DEBUG("shmkey(%d) query", shm_info.key_id);
		veos_key_id_query(shm_info.key_id, &key_id_valid, true);
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&key_id_valid,
			sizeof(key_id_valid), ret);
		break;
	default:
		ret = -EINVAL;
		VEOS_DEBUG("No such option for ipcs/ipcrm");
		ret = veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL, 0, ret);
	}

	VEOS_TRACE("Exiting");
	return ret;
}
/**
 * @brief Handles "RPM Query" request from RPM commmand.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -1 on failure.
 */
int veos_rpm_hndl_cmd_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int rpm_subcmd = -1;

	VEOS_TRACE("Entering");

	if (!pti)
		goto hndl_return;

	/* Fetch the RPM sub command ID */
	rpm_subcmd = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		veos_sub_cmd_id;

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
	VEOS_TRACE("Exiting");
	return retval;
}
