#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include "libved.h"
#include "psm_main.h"
#include "psm_rpm_interfaces.h"
#include "amm_rpm_interfaces.h"
#include "pseudo_veos.pb-c.h"
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
int veos_write_buf(int socket_fd, void *buf, int max_len)
{
	size_t transferred = 0;
	size_t write_byte;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!buf)
		goto send_error;

	while ((write_byte =
		write(socket_fd, buf + transferred,
		      max_len - transferred)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Sending Command from PSM"
						" failed %s\n",
						strerror(errno));
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			  "transferred = %d, write_byte = %d\n",
			  (int)transferred, (int)write_byte);
	}

send_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return transferred;

}

/**
 * @brief Sends the success/failure response from VEOS back to RPM command.
 *
 * @param[in] veos_soc_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to populated structure by VEOS
 * @param[in] len Size of populated structure
 * @param[in] ack_ret Return value send to RPM command
 */
void veos_rpm_send_cmd_ack(int veos_soc_fd, uint8_t *buf,
		int64_t len, int64_t ack_ret)
{
	int retval = -1;
	int pack_msg_len;
	void *pack_buf;
	PseudoVeosMessage rpm_ack = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData rpm_data;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Initializing message and populating return value */
	rpm_ack.has_syscall_retval = true;
	rpm_ack.syscall_retval = ack_ret;

	if (NULL != buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Structure to send of size: %ld\n",
				len);
		rpm_ack.has_pseudo_msg = true;
		rpm_data.data = buf;
		rpm_data.len = len;
		rpm_ack.pseudo_msg = rpm_data;
	}

	pack_msg_len = pseudo_veos_message__get_packed_size(&rpm_ack);
	pack_buf = malloc(pack_msg_len);
	if (NULL == pack_buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed: %s\n",
			strerror(errno));
		goto hndl_return;
	}

	memset(pack_buf, '\0', pack_msg_len);
	if (pack_msg_len != pseudo_veos_message__pack(&rpm_ack, pack_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"veos_rpm_send_cmd_ack pack failed\n");
		goto hndl_return;
	}

	retval = veos_write_buf(veos_soc_fd, pack_buf, pack_msg_len);
	if (retval < pack_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"written:%d bytes of total:%d bytes\n",
				retval, pack_msg_len);
		goto hndl_return;
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
 * @brief Handles the VE process getpriority request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_getpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_priority_req prio_req;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priority_req from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_rpm_handle_getpriority_req(&prio_req);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fails to get priority\n");
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&prio_req,
			sizeof(struct ve_priority_req), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE process setpriority request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_setpriority_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_priority_req prio_req;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_priority_req from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&prio_req, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_rpm_handle_setpriority_req(&prio_req);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fails to set priority\n");
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_CHECKPID request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_checkpid_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Check VE pid exists or not */
	retval = psm_rpm_handle_check_pid(pid);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"psm_rpm_handle_check_pid() returns: %d\n",
			retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_MEM_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_mem_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* TODO: Need to add AMM interfaces */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_MAP_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_map_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* TODO: Need to add AMM interfaces */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_PIDSTAT_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_pidstat_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_pidstatinfo_req pidstat;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* PSM will populate it's corresponding fields of
	 * struct ve_pidstatinfo_req.
	 */
	retval = psm_rpm_handle_pidstat_req(pid, &pidstat);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PSM fail in handling pidstat req for pid:%d\n",
				pid);
		goto hndl_return;
	}

	/* TODO: AMM interface to populate rest of the field of
	 * struct ve_pidstatinfo_req.
	 */
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&pidstat,
			sizeof(struct ve_pidstatinfo_req), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* TODO: Need to add AMM interfaces */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_PIDSTATUS_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_pidstatus_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_pidstatusinfo_req pidstatus;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Populate struct ve_pidstatusinfo_req */
	retval = psm_rpm_handle_pidstatus(pid, &pidstatus);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"psm_rpm_handle_pidstatus() fails return: %d\n",
			retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&pidstatus,
			sizeof(struct ve_pidstatusinfo_req), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_LOAD_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_load_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_load_req ve_load;
	struct ve_node_struct *p_ve_node;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	p_ve_node = VE_NODE(veos_start_node_id);

	/* Populating values in struct ve_load_req */
	retval = calc_last_1_5_15_load(p_ve_node,
			&(ve_load.av_1),
			&(ve_load.av_5),
			&(ve_load.av_15));
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to calculate VE node\n");
		retval = -EFAULT;
		goto hndl_return;
	}

	ve_load.runnable = p_ve_node->nr_active;
	ve_load.total_proc = p_ve_node->num_ve_proc;
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&ve_load,
			sizeof(struct ve_load_req), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_STAT_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_stat_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_statinfo_req statinfo;
	struct ve_node_struct *p_ve_node = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	p_ve_node = VE_NODE(veos_start_node_id);

	/* PSM will populate the struct ve_statinfo_req */
	retval = psm_rpm_handle_stat_req(p_ve_node, &statinfo);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to handle rpm stat req\n");
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&statinfo,
			sizeof(struct ve_statinfo_req), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_VMSTAT_INFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_vmstat_info_req(struct veos_thread_arg *pti)
{
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return;

	/* TODO: Need to add AMM interfaces */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_GET_RUSAGE request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_get_rusage_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_get_rusage_info ve_ru;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	retval = psm_rpm_handle_get_rusage_req(pid, &ve_ru);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to get rusage for pid: %d\n",
			pid);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&ve_ru,
			sizeof(struct ve_get_rusage_info), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_GET_SCHEDULER request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_sched_get_scheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_scheduler_parameter sched_param;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Populate the struct ve_scheduler_parameter */
	retval = psm_rpm_handle_sched_get_scheduler(pid, &sched_param);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"psm_rpm_handle_sched_get_scheduler() return: %d\n",
			retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_param,
			sizeof(struct ve_scheduler_parameter), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_SET_SCHEDULER request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_sched_set_scheduler_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_scheduler_parameter sched_param;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	/* Fetch the struct ve_scheduler_parameter from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&sched_param, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	retval = psm_rpm_handle_sched_set_scheduler(pid, sched_param);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fails in setting sched parameter of pid %d\n",
				pid);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_SCHED_GET_PARAM request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_sched_get_param_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_scheduler_parameter sched_param;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Populate the struct ve_scheduler_parameter */
	retval = psm_rpm_handle_sched_get_param(pid, &sched_param);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"psm_rpm_handle_sched_get_param() fails return: %d\n",
			retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_param,
			sizeof(struct ve_scheduler_parameter), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_GET_PRIORITY_MAX request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_get_priority_max_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_sched_limit_request sched_limit;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
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
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy received: %d\n",
				sched_limit.policy);
		retval = -EINVAL;
	}

	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_limit,
			sizeof(struct ve_sched_limit_request), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_GET_PRIORITY_MIN request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_get_priority_min_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_sched_limit_request sched_limit;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
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
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy received: %d\n",
				sched_limit.policy);
		retval = -EINVAL;
	}

	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&sched_limit,
			sizeof(struct ve_sched_limit_request), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_SET_AFFINITY request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_set_affinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_sched_affinity sched_affinity;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Fetch the struct ve_sched_affinity from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&sched_affinity, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_handle_setaffinity_request(pid, sched_affinity.mask);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SET AFFINITY Fail for pid: %d\n",
				pid);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_GET_AFFINITY request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_get_affinity_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int64_t mask;
	int pid;
	struct ve_sched_affinity sched_affinity;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Fetch the struct ve_sched_affinity from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&sched_affinity, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	mask = psm_handle_getaffinity_request(pid, sched_affinity.cpusetsize);
	if (0 > mask) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"GET AFFINITY Fail for pid: %d\n",
				pid);
		retval = mask;
		goto hndl_return;
	}

	/* Set the obtained mask in struct ve_sched_affinity */
	sched_affinity.mask = mask;
	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor,
			(uint8_t *)&sched_affinity,
			sizeof(struct ve_sched_affinity),
			retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_PRLIMIT request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_prlimit_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	struct ve_prlimitinfo prlimit;
	ProtobufCBinaryData rpm_pseudo_msg;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* Fetch the struct ve_prlimitinfo from pti */
	rpm_pseudo_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&prlimit, rpm_pseudo_msg.data, rpm_pseudo_msg.len);

	retval = psm_rpm_handle_prlimit(pid, &prlimit);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"psm_rpm_handle_prlimit() fails return: %d\n",
			retval);
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, (uint8_t *)&prlimit,
			sizeof(struct ve_prlimitinfo), retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles the VE_ACCTINFO request from RPM command.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int rpm_handle_acctinfo_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int pid;
	char *acct_file = NULL;
	PseudoVeosMessage *acct_req;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pti)
		goto hndl_return1;

	acct_req = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	pid = acct_req->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Recevied ACCT_REQ request from "
			"RPM command with pid :%d\n", pid);

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

	retval = psm_rpm_handle_acct(pid, acct_file);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEOS fail to do accounting.\n");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	/* Send the response back to RPM command */
	veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
			0, retval);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles "RPM Query" request from RPM commmand.
 *
 * @param[in] pti Contains the request message received from RPM command
 *
 * @return 0 on success, -errno on failure.
 */
int veos_rpm_hndl_cmd_req(struct veos_thread_arg *pti)
{
	int retval = -1;
	int rpm_subcmd;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	/* Fetch the RPM sub command ID */
	rpm_subcmd = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		veos_sub_cmd_id;

	switch (rpm_subcmd) {
	case VE_GETPRIORITY:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_GETPRIORITY\n");
		retval = rpm_handle_getpriority_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM get priority fails!\n");
			goto hndl_return;
		}
		break;
	case VE_SETPRIORITY:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_SETPRIORITY\n");
		retval = rpm_handle_setpriority_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM set priority fails!\n");
			goto hndl_return;
		}
		break;
	case VE_CHECKPID:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_CHECKPID\n");
		retval = rpm_handle_checkpid_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_CHECKPID fails!\n");
			goto hndl_return;
		}
		break;
	case VE_MEM_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_MEM_INFO\n");
		retval = rpm_handle_mem_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_MEM_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_MAP_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_MAP_INFO\n");
		retval = rpm_handle_map_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_MAP_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_PIDSTAT_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_PIDSTAT_INFO\n");
		retval = rpm_handle_pidstat_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_PIDSTAT_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_PIDSTATM_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_PIDSTATM_INFO\n");
		retval = rpm_handle_pidstatm_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_PIDSTATM_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_PIDSTATUS_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_PIDSTATUS_INFO\n");
		retval = rpm_handle_pidstatus_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_PIDSTATUS_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_LOAD_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_LOAD_INFO\n");
		retval = rpm_handle_load_req(pti);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_LOAD_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_STAT_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_STAT_INFO\n");
		retval = rpm_handle_stat_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_STAT_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_VMSTAT_INFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_VMSTAT_INFO\n");
		retval = rpm_handle_vmstat_info_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_VMSTAT_INFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_GET_RUSAGE:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_GET_RUSAGE\n");
		retval = rpm_handle_get_rusage_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_GET_RUSAGE fails!\n");
			goto hndl_return;
		}
		break;
	case VE_SCHED_GET_SCHEDULER:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_SCHED_GET_SCHEDULER\n");
		retval = rpm_handle_sched_get_scheduler_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_SCHED_GET_SCHEDULER fails!\n");
			goto hndl_return;
		}
		break;
	case VE_SCHED_SET_SCHEDULER:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_SCHED_SET_SCHEDULER\n");
		retval = rpm_handle_sched_set_scheduler_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_SCHED_SET_SCHEDULER fails!\n");
			goto hndl_return;
		}
		break;
	case VE_SCHED_GET_PARAM:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_SCHED_GET_PARAM\n");
		retval = rpm_handle_sched_get_param_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_SCHED_GET_PARAM fails!\n");
			goto hndl_return;
		}
		break;
	case VE_GET_PRIORITY_MAX:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_GET_PRIORITY_MAX\n");
		retval = rpm_handle_get_priority_max_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_GET_PRIORITY_MAX fails!\n");
			goto hndl_return;
		}
		break;
	case VE_GET_PRIORITY_MIN:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_GET_PRIORITY_MIN\n");
		retval = rpm_handle_get_priority_min_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_GET_PRIORITY_MIN fails!\n");
			goto hndl_return;
		}
		break;
	case VE_SET_AFFINITY:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_SET_AFFINITY\n");
		retval = rpm_handle_set_affinity_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_SET_AFFINITY fails!\n");
			goto hndl_return;
		}
		break;
	case VE_GET_AFFINITY:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_GET_AFFINITY\n");
		retval = rpm_handle_get_affinity_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_GET_AFFINITY fails!\n");
			goto hndl_return;
		}
		break;
	case VE_PRLIMIT:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_PRLIMIT\n");
		retval = rpm_handle_prlimit_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_PRLIMIT fails!\n");
			goto hndl_return;
		}
		break;
	case VE_ACCTINFO:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"RPM request VE_ACCTINFO\n");
		retval = rpm_handle_acctinfo_req(pti);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"RPM VE_ACCTINFO fails!\n");
			goto hndl_return;
		}
		break;
	case VE_RPM_INVALID:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Invalid RPM sub-Command Received\n");
		retval = -1;

		/* Send the failure response back to RPM command */
		veos_rpm_send_cmd_ack(pti->socket_descriptor, NULL,
				0, retval);
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
