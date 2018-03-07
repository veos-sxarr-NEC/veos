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
#include "libved.h"
#include "pseudo_veos_soc.h"
#include "pseudo_psmg_ipc.h"
#include "pseudo_veos.pb-c.h"
#include "velayout.h"

/**
* @brief This function sends new VE process intimation to PSM.
*
* @param[in] veos_sock_fd Descriptor used to communicate with PSM
* @param[in] ve_proc new VE process creation information
*
* @return On failure, returns -1 and on success, returns any positive value
*/
int pseudo_psm_send_new_ve_process(int veos_sock_fd, struct new_ve_proc ve_proc)
{
	int retval = -1;
	PseudoVeosMessage new_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData new_ve_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed\n",
				strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&new_ve_proc,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 * @return Returns -1 on failure and any positive value on success.
 */
int64_t pseudo_psm_send_schedule_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_schedule_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf = NULL;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				" Retruning failure\n");
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_schedule_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
* @return Returns -1 on failure and a positive value on success.
*/
int64_t pseudo_psm_recv_schedule_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage *ve_schedule_ack;
	void *buf = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				" Retruning failure\n");
		goto malloc_error;
	}

	buf = malloc(MAX_PROTO_MSG_SIZE);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for structure unpacking failed.\n");
		retval = -errno;
		goto malloc_error;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM schedule acknowledgment not received\n");
	} else {
		/* Unpack the structure */
		ve_schedule_ack = pseudo_veos_message__unpack(NULL, retval,
						      (const uint8_t *)(buf));
		if (NULL == ve_schedule_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack "
					"failed %ld\n", retval);
			retval = -1;
			goto hndl_return;
		}

		/* Check message for SCHEDULE failure */
		if (ve_schedule_ack->has_syscall_retval) {
			if (-1 == ve_schedule_ack->syscall_retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"Failed to receive "
						"SCHEDULE ACK\n");
				retval = ve_schedule_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"SCHEDULE ACK\n");
				retval = ve_schedule_ack->syscall_retval;
			}
		}
			pseudo_veos_message__free_unpacked(ve_schedule_ack,
					NULL);
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t pseudo_psm_block_syscall_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_block_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

       /* prepare request to be sent to PSM */
	ve_block_req.pseudo_veos_cmd_id = BLOCK;

	ve_block_req.has_pseudo_pid = true;
	ve_block_req.pseudo_pid = syscall(SYS_gettid);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Sending block for pid: %d\n",
			ve_block_req.pseudo_pid);
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_block_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_block_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t pseudo_psm_recv_block_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;


	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM BLOCK ACK receive failed\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed %ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for PSM GET BLOCK ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET BLOCK ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received BLOCK ACK "
					"for pid %ld\n", syscall(SYS_gettid));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Function sends UNBLOCK System Call request to VEOS.
*
*	Function internally invokes pseudo_veos_send_cmd() to send the
*	Unblock system call request to VEOS.
*
* @param[in] veos_sock_fd Socket descriptor for communication with VEOS.
*
* @return -1 on FAILURE , non-negative integer on SUCCESS.
*/
int64_t pseudo_psm_un_block_syscall_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_unblock_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	/* prepare request to be sent to PSM */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_unblock_req.pseudo_veos_cmd_id = UNBLOCK;

	ve_unblock_req.has_pseudo_pid = true;
	ve_unblock_req.pseudo_pid = syscall(SYS_gettid);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Sending unblock for pid: %d\n",
			ve_unblock_req.pseudo_pid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_unblock_req);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_unblock_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Function receives Unblock System Call ACK from VEOS.
*
*	Function internally invokes pseudo_veos_recv_cmd() to receive the
*	Unblock system call ACK from VEOS.
*
* @param[in] veos_sock_fd Socket Descriptor used for commnication with VEOS.
*
* @return -1 on FAILURE , non-negative integer on SUCCESS.
*/
int64_t pseudo_psm_recv_un_block_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM UNBLOCK ACK receive failed\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed %ld\n",
				 retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for GET UNBLOCK ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET UNBLOCK ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received "
					"UNBLOCK ACK for pid %ld\n",
					syscall(SYS_gettid));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Function communicates with VEOS for notifying the unblock system
* call request.
*
*	Function internally invokes "pseudo_psm_un_block_syscall_req" request
*	for communication with VEOS.
*	Function receives the Unblock system call acknowledgement from VEOS by
*	invoking "pseudo_psm_recv_un_block_ack".
*
* @return -1 on FAILURE , non-negative integer on SUCCESS.
*/
int64_t un_block_syscall_req_ve_os(void)
{
	int veos_sock_fd;
	ret_t retval = -1;

	/* Inform veos of blocking system call completion */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}

	/* Send UN BLOCK to veos */
	retval = pseudo_psm_un_block_syscall_req(veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send un block request\n");
	} else {
		/* Wait for UNBLOCK ACK from veos */
		retval = pseudo_psm_recv_un_block_ack(veos_sock_fd);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"UNBLOCK ACK not received\n");
		}
	}
	close(veos_sock_fd);

hndl_return:
	return retval;
}

/**
* pseudo_psm_set_syscall_return_req: Sends request to veos to set the
*				system call return value.
*
* @param veos_sock_fd: Descriptor used for commnication with veos
* @param syscall_ret: Contains the return value of system call.
*
* @return: On failure, returns -1 and on success, returns any positive value.
*/
int pseudo_psm_set_syscall_return_req(int veos_sock_fd, uint64_t reg_num,
		uint64_t syscall_ret)
{

	int retval = -1;
	PseudoVeosMessage set_ve_reg = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* prepare request to be sent to PSM */
	set_ve_reg.pseudo_veos_cmd_id = SET_REGVAL;

	set_ve_reg.has_pseudo_pid = true;
	set_ve_reg.pseudo_pid = syscall(SYS_gettid);

	set_ve_reg.has_syscall_retval = 1;
	set_ve_reg.syscall_retval = syscall_ret;

	pseudo_info.data = (uint8_t *)&reg_num;
	pseudo_info.len = sizeof(reg_num);

	set_ve_reg.has_pseudo_msg = true;
	set_ve_reg.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&set_ve_reg);
	buf = malloc(pseudo_msg_len);
	if (buf == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Malloc fails: %s\n", strerror(errno));
		retval = -errno;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&set_ve_reg,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
* pseudo_psm_recv_syscall_return_ack: This function will wait for the
* acknowledgment from veos which will ensure that veos has set the
* system call return value for VE process.
*
* @param veos_sock_fd: Descriptor used for commnication with veos.
*
* @return: On failure, returns -1 and on success, returns any positive value.
*/
int pseudo_psm_recv_syscall_return_ack(int veos_sock_fd)
{
	int64_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM schedule acknowledgment not received\n");
			  goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
				retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed %ld\n",
			  retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for SET RETURN ACK*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SET RETURN ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSM SET RETURN ACK received\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	return retval;
}
/**
* vedl_return_systemcall: This function will prepare request to be
* sent to veos to set the system call return value for the VE process.
*
* @param retval: Contains system call return value.
*
* @return: On failure, returns -1 and on success, returns any positive value.
*/
int ve_set_ve_reg(uint64_t reg_num, uint64_t syscall_ret)
{
	int retval = -1;
	int veos_sock_fd;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"socket creation failed.\n");
		retval = -1;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Setting retval %ld using veos for PID %ld\n",
			syscall_ret, syscall(SYS_gettid));
	retval = pseudo_psm_set_syscall_return_req(veos_sock_fd,
						reg_num, syscall_ret);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Failed to send set syscall request to PSM\n");
		goto hndl_return;
	} else {
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_syscall_return_ack(veos_sock_fd);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SET RETURN ACK not received\n");
			goto hndl_return;
		}
	}
	close(veos_sock_fd);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int64_t pseudo_psm_send_set_tidaddr_req(int veos_sock_fd,
		uint64_t set_tid_addr)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_set_tid_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData set_tid_ve_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for structure packing failed\n");
		retval = -errno;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_set_tid_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM which will
 * ensure that PSM has set the clear_child_tid for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
int64_t pseudo_psm_recv_set_tidaddr_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage *ve_set_tid_ack;
	char buf[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)buf,
			MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM set_tid_address ack not received\n");
	} else {
		/* Unpack the structure */
		ve_set_tid_ack = pseudo_veos_message__unpack(NULL, retval,
				(const uint8_t *)(buf));
		if (NULL == ve_set_tid_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack "
					"failed %ld\n",
					retval);
			retval = -1;
			goto hndl_return;
		}

		/* Check message for SET TID ADDR ACK */
		if (ve_set_tid_ack->has_syscall_retval) {
			if (ve_set_tid_ack->syscall_retval < 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					  "SET TID ADDR ACK receive failed\n");
				retval = ve_set_tid_ack->syscall_retval;
			} else {
				retval = ve_set_tid_ack->syscall_retval;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					  "PSM SET TID ADDR ACK received\n");
			}
		}
		pseudo_veos_message__free_unpacked(ve_set_tid_ack, NULL);
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
* @return On failure, returns -1 and on success, returns a positive value.
*/
int64_t pseudo_psm_send_clone_req(int veos_sock_fd,
		struct pseudo_ve_clone_info ve_clone_info,
		pid_t parent_pid) {
	ret_t retval = -1;
	PseudoVeosMessage ve_clone_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData clone_ve_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				" Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	if (parent_pid < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(parent_pid)."
				" Retruning failure\n");
		retval = -1;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_clone_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len :%ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
			  retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function sends fork() request to PSM
 *
 * @param[in] syscall_name syscall call name
 * @param[in] fork_info fork information of the VE process
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ret_t pseudo_psm_send_fork_req(char *syscall_name,
		struct pseudo_ve_clone_info fork_info,
		int veos_sock_fd)
{

	ret_t retval = -1;
	PseudoVeosMessage ve_fork_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData fork_ve_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Populating Request message for fork\n");
	/* Populate Pseudo<->PSM fork() request information
	 * structure
	 */
	ve_fork_req.pseudo_veos_cmd_id = FORK_VE_PROC;

	ve_fork_req.has_pseudo_pid = true;
	ve_fork_req.pseudo_pid = getppid();

	fork_ve_proc_msg.len = sizeof(struct pseudo_ve_clone_info);
	fork_ve_proc_msg.data = (uint8_t *)&fork_info;

	ve_fork_req.has_pseudo_msg = true;
	ve_fork_req.pseudo_msg = fork_ve_proc_msg;


	/* Pack ve_fork_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_fork_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_fork_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Send delete request to PSM
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[in] clean_all_threads 0 for exit and 1 for exit_group system call
 * @param[in] exit_code VE process exit code
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ret_t pseudo_psm_send_delete_ve_proc_req(int veos_sock_fd,
					int clean_all_threads,
					int exit_code)
{
	ret_t retval = -1;
	PseudoVeosMessage delete_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData delete_ve_proc_msg;
	struct ve_exit_req exit_req;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Popuate DELETE VE process message */
	delete_ve_proc.pseudo_veos_cmd_id = DEL_VE_PROC;

	delete_ve_proc.has_pseudo_pid = true;
	delete_ve_proc.pseudo_pid = syscall(SYS_gettid);


	exit_req.clean_all_thread = clean_all_threads;
	exit_req.exit_code = exit_code;

	delete_ve_proc_msg.len = sizeof(struct ve_exit_req);
	delete_ve_proc_msg.data = (uint8_t *)&exit_req;

	delete_ve_proc.has_pseudo_msg = true;
	delete_ve_proc.pseudo_msg = delete_ve_proc_msg;

	/* Pack delete_ve_proc before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&delete_ve_proc);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&delete_ve_proc,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int pseudo_psm_recv_delete_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage *delete_ack;
	char buf[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "PSM delete acknowledgment not received\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"PSM delete acknowledgment received\n");

		/* Unpack the structure */
		delete_ack = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(buf));
		if (NULL == delete_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack "
					"fail %ld\n", retval);
			retval = -1;
			goto hndl_return;
		}

		/* Check message for DELETE ACK */
		if (delete_ack->has_syscall_retval) {
			if (delete_ack->syscall_retval >= 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"DEL_VE_PROC ACK\n");
				retval = delete_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"PSEUDO failed to receive "
						"DEL_VE_PROC ACK\n");
				retval = delete_ack->syscall_retval;
			}
		}
		pseudo_veos_message__free_unpacked(delete_ack, NULL);
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* pseudo_psm_send_start_ve_proc_req: This function sends start ve request
* to PSM. PSM will schedule the VE process after this.
*
* @param context_info: Context information of the VE process
* @param veos_sock_fd: Descriptor used to communicate with PSM
*
* @return:  On failure, returns -1 and on success, returns any positive value
*/
int pseudo_psm_send_start_ve_proc_req(struct ve_context_info *context_info,
		int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage start_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData start_ve_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	/* Popuate START VE process message */
	start_ve_proc.pseudo_veos_cmd_id = START_VE_REQ;

	start_ve_proc.has_pseudo_pid = true;
	start_ve_proc.pseudo_pid = getpid();

	start_ve_proc_msg.len = sizeof(struct ve_context_info);
	start_ve_proc_msg.data = (uint8_t *)context_info;

	start_ve_proc.has_pseudo_msg = true;
	start_ve_proc.pseudo_msg = start_ve_proc_msg;

	/* Pack start_ve_proc before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&start_ve_proc);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&start_ve_proc,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}
	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
* @return Value greater than or equal to 0 on success, -1 on failure.
*/
int pseudo_psm_recv_start_ve_proc(int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage *pseudo_msg;
	char buff[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd, buff,
			MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM START VE PROC receive failed\n");
		goto hndl_return;
	} else {
		/* Unpack the structure */
		pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
				(const uint8_t *)(&buff));
		if (NULL == pseudo_msg) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"unpack failed\n");
			retval = -1;
			goto hndl_return;
		}
	}
	/* Check message for START VE PROC*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"START VE PROC Failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"START VE PROC Received "
					"Successfully\n");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* pseudo_psm_recv_clone_ack: This function will wait for the acknowledgement
* from PSM which will ensure that PSM has done the cloning work for VE side.
*
* @param veos_sock_fd: Descriptor used to communicate with PSM.
* @param clone_response_rcvd: structure containing core_id, node_id and return
*				value to be returned
*/
int64_t pseudo_psm_recv_clone_ack(int veos_sock_fd,
		struct clone_response *clone_response_rcvd)
{
	ret_t retval = -1;
	PseudoVeosMessage *clone_ack;
	char buf[MAX_PROTO_MSG_SIZE];
	struct ve_proc_info *clone_proc_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				" Retruning failure\n");
		retval = -1;
		goto hndl_return;
	}

	if (NULL == clone_response_rcvd) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(clone_response_rcvd)."
				" Retruning failure\n");

		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM clone acknowledgment not received\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"PSM clone acknowledgment received\n");

		/* Unpack the structure */
		clone_ack = pseudo_veos_message__unpack(NULL, retval,
							(const uint8_t *)(buf));
		if (NULL == clone_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"unpack failed\n");
			retval = -1;
			goto hndl_return;
		}

		clone_proc_info = (struct ve_proc_info *)
			((clone_ack->pseudo_msg).data);
		/* Check message for CLONE ACK */
		if (clone_ack->has_syscall_retval) {
			if (clone_ack->syscall_retval >= 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"CLONE_VE_PROC\n");
				clone_response_rcvd->core_id = clone_proc_info->core_id;
				clone_response_rcvd->node_id = clone_proc_info->node_id;
				clone_response_rcvd->offset = clone_proc_info->offset;
				retval = clone_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"CLONE_VE_PROC failed\n");
				retval = clone_ack->syscall_retval;
			}
			pseudo_veos_message__free_unpacked(clone_ack, NULL);
		}
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgement from PSM
 * which will ensure that PSM has successfully created child VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns core num of the
 *		core on which child VE process will be scheduled.
 */
int pseudo_psm_recv_fork_ack(int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage *fork_ack;
	char buf[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM FORK ACK receive failed\n");
	else {
		/* Unpack the structure */
		fork_ack = pseudo_veos_message__unpack(NULL, retval,
						       (const uint8_t *)(buf));
		if (NULL == fork_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack fail%d\n",
					retval);
			retval = -1;
			goto hndl_return;
		}

		/* Check message for FORK ACK */
		if (fork_ack->has_syscall_retval) {
			if (0 <= fork_ack->syscall_retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"FORK_VE_PROC\n");
				/* syscall_retval contains the child_core_id */
				retval = fork_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"failed to received "
						"FORK_VE_PROC\n");
				retval = fork_ack->syscall_retval;
			}
			pseudo_veos_message__free_unpacked(fork_ack, NULL);
		}
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
* @return:  On failure, returns -1 and on success, returns any positive value.
*/
int pseudo_psm_recv_load_binary_req(int veos_sock_fd,
		int *ve_core_id,
		int *ve_node_id)
{
	int retval = -1;
	PseudoVeosMessage *ld_binary_req;
	struct new_proc_info new_ve_proc;
	char buff[MAX_PROTO_MSG_SIZE];

	 VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd, buff,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PSM LOAD BINARY REQ receive failed\n");
	else {
		/* Unpack the structure */
		ld_binary_req = pseudo_veos_message__unpack(NULL, retval,
						    (const uint8_t *)(&buff));
		if (NULL == ld_binary_req) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"unpack failed\n");
			retval = -1;
			goto hndl_error;
		}

		if (ld_binary_req->has_syscall_retval) {
			if (0 <= ld_binary_req->syscall_retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"LOAD_BINARY_ACK\n");
				retval = ld_binary_req->syscall_retval;
				memcpy(&new_ve_proc,
						((PseudoVeosMessage *)
					 (ld_binary_req->pseudo_msg).data),
					(ld_binary_req->pseudo_msg).len);
				*ve_core_id = new_ve_proc.core_id;
				*ve_node_id = new_ve_proc.node_id;
			} else {
				retval = ld_binary_req->syscall_retval;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to receive "
						"LOAD_BINARY_ACK\n");
			}
		}
			pseudo_veos_message__free_unpacked(ld_binary_req, NULL);
	}

hndl_error:
	 VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t block_syscall_req_ve_os(void)
{
	int veos_sock_fd;
	ret_t retval = -1;

	/* Inform veos of blocking system call */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -1;
		goto hndl_return;
	}

	/* Send BLOCKING system call to veos */
	retval = pseudo_psm_block_syscall_req(veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send blocking system call "
				"request\n");
	} else {
		/* Wait for BLOCK ACK from veos */
		retval = pseudo_psm_recv_block_ack(veos_sock_fd);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"BLOCK_ACK not received\n");
		}
	}
	close(veos_sock_fd);

hndl_return:
	 VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}


/**
* @brief Request veos to halt cores.
*
*	Sends halt core request to veos.
*
* @param[in] veos_sock_fd Descriptor used to communicate with PSM.
* @param[in] core_flag	1 : single core halt request and
*			0 : all cores halt request.
* @param[in] pid PID of the VE process generating the request.
*
* @return Value greater than or equal to 0 on success, -1 on failure.
*/
int64_t pseudo_psm_halt_core_req(int veos_sock_fd,
				int core_flag,
				pid_t pid)
{
	ret_t retval = -1;
	PseudoVeosMessage core_halt_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData core_halt_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)"
				"Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	if (0 != core_flag && 1 != core_flag) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(core_flag)"
				" Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	if (pid < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(pid)"
				"Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	/* prepare request to be sent to PSM */
	core_halt_req.pseudo_veos_cmd_id = HALT_CORE;

	core_halt_req.has_pseudo_pid = true;
	core_halt_req.pseudo_pid = pid;

	core_halt_proc_msg.len = sizeof(core_flag);
	core_halt_proc_msg.data = (uint8_t *)&core_flag;

	core_halt_req.has_pseudo_msg = true;
	core_halt_req.pseudo_msg = core_halt_proc_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&core_halt_req);
	/* Pack core_halt_req before sending */
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&core_halt_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Waits for acknowledgment of "HALT CORE" request from veos.
*
*	This function will wait for the acknowledgment from veos which
*	will ensure that requested  VE core(s) are halted.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos.
*
* @return Returns 0 on success and a negative value on failure.
*/
int64_t pseudo_psm_recv_core_halt_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage *halt_core_ack;
	char buf[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				" Retruning failure\n");
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"CORE HALTED not received\n");
	} else {
		/* Unpack the structure */
		halt_core_ack = pseudo_veos_message__unpack(NULL, retval,
						    (const uint8_t *)(buf));
		if (NULL == halt_core_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack "
					"failed %ld\n",
					retval);
			retval = -1;
			goto hndl_return;
		}

		if (halt_core_ack->has_syscall_retval) {
			if (0 <= halt_core_ack->syscall_retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"HALT CORE ACK\n");
				retval = halt_core_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to receive "
						"HALT CORE ACK\n");
				retval = halt_core_ack->syscall_retval;
			}
		}
			pseudo_veos_message__free_unpacked(halt_core_ack, NULL);
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Request veos to start cores.
*	Sends request to veos to start the halted cores.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos.
* @param[in] core_flag	1 : single core start request and
*			0 : all cores start request.
* @param[in] pid PID of the process currently assigned to the
*		VE core to be started.
*
* @return Returns 0 on success and a negative value on failure.
*/
int64_t pseudo_psm_core_start_req(int veos_sock_fd,
		int core_flag, pid_t pid)
{
	ret_t retval = -1;
	PseudoVeosMessage core_start_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData core_start_proc_msg;
	void *buf;
	ssize_t pseudo_msg_len;


	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				"Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	if (0 != core_flag && 1 != core_flag) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(core_flag)."
				"Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	if (pid < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(pid). Retruning failure\n");
		retval = -1;
		goto malloc_error;
	}

	/* prepare request to be sent to PSM */
	core_start_req.pseudo_veos_cmd_id =  START_CORE;

	core_start_req.has_pseudo_pid = true;
	core_start_req.pseudo_pid = pid;

	core_start_proc_msg.len = sizeof(core_flag);
	core_start_proc_msg.data = (uint8_t *)&core_flag;

	core_start_req.has_pseudo_msg = true;
	core_start_req.pseudo_msg = core_start_proc_msg;

	/* Pack core_start_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&core_start_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&core_start_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
* @brief Waits for acknowledgment of "START CORE" request from veos.
*
*	Waits for the acknowledgment from veos which will ensure that
*	requested VE core(s) are started.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos.
*
* @return Returns 0 on success and a negative value on failure.
*/
int64_t pseudo_psm_recv_core_started_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage *core_started_ack;
	char buf[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument(veos_sock_fd)."
				" Returning failure\n");
		goto hndl_return;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM CORE STARTED receive failed\n");
	} else {
		/* Unpack the structure */
		core_started_ack = pseudo_veos_message__unpack(NULL, retval,
						       (const uint8_t *)(buf));
		if (NULL == core_started_ack) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_veos_message__unpack "
					"failed:%ld\n", retval);
			retval = -1;
			goto hndl_return;
		}

		/* Check message for CORE START failure */
		if (core_started_ack->has_syscall_retval) {
			if (0 <= core_started_ack->syscall_retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"PSEUDO received "
						"CORE STARTED ACK\n");
				retval = core_started_ack->syscall_retval;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to receive "
						"CORE STARTED ACK\n");
				retval = core_started_ack->syscall_retval;
			}
		}
		pseudo_veos_message__free_unpacked(core_started_ack, NULL);
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM for maximum
 * priority value of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On success it will return 0 else -errno or -1.
 */
ret_t pseudo_psm_send_get_priority_max_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_proc_req.pseudo_veos_cmd_id = GET_PRIOMAX_REQ;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = getpid();

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will wait for the acknowledgment from PSM which will
 * ensure that PSM has set the maximum priority for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On success it will return 0 else -errno or -1.
 */
int pseudo_psm_recv_get_priority_max_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	int priority_max = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");


	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET PRIOMAX ACK receive failed\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	if (pseudo_msg->has_syscall_retval) {
		/* Check message for GET PRIOMAX ACK */
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET PRIOMAX ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PSEUDO received GET_PRIOMAX ACK\n");
		retval = pseudo_msg->syscall_retval;
		if (pseudo_msg->has_pseudo_msg)
			memcpy(&priority_max, (pseudo_msg->pseudo_msg.data),
			       (pseudo_msg->pseudo_msg.len));
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return priority_max;
}

/**
 * @brief This function will prepare request to be sent to PSM for minimum
 * priority value of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 */
ret_t pseudo_psm_send_get_priority_min_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	ve_proc_req.pseudo_veos_cmd_id = GET_PRIOMIN_REQ;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = getpid();

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}


/**
 * @brief This function will wait for the acknowledgment from PSM which will
 * ensure that PSM has set the minimum priority value for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos.
 *
 * @return 0 on SUCCESS, negative on FAILURE
 */

int pseudo_psm_recv_get_priority_min_ack(int veos_sock_fd)
{
	int retval = -1;
	int priority_min = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET PRIOMIN ACK receive failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
						 retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed %d\n",
				retval);
		goto hndl_return;
	}

	/* Check message for GET PRIOMIN ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSEUDO GET PRIOMIN ACK receive "
					"failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received GET PRIOMIN ACK\n");
			retval = pseudo_msg->syscall_retval;
			if (pseudo_msg->has_pseudo_msg)
				memcpy(&priority_min,
						(pseudo_msg->pseudo_msg.data),
						(pseudo_msg->pseudo_msg.len));
		}
	}
		pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return priority_min;
}

/**
 * @brief This function will send getpriority request to veos
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] ve_pid pid of VE process
 *
 * @return On failure, returns -1 and on success, returns positive value
 */
ret_t pseudo_psm_send_getpriority_req(int veos_sock_fd, pid_t ve_pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_proc_req.pseudo_veos_cmd_id = GET_PRIO_REQ;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (ve_pid == 0)
		ve_pid = ve_proc_req.pseudo_pid;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ve_pid is %d\n", ve_pid);

	pseudo_info.data = (uint8_t *)&ve_pid;
	pseudo_info.len = sizeof(ve_pid);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will wait for the getpriority ack from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value
 */
int pseudo_psm_recv_getpriority_ack(int veos_sock_fd)
{
	int retval = -1;
	int priority = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET PRIO ACK receive failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%d\n",
				retval);
		goto hndl_return;
	}
	/* Check message for GET PRIO ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET PRIO ACK receive failed\n");
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received GET PRIO ACK\n");
			if (pseudo_msg->has_pseudo_msg)
				memcpy(&priority,
						(pseudo_msg->pseudo_msg.data),
						(pseudo_msg->pseudo_msg.len));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return priority;
}
/**
 * @brief This function will send setpriority request to veos
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] prio_info struct ve_prio_info contains info of VE Process
 *
 * @return On failure, returns -1 and on success, returns positive value
 *
 */
ret_t pseudo_psm_send_setpriority_req(int veos_sock_fd,
		struct ve_prio_info *prio_info)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!prio_info)
		goto malloc_error;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (prio_info->pid == 0)
		prio_info->pid = ve_proc_req.pseudo_pid;

	ve_proc_req.pseudo_veos_cmd_id = SET_PRIO_REQ;

	pseudo_info.data = (uint8_t *)prio_info;
	pseudo_info.len = sizeof(struct ve_prio_info);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
 * @brief This function will wait for the acknowledgment from veos to ensure
 * that priority is set in ve_task_struct
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and On success, returns positive value.
 */
ret_t pseudo_psm_recv_setpriority_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SET PRIO ACK receive failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for SET PRIO ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SET PRIO ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received PSM SET PRIO ACK\n");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will send getpriority request to veos
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] ve_pid PID of VE process
 *
 * @return On failure, returns -1 and on success, returns positive value
 */
ret_t pseudo_psm_send_getscheduler_req(int veos_sock_fd, pid_t ve_pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (ve_pid == 0)
		ve_pid = ve_proc_req.pseudo_pid;

	ve_proc_req.pseudo_veos_cmd_id = GET_SCHED_REQ;

	pseudo_info.data = (uint8_t *)&ve_pid;
	pseudo_info.len = sizeof(pid_t);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}
	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
* @brief This function will wait for the acknowledgment from veos for getting
* the scheduling policy
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos
*
* @return On failure, returns -1 and on success, returns positive value
*/
int pseudo_psm_recv_getscheduler_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	int policy = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET SCHED ACK receive failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				 retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for GET SCHED ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET SCHED ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received GET SCHED ACK\n");
			retval = pseudo_msg->syscall_retval;
			if (pseudo_msg->has_pseudo_msg)
				memcpy(&policy,
				       (pseudo_msg->pseudo_msg.data),
				       (pseudo_msg->pseudo_msg.len));
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return policy;
}


/**
 * @brief This function will send setscheduler request to veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] sched_info struct ve_sched_info contains info of VE Process
 *
 * @return On failure, returns -1 and on success, returns positive value
 */
ret_t pseudo_psm_send_setscheduler_req(int veos_sock_fd,
		struct ve_sched_info *sched_info)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData pseudo_info;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!sched_info)
		goto malloc_error;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (sched_info->pid == 0)
		sched_info->pid = ve_proc_req.pseudo_pid;

	ve_proc_req.pseudo_veos_cmd_id =  SET_SCHED_REQ;

	pseudo_info.data = (uint8_t *)sched_info;
	pseudo_info.len = sizeof(struct ve_sched_info);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
* @brief This function will wait for the acknowledgment from veos to ensure
* that requested policy is set in ve_task_struct.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos
*
* @return On failure, returns -1 and on success, returns positive value
*
*/
ret_t pseudo_psm_recv_setscheduler_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SET SCHED ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for SET SCHED ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SET SCHED ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received SET SCHED ACK\n");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will send request to veos for getting the scheduling
 *	 parameters
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] sched_info struct ve_sched_info contains info of VE Process.
 *
 * @return On failure, returns -1 and on success, returns positive value
 *
 */
ret_t pseudo_psm_send_sched_getparam_req(int veos_sock_fd,
		struct ve_sched_info *sched_info)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!sched_info)
		goto malloc_error;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (sched_info->pid == 0)
		sched_info->pid = ve_proc_req.pseudo_pid;

	ve_proc_req.pseudo_veos_cmd_id = GET_PARAM_REQ;


	pseudo_info.data = (uint8_t *)sched_info;
	pseudo_info.len = sizeof(struct ve_sched_info);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
 * @brief This function will wait for the scheduling parameters from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value
 */
int pseudo_psm_recv_sched_getparam_ack(int veos_sock_fd)
{
	int retval = -1;
	int rt_priority = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET PARAM ACK receive failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%d\n",
				retval);
		goto hndl_return;
	}

	/* Check message for GET PARAM ACK  */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET PARAM ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received GET PARAM ACK\n");
			retval = pseudo_msg->syscall_retval;
			if (pseudo_msg->has_pseudo_msg)
				memcpy(&rt_priority,
				       (pseudo_msg->pseudo_msg.data),
				       (pseudo_msg->pseudo_msg.len));

		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return rt_priority;
}

/**
 * @brief This function will send request to veos for setting parameters of
 * struct sched_param.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] sched_info Structure contains the information of VE process
 *
 * @return On failure, returns -1 and on success, returns positive value.
 */
ret_t pseudo_psm_send_sched_setparam_req(int veos_sock_fd,
		struct ve_sched_info *sched_info)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!sched_info)
		goto malloc_error;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	if (sched_info->pid == 0)
		sched_info->pid = ve_proc_req.pseudo_pid;

	ve_proc_req.pseudo_veos_cmd_id = SET_PARAM_REQ;


	pseudo_info.data = (uint8_t *)sched_info;
	pseudo_info.len = sizeof(struct ve_sched_info);

	ve_proc_req.has_pseudo_msg = true;
	ve_proc_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}
/**
 * @brief This function will wait for the acknowledgment from veos to ensure
 * that all parameters are set.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value.
 */
ret_t pseudo_psm_recv_sched_setparam_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SET PARAM ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for SET PARAM ACK  */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SET PARAM ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received SET PARAM ACK\n");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will send request to veos for getting the CPU and NUMA
 * node.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns positive value.
 */
ret_t pseudo_psm_send_getcpu_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_proc_req.pseudo_veos_cmd_id = GET_CPU_REQ;

	ve_proc_req.has_pseudo_pid = true;
	ve_proc_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_proc_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
 * @brief This function will wait for acknowledgement from veos.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[out] cpu_info Structure contain information for code id and node id
 *
 * @return On failure, returns -1 and on success, returns positive value.
 */
ret_t pseudo_psm_recv_getcpu_ack(int veos_sock_fd, struct ve_cpu_info *cpu_info)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!cpu_info)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET CPU ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	memcpy(cpu_info, pseudo_msg->pseudo_msg.data,
			pseudo_msg->pseudo_msg.len);

	/* Check message for GET CPU ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET CPU ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received GET CPU ACK\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
ret_t pseudo_psm_send_get_inr_req(int veos_sock_fd, pid_t ve_pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_proc_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_proc_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
* @brief This function will wait for SCHED_RR interval ack.
*
* @param[in] veos_sock_fd Descriptor used to communicate with veos
* @param[out] tp_info Contains time related paramters populated by veos
*
* @return On failure, returns -1 and on success, returns positive value.
*/
ret_t pseudo_psm_recv_get_inr_ack(int veos_sock_fd, struct timespec *tp_info)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tp_info)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"GET SCHED INTRVL ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	memcpy(tp_info, pseudo_msg->pseudo_msg.data,
			pseudo_msg->pseudo_msg.len);

	/* Check message for GET INR ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"GET SCHED INTRVL ACK "
					"receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received "
					"GET SCHED INTRVL ACK\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
ret_t pseudo_psm_send_clk_cputime_req(int veos_sock_fd,
		int type)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_clk_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData cputime;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* prepare request to be sent to PSM */
	ve_clk_req.pseudo_veos_cmd_id = CLK_CPUTIME;

	ve_clk_req.has_pseudo_pid = true;
	ve_clk_req.pseudo_pid = syscall(SYS_gettid);

	cputime.len = sizeof(type);
	cputime.data = (uint8_t *)&type;

	ve_clk_req.has_pseudo_msg = true;
	ve_clk_req.pseudo_msg = cputime;
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_clk_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_clk_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int64_t pseudo_psm_recv_clk_cputime_ack(int veos_sock_fd, struct timespec *tp)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tp)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM clk_cputime acknowledgment "
				"not received\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
						 (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for PSM clk_cputime ack  */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM clk_cputime ack failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(tp,
			       (pseudo_msg->pseudo_msg.data),
			       (pseudo_msg->pseudo_msg.len));
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"PSEUDO received clk_cputime\n");
		}
	}
		pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
int64_t pseudo_psm_send_get_rlimit_req(int veos_sock_fd,
		int resource, pid_t pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_rlimit_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_rlimit_req.pseudo_veos_cmd_id = GET_RLIMIT;

	ve_rlimit_req.has_pseudo_pid = true;
	ve_rlimit_req.pseudo_pid = pid;

	pseudo_info.len = sizeof(resource);
	pseudo_info.data = (uint8_t *)&resource;

	ve_rlimit_req.has_pseudo_msg = true;
	ve_rlimit_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rlimit_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_rlimit_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}
/**
 * @brief This function will wait for the acknowledgement from PSM and
 *	 the resource limit for VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 * @param[out] rlim Pointer to struct rlimit
e*
 * @return On failure, returns -1 and on success, returns any positive value.
 */
int64_t pseudo_psm_recv_get_rlimit_ack(int veos_sock_fd, struct rlimit *rlim)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!rlim)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET RLIMIT ack not received\n");
		retval = -1;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
			  retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET RLIMIT ack failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(rlim, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"PSEUDO received GET RLIMIT ACK\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t pseudo_psm_send_set_rlimit_req(int veos_sock_fd,
		int resource, struct rlimit rlim, pid_t pid)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_rlimit_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	struct rlimit_info rlim_info;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_rlimit_req.pseudo_veos_cmd_id = SET_RLIMIT;

	ve_rlimit_req.has_pseudo_pid = true;
	ve_rlimit_req.pseudo_pid = pid;

	rlim_info.resource = resource;
	rlim_info.rlim = rlim;

	pseudo_info.data = (uint8_t *)&rlim_info;
	pseudo_info.len = sizeof(rlim_info);

	ve_rlimit_req.has_pseudo_msg = true;
	ve_rlimit_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rlimit_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_rlimit_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t pseudo_psm_recv_set_rlimit_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SET RLIMIT ack not received\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check ack value fom veos */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SET RLIMIT ack failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"PSEUDO received SET RLIMIT\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief This function will prepare request to be sent to PSM to get affinity of
* VE process.
*
* @param[in] ve_sock_fd Descriptor used to communicate with PSM
* @param[in] pid PID of VE process
* @param[in] cpusetsize Size of cpu mask
*
* @return On failure, returns -1 and on success, returns any positive value
*/
ret_t pseudo_psm_send_getaffinity_req(int ve_sock_fd,
		pid_t pid, size_t cpusetsize)
{
	ret_t retval = -1;
	PseudoVeosMessage getaffinity_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	getaffinity_req.pseudo_veos_cmd_id = GET_AFFINITY;

	getaffinity_req.has_pseudo_pid = true;
	getaffinity_req.pseudo_pid = pid;

	pseudo_info.len = sizeof(cpusetsize);
	pseudo_info.data = (uint8_t *)&cpusetsize;

	getaffinity_req.has_pseudo_msg = true;
	getaffinity_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&getaffinity_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				 "malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&getaffinity_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(ve_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;


}
/**
 * @brief This function will wait for the acknowledgement from PSM and
 * the return value for VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 * @param[out] mask CPU mask
 *
 * @return On failure, returns -1, -2 and on success,returns retval for VE process.
 */
ret_t pseudo_psm_recv_getaffinity_ack(int ve_sock_fd, uint64_t  *mask)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!mask)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(ve_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GETAFFINITY ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "UNPACK FAIL\n");
		retval = -1;
		goto hndl_return;
	}

	/* Check ack value fom veos */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GETAFFINITY ack failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"PSEUDO received GETAFFINITY ACK\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
 */
ret_t pseudo_psm_send_setaffinity_req(int ve_sock_fd, pid_t pid, uint64_t mask)
{
	ret_t retval = -1;
	PseudoVeosMessage setaffinity_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	setaffinity_req.pseudo_veos_cmd_id = SET_AFFINITY;

	setaffinity_req.has_pseudo_pid = true;
	setaffinity_req.pseudo_pid = pid;

	pseudo_info.len = sizeof(mask);
	pseudo_info.data = (uint8_t *)&mask;

	setaffinity_req.has_pseudo_msg = true;
	setaffinity_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&setaffinity_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&setaffinity_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(ve_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;

}

/**
 * @brief This function will wait for the acknowledgement from PSM and
 * the return value for VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1, -2 and on success,returns retval for VE process.
 */
ret_t pseudo_psm_recv_setaffinity_ack(int ve_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(ve_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SETAFFINITY ACK receive failed\n");
		retval = -1;
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check ACK for GETAFFINITY*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SETAFFINITY ack failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"PSEUDO received SETAFFINITY ACK\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will prepare request to be sent to PSM to yield the
 * core of VE process.
 *
 * @param[in] ve_sock_fd Descriptor used to communicate with PSM
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 */
ret_t pseudo_psm_send_sched_yield_req(int ve_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage sched_yield_req = PSEUDO_VEOS_MESSAGE__INIT;
	ssize_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	sched_yield_req.pseudo_veos_cmd_id = SCHED_YIELD;

	sched_yield_req.has_pseudo_pid = true;
	sched_yield_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sched_yield_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&sched_yield_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(ve_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
*/
int64_t pseudo_psm_send_get_rusage_req(int veos_sock_fd, int who)
{
	ret_t retval = -1;
	PseudoVeosMessage ve_rusage_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info;
	ssize_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_rusage_req.pseudo_veos_cmd_id = GET_RUSAGE;

	ve_rusage_req.has_pseudo_pid = true;
	ve_rusage_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.len  = sizeof(who);
	pseudo_info.data = (uint8_t *)&who;

	ve_rusage_req.has_pseudo_msg = true;
	ve_rusage_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_rusage_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_rusage_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
			  retval);
			retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief This function will wait for the acknowledgement from PSM and
*	 the resource usage for VE process.
*
* @param[in] veos_sock_fd Descriptor used to communicate with PSM
* @param[out] ve_r Pointer to struct ve_rusage
*
* @return On failure, returns -1 and on success, returns any positive value
*/
int64_t pseudo_psm_recv_get_rusage_ack(int veos_sock_fd, struct ve_rusage *ve_r)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!ve_r)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM GET RUSAGE ack not received\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM GET RUSAGE acknowledgment "
					"not received\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(ve_r, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief It will prepare request to be sent to PSM to set the
 * prctl mm request of VE process.
 *
 * @param[in] veos_sock_fd: Descriptor used to communicate with PSM
 * @param[in] option: MM field to update
 * @param[in] value: value to provide to option
 *
 * @return positive value on success, -1 on failure.
 */
int64_t pseudo_psm_send_pr_set_mm_req(int veos_sock_fd, uint64_t option,
		uint64_t value)
{
	int64_t retval = -1;
	PseudoVeosMessage ve_pr_mm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info;
	struct prlimit_mm pr_mm;
	size_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_pr_mm_req.pseudo_veos_cmd_id = PRCTL_SET_MM;

	ve_pr_mm_req.has_pseudo_pid = true;
	ve_pr_mm_req.pseudo_pid = syscall(SYS_gettid);

	pr_mm.option = option;
	pr_mm.value = value;
	pseudo_info.len  = sizeof(struct prlimit_mm);
	pseudo_info.data = (uint8_t *)&pr_mm;

	ve_pr_mm_req.has_pseudo_msg = true;
	ve_pr_mm_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_pr_mm_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_pr_mm_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Sending command to PSM failed\n");

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief It will wait for the acknowledgement from PSM for
 * prctl mm request of VE process.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM
 *
 * @return positive value on success, -1 on failure.
 */
int64_t pseudo_psm_recv_pr_set_mm_ack(int veos_sock_fd)
{
	int64_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd, (void *)buf,
			MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM PR SET MM acknowledgment not received\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PRLIMT SET MM ack not received\n");
			retval = pseudo_msg->syscall_retval;
		} else
			retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief Function will send request to veos for getting information on
 * overall system statistics.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 *
 * @return positive value on success, -1 on failure.
 */
int pseudo_psm_send_sysinfo_req(int veos_sock_fd)
{
	ret_t retval = -1;
	PseudoVeosMessage sysinfo_req = PSEUDO_VEOS_MESSAGE__INIT;
	size_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	sysinfo_req.pseudo_veos_cmd_id = SYSINFO_REQ;

	sysinfo_req.has_pseudo_pid = true;
	sysinfo_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sysinfo_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&sysinfo_req,
				buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Wait for acknowledgement from VEOS for SYSINFO_REQ.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 * @param[in] vh_sysinfo pointer to struct sysinfo that will be filled by VEOS
 *
 * @return 0 value on success, -1 on failure
 */
int pseudo_psm_recv_sysinfo_ack(int veos_sock_fd, struct sysinfo *vh_sysinfo)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!vh_sysinfo)
		goto hndl_return;

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM SYSINFO_REQ ack not received\n");
		retval = -1;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SYSINFO_REQ retval "
					"received: %ld\n",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			memcpy(vh_sysinfo, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief This function will send request to veos for enabling/disabling
 * the accounting.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] path_buff Pointer to filename will be use for accounting
 *
 * @return 0 on success, -1 on failure.
 */
int pseudo_psm_send_acct_req(int veos_sock_fd, char *path_buff)
{
	ret_t retval = -1;
	PseudoVeosMessage acct_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData pseudo_info;
	size_t pseudo_msg_len;
	void *buf;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	acct_req.pseudo_veos_cmd_id = ACCT_REQ;

	acct_req.has_pseudo_pid = true;
	acct_req.pseudo_pid = syscall(SYS_gettid);

	if (NULL != path_buff) {
		pseudo_info.len  = strlen(path_buff);
		pseudo_info.data = (uint8_t *)path_buff;
		acct_req.has_pseudo_msg = true;
		acct_req.pseudo_msg = pseudo_info;
	}

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&acct_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&acct_req,
				buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
		retval = -1;
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %ld bytes\n",
				retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief This function will wait for acknowledgement from VEOS for ACCT_REQ
 * command.
 *
 * @param[in] veos_sock_fd Descriptor used to communication with veos
 *
 * @return 0 on success, -errno on failure.
 */
int pseudo_psm_recv_acct_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM ACCT_REQ ack not received\n");
		retval = -EFAULT;
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"pseudo_veos_message__unpack failed:%ld\n",
				retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Check message for ACK */
	if (pseudo_msg->has_syscall_retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM ACCT_REQ retval received: %ld\n",
				pseudo_msg->syscall_retval);
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
