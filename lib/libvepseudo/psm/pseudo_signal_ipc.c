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
#include "pseudo_signal_ipc.h"
#include "pseudo_veos.pb-c.h"
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
	int retval = -1;
	void *buf;
	ssize_t pseudo_msg_len;

	PseudoVeosMessage ve_signal_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_signal_req_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_signal_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
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
 * @brief Sends "SIGRETURN REQ" to veos
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns a positive value.
 */
int pseudo_psm_send_sigreturn_req(int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage ve_sigret_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_sigret_req.pseudo_veos_cmd_id = SIGRETURN_REQ;

	ve_sigret_req.has_pseudo_pid = true;
	ve_sigret_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_sigret_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_sigret_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
			  pseudo_msg_len);
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
	int retval = -1;
	PseudoVeosMessage ve_sigaction_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_sigaction_req_msg;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_sigaction_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
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
 * @brief Waits for the acknowledgment of "SIGACTION REQ" from veos
 *	which will ensure that veos has set the action for the signal.
 *
 * @param[out] old_act Stores the old action os the signal received from veos
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return On failure, returns -1 and on success, returns any positive value.
 */
int pseudo_psm_recv_sigaction_ack(struct sigaction *old_act, int veos_sock_fd)
{
	ret_t retval = -1;
	char buff[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buff, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sigaction ack from PSM failed\n");
		goto hndl_error;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
						 retval,
						 (const uint8_t *)buff);
	if (NULL == pseudo_msg) {
		retval = -1;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack failed %ld\n",
				retval);
		goto hndl_error;
	}

	/* Check message for SIGACTION ACK*/
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SIGACTION ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received SIGACTION ACK\n");
			retval = pseudo_msg->syscall_retval;
			memcpy(old_act, pseudo_msg->pseudo_msg.data,
			       pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
int pseudo_psm_recv_sigreturn_ack(int veos_sock_fd)
{
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sigreturn ack from PSM failed\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack failed %ld\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check message for SIGRETURN ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"SIGRETURN ACK Failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SIGRETURN ACK Received Successfully\n");
			retval = pseudo_msg->syscall_retval;
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Request veos to set new signal alternate stack
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 * @param[in] sigalt_req New signal stack information
 *
 * @return: On failure, returns -1 and on success, returns any positive value
 */
int pseudo_psm_send_setnew_sas(int veos_sock_fd,
		struct ve_sigalt_info *sigalt_req)
{
	int retval = -1;
	PseudoVeosMessage new_sas_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData ve_new_sas_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&new_sas_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
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
 * @brief Waits for an acknowledgment for "SET NEW SAS" request
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
	int retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			(void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"newsas ack from PSM failed\n");
		return -1;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval
			, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack failed:%d\n",
				retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for NEW SAS ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM NEW SAS ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PSEUDO received NEW SAS ACK\n");
		retval = pseudo_msg->syscall_retval;
		memcpy(sigalt_ack, pseudo_msg->pseudo_msg.data,
		       pseudo_msg->pseudo_msg.len);
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
int pseudo_psm_send_sigprocmask_req(sigset_t *newset,
		int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage sigprocmask_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");

	sigprocmask_req.pseudo_veos_cmd_id = SIGPROCMASK_REQ;

	sigprocmask_req.has_pseudo_pid = true;
	sigprocmask_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_info.data = (uint8_t *)newset;
	pseudo_info.len = sizeof(sigset_t);

	sigprocmask_req.has_pseudo_msg = true;
	sigprocmask_req.pseudo_msg = pseudo_info;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigprocmask_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&sigprocmask_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				pseudo_msg_len);
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
 * @brief Waits for acknowledgment of "SIGPROCMASK REQ" request.
 *	It also retrieves the old signal mask stored at veos.
 *
 * @param[out] oldset Stores the retrieved old signal mask
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_sigprocmask_ack(sigset_t *oldset, int veos_sock_fd)
{
	int retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
			buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sigprocmask ack from PSM failed\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
			retval, (const uint8_t *)buf);
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack failed: %d\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check for SIGPROC MASK  ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SIGPROC MASK ACK receive "
					"failed:%ld\n",
					pseudo_msg->syscall_retval);
			retval = pseudo_msg->syscall_retval;
			goto hndl_return;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PSEUDO received SIGPROC MASK ACK\n");
		retval = pseudo_msg->syscall_retval;
		if (pseudo_msg->has_pseudo_msg)
			memcpy(oldset, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
	ssize_t pseudo_msg_len;
	ProtobufCBinaryData pseudo_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		retval = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&hndl_excep_req,
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
 * @brief Request veos to fetch blocked pending signal list
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return: On failure, returns -1 and on success, returns any positive value
 */
int pseudo_psm_send_sigpending_req(int veos_sock_fd)
{
	int retval = -1;
	PseudoVeosMessage sigpending_req = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	sigpending_req.pseudo_veos_cmd_id = SIGPENDING_REQ;

	sigpending_req.has_pseudo_pid = true;
	sigpending_req.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&sigpending_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&sigpending_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
				 pseudo_msg_len);
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
 * @brief Waits for acknowledgment of "SIGPENDING REQ" request from veos.
 *
 * @param[out] veos_set Stores the set of pending signal information
 * @param[in] veos_sock_fd Descriptor used to communicate with veos
 *
 * @return Return 0 on success and negative value on failure.
 */
int pseudo_psm_recv_sigpending_ack(sigset_t *veos_set, int veos_sock_fd)
{
	int retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sigpending ack from PSM failed\n");
		goto hndl_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack failed:%d\n",
				retval);
		retval = -1;
		goto hndl_return;
	}

	/* Check for SIGPENDING  ACK */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM SIGPENDING ACK receive failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PSEUDO received SIGPENDING ACK\n");
			retval = pseudo_msg->syscall_retval;
			memcpy(veos_set, pseudo_msg->pseudo_msg.data,
					pseudo_msg->pseudo_msg.len);
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
	ret_t retval = -1;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				     (void *)&buf, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "SIGSUSPEND_REQ ack not received\n");
		goto hndl_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL,
					 retval, (const uint8_t *)(&buf));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "pseudo_veos_message__unpack failed:%ld\n",
			  retval);
		retval = -1;
		goto hndl_return;
	}
	/* Check message for PSM   */
	if (pseudo_msg->has_syscall_retval) {
		if (pseudo_msg->syscall_retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				  "PSM SIGSUSPEND REQ failed\n");
			retval = pseudo_msg->syscall_retval;
		} else {
			retval = pseudo_msg->syscall_retval;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				  "PSEUDO received ack for SIGSUSPEND_REQ\n");
		}
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
	int retval = -1;
	PseudoVeosMessage ve_sigsuspend_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_sigsuspend_req_msg;
	void *buf;
	size_t pseudo_msg_len;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "malloc for structure packing failed.\n");
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_sigsuspend_req,
							buf)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pack failed pseudo_msg_len : %ld\n",
			  pseudo_msg_len);
		goto hndl_return;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
				     pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
			  retval);
		retval = -1;
	}

hndl_return:
	free(buf);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
