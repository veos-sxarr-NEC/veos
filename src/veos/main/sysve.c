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
 * @file sysve.c
 * @brief Libsyve functions in VEOS side.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include "velayout.h"
#include "veos_defs.h"
#include "comm_request.h"
#include "proto_buff_schema.pb-c.h"
#include "task_mgmt.h"
#include "psm_comm.h"
#include "veos.h"
#include "pciatb_api.h"

static int veos_send_get_pci_sync_req_ack(int, uint64_t, uint64_t, int);

/**
 * @brief This function is invoked once VEOS receives "GET_PCI_SYNC" request
 * and get the setteings of PCISYAR and PCISYMR.
 *
 * @param[in] pti Pointer to the thread argument structure containing IPC data.
 *
 * @return  0 on Success, negative value on Failure.
 *
 * @retval To worker thread, -1 on IPC response Failure.
 * @retval To Pseudo Process, -EINVAL on PCISYAR / PCISYMR number or IPC request
 * argument is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
int veos_handle_get_pci_sync_req(veos_thread_arg_t *pti)
{
	int w_ret = 0;
	int p_ret = 0;
	PseudoVeosMessage *request = NULL;
	uint8_t syncnum = 0;
	uint64_t pci_val_ar = 0;
	uint64_t pci_val_mr = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/* Followin two error are caused by invalid IPC request argument. */
	request = (PseudoVeosMessage *)pti->pseudo_proc_msg;
	if (!(request->has_pseudo_msg)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Request has no massage");
		p_ret = -EINVAL;
		goto hndl_return;
	}
	if (request->pseudo_msg.data == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Request has invalid massage");
		p_ret = -EINVAL;
		goto hndl_return;
	}
	if (sizeof(syncnum) != request->pseudo_msg.len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Request has invalid size massage");
		p_ret = -EINVAL;
		goto hndl_return;
	}
	memcpy(&syncnum, request->pseudo_msg.data, request->pseudo_msg.len);

	/*
	 * veos_amm_get_pcisyar() and veos_amm_get_pcisymr() fail only when
	 * invalid register specified.
	 * */
	if (veos_amm_get_pcisyar(syncnum, &pci_val_ar) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to get the PCISYAR setting");
		p_ret = -EINVAL;
	} else if (veos_amm_get_pcisymr(syncnum, &pci_val_mr) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to get the PCISYMR setting");
		p_ret = -EINVAL;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "AR:%lu MR:%lu",
							pci_val_ar, pci_val_mr);

hndl_return:
	if (veos_send_get_pci_sync_req_ack(pti->socket_descriptor,
					pci_val_ar, pci_val_mr, p_ret)!= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Failed to veos_send_get_pci_sync_req_ack()");
		w_ret = -1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return w_ret;
}

/**
 * @brief This function sends result of "GET_PCI_SYNC" request.
 *
 * @param[in] pseudo_sock_fd Descriptor used to communicate with VEOS.
 * @param[in] pci_val_ar PCISYAR setting value.
 * @param[in] pci_val_mr PCISYMR setting value.
 * @param[in,out] ack_ret return value of "GET_PCI_SYNC" request.
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author libsysve
 */
static int veos_send_get_pci_sync_req_ack(int pseudo_sock_fd,
							uint64_t pci_val_ar,
							uint64_t pci_val_mr,
							int ack_ret)
{
	struct pcisval pci_val;
	int ret = -1;
	void *msg_buff = NULL;
	ssize_t msg_len = 0;
	ProtobufCBinaryData pci_sync_req_ack_msg;
	PseudoVeosMessage pci_sync_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	memset(&pci_val, '\0', sizeof(struct pcisval));
	memset(&pci_sync_req_ack_msg, '\0', sizeof(ProtobufCBinaryData));

	pci_sync_req_ack.has_syscall_retval = true;
	pci_sync_req_ack.syscall_retval = ack_ret;

	pci_val.pcisyar = pci_val_ar;
	pci_val.pcisymr = pci_val_mr;
	pci_sync_req_ack_msg.len = sizeof(struct pcisval);
	pci_sync_req_ack_msg.data = (uint8_t *)&pci_val;

	pci_sync_req_ack.has_pseudo_msg = true;
	pci_sync_req_ack.pseudo_msg = pci_sync_req_ack_msg;

	msg_len = pseudo_veos_message__get_packed_size(&pci_sync_req_ack);
	msg_buff = malloc(msg_len);

	if (msg_buff == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to malloc for GET_PCI_SYNC responce message buffer");
		goto hndl_return;
	}
	memset(msg_buff, '\0', msg_len);
	if (msg_len != pseudo_veos_message__pack(&pci_sync_req_ack, msg_buff)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "Failed to pack for GET_PCI_SYNC responce message");
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(pseudo_sock_fd, msg_buff, msg_len);
	if (ret < msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send GET_PCI_SYNC responce");
		goto hndl_return;
	}

	ret = 0;

hndl_return:
	free(msg_buff);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

int veos_handle_get_veos_pid_req(veos_thread_arg_t *pti)
{
	int ret = -1;
	void *msg_buff = NULL;
        ssize_t msg_len = 0;
	PseudoVeosMessage msg = PSEUDO_VEOS_MESSAGE__INIT;

        VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	msg.has_syscall_retval = true;
	msg.syscall_retval = getpid();
	msg.has_pseudo_msg = false;

	msg_len = pseudo_veos_message__get_packed_size(&msg);
        msg_buff = malloc(msg_len);
        if (msg_buff == NULL) {
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                        "Failed to malloc for GET_VEOS_PID responce message buffer");
                goto hndl_return;
        }
        memset(msg_buff, '\0', msg_len);
        if (msg_len != pseudo_veos_message__pack(&msg, msg_buff)) {
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                       "Failed to pack for GET_VEOS_PID responce message");
                goto hndl_return;
        }

        ret = psm_pseudo_send_cmd(pti->socket_descriptor, msg_buff, msg_len);
        if (ret < msg_len) {
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                                "Failed to send GET_VEOS_PID responce");
                goto hndl_return;
        }
	ret = 0;
hndl_return:
	free(msg_buff);
        VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
        return ret;
}
