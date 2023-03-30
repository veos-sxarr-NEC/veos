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
 * @file sysve_os.c
 * @brief sysve functions in pseudo process side.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <libudev.h>
#include "libved.h"
#include "libvepseudo.h"
#include <veos_arch_defs.h>
#include "veos_defs.h"
#include "sysve_os.h"
#include "comm_request.h"
#include "proto_buff_schema.pb-c.h"
#include "ve_socket.h"
#include "process_mgmt_comm.h"
#include "mm_transfer.h"
#include "handle.h"
#include "ve_swap_request.h"
#include "productinfo.h"

#define REG_MASK_ALL 0xffffffffffffffff

#define MAX_PCISYNC_REG_NUM                   3

static int ve_sys_get_pci_sync_req(int, uint8_t);
static int ve_sys_get_pci_sync_recv(int, struct pcisval *);
static int ve_sys_map_reg(uint64_t);

/**
 * @brief This function gets the setting of PCI synchronization from PCISYAR and
 * PCISYMR from VEOS.
 *
 * @param[in] handle VEOS handle of pseudo process
 * @param[in] syncnum The pair number of PCISYAR and PCISYMR (0, 1, 2, 3)
 * @param[in,out] pcisyar VEMVA of a variable to store the value gotten from
 * PCISYAR
 * @param[in,out] pcisymr VEMVA of a variable to store the value gotten from
 * PCISYMR
 *
 * @return 0 on Success, an negative error number on Failure.
 *
 * @retval -EFAULT on Pointer is invalid.
 * @retval -EINVAL on PCISYAR/PCISYMR number is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
int ve_sys_get_pci_sync(veos_handle *handle, uint8_t syncnum,
					uint64_t *pcisyar, uint64_t *pcisymr)
{
	int ret = 0;
	struct pcisval val;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");


	memset(&val, '\0', sizeof(struct pcisval));

	if (syncnum > MAX_PCISYNC_REG_NUM) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Invalid pair number was specified");
		ret = -EINVAL;
		goto hndl_return;
	}

	 VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"%dth pair was specified", syncnum);

	ret = ve_sys_get_pci_sync_req(handle->veos_sock_fd, syncnum);
	if (ret != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Failed to ve_sys_get_pci_sync_req()");
		goto hndl_return;
	}

	ret = ve_sys_get_pci_sync_recv(handle->veos_sock_fd, &val);
	if (ret != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Failed to ve_sys_get_pci_sync_recv()");
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "AR=%lu, MR=%lu",
						val.pcisyar, val.pcisymr);
	if (ve_send_data(handle, (uint64_t)pcisyar, sizeof(uint64_t),
							&(val.pcisyar)) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send the setting of PCISYAR");
		ret = -EFAULT;
	} else if (ve_send_data(handle, (uint64_t)pcisymr, sizeof(uint64_t),
							&(val.pcisymr)) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send the setting of PCISYMR");
		ret = -EFAULT;
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

/**
 * @brief This function sends "GET_PCI_SYNC" request.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 * @param[in] syncnum The pair number of PCISYAR and PCISYMR (0, 1, 2, 3).
 *
 * @return 0 on Success, -ENOMEM on insufficient memory is available.
 *
 * @internal
 *
 * @author libsysve
 */
static int ve_sys_get_pci_sync_req(int veos_sock_fd, uint8_t syncnum)
{
	int ret = 0;
	uint8_t snum = 0;
	void *msg_buff = NULL;
	ssize_t msg_len = 0;
	ProtobufCBinaryData req_syncnum_msg;
	PseudoVeosMessage req_syncnum = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	memset(&req_syncnum_msg, '\0', sizeof(ProtobufCBinaryData));

	req_syncnum.pseudo_veos_cmd_id = GET_PCI_SYNC;
	req_syncnum.has_pseudo_pid = true;
	req_syncnum.pseudo_pid = syscall(SYS_gettid);

	snum = syncnum;
	req_syncnum_msg.len = sizeof(uint8_t);
	req_syncnum_msg.data = (uint8_t *)&snum;

	req_syncnum.has_pseudo_msg = true;
	req_syncnum.pseudo_msg = req_syncnum_msg;

	msg_len = pseudo_veos_message__get_packed_size(&req_syncnum);
	msg_buff = malloc(msg_len);
	if (msg_buff == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to malloc for GET_PCI_SYNC message buffer");
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(msg_buff, '\0', msg_len);
	if (msg_len != pseudo_veos_message__pack(&req_syncnum, msg_buff)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to pack for GET_PCI_SYNC message");
		fputs("Failed to pack for GET_PCI_SYNC message\n",stderr);
		pseudo_abort();
	}

	ret = pseudo_veos_send_cmd(veos_sock_fd, msg_buff, msg_len);
	if (ret < msg_len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send GET_PCI_SYNC request");
		fputs("Failed to send GET_PCI_SYNC request\n",stderr);
		pseudo_abort();
	}

	ret = 0;

hndl_return:
	free(msg_buff);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

/**
 * @brief This function receives the result of "GET_PCI_SYNC" request.
 *
 * @param[in] veos_sock_fd Descriptor used to communicate with PSM.
 * @param[out] val Store the setting of  PCISYAR and PCISYMR.
 *
 * @return 0 on Success, -EINVAL on PCISYAR/PCISYMR number is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
static int ve_sys_get_pci_sync_recv(int veos_sock_fd, struct pcisval *val)
{
	int ret = 0;
	char buf[MAX_PROTO_MSG_SIZE];
	PseudoVeosMessage *pseudo_msg = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	memset(buf, '\0', sizeof(char) * MAX_PROTO_MSG_SIZE);

	ret = pseudo_veos_recv_cmd(veos_sock_fd, (void *)buf,
							MAX_PROTO_MSG_SIZE);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ret = %d", ret);

	if (ret < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive GET_PCI_SYNC response");
		fputs("Failed to receive GET_PCI_SYNC response\n",stderr);
		pseudo_abort();
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
						(const uint8_t *)buf);
	if (pseudo_msg == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to unpack for GET_PCI_SYNC response");
		fputs("Failed to unpack for GET_PCI_SYNC response\n",stderr);
		pseudo_abort();
	} else if (!(pseudo_msg->has_syscall_retval)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to get retval for GET_PCI_SYNC response");
		fputs("Failed to get retval for GET_PCI_SYNC response\n",stderr);
		pseudo_abort();
	}

	ret = pseudo_msg->syscall_retval;

	if (ret != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
		       "Failed to get the setting of PCISYAR, PCISYMR");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
							"retval = %d", ret);
		goto hndl_return;
	}

	if (!(pseudo_msg->has_pseudo_msg)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to get message for GET_PCI_SYNC response");
		fputs("Failed to get message for GET_PCI_SYNC response\n",stderr);
		pseudo_abort();
	}

	if (pseudo_msg->pseudo_msg.data == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to get data for GET_PCI_SYNC response");
		fputs("Failed to get data for GET_PCI_SYNC response\n",stderr);
		pseudo_abort();
	}

	if (sizeof(*val) != pseudo_msg->pseudo_msg.len) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
		       "GET_PCI_SYNC response has invalid size message");
		fputs("GET_PCI_SYNC response has invalid size message\n",stderr);
		pseudo_abort();
	}
	memcpy(val, pseudo_msg->pseudo_msg.data, pseudo_msg->pseudo_msg.len);

hndl_return:
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

/**
 * @brief This function gets fixed VEHVA mapping.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] region A region specified by macros.
 * @param[out] vehva VEMVA of a variable to store the start address in VEHVA
 * space of the specified region.
 *
 * @return 0 on Success, an negative error number on Failure.
 *
 * @retval -EINVAL on Region is invalid.
 * @retval -EFAULT on Pointer is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
int ve_sys_get_fixed_vehva(veos_handle *handle, uint64_t region,
							uint64_t *vehva)
{
	int ret = 0;
	uint64_t mapping = 0;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	ret = (*_veos_arch_ops->arch_get_fixed_vehva)(region, &mapping);
	if (ret < 0)
		return ret;

	if (ve_send_data(handle, (uint64_t)vehva, sizeof(uint64_t),
							&mapping) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				       "Failed to send fixed VEHVA mapping");
		ret = -EFAULT;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

/**
 * @brief This function sets the specified user register of the current VE core.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] reg Register specified by macros.
 * @param[in] value Value to be set to the register.
 * When VE_REGID_PSW is specified as a register, only bit 0 (advanced-off mode)
 * is set to PSM register. Other bits are ignored.
 *
 * @return 0 on Success, -EINVAL on Register is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
int ve_sys_set_user_reg(veos_handle *handle, uint64_t reg, uint64_t value)
{
	int ret = 0;
	int64_t mask = 0;
	int regid = -1;
	const char *name;

	PSEUDO_TRACE("Entering");

	regid = ve_sys_map_reg(reg);
	if ( (reg >= VE_REGID_PMC16) && (reg <= VE_REGID_PMC20)) {
		name = vedl_get_arch_class_name(handle->ve_handle);
		if(strncmp(name, "ve3", 3)) {
			regid = -1;
		}
	}

	if (regid == -1) {
		PSEUDO_ERROR("Invalid register %lu was specified", reg);
		ret = -EINVAL;
		goto hndl_return;
	}

	PSEUDO_DEBUG("reg %lu maps to regid %d", reg, regid);

	if (regid == VE_USR_PSW) {
		mask = (*_veos_arch_ops->arch_set_PSW_bitmask)();
	} else {
		mask = REG_MASK_ALL;
	}

	PSEUDO_DEBUG("reg = 0x%x, value = 0x%lx", regid, value);

	/* abort on IPC error */
	if (ve_set_user_reg(handle, regid, value, mask) != 0) {
		PSEUDO_DEBUG("Failed to set user register");
		fputs("Failed to set the user register\n",stderr);
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	} else
		PSEUDO_DEBUG("Set user register success");

hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief This function gets information from a sysfs file of current VE node.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] name A null-terminated name of sysfs file.
 * @param[out] buffer VEHVA of a buffer to store the information.
 * @param[in] size Buffer size.
 *
 * @return On Success, the number of bytes of the gotten information.
 * it excludes the null byte used to end output to string.
 * an negative error number on Failure.
 *
 * @retval -EFAULT on Pointer is invalid.
 * @retval -EINVAL on The name includes '/'.
 * @retval -ENOENT on Sysfs file does not exist.
 * @retval -EISDIR on The name is a directory's name.
 * @retval -ELOOP on The name is a symbolic link's name.
 * @retval -ENFILE on The system limit on the total number of open files has
 * been reached.
 * @retval -EMFILE on The process already has the maximum number of files open.
 * @retval -ENOMEM on Insufficient memory is available.
 * @retval -ENAMETOOLONG on The specified name is too long.
 *
 * @internal
 *
 * @author libsysve
 */
ssize_t ve_sys_get_ve_info(veos_handle *handle, char *name, char *buffer,
								size_t size)
{
	ssize_t ret;
	char *tmp_buffer = NULL;
	char filepath[PATH_MAX];
	char filename[PATH_MAX];
	ssize_t cnt = 0;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	memset(&filepath, '\0', sizeof(filepath));
	memset(&filename, '\0', sizeof(filename));

	if (name == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
							"NULL pointer");
		ret = -EFAULT;
		goto hndl_return;
	}
	ret = ve_recv_string(handle, (uint64_t)name,
					filename, sizeof(char) * PATH_MAX);
	if (ret < 0) {
		switch (ret) {
		case -1:
			ret = -errno;
			break;
		case -2:
			ret = -ENAMETOOLONG;
			break;
		case -3:
			ret = -EFAULT;
			break;
		case -4:
			ret = -ENAMETOOLONG;
			break;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Receiving string from VE failed: %s", strerror(-1 * ret));
		goto hndl_return;
	}
	if (strchr(filename, '/') != NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"The filename includes \'/\'");
		ret = -EINVAL;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "filename = %s",
								filename);

	tmp_buffer = (char *)malloc(size);
	if (tmp_buffer == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to malloc buffer for information");
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(tmp_buffer, '\0', size);

	ret = get_ve_info(handle, filename, filepath, tmp_buffer, &cnt, sizeof(filepath), size);
	if (ret != 0) {
		goto hndl_return;
	}

	if (ve_send_data(handle, (uint64_t)buffer, size, tmp_buffer) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to send %s info", filepath);
		ret = -EFAULT;
		goto hndl_return;
	}

	ret = cnt;

hndl_return:
	free(tmp_buffer);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

/**
 * @brief This function maps user register ID macro to usr_reg.
 *
 * @param[in] reg User register ID macro.
 *
 * @return usr_reg corresponding to specified user register ID macro on Success,
 * -1 on on Failure.
 *
 * @internal
 *
 * @author libsysve
 */
static int ve_sys_map_reg(uint64_t reg)
{

	int regid = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	if (reg == VE_REGID_PSW) {
		regid = VE_USR_PSW;
	} else if (reg == VE_REGID_PMMR){
		regid = VE_USR_PMMR;
	} else if (reg <= VE_REGID_PMCR3) {
		regid = VE_USR_PMCR00 + (reg - VE_REGID_PMCR0);
	} else if (reg <= VE_REGID_PMC15) {
		regid = VE_USR_PMC00 + (reg - VE_REGID_PMC0);
	} else if ( (reg >= VE_REGID_PMC16) && (reg <= VE_REGID_PMC20)) {
		regid = VE_USR_PMC16 + (reg - VE_REGID_PMC16);
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return regid;
}

/**
 * @brief This function sends a request message to VEOS and 
 *        receives a response.
 *
 * @param[in] handle 	VEOS handle of pseudo process.
 * @param[in] id 	request command ID
 * @param[in] data 	data for request command ID
 * @param[out] msg	a response message
 *
 * @return 0 on Success, an negative error number on Failure.
 *
 * @retval -EFAULT on Bad address
 * @retval -EBUSY on DMA descriptor table H has already been mapped.
 * @retval -ECANCELED on IPC message error.
 * @retval -ENOMEM on memory allocation error in malloc().
 *
 * @author libsysve
 */
int ve_request_veos(veos_handle *handle, 
		enum pseudo_veos_msg_id id,
		ProtobufCBinaryData *data,
		PseudoVeosMessage **reply_msg)
{
	int ret;
	PseudoVeosMessage msg = PSEUDO_VEOS_MESSAGE__INIT;
	PseudoVeosMessage *recv_msg;
	size_t msg_len;
	ssize_t recv_len;
	void *msg_buf;
	char recv_buf[MAX_PROTO_MSG_SIZE];
	const char *err_str = "Failed to communicate with VEOS\n";

	assert(handle != NULL);
	assert(0 <= id && id <= PSEUDO_VEOS_MAX_MSG_NUM);

	PSEUDO_TRACE("Entering");

	msg.pseudo_veos_cmd_id = id;
	msg.has_pseudo_pid = true;
	msg.pseudo_pid = syscall(SYS_gettid);
	if (data != NULL) {
		msg.has_pseudo_msg = true;
		msg.pseudo_msg = *data;
	}

	/* pack a message */
	msg_len = pseudo_veos_message__get_packed_size(&msg);
	if (msg_len == 0) {
		PSEUDO_ERROR("IPC message error(packed size)");
		fputs(err_str,stderr);
		pseudo_abort();
	}
	msg_buf = malloc(msg_len);
	if (msg_buf == NULL) {
		ret = -errno;
		PSEUDO_ERROR("Buffer allocation failed: %s", strerror(-ret));
		goto err_ret_nofree;
	}
	memset(msg_buf, 0x0, msg_len);
	ret = pseudo_veos_message__pack(&msg, msg_buf);
	if (ret <= 0) {
		PSEUDO_ERROR("IPC message error(pack)");
		fputs(err_str,stderr);
		pseudo_abort();
	}

	/* comunicate with Pseudo process */
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, msg_buf, msg_len);
	if (ret < 0) {
		PSEUDO_ERROR("IPC message error(send cmd)");
		fputs(err_str,stderr);
		pseudo_abort();
	}
	recv_len = pseudo_veos_recv_cmd(handle->veos_sock_fd, recv_buf, 
		MAX_PROTO_MSG_SIZE);
	if (recv_len < 0) {
		PSEUDO_ERROR("IPC message error(recv cmd)");
		fputs(err_str,stderr);
		pseudo_abort();
	}
	recv_msg = pseudo_veos_message__unpack(NULL, recv_len,
			(const uint8_t *)recv_buf);
	if (recv_msg == NULL) {
		PSEUDO_ERROR("IPC message error(unpack)");
		fputs(err_str,stderr);
		pseudo_abort();
	}

	ret = recv_msg->syscall_retval;
	/* set results */
	if (reply_msg != NULL) {
		*reply_msg = recv_msg;
		/* The caller function has to free "recv_msg" */
	} else {
		pseudo_veos_message__free_unpacked(recv_msg, NULL);
	}

	free(msg_buf);
err_ret_nofree:
	PSEUDO_TRACE("Exiting");
	
	return ret;
}

/**
 * @brief This function maps DMA description H to VEHVA.
 *
 * @param[in] handle 		VEOS handle of pseudo process.
 * @param[out] vehva_dmades 	VEHVA which DMA descriptor table H is mapped to
 * @param[out] vehva_dmactl 	VEHVA which DMA control register H is mapped to
 *
 * @return 0 on Success, an negative error number on Failure.
 *
 * @retval -EFAULT on Bad address
 * @retval -EBUSY on DMA descriptor table H has already been mapped.
 * @retval -ECANCELED on IPC message error.
 * @retval -ENOMEM on memory allocation error.
 *
 * @author libsysve
 */
int ve_sys_map_dmades(veos_handle *handle, uint64_t * vehva_dmades,
			uint64_t * vehva_dmactl)
{
	int ret;
	PseudoVeosMessage *reply_msg = NULL;
	struct userdma *dma;

	PSEUDO_TRACE("Entering");

	if (handle == NULL || vehva_dmades == NULL || vehva_dmactl == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s",strerror(-ret));
		goto hndl_return;
	}

	ret = ve_request_veos(handle, MAP_DMADES, NULL, &reply_msg);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to map user DMA: %s", strerror(-ret));
		goto hndl_return;
	}

	/* set results */
	if (reply_msg->has_pseudo_msg != true) {
		PSEUDO_DEBUG("The replied message from map_dmades() is broken");
		goto hndl_return;
	}
	dma = (struct userdma *)reply_msg->pseudo_msg.data;
	if (ve_send_data(handle, (uint64_t)vehva_dmades,
		sizeof(uint64_t), &dma->dmades) != 0) {
		ret = -EFAULT;
		PSEUDO_ERROR("Failed to send DMA descriptor"); 
	} else if (ve_send_data(handle, (uint64_t)vehva_dmactl,
		sizeof(uint64_t), &dma->dmactl) != 0) {
		ret = -EFAULT;
		PSEUDO_ERROR("Failed to send DMA control register"); 
	}

	pseudo_veos_message__free_unpacked(reply_msg, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief This function halts usermode DMA corrensponding to DMA descriptor H
 *        and unmaps it from VEHVA.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] vehva_dmades VEHVA which DMA descriptor table H is mapped to
 *
 * @return 0 on Success, an negative errornumber on Failure.
 *
 * @retval -EINVAL on DMA descriptor table H is not mapped
 *
 * @author libsysve
 */
int ve_sys_unmap_dmades(veos_handle *handle, uint64_t vehva_dmades)
{
	int ret;
	struct userdma dma;
	ProtobufCBinaryData data;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s",strerror(-ret));
		goto hndl_return;
	}

	data.len = sizeof(struct userdma);
	data.data = (uint8_t *)&dma;
	dma.dmades = vehva_dmades;

	ret = ve_request_veos(handle, UNMAP_DMADES, &data, NULL);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to unmap user DMA: %s", strerror(-ret));
		goto hndl_return;
	}

hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

int ve_sys_get_veos_pid(veos_handle *handle)
{
	int ret;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
                ret = -EFAULT;
                PSEUDO_ERROR("%s",strerror(-ret));
                goto hndl_return;
        }

	ret = ve_request_veos(handle, GET_VEOS_PID, NULL, NULL);;
hndl_return:
	PSEUDO_TRACE("Exiting");
        return ret;
}

/**
 * @brief Handler of ve_get_nonswappable().
 *        This function requests veos to tell maximum non-swappable memory size.
 *
 * @param [in] handle VEOS handle of pseudo process.
 * @param [in] buff Address of VE memory in which maximum non-swappable memory
 *                  size will be stored.
 * @return 0 on Success, -errno on failure.
 */
int64_t
ve_sys_get_mns(veos_handle *handle, uint64_t buff)
{
	int64_t retval = 0;
	int ret;
	PseudoVeosMessage *reply_msg = NULL;
	ProtobufCBinaryData data;
	pid_t pid = getpid();
	struct ve_ns_info_proc *ns_info;

	PSEUDO_TRACE("Entering");

	if (buff == 0) {
		retval = -EFAULT;
		goto handle_return;
	}
	data.len = sizeof(pid_t);
	data.data = (uint8_t *)&pid;

	PSEUDO_DEBUG("Request CMD_GET_MNS from %ld", syscall(SYS_gettid));
	retval = ve_request_veos(handle, CMD_GET_MNS, &data, &reply_msg);
	PSEUDO_DEBUG("VEOS return %ld against CMD_GET_MNS from %ld",
						retval, syscall(SYS_gettid));
	if (retval < 0) {
		PSEUDO_ERROR("Failed to communicate VEOS about CMD_GET_MNS");
		if (reply_msg == NULL)
			goto handle_return;
		else
			goto handle_unpacked;
	}
	if (reply_msg->has_pseudo_msg != true) {
		PSEUDO_ERROR("Responce against CMD_GET_MNS is invalid");
		retval = -ECANCELED;
		goto handle_unpacked;
	}
	ns_info = (struct ve_ns_info_proc *)reply_msg->pseudo_msg.data;

	PSEUDO_DEBUG("Send mns(%ld) to 0x%lx", ns_info->ns, buff);
	ret = ve_send_data(handle, buff, sizeof(int64_t), (void *)&ns_info->ns);
	if (ret != 0) {
		retval = -EFAULT;
		PSEUDO_ERROR("Faild to send mns %s", strerror(-ret));
	}

handle_unpacked:
	pseudo_veos_message__free_unpacked(reply_msg, NULL);

handle_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function requests veos to get the proginf information
 *
 * @param [in] handle VEOS handle of pseudo process.
 * @param [in] version Data structure version.
 * @param [in] buff buffer to store the proginf information.
 * @return 0 on Success, -errno on failure.
 */
int64_t
ve_sys_get_proginf_data(veos_handle *handle, uint64_t version, uint64_t buff)
{
	int64_t retval = 0;
	int ret;
	PseudoVeosMessage *reply_msg = NULL;
	struct proginf_v1 proginf_data;
	ProtobufCBinaryData data;
	const char *name;

	PSEUDO_TRACE("Entering");

	if (buff == 0) {
		retval = -EFAULT;
		goto handle_return;
	}
	name = vedl_get_arch_class_name(handle->ve_handle);
	if(!strncmp(name, "ve1", 3)) {
		retval = -ENOTSUP;
		goto handle_return;
	}
	PSEUDO_DEBUG("Request CMD_GET_PROGINF_DATA from %ld",
					syscall(SYS_gettid));
	data.len = sizeof(int);
	data.data = (uint8_t *)&version;
	retval = ve_request_veos(handle, CMD_GET_PROGINF_DATA,
						&data, &reply_msg);
	PSEUDO_DEBUG("VEOS return %ld against CMD_GET_PROGINF_DATA from %ld",
						retval, syscall(SYS_gettid));
	if (retval < 0) {
		PSEUDO_ERROR("Failed to communicate VEOS about CMD_GET_PROGINF_DATA");
		if (reply_msg == NULL)
			goto handle_return;
		else
			goto handle_unpacked;
	}
	if (reply_msg->has_pseudo_msg != true) {
		PSEUDO_ERROR("Responce against CMD_GET_PROGINF_DATA is invalid");
		retval = -ECANCELED;
		goto handle_unpacked;
	}
	memcpy(&proginf_data, reply_msg->pseudo_msg.data,
				sizeof(struct proginf_v1));

	ret = ve_send_data(handle, buff, sizeof(struct proginf_v1),
						&proginf_data);
	if (ret != 0) {
		retval = -EFAULT;
		PSEUDO_ERROR("Failed to send proginf data %s", strerror(-ret));
	}

handle_unpacked:
	pseudo_veos_message__free_unpacked(reply_msg, NULL);

handle_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handler of ve_set_next_thread_worker().
 *        This function requests veos to set flag wthich create next
 *        thread as worker.
 *
 * @param [in] handle VEOS handle of pseudo process.
 * @return 0 on Success, -errno on failure.
 */
int ve_sys_set_next_thread_worker(veos_handle *handle)
{
	int ret = 0;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s",strerror(-ret));
		goto hndl_return;
	}

	ret = ve_request_veos(handle, SET_NEXT_THREAD_WORKER, NULL, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handler of ve_stop_user_threads().
 *        This function set the flag which stop threads
 *        except worker thread in the process.
 *
 * @param [in] handle VEOS handle of pseudo process.
 * @return 0 on Success, -errno on failure.
 */
int ve_sys_stop_user_threads(veos_handle *handle)
{
	int ret = 0;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s", strerror(-ret));
		goto hndl_return;
	}
	ret = ve_request_veos(handle, STOP_USER_THREADS, NULL, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handler of ve_start_user_threads().
 *        This function set the flag which start threads
 *        except worker thread in the process.
 *
 * @param [in] handle VEOS handle of pseudo process.
 * @return 0 on Success, -errno on failure.
 */
int ve_sys_start_user_threads(veos_handle *handle)
{
	int ret = 0;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s", strerror(-ret));
		goto hndl_return;
	}

	ret = ve_request_veos(handle, START_USER_THREADS, NULL, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handler of ve_get_user_threads_state().
 *        This function check the flag which stop threads
 *        except worker thread in the process.
 *
 * @param [in] handle VEOS handle of pseudo process.
 *
 * @return 0 on Success, -errno on failure.
 */
int ve_sys_get_user_threads_state(veos_handle *handle)
{
	int ret = 0;

	PSEUDO_TRACE("Entering");

	if (handle == NULL) {
		ret = -EFAULT;
		PSEUDO_ERROR("%s", strerror(-ret));
		goto hndl_return;
	}

	ret = ve_request_veos(handle, GET_USER_THREADS_STATE, NULL, NULL);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return ret;
}

/**
 * @brief This function gets VE product neme from a sysfs file of current VE node and a correspondence table.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[out] name VEMVA of the buffer in VE memory to store VE product name.
 *                  VE product name will be a null-terminated string even if buffer size 
 *                  is small or equal to the size of information.
 * @param[in] size Buffer (name) size.
 *
 * @return On Success, an negative error number on Failure.
 *
 * @retval -EFAULT on Pointer is invalid.
 * @retval -EINVAL on Invalid argument.
 * @retval -ENOENT on Correspondence table file does not exist.
 * @retval -ENODEV on The product name does not exist in the correspondence table.
 * @retval -ENOMEM on Insufficient memory is available.
 *
 * @internal
 *
 * @author libsysve
 */
int ve_sys_get_ve_product_name(veos_handle *handle, char *name, size_t size)
{
	int ret = 0;
	char *tmp_buffer = NULL;
	char *model_buffer = NULL;
	char *type_buffer = NULL;
	char *model = "model";
	char *type = "type";
	char filepath[PATH_MAX];
	ssize_t cnt = 0;

	/* About 3 times <model>, <type> string */
	int model_type_size = 10;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	memset(&filepath, '\0', sizeof(filepath));

	if ((int)size <= 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Illegal argument (size_t size)");
		ret = -EINVAL;
		goto hndl_return;
	}

	if (name == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"NULL pointer");
		ret = -EFAULT;
		goto hndl_return;
	}

	tmp_buffer = (char *)malloc(size);
	if (tmp_buffer == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to malloc buffer for information");
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(tmp_buffer, '\0', size);

	model_buffer = (char *)malloc(model_type_size);
	if (model_buffer == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to malloc buffer for information");
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(model_buffer, '\0', model_type_size);

	type_buffer = (char *)malloc(model_type_size);
	if (type_buffer == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to malloc buffer for information");
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(type_buffer, '\0', model_type_size);

	ret = get_ve_info(handle, model, filepath, model_buffer, &cnt, sizeof(filepath), model_type_size);
	if (ret != 0) {
		goto hndl_return;
	}
	
	ret = get_ve_info(handle, type, filepath, type_buffer, &cnt, sizeof(filepath), model_type_size);
	if (ret != 0) {
		goto hndl_return;
	}

	ret = get_ve_product_name(model_buffer, type_buffer, tmp_buffer, size);
	if(ret != 0){
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Getting product name failed");
		goto hndl_return;
	}

	if (ve_send_data(handle, (uint64_t)name, size, tmp_buffer) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send veproduct info");
		ret = -EFAULT;
		goto hndl_return;
	}

	ret = 0;

hndl_return:
	free(tmp_buffer);
	free(model_buffer);
	free(type_buffer);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
	
}

/**
 * @brief This function gets information from a sysfs file of current VE node.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] filename A null-terminated name of sysfs file.
 * @param[out] filepath A path of sysfs file.
 * @param[out] buffer VEHVA of a buffer to store the information.
 * @param[out] cnt To store Read() return value.
 * @param[in] path_size Filepath buffer size.
 * @param[in] size Buffer size.
 *
 * @return On Success, the number of bytes of the gotten information.
 * it excludes the null byte used to end output to string.
 * an negative error number on Failure.
 *
 * @retval -EINVAL on The name includes '/'.
 * @retval -ENOENT on Sysfs file does not exist.
 * @retval -EISDIR on The name is a directory's name.
 * @retval -ELOOP on The name is a symbolic link's name.
 * @retval -ENFILE on The system limit on the total number of open files has
 * been reached.
 * @retval -EMFILE on The process already has the maximum number of files open.
 * @retval -ENAMETOOLONG on The specified name is too long.
 *
 * @internal
 *
 * @author libsysve
 */
ssize_t get_ve_info(veos_handle *handle, char *filename, char *filepath, char *buffer,
					ssize_t *cnt, size_t path_size, size_t size)
{
	ssize_t ret;
	const char *sysfs_path;
	int fd = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	sysfs_path = vedl_get_sysfs_path(handle->ve_handle);
	if (sysfs_path == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Getting sysfs path failed");
		ret = -EINVAL;
		goto hndl_return;
	}

	ret = snprintf(filepath, path_size, "%s/%s", sysfs_path, filename);
	/*  ret doesn't include null termination. */
	if (ret < 0 || ret > (path_size - 1)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"filename is too long");
		ret = -ENAMETOOLONG;
	goto hndl_return;

	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "filepath = %s",
								filepath);

	errno = 0;
	fd = open(filepath, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		ret = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to open %s.%s", filepath, strerror(errno));
		goto hndl_return;
	}

	errno = 0;
	*cnt = read(fd, buffer, size - 1);
	if (*cnt < 0) {
		ret = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to read %s.%s", filepath, strerror(errno));
		goto hndl_close;
	}

	ret = 0;

hndl_close:
	if (close(fd) != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to close file descriptor: %s", strerror(errno));
		ret = -errno;
	}

hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return ret;
}

