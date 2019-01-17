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
 * @file  mm_transfer.c
 * @brief Handles commands sent to PSEUDO PROCESS for memory transfer.
 *
 *	This contains the memory transfer functions that are invoked based
 *	on the request from the pseudo process.
 *
 * @internal
 * @author AMM
 */

#include <stdlib.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdbool.h>
#include "comm_request.h"
#include "ve_hw.h"
#include "dma.h"
#include "process_mgmt_comm.h"
#include "ve_socket.h"
#include "sys_mm.h"
#include "libved.h"
#include "mm_transfer.h"
#include "vemva_mgmt.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "libvepseudo.h"


/* NOTE: The below wrapper functions are designed same way as
 * defined in libved.c file
 */
/**
 * @brief calculate aligned addresses from top_address and bottom_address.
 *
 * @param[in] as structure for calculating address offset and datasize.
 */
void calc_address(struct addr_struct *as)
{
	/*
	 *  Calculate addresses.
	 *
	 *          VEMVA
	 *  low  |          |
	 *       +----------+ <----- aligned_top_address
	 *       |          |   ^    (8 Byte aligned)
	 *       |top_offset|   |
	 *       |          |   |
	 *       +----------+ <----- top_address
	 *       |          |   |
	 *       |    ^     |   |
	 *       |    |     |   |
	 *       |    |     |   |
	 *       | datasize | new_datasize
	 *       |    |     |   |
	 *       |    |     |   |
	 *       |    |     |   |
	 *       |    v     |   |
	 *       |          |   |
	 *       +----------+ <----- bottom_address
	 *       |bottom_off|   |
	 *       |set       |   v
	 *       +----------+ <----- aligned_bottom_address
	 *       |          |        (8 Byte aligned)
	 *  high |          |
	 */
	PSEUDO_TRACE("Invoked");
	as->aligned_top_address = (as->top_address & ~(ALIGN_BUFF_SIZE - 1));
	as->top_offset = as->top_address - as->aligned_top_address;
	if (as->bottom_address % ALIGN_BUFF_SIZE) {
		as->aligned_bottom_address =
		    (as->bottom_address & ~(ALIGN_BUFF_SIZE - 1)) + ALIGN_BUFF_SIZE;
		as->bottom_offset =
		    as->aligned_bottom_address - as->bottom_address;
	} else {
		as->aligned_bottom_address = as->bottom_address;
		as->bottom_offset = 0;
	}
	as->new_datasize = as->aligned_bottom_address - as->aligned_top_address;

	/* DEBUG print */
	PSEUDO_DEBUG("top_address =            %016llx",
			(unsigned long long)(as->top_address));
	PSEUDO_DEBUG("aligned_top_address =    %016llx",
			(unsigned long long)(as->aligned_top_address));
	PSEUDO_DEBUG("top_offset =             %d", as->top_offset);
	PSEUDO_DEBUG("bottom_address =         %016llx",
			(unsigned long long)(as->bottom_address));
	PSEUDO_DEBUG("aligned_bottom_address = %016llx",
			 (unsigned long long)(as->aligned_bottom_address));
	PSEUDO_DEBUG("bottom_offset =          %d", as->bottom_offset);
	PSEUDO_DEBUG("new_datasize =           %zd", as->new_datasize);
}

/**
* @brief This function will transfer/receive data for VE memory when
*	src, dest and size are aligned.
*
* @param[in] handle VEOS handle.
* @param[in] vemva  Virual address of VE memory.
* @param[in] vehva  Virtual address of VH memory.
* @param[in] size size of data to be tranfer/receive.
* @param[in] is_send whether to send/receive.
* @param[in] tid TID of VE thread to/from which memory is transferred.
*            This param is set for DMA request using specified tid
*
* @return returns zero if success else negative of errno.
*/
int direct_send_recv(veos_handle *handle, vemva_t vemva,
		vehva_t vehva, size_t size, bool is_send, pid_t tid)
{
	size_t size_remain = size;
	size_t chunk_sz = 0;
	int ret = 0;

	PSEUDO_TRACE("Entering");

	while (size_remain) {
		chunk_sz  = (size_remain >= VE_XFER_BLOCK_SIZE) ?
			VE_XFER_BLOCK_SIZE : size_remain;
		if (is_send) {
			ret = __ve_send_data(handle, vemva, chunk_sz, (void *)vehva, tid);
			if (ret < 0) {
				PSEUDO_DEBUG("error(%s) while transfering data to VE memory",
					strerror(-ret));
				goto xfer_done;
			}
		} else {
			ret = __ve_recv_data(handle, vemva, chunk_sz, (void *)vehva, tid);
			if (ret < 0) {
				PSEUDO_DEBUG("error(%s) while receiving data from VE memory",
					strerror(-ret));
				goto xfer_done;
			}
		}
		size_remain -= chunk_sz;
		vemva += chunk_sz;
		vehva +=  chunk_sz;

	}
	PSEUDO_DEBUG("Total Data %s is %ld Bytes",
			(is_send) ? "send" : "receive", size);
xfer_done:
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function is used to send data from VH to VE memory.
 * @param[in] handle VEOS handle
 * @param[in] address destination address
 * @param[in] datasize size of the data
 * @param[in] data data buffer to transfer
 *
 * @return On success return 0 and negative of errno on failure.
 */
int ve_send_data(veos_handle *handle, uint64_t address,
		size_t datasize, void *data)
{
	return ve_send_data_tid(handle, address, datasize, data, 0);
}

/**
 * @brief This function is used to send data from VH to VE memory.
 *
 * @param[in] handle VEOS handle
 * @param[in] address destination address
 * @param[in] datasize size of the data
 * @param[in] data data buffer to transfer
 * @param[in] tid TID of VE thread to/from which memory is transferred.
 *            This param is set for DMA request using specified tid
 *
 * @return On success return 0 and negative of errno on failure.
 */
int ve_send_data_tid(veos_handle *handle, uint64_t address,
		size_t datasize, void *data, pid_t tid)
{
	int ret = 0, tot_offset = 0;
	struct addr_struct *as = NULL;
	uint64_t *buf = NULL, *t_buf = NULL, *b_buf = NULL;
	vemva_t vemva = 0;
	uint64_t vehva = (uint64_t)data;
	void *src = NULL, *dst = NULL;
	size_t remain_sz = 0, data_xfer_sz = 0;
	bool one_cycle_xfer = true;
	bool first_cycle = true, last_cycle = false;

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("Invoked with address = 0x%lx size 0x%lx data %p",
			address, datasize, data);

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		goto exit_func1;
	}

	as->top_address = address;
	as->bottom_address = address + datasize;

	/*Aligned VEMVA address and size*/
	calc_address(as);
	remain_sz = as->new_datasize;
	vemva = as->aligned_top_address;


	/*If src, dst and size are align then send directly*/
	if (!as->top_offset && !as->bottom_offset && !(vehva % ALIGN_BUFF_SIZE)) {
		ret = direct_send_recv(handle, vemva, (vehva_t)vehva, remain_sz, true, tid);
		goto exit_func2;
	}

	data_xfer_sz = (remain_sz >= VE_XFER_BLOCK_SIZE) ?
		VE_XFER_BLOCK_SIZE : remain_sz;

	/*If size is less than VE_XFER_BLOCK_SIZE then memory
	 *transfer will be done in on cycle*/
	one_cycle_xfer = (remain_sz <= VE_XFER_BLOCK_SIZE) ? true : false;

	buf = (uint64_t *)malloc(data_xfer_sz);
	if (buf == NULL) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		goto exit_func1;
	}

	/* If top offset, then allocate top buffer and receive data. */
	if (as->top_offset != 0) {
		t_buf = (uint64_t *)malloc(ALIGN_BUFF_SIZE);
		if (t_buf == NULL) {
			ret = -errno;
			PSEUDO_DEBUG("Error (%s) while allocating memory",
					strerror(-ret));
			goto exit_func2;
		}
		/* Receiving top part of VE memory into top buffer */
		ret = __ve_recv_data(handle, as->aligned_top_address, ALIGN_BUFF_SIZE, t_buf, tid);
		if (ret) {
			PSEUDO_DEBUG("error while receiving top part of VE data");
			free(t_buf);
			goto exit_func2;
		}
	}

	/* If bottom offset, then allocate bottom buffer and receive data. */
	if (as->bottom_offset != 0) {
		b_buf = (uint64_t *)malloc(ALIGN_BUFF_SIZE);
		if (b_buf == NULL) {
			ret = -errno;
			PSEUDO_DEBUG("Error (%s) while allocating memory",
					strerror(-ret));
			free(t_buf);
			goto exit_func2;
		}
		/* receive bottom part of VE memory into bottom buffer */
		ret = __ve_recv_data(handle, as->aligned_bottom_address - ALIGN_BUFF_SIZE,
				ALIGN_BUFF_SIZE, b_buf, tid);
		if (ret) {
			PSEUDO_DEBUG("error while receiving bottom part of VE data");
			goto exit_func3;
		}
	}

	/* Receiving data in 64MB chunk or less. */
	while (remain_sz) {
		data_xfer_sz = (remain_sz >= VE_XFER_BLOCK_SIZE) ?
			VE_XFER_BLOCK_SIZE : remain_sz;

		/* Copying top data into buffer. */
		if (as->top_offset)
			memcpy(buf, t_buf, as->top_offset);

		if ((last_cycle || one_cycle_xfer) && as->bottom_offset) {
			/* Copying bottom data into buffer. */
			dst = (void *)((uint64_t)buf + (data_xfer_sz - as->bottom_offset));
			src = (void *)((uint64_t)b_buf + (ALIGN_BUFF_SIZE - as->bottom_offset));
			memcpy(dst, src, as->bottom_offset);
		}

		tot_offset = (one_cycle_xfer) ? (as->top_offset + as->bottom_offset) : as->top_offset;

		dst = (uint64_t *)((uint64_t)buf + as->top_offset);

		/* Copying actual data to be into buffer */
		memcpy(dst, (void*)vehva, (data_xfer_sz - tot_offset));

		/* Sending buffer to VE memory after padding top and bottom data*/
		ret = __ve_send_data(handle, vemva, data_xfer_sz, buf, tid);
		if (ret) {
			PSEUDO_DEBUG("error(%s) while sending data to VE memory",
				strerror(-ret));
			goto exit_func3;
		}

		/* All Data sent in one cycle*/
		if (one_cycle_xfer) goto exit_func3;

		vemva += data_xfer_sz;
		vehva += (first_cycle) ? (data_xfer_sz - as->top_offset) : data_xfer_sz;

		/* First cycle of Data sending is done */
		first_cycle =  false;
		as->top_offset = 0;

		/* Calculating Remaining size to be Send */
		remain_sz -= data_xfer_sz;

		/* If remaining size is less than or equal to VE_XFER_BLOCK_SIZE,
		 * then it is last cycle to send data */
		if (remain_sz <= VE_XFER_BLOCK_SIZE)
			last_cycle = true;


		PSEUDO_DEBUG("Total[%ld] Data Yet to send to VE", remain_sz);
	}

	PSEUDO_DEBUG("Total[%ld] Data send to VE", datasize);
exit_func3:
	if (t_buf) free(t_buf);
	if (b_buf) free(b_buf);
exit_func2:
	if (buf) free(buf);
exit_func1:
	if (as) free(as);
	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function used to receive data from VE memory.
 *
 * @param[in] handle VEOS handle
 * @param[in] address VE address
 * @param[in] datasize data size to receive
 * @param[out] data buffer to hold data
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int ve_recv_data(veos_handle *handle, uint64_t address,
		size_t datasize, void *data)
{
	return ve_recv_data_tid(handle, address, datasize, data, 0);
}

/**
 * @brief This function used to receive data from VE memory.
 *
 * @param[in] handle VEOS handle
 * @param[in] address VE address
 * @param[in] datasize data size to receive
 * @param[out] data buffer to hold data
 * @param[in] tid TID of VE thread to/from which memory is transferred.
 *            This param is set for DMA request using specified tid
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int ve_recv_data_tid(veos_handle *handle, uint64_t address,
		size_t datasize, void *data, pid_t tid)
{
	int ret = 0;
	struct addr_struct *as = NULL;
	void *src = NULL;
	uint64_t *buf = NULL, vehva = (uint64_t)data;
	vemva_t vemva = 0;
	size_t remain_sz = 0, data_xfer_sz = 0;
	bool one_cycle_xfer = true;
	bool first_cycle = true, last_cycle = false;
	int tot_offset = 0;

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("Invoked with address = 0x%lx size 0x%lx data %p",
			address, datasize, data);

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		goto exit_func1;
	}

	as->top_address = (vemva_t)address;
	as->bottom_address = (vemva_t)(address + datasize);

	/* Aligning the VEMVA and size */
	calc_address(as);

	remain_sz = as->new_datasize;
	vemva = as->aligned_top_address;

	/*If src, dst and size are align then receive directly */
	if (!as->top_offset && !as->bottom_offset && !(vehva % ALIGN_BUFF_SIZE)) {
		ret = direct_send_recv(handle, vemva, (vehva_t)vehva, remain_sz, false, tid);
		goto exit_func1;
	}

	/* If size is less than VE_XFER_BLOCK_SIZE then memory
	 * transfer will be done in on cycle */
	one_cycle_xfer = (remain_sz <= VE_XFER_BLOCK_SIZE) ? true : false;

	data_xfer_sz = (remain_sz >= VE_XFER_BLOCK_SIZE) ?
			VE_XFER_BLOCK_SIZE : remain_sz;

	/* Allocate buffer to receive data from VE,
	 * is src, dst and size are not aligned */
	buf = (uint64_t *)malloc(data_xfer_sz);
	if (buf == NULL) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allcating memory",
				strerror(-ret));
		goto exit_func1;
	}

	/* Receiving data in 64MB chunk or less */
	while (remain_sz) {
		PSEUDO_DEBUG("sending data to vehva = 0x%lx from vemva = 0x%lx",
				vehva, vemva);

		/* Calculating size to be receive from VE memory */
		data_xfer_sz = (remain_sz >= VE_XFER_BLOCK_SIZE) ?
				VE_XFER_BLOCK_SIZE : remain_sz;

		/* Receive data from VE memory into buffer */
		ret = __ve_recv_data(handle, vemva, data_xfer_sz, buf, tid);
		if (0 > ret) {
			PSEUDO_DEBUG("error(%s) while receiving data from VE",
				strerror(errno));
			goto exit_func2;
		}

		src = (void *)((uint64_t)buf + as->top_offset);

		if (one_cycle_xfer)
			tot_offset = as->top_offset + as->bottom_offset;
		else
			tot_offset = first_cycle ? as->top_offset :
				     (last_cycle ? as->bottom_offset : 0);

		/* Copying actual data into destination
		 * after skipping top and bottom data */
		memcpy((void *)vehva, src, (data_xfer_sz - tot_offset));


		/* All Data Receive in one cycle */
		if (one_cycle_xfer) goto exit_func2;

		vemva += data_xfer_sz;
		vehva += first_cycle ? (data_xfer_sz - as->top_offset) : data_xfer_sz;

		/* First cycle of Data receiving is done */
		first_cycle = false;
		as->top_offset = 0;

		/* Calculating Remaining size to be receive*/
		remain_sz -= data_xfer_sz;

		/* If remaining size is less than or equal to VE_XFER_BLOCK_SIZE,
		 * then it is last cycle to Receive data */
		if (remain_sz <= VE_XFER_BLOCK_SIZE)
			last_cycle = true;
		PSEUDO_DEBUG("Total[%ld] Yet to Data Receive From VE", remain_sz);
	}
	PSEUDO_DEBUG("Total[%ld] Data Receive From VE", datasize);

exit_func2:
	if (buf) free(buf);
exit_func1:
	if (as) free(as);
	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}
/**
 * @brief Send data to VE memory via DMA
 *
 * @param[in] handle VEOS handle
 * @param[in] address VE address
 * @param[in] datasize data size
 * @param[in] data VH buffer to hold data
 * @param[in] tid TID of VE thread to/from which memory is transferred.
 *            This param is set for DMA request using specified tid
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int __ve_send_data(veos_handle *handle, uint64_t address, size_t datasize,
		void *data, pid_t tid)
{
	int ret = 0;
	struct dma_args dma_param = {0};

	ve_dma_addrtype_t src_addrtype = VE_DMA_VHVA;
	ve_dma_addrtype_t dst_addrtype = VE_DMA_VEMVA;

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("SRC Addr: %p Dest Addr: %p Length: %d",
			(void *)data, (void *)address, (int)datasize);

	dma_param.srctype = src_addrtype;
	dma_param.srcaddr = (uint64_t)data;
	dma_param.dsttype = dst_addrtype;
	dma_param.dstaddr = address;
	dma_param.size = datasize;

	ret = amm_dma_xfer_req((uint8_t *)&dma_param, handle, tid);
	if (0 > ret) {
		PSEUDO_DEBUG("error(%s) while Posting DMA request", strerror(ret));
		ret = -EFAULT;
	}
	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief Receive VE memory to VH buffer.
 *
 * @param[in] handle VEOS handle
 * @param[in] address VE address
 * @param[in] datasize Data size
 * @param[out] data Buffer to hold data
 * @param[in] tid TID of VE thread to/from which memory is transferred.
 *            This param is set for DMA request using specified tid
 *
 * @return On success returns 0 and negative of errno.
 */
int __ve_recv_data(veos_handle *handle, uint64_t address,
		   size_t datasize, void *data, pid_t tid)
{
	int ret = 0;
	int local_ret = 0;
	struct dma_args dma_param = {0};

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("SRC Addr: %p Dest Addr: %p Length: %d",
			(void *)address, (void *)data, (int)datasize);

	ret = pthread_rwlock_rdlock(&sync_fork_dma);
	if (ret) {
		PSEUDO_DEBUG("Failed to acquire read lock for "
				"dma: %s", strerror(ret));
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	dma_param.srctype = VE_DMA_VEMVA;
	dma_param.dsttype = VE_DMA_VHVA;
	dma_param.srcaddr = address;
	dma_param.dstaddr = (uint64_t)data;
	dma_param.size = datasize;

	ret = amm_dma_xfer_req((uint8_t *)&dma_param, handle, tid);
	if (0 > ret) {
		PSEUDO_DEBUG("error while Posting DMA request");
		local_ret = -EFAULT;
	}

	ret = pthread_rwlock_unlock(&sync_fork_dma);
	if (ret) {
		PSEUDO_DEBUG("Failed to release read lock for "
				"dma: %s", strerror(ret));
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}
	if (local_ret)
		ret = local_ret;

	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief DMA Request to veos.
 *
 * @param[in] handle VEOS handle
 * @param[in] cmd message to send
 * @param[in] tid TID of VE thread to/from which memory is transferred.
 *            This param is set for DMA request using specified tid
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int amm_dma_xfer_req(uint8_t *dma_param, veos_handle *handle, pid_t tid)
{
	int ret = -1;
	ssize_t pseudo_msg_len = -1;
	PseudoVeosMessage *pseudo_rsp_msg = NULL;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};

	PSEUDO_DEBUG("Invoked");

	PseudoVeosMessage ve_dma_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_dma_req_msg;

	/*Pseudo Command message ID*/
	ve_dma_req.pseudo_veos_cmd_id = DMA_REQ;
	ve_dma_req.has_pseudo_pid = true;
	if (tid) {
		/* Set tid passed in params, in order to allow any thread of
		 * pseudo process to request DMA transfer. */
		ve_dma_req.pseudo_pid = tid;
	} else {
		ve_dma_req.pseudo_pid = syscall(SYS_gettid);
	}

	ve_dma_req_msg.len = sizeof(struct dma_args);
	ve_dma_req_msg.data = (uint8_t *)dma_param;

	/*Send info for VEOS*/
	ve_dma_req.has_pseudo_msg = true;
	ve_dma_req.pseudo_msg = ve_dma_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_dma_req);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_dma_req,
				(uint8_t *)cmd_buf_req)) {
		PSEUDO_DEBUG("internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		abort();
	}

	/* Command send to AMM for DMA request */
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to send request to veos, "
				" transferred %d bytes", ret);
		PSEUDO_ERROR("failed to communicate with veos");
		ret = -EFAULT;
		goto hndl_error;
	}

	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd,
			(void *)&cmd_buf_ack, MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_ERROR("failed to communicate with veos");
		ret = -EFAULT;
		goto hndl_error;
	}

	pseudo_rsp_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_rsp_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		abort();
	}

	if (pseudo_rsp_msg->syscall_retval < 0) {
		ret = pseudo_rsp_msg->syscall_retval;
		PSEUDO_DEBUG("error while receiving acknowledgement from VE OS");
	} else {
		ret = pseudo_rsp_msg->syscall_retval;
		PSEUDO_DEBUG("received acknowledgement from VE OS for DMA xfer req");
	}
	pseudo_veos_message__free_unpacked(pseudo_rsp_msg, NULL);

hndl_error:
	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 *@brief Receive string from VEMVA.
 *
 *	This function is same as vedl_recv_string. It is copied here
 *	to use the DMA library attached with veos.
 *
 *@param[in] handle VEOS handle
 *@param[in] from Starting address of string to receive (VEMVA)
 *@param[out] dest Destination buffer address to receive string.
 *@param[in] dest_size size of the string to receive.
 *
 *@return string length on success,failure return negative number
 *
 *   -1 other failure. check errno.
 *   -2 null character not found in the area.
 *   -3 failed to transfer the data from VEMVA.
 *   -4 destination buffer to store string is too small.
 */
int ve_recv_string(veos_handle *handle, uint64_t from, char *dest,
		size_t dest_size)
{
	int i = 0;
	int len = 0;
	int ret = 0;
	int ve_page_size = 0;
	uint64_t page_boundary = 0;
	size_t buff_size = 0;
	size_t recv_size = 0;
	char *buff = NULL;
	char *dest_p = dest;

	/* receive buffer size (4KB each) */
	buff_size = PAGE_SIZE_4KB;
	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("arguments: from: \
			0x%lx, dest = %p, dest_size = %ld",
			from, dest, dest_size);
	/* get VEMVA page size */
	/* Temporary set it 2MB. In actual environment, ask AMM to get it */
	/* Get the page size of VE address using ve_get_pgsz() */
	ve_page_size = __get_page_size((vemva_t)from);
	if (!ve_page_size) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Address is not find");
		return ret;
	}


	/* allocate buffer */
	buff = (char *)malloc(sizeof(char) * buff_size);
	if (buff == NULL) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allcating memory",
				strerror(-ret));
		return ret;
	}
	memset(buff, 0, buff_size);

	/* calc page boundary address. */
	page_boundary = (from & ~((uint64_t)ve_page_size - 1)) + ve_page_size;
	PSEUDO_DEBUG("from = 0x%016lx, page_boundary = 0x%016lx",
			from, page_boundary);

	/* first page when i == 0. second page when i == 1 */
	for (i = 0; i < 2; i++) {
		if (i == 0) {
			PSEUDO_DEBUG("receiving first page.");
		} else {
			page_boundary += ve_page_size;
			PSEUDO_DEBUG("receiving second page."
					"(this might fail)");
		}
		while (from != page_boundary) {

			/* calc recv_size */
			if (page_boundary < from + buff_size)
				recv_size = page_boundary - from;
			else
				recv_size = buff_size;

			PSEUDO_DEBUG("from = %016lx, to = %016lx"
					"(size = 0x%zx)",
					from, from + recv_size, recv_size);
			/* receive VE memory */
			ret = ve_recv_data(handle, from, recv_size, buff);
			if (ret) {
				PSEUDO_DEBUG("error while receiving date from VE");
				ret = FAIL2RCV;
				goto failure;
			}

			/* search null character from buff */
			for (len = 0; len < recv_size; len++) {
				if (buff[len] == '\0') {
					len++;
					break;
				} else if (dest_size == len) {
					PSEUDO_DEBUG("Null not found"
							"in prescribed range");
					ret = DSTSMLL;
					goto failure;
				}
				if (isprint(buff[len]) == 0
						&& buff[len] != '\n') {
					PSEUDO_DEBUG("non-printable character found");
				}
			}

			/* check if dest buffer size is enough or not */
			if (dest_size < ((uint64_t)dest_p + len) -
					(uint64_t)dest) {
				PSEUDO_DEBUG("dest buffer is too small");
				ret = DSTSMLL;
				goto failure;
			}
			memcpy(dest_p, buff, len);

			/* check if null character found or not */
			if (len != recv_size || buff[len-1] == '\0') {
				PSEUDO_DEBUG("null character found.");
				goto success;
			} else if (recv_size == dest_size) {
				PSEUDO_DEBUG("null character not found.");
				ret = NULLNTFND;
				goto failure;
			}


			/* let's ready for the next */
			dest_p = (char *)((uint64_t)dest_p + recv_size);
			from += recv_size;
		}
	}
	PSEUDO_DEBUG("null character not found in the area.");
	ret = NULLNTFND;
	goto failure;

success:
	len = strlen(dest);
	PSEUDO_DEBUG("str = %s", dest);
	PSEUDO_DEBUG("length = %d", len);
	ret = len;
failure:
	free(buff);
	PSEUDO_DEBUG("returned with %d", ret);
	PSEUDO_TRACE("returned");
	return ret;
}
