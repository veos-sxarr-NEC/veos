/**
 * @file  mem_xfer.c
 * @brief Handles commands sent to PSEUDO PROCESS for memory transfer.
 *
 *	This contains the memory transfer functions that are invoked based
 *	on the request from the pseudo process.
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
#include "veos_pseudo_interface.h"
#include "ve_hw.h"
#include "dma.h"
#include "pseudo_psmg_ipc.h"
#include "pseudo_veos_soc.h"
#include "syscall_amm.h"
#include "libved.h"
#include "mem_xfer.h"
#include "pseudo_veos.pb-c.h"
#include "velayout.h"

#define MAX_TRANS_SIZE  (2*1024*1024)
extern char *veos_sock_name; /*!< sockect name */

/* NOTE: The below wrapper functions are designed same way as
 * defined in libved.c file */
/**
* @brief This function used to send data from VH to VE.
*
* @param[in] handle VE driver handle
* @param[in] address Destination address to hold the data
* @param[in] datasize size of the data
* @param[in] data buffer to transfer
*
* @return On success returns 0 and -1 on failure
*/
int _ve_send_data_ipc(vedl_handle *handle,
		       uint64_t address, size_t datasize, void *data)
{
	int ret = 0;
	int errsv = 0;

	if (datasize % 8) {
		fprintf(stderr,
			"transfer length must be multiple of 8 Byte.\n");
		return -1;
	}

	/* split into 2MB transfer */
	while (datasize > MAX_TRANS_SIZE) {
		ret = _ve_send_data_ipc(handle, address,
					  MAX_TRANS_SIZE, data);
		if (ret)
			goto _ve_send_data_err;

		address += (uint64_t)MAX_TRANS_SIZE;
		datasize -= (size_t) MAX_TRANS_SIZE;
		data = data + MAX_TRANS_SIZE;
	}

	ret =  __ve_send_data(handle, address, datasize, data);
	if (ret) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"DMA transfer failed\n");
		goto _ve_send_data_err;
	}
	/* success */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "DMA transfer success\n");

 _ve_send_data_err:
	errno = errsv;
	return ret;
}

/**
* @brief structure for calculating address offset and datasize.
*/
struct addr_struct {
	uint64_t top_address;
	uint64_t bottom_address;
	uint64_t aligned_top_address;
	uint64_t aligned_bottom_address;
	int top_offset;
	int bottom_offset;
	size_t new_datasize;
};

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
	as->aligned_top_address = (as->top_address & ~(8 - 1));
	as->top_offset = as->top_address - as->aligned_top_address;
	if (as->bottom_address % 8) {
		as->aligned_bottom_address =
		    (as->bottom_address & ~(8 - 1)) + 8;
		as->bottom_offset =
		    as->aligned_bottom_address - as->bottom_address;
	} else {
		as->aligned_bottom_address = as->bottom_address;
		as->bottom_offset = 0;
	}
	as->new_datasize = as->aligned_bottom_address - as->aligned_top_address;

	/* DEBUG print */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"top_address =            %016llx\n",
			(unsigned long long)(as->top_address));
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"aligned_top_address =    %016llx\n",
			(unsigned long long)(as->aligned_top_address));
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"top_offset =             %d\n", as->top_offset);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"bottom_address =         %016llx\n",
			(unsigned long long)(as->bottom_address));
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"aligned_bottom_address = %016llx\n",
			 (unsigned long long)(as->aligned_bottom_address));
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"bottom_offset =          %d\n", as->bottom_offset);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"new_datasize =           %zd\n", as->new_datasize);

}

/**
* @brief This function is used to send data from VH to VE memory.
*
* @param[in] handle VE driver handle
* @param[in] address destination address
* @param[in] datasize size of the data
* @param[in] data data buffer to transfer
*
* @return On success return 0 and -1 on failure
*/
int ve_send_data(vedl_handle *handle, uint64_t address,
			   size_t datasize, void *data)
{
	int ret = 0;
	struct addr_struct *as;
	uint64_t *buff = NULL;
	int errsv = 0;

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		perror("malloc");
		return -1;
	}

	as->top_address = address;
	as->bottom_address = address + datasize;

	/* calc VEMVA addresses */
	calc_address(as);

	/* allocate bigger buffer than data */
	buff = (uint64_t *)malloc(as->new_datasize);
	if (buff == NULL) {
		errsv = errno;
		perror("malloc");
		ret = -1;
		goto ve_send_data_err_;
	}

	/* receive top part of VE memory */
	if (as->top_offset != 0) {
		ret = ve_recv_data(handle, as->aligned_top_address, 8, buff);
		if (ret) {
			errsv = errno;
			fprintf(stderr, "top part of ve_recv_data failed.\n");
			goto ve_send_data_err;
		}
	}

	/* receive bottom part of VE memory */
	if (as->bottom_offset != 0) {
		ret = ve_recv_data(handle, as->aligned_bottom_address - 8, 8,
				     (uint64_t *)((uint64_t)buff +
						  as->new_datasize - 8));
		if (ret) {
			errsv = errno;
			fprintf(stderr,
				"bottom part of ve_recv_data failed.\n");
			goto ve_send_data_err;
		}
	}

	/* copy data to the buffer */
	memcpy((uint64_t *)((uint64_t)buff + as->top_offset), data, datasize);

	/* finally, send buff to VE memory */
	ret = _ve_send_data_ipc(handle, as->aligned_top_address,
				  as->new_datasize, buff);
	if (ret) {
		errsv = errno;
		fprintf(stderr, "_ve_send_data_ipc failed.\n");
	}

 ve_send_data_err:
	free(buff);
 ve_send_data_err_:
	free(as);
	errno = errsv;
	return ret;
}

/**
* @brief This function used to receive data from VE memory.
*
* @param[in] handle VE driver handle
* @param[in] address VE address
* @param[in] datasize data size to receive
* @param[out] data buffer to hold data
*
* @return On success returns 0 and -1 on failure
*/
int ve_recv_data(vedl_handle *handle, uint64_t address,
		    size_t datasize, void *data)
{

	int ret = 0;
	struct addr_struct *as;
	uint64_t *buff = NULL;
	int errsv = 0;

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		perror("malloc");
		return -1;
	}

	as->top_address = address;
	as->bottom_address = address + datasize;

	/* calc VEMVA addresses */
	calc_address(as);

	/* allocate bigger buffer than data */
	buff = (uint64_t *)malloc(as->new_datasize);
	if (buff == NULL) {
		errsv = errno;
		perror("malloc");
		goto ve_recv_data_err1;
	}

	/* Receive buff from VE memory */
	ret = _ve_recv_data_ipc(handle, as->aligned_top_address,
				as->new_datasize, buff);
	if (ret) {
		errsv = errno;
		fprintf(stderr, "_ve_recv_data_ipc failed.\n");
		goto ve_recv_data_err;
	}

	/* copy data to the data buffer */
	memcpy(data, (uint64_t *)((uint64_t)buff + as->top_offset), datasize);

ve_recv_data_err:
	free(buff);
ve_recv_data_err1:
	free(as);
	errno = errsv;
	return ret;
}

/**
* @brief Receive VE memory (internal function)
*
* @param[in] handle VE driver handle
* @param[in] address VE address
* @param[in] datasize data size to receive
* @param[out] data data buffer to hold data
*
* @return On success returns 0 and -1 on failure
*/
int _ve_recv_data_ipc(vedl_handle *handle, uint64_t address,
			       size_t datasize, void *data)
{
	int ret = 0;
	int errsv = 0;

	if (datasize % 8) {
		fprintf(stderr,
			"transfer length must be multiple of 8 Byte.\n");
		return -1;
	}

	/* split into 2MB transfer */
	while (datasize > MAX_TRANS_SIZE) {
		ret = _ve_recv_data_ipc(handle, address,
					  MAX_TRANS_SIZE, data);
		if (ret)
			goto _ve_recv_data_err;

		address += (uint64_t)MAX_TRANS_SIZE;
		datasize -= (size_t) MAX_TRANS_SIZE;
		data = data + MAX_TRANS_SIZE;
	}
	ret = __ve_recv_data(handle, address, datasize, data);
	if (-1 == ret) {
		errsv = errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"DMA transfer failed for reception\n");
		goto _ve_recv_data_err;
	}
	/* success */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "memory received.\n");
 _ve_recv_data_err:
	errno = errsv;
	return ret;
}

/**
* @brief Send data to VE memory via DMA
*
* @param[in] handle VE driver handle
* @param[in] address VE address
* @param[in] datasize data size
* @param[in] data VH buffer to hold data
*
* @return On success returns 0 and -1 on error
*/
int __ve_send_data(vedl_handle *handle, uint64_t address, size_t datasize,
		   void *data)
{
	int retval = -1;
	struct dma_args dma_param;

	ve_dma_addrtype_t src_addrtype = VE_DMA_VHVA;
	ve_dma_addrtype_t dst_addrtype = VE_DMA_VEMVA;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"SRC Addr: %p Dest Addr: %p Length: %d\n",
			(void *)data, (void *)address, (int)datasize);

	dma_param.srctype = src_addrtype;
	dma_param.srcaddr = (uint64_t)data;
	dma_param.dsttype = dst_addrtype;
	dma_param.dstaddr = address;
	dma_param.size = datasize;

	retval = amm_dma_xfer_req((uint8_t *)&dma_param);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Posting DMA request failed\n");
		goto ret;
	}
	retval = 0;
ret:
	return retval;
}

/**
* @brief Receive VE memory to VH buffer.
*
* @param[in] handle VE driver handle
* @param[in] address VE address
* @param[in] datasize Data size
* @param[out] data Buffer to hold data
*
* @return On success returns 0 and -1 on error
*/
int __ve_recv_data(vedl_handle *handle, uint64_t address,
		   size_t datasize, void *data)
{
	int retval;
	struct dma_args dma_param;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"SRC Addr: %p Dest Addr: %p Length: %d\n",
			(void *)address, (void *)data, (int)datasize);

	dma_param.srctype = VE_DMA_VEMVA;
	dma_param.dsttype = VE_DMA_VHVA;
	dma_param.srcaddr = address;
	dma_param.dstaddr = (uint64_t)data;
	dma_param.size = datasize;


	retval = amm_dma_xfer_req((uint8_t *)&dma_param);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				" Posting DMA request failed\n");
		goto ret;
	}
	retval = 0;
ret:
	return retval;
}

/**
* @brief DMA Request to veos.
*
* @param[in] veos_sock_fd Socket descriptor for communication
* @param[in] cmd message to send
*
* @return  On success returns 0 and -1 on error
*/
int amm_dma_xfer_req(uint8_t *dma_param)
{
	int retval = -1;
	int veos_sock_fd;
	int pseudo_msg_len;
	PseudoVeosMessage *pseudo_rsp_msg;
	void *cmd_buf_req;
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	PseudoVeosMessage ve_dma_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_dma_req_msg;

	/*Pseudo Command message ID*/
	ve_dma_req.pseudo_veos_cmd_id = DMA_REQ;
	ve_dma_req.has_pseudo_pid = true;
	ve_dma_req.pseudo_pid = syscall(SYS_gettid);

	ve_dma_req_msg.len = sizeof(struct dma_args);
	ve_dma_req_msg.data = (uint8_t *)dma_param;

	/*Send info for VEOS*/
	ve_dma_req.has_pseudo_msg = true;
	ve_dma_req.pseudo_msg = ve_dma_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_dma_req);
	cmd_buf_req = malloc(pseudo_msg_len);
	if (NULL == cmd_buf_req) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed %s\n",
				strerror(errno));
		retval = -1;
		goto malloc_error;
	}
	memset(cmd_buf_req, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_dma_req,
				cmd_buf_req)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"DMA pack failed\n");
		retval = -1;
		goto hndl_error;
	}

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -1;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"socket creation failed\n");
		goto hndl_error;
	}


	/* Command send to AMM for DMA request */
	retval = pseudo_veos_send_cmd(veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);

	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Posting DMA request failed\n");
		perror("Error:");
		goto send_error;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd,
				(void *)&cmd_buf_ack, MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		retval = -1;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Fails to recv ACK from AMM\n");
		perror("Error:");
		goto send_error;
	}

	pseudo_rsp_msg = pseudo_veos_message__unpack(NULL, retval,
					(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_rsp_msg) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"unpack failed %d\n", retval);
			retval = -1;
			goto send_error;
	}

	if (pseudo_rsp_msg->syscall_retval < 0) {
		retval = pseudo_rsp_msg->syscall_retval;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive DMA_ACK\n");
	} else {
		retval = pseudo_rsp_msg->syscall_retval;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"DMA_ACK received successfully\n");
	}
	pseudo_veos_message__free_unpacked(pseudo_rsp_msg, NULL);

send_error:
	close(veos_sock_fd);
hndl_error:
	free(cmd_buf_req);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Receive string from VEMVA.
*
*	This function is same as vedl_recv_string. It is copied here
*	to use the DMA library attached with veos.
*
* @param[in] handle VE driver handle
* @param[in] from Starting address of string to receive (VEMVA)
* @param[out] dest Destination buffer address to receive string.
* @param[in] dest_size size of the string to receive.
*
* @return string length on success,failure return negative number
*
*   -1 other failure. check errno.
*   -2 null character not found in the area.
*   -3 failed to transfer the data from VEMVA.
*   -4 destination buffer to store string is too small.
*/
int ve_recv_string(vedl_handle *handle, uint64_t from, char *dest,
		     size_t dest_size)
{
	int i;
	int len;
	int ret;
	int ve_page_size;
	uint64_t page_boundary;
	size_t buff_size;
	size_t recv_size;
	char *buff;
	char *dest_p = dest;

	/* receive buffer size (4KB each) */
	buff_size = 4 * 1024;

	/* get VEMVA page size */
	/* Temporary set it 2MB. In actual environment, ask AMM to get it */
	ve_page_size = 2 * 1024 * 1024;

	/* allocate buffer */
	buff = (char *)malloc(sizeof(char) * buff_size);
	if (buff == NULL) {
		perror("malloc");
		return -1;
	}
	memset(buff, 0, buff_size);

	/* calc page boundary address. */
	page_boundary = (from & ~((uint64_t)ve_page_size - 1)) + ve_page_size;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"from = %016lx, page_boundary = %016lx\n",
			from, page_boundary);

	/* first page when i == 0. second page when i == 1 */
	for (i = 0; i < 2; i++) {
		if (i == 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"receiving first page.\n");
		} else {
			page_boundary += ve_page_size;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"receiving second page."
					"(this might fail)\n");
		}
		while (from != page_boundary) {

			/* calc recv_size */
			if (page_boundary < from + buff_size)
				recv_size = page_boundary - from;
			else
				recv_size = buff_size;

			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"from = %016lx, to = %016lx"
					"(size = 0x%zx)\n",
					from, from + recv_size, recv_size);

			/* receive VE memory */
			ret = ve_recv_data(handle, from, recv_size, buff);
			if (ret) {
				ret = -3;
				goto failure;
			}

			/* search null character from buff */
			for (len = 0; len < recv_size; len++) {
				if (buff[len] == '\0') {
					len++;
					break;
				}
				if (isprint(buff[len]) == 0
				    && buff[len] != '\n') {
					fprintf(stderr,
						"non-printable character found.\n");
				}
			}

			/* check if dest buffer size is enough or not */
			if (dest_size < ((uint64_t)dest_p + len) -
			    (uint64_t)dest) {
				fprintf(stderr, "dest buffer is too small.\n");
				ret = -4;
				goto failure;
			}
			memcpy(dest_p, buff, len);

			/* check if null character found or not */
			if (len != recv_size) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
						"null character found.\n");
				goto success;
			}

			/* let's ready for the next */
			dest_p = (char *)((uint64_t)dest_p + recv_size);
			from += recv_size;
		}
	}
	fprintf(stderr, "null character not found in the area.\n");
	return -2;

 success:
	len = strlen(dest);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "str = %s\n", dest);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "length = %d\n", len);
	ret = len;
 failure:
	free(buff);
	return ret;
}
