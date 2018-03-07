/**
 * @file syscall_amm.c
 * @brief Handles AMM related system calls encountered by VE process.
 *
 * This file contains AMM system call handlers for the various system calls
 * encountered by VE process.
 */

#include <sys/shm.h>
#include "syscall_common.h"
#include "libved.h"
#include "loader.h"
#include "memory.h"
#include "ve_hw.h"
#include "syscall_amm.h"
#include "mem_xfer.h"
#include "pseudo_veos_soc.h"
#include "pseudo_psmg_ipc.h"
#include "pseudo_veos.pb-c.h"
#include "veos_pseudo_interface.h"
#include "velayout.h"

__thread struct _ve_page_info ve_page_info;		/*!< VE page size info*/
uint64_t pseudo_vemva_count;				/*!< VEMVA dir count*/

/**
* @brief This function to handle mmap system call.
*
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle  Handle for VE driver interface
*/
void ve_mmap(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t addr;
	uint64_t size;
	uint64_t offset;
	int64_t retval;
	int prot;
	int flag;
	int filedes;
	void *ret_addr;
	uint64_t args[6];

	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Read mmap system call arguments */
	addr    = args[0];
	size    = args[1];
	prot    = (int)args[2];
	flag    = (int)args[3];
	filedes = (int)args[4];
	offset  = args[5];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"ARGS:: 0x%lu 0x%lx 0x%x 0x%x 0x%x 0x%lx\n",
			addr, size, prot, flag, filedes, offset);

	/* Request for mmap */
	ret_addr = __ve_mmap(handle, addr, size, prot, flag, filedes,
			offset, UNSET_ATB);
	if ((void *)-1 == ret_addr) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Mapping failed :%s\n", strerror(errno));
		retval = -errno;
	} else {
		retval = (uint64_t)ret_addr;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Return address of system call is :%lx\n",
			(uint64_t)ret_addr);

hndl_return:
	return_system_call(retval);
	return;
}

/**
* @brief Function to handle memory mapping request.
*
* @param[in] handle Handle for VE driver interface
* @param[out] addr Memory mapping is to be done at this address
* @param[in] size Size of the memory to map
* @param[in] prot Permission to set on mapped memory
* @param[in] flag Additional information for memory mapping
* @param[in] filedes File descriptor in case of file backed mapping
* @param[in] offset Offset of the file
* @param[in] atb_flag determines ATB to update or not
*
* @return On success returns virtual address* on failure returns (void *)-1
*/
void *__ve_mmap(vedl_handle *handle, uint64_t addr, uint64_t size,
		int prot, int flag, int filedes, uint64_t offset, int atb_flag)
{
	int64_t retval = -1;
	int ret;
	uint64_t rounded_size;
	int64_t offset_start;
	int64_t offset_end;
	void *ret_addr;

	struct file_map_stat *f_map_stat = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"vemva:%lx size:%lu prot:%x "
			"flag:%x fdesc:%x offset:%lx\n",
			addr, size, prot, flag, filedes, offset);

	if (!size) {
		errno = EINVAL;
		return (void *)-1;
	}

	if (flag & MAP_HUGETLB) {
		ve_page_info.page_size = PAGE_SIZE_64MB;
		ve_page_info.page_mask = PAGE_SIZE_64MB-1;
		ve_page_info.chunk_size = CHUNK_16GB;
		ve_page_info.chunk_mask = CHUNK_16GB-1;
	} else {
		ve_page_info.page_size = PAGE_SIZE_2MB;
		ve_page_info.page_mask = PAGE_SIZE_2MB-1;
		ve_page_info.chunk_size = CHUNK_512MB;
		ve_page_info.chunk_mask = CHUNK_512MB-1;
	}

	if (!IS_ALIGNED(size, ve_page_info.page_size)) {
		rounded_size = ALIGN(size, ve_page_info.page_size);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Roundup Size:%lu\n", rounded_size);
	} else {
		rounded_size = size;
	}

	/* Check for alignment (VE_PAGE_SIZE Alignment) of
	 * file offset received */
	if (!(MAP_ANON & flag)) {
		if (!IS_ALIGNED(offset, ve_page_info.page_size)) {
			errno = EINVAL;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Offset not aligned to "
					"2MB page boundary\n");
			errno = EINVAL;
			return (void *)-1;
		}

		offset_start = (int64_t)offset/ve_page_info.page_size;
		offset_end = (int64_t)((offset+rounded_size)
				/ve_page_info.page_size) - 1;
	} else {
		offset_start = 0;
		offset_end = (int64_t)(rounded_size/ve_page_info.page_size) - 1;
	}

	/* Check whether mapping is not related to heap/stack  */
	if (!((flag & VE_MAP_STACK) || (flag & VE_MMAP_GROWS_UP))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Anonymous Mapping\n");
		pthread_mutex_lock(&vemva_header.vemva_lock);
		ret_addr = pseudo_vemva_allocation(handle, addr, rounded_size,
				flag, prot, filedes, offset);
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		if ((void *)-1 == ret_addr) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VEMVA allocation failed !!\n");
			return ret_addr;
		}

	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"STACK or HEAP or Binary load MAPPING\n");
		/* Align addr to VE page size boundary if not aligned */
		ret_addr = (void *)addr;
		if (NULL != (void *)ret_addr) {
			if (!IS_ALIGNED((uint64_t)ret_addr,
						ve_page_info.page_size)) {
				ret_addr = (void *)ALIGN((uint64_t)ret_addr,
						ve_page_info.page_size);
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"Aligned VEMVA address:%lx\n",
						(uint64_t)ret_addr);
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"VEMVA already aligned\n");
			}
		} else {
			return (void *)-1;
		}
		/*
		 * TODO:We are not doing any VEMVA related handling here
		 * We have to update vemva_data structures in this mapping also
		 */
	}

	/*If File Backed*/
	if (!(MAP_ANON & flag)) {
		f_map_stat = (struct file_map_stat *)malloc
			(sizeof(struct file_map_stat));
		if (f_map_stat == NULL) {
			perror("malloc");
			return (void *)-1;
		}
		memset(f_map_stat, '\0', sizeof(struct file_map_stat));

		ret = fstat(filedes, &f_map_stat->file_stat);
		if (-1 == ret) {
			perror("fstat");
			free(f_map_stat);
			return (void *)-1;
		}

		f_map_stat->offset_start = offset_start;
		f_map_stat->offset_end = offset_end;
	}

	/* AMM communication */
	retval = amm_request_mmap(handle, (uint64_t)ret_addr, rounded_size,
			prot, flag, atb_flag, f_map_stat);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Request to AMM Failed\n");

		/*TODO: AMM error code is yet to design after analysing
		 * the standard error codes.It should be in such a way
		 * that there should not be any overlap with the standard
		 * errors.As of now setting it as EFAULT
		 */
		errno = EFAULT;
		return (void *)retval;
	}

	return (void *)ret_addr;
}
/**
* @brief  This function is used to communicate with AMM module.
*
* @param[in] handle Handle for VE driver interface
* @param[out] ret_addr mapped virtual address
* @param[in] size Size of the memory to map
* @param[in] prot Protection control bits
* @param[in] flag mapping control flags
* @param[in] atb_flag atb on core load flag
* @param[in] f_map_stat file stats to be mapped if file backed
* otherwise NULL.
*
* @return returns 0 on success and -1 on error
*/
int64_t amm_request_mmap(vedl_handle *handle, uint64_t ret_addr, uint64_t size,
		int prot, int flag, int atb_flag,
		struct file_map_stat *f_map_stat)
{
	int veos_sock_fd = -1;
	int64_t retval = -1;
	void *cmd_buf_req;
	size_t pseudo_msg_len;
	struct ve_mmap_cmd *cmd;
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE];

	PseudoVeosMessage *pseudo_msg;

	PseudoVeosMessage ve_mmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_mmap_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Requesting AMM for MMAP\n");
	cmd = (struct ve_mmap_cmd *)malloc(
			sizeof(struct ve_mmap_cmd));
	if (NULL == cmd) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to allocate memory for "
				"amm request block\n");
		goto malloc_error;
	}
	memset(cmd, 0, sizeof(struct ve_mmap_cmd));

	/*Populating struct ve_mmap_cmd buffer to Generate IPC Command */
	cmd->vaddr = ret_addr;
	cmd->size = size;
	cmd->perm = prot;
	cmd->flags = flag;
	cmd->atb_flag = atb_flag;

	/*File_backed handling*/
	if (!(MAP_ANON & flag)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"MAP_SHARED mmap\n");
		/*copy file specific Information in cmd buffer*/
		memcpy(&(cmd->f_map_stat), f_map_stat,
					sizeof(struct file_map_stat));
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"AMM request block vemva:%lx"
			"size:%lx\n "
			"AMM request block perm:%lx"
			"flags:%lx\n",
			cmd->vaddr, cmd->size, cmd->perm, cmd->flags);

	/* Popluate parameters for ve_mmap req */
	ve_mmap.pseudo_veos_cmd_id = CMD_MMAP;

	ve_mmap.has_pseudo_pid = true;
	ve_mmap.pseudo_pid = syscall(SYS_gettid);

	ve_mmap_msg.len = sizeof(struct ve_mmap_cmd);
	ve_mmap_msg.data = (uint8_t *)cmd;

	ve_mmap.has_pseudo_msg = true;
	ve_mmap.pseudo_msg = ve_mmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mmap);
	cmd_buf_req = malloc(pseudo_msg_len);
	if (NULL == cmd_buf_req) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed %s\n",
				strerror(errno));
		retval = -1;
		goto hndl_error;
	}
	memset(cmd_buf_req, '\0', pseudo_msg_len);

	/* Unix domain socket used as IPC between pseudo and AMM module */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		/* Error handling */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to create socket with AMM\n");
		goto send_error;
	}

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_mmap,
							cmd_buf_req)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"MMAP pack failed\n");
		retval = -1;
		goto send_error;
	}

	/* Command send to AMM for memory mapping */
	retval = pseudo_veos_send_cmd(veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"AMM communication fails for MMAP\n");
		goto send_error;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd, cmd_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Fails to recv ACK from AMM for MMAP\n");
		goto send_error;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
					 (const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"unpack failed retval:%ld %s\n",
			  retval, strerror(errno));
		retval = -1;
		goto send_error;
	}
	if (pseudo_msg->syscall_retval < 0) {
		/*
		 * TODO:
		 * VEOS(AMM) will send appropriate error code in
		 * pseudo_msg->syscall_retval we will have to fetch that
		 * and return to user.
		 */
		retval = -1;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive MMAP_ACK\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"MMAP successully completed\n");
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

send_error:
	free(cmd_buf_req);
hndl_error:
	close(veos_sock_fd);
	free(cmd);
malloc_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief  This function is used to handle memory unmap request.
*
* @param[in] handle Handle for VE driver interface
* @param[in] addr Start of the virtual address from where memory to unmap
* @param[in] size size of the memory to unmap
* @param[in] flag flag to control the munmap
* @param[in] atb_flag determines ATB to update or not
*
* @return  On success returns 0 and -1 on failure
*/
int64_t __ve_munmap(vedl_handle *handle, uint64_t addr,
		uint64_t size, int flag, int atb_flag)
{
	int veos_sock_fd = -1;
	int64_t retval = -1;
	void *cmd_buf_req;
	size_t pseudo_msg_len;
	struct ve_munmap_cmd *cmd;
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE];

	PseudoVeosMessage *pseudo_msg;

	PseudoVeosMessage ve_munmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_munmap_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/*
	 * munmap always required address that is aligned to
	 * 2MB page size boundary. AMM can't unmap page
	 * corresponding to unaligned address.
	 */
	if (!IS_ALIGNED((uint64_t)addr, ve_page_info.page_size)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Address is not page size aligned !\n");
		errno = EINVAL;
		goto hndl_error;
	}
	/* TODO:
	 * If size is not in the multiple of 2MB page size boundary, then
	 * it must be round-off to next page size boundary.
	 *
	 * It should be taken care by library that size should always passed
	 * aligned.
	 */
	if (!IS_ALIGNED((uint64_t)size, ve_page_info.page_size)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Rounding off size to next "
				"page size boundary\n");
		size = ALIGN((uint64_t)size, ve_page_info.page_size);
		goto hndl_error;
	}


	/*Change Bitmap*/
	/*Get VEMVA lock here*/
	if (!(flag & VE_MMAP_GROWS_UP)) {
		pthread_mutex_lock(&vemva_header.vemva_lock);
		retval = release_vemva(handle, (void *)addr, size, flag);
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		if (retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"release_vemva failed!!!\n");
			goto hndl_error;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Requesting AMM to free VE PHY pages "
			"mapped to VEMVA\n");

	/* Popluate parameters for ve_munmap req */
	ve_munmap.pseudo_veos_cmd_id = CMD_MUNMAP;

	ve_munmap.has_pseudo_pid = true;
	ve_munmap.pseudo_pid = syscall(SYS_gettid);

	cmd = (struct ve_munmap_cmd *)malloc(
			sizeof(struct ve_munmap_cmd));
	if (NULL == cmd) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Memory allocation failed for AMM req block\n");
		errno = ENOMEM;
		goto hndl_error;
	}
	memset(cmd, 0, sizeof(struct ve_munmap_cmd));

	cmd->vaddr = addr;
	cmd->size = size;
	cmd->atb_flag = atb_flag;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"AMM req block dump: vemva:%lx size:%lx\n",
			cmd->vaddr, cmd->size);

	ve_munmap_msg.len = sizeof(struct ve_munmap_cmd);
	ve_munmap_msg.data = (uint8_t *)cmd;

	ve_munmap.has_pseudo_msg = true;
	ve_munmap.pseudo_msg = ve_munmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_munmap);
	cmd_buf_req = malloc(pseudo_msg_len);
	if (NULL == cmd_buf_req) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed %s\n",
				strerror(errno));
		retval = -1;
		errno = ENOMEM;
		goto hndl_error1;
	}

	memset(cmd_buf_req, '\0', pseudo_msg_len);
	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_munmap, cmd_buf_req)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"munmap pack failed\n");
		retval = -1;
		errno = EFAULT;
		goto send_error;
	}

	/* Socket id to communicate with AMM */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		/* Error handling */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Socket to AMM failed\n");
		retval = -1;
		errno = EFAULT;
		goto send_error;
	}

	retval = pseudo_veos_send_cmd(veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"fails during unmap request\n");
		errno = EFAULT;
		goto send_error;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd, cmd_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Fails to recv ACK from AMM for CMD_MUNMAP\n");
		errno = EFAULT;
		goto send_error;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
					(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"unpack failed retval:%ld %s\n",
					retval, strerror(errno));
			retval = -1;
			errno = EFAULT;
			goto send_error;
	}

	if (pseudo_msg->syscall_retval < 0) {
		/*
		 * TODO:
		 * VEOS(AMM) will send appropriate error code in
		 * pseudo_msg->syscall_retval we will have to fetch that
		 * and return to user.
		 */
		retval = -1;
		errno = EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive MUNMAP_ACK\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"MUNMAP successully completed\n");
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

send_error:
	free(cmd_buf_req);
hndl_error1:
	free(cmd);
	close(veos_sock_fd);
hndl_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
* @brief This function is to handle munmap request.
*
* @param[in] syscall_num Syscall number
* @param[in] syscall_name Syscall name
* @param[in] handle Handle for VE driver interface
*/
void ve_munmap(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t addr;
	uint64_t size;
	int64_t retval;
	uint64_t args[2];
	/* Read mmap system call arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto err_return;
	}

	addr = args[0];
	size = args[1];
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"VEMVA 0x%lx of size 0x%lx to unmap\n", addr, size);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Calling core UNMAP handler\n");

	retval = get_page_size(addr);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Page Size not recognised\n");
		retval = -EINVAL;
		goto err_return;
	}

	/* Request for memory unmap */
	retval = __ve_munmap(handle, addr, size, 0, UNSET_ATB);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Fails to UNMAP memory region\n");
		goto err_return;
	}

err_return:
	return_system_call(retval);
	return;
}

/**
* @brief  This function is used to handle
* Heap space extension/reduction request.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handle for VE driver interface
*/
void ve_brk(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	int64_t retval = -1;
	void *ret_addr = (void *)-1;
	uint64_t  old_top_address, new_top_address;
	int64_t size;
	uint64_t args[1];

	/* Get sys call args */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"BRK:: vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Get the previous heap top */
	old_top_address = ve_info.heap_top;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Without alignment current HEAP TOP:0x%lx\n",
			old_top_address);

	retval = get_page_size(old_top_address);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Page Size not recognised\n");
	}

	/*
	 * We are supporting only 2MB page size only
	 * * for address space.
	 * This Should be removed in Future.
	 */
	ve_page_info.page_size = PAGE_SIZE_2MB;
	ve_page_info.page_mask = ve_page_info.page_size - 1;
	ve_page_info.chunk_size = ve_page_info.page_size * 256;
	ve_page_info.chunk_mask = ve_page_info.chunk_size - 1;

	/* Check if previous heap is aligned */
	if (!IS_ALIGNED(old_top_address, ve_page_info.page_size))
		old_top_address = ALIGN(old_top_address,
				ve_page_info.page_size);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"With alignment current HEAP TOP:0x%lx\n",
			old_top_address);

	new_top_address = ALIGN(args[0], ve_page_info.page_size);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"HEAP: new_top_address without alignment:0x%lx\n",
			args[0]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"HEAP: new_top_address aligned:0x%lx\n",
			new_top_address);

	/* If brk syscall argument received is NULL
	 * then current heap top is sent to VE program */
	if (0 == new_top_address) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Requesting current HEAP TOP\n");
		retval = old_top_address;
		goto send_return;
	}

	/* Check if requested value is same as current heap top */
	if (new_top_address == old_top_address) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Old(%lx) and new(%lx) heap limit are same\n",
				old_top_address, new_top_address);
		retval = old_top_address;
		goto send_return;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"ARG1 (addr) in brk:0x%lx\n", args[0]);

	/* Calculate Heap size to change */
	size = new_top_address - old_top_address;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Size Received:%ld\n", size);

	if (size > 0) {
		/* check that while increasing the heap it doesn't overlap the
		 * stack region.
		 */
		if ((old_top_address + size) > ve_info.stack_pointer_aligned) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Heap overlapping the stack.\n");
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Current aligned stack pointer: %lx\n",
					ve_info.stack_pointer_aligned);
			errno = ENOMEM;
			retval = old_top_address;
			goto send_return;
		}
		/* Request for Heap extension */
		ret_addr = ve_heap_extend(handle, old_top_address, size);
		if ((void *)-1 == ret_addr) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fail to EXTEND HEAP LIMIT\n");
			errno = ENOMEM;
			retval = old_top_address;
			goto send_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	} else {
		size = -size;
		/* Req for Heap release , check whether release request
		 * goes beyond the heap starting point */
		if (new_top_address < ALIGN(ve_info.heap_start,
					ve_page_info.page_size)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fail to dec HEAP LIMIT, "
					"It goes beyond heap start\n");
			errno = EINVAL;
			retval = old_top_address;
			goto send_return;
		}
		retval = ve_heap_reduce(handle, new_top_address, size);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fail to decrease HEAP LIMIT\n");
			errno = ENOMEM;
			retval = old_top_address;
			goto send_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	}
	retval = ve_info.heap_top;

send_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"HEAP TOP Returned:0x%lx\n", (uint64_t)retval);
hndl_return:
	return_system_call(retval);
	return;
}

/**
* @brief This function handles heap space extention request.
*
* @param[in] handle Handle for VE driver interface
* @param[in] old_top_address VE virtual address to unmap
* @param[in] size size of the heap space to release
*
* @return  On success returns mapped address* and (void *)-1 on failure
*/
void *ve_heap_extend(vedl_handle *handle, uint64_t old_top_address,
		uint64_t size)
{
	void *retval;

	/* Request to extend VE program Heap space */
	retval = __ve_mmap(handle, old_top_address, size,
			PROT_READ | PROT_WRITE,
			MAP_FIXED | VE_MMAP_GROWS_UP | VE_MAP_ANONYMOUS,
			-1, 0, UNSET_ATB);
	if ((void *)-1 == retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Extending HEAP LIMIT: Fails to mmap");
	return retval;
}

/**
* @brief This function handles heap space reduction request.
*
* @param[in] handle Handle for VE driver interface
* @param[in] new_top_address VE virtual address to map
* @param[in] size size of the space to map
*
* @return  On success returns 0 and -1 on failure
*/
int64_t ve_heap_reduce(vedl_handle *handle, uint64_t new_top_address,
		uint64_t size)
{
	int retval, flag;

	/* Request to reduce VE program Heap space */
	flag  = VE_MMAP_GROWS_UP;
	retval = __ve_munmap(handle, new_top_address, size, flag, UNSET_ATB);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Decreasing HEAP LIMIT: Fails to unmap\n");
		return -1;
	}
	return retval;
}

/**
* @brief  This function handles grow system call
* from VE process to make request to AMM for VE stack space extension.
*
* @param[in] syscall_num grow syscall number
* @param[in] syscall_name syscall name
* @param[in] handle Handle for VE driver interface
*/
void ve_grow(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	int prot, flag;
	uint64_t size;
	uint64_t old_bottom_address;
	uint64_t new_bottom_address;
	uint64_t new_stack_limit;
	int64_t retval = -1;
	void *ret_addr;
	uint64_t args[2];
	/* Read syscall arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed.(%s)\n",
				syscall_name);
		goto send_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Grow syscall oldbottom addr : 0x%lx\n", args[0]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Grow syscall newbottom addr : 0x%lx\n", args[1]);

	/* Get grow syscall arguments */
	old_bottom_address = args[0];
	new_bottom_address = args[1];

	if (new_bottom_address >= old_bottom_address) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"New bottom address is >="
				" old bottom address\n");
		goto send_return;
	}

	/*
	 * We are supporting only 2MB page size only
	 * for address space.
	 * This Should be removed in Future.
	 *
	 * This is equvalent to get page_size
	 */
	ve_page_info.page_size = PAGE_SIZE_2MB;
	ve_page_info.page_mask = ve_page_info.page_size - 1;
	ve_page_info.chunk_size = ve_page_info.page_size * 256;
	ve_page_info.chunk_mask = ve_page_info.chunk_size - 1;

	if (!IS_ALIGNED((uint64_t)new_bottom_address, ve_page_info.page_size)) {
		/*
		 * TODO: Stack grows downwards so aligned address should be
		 * roundown and ALIGN macro gives roundup aligned address.
		 */
		new_bottom_address = (uint64_t)ALIGN(
				(uint64_t)new_bottom_address,
				ve_page_info.page_size) -
			ve_page_info.page_size;
	}

	/*
	 * While changing the stack limit Check:
	 * 1. If it overlaps the process heap or not.
	 * 2. If STACK LIMIT is defined, then check if it is
	 * going beyond the limit or not.
	 *
	 * If stack grows and goes beyond in both the cases,
	 * SIGSEGV is sent.
	 */
	if (new_bottom_address < ve_info.stack_limit) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Stack is going beyond the STACK Limit.\n");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Stack limit: %lx\n", ve_info.stack_limit);
		retval = -EFAULT;
		goto send_return;
	}

	if (new_bottom_address < ve_info.heap_top) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Stack is going beyond the Heap top.\n");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Current Heap top: %lx\n", ve_info.heap_top);
		goto send_return;
	}

	/* Calculate size of the VE program stack space to extend */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"New bottom address:%lx\n", new_bottom_address);
	size = ((uint64_t)old_bottom_address) -
		((uint64_t)new_bottom_address);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"STACK size to extend:%lx\n", size);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"STACK OLD LIMIT:%lx\n", old_bottom_address);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"STACK NEW LIMIT:%lx\n", new_bottom_address);

	/* Set the protection */
	prot = VE_PROT_READ|VE_PROT_WRITE;
	/* Set flag to indicate this is for stack space allocation */
	flag = MAP_FIXED | VE_MAP_ANONYMOUS | VE_MAP_STACK;

	/* Request for memory map */
	ret_addr = __ve_mmap(handle, old_bottom_address, size, prot,
			flag, -1, 0, UNSET_ATB);
	if ((void *)-1 == ret_addr) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to map more STACK\n");
		goto send_return;
	}

	/* New stack limit to update
	 * musl libc will do this in future */
	new_stack_limit = new_bottom_address;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"New Stack Limit changed to: 0x%lx\n",
			new_stack_limit);

	/* Update new stack limit into SR08 register */
	if (-1 == ve_set_ve_reg(SR08, new_stack_limit)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_set_ve_reg failed. #[S08]=0x%lx\n",
				old_bottom_address);
		goto send_return;
	}

	/*
	 * After succesfull grow, update the value of new stack
	 * pointer aligned.
	 */
	ve_info.stack_pointer_aligned = new_stack_limit;
	return;
send_return:
	/*
	 * On failure killing overself by sending
	 * SIGSEGV.
	 */
	kill(getpid(), 11);
	return;
}

/**
* @brief  This function is used to
* communicate with AMM module for updating memory protection.
*
* @param[in] handle Handle for VE driver interface
* @param[out] ret_addr mapped virtual address
* @param[in] size Size of the memory to map
* @param[in] prot Protection control bits
* @param[in] atb_flag determines ATB to update or not
*
* @return returns 0 on success and -1 on error
*/
int64_t amm_request_mprotect(vedl_handle *handle, uint64_t ret_addr,
		uint64_t size, int prot, int atb_flag)
{
	int veos_sock_fd;
	int64_t retval = -1;
	PseudoVeosMessage ve_mprotect_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData mprotect_ve_proc_msg;
	void *buf;
	char mprot_buf_ack[MAX_PROTO_MSG_SIZE];
	ssize_t pseudo_msg_len;
	PseudoVeosMessage *mprotect_ack = NULL;
	struct pseudo_mprotect_req mprotect_request;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	/* Populate mprotect_request structure */
	mprotect_request.ret_addr = ret_addr;
	mprotect_request.size = size;
	mprotect_request.prot = prot;
	mprotect_request.atb_flag = atb_flag;

	/* prepare request to be sent to AMM */
	ve_mprotect_req.pseudo_veos_cmd_id = CMD_MPROTECT;

	ve_mprotect_req.has_pseudo_pid = true;
	ve_mprotect_req.pseudo_pid = syscall(SYS_gettid);

	ve_mprotect_req.has_pseudo_msg = true;
	mprotect_ve_proc_msg.len = sizeof(struct pseudo_mprotect_req);
	mprotect_ve_proc_msg.data = (uint8_t *)&mprotect_request;
	ve_mprotect_req.pseudo_msg = mprotect_ve_proc_msg;

	/* Pack ve_mprotect_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mprotect_req);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for structure packing failed.\n");
		retval = -errno;
		goto hndl_return;
	}
	pseudo_veos_message__pack(&ve_mprotect_req, buf);

	/* Unix domain socket used as IPC between pseudo and AMM module */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to create socket with AMM\n");
		goto hndl_return1;
	}

	/* Send command to AMM for memory mapping */
	retval = pseudo_veos_send_cmd(veos_sock_fd, buf,
			pseudo_msg_len);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"AMM communication failed: %s\n",
				strerror(errno));
		goto free_mem;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"AMM request block vemva:%lx pid:%lx size:%lx\n",
			mprotect_request.ret_addr, syscall(SYS_gettid),
			mprotect_request.size);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"AMM request block perm:%x\n", mprotect_request.prot);

	retval = pseudo_veos_recv_cmd(veos_sock_fd, mprot_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to recv ACK from AMM: %s\n",
				strerror(errno));
		goto free_mem;
	}

	/* Unpack the structure */
	mprotect_ack = pseudo_veos_message__unpack(NULL, retval,
			(const uint8_t *)(mprot_buf_ack));
	if (NULL == mprotect_ack) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_veos_message__unpack %ld\n",
				retval);
		retval = -1;
		goto free_mem;
	}
	if (mprotect_ack->syscall_retval < 0) {
		retval = mprotect_ack->syscall_retval;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive MPROTECT ACK\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"MPROTECT successully completed\n");
		retval = mprotect_ack->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(mprotect_ack, NULL);

free_mem:
	close(veos_sock_fd);
hndl_return1:
	free(buf);
hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return retval;
}

/**
* @brief  This function to handle mprotect system call.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handle for VE driver interface
*/
void ve_mprotect(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t addr;
	uint64_t len, rounded_len;
	int prot;
	int64_t retval;
	uint64_t args[3];

	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto err_mprotect;
	}

	/* Read mprotect system call arguments */
	addr	= args[0];
	len	= args[1];
	prot	= (int)args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"ARGS:: 0x%lx 0x%lx 0x%x\n",
			addr, len, prot);

	retval = get_page_size(addr);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Page Size not recognised\n");
		retval = -EINVAL;
		goto err_mprotect;
	}

	/* Check address is 2MB page size aligned or not */
	if (!IS_ALIGNED((uint64_t)addr, ve_page_info.page_size)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VEMVA address is not aligned\n");
		retval = -EINVAL;
		goto err_mprotect;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"VEMVA already aligned\n");

	/* Align length to 2MB page size */
	if (!IS_ALIGNED(len, ve_page_info.page_size)) {
		rounded_len = ALIGN(len, ve_page_info.page_size);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Roundup length: %lu\n", rounded_len);
	} else {
		rounded_len = len;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Length already aligned: %lu\n", rounded_len);
	}

	/* Call VH mprotect system call */
	retval = syscall(syscall_num, addr, rounded_len, prot);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ARGS dump: arg1 %lx arg2 %ld arg3 %d\n",
				addr, rounded_len, prot);
		goto err_mprotect;
	}

	/* AMM communication */
	retval = amm_request_mprotect(handle, addr, rounded_len, prot,
			UNSET_ATB);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Request to AMM Failed\n");

		/*TODO: AMM error code is yet to design after analysing
		 * the standard error codes.It should be in such a way
		 * that there should not be any overlap with the standard
		 * errors.As of now setting it as EFAULT
		 */
		retval = -EFAULT;
		goto err_mprotect;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"syscall %s returned %d\n",
			syscall_name,
			(int)retval);

err_mprotect:
	return_system_call(retval);
	return;
}

/**
* @brief  This function to handle msync system call.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handle for VE driver interface
*/
void ve_msync(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t ve_addr;
	size_t size;
	int64_t retval;
	int flag;
	uint64_t args[3];
	uint64_t end;

	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto hndl_error;
	}

	/*Read msync system call arguments */
	ve_addr = (uint64_t)args[0];
	size = (size_t)args[1];
	flag    = (int)args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Arguments received 0x%lx 0x%lx 0x%x\n",
			(uint64_t)ve_addr, size, flag);

	end = ve_addr + size;
	if (end < ve_addr) {
		retval = -ENOMEM;
		goto hndl_error;
	}
	if (ve_addr == end) {
		retval = 0;
		goto hndl_error;
	}

	/* Check address is 2MB page size aligned or not */
	if (!IS_ALIGNED(ve_addr, ve_page_info.page_size)) {
		retval = -EINVAL;
		goto hndl_error;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"VEMVA is aligned\n");
	}

	 /* aligned size to page size.*/
	if (!IS_ALIGNED(size, ve_page_info.page_size))
		/*
		 * RoundUp Size
		 */
		size = ALIGN(size, ve_page_info.page_size);

	retval = get_page_size(ve_addr);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Page Size not recognised\n");
		retval = -ENOMEM;
		goto hndl_error;
	}

	/*call __ve_msync here*/
	retval	= __ve_msync(handle, (void *)ve_addr, size, flag);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"__ve_msync returned failure\n");
		goto hndl_error;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Return value of system call is :%lx\n", retval);

hndl_error:
	return_system_call(retval);
	return;
}

/**
* @brief This function handles the sync functionality.
*
* @param[in] handle vedl_handle
* @param[in] vemva Virtual Address of VE Process to be synced.
* @param[in] size size of data to be synced.
* @param[in] flag msync flags.
*
* @return  Return 0 on Success and -1 on error.
*/
int64_t __ve_msync(vedl_handle *handle, void *vemva, uint64_t size, int flag)
{
	void *ve_addr;
	void *vh_addr;
	int64_t retval = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	ve_addr = vemva;
	vh_addr = vemva;

	/*
	 * If any bit other than MS_ASYNC | MS_INVALIDATE | MS_SYNC
	 * is set Return EINVAL
	 * */
	if (flag & ~(MS_SYNC | MS_ASYNC | MS_INVALIDATE)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"invalid flags\n");
		retval = -1;
		errno = EINVAL;
		goto return1;
	}

	/*If MS_ASYNC and MS_SYNC Both flags are provided then Return EINVAL*/
	if ((flag & MS_ASYNC) && (flag & MS_SYNC)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"MS_ASYNC and MS_SYNC cannot proviede together\n");
		retval = -1;
		errno = EINVAL;
		goto return1;
	}

	/*Check if the address received is VE Page aligned or not.*/
	if (!IS_ALIGNED((uint64_t)ve_addr, ve_page_info.page_size)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve address is not aligned\n");
		retval = -1;
		errno = EINVAL;
		goto return1;
	}

	/* receive the data from VE memory*/
	if (-1 == ve_recv_data(handle, (uint64_t)ve_addr, size, vh_addr)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_data fail\n");
		retval = -1;
		errno = EFAULT;
		goto return1;
	}

	/*call VH system call */
	if (flag & (MS_SYNC | MS_ASYNC | MS_INVALIDATE)) {
		retval = msync(vh_addr, size, flag);
		if (-1 == retval) {
			retval = -1;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"msync failed %s\n",
					strerror(errno));
			goto return1;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"msync done %s\n", strerror(errno));
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
return1:
	return retval;
}
/**
* @brief This function is used to obtain virtual memory for VE on VH side.
*
* @param[in] handle handle vedl_handle
* @param[out] addr Memory address for mapping
* @param[in] size Memory length to map
* @param[in] flag flag to control memory mapping
* @param[in] prot Memory protection flag
* @param[in] fd File descriptor for file backed mapping
* @param[in] offset Offset to file
*
* @return  return virtual address on success and (void *)-1 on error
*/
void *pseudo_vemva_allocation(vedl_handle *handle, uint64_t addr, uint64_t size,
		int flag, int prot, int fd, uint64_t offset)
{
	struct pseudo_vemva *vemva_tmp = NULL;
	void *vemva = (void *)-1;
	uint64_t count;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"ARGS:: addr:%lx size:%lx flag:%x "
			"prot:%x fd:%x offset:%lx\n",
			addr, size, flag, prot, fd, offset);

	/*If addr is unaligned and map FIXED is Specified Return ERROR*/
	if (!IS_ALIGNED(addr, ve_page_info.page_size)) {
		if (flag & MAP_FIXED) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Unaligned addr.\n");
			errno = EINVAL;
			return (void *)-1;
		} else {
			addr = ALIGN(addr, ve_page_info.page_size) -
				ve_page_info.page_size;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"Roundup addr:%lu\n", addr);
		}
	}

	/*
	 * Calculate the Number of pages Required
	 */
	count = size/ve_page_info.page_size;

	if (!addr && !(flag & MAP_FIXED)) {
		/*scan the list for free pages*/
		vemva = scan_pseudo_vemva(count, flag | MARK_BITS);
		if ((void *)-1 == vemva) {
			vemva_tmp = create_pseudo_vemva(0, flag);
			if (NULL == vemva_tmp)
				goto err_exit;
			/**
			 * Now the request can be fulfilled.
			 * As a new VEMVA is just allocated
			 */
			vemva = pseudo_get_free_vemva(vemva_tmp,
					count, MARK_BITS);
			if ((void *)-1 == vemva)
				goto err_exit;
		}
	} else if (!addr && (flag & MAP_FIXED)) {
		errno = EINVAL;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument.\n");
		goto err_exit;
	} else {
		vemva = avail_vemva(handle, addr, size, flag);
		if ((void *)-1 == vemva)
			goto err_exit;
	}

	/* mmap the space with the permissions and flag given by the user */
	pthread_mutex_lock(&vemva_header.vhos_mmap_lock);
	if (vemva != mmap(vemva, size, prot, MAP_FIXED | flag, fd, offset)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH OS mmap failed\n");
		if (vemva_mark_unused((uint64_t)vemva, size))
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in setting bits in list.\n");
		if (vemva_mark_unsyncable((uint64_t)vemva, size))
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in setting bits in list.\n");
		pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
		goto err_exit;
	}
	pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);

	/*update msync_bitmap*/
	if ((flag & MAP_SHARED) && (prot & PROT_WRITE) &&
				!(prot & PROT_NONE)) {
		if (vemva_mark_syncable((uint64_t)vemva, size)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in clearing msync "
					"bits in list.\n");
			goto err_exit;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: vemva %p\n", vemva);
	return vemva;
err_exit:
	return (void *)-1;
}

/**
* @brief This function allocate the VEMVA memory.
*
*	if MAP_FIXED flag is passed by the user who calls
*	mmap(). Also do unmap if requested VEMVA was already
*	allocated to VE process.
*
* @param[in] handle Pointer to VEDL handle
* @param[in] vemva_tmp Pointer to pseudo vemva list
* @param[out] vaddr VEMVA to map
* @param[in] entry Offset in the list where the inputed VEMVA lies
* @param[in] count Number of 2MB virtual addreses required
* @param[in] flag Additional map information.
*
* @return  On Success,returns VEMVA address or (void *)-1 in case of failure.
*/
void *vemva_map_fixed(vedl_handle *handle, struct pseudo_vemva *vemva_tmp,
		uint64_t vaddr, int64_t entry, int64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;

	uint64_t size = count*ve_page_info.page_size;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: vaddr: %p\n",
			(void *)vaddr);
	if ((count + entry) <= MAX_VEMVA_PER_LIST) {
		/*Check If VEMVA are available or not*/
		if (flag & SYNC_ONLY) {
			sync_syncable_data(handle, (void *)vaddr, size);
		} else {
			if (check_bits_unused(vemva_tmp->bitmap,
						entry, count)) {
				if (free_vemva(handle, vemva_tmp, entry,
							count, flag)) {
					VE_LOG(CAT_PSEUDO_CORE,
							LOG4C_PRIORITY_ERROR,
							"Error making VEMVA "
							"available\n");
					goto err_exit;
				}
			}
			mark_bits_used(vemva_tmp->bitmap, entry, count);
		}
		vemva = (void *)vaddr;
	} else {
		errno = EINVAL;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Can't allocate VEMVA.\n");
		goto err_exit;
	}
err_exit:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: vemva: %p\n", vemva);
	return vemva;
}
/**
* @brief  This function allocate the VEMVA.
*
*	This function will allocate the VE memory
*	if MAP_FIXED flag is not passed by the user who calls mmap().
*
* @param[in] vemva_tmp Pointer to pseudo vemva list
* @param[out] vaddr VEMVA to map
* @param[in] entry Offset in the list where the inputed VEMVA lies
* @param[in] count Number of 2MB virtual addreses required
* @param[in] flag Additional map information.
*
* @return  On Success, VEMVA or (void *)-1 in case of failure.
*/
void *vemva_not_map_fixed(struct pseudo_vemva *vemva_tmp,
		uint64_t vaddr, int64_t entry, int64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: vaddr: %p\n",
			(void *)vaddr);

	if (entry + count <= MAX_VEMVA_PER_LIST) {
		/*Check If VEMVA are available or not*/
		if (!check_bits_unused(vemva_tmp->bitmap, entry, count)) {
			mark_bits_used(vemva_tmp->bitmap, entry, count);
			vemva = (void *)vaddr;
		} else {
			vemva = pseudo_get_free_vemva(vemva_tmp,
					count, MARK_BITS);
		}
	} else {
		vemva = pseudo_get_free_vemva(vemva_tmp, count, MARK_BITS);
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: vemva: %p\n", vemva);
	return vemva;
}
/**
* @brief  This function allocate the VE virtual address.
*
*	This function allocate the VE virtual address if address is
*	given as a argument in mmap().
*
* @param[in] handle Pointer to VEDL handle
* @param[mmap] vaddr VEMVA to map
* @param[in] size Size of the memory to map
* @param[in] flag Additional information for memory mapping
*
* @return  On Success, return the request VEMVA or NULL in case of error.
*/
void *avail_vemva(vedl_handle *handle, uint64_t vaddr,
		uint64_t size, uint64_t flag)
{
	struct pseudo_vemva *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;
	void *vemva = (void *)-1;

	void *vemva_base;
	int64_t entry;
	uint64_t count;
	uint64_t required_type;

	count = size / ve_page_info.page_size;

	vemva_base = (void *)((uint64_t)vaddr & ~ve_page_info.chunk_mask);
	entry = ((uint64_t)vaddr &
			ve_page_info.chunk_mask)/ve_page_info.page_size;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: addr: %p Size: %lx "
			"flags: %ld\n",
			(void *)vaddr, size, flag);

	if (flag & MAP_HUGETLB)
		required_type = ANON_SPACE_64MB;
	else
		required_type = ANON_SPACE_2MB;

	/*Fetch the bitmap from vemva_start*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);

		if (vemva_tmp->type != required_type)
			continue;

		if (vemva_base == vemva_tmp->vemva_base &&
				(flag & MAP_FIXED)) {
			vemva = vemva_map_fixed(handle, vemva_tmp,
					vaddr, entry, count, flag);
			break;
		} else if (vemva_base == vemva_tmp->vemva_base &&
				!(flag & MAP_FIXED)) {
			vemva = vemva_not_map_fixed(vemva_tmp,
					vaddr, entry, count, flag);
			break;
		}
	}

	/*Now the request could not be completed using existing list*/
	if ((void *)-1 == vemva) {
		vemva_tmp = create_pseudo_vemva(vaddr, flag);
		if (NULL == vemva_tmp) {
			if (!(flag & MAP_FIXED)) {
				if (flag & SYNC_ONLY)
					vemva = scan_pseudo_vemva(count,
							flag | ~MARK_BITS);
				else
					vemva = scan_pseudo_vemva(count,
							flag | MARK_BITS);
			}
			goto err_exit;
		}
		/*Check If the requested block of VEMVA lies in this chunk*/
		if ((vemva_tmp->vemva_base == vemva_base) &&
				(entry + count <= MAX_VEMVA_PER_LIST)) {
			if (!(flag & SYNC_ONLY))
				mark_bits_used(vemva_tmp->bitmap,
						entry, count);
			vemva = (void *)vaddr;
		} else if (flag & MAP_FIXED) {
			if (fini_pseudo_vemva(vemva_tmp)) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"fini_pseudo_vemva failed.\n");
				goto err_exit;
			}
			errno = EINVAL;
			goto err_exit;
		} else {
			/*Serve the request from this chunk*/
			if (flag & SYNC_ONLY)
				vemva = pseudo_get_free_vemva(vemva_tmp,
						count, ~MARK_BITS);
			else
				vemva = pseudo_get_free_vemva(vemva_tmp,
						count, MARK_BITS);
		}
	}

err_exit:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: vemva: %p\n", vemva);
	return vemva;
}
/**
* @brief  This function is used to allocate and intilize VEMVA.
*
* @param[out] vaddr VE virtual address
* @param[in] flag large or Huge pseudo_vemva.
*
* @return  On Success, returns the pointer to pseudo vemva list or NULL
* in case of failure.
*/
struct pseudo_vemva *init_pseudo_vemva(uint64_t vaddr, uint64_t flag)
{
	void *vemva_base;
	struct pseudo_vemva *vemva_tmp;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: vaddr:"
			"%lx flag: 0x%lx\n", vaddr, flag);
	vemva_tmp = (struct pseudo_vemva *)malloc(sizeof(struct pseudo_vemva));
	if (vemva_tmp == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc in alloc_vemva FAILED\n");
		return NULL;
	}

	memset(vemva_tmp, 0, sizeof(struct pseudo_vemva));
	if (!vaddr) {
		vemva_base = get_aligned_vemva(flag);
		if (NULL == vemva_base) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Can't get 512Mb Chunk.\n");
			free(vemva_tmp);
			return NULL;
		}
		/*Set type field of vemva_tmp*/
		if (flag & MAP_HUGETLB)
			/*64MB Page_Size, Anon space mapping.*/
			vemva_tmp->type = ANON_SPACE_64MB;
		else
			/*2MB Page_Size, Anon space mapping.*/
			vemva_tmp->type = ANON_SPACE_2MB;
	} else if (!((flag & VE_MAP_STACK) || (flag & VE_MMAP_GROWS_UP))) {
		/*check if vaddr lies in anon space*/
		vemva_base = (void *)(vaddr & ~(ve_page_info.chunk_mask));

		/*
		 * Check failure conditions here
		 */
		if ((!(((uint64_t)vemva_base >= vemva_header.ve_anon_start) &&
		((uint64_t)vemva_base <= vemva_header.ve_anon_start+CHUNK_512GB)))
				&& (flag & MAP_FIXED)) {
			errno = EINVAL;
			return NULL;
		}
		if (!(flag & MAP_HUGETLB)) {
			if ((!(((uint64_t)vemva_base >=
				(vemva_header.top_large)) &&
				((uint64_t)vemva_base <=
				vemva_header.top_large + CHUNK_16GB)))
				&& (flag & MAP_FIXED)) {
				errno = EINVAL;
				return NULL;
			}
		}

		/*Set type field of vemva_tmp*/
		if (flag & MAP_HUGETLB)
			/*64MB Page_Size, Anon space mapping.*/
			vemva_tmp->type = ANON_SPACE_64MB;
		else
			/*2MB Page_Size, Anon space mapping.*/
			vemva_tmp->type = ANON_SPACE_2MB;
	} else {

		/*check if vaddr lies in addr space*/
		vemva_base = (void *)(vaddr & ~(ve_page_info.chunk_mask));

		/*
		 * Check failure conditions here
		 */
		if (!(((uint64_t)vemva_base >= vemva_header.ve_text) &&
					((uint64_t)vemva_base <= vemva_header.ve_text+CHUNK_512GB))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"vemva lies in mmap chunk\n");
			errno = EINVAL;
			return NULL;
		}

		/*Set type field of vemva_tmp*/
		if (flag & MAP_HUGETLB)
			/*64MB Page_Size, Addr space mapping.*/
			vemva_tmp->type = ADDR_SPACE_64MB;
		else
			/*2MB Page_Size, Addr space mapping.*/
			vemva_tmp->type = ADDR_SPACE_2MB;
	}

	vemva_tmp->vemva_base = vemva_base;
	/*SET bitmap to all 1's Indicating all the pages are unused*/
	memset(vemva_tmp->bitmap, 0xff, sizeof(vemva_tmp->bitmap));

	/*SET sync_bitmap to all 1's Indicating NO pages have to be synced */
	memset(vemva_tmp->sync_bitmap, 0xff, sizeof(vemva_tmp->sync_bitmap));

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"New VEMVA List created with base: 0x%lx\n",
			(long int)vemva_base);

	return vemva_tmp;
}
/**
* @brief  This function removes the entry from pseudo vemvai list.
*
* @param[in] vemva_tmp Pointer to pseudo vemva
*
* @return  On Success, returns 1 and 0 in case of failure.
*/
int fini_pseudo_vemva(struct pseudo_vemva *vemva_tmp)
{
	int retval;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: vemva_tmp: %p\n",
			vemva_tmp);
	/*unmap vemva_base*/
	retval = munmap(vemva_tmp->vemva_base, CHUNK_512MB);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH OS munmap failed\n");
		perror("Error:");
		return -1;
	}
	list_del(&vemva_tmp->list);
	pseudo_vemva_count--;
	/*free vemva descriptor*/
	free(vemva_tmp);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Success\n");
	return 0;
}

/**
* @brief  This function is used to find free VEMVA.
*
*	It will Calculate virtual address according to free bitmap Index and
*	VEMVA Base,clear the corresponding bits(That will represent used
*	VEMVA).
*
* @param[in] vemva_tmp Pointer to pseudo vemva list
* @param[in] count Number of 2MB virtual address
* @param[in] flag Additional information contained in flag.
*
* @return  On Success, return the available VEMVA or (void *)-1
* in case of error.
*/
void *pseudo_get_free_vemva(struct pseudo_vemva *vemva_tmp, int64_t count,
		uint64_t flag)
{
	void *vemva;
	int64_t entry;
	int64_t contigious_free = 0;
	int64_t word_index, bit_index;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva_tmp %p count %ld\n",
			vemva_tmp, count);
	for (word_index = 0; word_index < WORDS_PER_BITMAP; word_index++) {
		for (bit_index = 0; bit_index < BITS_PER_WORD; bit_index++) {
			if (vemva_tmp->bitmap[word_index] &
					((uint64_t)1<<bit_index)) {
				contigious_free++;
				if (contigious_free == count)
					goto out;
			} else
				contigious_free = 0;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "Return: failure\n");
	return (void *)-1;
out:
	/*
	 * Clear The corresponding Bits. As a zero represent used.
	 */
	entry = ((word_index*BITS_PER_WORD)+(bit_index-count+1));
	if (flag & MARK_BITS)
		mark_bits_used(vemva_tmp->bitmap, entry, count);
	/*
	 * Calculate virtual address according to free Index and VEMVA Base
	 */
	vemva = vemva_tmp->vemva_base + (ve_page_info.page_size * entry);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: vemva: %p\n", vemva);
	return vemva;
}

/**
* @brief  This function is used to de allocate virtual memory for VE.
*
* @param[in] handle Handle for VE driver interface
* @param[in] vemva_addr Virtual VE address to be de allocated
* @param[in] size Memory size to map
* @param[in] flag Additional Information for mapping.
*
* @return  return 0 on success and -1 on error.
*/
int release_vemva(vedl_handle *handle, void *vemva_addr, size_t size, int flag)
{
	void *vemva_base;
	int64_t entry;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;
	struct pseudo_vemva *vemva_del = NULL;

	int64_t count;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva_addr %p size %lx\n",
			vemva_addr, size);
	count = size/ve_page_info.page_size;

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vemva_addr &
			(~(ve_page_info.chunk_mask)));
	/*Calculate entry using vemva_addr*/
	entry = ((uint64_t)vemva_addr &
			(ve_page_info.chunk_mask))/ve_page_info.page_size;


	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct pseudo_vemva, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}
		if (vemva_del == NULL) {
			errno = EINVAL;
			return -1;
		}

		/*Set the corresponding bits in bitmap to make it available*/
		mark_bits_unused(vemva_del->bitmap, entry, count);

		sync_syncable_data(handle, vemva_addr, size);

		/* Set the corresponding bits in msync bitmap
		 * to make it available
		 */
		mark_bits_unused(vemva_del->sync_bitmap, entry, count);

		/* Do VHOS mmap on the address space to free
		 * with PROT_NONE and MAP_ANON | MAP_FIXED
		 */
		pthread_mutex_lock(&vemva_header.vhos_mmap_lock);
		if (vemva_addr != mmap(vemva_addr, size, PROT_NONE,
					MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
					-1, 0)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS mmap failed With MAP_FIXED\n");
			perror("VHOS mmap");
			pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
			return -1;
		}
		pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Return: Success\n");
		return 0;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Failure\n");
	return -1;
}

/*TODO: These Bitmap Manipulation routines should be more optimised*/
/**
* @brief  This function marks the requested bits in the bitmap as used.
*
* @param[in] bitmap Pseudo VEMVA list bitmap
* @param[in] entry Offset in the list
* @param[in] count Number of 2MB virtual address
*/
void mark_bits_used(uint64_t *bitmap, int64_t entry, int64_t count)
{
	int64_t word, bit;
	int64_t ent;

	word = entry/BITS_PER_WORD;
	bit = entry%BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		bitmap[word] = bitmap[word] & (~((uint64_t)1 << bit++));
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
}

/**
* @brief  This function check that requested bits are already used or not.
*
* @param[in] bitmap Pseudo VEMVA list bitmap
* @param[in] entry Offset in the list
* @param[in] count Number of 2MB virtual address
*
* @return  On Success, it returns 0 and -1 on failure.
*/
int check_bits_used(uint64_t *bitmap, int64_t entry, int64_t count)
{
	int64_t word, bit;
	int64_t ent;

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		if (bitmap[word] & ((uint64_t)1 << bit++))
			goto err_out;
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	return 0;
err_out:
	return -1;
}

/**
* @brief  This functions check that request bits are already used or not.
*
* @param[in] bitmap Pseudo VEMVA list bitmap
* @param[in] entry Offset in the list
* @param[in] count Number of 2MB virtual address
*
* @return  On Success, it returns 0 and -1 on failure.
*/
int check_bits_unused(uint64_t *bitmap, int64_t entry, int64_t count)
{
	int64_t word, bit;
	int64_t ent;

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		if (!(bitmap[word] & ((uint64_t)1 << bit++)))
			goto err_out;
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	return 0;
err_out:
	return -1;
}

/**
* @brief This function sets(Marks as available) the bitmap
* in pseudo vemva list corresponding to VEMVA given till the size.
*
* @param[out] vemva VEMVA whose bits to set
* @param[in] size Size of the request
*
* @return on success return 0 and -1 on failure
*/
int vemva_mark_unused(uint64_t vemva, uint64_t size)
{
	int64_t entry;
	int64_t count;
	uint64_t vemva_base;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva %lx size %lx\n",
			vemva, size);
	vemva_base = (vemva & (~(ve_page_info.chunk_mask)));
	count = size / ve_page_info.page_size;

	/* Calculate entry using vemva */
	entry = (vemva & (ve_page_info.chunk_mask))/
		ve_page_info.page_size;

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);
		if ((uint64_t)vemva_tmp->vemva_base == vemva_base)
			goto unuse_bits;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"VEMVA not found in existing list\n");
	return -1;
unuse_bits:
	mark_bits_unused(vemva_tmp->bitmap, entry, count);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "VEMVA marked unused\n");
	return 0;
}

/**
* @brief  This function release the already allocated VEMVA to VE process.
*
* @param[in] handle Pointer to VEDL handle
* @param[in] vemva_tmp Pointer to pseudo_vemva list
* @param[in] entry Offset in the list
* @param[in] count Number of 2MB virtual address to release
* @param[in] flag Additional Information.
*
* @return  On Success, it returns 0 and -1 on failure.
*/
int free_vemva(vedl_handle *handle, struct pseudo_vemva *vemva_tmp,
		int64_t entry, int64_t count, uint64_t flag)
{
	int64_t word, bit;
	int64_t ent;
	int64_t retval;
	uint64_t addr;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva_tmp %p entry %ld count %ld\n",
			vemva_tmp, entry, count);
	if ((entry + count) > MAX_VEMVA_PER_LIST)
		goto err_out;

	for (ent = 0; ent < count; ent++) {
		word = entry / BITS_PER_WORD;
		bit = entry % BITS_PER_WORD;
		if (!(vemva_tmp->bitmap[word] & ((uint64_t)1<<bit))) {
			addr = (uint64_t)(vemva_tmp->vemva_base +
					(entry * ve_page_info.page_size));
			/* TODO: VEMVA Locking has to be enhanced
			 * For Now We will Release the lock here and
			 * after __ve_munmap we will get it back*/
			pthread_mutex_unlock(&vemva_header.vemva_lock);
			retval = __ve_munmap(handle, addr,
					ve_page_info.page_size, 0, UNSET_ATB);
			pthread_mutex_lock(&vemva_header.vemva_lock);
			if (-1 == retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Fails to UNMAP memory region\n"
						);
				retval = -errno;
				goto err_out;
			}
		}
		entry++;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Success\n");
	return 0;
err_out:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Failure\n");
	return -1;
}

/**
* @brief  This function marks the bits as unused in the
* pseudo vemva bitmap at an entry till the count given.
*
* @param[out] bitmap[4] Pseudo VEMVA list bitmap
* @param[in] entry Position from which bits are set
* @param[in] count Number of bits to set
*/
void mark_bits_unused(uint64_t bitmap[4], int64_t entry, int64_t count)
{
	int64_t word, bit;
	int ent;

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		bitmap[word] = bitmap[word] | ((uint64_t)1 << bit++);
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
}

/**
* @brief  This function scans all the already created VEMVA
* list to get the available VEMVA's multiple of count of size 2MB.
*
* @param[in] count Multiple of 2MB Virtual Address required.
* @param[in] flag Additional scan information contained in flag.
*
* @return  On Success, return the VEMVA and on failure return (void *)-1
*/
void *scan_pseudo_vemva(uint64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;
	uint64_t required_type;
	struct pseudo_vemva *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;

	if (flag & MAP_HUGETLB)
		required_type = ANON_SPACE_64MB;
	else
		required_type = ANON_SPACE_2MB;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: count %ld\n", count);
	/*
	 * Scan the entire pseudo_vemva list to get the available
	 * VEMVA.
	 */
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);

		if (vemva_tmp->type != required_type)
			continue;

		vemva = pseudo_get_free_vemva(vemva_tmp, count, flag);
		if (vemva == (void *)-1)
			continue;
		else
			break;
	}
	if (vemva != (void *)-1)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Return: vemva %p\n", vemva);
	else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"No free VEMVA found in existing list\n");
	return vemva;
}

/**
* @brief  This function creates a new VEMVA Chunk.
*
*	and chunk should contain vaddr in it.
*
* @param[in] vaddr VEMVA in a chunk.
* @param[in] flag Additional information for required VEMVA .
*
* @return  On Success, return pointer to struct pseudo_vemva and
* NULL in case of failure.
*/
struct pseudo_vemva *create_pseudo_vemva(uint64_t vaddr, uint64_t flag)
{
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vaddr %p\n", (void *)vaddr);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Pseudo VEMVA Count: %ld\n", pseudo_vemva_count);

	/*
	 * Depending upon MAX_VEMVA_LIST if new pseudo_vemva
	 * list can be allocated or not.
	 */
	if (pseudo_vemva_count >= MAX_VEMVA_LIST) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Can not allocate more VEMVA list.\n");
		errno = ENOMEM;
		goto err_exit;
	}

	/*Allocate a new chunk of memory and Initalize it*/
	vemva_tmp = init_pseudo_vemva(vaddr, flag);
	if (vemva_tmp == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"init_pseudo_vemva failed.\n");
		goto err_exit;
	}

	/*Add the newly allocated descriptor in the End of the list*/
	list_add_tail(&vemva_tmp->list, &vemva_header.vemva_list);
	pseudo_vemva_count++;
err_exit:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Return: pseudo_vemva_desc %p\n", vemva_tmp);
	return vemva_tmp;
}

/**
* @brief  This Function Initialize vemva_header.
*
* @return  Return 0 on Success -1 on error.
*/
int init_vemva_header(void)
{
	void *mmap_chunk_base;
	/*Allocate 512GB mmap chunk here*/
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Reserving mmap_chunk.\n");
	mmap_chunk_base = get_512GB_aligned_vemva();
	if ((void *)-1 == mmap_chunk_base) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH mmap failed: %s\n", strerror(errno));
		return -1;
	}

	vemva_header.ve_anon_start = (uint64_t)mmap_chunk_base;
	vemva_header.base_large = (uint64_t)mmap_chunk_base;
	vemva_header.top_large = (uint64_t)mmap_chunk_base;
	vemva_header.base_huge = CHUNK_16GB+(uint64_t)mmap_chunk_base;
	vemva_header.top_huge = CHUNK_16GB+(uint64_t)mmap_chunk_base;

	/*init VEMVA lock*/
	if (0 != pthread_mutex_init(&vemva_header.vemva_lock, NULL)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Init vemva_lock failed\n");
		return -1;
	}

	/*init mmap_lock*/
	if (0 != pthread_mutex_init(&vemva_header.vhos_mmap_lock, NULL)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Init mmap_lock failed\n");
		return -1;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Success\n");
	return 0;
}

/**
* @brief  This function mark sync_bitmap bits showing file backed mmap.
*
* @param[out] vemva VEMVA whose bits to set
* @param[in] size Size of the request
*
* @return  Return 0 on success and -1 on error.
*/
int vemva_mark_syncable(uint64_t vemva, uint64_t size)
{
	int64_t retval = -1;
	int64_t entry;
	int64_t count;
	uint64_t vemva_base;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	vemva_base = (vemva & (~(ve_page_info.chunk_mask)));
	count = size / ve_page_info.page_size;

	/* Calculate entry using vemva */
	entry = (vemva & (ve_page_info.chunk_mask))/ve_page_info.page_size;

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);
		if ((uint64_t)vemva_tmp->vemva_base == vemva_base)
			goto clear_bits;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Err_Out Func\n");
	return retval;
clear_bits:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
	mark_bits_used(vemva_tmp->sync_bitmap, entry, count);
	return 0;
}

/**
* @brief  This function clears sync_bitmap bits showing file backed mmap.
*
* @param[out] vemva VEMVA whose bits to set
* @param[in] size Size of the request
*
* @return  Return 0 on success and -1 on error.
*/
int vemva_mark_unsyncable(uint64_t vemva, uint64_t size)
{
	int64_t retval = -1;
	int64_t entry;
	int64_t count;
	uint64_t vemva_base;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	vemva_base = (vemva & (~(ve_page_info.chunk_mask)));
	count = size / ve_page_info.page_size;

	/* Calculate entry using vemva */
	entry = (vemva & (ve_page_info.chunk_mask))/ve_page_info.page_size;

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);
		if ((uint64_t)vemva_tmp->vemva_base == vemva_base)
			goto clear_bits;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Err_Out Func\n");
	return retval;
clear_bits:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
	mark_bits_unused(vemva_tmp->sync_bitmap, entry, count);
	return 0;
}


/**
* @brief  This function clears msync_bitmap bits
* showing file backed mmap.
*
* @param[in] vemva VEMVA whose bits to set
* @param[in] size Size of the request
*
* @return  Return 0 on success and -1 on error.
*/
int vemva_mark_used(uint64_t vemva, uint64_t size)
{
	int64_t retval = -1;
	int64_t entry;
	int64_t count;
	uint64_t vemva_base;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	vemva_base = (vemva & (~(ve_page_info.chunk_mask)));
	count = size / ve_page_info.page_size;

	/* Calculate entry using vemva */
	entry = (vemva & (ve_page_info.chunk_mask))/ve_page_info.page_size;

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);
		if ((uint64_t)vemva_tmp->vemva_base == vemva_base)
			goto clear_bits;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Err_Out Func\n");
	return retval;
clear_bits:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
	mark_bits_used(vemva_tmp->bitmap, entry, count);
	return 0;
}

/**
* @brief  This function traverse through the pseudo_vemva_desc list
* and syncs file_backed data on ve memory, to the disk on VH.
*
* @param[in] handle Pointer to struct vedl_handle.
*/
void sync_at_exit(vedl_handle *handle)
{
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);
		/*access sync_bitmap*/
		if (vemva_tmp->type == ANON_SPACE_2MB)
			sync_data(handle, vemva_tmp->vemva_base,
					vemva_tmp->sync_bitmap);
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
}

/**
* @brief  This function sync the data which has to be synced,by scaning
* a particular bitmap.
*
* @param[in] handle Pointer to struct vedl_handle.
* @param[in] vemva_base Pointer to the base address of the chunk.
* @param[in] bitmap[WORDS_PER_BITMAP] Pointer to bitmap to be scanned.
*/
void sync_data(vedl_handle *handle, void *vemva_base,
		uint64_t bitmap[WORDS_PER_BITMAP])
{
	int64_t word = 0;
	int64_t bit = 0;
	uint64_t ent;
	uint64_t size;
	uint64_t ve_addr;
	int64_t ret;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "In Func\n");
	ret = get_page_size((uint64_t)vemva_base);
	if (-1 == ret) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Page Size not recognised\n");
		errno = EINVAL;
		return;
	}

	for (ent = 0; ent < (BITS_PER_WORD * WORDS_PER_BITMAP); ent++) {
		if (!(bitmap[word] & ((uint64_t)1 << bit))) {
			size = ve_page_info.page_size;
			ve_addr = (uint64_t)vemva_base |
				(((word*BITS_PER_WORD)+bit)*
				 ve_page_info.page_size);
			ret = __ve_msync(handle, (void *)ve_addr,
					size, MS_SYNC);
			if (ret) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"__ve_msync failed\n");
				return;
			}
		}
		if (++bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
}

/**
* @brief  This function sync the data which has to be synced, by scaning
* a particular bitmap.
*
* @param[in] handle Pointer to struct vedl_handle.
* @param[in] vaddr vemva to sync.
* @param[in] size size to be synced.
*/
void sync_syncable_data(vedl_handle *handle, void *vaddr, uint64_t size)
{
	struct pseudo_vemva *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;
	void *vemva_base;
	int64_t ent;
	int64_t entry;
	int64_t entry_end;
	int64_t word = 0;
	int64_t bit = 0;
	uint64_t ve_addr;
	int64_t ret;

	vemva_base = (void *)((uint64_t)vaddr &
			(~(ve_page_info.chunk_mask)));
	entry = ((uint64_t)vaddr &
			(ve_page_info.chunk_mask))/ve_page_info.page_size;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: addr: %p Size: %lx\n", vaddr, size);

	/*Fetch the bitmap from vemva_start*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);

		if (vemva_tmp->type != ANON_SPACE_2MB)
			continue;
		if (vemva_base == vemva_tmp->vemva_base)
			break;
		else
			vemva_tmp = NULL;
	}

	if (vemva_tmp == NULL) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid vaddr\n");
		return;
	}

	entry_end = entry + size/ve_page_info.page_size;
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = entry; ent < entry_end; ent++) {
		if (!(vemva_tmp->sync_bitmap[word] &
					((uint64_t)1 << bit))) {
			size = ve_page_info.page_size;
			ve_addr = (uint64_t)vemva_base |
				((((word*BITS_PER_WORD)+bit))
				 * ve_page_info.page_size);
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"ve_addr: %p\n", (void*)ve_addr);
			ret = __ve_msync(handle, (void *)ve_addr,
					size, MS_SYNC);
			if (ret) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"__ve_msync failed\n");
				return;
			}
		}
		if (++bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
}

/**
* @brief  This function is to handle mremap system call.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handle for VE driver interface
*/
void ve_mremap(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t vaddr_old;
	uint64_t size_old;
	uint64_t size_new;
	uint64_t flag;
	uint64_t vaddr_new;
	int64_t  retval;
	uint64_t args[5];

	retval = vedl_get_syscall_args(handle, args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
		goto exit_1;
	}

	vaddr_old = args[0];
	size_old  = args[1];
	size_new  = args[2];
	flag	  = args[3];
	vaddr_new = args[4];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "ARGS:: vaddr_old: 0x%lx, "
			"size_old: 0x%lx,"
			"size_new: 0x%ld, flags: 0x%ld, vaddr_new: 0x%lx\n",
			vaddr_old, size_old, size_new, flag, vaddr_new);

	retval = __ve_mremap(handle, (void *)vaddr_old, size_old,
			size_new, flag, (void *)vaddr_new);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Request to AMM Failed\n");
		retval = -EFAULT;
		goto exit_1;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Return value of mremap: %lx\n",
			(uint64_t)retval);
exit_1:
	return_system_call(retval);
	return;
}

/**
* @brief Function to handle memory re mapping request.
*
* @param[in] handle Handle for VE driver interface
* @param[in] vaddr_old old virtual address to remap
* @param[in] size_old old size to remap
* @param[in] size_new new size to remap
* @param[in] flags flag field of mremap
* @param[in] vaddr_new This argment is optional.
*	It spesify the virtual address to which remapping has to be  done.
*
* @return  Return 0 on sucess, -1 on error.
*/
int64_t __ve_mremap(vedl_handle *handle, void *vaddr_old, uint64_t size_old,
		uint64_t size_new, uint64_t flags, void *vaddr_new)
{
	int64_t retval = -1;
	void *vaddr = NULL;

	/*Check Basic Error Conditions*/
	if (flags & ~(MREMAP_FIXED | MREMAP_MAYMOVE)) {
		errno = EINVAL;
		return retval;
	}

	if ((flags & MREMAP_FIXED) && !(flags & MREMAP_MAYMOVE)) {
		errno = EINVAL;
		return retval;
	}

	if ((uint64_t)vaddr_old & ~ve_page_info.page_mask) {
		errno = EINVAL;
		return retval;
	}
	/*Size should be rounded down*/
	size_old = size_old & (ve_page_info.page_mask);
	size_new = size_new & (ve_page_info.page_mask);

	/*
	 * check if Old_addr + size is already mapped and
	 * remapable?
	 */
	if (!vemva_mapped(vaddr_old, size_old)) {
		errno = EINVAL;
		return retval;
	}

	/*
	 * Linux allow a zero old-len as a special case.
	 * But we in aurora will not support zero old length
	 * and zero new-len as well.
	 */
	if ((!size_new) || (!size_old)) {
		errno = EINVAL;
		return retval;
	}

	if (flags & MREMAP_FIXED) {
		/*
		 * Check if the location we're moving into overlaps the
		 * old location at all, and fail if it does.
		 */
		if ((vaddr_new <= vaddr_old) &&
				(vaddr_new + size_new) > vaddr_old) {
			errno = EINVAL;
			return retval;
		}

		if ((vaddr_old <= vaddr_new) &&
				(vaddr_old + size_old) > vaddr_new) {
			errno = EINVAL;
			return retval;
		}

		if ((uint64_t)vaddr_new & ~ve_page_info.page_mask) {
			errno = EINVAL;
			return retval;
		}
	}

	/*
	 * Always allow a shrinking remap: that just unmaps
	 * the unnecessary pages..
	 */
	if (size_old >= size_new) {
		/*Going to shrink*/
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"VADDR_OLD will shrink!!!\n");
		if (size_old != size_new) {
			retval = __ve_munmap(handle, (uint64_t)
					(vaddr_old+size_new),
					(size_old - size_new), 0, UNSET_ATB);
			if (retval)
				return retval;
		}

		/*
		 * Check if mapping has to be moved
		 */
		if (!(flags & MREMAP_FIXED)) {
			retval = 0;
			return retval;
		} else {
			/*
			 * mapping has to be moved
			 */
			size_old = size_new;
		}
	}
	/*
	 * VEMVA update according to mremap.
	 */
	pthread_mutex_lock(&vemva_header.vemva_lock);
	vaddr = update_vemva(handle, vaddr_old, size_old,
			size_new, flags, vaddr_new);
	pthread_mutex_unlock(&vemva_header.vemva_lock);
	if ((void *)-1 == vaddr) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vemva_update failed\n");
		errno = EFAULT;
		return -1;
	}

	if (mlock(vaddr, size_new)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH mlock fails!!\n");
		perror("mlock");
		return -1;
	}

	/*Request AMM for mremap*/
	retval = amm_request_mremap(handle, (uint64_t)vaddr_old, size_old,
			size_new, (uint64_t)vaddr);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Request to AMM Failed\n");
		errno = EFAULT;
	}

	if (munlock(vaddr, size_new)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH mlock fails!!\n");
		perror("mlock");
		return -1;
	}

	return retval;
}

/**
* @brief  This function updates the vemva data structures for mremap request.
*
* @param[in] handle Handle to VE driver.
* @param[in] vaddr_old virtual address to which remapping has to be  done
* @param[in] size_old old size to remap
* @param[in] size_new new size to remap
* @param[in] flag field of mremap
* @param[in] vaddr_new This argment is optional. It spesify the
*
* @return  Return virtual address to which the mapping has to be moved.
* Return (void *)-1 in case of failure.
*/
void *update_vemva(vedl_handle *handle, void *vaddr_old, uint64_t size_old,
		uint64_t size_new, uint64_t flag, void *vaddr_new)
{
	struct pseudo_vemva *vemva_tmp = NULL;
	void *vaddr = NULL;

	/*
	 * size_old will never be > size_new at this stage
	 * Both can be equal, or size_new > size_old.
	 */
	if (flag & MREMAP_FIXED) {
		/*
		 * This is the case of move
		 */
		vaddr = avail_vemva(handle, (uint64_t)vaddr_new,
				size_new, MAP_FIXED | SYNC_ONLY);
		if ((void *)-1 == vaddr)
			return (void *)-1;
	} else if (flag & MREMAP_MAYMOVE) {
		/*
		 * Check If vaadr_old+size_old is expandable to
		 * vaddr_old+size_new?
		 */
		if (vemva_is_expandable(vaddr_old, size_old, size_new)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"VADDR_OLD is expandable!!!\n");
			vaddr = vaddr_old;
			/*
			 * In This Case some special handling (munmap() the
			 * range size_old-size_new)is required
			 */
		} else {
			/*
			 * This is the case of move
			 */
			uint64_t count;
			flag |= MREMAP_FIXED;
			count = size_new/ve_page_info.page_size;

			vaddr = scan_pseudo_vemva(count, flag | ~MARK_BITS);
			if ((void *)-1 == vaddr) {
				vemva_tmp = create_pseudo_vemva(0, flag);
				if (NULL == vemva_tmp)
					return (void *)-1;
				/**
				 * Now the request can be fulfilled.
				 * As a new VEMVA is just allocated
				 */
				vaddr = pseudo_get_free_vemva(vemva_tmp, count,
						~MARK_BITS);
				if ((void *)-1 == vaddr)
					return (void *)-1;
			}
		}
	} else {
		/*
		 * Check If vaadr_old+size_old is expandable to
		 * vaddr_old+size_new?
		 */
		if (vemva_is_expandable(vaddr_old, size_old, size_new)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"VADDR_OLD is expandable!!!\n");
			vaddr = (void *)vaddr_old;
			/*
			 * In This Case some special handling (munmap() the
			 * range size_old-size_new)is required
			 */
		} else {
			return (void *)-1;
		}
	}

	/*
	 * Take Lock here
	 */
	pthread_mutex_lock(&vemva_header.vhos_mmap_lock);

	/*
	 * call VHOS mremap
	 */
	if (flag & MREMAP_FIXED) {
		/*Sync vaddr_old + size_old if syncable*/
		sync_syncable_data(handle, (void *)vaddr_old, size_old);

		if (vaddr != mremap((void *)vaddr_old, size_old, size_new,
					flag, (void *)vaddr)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					" VH OS mremap failed: "
					" ARGS: vaddr_old: %p, size_old: %p, "
					" size_new: %p, flag: "
					" %ld, vaddr_new: %p\n ",
					(void *)vaddr_old, (void *)size_old,
					(void *)size_new, flag,
					(void *)vaddr);
			perror("VHOS mremap");
			return (void *)-1;
		}

		/*
		 * Refill the hole.Do VHOS mmap on the address space to free
		 * with PROT_NONE and MAP_ANON | MAP_FIXED
		 */
		if ((void *)vaddr_old != mmap((void *)vaddr_old, size_old,
					PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS
					|MAP_FIXED, -1, 0)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS mmap failed With MAP_FIXED\n");
			return (void *)-1;
		}
	} else {
		/*Sync vaddr_old + size_old if syncable*/
		sync_syncable_data(handle, (void *)vaddr_old, size_old);

		/*
		 * When we are going to expand the mapping we should make
		 * it available to pseudo first*/
		if (munmap((void *)(vaddr_old + size_old),
					size_new-size_old)) {
			perror("munmap");
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS munmap failed:"
					"ARGS: vaddr_old: %p, size_old: %p,"
					"size_new: %p\n", (void *)vaddr_old,
					(void *)size_old, (void *)size_new);
			/*Cleanup has to be done here*/
			return (void *)-1;
		}

		/*
		 * Call VHOS mremap to access page cache
		 */
		vaddr = mremap((void *)vaddr_old, size_old, size_new, flag);
		if (MAP_FAILED == vaddr) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS mremap failed:"
					"ARGS: vaddr_old: %p, size_old: %p,"
					"size_new: %p, flag: %ld,"
					"vaddr_new: %p\n",
					(void *)vaddr_old, (void *)size_old,
					(void *)size_new, flag,
					(void *)vaddr);
			perror("VHOS mremap");
			return (void *)-1;
		}
	}

	if ((void *)-1 == vaddr) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VEMVA allocation failed !!\n");
		return (void *)-1;
	}

	/*
	 * Update bits finally
	 */
	if (flag & MREMAP_FIXED) {
		if (vemva_mark_unused((uint64_t)vaddr_old, size_old)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in setting bits in list.\n");
			return (void *)-1;
		}
		if (vemva_mark_used((uint64_t)vaddr, size_new)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in setting bits in list.\n");
			return (void *)-1;
		}
		if (vemva_syncable(vaddr_old, size_old)) {
			if (vemva_mark_unsyncable(
						(uint64_t)vaddr_old,
						size_old)) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Fails in setting "
						"bits in list.\n");
				return (void *)-1;
			}

			if (vemva_mark_syncable((uint64_t)vaddr, size_new)) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Fails in clearing msync "
						"bits in list.\n");
				return (void *)-1;
			}
		}
	} else {
		if (vemva_mark_used((uint64_t)vaddr_old, size_new)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in setting bits in list.\n");
			return (void *)-1;
		}
		if (vemva_syncable(vaddr_old,
					size_old)) {
			if (vemva_mark_syncable(
						(uint64_t)vaddr_old, size_new)) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Fails clearing msync "
						"bits in list.\n");
				return (void *)-1;
			}
		}
	}

	pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
	/* Release Lock */
	return vaddr;
}

/**
* @brief This function verify if the virtual address has been mapped or not.
*
* @param[in] vemva_addr Virtual address to verify
* @param[in] size size to verify
*
* @return  Return 1 on success, 0 on error.
*/
int vemva_mapped(void *vemva_addr, size_t size)
{
	void *vemva_base;
	int retval;
	int64_t entry;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;
	struct pseudo_vemva *vemva_del = NULL;

	int64_t count;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva_addr %p size %lx\n",
			vemva_addr, size);
	count = size/ve_page_info.page_size;

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vemva_addr &
			(~(ve_page_info.chunk_mask)));
	/*Calculate entry using vemva_addr*/
	entry = ((uint64_t)vemva_addr &
			(ve_page_info.chunk_mask))/ve_page_info.page_size;

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct pseudo_vemva, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}
		if (vemva_del == NULL) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx "
					"not allocated\n",
					vemva_addr, size);
			return 0;
		}

		/*Check Bitmap If the VEMVA's were allocated or not*/
		retval = check_bits_used(vemva_del->bitmap, entry, count);
		if (retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx "
					"not allocated\n",
					vemva_addr, size);
			return 0;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx allocated\n",
					vemva_addr, size);
			return 1;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"vemva %p with size %lx is invalid\n",
			vemva_addr, size);
	return 0;
}

/**
* @brief  Check if the vemva is syncable or not.
*
* @param[in] vemva_addr Virtual Address to check.
* @param[in] size Size to check.
*
* @return Return 1 on success, and 0 on error.
*/
int vemva_syncable(void *vemva_addr, size_t size)
{
	void *vemva_base;
	int retval;
	int64_t entry;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;
	struct pseudo_vemva *vemva_del = NULL;

	int64_t count;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"ARGS: vemva_addr %p size %lx\n",
			vemva_addr, size);
	count = size/ve_page_info.page_size;

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vemva_addr &
			(~(ve_page_info.chunk_mask)));
	/*Calculate entry using vemva_addr*/
	entry = ((uint64_t)vemva_addr &
			(ve_page_info.chunk_mask))/ve_page_info.page_size;

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct pseudo_vemva, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}
		if (vemva_del == NULL) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx "
					"not allocated\n",
					vemva_addr, size);
			return 0;
		}

		/*Check Bitmap If the VEMVA's were allocated or not*/
		retval = check_bits_used(vemva_del->sync_bitmap, entry, count);
		if (retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx "
					"is not syncable\n",
					vemva_addr, size);
			return 0;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vemva %p with size %lx is syncable\n",
					vemva_addr, size);
			return 1;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"vemva %p with size %lx is invalid\n",
			vemva_addr, size);
	return 0;
}

/**
* @brief Check if the vemva is expandable or not.
*
* @param[in] vaddr Virtual address to check.
* @param[in] size_old Size to check.
* @param[in] size_new Size upto which vaddr should be expandable.
*
* @return Return 1 if expandable and 0 if not.
*/
int vemva_is_expandable(void *vaddr, uint64_t size_old, uint64_t size_new)
{
	struct pseudo_vemva *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;
	void *vemva_base;
	int64_t entry;
	int64_t entry_1;
	int64_t count_1;

	count_1 = (size_new - size_old) / ve_page_info.page_size;

	vemva_base = (void *)((uint64_t)vaddr &
			(~ve_page_info.chunk_mask));
	entry = ((uint64_t)vaddr &
			ve_page_info.chunk_mask)/ve_page_info.page_size;

	entry_1 = entry + (size_old/ve_page_info.page_size);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"vaddr: %p size_old: %lx size_new: %lx\n",
			vaddr, size_old, size_new);

	/*Fetch the bitmap from vemva_start*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct pseudo_vemva, list);

		if (vemva_tmp->type != ANON_SPACE_2MB)
			continue;

		if (vemva_base == vemva_tmp->vemva_base) {
			/*Check If VEMVA are available or not*/
			if (!check_bits_unused(vemva_tmp->bitmap,
						entry_1, count_1)) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"vaddr_old + size_old "
						"is expandable\n");
				return 1;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"vaddr_old + size_old "
						"is not expandable\n");
				return 0;
			}
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vaddr invalid: %p\n", vaddr);
	return 0;
}

/**
* @brief  Request amm to remap virtual memory.
*
* @param[in] handle Handle for VE driver.
* @param[in] vaddr_old Virtual address to remap
* @param[in] size_old Size from mapping has to be remapped.
* @param[in] size_new Size to mapping has to be remapped.
* @param[in] vaddr_new New address to which mapping should move.
*
* @return Return 0 on success and -1 on error.
*/
int64_t amm_request_mremap(vedl_handle *handle, uint64_t vaddr_old,
		uint64_t size_old, uint64_t size_new, uint64_t vaddr_new)
{
	int veos_sock_fd;
	int64_t retval = -1;
	void *cmd_buf_req;
	size_t pseudo_msg_len;
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE];
	struct mremap_cmd mremap_cmd;

	PseudoVeosMessage *pseudo_msg;

	PseudoVeosMessage ve_mremap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_mremap_msg;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Requesting AMM for mremap\n");

	/* Generate IPC Command */
	mremap_cmd.vaddr_old = vaddr_old;
	mremap_cmd.vaddr_new = vaddr_new;
	mremap_cmd.size_old = size_old;
	mremap_cmd.size_new = size_new;

	/* Popluate parameters for ve_mremap req */
	ve_mremap.pseudo_veos_cmd_id = CMD_MREMAP;
	ve_mremap.has_pseudo_pid = true;
	ve_mremap.pseudo_pid = syscall(SYS_gettid);

	ve_mremap_msg.len = sizeof(struct mremap_cmd);
	ve_mremap_msg.data = (uint8_t *)&mremap_cmd;

	ve_mremap.has_pseudo_msg = true;
	ve_mremap.pseudo_msg = ve_mremap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mremap);
	cmd_buf_req = malloc(pseudo_msg_len);
	if (NULL == cmd_buf_req) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed %s\n",
				strerror(errno));
		goto hndl_error;
	}
	memset(cmd_buf_req, '\0', pseudo_msg_len);
	pseudo_veos_message__pack(&ve_mremap, cmd_buf_req);

	/* Unix domain socket used as IPC between pseudo and AMM module */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		/* Error handling */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "Fail to create socket with AMM\n");
		retval = -1;
		goto hndl_error1;
	}

	/* Command send to AMM for memory mapping */
	retval = pseudo_veos_send_cmd(veos_sock_fd, cmd_buf_req, pseudo_msg_len);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			  "AMM communication fails for MREMAP retval :%ld\n",
			  retval);
		goto send_error;
	}

	retval = pseudo_veos_recv_cmd(veos_sock_fd, cmd_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Fails to recv ACK from AMM\n");
		goto send_error;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, retval,
					 (const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"unpack failed retval:%ld %s\n",
				retval, strerror(errno));
		retval = -1;
		goto send_error;
	}

	if (pseudo_msg->syscall_retval < 0) {
		retval = pseudo_msg->syscall_retval;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive MREMAP_ACK\n");
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"MREMAP_ACK successully completed\n");
		retval = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

send_error:
	close(veos_sock_fd);
hndl_error1:
	free(cmd_buf_req);
hndl_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief This function will allocate a 512 GB of VHVA chunk
* which will be 512 GB aligned as well.
*
* @return Will return base address of the chunk on success and (void *)-1 on error.
*/
void *get_512GB_aligned_vemva()
{
	int64_t retval;
	void *vaddr;
	int vh_page_size;
	uint64_t size_align, size_unmap;
	void *vaddr_unaligned, *vaddr_aligned;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: void\n");
	pthread_mutex_lock(&vemva_header.vhos_mmap_lock);
	vaddr = mmap(NULL, CHUNK_512GB, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
	if ((void *)-1 == vaddr) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH OS mmap fails.\n");
		return NULL;
	}
	retval = munmap(vaddr, CHUNK_512GB);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH OS munmap failed\n");
		return NULL;
	}
	/* New size calculation */
	vh_page_size = getpagesize();
	size_align = CHUNK_512GB + CHUNK_512GB - vh_page_size;
	/* mmap with new size */
	pthread_mutex_lock(&vemva_header.vhos_mmap_lock);
	vaddr_unaligned = mmap((void *)vaddr, size_align,
			PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
	if ((void *)-1 == vaddr_unaligned) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH OS mmap failed\n");
		return vaddr_unaligned;
	}
	/* Align the address to 512MB page boundary  */
	vaddr_aligned = (void *)ALIGN((uint64_t)vaddr_unaligned,
			CHUNK_512GB);
	/* Release additional mapped area */
	size_unmap = ((uint64_t)vaddr_aligned - (uint64_t)vaddr_unaligned);
	if (size_unmap > 0) {
		retval = munmap(vaddr_unaligned, size_unmap);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS munmap failed: %s\n",
					strerror(errno));
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ArgsDump,arg1: %p arg2: %ld\n",
					(void *)(vaddr_unaligned), size_unmap);
			return (void *)retval;
		}
	}
	size_unmap = ((uint64_t)vaddr_unaligned + CHUNK_512GB +
			CHUNK_512GB - vh_page_size) -
		((uint64_t)vaddr_aligned + CHUNK_512GB);
	/* Release additional mapped area */
	if (size_unmap > 0) {
		retval = munmap((void *)(vaddr_aligned + CHUNK_512GB),
				size_unmap);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"VH OS munmap failed: %s\n",
					strerror(errno));
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ArgsDump,arg1: %p arg2: %ld\n",
					(void *)(vaddr_aligned+CHUNK_512GB),
					size_unmap);
			return (void *)retval;
		}
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"Aligned 512MB Addr Obtained: 0x%lx\n",
			(long int)vaddr_aligned);
	return vaddr_aligned;
}

/**
* @brief This function will give Aligned VEMVA chunk as per the requested flag.
*
* @param[in] flag To specify the required chunk (large or hug
*
* @return returns vemva_base of required chunk.
*/
void *get_aligned_vemva(uint64_t flag)
{
	uint64_t tmp_top;
	if (flag & MAP_HUGETLB) {
		tmp_top = vemva_header.top_huge;
		vemva_header.top_huge += CHUNK_16GB;
		return (void *)tmp_top;
	} else {
		tmp_top = vemva_header.top_large;
		vemva_header.top_large += CHUNK_512MB;
		return (void *)tmp_top;
	}
}

/**
* @brief  get the page_size of given virtual address.
*
* @param[in] vaddr vemva address to get page size
*
* @return
*/
int get_page_size(uint64_t vaddr)
{
	void *vemva_base;
	void *vemva_base_h;
	struct list_head *temp_list_head = NULL;
	struct pseudo_vemva *vemva_tmp = NULL;
	struct pseudo_vemva *vemva_req = NULL;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARGS: vaddr %p\n",
			(void *)vaddr);

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vaddr &
			(~(CHUNK_512MB_MASK)));
	vemva_base_h = (void *)((uint64_t)vaddr &
			(~(CHUNK_16GB_MASK)));

	memset(&ve_page_info, '\0', sizeof(ve_page_info));

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct pseudo_vemva, list);
			if ((vemva_tmp->vemva_base == vemva_base) ||
				(vemva_tmp->vemva_base == vemva_base_h)) {
				vemva_req = vemva_tmp;
				break;
			}
		}
		if (vemva_req == NULL) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p not found in "
					"allocated DIRs\n",
					(void *)vaddr);
			return -1;
		}

		if (vemva_req->type == ANON_SPACE_2MB) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p lies in ANON_SPACE_2MB\n",
					(void *)vaddr);
			ve_page_info.page_size = PAGE_SIZE_2MB;
		} else if (vemva_req->type == ANON_SPACE_64MB) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p lies in ANON_SPACE_64MB\n",
					(void *)vaddr);
			ve_page_info.page_size = PAGE_SIZE_64MB;
		} else if (vemva_req->type == ADDR_SPACE_2MB) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p lies in ADDR_SPACE_2MB\n",
					(void *)vaddr);
			ve_page_info.page_size = PAGE_SIZE_2MB;
		} else if (vemva_req->type == ADDR_SPACE_64MB) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p lies in ADDR_SPACE_64MB\n",
					(void *)vaddr);
			ve_page_info.page_size = PAGE_SIZE_64MB;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"vaddr %p type not recognised\n",
					(void *)vaddr);
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Return: Failure\n");
			return -1;
		}

	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"vaddr %p type not recognised\n",
				(void *)vaddr);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Return: Failure\n");
		return -1;
	}



	ve_page_info.page_mask = ve_page_info.page_size - 1;
	ve_page_info.chunk_size = ve_page_info.page_size * 256;
	ve_page_info.chunk_mask = ve_page_info.chunk_size - 1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Return: Success\n");
	return 0;
}

void ve_process_vm_readv(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_process_vm_writev(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_remap_file_pages(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_get_mempolicy(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_mbind(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_set_mempolicy(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_move_pages(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_migrate_pages(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
