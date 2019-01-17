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
 * @file sys_mm.c
 * @brief Handles AMM related system calls encountered by VE process.
 *
 * This file contains AMM system call handlers for the various system calls
 * encountered by VE process.
 *
 * @internal
 * @author AMM
 */

#include <sys/shm.h>
#include "sys_common.h"
#include "libved.h"
#include "loader.h"
#include "ve_memory.h"
#include "ve_hw.h"
#include "sys_mm.h"
#include "sys_process_mgmt.h"
#include "vemva_mgmt.h"
#include "mm_transfer.h"
#include "ve_socket.h"
#include "process_mgmt_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "comm_request.h"
#include "velayout.h"
#include "sys_process_mgmt.h"
#include "exception.h"

/**
 * @brief This interface will send request to veos to sync vhva.
 *
 * @param[in] handle VEOS handle.
 *
 * @return This interface will return 0 on success and negative of
 * errno on failure.
 */
int ve_sync_vhva(veos_handle *handle)
{
	int ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PseudoVeosMessage *pseudo_msg = NULL;
	PseudoVeosMessage vhva_sync_cmd = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("invoked");

	vhva_sync_cmd.pseudo_veos_cmd_id = VHVA_SYNC;
	vhva_sync_cmd.has_pseudo_pid = true;
	vhva_sync_cmd.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vhva_sync_cmd);

	msg_len = pseudo_veos_message__pack(&vhva_sync_cmd,
			(uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}
	/* Command send to VEOS for ATB init*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while sending IPC command\
				VHVA_SYNC to VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while sending request to VE OS",
				strerror(-ret));
		goto error_return;
	}

	/* Receiving ACK for command ATB init*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack, MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for VHVA_SYNC\
				 from VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS",
				strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while syncing vhva",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) occurred on VE OS while synching data",
				strerror(-ret));
	} else {
		PSEUDO_DEBUG("vhva sync operation successful on VE OS");
		ret = pseudo_msg->syscall_retval;
	}

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This interface will send request to veos to initialize ATB dir.
 *
 * @param[in] handle VEOS handle.
 * @param[in] vemva Base address of new VEMVA chunk allocated
 * from ve_get_vemva().
 * @param[in] page_size  page size of allocated chunk 2MB/64MB.
 *
 * @return This interface will return 0 on success and negative of errno
 * value on failure.
 */
int new_vemva_chunk_atb_init(veos_handle *handle, vemva_t vemva, size_t page_size)
{
	int ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	struct vemva_init_atb_cmd *cmd = NULL;

	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage vemva_init_atb = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData vemva_init_atb_msg = {0};

	PSEUDO_TRACE("invoked with vaddr(0x%lx) and size(0x%lx)", vemva, page_size);

	cmd = (struct vemva_init_atb_cmd *)calloc(1, sizeof(struct vemva_init_atb_cmd));
	if (NULL == cmd) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating mem for vemva_init_atb_cmd",
				strerror(-ret));
		goto error_return;
	}
	/*
	 * Populating struct vemva_init_atb_cmd buffer
	 * to Generate IPC Command
	 */
	cmd->vaddr = vemva;
	cmd->page_size = page_size;

	vemva_init_atb.pseudo_veos_cmd_id = VEMVA_INIT_ATB;

	vemva_init_atb.has_pseudo_pid = true;
	vemva_init_atb.pseudo_pid = syscall(SYS_gettid);

	vemva_init_atb_msg.len = sizeof(struct vemva_init_atb_cmd);
	vemva_init_atb_msg.data = (uint8_t *)cmd;

	vemva_init_atb.has_pseudo_msg = true;
	vemva_init_atb.pseudo_msg = vemva_init_atb_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vemva_init_atb);

	msg_len = pseudo_veos_message__pack(&vemva_init_atb,
			(uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* Command send to VEOS for ATB init*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while sending IPC command\
				VEMVA_INIT_ATB to VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while sending request\
				 to VE OS", strerror(-ret));
		goto error_return;
	}

	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for \
				VEMVA_INIT_ATB from VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS",
				strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}
	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while initialing ATB",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) occurred on VE OS while initialing ATB",
				strerror(-ret));
	} else {
		PSEUDO_DEBUG("ATB intialization for vemva(0x%lx) successful\
				 on VE OS", vemva);
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This function will copy the base address of dir
 * veshm bitmap into the structure veshm_struct.
 *
 * @param[out] veshm Address of array where all information will be copied.
 */
void copy_vemva_dir_info(struct veshm_struct *veshm)
{
	int count = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *veshm_data = NULL;

	PSEUDO_TRACE("invoked");
	/*Scan VEMVA list for the matching vemva_base*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		veshm_data = list_entry(temp_list_head,
				struct vemva_struct, list);
		veshm[count].vemva_base = (uint64_t)veshm_data->vemva_base;
		PSEUDO_DEBUG("copied dir with vemva base(0x%lx)",
				veshm[count].vemva_base);
		memcpy(&veshm[count].bitmap,
				&veshm_data->veshm_bitmap,
				sizeof(veshm_data->veshm_bitmap));
		count++;
	}
	PSEUDO_TRACE("returned");
}

/**
 * @brief This function will update ve page info.
 *
 * @param[in/out] flag This flag will indicate page size.
 */
void update_ve_page_info(uint64_t *flag)
{
	uint64_t pgsz = *flag;

	PSEUDO_TRACE("invoked");
	if (pgsz & MAP_64MB) {
		ve_page_info.page_size = PAGE_SIZE_64MB;
		ve_page_info.page_mask = PAGE_SIZE_64MB-1;
		ve_page_info.chunk_size = CHUNK_16GB;
		ve_page_info.chunk_mask = CHUNK_16GB-1;
		PSEUDO_DEBUG("Updating info for (%s) page",
				pgsz_to_pgstr(PAGE_SIZE_64MB));
	} else if (pgsz & MAP_2MB) {
		ve_page_info.page_size = PAGE_SIZE_2MB;
		ve_page_info.page_mask = PAGE_SIZE_2MB-1;
		ve_page_info.chunk_size = CHUNK_512MB;
		ve_page_info.chunk_mask = CHUNK_512MB-1;
		PSEUDO_DEBUG("Updating info for (%s) page",
				pgsz_to_pgstr(PAGE_SIZE_2MB));
	} else {
		ve_page_info.page_size = default_page_size;
		ve_page_info.page_mask = default_page_size-1;
		ve_page_info.chunk_size = default_page_size *
			ENTRIES_PER_DIR;
		ve_page_info.chunk_mask = ve_page_info.chunk_size-1;
		pgsz |= (default_page_size == PAGE_SIZE_2MB) ?
			MAP_2MB : MAP_64MB;
		*flag |= pgsz;
		PSEUDO_DEBUG("Updating info for default page size(0x%lx)",
				default_page_size);
	}
	/*set update flag*/
	ve_page_info.updated = 1;
	PSEUDO_TRACE("returned");
}

/**
 * @brief This function to handle mmap system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return On success returns mapped address, on returns negative of
 * errno on failure.
 */
ret_t ve_mmap(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0;
	size_t size = 0;
	off_t offset = 0;
	ret_t ret = 0;
	int prot = 0;
	uint64_t flag = 0;
	int filedes = 0;
	void *ret_addr = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("invoked");

	/* Get argument provided by user */
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (ret < 0) {
		PSEUDO_DEBUG("Error while fetching syscall(%s) argument",
				syscall_name);
		ret = -EFAULT;
		goto error_return;
	}

	/* Read mmap system call arguments */
	vemva    = args[0];
	size    = args[1];
	prot    = (int)args[2];
	flag    = (uint64_t)args[3];
	filedes = (int)args[4];
	offset  = args[5];

	PSEUDO_DEBUG("syscall(%s) argc vemav(0x%lx) size(0x%lx) "
			"prot(0x%x) flag(0x%lx) fd(0x%x) offset(0x%lx)",
			syscall_name, vemva, size, prot, flag, filedes, offset);

	/* Request for mmap */
	ret_addr = __ve_mmap(handle, vemva, size, prot, flag, filedes, offset);
	if (MAP_FAILED == ret_addr) {
		ret = -errno;
		PSEUDO_ERROR("Error(%s) for syscall(%s)", strerror(errno), syscall_name);
	} else {
		PSEUDO_DEBUG("(%s) syscall success (vemva:%p)", syscall_name, ret_addr);
		ret = (ret_t)ret_addr;
	}

error_return:
	PSEUDO_TRACE("returned(0x%lx)", ret);
	return ret;
}

/**
 * @brief Function to handle memory mapping request.
 *
 * @param[in] handle VEOS handle
 * @param[in] addr Memory mapping is to be done at this address
 * @param[in] size Size of the memory to map
 * @param[in] prot Permission to set on mapped memory
 * @param[in] flag Additional information for memory mapping
 * @param[in] filedes File descriptor in case of file backed mapping
 * @param[in] offset Offset of the file
 *
 * @return On success returns virtual address* on failure returns MAP_FAILED
 * and set errno.
 */
void *__ve_mmap(veos_handle *handle, vemva_t addr, size_t size,
		int prot, uint64_t flag, int filedes, off_t offset)
{
	int64_t ret = 0;
	int ve_prot = 0;
	int64_t errno_ret = 0, mmap_flag = 0;
	size_t aligned_sz = 0, align_fsz = 0;
	off_t off_s = 0;
	off_t off_e = 0;
	void *ret_addr = NULL;
	struct file_stat *f_stat = NULL;

	PSEUDO_TRACE("invoked with vemva(0x%lx) size(0x%lx) prot(%x) "
			"flag(0x%lx) fd(%d) offset(0x%lx)",
			addr, size, prot, flag, filedes, offset);

	ve_prot = prot;
	/* If file back mmap than add PROT_READ in protection bit
	 * to enble VHVA translation by DMA engine
	 */
	if (!(flag & MAP_ANON)) {
		prot |= PROT_READ;
	}

	/* Check for the validity of flag */
	if (flag & (MAP_GROWSDOWN | MAP_HUGETLB | MAP_LOCKED | MAP_NONBLOCK
				| MAP_POPULATE | MAP_32BIT)) {
		PSEUDO_DEBUG("Error(%s) flag(0x%lx)", strerror(EINVAL), flag);
		errno = EINVAL;
		return MAP_FAILED;
	}

	/* Update ve page info*/
	update_ve_page_info(&flag);


	/*
	 * Check for alignment (VE_PAGE_SIZE Alignment) of
	 * file offset received
	 */
	if (!(MAP_ANON & flag)) {
		if (!IS_ALIGNED(offset, ve_page_info.page_size)) {
			PSEUDO_DEBUG("Offset is not aligned to page boundary");
			errno = EINVAL;
			return MAP_FAILED;
		}
		f_stat = (struct file_stat *)calloc(1, sizeof(struct file_stat));
		if (f_stat == NULL) {
			ret = errno;
			PSEUDO_DEBUG("Error(%s) while allocating mem for f_stat",
					strerror(ret));
			return MAP_FAILED;
		}
		ret = fstat(filedes, &f_stat->stat);
		if (0 > ret) {
			ret = errno;
			PSEUDO_DEBUG("Error(%s) while getting file stat", strerror(ret));
			free(f_stat);
			return MAP_FAILED;
		}

	}

	/* Is size zero ?*/
	if (!size) {
		PSEUDO_DEBUG("Error(%s) size(0x%lx)", strerror(EINVAL), size);
		free(f_stat);
		errno = EINVAL;
		return MAP_FAILED;
	}

	/*align size with page size*/
	aligned_sz = size;
	if (!IS_ALIGNED(size, ve_page_info.page_size)) {
		aligned_sz = ALIGN(size, ve_page_info.page_size);
		PSEUDO_DEBUG("Given size aligned to (0x%lx)", aligned_sz);
		if (!aligned_sz) {
			free(f_stat);
			errno = ENOMEM;
			return MAP_FAILED;
		}
	}
	/*calculate start and end offset*/
	if (!(MAP_ANON & flag)) {
		off_s = (off_t)(offset / ve_page_info.page_size);
		off_e = (off_t)(((offset + aligned_sz) / ve_page_info.page_size) - 1);

		f_stat->offset_start = off_s;
		f_stat->offset_end = off_e;
		f_stat->pgsz = ve_page_info.page_size;
		PSEUDO_DEBUG("file backed mmap request off_s(0x%lx) "
				"to off_e(0x%lx) with (%s) page", off_s, off_e,
				pgsz_to_pgstr(f_stat->pgsz));

	}

	/* Check whether mapping is not related to heap/stack  */
	if ((flag & MAP_SHARED) && ((flag & MAP_STACK) ||
				(flag & MAP_ADDR_SPACE))) {
		PSEUDO_DEBUG("Error(%s) flag(0x%lx)", strerror(EINVAL), flag);
		errno = EINVAL;
		free(f_stat);
		return MAP_FAILED;
	}
	/*addr should not be null if MAP_ADDR_SPACE flag is set*/
	if ((NULL == (void *)addr) && (flag & MAP_ADDR_SPACE)) {
		PSEUDO_DEBUG("Error(%s) addr should not(0x%lx)"
				"if MAP_ADDR_SPACE flag is set", strerror(EINVAL), addr);
		errno = EINVAL;
		free(f_stat);
		return MAP_FAILED;
	}

	ret_addr = ve_get_vemva(handle, addr, aligned_sz,
			flag, prot, filedes, offset);
	if (MAP_FAILED == ret_addr) {
		ret = errno;
		PSEUDO_DEBUG("Error(%s) while getting free vemva", strerror(ret));
		free(f_stat);
		errno = ret;
		return ret_addr;
	}

	/*
	 * In case of MAP_STACK do not have to allocate
	 * any physical page, virtual address will not
	 * be backed by any page physically
	 */
	prot = ve_prot;
	if (!(flag & MAP_STACK) ||
			((flag & MAP_STACK) && (flag & MAP_FIXED))) {
		/* AMM communication */
		ret = amm_request_mmap(handle, (uint64_t)ret_addr,
				aligned_sz, prot, flag, f_stat);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while sending mmap request to VE OS",
					strerror(-ret));

			errno_ret = -ret;
			ret = ve_free_vemva((void *)ret_addr, size);
			if (0 > ret)
				PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
						strerror(-ret), ret_addr);
			free(f_stat);
			errno = errno_ret;
			return MAP_FAILED;
		}
	}

	/* if file back mmap than do mprotect with user provided flag
	 * to avoid any mis-match between vhva and VEMVA
	 */
	if (!(flag & MAP_ANON)) {
		ret = mprotect(ret_addr, aligned_sz, ve_prot);
		if (0 > ret) {
			errno_ret = errno;
			PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
					strerror(-ret));
			ret = ve_free_vemva((void *)ret_addr, size);
			if (0 > ret)
				PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
						strerror(-ret), ret_addr);
			free(f_stat);
			errno = errno_ret;
			return MAP_FAILED;
		}
		/*
		 * As per #948 we are mmaping the SIG_BUS region of file with
		 * MAP_ANON|MAP_FIXED to access the futex varible stored in the
		 * this region.
		 */
		align_fsz = ALIGN(f_stat->stat.st_size, PAGE_SIZE_4KB);
		if (offset < align_fsz)
			align_fsz -= offset;
		if ((offset < f_stat->stat.st_size) && (0 < (int64_t)(aligned_sz - align_fsz))) {
			PSEUDO_DEBUG("offset %ld f_stat->stat.st_size  %ld",
					offset, align_fsz);
			mmap_flag = (flag | MAP_FIXED | MAP_ANON) &
				(~(MAP_2MB | MAP_64MB | MAP_VESHM | MAP_ADDR_SPACE));
			if (MAP_FAILED == mmap((void*)((uint64_t)ret_addr + align_fsz),
						aligned_sz - align_fsz,
						ve_prot,
						mmap_flag,
						-1, 0)) {
				errno_ret = errno;
				PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
						strerror(errno_ret));
				ret = ve_free_vemva((void *)ret_addr, size);
				if (0 > ret)
					PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
							strerror(-ret), ret_addr);
				free(f_stat);
				errno = errno_ret;
				return MAP_FAILED;
			}
		}
	}

	/*Clearing ve page info*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%p)", ret_addr);
	free(f_stat);
	return ret_addr;
}

/**
 * @brief This function is used to communicate with AMM module.
 *
 * @param[in] handle VEOS handle
 * @param[in] vemva mapped virtual address
 * @param[in] size Size of the memory to map
 * @param[in] prot Protection control bits
 * @param[in] flag mapping control flags
 * @param[in] f_stat file stats to be mapped if file backed
 * otherwise NULL.
 *
 * @return returns 0 on success and negative of errno on failure.
 */
int64_t amm_request_mmap(veos_handle *handle, vemva_t vemva, size_t size,
		int prot, uint64_t flag, struct file_stat *f_stat)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	struct ve_mmap_cmd *cmd = NULL;
	PseudoVeosMessage *pseudo_msg = NULL;
	PseudoVeosMessage ve_mmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_mmap_msg = {0};

	PSEUDO_TRACE("invoked");

	cmd = (struct ve_mmap_cmd *)calloc(1, sizeof(struct ve_mmap_cmd));
	if (NULL == cmd) {
		PSEUDO_DEBUG("Fail to allocate memory for "
				"amm request block\n");
		goto error_return;
	}

	/* Populating struct ve_mmap_cmd buffer to Generate IPC Command */
	cmd->vaddr = vemva;
	cmd->perm = prot;
	cmd->flags = flag;
	cmd->size = size;

	if (!(MAP_ANON & flag)) {
		/*copy file specific Information in cmd buffer*/
		memcpy(&(cmd->f_stat), f_stat, sizeof(struct file_stat));
	}

	PSEUDO_DEBUG("Sending request for MMAP with vemva(0x%lx) "
			"size(0x%lx) perm(0x%x) flags(0x%lx)",
			cmd->vaddr, cmd->size, cmd->perm, cmd->flags);

	/* Populate parameters for ve_mmap req */
	ve_mmap.pseudo_veos_cmd_id = CMD_MMAP;

	ve_mmap.has_pseudo_pid = true;
	ve_mmap.pseudo_pid = syscall(SYS_gettid);

	ve_mmap_msg.len = sizeof(struct ve_mmap_cmd);
	ve_mmap_msg.data = (uint8_t *)cmd;

	ve_mmap.has_pseudo_msg = true;
	ve_mmap.pseudo_msg = ve_mmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mmap);

	msg_len = pseudo_veos_message__pack(&ve_mmap, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* Sending command CMD_MMAP to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while sending IPC request for CMD_MMAP to VE OS");
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}
	/* Receiving ACK for command CMD_MMAP*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (-1 == ret) {
		PSEUDO_DEBUG("Error while getting ACk for CMD_MMAP from VE OS");
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while mapping vemva(0x%lx)",
				strerror(-ret), vemva);
	} else {
		PSEUDO_DEBUG("vemva(0x%lx) mapping operation successfully done on VE", vemva);
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function is used to handle memory unmap request.
 *
 * @param[in] handle VEOS handle
 * @param[in] vemva Start of the virtual address from where memory to unmap
 * @param[in] size size of the memory to unmap
 * @param[in] del_dir bool to decide dir should be deleted or not.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t __ve_munmap(veos_handle *handle, vemva_t vemva,
		size_t size, bool del_dir)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	size_t pg_size = 0;
	struct ve_munmap_cmd *cmd = NULL;

	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage ve_munmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_munmap_msg = {0};

	PSEUDO_TRACE("invoked");

	/* Check for tha validity of address */
	if (vemva < 0) {
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		ret = -EINVAL;
		goto error_return;
	} else if (!vemva) {
		PSEUDO_DEBUG("vemva(0x%lx) nothing to do", vemva);
		ret = 0;
		goto error_return;
	} else {
		ret = get_page_size(vemva);
		if (ret < 0) {
			PSEUDO_DEBUG("vemva(0x%lx) is not mapped", vemva);
			ret = 0;
			goto error_return;
		} else {
			pg_size = ve_page_info.page_size;
			PSEUDO_DEBUG("vemva(0x%lx) was mapped with (%s) page",
					vemva, pgsz_to_pgstr(pg_size));
		}
	}

	/* Check is address is aligned to pagesize or not*/
	if (!IS_ALIGNED(vemva, pg_size)) {
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		ret = -EINVAL;
		goto error_return;
	}

	/* Check is size is aligned to pagesize or not*/
	if (!IS_ALIGNED(size, pg_size)) {
		size = ALIGN((uint64_t)size, PAGE_SIZE_2MB);
		PSEUDO_DEBUG("Aligned size (0x%lx) with page size", size);
	}

	/* Popluate parameters for ve_munmap req */
	ve_munmap.pseudo_veos_cmd_id = CMD_MUNMAP;

	ve_munmap.has_pseudo_pid = true;
	ve_munmap.pseudo_pid = syscall(SYS_gettid);

	cmd = (struct ve_munmap_cmd *)calloc(1, sizeof(struct ve_munmap_cmd));
	if (NULL == cmd) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for ve_munmap_cmd",
				strerror(-ret));
		goto error_return;
	}

	cmd->vaddr = vemva;
	cmd->size = size;

	PSEUDO_DEBUG("sending request to munmap for vemva(0x%lx) with size(0x%lx)",
			cmd->vaddr, cmd->size);

	ve_munmap_msg.len = sizeof(struct ve_munmap_cmd);
	ve_munmap_msg.data = (uint8_t *)cmd;

	ve_munmap.has_pseudo_msg = true;
	ve_munmap.pseudo_msg = ve_munmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_munmap);

	msg_len = pseudo_veos_message__pack(&ve_munmap, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* sending CMD_MUNMAP to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while sending ICP command CMD_MUNMAP to VE OS");
		ret = -EFAULT;
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}

	/* receiving ACK for CMD_MUNMAP from VE OS*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while getting ACK for CMD_MUNMAP from VE OS");
		ret = -EFAULT;
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while unmapping vemva(0x%lx)",
				strerror(-ret), vemva);
	} else
		PSEUDO_DEBUG("vemva(0x%lx) unmapping operation successfully done on VE", vemva);

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

	/*Freeing vemva*/
	ret = __ve_free_vemva((void *)vemva, size, del_dir);
	if (0 > ret)
		PSEUDO_DEBUG("Error(%s) while freeing vemva(0x%lx)",
				strerror(-ret), vemva);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function is to handle munmap request.
 *
 * @param[in] syscall_num Syscall number
 * @param[in] syscall_name Syscall name
 * @param[in] handle VEOS handle
 *
 * @return On success return 0, returns negative of errno on failure.
 */
ret_t ve_munmap(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0;
	size_t size = 0;
	ret_t ret = 0;
	uint64_t args[2];

	PSEUDO_TRACE("invoked");

	/*Fetch system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argument",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	vemva = (vemva_t)args[0];
	size = (size_t)args[1];

	/* length should not be zero or negative */
	if ((int64_t)size <= 0) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) size(0x%lx)", strerror(-ret), size);
		goto error_return;
	}

	PSEUDO_DEBUG("syscall(%s) argc vemav(0x%lx) size(0x%lx)", syscall_name, vemva, size);

	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = __ve_munmap(handle, vemva, size, true);
	if (0 > ret) {
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_DEBUG("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}
	pthread_mutex_unlock(&vemva_header.vemva_lock);
error_return:
	/* Initialize ve_page_info struct to zero while returning*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
* @brief This function is used to handle Heap space extension/reduction request.
*
* @param[in] syscall_num System call number.
* @param[in] syscall_name System call name.
* @param[in] handle VEOS handle.
*
* @return returns new program break on success else old program break.
*/
ret_t ve_brk(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	void *ret_addr = NULL;
	vemva_t old_top = 0;
	vemva_t new_top = 0;
	size_t size = 0;
	uint64_t args[1] = {0};
	uint64_t flag = 0;

	PSEUDO_TRACE("invoked");
	/* Get the previous heap top */
	old_top = ve_info.heap_top;
	PSEUDO_DEBUG("current unaligned heap top(0x%lx)", old_top);

	/*Fetching syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argument",
				strerror(-ret), syscall_name);
        ret = old_top;
		goto error_return;
	}

	PSEUDO_DEBUG("syscall(%s) args heap top(0x%lx)", syscall_name, args[0]);

	/*Updating ve page info with default page*/
	flag = 0;
	update_ve_page_info(&flag);

	/* Check if previous heap is aligned */
	if (!IS_ALIGNED(old_top, ve_page_info.page_size))
		old_top = ALIGN(old_top, ve_page_info.page_size);


	PSEUDO_DEBUG("current aligned heap top(0x%lx)", old_top);

	PSEUDO_DEBUG("new unaligned heap top(0x%lx)", args[0]);

	new_top = ALIGN((uint64_t)args[0], ve_page_info.page_size);

	PSEUDO_DEBUG("new aligned heap top(0x%lx)", new_top);

	/* If brk syscall argument received is NULL
	 * then current heap top is sent to VE program */
	if (0 == new_top) {
		PSEUDO_DEBUG("requesting for current heap top");
		ret = old_top;
		goto error_return;
	}

	/* Check if requested value is same as current heap top */
	if (new_top == old_top) {
		PSEUDO_DEBUG("old heap top (0x%lx) and new heap top(0x%lx) are same",
				old_top, new_top);
		ret = old_top;
		goto error_return;
	}

	/* Calculate Heap size to change */
	size = new_top - old_top;
	PSEUDO_DEBUG("heap size to be changed(0x%lx)", size);

	if ((int64_t)size > 0) {
		/* check that while increasing the heap it doesn't overlap the
		 * stack region.
		 */
		if ((old_top + size) > ve_info.stack_pointer_aligned) {
			PSEUDO_DEBUG("Current aligned stack pointer(0x%lx)",
					ve_info.stack_pointer_aligned);
			PSEUDO_DEBUG("heap overlapping the stack");
			ret = old_top;
			goto error_return;
		}
		/* Request for Heap extension */
		ret_addr = ve_heap_extend(handle, old_top, size);
		if (MAP_FAILED == ret_addr) {
			PSEUDO_DEBUG("Error while extending the heap");
			ret = old_top;
			goto error_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	} else {
		size = -size;
		/* Req for Heap release , check whether release request
		 * goes beyond the heap starting point */
		if (new_top < ALIGN(ve_info.heap_start,
					ve_page_info.page_size)) {
			PSEUDO_DEBUG("Error while decreasing heap to new heap top(0x%lx)", new_top);
			ret = old_top;
			goto error_return;
		}
		ret = ve_heap_reduce(handle, new_top, size);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while decreasing heap to new heap top(0x%lx)",
					strerror(-ret), new_top);
			ret = old_top;
			goto error_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	}
	ret = ve_info.heap_top;

error_return:
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returnig heap top(0x%lx)", ret);
	return ret;
}

/**
 * @brief This function handles heap space extension request.
 *
 * @param[in] handle VEOS handle
 * @param[in] old_top_address VE virtual address to unmap
 * @param[in] size size of the heap space to release
 *
 * @return On success returns mapped address* and (void *)-1 on failure.
 */
void *ve_heap_extend(veos_handle *handle, vemva_t old_top,
		size_t size)
{
	void *ret = NULL;
	uint64_t flag = MAP_FIXED | MAP_ADDR_SPACE | MAP_ANON | MAP_PRIVATE;

	PSEUDO_TRACE("invoked to exend heap top(0x%lx) by size(0x%lx)", old_top, size);

	/* Request to extend VE program Heap space */
	ret = __ve_mmap(handle, old_top, size, PROT_WRITE|PROT_READ, flag, -1, 0);
	if (MAP_FAILED == ret)
		PSEUDO_DEBUG("Error while mapping the heap to new limit");

	PSEUDO_DEBUG("heap top (%p) extented by size(0x%lx)", ret, size);
	PSEUDO_TRACE("returned(%p)", ret);
	return ret;
}

/**
 * @brief This function handles heap space reduction request.
 *
 * @param[in] handle VEOS handle
 * @param[in] new_top_address VE virtual address to map
 * @param[in] size size of the space to map
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t ve_heap_reduce(veos_handle *handle, vemva_t new_top, size_t size)
{
	int ret = 0;

	PSEUDO_TRACE("invoked to reduce heap top(0x%lx) by size(0x%lx)", new_top, size);

	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = __ve_munmap(handle, new_top, size, true);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while unmapping the heap to new limit");
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		return ret;
	}

	pthread_mutex_unlock(&vemva_header.vemva_lock);
	PSEUDO_DEBUG("heap top (0x%lx) reduce by size(0x%lx)", new_top, size);
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This function handles grow system call
 * from VE process to make request to AMM for VE stack space extension.
 *
 * @param[in] syscall_num grow syscall number
 * @param[in] syscall_name syscall name
 * @param[in] handle VEOS handle
 *
 * @return SR00 is not updtaed as grow does not return anything.
 * However, new stack limit is always set in SR08 in case of success as
 * well as in failure.
 *
 */
ret_t ve_grow(int syscall_num, char *syscall_name, veos_handle *handle)
{
	int prot = 0;
	uint64_t flag = 0;
	size_t size = 0;
	int idx = 0;
	vemva_t old_bottom = 0;
	vemva_t new_bottom = 0;
	vemva_t actual_new_bottom;
	vemva_t requested_new_bottom;
	vemva_t new_stack_limit = 0;
	int64_t ret = 0;
	void *ret_addr = NULL;
	uint64_t args[2] = {0};
	vemva_t guard_addr = 0;
	pid_t tid = syscall(SYS_gettid);
	pid_t pid = getpid();
	unsigned long alt_stk_sp = 0;
	size_t alt_stk_sz = 0;

	PSEUDO_TRACE("invoked");

	/* Fetching the system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching the syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto out;
	}

	PSEUDO_DEBUG("syscall(%s) args old stack bottom(0x%lx) "
			"new stack bottom(0x%lx)", syscall_name, args[0], args[1]);

	ret = pthread_mutex_lock(&tid_counter_mutex);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to acquire mutex lock");
		PSEUDO_DEBUG("Failed to acquire lock, return value %d",
				-((int)ret));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* Finding guard address from global array*/
	idx = find_global_array_index(tid);
	if (VEOS_MAX_VE_THREADS == idx) {
		PSEUDO_ERROR("Failed to get thread index");
		fprintf(stderr, "Internal thread resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}


	/*Check pid and tid, update guard_addr accordingly*/

	if (pid != tid) {
		guard_addr = global_tid_info[idx].
			guard_ptr;
	} else {
		guard_addr = 0;
		flag |= MAP_ADDR_SPACE;
	}

	/* Fetch alternate stack details from global tid structure */
	alt_stk_sp =  global_tid_info[idx].sas_ss_sp;
	alt_stk_sz = global_tid_info[idx].sas_ss_size ;

	PSEUDO_DEBUG("Current Stack limit(0x%lx) Alternate stack SP (0x%lx)"
			"Alt stack size %d",
			old_bottom, alt_stk_sp, (int)alt_stk_sz);

	ret = pthread_mutex_unlock(&tid_counter_mutex);
	if (ret!= 0) {
		PSEUDO_ERROR("Failed to release mutex lock");
		PSEUDO_DEBUG("Failed to release lock, return value %d",
				-((int)ret));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	old_bottom = args[0];
	new_bottom = args[1];

	if (new_bottom >= old_bottom) {
		PSEUDO_DEBUG("new_bottom(0x%lx) is greater than old_bottom(0x%lx)",
				new_bottom, old_bottom);
		goto out;
	}

	/* Check if grow is invoked while alternate stack is active.
	 * If yes, we simply return the new stack limit.
	 * */
	if ((old_bottom >= alt_stk_sp) && (old_bottom - alt_stk_sp <= alt_stk_sz)) {
		PSEUDO_ERROR("Alternate stack active. Behaviour will be undesirable");
		goto out;
	}

	/*update ve page info*/
	update_ve_page_info(&flag);

	requested_new_bottom = new_bottom;
	/*
	 * Stack area for signal handling is required.
	 */
	actual_new_bottom = requested_new_bottom - STACK_AREA_FOR_SIGNAL;

	new_bottom = ALIGN_RD(new_bottom, ve_page_info.page_size);
	actual_new_bottom = ALIGN_RD(actual_new_bottom, ve_page_info.page_size);
	old_bottom = ALIGN_RD(old_bottom, ve_page_info.page_size);

	if (pid == tid) {
		/*
		 * While changing the stack limit Check:
		 * 1. If it overlaps the process heap or not.
		 * 2. If STACK LIMIT is defined, then check if it is
		 * going beyond the limit or not.
		 *
		 * If stack grows and goes beyond in both the cases,
		 * we just return the new stack limit.
		 * Let hardware exception occur.
		 */
		if (new_bottom < ve_info.stack_limit) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing stack limit(0x%lx)",
				new_bottom, ve_info.stack_limit);
			goto out;
		}
		if (new_bottom < ve_info.heap_top) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing heap top(0x%lx)",
				new_bottom, ve_info.heap_top);
			goto out;
		}

		if (actual_new_bottom < ve_info.stack_limit) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing stack limit(0x%lx)",
				new_bottom, ve_info.stack_limit);
			actual_new_bottom = ve_info.stack_limit;
		}
		if (actual_new_bottom < ve_info.heap_top) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing heap top(0x%lx)",
				new_bottom, ve_info.heap_top);
			actual_new_bottom = ve_info.heap_top;
		}
	}

	/*
	 * We try to allocate physical pages including area for signal handling.
	 */
	size = (old_bottom - actual_new_bottom);
	if (guard_addr && (actual_new_bottom < guard_addr)) {
		size -= (guard_addr - actual_new_bottom);
		if ((int64_t)size <= 0)
			goto out;
	}

	/*
	 * Check if actual_new_bottom address >= page aligned old_bottom address
	 */
	if (actual_new_bottom >= old_bottom)
		goto out;

	PSEUDO_DEBUG("actual new stack bottom(0x%lx)", actual_new_bottom);
	PSEUDO_DEBUG("old stack bottom(0x%lx)", old_bottom);
	PSEUDO_DEBUG("stack to be increase by size(0x%lx)", size);

	/* Set the protection */
	prot = PROT_WRITE;
	/* Set flag to indicate this is for stack space allocation */
	flag |= MAP_FIXED | MAP_ANON | MAP_PRIVATE | MAP_STACK;

	/* Request for memory map */
	ret_addr = __ve_mmap(handle, actual_new_bottom, size, prot,
			flag, -1, 0);
	if (MAP_FAILED != ret_addr) {
		/*
		 * After succesfull grow, update the value of new stack
		 * pointer aligned.
		 */
		if (pid == tid)
			ve_info.stack_pointer_aligned = (uint64_t)actual_new_bottom;
		/*
		 * Update new_bottom to return value exclude stack area for
		 * signal. But, update new_bottom to return actual value if
		 * we have failed to allocate stack area for signal.
		 */
		if ((requested_new_bottom - actual_new_bottom)
			> STACK_AREA_FOR_SIGNAL)
			new_bottom = actual_new_bottom + STACK_AREA_FOR_SIGNAL;
		else
			new_bottom = actual_new_bottom;
	} else if (new_bottom != actual_new_bottom) {
		PSEUDO_DEBUG("Error while mapping new stack including area for signal handling");
		/*
		 * VEOS fails to allocate physical pages including a
		 * area for signal_handling. So, we try to allocate
		 * physical pages excluding a area for
		 * signal_handling.
		 */
		size = (old_bottom - new_bottom);
		if (new_bottom >= old_bottom)
			goto out;

		if (guard_addr && (new_bottom < guard_addr)) {
			size -= (guard_addr - new_bottom);
			if ((int64_t)size <= 0)
				goto out;
		}

		PSEUDO_DEBUG("new stack bottom(0x%lx)", new_bottom);
		PSEUDO_DEBUG("old stack bottom(0x%lx)", old_bottom);
		PSEUDO_DEBUG("stack to be increase by size(0x%lx)", size);
		ret_addr = __ve_mmap(handle, new_bottom, size, prot,
				flag, -1, 0);
		if (MAP_FAILED != ret_addr) {
			/*
			 * After succesfull grow, update the value of new stack
			 * pointer aligned.
			 */
			if (pid == tid)
				ve_info.stack_pointer_aligned = (uint64_t)new_bottom;
		} else
			PSEUDO_DEBUG("Error while mapping new stack");
	}
out:
	new_stack_limit = new_bottom;

	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returning new stack(0x%lx)", new_stack_limit);
	return new_stack_limit;
}

/**
 * @brief This function is used to
 * communicate with AMM module for updating memory protection.
 *
 * @param[in] handle VEOS handle
 * @param[out] ret_addr mapped virtual address
 * @param[in] size Size of the memory to map
 * @param[in] prot Protection control bits
 *
 * @return returns 0 on success and negative of errno on failure.
 */
int64_t amm_request_mprotect(veos_handle *handle, vemva_t vemva,
		size_t size, int prot)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage ve_mprotect_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData mprotect_ve_proc_msg = {0};
	ssize_t pseudo_msg_len = 0, msg_len = -1;
	PseudoVeosMessage *mprotect_ack = NULL;
	struct pseudo_mprotect_req mprotect_request = {0};

	PSEUDO_TRACE("invoked");

	/* Populate mprotect_request structure */
	mprotect_request.ret_addr = vemva;
	mprotect_request.size = size;
	mprotect_request.prot = prot;

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

	msg_len = pseudo_veos_message__pack(&ve_mprotect_req, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	PSEUDO_DEBUG("sending request to mprotect with vemva(0x%lx) "
			"pid(%ld) size(0x%lx) prot(%d)",
			mprotect_request.ret_addr, syscall(SYS_gettid),
			mprotect_request.size, mprotect_request.prot);

	/* sending CMD_MPROTECT to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req,
			pseudo_msg_len);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while sending IPC command CMD_MPROTECT to VE OS");
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}
	/* receiving ACK for CMD_MPROTECT from VE OS*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while getting ACK for CMD_MPROTECT to VE OS");
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}

	/* Unpack the structure */
	mprotect_ack = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(cmd_buf_ack));
	if (NULL == mprotect_ack) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}
	if (mprotect_ack->syscall_retval < 0) {
		ret = mprotect_ack->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while mprotect vemva(0x%lx)",
			strerror(-ret), vemva);
	} else {
		PSEUDO_DEBUG("mprotect operation on vemva(0x%lx)"
			"successfully done on VE", vemva);
		ret = mprotect_ack->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(mprotect_ack, NULL);

error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function to handle mprotect system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success returns zero, returns negative of errno on failure.
 */
ret_t ve_mprotect(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0, addr_end = 0;
	size_t len = 0;
	int prot;
	ret_t ret = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("invoked");

	/*Fetching system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argumnets",
				strerror(-ret), syscall_name);
		ret = -EFAULT;
		goto error_return;
	}

	vemva	= (vemva_t)args[0];
	len	= (size_t)args[1];
	prot	= (int)args[2];

	PSEUDO_DEBUG("syscall(%s) args vemav(0x%lx) size(0x%lx) prot(0x%x)",
			syscall_name, vemva, len, prot);

	/* check if address is aligned or not*/
	if (!IS_ALIGNED(vemva, PAGE_SIZE_2MB)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		goto error_return;
	}

	/* Is length zero */
	if (!len) {
		ret = 0;
		PSEUDO_DEBUG("length is invalid\n");
		goto error_return;
	}

	/* align length with 2 MB page size temparaly*/
	len = ALIGN(len, PAGE_SIZE_2MB);

	/*
	 * ending address should be greather than starting
	 * if not it that such mapping is not available.
	 */
	addr_end = vemva + len;
	if (addr_end <= vemva) {
		PSEUDO_DEBUG("address is NULL\n");
		ret = -ENOMEM;
		goto error_return;
	}

	/* Get the actual page size */
	if (vemva) {
		ret = get_page_size(vemva);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while getting page size", strerror(-ret));
			goto error_return;
		}
	} else {
		PSEUDO_DEBUG("address is NULL\n");
		ret = -ENOMEM;
		goto error_return;
	}


	/*check whether memory ref by addr is mapped or not*/
	ret = vemva_mapped((void *)vemva, len, MARK_USED);
	if (0 >= ret) {
		ret = -ENOMEM;
		PSEUDO_DEBUG("vemav(0x%lx) is not mapped", vemva);
		goto error_return;
	}

	/*
	 * if page size is not 2MB then check
	 * whether len and addr is aligned with actual page size
	 */
	if (ve_page_info.page_size != PAGE_SIZE_2MB) {
		len = ALIGN(len, ve_page_info.page_size);
		if (!IS_ALIGNED(vemva, ve_page_info.page_size)) {
			ret = -EINVAL;
			PSEUDO_DEBUG("Error(%s) vemav(0x%lx) is not alinged",
					strerror(-ret), vemva);
			goto error_return;
		}
	}

	/* Call VH mprotect system call */
	ret = syscall(syscall_num, vemva, len, prot);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while off loading syscall(%s) on VH",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	/*sending request*/
	ret = amm_request_mprotect(handle, vemva, len, prot);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		goto error_return;
	}

error_return:
	/*initialize ve_page_info to zero struct while returning*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function to handle msync system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success return zero, returns negative of errno on failure.
 */
ret_t ve_msync(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0, ve_end = 0;
	size_t size = 0;
	ret_t ret = 0;
	int flag = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("invoked");

	/* Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (ret < 0) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while fetching syscall(%s) arguments",
				syscall_name);
		goto error_return;
	}

	vemva = (vemva_t)args[0];
	size = (size_t)args[1];
	flag    = (int)args[2];

	PSEUDO_DEBUG("syscall(%s) args vemva(0x%lx) size(0x%lx) flag(0x%x)",
			syscall_name, vemva, size, flag);

	 /* check whether addr is aligned or not*/
	if (!IS_ALIGNED(vemva, PAGE_SIZE_2MB)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx) is not aligned",
			strerror(-ret), vemva);
		goto error_return;
	}

	size = ALIGN(size, PAGE_SIZE_2MB);

	/* Check is size is negative or not*/
	ve_end = vemva + size;
	if (ve_end < vemva) {
		ret = -ENOMEM;
		goto error_return;
	}
	/*
	 * if start and end are equal its mean that length is zero
	 * there is nothing to do.
	 */
	if (vemva == ve_end) {
		ret = 0;
		goto error_return;
	}

	/*Align the size*/
	PSEUDO_DEBUG("aligned size(0x%lx) with page size", size);

	/* Get the actual page size */
	if (vemva) {
		ret = get_page_size(vemva);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while getting page size", strerror(-ret));
			goto error_return;
		}
	} else {
		PSEUDO_DEBUG("Error(%s) vemav(0x%lx)", strerror(-ret), vemva);
		ret = -ENOMEM;
		goto error_return;
	}

	/* check whether memory referrence by ve_addr is mapped or not */
	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = vemva_mapped((void *)vemva, size, MARK_USED);
	if (0 >= ret) {
		ret = -ENOMEM;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx) is not mapped", strerror(-ret), vemva);
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		goto error_return;
	}
	/*
	 * if actual page size is not 2MB, then align
	 * size with actual page size
	 */
	if (ve_page_info.page_size != PAGE_SIZE_2MB) {
		size = ALIGN(size, ve_page_info.page_size);
		/*check if ve_addr is aligned or not*/
		if (!IS_ALIGNED(vemva, ve_page_info.page_size)) {
			ret = -EINVAL;
			PSEUDO_DEBUG("Error(%s) vemav(0x%lx) is not aligned",
				strerror(-ret), vemva);
			pthread_mutex_unlock(&vemva_header.vemva_lock);
			goto error_return;
		}
	}

	ret = __ve_msync(handle, vemva, size, flag);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}

	pthread_mutex_unlock(&vemva_header.vemva_lock);
error_return:
	/*initiale ve_page_info to zero struct while returning.*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function handles the sync functionality.
 *
 * @param[in] handle veos_handle
 * @param[in] vemva Virtual Address of VE Process to be synced.
 * @param[in] size size of data to be synced.
 * @param[in] flag msync flags.
 *
 * @return Return 0 on Success and negative of errno on failure.
 */
int64_t __ve_msync(veos_handle *handle, vemva_t vemva, size_t size, int flag)
{
	vemva_t vemva_ve = vemva;
	vemva_t vemva_vh = vemva;
	int64_t ret = 0, count = 0, pgsize = 0;

	PSEUDO_TRACE("invoked");

	/*
	 * If any bit other than MS_ASYNC | MS_INVALIDATE | MS_SYNC
	 * is set Return EINVAL
	 * */
	if (flag & ~(MS_SYNC | MS_ASYNC)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) flag(0x%x)", strerror(-ret), flag);
		goto error_return;
	}

	/*If MS_ASYNC and MS_SYNC Both flags are provided then Return EINVAL*/
	if ((flag & MS_ASYNC) && (flag & MS_SYNC)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) flag(0x%x)", strerror(-ret), flag);
		goto error_return;
	}

	/*Check if the address received is VE Page aligned or not.*/
	if (!IS_ALIGNED((uint64_t)vemva_ve, ve_page_info.page_size)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva_ve(%lx) is not aligned",
				strerror(-ret), vemva_ve);
		goto error_return;
	}
	pgsize = ve_page_info.page_size;
	count = size/pgsize;
	while (count) {
		/*
		 * check is vemva is file backed
		 * before accessing vh memory
		 */
		if (vemva_mapped((void *)vemva, pgsize, MARK_FILE|MARK_USED)) {
			/* receive the data from VE memory*/
			ret = __ve_recv_data(handle, (uint64_t)vemva_ve, pgsize, (void *)vemva_vh, 0);
			if (0 > ret) {
				PSEUDO_TRACE("Error(%s) while receiving date from VE",
						strerror(-ret));
				goto error_return;
			}

			/*off loading syscall on VH*/
			if (flag & (MS_SYNC | MS_ASYNC | MS_INVALIDATE)) {
				ret = msync((void *)vemva_vh, pgsize, flag);
				if (0 > ret) {
					ret = -errno;
					PSEUDO_DEBUG("Error(%s) while off loading the syscall(msync) on VH",
							strerror(-ret));
				}
			}
		}
		vemva_vh += pgsize;
		vemva_ve += pgsize;
		count--;
	}
error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function does the data transfer to a VE process from
 * another VE process.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return 0 on success, returns negative of errno on failure.
 */
ret_t ve_process_vm_readv(int syscall_num, char *syscall_name, veos_handle *handle)
{
	pid_t pid = 0;
	uint64_t l_iovec = 0;
	struct iovec *vhremote_iovec = NULL;
	uint64_t riovcnt = 0;
	struct iovec *vhlocal_iovec = NULL;
	uint64_t r_iovec = 0;
	uint64_t liovcnt = 0;
	uint64_t flags = 0;
	int64_t ret = -1;
	uint64_t args[6] = {0};

	/*Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	pid = (pid_t)args[0];
	l_iovec = args[1];
	liovcnt = args[2];
	r_iovec = args[3];
	riovcnt = args[4];
	flags = args[5];

	PSEUDO_DEBUG("syscall(%s) args pid(%d) l_iovec(0x%lx) liovcnt(0x%lx) "
			"r_iovec(0x%lx) riovcnt(0x%lx) flags(0x%lx)", syscall_name,
			pid, l_iovec, liovcnt, r_iovec, riovcnt, flags);

	/* Check the iovec count is valid or not */
	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) liovcnt(0x%lx)", strerror(-ret), liovcnt);
		goto error_return;
	}
	/*If local iovec count or remote iovec count is zero
	 * means we have nothing to read, so return success
	 */
	if (!liovcnt || !riovcnt) {
		ret = 0;
		goto error_return;
	}

	/*If pointer to local iovec or remote iovec is NULL than return failure.*/
	if (!l_iovec || !r_iovec) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) l_iovec(0x%lx) r_iovec(0x%lx)",
				strerror(-ret), l_iovec, r_iovec);
		goto error_return;
	}

	vhremote_iovec = (struct iovec *)calloc(1, sizeof(struct iovec)
			* riovcnt);
	if (NULL == vhremote_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	vhlocal_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * liovcnt);
	if (NULL == vhlocal_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	/*Read from ve memory and store to local buff for manipulation*/
	ret = ve_recv_data(handle, l_iovec, sizeof(struct iovec) * liovcnt,
			(void *)vhlocal_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	/*Read from ve memory and store to local buff for manipulation*/
	ret = ve_recv_data(handle, r_iovec, sizeof(struct iovec) * riovcnt,
			(void *)vhremote_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for r_iovec",
				strerror(-ret));
		goto error_return;
	}

	/* Call VH process_vm_readv for checking access and capability*/
	ret = process_vm_readv(pid, vhlocal_iovec, 1, vhremote_iovec, 1,
			flags);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while transferring data from the remote"
				"process to the local process on VH", strerror(-ret));
		goto error_return;
	}

	/*Check the validation of local iovec*/
	ret = ve_check_iovec(vhlocal_iovec, liovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhremote_iovec, riovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = __ve_process_vm_rw(handle, vhlocal_iovec, liovcnt,
			vhremote_iovec, riovcnt, pid, 0);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}

error_return:
	if (vhlocal_iovec)
		free(vhlocal_iovec);
	if (vhremote_iovec)
		free(vhremote_iovec);

	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function does the data transfer from  a VE process to
 * another VE process.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return 0 on success, returns negative of errno on failure.
 */
ret_t ve_process_vm_writev(int syscall_num, char *syscall_name, veos_handle *handle)
{
	pid_t pid = 0;
	uint64_t l_iovec = 0;
	struct iovec *vhremote_iovec = NULL;
	uint64_t riovcnt = 0;
	struct iovec *vhlocal_iovec = NULL;
	uint64_t r_iovec = 0;
	uint64_t liovcnt = 0;
	uint64_t flags = 0;
	int64_t ret = -1;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("invoked");

	/*Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	pid = (pid_t)args[0];
	l_iovec = args[1];
	liovcnt = args[2];
	r_iovec = args[3];
	riovcnt = args[4];
	flags = args[5];

	PSEUDO_DEBUG("syscall(%s) args pid(%d) l_iovec(0x%lx) liovcnt(0x%lx) "
			"r_iovec(0x%lx) riovcnt(0x%lx) flags(0x%lx)", syscall_name,
			pid, l_iovec, liovcnt, r_iovec, riovcnt, flags);

	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) liovcnt(0x%lx)", strerror(-ret), liovcnt);
		goto error_return;
	}

	if (!liovcnt || !riovcnt) {
		ret = 0;
		goto error_return;
	}

	if (!l_iovec || !r_iovec) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) l_iovec(0x%lx) r_iovec(0x%lx)",
				strerror(-ret), l_iovec, r_iovec);
		goto error_return;
	}

	vhremote_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * riovcnt);
	if (NULL == vhremote_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	vhlocal_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * liovcnt);
	if (NULL == vhlocal_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_recv_data(handle, l_iovec, sizeof(struct iovec) * liovcnt,
			(void *)vhlocal_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_recv_data(handle, r_iovec, sizeof(struct iovec) * riovcnt,
			(void *)vhremote_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhlocal_iovec, liovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhremote_iovec, riovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}
	ret = process_vm_writev(pid, vhlocal_iovec, 1, vhremote_iovec, 1,
			flags);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while transferring data from the local"
				"process to the remote process on VH", strerror(-ret));
		goto error_return;
	}

	ret = __ve_process_vm_rw(handle, vhlocal_iovec, liovcnt,
			vhremote_iovec, riovcnt, pid, 1);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}
error_return:
	if (vhlocal_iovec)
		free(vhlocal_iovec);
	if (vhremote_iovec)
		free(vhremote_iovec);

	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function do read/write operation to/from specified process
 * memory to/from calling process memory.
 *
 * @param[in] handle VEOS handle.
 * @param[in] local_iovec iovec array specifying where to copy to/from locally.
 * @param[in] liovcnt number of elements in local iovec array.
 * @param[in] remote_iovec iovec array specifying where to copy to/from
 * remote process.
 * @param[in] riovcnt Number of elements in local iovec array.
 * @param[in] pid Pid of process to/from read/write.
 * @param[in] type Type of operation read/write.
 * 0 for read from remote process, 1 for write to remote process.
 *
 * @return On success return number of bytes read/write to/from remote process
 * and negative of errno on failure.
 */
int64_t __ve_process_vm_rw(veos_handle *handle, struct iovec *local_iovec,
		uint64_t liovcnt, struct iovec *remote_iovec, uint64_t riovcnt,
		pid_t pid, int type)
{
	size_t cur_lcnt = 0, curr_l_offset = 0;
	int64_t total_rw = 0, ret = 0, idx = 0;

	PSEUDO_TRACE("invoked");

	for (idx = 0; idx < riovcnt; idx++) {
		ret = ve_process_vm_rw_single_iov(handle,
				(remote_iovec + idx),
				local_iovec, liovcnt, &cur_lcnt,
				&curr_l_offset,	pid, type);
		if (0 > ret) {
			if (!total_rw) {
				total_rw = -1;
				break;
			}
			break;
		}
		total_rw += ret;
		PSEUDO_DEBUG("total byte %s (%ld) riovcnt %ld",
				(type) ? "written":"read", total_rw, idx);
	}

	PSEUDO_TRACE("returned(%ld)", total_rw);
	return total_rw;

}

/**
 * @brief This function check the validity of each iovec.
 *
 * @param[in] iovec Pointer to check the iovec.
 * @param[in] iovcnt Number of iovec to check.
 *
 * @return On success return 0 and negative of errno on failure.
 */
int64_t ve_check_iovec(struct iovec *iovec, uint64_t iovcnt)
{
	ssize_t len = 0;
	int idx = 0;

	PSEUDO_TRACE("invoked");

	for (idx = 0; idx < iovcnt; idx++) {
		len = (ssize_t)iovec[idx].iov_len;
		if (0 > len) {
			PSEUDO_DEBUG("Error(%s) len(0x%lx)", strerror(EINVAL), len);
			return -EINVAL;
		}
		PSEUDO_DEBUG("iovec[%d].iov_length(0x%lx)", idx, len);
	}

	PSEUDO_TRACE("returned(0)");
	return 0;
}

/**
 * @brief This function do read/write operation to/from specified process
 * memory to/from calling process memory for each iovec.
 *
 * @param[in] handle Handle VEOS handle.
 * @param[in] r_iovec remote_iovec iovec array specifying where to copy
 * to/from remotelly.
 * @param[in] local_iovec local_iovec iovec array specifying where to copy
 * to/from locally.
 * @param[in] liovcnt number of elements in local iovec array
 * @param[in] curr_lcnt Current numeber local_iovev to/from read/write.
 * @param[in,out] curr_l_offset Current offset on local iovec to read/write.
 * @param[in] r_pid Pid of process to/from read/write
 * @param[in] type Type of operation read/write.
 * 0 for read from remote process, 1 for write to remote process.
 *
 * @return On success return number of bytes read/write to/from remote process.
 * and negative of errno on failure.
 */
int64_t ve_process_vm_rw_single_iov(veos_handle *handle, struct iovec *r_iovec,
		struct iovec *local_iovec, size_t liovcnt,
		size_t *curr_lcnt, size_t *curr_l_offset, pid_t r_pid,
		int type)
{
	vemva_t addr = 0, nr_pages = 0, nr_page_copied = 0;
	offset_t start_offset = 0;
	size_t pg_size = 0, min = 0;
	int64_t data_loops = 0, ret = -1;
	struct ve_process_rw_info *cmd = NULL;
	pg_size = PAGE_SIZE_2MB;

	PSEUDO_TRACE("invoked");

	/* Getting the base address for checking read/write permission */
	if (!IS_ALIGNED((uint64_t)(r_iovec[0].iov_base),
				ve_page_info.page_size)) {
		PSEUDO_DEBUG("Offset is not aligned to page boundary");
		addr = ALIGN_RD((uint64_t)(r_iovec[0].iov_base), pg_size);
	} else
		addr = (vemva_t)(r_iovec[0].iov_base);

	nr_pages = (r_iovec[0].iov_len)/pg_size;

	if (!nr_pages)
		nr_pages = 1;
	PSEUDO_DEBUG("addr  = 0x%lx, rbase vemva = %p", addr,
			r_iovec[0].iov_base);

	nr_page_copied = 0;
	start_offset = (offset_t)r_iovec[0].iov_base - addr;

	cmd = (struct ve_process_rw_info *)calloc(1, sizeof(struct
				ve_process_rw_info));
	if (NULL == cmd) {
		PSEUDO_DEBUG("Error(%s) while allocating mem for ve_process_rw_info",
				strerror(errno));
		return -errno;
	}
	cmd->base_rvemva = (uint64_t)(r_iovec[0].iov_base);
	cmd->r_len = r_iovec[0].iov_len;

	/* This for loop will read/write from/to one remote iovec
	 * to/from local iovecs base on iovec length*/
	for (; *curr_lcnt < liovcnt && nr_page_copied < nr_pages;) {
		while ((0 == local_iovec[*curr_lcnt].iov_len))
			(*curr_lcnt)++;
		if (*curr_lcnt == liovcnt || 0 == r_iovec[0].iov_len)
			break;

		min = (size_t)MIN_2(uint64_t, pg_size - start_offset,
				(r_iovec[0].iov_len - data_loops));
		if (start_offset >= pg_size)
			min = r_iovec[0].iov_len - data_loops;
		PSEUDO_DEBUG("first  min  = 0x%lx", min);
		min = (size_t)MIN_2(uint64_t, min, (local_iovec[*curr_lcnt].iov_len -
					*curr_l_offset));
		PSEUDO_DEBUG("second min  = 0x%lx", min);

		cmd->r_pid = r_pid;
		cmd->lcov_offset = *curr_l_offset;
		cmd->rcov_offest = start_offset;
		cmd->local_vemva = (vemva_t)(local_iovec[*curr_lcnt].iov_base);
		cmd->remote_vemva = (vemva_t)(addr + (pg_size * nr_page_copied));
		cmd->len = min;
		cmd->vm_rw = type;

		/*sending request veos*/
		ret = amm_send_proc_vm_rw_req(handle,
				(struct ve_process_rw_info *)cmd);
		if (0 > ret) {
			if (!data_loops) {
				data_loops = -1;
				PSEUDO_DEBUG("Error(%s) while sending proc vm (read/write) req",
						strerror(-ret));
				goto error_return;
			} else {
				PSEUDO_DEBUG("Error(%s) while sending proc vm (read/write) req",
						strerror(-ret));
				goto error_return;

			}
		}
		data_loops += min;
		*curr_l_offset = (*curr_l_offset) + min;
		/* Moving to next local iovec */
		if (((*curr_l_offset) >= (local_iovec[*curr_lcnt].iov_len))) {
			(*curr_lcnt)++;
			*curr_l_offset = 0;
		}
		start_offset += min;
		if (data_loops >= pg_size)
			nr_page_copied++;
		/* Check if one remote iovec is completed or not */
		if (data_loops >= r_iovec[0].iov_len)  {
			PSEUDO_DEBUG("data_loops >= r_iovec[0].iov_len");
			break;
		}
	}

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", data_loops);
	return	data_loops;
}

/**
 * @brief This function is used to communicate with AMM module.
 *
 * @param[in] handle VEOS handle.
 * @param[in] cmd_buf Pointer to the data_buf that contain information to send.
 *
 * @return returns positive number on success and negative of errno on failure.
 */
int64_t amm_send_proc_vm_rw_req(veos_handle *handle,
		struct ve_process_rw_info *cmd_buf)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage ve_vm_rw = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_vm_rw_msg = {0};

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("base_rvemva = 0x%lx, r_len = 0x%lx, len = 0x%lx"
			" lcov_offeset = 0x%lx, rcov_offest = 0x%lx"
			" remote_vemva = 0x%lx local_vemva = 0x%lx"
			"vm_rw = %d",
			cmd_buf->base_rvemva, cmd_buf->r_len,
			cmd_buf->len, cmd_buf->lcov_offset,
			cmd_buf->rcov_offest, cmd_buf->remote_vemva,
			cmd_buf->local_vemva, cmd_buf->vm_rw);


	ve_vm_rw.pseudo_veos_cmd_id = CMD_VMRW;

	ve_vm_rw.has_pseudo_pid = true;
	ve_vm_rw.pseudo_pid = syscall(SYS_gettid);

	ve_vm_rw_msg.len = sizeof(struct ve_process_rw_info);
	ve_vm_rw_msg.data = (uint8_t *)cmd_buf;

	ve_vm_rw.has_pseudo_msg = true;
	ve_vm_rw.pseudo_msg = ve_vm_rw_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_vm_rw);

	msg_len = pseudo_veos_message__pack(&ve_vm_rw, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_DEBUG("internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		abort();
	}

	/* sending CMD_VMRW to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to send request to veos (transferred %ld bytes)", ret);
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(ret));
		goto error_return;
	}
	/*receiving ACK for CMD_VMRW from veos*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack, MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for CMD_VMRW from VE OS",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(ret));
		goto error_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS for system call(process_vm_%sv)",
				strerror(-ret), (cmd_buf->vm_rw) ? "write" : "read");
		PSEUDO_ERROR("Error(%s) occurred on VE OS for system call(process_vm_%sv)",
				strerror(-ret), (cmd_buf->vm_rw) ? "write" : "read");
	} else {
		PSEUDO_DEBUG("process vm %sv operation successfully done on VE",
				(cmd_buf->vm_rw) ? "write" : "read");
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

ret_t ve_remap_file_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_get_mempolicy(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_mbind(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_set_mempolicy(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_move_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_migrate_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}
