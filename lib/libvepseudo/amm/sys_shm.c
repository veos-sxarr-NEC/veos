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
 * @file sys_shm.c
 * @brief handle shared memory related system call from pseudo process.
 *
 *	This contains the shared memory specific system call from pseudo side
 *
 * @internal
 * @author AMM
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include "sys_common.h"
#include "sys_shm.h"
#include "mm_transfer.h"
#include "sys_mm.h"
#include "ve_socket.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "ve_memory.h"

/**
 * @brief This function to handle shmget system call
 *
 * @param[in] syscall_num syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success return shmid, returns negative of errno on failure.
 */
ret_t ve_shmget(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	uint64_t args[3] = {0};
	key_t key = 0;
	size_t aligned_size = 0, size = 0;
	struct shm_seginfo *shm_info = NULL;
	int shmflg = 0, vh_shmflg = 0;
	int64_t shmid = 0;

	PSEUDO_TRACE("invoked");
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to fetch syscall (%s) args",
				syscall_name);
		ret = -EFAULT;
		goto shmget_ret;
	}

	/* Read shmget system call arguments */
	key	= (key_t)args[0];
	size	= (size_t)args[1];
	shmflg	= (int)args[2];
	vh_shmflg = shmflg;

	PSEUDO_DEBUG("syscall(%s) args:key(0x%x) size(0x%lx) flag(0x%x)",
			syscall_name, key, size, shmflg);
	/* Check user has provided the shm page size flag or not.
	 * If not provided than provide default page size as per
	 * binary page size */
	if ((!(shmflg & SHM_2MB)) && (!(shmflg & SHM_64MB)))
		shmflg |= (default_page_size == PAGE_SIZE_2MB)
				? SHM_2MB : SHM_64MB;

	if (shmflg & SHM_64MB) {
		aligned_size = ALIGN(size, PAGE_SIZE_64MB);
		PSEUDO_DEBUG("shm seg aligned size %lx with %s mode",
			aligned_size, pgsz_to_pgstr(PAGE_SIZE_64MB));
	} else {
		aligned_size  = ALIGN(size, PAGE_SIZE_2MB);
		PSEUDO_DEBUG("shm seg aligned size %lx with %s mode",
			aligned_size, pgsz_to_pgstr(PAGE_SIZE_2MB));
	}

	if (shmflg & SHM_HUGETLB) {
		PSEUDO_DEBUG("SHM_HUGETLB flag not supported");
		ret = -EINVAL;
		goto shmget_ret;
	}
	vh_shmflg = vh_shmflg & (~(SHM_64MB | SHM_2MB));
	/* Provide SHM_NORESERVE flag while getting shm segment as
	 * we are not accessing the VH shm memory */
	vh_shmflg |= SHM_NORESERVE;

	/* Call VH OS shmget() system call
	 */
	PSEUDO_DEBUG("invoke host shmget()");
	shmid = shmget(key, size, vh_shmflg);
	if (0 > shmid) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) from host shmget()",
					strerror(-ret));
		goto shmget_ret;
	}

	shm_info = amm_request_shmget(handle, key, shmid,
			aligned_size, shmflg);
	if (NULL == shm_info) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while getting shm segment from VEOS",
			strerror(-ret));
		goto shmget_ret;
	}

	PSEUDO_TRACE("syscall (%s) returned with shmid(0x%lx)",
			syscall_name, shmid);
	ret = shmid;
shmget_ret:
	if (shm_info)
		free(shm_info);
	return ret;
}

/**
 * @brief This function is used to communicate with veos module
 * for Creating Shared memory segment.
 *
 * @param[in] handle VEOS handle
 * @param[in] key SHM unique key
 * @param[in] shmid Shared memory unique ID
 * @param[in] size Shared memory segment size
 * @param[in] shmflg Shared memory segment flag
 *
 * @return Returns pointer of struct shm_seginfo on success and
 * returns NULL on failure.
 */
struct shm_seginfo *amm_request_shmget(veos_handle *handle, key_t key,
		int64_t shmid, size_t size, int shmflg)
{
	ret_t ret = 0;
	struct ve_shm_cmd req = {0};
	struct shm_seginfo *shm_info = NULL;

	PSEUDO_TRACE("invoked");

	shm_info = (struct shm_seginfo *)calloc(1,
			sizeof(struct shm_seginfo));
	if (NULL == shm_info) {
		PSEUDO_DEBUG("failed to allocate shm info");
		return NULL;
	}

	/* Generate IPC Command */
	req.key = key;
	req.shmid = shmid;
	req.size = size;
	req.flag = shmflg;
	req.create = true;

	PSEUDO_DEBUG("request params: key(0x%x), id(0x%lx), size(0x%lx) flag(%x) creat(%u)",
			req.key, req.shmid, req.size, req.flag, req.create);

	ret = ve_shm_request(&req, handle->veos_sock_fd,
			CMD_SHMGET, shm_info);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to get ack from VEOS");
		free(shm_info);
		errno = -ret;
		shm_info = NULL;
	}

	PSEUDO_TRACE("returned");
	return shm_info;
}

/**
 * @brief This function is used to communicate with veos module
 * for Creating Shared memory segment.
 *
 * @param[in] handle VEOS handle
 * @param[in] shmid Shared memory unique ID
 *
 * @return Returns pointer of struct shm_seginfo on success and
 * returns NULL on failure.
 */
struct shm_seginfo *ve_get_shm_seg_pgmode(veos_handle *handle, int64_t shmid)
{
	int64_t ret = -1;
	struct ve_shm_cmd req = {0};
	struct shm_seginfo *shm_info = NULL;

	PSEUDO_TRACE("invoked");

	shm_info = (struct shm_seginfo *)calloc(1, sizeof(struct shm_seginfo));
	if (NULL == shm_info) {
		PSEUDO_DEBUG("failed to allocate shm info");
		return NULL;
	}

	/* Generate IPC Command */
	req.shmid = shmid;
	req.create = false;

	PSEUDO_DEBUG("shm req params: id(%lx), creat(%x)",
			req.shmid, req.create);

	ret = ve_shm_request(&req, handle->veos_sock_fd,
			CMD_SHMGET, shm_info);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while getting ack from veos",
					strerror(-ret));
		goto handle_err;
	}

	PSEUDO_TRACE("returned");
	return shm_info;
handle_err:
	free(shm_info);
	errno = -ret;
	return NULL;
}

/**
 * @brief This function will send ipc request to veos for system call
 * like shmget, shmat, shmdt.
 *
 * @param[in] req Ref to command struct.
 * @param[in] veos_sock_fd VEOS sock fd to communicate with veos.
 * @param[in] req_id Request commnd id.
 * @param[out] shm_info Shared memory segment related information.
 *
 * @return Returns zero on success and negative of errno on failure.
 */
int ve_shm_request(struct ve_shm_cmd *req, int veos_sock_fd,
				int req_id,
				struct shm_seginfo *shm_info)
{
	void *pb_req = NULL;
	size_t pseudo_msg_len = 0;
	int ret = 0;
	char ack[CMD_BUFFER_SIZE] = {'0'};

	PseudoVeosMessage *pseudo_msg = NULL;
	PseudoVeosMessage ve_shm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_shm_req_msg = {0};

	PSEUDO_TRACE("invoked");

	/* Popluate parameters for ve_shm_req req */
	ve_shm_req.pseudo_veos_cmd_id = req_id;

	ve_shm_req.has_pseudo_pid = true;
	ve_shm_req.pseudo_pid = syscall(SYS_gettid);

	ve_shm_req_msg.len = sizeof(struct ve_shm_cmd);
	ve_shm_req_msg.data = (uint8_t *)req;

	ve_shm_req.has_pseudo_msg = true;
	ve_shm_req.pseudo_msg = ve_shm_req_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_shm_req);

	pb_req = calloc(1, pseudo_msg_len);
	if (NULL == pb_req) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) while allocating pb req",
				strerror(errno));
		goto hndl_return;
	}

	PSEUDO_DEBUG("allocating pb req(%p) of size(0x%lx)",
			pb_req, pseudo_msg_len);

	pseudo_veos_message__pack(&ve_shm_req, pb_req);

	ret = pseudo_veos_send_cmd(veos_sock_fd, pb_req,
				pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to send shm req to VEOS");
		goto hndl_error;
	}

	ret = pseudo_veos_recv_cmd(veos_sock_fd, ack, CMD_BUFFER_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to get VEOS ack for shm req");
		goto hndl_error;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
					(const uint8_t *)(ack));
	if (NULL == pseudo_msg) {
			PSEUDO_DEBUG("failed to unpack pb msg for shm req");
			ret = -1;
			goto hndl_error;
	}

	/*fetch bitmap in case of shm_info is not NULL*/
	PSEUDO_DEBUG("copy shm info");
	if (shm_info) {
		memcpy(shm_info,
		       ((PseudoVeosMessage *)(pseudo_msg->pseudo_msg).data),
				sizeof(struct shm_seginfo));
	}

	ret = pseudo_msg->syscall_retval;
	if (0 > ret) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error (%s) by VEOS for shm req", strerror(-ret));
	} else {
		PSEUDO_DEBUG("shm req handled succesfully by VEOS");
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

hndl_error:
	free(pb_req);
hndl_return:
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function to handle shmat system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success return shared memory addres, returns negative
 * errno on failure.
 */
ret_t ve_shmat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	int64_t shmid = 0;
	vemva_t shmaddr = 0;
	int64_t shmflag = 0;
	void *ret_addr = NULL;
	uint64_t args[3] = {0};
	size_t size = 0;
	int pgmod = 0;
	struct shm_seginfo *shm_info = NULL;

	PSEUDO_TRACE("invoked");
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("failed to fetch syscall (%s) args", syscall_name);
		goto hndl_return;
	}

	/* Read shmat system call arguments */
	shmid	= (int64_t)args[0];
	shmaddr = (vemva_t)args[1];
	shmflag	= (int64_t)args[2];

	PSEUDO_DEBUG("syscall(%s) args: id(%ld) shmaddr(0x%lx) flag( 0x%lx)",
			syscall_name, shmid, shmaddr, shmflag);

	shm_info = ve_get_shm_seg_pgmode(handle, shmid);
	if (!shm_info) {
		ret = -errno;
		PSEUDO_DEBUG("failed to get shm seg page mode from VEOS");
		goto hndl_return;
	}

	pgmod = shm_info->pgmod;
	size = shm_info->size;
	shmflag |= (pgmod == PG_2M) ? SHM_2MB : SHM_64MB;

	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	ve_page_info.page_size = (uint64_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB :
			PAGE_SIZE_64MB);

	ve_page_info.page_mask = ve_page_info.page_size - 1;
	ve_page_info.chunk_size = ve_page_info.page_size *
		ENTRIES_PER_DIR;
	ve_page_info.chunk_mask = ve_page_info.chunk_size - 1;
	ve_page_info.updated = 1;

	PSEUDO_DEBUG("%s chunk of %s with chunk mask(%lx) and page mask(%lx)",
			chsz_to_chstr(ve_page_info.chunk_size),
			pgmod_to_pgstr(pgmod), ve_page_info.chunk_mask,
			ve_page_info.page_mask);
	/* Request for shmat */
	ret_addr = __ve_shmat(handle, shmid, shmaddr, shmflag, size);
	if ((void *)-1 == ret_addr) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) from VEOS for shmat() req",
				strerror(-ret));
	} else {
		ret = (uint64_t)ret_addr;
	}


hndl_return:
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	if (shm_info)
		free(shm_info);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief Function to handle shared memory attach request.
 *
 * @param[in] handle VEOS handle
 * @param[in] shmid Shared Memory unique ID
 * @param[in] shmaddr Memory mapping is to be done at this address
 * @param[in] shmflag Additional information for memory mapping
 *
 * @return On success returns mapped virtual address failure returns
 * (void *)-1 and set errno.
 */
vemva_t *__ve_shmat(veos_handle *handle, int64_t shmid, vemva_t shmaddr,
		int shmflag, size_t size)
{
	int ret = 0;
	int64_t shmperm = 0;
	int64_t flag_mmap = 0, errno_ret = 0;
	int shmat_flag = 0;
	void *shmaddr_tmp = NULL, *ret_addr = NULL;

	PSEUDO_TRACE("invoked");
	/* Align size to next VE page boundary */

	PSEUDO_DEBUG("req to attach shm segid(%ld) of size(0x%lx) at"
			"vemva(0x%lx) and flag( 0x%x)",
			shmid, size, shmaddr, shmflag);

	size = ALIGN(size, ve_page_info.page_size);
	PSEUDO_DEBUG("aligned shm attach size is %lx", size);


	if (shmaddr < 0) {
		PSEUDO_DEBUG("Invalid shmaddr(0x%lx)\n", shmaddr);
		errno = ENOMEM;
		return (void *)-1;

	}

	if (shmaddr && (shmflag & SHM_RND)) {
		shmaddr = shmaddr & ~(ve_page_info.page_mask);
		PSEUDO_DEBUG("shm vemva(0x%lx)", shmaddr);
		flag_mmap |= MAP_FIXED;
	} else if (shmaddr && (shmflag & SHM_REMAP)) {
		PSEUDO_DEBUG("shm vemva(0x%lx) specified with remap option",
				shmaddr);
		if (!IS_ALIGNED(shmaddr, ve_page_info.page_size)) {
			PSEUDO_DEBUG("shm vemva(%lx) not aligned with"
				"req page type", shmaddr);
			errno = EINVAL;
			return (void *)-1;
		}
		flag_mmap |= MAP_FIXED;
	} else if (!shmaddr && (shmflag & SHM_REMAP)) {
		PSEUDO_DEBUG("Invalid shm address with remap flag");
		errno = EINVAL;
		return (void *)-1;
	}

	if (!IS_ALIGNED(shmaddr, ve_page_info.page_size)) {
		PSEUDO_DEBUG("Invalid shm address with remap flag");
		errno = EINVAL;
		return (void *)-1;
	}

	/* shared memory segment write permission ?*/
	shmperm = (shmflag & SHM_RDONLY) ? PROT_READ :
		PROT_WRITE | PROT_READ;
	flag_mmap |= MAP_SHARED | MAP_ANON;
	flag_mmap |= (shmflag & SHM_2MB) ? MAP_2MB :
			(shmflag & SHM_64MB) ? MAP_64MB : 0;

	PSEUDO_DEBUG("reserve vemva for shm segment id(%lx)", shmid);
	ret_addr = ve_get_vemva(handle, shmaddr, size,
			flag_mmap, shmperm, -1, 0);
	if ((void *)-1 == ret_addr) {
		PSEUDO_DEBUG("failed to reserve vemva for shmid(0x%lx)", shmid);
		return ret_addr;
	}
	shmaddr_tmp = ret_addr;

	/*
	 * Call VH OS shmat() system call. SHM_REMAP flag is appended to
	 * attach the segment on the given virtual address only.
	 */
	shmat_flag = (shmflag | SHM_REMAP) & (~(SHM_2MB | SHM_64MB));
	shmaddr_tmp = shmat(shmid, shmaddr_tmp, shmat_flag);
	if ((void *)-1 == shmaddr_tmp) {
		errno_ret = errno;
		PSEUDO_DEBUG("Error (%s) in host shmat() req for id(0x%lx)",
				strerror(-errno), shmid);
		ret = ve_free_vemva((void *)ret_addr, size);
		if (0 > ret)
			PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
					strerror(-ret), ret_addr);

		errno = errno_ret;
		goto shmat_ret;
	}

	/* veos Communication */
	ret = amm_request_shmat(handle, shmid,
			(uint64_t)shmaddr_tmp, size, shmperm);
	if (0 > ret) {
		PSEUDO_DEBUG("shmat() req for id(%lx) fails from VEOS",
				shmid);
		/* veos error code is yet to design after analysing
		 * the standard error codes.It should be in such a way
		 * that there should not be any overlap with the standard
		 * errors.As of now setting it as EFAULT
		 */
		errno_ret = -ret;
		ret = ve_free_vemva((void *)ret_addr, size);
		if (0 > ret)
			PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
					strerror(-ret), ret_addr);

		errno = errno_ret;
		shmaddr_tmp = (void *)-1;
		goto shmat_ret;
	}

shmat_ret:
	PSEUDO_TRACE("returned");
	return shmaddr_tmp;
}

/**
 * @brief This function is used to communicate with veos module for memmory mapping.
 *
 * @param[in] handle VEOS handle
 * @param[in] key SHM unique key
 * @param[in] shmid Shared memory unique ID
 * @param[out] shmaddr Shared memory VEMVA
 * @param[in] size Shared memory segment size
 * @param[in] perm Shared memory segment permissions
 *
 * @return returns 0 on success and negative of errno on failure.
 */
ret_t amm_request_shmat(veos_handle *handle, int64_t shmid,
		vemva_t shmaddr, size_t size, int64_t shmperm)
{
	ret_t ret = 0;
	struct ve_shm_cmd req = {0};

	PSEUDO_TRACE("invoked");

	PSEUDO_DEBUG("to attach shm segid(0x%lx) at vemva(0x%lx)"
		"of size(0x%lx) with %s perm", shmid, shmaddr, size,
		perm_to_shmstr(shmperm));

	/* Generate IPC Command */
	req.vaddr = shmaddr;
	req.size = size;
	req.shmid = shmid;
	req.shmperm = shmperm;

	PSEUDO_DEBUG("vaddr(0x%lx), size(0x%lx), shmid(0x%lx)"
			"shmperm(%lx)", req.vaddr, req.size, req.shmid,
			req.shmperm);

	ret = ve_shm_request(&req, handle->veos_sock_fd, CMD_SHMAT, NULL);
	if (0 > ret)
		PSEUDO_DEBUG("Error (%s) while getting ack from veos",
					strerror(-ret));

	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function to handle shmctl system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in,out] VEOS handle
 *
 * @return On success return zero, returns negative of errno on failure.
 */
ret_t ve_shmctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	int64_t shmid = 0;
	int64_t cmd = 0;
	uint64_t shmid_ds_ptr = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("invoked");
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("failed to fetch syscall (%s) args", syscall_name);
		goto hndl_return;
	}

	/* Read shmctl system call arguments */
	shmid = (int64_t)args[0];
	cmd = (int64_t)args[1];
	shmid_ds_ptr = (uint64_t)args[2];

	PSEUDO_DEBUG("syscall(%s) args: id(%ld) cmd(%lx)",
			syscall_name, shmid, cmd);

	if (0 > cmd) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error (%s) while handling shmctl() req.",
				strerror(-ret));
		goto hndl_return;
	}

	/* Request for shmctl */
	ret = __ve_shmctl(handle, shmid, cmd, shmid_ds_ptr);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while handling shmctl() req.",
			strerror(-ret));
	}

hndl_return:
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function is used to handle shared memory control request.
 *
 * @param[in] handle VEOS handle
 * @param[in] shmid Shared memory unique ID
 * @param[in] cmd Shared memory control request cmd
 * @param[out] shmid_ds_ptr VEMVA to struct shmid_ds
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t __ve_shmctl(veos_handle *handle, int64_t shmid,
		int64_t cmd, uint64_t shmid_ds_ptr)
{
	int ret = 0;
	struct shmid_ds *buf = NULL;

	PSEUDO_TRACE("invoked");
	buf = (struct shmid_ds *)calloc(1, sizeof(struct shmid_ds));
	if (NULL == buf) {
		ret = -ENOMEM;
		PSEUDO_DEBUG("Error (%s) while allocating shmid_ds",
			strerror(-ret));
		return ret;
	}
	PSEUDO_DEBUG("allocated shmid_ds(%p) of size(0x%lx)", buf,
			sizeof(struct shmid_ds));

	switch (cmd) {
	case IPC_INFO:
	case SHM_INFO:
	case SHM_STAT:
	case IPC_STAT:
		/* Call VH OS shmctl() syscall */
		if (!shmid_ds_ptr) {
			ret = -EFAULT;
			goto shmctl_err;
		}
		ret = shmctl(shmid, cmd, buf);
		if (0 > ret) {
			ret = -errno;
			PSEUDO_DEBUG("Error (%s) by host shmctl()"
				"for shmid(0x%lx)", strerror(-ret), shmid);
			goto shmctl_err;
		}
		/* Copy the obtained information
		 * (struct shmid_ds) from linux
		 * kernel regarding shared memory segment in VE memory.
		 */
		ret = ve_send_data(handle, shmid_ds_ptr,
				sizeof(struct shmid_ds), (void *)buf);
		if (0 > ret) {
			PSEUDO_DEBUG("failed to send shmid_ds to VE mem");
			goto shmctl_err;
		}
		break;
	case IPC_RMID:
		/* Request veos for destroy of shared memory
		 * segment.
		 */
		ret = amm_request_shmctl_rmid(handle, shmid);
		if (0 > ret) {
			PSEUDO_DEBUG("failed to req VEOS to handle shmctl()");
			goto shmctl_err;
		}
		break;
	case IPC_SET:
		/* Retreive the information(struct shmid_ds)
		 * from VE memory.
		 */
		ret = ve_recv_data(handle, shmid_ds_ptr,
				sizeof(struct shmid_ds), (void *)buf);
		if (0 > ret) {
			PSEUDO_DEBUG("failed to fetch shmid_ds from VE mem");
			goto shmctl_err;
		}
		/* Call VH OS shmctl() syscall */
		ret = shmctl(shmid, cmd, buf);
		if (0 > ret) {
			ret = -errno;
			PSEUDO_DEBUG("Error (%s) by host shmctl()"
				"for shmid(0x%lx)", strerror(-ret), shmid);
			goto shmctl_err;
		}
		break;
	case SHM_LOCK:
	case SHM_UNLOCK:
		PSEUDO_DEBUG("flag SHM_UNLOCK is not supported");
		ret = -EINVAL;
		break;
	}
shmctl_err:
	free(buf);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function is used to communicate with veos module for
 * removing shared memory segemnt.
 *
 * @param[in] handle VEOS handle
 * @param[in] shmid Shared memory unique ID
 *
 * @return returns 0 on success and negative of errno on failure.
 */
int64_t amm_request_shmctl_rmid(veos_handle *handle, int64_t shmid)
{
	ret_t ret = 0;
	struct ve_shm_cmd req = {0};

	PSEUDO_TRACE("invoked");
	memcpy(&(req.shmid), &shmid, sizeof(shmid));
	ret = ve_shm_request(&req, handle->veos_sock_fd, CMD_SHMCTL, NULL);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while getting ack from veos",
					strerror(-ret));
		goto hndl_error;
	}

	/* Call VH OS shmctl system call */
	/*
	 * whether this case can occur
	 * Case when host shm is removed but
	 * VE process is not removed
	 * next time same id assigned to
	 * other process create new shm
	 * and get same id
	 */

	ret = shmctl(shmid, IPC_RMID, 0);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error (%s) in host shmctl() req for id(%lx)",
				strerror(-ret), shmid);
		goto hndl_error;
	}

	PSEUDO_DEBUG("VEOS ack for shmctl():rmid succeed");
hndl_error:
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function to handle shmdt system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success return zero, returns negative of errno on failure.
 */
ret_t ve_shmdt(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	vemva_t shmaddr = 0;
	uint64_t args[1] = {0};

	PSEUDO_TRACE("invoked");
	ret = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("failed to fetch syscall (%s) args", syscall_name);
		goto hndl_return;
	}

	/* Read shmdt system call arguments */
	shmaddr = (vemva_t)args[0];

	if (shmaddr <= 0) {
		ret = -EINVAL;
		goto hndl_return;
	}

	PSEUDO_DEBUG("shm detach req at shm address %lx", shmaddr);

	ret = get_page_size(shmaddr);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while getting pgsz at addr %lx",
				strerror(-ret), shmaddr);
		goto hndl_return;
	}

	/* check shmaddr is aligned and Is shmaddr zero*/
	if ((shmaddr & ~(~(ve_page_info.page_size - 1))) | (!shmaddr)) {
		PSEUDO_DEBUG("Invalid address for shm detach");
		ret = -EINVAL;
		goto hndl_return;
	}

	/* Request for shmdt */
	ret = __ve_shmdt(handle, shmaddr);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while detaching shm at addr %lx",
				strerror(-ret), shmaddr);
	}

hndl_return:
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief This function is used to handle shared memory detach request.
 *
 * @param[in] handle VEOS handle
 * @param[in] shmaddr VEMVA of attached shared memory
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t __ve_shmdt(veos_handle *handle, vemva_t shmaddr)
{
	ret_t ret = 0;
	struct ve_shm_cmd req = {0};
	struct shm_seginfo shm_info = {0};
	uint64_t i = 0, count = 0, word = 0, bit = 0;

	PSEUDO_TRACE("invoked");

	/* Generate IPC Command */

	req.vaddr = shmaddr;
	PSEUDO_DEBUG("detaching shm from vemva %lx", shmaddr);
	PSEUDO_DEBUG("req(%p), vfd(%d), req_id(%d), shminfo(%p)",
			&req, handle->veos_sock_fd, CMD_SHMDT,
			&shm_info);
	ret = ve_shm_request(&req, handle->veos_sock_fd, CMD_SHMDT,
				&shm_info);
	if (0 > ret) {
		PSEUDO_DEBUG("Error (%s) while getting ack from veos",
					strerror(-ret));
		goto send_error;
	}

	count = shm_info.size/ve_page_info.page_size;
	PSEUDO_DEBUG("detaching shm of size %ld at addr %lx",
			shm_info.size, shmaddr);
	PSEUDO_TRACE("iterating for each vemva to detach");
	for (i = 0, word = 0, bit = 0; i < count; i++) {
		if (shm_info.bitmap[word] & ((uint64_t)1<<bit)) {
			PSEUDO_TRACE("detach bmap(%p) bmap_idx(0x%lx) val(0x%lx)",
				shm_info.bitmap, word, shm_info.bitmap[word]);

			ret = ve_free_vemva((void *)shmaddr,
					ve_page_info.page_size);
			if (ret) {
				PSEUDO_DEBUG("Error (%s) while freeing %s vemva(%lx)"
					"for shmdt() req",
					strerror(-ret), pgsz_to_pgstr
					(ve_page_info.page_size),
					shmaddr);
				goto send_error;
			}
		}
		if (++bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}

		shmaddr += ve_page_info.page_size;
		PSEUDO_TRACE("next vemva %lx for shmdt() req",
				shmaddr);
	}
	PSEUDO_TRACE("iteration to detach vemva for shmdt() ends");
send_error:
	PSEUDO_TRACE("returned");
	return ret;
}
