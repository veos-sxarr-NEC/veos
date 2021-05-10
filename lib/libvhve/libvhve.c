/*
 * Copyright (C) 2020-2021 NEC Corporation
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
 * @file  libvhve.c
 * @brief implementation of libvhve APIs.
 *
 * This file contains the routines implementation that are used to request to
 * VEOS for operating VE DMA from VH process.
 *
 * @internal
 * @author VHVE
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>
#include "vhve.h"
#include "vhve_common.h"
#include "list.h"
#include "vhve_request.h"
#include "veos_sock.h"

/**
 * @brief This function open new VEOS handle for VHVE and return id of handle.
 *
 * @note Allow to create handle equal or less than 128 per one VEOS.
 * @note fork() and vfork() creates child process having handle id
 *       created by parent, but don't use this copied handle id in child.
 * @note Don't share veos_handle among some threads.
 *
 * @param n node number of VEOS
 *
 * @retval id of VEOS handle on success
 * @retval 0 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ENOMEM  no memory to accept this request
 * - EBUSY  failed to communicate with worker of VEOS
 */
uint64_t vhve_create_veos_handle(int n)
{
	uint64_t ret = 0;
	char *sock_path;
	vhve_veos_handle *hdl;
	int errv = 0;

	sock_path = malloc(PATH_MAX);
	if (sock_path == NULL) {
		errv = errno;
		VHVE_ERROR("ERROR sock create");
		goto err_soc;
	}
	snprintf(sock_path, PATH_MAX,
			"%s/veos%d_vhve.sock", VEOS_SOC_PATH, n);

	hdl = vhve_veos_handle_alloc(sock_path);
	if (!hdl) {
		errv = errno;
		VHVE_ERROR("ERROR veos handle create");
		goto err_hndl;
	}
	ret = (uint64_t)hdl;

err_hndl:
	free(sock_path);
err_soc:
	errno = errv;
	return ret;
}

/**
 * @brief This function close VEOS handle for VHVE
 *
 * @note When VEOS has DMA request which has't started yet and this
 *       function is called, the request is canceled by VEOS.
 *
 * @param hndl id of VEOS handle
 */
void vhve_release_veos_handle(uint64_t hdl)
{
	vhve_veos_handle *hndl = (vhve_veos_handle *)hdl;

	vhve_veos_handle_free(hndl);

	return;
}

/**
 * @brief This function starts asynchronous read VE memory.
 *
 * @note Do not fork() and system() while read request is incomplete
 * @note To ensure ordering of read/write request,
 *       please specify VHVE_DMA_OPT_SYNC in opt
 * @note Completion of DMA request with VHVE_DMA_OPT_SYNC ensures that
 *       VEOS also completes all DMA requests received before this request.
 * @note vh_addr and ve_addr should be aligned to 8-byte
 * @note length should be multiple of 8-byte
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] pid VE process ID
 * @param[in] ve_addr address of VE memory
 * @param[in] vh_addr pointer to read buffer
 * @param[in] len size of read
 * @param[in] opt logical sum of macro with VHVE_DMA_OPT_ prefix
 *
 * @retval id of request on success
 * @retval 0 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - ESRCH  not found VE process
 * - EPERM  client uid and gid are not same as VE processe's
 * - ENOMEM  No memory to accept this request
 * - EFAULT  failed to start DMA
 */
uint64_t vhve_dma_aread_vemem(uint64_t hdl, int pid, uint64_t ve_addr,
		void *vh_addr, size_t length, uint64_t opt)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	uint64_t retval = 0;

	if (vhve_dma_check_args((uint64_t)vh_addr, ve_addr, length)) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.vepid = (uint64_t)pid;
	args.srcaddr = ve_addr;
	args.dstaddr = (uint64_t)vh_addr;
	args.size = (uint64_t)length;
	args.opt = opt;

	VHVE_DEBUG("DMA_REQ Async read: handle=%lx, VH pid=%d, VHVA=%p,"
			"VE pid=%d, VEMVA=%lx, size=%zd, opt=%lx",
			hdl, getpid(), vh_addr, pid, ve_addr, length, opt);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (!ret.ret)
			retval = ret.val;
		else
			errno = -ret.ret;
	}

	return retval;
}

/**
 * @brief This function starts asynchronous write VE memory.
 *
 * @note Do not fork() and system() while write request is incomplete
 * @note To ensure ordering of read/write request,
 *       please specify VHVE_DMA_OPT_SYNC in opt
 * @note Completion of DMA request with VHVE_DMA_OPT_SYNC ensures that
 *       VEOS also completes all DMA requests received before this request.
 * @note vh_addr and ve_addr should be aligned to 8-byte
 * @note length should be multiple of 8-byte
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] pid VE process ID
 * @param[in] ve_addr address of VE memory
 * @param[in] vh_addr pointer to write buffer
 * @param[in] len size of write
 * @param[in] opt logical sum of macro with VHVE_DMA_OPT_ prefix
 *
 * @retval id of request on success
 * @retval 0 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - ESRCH  not found VE process
 * - EPERM  client uid and gid are not same as VE processe's
 * - ENOMEM  No memory to accept this request
 * - EFAULT  failed to start DMA
 */
uint64_t vhve_dma_awrite_vemem(uint64_t hdl, int pid, uint64_t ve_addr,
		void *vh_addr, size_t length, uint64_t opt)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	uint64_t retval = 0;

	if (vhve_dma_check_args((uint64_t)vh_addr, ve_addr, length)) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.is_write = 1;
	args.vepid = (uint64_t)pid;
	args.srcaddr = (uint64_t)vh_addr;
	args.dstaddr = ve_addr;
	args.size = (uint64_t)length;
	args.opt = opt;

	VHVE_DEBUG("DMA_REQ Async write: handle=%lx, VH pid=%d, VHVA=%p,"
			"VE pid=%d, VEMVA=%lx, size=%zd, opt=%lx",
			hdl, getpid(), vh_addr, pid, ve_addr, length, opt);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (!ret.ret)
			retval = ret.val;
		else
			errno = -ret.ret;
	}

	return retval;
}

/**
 * @brief This function reads from VE memory.
 *
 * @note Do not fork() and system() while this function is incomplete
 * @note To ensure ordering of read/write request,
 *       please specify VHVE_DMA_OPT_SYNC in opt
 * @note Completion of DMA request with VHVE_DMA_OPT_SYNC ensures that
 *       VEOS also completes all DMA requests received before this request.
 * @note vh_addr and ve_addr should be aligned to 8-byte
 * @note length should be multiple of 8-byte
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] pid VE process ID
 * @param[in] ve_addr address of VE memory
 * @param[in] vh_addr pointer to read buffer
 * @param[in] len size of read
 * @param[in] opt logical sum of macro with VHVE_DMA_OPT_ prefix
 *
 * @retval 0 on success
 * @retval -1 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - ESRCH  not found VE process
 * - EPERM  client uid and gid are not same as VE processe's
 * - EFAULT  failure of DMA
 */
int vhve_dma_read_vemem(uint64_t hdl, int pid, uint64_t ve_addr,
		void *vh_addr, size_t length, uint64_t opt)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	int retval = -1;

	if (vhve_dma_check_args((uint64_t)vh_addr, ve_addr, length)) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.is_wait = 1;
	args.vepid = (uint64_t)pid;
	args.srcaddr = ve_addr;
	args.dstaddr = (uint64_t)vh_addr;
	args.size = (uint64_t)length;
	args.opt = opt;

	VHVE_DEBUG("DMA_REQ read: handle=%lx, VH pid=%d, VHVA=%p, "
			"VE pid=%d, VEMVA=%lx, size=%zd, opt=%lx",
			hdl, getpid(), vh_addr, pid, ve_addr, length, opt);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (!ret.ret)
			retval = 0;
		else
			errno = -ret.ret;
	}

	return retval;
}

/**
 * @brief This function writes to VE memory.
 *
 * @note Do not fork() and system() while this function is incomplete
 * @note To ensure ordering of read/write request,
 *       please specify VHVE_DMA_OPT_SYNC in opt
 * @note Completion of DMA request with VHVE_DMA_OPT_SYNC ensures that
 *       VEOS also completes all DMA requests received before this request.
 * @note vh_addr and ve_addr should be aligned to 8-byte
 * @note length should be multiple of 8-byte
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] pid VE process ID
 * @param[in] ve_addr address of VE memory
 * @param[in] vh_addr pointer to write buffer
 * @param[in] len size of read
 * @param[in] opt logical sum of macro with VHVE_DMA_OPT_ prefix
 *
 * @retval 0 on success
 * @retval -1 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - ESRCH  not found VE process
 * - EPERM  client uid and gid are not same as VE processe's
 * - EFAULT  failure of DMA
 */
int vhve_dma_write_vemem(uint64_t hdl, int pid, uint64_t ve_addr,
		void *vh_addr, size_t length, uint64_t opt)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	int retval = -1;

	if (vhve_dma_check_args((uint64_t)vh_addr, ve_addr, length)) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.is_write = 1;
	args.is_wait = 1;
	args.vepid = (uint64_t)pid;
	args.srcaddr = (uint64_t)vh_addr;
	args.dstaddr = ve_addr;
	args.size = (uint64_t)length;
	args.opt = opt;

	VHVE_DEBUG("DMA_REQ write: handle=%lx, VH pid=%d, VHVA=%p,"
			"VE pid=%d, VEMVA=%lx, size=%zd, opt=%lx",
			hdl, getpid(), vh_addr, pid, ve_addr, length, opt);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (!ret.ret)
			retval = 0;
		else
			errno = -ret.ret;
	}

	return retval;
}

/**
 * @brief This function waits for an asynchronous read/write request.
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] reqid request id
 *
 * @retval 0 on success
 * @retval -1 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - EFAULT  failure of DMA
 */
int vhve_dma_wait(uint64_t hdl, uint64_t reqid)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	int retval = -1;

	if (reqid == 0) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.reqid = reqid;
	args.is_wait = 1;

	VHVE_DEBUG("DMA_REQ wait: handl=%lx, reqest=%lx",
			hdl, reqid);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (!ret.ret)
			retval = 0;
		else
			errno = -ret.ret;
	}

	return retval;
}

/**
 * @brief This function peeks result of an asynchronous read/write request.
 *
 * @param[in] hdl id of VEOS handle
 * @param[in] reqid request id
 *
 * @retval 0 on success, request has finished
 * @retval 1 on success, request has not finished yet
 * @retval -1 on failure and following errno is set
 * - EINVAL  invalid argument
 * - ECOMM  communication error with VEOS on send
 * - ENODATA  communication error with VEOS on receive
 * - EFAULT  failure of DMA
 */
int vhve_dma_query(uint64_t hdl, uint64_t reqid)
{
	struct vhve_dma_args args = { 0 };
	struct vhve_result ret;
	int retval = -1;

	if (reqid == 0) {
		errno = EINVAL;
		return retval;
	}

	args.cmd = VHVE_DMA_REQ;
	args.reqid = reqid;

	VHVE_DEBUG("DMA_REQ query: handle=%lx, reqest=%lx",
			hdl, reqid);

	if (!vhve_request_to_veos((vhve_veos_handle *)hdl, &args,
				sizeof(struct vhve_dma_args), &ret)) {
		if (ret.ret >= 0)
			retval = ret.ret;
		else
			errno = -ret.ret;
	}

	return retval;
}
