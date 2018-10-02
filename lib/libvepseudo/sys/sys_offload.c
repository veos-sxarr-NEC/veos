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
* @file sys_offload.c
* @brief Handles LPPG related system calls encountered by VE process.
*
* This file contains LPPG related system call handlers for the various
* system calls encountered by VE process.
*
* @internal
* @author Pseudo/System Call Handling
*/

#include "sys_common.h"
#include "sys_offload.h"
#include "mm_transfer.h"
#include "velayout.h"
#include "exception.h"
#include "ve_socket.h"
#include "signal_comm.h"
#include "process_mgmt_comm.h"
#include "vh_mem_alloc.h"
#include "vemva_mgmt.h"

#define SIZE_512	0x200

/**
 * @brief Generic Handler for write() and pwrite64() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and then offloads the functionality to VH OS
 *	write()/pwrite64() system call.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_write_pwrite64(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	char *write_buff = NULL;
	size_t recv_size = 0;
	uint64_t args[4] = {0};
	sigset_t signal_mask = { {0} };
	int flags = 0;

	PSEUDO_TRACE("Entering");
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
				"arguments, (%s) returned %d\n",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (syscall_num == SYS_pwrite64) {
		if ((loff_t)args[3] < 0) {
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	/* receive write buffer size from VE memory */
	recv_size = args[2];
	if ((ssize_t) recv_size < 0) {
		retval = -EFAULT; /* Mapped as per the kernel implementation for refrence access_ok */
		goto hndl_return;
	}

	if (recv_size > MAX_RW_COUNT)
		recv_size = MAX_RW_COUNT;

	if (args[1]) {
		/* allocate memory to store write data */
		flags = fcntl(args[0],F_GETFL,0);
		if (flags & O_DIRECT) {
			if (!IS_ALIGNED(args[1], SIZE_512)) {
				PSEUDO_DEBUG("O_DIRECT set and VE buffer is unaligned");
				retval = -EINVAL;
				goto hndl_return;
			}
			/* Under Linux 2.6, alignment to 512-byte boundaries suffices
			 * e.g -
			 * 1 --> posix_memalign(&write_buff,512,recv_size);
			 * 2 --> memalign(sysconf(_SC_PAGESIZE),size);
			 */
			write_buff = (char *)vh_alloc_buf(recv_size, true);
		} else {
			write_buff = (char *)vh_alloc_buf(recv_size, false);
		}

		if (NULL == write_buff) {
			retval = -ENOSPC;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("Failed(%s) to create buffer to"
					" store argumentsi, write_buff",
					strerror(errno));
			goto hndl_return;
		}

		/* receive the write buffer */
		if (0 > ve_recv_data(handle, args[1],
					recv_size, (uint64_t *)write_buff)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[0]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			(char *)write_buff, recv_size, args[3]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		goto hndl_return1;
	} else
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	vh_free_buf(write_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles write() system call for VE.
 *
 *	ssize_t write(int fd, const void *buf, size_t count);
 *
 *	This function uses generic handler "ve_hndl_write_pwrite64" as write()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_write(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_write_pwrite64(syscall_num, syscall_name, handle);
}

/**
 * @brief Generic Handler for writev() and pwritev() system calls for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS writev()/pwritev() system call.
 *	It copies the data to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_writev(),
 *	ve_pwritev().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_writev_pwritev(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	struct iovec *vh_iov = NULL;
	int iovcnt = 0;
	int i = 0;
	uint64_t args[4] = {0};
	uint64_t **vh_buff_addr = NULL;
	sigset_t signal_mask = { {0} };
	int dio_flag = -1;

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments,(%s) returned %d\n",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* writev() iovcnt from VE memory */
	iovcnt = args[2];
	PSEUDO_DEBUG("VE buffer count : %d", iovcnt);

	/* Validate the input arguments */
	if ((UIO_MAXIOV < iovcnt) || (0 >= iovcnt) || (NULL == (void *)args[1]))
	{
		if (NULL == (void *)args[1])
			retval = -EFAULT;
		else if(iovcnt == 0)
			retval = 0;
		else
			retval = -EINVAL;
		goto hndl_return;
	}

	/* local memory buffer to store writev data */
	vh_iov = (struct iovec *)vh_alloc_buf(iovcnt * sizeof(struct iovec), false);
	if (NULL == vh_iov) {
		retval = -ENOSPC;
		PSEUDO_ERROR("Failed to create local memory buffer");
		PSEUDO_DEBUG("vh_iov : calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	/* receive writev() const struct iovec*  from VE memory */
	if (0 > ve_recv_data(handle, args[1],
				(iovcnt * sizeof(struct iovec)),
				(uint64_t *)(vh_iov))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[0]",
					strerror(errno), SYSCALL_NAME);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Validate the the buffer and length */
	/* Asume buffer and respective lengths are ok.*/
	retval = 0;
	for (i = 0; i < iovcnt; i++) {
		if (vh_iov[0].iov_base == NULL)
			retval = -EFAULT;
		else if ((ssize_t)vh_iov[i].iov_len < 0)
			retval = -EINVAL;
		else if((ssize_t)vh_iov[i].iov_len > MAX_RW_COUNT) {
			vh_iov[i].iov_len = MAX_RW_COUNT;
		}
		else
			;
		if (retval != 0)
			goto hndl_return1;
	}

	/* create VH buffers */
	vh_buff_addr = vh_alloc_buf(iovcnt * (sizeof(uint64_t)), false);
	if (NULL == vh_buff_addr) {
		retval = -ENOSPC;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("vh_buff_addr : calloc %s failed %s",
			SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	}

	dio_flag = fcntl(args[0],F_GETFL,0);
	if (dio_flag & O_DIRECT)
		dio_flag = 1;
	else
		dio_flag = 0;
	/* Create VH environment for writev() */
	for (i = 0; i < iovcnt; i++) {
		PSEUDO_DEBUG("VE data: buff: %d length :%lu data:%lu",
				i, (unsigned long)(vh_iov[i].iov_len),
				(unsigned long)vh_iov[i].iov_base);

		if ((NULL != (void *)vh_iov[i].iov_base) &&
				(0 != (ssize_t)vh_iov[i].iov_len)) {
			if (dio_flag) {
				if (!IS_ALIGNED(args[1], SIZE_512)) {
					PSEUDO_DEBUG("O_DIRECT set and"
							" VE buffer is unaligned");
					retval = -EINVAL;
					goto hndl_return2;
				}
				vh_buff_addr[i] =
					(uint64_t *)vh_alloc_buf(
							vh_iov[i].iov_len, true);
			} else {
				vh_buff_addr[i] = (uint64_t *)vh_alloc_buf
					((vh_iov[i].iov_len), false);
			}

			if (NULL != (void *)vh_buff_addr[i]) {
				if (0 > ve_recv_data(handle,
					(uint64_t)(vh_iov[i].iov_base),
					(vh_iov[i].iov_len*sizeof(char)),
					(uint64_t *)(vh_buff_addr[i]))) {
						PSEUDO_DEBUG("Failed to receive"
							" args[%d] from ve", i);
						PSEUDO_ERROR("Failed(%s) to"
						" receive %s arguments from"
						" ve", strerror(errno),
						SYSCALL_NAME);
						retval = -EFAULT;
						goto hndl_return2;
				}
			} else {
				retval = -ENOSPC;
				PSEUDO_ERROR("calloc fail for buffer %d",
						i+1);
				goto hndl_return2;
			}
		}
		vh_iov[i].iov_base = (void *)vh_buff_addr[i];
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], vh_iov, iovcnt, args[3]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME,
			strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			* set retval to -VE_ERESTARTSYS. VE process
			* will restart the syscall if SA_RESTART
			* flag is provided for signal
			**/
			retval = -VE_ERESTARTSYS;
	} else
		PSEUDO_DEBUG("syscall %s writev %lu bytes",
				SYSCALL_NAME, retval);
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* cleaning local storage */
hndl_return2:
	for (i = 0; i < iovcnt; i++) {
		if (NULL != (void *)vh_buff_addr[i])
			vh_free_buf(vh_buff_addr[i]);
	}
	vh_free_buf(vh_buff_addr);
hndl_return1:
	vh_free_buf(vh_iov);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Generic handler for readv() and preadv() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS readv()/preadv() system call. This
 *	function after receiving the data from VH OS call copies the data to
 *	VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_readv(),
 *	ve_preadv().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_readv_preadv(int syscall_num, char *syscall_name,
					veos_handle *handle)
{
	ssize_t retval = -1;
	struct iovec *vh_iov = NULL;
	int iovcnt = 0, i = 0;
	int err_flag = -1;
	int cnt = 0;
	uint64_t args[4] = {0};
	uint64_t *ve_buff_addr = NULL;
	sigset_t signal_mask = { {0} };
	size_t send_bytes = -1;
	int dio_flag = -1;

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall "
				"arguments,(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive readv()iovcnt from VE memory */
	iovcnt = args[2];
	/* Validate the input arguments */
	if ((UIO_MAXIOV < iovcnt) ||
		(iovcnt <= 0) ||
		(NULL == (void *)args[1])) {
		if (NULL == (void *)args[1])
			retval = -EFAULT;
		else if(0 == iovcnt)
			retval = 0;
		else
			retval = -EINVAL;
		goto hndl_return;
	}
	/* Create local memory to store readv data */
	vh_iov = (struct iovec *)calloc(iovcnt, sizeof(struct iovec));
	if (NULL == vh_iov) {
		retval = -EIO;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("vh_iov : calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	/* Receive environment for readv from VE */
	if (0 > ve_recv_data(handle, args[1],
				(iovcnt*sizeof(struct iovec)),
				(uint64_t *)(vh_iov))) {
		PSEUDO_ERROR("Failed(%s) to receive %s arguments from ve",
				strerror(errno), SYSCALL_NAME);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Validate the buffer and length */
	retval = 0;
	for (i = 0; i < iovcnt; i++) {
		if (vh_iov[0].iov_base == NULL)
			retval = -EFAULT;
		else if ((ssize_t)vh_iov[i].iov_len < 0)
			retval = -EINVAL;
		else if((ssize_t)vh_iov[i].iov_len > MAX_RW_COUNT) {
                        vh_iov[i].iov_len = MAX_RW_COUNT;
                }
		else
			;
		if (retval != 0)
			goto hndl_return1;
	}

	/* create buffer to store VE buffer addresses */
	ve_buff_addr = calloc(iovcnt, sizeof(uint64_t));
	if (NULL == ve_buff_addr) {
		retval = -EIO;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("ve_buff_addr : calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	}

	dio_flag = fcntl(args[0], F_GETFL, 0);
	if (dio_flag & O_DIRECT)
		dio_flag = 1;
	else
		dio_flag = 0;

	/* Allocate memory for VH buffers */
	for (i = 0; i < iovcnt; i++) {
		ve_buff_addr[i] = (uint64_t)vh_iov[i].iov_base;
		vh_iov[i].iov_base = NULL;
		if (dio_flag) {
			vh_iov[i].iov_base = (char *)valloc(vh_iov[i].iov_len);
		} else {
			vh_iov[i].iov_base = (void *)calloc
				((vh_iov[i].iov_len), sizeof(char));
		}

		if (NULL == (void *) vh_iov[i].iov_base) {
			retval = -EIO;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("Error(%s) for calloc in "
					"buffer %d", strerror(errno), i);
			err_flag = 1;
			goto hndl_return2;
		}
		cnt++;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* All things is ready now its time to call linux VH system call */
	retval = syscall(syscall_num, args[0], vh_iov, iovcnt, args[3]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		err_flag = 1;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			* set retval to -VE_ERESTARTSYS. VE process
			* will restart the syscall if SA_RESTART
			* flag is provided for signal
			* */
			retval = -VE_ERESTARTSYS;

		goto hndl_return2;
	} else {
		PSEUDO_DEBUG("syscall %s readv %lu bytes",
				SYSCALL_NAME, retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return2:
	send_bytes = (size_t)retval;
	for (i = 0; i < cnt; i++) {
		if(!send_bytes)
			break;
		if (NULL != (void *)vh_iov[i].iov_base) {
			if (err_flag != 1) {
				if (send_bytes >= vh_iov[i].iov_len) {
					send_bytes = send_bytes - vh_iov[i].iov_len;
				} else {
					vh_iov[i].iov_len = send_bytes;
					send_bytes = 0;
				}
				if (ve_buff_addr[i] && vh_iov[i].iov_len) {
					if (0 > ve_send_data(handle,
						(uint64_t)(ve_buff_addr[i]),
						(vh_iov[i].iov_len),
						(uint64_t *)vh_iov[i].iov_base)) {
						PSEUDO_ERROR("Failed to send"
							" data to VE memory");
						PSEUDO_DEBUG("%s Failed(%s) to"
							" send data:"
							" %d", SYSCALL_NAME,
							strerror(errno), i);
						retval = -EFAULT;
						err_flag = 1;
					} else {
						PSEUDO_DEBUG("buffer %d send"
							" to ve", i);
					}
				} else {
					PSEUDO_DEBUG("vh_iov[%d].iov_len = %zu",
							i, vh_iov[i].iov_len);
				}

			}
		}
	}
	free(ve_buff_addr);
hndl_return1:
	for (i = 0; i < cnt; i++) {
		if (vh_iov[i].iov_base != NULL)
			free(vh_iov[i].iov_base);
	}
	free(vh_iov);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles readv() system call for VE.
 *
 *	ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
 *
 *	This function uses generic handler(ve_hndl_readv_preadv) as readv()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_readv(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_readv_preadv(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles writev() system call for VE.
 *
 *	ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
 *
 *	This function uses generic handler(ve_hndl_writev_pwritev) as writev()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_writev(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_writev_pwritev(syscall_num, syscall_name, handle);
}

/**
 * @brief Generic handler for read() and pread64() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS read()/pread64() system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_read(),
 *	ve_pread64().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_read_pread64(int syscall_num, char *syscall_name,
					veos_handle *handle)
{
	ret_t retval = -1;
	char *read_buff = NULL;
	size_t send_size = 0;
	uint64_t args[4] = {0};
	sigset_t signal_mask = { {0} };
	int flags = 0;

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (syscall_num == SYS_pread64) {
		if ((loff_t)args[3] < 0) {
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	/* receive read() buffer size from VE memory */
	send_size = args[2];
	if ((ssize_t) send_size < 0) {
		retval = -EFAULT;
		goto hndl_return;
	}

	if (send_size > MAX_RW_COUNT)
		send_size = MAX_RW_COUNT;

	/* allocate memory to store read data */
	if (args[1]) {
		flags = fcntl(args[0],F_GETFL,0);
		if (flags & O_DIRECT) {
			/* Under Linux 2.6, alignment to 512-byte boundaries suffices
			 * e.g -
			 * 1 --> posix_memalign(&write_buff,512,send_size);
			 * 2 --> memalign(sysconf(_SC_PAGESIZE),send_size);
			 */
			read_buff = (char *)valloc(send_size);
		} else {
			read_buff = (char *)calloc(send_size, sizeof(char));
		}

		if (NULL == read_buff) {
			retval = -EIO;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("read_buff : calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* check whether VE address is valid or invalid */
		retval = ve_is_valid_address(handle, args[1]);
		if (retval < 0) {
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			args[1] ? (char *)read_buff : NULL, send_size, args[3]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));

		/* Post-processing of syscall started, blocking signals */
		PSEUDO_DEBUG("Blocked signals for post-processing");

		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall = %s read_buf= %s\n read %lu bytes",
				SYSCALL_NAME, (char *)read_buff, retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");


	/* send the read buffer */
	if (args[1] && retval) {
		if (0 > ve_send_data(handle, args[1],
					retval, (uint64_t *)read_buff)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

hndl_return1:
	free(read_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles read() system call for VE.
 *
 *	ssize_t read(int fd, void *buf, size_t count);
 *
 *	This function uses generic handler "ve_hndl_read_pread64" as read()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_read(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_read_pread64(syscall_num, syscall_name, handle);
}

/**
* @brief Handles open() system call functionality for VE.
*
*      int open(const char *pathname, int flags);
*      int open(const char *pathname, int flags, mode_t mode);
*
*      This function fetches Path from VEMVA using VE driver interface
*      and offloads the functionality to VH OS system call.
*
* @param[in] syscall_num  System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_open(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	uint64_t args[3] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
				"arguments, (%s) returned %d",
					SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument */
		path_buff = (char *)calloc(PATH_MAX, sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("patch_buff : calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/*receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0], (char *)path_buff,
				 PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("failed to receive string "
				"from ve, (%s) returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
	/* call VH system call */
	retval = syscall(syscall_num,
			path_buff,
			args[1],
			args[2]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles close() system call for VE.
*
*	int close(int fd);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS close() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_close(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[1] = {0};
	ret_t retval = -1;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, (%s) returned %d\n",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles stat() system call functionality for VE.
*
*	int stat(const char *path, struct stat *buf);
*
*	This function uses generic handler "ve_hndl_p_char_p_stat_buf" as stat()
*	functionality for ve has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_stat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_stat_buf(syscall_num, syscall_name, handle);
}

/**
* @brief Handles fstat() system call for VE.
*
*	int fstat(int fd, struct stat *buf);
*
*	This function fetches the arguments from VEHVA/VEMVA and then invokes
*	VH OS fstat() system call. "stat" buffer returned from VH OS system call
*	is then copied back to VEMVA using VE driver interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_fstat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct stat stat_buf = {0};
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], &stat_buf);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	if (args[1]) {
		/* send the filled stat buf */
		if (0 > ve_send_data(handle, args[1],
					sizeof(struct stat),
				 (uint64_t *)(&stat_buf))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
		}
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles lstat() system call functionality for VE.
*
*	int lstat(const char *path, struct stat *buf);
*
*	This function uses generic handler "ve_hndl_p_char_p_stat_buf" as
*	lstat() functionality for ve has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_lstat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_stat_buf(syscall_num, syscall_name, handle);
}

/**
* @brief Handles poll() system call for VE.
*
*	int poll(struct pollfd *fds, nfds_t nfds, int timeout);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS poll() system call. The data to
*	be send to VEMVA is done using VE driver interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_poll(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct pollfd *fds = NULL;
	nfds_t nfds = 0;
	uint64_t args[3] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	nfds = args[1];
	if (nfds > RLIMIT_NOFILE || 0 > (int)nfds){
		retval = -EINVAL;
		goto hndl_return;
	}

	fds = (struct pollfd *)calloc(nfds, sizeof(struct pollfd));
	if (NULL == fds) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internal memory"
				" buffer");
		PSEUDO_DEBUG("fds : calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	if (NULL != (void *)args[0]) {
		if (0 > ve_recv_data(handle, args[0],
					(nfds*sizeof(struct pollfd)),
					(uint64_t *)(fds))) {
			PSEUDO_ERROR("Failed(%s) to receive %s argument",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
	PSEUDO_DEBUG("fds[0].fd = %d", fds[0].fd);
	PSEUDO_DEBUG("fds[0].events=%d", fds[0].events);
	PSEUDO_DEBUG("fds[1].fd=%d", fds[1].fd);
	PSEUDO_DEBUG("fds[1].events=%d", fds[1].events);

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, args[0] ? fds : NULL, nfds, args[2]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");


	/* Copy back FD's to VE area */
	if (NULL != (void *)args[0]) {
		if (0 > ve_send_data(handle, args[0],
					sizeof(struct pollfd),
					(uint64_t *)(fds))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[0]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
hndl_return1:
	free(fds);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the lseek() system call functionality for VE.
 *
 *	off_t lseek(int fd, off_t offset, int whence);
 *
 *	This function uses generic handler "ve_generic_offload" as lseek()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_lseek(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles ioctl() system call functionality for VE.
 *
 *	int ioctl(int d, int request, ...);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *	Only Tty ioctl commands are currently supported.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 * */
ret_t ve_ioctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	unsigned int bytes = 0;
	char *buff = NULL;
	int argp = 0;
	struct termios termios_buff = {0};
	struct termio termio_buff = {0};
	struct winsize winsize_buff = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	PSEUDO_DEBUG("tty ioctl command is: %lu", args[1]);

	/* handling added for tty_ioctl commands */
	switch (args[1]) {
	/* following commands take pointer to struct termios
	 * as third argument and the structure is to be copied
	 * back to VE area
	 * */
	case TCGETS:
	case TIOCGLCKTRMIOS:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&termios_buff);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");


		/* send the filled termios_buf */
		if (NULL != (void *)args[2]) {
			if (0 > ve_send_data(handle, args[2],
						sizeof(struct termios),
						(uint64_t *)(&termios_buff))) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following command takes pointer to struct termio
		 * as third argument and the structure is to be copied
		 * back to VE area
		 * */
	case TCGETA:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &termio_buff : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");

		/* send the filled termio_buf */
		if (NULL != (void *)args[2]) {
			if (0 > ve_send_data(handle, args[2],
						sizeof(struct termio),
						(uint64_t *)(&termio_buff))) {
				PSEUDO_ERROR("Failed to send data to VE"
					" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following command takes pointer to struct winsize
		 * as third argument and the structure is to be copied
		 * back to VE area
		 * */
	case TIOCGWINSZ:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &winsize_buff : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		PSEUDO_DEBUG("Blocked signals for post-processing");

		/* send the filled winsize_buf */
		if (NULL != (void *)args[2]) {
			if (0 > ve_send_data(handle, args[2],
						sizeof(struct winsize),
						(uint64_t *)(&winsize_buff))) {
				PSEUDO_ERROR("Failed to send data to VE"
					" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;
		/* Following command takes pointer to an integer
		 * variable and pass to kernel.
		 */
	case FIONBIO:
		if (args[2]) {
			if (0 > ve_recv_data(handle, args[2],
						sizeof(int), &argp)) {
				PSEUDO_ERROR("Failed(%s) to receive %s"
						" argument from ve",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &argp : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		PSEUDO_DEBUG("Blocked signals for post-processing");

		break;
		/* following commands take pointer to struct termios
		 * as third argument and structure pointer is not
		 * copied to VE area
		 * */
	case TCSETS:
	case TCSETSW:
	case TCSETSF:
	case TIOCSLCKTRMIOS:
		/* receive struct termios data buffer from VE */
		if (args[2]) {
			if (0 > ve_recv_data(handle, args[2],
					sizeof(struct termios),
						&termios_buff)) {
				PSEUDO_ERROR("Failed(%s) to receive %s"
						" argument from ve",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &termios_buff : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");


		break;

		/* following commands take pointer to struct termio
		 * as third argument and structure pointer is
		 * not copied to VE area
		 * */
	case TCSETAW:
	case TCSETAF:
	case TCSETA:
		/* Receive struct termio data buffer from VE */
		if (args[2]) {
			if (0 > ve_recv_data(handle, args[2],
					sizeof(struct termio), &termio_buff)) {
				PSEUDO_ERROR("Failed(%s) to receive %s"
						" argument from ve",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &termio_buff : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");
		break;

		/* following commands take pointer to struct winsize as
		 * third argument and structure pointer is not copied
		 * to VE area
		 * */
	case TIOCSWINSZ:
		/* Receive struct winsize data buffer from VE */
		if (args[2]) {
			if (0 > ve_recv_data(handle, args[2],
					sizeof(struct winsize),
					&winsize_buff)) {
				PSEUDO_ERROR("Failed(%s) to receive %s"
						" argument from ve",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &winsize_buff : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");
		break;

		/* following commands take integer pointer as
		 * third argument and it is to be copied back
		 * to VE area
		 * */
	case FIONREAD:		/* or TIOCINQ */
	case TIOCOUTQ:
	case TIOCGETD:
	case TIOCMGET:
	case TIOCGSID:
	case TIOCGSOFTCAR:
	case TIOCGPGRP:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &bytes : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");


		/* Copy back integer value to VE area */
		if (NULL != (void *)args[2]) {
			if (0 > ve_send_data(handle, args[2],
						sizeof(unsigned int),
						(unsigned int *)(&bytes))) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following commands take integer pointer as
		 * third argument and integer pointer is not copied
		 * to VE area
		 * */
	case TIOCSETD:
	case TIOCPKT:
	case TIOCMSET:
	case TIOCMBIC:
	case TIOCMBIS:
	case TIOCSSOFTCAR:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				args[2] ? &bytes : NULL);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocked signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");
		break;

		/* following commands take integer as third argument */
	case TCSBRK:
	case TCSBRKP:
	case TCXONC:
	case TCFLSH:
	case TIOCSCTTY:

		/* following commands take void as third argument */
	case TIOCSBRK:
	case TIOCCBRK:
	case TIOCCONS:
	case TIOCNOTTY:
	case TIOCEXCL:
	case TIOCNXCL:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				args[2]);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		/* write return value */
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			PSEUDO_DEBUG("Blocking signals for post-processing");
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocking signals for post-processing");
		break;

		/* following command take character pointer as third argument */
	case TIOCSTI:
		/* allocate memory to receive contents of
		 * third argument */
		if (args[2]) {
			buff = (char *)calloc(PATH_MAX, sizeof(char));
			if (NULL == buff) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("buff : calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return;
			}
			/*receive contents of third argument */
			retval = ve_recv_string(handle, args[2],
					(char *)buff, PATH_MAX);
			if (retval < 0) {
				PSEUDO_ERROR("failed to receive string "
						"(%s) returned %d",
						SYSCALL_NAME, (int)retval);
				retval = -EFAULT;
				goto hndl_buff_free;
			}
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished"
				", unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				buff);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			if (EINTR == -retval)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			PSEUDO_DEBUG("Blocked signals for post-processing");
			goto hndl_buff_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_buff_free:
		free(buff);
		break;

	default:
		PSEUDO_INFO("ONLY tty_ioctl ARE SUPPORTED");
		retval = -ENOTSUP;
		goto hndl_return;
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles pread64() system call for VE.
*
*	ssize_t pread64(int fd, void *buf, size_t count, off64_t offset);
*
*	This function uses generic handler "ve_hndl_read_pread64" as pread64()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_pread64(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_read_pread64(syscall_num, syscall_name, handle);
}

/**
* @brief Handles pwrite64() system call for VE.
*
*	ssize_t pwrite64(int fd, void *buf, size_t count, off64_t offset);
*
*	This function uses generic handler "ve_hndl_write_pwrite64" as
*	pwrite64()functionality for ve has common pre and
*	post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_pwrite64(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_write_pwrite64(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles access() system call functionality for VE.
 *
 *	int access(const char *pathname, int mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as access()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_access(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pipe() and pipe2() system calls for VE.
 *
 *	int pipe(int pipefd[2]);
 *	int pipe2(int pipefd[2], int flags);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	pipe/pipe2()system call.
 *	This function sends the data to be written to VEMVA using VE driver
 *	interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_pipe(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	int fd[2] = {0};
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall arguments,"
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0] ? fd : NULL, args[1]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	if (args[0]) {
		if (0 > ve_send_data(handle, args[0],
					(sizeof(int) * 2), (uint64_t *)fd)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[0]", SYSCALL_NAME,
						strerror(errno));
			goto hndl_return;
		}
	}
	PSEUDO_DEBUG("syscall %s returned %d",
			SYSCALL_NAME, (int)retval);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles select() system call functionality for VE.
*
*	int select(int nfds, fd_set *readfds, fd_set *writefds,
*		fd_set *exceptfds, struct timeval *timeout);
*
*	This function fetches the arguments from VEHVA/VEMVA and then invokes
*	the VH OS select() system call. Updated buffers received from VH OS are
*	are then copied back to VEMVA using VE driver interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_select(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	fd_set rfds = { {0} };
	fd_set wfds = { {0} };
	fd_set excptfds = { {0} };
	struct timeval tv = {0};
	uint64_t args[5] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -ENOMEM;
		goto hndl_return;
	}

	if ((int)args[0] < 0)
	{
		retval = -EINVAL;
		goto hndl_return;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&excptfds);

	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(fd_set), (uint64_t *)(&rfds))) {
			PSEUDO_ERROR("failed to receive data from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[2]) {
		if (0 > ve_recv_data(handle, args[2],
					sizeof(fd_set), (uint64_t *)(&wfds))) {
			PSEUDO_ERROR("failed to receive data from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[3]) {
		if (0 > ve_recv_data(handle, args[3],
					sizeof(fd_set),
					(uint64_t *)(&excptfds))) {
			PSEUDO_ERROR("failed to receive data from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[4]) {
		if (0 > ve_recv_data(handle, args[4],
					sizeof(struct timeval),
					(uint64_t *)(&tv))) {
			PSEUDO_ERROR("failed to receive data from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("syscall arguments (nfds: 0x%lx, rfds: 0x%lx,"
			" wfds: 0x%lx, excptfds: 0x%lx, tv: 0x%lx)",
			args[0], args[1], args[2],
			args[3], args[4]);

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			args[1] ? &rfds : NULL,
			args[2] ? &wfds : NULL,
			args[3] ? &excptfds : NULL,
			args[4] ? &tv : NULL);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	} else if (retval) {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	} else {
		PSEUDO_DEBUG("No ACTIVITY on fd set");
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* Copy back FD's to VE area */
	if (NULL != (void *)args[1]) {
		if (0 > ve_send_data(handle, args[1],
					sizeof(fd_set), (uint64_t *)(&rfds))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[2]) {
		if (0 > ve_send_data(handle, args[2],
					sizeof(fd_set), (uint64_t *)(&wfds))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[3]) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(fd_set),
					(uint64_t *)(&excptfds))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[3]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/**
	 * Linux updates tv. Hence updating it. This is not a POSIX
	 * requirement
	 */
	if (NULL != (void *)args[4]) {
		if (0 > ve_send_data(handle, args[4],
					sizeof(struct timeval),
					(uint64_t *)(&tv))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[4]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles madvise() system call functionality for VE.
 *
 *	int madvise(void *addr, size_t length, int advice);
 *
 *	This function will always return success because paging is
 *	unsupported but ported application may invoke the madvise()
 *	system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_madvise(int syscall_num, char *syscall_name, veos_handle *handle)
{
	/* This function will always return success because paging is
	 * unsupported but ported application may invoke the madvise()
	 * system call
	 */
	PSEUDO_INFO("syscall is unsupported");
	return 0;
}

/**
* @brief Handles system call functionality for dup(), dup2(), dup3() syscall in VE.
*
*	int dup(int oldfd);
*	int dup2(int oldfd, int newfd);
*	int dup3(int oldfd, int newfd, int flags);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS dup(), dup2(), dup3() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_generic_dup(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[3] = {0};
	ret_t retval = -1;
	sigset_t signal_mask = { {0} };
	int num_args = 0;

	PSEUDO_TRACE("Entering");

	switch (syscall_num) {
	case SYS_dup:
		num_args = 1;
		break;
	case SYS_dup2:
		num_args = 2;
		break;
	case SYS_dup3:
		num_args = 3;
		break;
	default:
		retval = -EINVAL;
		goto hndl_return;
	}

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, num_args);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			args[2]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles dup() system call functionality for VE.
 *
 *	int dup(int oldfd);
 *
 *	This function uses "ve_generic_dup" handler as
 *	dup() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_dup(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_dup(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles dup2() system call functionality for VE.
 *
 *	int dup2(int oldfd, int newfd);
 *
 *	This function uses "ve_generic_dup" handler as
 *	dup2() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_dup2(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_dup(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pause() system call functionality for VE.
 *
 *	int pause(void);
 *
 *	This function invokes the VH OS pause() system call as pause()
 *	system call functionality for ve.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_pause(int syscall_num, char *syscall_name, veos_handle *handle)
{
	reg_t retval = -1;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s returned %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;

	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles nanosleep() system call functionality for VE.
 *
 *	int nanosleep(const struct timespec *req, struct timespec *rem);
 *
 *	This function fetches arguments from VEHVA/VEMVA and then invokes the
 *	VH OS nanosleep() system call. Updated buffers received from VH OS are
 *	then copied back to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_nanosleep(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timespec req = {0};
	struct timespec rem = {0};
	uint64_t args[2] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		if (0 > ve_recv_data(handle, args[0],
					sizeof(struct timespec),
					(uint64_t *)(&req))) {
			PSEUDO_ERROR("failed to receive data from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s argument[0]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}

		/* tv_nsec can't have more nanoseconds then a second */
		if ((req.tv_sec < 0) ||
			(req.tv_nsec >= NSEC_PER_SEC)) {
			retval = -EINVAL;
			goto hndl_return;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0] ? &req : NULL,
			args[1] ? &rem : NULL);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		/* If nanosleep is interrupted,
		 * remaining time is written into rem. */
		if (EINTR == -retval) {
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;

			if (args[1]) {
				PSEUDO_DEBUG("rem.tv_sec=%lld rem.tv_nsec=%ld",
						(long long)rem.tv_sec,
						rem.tv_nsec);

				if (0 > ve_send_data(handle, args[1],
							sizeof(struct timespec),
							(uint64_t *)(&rem))) {
					PSEUDO_ERROR("Failed to send data to"
						" VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send "
							"data: args[1]",
							SYSCALL_NAME,
							strerror(errno));
					retval = -EFAULT;
					goto hndl_return;
				}
			}
			goto hndl_return;
		}
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles getitimer() system call functionality for VE.
 *
 *      int getitimer(int which, struct itimerval *curr_value);
 *
 *      This function fetches arguments from VEHVA/VEMVA and then invokes the
 *      VH OS getitimer() system call. Updated buffers received from VH OS are
 *      then copied back to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getitimer(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct itimerval t_val = { {0} };

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments");
		retval = -EFAULT;
		goto hndl_return;
	}

	/* return with EINVAL error value if timer option
	 * ITIMER_VIRTUAL and ITIMER_PROF is given.
	 */
	if (args[0] == ITIMER_VIRTUAL || args[0] == ITIMER_PROF) {
		PSEUDO_INFO("SYSTEM CALL NOT SUPPORTED WITH"
				" SPECIFIED TIMER OPTION");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &t_val : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[1]) {
		if (0 > ve_send_data(handle, args[1],
				sizeof(struct itimerval), &t_val)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned successfully with %d",
			SYSCALL_NAME, (int)retval);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles alarm() system call functionality for VE.
 *
 *      unsigned int alarm(unsigned int seconds);
 *
 *      This function uses generic handler "ve_generic_offload" as
 *      alarm() functionality for ve has common pre and post
 *      processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_alarm(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setitimer() system call functionality for VE.
 *
 *      int setitimer(int which, const struct itimerval *new_value,
 *                           struct itimerval *old_value);
 *
 *      This function fetches arguments from VEHVA/VEMVA and then invokes the
 *      VH OS setitimer() system call. Updated buffers received from VH OS are
 *      then copied back to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setitimer(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct itimerval *vh_new_value = NULL;
	struct itimerval *vh_old_value = NULL;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	switch (args[0]) {

		/* following command takes pointer to struct itimerval
		 * type structure as second and third argument. Third
		 * argument is to be copied back to VE area
		 * */
	case ITIMER_REAL:

		/* Create local memory to store structure data for new_value */
		if (NULL != (void *)args[1]) {
			vh_new_value = (struct itimerval *)
				calloc(1, sizeof(struct itimerval));
			if (NULL == vh_new_value) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("vh_new_value: calloc "
					"%s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return;
			}

			/* receive the itimerval structure data from VE */
			if (0 > ve_recv_data(handle, args[1],
						sizeof(struct itimerval),
						(uint64_t *)(vh_new_value))) {
				PSEUDO_ERROR("failed to receive data from"
						" VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive %s"
					" argument[1] from ve",
					strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_local_free1;
			}
		}

		/* Create local memory to store structure data for old_value */
		if (NULL != (void *)args[2]) {
			vh_old_value = (struct itimerval *)
				calloc(1, sizeof(struct itimerval));
			if (NULL == vh_old_value) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal memory"
						" buffer");
				PSEUDO_DEBUG("vh_old_value: calloc "
					"%s failed %s",
					SYSCALL_NAME, strerror(errno));
				goto hndl_local_free1;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num, args[0],
			vh_new_value, vh_old_value);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_local_free2;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		/* send the filled vh_old_value data */
		if (NULL != (void *)args[2]) {
			if (0 > ve_send_data(handle, args[2],
				sizeof(struct itimerval),
					(uint64_t *)(vh_old_value))) {
				PSEUDO_ERROR("Failed to send data to VE"
					" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[0]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
			}
		}
hndl_local_free2:
		free(vh_old_value);
hndl_local_free1:
		free(vh_new_value);
		break;

	default:
		PSEUDO_ERROR("Invalid flag passed");
		retval = -EINVAL;
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the getpid() system call functionality for VE.
 *
 *	pid_t getpid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getpid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getpid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	PSEUDO_TRACE("Entering");
	retval =  ve_generic_offload(syscall_num, syscall_name, handle);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to get process id");
		fprintf(stderr, "failure in getting pid\n");
		pseudo_abort();
	}
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sendfile() system call functionality for VE.
 *
 *	ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS sendfile() system call.
 *	It returns the return value of system call back to the VEMVA/VEHVA
 *	using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_sendfile(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	off_t offset = 0;

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive content of 3rd argument */
	if (NULL != (void *)args[2]) {
		if (0 > ve_recv_data(handle, args[2],
					sizeof(off_t), &offset)) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" argument[2] from ve",
					strerror(errno), SYSCALL_NAME);
					retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1],
			args[2] ? &offset : NULL, args[3]);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed", SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[2]) {
		if (0 > ve_send_data(handle, args[2], sizeof(off_t),
					&offset)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the socket() system call functionality for VE.
*
*	int socket(int domain, int type, int protocol);
*
*	This function uses generic handler "ve_generic_offload" as socket()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num  System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_socket(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles connect() system call functionality for VE.
*
*	int connect(int sockfd, const struct sockaddr *addr,
*	 socklen_t addrlen)
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS connect() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_connect(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};
	socklen_t addr_len = 0;
	uint64_t args[3] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	addr_len = (socklen_t)args[2];

	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					addr_len,
					(uint64_t *)(&addr))) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" argument[1] from ve",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		} else {
			/* unblock all signals except the one
			 * actualy blocked by VE process
			 * */
			PSEUDO_DEBUG("Pre-processing finished,"
					" unblock signals");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
			/* calling kernel System call on VH side */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr, addr_len);
		}
	} else {
		PSEUDO_ERROR("%s is invoked with sockaddr= NULL",
				SYSCALL_NAME);
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* calling kernel System call on VH side  with sock addr as NULL
		 * Kernel will return an error which is propagated back to VE
		 */
		retval = syscall(syscall_num, args[0], args[1], addr_len);
	}
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles accept() and accept4() system call functionality for VE.
*
*	This generic function receives data and arguments from VEHVA/VEMVA
*	using VE driver interface and then invokes the VH OS accept()/accept4()
*	system call.
*	The updated buffers returned from VH OS are copied back to VEMVA using
*	VE driver interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t do_accept(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;

	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};

	socklen_t addr_len = 0;
	uint64_t args[4] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/*
	 * if sock addr is received as NULL from VE pass NULL as sock addr to
	 * kernel system call. sock addr len is deliberatley passed as NULL
	 * since man page says that if sock addr is NULL ,
	 * sock len should also be NULL
	 * hence no sock len is fetched from VE side and NULL is only passed
	 * even if sock len is NON NULL on VE
	 */

	if (NULL == (void *)args[1]) {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		retval = syscall(syscall_num, args[0], args[1], NULL);
	} else {
		/*sock addr is not NULL */
		if (NULL != (void *)args[2]) {
			/*sock len addr is not NULL fetch data from VE*/
			if (0 > ve_recv_data(handle, args[2],
						sizeof(socklen_t),
						(uint64_t *)(&addr_len))) {
				PSEUDO_ERROR("failed to receive data from"
						" VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive %s"
						" argument[2] from ve",
					strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}

			/* unblock all signals except the one actualy
			 * blocked by VE process
			 * */
			PSEUDO_DEBUG("Pre-processing finished, unblock "
					"signals");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
			/*calling kernel System call on VH side ->
			 * addr is populated by kernel
			 */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr,
					&addr_len, args[3]);
		} else {
			/* unblock all signals except the one actualy
			 * blocked by VE process
			 * */
			PSEUDO_DEBUG("Pre-processing finished, "
				"unblock signals");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

			/* sock addr is non  NULL but sock len addr is
			 * NULL, kernel throws error , propagate to VE
			 */
			retval = syscall(syscall_num, args[0],
					(struct sockaddr *)&addr,
						args[2], args[3]);
		}
	}
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");


	/* send addr received from kernel to VE side
	 * in case sock addr was non NULL on VE
	 */
	if (NULL != (void *)args[1]) {

		if (0 > ve_send_data(handle, args[1],
				addr_len, (uint64_t *)(&addr))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
		 /* send addr_len recvd from kernel to VE side */
		if (NULL != (void *)args[2]) {
			PSEUDO_DEBUG("addr_len received from kernel = %d",
					addr_len);
			if (0 > ve_send_data(handle, args[2],
					sizeof(socklen_t),
					(uint64_t *)(&addr_len))) {
				PSEUDO_ERROR("Failed to send data to VE"
					" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handle accept() system call functionality for VE.
*
*	int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
*
*	This function uses generic handler "do_accept" as accept()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process
*/
ret_t ve_accept(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return do_accept(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles sendto() system call functionality for VE.
 *
 *	ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
 *		const struct sockaddr *dest_addr, socklen_t addrlen);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS sendto() system call.
 *	It returns the return value of system call back to the VEMVA/VEHVA
 *	using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_sendto(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[6] = {0};
	struct sockaddr_storage addr = {0};
	char *send_buff = NULL;
	size_t len = 0;
	socklen_t addr_len = 0;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"%s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	len = args[2];

	if (len > MAX_RW_COUNT)
		len = MAX_RW_COUNT;

	if (args[1] && len) {

		/* allocate memory for content of 2nd argument */
		send_buff = (char *)calloc(len, sizeof(char));
		if (send_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("In sendto(): calloc failed(%s)",
					strerror(errno));
			goto hndl_return;
		}
		if (0 > ve_recv_data(handle, args[1], len, send_buff)) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" argument[1] from ve",
					strerror(errno), SYSCALL_NAME);
					retval = -EFAULT;
			goto hndl_return1;
		}
	}

	addr_len = args[5];
	if (addr_len < 0 || addr_len > sizeof(struct sockaddr_storage)) {
		retval = -EINVAL;
		goto hndl_return1;
	}

	if (args[4] && addr_len) {
		if (0 > ve_recv_data(handle, args[4], addr_len, &addr)) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" argument[4] from ve",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_ERROR("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], send_buff, len,
			args[3], args[4] ? &addr : NULL, args[5]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*Check retval of system call*/
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return1;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return1:
	if (send_buff != NULL) {
		free(send_buff);
		send_buff = NULL;
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles recvfrom() system call functionality for VE.
 *
 *      ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
 *              struct sockaddr *src_addr, socklen_t *addrlen);
 *
 *      This function receives data and arguments from VEMVA/VEHVA using
 *      VE driver interface and invokes VH OS recvfrom() system call.
 *      Buffered data from VH OS copied back to the VE process using VE
 *      driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_recvfrom(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[6] = {0};
	sigset_t signal_mask = { {0} };
	char *data_buff = NULL;
	struct sockaddr_storage addr = {0};
	socklen_t vh_addrlen = 0;
	size_t len = 0;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = EFAULT;
		goto hndl_return;
	}

	len = args[2];

	if (len == 0) {
		retval = 0;
		goto hndl_return;
	}
	else if (len > MAX_RW_COUNT)
		len = MAX_RW_COUNT;

	if (args[1]) {
		/* allocate memory for data from VH OS */
		data_buff = (char *)calloc(len, sizeof(char));
		if (data_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("In recvfrom(): calloc "
					"failed(%s) for args[1]",
					strerror(errno));
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[4])
	{
		/* receive content of 6th argument */
		if (NULL != (void *)args[5]) {
			if (0 > ve_recv_data(handle, args[5], sizeof(socklen_t),
						(uint64_t *)(&vh_addrlen))) {
				PSEUDO_ERROR("failed to receive data from"
						" VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive %s"
						" argument[5] from ve",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return1;
			}
		}
	} else {
		args[5] = (uint64_t)NULL;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], data_buff,
			(size_t)len, args[3],
			args[4] ? (struct sockaddr *)&addr : NULL,
			args[5] ? &vh_addrlen : NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (retval < 0) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return1;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[1]) {
		if (0 > ve_send_data(handle, args[1], len,
					(uint64_t *)(data_buff))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
				" args[1]", SYSCALL_NAME,
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* send address buffered from VH to VEMVA and also
	 * length of the address
	 * */
	if (args[4] && args[5]) {
		if (0 > ve_send_data(handle, args[4], vh_addrlen,
					(uint64_t *)(&addr))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
				" args[4]", SYSCALL_NAME,
					strerror(errno));
			if (retval > 0 && errno == 0) /* Expeced and mapped to Kernel behaviour */
				retval = retval;
			else
				retval = -EFAULT;

			PSEUDO_DEBUG("%s syscall returned with %d",
					SYSCALL_NAME, (int)retval);
			goto hndl_return1;
		}

		if (0 > ve_send_data(handle, args[5], sizeof(socklen_t),
					(uint64_t *)(&vh_addrlen))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
				" args[5]", SYSCALL_NAME,
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return1:
	free(data_buff);
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief handles sendmsg() system call functionality for VE.
 *
 *	ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS sendmsg() system call with this
 *	received data. It returns the return value of system call back to VE
 *	process using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_sendmsg(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	struct msghdr ve_msg = {0};
	socklen_t ve_msg_namelen = 0;
	size_t ctl_len = 0, iov_len = 0;
	int i = 0, temp = 0;
	char *msg_ctl = NULL, *msg_name = NULL;
	struct iovec *ve_iov = NULL, *vh_iov = NULL;
	sigset_t signal_mask = { {0} };

	PSEUDO_DEBUG("%s syscall is called", SYSCALL_NAME);

	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

        /* Validation of input arguments */
        if (NULL == (void *)args[1]) {
                retval = -EFAULT;
                goto hndl_return;
        }

        /* receive contents of 2nd argument */
        if (0 > ve_recv_data(handle, args[1],
				sizeof(struct msghdr), &ve_msg)) {
		PSEUDO_ERROR("failed to receive data from"
				" VE memory");
		PSEUDO_DEBUG("Failed(%s) to receive %s"
				" argument[1] from ve",
				strerror(errno), SYSCALL_NAME);
		retval = -EFAULT;
                goto hndl_return;
        }

        /* Validation of input arguments from args[1] */
	ve_msg_namelen = ve_msg.msg_namelen;
	if ((NULL == (void *)ve_msg.msg_name) ||
			(INT_MAX < ve_msg_namelen) ||
			(ve_msg_namelen <= 0)) {
		if (NULL == (void *)ve_msg.msg_name) {
			ve_msg_namelen = 0;
			msg_name = NULL;
		} else if (ve_msg_namelen > sizeof(struct sockaddr_storage)) {
			ve_msg_namelen = sizeof(struct sockaddr_storage);
		} else {
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	iov_len = ve_msg.msg_iovlen;
	if ((UIO_MAXIOV < iov_len)
			|| (iov_len <= 0)
			|| (NULL == (void *)ve_msg.msg_iov)) {
		if (NULL == (void *)ve_msg.msg_iov) {
			vh_iov = NULL;
			ve_iov = NULL;
		} else if (0 == iov_len) {
			retval = 0;
			goto hndl_return;
		} else {
			retval = -EMSGSIZE;
			goto hndl_return;
		}
	}

	msg_ctl = (char *)ve_msg.msg_control;
	ctl_len = ve_msg.msg_controllen;
	if ((INT_MAX < ctl_len)
			|| (ctl_len <= 0)
			|| (NULL == (void *)ve_msg.msg_control)) {
		if (NULL == (void *)ve_msg.msg_control) {
			msg_ctl = NULL;
		} else if (ctl_len < INT_MAX) {
			if (ctl_len == 0) {
				msg_ctl = (char *)malloc(sizeof(char));
			}
			ctl_len = ctl_len;
		} else {
			retval = -ENOBUFS;
			goto hndl_return;
		}
	}

	/* allocate memory to store messages from VE process */
	ve_iov = (struct iovec *)calloc(iov_len, sizeof(struct iovec));
	vh_iov = (struct iovec *)calloc(iov_len, sizeof(struct iovec));
	if (ve_iov == NULL || vh_iov == NULL) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("In sendmsg(): calloc failed(%s) for iov",
					strerror(errno));
		goto hndl_return;
	}

	if (ve_msg.msg_name) {
		msg_name = (char *)calloc(ve_msg_namelen, sizeof(char));
		if (msg_name == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("In sendmsg(): calloc "
					"failed(%s) for msg_name",
					strerror(errno));
			goto hndl_return;
		}

		if (0 > ve_recv_data(handle, (uint64_t)ve_msg.msg_name,
					ve_msg_namelen, msg_name)) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" structure(msg_name) specific data",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		ve_msg.msg_name = (void *)msg_name;
	}

	if (msg_ctl) {
		/* When msg_control buffer is a valid address but msg_controllen is
		 * ZERO then malloc/calloc & ve_recv_data will be skiped.
		 * Only dummy buffer will be passed to map the kernel behaviour.
		 */
		if (ctl_len) {
			msg_ctl = (char *)calloc(ctl_len, sizeof(char));
			if (msg_ctl == NULL) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("In sendmsg(): calloc failed(%s) for"
						" msg_ctl", strerror(errno));
				goto hndl_return;
			}

			if (0 > ve_recv_data(handle,
						(uint64_t)ve_msg.msg_control,
						ctl_len, msg_ctl)) {
				PSEUDO_ERROR("failed to receive data from"
						" VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive %s"
						" structure(msg_control) data",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		ve_msg.msg_control = msg_ctl;
	}

	/* receive message data from VEMVA */
	if ((void *)ve_msg.msg_iov != NULL) {
		if (0 > ve_recv_data(handle, (uint64_t)ve_msg.msg_iov,
					iov_len * sizeof(struct iovec),
					ve_iov)) {
			PSEUDO_ERROR("failed to receive data from"
					" VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive %s"
					" structure(iovec)",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}

		for (i = 0; i < iov_len; i++) {
			if ((NULL != (void *)ve_iov[i].iov_base) &&
					(0 != ve_iov[i].iov_len)) {

				vh_iov[i].iov_base = (char *)calloc
				(ve_iov[i].iov_len, sizeof(char));
				if (vh_iov[i].iov_base == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
					" internal memory buffer");
					PSEUDO_DEBUG("calloc %s failed",
						SYSCALL_NAME);
					goto hndl_return;
				}
				temp++;

				if (0 > ve_recv_data(handle,
					(uint64_t)ve_iov[i].iov_base,
						ve_iov[i].iov_len,
						vh_iov[i].iov_base)) {
					PSEUDO_ERROR("failed to receive data"
							" from VE memory");
					PSEUDO_DEBUG("Failed(%s) to receive"
						" %s structure(msg_iov)",
						strerror(errno),
						SYSCALL_NAME);
					retval = -EFAULT;
					goto hndl_return;
				}
			}
			vh_iov[i].iov_len = ve_iov[i].iov_len;
		}

		ve_msg.msg_iov = vh_iov;
		ve_msg.msg_iovlen = iov_len;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, args[0], &ve_msg, args[2]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (retval < 0) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

	/* free all the allocated resources */
hndl_return:
	if (msg_ctl != NULL)
		free(msg_ctl);
	if (msg_name != NULL)
		free(msg_name);
	if (vh_iov != NULL)
	{
		for (i = temp; i > 0; i--)
		{
			if (vh_iov[i-1].iov_base != NULL)
				free(vh_iov[i-1].iov_base);
		}
		free(vh_iov);
	}
	if (ve_iov != NULL)
		free(ve_iov);
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief handles recvmsg() system call functionality for VE.
 *
 * ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
 *
 *      This function fetches arguments from VE using ve driver
 *      interface.Fetch data for output pointer elements and allocate
 *      its own buffers to accommodate data from VH kernel then send
 *      this data to VE process.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_recvmsg(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	size_t msg_len = 0;
	size_t iov_len = 0;
	size_t ctl_len = 0;
	char *msg_name = NULL;
	char *msg_control = NULL;
	struct iovec *ve_iov = NULL, *vh_iov = NULL;
	struct msghdr ve_hdr = {0}, vh_hdr = {0};
	sigset_t signal_mask = { {0} };
	int i = 0;

	PSEUDO_TRACE("Entering");
        /* get system call arguments */
        retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
        if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall "
			"arguments,%s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Validation of input arguments */
	if (NULL == (void *)args[1]) {
		retval = -EFAULT;
		goto hndl_return;
	}

        /* receive contents of 2nd argument */
        if (0 > ve_recv_data(handle, args[1],
				sizeof(struct msghdr), &ve_hdr)) {
		PSEUDO_ERROR("failed to receive data"
				" from VE memory");
		PSEUDO_DEBUG("Failed(%s) to receive"
				" %s structure(msghdr)",
				strerror(errno), SYSCALL_NAME);
                retval = -EFAULT;
                goto hndl_return;
        }

	/* Validation of input arguments from args[1] */
	msg_len = ve_hdr.msg_namelen;
	if ((NULL == (void *)ve_hdr.msg_name) ||
			(INT_MAX < msg_len) ||
			(msg_len <= 0)) {
		if (NULL == (void *)ve_hdr.msg_name) {
			msg_len = 0;
			msg_name = NULL;
		} else if (msg_len > sizeof(struct sockaddr_storage)) {
			msg_len = sizeof(struct sockaddr_storage);
		} else {
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	iov_len = ve_hdr.msg_iovlen;
	if ((UIO_MAXIOV < iov_len)
			|| (iov_len <= 0)
			|| (NULL == (void *)ve_hdr.msg_iov)) {
		if (NULL == (void *)ve_hdr.msg_iov) {
			vh_iov = NULL;
			ve_iov = NULL;
		} else if (0 == iov_len) {
			retval = 0;
			goto hndl_return;
		} else {
			retval = -EMSGSIZE;
			goto hndl_return;
		}
	}

	ctl_len = ve_hdr.msg_controllen;
	if ((INT_MAX < ctl_len)
			|| (ctl_len <= 0)
			|| (NULL == (void *)ve_hdr.msg_control)) {
		if (NULL == (void *)ve_hdr.msg_control) {
			msg_control = NULL;
		} else if (NULL != (void *)ve_hdr.msg_control) {
			msg_control = (char *)calloc(ctl_len, sizeof(char));
			if (NULL == msg_control) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("calloc failed(%s) for"
						"msg_control",
						strerror(errno));
				goto hndl_return;
			}
		} else {
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	/* allocate memory for msg_name option in msg_hdr
	 * to get output from kernel.
	 */
	if (ve_hdr.msg_name) {
		msg_name = (char *)calloc(msg_len, sizeof(char));
		if (msg_name == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("calloc failed(%s) for msg_name",
					strerror(errno));
			goto hndl_return;
		}
	}

	/* allocate memory to bufferes for storing data from VH OS */
        if (ve_hdr.msg_iov) {
                ve_iov = (struct iovec *)calloc(iov_len, sizeof(struct iovec));
                vh_iov = (struct iovec *)calloc(iov_len, sizeof(struct iovec));
		if (ve_iov == NULL || vh_iov == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("calloc failed(%s) for iov",
					strerror(errno));
			goto hndl_return;
		}
		/* receive addresses of VE side buffers
		 * which will later fill up by messages
		 */
		if (0 > ve_recv_data(handle, (uint64_t)ve_hdr.msg_iov,
					iov_len * sizeof(struct iovec),
					(void *)ve_iov)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s address of buffers",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		/* Validate the the buffer and length */
		/* Asume buffer and respective lengths are ok.*/
		retval = 0;
		for (i = 0; i < iov_len; i++) {
			if (ve_iov[0].iov_base == NULL)
				retval = -EFAULT;
			else if ((ssize_t)ve_iov[i].iov_len < 0)
				retval = -EINVAL;
			else
				;
			if (retval != 0)
				goto hndl_return;
		}

		/* allocate memory for buffers to store message data */
		for (i = 0; i < iov_len; i++) {
			if (ve_iov[i].iov_base && ve_iov[i].iov_len) {
				vh_iov[i].iov_base = (char *)calloc
					(ve_iov[i].iov_len, sizeof(char));
				if (vh_iov[i].iov_base == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						" internal memory buffer");
					PSEUDO_DEBUG("calloc failed(%s) to"
						" receive vh_iov[%d].iov_base",
							strerror(errno), i);
					goto hndl_return;
				}
				vh_iov[i].iov_len = ve_iov[i].iov_len;
			}
		}
	}

	/* prepare a struct msghdr to send it to VH kernel.*/
        vh_hdr.msg_name = msg_name;
        vh_hdr.msg_namelen = msg_len;
        vh_hdr.msg_iov = vh_iov;
        vh_hdr.msg_iovlen = iov_len;
        vh_hdr.msg_control = msg_control;
        vh_hdr.msg_controllen = ctl_len;

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call to VH kernel */
	retval = syscall(syscall_num, args[0], &vh_hdr, args[2]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (retval < 0) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* if msg_name member of struct msghdr is
	 * not equal to NULL then send msg_name data
	 * to VE process.
	 */
	if (ve_hdr.msg_name) {
		if (0 > ve_send_data(handle, (uint64_t)ve_hdr.msg_name,
					msg_len, (void *)msg_name)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
				" msg_name", SYSCALL_NAME,
					strerror(errno));
			/*
			 * Beacause msg_name in msghdr struct is an
			 * optional, kernel does not return any
			 * error code if it is given an invalid address.
			 * So to map this functionality into pseudo
			 * side there is not return value is being set.
			 */
		}
	}

	/* if msg_control member is not equal to NULL
	 * then send its data to VE.
	 */
	if (msg_control) {
		if (0 == ve_is_valid_address(handle,
			(uint64_t)ve_hdr.msg_control)) {
			if (0 > ve_send_data(handle,
						(uint64_t)ve_hdr.msg_control,
					ctl_len, (void *)msg_control)) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" msg_control", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
	}

        /* Send message to VEMVA */
	if (ve_hdr.msg_iov) {
		for (i = 0; i < iov_len; i++) {
			if (ve_iov[i].iov_base) {
				if (0 > ve_send_data(handle,
					(uint64_t)ve_iov[i].iov_base,
					vh_iov[i].iov_len,
					vh_iov[i].iov_base)) {
					PSEUDO_ERROR("Failed to send data"
						" to VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send"
						" data: %d", SYSCALL_NAME,
						strerror(errno), i);
					retval = -EFAULT;
					goto hndl_return;
				}
			}
		}
	}

	ve_hdr.msg_flags = vh_hdr.msg_flags;
	ve_hdr.msg_controllen = vh_hdr.msg_controllen;
	if (0 > ve_send_data(handle, (uint64_t)args[1],
				sizeof(struct msghdr), &ve_hdr)) {
		PSEUDO_ERROR("Failed to send data to VE memory");
		PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" ve_hdr", SYSCALL_NAME,
						strerror(errno));
		retval = -EFAULT;
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

        /* clean up all the acquired memory resources */
hndl_return:
	if (msg_name != NULL)
		free(msg_name);
	if (msg_control != NULL)
		free(msg_control);
	if (NULL != (void *)vh_iov) {
		for (i = 0; i < iov_len; i++) {
			if (vh_iov[i].iov_base != NULL)
				free(vh_iov[i].iov_base);
		}
		free(vh_iov);
	}
	if (ve_iov != NULL)
		free(ve_iov);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles shutdown() system call for VE.
 *
 *      int shutdown(int sockfd, int how);
 *
 *      This function uses generic handler "ve_generic_offload" as shutdown()
 *      functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_shutdown(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles bind() system call for VE.
*
*	int bind(int sockfd, const struct sockaddr *addr,
*		socklen_t addrlen);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS bind() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process
*/
ret_t ve_bind(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;

	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};

	socklen_t addr_len = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	addr_len = (socklen_t)args[2];

	if ((int)addr_len < 0 || (int)addr_len > sizeof(struct sockaddr_storage))
		return -EINVAL;

	if (NULL != (void *)args[1] && addr_len) {
		if (0 > ve_recv_data(handle, args[1],
					addr_len,
					(uint64_t *)(&addr))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		} else {
		       /*calling kernel System call on VH side */
			retval = syscall(syscall_num, args[0],
				(struct sockaddr *)&addr, addr_len);
		}

	} else {
		PSEUDO_ERROR("%s is invoked with sockaddr= NULL",
				SYSCALL_NAME);
		/*calling kernel System call on VH side  with sock addr as NULL
		 * Kernel will return an error which is propagated back to VE
		 */
		retval = syscall(syscall_num, args[0], args[1], addr_len);
	}

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief  Handles listen() system call functionality for VE.
*
*	int listen(int sockfd, int backlog);
*
*	This function uses generic handler "ve_generic_offload" as listen()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_listen(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief handles both getsockname() and getpeername() system calls
* functionality for VE.
*
*	This function receives the data and arguments from VEMVA/VEHVA and
*	affloads the functionality to VH OS getsockname()/getpeername()system
*	call. After receiving data from VH OS call copies the data to VEMVA
*	using VE driver interface.
*
* @param[in] syscall_num: System call number
* @param[in] syscall_name: System call name
* @param[in] handle: Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_getsockpeer_name(int syscall_num, char *syscall_name, veos_handle *handle)
{

	uint64_t args[3] = {0};
	struct sockaddr_storage addr = {0};
	ret_t retval = -1;
	socklen_t *len = NULL;
	int user_len = 0;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[2]) {
		len = (socklen_t *)calloc(1, sizeof(socklen_t));
		if (len == NULL) {
			retval = -ENOBUFS;
			PSEUDO_ERROR("Failed to create internal memory buffer");
			PSEUDO_DEBUG("len: calloc failed(%s) for socklen",
					strerror(errno));
			goto hndl_return;
		}
		if (0 > ve_recv_data(handle, args[2],
					sizeof(socklen_t),
					len)) {
			retval = -EFAULT;
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}

		/* Local storage of user buffer length to be used while sending
		 * data buffered from kernel to VE process. (Refer man page getsockname(2)).
		 */
		user_len = (int)*len;
	}

	/* call VH system call */
	if ((void *)args[1] != NULL) {
		retval = syscall(syscall_num, args[0],
				(struct sockaddr *)&addr, len);
	} else {
		retval = syscall(syscall_num, args[0], args[1], len);
	}

	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	if (args[1]) {
		/* send buffered data of addr to VEHVA/VEMVA */
		if (0 > ve_send_data(handle, args[1],
				user_len, &addr)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* send sock length */
		if (0 > ve_send_data(handle, args[2],
					sizeof(socklen_t),
					len)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[2]", SYSCALL_NAME,
						strerror(errno));
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);
hndl_return:
	if (len != NULL)
		free(len);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handle getsockname() system call functionality for VE.
*
*	int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
*
*	This function uses generic handler "ve_getsockpeer_name" as
*	getsockname() functionality for ve has common pre and post
*	processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_getsockname(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_getsockpeer_name(syscall_num, syscall_name, handle);
}


/**
* @brief Handle getpeername() systemca call fiuncitonality for VE.
*
*	int getpeername(int sockfd, struct sockaddr *addr, socklen_t
*	       *addrlen);
*
*	This function uses generic handler "ve_getsockpeer_name" as
*	getpeername() functionality for ve has common pre and post
*	processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_getpeername(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_getsockpeer_name(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles socketpair() system call for VE.
 *
 *      int socketpair(int domain, int type, int protocol, int sv[2]);
 *
 *      This function fetches the arguments from VEHVA/VEMVA using VE driver
 *      interface and then invokes the VH OS socketpair() system call. The
 *      data to be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_socketpair(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	int *vh_sv = NULL;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall arguments,(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Create local memory to store data */
	if (NULL != (void *)args[3]) {
		vh_sv = (int *)calloc(2, sizeof(int));
		if (NULL == vh_sv) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("vh_sv: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1], args[2], vh_sv);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	/* send the received buffer */
	if (NULL != (void *)args[3]) {
		if (0 > ve_send_data(handle, args[3],
					(sizeof(int) * 2), (uint64_t *)vh_sv)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[3]", SYSCALL_NAME,
						strerror(errno));

		}
	}

hndl_return1:
	free(vh_sv);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles setsockopt() system call for VE.
 *
 *      int setsockopt(int sockfd, int level, int optname,
 *                      const void *optval, socklen_t optlen);
 *
 *      This function fetches the arguments from VEHVA/VEMVA using VE driver
 *      interface and then invokes VH OS setsockopt() system call. The data to
 *      be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE prcess
 */
ret_t ve_setsockopt(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	void *vh_optval = NULL;
	socklen_t vh_optlen = 0;
	uint64_t args[5] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %lu",
				SYSCALL_NAME, retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* get size of the buffer from args[4] */
	vh_optlen = (socklen_t)args[4];

	if(0 >= (int)vh_optlen){
                retval = -EINVAL;
                goto hndl_return;
        }

	PSEUDO_DEBUG("VE buffer size : %d", vh_optlen);

	/*if args[3] is not NULL*/
	if (NULL != (void *)args[3]) {
		/* allocate local memory buffer to store optval argument data */
		vh_optval = (void *)calloc(vh_optlen, sizeof(char));
		if (NULL == vh_optval) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("vh_optval: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* receive optval from VE memory */
		if (0 > ve_recv_data(handle, args[3],
					(vh_optlen * sizeof(char)),
					(uint64_t *)(vh_optval))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			args[2],
			vh_optval,
			vh_optlen);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	/* cleaning local storage */
hndl_return1:
	free(vh_optval);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief handles getsockopt() system call functionality for VE.
*
*	int getsockopt(int sockfd, int level, int optname,
*	                      void *optval, socklen_t *optlen);
*
*	This function receives data and arguments from VEHVA/VEMVA and offloads
*	the sunctionality to VH OS getsockopt() system call. After receiving
*	data from VH OS call copies the data to VEMVA using VE driver interface.
*	It returns the return value of system call back to VE process using
*	"return_system_system call" interface.
*
* @param[in] syscall_num: System call number
* @param[in] syscall_name: System call name
* @param[in] handle: Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_getsockopt(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};
	char *buff = NULL;
	size_t len = 0;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval =  vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		retval = -EFAULT;
		PSEUDO_ERROR("vedl_get_syscall_args is failed. %s returned %d",
				SYSCALL_NAME, (int)retval);
		goto hndl_return;
	}

	if (args[4]) {
		/* receive length of data */
		if (0 > ve_recv_data(handle, args[4], sizeof(int), &len)) {
			retval = -EFAULT;
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}

		if(0 > (int)len){
			retval = -EINVAL;
			goto hndl_return;
		}

		if (args[3]) {
			buff = (char *)calloc(len, sizeof(char));
			if (buff == NULL) {
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("buff: calloc %s failed",
							SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1], args[2],
						buff, &len);
	} else {
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1], args[2],
						buff, args[4]);
	}

	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[3] && len) {
		/* send data to VE process */
		if (0 > ve_send_data(handle, args[3], len, buff)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[3]", SYSCALL_NAME,
						strerror(errno));
			goto hndl_return;
		}
	}

	if (args[4]) {
		/* send length of data */
		if (0 > ve_send_data(handle, args[4], sizeof(int), &len)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[4]", SYSCALL_NAME,
						strerror(errno));
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
					SYSCALL_NAME, (int)retval);

hndl_return:
	if (buff != NULL)
		free(buff);
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles uname() system call functionality for VE.
*
*	int uname(struct utsname *buf);
*
*	This function fetches arguments from VEHVA/VEMVA and then invokes the
*	VH OS uname() system call. Updated buffers received from VHOS are
*	then copied back to VEMVA using VE driver interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_uname(int syscall_num, char *syscall_name, veos_handle *handle)
{

	ret_t retval = -1;
	struct utsname *uname_buf = NULL;
	uint64_t args[1] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Create local memory to store structure data */
	if (NULL != (void *)args[0]) {
		uname_buf = (struct utsname *)calloc(1, sizeof(struct utsname));
		if (NULL == uname_buf) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("uname_buf:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, uname_buf);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	/* send the filled utsname */
	if (NULL != (void *)args[0]) {
		/*populating statically value of machin to VE*/
		strncpy(uname_buf->machine, "VE", sizeof(uname_buf->machine));

		if (0 > ve_send_data(handle, args[0],
			sizeof(struct utsname), (uint64_t *)(uname_buf))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data:"
					" args[0]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
		}
	}

hndl_return1:
	free(uname_buf);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles semget() system call functionality for VE.
*
* int semget(key_t key, int nsems, int semflg);
*
*	This function uses generic handler "ve_generic_offload" as semget()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_semget(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Generic handler for semop() and semtimedop() system call for VE.
*
*	This function receives data and arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS semop()/semtimedop() system
*	call.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_generic_semop(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[4] = {0};
	ret_t retval = -1;
	char *sbuf = NULL;
	FILE *file = NULL;
	struct timespec tval = {0};
	sigset_t signal_mask = { {0} };
	int semmsl = 0;
	int semmns = 0;
	int semmni = 0;
	int semopm = 0;

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (syscall_num == SYS_semop)
		args[3] = '\0';

	if (args[1] && args[2]) {

		/* Fetching max value of semopm supported by kernel */
		if ((file = fopen(PROC_SEM_PATH, "r")) != NULL) {
			if (fscanf(file, "%d %d %d %d", &semmsl, &semmns,
						&semopm, &semmni) == 4) {
				PSEUDO_INFO("Fetching from proc fs success"
					" semopm = %d", semopm);
				if (args[2] > semopm) {
					retval = -E2BIG;
					fclose(file);
					goto hndl_return;
				}
			}
			fclose(file);
		}

		sbuf = (char *)calloc(args[2], sizeof(struct sembuf));
		if (sbuf == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
				" buffer");
			PSEUDO_DEBUG("sbuf:calloc %s failed",
					SYSCALL_NAME);
			goto hndl_return;
		}

		/* receive data from VEMVA/VEHVA */
		if (0 > ve_recv_data(handle, args[1],
					args[2] * sizeof(struct sembuf),
					sbuf)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[3]) {
		if (0 > ve_recv_data(handle, args[3],
					sizeof(struct timespec),
					&tval)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num, args[0], sbuf, args[2], &tval);
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num, args[0], sbuf, args[2], args[3]);
	}
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 */
			retval = -VE_ENORESTART;

		goto hndl_return;
	} else {
		PSEUDO_DEBUG("%s system call returned",
				SYSCALL_NAME);

	}
	PSEUDO_DEBUG("Blocked signals for post-processing");
hndl_return:
	if (sbuf != NULL)
		free(sbuf);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}


/**
* @brief Handles semop() system call functionality for VE.
*
*	int semop(int semid, struct sembuf *sops, size_t nsops);
*
*	This function uses generic handler "ve_generic_semop" as semop()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process
*/
ret_t ve_semop(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_semop(syscall_num, syscall_name, handle);
}

/**
* @brief Handles semctl() system call functionality for VE.
*
*	int semctl(int semid, int semnum, int cmd, ...);
*
*	This function receive data and arguments from VEHVA/VEMVA using
*	VE driver interface and then invoke VH OS semctl() system call.
*	After call to VH OS return the buffered data back to VE process.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_semctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	struct semid_ds buf = { {0} };
	unsigned short *array = NULL;
	struct seminfo __buf = {0};
	union semun {
		int val;
		struct semid_ds *buf;
		unsigned short *array;
		struct seminfo *__buf;
	} arg = {0};

	PSEUDO_TRACE("Entering");
	/* get system call rguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	switch (args[2]) {

	case IPC_STAT:
	case SEM_STAT:
		arg.buf = &buf;

		/* call VH system call */
		if ((void *)args[3] != NULL) {
			retval = syscall(syscall_num, args[0],
					args[1], args[2], arg);
		} else {
			retval = syscall(syscall_num, args[0],
					args[1], args[2], args[3]);
		}

		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed :%s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		if (args[3]) {
			/* send data to VEMVA/VEHVA */
			if (0 > ve_send_data(handle, args[3],
						sizeof(struct semid_ds),
							&buf)) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
						" IPC_STAT", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;
	case IPC_INFO:
	case SEM_INFO:
		arg.__buf = &__buf;

		/* call VH system call */
		if ((void *)args[3] != NULL) {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], arg);
		} else {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], args[3]);
		}

		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed :%s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		if (args[3]) {
			if (0 > ve_send_data(handle, args[3],
					sizeof(struct seminfo),
						&__buf)) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
						" IPC_INFO", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;
	case GETPID:
	case GETVAL:
	case SETVAL:
	case GETNCNT:
	case GETZCNT:
	case IPC_RMID:
		/* call VH sysstem call */
		if (args[2] == SETVAL) {
			retval = syscall(syscall_num, args[0],
					args[1], args[2], args[3]);
		} else {
			retval = syscall(syscall_num, args[0],
					args[1], args[2]);
		}
		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed :%s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		break;
	case IPC_SET:
		if (args[3]) {
			/* recieving data from VEMVA/VEHVA */
			if (0 > ve_recv_data(handle, args[3],
						sizeof(struct semid_ds),
						&buf)) {
				PSEUDO_ERROR("failed to receive data"
						" from VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive"
						" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		arg.buf = &buf;

		/* call VH system call */
		if ((void *)args[3] != NULL) {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], arg);
		} else {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], args[3]);
		}

		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed :%s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		break;
	case SETALL:
	case GETALL:

		arg.buf = &buf;

		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],
				IPC_STAT, arg);
		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed %s :",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		array = (unsigned short *)calloc
			(buf.sem_nsems, sizeof(unsigned short));
		if (array == NULL) {
			PSEUDO_ERROR("Failed to create internal memory"
				" buffer");
			PSEUDO_DEBUG("array:calloc failed(%s) in setall/getall",
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}

		if (args[2] == SETALL && args[3]) {
			if (0 > ve_recv_data(handle, args[3],
					buf.sem_nsems * sizeof(unsigned short),
						array)) {
				PSEUDO_ERROR("failed to receive data"
						" from VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive"
						" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		arg.buf = NULL;
		arg.array = array;
		/* call VH system call */
		if ((void *)args[3] != NULL) {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], arg);
		} else {
			retval = syscall(syscall_num, args[0], args[1],
					args[2], args[3]);
		}

		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall failed %s :",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		if (args[2] == GETALL && args[3]) {
			if (0 > ve_send_data(handle, args[3],
					buf.sem_nsems * sizeof(unsigned short),
							array)) {
				PSEUDO_ERROR("Failed to send data to VE"
					" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send data:"
						" GETALL", SYSCALL_NAME,
						strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

	default:
		PSEUDO_INFO("INVALID semctl COMMAND VALUE");
		retval = -EINVAL;
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);

hndl_return:
	if (array != NULL)
		free(array);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* ebrief Handles ve_msgget(e system call for VE.
*
*	int msgget(key_t key, int msgflg);
*
*	This function uses generic handler "ve_generic_offload" as msgget()
*	functionality for VE has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_msgget(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles ve_msgsnd() system call for VE.
 *
 *	int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and offloads the functionality to VH OS msgsnd()
 *	system call.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_msgsnd(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t msgsz = 0;
	uint64_t args[4] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to receive arguments. "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		return retval;
	}
	msgsz = args[2];
	struct msg {
		long mtype;
		char mtext[msgsz];
	} *msgp = NULL;

	if (args[1]) {
		/* allocate memory to store read data */
		msgp = (struct msg *)malloc(sizeof(struct msg));
		if (NULL == msgp) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
				" buffer");
			PSEUDO_DEBUG("msgp:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		memset(msgp, '\0', (sizeof(struct msg)));

		if (0 > ve_recv_data(handle, args[1],
					(sizeof(struct msg)), (uint64_t *)msgp)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			msgp, msgsz, args[3]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		PSEUDO_DEBUG("syscall = %s send buf = %s\n retval %lu",
				SYSCALL_NAME,
				msgp ? msgp->mtext : "msgp is NULL", retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	free(msgp);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles ve_msgrcv() system call for VE.
 *
 *	ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
 *		int msgflg);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS msgrcv() system call.
 *	Updated buffers returned from VH OS are copied back to VEMVA using VE
 *	driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_msgrcv(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t msgsz = 0;
	long msgtype = 0;
	uint64_t args[5] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to receive arguments. "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		return retval;
	}
	msgsz = args[2];
	msgtype = args[3];

	struct msg {
		long mtype;
		char mtext[msgsz];
	} *msgp = NULL;

	/* allocate memory to store read data */
	msgp = (struct msg *)malloc(sizeof(struct msg));
	if (NULL == msgp) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("msgp:calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}
	memset(msgp, '\0', (sizeof(struct msg)));

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			msgp, msgsz, msgtype, args[4]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		goto hndl_return1;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");


	if (args[1]) {
		if (0 > ve_send_data(handle, args[1],
					(sizeof(struct msg)),
					(uint64_t *)msgp)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
	}
	PSEUDO_DEBUG("syscall = %s read_buf= %s read %lu bytes",
			SYSCALL_NAME, msgp ? msgp->mtext : "Null message",
			retval);
hndl_return1:
	free(msgp);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles ve_msgctl() system call for VE.
*
*	int msgctl(int msqid, int cmd, struct msqid_ds *buf);
*
*	This function receives the data and arguments from VEMVA/VEHVA using
*	VE driver interface.
*	It offloads the functionality to VH OS msgctl() system call.
*	Updated buffers returned from VH OS are copied back to VEMVA using
*	using VE driver interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_msgctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct msqid_ds msqds = { {0} };
	struct msginfo msg_info = {0};
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to receive arguments. "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	switch (args[1]) {
	case IPC_SET:
	case IPC_STAT:
	case MSG_STAT:
	case IPC_RMID:
		/* To receive struct ve_file_lock values from VE */
		if (IPC_SET == args[1] && args[2]) {
			if (0 > ve_recv_data(handle, args[2],
						sizeof(struct msqid_ds),
						(uint64_t *)(&msqds))) {
				retval = -EFAULT;
				PSEUDO_ERROR("failed to receive data"
						" from VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive"
						" %s argument[2]",
						strerror(errno), SYSCALL_NAME);
				goto hndl_return;
			}
		}
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],	&msqds);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		} else if (MSG_STAT == args[1] || IPC_STAT == args[1]) {
			if (args[2]) {
				if (0 > ve_send_data(handle, args[2],
							sizeof(struct msqid_ds),
							(uint64_t *)&msqds)) {
					retval = -EFAULT;
					PSEUDO_ERROR("Failed to send"
							" data to VE memory");
					PSEUDO_DEBUG("%s Failed(%s)"
							" to send args[2]",
							SYSCALL_NAME,
							strerror(errno));
					goto hndl_return;
				}
			}
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
			goto hndl_return;
		}
	case IPC_INFO:
	case MSG_INFO:
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1], &msg_info);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		if (args[2]) {
			/* Send the filled ve_file_lock to VE */
			if (0 > ve_send_data(handle, args[2],
						sizeof(struct msginfo),
						(uint64_t *)(&msg_info))) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
				goto hndl_return;
			}
		}
		goto hndl_return;
	default:
		PSEUDO_INFO("INVALID msgctl FLAG VALUE");
		retval = -EINVAL;
}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles fcntl() system call functionality for VE.
 *
 *	int fcntl(int fd, int cmd, ...);
 *
 *	This function receives the arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS  system call.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_fcntl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	struct f_owner_ex f_owner = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;

		/* write return value */
		return retval;
	}
	/* check for number of argument */
	switch (args[1]) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_GETFD:
	case F_SETFD:
	case F_GETFL:
	case F_SETFL:
	case F_SETOWN:
	case F_GETPIPE_SZ:
	case F_SETPIPE_SZ:
		retval = ve_generic_offload(syscall_num, syscall_name, handle);
		break;
	case F_GETOWN:
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				args[2]);
		/* In case f_owner of the args[0] is a process group,
		 * the return value is a negative value between the
		 * range of -1 to -4095. Same negative value is
		 * returned to the VE using retval.
		 * For more information regarding this please check
		 * man page for fcntl.
		 * */
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
		break;
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		retval = ve_hndl_int_int_p_flock_buf(syscall_num,
				syscall_name, handle);
		break;
		/* These flags required further investigation in case of
		 * signal handling. For now offloading it to generic handler.
		 * */
	case F_NOTIFY:
	case F_GETLEASE:
	case F_SETLEASE:
	case F_GETSIG:
	case F_SETSIG:
		retval = ve_generic_offload(syscall_num, syscall_name, handle);
		break;
	case F_SETOWN_EX:
	case F_GETOWN_EX:
		if (F_SETOWN_EX == args[1]) {
			if (args[2]) {
				if (0 > ve_recv_data(handle, args[2],
						sizeof(struct f_owner_ex),
						&f_owner)) {
					PSEUDO_ERROR("failed to receive data"
							" from VE memory");
					PSEUDO_DEBUG("Failed(%s) to receive"
							" %s argument[2] for"
							" F_GETOWN_EX",
							strerror(errno),
							SYSCALL_NAME);
					retval = -EFAULT;
					return retval;
				}
			}
		}

		retval = syscall(syscall_num, args[0], args[1],
					args[2] ? &f_owner : NULL);
		if (retval == -1) {
			retval = -errno;
			PSEUDO_ERROR("%s syscall is failed %s",
				SYSCALL_NAME, strerror(errno));
			return retval;
		}

		if (F_GETOWN_EX == args[1]) {
			if (args[2]) {
				if (0 > ve_send_data(handle, args[2],
						sizeof(struct f_owner_ex),
						&f_owner)) {
					PSEUDO_ERROR("Failed to send data"
						" to VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send"
						" data for F_GETOWN_EX",
							SYSCALL_NAME,
							strerror(errno));
					retval = -EFAULT;
					return retval;
				}
			}
		}
		break;
	default:
		PSEUDO_INFO("INVALID FLAG PASSED IN "
				"FCNTL SYSTEM CALL");
		retval = -EINVAL;
	}
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles flock() system call functionality for VE.
*
*	int flock(int fd, int operation);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS flock() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_flock(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[2];
	ret_t retval = -1;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the fsync() system call functionality for VE.
 *
 *	int fsync(int fd);
 *
 *	This function uses generic handler "ve_generic_offload" as fsync()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fsync(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fdatasync() system call functionality for VE.
 *
 *	int fdatasync(int fd);
 *
 *	This function uses generic handler "ve_generic_offload" as fdatasync()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fdatasync(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles truncate() system call functionality for VE.
*
*	int truncate(const char *path, off_t length);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS truncate() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_truncate(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	uint64_t args[2] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
					SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument */
		path_buff = (char *)calloc(PATH_MAX, sizeof(char));
		if (NULL == path_buff) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/*receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0],
			 (char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, path_buff, args[1]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles ftruncate() system call functionality for VE
*
*	int ftruncate(int fd, off_t length);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS ftruncate() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_ftruncate(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[2] = {0};
	ret_t retval = -1;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Generic Handler for getdents() and getdents64() system call for VE.
 *
 *	This function receives the arguments from VEMVA/VEHVA using VE driver
 *	interface then invokes the VH OS getdents()/getdents64() system call.
 *	After call to VH OS buffered data from VH OS copied back to the VEMVA
 *	using VE driver interface.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_generic_getdents(int syscall_num, char *syscall_name,
				veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	char *dent = NULL;

	PSEUDO_TRACE("Entering");

	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[1] && args[2]) {
		/* allocate memory to buffer data from VH OS */
		dent = (char *)calloc(args[2], sizeof(char));
		if (dent == NULL) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
				" buffer");
			PSEUDO_DEBUG("dent: calloc %s failed",
					SYSCALL_NAME);
			goto hndl_return;
		}

		/* check whether VE address is valid or invalid */
		retval = ve_is_valid_address(handle, args[1]);
		if (retval < 0) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH kernel */
	retval = syscall(syscall_num, args[0], dent, args[2]);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed", SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[1] && retval) {
		/* send data fetched from kernel to VE process */
		if (0 > ve_send_data(handle, args[1], (int)retval, dent)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

hndl_return:
	if (dent != NULL)
		free(dent);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the getdents() system call functionlity for VE.
 *
 *	int getdents(unsigned int fd, struct linux_dirent *dirp,
 *			unsigned int count);
 *
 *	This function uses generic handler "ve_generic_getdents" as getdents()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getdents(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_getdents(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles getcwd() system call functionality for VE.
 *
 *	long getcwd(char *buf, unsigned long size);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA and then invokes
 *	the VH OS system call.
 *	Buffer containing current working directory received
 *	as output from VH OS system call is then copied back to VEMVA using VE
 *	driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getcwd(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t recv_size = 0;
	char *path_buf = NULL;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	recv_size = args[1];

	if (args[0] && recv_size) {
		/* allocate memory for current path to be fetched */
		path_buf = (char *)calloc(recv_size, sizeof(char));
		if (NULL == path_buf) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory buffer");
			PSEUDO_DEBUG("path_buf:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0] ? path_buf : NULL, recv_size);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	/* send the filled path_buf */
	if (0 > ve_send_data(handle, args[0],
				(int)retval, (uint64_t *)(path_buf))) {
		PSEUDO_ERROR("Failed to send data to VE memory");
		PSEUDO_DEBUG("%s Failed(%s) to send args[0]",
					SYSCALL_NAME, strerror(errno));
		retval = -EFAULT;
		goto hndl_return1;
	}

hndl_return1:
	free(path_buf);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles chdir() system call functionality for VE.
 *
 *	int chdir(const char *path);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chdir()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_chdir(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fchdir() system call functionality for VE.
 *
 *	int fchdir(int fd);
 *
 *	This function uses generic handler "ve_generic_offload" as fchdir()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fchdir(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles rename() system call functionality for VE.
 *
 *	int rename(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as rename()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_rename(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mkdir() system call functionality for VE.
 *
 *	int mkdir(const char *pathname, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mkdir()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_mkdir(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles rmdir() system call functionality for VE.
 *
 *	int rmdir(const char *pathname);
 *
 *	This function uses generic handler "ve_hndl_p_char" as rmdir()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_rmdir(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles creat() system call functionality for VE.
*
*	int creat(const char *pathname, mode_t mode);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS creat() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_creat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	uint64_t args[2] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
					SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);

		/*receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, path_buff, args[1]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles link() system call functionality for VE.
 *
 *	int link(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as link()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_link(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles unlink() system call functionality for VE.
 *
 *	int unlink(const char *pathname);
 *
 *	This function uses generic handler "ve_hndl_p_char" as unlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_unlink(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles symlink() system call functionality for VE.
 *
 *	int symlink(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as symlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_symlink(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles readlink() system call functionality for VE.
 *
 *	ssize_t readlink(const char *path, char *buf, size_t bufsiz);
 *
 *	This function fetches arguments from VEHVA/ VEMVA and then invokes the
 *	VH OS readlink() system call.
 *	ve_recv_string is used to fetch symlink name from VE side.
 *	Buffer(containig symbolic link data)
 *	received as output from VH OS system call is then copied back to VEMVA
 *	using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_readlink(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *symlink = NULL;
	char *buffer = NULL;
	size_t recv_size = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* prepare buffer */
	recv_size = args[2];

	if ((int)recv_size <= 0)
		return -EINVAL;

	/* allocate memory to send contents of 2nd argument */
	buffer = (char *)malloc(recv_size * sizeof(char));
	if (NULL == buffer) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("buffer:calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}
	memset(buffer, '\0', recv_size);

	if (args[0]) {
		/* allocate memory for storing symbolic link name */
		symlink = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == symlink) {
			retval = -errno;
			PSEUDO_ERROR("symlink: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
		memset(symlink, '\0', PATH_MAX);

		/* receive symlink name from VE side */
		retval = ve_recv_string(handle, args[0], (char *)symlink,
			 PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string"
					"(%s) returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, symlink, buffer, recv_size);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return2;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	if (args[1]) {
		/* copy back obtained buffer to VE area */
		if (0 > ve_send_data(handle, args[1],
					recv_size, (uint64_t *)buffer)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return2;
		}
	}
hndl_return2:
	free(symlink);
hndl_return1:
	free(buffer);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles chmod() system call functionality for VE.
 *
 *	int chmod(const char *path, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chmod()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_chmod(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fchmod() system call functionality for VE.
 *
 *	int fchmod(int fd, mode_t mode);
 *
 *	This function uses generic handler "ve_generic_offload" as fchmod()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fchmod(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles chown() system call functionality for VE.
 *
 *	int chown(const char *path, uid_t owner, gid_t group);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chown()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_chown(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fchown() system call functionality for VE.
 *
 *	int fchown(int fd, uid_t owner, gid_t group);
 *
 *	This function uses generic handler "ve_generic_offload" as fchown()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fchown(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles lchown() system call functionality for ve.
 *
 *	int lchown(const char *path, uid_t owner, gid_t group);
 *
 *	This function uses generic handler "ve_hndl_p_char" as lchown()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_lchown(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the umask() system call functionality for VE.
 *
 *	mode_t umask(mode_t mask);
 *
 *	This function uses generic handler "ve_generic_offload" as umask()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_umask(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getuid() system call functionality for VE.
 *
 *	uid_t getuid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getuid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getgid() system call functionality for VE.
 *
 *	gid_t getgid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getgid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setuid() system call for ve.
 *
 *	int setuid(uid_t gid);
 *
 *	This function set the UID of the VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 *
 * @return 0 on success, -1 or errno on failure.
 */
ret_t ve_setuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EAGAIN;
		goto hndl_return;
	}

	retval = syscall(syscall_num, args[0]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return;
	}

	/* Send veos request to set uid */
	retval = pseudo_psm_send_setuidgid_req
		(handle->veos_sock_fd, args[0], false);
	if (-1 == retval) {
		retval = -EAGAIN;
		PSEUDO_ERROR("failed to send setuid  info to PSM");
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_setuidgid_ack(handle->veos_sock_fd);
	if (-1 == retval) {
		retval = -EAGAIN;
		PSEUDO_ERROR("setuid ack not received");
		goto hndl_return;
	}
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles setgid() system call for ve.
 *
 *	int setgid(gid_t gid);
 *
 *	This function set the GID of the VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 *
 * @return 0 on success, -1 or errno on failure.
 */
ret_t ve_setgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EPERM;
		goto hndl_return;
	}

	retval = syscall(syscall_num, args[0]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return;
	}

	/* Send veos request to set gid */
	retval = pseudo_psm_send_setuidgid_req
		(handle->veos_sock_fd, args[0], true);
	if (-1 == retval) {
		retval = -EPERM;
		PSEUDO_ERROR("failed to send setgid info to PSM");
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_setuidgid_ack(handle->veos_sock_fd);
	if (0 > retval) {
		retval = -EPERM;
		PSEUDO_ERROR("setgid ack not received");
		goto hndl_return;
	}

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the geteuid() system call functionality for VE.
 *
 *	uid_t geteuid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as geteuid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_geteuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getegid() system call functionality for VE.
 *
 *	gid_t getegid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getegid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getegid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the setpgid() system call functionality for VE.
 *
 *	int setpgid(pid_t pid, pid_t pgid);
 *
 *	This function uses generic handler "ve_generic_offload" as setpgid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setpgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getppid() system call functionality for VE.
 *
 *	pid_t getppid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getppid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getppid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;

	PSEUDO_TRACE("Entering");

	retval =  ve_generic_offload(syscall_num, syscall_name, handle);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to get process parent id");
		fprintf(stderr, "failure in getting PPID\n");
		pseudo_abort();
	}
	PSEUDO_TRACE("Exiting");

	return retval;
}

/**
 * @brief Handles the getpgrp() system call functionality for VE.
 *
 *	pid_t getpgrp(void);
 *
 *	This function uses generic handler "ve_generic_offload" as getpgrp()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getpgrp(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the setsid() system call functionality for VE.
 *
 *	pid_t setsid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as setsid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setsid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the setreuid() system call functionality for VE.
 *
 *	int setreuid(uid_t ruid, uid_t euid);
 *
 *	This function uses generic handler "ve_generic_offload" as setreuid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setreuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the setregid() system call functionality for VE.
 *
 *	int setregid(gid_t rgid, gid_t egid);
 *
 *	This function uses generic handler "ve_generic_offload" as setregid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setregid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getgroups() system call functionality for VE.
 *
 *	int getgroups(int size, gid_t list[]);
 *
 *	This function receives the argumets from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS getgroups() system call.
 *	After system call to VH OS buffered data copied back to the
 *	VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getgroups(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	gid_t *list = NULL;

	PSEUDO_TRACE("Entering");

	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if ((int)args[0] < 0)
		return -EINVAL;

	if (args[1] && args[0]) {
		/* allocate memory to store data receive from VH OS */
		list = (gid_t *)calloc(args[0], sizeof(gid_t));
		if (list == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("list: calloc %s failed",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(list, '\0', args[0]*sizeof(gid_t));
	}

	/* call to VH kernel */
	retval = syscall(syscall_num, args[0], list);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[1] && args[0]) {
		/* send contents of 2nd argument to VEMVA/VEHVA */
		if (0 > ve_send_data(handle, args[1], args[0] * sizeof(gid_t),
					list)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send contents of 2nd"
					" argument", SYSCALL_NAME,
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

hndl_return:
	if (list != NULL)
		free(list);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the setresuid() system call functionality for VE.
 *
 *	int setresuid(uid_t ruid, uid_t euid, uid_t suid);
 *
 *	This function uses generic handler "ve_generic_offload" as setresuid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setresuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles syslog() system call functionality for VE.
 *
 *      int syslog(int type, char *bufp, int len);
 *
 *      This function fetches the arguments from VEHVA/VEMVA using VE driver
 *      interface and then invokes the VH OS syslog() system call. The data
 *      to be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_syslog(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *vh_bufp = NULL;
	int vh_len = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* get size of the buffer from args[2] */
	vh_len = (int)args[2];
	PSEUDO_DEBUG("VE buffer len : %d", vh_len);

	/* Allocate memory for vh_bufp */
	if ((NULL != (void *)args[1]) && (vh_len > 0)) {
		vh_bufp = (char *)calloc(vh_len, sizeof(char));
		if (NULL == vh_bufp) {
			retval = -EINVAL;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("vh_bufp:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* Receive bufp from VE side */
		retval = ve_recv_data(handle, args[1],
				vh_len, (char *)vh_bufp);
		if (retval < 0) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EINVAL;
			goto hndl_return1;
		}
	}

	if ((vh_len == 0) && ((void *)args[1] != NULL)) {
		if ((args[0] == 2) || (args[0] == 3) || (args[0] == 4)) {
			vh_bufp = (char *)malloc(sizeof(char));
			if (vh_bufp == NULL) {
				PSEUDO_ERROR("Failed to create internal"
						" buffer");
				PSEUDO_DEBUG("vh_bufp:malloc failed for"
						" vh_bufp");
				retval = -EINVAL;
				goto hndl_return1;
			}
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], vh_bufp, vh_len);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

hndl_return1:
	free(vh_bufp);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles setgroups() system call functionality for VE.
 *
 *      int setgroups(size_t size, const gid_t *list);
 *
 *      This function fetches the arguments from VEHVA/VEMVA using VE driver
 *      interface and then invokes the VH OS setgroups() system call. The
 *      data to be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setgroups(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t vh_size = 0;
	gid_t *vh_list = NULL;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* get size of list from VE memory */
	vh_size = args[0];

	if(NGROUPS_MAX < vh_size){
		retval = -EINVAL;
                goto hndl_return;
	}
	PSEUDO_DEBUG("VE buffer size : %lu", vh_size);

	/* allocate local memory buffer to store list argument data */
	if (NULL != (void *)args[1]) {
		vh_list = (gid_t *)calloc(vh_size, sizeof(gid_t));
		if (NULL == vh_list) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("vh_list:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* receive setgroups() gid_t *list  from VE memory */
		if (0 > ve_recv_data(handle, args[1],
					(vh_size * sizeof(gid_t)),
					(uint64_t *)(vh_list))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, vh_size, vh_list);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	/* cleaning local storage */
hndl_return1:
	free(vh_list);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles getresuid() system call functionality for VE.
 *
 *	int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
 *
 *	This function uses generic handler "ve_hndl_p_int_p_int_p_int" as
 *	getresuid()i functionality for ve has common
 *	pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getresuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	 return ve_hndl_p_int_p_int_p_int(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the setresgid() system call functionality for VE.
 *
 *	int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
 *
 *	This function uses generic handler "ve_generic_offload" as setresgid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setresgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles getresgid() system call functionality for VE.
 *
 *	int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
 *
 *	This function uses generic handler "ve_hndl_p_int_p_int_p_int" as
 *	getresgid() functionality for VE has common pre and
 *	post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name  System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getresgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_int_p_int_p_int(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getpgid() system call functionality for VE.
 *
 *	pid_t getpgid(pid_t pid);
 *
 *	This function uses generic handler "ve_generic_offload" as getpgid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getpgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setfsuid() system call functionality for VE.
 *
 *      int setfsuid(uid_t fsuid);
 *
 *      This function uses generic handler "ve_generic_offload" as
 *      setfsuid() functionality for ve has common pre and post
 *      processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setfsuid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setfsgid() system call functionality for VE.
 *
 *      int setfsgid(uid_t fsgid);
 *
 *      This function uses generic handler "ve_generic_offload" as
 *      setfsgid() functionality for ve has common pre and post
 *      processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_setfsgid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getsid() system call functionality for VE.
 *
 *	pid_t getsid(pid_t pid);
 *
 *	This function uses generic handler "ve_generic_offload" as getsid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_getsid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles utime() system call functionality for VE.
 *
 *	int utime(const char *filename, const struct utimbuf *times);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA using VE driver
 *	interface and then invokes the VH OS utime() system call.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_utime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	struct utimbuf time = {0};
	int recv_size = 0;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");

	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EACCES;
		goto hndl_return;
	}

	recv_size = PATH_MAX;

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument */
		path_buff = (char *)calloc(recv_size, sizeof(char));
		if (NULL == path_buff) {
			retval = -EACCES;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* receive contents of 1st argument(filename) */
		retval = ve_recv_string(handle, args[0],
			 (char *)path_buff, recv_size);
		if (retval < 0) {
			PSEUDO_ERROR("failed to receive string (%s)"
					" returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EACCES;
			goto hndl_return1;
		}
	}

	/* receive contents of 2nd argument(utimbuf) */
	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(struct utimbuf),
					(uint64_t *)&time)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EACCES;
			goto hndl_return1;
		}
		/* call VH system call */
		retval = syscall(syscall_num, path_buff, &time);
	} else {
		/* call VH system call */
		retval = syscall(syscall_num, path_buff, NULL);
	}

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles mknod() system call functionality for VE.
 *
 *	int mknod(const char *pathname, mode_t mode, dev_t dev);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mknod()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_mknod(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles ustat() system call functionality for VE.
*
*	int ustat(dev_t dev, struct ustat *ubuf);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS ustat() system call. The data to
*	be send to VEMVA is done using VE driver interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_ustat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct ustat *ustat_buf = NULL;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Create local memory to store structure data */
	if (NULL != (void *)args[1]) {
		ustat_buf = (struct ustat *)calloc(1, sizeof(struct ustat));
		if (NULL == ustat_buf) {
			retval = -EINVAL;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("ustat_buf: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], ustat_buf);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	/* send the filled ustat buffer */
	if (NULL != (void *)args[1]) {
		if (0 > ve_send_data(handle, args[1],
			sizeof(struct ustat), (uint64_t *)(ustat_buf))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
		}
	}

hndl_return1:
	free(ustat_buf);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles statfs() system call functionality for VE.
*
*	int statfs(const char *path, struct statfs *buf);
*
*	This function receives data and arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS statfs() system call. Buffered
*	data send back to the VE process using VE driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_statfs(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct statfs stat = {0};
	char *path_buff = NULL;

	PSEUDO_TRACE("Entering");

	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s"
				" returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if ((void *)args[0] != NULL) {
		/* allocate memory for contents of 1st argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (path_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("path_buff:malloc %s failed",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(path_buff, '\0', (PATH_MAX * sizeof(char)));

		/* receives contents of 1st argument in path_buff buffer */
		retval = ve_recv_string(handle, args[0], path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, path_buff, &stat);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed", SYSCALL_NAME);
		goto hndl_return;
	}

	if ((void *)args[1] != NULL) {
		/* send required data to VE process */
		if (0 > ve_send_data(handle, args[1],
					sizeof(struct statfs), &stat)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned successfully",
			SYSCALL_NAME);
hndl_return:
	if (path_buff != NULL)
		free(path_buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles fstatfs() system call functionality for VE.
*
*	int fstatfs(int fd, struct statfs *buf);
*
*	This function receives arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS fstatfs() system call.
*	Buffered data from VH OS copied back to VE process using VE
*	driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_fstatfs(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct statfs stat = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments %s returned"
				" %d", SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &stat : NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 */
			retval = -VE_ERESTARTSYS;
			PSEUDO_DEBUG("Blocking signals for"
			" post-processing");

		goto hndl_return;
	}
	PSEUDO_DEBUG("Blocking signals for post-processing");

	if (args[1]) {
		/* send buffered data from VH to VEMVA/VEHVA */
		if (0 >  ve_send_data(handle, args[1],
				sizeof(struct statfs), &stat)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles mlock() system call functionality for VE.
 *
 *	int mlock(const void *addr, size_t len);
 *
 *	This function will always return success because paging is
 *	unsupported but ported application may invoke the mlock()
 *	system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_mlock(int syscall_num, char *syscall_name, veos_handle *handle)
{
	/* This function will always return success because paging is
	 * unsupported but ported application may invoke the mlock()
	 * system call
	 */
	PSEUDO_INFO("syscall is unsupported");
	return 0;
}

/**
 * @brief Handles munlock() system call functionality for VE.
 *
 *	int munlock(const void *addr, size_t len);
 *
 *	This function will always return success because paging is
 *	unsupported but ported application may invoke the munlock()
 *	system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_munlock(int syscall_num, char *syscall_name, veos_handle *handle)
{
	/* This function will always return success because paging is
	 * unsupported but ported application may invoke the munlock()
	 * system call
	 */
	PSEUDO_INFO("syscall is unsupported");
	return 0;
}

/**
 * @brief Handles mlockall() system call functionality for VE.
 *
 *	int mlockall(int flags);
 *
 *	This function will always return success because paging is
 *	unsupported but ported application may invoke the mlockall()
 *	system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_mlockall(int syscall_num, char *syscall_name, veos_handle *handle)
{
	/* This function will always return success because paging is
	 * unsupported but ported application may invoke the mlockall()
	 * system call
	 */
	PSEUDO_INFO("syscall is unsupported");
	return 0;
}

/**
 * @brief Handles munlockall() system call functionality for VE.
 *
 *	int munlockall(void);
 *
 *	This function will always return success because paging is
 *	unsupported but ported application may invoke the munlockall()
 *	system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_munlockall(int syscall_num, char *syscall_name, veos_handle *handle)
{
	/* This function will always return success because paging is
	 * unsupported but ported application may invoke the munlockall()
	 * system call
	 */
	PSEUDO_INFO("syscall is unsupported");
	return 0;
}

/**
* @brief Handles vhangup() system call for VE.
*
*	int vhangup(void);
*
*	This function uses generic handler "ve_generic_offload" as vhangup()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_vhangup(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pivot_root() system call functionality for VE.
 *
 *	int pivot_root(const char *new_root, const char *put_old);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as
 *	pivot_root() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_pivot_root(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles chroot() system call functionality for VE.
 *
 *	int chroot(const char *path);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chroot()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_chroot(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the sync() system call functionality for VE.
 *
 *	void sync(void);
 *
 *	This function uses generic handler "ve_generic_offload" as sync()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_sync(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mount() system call functionality for VE.
 *
 *	int mount(const char *source, const char *target,
 *		const char *filesystemtype, unsigned long mountflags,
 *			const void *data);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using
 *	VE driver interface and then invokes VH OS mount() system call.
 *	It returns the return value of system call back to the VE process
 *	using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_mount(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};
	char *path_buff1 = NULL, *path_buff2 = NULL;
	char *path_buff3 = NULL, *path_buff4 = NULL;

	PSEUDO_TRACE("Entering");

	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive content of 1st argument */
		path_buff1 = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff1 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff1: calloc failed(%s) for"
					" args[0]",
					strerror(errno));
			goto hndl_return;
		}

		/* receive content of 1st argument */
		retval = ve_recv_string(handle, args[0], path_buff1, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[1]) {
		/* allocate memory to receive content of 2nd argument */
		path_buff2 = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff2 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff2: calloc failedi(%s) for"
				" args[1]", strerror(errno));
			goto hndl_return;
		}

		/* receive contents of 2nd argument */
		retval = ve_recv_string(handle, args[1], path_buff2, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* allocate memory to receive contents of 3rd argument */
		path_buff3 = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff3 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff3:calloc failed(%s) for args[2]"
					, strerror(errno));
			goto hndl_return;
		}

		/* receive contents of 3rd argumrnt */
		retval = ve_recv_string(handle, args[2], path_buff3, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[4]) {
		/* allocate memory to receive content of 5th arguments */
		path_buff4 = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff4 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("path_buff4:calloc(%s) failed for args[4]"
					, strerror(errno));
			goto hndl_return;
		}

		/* receive contents of 5th argument */
		retval = ve_recv_string(handle, args[4], path_buff4, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, path_buff1, path_buff2,
			path_buff3, args[3], path_buff4);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return:
	if (path_buff1 != NULL)
		free(path_buff1);

	if (path_buff2 != NULL)
		free(path_buff2);

	if (path_buff3 != NULL)
		free(path_buff3);

	if (path_buff4 != NULL)
		free(path_buff4);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles umount2() system call functionality for VE.
 *
 *	int umount2(const char *target, int flags);
 *
 *	This function uses generic handler "ve_hndl_p_char" as umount2()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_umount2(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Generic handler for sethostname() and setdomainname() system call for VE.
 *
 *      This function receives the data and arguments from VEMVA/VEHVA and
 *      offloads the functionality to VH OS sethostname()/setdomainname()
 *      system call. This function after receiving the data from VH OS call
 *      copies the data to VEMVA using VE driver interface.
 *
 *      Following system calls use this generic handler:
 *      ve_sethostname(),
 *      ve_setdomainname().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_hndl_sethostname_setdomainname(int syscall_num,
		char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *name_buff = NULL;
	size_t vh_len = 0;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* get size of the buffer from args[1] */
	vh_len = args[1];
	PSEUDO_DEBUG("VE buffer len : %ld", vh_len);

	if (vh_len > __NEW_UTS_LEN) {
		retval = -EINVAL;
		goto hndl_return;
	}

	/*if args[0] is not NULL*/
	if (args[0] && (vh_len > 0)) {
		/* allocate memory to receive contents of 1st argument */
		name_buff = (char *)calloc(vh_len, sizeof(char));
		if (NULL == name_buff) {
			retval = -EINVAL;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("name_buff:calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/*receive contents of 1st argument */
		retval = ve_recv_data(handle, args[0], vh_len,
				(char *)name_buff);
		if (retval < 0) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, name_buff, args[1]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

hndl_return1:
	free(name_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sethostname() system call for VE.
 *
 *      int sethostname(const char *name, size_t len);
 *
 *      This function uses generic handler(ve_hndl_sethostname_setdomainname)
 *      as sethostname() functionality for ve has common pre and post processing
 *      needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */
ret_t ve_sethostname(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_sethostname_setdomainname(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setdomainname() system call for VE.
 *
 *      int setdomainname(const char *name, size_t len);
 *
 *      This function uses generic handler(ve_hndl_sethostname_setdomainname)
 *      as setdomainname() functionality for ve has common pre and post
 *      processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */
ret_t ve_setdomainname(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_sethostname_setdomainname(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the iopl() system call functionality for VE.
 *
 *	int iopl(int level);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	iopl() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */
ret_t ve_iopl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the ioperm() system call functionality for VE.
 *
 *	int ioperm(unsigned long from, unsigned long num, int turn_on);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	ioperm() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */
ret_t ve_ioperm(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles ve_quotactl() system call functionality for VE.
 *
 *	int quotactl(int cmd, const char *special, int id, caddr_t addr);
 *
 *	This function fetches the arguments from VEHVA/VEMVA using VE driver
 *	interface and then invokes the VH OS quotactl() system call. The
 *	data to be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_quotactl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *special = NULL;
	char *buff = NULL;
	unsigned int vh_subcmd = 0;
	struct dqblk *vh_dqblk = NULL;
	struct dqinfo *vh_dqinfo = NULL;
	char *fmt_num = NULL;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive "special" argument */
	if (NULL != (void *)args[1]) {
		special = (char *)calloc(PATH_MAX, sizeof(char));
		if (NULL == special) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("special: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* receive the "special" argument*/
		retval = ve_recv_string(handle, args[1],
				(char *)special, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string. (%s)"
				" returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* obtain the value of subcmd from cmd argument */
	vh_subcmd = (unsigned int)args[0] >> SUBCMDSHIFT;

	switch (vh_subcmd) {

		/* following command takes pointer to a pathname of
		 * a file containing the quotas for the file system,
		 * as fourth argument.
		 * */
	case Q_QUOTAON:

		/* allocate memory for storing contents of fourth
		 * argument */
		if (NULL != (void *)args[3]) {
			buff = (char *)calloc(PATH_MAX, sizeof(char));
			if (NULL == buff) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("buff: calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}

			/*receive contents of fourth argument */
			retval = ve_recv_string(handle, args[3],
					(char *)buff, PATH_MAX);
			if (retval < 0) {
				PSEUDO_ERROR("Failed to receive string(%s)"
						" returned %d",
						SYSCALL_NAME, (int)retval);
				if (retval == -2)
					retval = -ENAMETOOLONG;
				else
					retval = -EFAULT;
				goto hndl_buff_free;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				buff);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_buff_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}
hndl_buff_free:
		free(buff);
		break;

		/* Third and fourth arguments are ignored in
		 * following command*/
	case Q_QUOTAOFF:

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				args[3]);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		break;

		/* following command takes pointer to struct dqblk as
		 * fourth argument and it is to be copied back
		 * to VE area
		 * */
	case Q_GETQUOTA:

		/* Create local memory to store vh_dqblk structure*/
		if (NULL != (void *)args[3]) {
			vh_dqblk = (struct dqblk *)
					calloc(1, sizeof(struct dqblk));
			if (NULL == vh_dqblk) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("vh_dqblk: calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				vh_dqblk);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_get_dqblk_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		/* send the filled dqblk buffer */
		if (NULL != (void *)args[3]) {
			if (0 > ve_send_data(handle, args[3],
						sizeof(struct dqblk),
						(uint64_t *)(vh_dqblk))) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
						SYSCALL_NAME, strerror(errno));
				retval = -EFAULT;
			}
		}
hndl_get_dqblk_free:
		free(vh_dqblk);

		break;

		/* following command takes pointer to struct dqblk as
		 * fourth argument.
		 * */
	case Q_SETQUOTA:

		/* allocate memory for storing contents of fourth
		 * argument */
		if (NULL != (void *)args[3]) {
			vh_dqblk = (struct dqblk *)
					calloc(1, sizeof(struct dqblk));
			if (NULL == vh_dqblk) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("vh_dqblk: calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}

			/* get the dqblk structure values */
			if (0 > ve_recv_data(handle, args[3],
						sizeof(struct dqblk),
						(uint64_t *)(vh_dqblk))) {
				PSEUDO_ERROR("failed to receive data"
						" from VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive"
						" %s argument[3]",
						strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_set_dqblk_free;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				vh_dqblk);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_set_dqblk_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

hndl_set_dqblk_free:
		free(vh_dqblk);

		break;

		/* following command takes pointer to struct dqinfo as
		 * fourth argument, and it is to be copied back
		 * to VE area
		 * */
	case Q_GETINFO:

		/* Create local memory to store structure data */
		if (NULL != (void *)args[3]) {
			vh_dqinfo = (struct dqinfo *)calloc
				(1, sizeof(struct dqinfo));
			if (NULL == vh_dqinfo) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("vh_dqinfo :calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				vh_dqinfo);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_get_dqinfo_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		/* send the filled dqinfo buffer */
		if (NULL != (void *)args[3]) {
			if (0 > ve_send_data(handle, args[3],
						sizeof(struct dqinfo),
						(uint64_t *)(vh_dqinfo))) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
						SYSCALL_NAME, strerror(errno));
				retval = -EFAULT;
			}
		}
hndl_get_dqinfo_free:
		free(vh_dqinfo);

		break;

		/* following command takes pointer to struct dqinfo as
		 * fourth argument.
		 * */
	case Q_SETINFO:

		/* allocate memory for storing contents of fourth
		 * argument */
		if (NULL != (void *)args[3]) {
			vh_dqinfo = (struct dqinfo *)calloc
				(1, sizeof(struct dqinfo));
			if (NULL == vh_dqinfo) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("vh_dqinfo: calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}

			/* get the dqinfo structure values */
			if (0 > ve_recv_data(handle, args[3],
						sizeof(struct dqinfo),
						(uint64_t *)(vh_dqinfo))) {
				PSEUDO_ERROR("failed to receive data"
					" from VE memory");
				PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
				retval = -EFAULT;
				goto hndl_set_dqinfo_free;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				vh_dqinfo);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_set_dqinfo_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

hndl_set_dqinfo_free:
		free(vh_dqinfo);

		break;

		/* following command takes pointer to a 4-byte buffer
		 * as fourth argument, and it is to be copied back
		 * to VE area
		 * */
	case Q_GETFMT:

		/* Create local memory to store 4-byte buffer */
		if (NULL != (void *)args[3]) {
			fmt_num = (char *)calloc(4, (sizeof(char)));
			if (NULL == fmt_num) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to create internal"
						" memory buffer");
				PSEUDO_DEBUG("fmt_num: calloc %s failed %s",
						SYSCALL_NAME, strerror(errno));
				goto hndl_return1;
			}
		}

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				fmt_num);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_fmt_num_free;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		/* send the filled 4-byte buffer to VE area */
		if (NULL != (void *)args[3]) {
			if (0 > ve_send_data(handle, args[3],
					(4 * sizeof(char)),
					(uint64_t *)(fmt_num))) {
				PSEUDO_ERROR("Failed to send data to VE"
						" memory");
				PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
						SYSCALL_NAME, strerror(errno));
				retval = -EFAULT;
			}
		}
hndl_fmt_num_free:
		free(fmt_num);

		break;

		/* Third and fourth arguments are ignored in
		 * following command*/
	case Q_SYNC:

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				special,
				args[2],
				args[3]);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					SYSCALL_NAME, (int)retval);
		}

		break;

	default:
		PSEUDO_ERROR("argument not supported");
		retval = -EINVAL;
		goto hndl_return1;
	}

hndl_return1:
	free(special);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the gettid() system call functionality for VE.
 *
 *	pid_t gettid(void);
 *
 *	This function uses generic handler "ve_generic_offload" as gettid()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_gettid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;

	retval =  ve_generic_offload(syscall_num, syscall_name, handle);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to get thread id");
		fprintf(stderr, "failure in getting tid\n");
		pseudo_abort();
	}
	return retval;
}

/**
* @brief Handles ve_readahead() system call for VE.
*
*	ssize_t readahead(int fd, off64_t offset, size_t count);
*
*	This function uses generic handler "ve_generic_offload" as readahead()
*	functionality for VE has common pre and post processing needs.
*
* Note: In ve, we are not supporting page cache as of now, so system call
* will be directly offloaded to kernel.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_readahead(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setxattr() system call for VE.
 *
 *	int setxattr(const char *path, const char *name,
 *		const void *value, size_t size, int flags);
 *
 *	This function uses generic handler
 *	"ve_hndl_set_xattr_p_char_p_char_p_void"
 *	as setxattr() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_setxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_set_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
* @brief Handles lsetxattr() system call for VE.
*
*	int lsetxattr(const char *path, const char *name,
*		const void *value, size_t size, int flags);
*
*	This function uses generic handler
*	"ve_hndl_set_xattr_p_char_p_char_p_void" as lsetxattr() functionality
*	for VE has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_lsetxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_set_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
* @brief Handles fsetxattr() system call for VE.
*
*	int fsetxattr(const char *path, const char *name,
*		const void *value, size_t size, int flags);
*
*	This function does the following:
*	Reads the system call arguments from VEMVA using VE driver interfaces.
*	Invokes ve_recv_string for fetching the value of system call argument
*	pathname and extended attribute name from VEMVA.
*	Offload the system call to VH OS.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_fsetxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	void *buffer2 = NULL;
	size_t size = 0;
	uint64_t args[5] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive value of args[3] from VE memory */
	size = args[3];
	if (size > XATTR_SIZE_MAX) {
		retval = -E2BIG;
		goto hndl_return;
	}

	if (args[1]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc((XATTR_NAME_MAX + 1) * sizeof(char));
		if (NULL == buffer1) {
			PSEUDO_ERROR("Failed to create internel buffer");
			retval = -errno;
			goto hndl_return1;
		}
		memset(buffer1, '\0', (XATTR_NAME_MAX + 1));

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[1],
				(char *)buffer1, (XATTR_NAME_MAX + 1));
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string(%s) returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[2] && size) {
		/* Allocate memory for buffer2 */
		buffer2 = (void *)malloc(sizeof(char) * size);
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("buffer2: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
		memset(buffer2, '\0', size);

		/* Receive buffer2 from VE side */
		if (0 > ve_recv_data(handle, args[2],
					size, (void *)buffer2)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			buffer2,
			size,
			args[4]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return2;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles getxattr() system call functionality for VE.
 *
 *	ssize_t getxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *	This function uses generic handler
 *	"ve_hndl_get_xattr_p_char_p_char_p_void" as getxattr() functionality
 *	for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_get_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
 * @brief Handles lgetxattr() system call functionality for VE.
 *
 *	ssize_t lgetxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *	This function uses generic handler
 *	"ve_hndl_get_xattr_p_char_p_char_p_void"as lgetxattr()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_lgetxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_get_xattr_p_char_p_char_p_void(syscall_num,
							syscall_name, handle);
}

/**
 * @brief Handles fgetxattr() system call functionality for VE.
 *
 *	ssize_t fgetxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *
 *	This function fetches arguments from VEMVA using VE driver interface.
 *	As length of Pathname/Extended attribute name is unknown this
 *	function uses ve_recv_string().
 *	It then offloads the functionality to VH OS system call.
 *	Updated buffers received from VH OS are copied back to VEMVA using VE
 *	driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 * */
ret_t ve_fgetxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	void *buffer2 = NULL;
	size_t size = 0;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive value of args[3] from VE memory */
	size = args[3];
	if (size > XATTR_SIZE_MAX)
		size = XATTR_SIZE_MAX;

	if (args[1]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc((XATTR_NAME_MAX + 1) * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("buffer1: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(buffer1, '\0', (XATTR_NAME_MAX + 1));

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[1],
			(char *)buffer1, (XATTR_NAME_MAX + 1));
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string(%s) returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[2]) {
		/* Allocate memory for buffer2 */
		buffer2 = (void *)malloc(size * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("buffer2: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
		memset(buffer2, '\0', size);
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			buffer2,
			size);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return2;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	if (args[2] && retval && size) {
		/* send data to VE memory */
		if (0 > ve_send_data(handle, args[2],
					retval, (uint64_t *)(buffer2))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return2;
		}
	}

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief handles listxattr() and llistxattr() system call functionality for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS listxattr()/llistxattr()
 *	system call. This function after receiving the data from VH OS call
 *	copies the data to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_listxattr(),
 *	ve_llistxattr().
 *
 * @param[in] syscall_num: System call number
 * @param[in] syscall_name: System call name
 * @param[in] handle: VEOS handle
 *
 * @return system call value to VE process
 */
ret_t ve_generic_listxattr(int syscall_num, char *syscall_name,
				veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	char *buff = NULL;
	char *path_buff = NULL;
	size_t size = 0;

	PSEUDO_TRACE("Entering");

	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive value of args[2] from VE memory */
	size = args[2];
	if (size > XATTR_LIST_MAX)
		size = XATTR_LIST_MAX;

	if (args[0]) {
		/* allocate buffer to store content of 1st argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (path_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("In %s: malloc failed",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX * sizeof(char));

		/* fetch content of 1st argument */
		retval = ve_recv_string(handle, args[0], path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[1] && size) {
		/* allocate memory for buff */
		buff = (char *)malloc(size * sizeof(char));
		if (buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("In %s: malloc failed",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buff, '\0', size);
	}

	/* call VH kernel */
	retval = syscall(syscall_num, path_buff, buff, size);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[1] && retval && size) {
		/* send data to VE memory */
		if (0 > ve_send_data(handle, args[1], retval, buff)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

hndl_return:
	if (buff != NULL)
		free(buff);
	if (path_buff != NULL)
		free(path_buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief handles listxattr() system call functionality for VE.
 *
 *	ssize_t listxattr(const char *path, char *list, size_t size);
 *
 *	This function uses generic handler(ve_generic_listxattr) as
 *	listxattr() functionality for ve has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num: System call number
 * @param[in] syscall_name: System call name
 * @param[in] handle: VEOS handle
 *
 * @return system call value to VE process
 */
ret_t ve_listxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_listxattr(syscall_num, syscall_name, handle);
}

/**
 * @brief handles llistxattr() system call functionality for VE.
 *
 *	ssize_t llistxattr(const char *path, char *list, size_t size);
 *
 *	This function uses generic handler(ve_generic_listxattr) as
 *	llistxattr() functionality for ve has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num: System call number
 * @param[in] syscall_name: System call name
 * @param[in] handle: VEOS handle
 *
 * @return system call value to VE process
 */
ret_t ve_llistxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_listxattr(syscall_num, syscall_name, handle);
}

/**
* @brief handles flistxattr() system call functionality for VE.
*
*	ssize_t flistxattr(int fd, char *list, size_t size);
*
*	This function receives arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS flistxattr() system call.
*	Buffered data from VH copied back to VE process using VE driver
*	interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_flistxattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	char *buff = NULL;
	size_t size = 0;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failedto fetch syscall arguments %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive value of args[2] from VE memory */
	size = args[2];
	if (size > XATTR_LIST_MAX)
		size = XATTR_LIST_MAX;

	if ((void *)args[1] != NULL) {
		/* allocate memory to store data from VH */
		buff = (char *)malloc(size * sizeof(char));
		if (buff == NULL) {
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("buff: malloc failed in %s",
						SYSCALL_NAME);
			retval = -errno;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], buff, size);
	if (retval == -1) {
		PSEUDO_ERROR("%s syscall is failed",
					SYSCALL_NAME);
		retval = -errno;
		goto hndl_return;
	}

	if (args[1] && retval && size) {
		/* send buffered data to VEMVA */
		if (0 > ve_send_data(handle, args[1], retval,
						buff)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_ERROR("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);

hndl_return:
	if (buff)
		free(buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles removexattr() system call functionality for VE.
 *
 *	int removexattr(const char *path, const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as
 *	removexattr()functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */

ret_t ve_removexattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles lremovexattr() system call functionality for VE.
 *
 *	int lremovexattr(const char *path, const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char"
 *	as lremovexattr()functionality for VE has common pre and
 *	post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */

ret_t ve_lremovexattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles fremovexattr() system call functionality for VE.
 *
 *	int fremovexattr(int fd, const char *name);
 *
 *	This function uses generic handler(ve_hndl_int_p_char) as fremovexattr()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 */

ret_t ve_fremovexattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles lookup_dcookie() system call for VE.
 *
 *      int lookup_dcookie(u64 cookie, char *buffer, size_t len);
 *
 *      This function fetches the arguments from VEHVA/VEMVA using VE driver
 *      interface and then invokes the VH OS lookup_dcookie() system call.
 *      The data to be send to VEMVA is done using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_lookup_dcookie(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t len = 0;
	char *vh_buffer = NULL;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %lu",
				SYSCALL_NAME, retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive buffer len from VE memory */
	len = args[2];
	PSEUDO_DEBUG("VE buffer length : %lu", len);

	/* Create local memory to store the buffer at VH side */
	if (NULL != (void *)args[1]) {
		vh_buffer = (char *)calloc(len, sizeof(char));
		if (NULL == vh_buffer) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("vh_buffer: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	/* Invoking system call on VH side */
	retval = syscall(syscall_num, args[0], vh_buffer, len);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	/* send data to VE memory.*/
	if (NULL != (void *)args[1]) {
		if (0 > ve_send_data(handle, args[1], len,
					(uint64_t *)(vh_buffer))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

hndl_return1:
	free(vh_buffer);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the epoll_create() system call functionality for VE.
*
*	int epoll_create(int size);
*
*	This function uses generic handler "ve_generic_offload" as
*	epoll_create() functionality for VE has common pre and post
*	processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_epoll_create(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the getdents() system call functionlity for VE.
 *
 *	int getdents64(unsigned int fd, struct linux_dirent64 *dirp,
 *			unsigned int count);
 *
 *	This function uses generic handler "ve_generic_getdents" as getdents64()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_getdents64(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_getdents(syscall_num, syscall_name, handle);
}

/**
* @brief Handles semtimedop() system call functionality for VE.
*
*	int semtimedop(int semid, struct sembuf *sops, size_t nsops,
*	                      const struct timespec *timeout);
*
*	This function uses generic handler "ve_generic_semop" as semtimedop()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process
*/
ret_t ve_semtimedop(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_semop(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fadvise64() system call functionality for VE.
 *
 *	int fadvise64(int fd, loff_t offset, size_t len, int advice)
 *
 *	This function uses generic handler "ve_generic_offload" as fadvise64()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fadvise64(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles timer_create() system call functionality for VE.
*
* 	int timer_create(clockid_t clockid, struct sigevent *sevp,
* 					timer_t *timerid);
*
*	This function receives data and arguments from VEMVA/VEHVA using
*	VE driver interface and then invokes VH OS system call. After call
*	to VH os returned the buffered data back to the VE process.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_timer_create(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	timer_t timer_id = 0;
	clockid_t clockid = 0;
	struct ksigevent {
		union sigval sigev_value;
		int sigev_signo;
		int sigev_notify;
		int sigev_tid;
	} sig = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	clockid = (clockid_t)args[0];

	PSEUDO_DEBUG("Clock Id: %d", clockid);

	if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
		PSEUDO_INFO("timer_create is not supported for "
				"Process/Thread CPU clock");
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[1]) {
		/* receive sigevent data from VEMVA/VEHVA */
		if (0 > ve_recv_data(handle, args[1],
				sizeof(struct ksigevent), &sig)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* receive timer_t data from VEMVA/VEHVA */
		if (0 > ve_recv_data(handle, args[2],
				sizeof(timer_t), &timer_id)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
				args[1] ? &sig : NULL,
				args[2] ? &timer_id : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[2]) {
		/* sending timer id to VE process */
		if (0 > ve_send_data(handle, args[2],
					sizeof(timer_t), &timer_id)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	PSEUDO_DEBUG("%s syscall returned",
			SYSCALL_NAME);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handle timer_settime system call functionality for VE.
*
* 	int timer_settime(timer_t timerid, int flags,
* 			const struct itimerspec *new_value,
* 			struct itimerspec *old_value);
*
*	This function receives data and arguments from VEMVA/VEHVA using
*	VE driver interface and then invoke VH OS timer_settime() system
*	call.After call to VH OS return the buffered data back to the VE
*	process.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_timer_settime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	struct itimerspec new_val = { {0} };
	struct itimerspec old_val = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[2]) {
		/* receive timer data from VEMVA/VEHVA  */
		if (0 > ve_recv_data(handle, args[2],
					sizeof(struct itimerspec), &new_val)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1],
					args[2] ? &new_val : NULL,
					args[3] ? &old_val : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed", SYSCALL_NAME);
		goto hndl_return;
	}

	/* send data to VEMVA/VEHVA*/
	if (args[3]) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(struct itimerspec), &old_val)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handle timer_gettime() system call functionality for VE.
*
* 	int timer_gettime(timer_t timerid, struct itimerspec *curr_value);
*
*	This function receive arguments from VEMVA/VEHVA using VE driver
*	interface and invokes VH OS timer_gettime() system call. After
*	call to VH OS return the buffered data to VE process.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_timer_gettime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct itimerspec curr_val = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments");
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &curr_val : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	if (args[1]) {
		/* send data to VEMVA/VEHVA */
		if (0 > ve_send_data(handle, args[1],
				sizeof(struct itimerspec), &curr_val)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_ERROR("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles timer_getoverrun() system call functionality for VE.
*
*	int timer_getoverrun(timer_t timerid);
*
*	This function uses generic handler "ve_generic_offload" as
*	timer_getoverrun() functionality for VE has common pre and
*	post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_timer_getoverrun(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles timer_delete() system call functionality for VE.
*
*	int timer_delete(timer_t timerid);
*
*	This function uses generic handler "ve_generic_offload" as
*	timer_delete() functionality for VE has common pre and post
*	processing needs
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_timer_delete(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles clock_nanosleep() system call functionality for VE.
 *
 *	int clock_nanosleep(clockid_t clock_id, int flags,
 *		const struct timespec *request,
 *			struct timespec *remain);
 *
 *	This function fetches arguments from VEHVA/VEMVA and then invokes the
 *	VH OS clock_nanosleep() system call. Updated buffers received from
 *	VH OS are then copied back to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_clock_nanosleep(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timespec req = {0};
	struct timespec rem = {0};
	int flag = 0;
	uint64_t args[4] = {0};
	clockid_t clockid = 0;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	flag = args[1];

	clockid = (clockid_t)args[0];

	PSEUDO_DEBUG("Clock Id: %d", clockid);

	if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
		PSEUDO_INFO("clock_nanosleep is not supported for "
				"Process CPU clock");
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[2]) {

		/* receive contents of 3rd argument */
		if (0 > ve_recv_data(handle, args[2],
				sizeof(struct timespec), (uint64_t *)(&req))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], flag,
			args[2] ? &req : NULL, args[3] ? &rem : NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));

		/* If clock_nanosleep is interrupted,
		 * remaining time is written into rem. */
		if (EINTR == -retval) {

			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
			if (args[3] && !(TIMER_ABSTIME & flag)) {
				PSEUDO_DEBUG("rem.tv_sec=%lld rem.tv_nsec=%ld",
						(long long)rem.tv_sec,
							rem.tv_nsec);

				/* send buffered data from VH to VEMVA/VEHVA */
				if (0 > ve_send_data(handle, args[3],
						sizeof(struct timespec),
							(uint64_t *)(&rem))) {
					PSEUDO_ERROR("Failed to send data to"
							" VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send"
						" args[3]", SYSCALL_NAME,
						strerror(errno));
					retval = -EFAULT;
				}
			}
		}

	} else {

		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the epoll_wait() system call functionality for VE.
*
*	int epoll_wait(int epfd, struct epoll_event *events,
*			int maxevents, int timeout);
*
*	This function receives the arguments from VEMVA/VEHVA using VE driver
*	interface and invokes the VH OS epoll_wait() system call.
*	Updated buffers returned from VH OS are copied back to VEMVA using VE
*	driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @rteurn system call value to VE process.
*/
ret_t ve_epoll_wait(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	struct epoll_event *ve_event = NULL;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments,%s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[1] && ((int)args[2] > 0)) {

		if ((int)args[2] > EP_MAX_EVENTS) {
			retval = -EINVAL;
			goto hndl_return;
		}

		/* allocate memory to receive list of events from kernel */
		ve_event = (struct epoll_event *)
			calloc(args[2], sizeof(struct epoll_event));
		if (ve_event == NULL) {
			PSEUDO_ERROR("Failed to create internal"
				" memory buffer");
			PSEUDO_DEBUG("ve_event: calloc %s failed",
						SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], ve_event,
				args[2], args[3]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[1]) {
		/* send list of events to VEMVA/VEHVA */
		if (0 > ve_send_data(handle, args[1],
				args[2] * sizeof(struct epoll_event),
					ve_event)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send event list",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

hndl_return:
	if (ve_event != NULL)
		free(ve_event);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the epoll_ctl() system call functionality for VE.
*
*	int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
*
*	This function receives data and arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS epoll_ctl() system call.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_epoll_ctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	struct epoll_event *ve_event = NULL;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[3]) {
		/* allocate memory to store contents of 4th argument */
		ve_event = (struct epoll_event *)
				malloc(sizeof(struct epoll_event));
		if (ve_event == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("ve_event: malloc %s failed",
						SYSCALL_NAME);
			goto hndl_return;
		}
		memset(ve_event, '\0', sizeof(struct epoll_event));

		/* receive contents of 4th argument */
		if (0 > ve_recv_data(handle, args[3],
				sizeof(struct epoll_event), ve_event)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1],
			args[2], ve_event);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed", SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);

hndl_return:
	if (ve_event != NULL)
		free(ve_event);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles utimes() system call functionality for VE.
*
*	int utimes(const char *filename, const struct timeval times[2]);
*
*	This function fetches arguments from VEHVA/VEMVA and then invokes the
*	VH OS utimes() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_utimes(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timeval vh_times[2] = { {0} };
	char *file_name = NULL;
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EACCES;
		goto hndl_return;
	}
	/* allocate memory to receive file name */
	if (NULL != (void *)args[0]) {
		file_name = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == file_name) {
			retval = -EACCES;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(file_name, '\0', PATH_MAX);

		/* receive the file name */
		retval = ve_recv_string(handle, args[0],
				(char *)file_name, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EACCES;
			goto hndl_return1;
		}
	}

	/* receive struct timeval values from VE memory */
	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					(sizeof(vh_times)),
					(uint64_t *)(vh_times))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EACCES;
			goto hndl_return1;
		}
		/* call VH system call if 2nd argument is not NULL */
		retval = syscall(syscall_num, file_name, vh_times);
	} else {
		/* call VH system call if 2nd argument is NULL */
		retval = syscall(syscall_num, file_name, args[1]);
	}

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	/* cleaning local storage */
hndl_return1:
	free(file_name);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles mq_open() system call functionality for VE.
*
*	mqd_t mq_open(const char *name, int oflag);
*	mqd_t mq_open(const char *name, int oflag, mode_t mode,
*		struct mq_attr *attr);
*
*	This function receives the data and arguments from VEMVA/VEHVA using
*	VE driver interface.As length of path is unknown this function uses
*	ve_recv_string().
*	It then offloads the functionality to VH OS system call.
*
* @param syscall_num System call number.
* @param syscall_name System call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_mq_open(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	struct mq_attr attr = {0};
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument i.e PATH */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("path_buff: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);

		/* receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0], (char *)path_buff,
			 PATH_MAX);
		if (0 > retval) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EINVAL;
			goto hndl_return1;
		}
	}

	/* receive content of 4th argument i.e struct mq_attr */
	if (NULL != (void *)args[3]) {
		if (0 > ve_recv_data(handle, args[3],
					sizeof(struct mq_attr), &attr)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EINVAL;
			goto hndl_return1;
		}
		/* call VH system call if 4th argument is not NULL */
		retval = syscall(syscall_num, path_buff, args[1], args[2], &attr);
	} else {
		/* call VH system call if 4th argument is NULL */
		retval = syscall(syscall_num, path_buff, args[1],
				args[2], args[3]);
	}

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles mq_unlink() system call functionality for VE.
 *
 *	int mq_unlink(const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mq_unlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_mq_unlink(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles mq_timedsend() system call functionality for VE.
*
*	int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
*		unsigned msg_prio, const struct timespec *abs_timeout);
*
*	This function fetches the arguments and data from VEMVA/VEHVA
*	using VE driver interface. It offloads the functionality to VH OS
*	mq_timedsend() system call.
*
* @param[in] syscall_num System call number.
* @param[in] syscall_name System call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_mq_timedsend(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *msgptr = NULL;
	size_t msg_len = 0;
	struct timespec abs_timeout = {0};
	uint64_t args[5] = {0};
	sigset_t signal_mask = { {0} };
	struct mq_attr attr = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to receive arguments. "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* receive send buffer size from VE memory */
	msg_len = args[2];

	if (mq_getattr(args[0], &attr) < 0)
	{
		retval = -EBADF;
		PSEUDO_ERROR("Fetch msg queue attribute : Failed");
		goto hndl_return;
	}

	if (msg_len > attr.mq_msgsize)
	{
		retval = -EMSGSIZE;
		goto hndl_return;
	}

	if (args[3] >= (unsigned long) MQ_PRIO_MAX)
	{
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[1]) {
		/* allocate memory to store send data */
		msgptr = (char *)malloc(msg_len * sizeof(char));
		if (NULL == msgptr) {
			retval = -EINVAL;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("msgptr: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(msgptr, '\0', msg_len);

		/* receive contents to be send from 1st argument */
		if (0 > ve_recv_data(handle, args[1],
					msg_len, (uint64_t *)msgptr)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
	/* receive the struct timespec values from 5th argument */
	if (NULL != (void *)args[4]) {
		if (0 > ve_recv_data(handle, args[4],
					sizeof(struct timespec),
					(uint64_t *)&abs_timeout)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call if time is specified in 5th argument */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, args[3], &abs_timeout);
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if 5th argument is NULL */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, args[3], args[4]);
	}
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	free(msgptr);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles mq_timedreceive() system call functionality for VE.
 *
 *	ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
 *		unsigned *msg_prio, const struct timespec *abs_timeout);
 *
 *	This function fetches the arguments and data from VEMVA/VEHVA and
 *	offloads the functionality to VH OS mq_timedreceive() system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ssize_t ve_mq_timedreceive(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ssize_t retval = -1;
	char *msgptr = NULL;
	size_t msg_len = 0;
	struct timespec abs_timeout = {0};
	unsigned prio = 0;
	uint64_t args[5] = {0};
	sigset_t signal_mask = { {0} };
	struct mq_attr attr = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to receive arguments. "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* receive buffer size from VE memory */
	msg_len = args[2];

	if (mq_getattr(args[0], &attr) < 0)
	{
		retval = -EBADF;
		PSEUDO_ERROR("Fetch msg queue attribute : Failed");
		goto hndl_return;
	}

	if ((long int)msg_len < attr.mq_msgsize)
	{
		retval = -EMSGSIZE;
		goto hndl_return;
	}

	/* allocate memory to store data */
	msgptr = (char *)calloc(msg_len, sizeof(char));
	if (NULL == msgptr) {
		retval = -EINVAL;
		PSEUDO_ERROR("Failed to create internal memory buffer");
		PSEUDO_DEBUG("msgptr: calloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	/* receive the struct timespec values from 5th argument */
	if (NULL != (void *)args[4]) {
		if (0 > ve_recv_data(handle, args[4],
					sizeof(struct timespec),
					(uint64_t *)&abs_timeout)) {
			retval = -EFAULT;
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if time is specified in 5th argument */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, &prio, &abs_timeout);
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		PSEUDO_DEBUG("Pre-processing finished, unblock signals");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if 5th argument is NULL */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, &prio, args[4]);
	}
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		/* Post-processing of syscall started, blocking signals */
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[1] && retval) {

		/* Number of bytes receive from kernel successfully */
		msg_len = (size_t)retval;

		/* send the received buffer */
		if (0 > ve_send_data(handle, args[1],
					msg_len, (uint64_t *)msgptr)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
	}

	if (args[3]) {
		/* send the received priority */
		if (0 > ve_send_data(handle, args[3],
					sizeof(unsigned), (uint64_t *)&prio)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
					SYSCALL_NAME, strerror(errno));
		}
	}
hndl_return1:
	free(msgptr);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles mq_notify() system call functionality for VE.
 *
 *	int mq_notify(mqd_t mqdes, const struct sigevent *sevp);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using
 *	VE driver interface and invokes VH OS mq_notify() system call.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_mq_notify(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct sigevent sigev = { {0} };
	static const char zeros[32] = {0};

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetchsyscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	if ((void *)args[1] != NULL) {
		/* receive contents of 2nd argument */
		if (0 > ve_recv_data(handle, (uint64_t)args[1],
					sizeof(struct sigevent), &sigev)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EINVAL;
			goto hndl_return;
		}

		if (sigev.sigev_notify == SIGEV_THREAD)
			sigev.sigev_value.sival_ptr = (void *)&zeros;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &sigev : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles mq_getsetattr() system call functionality for VE.
*
*	int mq_getsetattr(mqd_t mqdes, struct mq_attr *newattr,
*		struct mq_attr *oldattr);
*
*      This function fetches the arguments and data from VEMVA/VEHVA
*      using VE driver interface. It then offloads the functionality to
*      VH OS mq_getsetattr() system call.Updated buffers received from VH OS
*      are sent back to VEMVA using VE driver interface.
*
* @param syscall_num System call number.
* @param syscall_name System call name.
* @param handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_mq_getsetattr(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct mq_attr oldattr = {0};
	struct mq_attr newattr = {0};
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (0 > retval) {
		PSEUDO_ERROR("Failed to get argument. (%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* To handle mq_getattr library function */
	if (args[1]) {
		/* receive the new attributes from VE */
		if (0 > ve_recv_data(handle, args[1],
					sizeof(struct mq_attr),
					(uint64_t *)&newattr)) {
			retval = -EFAULT;
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &newattr : NULL,
			args[2] ? &oldattr : NULL);

	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}

	if (args[2]) {
		if (0 > ve_send_data(handle, args[2],
					sizeof(struct mq_attr), &oldattr)) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("syscall %s returned %d",
			SYSCALL_NAME, (int)retval);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the ioprio_set() system call functionality for VE.
 *
 *	int ioprio_set(int which, int who, int ioprio);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	ioprio_set() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_ioprio_set(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the ioprio_get() system call functionality for VE.
 *
 *	int ioprio_get(int which, int who);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	ioprio_get() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_ioprio_get(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the inotify_init() system call functionality for VE.
 *
 *	int inotify_init(void);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	inotify_init() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_inotify_init(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief handles inotify_add_watch() system call functionality for VE.
 *
 *	int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
 *
 *	This function fetches arguments from VEHVA/VEMVA and then invokes the
 *	VH OS inotify_add_watch() system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_inotify_add_watch(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	char *path_buff = NULL;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall argument %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (NULL != (void *)args[1]) {

		/* allocate memory to receive content of 2nd argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (path_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("path_buff: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);

		/* receive contents of 2nd argument */
		retval = ve_recv_string(handle, args[1],
				(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	retval = syscall(syscall_num, args[0], path_buff, args[2]);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
	} else {
		PSEUDO_DEBUG("%s syscall returned",
				SYSCALL_NAME);
	}

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the inotify_rm_watch() system call functionality for VE.
 *
 *	int inotify_rm_watch(int fd, int wd);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	inotify_rm_watch() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_inotify_rm_watch(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles openat() system call functionality for VE.
 *
 *	int openat(int dirfd, const char *pathname, int flags);
 *	int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as openat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_openat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mkdirat() system call functionality for VE.
 *
 *	int mkdirat(int dirfd, const char *pathname, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as mkdirat()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_mkdirat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mknodat() system call functionality for VE.
 *
 *	int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as mknodat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_mknodat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles fchownat() system call functionality for VE.
 *
 *	int fchownat(int dirfd, const char *pathname,
 *		uid_t owner, gid_t group, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as fchownat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_fchownat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mount() system call functionality for VE.
 *
 *	int futimesat(int dirfd, const char *pathname,
 *			const struct timeval times[2]);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using
 *	VE driver interface and then invokes VH OS futimesat() system call.
 *	It returns the return value of system call back to the VE process
 *	using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_futimesat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	struct timeval times[2] = { {0} };
	char *path_buff = NULL;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -ENOTDIR;
		goto hndl_return;
	}

	if (args[1]) {
		/* allocate memory to receive content of 2nd arguments */
		path_buff = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff == NULL) {
			PSEUDO_ERROR("Failed to create internal memory"
					" buffer");
			PSEUDO_DEBUG("In %s: calloc failed",
					SYSCALL_NAME);
			retval = -ENOTDIR;
			goto hndl_return;
		}

		/* receive contents of 2nd argument from VEMVA */
		retval = ve_recv_string(handle, args[1],
				(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("%s: Failed to receive string",
					SYSCALL_NAME);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* receive contents of 3rd argument from VEMVA */
		if (0 > ve_recv_data(handle, args[2],
					sizeof(times), &times)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -ENOTDIR;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], path_buff,
			args[2] ? &times : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned", SYSCALL_NAME);

hndl_return:
	if (path_buff != NULL)
		free(path_buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles newfstatat() system call functionality for VE.
 *
 *	int newfstatat(int dirfd, const char *pathname,
 *		struct stat *buf, int flags);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA using VE driver
 *	interface and then invokes the VH OS newfstatat() system call.
 *	Updated buffers received from VH OS are copied back to VEMVA using
 *	VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_newfstatat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct stat buffer = {0};
	char *pathname = NULL;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[1]) {
		/* allocate memory to receive path name */
		pathname = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == pathname) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("pathname: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(pathname, '\0', PATH_MAX);

		/* receive the path name */
		retval = ve_recv_string(handle, args[1],
				(char *)pathname, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], pathname,
				args[2] ? &buffer : NULL, args[3]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	if (args[2]) {

		/* send the filled stat_buf */
		if (0 > ve_send_data(handle, args[2],
				sizeof(struct stat), (uint64_t *)(&buffer))) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
		}
	}

hndl_return1:
	free(pathname);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles unlinkat() system call functionality for VE.
 *
 *	int unlinkat(int dirfd, const char *pathname, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as unlinkat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_unlinkat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles renameat() system call functionality for VE.
 *
 *	int renameat(int olddirfd, const char *oldpath,
 *		int newdirfd, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_int_p_char_int_p_char" as
 *	renameat() functionality for ve has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_renameat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles linkat() system call functionality for VE.
 *
 *	int linkat(int olddirfd, const char *oldpath,
 *		int newdirfd, const char *newpath, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char_int_p_char" as
 *	linkat() functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_linkat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles symlinkat() system call functionality for VE.
 *
 *	int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_int_p_char" as
 *	symlinkat() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_symlinkat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles readlinkat() system call functionality for VE.
 *
 *	int readlinkat(int dirfd, const char *pathname, char *buf,
 *		size_t bufsiz);
 *
 *	This function fetches arguments from VEHVA/ VEMVA using VE driver
 *	interface. It then invokes the VH OS readlinkat() system call.
 *	As the symlink name length is unknown , it uses "ve_recv_string" to
 *	fetch the same. Buffer(containig symbolic link data)
 *	received as output from VH OS system call is then copied back to VEMVA
 *	area using VE driver interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_readlinkat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *symlink = NULL;
	char *buffer = NULL;
	size_t recv_size = 0;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("failed to fetch syscall arguments, "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -ENOTDIR;
		goto hndl_return;
	}

	/* prepare buffer */
	recv_size = args[3];

	if(0 >= (int)recv_size){
                retval = -EINVAL;
                goto hndl_return;
        }

	/* allocate memory to send contents of 2nd argument */
	buffer = (char *)malloc(recv_size * sizeof(char));
	if (NULL == buffer) {
		retval = -ENOTDIR;
		PSEUDO_ERROR("Failed to create internel buffer");
		PSEUDO_DEBUG("buffer: malloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	}
	memset(buffer, '\0', recv_size);

	if (args[1]) {
		/* allocate memory for storing symbolic link name */
		symlink = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == symlink) {
			retval = -ENOTDIR;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return1;
		}
		memset(symlink, '\0', PATH_MAX);

		/* receive symlink name from VE side */
		retval = ve_recv_string(handle, args[1],
			(char *)symlink, PATH_MAX);
		if (0 > retval) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -ENOTDIR;
			goto hndl_return2;
		}
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0], symlink, buffer, recv_size);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return2;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	if (args[2]) {
		/* copy back obtained buffer to VE area */
		if (0 > ve_send_data(handle, args[2],
					recv_size, (uint64_t *)buffer)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			retval = -ENOTDIR;
			goto hndl_return2;
		}
	}
hndl_return2:
	free(symlink);
hndl_return1:
	free(buffer);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles fchmodat() system call functionality for VE.
 *
 *	int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as fchmodat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_fchmodat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles faccessat() system call functionality for VE.
 *
 *	int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as faccessat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */

ret_t ve_faccessat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles pselect6() system call functionality for VE.
*
*	int pselect6(int nfds, fd_set *readfds, fd_set *writefds,
*		fd_set *exceptfds, const struct timespec *timeout,
*			struct *data);
*
*	The final argument of the pselect6() system call is a
*	structure of the form:
*	struct {
*		const sigset_t *ss;(Pointer to signal set)
*		size_t	ss_len; (Size (in bytes) of object
*				pointed to by 'ss')
*	};
*
*	This function receives data and arguments from VEMVA/VEHVA using
*	VE driver interface and invokes VH OS pselect6() system call.
*	Buffered data from VH OS copied back to VE process using VE driver
*	interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_pselect6(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	ret_t ret = -1;
	uint64_t args[6] = {0};
	fd_set rfds = { {0} };
	fd_set wfds = { {0} };
	fd_set excptfds = { {0} };
	struct timespec tv = {0};
	sigset_t sigmask = { {0} };
	struct ve_signal_mask ve_mask = { { {0} } };
	long mask[2] = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("falied to fetch syscall argument %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&excptfds);

	/* Receive contents of 2nd, 3rd, 4th, 5th and 6th argument
	 * if not NULL.
	 */
	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(fd_set), (uint64_t *)(&rfds))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[2]) {
		if (0 > ve_recv_data(handle, args[2],
					sizeof(fd_set), (uint64_t *)(&wfds))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[3]) {
		if (0 > ve_recv_data(handle, args[3],
					sizeof(fd_set),
					(uint64_t *)(&excptfds))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[4]) {
		if (0 > ve_recv_data(handle, args[4],
					sizeof(struct timespec),
					(uint64_t *)(&tv))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[5]) {
		if (0 > ve_recv_data(handle, args[5],
					sizeof(mask),
					(uint64_t *)(mask))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed(%s) to receive"
					" %s argument[5]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		if (NULL != (void *)mask[0]) {
			/* receive value of sigmask */
			if (0 > ve_recv_data(handle, mask[0],
					sizeof(sigset_t), &sigmask)) {
				PSEUDO_ERROR("failed to receive data"
					" from VE memory");
				PSEUDO_DEBUG("Failed (%s) to receive"
					"sigmask value",
					strerror(errno));
				retval = -EFAULT;
				goto hndl_return;
			}
			sigdelset(&sigmask, SIGCONT);
			mask[0] = (long)&sigmask;
		}
	}

	memset(&ve_mask, 0, sizeof(struct ve_signal_mask));
	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	ve_mask.mask = true;
	ve_mask.how = SIG_SETMASK;
	memcpy(&ve_mask.newset, &sigmask, sizeof(sigset_t));

	retval = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d",	syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &rfds : NULL,
				args[2] ? &wfds : NULL,
				args[3] ? &excptfds : NULL,
				args[4] ? &tv : NULL,
				args[5] ? mask : NULL);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval) {
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 */
			retval = -VE_ENORESTART;
			ve_mask.store_mask = 1;
		}
		goto restore_sigmask;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* send buffered data from VH OS for 2nd, 3rd and 4th
	 * argument to VEMVA/VEHVA
	 */
	if (NULL != (void *)args[1]) {
		if (0 > ve_send_data(handle, args[1],
					sizeof(fd_set), &rfds)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto restore_sigmask;
		}
	}

	if (NULL != (void *)args[2]) {
		if (0 > ve_send_data(handle, args[2],
					sizeof(fd_set), &wfds)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[2]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto restore_sigmask;
		}
	}

	if (NULL != (void *)args[3]) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(fd_set), &excptfds)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto restore_sigmask;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);
restore_sigmask:
	/* Communicate with veos to restore signal mask
	 * */
	memcpy(&ve_mask.newset, &ve_mask.oldset, sizeof(sigset_t));
	ret = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}
	ret = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d", syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles ppoll() system call functionality for VE.
*
*	int ppoll(struct pollfd *fds, nfds_t nfds,
*			const struct timespec *timeout_ts,
*				const sigset_t *sigmask);
*
*	This function receives data and arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS ppoll() system call. Buffered data
*	from VH OS copied back to VE process using VE driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_ppoll(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1, ret = -1;
	uint64_t args[5] = {0};
	struct pollfd *pfd = NULL;
	struct timespec tms = {0};
	struct ve_signal_mask ve_mask = { { {0} } };
	sigset_t mask = { {0} };
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("vedl_get_syscall_args is failed %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	memset(&ve_mask, 0, sizeof(struct ve_signal_mask));

	if ((args[0]) && ((int)args[1] > 0)) {
		/* allocate memory for contents of 1st argument */
		pfd = (struct pollfd *)malloc(args[1] * sizeof(struct pollfd));
		if (pfd == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("pfd: malloc %s failed",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(pfd, '\0', args[1] * sizeof(struct pollfd));

		if (0 > ve_recv_data(handle, args[0],
					args[1] * sizeof(struct pollfd), pfd)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[0]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		if (0 > ve_recv_data(handle, args[2],
					sizeof(struct timespec), &tms)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[3]) {
		if (0 > ve_recv_data(handle, args[3],
					sizeof(sigset_t), &mask)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		sigdelset(&mask, SIGCONT);
	}

	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	ve_mask.mask = true;
	ve_mask.how = SIG_SETMASK;
	memcpy(&ve_mask.newset, &mask, sizeof(sigset_t));

	retval = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d",	syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, pfd, args[1], args[2] ? &tms : NULL,
			args[3] ? &mask : NULL, args[4]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval for syscall*/
	if (-1 == retval) {
		retval = -errno;
		if (EINTR == -retval) {
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 */
			retval = -VE_ENORESTART;
			ve_mask.store_mask = 1;
		}
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		/* Post-processing of syscall started, blocking signals */
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto restore_sigmask;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[0] && (args[1] > 0)) {
		if (0 > ve_send_data(handle, args[0],
				args[1] *  sizeof(struct pollfd), pfd)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[0]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto restore_sigmask;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

restore_sigmask:
	/* Communicate with veos to restore signal mask
	 * */
	memcpy(&ve_mask.newset, &ve_mask.oldset, sizeof(sigset_t));
	ret = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}
	ret = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d", syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}

hndl_return:
	if (pfd != NULL)
		free(pfd);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles splice() system call functionality for VE.
 *
 *	ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
 *			loff_t *off_out, size_t len, unsigned int flags);
 *
 *	This function fetches the arguments from VEHVA/VEMVA using VE driver
 *	interface and then invokes the VH OS splice() system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_splice(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	size_t recv_size = 0;
	uint64_t args[6] = {0};
	loff_t *read_off1 = NULL, *read_off2 = NULL;

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (0 > retval) {
		PSEUDO_ERROR("Fetching (%s) arguments failed and returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* receive buffer size from ve memory */
	recv_size = args[4];

	if (NULL != (void *)args[1]) {

		/* allocate memory for offset1 */
		read_off1 = (loff_t *)malloc(sizeof(loff_t));
		if (read_off1 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("read_off1: malloc (%s) failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(read_off1, '\0', sizeof(loff_t));

		/* receive the offset from VE memory */
		if (0 > ve_recv_data(handle, args[1],
				sizeof(loff_t), (uint64_t *)read_off1)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[3]) {

		/* allocate memory for offset2 */
		read_off2 = (loff_t *)malloc(sizeof(loff_t));
		if (read_off2 == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("read_off2: malloc (%s) failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(read_off2, '\0', sizeof(loff_t));

		/* receive the offset from VE memory */
		if (0 > ve_recv_data(handle, args[3],
				sizeof(loff_t), (uint64_t *)read_off2)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[3]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], read_off1, args[2],
			read_off2, recv_size, args[5]);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("syscall (%s) failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall (%s) success %d",
				SYSCALL_NAME, (int)retval);
	}

	/* send modified read_off1 value at VE side */
	if (args[1]) {
		if (0 > ve_send_data(handle, args[1],
					sizeof(loff_t), read_off1)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[1]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* send modified read_off2 value at VE side */
	if (args[3]) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(loff_t), read_off2)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send args[3]",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

hndl_return:
	if (NULL != read_off1)
		free(read_off1);

	if (NULL != read_off2)
		free(read_off2);
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the tee() system call functionality for VE.
*
*	ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
*
*	This function uses generic handler "ve_generic_offload" as tee()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_tee(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles sync_file_range() system call functionality for VE.
*
*	int sync_file_range(int fd, off64_t offset, off64_t nbytes,
*				unsigned int flags);
*
*	This function uses generic handler "ve_generic_offload" as
*	sync_file_range functionality for VE has common pre and post
*	processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_sync_file_range(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles vmsplice() system call for VE.
*
*	ssize_t vmsplice(int fd, const struct iovec *iov,
*			unsigned long nr_segs, unsigned int flags);
*
*	This function receives the data and arguments from VEMVA/VEHVA using
*	VE driver interface and offloads the functionality to VH OS vmsplice()
*	system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_vmsplice(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct iovec *vh_iov = NULL;
	struct iovec *ve_iov = NULL;
	unsigned long nr_segs = 0;
	int fd, i = 0;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* receive count of ranges of user memory from VE memory */
	nr_segs = args[2];
	if (nr_segs > UIO_MAXIOV) {
		retval = -EINVAL;
		goto hndl_return;
	} else if (!nr_segs) {
		retval = 0;
		goto hndl_return;
	}
	PSEUDO_DEBUG("VE buffer count : %lu", nr_segs);

	fd = fcntl(args[0], F_GETFL);
	if (fd == -1) {
		retval = -EBADF;
		goto hndl_return;
	}

	if (NULL != (void *)args[1]) {
		/* local memory buffer to store vmsplice() struct iovec data */
		vh_iov = (struct iovec *)malloc(nr_segs * sizeof(struct iovec));
		ve_iov = (struct iovec *)malloc(nr_segs * sizeof(struct iovec));
		if ((NULL == vh_iov) || (NULL == ve_iov)) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_iov/ve_iov: malloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(vh_iov, '\0', (nr_segs * sizeof(struct iovec)));
		memset(ve_iov, '\0', (nr_segs * sizeof(struct iovec)));

		/* receive vmsplice() struct iovec*  from VE memory */
		if (0 > ve_recv_data(handle, args[1],
					(nr_segs * sizeof(struct iovec)),
					(uint64_t *)(vh_iov))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}

		/* store ve buffer addresses */
		memcpy(ve_iov, vh_iov, (nr_segs * sizeof(struct iovec)));

		/*create VH environment for vmsplice() */
		for (i = 0; i < nr_segs; i++) {
			PSEUDO_DEBUG("VE data: buff: %d length :%lu data:%lu",
					i, (unsigned long)(vh_iov[i].iov_len),
					(unsigned long)vh_iov[i].iov_base);

			if (vh_iov[i].iov_len > MAX_RW_COUNT)
				vh_iov[i].iov_len = MAX_RW_COUNT;

			if ((NULL != (void *)vh_iov[i].iov_base) &&
					(0 != vh_iov[i].iov_len)) {

				vh_iov[i].iov_base = (uint64_t *)malloc
					((vh_iov[i].iov_len) * sizeof(char));
				if ((void *)vh_iov[i].iov_base == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						"internel buffer");
					PSEUDO_DEBUG("malloc fail for buffer"
							" %d",
							i+1);
					goto hndl_return1;
				}

				if (fd == 1) {
					if (0 > ve_recv_data(handle,
						(uint64_t)(ve_iov[i].iov_base),
						(ve_iov[i].iov_len*sizeof(char)),
						(uint64_t *)(vh_iov[i].iov_base))) {
						PSEUDO_ERROR("failed to"
							" receive data"
							" from VE memory");
						PSEUDO_DEBUG("Failed (%s) to"
							" receive"
							" %s argument[%d]",
							strerror(errno),
							SYSCALL_NAME, i);
						retval = -EFAULT;
						goto hndl_return1;
					}
				}
			}
		}
	}

	/*call VH system call */
	retval = syscall(syscall_num, args[0], vh_iov, nr_segs, args[3]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
					strerror(errno));
		goto hndl_return1;
	}

	if (fd == 0 && (void *)args[1]) {
		for (i = 0; i < nr_segs; i++) {
			if (0 > ve_send_data(handle, (uint64_t)ve_iov[i].iov_base,
					vh_iov[i].iov_len, vh_iov[i].iov_base)) {
				retval = -EFAULT;
				PSEUDO_ERROR("Failed to send data to VE memory");
				PSEUDO_DEBUG("%s Failed(%s) to send vh_iov[%d] data",
						SYSCALL_NAME, strerror(errno), i);
				break;
			}
		}
	}


	/* cleaning local storage */
hndl_return1:
	if (NULL != vh_iov)
	{
		for (i = 0; i < nr_segs; i++)
			if (vh_iov[i].iov_base != NULL)
				free(vh_iov[i].iov_base);

	        free(vh_iov);
		vh_iov = NULL;
	}
	free(ve_iov);
	ve_iov = NULL;
hndl_return:
	if (vh_iov != NULL)
		free(vh_iov);
	if (NULL != ve_iov)
		free(ve_iov);
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles utimensat() system call functionality for VE.
*
*	int utimensat(int dirfd, const char *pathname,
*		const struct timespec times[2], int flags);
*
*	This function fetches arguments from VEHVA/VEMVA and then invokes the
*	VH OS utimensat() system call.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return system call value to VE process.
*/
ret_t ve_utimensat(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timespec vh_times[2] = { {0} };
	char *file_name = NULL;
	uint64_t args[4] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (0 > retval) {
		PSEUDO_ERROR("Get arguments failed.(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive file name */
	if (NULL != (void *)args[1]) {
		file_name = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == file_name) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("file_name: malloc %s failed %s",
				SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}
		memset(file_name, '\0', PATH_MAX);

		/* receive the file name */
		retval = ve_recv_string(handle, args[1],
				(char *)file_name, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string"
					" (%s) returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* receive struct timespec from VE memory */
	if (NULL != (void *)args[2]) {
		if (0 > ve_recv_data(handle, args[2],
					(sizeof(vh_times)),
					(uint64_t *)(vh_times))) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* call VH system call if 3rd argument is not NULL */
		retval = syscall(syscall_num, args[0],
				file_name, vh_times, args[3]);
	} else {
		/* call VH system call if 3rd argument is NULL */
		retval = syscall(syscall_num, args[0],
				file_name, args[2], args[3]);
	}

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", SYSCALL_NAME,
				strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}
	/* cleaning local storage */
hndl_return1:
	free(file_name);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles the epoll_pwait() system call functionality for VE.
*
*	int epoll_pwait(int epfd, struct epoll_event *events,
*		int maxevents, int timeout, const sigset_t *sigmask);
*
*	This function receives data and arguments from VEMVA/VEHVA using
*	VE driver interface and invokes VH OS epoll_pwait() system call.
*	Updated buffers returned from VH OS are copied back to the VEMVA
*	using VE driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_epoll_pwait(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[6] = {0};
	ret_t ret = -1;
	int maxevents;
	sigset_t sigmask = { {0} };
	struct epoll_event *ve_event = NULL;
	struct ve_signal_mask ve_mask = { { {0} } };
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments,%s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	maxevents = args[2];

	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
	{
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[1]) {
		/**allocate memory to receive list of events from kernel
		 * and then send it to VEMVA/VEHVA
		 */
		ve_event = (struct epoll_event *)
			malloc(maxevents * sizeof(struct epoll_event));
		if (ve_event == NULL) {
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("ve_event: malloc failed for args[2]");
			retval = -EFAULT;
			goto hndl_return;
		}
		memset(ve_event, '\0', maxevents * sizeof(struct epoll_event));
	}

	if (args[4]) {
		/* receive sigmask data */
		if (0 > ve_recv_data(handle, (uint64_t)args[4],
					args[5], (void *)&sigmask)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" sigmask from ve",
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
		sigdelset(&sigmask, SIGCONT);
	}

	memset(&ve_mask, 0, sizeof(struct ve_signal_mask));
	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	ve_mask.mask = true;
	ve_mask.how = SIG_SETMASK;
	memcpy(&ve_mask.newset, &sigmask, sizeof(sigset_t));

	retval = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d",	syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], ve_event, maxevents,
				args[3], args[4] ? &sigmask : NULL, args[5]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			ve_mask.store_mask = 1;
		goto restore_sigmask;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[1]) {
		/* send event list buffered by VH kernel
		 * to VEMVA/VEHVA
		 */
		if (0 > ve_send_data(handle, args[1],
				maxevents * sizeof(struct epoll_event),
						ve_event)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send list of events",
					SYSCALL_NAME, strerror(errno));
			retval = -EFAULT;
			goto restore_sigmask;
		}
	}

	PSEUDO_DEBUG("%s syscall returned with %d",
				SYSCALL_NAME, (int)retval);
restore_sigmask:

	/* Communicate with veos to restore signal mask */
	memcpy(&ve_mask.newset, &ve_mask.oldset, sizeof(sigset_t));
	ret = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}
	ret = pseudo_psm_recv_sigprocmask_ack(&ve_mask,
			handle->veos_sock_fd);
	if (0 > (int)ret) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
			" returned %d", syscall_name, (int)ret);
		retval = -EFAULT;
		goto hndl_return;
	}

hndl_return:
	if (ve_event != NULL)
		free(ve_event);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles timerfd_create() system call functionality for VE.
 *
 *	int timerfd_create(int clockid, int flags);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	timerfd_create() functionality uses common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_timerfd_create(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the eventfd() system call functionality for VE.
 *
 *	int eventfd(unsigned int initval, int flags);
 *
 *	This function uses generic handler "ve_generic_offload" as eventfd()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_eventfd(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the fallocate() system call functionality for VE.
 *
 *	int fallocate(int fd, int mode, off_t offset, off_t len);
 *
 *	This function uses generic handler "ve_generic_offload" as fallocate()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_fallocate(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles timerfd_settime() system call functionlity for VE.
 *
 *	int timerfd_settime(int fd, int flags,
 *		const struct itimerspec *new_value,
 *			struct itimerspec *old_value);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS timerfd_settime() system call.
 *	Buffered data from VH OS is sent back to the VE process using VE
 *	driver interface. It also returns the return value of system call
 *	back to the VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_timerfd_settime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	struct itimerspec new = { {0} };
	struct itimerspec old = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (NULL != (void *)args[2]) {
		/* receive contents of 3rd arguments */
		if (0 > ve_recv_data(handle, args[2],
					sizeof(struct itimerspec), &new)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* Call VH system call */
	retval = syscall(syscall_num, args[0], args[1],
		args[2] ? &new : NULL, args[3] ? &old : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	/* send contents of 4th argument */
	if (NULL != (void *)args[3]) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(struct itimerspec), &old)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
					" memory args[3]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall is returned successfully",
			SYSCALL_NAME);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles timerfd_gettime() system call functionality for VE.
 *
 *      int timerfd_gettime(int fd, struct itimerspec *curr_value);
 *
 *      This function receives arguments from VEMVA/VEHVA using VE driver
 *      interface and invokes VH OS timerfd_gettime() system call.
 *      Buffered data from VH OS is copied back to VE process using VE driver
 *      interface. It also returns the return value of system call back to
 *      VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_timerfd_gettime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2] = {0};
	struct itimerspec curr_value = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Call VH system call */
	retval = syscall(syscall_num, args[0], args[1] ? &curr_value : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	if (NULL != (void *)args[1]) {

		/* send timer value to ve process */
		if (0 > ve_send_data(handle, args[1],
				sizeof(struct itimerspec),
					&curr_value)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
					" memory args[1]", SYSCALL_NAME,
						strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles accept4() system call functionality for VE.
*
*	int accept4(int sockfd, struct sockaddr *addr,
*				socklen_t *addrlen, int flags);
*
*	This function uses generic handler "do_accept" as accept4()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num: System call number
* @param[in] syscall_name: System call name
* @param[in] handle: Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_accept4(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return do_accept(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the eventfd2() system call functionality for VE.
 *
 *	int eventfd2(unsigned int count, int flags);
 *
 *	This function uses generic handler "ve_generic_offload" as eventfd2()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_eventfd2(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles the epoll_create1() system call functionlity for VE.
*
*	int epoll_create1(int flags);
*
*	This function uses generic handler "ve_generic_offload" as epoll_create1
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle Handler for VE driver interface
*
* @return system call value to VE process.
*/
ret_t ve_epoll_create1(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles dup3() system call functionality for VE.
 *
 *	int dup3(int oldfd, int newfd, int flags);
 *
 *	This function uses "ve_generic_dup" handler as
 *	dup3() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_dup3(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_dup(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pipe2() system call functionality for VE.
 *
 *	int pipe2(int pipefd[2], int flags);
 *
 *	This function uses same handler "ve_pipe" as pipe2()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_pipe2(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_pipe(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles the inotify_init1() system call functionality for VE.
 *
 *	int inotify_init1(int flags);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	inotify_init1() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_inotify_init1(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles preadv() system call for VE.
 *
 *	ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
 *		off_t offset);
 *
 *	This function uses generic handler "ve_hndl_readv_preadv" as preadv()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 *
 */
ret_t ve_preadv(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_readv_preadv(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pwritev() system call for VE.
 *
 *	ssize_t pwritev(int fd, const struct iovec *iov,
 *		int iovcnt, off_t offset);
 *
 *	This function uses generic handler "ve_hndl_writev_pwritev" as pwritev()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_pwritev(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_writev_pwritev(syscall_num, syscall_name, handle);
}

/**
* @brief Handles recvmmsg() system call functionality for VE.
*
*	int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
*			unsigned int flags, struct timespec *timeout);
*
*	This function receives data and arguments from VEMVA/VEHVA using VE
*	driver interface and invokes VH OS recvmmsg() system call. Buffered
*	data from VH copied back to the VE process using VE driver interface.
*
* @param[in] syscall_num System call number
* @param[in] syscall_name System call name
* @param[in] handle VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_recvmmsg(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};
	struct mmsghdr *ve_hdr = NULL, *vh_hdr = NULL;
	char *msg_name = NULL, *msg_ctl = NULL;
	size_t iov_len = 0, ctl_len = 0, msg_iovlen = 0;
	struct iovec *vh_iov = NULL;
	struct timespec timeout = {0};
	unsigned int vlen = 0;
	size_t len = 0;
	int i = 0, k = 0;
	int socktype_max = SOCK_PACKET+1;
	int sock_type = socktype_max, length = sizeof(int);
	socklen_t name_len = 0;
	sigset_t signal_mask = { {0} };

	struct iov_data {
		struct iovec *ve_iov;
	};
	struct iov_data *iov = NULL;

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	(void)getsockopt(args[0], SOL_SOCKET, SO_TYPE, &sock_type, (socklen_t *)&length);

	/* check for NULL for args[1] */
	if ((void *)args[1] == NULL) {
		PSEUDO_ERROR("pointer to array of msghdr is NULL");
		return -EFAULT;
	}

	vlen = args[2];
	iov = (struct iov_data *)malloc(vlen * sizeof(struct iov_data));
	if (iov == NULL) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internel buffer");
		PSEUDO_DEBUG("iov: malloc %s failed", SYSCALL_NAME);
		goto hndl_return;
	}
	memset(iov, '\0', vlen * sizeof(struct iov_data));

	/**
	 * allocate memory to vh_hdr for storing
	 * data from socket
	 */
	vh_hdr = (struct mmsghdr *)malloc(vlen * sizeof(struct mmsghdr));
	if (vh_hdr == NULL) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internel buffer");
		PSEUDO_DEBUG("vh_hdr: malloc %s failed", SYSCALL_NAME);
		goto hndl_return;
	}
	memset(vh_hdr, '\0', vlen * sizeof(struct mmsghdr));

	/**
	 * allocate memory to ve_hdr for storing ve pointer ]
	 * values on which later message will be sent to VE.
	 */
	ve_hdr = (struct mmsghdr *)malloc
		(vlen * sizeof(struct mmsghdr));
	if (ve_hdr == NULL) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create internel buffer");
		PSEUDO_DEBUG("ve_hdr: malloc %s failed", SYSCALL_NAME);
		goto hndl_return;
	}
	memset(ve_hdr, '\0', vlen * sizeof(struct mmsghdr));

	if (0 > ve_recv_data(handle, (uint64_t)args[1],
				vlen * sizeof(struct mmsghdr),
				ve_hdr)) {
		PSEUDO_ERROR("failed to receive data"
					" from VE memory");
		PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
		retval = -EFAULT;
		goto hndl_return;
	}

	while (len < vlen) {

		name_len = ve_hdr[len].msg_hdr.msg_namelen;

		if (((int)ve_hdr[0].msg_hdr.msg_namelen < 0) &&
				(ve_hdr[0].msg_hdr.msg_name != NULL)) {
			retval = -EINVAL;
			goto hndl_return;
		}

		if ((sock_type == SOCK_DGRAM) && (name_len > 0)) {
			if (ve_hdr[0].msg_hdr.msg_name &&
				ve_is_valid_address(handle,
				(uint64_t)ve_hdr[0].msg_hdr.msg_name)) {
				retval = -EFAULT;
				goto hndl_return;
			}
		}

		if (ve_hdr[len].msg_hdr.msg_name && name_len) {
			msg_name = (char *)malloc(name_len * sizeof(char));
			if (msg_name == NULL) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internel"
						" buffer");
				PSEUDO_DEBUG("msg_name: malloc %s fail for"
						" msg_name",
						SYSCALL_NAME);
				goto hndl_return;
			}
			memset(msg_name, '\0', name_len * sizeof(char));

			vh_hdr[len].msg_hdr.msg_name = msg_name;
			vh_hdr[len].msg_hdr.msg_namelen = name_len;
		} else {
			vh_hdr[len].msg_hdr.msg_name = NULL;
			vh_hdr[len].msg_hdr.msg_namelen = name_len;
		}

		ctl_len = ve_hdr[len].msg_hdr.msg_controllen;
		if (ve_hdr[len].msg_hdr.msg_control) {
			msg_ctl = (char *)malloc(ctl_len * sizeof(char));
			if (msg_ctl == NULL) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internel"
						" buffer");
				PSEUDO_DEBUG("msg_ctl: malloc %s fail for"
						" msg_ctl",
						SYSCALL_NAME);
				goto hndl_return;
			}
			memset(msg_ctl, '\0', ctl_len * sizeof(char));

			vh_hdr[len].msg_hdr.msg_control = msg_ctl;
			vh_hdr[len].msg_hdr.msg_controllen = ctl_len;
		} else {
			vh_hdr[len].msg_hdr.msg_control = NULL;
			vh_hdr[len].msg_hdr.msg_controllen = ctl_len;
		}

		if (ve_hdr[len].msg_hdr.msg_iov != NULL) {
			msg_iovlen = ve_hdr[len].msg_hdr.msg_iovlen;
			iov[len].ve_iov = (struct iovec *)malloc
				(msg_iovlen * sizeof(struct iovec));
			if (iov[len].ve_iov == NULL) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internel"
						" buffer");
				PSEUDO_DEBUG("iov[%d] malloc %s failed",
						(int)len, SYSCALL_NAME);
				goto hndl_return;
			} else {
				memset(iov[len].ve_iov, '\0',
					msg_iovlen * sizeof(struct iovec));
				if (0 > ve_recv_data(handle,
					(uint64_t)ve_hdr[len].msg_hdr.msg_iov,
					msg_iovlen * sizeof(struct iovec),
					iov[len].ve_iov)) {
					PSEUDO_ERROR("failed to receive data"
						" from VE memory");
					PSEUDO_DEBUG("Failed (%s) to receive"
					" %s structure specific(msg_iov) data",
					strerror(errno), SYSCALL_NAME);
					retval = -EFAULT;
					goto hndl_return;
				}
			}

			vh_iov = (struct iovec *)malloc
				(msg_iovlen * sizeof(struct iovec));
			if (vh_iov == NULL) {
				retval = -errno;
				PSEUDO_ERROR("Failed to create internel"
						" buffer");
				PSEUDO_DEBUG("vh_iov: malloc %s failed",
						SYSCALL_NAME);
				goto hndl_return;
			}
			memset(vh_iov, '\0',
					msg_iovlen * sizeof(struct iovec));

			/* allocate buffers to store message data */
			vh_hdr[len].msg_hdr.msg_iov = vh_iov;
			vh_hdr[len].msg_hdr.msg_iovlen = msg_iovlen;
			for (i = 0; i < msg_iovlen; i++) {
				iov_len = iov[len].ve_iov[i].iov_len;

				if ((int)iov_len < 0) {
					retval = -EINVAL;
					goto hndl_return;
				}

				if (iov[len].ve_iov[i].iov_base != NULL) {
					vh_iov[i].iov_base = (char *)calloc
						(iov_len, sizeof(char));
					if (vh_iov[i].iov_base == NULL) {
						retval = -errno;
						PSEUDO_ERROR("Failed to cre"
						"ate internal memory buffer");
						PSEUDO_DEBUG("vh_iov[%d]: call"
							"oc %s failed", i,
							SYSCALL_NAME);
						goto hndl_return;
					}
					vh_iov[i].iov_len = iov_len;
				} else {
					vh_iov[i].iov_base = NULL;
					vh_iov[i].iov_len = iov_len;
				}
			}
		}
		len++;
	}

	if (args[4]) {
		if (0 > ve_recv_data(handle, (uint64_t)args[4],
					sizeof(struct timespec), &timeout)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[4]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/**
	 * unblock all signals except the one actualy
	 * blocked by VE process
	 */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, args[0], vh_hdr, args[2],
			args[3], args[4] ? &timeout : NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (retval < 0) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 */
			retval = -VE_ENORESTART;
		goto hndl_return;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* send required data to VEMVA/VEHVA */
	len = 0;
	/* Here retval is the number of datagrams received successfully.
	 ** Therefore looping against it while sending the data back to VE.
	 */
	while (len < retval) {
		if (ve_hdr[len].msg_hdr.msg_name && name_len) {
			if (0 == ve_is_valid_address(handle,
					(uint64_t)ve_hdr[len].
					msg_hdr.msg_name) &&
					(sock_type == SOCK_DGRAM)) {
				if (0 > ve_send_data(handle, (uint64_t)
							ve_hdr[len].
							msg_hdr.msg_name,
							vh_hdr[len].
							msg_hdr.msg_namelen,
							vh_hdr[len].
							msg_hdr.msg_name)) {
					PSEUDO_ERROR("Failed to send data to"
							" VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send"
						" data to VE"
						" memory msg_name",
						SYSCALL_NAME,
						strerror(errno));
					retval = -EFAULT;
					goto hndl_return;
				}
			}
		}

		if (ve_hdr[len].msg_hdr.msg_control) {
			/* check whether VE address is valid or invalid */
			if (0 == ve_is_valid_address(handle,
					(uint64_t)ve_hdr[len].msg_hdr.
					msg_control)) {
				if (0 > ve_send_data(handle, (uint64_t)
							ve_hdr[len].
							msg_hdr.msg_control,
							vh_hdr[len].
							msg_hdr.msg_controllen,
							vh_hdr[len].
							msg_hdr.
							msg_control)) {
					PSEUDO_ERROR("Failed to send data to"
							" VE memory");
					PSEUDO_DEBUG("%s Failed(%s) to send"
							" data to VE"
							" memory msg_control",
							SYSCALL_NAME,
							strerror(errno));
					retval = -EFAULT;
					goto hndl_return;
				}
			}
		}

		msg_iovlen = ve_hdr[len].msg_hdr.msg_iovlen;

		/* send message data to VEMVA */
		if (ve_hdr[len].msg_hdr.msg_iov) {
			for (i = 0; i < msg_iovlen; i++) {
				if (iov[len].ve_iov[i].iov_base != NULL) {
					if (0 > ve_send_data(handle, (uint64_t)
						iov[len].ve_iov[i].iov_base,
						iov[len].ve_iov[i].iov_len,
						vh_hdr[len].msg_hdr
						.msg_iov[i].iov_base)) {
						PSEUDO_ERROR("Failed to send"
						" data to VE memory");
						retval = -EFAULT;
						goto hndl_return;
					}
				}
			}
		}
		len++;
	}
	/**
	 * send array of mmsghdr struct to update
	 * value of second elements of struct mmsghdr
	 */
	for (i = 0; i < vlen; i++) {
		ve_hdr[i].msg_len = vh_hdr[i].msg_len;
		ve_hdr[i].msg_hdr.msg_namelen = vh_hdr[i].msg_hdr.msg_namelen;
		ve_hdr[i].msg_hdr.msg_flags = vh_hdr[i].msg_hdr.msg_flags;
		ve_hdr[i].msg_hdr.msg_controllen
				= vh_hdr[i].msg_hdr.msg_controllen;
	}

	if (0 > ve_send_data(handle, args[1],
				vlen * sizeof(struct mmsghdr),
				ve_hdr)) {
		PSEUDO_ERROR("Failed to send data to VE memory");
		PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
				" memory args[1]", SYSCALL_NAME,
				strerror(errno));
		retval = -EFAULT;
		goto hndl_return;
	}
	PSEUDO_DEBUG("%s syscall returned with %d",
			SYSCALL_NAME, (int)retval);

hndl_return:
	/* clean all the acquired memory */
	if (vh_hdr) {
		for (i = 0; i < vlen; i++) {
			if (iov) {
				if (iov[i].ve_iov != NULL)
					free(iov[i].ve_iov);
			}
			if (NULL != (void *)&vh_hdr[i].msg_hdr) {
				vh_iov = vh_hdr[i].msg_hdr.msg_iov;
				len = vh_hdr[i].msg_hdr.msg_iovlen;
				if (NULL != vh_iov) {
					for (k = 0; k < len; k++)
						free(vh_iov[k].iov_base);

					free(vh_iov);
				}
				free(vh_hdr[i].msg_hdr.msg_name);
				free(vh_hdr[i].msg_hdr.msg_control);

			}
		}
	}
	free(vh_hdr);
	free(ve_hdr);
	free(iov);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles fanotify_init() system call functionality for VE.
 *
 *	int fanotify_init(unsigned int flags, unsigned int event_f_flags);
 *
 *	This function uses generic handler "ve_generic_offload" as
 *	fanotify_init() functionality for ve has common pre and post
 *	processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_fanotify_init(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief handles fanotify_mark() system call functionality for VE.
 *
 *	int fanotify_mark(int fanotify_fd, unsigned int flags,
 *			uint64_t mask, int dirfd, const char *pathname);
 *
 *	This function receives data and arguments from VEMVA/VEHVA using VE
 *	driver interface and invokes VH OS fanotify_mark() system call.
 *	It returns the return value of system call back to the VEMVA using
 *	VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_fanotify_mark(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};
	char *path_buff = NULL;

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments,%s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EINVAL;
		goto hndl_return;
	}

	if ((void *)args[4] != NULL) {

		/* allocate memory to receive content of 1st argument */
		path_buff = (char *)calloc(PATH_MAX, sizeof(char));
		if (path_buff == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internal"
					" memory buffer");
			PSEUDO_DEBUG("path_buff: calloc %s failed %s",
					SYSCALL_NAME, strerror(errno));
			goto hndl_return;
		}

		/* receive contents of 1st argument */
		retval = ve_recv_string(handle, args[4],
				(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EINVAL;
			goto hndl_return;
		}
	}

	retval = syscall(syscall_num, args[0], args[1], args[2], args[3],
			args[4] ? path_buff : NULL);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall failed",
				SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall returned successfully",
			SYSCALL_NAME);

hndl_return:
	if (path_buff != NULL)
		free(path_buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief handles name_to_handle_at() system call functionality for VE.
*
* int name_to_handle_at(int dirfd, const char *pathname,
*				struct file_handle *handle,
*				int *mount_id, int flags);
*
* @param[in] syscall_num: System call number
* @param[in] syscall_name: System call name
* @param[in] handle: VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_name_to_handle_at(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};
	char *path_buff = NULL;
	int mount_id = 0;
	unsigned int hb = 0;
	struct file_handle fh = {0};
	struct file_handle *f_handle = NULL;

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if ((void *)args[1] != NULL) {
		/* allocate buffer to store content of 2nd argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (path_buff == NULL) {
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("In %s malloc failed", SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX * sizeof(char));

		/* fetch content of 2nd argument */
		retval = ve_recv_string(handle, args[1], path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive string %s returned %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return;
		}
	}

	if ((void *)args[2] != NULL) {
		if (0 > ve_recv_data(handle, args[2],
				sizeof(struct file_handle), &fh)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[2]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}

		if (fh.handle_bytes > MAX_HANDLE_SZ) {
			retval = -EINVAL;
			goto hndl_return;
		}

		f_handle = malloc(fh.handle_bytes + sizeof(struct file_handle));
		if (f_handle == NULL) {
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("f_handle: malloc failed for file_handle");
			retval = -EFAULT;
			goto hndl_return;
		}
		memset(f_handle, '\0',
			(fh.handle_bytes + sizeof(struct file_handle)));

		f_handle->handle_bytes = fh.handle_bytes;
		f_handle->handle_type = fh.handle_type;
	}

	retval = syscall(syscall_num, args[0], path_buff,
			f_handle, &mount_id, args[4]);
	if (retval == -1) {

		/* EOVERFLOW is returned by kernel in two cases as follows
		 *	1. When handle_bytes is zero
		 *	2. handle_bytes is less then the actual size of f_handle
		 * Hence when kernel returns EOVERFLOW we need to invoke
		 * ve_send_data() to send the updated handle_bytes returned
		 * by kernel on VE side.
		 * */
		if (errno != EOVERFLOW) {
			retval = -errno;
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
					" memory args[0]", SYSCALL_NAME,
					strerror(errno));
			goto hndl_return;
		} else {
			retval = -errno;
		}
	}

	if ((fh.handle_bytes == 0)
			|| ((void *)args[2] && (fh.handle_bytes
				< f_handle->handle_bytes)))
		hb = 0;
	else if ((void *)args[2])
		hb = f_handle->handle_bytes;
	else // do nothing
		;

	if ((void *)args[2] != NULL) {
		if (0 > ve_send_data(handle, args[2],
					hb + sizeof(struct file_handle),
					f_handle)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
					" memory args[2]", SYSCALL_NAME,
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* send mount_id */
	if ((void *)args[3] != NULL) {
		if (0 > ve_send_data(handle, args[3],
					sizeof(int), &mount_id)) {
			PSEUDO_ERROR("Failed to send data to VE memory");
			PSEUDO_DEBUG("%s Failed(%s) to send data to VE"
					" memory args[3]", SYSCALL_NAME,
					strerror(errno));
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	PSEUDO_DEBUG("%s syscall is returned", SYSCALL_NAME);

hndl_return:
	if (f_handle != NULL)
		free(f_handle);
	if (path_buff != NULL)
		free(path_buff);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief handles open_by_handle_at() system call functionality for VE.
*
* int open_by_handle_at(int mount_fd, struct file_handle *handle,
*                              int flags);
*
* @param[in] syscall_num: System call number
* @param[in] syscall_name: System call name
* @param[in] handle: VEOS handle
*
* @return system call value to VE process
*/
ret_t ve_open_by_handle_at(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	struct file_handle fh = {0};
	struct file_handle *f_handle = NULL;

	PSEUDO_TRACE("Entering");
	/* get syscall arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive content of file handle structure */
	if ((void *)args[1] != NULL) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(struct file_handle), &fh)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}

		if ((fh.handle_bytes == 0) || (fh.handle_bytes > MAX_HANDLE_SZ)) {
			retval = -EINVAL;
			goto hndl_return;
		}

		f_handle = (struct file_handle *)malloc
				(fh.handle_bytes + sizeof(struct file_handle));
		if (f_handle == NULL) {
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("f_handle: malloc failed for file_handle");
			retval = -EFAULT;
			goto hndl_return;
		}
		memset(f_handle, '\0',
			(fh.handle_bytes + sizeof(struct file_handle)));

		if (0 > ve_recv_data(handle, args[1], fh.handle_bytes +
						sizeof(struct file_handle),
						f_handle)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s file handle from VE",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* call VH kernel */
	retval = syscall(syscall_num, args[0], f_handle, args[2]);
	if (retval == -1) {
		retval = -errno;
		PSEUDO_ERROR("%s syscall is failed", SYSCALL_NAME);
		goto hndl_return;
	}

	PSEUDO_DEBUG("%s syscall is returned", SYSCALL_NAME);

hndl_return:
	if (f_handle != NULL)
		free(f_handle);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the syncfs() system call functionality for VE.
 *
 *	int syncfs(int fd);
 *
 *	This function uses generic handler "ve_generic_offload" as syncfs()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_syncfs(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief handles sendmmsg() system call functionality for VE.
 *
 *      int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
 *                              unsigned int flags);
 *
 *      This function receives data and arguments from VEMVA/VEHVA using VE
 *      driver interface and invokes VH OS sendmmsg() system call with this
 *      data. It returns the return value of system call back to VEMVA using
 *      VE driver interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_sendmmsg(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	size_t iovlen = 0;
	size_t name_len = 0;
	size_t ctl_len = 0;
	size_t vlen = 0;
	size_t len = 0;
	ssize_t vh_buff_len = 0;
	int i = 0, j = 0;
	struct mmsghdr *vh_msgvec = NULL;
	struct iovec **vh_msg_iov = NULL;
	char **vh_msg_name = NULL;
	char **vh_msg_ctl = NULL;
	char ***vh_buff_addr = NULL;
	uint64_t ve_msg_len = 0;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");
	/* get system call arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments, %s"
				" returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	vlen = (unsigned int)args[2];
	if (UIO_MAXIOV < vlen)
		vlen = UIO_MAXIOV;

	if (NULL != (void *)args[1]) {

		/* allocate memory to store contents of 2nd argument */
		vh_msgvec = (struct mmsghdr *)
			malloc(vlen * sizeof(struct mmsghdr));
		if (vh_msgvec == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_msgvec: malloc %s failed for mmsghdr",
					SYSCALL_NAME);
			goto hndl_return;
		}
		memset(vh_msgvec, '\0', (vlen * sizeof(struct mmsghdr)));

		/* receive contents of 2nd argument */
		if (0 > ve_recv_data(handle, args[1],
				vlen * sizeof(struct mmsghdr), vh_msgvec)) {
			PSEUDO_ERROR("failed to receive data"
					" from VE memory");
			PSEUDO_DEBUG("Failed (%s) to receive"
					" %s argument[1]",
					strerror(errno), SYSCALL_NAME);
			retval = -EFAULT;
			free(vh_msgvec);
			goto hndl_return;
		}

		/* Create local memory to store msg_name values */
		vh_msg_name = (char **)malloc(vlen * sizeof(uint64_t));
		if (vh_msg_name  == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_msg_name: malloc %s failed for"
					" msg_name",
					SYSCALL_NAME);
			free(vh_msgvec);
			goto hndl_return;
		}
		memset(vh_msg_name, '\0', (vlen * sizeof(uint64_t)));

		/* Create local memory to store msg_control values */
		vh_msg_ctl = (char **)malloc(vlen * sizeof(uint64_t));
		if (vh_msg_ctl  == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_msg_ctl: malloc %s failed for"
					" msg_name",
					SYSCALL_NAME);
			free(vh_msgvec);
			free(vh_msg_name);
			goto hndl_return;
		}
		memset(vh_msg_ctl, '\0', (vlen * sizeof(uint64_t)));

		/* Create local memory to store msg_iov values */
		vh_msg_iov = (struct iovec **)malloc(vlen * sizeof(uint64_t));
		if (vh_msg_iov  == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_msg_iov: malloc %s failed for"
					" msg_name",
					SYSCALL_NAME);
			free(vh_msgvec);
			free(vh_msg_name);
			free(vh_msg_ctl);
			goto hndl_return;
		}
		memset(vh_msg_iov, '\0', (vlen * sizeof(uint64_t)));

		/*create VH buffers */
		vh_buff_addr = (char ***)malloc(vlen * sizeof(uint64_t));
		if (vh_buff_addr == NULL) {
			retval = -errno;
			PSEUDO_ERROR("Failed to create internel buffer");
			PSEUDO_DEBUG("vh_buff_addr: malloc %s failed for"
					" msg_ctl",
					SYSCALL_NAME);
			free(vh_msgvec);
			free(vh_msg_name);
			free(vh_msg_ctl);
			free(vh_msg_iov);
			goto hndl_return;
		}
		memset(vh_buff_addr, '\0', (vlen * sizeof(uint64_t)));

		uint64_t first_msghdr_msgname = (uint64_t)vh_msgvec[0].msg_hdr.msg_name;

		/*create VH environment for sendmmsg() */
		while (len < vlen) {

			name_len = vh_msgvec[len].msg_hdr.msg_namelen;
			if ((name_len > 0) && first_msghdr_msgname &&
				ve_is_valid_address(handle, first_msghdr_msgname)) {
				retval = -EFAULT;
				goto hndl_return1;
			}

			if ((NULL != (void *)vh_msgvec[len].msg_hdr.msg_name)
				&& (0 != name_len)) {
				vh_msg_name[len] = (char *)
					malloc(name_len * sizeof(char));
				if (vh_msg_name[len]  == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						" internel buffer");
					PSEUDO_ERROR("malloc %s failed "
						"for msg_name",
						SYSCALL_NAME);
					goto hndl_return1;
				}
				memset(vh_msg_name[len], '\0',
						(name_len * sizeof(char)));

				if (0 > ve_recv_data(handle, (uint64_t)
					vh_msgvec[len].msg_hdr.msg_name,
						name_len * sizeof(char),
							vh_msg_name[len])) {
					PSEUDO_ERROR("failed to receive data"
						" from VE memory");
					PSEUDO_DEBUG("Failed (%s) to receive"
					" %s structure specific(msg_name)"
					" data", strerror(errno),
						SYSCALL_NAME);
					retval = -EFAULT;
					goto hndl_return1;
				}
				vh_msgvec[len].msg_hdr.msg_name =
					vh_msg_name[len];
			}

			ctl_len = vh_msgvec[len].msg_hdr.msg_controllen;
			if (ctl_len > INT_MAX) {
				retval = -ENOBUFS;
				goto hndl_return1;
			}

			if ((NULL != (void *)
					vh_msgvec[len].msg_hdr.msg_control) &&
						(0 != ctl_len)) {
				vh_msg_ctl[len] = (char *)
					malloc(ctl_len * sizeof(char));
				if (vh_msg_ctl[len] == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						" internel buffer");
					PSEUDO_DEBUG("malloc %s failed "
							"for msg_ctl",
							SYSCALL_NAME);
					goto hndl_return1;
				}
				memset(vh_msg_ctl[len], '\0',
						(ctl_len * sizeof(char)));

				if (0 > ve_recv_data(handle, (uint64_t)
					vh_msgvec[len].msg_hdr.msg_control,
						ctl_len * sizeof(char),
							vh_msg_ctl[len])) {
				PSEUDO_ERROR("failed to receive data"
						" from VE memory");
				PSEUDO_DEBUG("Failed (%s) to receive"
					" %s structure specific(msg_ctl)"
					"data", strerror(errno),
						SYSCALL_NAME);
					retval = -EFAULT;
					goto hndl_return1;
				}
				vh_msgvec[len].msg_hdr.msg_control =
					vh_msg_ctl[len];
			}

			iovlen = vh_msgvec[len].msg_hdr.msg_iovlen;
			if (iovlen > UIO_MAXIOV) {
				retval = -EMSGSIZE;
				goto hndl_return1;
			}

			if ((NULL != (void *)vh_msgvec[len].msg_hdr.msg_iov) &&
				(0 != iovlen)) {

				vh_msg_iov[len] = (struct iovec *)
					malloc(iovlen * sizeof(struct iovec));
				if (vh_msg_iov[len] == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						" internel buffer");
					PSEUDO_DEBUG("malloc %s failed "
							"for ve_iov",
							SYSCALL_NAME);
					goto hndl_return1;
				}
				memset(vh_msg_iov[len], '\0',
					(iovlen * sizeof(struct iovec)));

				if (0 > ve_recv_data(handle, (uint64_t)
						vh_msgvec[len].msg_hdr.msg_iov,
						iovlen * sizeof(struct iovec),
							vh_msg_iov[len])) {
					PSEUDO_ERROR("failed to receive data"
						" from VE memory");
					PSEUDO_DEBUG("Failed (%s) to receive"
					" %s structure specific(iov_len) data",
						strerror(errno), SYSCALL_NAME);
					retval = -EFAULT;
					goto hndl_return1;
				}
				vh_msgvec[len].msg_hdr.msg_iov =
					vh_msg_iov[len];
				vh_msgvec[len].msg_hdr.msg_iovlen = iovlen;

				vh_buff_addr[len] = (char **)malloc
					(iovlen * sizeof(uint64_t));
				if (vh_buff_addr[len] == NULL) {
					retval = -errno;
					PSEUDO_ERROR("Failed to create"
						" internel buffer");
					goto hndl_return1;
				}
				memset(vh_buff_addr[len], '\0',
						(iovlen * sizeof(uint64_t)));

				for (i = 0; i < iovlen; i++) {

					vh_buff_len =
						vh_msg_iov[len][i].iov_len;

					if (vh_buff_len < 0) {
						retval = -EINVAL;
						goto hndl_return1;
					}

					if ((NULL != (void *)
						vh_msg_iov[len][i].iov_base) &&
							(0 != vh_buff_len)) {

						vh_buff_addr[len][i] =
							(char *) malloc
							(vh_buff_len * sizeof
								(char));
						if (vh_buff_addr
						[len][i] == NULL) {
							retval = -errno;
							goto hndl_return1;
						}
						memset(vh_buff_addr[len][i],
						'\0', (vh_buff_len * sizeof
							(char)));

						if (0 > ve_recv_data(handle,
							(uint64_t)
							vh_msg_iov
							[len][i].iov_base,
							vh_buff_len * sizeof
							(char), vh_buff_addr
								[len][i])) {
							PSEUDO_ERROR("failed"
							" to receive data"
							" from VE memory");
							PSEUDO_DEBUG("Failed"
							" (%s) to receive"
							" %s vh_msg_iov[%d]",
							strerror(errno),
							SYSCALL_NAME, i);
							retval = -EFAULT;
							goto hndl_return1;
						}
					}
					vh_msgvec[len].msg_hdr.msg_iov[i].
					iov_base = vh_buff_addr[len][i];
				}
			}

			len++;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], vh_msgvec, vlen, args[3]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/*check retval of syscall*/
	if (retval < 0) {
		retval = -errno;
		PSEUDO_DEBUG("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 **/
			retval = -VE_ENORESTART;

		goto hndl_return1;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (NULL != (void *)args[1]) {
		for (i = 0; i < vlen; i++) {
			ve_msg_len = ((uint64_t)
				((struct mmsghdr *)args[1] + i) +
					((sizeof(struct msghdr))));
			if (0 > ve_send_data(handle, (uint64_t)ve_msg_len,
						sizeof(unsigned int),
						&(vh_msgvec[i].msg_len))) {
				PSEUDO_ERROR("Failed(%s) to send data to VE"
					" memory", strerror(errno));
				retval = -EFAULT;
				goto hndl_return1;
			}
		}
	}

	PSEUDO_DEBUG("%s syscall retruned", SYSCALL_NAME);

	/* deallocate all the allocated resources */
hndl_return1:
	if (NULL != (void *)args[1]) {
		if (NULL != (void *)vh_buff_addr) {
			for (j = 0; j < vlen; j++) {
				if (vh_buff_addr[j])
					for (i = 0;
						i < vh_msgvec[j].msg_hdr.
							msg_iovlen; i++)
						free(vh_buff_addr[j][i]);
			}
		}
		for (i = 0; i < vlen; i++) {
			if (vh_msg_name && vh_msg_name[i])
				free(vh_msg_name[i]);
			if (vh_msg_ctl && vh_msg_ctl[i])
				free(vh_msg_ctl[i]);
			if (vh_msg_iov && vh_msg_iov[i])
				free(vh_msg_iov[i]);
			if (vh_buff_addr && vh_buff_addr[i])
				free(vh_buff_addr[i]);
		}

		free(vh_msg_name);
		free(vh_msg_ctl);
		free(vh_msg_iov);
		free(vh_buff_addr);

		free(vh_msgvec);
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}
