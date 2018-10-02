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
* @file sys_common.c
* @brief Handles system calls encountered by VE process.
*
* This file contains system call handlers for the various system calls
* encountered by VE process.
*
* @internal
* @author Pseudo/System Call Handling
*/

#include "sys_common.h"
#include "syscall_impl.h"
#include "process_mgmt_comm.h"
#include "mm_transfer.h"
#include "sysve.h"
#include "vhcall.h"
#include "vhcall_os.h"
#include "velayout.h"
#include "ve_socket.h"
#include "sysve_os.h"
#include "pseudo_cr.h"
#include "pseudo_veshm.h"
#include "pseudo_vhshm.h"
#include "sys_veaio.h"

/**
 * @brief This function will be invoked to handle the MONC interrupt
 * that occurred on VE core.
 *
 *	Function communicates with VEOS to update the VE task state as WAIT.
 *	Function invokes appropriate system call handler based upon the
 *	system call number argument it receives.
 *	After the execution of system call handler, function will communicate
 *	with VEOS to update the state of VE task as RUNNING.
 *
 * @param[in] handle VEOS handle.
 * @param[in] syscall_num System call number.
 */
void ve_syscall_handler(veos_handle *handle, int syscall_num)
{
	ret_t retval = -1;
	bool blocking_syscall = false;

	PSEUDO_TRACE("Entering");

	if (syscall_num >= NR_ve_syscalls) {
		PSEUDO_ERROR("INVALID SYSCALL %d", syscall_num);
		retval = -ENOSYS;
		goto SET_REGVAL_REQ;
	}

	PSEUDO_DEBUG("received request for syscall_num = %d", syscall_num);

	/* Send BLOCKING System call request to veos */
	if (strncmp("B", MSYS_CALL_BLOCKFLAG(syscall_num), 1) == 0) {
		blocking_syscall = true;
		block_syscall_req_ve_os(handle);
	}

	/* call sytemcall */
	if (NULL != MSYS_CALL_FNPTR(syscall_num)) {
		retval = MSYS_CALL_FNPTR(syscall_num)(syscall_num,
				MSYS_CALL_NAME(syscall_num), handle);
	} else {
		PSEUDO_DEBUG("SYSCALL %d not supported", syscall_num);
		retval = -ENOTSUP;
	}

SET_REGVAL_REQ:
	/* Send UN BLOCK and set REGVAL request to veos */
	un_block_and_retval_req(handle, syscall_num, retval, blocking_syscall);
	PSEUDO_TRACE("Exiting");
	return;
}
/**
 *
 * @brief Handles those system calls for ve which do not have
 * pointer arguments and does not require special handling
 * with respect to VE hardware.
 *
 * @details
 * Following system calls use this generic handler.
 *
 * int fchdir(int fd);
 * int fchmod(int fd, mode_t mode);
 * int fchown(int fd, uid_t owner, gid_t group);
 * uid_t geteuid(void);
 * gid_t getgid(void);
 * gid_t getegid(void);
 * pid_t getpgid(pid_t pid);
 * pid_t getpgrp(void);
 * pid_t getpid(void);
 * pid_t getppid(void);
 * pid_t getsid(pid_t pid);
 * pid_t gettid(void);
 * uid_t getuid(void);
 * off_t lseek(int fd, off_t offset, int whence);
 * int setpgid(pid_t pid, pid_t pgid);
 * int setreuid(uid_t ruid, uid_t euid);
 * int setregid(gid_t rgid, gid_t egid);
 * int setresuid(uid_t ruid, uid_t euid, uid_t suid);
 * int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
 * pid_t setsid(void);
 * int socket(int domain, int type, int protocol);
 * mode_t umask(mode_t mask);
 * ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags);
 * int unshare(int flags);
 * int vhangup(void);
 * int setfsgid(uid_t fsgid);
 * int setfsuid(uid_t fsuid);
 * int shutdown(int sockfd, int how);
 * unsigned int alarm(unsigned int seconds);
 * int inotify_init(void);
 * int inotify_rm_watch(int fd, int wd);
 * int inotify_init1(int flags);
 * int iopl(int level);
 * int ioperm(unsigned long from, unsigned long num, int turn_on);
 * int ioprio_set(int which, int who, int ioprio);
 * int ioprio_get(int which, int who);
 * int fanotify_init(unsigned int flags, unsigned int event_f_flags);
 * int timerfd_create(int clockid, int flags);
 * int eventfd(unsigned int initval, int flags);
 * int sync_file_range(int fd, off64_t offset, off64_t nbytes,
 *				unsigned int flags);
 * int epoll_create(int size);
 * int epoll_create1(int flags);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 */
ret_t ve_generic_offload(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	uint64_t args[6] = {0};
	ret_t retval = -1;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("Generic Handler for %s is called", SYSCALL_NAME);
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("%s failure: "
				"failed to fetch system call aguments,"
				" return value %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	switch (syscall_num)
	{
		case __NR_epoll_create:
		case __NR_epoll_create1:
			{
				if ((ssize_t)args[0] < 0)
				{
					retval = -EINVAL;
					goto hndl_return;
				}
			}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			args[2],
			args[3],
			args[4],
			args[5]);
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
 * @brief Generic Handler for system calls of VE that have first argument as a
 * pointer to char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_access(),
 *	ve_chdir(),
 *	ve_chmod(),
 *	ve_chown(),
 *	ve_chroot(),
 *	ve_lchown(),
 *	ve_mkdir(),
 *	ve_mknod(),
 *	ve_rmdir(),
 *	ve_unlink(),
 *	ve_umount2(),
 *	ve_mq_unlink().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_p_char(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive contents of 1st argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);

		/*receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0],
			(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			path_buff,
			args[1],
			args[2],
			args[3],
			args[4],
			args[5]);

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
 * @brief Generic Handler for system calls of VE that have first argument as
 * an int and second argument is a pointer to char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_faccessat(),
 *	ve_fchmodat(),
 *	ve_fchownat(),
 *	ve_fremovexattr(),
 *	ve_mkdirat(),
 *	ve_mknodat(),
 *	ve_openat(),
 *	ve_unlinkat().
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_int_p_char(int syscall_num, char *syscall_name,
					veos_handle *handle)
{
	ret_t retval = -1;
	char *path_buff = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[1]) {
		/* allocate memory to receive contents of 2nd argument */
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);

		/*receive contents of 2nd argument */
		retval = ve_recv_string(handle, args[1],
			(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			path_buff,
			args[2],
			args[3],
			args[4],
			args[5]);

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
 * @brief Generic Handler for system calls of VE that have first and
 * third argument as an int and second and fourth argument as a pointer to
 * char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_renameat(),
 *	ve_linkat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_int_p_char_int_p_char(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	char *buffer2 = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[1]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buffer1, '\0', PATH_MAX);

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[1],
			(char *)buffer1, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[3]) {
		/* Allocate memory for buffer2 */
		buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}
		memset(buffer2, '\0', PATH_MAX);

		/* Receive buffer2 from VE side */
		retval = ve_recv_string(handle, args[3],
			(char *)buffer2, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			args[2],
			buffer2,
			args[4],
			args[5]);
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
 * @brief Generic Handler for system calls of VE that have their first and
 * third argument as a pointer to char and second argument as an int.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *	ve_symlinkat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_p_char_int_p_char(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	char *buffer2 = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buffer1, '\0', PATH_MAX);

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[0],
			(char *)buffer1, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
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
		buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}
		memset(buffer2, '\0', PATH_MAX);

		/* Receive buffer2 from VE side */
		retval = ve_recv_string(handle, args[2],
			(char *)buffer2, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			args[1],
			buffer2,
			args[3],
			args[4],
			args[5]);
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
 * @brief Generic Handler for system calls of VE that have first and second
 * argument as a pointer to char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_rename(),
 *	ve_link(),
 *	ve_symlink(),
 *	ve_removexattr(),
 *	ve_lremovexattr(),
 *	ve_pivot_root().
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name  System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_p_char_p_char(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	char *buffer2 = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buffer1, '\0', PATH_MAX);

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[0], (char *)buffer1,
			 PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[1]) {
		/* Allocate memory for buffer2 */
		buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}
		memset(buffer2, '\0', PATH_MAX);

		/* Receive buffer2 from VE side */
		retval = ve_recv_string(handle, args[1],
			(char *)buffer2, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			buffer2,
			args[2],
			args[3],
			args[4],
			args[5]);
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
 * @brief Generic Handler for system calls of VE that have first and
 * second argument as a pointer to char and third argument as pointer to void.
 *
 *	This generic function is used by respective ve_<sys_call_name> handlers
 *	which have similar requirements and similar post and pre processing
 *	needs.
 *	This function fetches Pathname/Extended attribute name from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.
 *	As length of Pathname/Extended attribute name is
 *	unknown this function uses ve_recv_string().
 *	This function retrieve an extended attribute value from VH OS and
 *	then these values are copied back to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_getxattr(),
 *	ve_lgetxattr().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_get_xattr_p_char_p_char_p_void(int syscall_num, char *syscall_name,
						veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	char *buffer2 = NULL;
	void *buffer3 = NULL;
	size_t size = 0;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive value of args[3] from VE memory */
	size = args[3];
	if (size > XATTR_SIZE_MAX)
		size = XATTR_SIZE_MAX;

	if (args[0]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buffer1, '\0', PATH_MAX);

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[0],
			(char *)buffer1, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[1]) {
		/* Allocate memory for buffer2 */
		buffer2 = (char *)malloc((XATTR_NAME_MAX + 1) * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}
		memset(buffer2, '\0', (XATTR_NAME_MAX + 1));

		/* Receive buffer2 from VE side */
		retval = ve_recv_string(handle, args[1],
			(char *)buffer2, (XATTR_NAME_MAX + 1));
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -4)
				retval = -ERANGE;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* Allocate memory for buffer3 */
	if (args[2]) {
		buffer3 = (void *)malloc(size * sizeof(char));
		if (NULL == buffer3) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return2;
		}
		memset(buffer3, '\0', size);
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			buffer2,
			buffer3,
			size,
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return3;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

	if (args[2] && retval && size) {
		/* send data to VE memory */
		if (0 > ve_send_data(handle, args[2],
					retval, (void *)buffer3)) {
			PSEUDO_DEBUG("%s failed to send args[2] to ve",
					SYSCALL_NAME);
			PSEUDO_ERROR("Failed to send data to VE memory");
			retval = -EFAULT;
			goto hndl_return3;
		}
	}

hndl_return3:
	free(buffer3);
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
 * @brief Generic Handler for system calls of VE that have first and second
 * argument as a pointer to char and third as pointer to void.
 *
 *	This generic function is used by respective ve_<sys_call_name> handlers
 *	which have similar requirements and similar post and pre processing
 *	needs.
 *	This function fetches Pathname, Extended attribute name and value from
 *	VEMVA using VE driver interface.
 *	As length of Pathname/Extended attribute name is
 *	unknown this function uses ve_recv_string().
 *	It then offloads the functionality to VH OS system call.
 *
 *	Following system calls use this generic handler:
 *	ve_setxattr(),
 *	ve_lsetxattr().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_set_xattr_p_char_p_char_p_void(int syscall_num,
				char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	char *buffer2 = NULL;
	void *buffer3 = NULL;
	size_t size = 0;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
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

	if (args[0]) {
		/* Allocate memory for buffer1 */
		buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buffer1) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(buffer1, '\0', PATH_MAX);

		/* Receive buffer1 from VE side */
		retval = ve_recv_string(handle, args[0],
			(char *)buffer1, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}

	if (args[1]) {
		/* Allocate memory for buffer2 */
		buffer2 = (char *)malloc((XATTR_NAME_MAX + 1) * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return1;
		}
		memset(buffer2, '\0', (XATTR_NAME_MAX + 1));

		/* Receive buffer2 from VE side */
		retval = ve_recv_string(handle, args[1],
				(char *)buffer2, (XATTR_NAME_MAX + 1));
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -4)
				retval = -ERANGE;
			else
				retval = -EFAULT;
			goto hndl_return2;
		}
	}

	if (args[2] && size) {
		/* Allocate memory for buffer3 */
		buffer3 = (void *)malloc(sizeof(char) * size);
		if (NULL == buffer3) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return2;
		}
		memset(buffer3, '\0', size);

		/* Receive buffer3 from VE side */
		if (size > 0) {
			if (0 > ve_recv_data(handle, args[2],
						size, (void *)buffer3)) {
				PSEUDO_ERROR("failed to receive "
					"args[2] form ve");
				retval = -EFAULT;
				goto hndl_return3;
			}
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			buffer2,
			buffer3,
			size,
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return3;
	} else {
		PSEUDO_DEBUG("syscall %s returned %lu",
				SYSCALL_NAME, retval);
	}

hndl_return3:
	free(buffer3);
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
 * @brief Generic Handler for system calls of VE that have first, second
 * and third argument as a pointer to int.
 *
 *	This generic function is used by respective ve_<sys_call_name> handlers
 *	which have similar requirements and similar post and pre processing
 *	needs.
 *	It offloads the functionality to VH OS system call.
 *	This function gets real, effective and saved user/group IDs
 *	from VH OS and then these values are copied back to VEMVA
 *	using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_getresuid(),
 *	ve_getresgid().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_p_int_p_int_p_int(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	/* real, effective and saved user/group IDs */
	unsigned int rid = 0, eid = 0, sid = 0;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0] ? &rid : NULL,
			args[1] ? &eid : NULL,
			args[2] ? &sid : NULL,
			args[3],
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	/* Copy back real, effective and saved user/group IDs to VE area */
	if (NULL != (void *)args[0]) {
		if (0 > ve_send_data(handle, args[0],
					sizeof(unsigned int),
					(unsigned int *)(&rid))) {
			PSEUDO_DEBUG("%s failed to send args[0] to ve",
					SYSCALL_NAME);
			PSEUDO_ERROR("Failed to send data to VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[1]) {
		if (0 > ve_send_data(handle, args[1],
					sizeof(unsigned int),
					(unsigned int *)(&eid))) {
			PSEUDO_DEBUG("%s failed to send args[1] to ve",
					SYSCALL_NAME);
			PSEUDO_ERROR("Failed to send data to VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)args[2]) {
		if (0 > ve_send_data(handle, args[2],
					sizeof(unsigned int),
					(unsigned int *)(&sid))) {
			PSEUDO_DEBUG("%s failed to send args[2] to ve",
					SYSCALL_NAME);
			PSEUDO_ERROR("Failed to send data to VE memory");
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
 * @brief Generic Handler for system calls of VE that have a first argument
 * as a pointer to char and second argument as pointer to "stat" structure.
 *
 *	This generic function is used by respective ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and pre
 *	processing needs. This function fetches Path from VEMVA using VE
 *	driver interface. As length of path is unknown this function uses
 *	ve_recv_string(). This function offloads the functionality to VH OS
 *	system call and gets the information about a file from VH OS .
 *	These values are copied back to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_stat(),
 *	ve_lstat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 */
ret_t ve_hndl_p_char_p_stat_buf(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct stat buffer = {0};
	char *file_name = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0]) {
		/* allocate memory to receive file name */
		file_name = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == file_name) {
			retval = -errno;
			PSEUDO_ERROR("Failed(%s) to allocate buffer to"
					" receive(%s) argument",
					strerror(errno), SYSCALL_NAME);
			goto hndl_return;
		}
		memset(file_name, '\0', PATH_MAX);

		/* receive the file name */
		retval = ve_recv_string(handle, args[0],
			 (char *)file_name, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to get (%s) argument: retval %d",
					SYSCALL_NAME, (int)retval);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
	}
	/* call VH system call */
	retval = syscall(syscall_num,
			file_name,
			&buffer,
			args[2],
			args[3],
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
				SYSCALL_NAME, strerror(errno));
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
	}

	if (args[1]) {
		/* send the filled stat_buf */
		if (0 > ve_send_data(handle, args[1],
				sizeof(struct stat), (uint64_t *)(&buffer))) {
			PSEUDO_DEBUG("%s failed to send args[1] to ve",
					SYSCALL_NAME);
			PSEUDO_ERROR("Failed to send data to VE memory");
			retval = -EFAULT;
		}
	}
hndl_return1:
	free(file_name);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Generic Handler for system calls of VE that have first and
 * second argument as int and third argument as pointer to "flock" structure.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH.
 *	This function gets the information about file lock from VH OS and then
 *	these values are copied back to VEMVA using VE driver interface.
 *
 *	Following system calls use this generic handler:
 *	ve_fcntl().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process.
 * */
ret_t ve_hndl_int_int_p_flock_buf(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct flock ve_file_lock = {0};
	uint64_t args[3] = {0};

	PSEUDO_TRACE("Entering");

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("failed to fetch syscall arguments "
				"(%s) returned %d",
				SYSCALL_NAME, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* To receive struct ve_file_lock values from VE */
	if ((F_SETLK == args[1]) || (F_SETLKW == args[1]) ||
				(F_GETLK == args[1])) {
		if (args[2]) {
			if (0 > ve_recv_data(handle, args[2],
				 sizeof(struct flock),
					(uint64_t *)(&ve_file_lock))) {
				PSEUDO_ERROR("failed to receive "
					"args[2] from ve");
				retval = -EFAULT;
				goto hndl_return;
			}
		}

	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1],
			args[2] ? &ve_file_lock : NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s",
			SYSCALL_NAME, strerror(errno));

	} else if (F_GETLK == args[1]) {
		if (args[2]) {
			/* Send the filled ve_file_lock to VE */
			if (0 > ve_send_data(handle, args[2],
				 sizeof(struct flock),
					(uint64_t *)(&ve_file_lock))) {
				PSEUDO_DEBUG("%s failed to send args[2] to ve",
						SYSCALL_NAME);
				PSEUDO_ERROR("Failed to send data to"
						" VE memory");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		PSEUDO_DEBUG("syscall %s returned %d",
				SYSCALL_NAME, (int)retval);
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
 * ve_sysve
 *
 * @param handle : VEOS handle
 */
ret_t ve_sysve(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[6] = {0};
	ret_t retval = -1;

	PSEUDO_TRACE("Entering");
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to syscall arguments");
		return -EFAULT;
	}

	PSEUDO_DEBUG("ve_sysve() is called. (sub:%d)", (int)args[0]);

	switch ((int)args[0]) {	/* sub command */
	case VE_SYSVE_DUMMY:
		/* dummy, error */
		retval = -EINVAL;
		break;
	case VE_SYSVE_VHCALL_INSTALL:
		retval = sys_vhcall_install(handle, args[1]);
		break;
	case VE_SYSVE_VHCALL_FIND:
		retval = sys_vhcall_find(handle, args[1], args[2]);
		break;
	case VE_SYSVE_VHCALL_INVOKE:
		retval = sys_vhcall_invoke(handle, args[1], args[2], args[3],
					   args[4], args[5]);
		break;
	case VE_SYSVE_VHCALL_UNINSTALL:
		retval = sys_vhcall_uninstall(handle, args[1]);
		break;
	case VE_SYSVE_VESHM_CTL:
		retval = ve_veshm(handle, &args[1]);
		break;
	case VE_SYSVE_CR_CTL:
		retval = ve_cr(handle, &args[1]);
		break;
	case VE_SYSVE_GET_PCISYNC:
		retval = ve_sys_get_pci_sync(handle, args[1],
				(uint64_t *)args[2], (uint64_t *)args[3]);
		break;
	case VE_SYSVE_GET_FIXED_VEHVA:
		retval = ve_sys_get_fixed_vehva(handle, args[1],
							(uint64_t *)args[2]);
		break;
	case VE_SYSVE_SET_USER_REG:
		retval = ve_sys_set_user_reg(handle, args[1], args[2]);
		break;
	case VE_SYSVE_GET_VE_INFO:
		retval = ve_sys_get_ve_info(handle, (char *)args[1],
						(char *)args[2], args[3]);
		break;
	case VE_SYSVE_VHSHM_CTL:
		retval = sys_vhshm(handle, &args[1]);
		break;
	case VE_SYSVE_MAP_DMADES:
		retval = ve_sys_map_dmades(handle,(uint64_t *)args[1],
						(uint64_t *)args[2]);
		break;
	case VE_SYSVE_UNMAP_DMADES:
		retval = ve_sys_unmap_dmades(handle,(uint64_t)args[1]);
		break;
	case VE_SYSVE_AIO_READ:
		retval = sys_ve_aio_read(handle, (void *)args[1], (int)args[2],
				(ssize_t)args[3], (void *)args[4], args[5]);
		break;
	case VE_SYSVE_AIO_WRITE:
		retval = sys_ve_aio_write(handle, (void *)args[1], (int)args[2],
				(ssize_t)args[3], (void *)args[4], args[5]);
		break;
	case VE_SYSVE_AIO_WAIT:
		retval = sys_ve_aio_wait(handle, (void *)args[1]);
		break;
	default:
		/* write return value */
		retval = -EINVAL;
		break;
	}
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief VEOS handle Constructor routine
 *
 *     This routine allocates memory to veos_handle, initialises it
 *     and then returns the handler back to the caller.
 *
 * @param[in] device socket file for vedriver
 * @param[in] os_socket socket file for VEOS
 * @param[in] parent_handle VEOS handle
 * @param[in] vefd VE driver fd.
 *
 * @return pointer to veos handle on success and NULL on failure
 */
veos_handle *veos_handle_create(char *device, char *os_socket,
			veos_handle *parent_handle, int vefd)
{
	veos_handle *veos_hndl = NULL;
	vedl_handle *vedl_hndl = NULL;
	int fd = 0;
	int errv = 0;

	PSEUDO_TRACE("Entering");

	if (device == NULL || os_socket == NULL) {
		PSEUDO_ERROR("Invalid(NULL) device file or socket file "
				"path received");
		return NULL;
	}

	/* allocate memory for veos handle */
	veos_hndl = (veos_handle *)malloc(sizeof(veos_handle));
	if (veos_hndl == NULL) {
		errv = errno;
		PSEUDO_ERROR("Failed to allocate memory for handle structure, "
				"return value %s", strerror(errno));
		goto return_hndl;
	}
	memset(veos_hndl, '\0', sizeof(veos_handle));

	fd = pseudo_veos_soc(os_socket);
	if (fd < 0) {
		PSEUDO_ERROR("Failed to create socket");
		errv = errno;
		goto err_hndl;
	}

	veos_hndl->veos_sock_fd = fd;
	veos_hndl->veos_sock_name = strdup(os_socket);
	veos_hndl->device_name = strdup(device);
	if (veos_hndl->device_name == NULL ||
			veos_hndl->veos_sock_name == NULL) {
		errv = errno;
		PSEUDO_ERROR("Failed to duplicate the string");
		PSEUDO_DEBUG("Failed to duplicate the string, return value %s",
				strerror(errno));
		goto err_hndl;
	}

	if (parent_handle == NULL)
		vedl_hndl = vedl_open_ve(device, vefd);
	else
		vedl_hndl = vedl_request_new_handle(parent_handle->ve_handle, device);

	if (vedl_hndl == NULL) {
		errv = errno;
		PSEUDO_ERROR("Failed to create driver handle");
		PSEUDO_DEBUG("Failed to create driver handle, return value %s",
				strerror(errno));
		goto err_hndl;
	}
	veos_hndl->ve_handle = vedl_hndl;

	return veos_hndl;

err_hndl:
	if (veos_hndl->device_name != NULL)
		free(veos_hndl->device_name);
	if (veos_hndl->veos_sock_name != NULL)
		free(veos_hndl->veos_sock_name);
	free(veos_hndl);
return_hndl:
	PSEUDO_TRACE("Exiting");
	errno = errv;
	return NULL;
}

/**
 * @brief Destructor routine for VEOS handler.
 *
 *     This routine first closes the vedl_handle and then frees
 *     the memory allocated to veos handle memory.
 *
 * @param handle VEOS handle
 */
void veos_handle_free(veos_handle *handle)
{
	int retval = -1;

	if (handle) {
		/* if sockets are still open, then close here */
		if (handle->ve_handle) {
			/* close VEDL handle */
			retval = vedl_close_ve(handle->ve_handle);
			if (retval)
				PSEUDO_ERROR("close VEDL handle failed.");

			close(handle->veos_sock_fd);
		}
		free(handle->device_name);
		free(handle->veos_sock_name);

		/* freeing VEOS handle memory */
		free(handle);
	}
}

/**
 * @brief This function will be invoked to check invalid VE address.
 *
 *	This function calls ve_recv_data() to receive 1 byte from VE
 *	address to validate non NULL VE address for successful
 *	read/write operations.
 *
 * @param[in] handle VEOS handle.
 * @param[in] addr VE address.
 *
 * @return 0 on success and -1 on failure
 */
ret_t ve_is_valid_address(veos_handle *handle, uint64_t addr)
{
	ret_t retval = -1;
	char check_buff[1] = {0};

	/* check whether VE address is valid or invalid by
	 * receiving 1 byte data from the VE address
	 * */
	retval = ve_recv_data(handle, addr, 1, check_buff);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to receive data from VE memory");
		return -1;
	}

	PSEUDO_DEBUG("Successfully received data from VE memory");
	return 0;
}
