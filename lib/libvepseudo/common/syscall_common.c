/**
* @file syscall.c
* @brief Handles system calls encountered by VE process.
*
* This file contains system call handlers for the various system calls
* encountered by VE process.
*/

#include "syscall_common.h"
#include "syscall_impl.h"
#include "pseudo_psmg_ipc.h"
#include "mem_xfer.h"
#include "sysve.h"
#include "vhcall.h"
#include "vhcall_os.h"
#include "velayout.h"

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
 * @param[in] handle Handle for VE driver interface.
 * @param[in] syscall_num System call number.
 */
void ve_syscall_handler(vedl_handle *handle, int syscall_num)
{
	if (syscall_num > NR_ve_syscalls) {
		fprintf(stderr, "INVALID SYSCALL %d\n", syscall_num);
		return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"syscall_num = %d\n", syscall_num);

	/* Send BLOCKING System call request to veos */
	block_syscall_req_ve_os();
	/* call sytemcall */
	if (NULL != MSYS_CALL_FNPTR(syscall_num))
		MSYS_CALL_FNPTR(syscall_num)(syscall_num,
				MSYS_CALL_NAME(syscall_num), handle);
	else
		fprintf(stderr, "SYSCALL %d not supported\n", syscall_num);

	/* Send UN BLOCK request to veos */
	un_block_syscall_req_ve_os();

	return;
}

/**
 * ve_sys_ni_syscall
 *
 * @param syscall_num : System Call number
 * @param syscall_name : System Call name
 * @param handle : Handle for VE driver interface
 */
void ve_sys_ni_syscall(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	/* If the syscall number is not assigned to specific function,
	 * this function will be called. */
	printf("This function is not implemented yet.\n");
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
 * int setgid(gid_t gid);
 * int setpgid(pid_t pid, pid_t pgid);
 * int setreuid(uid_t ruid, uid_t euid);
 * int setregid(gid_t rgid, gid_t egid);
 * int setresuid(uid_t ruid, uid_t euid, uid_t suid);
 * int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
 * pid_t setsid(void);
 * int setuid(uid_t uid);
 * int socket(int domain, int type, int protocol);
 * mode_t umask(mode_t mask);
 * int shmget(key_t key, size_t size, int shmflg);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_generic_offload(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	uint64_t args[6];
	ret_t retval = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Generic Handler for SYSCALL %s invoked\n",
			syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Generic Handler for system calls of VE that have first argument as a
 * pointer to char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_access(),
 *	ve_chdir(),
 *	ve_chmod(),
 *	ve_chown(),
 *	ve_chroot(),
 *	ve_creat(),
 *	ve_lchown(),
 *	ve_mkdir(),
 *	ve_mknod(),
 *	ve_rmdir(),
 *	ve_unlink().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_p_char(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/*receive contents of 1st argument */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Generic Handler for system calls of VE that have first argument as
 * an int and second argument is a pointer to char.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
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
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_int_p_char(int syscall_num, char *syscall_name,
					vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 2nd argument */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/*receive contents of 2nd argument */
	retval = ve_recv_string(handle, args[1], (char *)path_buff, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	system call.It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *
 *	ve_renameat(),
 *	ve_linkat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_int_p_char_int_p_char(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1, *buffer2;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[1], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(buffer2, '\0', PATH_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[3], (char *)buffer2, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * ve_hndl_int_p_char_p_char
 *
 * Handles those system calls for ve which have their first argument
 * as int and second and third argument as a pointer to char.
 * This generic function is used by respective ve_<sys_call_name>
 * handlers which have similar requirements and similar post and
 * pre processing needs. This function fetches Path from VEMVA using VE
 * driver interface. As length of path is unknown this function uses
 * ve_recv_string().
 *
 * Following system calls use this generic handler.
 *
 * @param syscall_num : System Call number
 * @param syscall_name : System Call name
 * @param handle : Handle for VE driver interface
 */
void ve_hndl_int_p_char_p_char(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	reg_t retval = -1;
	char *buffer1, *buffer2;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[1], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		goto hndl_return1;
	}
	memset(buffer2, '\0', PATH_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[2], (char *)buffer2, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			buffer2,
			args[3],
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Generic Handler for system calls of VE that have their first and
 * third argument as a pointer to char and second argument as an int.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing needs.This function fetches Path from VEMVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	system call.It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *	As length of path is unknown this function uses ve_recv_string().
 *
 *	Following system calls use this generic handler:
 *	ve_symlinkat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_p_char_int_p_char(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1, *buffer2;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[0], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return1;
	}
	memset(buffer2, '\0', PATH_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[2], (char *)buffer2, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *
 *	ve_rename(),
 *	ve_link(),
 *	ve_symlink(),
 *	ve_removexattr(),
 *	ve_lremovexattr().
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name  System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_p_char_p_char(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1, *buffer2;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[0], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(buffer2, '\0', PATH_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[1], (char *)buffer2, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_getxattr(),
 *	ve_lgetxattr().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 *
 */
void ve_hndl_get_xattr_p_char_p_char_p_void(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1, *buffer2;
	void *buffer3 = NULL;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[0], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(XATTR_NAME_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(buffer2, '\0', XATTR_NAME_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[1], (char *)buffer2, XATTR_NAME_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	/* Allocate memory for buffer3 */
	if (args[3]) {
		buffer3 = (void *)malloc(args[3] * sizeof(char));
		if (NULL == buffer3) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return2;
		}
		memset(buffer3, '\0', args[3]);
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			buffer2,
			buffer3,
			args[3],
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return3;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	if (args[3]) {
		/* using args[3] to send data as buffer3
		 * length is args[3]
		 * */
		if (-1 == ve_send_data(handle, args[2],
					args[3], (void *)(&buffer3))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to senda"
					" args[2]\n");
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
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_setxattr(),
 *	ve_lsetxattr().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 *
 */
void ve_hndl_set_xattr_p_char_p_char_p_void(int syscall_num,
				char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1, *buffer2;
	void *buffer3 = NULL;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', PATH_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[0], (char *)buffer1, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	buffer2 = (char *)malloc(XATTR_NAME_MAX * sizeof(char));
	if (NULL == buffer2) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(buffer2, '\0', XATTR_NAME_MAX);

	/* Receive buffer2 from VE side */
	retval = ve_recv_string(handle, args[1],
				(char *)buffer2, XATTR_NAME_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	/* Allocate memory for buffer3 */
	if (args[3]) {
		buffer3 = (void *)malloc(sizeof(char) * args[3]);
		if (NULL == buffer3) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return2;
		}
		memset(buffer3, '\0', args[3]);

		/* Receive buffer3 from VE side */
		if (-1 == ve_recv_data(handle, args[2],
				args[3], (void *)buffer3)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to receive"
					" args[2]\n");
			retval = -EFAULT;
			goto hndl_return3;
		}
}

	/* call VH system call */
	retval = syscall(syscall_num,
			buffer1,
			buffer2,
			buffer3,
			args[3],
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return3;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return3:
	free(buffer3);
hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_getresuid(),
 *	ve_getresgid().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_p_int_p_int_p_int(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	/* real, effective and saved user/group IDs */
	unsigned int rid, eid, sid;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			&rid,
			&eid,
			&sid,
			args[4],
			args[5]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}

	/* Copy back real, effective and saved user/group IDs to VE area */
	if (NULL != (void *)args[0]) {
		if (-1 == ve_send_data(handle, args[0],
					sizeof(unsigned int), (unsigned int *)(&rid))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to send"
					" args[0]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[1]) {
		if (-1 == ve_send_data(handle, args[1],
					sizeof(unsigned int), (unsigned int *)(&eid))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to send"
					" args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[2]) {
		if (-1 == ve_send_data(handle, args[2],
					sizeof(unsigned int), (unsigned int *)(&sid))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to send"
					" args[2]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_stat(),
 *	ve_lstat().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_p_char_p_stat_buf(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct stat buffer;
	char *file_name;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive file name */
	file_name = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == file_name) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(file_name, '\0', PATH_MAX);

	/* receive the file name */
	retval = ve_recv_string(handle, args[0], (char *)file_name, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* send the filled stat_buf */
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct stat), (uint64_t *)(&buffer))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[1]\n");
		retval = -EFAULT;
	}

hndl_return1:
	free(file_name);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_fcntl().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 * */
void ve_hndl_int_int_p_flock_buf(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct flock ve_file_lock;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* To receive struct ve_file_lock values from VE */
	if ((F_SETLK == args[1]) || (F_SETLKW == args[1])) {
		if (-1 == ve_recv_data(handle, args[2], sizeof(struct flock),
				(uint64_t *)(&ve_file_lock))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to receive"
					" args[2]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			&ve_file_lock);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
			syscall_name, strerror(errno));

	} else if (F_GETLK == args[1]) {
		/* Send the filled ve_file_lock to VE */
		if (-1 == ve_send_data(handle, args[2], sizeof(struct flock),
						(uint64_t *)(&ve_file_lock))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to send"
					" args[2]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * ve_sysve
 *
 * @param handle : Handle for VE driver interface
 */
void ve_sysve(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args[6];
	extern int memdump64(long long, int);
	reg_t retval;

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. (ve_sysve)\n");
		return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"ve_sysve() is called. (sub:%d)\n", (int)args[0]);

	switch (args[0]) {	/* sub command */
	case VE_SYSVE_DUMMY:
		/* dummy, error */
		return_system_call(-1);
		break;
	case VE_SYSVE_MEMDUMP:
		/* sysve(memdump, *buffer, size) */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"memdump is called.\n");

		char *write_buff;
		int recv_size;

		/* receive write buffer from VE memory */
		recv_size = ((args[2] + 7) >> 3) << 3;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"write_buff=%p, args[2]=%x, recv_size=%x\n",
				(char *)args[1], (int)args[2],
				recv_size);
		write_buff = (char *)malloc(recv_size * sizeof(char));
		ve_recv_data(handle, args[1], recv_size,
					(uint64_t *) write_buff);
		/* call VH system call */
		retval = memdump64((long long)write_buff, (int)args[2]);

		/* write return value */
		return_system_call(retval);
		free(write_buff);
		break;
	case VE_SYSVE_VHCALL_INSTALL:
		retval = sys_vhcall_install(handle, args[1]);
		return_system_call(retval);
		break;
	case VE_SYSVE_VHCALL_FIND:
		retval = sys_vhcall_find(handle, args[1], args[2]);
		return_system_call(retval);
		break;
	case VE_SYSVE_VHCALL_INVOKE:
		retval = sys_vhcall_invoke(handle, args[1], args[2], args[3],
					   args[4], args[5]);
		return_system_call(retval);
		break;
	case VE_SYSVE_VHCALL_UNINSTALL:
		retval = sys_vhcall_uninstall(handle, args[1]);
		return_system_call(retval);
		break;
	default:
		/* write return value */
		return_system_call(-1);
		break;
	}
}
