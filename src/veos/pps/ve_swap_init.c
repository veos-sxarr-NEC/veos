/*
 * Copyright (C) 2019-2020 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file ve_swap_init.c
 * @brief Initialization of PPS
 *
 * This contains the functions that are used to initialize PPS data structures.
 * VEOS uses these data structures to handle Swap-out and Swap-in  requests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <log4c.h>
#include <pthread.h>
#include "velayout.h"
#include "ve_swap.h"
#include "veos.h"
#include "ve_mem.h"
#include "buddy.h"

#define LOCKSIZE_UNIT 64 * 1024 * 1024
#define ISDIGIT(c)      ((unsigned)c-'0' < 10)

log4c_category_t *cat_os_pps;
static void *pps_buffer_addr;
static void *pps_file_transfer_buffer_addr;

/*
Allocate                  Deallocate
veos_alloc_ppsbuf     <-> veos_free_ppsbuf
veos_pps_alloc_ppsbuf <-> veos_pps_dealloc_ppsbuf
veos_pps_init_buddy   <-> veos_pps_free_buddy
*/

/**
 * @brief Initialize category for PPS
 *
 * @retval 0 on success,
 * @retval -1 on failure
 */
int
veos_pps_log4c_init(void)
{
	cat_os_pps = log4c_category_get("veos.os_module.pps");
	if (cat_os_pps == NULL) {
		 return -1;
	}

	PPS_DEBUG(cat_os_pps, "Initialized log4c");

	return 0;
}

/**
 * @brief Fetches the node number from VEOS socket file.
 *
 * @param[in] s string contains the veos socket file path
 *
 * @return node number on which this ve process will run
 */
int get_ve_node_num_from_sock_file(char *s)
{
	int n = 0;

	while (*s != '\0') {
		if (ISDIGIT(*s))
			n = 10*n + (*s - '0');
		else if (*s == '.')
			break;

		s++;
	}
	return n;
}

/**
 * @brief out put mode info for PPS
 *
 * @retval 0 on success,
 * @retval -1 on failure
 */
int print_pps_mode_info(char pps_file_path, size_t pps_file_size,
					bool mem_mode_flg, bool file_mode_flg)
{
	int retval = -1;
	/* Out put PPS mode */
	if ((mem_mode_flg) && (file_mode_flg)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"PPS mode is MIX_MODE");
		fprintf(stderr, "Partial Process Swapping mode is mix mode\n");
		if (pps_file_path == '\0') {
			fprintf(stderr,
			"Initializing Partial Process Swapping failed.\n");
			fprintf(stderr, "--ve-swap-file-path is not set\n");
			goto hndl_return;
		} else if (pps_file_size == 0) {
			fprintf(stderr,
			"Initializing Partial Process Swapping failed.\n");
			fprintf(stderr, "--ve-swap-file-max is not set\n");
			goto hndl_return;
		}
	} else if (mem_mode_flg) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"PPS mode is MEM_MODE");
		fprintf(stderr, "Partial Process Swapping mode is memory mode\n");
	} else if (file_mode_flg) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"PPS mode is FILE_MODE");
		fprintf(stderr, "Partial Process Swapping mode is file mode\n");
		if (pps_file_path == '\0') {
			fprintf(stderr,
			"Initializing Partial Process Swapping failed.\n");
			fprintf(stderr, "--ve-swap-file-path is not set\n");
			goto hndl_return;
		} else if (pps_file_size == 0) {
			fprintf(stderr,
			"Initializing Partial Process Swapping failed.\n");
			fprintf(stderr, "--ve-swap-file-max is not set\n");
			goto hndl_return;
		}
	}

	retval = 0;
hndl_return:
	return retval;
}

/**
 * @brief Allocation PPS buffer and lock it into RAM.
 *
 * @param[in] pps_buf_size Size of PPS buffer in MB.
 *
 * @return Pointer to PPS buffer on Success, NULL on failure.
 */
static void
*veos_pps_alloc_ppsbuf(size_t pps_buf_size, bool is_pps_buf, bool is_shared)
{
	int ret;
	uint64_t tmp;
	void *ptr;
	void *retptr = NULL;
	size_t size, locked_size, remained;
	bool lock_on_going = true;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	PPS_DEBUG(cat_os_pps, "Buffer size is %ldMB", pps_buf_size);

	size = ((pps_buf_size + (PPS_BUFFPAGE_SIZE - 1)) /
					PPS_BUFFPAGE_SIZE) * PPS_BUFFPAGE_SIZE;
	PPS_DEBUG(cat_os_pps, "round up to %ldMB", size);
	size *= 1024 * 1024ULL;

	if(!is_shared){
		ptr = mmap(NULL, size, PROT_READ|PROT_WRITE,
			MAP_POPULATE|MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB,
			-1, 0);
	}else{
		ptr = mmap(NULL, size, PROT_READ|PROT_WRITE,
			MAP_POPULATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_SHARED,
			-1, 0);
	}

	if (ptr == MAP_FAILED) {
		if (errno == ENOMEM)
			fprintf(stderr, "Need more free HugePages\n");
		PPS_ERROR(cat_os_pps, "Failed to allocate buffer for PPS"
						" due to %s", strerror(errno));
		goto hndl_return;
	}
	PPS_DEBUG(cat_os_pps, "mmap for pps file is end ptr is %p", ptr);
	for (locked_size = 0, remained = size, tmp = (uint64_t)ptr;
				lock_on_going; remained -= LOCKSIZE_UNIT) {
		if (terminate_flag) {
			PPS_ERROR(cat_os_pps, "Interrupted by termination");
			goto hndl_unlock;
		}
		if (remained <= LOCKSIZE_UNIT) {
			lock_on_going = false;
			PPS_DEBUG(cat_os_pps,
				"remained lock size : %ld, lock addr 0x%lx",
				remained / (1024 * 1024), tmp);
			ret = mlock((void *)tmp, remained);
		} else {
			PPS_DEBUG(cat_os_pps,
					"lock size : %d, lock addr 0x%lx",
					LOCKSIZE_UNIT / (1024 * 1024), tmp);
			ret = mlock((void *)tmp, LOCKSIZE_UNIT);
		}
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to lock buffer for pps"
					" into RAM due to %s", strerror(errno));
			PPS_ERROR(cat_os_pps, "locked_size : 0x%lx, "
				  "remained : 0x%lx", locked_size, remained);
			goto hndl_unlock;
		}
		tmp += LOCKSIZE_UNIT;
		locked_size += LOCKSIZE_UNIT;
	}

	retptr = ptr;
	if (is_pps_buf)
		vnode->pps_buf_size = size;

	goto hndl_return;

hndl_unlock:
	if (locked_size > 0) {
		ret = munlock(ptr, locked_size);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to unlock buffer for PPS"
						"due to %s", strerror(errno));
		}
	}

	ret = munmap(ptr, size);
	if (ret != 0)
		PPS_ERROR(cat_os_pps, "Failed to free buffer for PPS"
						" due to %s", strerror(errno));

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retptr;
}

/**
 * @brief Free PPS buffer
 *
 * @param[in] buffer Pointer to PPS buffer
 *
 * @retval None
 */
static void
veos_pps_dealloc_ppsbuf(void *buffer, void *transfer_buffer)
{
	int ret;
	struct ve_node_struct *vnode = VE_NODE(0);
	size_t size;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if (buffer != NULL) {
		size = vnode->pps_buf_size;
		ret = munlock(buffer, size);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to unlock buffer for PPS"
						" due to %s", strerror(errno));
		}

		ret = munmap(buffer, size);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to free buffer for PPS"
						" due to %s", strerror(errno));
		}

		vnode->pps_buf_size = 0;
	}

	if (transfer_buffer != NULL) {
		ret = munlock(transfer_buffer, PPS_TRANSFER_BUFFER_SIZE_BYTE);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to unlock transfer buffer"
					" for PPS due to %s", strerror(errno));
		}

		ret = munmap(transfer_buffer, PPS_TRANSFER_BUFFER_SIZE_BYTE);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to free transfer buffer"
					" for PPS due to %s", strerror(errno));
		}
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Initialize buddy of PPS buffer
 *
 * @param[in] buffer Pointer to PPS buffer
 *
 * @retval 0 on Success,
 * @retval -1 on failure.
 */
static int
veos_pps_init_buddy(void *buffer)
{
	int retval = -1;
	int i;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	vnode->pps_mp = veos_buddy_init((uint64_t)buffer,
					vnode->pps_buf_size, PAGE_SIZE_2MB);
	if (vnode->pps_mp == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to init mempool for PPS");
		goto hndl_return;
	}
	pthread_mutex_init(&(vnode->pps_mp->buddy_mempool_lock), NULL);
	vnode->swap_request_pids_enable = true;
	vnode->resource_freed = false;
	for (i = 0; i < VE_MAX_NUMA_NODE; i++) {
		vnode->pps_mp_used[i] = 0;
	}
	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Finalize buddy of PPS buffer
 *
 * @retval None
 */
static void
veos_pps_free_buddy(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = pthread_mutex_destroy(&(vnode->pps_mp->buddy_mempool_lock));
	if (ret != 0)
		PPS_ERROR(cat_os_pps, "Failed to destroy buddy_mempool_lock"
						" due to %s", strerror(ret));
	buddy_deinit(vnode->pps_mp);

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Finalize buddy of PPS file offset
 *
 * @retval None
 */
static void
veos_pps_free_offset_buddy(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = pthread_mutex_destroy(&(vnode->pps_file_offset->buddy_mempool_lock));
	if (ret != 0)
		PPS_ERROR(cat_os_pps, "Failed to destroy buddy_mempool_lock"
						" due to %s", strerror(ret));
	buddy_deinit(vnode->pps_file_offset);

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}


/**
 * @brief Create swap thread
 *
 * @retval 0 on Success,
 * @retval -1 on failure.
 */
static int
veos_pps_create_swap_thread(void)
{
	int retval = -1;
	int ret = 0;
	pthread_t swap_thread;
	pthread_attr_t attr;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to init attribute for swap thread due to %s",
			strerror(ret));
		goto hndl_return;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to set DETACHED attribute for swap thread"
			" due to %s", strerror(ret));
		goto hndl_destroy;
	}

	ret = pthread_create(&swap_thread, &attr, &ve_swap_thread, NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to create swap thread due to %s",
								strerror(ret));
	} else {
		retval = 0;
	}

hndl_destroy:
	ret = pthread_attr_destroy(&attr);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to destroy attribute for swap thread due to %s",
			strerror(ret));
		retval = -1;
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function create child process (PPS file handler).
 * The process open and write PPS file with specified user and group.
 *
 * @param[in] path path of PPS file
 * @param[in] file descriptor for socket
 * @param[in] uid user id 
 * @param[in] gid group id
 * @param[out] chld_pid child process
 *
 * @retval 0 on Success
 * @retval -1 on Failure
 */
int fork_pps_file_handler(char *path, int sockfd[], uid_t uid, gid_t gid, 
							pid_t *chld_pid)
{
	pid_t pps_file_handler_pid;
	int status = -1;
	int p_ret_status = -1;
	struct ve_swap_file_hdr_comm p_msg;
	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pps_file_handler_pid = fork();
	if (-1 == pps_file_handler_pid) {
		PPS_ERROR(cat_os_pps,"Failed to create PPS file handler "
								"process");
		close(sockfd[0]);
		close(sockfd[1]);
		goto hndl_return;
	} else if (0 == pps_file_handler_pid) {
		int pps_f_fd = -1;
		int ret_status = -1;
		ssize_t write_ret;
		int cls_ret = -1;
		struct ve_swap_file_hdr_comm msg;
	
		close(sockfd[1]);

		/* Set the gid to the current process */
		if (setgid(gid) == -1){
			PPS_ERROR(cat_os_pps,"Faild to set gid to PPS file "
				"handler Child process");
			memset(&msg,'\0',sizeof(struct ve_swap_file_hdr_comm));
			msg.kind = PPS_F_HDR_START_RET;
			msg.int_ret = -1;
			msg.r_errno = errno;
			ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
			goto chld_close_proc_file;
		}

		/* Set the uid to the current process */
		if (setuid(uid) == -1){
			PPS_ERROR(cat_os_pps,"Faild to set uid to PPS file "
				"handler Child process");
			memset(&msg,'\0',sizeof(struct ve_swap_file_hdr_comm));
			msg.kind = PPS_F_HDR_START_RET;
			msg.int_ret = -1;
			msg.r_errno = errno;
			ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
			goto chld_close_proc_file;
		}
		
		/* Enter a loop that receives a request from VEOS process.
		 * Exit the loop when a termination request or communication 
		 * error occurs. */
		memset(&msg,'\0',sizeof(struct ve_swap_file_hdr_comm));
		msg.kind = PPS_F_HDR_START_RET;
		msg.int_ret = 0;
		msg.r_errno = 0;
		ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
		if (ret_status < 0){
			PPS_ERROR(cat_os_pps,"send error at sending start ack"
				" in PPS file handler Child process");
			goto chld_close_proc_file;
		}
		while(1){
			memset(&msg,'\0',sizeof(struct ve_swap_file_hdr_comm));
			ret_status = recv_pps_file_handler_comm(sockfd[0], 
						&msg);
			if (ret_status < 0){
				break;
			}
			if (msg.kind == PPS_F_HDR_TERMINATE_REQ){
				break;
			}
			if (msg.kind == PPS_F_HDR_OPEN_FD_REQ){
				/* Get file descriptor of pps_to_file */
				memset(&msg, '\0', 
					sizeof(struct ve_swap_file_hdr_comm));
				pps_f_fd = open(path, O_RDWR | O_CREAT, 
								S_IRWXU);
				msg.kind = PPS_F_HDR_OPEN_FD_RET;
				msg.int_ret = pps_f_fd;
				msg.r_errno = errno;
				ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
				if (ret_status < 0){
					PPS_ERROR(cat_os_pps,"send error at "
						"sending fd in PPS file "
						"handler Child process");
					break;
				}
			}
			if (msg.kind == PPS_F_HDR_WRITE_REQ){
				write_ret = pwrite(pps_f_fd, 
				pps_file_transfer_buffer_addr, msg.cnt, 
								msg.off);
				memset(&msg, '\0', 
					sizeof(struct ve_swap_file_hdr_comm));
				msg.kind = PPS_F_HDR_WRITE_RET;
				msg.ssize_ret = write_ret;
				msg.r_errno = errno;
				ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
				if (ret_status < 0){
					PPS_ERROR(cat_os_pps,"Send error in "
					"PPS file handler Child process");
					break;
				}
			}
			if (msg.kind == PPS_F_HDR_CLOSE_FD_REQ){
				cls_ret = close(pps_f_fd);
				memset(&msg, '\0', 
					sizeof(struct ve_swap_file_hdr_comm));
				msg.kind = PPS_F_HDR_CLOSE_FD_RET;
				msg.int_ret = cls_ret;
				msg.r_errno = errno;
				ret_status = send_pps_file_handler_comm(
							sockfd[0], msg);
				if (ret_status < 0){
					PPS_ERROR(cat_os_pps,"Send error in "
					"PPS file handler Child process");
					break;
				}
			}
		}

		close(pps_f_fd);
chld_close_proc_file:
		close(sockfd[0]);
		PPS_INFO(cat_os_pps,"PPS file handler Child "
					"process exit");
		_exit(ret_status);
	}

	close(sockfd[0]);
	memset(&p_msg,'\0',sizeof(struct ve_swap_file_hdr_comm));
	p_ret_status = recv_pps_file_handler_comm(sockfd[1], &p_msg);
	if (p_ret_status < 0){
		close(sockfd[1]);
		goto hndl_return;
	}
	if (p_msg.int_ret < 0){
		errno = p_msg.r_errno;
		close(sockfd[1]);
		goto hndl_return;
	}
	*chld_pid = pps_file_handler_pid;
	status = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return status;
}


/**
 * @brief This function allocates PPS buffer for PPS and locks all buffer into
 * RAM, and initializes management information of PPS buffer. And then, this
 * function creates "swap thread".
 *
 * @param[in] pps_buf_size Size of PPS buffer in MB
 *
 * @retval 0 on success,
 * @retval -1 on failure.
 */
int
veos_alloc_ppsbuf(size_t pps_buf_size, size_t pps_file_buf_size)
{
	int retval = -1;
	int ret;
	pid_t chld_pid = -1;
	int socket_fd[2];
	int fork_sts = -1;

	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	INIT_LIST_HEAD(&(vnode->swap_request_pids_queue));
	pthread_mutex_init(&(vnode->swap_request_pids_lock), NULL);
	pthread_cond_init(&(vnode->swap_request_pids_cond), NULL);

	if (pps_buf_size != 0) {
		pps_buffer_addr = veos_pps_alloc_ppsbuf(pps_buf_size, true, 
									false);
			if (pps_buffer_addr == NULL)
				goto hndl_return;

		ret = veos_pps_init_buddy(pps_buffer_addr);
		if (ret != 0)
			goto hndl_dealloc;
	}
	if (pps_file_buf_size != 0) {
		pps_file_transfer_buffer_addr =
			veos_pps_alloc_ppsbuf(pps_file_buf_size, false, 
					!(vnode->pps_file.is_created_by_root));
		vnode->pps_file_transfer_buffer = pps_file_transfer_buffer_addr;
		if (pps_file_transfer_buffer_addr == NULL) {
			goto hndl_free_buddy;
		}
		pthread_mutex_lock_unlock(&(vnode->pps_file_lock), LOCK,
					"Failed to aqcuire pps_file_lock");
		if(!vnode->pps_file.is_created_by_root){
                	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socket_fd) 
									!= 0) {
                        	PPS_ERROR(cat_os_pps, "Failed to create "
				"communication channel for PPS file handler"
				" due to %s", strerror(errno));
				pthread_mutex_lock_unlock(
					&(vnode->pps_file_lock), UNLOCK,
					"Failed to release pps_file_lock");
				goto hndl_free_buddy;
                	}
			fork_sts = fork_pps_file_handler(
				vnode->pps_file.path, socket_fd, 
				vnode->pps_file.uid, vnode->pps_file.gid, 
				&chld_pid);
			if (fork_sts < 0){
                        	PPS_ERROR(cat_os_pps, "Failed to create "
				"process of PPS file handler"
				" due to %s", strerror(errno));
				pthread_mutex_lock_unlock(
					&(vnode->pps_file_lock), UNLOCK,
					"Failed to release pps_file_lock");
				goto hndl_free_buddy;
			}

		}
		vnode->pps_file.child_pid = chld_pid;
		vnode->pps_file.sockfd = socket_fd[1];
		pthread_mutex_lock_unlock(&(vnode->pps_file_lock), UNLOCK,
				"Failed to release pps_file_lock");

	}

	ret = veos_pps_create_swap_thread();
	if (ret != 0)
		goto hndl_free_buddy;

	retval = 0;
	goto hndl_return;

hndl_free_buddy:
	if (pps_buf_size != 0)
		veos_pps_free_buddy();

hndl_dealloc:
	veos_pps_dealloc_ppsbuf(pps_buffer_addr, pps_file_transfer_buffer_addr);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function clears all management information,
 * unlocks all buffer from RAM, and frees PPS buffer for PPS.
 *
 * @retval None
 */
void
veos_free_ppsbuf(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	size_t pps_buf_size;
	size_t pps_file_size;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pps_buf_size = vnode->pps_buf_size;
	pps_file_size = vnode->pps_file.size;
	PPS_DEBUG(cat_os_pps, "pps_buf_size : 0x%lx", pps_buf_size);
	PPS_DEBUG(cat_os_pps, "pps_file_size : 0x%lx", pps_file_size);
	if (pps_buf_size > 0) {
		veos_pps_free_buddy();
	}

	if (pps_file_size > 0) {
		veos_pps_free_offset_buddy();
	}
	veos_pps_dealloc_ppsbuf(pps_buffer_addr, pps_file_transfer_buffer_addr);

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Initialize buddy of PPS file
 *
 * @retval 0 on Success,
 * @retval -1 on failure.
 */
static int
veos_pps_file_init_buddy(void)
{
	int retval = -1;
	int i;
	uint64_t start = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	vnode->pps_file_offset = veos_buddy_init(start, vnode->pps_file.size,
								PAGE_SIZE_2MB);
	if (vnode->pps_file_offset == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to init mempool for PPS file");
		goto hndl_return;
	}
	pthread_mutex_init(&(vnode->pps_file_offset->buddy_mempool_lock), NULL);
	vnode->swap_request_pids_enable = true;
	vnode->resource_freed = false;
	for (i = 0; i < VE_MAX_NUMA_NODE; i++) {
		vnode->pps_file_used[i] = 0;
	}
	retval = 0;

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function set path of veswap file to node struct.
 *
 * @param[in] Path of veswap file
 * @param[in] Size of veswap file
 * @param[in] uid to create veswap file
 * @param[in] gid to create veswap file
 *
 * @retval None
 */
int
veos_init_pps_file_info(char *pps_file_path, size_t pps_file_size,
		char *drv_sock_file, uid_t pps_file_uid, gid_t pps_file_gid)
{
	int retval = 0;
	int node_num = 0;
	char hostname[PATH_MAX] = {'\0'};
	struct stat s_buf;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	pthread_mutex_init(&(vnode->pps_file_lock), NULL);

	if((pps_file_path == NULL) || (pps_file_size == 0))
		goto hndl_return;

	/* Set pps file path to ve_node_struct */
	PPS_DEBUG(cat_os_pps, "drv_sock_file is %s", drv_sock_file);
	node_num = get_ve_node_num_from_sock_file(drv_sock_file);
	if (gethostname(hostname, sizeof(hostname)) != 0) {
		PPS_DEBUG(cat_os_pps, "Can not get host name, errno is %d",
									errno);
		strncpy(hostname, "UnknownHost", sizeof(hostname));
	}
	snprintf(vnode->pps_file.path, PATH_MAX * 2, "%s_%s.%d",
					pps_file_path, hostname, node_num);
	if(strlen(vnode->pps_file.path) > PATH_MAX) {
		PPS_ERROR(cat_os_pps, "Path of PPS file is too long");
		retval = -1;
		goto hndl_return;
	}
	PPS_DEBUG(cat_os_pps, "Path of pps file in host %s for node%d is %s",
				hostname, node_num, vnode->pps_file.path);

	/* Set pps file size to ve_node_struct */
	PPS_DEBUG(cat_os_pps, "pps file orignal size is %ldMB", pps_file_size);
	pps_file_size = pps_file_size * (1024 * 1024);
	if ((pps_file_size % PAGE_SIZE_2MB) != 0) {
		pps_file_size = ((pps_file_size / PAGE_SIZE_2MB + 1)
							* PAGE_SIZE_2MB);
	}
	vnode->pps_file.size = pps_file_size;
	PPS_DEBUG(cat_os_pps, "pps file size is %ldbyte", vnode->pps_file.size);

	/* Delete file if the file already exists when starting VEOS*/
	if(stat(vnode->pps_file.path, &s_buf) == -1) {
		PPS_DEBUG(cat_os_pps, "Not need to delete because it is maybe "
								"a dir");
		errno = 0;
	} else if(!S_ISDIR(s_buf.st_mode)) {
		remove(vnode->pps_file.path); 
		errno = 0;
	}
	 /* Set flag */
	vnode->pps_file.is_opened = false;
	vnode->pps_file.not_del_after_swapin = false;

	/* Init buddy */
	if (veos_pps_file_init_buddy() != 0) {
		PPS_ERROR(cat_os_pps, "Failed to initialize buddy of PPS file");
		retval = -1;
	}
	 /* Set uid and gid */
	vnode->pps_file.uid = pps_file_uid;
	vnode->pps_file.gid = pps_file_gid;
	
	if((pps_file_uid == 0) && (pps_file_gid == 0)){
		vnode->pps_file.is_created_by_root = true;
	}else{
		vnode->pps_file.is_created_by_root = false;
	}
	vnode->pps_file.child_pid = -1;
	vnode->pps_file.sockfd = -1;


hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function make dir of PPS file.
 *
 * @param[out] Dir of PPS file
 *
 * @retval 0 on Success
 * @retval -1 on Failure
 */
static int veos_mkdir_pps_file(char *file_dir)
{
	int retval = -1;
	char *p;
	int i = 0;
	DIR *pps_file_dirp;
	char mkdir_path[PATH_MAX] =  {'\0'};

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	p = file_dir;

	while(*p) {
		while(*p != '/' && *p != '\0') {
			i++;
			p++;
		}
		if (i != 0) {
			strncpy(mkdir_path, file_dir, i);
			PPS_DEBUG(cat_os_pps, "mkdir path is %s", mkdir_path);
			pps_file_dirp = opendir(mkdir_path);
			if (pps_file_dirp == NULL) {
				if(mkdir(mkdir_path, S_IRWXU) == -1) {
					PPS_DEBUG(cat_os_pps,
						"Failed to mkdir for PPS file"
						" due to %s", strerror(errno));
					return retval;
				}
			}
			closedir(pps_file_dirp);
		}
		i++;
		p++;
	}
	retval = 0;

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function request to open PPS file 
 * to PPS file handler.
 *
 * @param[in] file descriptor for socket
 *
 * @retval file descriptor on Success
 * @retval -1 on Failure
 */
int open_pps_file_handler(int sockfd)
{
	int pps_file_fd = -1;
	int ret_stat = -1;
	struct ve_swap_file_hdr_comm msg;

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
	msg.kind = PPS_F_HDR_OPEN_FD_REQ;
	ret_stat = send_pps_file_handler_comm(sockfd, msg);
	if(ret_stat < 0){
		PPS_ERROR(cat_os_pps,"send req open fd %s", 
						strerror(errno));
		goto hndl_return;
	}
	memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
	ret_stat = recv_pps_file_handler_comm(sockfd, &msg);
	if(ret_stat < 0){
		PPS_ERROR(cat_os_pps,"recv open fd %s", 
						strerror(errno));
		goto hndl_return;
	}
	if(msg.int_ret < 0){
		errno = msg.r_errno;
	}
	pps_file_fd = msg.int_ret;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return pps_file_fd;
}

/**
 * @brief This function open PPS file.
 *
 * @param[in] vnode Pointer to ve_node_struct structure
 *
 * @retval 0 on Success
 * @retval -1 on Failure
 */
int veos_open_pps_file(struct ve_node_struct *vnode)
{
	int retval = -1;
	int pps_file_fd = 0;
	char pps_file_dir[PATH_MAX * 2] = {'\0'};
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pthread_mutex_lock_unlock(&(vnode->pps_file_lock), LOCK,
				"Failed to aqcuire pps_file_lock");

	/* Check PPS mode */
	if ((vnode->pps_file.path[0] == '\0') || (vnode->pps_file.size == 0)) {
		PPS_DEBUG(cat_os_pps, "there is not file mode or mix mode");
		retval = 0;
		goto hndl_return;
	}

	/* Set flag to true,
	 * file can not be deleted after swap in when no resource is swapped out
	 */
	vnode->pps_file.not_del_after_swapin = true;

	if(vnode->pps_file.is_opened) {
		PPS_DEBUG(cat_os_pps, "PPS file has been opened");
		retval = 0;
		goto hndl_return;
	}
	strncpy(pps_file_dir, vnode->pps_file.path, PATH_MAX * 2);
	strncpy(pps_file_dir, dirname(pps_file_dir), PATH_MAX);
	PPS_DEBUG(cat_os_pps, "pps file %s will be opened",
							vnode->pps_file.path);
	PPS_DEBUG(cat_os_pps, "dir of pps file is %s", pps_file_dir);
	errno = 0;

	if(vnode->pps_file.is_created_by_root){
		/* open as root */
		pps_file_fd = open(vnode->pps_file.path, O_RDWR | O_CREAT, 
								S_IRWXU);	
		if ((pps_file_fd == -1) && (errno == ENOENT)) {
			ret = veos_mkdir_pps_file(pps_file_dir);
			if (ret != 0) {
				PPS_ERROR(cat_os_pps, "Failed to make dir of"
					"PPS file due to %s", strerror(errno));
				goto hndl_return;
			}
			pps_file_fd = open(vnode->pps_file.path, O_RDWR | 
					O_CREAT, S_IRWXU);
		}
	}else{
		/* open as non-root */
		pps_file_fd = open_pps_file_handler(vnode->pps_file.sockfd);	
	}

	if (pps_file_fd == -1) {
		PPS_ERROR(cat_os_pps, "Failed to open PPS file due to %s",
							strerror(errno));
		goto hndl_return;
	}

	vnode->pps_file.fd = pps_file_fd; 
	vnode->pps_file.is_opened = true;

	retval = 0;

hndl_return:
	pthread_mutex_lock_unlock(&(vnode->pps_file_lock), UNLOCK,
				"Failed to release pps_file_lock");

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function close and del PPS file.
 *
 * @param[in] vnode Pointer to ve_node_struct structure
 *
 * @retval None
 */
void veos_del_pps_file(struct ve_node_struct *vnode)
{
	struct stat s_buf;
	struct ve_swap_file_hdr_comm msg;
	int ret_stat = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	if(stat(vnode->pps_file.path, &s_buf) == -1) {
		PPS_DEBUG(cat_os_pps, "Not need to delete because it is maybe "
								"a dir");
		goto hndl_exit;
	} else if(S_ISDIR(s_buf.st_mode)) {
		PPS_DEBUG(cat_os_pps, "Not need to delete because it is a dir");
		goto hndl_exit;
	}

	if (vnode->pps_file.not_del_after_swapin) {
		PPS_DEBUG(cat_os_pps, "File is not need to delete");
		goto hndl_exit;
	}

	if(!vnode->pps_file.is_created_by_root){
		memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
		msg.kind = PPS_F_HDR_CLOSE_FD_REQ;
		ret_stat = send_pps_file_handler_comm(vnode->pps_file.sockfd, msg);
		if (ret_stat < 0){
			goto fd_close;
		}
		memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
		recv_pps_file_handler_comm(vnode->pps_file.sockfd, &msg);
	}
fd_close:
	close(vnode->pps_file.fd);
	vnode->pps_file.fd = -1;
	vnode->pps_file.is_opened = false;
	vnode->pps_file.not_del_after_swapin = false;
	remove(vnode->pps_file.path);

hndl_exit:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief check swapin is need to pthread_cond_wait or not when there are not
 *  enough resource on VE side.
 *  swapin is need to pthread_cond_wait when:
 *  In the processes connected to the queue, all of them are swapping in
 *  In the processes connected to the queue, there a process with a status of
 *  swapping out is included, and the PPS buffer or swap file is full
 *  (when there is no 64MB page)
 *
 * @param [in] pointer to ve_node_struct
 * @retval true need to pthread_cond_wait
 * @retval false not need to pthread_cond_wait
 */
bool check_swap_in_need_wait(struct ve_node_struct *vnode)
{
	bool retval = false;
	int ret = -1;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = check_swap_out_in_process(SWAPPING_OUT);
	if (ret != 0) {
		PPS_DEBUG(cat_os_pps, "need wait because no swap out request");
		retval = true;
		goto hndl_return;
	}

	if (vnode->pps_mp != NULL) {
		PPS_DEBUG(cat_os_pps, "need check mem buddy");
		pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock),
		LOCK,
		"Failed to acquire PPS buddy lock");
		ret = check_free_buddy(vnode->pps_mp, PPS_PAGE_SIZE_64MB);
		if (ret == 0) {
			PPS_DEBUG(cat_os_pps, "free mem buddy is exist");
			goto hndl_free;
		}
	}

	if (vnode->pps_file_offset != NULL) {
		PPS_DEBUG(cat_os_pps, "need check file buddy");
		pthread_mutex_lock_unlock(
			&(vnode->pps_file_offset->buddy_mempool_lock),
			LOCK,
			"Failed to acquire PPS file buddy lock");
		ret = check_free_buddy(vnode->pps_file_offset, PPS_PAGE_SIZE_64MB);
		if (ret == 0) {
			PPS_DEBUG(cat_os_pps, "free file buddy is exist");
			goto hndl_free;
		}
	}

	PPS_DEBUG(cat_os_pps, "need wait because no enough resource");
	retval = true;

hndl_free:
	if (vnode->pps_mp != NULL) {
		pthread_mutex_lock_unlock(&(vnode->pps_mp->buddy_mempool_lock),
		UNLOCK,
		"Failed to release PPS buddy lock");
	}

	if (vnode->pps_file_offset != NULL) {
		pthread_mutex_lock_unlock(
			&(vnode->pps_file_offset->buddy_mempool_lock),
			UNLOCK,
			"Failed to release PPS file buddy lock");
	}
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

