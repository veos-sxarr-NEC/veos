/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file  veos_ipc.c
 * @brief Handling IPC requests from pseudo processes and commands.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <log4c.h>
#include <dhash.h>
#include "comm_request.h"
#include "vhve_request.h"
#include "task_mgmt.h"
#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"
#include "velayout.h"
#include "veos.h"
#include "veos_handler.h"
#include "locking_handler.h"
#include "ve_swap.h"
#include "ve_list.h"

int nr_thrds = 0;
int nr_vhve_thrds = 0;
pthread_spinlock_t nr_thrds_lock;
pthread_mutex_t nr_vhve_thrds_lock = PTHREAD_MUTEX_INITIALIZER;
__thread int prefered_core = 0;

extern void veos_vhve_dma_hash_free_all(hash_table_t *);

/**
 * @brief Handling of failure for veos handler
 *
 * @param[in] pti Thread "pti" for the handler
 *
 * @internal
 * @author PSMG / Process management
 */
void veos_handle_pseudo_proc_req_failure(veos_thread_arg_t *pti)
{
	PseudoVeosMessage new_ve_proc = PSEUDO_VEOS_MESSAGE__INIT;
	char cmd_buff[MAX_PROTO_MSG_SIZE] = {0};
	size_t pseudo_msg_len = -1, msg_len = -1;
	int retval = -1;

	VEOS_TRACE("Entering");

	new_ve_proc.has_syscall_retval = true;
	new_ve_proc.syscall_retval = -EFAULT;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&new_ve_proc);

	msg_len = pseudo_veos_message__pack(&new_ve_proc, (uint8_t *)cmd_buff);
	if (msg_len != pseudo_msg_len) {
		VEOS_ERROR("Packing message protocol buffer error");
		VEOS_DEBUG("Expected length: %ld Transferred length: %ld",
				pseudo_msg_len, msg_len);
		goto hndl_return;
	}
	retval = psm_pseudo_send_cmd(pti->socket_descriptor, cmd_buff,
			pseudo_msg_len);
	if (-1 == retval) {
		VEOS_ERROR("Failed to send response to pseudo process");
		VEOS_DEBUG("Expected bytes: %ld Transferred bytes: %d",
				pseudo_msg_len, retval);
	}

hndl_return:
	VEOS_TRACE("Exiting");
}

/**
 * @brief Invokes the handler function based on received message
 *
 * This function will authenticate the TID of requesting process
 * using SO_PEERCRED.
 *
 * @param[in] pti Thread "pti" for the handler
 *
 * @return 0 on Success, negative  on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int pseudo_proc_veos_handler(veos_thread_arg_t *pti)
{
	int sd = 0, rwl = -1, ret = -1;
	socklen_t len = 0;
	bool rw_lock = false;
	bool is_need_lock = false;
	pthread_t tid = pthread_self();
	PseudoVeosMessage *pseudo_msg = NULL;
	char cmd_buff[MAX_PROTO_MSG_SIZE];
	pid_t host_pid = -1;
	struct ve_task_struct *ve_task = NULL;
	struct ve_ipc_sync *ipc_sync = NULL;
	bool pid_checked = false;

	VEOS_TRACE("Entering");

	sd = pti->socket_descriptor;
	len = sizeof(struct ucred);

	memset(cmd_buff, '\0', MAX_PROTO_MSG_SIZE);
	ret = recv(sd, cmd_buff, MAX_PROTO_MSG_SIZE, 0);
	if (ret == -1) {
		VEOS_ERROR("client socket closed");
		VEOS_DEBUG("TID: %u connection lost", (unsigned int)tid);
		goto hndl_error;
	} else if (0 == ret) {
		VEOS_DEBUG("Peer process has performed an orderly"
				" shutdown");
		ret = -1;
		goto hndl_return;
	}

	/* Acquire reader lock befor handling IPC request */
	rwl = pthread_rwlock_tryrdlock(&handling_request_lock);
	if (rwl != 0) {
		VEOS_ERROR("Failed to acquire request handling Lock,"
			"return value %s", strerror(rwl));
		ret = -1;
		goto hndl_return;
	}
	rw_lock = true;

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(cmd_buff));
	if (NULL == pseudo_msg) {
		VEOS_ERROR("Unpacking message protocol buffer error");
		goto hndl_error;
	}

	if ((pseudo_msg->pseudo_veos_cmd_id >= PSEUDO_VEOS_MAX_MSG_NUM)
			|| (pseudo_msg->pseudo_veos_cmd_id < 0)) {
		VEOS_ERROR("VE OS received request for invalid command");
		VEOS_DEBUG("cmd id: %d", pseudo_msg->pseudo_veos_cmd_id);
		goto hndl_error;
	}

	/* Get options on socket */
	ret = getsockopt(sd, SOL_SOCKET, SO_PEERCRED, &(pti->cred), &len);
	if (0 != ret) {
		VEOS_ERROR("Failed to get options on socket, return "
				"value %s", strerror(errno));
		goto hndl_error;
	}

	if (pti->saved_pseudo_pid &&
		pti->saved_pseudo_pid == pseudo_msg->pseudo_pid)
		host_pid = pti->saved_host_pid;
	else {
		/* Convert namespace pid to host pid */
		host_pid = vedl_host_pid(VE_HANDLE(0), pti->cred.pid,
					pseudo_msg->pseudo_pid);
		if (host_pid <= 0) {
			VEOS_DEBUG("PID conversion failed, host: %d"
				" namespace: %d"
				" error: %s",
				pti->cred.pid,
				pseudo_msg->pseudo_pid,
				strerror(errno));
			goto hndl_error;
		}
	}

	/*
	 * We acquire ve_relocate_lock then invoke
	 * find_ve_task_struct(), because ve_task_struct is removed
	 * from a core and added to another core during relocation.
	 */
	ret = pthread_rwlock_rdlock(&(VE_NODE(0)->ve_relocate_lock));
	if (0 > ret) {
		VEOS_ERROR("Failed to acquire relocate lock, retval %d", ret);
		veos_abort("Failed to acquire relocate lock");
	}
	ve_task = find_ve_task_struct(host_pid);
	ret = pthread_rwlock_unlock(&(VE_NODE(0)->ve_relocate_lock));
	if (0 > ret) {
		VEOS_ERROR("Failed to release relocate lock, retval %d", ret);
		veos_abort("Failed to release relocate lock");
	}
	if (ve_task != NULL) {
		prefered_core = ve_task->core_id;
		if (ve_task->group_leader->pid == host_pid)
			pid_checked = true;
		ipc_sync = ve_get_ipc_sync(ve_task);
		put_ve_task_struct(ve_task);
		if (ipc_sync != NULL) {
			is_need_lock = true;
			/*
			 * We acquire swap_exclusion_lock to wait
			 * swap-in if the VE process is swapped out.
			 * Note ve_task_struct will be removed if
			 * VE process terminates.
			 */
			pthread_mutex_lock_unlock(
				&(ipc_sync->swap_exclusion_lock), LOCK,
				"Failed to aqcuire swap_exclusion_lock");
			while (ipc_sync->swapping != 0) {
				pthread_cond_wait(&(ipc_sync->swapping_cond),
					&(ipc_sync->swap_exclusion_lock));
			}
			ipc_sync->handling_request++;
			VEOS_DEBUG("ipc_sync(%p) : handling_request %d",
					ipc_sync, ipc_sync->handling_request);
			pthread_mutex_lock_unlock(
				&(ipc_sync->swap_exclusion_lock), UNLOCK,
				"Failed to release swap_exclusion_lock");
		}
	}

	if (!pid_checked) {
		ret = syscall(SYS_tgkill, pti->cred.pid, host_pid, 0);
		if (ret == -1) {
			VEOS_ERROR("Authentication failure");
			VEOS_DEBUG("PID: %d is not a valid process cred pid: %d",
				pseudo_msg->pseudo_pid, pti->cred.pid);
			goto hndl_error;
		}
	}

	pti->saved_pseudo_pid = pseudo_msg->pseudo_pid;
	pti->saved_host_pid = host_pid;
	pseudo_msg->pseudo_pid = host_pid;
	pti->pseudo_proc_msg = pseudo_msg;

	VEOS_DEBUG("PID[%ld] VEOS received request %s for pseudo pid: %d",
			syscall(SYS_gettid),
			pseudo_veos_cmd[pseudo_msg->pseudo_veos_cmd_id].cmdname,
			pseudo_msg->pseudo_pid);


	/* Get ipc read lock */
	ret = pthread_rwlock_rdlock(&(VE_NODE(0)->ve_relocate_lock));
	if (0 > ret) {
		VEOS_ERROR("Failed to acquire relocate lock, retval %d", ret);
		veos_abort("Failed to acquire relocate lock");
	}
	ret = pseudo_veos_cmd[pseudo_msg->pseudo_veos_cmd_id].handler(pti);
	if (0 > ret) {
		ret = -1;
		VEOS_ERROR("Failed to handle system call request from "
				"pseudo process");
		pthread_rwlock_unlock(&(VE_NODE(0)->ve_relocate_lock));
		goto hndl_return;
	}

	ret = pthread_rwlock_unlock(&(VE_NODE(0)->ve_relocate_lock));
	if (0 > ret) {
		VEOS_ERROR("Failed to release relocate lock, retval %d", ret);
		veos_abort("Failed to release relocate lock");
	}

	VEOS_DEBUG("%s Request Handled",
			pseudo_veos_cmd[pseudo_msg->pseudo_veos_cmd_id].cmdname);
	ret = 0;
	goto hndl_return;

hndl_error:
	ret = -1;
	veos_handle_pseudo_proc_req_failure(pti);

hndl_return:
	if (pseudo_msg != NULL)
		pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

	if (is_need_lock) {
		pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock),
				LOCK, "Failed to aqcuire swap_exclusion_lock");
		ipc_sync->handling_request--;
		VEOS_DEBUG("ipc_sync(%p) : handling_request %d",
					ipc_sync, ipc_sync->handling_request);
		if (ipc_sync->handling_request == 0)
			pthread_cond_signal(&(ipc_sync->handling_request_cond));
		pthread_mutex_lock_unlock(&(ipc_sync->swap_exclusion_lock),
				UNLOCK, "Failed to release swap_exclusion_lock");
		ve_put_ipc_sync(ipc_sync);
	}

	if (rw_lock == true) {
		rwl = pthread_rwlock_unlock(&handling_request_lock);
		if (rwl != 0)
			VEOS_ERROR("Failed to release request handling lock, "
					"return value %s", strerror(rwl));
	}

	VEOS_TRACE("Exiting");
	return ret;
}

/**
 * @brief Invokes the handler function based on received message
 *
 * @param[in] pti Thread "pti" for the handler
 *
 * @return 0 on Success, negative  on failure
 *
 * @internal
 * @author VHVE
 */
int vh_proc_veos_handler(veos_vhve_thread_arg_t *pti)
{
	int sd = -1, rwl = -1, ret = -1;
	socklen_t len = 0;
	bool rw_lock = false;
	pthread_t tid = pthread_self();
	char cmd_buff[MAX_VHVE_MSG_SIZE];
	struct vhve_result msg = { VHVE_RESULT, 0, 0 };
	uint64_t *cmd, *vhpid;

	VEOS_TRACE("Entering");

	sd = pti->socket_descriptor;
	len = sizeof(struct ucred);

	ret = recv(sd, cmd_buff, MAX_VHVE_MSG_SIZE, 0);
	if (ret == -1) {
		VEOS_DEBUG("client vh process socket closed");
		VEOS_DEBUG("TID: %u connection lost", (unsigned int)tid);
		goto hndl_return;
	} else if (0 == ret) {
		VEOS_DEBUG("Peer process has performed an orderly"
				" shutdown");
		ret = -1;
		goto hndl_return;
	}
	pti->vh_proc_size = ret;
	cmd = (uint64_t *)cmd_buff;

	/* Acquire reader lock befor handling IPC request */
	rwl = pthread_rwlock_tryrdlock(&handling_request_lock);
	if (rwl != 0) {
		VEOS_ERROR("Failed to acquire request handling Lock,"
				"return value %s", strerror(rwl));
		ret = -1;
		goto hndl_return;
	}
	rw_lock = true;

	if (*cmd >= VHVE_VEOS_MAX_MSG_NUM) {
		VEOS_ERROR("VE OS received request for invalid command");
		VEOS_DEBUG("cmd id: %ld", *cmd);
		goto hndl_error;
	}
	vhpid  =  (uint64_t *)(cmd_buff+16);

	/* Get options on socket */
	ret = getsockopt(sd, SOL_SOCKET, SO_PEERCRED, &(pti->cred), &len);
	if (0 != ret) {
		VEOS_ERROR("Failed to get options on socket, return "
				"value %s", strerror(errno));
		goto hndl_error;
	}

	pti->vh_proc_msg = cmd_buff;

	VEOS_DEBUG("PID[%ld] VEOS received request %s for VH process pid: %ld",
			syscall(SYS_gettid), pseudo_veos_cmd[*cmd].cmdname,
			*vhpid);

	ret = vhve_veos_cmd[*cmd].handler(pti);
	if (0 > ret) {
		ret = -1;
		VEOS_ERROR("Failed to handle request from "
				"vh process");
		goto hndl_return;
	}

	VEOS_DEBUG("%s Request Handled",
			vhve_veos_cmd[*cmd].cmdname);
	ret = 0;
	goto hndl_return;

hndl_error:
	msg.ret = -EFAULT;
	ret = psm_pseudo_send_cmd(pti->socket_descriptor, &msg,
			sizeof(struct vhve_result));
	if (sizeof(struct vhve_result) != ret) {
		VEOS_DEBUG("Failed to send response to VH process");
		VEOS_DEBUG("Expected bytes: %d Transferred bytes: %d",
				16, ret);
	}
	ret = -1;

hndl_return:
	if (rw_lock == true) {
		rwl = pthread_rwlock_unlock(&handling_request_lock);
		if (rwl != 0)
			VEOS_ERROR("Failed to release request handling lock, "
					"return value %s", strerror(rwl));
	}

	VEOS_TRACE("Exiting");
	return ret;
}

/**
 * @brief Handles request from Pseudo Process
 *
 * @param[in] arg Thread "pti" which will handle the message
 *
 * @return void pointer
 *
 * @internal
 * @author PSMG / Process management
 */
static void *veos_worker_thread(void *arg)
{
	int ret = -1;
	struct veos_thread_arg *pti = (struct veos_thread_arg *)arg;
	pthread_t selfid = pthread_self();

	VEOS_TRACE("Entering");

	VEOS_DEBUG("Tid %u is started", (unsigned int)selfid);

	while (!terminate_flag) {

		VEOS_DEBUG("TID:%u socket descriptor number is %d",
				(unsigned int)selfid,
				pti->socket_descriptor);

		/* stat server process */
		ret = pseudo_proc_veos_handler(pti);
		if (ret == -1) {
			VEOS_DEBUG("Failed to handle the request from "
					"pseudo process");
			goto thread_end;
		}
	}

	VEOS_DEBUG("Termination flag SET VEOS worker thread exiting");
thread_end:
	ret = pthread_spin_lock(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to acquire spin lock, return value %s",
				strerror(ret));
	nr_thrds--;    /* decrease no. of threads */
	ret = pthread_spin_unlock(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to release spin lock, return value %s",
				strerror(ret));
	close(pti->socket_descriptor);

	free(pti);
	VEOS_TRACE("Exiting");
	return 0;
}

/**
 * @brief Handles request from VH Process(not PSEUDO)
 *
 * @param[in] arg Thread "pti" which will handle the message
 *
 * @return void pointer
 *
 * @internal
 * @author VHVE
 */
static void *veos_vhve_worker_thread(void *arg)
{
	int ret = -1;
	char c = 'a';
	hash_table_t *dma_req_hdl_list;
	struct veos_vhve_thread_arg *pti = (struct veos_vhve_thread_arg *)arg;
	pthread_t selfid = pthread_self();

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Tid %u is started", (unsigned int)selfid);

	ret = psm_pseudo_send_cmd(pti->socket_descriptor, &c, 1);
	if (1 != ret) {
		VEOS_ERROR("Failed to send first message to VH process");
		goto error_hndl;
	}

	ret = hash_create(VHVE_DMAREQ_HASH_SIZE, &dma_req_hdl_list, NULL, NULL);
	if (HASH_SUCCESS != ret) {
		VEOS_ERROR("VHVE: Fail to initialize hash table (%s)",
				hash_error_string(ret));
		goto error_hndl;
	}

	pti->dma_req_hdl_list = dma_req_hdl_list;

	while (!terminate_flag) {

		VEOS_DEBUG("TID:%u socket descriptor number is %d",
				(unsigned int)selfid,
				pti->socket_descriptor);

		/* start server process */
		ret = vh_proc_veos_handler(pti);
		if (ret == -1) {
			VEOS_DEBUG("Failed to handle the request from "
					"VH process");
			goto thread_end;
		}
	}

	VEOS_DEBUG("Termination flag SET VEOS worker thread exiting");

thread_end:
	veos_vhve_dma_hash_free_all(dma_req_hdl_list);
        hash_destroy(dma_req_hdl_list);
error_hndl:
	ret = pthread_mutex_lock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to acquire mutex lock, return value %s",
				strerror(ret));
	nr_vhve_thrds--;    /* decrease no. of threads */
	ret = pthread_mutex_unlock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to release mutex lock, return value %s",
				strerror(ret));
	close(pti->socket_descriptor);
	free(pti);

	VEOS_TRACE("Exiting");
	return 0;
}


/**
 * @brief Function used to create dedicate worker thread
 *
 * @details Creates dedicated worker thread per pseudo process
 *		to handle ipc request from pseudo.
 *
 * @param[in] sock: Connected socket fd
 * @param[in] attr: Thread attribute
 *
 * @internal
 * @author PSMG / Process management
 */
static void create_and_start_worker(int sock, pthread_attr_t attr)
{
	int ret = -1;
	pthread_t tid;
	struct veos_thread_arg *veos_pt_info = NULL;

	VEOS_TRACE("Entering");

	if (!(nr_thrds < VEOS_MAX_THREADS)) {
		VEOS_ERROR("Cannot accept more connections");
		VEOS_DEBUG("Max number of connections accpeted: %d",
				VEOS_MAX_THREADS);
		close(sock);
		goto hndl_return;
	}

	veos_pt_info = (struct veos_thread_arg *)malloc
		(sizeof(struct veos_thread_arg));
	if (veos_pt_info == NULL) {
		VEOS_CRIT("Failed to allocate memory for VEOS thread arguments,"
				" return value %s", strerror(errno));
		close(sock);
		goto hndl_return;
	}
	memset(veos_pt_info, '\0', sizeof(struct veos_thread_arg));

	veos_pt_info->socket_descriptor = sock;
	ret = pthread_create(&tid, &attr, &veos_worker_thread,
			(void *)veos_pt_info);
	if (ret != 0) {
		VEOS_FATAL("Failed to create VEOS worker thread %s",
				strerror(ret));
		close(sock);
		free(veos_pt_info);
		goto hndl_return;
	}
	ret = pthread_spin_lock(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to acquire spin lock, return value %s",
				strerror(ret));
	nr_thrds++;        /* increase no of threads */
	ret = pthread_spin_unlock(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to release spin lock, return value %s",
				strerror(ret));

	VEOS_DEBUG("Thread created no: %d with TID %u", nr_thrds, (unsigned int)tid);

hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Function used to create dedicate worker thread
 *
 * @details Creates dedicated worker thread per VH process
 *              to handle ipc request from libvhve.
 *
 * @param[in] sock: Connected socket fd
 * @param[in] attr: Thread attribute
 *
 * @internal
 * @author VHVE
 */
static void create_and_start_vhve_worker(int sock, pthread_attr_t attr)
{
	int ret = -1;
	int local_nr_vhve_thrds;
	pthread_t tid;
	struct veos_vhve_thread_arg *veos_pt_info = NULL;

	VEOS_TRACE("Entering");

	ret = pthread_mutex_lock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to acquire mutex lock, return value %s",
				strerror(ret));
	local_nr_vhve_thrds = nr_vhve_thrds;
	ret = pthread_mutex_unlock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to release mutex lock, return value %s",
				strerror(ret));

	if (local_nr_vhve_thrds >= VEOS_VHVE_MAX_THREADS) {
		VEOS_ERROR("Cannot accept more connections");
		VEOS_DEBUG("Max number of connections accpeted: %d",
				VEOS_VHVE_MAX_THREADS);
		close(sock);

		goto hndl_return;
	}

	veos_pt_info = (struct veos_vhve_thread_arg *)malloc
		(sizeof(struct veos_vhve_thread_arg));
	if (veos_pt_info == NULL) {
		VEOS_CRIT("Failed to allocate memory for VEOS thread arguments,"
				" return value %s", strerror(errno));
		close(sock);
		goto hndl_return;
	}
	memset(veos_pt_info, '\0', sizeof(struct veos_thread_arg));

	veos_pt_info->socket_descriptor = sock;
	ret = pthread_create(&tid, &attr, &veos_vhve_worker_thread,
			(void *)veos_pt_info);
	if (ret != 0) {
		VEOS_FATAL("Failed to create VEOS worker thread %s",
				strerror(ret));
		close(sock);
		free(veos_pt_info);
		goto hndl_return;
	}
	ret = pthread_mutex_lock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to acquire mutex lock, return value %s",
				strerror(ret));
	nr_vhve_thrds++;        /* increase no of threads */
	ret = pthread_mutex_unlock(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to release mutex lock, return value %s",
				strerror(ret));

	VEOS_DEBUG("Thread created no: %d with TID %u", nr_thrds, (unsigned int)tid);

hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Veos main thread
 *
 * @details veos handler function for handling messages from
 * Pseudo or VH process and assigning Worker Threads to handle those messages
 *
 * @internal
 * @author PSMG / Process management
 */
void veos_main_thread(void *arg)
{
	int ret = -1;
	int l_sock[2];
	l_sock[0] = *(int *)arg;
	l_sock[1] = *(int *)((char *)arg+4);
	int a_sock[2];
	int max_l_sock = l_sock[0] > l_sock[1] ? l_sock[0]:l_sock[1];

	fd_set fds, readfds;
	struct timeval tv = {0};
	pthread_attr_t attr;

	VEOS_TRACE("Entering");

	if (pthread_attr_init(&attr) != 0) {
		VEOS_ERROR("Initializing thread attribute failed");
		goto hndl_return;
	}
	if (pthread_spin_init(&nr_thrds_lock, 0) != 0) {
		VEOS_ERROR("Failed to initialize spinlock variable");
		goto hndl_return;
	}
	if (pthread_attr_setdetachstate(&attr,
				PTHREAD_CREATE_DETACHED) != 0) {
		VEOS_ERROR("Failed to set detachstate attribute");
		goto hndl_return;
	}

	FD_ZERO(&readfds);
	FD_SET(l_sock[0], &readfds);
	FD_SET(l_sock[1], &readfds);

	/* main loop */
	while (terminate_flag == 0) {
		a_sock[0] = -1;
		a_sock[1] = -1;
		/* accept connection */
		while (1) {
			fflush(stdout);
			memcpy(&fds, &readfds, sizeof(fd_set));
			tv.tv_sec = TIMEOUT_SEC;
			tv.tv_usec = TIMEOUT_USEC;
			ret = select(max_l_sock + 1, &fds, NULL, NULL, &tv);
			if (terminate_flag == 1)
				goto terminate;

			if (ret == 0)
				continue;
			else if (ret == -1) {
				VEOS_ERROR("Failed to monitor on "
						"file descriptors,"
						" returned %s",
						strerror(errno));
				goto hndl_return;
			}

			if (FD_ISSET(l_sock[0], &fds)) {
				a_sock[0] = accept(l_sock[0], NULL, NULL);
				if (a_sock[0] == -1) {
					VEOS_ERROR("Failed to accept "
							"connection, "
							"returned: %s",
							strerror(errno));
				}
			}
			if (FD_ISSET(l_sock[1], &fds)) {
				a_sock[1] = accept(l_sock[1], NULL, NULL);
				if (a_sock[1] == -1) {
					VEOS_ERROR("Failed to accept "
							"connection, "
							"returned: %s",
							strerror(errno));
				}
			}
			if (a_sock[0] >= 0 || a_sock[1] >= 0)
				break;
		}

		/* Creating worker threads*/
		if (a_sock[0] >= 0)
			create_and_start_worker(a_sock[0], attr);
		if (a_sock[1] >= 0)
			create_and_start_vhve_worker(a_sock[1], attr);
	}
terminate:
	VEOS_DEBUG("Termination flag SET VEOS main thread exiting");
	close(l_sock[0]);
	close(l_sock[1]);
	ret = pthread_attr_destroy(&attr);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy thread attribute, "
				"return value %s", strerror(ret));
	ret = pthread_spin_destroy(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy the spinlock variable, "
				"return value %s", strerror(ret));
	ret = pthread_mutex_destroy(&nr_vhve_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy the spinlock variable for VHVE, "
				"return value %s", strerror(ret));
	VEOS_TRACE("Exiting");
	return;
hndl_return:
	close(l_sock[0]);
	close(l_sock[1]);
	ret = pthread_attr_destroy(&attr);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy thread attribute, "
				"return value %s", strerror(ret));
	VEOS_TRACE("Exiting");
	veos_abort("VEOS Main thread failure...");
}
