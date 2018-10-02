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
#include "comm_request.h"
#include "task_mgmt.h"
#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"
#include "velayout.h"
#include "veos.h"
#include "veos_handler.h"

int nr_thrds = 0;
pthread_spinlock_t nr_thrds_lock;

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
	pthread_t tid = pthread_self();
	PseudoVeosMessage *pseudo_msg = NULL;
	char cmd_buff[MAX_PROTO_MSG_SIZE];

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

	ret = syscall(SYS_tgkill, pti->cred.pid, pseudo_msg->pseudo_pid, 0);
	if (ret == -1) {
		VEOS_ERROR("Authentication failure");
		VEOS_DEBUG("PID: %d is not a valid process",
				pseudo_msg->pseudo_pid);
		goto hndl_error;
	}

	VEOS_DEBUG("PID[%ld] VEOS received request %s for pseudo pid: %d",
			syscall(SYS_gettid),
			pseudo_veos_cmd[pseudo_msg->pseudo_veos_cmd_id].cmdname,
			pseudo_msg->pseudo_pid);

	pti->pseudo_proc_msg = pseudo_msg;

	/* Get ipc read lock */
	ret = pthread_rwlock_rdlock(&(VE_NODE(0)->ve_relocate_lock));
	if (0 > ret) {
		VEOS_ERROR("Failed to acquire relocate lock, retval %d", ret);
		veos_abort("Failed to acquire relocate lock");
	}
	ret = pseudo_veos_cmd[pseudo_msg->pseudo_veos_cmd_id].handler(pti);
	if (0 > ret) {
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
 * @brief Veos main thread
 *
 * @details veos handler function for handling messages from
 * Pseudo process and assigning Worker Threads to handle those messages
 *
 * @internal
 * @author PSMG / Process management
 */
void veos_main_thread(void *arg)
{
	int ret = -1;
	int l_sock = *(int *)arg;
	int a_sock = 0;

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
	FD_SET(l_sock, &readfds);

	/* main loop */
	while (terminate_flag == 0) {
		/* accept connection */
		while (1) {
			fflush(stdout);
			memcpy(&fds, &readfds, sizeof(fd_set));
			tv.tv_sec = TIMEOUT_SEC;
			tv.tv_usec = TIMEOUT_USEC;
			ret = select(l_sock+1, &fds, NULL, NULL, &tv);
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

			if (FD_ISSET(l_sock, &fds)) {
				a_sock = accept(l_sock, NULL, NULL);
				if (a_sock == -1) {
					VEOS_ERROR("Failed to accept "
							"connection, "
							"returned: %s",
							strerror(errno));
					continue;
				}
				break;
			}
		}

		/* Creating worker threads*/
		create_and_start_worker(a_sock, attr);
	}
terminate:
	VEOS_DEBUG("Termination flag SET VEOS main thread exiting");
	close(l_sock);
	ret = pthread_attr_destroy(&attr);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy thread attribute, "
				"return value %s", strerror(ret));
	ret = pthread_spin_destroy(&nr_thrds_lock);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy the spinlock variable, "
				"return value %s", strerror(ret));
	VEOS_TRACE("Exiting");
	return;
hndl_return:
	close(l_sock);
	ret = pthread_attr_destroy(&attr);
	if (ret != 0)
		VEOS_ERROR("Failed to destroy thread attribute, "
				"return value %s", strerror(ret));
	VEOS_TRACE("Exiting");
	veos_abort("VEOS Main thread failure...");
}
