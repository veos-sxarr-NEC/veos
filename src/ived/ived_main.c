/**
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
 * @file  ived_main.c
 * @brief Main source of IVED (daemon)
 *
 * @internal
 * @author VESHM
 */
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <search.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include <uuid/uuid.h>
#include <poll.h>
#include <log4c.h>
#include <systemd/sd-daemon.h>
#include "config.h"
#include "ve_list.h"
#include "ived_common.h"
#include "ived_ipc.h"
#include "ived.pb-c.h"
#include "ived.h"
#include "ived_cr_core.h"
#include "ived_veshm_core.h"
#include "ived_main.h"
#include "ived_ipc_func.h"
#include "veshm_ipc.h"
#include "cr_ipc.h"
#include "ived_core.h"
#include "veshm_core.h"
#include "cr_core.h"

char *ived_sock_file = NULL;
static ived_thread_arg_t *pt_info;
static pthread_t *worker_tid;
static sem_t worker_sem;
static volatile sig_atomic_t thread_running = 0;

struct veos_info veos_info[MAX_VE_NODE];

uuid_t null_id;

log4c_category_t *log4cat_main = NULL;
log4c_category_t *log4cat_veshm= NULL;
log4c_category_t *log4cat_cr   = NULL;

/* Lock and Lock Attributes */
pthread_mutexattr_t chkmutex;	/* PTHREAD_MUTEX_ERRORCHECK_NP */
pthread_mutex_t node_idx_lock;	/* For OS registration */
pthread_mutex_t boot_lock[MAX_VE_NODE];	/* A register OS request must acquire it.*/

/* When IVED acquires locks, IVED must acquires locks
 * in this order.
 * 1. node_idx_lock		 # OS boot only
 * 2. veos_info[].os_lock
 * 3. boot_lock[]		 # OS boot only
 * 4. struct process_info.proc_info
 */

#define UNUSED	-1
#define ROOT_USR 0

struct ived_handler_list ived_ipc_handlers[IVED_MAX_CMD_NUM] = {
	{IVED_COMMON,	ived_handle_daemon_request},
	{IVED_VESHM,	ived_handle_veshm_request},
	{IVED_CR,	ived_handle_cr_request},
	{-1,		NULL},
};


/**
 * @brief Initialize IVED
 *
 * @return 0 on success, -1 on failure
 */
int
initialize_ived()
{
	int i, j;
	int ret = 0, retval = 0;
	struct sigaction act;
	struct cr_page_info *cr_info = NULL;

	/* log4c */
	log4cat_main = log4c_category_get("veos.ived.main");
	log4cat_veshm= log4c_category_get("veos.ived.veshm");
	log4cat_cr   = log4c_category_get("veos.ived.cr");
	log4cat_lib  = log4c_category_get("veos.ived");

	/* Initialize attributes */
	pthread_mutexattr_init(&chkmutex);
	pthread_mutexattr_settype(&chkmutex, PTHREAD_MUTEX_ERRORCHECK_NP);

	node_idx_lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;

	for (i=0; i< MAX_VE_NODE; i++){
		ret = pthread_mutex_init(&boot_lock[i], NULL);
		if ( ret != 0 ){
			IVED_CRIT(log4cat_main, "Initializing IVED failed: %s", 
				  strerror(ret));
			return (-1);
		}
	}

	/* Initialize semaphore */
	ret = sem_init(&worker_sem, 0, MAX_THREADS);
	if ( ret != 0 ){
		IVED_CRIT(log4cat_main, "Initializing IVED failed: %s", 
			  strerror(ret));
		return (-1);
	}

	/* data structures */
	for (i=0; i< MAX_VE_NODE; i++){
		veos_info[i].node_stat = VE_STAT_UNUSED;
		veos_info[i].os_pid    = UNUSED;
		veos_info[i].drv_socket_name = NULL;
		veos_info[i].veos_sock  = UNUSED;
		ret = pthread_mutex_init(&veos_info[i].veos_sock_lock, NULL); 
		ret = pthread_mutex_init(&veos_info[i].os_lock, &chkmutex);
		ret = pthread_cond_init(&veos_info[i].os_cv, NULL);
		if (ret != 0){
			IVED_CRIT(log4cat_main, "Initializing IVED failed: %s",
				  strerror(errno));
			return (-1);
		}
		INIT_LIST_HEAD(&veos_info[i].proc_info_list);
		INIT_LIST_HEAD(&veos_info[i].veshm_mem_info_list);

		veos_info[i].cr_page_info = (struct cr_page_info *)malloc
			(sizeof(struct cr_page_info) * NODE_CR_PAGE_NUM);
		if (veos_info[i].cr_page_info == NULL){
			IVED_CRIT(log4cat_main, "Initializing IVED failed: %s",
				  strerror(errno));
			return (-1);
		}
		for (j=0; j < NODE_CR_PAGE_NUM; j++){
			cr_info = &(veos_info[i].cr_page_info[j]);
			cr_info->os_info       = &veos_info[i];
			cr_info->cr_page_num   = i;
			cr_info->uid           = UNUSED;
			cr_info->mode_flag     = CR_MODE_INIT;
			cr_info->reference_cnt = 0;
			INIT_LIST_HEAD(&cr_info->erase_list);
			INIT_LIST_HEAD(&cr_info->cr_users_list);
			ret = pthread_mutex_init(&cr_info->cr_lock, &chkmutex);
			if (ret != 0){
				IVED_CRIT(log4cat_main, "Initializing IVED failed: %s",
					  strerror(errno));
				return (-1);
			}
		}
	}

	/* Ignore signals */
	act.sa_handler = SIG_IGN;
	act.sa_flags   = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);
	sigaction(SIGTSTP, &act, NULL);
	sigaction(SIGTTOU, &act, NULL);
	sigaction(SIGTTIN, &act, NULL);
	assert( errno == 0 );

	/* etc. */
	uuid_clear(null_id);

	IVED_INFO(log4cat_main, "IVED initialized");
	return (retval);
}

/**
 * @brief Check VEOS process by kill()
 *
 * NOTE: PID is reused. Even though kill() succeeded,
 * PID may not be VEOS. Therefore, return value of this 
 * function is 0 when kill() returns 0.
 *
 * @param [in] os_pid	  PID of VEOS
 *
 * @return 0 or VE_STAT_STOP on success, -1 on failure
 * @retval 0 (Not change)
 * @retval VE_STAT_STOP
 * @retval -1 on failure
 */
int
test_os_pid(int os_pid){
	int ret, retval = -1;

	errno = 0;
	ret = kill(os_pid, 0);
	if (ret == 0){
		retval = 0;

	} else {
		if (errno == ESRCH){
			retval = VE_STAT_STOP;
		} else {
			IVED_ERROR(log4cat_main, 
				   "OS pid test failed (pid:%d, %s)",
				   os_pid, strerror(errno));
			retval = -1;
		}
	}
	IVED_DEBUG(log4cat_main, "retval: %d", retval);
	return(retval);
}


/**
 * @brief Check a socket to VEOS by poll()
 *
 * @param [in] os_pid	  PID of VEOS
 * @param [in] veos_sock  Socket to VEOS
 *
 * @return 0 or VE_STAT_STOP on success, -1 on failure
 * @retval 0 (Not change)
 * @retval VE_STAT_STOP
 * @retval -1 on failure
 */
int
test_os_socket(int os_pid, int veos_sock){
	int retval = -1;
	struct pollfd pollfd;
	int pollval;

	if (veos_sock <= 0){
		return(-1);
	}

	/* Check a connection to the target OS */
	pollfd.fd      = veos_sock;
	pollfd.events  = POLLRDHUP;
	pollfd.revents = 0;

	pollval = poll(&pollfd, 1, 0);

	if (pollval == 0){
		/* timeout and no events */
		retval = 0;

	} else if (pollval < 0){
		IVED_ERROR(log4cat_main, 
			   "OS socket test failed (pid:%d, %s)",
			   os_pid, strerror(errno));
		retval = -1;

	} else if (pollval > 0){
		if (pollfd.revents & POLLNVAL){
			IVED_DEBUG(log4cat_main, 
				   "OS socket test: Socket not open (pid:%d)",
				   os_pid);
			retval = VE_STAT_STOP;
		}
		if (pollfd.revents & POLLERR){
			IVED_ERROR(log4cat_main, 
				   "OS socket test: Error condition (pid:%d)",
				   os_pid);
			retval = 0;
		}
		if (pollfd.revents & (POLLRDHUP | POLLHUP)){
			retval = VE_STAT_STOP;
		}
	}

	IVED_DEBUG(log4cat_main, "retval: %d", retval);
	return (retval);
}


/**
 * @brief Read os_state file and set node_stat to STOP if it is offline
 * NOTE: Before entering this function, a caller must acquire a lock.
 * os_lock
 *
 * @param [in] os_info Target os
 *
 * @return 0 on success, -1 on failure
 */
int
test_os_state(struct veos_info *os_info)
{
	int ret, retval = -1;

	if (os_info == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		goto err_ret;
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0)
		goto err_ret;

	/* Check status */
	if(os_info->node_stat == VE_STAT_STOP)
		goto ret_success;

	/* NOTE: Even if a process whose pid is "os_info->os_pid" exists,
	 * the process may not VEOS. It is because PID can be recycled. 
	 * Checking by kill(pid,0) is not enough. */

	ret = test_os_pid(os_info->os_pid);

	if ( ret != VE_STAT_STOP ){
		/* Check by socket status */
		pthread_mutex_lock(&os_info->veos_sock_lock);
		ret = test_os_socket(os_info->os_pid, os_info->veos_sock);
		pthread_mutex_unlock(&os_info->veos_sock_lock);
	}
	if (ret == 0){
		/* VE_STAT_RUNNING */
		goto ret_success;
	} else if (ret < 0){
		goto err_ret;
	}

	IVED_INFO(log4cat_main, "Update OS node_stat (%s): %s -> STOP",
		  os_info->drv_socket_name,
		  (os_info->node_stat == VE_STAT_RUNNING) ?  "RUNNING" :
		  (os_info->node_stat == VE_STAT_STOP) ?  "STOP" :
		  (os_info->node_stat == VE_STAT_UNUSED) ?  "UNUSED" :
		  "UNKNOWN");
	os_info->node_stat = VE_STAT_STOP;

ret_success:
	retval = 0;
err_ret:
	IVED_TRACE(log4cat_main, "retval:%d.", retval);
	return(retval);
}

/**
 * @brief Processing a request.
 *
 * IVED checks a request whether it is a single request or it causes 
 * successive requests by main command of the request.
 * If a request is registration of VEOS, IVED calls server process function.
 *
 * @param [in]     pti	 Pointer of thread information	
 *
 * @return: On success returns 0 and 1 on failure
 */
int 
process_request(ived_thread_arg_t *pti) 
{
	int i;
	int ret;
	int retval = 1;
	int sd;			/* socket descriptor */
	uint8_t	*message_buf = NULL;
	RpcCommand *rpc_command = NULL;
	int (*handler)(ived_thread_arg_t *);
	pthread_t tid = pthread_self();
	int message_len;

	int rpc_retval = IVED_REQ_NG;	/* Return value of RPC message */
	int rpc_reterr = 0;	/* Return error of RPC message */

	if (pti == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	sd = pti->socket_descriptor;
	IVED_TRACE(log4cat_main, "TID[%u] Server Process sd = %d", 
		   (unsigned int)tid, sd);

	message_buf = pti->telegram_buf;
	ret = ived_rpc_receive(sd, &message_buf);
	if (ret < 0) {
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}
	message_len = ret;

	/* Unpack the main command only */
	rpc_command = rpc_command__unpack(NULL, message_len, message_buf);
	if (rpc_command == NULL){
		IVED_ERROR(log4cat_main, 
			   "TID[%u] Unpacking a message failed.\n",
			   (unsigned int)tid);
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	/* Main command and packed request are set in pti, and 
	 * call specified handler. 
	 * The handler sends a reply.
	 */
	handler = NULL;
	for (i = 0; i< IVED_MAX_CMD_NUM; i++){
		if (ived_ipc_handlers[i].command != rpc_command->cmd){
			continue;
		} else {
			pti->request = rpc_command;
			handler = ived_ipc_handlers[i].handler;
			break;
		}
	}
	IVED_TRACE(log4cat_main, "[%u] cmd = %d handler: %p", 
		   (uint)pthread_self(),
		   rpc_command->cmd, handler);
	if (handler == NULL){
		IVED_CRIT(log4cat_main, "handler is not found.");
		rpc_reterr = -ECANCELED;
		goto err_ret;
	}

	retval = 0;
	rpc_retval = IVED_REQ_OK; /* It is not send. */

	handler(pti);		/* call a specified function */

err_ret:
	if (pti != NULL){
		pti->request = NULL;
	}

	if (rpc_command != NULL)
		rpc_command__free_unpacked(rpc_command, NULL);
	if (message_buf != NULL)
		memset(message_buf, 0, IVED_BUF_MAX_SIZE);
	if (retval == 1){
		IVED_ERROR(log4cat_main, "Receiving a request failed");
		if (pti != NULL){
			ived_send_int64(pti->socket_descriptor, 
					rpc_retval, rpc_reterr);
		}

	}
	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());
	return retval;
}


/**
 * @brief Mark worker thread as usable.
 * 
 * @param [in]     pti	 Pointer of thread information	
 *
 * @returne0
 */
static int
change_thread_unused(ived_thread_arg_t *pti)
{
	if (pti == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		abort();
	}
	errno = 0;
	pthread_mutex_lock(&pti->mtx);
	pti->tid_used = THREAD_WAIT_FOR_USE;
	pti->socket_not_close = 0;
	pthread_mutex_unlock(&pti->mtx);

	return(0);
}


/**
 * @brief  worker thread function
 *
 * It is started by the main thread. This function checks socket's credential.
 * If this function failed, it sends a return message to a client.
 *
 * @param [in]   arg Argument to worker thread which is REQ packet
 *
 * @return 0 on success, 1 on failure
 */
static void *
ived_thread_start(void *arg) 
{
	int ret = 0;
	int retval=0;		/* return value of this function */
	ived_thread_arg_t *pti = (ived_thread_arg_t *)(void *)arg;
	pthread_t selfid = pthread_self();
	int ucred_size = sizeof(struct ucred);
	sigset_t set;

	int rpc_retval = 0;	/* Return value of RPC message */
	int rpc_reterr = 0;	/* Return error of RPC message */

	IVED_DEBUG(log4cat_main, "tid %u is started.", (unsigned int)selfid);

	if (pti == NULL){
		IVED_CRIT(log4cat_main, "Thread data is invalid.");
		goto pti_error;
	}

	/* Ignore signals */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGABRT);
	sigaddset(&set, SIGQUIT);
	ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
	assert( ret == 0 );

	pthread_mutex_init(&pti->mtx, NULL);
	pthread_cond_init(&pti->cond, NULL);

	ret = get_rpc_buf(&pti->telegram_buf, IVED_BUF_MAX_SIZE);
	if (ret != 0){
		IVED_CRIT(log4cat_main, "Allocating a buffer failed");
		goto pti_error;
	}
	memset(pti->telegram_buf, 0, IVED_BUF_MAX_SIZE);

	while (thread_running) {
		pthread_mutex_lock(&pti->mtx);

		/* wait until awaken */
		while (pti->tid_used != THREAD_IN_USE) {
			pthread_cond_wait(&pti->cond, &pti->mtx);
			if (pti->tid_used == THREAD_STOP) {
				pthread_mutex_unlock(&pti->mtx);
				IVED_INFO(log4cat_main, "[%u] Thread is shutting down.",
					  (uint)pthread_self());
				goto thread_end;
			}
		}

		pthread_mutex_unlock(&pti->mtx);
		IVED_TRACE(log4cat_main, "[%u] socket descriptor number is %d",
			   (unsigned int)selfid, pti->socket_descriptor);

		ret = getsockopt(pti->socket_descriptor, SOL_SOCKET, 
				 SO_PEERCRED, &(pti->cred), 
				 (socklen_t *)&ucred_size);
		if (ret != 0 ){
			IVED_ERROR(log4cat_main, "Getting credential failed.(%s)",
				   strerror(errno));
			rpc_retval = IVED_REQ_NG;
			rpc_reterr = -ECANCELED;
		}
		if (pti->cred.uid != ROOT_USR){
			IVED_DEBUG(log4cat_main, "Credential check failed.");
			rpc_retval = IVED_REQ_NG;
			rpc_reterr = -EACCES;
		}

		if (rpc_retval == IVED_REQ_NG){
			IVED_DEBUG(log4cat_main, "Connection failed");
			ived_send_int64(pti->socket_descriptor, 
					rpc_retval, rpc_reterr);
			close(pti->socket_descriptor);
			pti->socket_descriptor = -1;

			rpc_retval = 0;
			rpc_reterr = 0;

			/* Cancel a request */
			change_thread_unused(pti);
			sem_post(&worker_sem);

			continue;
		}

		process_request(pti);

		if (pti->socket_not_close == 0){
			/* If a request is IVED_OS_REG, socket_not_close is
			 * set 1.  The socket is reused for a request from IVED. */
			close(pti->socket_descriptor);
			pti->socket_descriptor = -1;
		}

		/* Finish a request */
		change_thread_unused(pti);
		sem_post(&worker_sem);

		IVED_DEBUG(log4cat_main, 
			   "Request Handled and thread released.\n");
	}

thread_end:
	pthread_mutex_destroy(&pti->mtx);
	pthread_cond_destroy(&pti->cond);
	if (pti->telegram_buf != NULL){
		free(pti->telegram_buf);
	}

pti_error:
	pthread_exit(&retval);
}


/**
 * @brief  This function cleanups the resources required
 * for the VE node.
 *
 * @return None
 */
int 
ived_shutdown()
{
	int i;

	/* Nortify ived status to systemctl. */
	sd_notify(0, "STOPPING=1");

	IVED_INFO(log4cat_main, "[%u] Start IVED shutdown.", 
		  (unsigned int) pthread_self());
	for (i = 0; i < MAX_THREADS; i++) {
		pthread_mutex_lock(&pt_info[i].mtx);
		pt_info[i].tid_used = THREAD_STOP;
		pthread_cond_signal(&pt_info[i].cond);
		pthread_mutex_unlock(&pt_info[i].mtx);
	}

	/* Wait worker threads' exit */
	for (i = 0; i < MAX_THREADS; i++) {
		pthread_join(worker_tid[i], NULL);
	}

	/* Clear lock/cond of veos data structures */
	for (i=0; i< MAX_VE_NODE; i++){
		pthread_mutex_destroy(&veos_info[i].veos_sock_lock); 
		pthread_mutex_destroy(&veos_info[i].os_lock);
		pthread_cond_destroy(&veos_info[i].os_cv);
	}

	sem_destroy(&worker_sem);

	IVED_INFO(log4cat_main, "ived shutdown succeeded.");
	log4c_fini();

	exit(0);
}

/**
 * sigint_handler: Signal Handler function
 *
 * @param : Integer type arg
 */
void 
sigint_handler(int arg) 
{
	thread_running = 0;
}

/**
 * @brief This thread waits connection from VEOS and 
 * pass them to next processing phase.
 *
 */
void 
ived_main_thread() 
{
	int i;
	int l_sock;
	int a_sock;
	struct sigaction act;

	struct sockaddr_un sa = {0};

	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());

	/* Set signal handler */
	act.sa_handler = sigint_handler;
	act.sa_flags   = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGABRT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	assert( errno == 0 );

	/* create socket */
	if ((l_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		IVED_FATAL(log4cat_main, "Socket for IVED server failed.");
		goto ived_error;
	}

	/* create sockaddr_un */
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, ived_sock_file, sizeof(sa.sun_path));
	sa.sun_path[sizeof(sa.sun_path)-1] = '\0';

	/* remove file if already exists */
	remove(sa.sun_path);

	/* bind */
	if (bind(l_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		IVED_FATAL(log4cat_main, "IVED Server could not bind.");
		goto ived_error;
	}

	/* listen */
	if ((listen(l_sock, 80)) == -1) {
		IVED_FATAL(log4cat_main, "IVED listen failed.");
		goto ived_error;
	}
	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());

	/* Nortify ived status to systemctl. */
	sd_notify(0, "READY=1");

	/* main loop */
	while (1) {
		/* accept connection */
		while (1) {
			if (thread_running == 0)
				goto ived_terminate; 

			sem_wait(&worker_sem);

			IVED_TRACE(log4cat_main, "Get semaphore.") ;
			errno = 0;
			a_sock = accept(l_sock, NULL, NULL);
			if (a_sock == -1) {
				if (errno == EBADF || errno == EINVAL){
					IVED_CRIT(log4cat_main, 
						  "Accept a connection: %s", 
						  strerror(errno));
					goto ived_terminate; 
				}
				IVED_WARN(log4cat_main, 
					  "Accept a connection: %s", 
					  strerror(errno));
				continue;
			}
			break;
		}

		IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());
		/* find unused thread and assign socket number */
		for (i = 0; i < MAX_THREADS; i++) {
			pthread_mutex_lock(&pt_info[i].mtx);
			if ((pt_info[i].tid_used == THREAD_WAIT_FOR_USE)){
				/* thread waiting for use is found */
				/* mark as in use */
				pt_info[i].tid_used = THREAD_IN_USE;

				/* set socket descriptor */
				pt_info[i].socket_descriptor = a_sock;

				/* wake the thread up */
				pthread_cond_signal(&pt_info[i].cond);
				pthread_mutex_unlock(&pt_info[i].mtx);
				break;
			} else {
				/* unlock and try other one */
				pthread_mutex_unlock(&pt_info[i].mtx);
			}
		}

		IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());
	}

ived_error:
	thread_running = 0;
ived_terminate:
	remove(sa.sun_path);
	ived_shutdown();
	return;
}


/**
 * main : main routine for IVED (VESHM/CR Manager)
 *
 * @param argc: Command line argument count
 * @param argv: Reference to array containing
 * command line argument
 *
 * @return: On success returns 0 and -1 on failure
 */
int 
main(int argc, char *argv[]) 
{
	int ret = 0;
	int index = 0;
	int i, s;
	int sun_path_len = 0;
	struct sockaddr_un sa;

	errno = 0;	/* errno is initialized to 2 (?) */

	/*
	 * Socket file 
	 */

	/* It seems like we don't use UNIX_PATH_MAX, because sys/un.h
	 * changed UNIX_PATH_MAX to constant number. */
	sun_path_len = sizeof(sa.sun_path);
	struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"socket", required_argument, NULL, 's'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0}
	};
	while (1) {
		s = getopt_long(argc, argv, "s:hV", long_options,
				&index);
		if (s == -1)
			break;
		switch (s) {
		case 's':
			if (strlen(optarg) > (sun_path_len-1) ){
				fprintf(stderr,
					"Socket path is too long.: %s\n", 
					optarg);
				return (EXIT_FAILURE);
			}
			if (ived_sock_file != NULL){
				free(ived_sock_file);
			}
			ived_sock_file = strndup(optarg, sun_path_len-1);
			break;
		case 'V':
			fprintf(stderr, "ived (%s) %s\n", 
				PACKAGE, PACKAGE_VERSION);
			return(EXIT_SUCCESS);
		case 'h':
		default:
			fprintf(stderr, "usage: %s [-V] -s socket \n", 
				basename(argv[0]));
			return(EXIT_FAILURE);
		}

	}

	if (ived_sock_file == NULL){
		fprintf(stderr, "usage: %s [-V] -s socket \n", 
			basename(argv[0]));
		exit(EXIT_FAILURE);
	}

	if (geteuid() != 0){
		fprintf(stderr, "%s\n", strerror(EPERM));
		exit(EXIT_FAILURE);
	}

	ret = initialize_ived();
	if (ret != 0 ){
		IVED_FATAL(log4cat_main, "Initializing failed.");
		exit(EXIT_FAILURE);
	}

	/* allocate tid */
	worker_tid = (pthread_t *)malloc(MAX_THREADS * sizeof(pthread_t));
	if (worker_tid == NULL){
		IVED_FATAL(log4cat_main, "Initializing failed: %s",
			   strerror(errno));
		exit(EXIT_FAILURE);
	}
	IVED_DEBUG(log4cat_main, "worker_tid = %p", worker_tid);

	/* allocate thread info structure */
	pt_info = (ived_thread_arg_t *)malloc
		(MAX_THREADS * sizeof(ived_thread_arg_t));
	if (pt_info == NULL){
		IVED_FATAL(log4cat_main, "Initializing failed: %s",
			   strerror(errno));
		exit(EXIT_FAILURE);
	}
	IVED_DEBUG(log4cat_main, "ptinfo = %p", pt_info);

	/* create threads */
	thread_running = 1;
	for (i = 0; i < MAX_THREADS; i++) {
		pthread_create(&worker_tid[i], NULL, ived_thread_start,
			       (void *)(ived_thread_arg_t *)&pt_info[i]);
		pt_info[i].tid_used = THREAD_WAIT_FOR_USE;
	}

	ived_main_thread();
	return(EXIT_SUCCESS);
}


/**
 * @brief Get index number of veos_info by drv_socket_name
 * If there is no veos_info[] which uses drv_socket_name,
 * this function returns index number of a new data structure.
 *
 * NOTE: This function acquires boot_lock[] and os_lock on success.
 *
 * @param [in]     drv_socket_name  VEOS's driver socket name
 *
 * @return index number or code number of result
 * @retval index number of veos_info on success
 * @retval -ENOENT    on failure
 * @retval -EBUSY     on failure
 * @retval -ECANCELED on failure 
 */
int 
get_node_idx_by_name(const char *drv_socket_name)
{
	int i;
	int ret;
	int found = 0;
	int node_idx = -ENOENT;
	int unused_idx = -ENOENT;
	struct veos_info *os_info;

	if (drv_socket_name == NULL){
		IVED_CRIT(log4cat_main, "Argument is invalid.");
		assert(0);
		return(-ECANCELED);
	}

	pthread_mutex_lock(&node_idx_lock);

	for (i=0; i<MAX_VE_NODE; i++){
		os_info = &veos_info[i];

		pthread_mutex_lock(&os_info->os_lock);
		if (os_info->os_pid == UNUSED){
			unused_idx = i;
			pthread_mutex_unlock(&os_info->os_lock);
			continue;
		}
		if (os_info->drv_socket_name == NULL){
			IVED_DEBUG(log4cat_main, "Name null: pid:%d",
				   os_info->os_pid);
			pthread_mutex_unlock(&os_info->os_lock);
			continue;
		}
		ret = strcmp(drv_socket_name,
			     os_info->drv_socket_name);
		if (ret == 0){
			/* same socket name */
			pthread_mutex_unlock(&os_info->os_lock);
			node_idx = i;
			found = 1;
			goto found_node;
		}
		pthread_mutex_unlock(&os_info->os_lock);
	}

	if (unused_idx == -ENOENT){
		IVED_ERROR(log4cat_main, "Vacant data slot is not found");
		goto err_ret;
	} 

	/* Use a free slot */
	node_idx = unused_idx;

found_node:
	/* Acquire boot_lock[] per node */
	ret = pthread_mutex_trylock(&boot_lock[node_idx]);
	if (ret == EBUSY){
		node_idx = -EBUSY;
		goto err_ret;
	}

	/* Acquire os_lock again */
	os_info = &veos_info[node_idx];
	pthread_mutex_lock(&os_info->os_lock);

	/* Check os_info again */
	if (found == 0){
		if (os_info->os_pid != UNUSED){
			pthread_mutex_unlock(&os_info->os_lock);
			pthread_mutex_unlock(&boot_lock[node_idx]);
			node_idx = -EBUSY;
			goto err_ret;
		}
		os_info->drv_socket_name = 
			strndup(drv_socket_name, PATH_MAX);

	} else if ( found == 1 ){
		/* When all of the following conditions are true,
		 * a thread may overwrite drv_socket_name.
		 * - A former VEOS finished its registration. 
		 * - The former VEOS unlocked boot_lock[node_idx].
		 * - A latter VEOS is allocated the same node_idx.
		 * - The latter VEOS succeed to acquire boot_lock[node_idx]. 
		 */
		if (os_info->drv_socket_name == NULL){
			pthread_mutex_unlock(&os_info->os_lock);
			pthread_mutex_unlock(&boot_lock[node_idx]);
			node_idx = -EBUSY;
			goto err_ret;
		}
		ret = strcmp(drv_socket_name,
			     os_info->drv_socket_name);
		if (ret != 0){
			pthread_mutex_unlock(&os_info->os_lock);
			pthread_mutex_unlock(&boot_lock[node_idx]);
			node_idx = -EBUSY;
			goto err_ret;
		}
	}

err_ret:
	if (node_idx == -EBUSY){
		IVED_ERROR(log4cat_main, 
			   "OS registration of %s is progressing by another request",
			   drv_socket_name);
		IVED_ERROR(log4cat_main, 
			   "or an allocated data slot became unavailable.");
		IVED_DEBUG(log4cat_main, "Assigned slot: %d", node_idx);
	}
	pthread_mutex_unlock(&node_idx_lock);
	return (node_idx);
}

/**
 * @brief Get a data structure of veos_info 
 * This function locks os_lock of a returned entry. 
 *
 * If id is set UNUSED, this function returns a new structure.
 *
 * @param [in]     id     ID of veos or UNUSED
 *
 * @return pointer of struct veos_info on success, NULL on failure.
 */

struct veos_info *
get_osinfo_struct(pid_t id)
{
	int ret;
	int i;
	struct veos_info *retval = NULL;

	for (i= 0; i < MAX_VE_NODE; i++){
		ret = pthread_mutex_lock(&veos_info[i].os_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_main, "Acquire OS lock: %s",
				   strerror(ret));
		}

		if (veos_info[i].os_pid == id){
			retval = &veos_info[i];
			break;
		} else {
			pthread_mutex_unlock(&veos_info[i].os_lock);
		}
	}

	IVED_DEBUG(log4cat_main, "OS info: id(param):%d, index:%d, retval:%p",
		   id, i, retval);
	return (retval);
}	

/**
 * @brief Check whether os info can be clear os information
 * 
 * cr_page_info[all].cr_lock are used in this function.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 *       This function DOESN'T UNLOCK os_lock.
 *
 * @param [in]    os_info    Pointer of VEOS info
 * @param [in]    self	     If 1, clear osinfo of caller
 *
 * @return Result of clearing os_info
 * @return 0  : os_info is cleared.
 * @return 1  : os_info is NOT cleared.
 * @return -1 : an error occured.
 */
int
try_clear_osinfo(struct veos_info *os_info, int self)
{
	int i;
	int ret;
	int retval = 1;
	int using_cr = 0;
	int locked;

	IVED_TRACE(log4cat_main, "PASS");

	if (os_info == NULL){
		IVED_CRIT(log4cat_main, "Cleared OS is not specified.");
		return(-1);
	}
	if (self != 0 && self != VEOS_SELF_SHUTDOWN){
		IVED_CRIT(log4cat_main, "Argument is invalid.");
		return(-1);
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_main, "Not locked (os)");
		return (-1);
	}

	test_os_state(os_info);
	if (os_info->node_stat == VE_STAT_RUNNING
	    && self != VEOS_SELF_SHUTDOWN){
		/* If a caller process is terminating or restarting, 
		 * e.g. a caller function is erase_os_info, node_stat
		 * is always VE_STAT_RUNNING. In a such case,
		 * this if statement must fail, so that this function
		 * clears os_info. A variable "self" controls it. */
		return(1);
	}

	/* Clean up */
	for (i=0; i < NODE_CR_PAGE_NUM; i++){
		locked = 0;
		ret = pthread_mutex_lock(&os_info->cr_page_info[i].cr_lock);
		if (ret == EDEADLK){
			locked = 1;
			/* cr will be cleared later */
		}
		if (os_info->cr_page_info[i].uid != (uid_t) UNUSED)
			using_cr++; 

		if (locked == 0){
			pthread_mutex_unlock(&os_info->cr_page_info[i].cr_lock);
		}
	}

	if (os_info->proc_info_num == 0 
	    && os_info->veshm_mem_num == 0
	    && using_cr == 0 ){

		IVED_DEBUG(log4cat_main, "Registration of %s is cleared",
			   os_info->drv_socket_name);

		/* Note: locks and os_cv (cond) are reused (e.g. cond_wait).
		 * Don't destroy them. */
		os_info->node_stat      = VE_STAT_UNUSED;
		os_info->os_pid         = UNUSED;
		os_info->bar01_paddr    = 0;
		os_info->bar_cr_paddr     = 0;
		os_info->pciatb_pgsize  = 0;

		pthread_mutex_lock(&os_info->veos_sock_lock);
		close(os_info->veos_sock);
		os_info->veos_sock      = UNUSED;
		pthread_mutex_unlock(&os_info->veos_sock_lock);

		free(os_info->drv_socket_name);
		os_info->drv_socket_name = NULL;

		/* Wake up a thread which is registering a OS. 
		 * (Clean up while booting.) */
		pthread_cond_signal(&os_info->os_cv); 
		retval = 0;
	} else {
		IVED_INFO(log4cat_main, 
			  "Resources on %s is still used. (OS status: STOP)",
			  os_info->drv_socket_name);

		os_info->node_stat     = VE_STAT_STOP;
		retval = 1;
	}

	return(retval);
}

/**
 * @brief Search OS node and process information by process ID
 * This function acquires os_lock and proc_lock.
 *
 * NOTE: When an argument pid is valid, this function returns an address
 * a runnning process's data. When an argument uuid_proc is valid, this 
 * function traverses all processes and returns an address of a process.
 *
 * NOTE: Don't call this function if a caller function keep locking
 * os_lock of other VEOS. This function unlocks os_lock of not target VEOS.
 *
 * @param [in]      pid		PID of a target process or -1
 * @param [in]      uuid_proc   UUID of a target process or uuid of "NULL"
 * @param [out]     os_info	Pointer of veos_info
 * @param [out]     proc_info	Pointer of  a running process_info 
 *
 * @return 0. On failure, os_info and proc_info are NULL
 */
int
search_node_proc_info(int pid, uuid_t uuid_proc,
		      struct veos_info **os_info, 
		      struct process_info **proc_info)
{
	int ret;
	int i;
	struct process_info *procp = NULL;

	assert(os_info   != NULL);
	assert(proc_info != NULL);

	if (os_info == NULL || proc_info == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	for (i=0; i < MAX_VE_NODE; i++){
		ret = pthread_mutex_lock(&veos_info[i].os_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_main, "Acquire OS lock: %s",
				   strerror(ret));
		}

		procp = get_procinfo_struct(&veos_info[i], pid, uuid_proc, 0);
		if (procp != NULL){
			break;
		} else {
			pthread_mutex_unlock(&veos_info[i].os_lock);
		}
	}

	if (procp == NULL){
		*proc_info = NULL;
		*os_info   = NULL;
	} else {
		*proc_info = procp;
		*os_info   = procp->os_info;
	}

	IVED_DEBUG(log4cat_main, "proc_info=%p", *proc_info);
	IVED_DEBUG(log4cat_main, "os_info=%p", *os_info);
	return (0);
}


/**
 * @brief Check process_info by pid
 *
 * @param [in]     osdata  Pointer to an OS
 * @param [in]     pid     PID of veos or UNUSED
 *
 * @return 1 when mached, 0 when mismatched
 */
static int
check_proc_entry_by_pid(struct process_info *entry, int pid)
{
	int found = 0;
	if (entry == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(0);
	}
	if ( entry->pid == pid 
	     && entry->proc_stat == VE_STAT_RUNNING){
		found = 1;
	}
	return (found);
}

/**
 * @brief Check process_info by UUID
 *
 * @param [in]     osdata  Pointer to an OS
 * @param [in]     uuid_proc  UUID of proccess
 *
 * @return 1 when mached, 0 when mismatched
 */
static int
check_proc_entry_by_uuid(struct process_info *entry, uuid_t uuid_proc)
{
	int found = 0;
	if (entry == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(0);
	}
	if ( uuid_compare(entry->uuid_proc, uuid_proc) == 0){
		IVED_TRACE(log4cat_main, "Match");
		found = 1;
	}
	return (found);
}

/**
 * @brief Get a data structure of process info and acquire locks of 
 * the proocess and a corresponding OS 
 *
 * NOTE: When an argument pid is valid, this function returns an address
 * a runnning process's data. When an argument uuid_proc is valid, this 
 * function traverses all processes and returns an address of a process.
 *
 * NOTE: Before entering this function, a caller must acquire an OS lock.
 *
 * NOTE: Don't call this function if a caller function keep locking
 * proc_lock of other processes. This function unlocks proc_lock of not target
 * process.
 *
 * mode is 0 or ORed value of the following flags:
 * CREATE_INFO	If there is not the specified data in a process list,
 *              this function creates a new data structure.
 *
 * @param [in]     osdata    Pointer to an OS
 * @param [in]     pid       PID of process 
 * @param [in]     uuid_proc UUID of process
 * @param [in]     mode      mode
 *
 * @return pointer of struct process_info on success, NULL on failure.
 */
struct process_info *
get_procinfo_struct(struct veos_info *osdata, int pid, uuid_t uuid_proc, 
		    int mode)
{
	int ret;
	int flag_uuid;
	struct process_info *entry = NULL;
	struct process_info *ret_ent = NULL;
	struct list_head *list_p;
	int found = 0;

	assert(osdata != NULL);
	if (osdata == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		goto err_ret;
	}

	ret = ived_check_mutex_locked(&osdata->os_lock);
	if (ret != 0 ){
		goto err_ret;
	}

	if (uuid_is_null(uuid_proc))
		flag_uuid = 0;
	else
		flag_uuid = 1;

	list_for_each(list_p, &(osdata->proc_info_list)){
		entry = list_entry(list_p, struct process_info, list);

		ret = pthread_mutex_lock(&entry->proc_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_main, "Acquire Process lock: %s",
				   strerror(ret));
		}

		if (flag_uuid == 0){
			found = check_proc_entry_by_pid(entry, pid);
		} else {
			found = check_proc_entry_by_uuid(entry, uuid_proc);
		}
		if (found == 1){
			ret_ent = entry;
			break;
		} else {
			pthread_mutex_unlock(&entry->proc_lock);
		}
	}
	if ( found == 0 && (mode & CREATE_INFO)){
		IVED_DEBUG(log4cat_main, "New proc info"); 
		entry = (struct process_info *)malloc 
			(sizeof(struct process_info));
		if (entry == NULL){
			IVED_CRIT(log4cat_main, "Process data allocation failed");
			goto err_ret;
		}

		entry->pid = UNUSED;
		pthread_mutex_init(&entry->proc_lock, &chkmutex);
		INIT_LIST_HEAD(&entry->list);
		INIT_LIST_HEAD(&entry->having_veshm_info);
		INIT_LIST_HEAD(&entry->attaching_veshm_info);
		INIT_LIST_HEAD(&entry->using_cr_info);

		pthread_mutex_lock(&entry->proc_lock);
		ret_ent = entry;
	}

err_ret:
	IVED_DEBUG(log4cat_main, "os:%p pid:%d ret_ent=%p, found=%d", 
		   osdata, pid, ret_ent, found);
	return (ret_ent);
}

/**
 * @brief Erase struct process info
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * os_lock, proc_lock
 *
 * @param [in]    os_info    Pointer of VEOS info
 * @param [in]    proc_info  Terget process info to erase
 *
 * @return 0 on success, -1 on failure.
 */
int
erase_procinfo_struct(struct veos_info *os_info, struct process_info *proc_info)
{
	int ret = 0;
	assert(os_info != NULL);
	assert(proc_info != NULL);

	if (os_info == NULL || proc_info == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	/* NOTE: os_lock and proc_lock must locked. */
	ret = ived_check_mutex_locked(&os_info->os_lock);
	assert(ret == 0);
	if (ret != 0){
		IVED_DEBUG(log4cat_main, "Not locked (os)");
		return (-1);
	}
	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	assert(ret == 0);
	if (ret != 0){
		IVED_DEBUG(log4cat_main, "Not locked (process)");
		return (-1);
	}

	/* Release proc_info */
	pthread_mutex_unlock(&proc_info->proc_lock);
	ret = pthread_mutex_destroy(&proc_info->proc_lock);
	if (ret != 0){
		pthread_mutex_lock(&proc_info->proc_lock);
		IVED_ERROR(log4cat_main, "Erasing mutex error: %s", 
			   strerror(ret));
		return (-1);
	}

	IVED_DEBUG(log4cat_main, "Cleared process data of pid:%d",
		   proc_info->pid);

	os_info->proc_info_num--;
	list_del(&proc_info->list);

	free(proc_info);
	return(0);
}

/**
 * @brief Test whether a process info can be cleared, then erase data
 * proc_info->proc_lock is unlocked at the end of this function.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * proc_lock, os_lock
 *
 * @param [in]    proc_info  Terget process info to erase
 *
 * @return Result of eraseing
 * @retval 0  proc_info is released
 * @retval 1  proc_info is NOT released
 * @retval -1 An error occured, proc_info is not released
 */
int
try_erase_procinfo(struct process_info *proc_info)
{
	int ret;
	struct veos_info *os_info = NULL;
	int i;
	IVED_TRACE(log4cat_main, "PASS");

	if ( proc_info == NULL ){
		IVED_DEBUG(log4cat_main, "Argument is NULL");
		ret = -1;
		goto err_ret;
	}

	os_info = proc_info->os_info;
	if ( os_info == NULL) {
		IVED_DEBUG(log4cat_main, "OS data is not found. (VE proc ID:%d",
			   proc_info->pid);
		ret = -1;
		goto err_ret;
	}

	dump_proc_info(proc_info);

	if (proc_info->proc_stat == VE_STAT_RUNNING){
		ret = 1;
		goto ret_success;
	}

	if ((proc_info->own_veshm_num != 0) 
	    || (proc_info->attach_veshm_num != 0)){
		ret = 1;
		goto ret_success;
	}

	for (i= 0; i < CRD_ENTRY; i++){
		if (proc_info->local_crd[i] != NULL){
			ret = 1;
			goto ret_success;
		}
	}
	if (list_empty(&proc_info->using_cr_info) == 0){ /* Not empty */
		ret = 1;
		goto ret_success;
	}

	ret = erase_procinfo_struct(os_info, proc_info);

	return(ret);

ret_success:
err_ret:
	if (proc_info != NULL)
		pthread_mutex_unlock(&proc_info->proc_lock);
	return(ret);
}

/**
 * @brief Release resources of all process in a target VE node
 *
 * NOTE: Before entering this function, a caller must acquire a os lock.
 *
 * @param [in] os_info Target VEOS
 *
 * @return 0 on success, -1  on failure
 */
int
release_all_resource(struct veos_info *os_info, 
		     struct list_head *erase_veshm_list,
		     struct list_head *erase_cr_list)
{
	int ret = 0;
	struct list_head *proc_list_p, *list_n;
	struct process_info *proc_info = NULL;

	IVED_TRACE(log4cat_main, "PASS");
	assert(os_info != NULL);
	if (os_info == NULL || erase_veshm_list == NULL 
	    || erase_cr_list == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	list_for_each_safe(proc_list_p, list_n, &(os_info->proc_info_list)){
		proc_info = list_entry(proc_list_p, 
				       struct process_info, list);
		ret = pthread_mutex_lock(&proc_info->proc_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_main, "Acquire Process lock: %s",
				   strerror(ret));
		}

		IVED_TRACE(log4cat_main, "Clearing process: PID: %d",
			   proc_info->pid);

		/* Do close and detach operations. 
		 * proc_info may be freed. */
		proc_info->proc_stat = VE_STAT_STOP;
		ret = ived_veshm_discard_all
			(os_info, proc_info, IVED_VEOS_EXIT, erase_veshm_list);

		ret = ived_cr_discard_all(os_info, proc_info, 
					  IVED_VEOS_EXIT, erase_cr_list);

		/* try_erase_procinfo unlocks proc_lock */
		ret = try_erase_procinfo(proc_info);
		if (ret != 0){
			IVED_DEBUG(log4cat_main, 
				   "Process is not freed. (result:%d)", ret);
		}

		/* NOTE: Clear VESHMs used by the process later.
		 * (In a caller function) */
	}

	IVED_DEBUG(log4cat_main, "retval:%d", ret);
	return(0);
}

/**
 * @brief Wait to change node_status to VE_STAT_UNUSED of a target os.
 *
 * @param [in] os_info  Old VEOS's data structure
 *
 * @return 0 on success, other value on failure
 * @retval 0
 * @retval -1, EINVAL, EACCES 
 */
int
wait_resource_clear(struct veos_info *os_info)
{
	int ret, retval = 0;
	struct timespec timeout;

	IVED_TRACE(log4cat_main, "PASS");
	assert(os_info != NULL);

	if (os_info == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0)
		return(-1);

	/* Wait veos_info[os_index].node_stat becomes UNUSED. */
	ret = clock_gettime(CLOCK_REALTIME, &timeout);
	if (ret != 0){
		IVED_ERROR(log4cat_main, "Wait resource clearing: %s", 
			   strerror(errno));
		return (-1);
	}
	timeout.tv_sec += BOOT_TIMEOUT;
	while (os_info->node_stat != VE_STAT_UNUSED){
		retval = pthread_cond_timedwait(&os_info->os_cv, 
						&os_info->os_lock, &timeout);
		if (retval != 0)
			break;
	}
	IVED_DEBUG(log4cat_main, "retval:%d", retval);
	return(retval);
}


/** 
 * @brief Clear all old VEOS's resources 
 * NOTE: Before entering this function, a caller must acquire a lock.
 *
 * @param [in] os_index
 *
 * @return 0 on success, -1 on failure
 */
int
clear_old_os_resource(struct veos_info *os_info)
{
	int ret;
	struct list_head erase_veshm_list, erase_cr_list;

	assert(os_info != NULL);
	if (os_info == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	INIT_LIST_HEAD(&erase_veshm_list);
	INIT_LIST_HEAD(&erase_cr_list);

	/* Note: Before entering this function, lock os_info->os_lock. */

	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0)
		return(-1);

	if (os_info->node_stat != VE_STAT_STOP){
		IVED_ERROR(log4cat_main, "Illegal invoking. OS stat:%d",
			   os_info->node_stat);
		return(-1);
	}

	ret = release_all_resource(os_info, 
				   &erase_veshm_list, &erase_cr_list);
	if (ret != 0){
		goto err_ret;
	}

	/* Send SIGKILL to VESHM users which exist on remote nodes. */
	ived_veshm_kill_remote_process(os_info);

	/* Send SIGKILL to CR users which exist on remote nodes. */
	ived_cr_kill_remote_process(os_info);

	pthread_mutex_unlock(&os_info->os_lock);

	/* Clear VESHMs. */
	erase_veshm_info_batch(os_info, &erase_veshm_list);

	/* Release remote CRs */
	erase_cr_info_batch(&erase_cr_list);

	ret = pthread_mutex_lock(&os_info->os_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_main, "Acquire OS lock: %s", strerror(ret));
	}
	ret = try_clear_osinfo(os_info, VEOS_SELF_SHUTDOWN);
	if (ret > 0){
		/* Wait remote processes' termination */ 
		ret = wait_resource_clear(os_info);
	} 

err_ret:
	IVED_DEBUG(log4cat_main, "retval:%d", ret);
	return(ret);
}


/**
 * @brief Register VEOS data with VEOS information
 *
 * @param [in]     pti	 Pointer of thread information	
 *
 * @return  0 on success, -1 on failure.
 */
int
ived_register_osdata(ived_thread_arg_t *pti, RpcIvedArg *request)
{
	int i;
	int ret;
	int rpc_reterr = -ECANCELED;
	struct veos_info *os = NULL;
	int node_idx = -1;

	assert(pti != NULL);
	assert(request != NULL);

	if (pti == NULL || request == NULL 
	    || request->register_os_arg == NULL
	    || request->register_os_arg->socket_name == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		goto err_ret_nolock;
	}

	IVED_DEBUG(log4cat_main, "OS registration: node: %s",
		   request->register_os_arg->socket_name);

	if ( request->register_os_arg->pid != pti->cred.pid){
		IVED_ERROR(log4cat_main, "Suspicious request from %d (pid:%d)",
			   pti->cred.pid, request->register_os_arg->pid);
		rpc_reterr = -EACCES;
		goto err_ret_nolock;
	}

	/* get_node_idx_by_name acquires boot_lock[] and os_lock */
	node_idx = get_node_idx_by_name(request->register_os_arg->socket_name);
	if (node_idx < 0){
		rpc_reterr = -EBUSY;
		goto err_ret_nolock;
	}
	IVED_DEBUG(log4cat_main, "Use index[%d]", node_idx);

	/* Note:  node_stat
	 * VE_STAT_RUNNING means that an OS is running.
	 * VE_STAT_STOP means that an OS stops but resources managed by
	 * the OS is shared by other proceses.
	 * VE_STAT_UNUSED means the data structure is not used.
	 */

	os = &veos_info[node_idx];

	if (os->os_pid != UNUSED){
		test_os_state(os);

		/* If node_stat == VE_STAT_STOP, goto clean up routine. */

		if (os->node_stat == VE_STAT_RUNNING){
			IVED_ERROR(log4cat_main, 
				   "OS registration: Multiple request for %s",
				   request->register_os_arg->socket_name);
			rpc_reterr = -EEXIST;
			goto err_ret_os_unlock;
		}
	}

	if (os->node_stat == VE_STAT_STOP){
		IVED_DEBUG(log4cat_main, "Clean up shared resources.");
		/* clear_old_os_resource doesn't unlock os_lock */
		ret = clear_old_os_resource(os);
		if (ret != 0){
			IVED_ERROR(log4cat_main, 
				   "Booting %s failed: Retry later",
				   request->register_os_arg->socket_name);
			rpc_reterr = -ECANCELED;
			goto err_ret_os_unlock;
		}
	}

	/* Fill veos_info with node specific data */
	os->node_stat	    = VE_STAT_RUNNING;
	os->pciatb_pgsize   = request->register_os_arg->pciatb_pgsize;
	if (os->drv_socket_name == NULL){
		os->drv_socket_name = 
			strndup(request->register_os_arg->socket_name,
				PATH_MAX);
	}
	os->veos_sock	    = pti->socket_descriptor;
	os->os_pid	    = request->register_os_arg->pid;
	os->bar01_paddr	    = request->register_os_arg->bar01_addr;
	os->bar_cr_paddr    = request->register_os_arg->bar_cr_addr;
	os->proc_info_num   = 0;
	os->veshm_mem_num   = 0;

	/* Validate CR page */
	for (i=0; i < NODE_CR_PAGE_NUM; i++){
		os->cr_page_info[i].cr_page_num   = i;
	}

	IVED_INFO(log4cat_main, 
		  "New VE node: Device:%s os pid:%d PCIATB size: %"PRIx64"",
		  os->drv_socket_name, os->os_pid, os->pciatb_pgsize);

	dump_os_info(os);

	/* send reply to client */
	ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);
	/* If the reply failed, it is no problem. If the reply reached to VEOS,
	 * VEOS will connect IVED. If no, VEOS will reboot.*/

	ret = pthread_mutex_unlock(&os->os_lock);
	assert(ret == 0);

	pthread_mutex_unlock(&boot_lock[node_idx]);
	IVED_INFO(log4cat_main, "OS registration: Succeeded");

	return(0);

err_ret_os_unlock:
	pthread_mutex_unlock(&os->os_lock);
	pthread_mutex_unlock(&boot_lock[node_idx]);

err_ret_nolock:
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
				rpc_reterr);
	IVED_ERROR(log4cat_main, "OS registration: Failed");
	return(-1);
}

/**
 * @brief Erase VEOS data from VEOS information
 *
 * @param [in] pti    	 Pointer of thread information	
 * @param [in] request	 Pointer of a request
 *
 * @return  returns 0
 */
int
ived_erase_osdata(ived_thread_arg_t *pti, RpcIvedArg *request)
{
	int retval = -1;
	struct veos_info *os = NULL;
	int os_pid = -1;

	if (pti == NULL || request == NULL || request->register_os_arg == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		if (pti != NULL)
			ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, 
					-ECANCELED);
		goto err_ret;
	} 

	IVED_DEBUG(log4cat_main, "OS erasing: os pid: %d",
		   request->register_os_arg->pid);

	if (request->register_os_arg->pid != pti->cred.pid){
		IVED_ERROR(log4cat_main, 
			   "VEOS's pid doesn't match requester's pid.");
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, -EACCES);
		goto err_ret;
	}

	os = get_osinfo_struct(request->register_os_arg->pid);
	if (os == NULL){
		IVED_ERROR(log4cat_main, "Requested VEOS is not found.");
		ived_send_int64(pti->socket_descriptor, IVED_REQ_NG, -ESRCH);
		goto err_ret;
	}

	/* Send SIGKILL to VESHM users which exist on remote nodes. */
	ived_veshm_kill_remote_process(os);

	/* Send SIGKILL to CR users which exist on remote nodes. */
	ived_cr_kill_remote_process(os);

	/* VEOS detects close(socket) and stop a thread. */
	pthread_mutex_lock(&os->veos_sock_lock);
	shutdown(os->veos_sock, SHUT_RDWR);
	close(os->veos_sock);
	os->veos_sock = UNUSED;

	pthread_mutex_unlock(&os->veos_sock_lock);

	os_pid = os->os_pid;

	os->node_stat     = VE_STAT_STOP;

	try_clear_osinfo(os, VEOS_SELF_SHUTDOWN);
	pthread_mutex_unlock(&os->os_lock);

	IVED_INFO(log4cat_main, "OS registration is cleared. (pid:%d)",
		  os_pid);
	dump_os_info(os);

	/* send reply to client */
	retval = ived_send_int64(pti->socket_descriptor, IVED_REQ_OK, 0);

err_ret:
	IVED_DEBUG(log4cat_main, "retval: %d", retval);
	return(retval);
}

/**
 * @brief Register process data with process information
 *
 * @param [in] pti    	 Pointer of thread information	
 * @param [in] request	 Pointer of a request
 *
 * @return  0 on success, -1 on failure.
 */
int
ived_register_procdata(ived_thread_arg_t *pti, RpcIvedArg *request)
{
	int i;
	int rpc_retval = IVED_REQ_NG, rpc_reterr = 0;
	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	pid_t pid = -1;

	if (pti == NULL || request == NULL || request->proc_arg == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		rpc_reterr = -ECANCELED;
		goto err_ret_nolock;
	}

	os_info = get_osinfo_struct(pti->cred.pid);
	if (os_info == NULL){
		rpc_reterr = -ESRCH;
		goto err_ret_nolock;
	}

	if ((unsigned int)os_info->proc_info_num + 1 > INT_MAX){
		IVED_ERROR(log4cat_main, "Too many processes (%s)",
			   os_info->drv_socket_name);
		rpc_reterr = -EUSERS;
		goto err_ret_os_unlock;
	}

	pid = request->proc_arg->pid;
	proc_info = get_procinfo_struct(os_info, pid, null_id, CREATE_INFO);
	if (proc_info == NULL){
		rpc_reterr = -ECANCELED;
		goto err_ret_os_unlock;
	}

	if (proc_info->pid != UNUSED){
		IVED_ERROR(log4cat_main, 
			   "Multiple request for the process; PID:%d", pid);
		rpc_reterr = -EINVAL;
		goto err_ret_proc_unlock;
	}

	/* Store arguments of the requested*/
	IVED_DEBUG(log4cat_main, "proc_info:%p",proc_info);
	proc_info->proc_stat            = VE_STAT_RUNNING;
	proc_info->pid			= pid;
	proc_info->os_info		= os_info;
	proc_info->own_veshm_num	= 0;
	proc_info->attach_veshm_num	= 0;
	for (i= 0; i < CRD_ENTRY; i++){
		proc_info->local_crd[i] = NULL;
	}
	uuid_copy(proc_info->uuid_proc, request->proc_arg->uuid_proc.data);
	dump_proc_info(proc_info);

	os_info->proc_info_num++;
	list_add(&proc_info->list , &os_info->proc_info_list);

	rpc_retval = IVED_REQ_OK;

err_ret_proc_unlock:
	pthread_mutex_unlock(&proc_info->proc_lock);
err_ret_os_unlock:
	pthread_mutex_unlock(&os_info->os_lock);
err_ret_nolock:
	/* send reply to client */
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, rpc_retval, rpc_reterr);

	if (rpc_retval == IVED_REQ_OK){
		IVED_DEBUG(log4cat_main, "Process(pid:%d) registered", pid);
	} else {
		if (pid == -1)
			IVED_ERROR(log4cat_main, "Process(pid:unknown) registration failed");
		else
			IVED_ERROR(log4cat_main, "Process(pid:%d) registration failed", 
				   pid);
	}
	return(rpc_retval);
}

/**
 * @brief Erase process data from proccess information
 *
 * @param [in] pti    	 Pointer of thread information	
 * @param [in] request	 Pointer of a request
 *
 * @return  0 on success, -1 on failure.
 */
int
ived_erase_procdata(ived_thread_arg_t *pti, RpcIvedArg *request)
{
	int retval = -1;
	int64_t rpc_retval = IVED_REQ_NG; 
	int rpc_reterr = 0;
	int pid  = -1;
	uuid_t req_uuid_proc;
	struct veos_info *os_info = NULL;
	struct process_info *proc_info = NULL;
	struct list_head erase_veshm_list, erase_cr_list;

	assert(pti != NULL);
	assert(request != NULL);
	if (pti == NULL || request == NULL || request->proc_arg == NULL){
		rpc_reterr = -ECANCELED;
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		goto err_ret;
	}

	INIT_LIST_HEAD(&erase_veshm_list);
	INIT_LIST_HEAD(&erase_cr_list);

	uuid_copy(req_uuid_proc, request->proc_arg->uuid_proc.data);
	dump_uuid("Try to erase proc", req_uuid_proc);

	/* Get process info */
	search_node_proc_info(-1, req_uuid_proc, &os_info, &proc_info);
	if (os_info == NULL || proc_info == NULL){
		rpc_reterr = -ESRCH;
		IVED_ERROR(log4cat_main, 
			   "Register process: %s", strerror(-rpc_reterr));
		goto err_ret;
	}
	pid = proc_info->pid;

	if ( os_info->os_pid != pti->cred.pid ){
		pthread_mutex_unlock(&os_info->os_lock);
		pthread_mutex_unlock(&proc_info->proc_lock);
		IVED_ERROR(log4cat_main, "Invalid request from pid:%d",
			   pti->cred.pid);
		rpc_reterr = -EACCES;
		goto err_ret;
	}

	proc_info->proc_stat = VE_STAT_STOP;

	/* Detach all VESHM areas. */
	ived_veshm_discard_all(os_info, proc_info, 
			       request->proc_arg->mode_flag,
			       &erase_veshm_list);

	/* Release CRs */
	ived_cr_discard_all(os_info, proc_info, proc_info->proc_stat,
			    &erase_cr_list);

	/* Release proc_info */
	/* try_erase_procinfo unlocks proc_lock. */
	try_erase_procinfo(proc_info);

	pthread_mutex_unlock(&os_info->os_lock);

	/* Try to clear VESHMs */
	erase_veshm_info_batch(os_info, &erase_veshm_list);

	/* Release remote CRs */
	erase_cr_info_batch(&erase_cr_list);

	rpc_retval = IVED_REQ_OK;
	retval = 0;

err_ret:
	if (pti != NULL)
		ived_send_int64(pti->socket_descriptor, rpc_retval, rpc_reterr);

	if (rpc_retval == IVED_REQ_OK){
		IVED_DEBUG(log4cat_main, "Process(pid:%d) registration erased", 
			   pid);
	} else {
		IVED_ERROR(log4cat_main, "Process(pid:%d) erasing failed", 
			   pid);
	}

	return (retval); 
}

