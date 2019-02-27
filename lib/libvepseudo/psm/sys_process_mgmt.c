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
 * @file syscall.c
 * @brief Handles system calls encountered by VE process.
 *
 * This file contains system call handlers for the various system calls
 * encountered by VE process.
 */

#include <sys/types.h>
#include <string.h>
#include <sys/shm.h>
#include <linux/futex.h>
#include "handle.h"
#include "process_mgmt_comm.h"
#include "mm_transfer.h"
#include "sys_process_mgmt.h"
#include "sys_mm.h"
#include "exception.h"
#include "velayout.h"
#include "loader.h"
#include "pseudo_ptrace.h"
#include <proc/readproc.h>
#include <sys/statvfs.h>
#include "pseudo_vhshm.h"
#include "pseudo_veshm.h"
#include "sys_accelerated_io.h"
#include "veshm_defs.h"

int tid_counter = -1;
pthread_mutex_t readproc_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Return struct tid_info array index corresponding to the thread ID.
 *
 *	This function serches for the given thread ID in the struct tid_info
 *	array and returns the corresponding index. If thread ID is specified
 *	as 0, it returns the index of the first free entry.
 *
 * @param[in] tid Thread ID.
 *
 * @return If thread ID is non zero, returns the corresponding index of tid_info
 * array. If tid is not present, returns VEOS_MAX_VE_THREADS. If thread ID is
 * specified as 0, returns index of the first free entry.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int find_global_array_index(int tid)
{
	int index = -1;

	for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {
		if (global_tid_info[index].tid_val == tid)
			break;
	}

	return index;
}

/**
 * @brief Clear the entry in struct tid_info array.
 *
 *	This function clears the entry in struct tid_info array corresponding
 *	to the given thread ID.
 *
 * @param[in] tid Thread ID.
 *
 * @internal
 * @author PSMG / MP-MT
 */
static void clear_global_array_entry(int index)
{

	global_tid_info[index].tid_val = 0;
	global_tid_info[index].mutex =
		(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	global_tid_info[index].cond =
		(pthread_cond_t)PTHREAD_COND_INITIALIZER;
	global_tid_info[index].flag = 0;
	global_tid_info[index].ctid_address = 0;
	global_tid_info[index].guard_ptr = 0;

	/*
	 * Decrement global tid_counter
	 */
	tid_counter--;
	PSEUDO_DEBUG("Clear entries for Thread index : %d "
			"& Available Threads are : %d",
			index, tid_counter);
	return;
}

/**
 * @brief deletion of task for VE side
 *
 * void process_thread_cleanup(veos_handle *handle)
 *
 * @param handle[in] VEOS handle
 *
 * @internal
 * @author PSMG / MP-MT
 */
void process_thread_cleanup(veos_handle *handle, int exit_code)
{
	int index_local = -1;
	pid_t tid = syscall(SYS_gettid);
	uint64_t ctid_status = 0;
	uint64_t tid_addr = (uint64_t)NULL;
	ret_t retval = -1;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("tid_counter : %d, tid : %d", tid_counter,
			tid);

	/* Acquire mutex lock */
	retval = pthread_mutex_lock(&tid_counter_mutex);
	if (retval != 0) {
		PSEUDO_ERROR("clone() failure: Failed to acquire "
				"mutex lock");
		PSEUDO_DEBUG("Failed to acquire lock, return value %d",
				-((int)retval));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	index_local = find_global_array_index(tid);
	if (index_local == VEOS_MAX_VE_THREADS) {
		PSEUDO_ERROR("TID %d not found", tid);
		pseudo_abort();
	}

	PSEUDO_DEBUG("index_local : %d, ctid_address : %lx", index_local,
		(unsigned long)global_tid_info[index_local].ctid_address);

	tid_addr = (uint64_t)global_tid_info[index_local].ctid_address;

	/* clean up of the corresponding entry in the global tid array */
	if (index_local > 0)
		clear_global_array_entry(index_local);

	/* Release mutex lock */
	retval = pthread_mutex_unlock(&tid_counter_mutex);
	if (retval != 0) {
		PSEUDO_ERROR("clone() failure: Failed to release "
				"mutex lock");
		PSEUDO_DEBUG("Failed to release lock, return value %d",
				-((int)retval));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* send FUTEX_WAKE on clear_child_tid address.*/
	if (tid_addr) {
		ve_send_data(handle, tid_addr, sizeof(pid_t),
				(uint64_t *)(&ctid_status));
		/* Change VH memory permission into READ and WRITE */
		retval = mprotect((void *)(tid_addr & ADDR_MASK),
				getpagesize(), PROT_WRITE|PROT_READ);
		if (retval != 0)
			PSEUDO_ERROR("Cannot access memory");
		else {
			retval = 0;
			__atomic_store((volatile ret_t *)(tid_addr),
					(ret_t *)&retval, __ATOMIC_SEQ_CST);
			syscall(SYS_futex, tid_addr, FUTEX_WAKE, 1,
					NULL, NULL, NULL);
		}
	}

	/* Send request to VEOS for cleanup of VE process */
	retval = pseudo_psm_send_delete_ve_proc_req(
			handle->veos_sock_fd, EXIT_THREAD,
			exit_code, -1);
	if (retval < 0) {
		PSEUDO_ERROR("delete failure: veos request error");
		PSEUDO_DEBUG("Failed to send request to veos, return value %d",
				(int)retval);
		goto thread_cleanup;
	}

	/* wait for acknowledgment from VEOS */
	retval = pseudo_psm_recv_delete_ack(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("exit() failure: veos acknowledgement error");
                PSEUDO_DEBUG("Failed to get acknowledgement from veos, return "
                                "value %d", (int)retval);
	} else {
		PSEUDO_DEBUG("retval received : %ld", retval);
	}

thread_cleanup:
	/* #789 : Not closing fd's in case cleanup is invoked for main thread
	 * as it might happen that a thread of its thread group may invoke execve()
	 * For execve(), we need to reserve main thread's drive fd
	 * */
	if (getpid() != syscall(SYS_gettid))
		veos_handle_free(handle);
	PSEUDO_TRACE("Exiting");
	return;
}

/**
 * @brief This function is invoked when VE process is exited.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success and negative error value on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_exit(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args = 0;
	ret_t retval = -1;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, &args, 1);
	if (retval < 0) {
                PSEUDO_ERROR("exit() failure: Failed to fetch system call "
                                "arguments");
	}

	/* Check whether PTRACE_O_TRACEEXIT is enabled */
	if (IS_VE_TRACED(handle->ve_handle) &&
			(VE_PTRACE_OPTION(handle->ve_handle) &
			 PTRACE_O_TRACEEXIT)) {
		PSEUDO_DEBUG("PID: %ld is traced and "
				"PTRACE_O_TRACEEXIT event"
				" is Enabled",
				syscall(SYS_gettid));

		ptrace_event_notify(handle, (args & BYTE_MASK) << 8);
		send_sig_to_itself(SIGTRAP,
				(SIGTRAP | (PTRACE_EVENT_EXIT << 8)),
				NULL);
	}

	PSEUDO_DEBUG("Unregister ve buffer from DMAATB for accelerated io");
	sys_accelerated_unregister_ve_buf_vehva(handle);

	PSEUDO_DEBUG("Acquiring lock for ve_exit() syscall");
	if (pthread_mutex_lock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to acquire global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	process_thread_cleanup(handle, (args & BYTE_MASK) << 8);

	PSEUDO_DEBUG("Releasing lock for ve_exit() syscall");
	if (pthread_mutex_unlock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to release global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	/* call pthread_exit to perform cleanup of library specific data
	 * structure(s)
	 */
	pthread_exit(&args);
}

/**
 * @brief Thread start function for child pseudo process thread.
 *
 *	This function is the start function of the child pseudo process thread.
 *	This is invoked from the pseudo process clone() handler routine.
 *	This function will wait for the exceptions from VE child thread.
 *
 * @param[in] thread_args Structure containing the arguments of thread function.
 *
 * @internal
 * @author PSMG / MP-MT
 */
static void thread_dummy_func(void *thread_args)
{
	veos_handle *child_handle = NULL;
	ret_t retval = 1;
	struct thread_func_args *thread_dummy_func_args = NULL;
	veos_handle *parent_handle = NULL;
	int index = ((struct thread_func_args *)thread_args)->tid_val_index;;
	struct pseudo_ve_clone_info ve_clone_info = {0};
	struct clone_response clone_response_rcvd = {0};
	void (*exception_handler) (veos_handle *, void *);
	void *extra_arg = NULL;

	PSEUDO_TRACE("Entering");
	thread_dummy_func_args =
		(struct thread_func_args *) malloc (sizeof(struct thread_func_args));
	if (NULL == thread_dummy_func_args) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory");
		goto hndl_return;
	}
	memset(thread_dummy_func_args, '\0', sizeof(struct thread_func_args));
	memcpy(thread_dummy_func_args, thread_args, sizeof(struct thread_func_args));
	parent_handle = thread_dummy_func_args->parent_handle;
	exception_handler = thread_dummy_func_args->handler;
	extra_arg = (void *)thread_dummy_func_args->extra_arg;

	/* Populate structure sending to PSM */
	ve_clone_info.flags = thread_dummy_func_args->flags;
	ve_clone_info.stack_ptr = thread_dummy_func_args->stack_ptr;
	ve_clone_info.ptid = thread_dummy_func_args->ptid;
	ve_clone_info.ctid = thread_dummy_func_args->ctid;
	ve_proc_sigmask = thread_dummy_func_args->sigmask_var;

	/* Populate the parent pid in clone info before cleaning the heap */
	ve_clone_info.parent_pid = thread_dummy_func_args->parent_pid;

	free(thread_dummy_func_args);

	/* Create a new handle for child thread */
	child_handle = veos_handle_create(parent_handle->device_name,
			parent_handle->veos_sock_name, parent_handle, -1);
	if (child_handle == NULL) {
		PSEUDO_ERROR("clone() failed: Failed to create new handle "
				"for child");
		PSEUDO_DEBUG("Failed to create new handle, return value %d, "
				"mapped value %d", (int)errno, -EAGAIN);
		retval = -EAGAIN;
		goto hndl_return;
	}

	g_handle = child_handle;

	global_tid_info[index].vefd = g_handle->ve_handle->vefd;
	global_tid_info[index].veos_hndl = g_handle;

	/* Update global_tid_info containing tid(s) */
	global_tid_info[index].tid_val = syscall(SYS_gettid);

	PSEUDO_DEBUG("index: %d, global_tid_info[index].tid_val: %d",
			index, global_tid_info[index].tid_val);

	ve_clone_info.child_pid = global_tid_info[index].tid_val;

	PSEUDO_DEBUG("TID struct vefd %d",
			g_handle->ve_handle->vefd);

	/* Request VEOS to perform cloning */
	retval = pseudo_psm_send_clone_req(child_handle->veos_sock_fd, ve_clone_info,
			(pid_t)ve_clone_info.parent_pid);
	if (retval < 0) {
		PSEUDO_ERROR("clone() failure: veos request error");
		PSEUDO_DEBUG("Failed to send request to veos, return value %d, "
				"mapped value %d", (int)retval, -ENOMEM);
		retval = -ENOMEM;
		goto hndl_return;
	}

	/* Wait for ACK from VEOS */
	retval = pseudo_psm_recv_clone_ack(child_handle->veos_sock_fd,
			&clone_response_rcvd);
	if (retval < 0) {
		PSEUDO_ERROR("clone() failure: veos acknowledgement error");
		PSEUDO_DEBUG("Failed to get acknowledgement from veos, return "
				"value %d", (int)retval);
		goto hndl_return;
	}

	PSEUDO_DEBUG("CLONE_RESPONSE core_id: %d node_id: %d",
			clone_response_rcvd.core_id,
			clone_response_rcvd.node_id);

	PSEUDO_DEBUG("Offset: %d", clone_response_rcvd.offset);

	/* Set the offset of VH Child corresponding to VE Child thread */
	vedl_set_syscall_area_offset(child_handle->ve_handle,
				clone_response_rcvd.offset);

	/* Intimate PSM to schedule the newly created VE child thread */
	retval = pseudo_psm_send_schedule_req(child_handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("clone() failure: veos scheduling request error");
		PSEUDO_DEBUG("Failed to send request to veos, return value %d, "
				"mapped value %d", (int)retval, -EAGAIN);
		retval = -EAGAIN;
		goto delete_ve_task_struct;
	}

	/* Wait for the acknowledgement from PSM */
	retval = pseudo_psm_recv_schedule_ack(child_handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("clone() failure: veos scheduling acknowledgement "
				"error");
		PSEUDO_DEBUG("Failed to get acknowledgement from veos, return "
				"value %d, mapped value %d", (int)retval,
				-EAGAIN);
		retval = -EAGAIN;
		goto delete_ve_task_struct;
	}
	/* Resume the functionality of parent VH process */
	/* Acquire mutex lock */
	retval = pthread_mutex_lock(&(global_tid_info[index].mutex));
	if (retval != 0) {
		PSEUDO_ERROR("clone() failed: Failed to acquire mutex lock");
		PSEUDO_DEBUG("Failed to acquire lock, return value %d",
				-((int)retval));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	PSEUDO_DEBUG("Index : %d, RESUME PARENT : %d",
			index, global_tid_info[index].flag & RESUME_PARENT_BIT);

	global_tid_info[index].flag |= RESUME_PARENT_BIT;

	/* Signal parent, to continue execution */
	retval = pthread_cond_signal(&(global_tid_info[index].cond));
	if (retval != 0) {
		PSEUDO_ERROR("Signalling on conditional variable failed");
		PSEUDO_DEBUG("Failed to signal on condition, return value %d",
				-((int)retval));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* Release mutex lock */
	retval =  pthread_mutex_unlock(&(global_tid_info[index].mutex));

	if (retval != 0) {
		PSEUDO_ERROR("clone() failed: Failed to release mutex lock");
		PSEUDO_DEBUG("Failed to release lock, return value %d",
				-((int)retval));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	exception_handler(child_handle, extra_arg);

delete_ve_task_struct:
	global_tid_info[index].ctid_address = 0;
	process_thread_cleanup(child_handle, -1);

hndl_return:
	global_tid_info[index].flag |= CHILD_STATUS_BIT;
	global_tid_info[index].flag |= retval;
	global_tid_info[index].flag |= RESUME_PARENT_BIT;
	retval = pthread_cond_signal(&(global_tid_info[index].cond));
	if (retval != 0) {
		PSEUDO_ERROR("Signalling on condition variable failed");
		PSEUDO_DEBUG("Failed to signal on condition, return "
				"value %d", -((int)retval));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}
	PSEUDO_TRACE("Exiting");
	return;
}

/**
 * @brief Handles VE process or VE thread creation depending on the clone flags.
 *
 *	This function implements the clone() system call functionality once
 *	clone() system call is offloaded on VH.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle VEOS handle
 * @param[in] exception_handler exception handler loop function.
 * @param[in] extra_arg argument for exception handler function.
 *
 * @return On success, the thread ID of the child process is returned.
 * On failure, negative error number is returned.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve__do_clone(int syscall_num, char *syscall_name, veos_handle *handle,
			void (*exception_handler)(veos_handle *, void *),
					void *extra_arg)
{
	ret_t retval = -1, ret = -1, child_tid = -1;
	pthread_attr_t thread_attr;
	pthread_t new_thread;
	uint64_t clone_args[6];
	unsigned detach_flags , thread_flags;
	int index_local = -1;
	struct thread_func_args thread_dummy_func_args;

	detach_flags = thread_flags = CLONE_VM | CLONE_FS |
				CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
				CLONE_SYSVSEM | CLONE_SETTLS |
				CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | 0;

	detach_flags -= CLONE_CHILD_CLEARTID;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	if (exception_handler == NULL) {
		PSEUDO_ERROR("Invalid argument exception handler");
		retval = -ENOMEM;
		goto hndl_return1;
	}

	/* Fetch arguments using handle obtained*/
	retval = vedl_get_syscall_args(handle->ve_handle, clone_args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("clone() failure: Failed to fetch system call "
				"arguments");
		PSEUDO_DEBUG("Failed to fetch arguments, return value %d, "
				"mapped value %d", (int)retval, -ENOMEM);
		retval = -ENOMEM;
		goto hndl_return1;
	}

	/* Clear the CLONE_DETACHED bit from the thread flag group */
	clone_args[0] &= ~(CLONE_DETACHED);
	PSEUDO_DEBUG("clone_args[0] : %lu", clone_args[0]);

	if ((thread_flags == clone_args[0]) || (detach_flags == clone_args[0])) {

		/* Return error if tls argument passed as NULL */
		if (NULL == (uint64_t *)clone_args[4]) {
			PSEUDO_ERROR("clone() failure: Invalid TLS argument");
			retval = -EINVAL;
			goto hndl_return1;
		}

		/* Initialize attributes for new thread to be created */
		retval = pthread_attr_init(&thread_attr);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to initialise "
					"attribute");
			PSEUDO_DEBUG("Initialising attribute failed, return "
					"value %d, mapped value %d",
					-((int)retval), -ENOMEM);
			retval = -ENOMEM;
			goto hndl_return1;
		}

		/* Set detach attribute */
		retval = pthread_attr_setdetachstate(&thread_attr,
				PTHREAD_CREATE_DETACHED);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to set "
					"detach state");
			PSEUDO_DEBUG("Setting detach state failed, return "
					"value %d, mapped value %d",
					-((int)retval), -ENOMEM);
			retval = -ENOMEM;
			goto hndl_return;
		}

		/* tid_counter updation starts here */

		/* Acquire mutex lock */
		retval = pthread_mutex_lock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to acquire "
					"mutex lock");
			PSEUDO_DEBUG("Failed to acquire lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		PSEUDO_DEBUG("tid_counter: %d, index_local: %d",
				tid_counter, index_local);

		index_local = find_global_array_index(0);
		if (index_local == VEOS_MAX_VE_THREADS) {
			PSEUDO_ERROR("MAX(%d) threads created for VE process"
					". Cannot create more threads",
					VEOS_MAX_VE_THREADS);
			retval = pthread_mutex_unlock(&tid_counter_mutex);
			if (retval != 0) {
				PSEUDO_ERROR("clone() failure: Failed to "
						"release mutex lock");
				PSEUDO_DEBUG("Failed to release lock, return "
						"value %d", -((int)retval));
				fprintf(stderr, "Internal resource usage "
						"error\n");
				/* FATAL ERROR: abort current process */
				pseudo_abort();
			}
			retval = -EAGAIN;
			goto hndl_return;
		}
		global_tid_info[index_local].tid_val = -1;
		tid_counter++; /* Update tid_counter */
		PSEUDO_DEBUG("Creating new thread no : %d", tid_counter);

		global_tid_info[index_local].flag = 0;
		global_tid_info[index_local].mutex =
			(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		global_tid_info[index_local].cond =
			(pthread_cond_t)PTHREAD_COND_INITIALIZER;
		global_tid_info[index_local].guard_ptr = clone_args[5];

		PSEUDO_DEBUG("index_local : %d", index_local);
		PSEUDO_DEBUG("global_tid_info[index_local].tid_val: %d",
				global_tid_info[index_local].tid_val);

		/* Populate structure to be passed in the thread function */
		thread_dummy_func_args.parent_handle = handle;
		thread_dummy_func_args.tid_val_index = index_local;
		thread_dummy_func_args.flags = clone_args[0];
		thread_dummy_func_args.stack_ptr = clone_args[1];
		thread_dummy_func_args.ptid = clone_args[2];
		global_tid_info[index_local].ctid_address =
			thread_dummy_func_args.ctid = clone_args[3];
		thread_dummy_func_args.parent_pid = syscall(SYS_gettid);
		thread_dummy_func_args.sigmask_var = ve_proc_sigmask;
		thread_dummy_func_args.handler = exception_handler;
		thread_dummy_func_args.extra_arg = extra_arg;

		if (detach_flags == clone_args[0])
			global_tid_info[index_local].ctid_address = 0;

		PSEUDO_DEBUG("thread_dummy_func_args.flags : %lu",
				thread_dummy_func_args.flags);
		PSEUDO_DEBUG("thread_dummy_func_args.stack_ptr : %lx",
				thread_dummy_func_args.stack_ptr);
		PSEUDO_DEBUG("thread_dummy_func_args.ctid : %lx",
				thread_dummy_func_args.ctid);
		PSEUDO_DEBUG("thread_dummy_func_args.parent_pid : %lu",
				(long int)thread_dummy_func_args.parent_pid);
		PSEUDO_DEBUG("tid_counter : %d, index_local: %d",
				tid_counter, index_local);

		/* Release mutex lock */
		retval = pthread_mutex_unlock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to release "
					"mutex lock");
			PSEUDO_DEBUG("Failed to release lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		/* tid_counter updation ends here */

		/* Create VE corresponding VH child thread */
		retval = pthread_create(&new_thread, &thread_attr,
				(void *)&thread_dummy_func,
				(void *)&thread_dummy_func_args);

		if (retval != 0) {
			retval = -retval;
			PSEUDO_ERROR("clone() failure: Failed to create new "
					"thread return value %d",
					-((int)retval));
			goto hndl_return;
		}

		/* wait till the child is done with its initialisation for VE
		 * side thread to be created.
		 */
		/* Acquire mutex lock */
		retval = pthread_mutex_lock(&(global_tid_info[index_local].
					mutex));
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to acquire "
					"mutex lock");
			PSEUDO_DEBUG("Failed to acquire lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		while (0 == (global_tid_info[index_local].flag &
						RESUME_PARENT_BIT)) {
			/* wait for child thread to complete */
			retval = pthread_cond_wait(
					&(global_tid_info[index_local].cond),
					&(global_tid_info[index_local].mutex));
			if (retval != 0) {
				PSEUDO_ERROR("clone() failure: Failed to wait "
						"on condition variable");
				PSEUDO_DEBUG("Failed to wait on condition, "
						"return value %d",
						-((int)retval));
				fprintf(stderr, "Internal resource usage "
						"error\n");
				/* FATAL ERROR: abort current process */
				pseudo_abort();
			}
		}

		child_tid = global_tid_info[index_local].tid_val;

		/* Release mutex lock */
		retval = pthread_mutex_unlock(&(global_tid_info[index_local].
					mutex));
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to release "
					"mutex lock");
			PSEUDO_DEBUG("Failed to release lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		if (0 == (global_tid_info[index_local].flag & CHILD_STATUS_BIT)) {
			retval = child_tid;
			/* Check whether PTRACE_O_TRACECLONE is enabled */
			if (IS_VE_TRACED(handle->ve_handle) &&
					(VE_PTRACE_OPTION(handle->ve_handle) &
					 PTRACE_O_TRACECLONE)) {
				PSEUDO_DEBUG("PID: %ld is traced and "
						"PTRACE_O_TRACECLONE event is"
						"Enabled", syscall(SYS_gettid));
				send_sig_to_itself(SIGTRAP,
						(SIGTRAP | (PTRACE_EVENT_CLONE<<8)),
						NULL);
			} else {
				PSEUDO_DEBUG("PID: %ld is not traced",
						syscall(SYS_gettid));
			}
			goto hndl_return;
		}

		/* Set the error returned by VH child thread */
		retval = -(global_tid_info[index_local].flag & ERRNO_MASK);
	} else if (((CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD)
				== clone_args[0]) ||
			((CLONE_PARENT_SETTID | SIGCHLD) == clone_args[0]) ||
			((CLONE_VM | CLONE_VFORK | SIGCHLD) == clone_args[0]) ||
			(SIGCHLD == clone_args[0])) {
			syscall_name = "clone";
		/* Create new child process */
		return ve_do_fork(clone_args, syscall_name, handle);
	} else {
		PSEUDO_INFO("Invalid clone flags, Not supported");
		retval = -EINVAL;
		goto hndl_return1;
	}

	ret = pthread_cancel(new_thread);
	if (ret != 0) {
		PSEUDO_ERROR("clone() failure: Failed to cancel thread");
		PSEUDO_DEBUG("Failed to cancel thread, return value %d, "
				"mapped value %d", (int)ret, -ENOMEM);
		retval = -ENOMEM;
	}

	/* clean up of the corresponding entry in the global tid array */
	ret = pthread_mutex_lock(&tid_counter_mutex);
	if (ret != 0) {
		PSEUDO_ERROR("clone() failure: Failed to acquire mutex lock");
		PSEUDO_DEBUG("Failed to acquire lock, return value %d",
							-((int)ret));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	clear_global_array_entry(index_local);

	ret = pthread_mutex_unlock(&tid_counter_mutex);
	if (ret != 0) {
		PSEUDO_ERROR("clone() failure: Failed to release mutex lock");
		PSEUDO_DEBUG("Failed to release lock, return value %d",
							-((int)ret));
		fprintf(stderr, "Internal resource usage error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

hndl_return:
	if (retval < 0) {
		ret = pthread_attr_destroy(&thread_attr);
		if (ret != 0) {
			PSEUDO_ERROR("Failed to destroy attr, return value %d",
					-((int)ret));
		}
	}
hndl_return1:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}

/**
 * @brief Pseudo side clone handler.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle ve driver handle to communicate between pseudo process and
 *             ve driver.
 *
 * @return system call value to VE process.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_clone(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;

	PSEUDO_DEBUG("Acquiring lock for ve_clone() syscall");
	if (pthread_mutex_lock(&(global_tid_info[0].mutex))) {
		PSEUDO_DEBUG("Failed to acquire global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	retval = ve__do_clone(syscall_num, syscall_name, handle,
			pse_exception_handler, NULL);

	PSEUDO_DEBUG("Releasing lock for ve_clone() syscall");
	if (pthread_mutex_unlock(&(global_tid_info[0].mutex))) {
		PSEUDO_DEBUG("Failed to release global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	return retval;
}

/**
 *  @brief Checks that Process is alive or not by accessing proc interface
 *
 *  @param[in] pid of process whose proc entry is to be read.
 *
 *  @return -1 if task state of process has become ZOMBIE or readproc()
 *  fails for "pid", else 0 is returned if process is alive.
 */
int ve_premature_child_exit(pid_t pid)
{
	PROCTAB *proc;
	proc_t *proc_info;
	int ret = -1;
	int locked;

	locked = pthread_mutex_lock(&readproc_mutex);
	if (0 != locked) {
		PSEUDO_DEBUG("Failed to acquire read proc lock: %s",
				strerror(locked));
		goto handle_failure;
	}

	proc = openproc(PROC_FILLSTAT|PROC_PID, &pid);
	if (NULL == proc) {
		PSEUDO_DEBUG("Fails to open proc interface for pid: %d", pid);
		goto handle_error;
	}

	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		PSEUDO_DEBUG("Fail to read proc information for pid: %d", pid);
		closeproc(proc);
		goto handle_error;
	}

	if (proc_info->state == 'Z') {
		PSEUDO_DEBUG("VH process has become zombie");
		freeproc(proc_info);
		closeproc(proc);
		goto handle_error;
	}
	freeproc(proc_info);
	closeproc(proc);
	ret = 0;
handle_error:
	locked = pthread_mutex_unlock(&readproc_mutex);
	if (0 != locked) {
		PSEUDO_DEBUG("Failed to release read proc lock: %s",
				strerror(locked));
		ret = -1;
	}

handle_failure:
	return ret;
}

/**
 * @brief Handles VE process creation once fork() and vfork() are offloaded on
 * VH.
 *
 * @param[in] clone_args[] argmunets received for system call handling
 *             (i.e. by fork(), vfork() or clone()).
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return on success, the pid of the child process is returned in the
 * parent, and 0 is returned in the child. on failure, negative error number
 * is returned.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_do_fork(uint64_t clone_args[], char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	ret_t delete_ret = 0;
	pid_t pid, child_pid = -1;
	volatile int *shared_var = NULL;
	struct pseudo_ve_clone_info ve_fork_info = {0};
	int offset = -1;
	int shmid = 0;
	int trace = 0;
	int index = 0;
	pid_t tid = syscall(SYS_gettid);

	PSEUDO_TRACE("Entering");

	shared_var = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if ((void *)-1 == (void *)shared_var) {
		PSEUDO_ERROR("Failed to allocate memory for shared variable");
		PSEUDO_DEBUG("Failed to map the address, return value %d, "
				"mapped value %d", -errno, -ENOMEM);
		retval = -ENOMEM;
		goto hndl_fail4;
	}
	*shared_var = DO_FORK_INIT;

	sys_prepar_clear_all_vhshm_resource();

	/* Create new child process */
	retval = pthread_rwlock_wrlock(&sync_fork_dma);
	if (retval) {
		PSEUDO_ERROR("failed to acquire write lock to"
				" synchronise dma %s", strerror(retval));
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}
	child_pid = pid =  fork();
	if (0 < pid) {
		retval = pthread_rwlock_unlock(&sync_fork_dma);
		if (retval) {
			PSEUDO_ERROR("failed to release write lock to"
					" synchronize dma %s", strerror(retval));
			fprintf(stderr, "Internal resource usage error\n");
			pseudo_abort();
		}
		/* In Parent VH Context */
		PSEUDO_DEBUG("Child PID = %d Parent PID = %ld",
				pid, syscall(SYS_gettid));

		do {
			/*
			 * In case when VH child process exits abnormally
			 * without changing shared variable, for instance,
			 * calling pseudo_abort(), break polling on the shared_variable.
			 *
			 * However, ve_premature_child_exit() will return non-zero
			 * in case where child exited normally before parent could check
			 * the shared variable in next iteration, hence falsely returning
			 * failure. Hence, we recheck whether child has updated
			 * the shared_var.
			 * */
			if (ve_premature_child_exit(pid) &&
					DO_FORK_SUCCESS != *shared_var) {
				*shared_var = -EAGAIN;
				PSEUDO_ERROR("VH child process exit"
						" unexpectdly");
				break;
			}
		} while (DO_FORK_INIT == *shared_var);

		if (DO_FORK_SUCCESS != *shared_var) {
			/* cleanup of child process
			 * which is present on VH but not on VE
			 */
			PSEUDO_DEBUG("VE fork failed. wait() for "
					"VH child process with PID:"
					" %d", (int) pid);
			if (waitpid(pid, NULL, 0) == -1) {
				PSEUDO_ERROR("wait failed for VH child: "
						"%d, errno: %d ",
						pid, -errno);
			}
			retval = *shared_var;
		} else
			retval = pid;

		/* Check whether PTRACE_O_TRACEFORK is enabled */
		if (IS_VE_TRACED(handle->ve_handle) &&
				(VE_PTRACE_OPTION(handle->ve_handle) &
				 PTRACE_O_TRACEFORK) &&
				!(clone_args[0] & CLONE_VFORK)) {
			PSEUDO_DEBUG("PID: %ld is traced and PTRACE_O_TRACEFORK"
					" event is Enabled",
					syscall(SYS_gettid));
			trace = (SIGTRAP | (PTRACE_EVENT_FORK<<8));
		}

		/* Check whether PTRACE_O_TRACEVFORK is enabled */
		if (IS_VE_TRACED(handle->ve_handle) &&
				(VE_PTRACE_OPTION(handle->ve_handle) &
				 PTRACE_O_TRACEVFORK) &&
				clone_args[0] & CLONE_VFORK) {
			PSEUDO_DEBUG("PID: %ld is traced and "
					"PTRACE_O_TRACEVFORK "
					" event is Enabled",
					syscall(SYS_gettid));
			trace = (SIGTRAP | (PTRACE_EVENT_VFORK<<8));
		}

		sys_clear_all_vhshm_resource(pid);

		/* If trace event enabled send SIGTRAP to itself and
		 * populate ptrace event information in si_code.
		 */
		if (trace)
			send_sig_to_itself(SIGTRAP, trace, NULL);

	} else if (0 == pid) {
		/* In Child VH Context */
		pid = syscall(SYS_gettid);
		veos_handle *p_handle = handle;
		if (log4c_init()) {
			pseudo_abort();
		}
		if (!log4c_category_get("veos.pseudo_process.core")) {
			pseudo_abort();
		}
		retval = pthread_rwlock_unlock(&sync_fork_dma);
		if (retval) {
			PSEUDO_ERROR("failed to release write lock to"
					" synchronize dma %s", strerror(retval));
			fprintf(stderr, "Internal resource usage error\n");
			pseudo_abort();
		}

		/* After fork() re-initalize the syscall trap field in child */
		sys_enter_trap = false;

		if (clone_args[0] & CLONE_VFORK) {
			/* Get new VEDL handle for vforked child*/
			PSEUDO_DEBUG("Creating new handle for vforked child");
			offset = vedl_get_syscall_area_offset(handle->ve_handle);

			handle = veos_handle_create(p_handle->device_name,
					p_handle->veos_sock_name, p_handle, -1);
			if (handle == NULL) {
				PSEUDO_ERROR("%s failure: Creation of new "
						"handle for vforked child "
						"failed", syscall_name);
				PSEUDO_DEBUG("Failed to create handle for "
						"vforked child, return "
						"value: %d, mapped value %d",
						-errno, -EAGAIN);
				retval = -EAGAIN;
				goto hndl_fail3;
			}
			/* Update global handle */
			g_handle = handle;
			PSEUDO_DEBUG("Closing parent's threads fd in vforked child");
			for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {
				if (global_tid_info[index].tid_val > 0) {
					PSEUDO_DEBUG("closing fd's for PID %d",
							global_tid_info[index].tid_val);
					retval = vedl_close_ve(global_tid_info[index].veos_hndl->ve_handle);
					if (retval)
						PSEUDO_ERROR("close VEDL handle failed.");
					close(global_tid_info[index].veos_hndl->veos_sock_fd);
					global_tid_info[index].veos_hndl->ve_handle = NULL;
					veos_handle_free(global_tid_info[index].veos_hndl);
				}
			}

			/* Set the offset of VH Child */
			vedl_set_syscall_area_offset(handle->ve_handle, offset);
		} else {
			shmdt(handle->ve_handle->lshm_addr);

			PSEUDO_DEBUG("Closing parent's threads fd in forked child");
			for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {
				if (global_tid_info[index].tid_val > 0) {
					PSEUDO_DEBUG("closing fd's for PID %d",
							global_tid_info[index].tid_val);
					retval = vedl_close_ve(global_tid_info[index].veos_hndl->ve_handle);
					if (retval)
						PSEUDO_ERROR("close VEDL handle failed.");
					close(global_tid_info[index].veos_hndl->veos_sock_fd);
					global_tid_info[index].veos_hndl->ve_handle = NULL;
				}
			}

			/* Get new VEDL handle for forked child VH process */
			PSEUDO_DEBUG("Creating new handle for forked child");
			handle = veos_handle_create(p_handle->device_name,
					p_handle->veos_sock_name, NULL, -1);
			if (handle == NULL) {
				PSEUDO_ERROR("%s failure: Creation of new "
						"handle for forked child "
						"failed", syscall_name);
				PSEUDO_DEBUG("Failed to create handle for "
						"forked child, return "
						"value: %d, mapped value %d",
						-errno, -EAGAIN);
				retval = -EAGAIN;
				goto hndl_fail3;
			}
			/* Update global handle */
			g_handle = handle;

			/* Closing parent VE process handler */
			for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {

				if (global_tid_info[index].tid_val > 0) {
					PSEUDO_DEBUG("Freeing veos handle for PID %d",
							global_tid_info[index].tid_val);
					veos_handle_free(global_tid_info[index].veos_hndl);
				}
			}

			/* Set offset to zero, just in case */
			vedl_set_syscall_area_offset(handle->ve_handle, 0);
		}

		/* Re-initialize global tid array and tid_counter */
		memset(((void *)global_tid_info)+sizeof(struct tid_info), 0,
				sizeof(global_tid_info) - sizeof(struct tid_info));
		tid_counter = 0;
		/* Update global tid array for main thread */
		global_tid_info[0].vefd = g_handle->ve_handle->vefd;
		global_tid_info[0].veos_hndl = g_handle;
		global_tid_info[0].tid_val = getpid();
		global_tid_info[0].flag = clone_args[0];
		global_tid_info[0].mutex =
			(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		global_tid_info[0].cond =
			(pthread_cond_t)PTHREAD_COND_INITIALIZER;
		global_tid_info[0].guard_ptr = clone_args[5];

		PSEUDO_DEBUG("TID struct vefd : %d, VE driver fd %d",
				global_tid_info[0].vefd,
				g_handle->ve_handle->vefd);

		PSEUDO_DEBUG("handle: %p", handle);

		if (!(clone_args[0] & CLONE_VFORK)) {
			PSEUDO_DEBUG("Initialising lshm area for child");
			shmid = init_lhm_shm_area(handle);
			if (shmid < 0) {
				PSEUDO_ERROR("%s failure: Intialising shared "
						"memory region failed",
						syscall_name);
				PSEUDO_DEBUG("Failed to intialize shared "
						"memory, return value %d, "
						"mapped value %d",
						-errno, -ENOMEM);
				retval = -ENOMEM;
				goto hndl_fail1;
			}
		}

		/* prepare structure to be sent to PSM */
		ve_fork_info.parent_pid = tid;
		ve_fork_info.flags = clone_args[0];
		ve_fork_info.stack_ptr = clone_args[1];
		ve_fork_info.ptid = clone_args[2];
		ve_fork_info.ctid = clone_args[3];
		ve_fork_info.shm_lhm_addr =
			(uint64_t)vedl_get_shm_lhm_addr(handle->ve_handle);
		ve_fork_info.shmid = shmid;

		memset(&ve_fork_info.veshm_dir, BYTE_MASK,
				sizeof(struct veshm_struct) * VESHM_DIR_SIZE);
		/*
		 * copy base and veshm bitmat of all allocated dir
		 * into ve_fork_info */
		copy_vemva_dir_info(ve_fork_info.veshm_dir);

		sys_clear_all_vhshm_resource(CHILD_PROCESS);

		/* Request VEOS to perform cloning */
		retval = pseudo_psm_send_fork_req(syscall_name,
				ve_fork_info,
				handle->veos_sock_fd);
		if (retval < 0) {
			PSEUDO_ERROR("%s failure: veos request error", syscall_name);
			PSEUDO_DEBUG("Failed to send request to veos, return "
					"value %d, mapped value %d",
					(int)retval, -ENOMEM);
			retval = -ENOMEM;
			goto hndl_fail2;
		} else {
			/* Wait for ACK from VEOS */
			retval = pseudo_psm_recv_fork_ack(handle->veos_sock_fd);
			if (retval < 0) {
				PSEUDO_ERROR("%s failure: veos acknowledgement "
						"error", syscall_name);
				PSEUDO_DEBUG("Failed to get acknowledgement "
						"from, return value %d",
						(int)retval);
				goto hndl_fail2;
			}
		}

		/* Store child thread ID in child memory */
		if (clone_args[0] & CLONE_CHILD_SETTID) {
			if (NULL != (uint64_t *)clone_args[3]) {
				retval = ve_send_data(handle, clone_args[3],
						sizeof(pid_t), (void *)&pid);
				if (retval < 0) {
					PSEUDO_ERROR("%s failure: Failed to set"
							" TID in child context",
							syscall_name);
					PSEUDO_DEBUG("Failed to set TID in "
							"child context, return "
							"value %d, mapped "
							"value %d", -errno,
							-ENOMEM);
					*shared_var = DO_FORK_FAIL;
					retval = -ENOMEM;
					goto hndl_fail1;
				}
			}
		}

		/* Clear the tracing information for vhild process */
		memset((void *)PTRACE_PRIVATE_DATA, 0, getpagesize());

		/* Send veos request to schedule the newly
		 * created child VE process on VE core
		 * */
		retval = pseudo_psm_send_schedule_req(handle->veos_sock_fd);
		if (retval < 0) {
			PSEUDO_ERROR("%s failure: veos scheduling request "
					"error", syscall_name);
			PSEUDO_DEBUG("Failed to send request to veos, return "
					"value %d, mapped value %d",
					(int)retval, -EAGAIN);
			retval = -EAGAIN;
			goto hndl_fail1;
		} else {
			/* Waiting for ACK from PSM */
			retval = pseudo_psm_recv_schedule_ack(handle->veos_sock_fd);
			if (retval < 0) {
				PSEUDO_ERROR("%s failure: veos scheduling "
						"acknowledegment error",
						syscall_name);
				PSEUDO_DEBUG("Failed to get acknowledegment "
						"from veos, return value %d, "
						"mapped value %d",
						(int)retval, -EAGAIN);
				retval = -EAGAIN;
				goto hndl_fail1;
			}
		}

		retval = 0;
		*shared_var = DO_FORK_SUCCESS;

		/* Free the VH buffer of acc IO */
		sys_accelerated_free_vh_buf();

		/* Handle return of the fork/vfork system call
		 * Call exception handler with new handle
		 */
		pse_exception_handler(handle, NULL);
	} else {
		retval = pthread_rwlock_unlock(&sync_fork_dma);
		if (retval) {
			PSEUDO_ERROR("failed to release write lock to"
					" synchronize dma %s", strerror(retval));
			fprintf(stderr, "Internal resource usage error\n");
			pseudo_abort();
		}
		retval = -errno;
		PSEUDO_ERROR("VH fork() failed for PID %ld",
				syscall(SYS_gettid));
		PSEUDO_DEBUG("VH fork failed, return value %d", (int)retval);
	}

	munmap((void *)shared_var, sizeof(int));
	/* write return value */
	return retval;

hndl_fail1:
	if ((delete_ret = pseudo_psm_send_delete_ve_proc_req
				(handle->veos_sock_fd, 0, -1, -1)) < 0) {
		PSEUDO_ERROR("%s failure: veos cleanup request "
				"error", syscall_name);
		PSEUDO_DEBUG("Failed to send request to veos, return value %d",
				(int)delete_ret);
		goto hndl_fail2;
	}

	/* wait for acknowledgment from PSM */
	delete_ret = pseudo_psm_recv_delete_ack(handle->veos_sock_fd);
	if (delete_ret < 0) {
		PSEUDO_ERROR("%s failure: veos cleanup acknowledgement "
				"error", syscall_name);
		PSEUDO_DEBUG("Failed to send acknowledgement to veos, return "
				"value %d", (int)delete_ret);
	} else
		PSEUDO_DEBUG("errno from new child process: %s",
				strerror(retval));

hndl_fail2:
	veos_handle_free(handle);

hndl_fail3:
	*shared_var = retval;
	munmap((void *)shared_var, sizeof(int));
	if (child_pid == 0) {
		PSEUDO_ERROR("Child process creation failed");
		exit(EXIT_FAILURE);
	}
hndl_fail4:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles vfork() functionality for veos
 *
 * pid_t vfork(void);
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return on success, the pid of the child process is returned in the
 * parent, and 0 is returned in the child. on failure, negative error number
 * is returned.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_vfork(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t clone_args[6];
	ret_t retval = -1;

	clone_args[0] = CLONE_VM | CLONE_VFORK | SIGCHLD | 0;
	clone_args[1] = 0;
	clone_args[2] = 0;
	clone_args[3] = 0;
	clone_args[4] = 0;
	clone_args[5] = 0;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	PSEUDO_DEBUG("Acquiring lock for vfork() syscall");
	if (pthread_mutex_lock(&(global_tid_info[0].mutex))) {
		PSEUDO_DEBUG("Failed to acquire global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	syscall_name = "vfork";
	retval = ve_do_fork(clone_args, syscall_name, handle);

	PSEUDO_DEBUG("Releasing lock for vfork() syscall");
	if (pthread_mutex_unlock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to release global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles fork() functionality for veos
 *
 * pid_t fork(void);
 *
 * @param syscall_num System call number
 * @param syscall_name System call name
 * @param handle VEOS handle
 *
 * @return on success, the pid of the child process is returned in the
 * parent, and 0 is returned in the child. on failure, negative error number
 * is returned.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_fork(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t clone_args[6];
	ret_t retval = -1;

	clone_args[0] = SIGCHLD | 0;
	clone_args[1] = 0;
	clone_args[2] = 0;
	clone_args[3] = 0;
	clone_args[4] = 0;
	clone_args[5] = 0;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	PSEUDO_DEBUG("Acquiring lock for fork() syscall");
	if (pthread_mutex_lock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to acquire global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	syscall_name = "fork";
	retval = ve_do_fork(clone_args, syscall_name, handle);

	PSEUDO_DEBUG("Releasing lock for fork() syscall");
	if (pthread_mutex_unlock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to release global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}


	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles execve functionality for VE process.
 *
 * int execve(const char *filename, char *const argv[],
 *			char *const envp[]);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_execve(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	char *exe_name = NULL;
	char * real_exe_name = NULL;
	char *head = NULL;
	uint64_t args[3] = {0};
	struct statvfs st = {0};
	struct stat sb = {0};
	char ve_env[][24] = {"VE_EXEC_PATH=", "PWD=", "LOG4C_RCPATH=", "HOME=","VE_LD_ORIGIN_PATH="};
	int indx = 0;
	int ve_env_given[5] = {0};
	/* To fetch VE pointers */
	char *execve_arg[EXECVE_MAX_ARGS] = {NULL};
	char *execve_envp[EXECVE_MAX_ENVP] = {NULL};
	/* To store VH pointers */
	char *execve_vh_arg[EXECVE_MAX_ARGS] = {NULL};
	char *execve_vh_envp[EXECVE_MAX_ENVP] = {NULL};
	int cntr = 0;
	int fd = -1;

	/* elf_type depicts whether execve will execute VH binary
	 * or it will load a VE binary
	 * If elf_type = 2 , then VH binary will be loaded
	 * else if elf_type = 3, then VE binary will be loaded
	 * */
	int elf_type = EXIT_EXECVE_VH;
	int shift_cntr = 0;
	int kill_flag = 0;
	int exe_flag = 0;
	sigset_t signal_mask;
	int loop_cntr = 0;
	int vefd = 0;
	int index = 0;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("execve() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value %d mapped to -EFAULT",
				syscall_name, (int)retval);

		retval = -EFAULT;
		goto hndl_fail;
	}

	/* allocate memory for storing VE binary name */
	exe_name = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == exe_name) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory "
				"for storing VE binary name");
		goto hndl_fail;
	}
	memset(exe_name, '\0', PATH_MAX);

	PSEUDO_DEBUG("Acquiring lock for execve() syscall");
	if (pthread_mutex_lock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to acquire global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	/* receive contents of 1st argument(filename) */
	retval = ve_recv_string(handle, args[0], (char *)exe_name, PATH_MAX);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to receive argument");
		PSEUDO_DEBUG("Failed to receive argument, retval %d "
				"mapped to -EFAULT",
				(int)retval);
		if (retval == -2)
			retval = -ENAMETOOLONG;
		else
			retval = -EFAULT;
		goto hndl_fail1;
	}

	/* To Fetch the real path of binary */
	real_exe_name = realpath(exe_name, NULL);
	if (NULL == real_exe_name) {
		retval = -errno;
		PSEUDO_ERROR("Fail(%s) to get realpath of:%s",
				strerror(errno),
				exe_name);
		goto hndl_fail1;
	}

	PSEUDO_DEBUG("Realpath of binary is %s", real_exe_name);

	retval = statvfs(real_exe_name, &st);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("File stat fail: %s",
				strerror(errno));
		goto hndl_fail1;
	}

	/* Check if noexec flag was set when the directory was mounted */
	if (st.f_flag & ST_NOEXEC) {
		PSEUDO_ERROR("Executing from a directory mounted with noexec");
		retval = -EACCES;
		goto hndl_fail1;
	}

	/* Check if realpath has search permissions
	 * If not, then EACCES should be returned */
	retval = access(real_exe_name, F_OK);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("Path of binary inaccessible");
		PSEUDO_DEBUG("Accessing real_path to binary failed, "
				"errno %d", errno);
		goto hndl_fail1;
	}

	retval = stat(real_exe_name, &sb);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("File stat fail: %s",
				strerror(errno));
		goto hndl_fail1;
	}

	if (!S_ISREG(sb.st_mode)) {
		PSEUDO_ERROR("Not a regular file");
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				-errno, -EACCES);
		retval = -EACCES;
		goto hndl_fail1;
	}

	/* Check if the file has execute permissions */
	if (!(sb.st_mode & S_IXUSR)) {
		PSEUDO_ERROR("File doesn't have executable permissions");
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				-errno, -EACCES);
		retval = -EACCES;
		goto hndl_fail1;
	}

	if (S_ISDIR(sb.st_mode)) {
		PSEUDO_ERROR("execve() failure: Is a directory");
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				-errno, -EISDIR);
		retval = -EISDIR;
		goto hndl_fail1;
	}


	/* To check whether the binary (pointed by real_exe_name)
	 * is VE binary or VH binary */
	head = open_bin_file(real_exe_name, &fd);
	if (head) {
		if (!chk_elf_consistency((Elf_Ehdr *)head)) {
			PSEUDO_DEBUG("%s is VE binary", real_exe_name);
			elf_type = EXIT_EXECVE_VE;
			exe_flag = 1;
			shift_cntr = VE_EXECVE_ARGS;
			/* Insertion of ve specific arguments inherited
			 * from current process */

			execve_vh_arg[0] = VE_EXEC_PATH;
			execve_vh_arg[1] = "-d";
			execve_vh_arg[2] = handle->device_name;
			execve_vh_arg[3] = "-s";
			execve_vh_arg[4] = handle->veos_sock_name;
			execve_vh_arg[5] = real_exe_name;

			PSEUDO_DEBUG("CREATED VE ARGUMENT LIST AT VH");
			for (cntr = 0; cntr <= shift_cntr; cntr++) {
				PSEUDO_DEBUG("ARG%d -> %s",
						cntr, execve_vh_arg[cntr]);
			}
		}
		free(head); /* done with elf check */
	} else {
		retval = -errno;
		PSEUDO_ERROR("Failed to check binary type");
		goto hndl_fail1;

	}

	loop_cntr = 0;
	for (;;) {
		PSEUDO_DEBUG("ARGV[%d] %p", loop_cntr, (void *)execve_arg + loop_cntr);
		if (0 > ve_recv_data(handle, (uint64_t)args[1] + (loop_cntr * sizeof(char *)),
					sizeof(char *), (void *)(execve_arg + loop_cntr)))
			break;
		loop_cntr++;
		if (loop_cntr >= (EXECVE_MAX_ARGS - shift_cntr))
			break;
	}

	if (loop_cntr == 0) {
		PSEUDO_ERROR("argv argument passed to execve is NULL");
		retval = -EFAULT;
		goto hndl_fail1;
	}

	for (cntr = exe_flag; cntr < (EXECVE_MAX_ARGS - shift_cntr) ; cntr++) {
		PSEUDO_DEBUG("Fetchin argument number %d", cntr - exe_flag + 1);
		if (0 == execve_arg[cntr])
			break;
		execve_vh_arg[cntr+shift_cntr] =
			(char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == execve_vh_arg[cntr+shift_cntr]) {
			retval = -errno;
			goto hndl_fail2;
		}
		memset(execve_vh_arg[cntr+shift_cntr], '\0', PATH_MAX);

		/* receive contents of VE  arguments */
		retval = ve_recv_string(handle, (uint64_t)execve_arg[cntr],
				execve_vh_arg[cntr+shift_cntr], PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive argument");
			PSEUDO_DEBUG("Failed to receive argument returning %d"
					" mapped to -EFAULT",
					(int)retval);
			retval = -EFAULT;
			goto hndl_fail2;
		}
		PSEUDO_DEBUG("VE ARGUMENT %d -> %s",
				cntr+shift_cntr,
				execve_vh_arg[cntr+shift_cntr]);
	}
	if (cntr >= (EXECVE_MAX_ARGS - shift_cntr)) {
		PSEUDO_ERROR("Argument count exceeded");
		retval = -E2BIG;
		goto hndl_fail2;
	}

	if (NULL != (uint64_t *)args[2]) {
		loop_cntr = 0;
		for (;;) {
			PSEUDO_DEBUG("ENV[%d] %p", loop_cntr, (void *)execve_envp + loop_cntr);
			if (0 > ve_recv_data(handle, (uint64_t)args[2]
						+ (loop_cntr * sizeof(char *)),
						sizeof(char*),
						(void *)(execve_envp + loop_cntr))) {
				break;
			}
			loop_cntr++;
			if (loop_cntr >= EXECVE_MAX_ENVP)
				break;
		}
	} else {
		PSEUDO_DEBUG("No Environment variables given");
		execve_envp[0] = (char *)args[2];
	}

	for (cntr = 0; cntr < EXECVE_MAX_ENVP; cntr++) {
		if (0 == execve_envp[cntr])
			break;
		execve_vh_envp[cntr] = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == execve_vh_envp[cntr]) {
			retval = -errno;
			goto hndl_fail2;
		}
		memset(execve_vh_envp[cntr], '\0', PATH_MAX);

		/* receive contents of VE environment variables */
		retval = ve_recv_string(handle, (uint64_t)execve_envp[cntr],
				(char *)execve_vh_envp[cntr], PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failed to receive argument");
			PSEUDO_DEBUG("Failed to receive argument returning %d"
					", mapped value: %d",
					(int)retval, -EFAULT);
			retval = -EFAULT;
			goto hndl_fail2;
		}
		/* Check and maintain which VE specific environment variables
		 * exist in environment variable array received as argument
		 * to execve()
		 * */
		if (exe_flag) {
			for (indx = 0; indx < 5; indx++) {
				if (!strncmp(execve_vh_envp[cntr],
					ve_env[indx], strlen(ve_env[indx]))) {
					ve_env_given[indx] = 1;
					break;
				}
			}
		}
	}

	if (cntr >= EXECVE_MAX_ENVP) {
		PSEUDO_ERROR("Environment variable count exceeded");
		retval = -E2BIG;
		goto hndl_fail2;
	}

	/* Pass ve specific environment variables inherited
	 * from current process to execve'ed process if not already passed
	 * in environment variable array received as argument to execve().
	 * */
	if (exe_flag) {
		for (indx = 0; indx < 5; indx++) {
			if (ve_env_given[indx])
				continue;

			if (cntr >= EXECVE_MAX_ENVP) {
				PSEUDO_ERROR("Environment variable count exceeded");
				retval = -E2BIG;
				goto hndl_fail2;
			}
			execve_vh_envp[cntr] = (char *)malloc(PATH_MAX
					* sizeof(char));
			if (NULL == execve_vh_envp[cntr]) {
				retval = -errno;
				goto hndl_fail2;
			}
			memset(execve_vh_envp[cntr], '\0', PATH_MAX);
			switch(indx) {
			case 0:
				sprintf(execve_vh_envp[cntr],
						"VE_EXEC_PATH=%s",
						getenv("VE_EXEC_PATH"));
				execve_vh_envp[++cntr] = NULL;
				break;
			case 1:
				sprintf(execve_vh_envp[cntr],
						"PWD=%s", getenv("PWD"));
				execve_vh_envp[++cntr] = NULL;
				break;
			case 2:
				sprintf(execve_vh_envp[cntr],
						"LOG4C_RCPATH=%s",
						getenv("LOG4C_RCPATH"));
				execve_vh_envp[++cntr] = NULL;
				break;
			case 3:
				sprintf(execve_vh_envp[cntr],
						"HOME=%s", getenv("HOME"));
				execve_vh_envp[++cntr] = NULL;
				break;
			case 4:
				sprintf(execve_vh_envp[cntr],
						"VE_LD_ORIGIN_PATH=%s", getenv("VE_LD_ORIGIN_PATH"));
				execve_vh_envp[++cntr] = NULL;
				break;
			}
		}
	}

	for (cntr = 0; cntr < EXECVE_MAX_ARGS; cntr++) {
		if (0 == execve_vh_envp[cntr])
			break;

		PSEUDO_DEBUG("VE ENVIRONMENT LIST");
		PSEUDO_DEBUG("ENV[%d] -> %s",
				cntr, execve_vh_envp[cntr]);
	}

	/* Extract vefd to be saved */
	if (getpid() != syscall(SYS_gettid)) {
		vefd = global_tid_info[0].vefd;
		PSEUDO_DEBUG("PID %ld Saving Parent's [%d] vefd %d TID %d",
				syscall(SYS_gettid),
				getpid(), vefd, global_tid_info[0].tid_val);
	} else {
		vefd = handle->ve_handle->vefd;
		PSEUDO_DEBUG("PID %d Saving its vefd %d",
				getpid(), vefd);
	}

	/* start VE program and wait for exception */
	/* Send request to PSM for cleanup of VE process */
	/* handle->fd contains already opened ve_driver fd and it
	 * will be store in ve_task_struct */
	retval = pseudo_psm_send_delete_ve_proc_req(handle->veos_sock_fd,
			elf_type, -1, vefd);
	if (retval < 0) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		PSEUDO_ERROR("execve() failure: veos request error, return value %d",
				(int)retval);
		PSEUDO_DEBUG("VEOS cleanup fails");
		goto hndl_fail2;
	}

	retval = pseudo_psm_recv_delete_ack(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d"
				, (int)retval, -EFAULT);
		retval = -EFAULT;
		PSEUDO_ERROR("execve failure: "
				"veos delete acknowledgement error, return value %d",
				(int)retval);
		kill_flag = 1;
		goto hndl_fail2;
	}

	if (elf_type == EXIT_EXECVE_VH) {
		if (handle->ve_handle) {
			/* close VEDL handle */
			retval = vedl_close_ve(handle->ve_handle);
			if (retval)
				PSEUDO_ERROR("close VEDL handle failed.");
		}
		free(handle->device_name);
		free(handle->veos_sock_name);
	}

	/* Close all valid thread vefd */
	for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {
		/* Skip if main thread invoked execve with
		 * VE binary
		 * */
		if ((index == 0) && (elf_type == EXIT_EXECVE_VE))
			continue;
		if (global_tid_info[index].tid_val > 0)
			close(global_tid_info[index].vefd);
	}

	for (cntr = 0; cntr < EXECVE_MAX_ENVP; cntr++) {
		if (0 == execve_vh_arg[cntr])
			break;

		PSEUDO_DEBUG("VE ARGUMENT LIST");
		PSEUDO_DEBUG("ARG[%d] -> %s",
				cntr, execve_vh_arg[cntr]);
	}

	/* Unblock all the signals except the ones which are blocked by the
	 * VE Process, else it will be impossible to recover the original
	 * mask for exec VE/VH program.*/
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigemptyset(&signal_mask);
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	if (exe_flag) {
		execve(execve_vh_arg[0], execve_vh_arg, execve_vh_envp);
	} else {
		execve(real_exe_name, execve_vh_arg, execve_vh_envp);
	}
	retval = -errno;
	PSEUDO_ERROR("VH execve failed due to: %d %s", errno, strerror(errno));
	fprintf(stderr, "VE process setup failed\n");

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (retval) {
		PSEUDO_ERROR("execve failed %s", strerror(errno));
		kill_flag = 1;
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_fail2:
	/* Release all the buffers */
	cntr = shift_cntr + exe_flag;
	while (NULL != execve_vh_arg[cntr] && cntr < EXECVE_MAX_ARGS) {
		PSEUDO_DEBUG("Freeing argument number %d", cntr);
		free(execve_vh_arg[cntr++]);
	}

	cntr = 0;
	while (NULL != execve_vh_envp[cntr] && cntr < EXECVE_MAX_ENVP - 1) {
		PSEUDO_DEBUG("Freeing environment variable %d", cntr);
		free(execve_vh_envp[cntr++]);
	}
hndl_fail1:
	if (real_exe_name != NULL)
		free(real_exe_name);
	if (exe_name != NULL)
		free(exe_name);
	/* Cleaning of all the task associated with pid*/
	if (kill_flag == 1) {
		close(fd);
		kill(getpid(), SIGKILL);
		return retval;
	}
hndl_fail:
	PSEUDO_DEBUG("Releasing lock for execve() syscall");
	if (pthread_mutex_unlock(&(global_tid_info[0].mutex)) != 0) {
		PSEUDO_DEBUG("Failed to release global_tid lock");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}
	close(fd);
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles wait4() system call functionality for VE.
 *
 * pid_t wait4(pid_t pid, int *status, int options,
 *		struct rusage *rusage);
 *
 * This function fetches the arguments from VEHVA/VEMVA and then invokes the
 * VH OS wait4() system call.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call value to VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_wait4(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t wait4_args[4];
	ret_t retval = -1;
	ret_t pid = -1;
	int status = -1;
	struct rusage r = {{0}};
	struct ve_rusage ve_r = {{0}};
	struct ve_rusage_info rusage_task = {0};
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);
	retval = vedl_get_syscall_args(handle->ve_handle, wait4_args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for wait4 system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EINVAL);
		retval = -EINVAL;
		return retval;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");

	sigemptyset(&signal_mask);
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	pid = retval = syscall(syscall_num, wait4_args[0], &status,
			wait4_args[2], &r);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	PSEUDO_DEBUG("status: %d, exited: %d, exitstatus: %d,"
			"signaled: %d, termsig: %d",
			status, WIFEXITED(status), WEXITSTATUS(status),
			WIFSIGNALED(status), WTERMSIG(status));

	if (-1 == retval) {
		retval = -errno;
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		PSEUDO_ERROR("wait4 failed: %s", strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		/* Post-processing of syscall started, blocking signals */
		goto hndl_return;
	} else
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	PSEUDO_DEBUG("Blocked signals for post-processing");

	/* Get the VE specific rusage from VEOS.*/
	rusage_task.pid = retval ? retval : wait4_args[0];
	rusage_task.who = RUSAGE_SELF;

	/* Set child eligible to be reaped if:
	 * 1. return value > 0
	 * 2. child has exited anyhow */
	if (pid > 0 && (WIFEXITED(status) || WIFSIGNALED(status))) {
		PSEUDO_DEBUG("Child %d to be reaped now", rusage_task.pid);
		rusage_task.cleanup = true;
	}

	if (rusage_task.pid > 0) {
		retval = pseudo_psm_send_get_rusage_req(handle->veos_sock_fd,
				rusage_task);
		if (retval < 0) {
			PSEUDO_ERROR("Request for getting resource usage failed");
			PSEUDO_DEBUG("%s failure: rusage request returned %d",
					syscall_name, (int) retval);
			PSEUDO_DEBUG("Mapping retval %d to errno %d",
					(int) retval, -EINVAL);
			retval = -EINVAL;
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_get_rusage_ack(handle->veos_sock_fd,
				&ve_r);
		if (retval < 0) {
			PSEUDO_ERROR("Getting resource usage acknowledgement failed");
			PSEUDO_DEBUG("%s failure: rusage acknowledgement returned %d",
					syscall_name, (int)retval);
			/* In case of -ESRCH, task is not found on VE, but
			 * it is not a failure case */
			if (retval == -ESRCH) {
				PSEUDO_DEBUG("Task not found on VE");
			} else {
				PSEUDO_DEBUG("Mapping retval %d to errno %d",
						(int) retval, -EINVAL);
				retval = -EINVAL;
				goto hndl_return;
			}
		}

		/* Update the value in struct rusage obtained from VEOS*/
		if (retval != -ESRCH) {
			r.ru_utime = ve_r.ru_utime;
			r.ru_maxrss = ve_r.ru_maxrss;
			r.ru_nvcsw = ve_r.nvcsw;
			r.ru_nivcsw = ve_r.nivcsw;
		}
		/* In VE stime would be zero */
		r.ru_stime = (struct timeval){0,0};

		if (NULL != (void *)wait4_args[3]) {
			if (0 > ve_send_data(handle, wait4_args[3],
						sizeof(struct rusage), (uint64_t *)(&r))) {
				PSEUDO_ERROR("Sending data to VE memory failed");
				PSEUDO_DEBUG("%s failure: veos send data "
						"error, return value %d",
						syscall_name, (int)retval);
				retval = -EINVAL;
				goto hndl_return;
			}
		}
	}

	if (NULL != (void *)wait4_args[1]) {
		if (0 > ve_send_data(handle, wait4_args[1],
				sizeof(int), (uint64_t *)(&status))) {
			PSEUDO_ERROR("Sending data to VE memory failed");
			PSEUDO_DEBUG("%s failure: veos send data "
					"error, return value %d",
					syscall_name, (int)retval);
			retval = -EINVAL;
			goto hndl_return;
		}
	}

	retval = pid;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles gettimeofday() system call functionality for ve
 * @details
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 *
 * This function returned the timeval and timezone structure values after
 * successful execution. Currently using VH time for this purpose. Timezone
 * can be NULL as glibc and libc not support this.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call value to VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_gettimeofday(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timeval tval = {0};
	struct timezone tzone = {0};
	uint64_t args[2];

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("gettimeofday() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, &tval, &tzone);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall gettimeofday() failed %s",
				strerror(errno));
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}
	/* send the timeval values to VE */
	if (0 > ve_send_data(handle, args[0],
				sizeof(struct timeval), (uint64_t *)(&tval))) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	PSEUDO_DEBUG("Timeval returned values = tval.tv_sec = %ld "
			"tval.tv_usec = %ld",
			(long)tval.tv_sec, (long)tval.tv_usec);

	/* send the timezone values to VE.
	 * The use of the timezone structure is obsolete according to linux,
	 * so will always return garbage in libc and glibc.
	 * We can pass NULL here.
	 */

	if (0 != args[1]) {
		if (0 > ve_send_data(handle, args[1],
					sizeof(struct timezone),
					(uint64_t *)(&tzone))) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	PSEUDO_DEBUG("Timezone returned values = tzone.tz_minuteswest = %d "
			"tzone.tz_dsttime = %d",
			tzone.tz_minuteswest, tzone.tz_dsttime);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function get the rlimit based on resource recived.
 * It decides based on the resource to offload to VHOS or VEOS.
 *
 * int do_getrlimit(pid_t pid, struct ve_prlimit_info *prlimit_info,
 * struct rlimit *rlim)
 *
 * @return On success it will return 0 else -errno or -1.
 *
 * @internal
 * @author PSMG / Process management
 */
int do_getrlimit(pid_t pid, int resource,
		struct rlimit *rlim, veos_handle *handle)
{
	int retval = -1;

	PSEUDO_TRACE("Entering");

	switch (resource) {
	case RLIMIT_CPU:
	case RLIMIT_AS:
	case RLIMIT_CORE:
	case RLIMIT_DATA:
	case RLIMIT_SIGPENDING:
	case RLIMIT_RSS:
	case RLIMIT_STACK:
		/* interact with PSM to get the resource rlimit.
		*/
		retval = pseudo_psm_send_get_rlimit_req(handle->veos_sock_fd,
					resource, pid);
		if (retval < 0) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", retval, -EFAULT);
			retval = -EFAULT;
			PSEUDO_ERROR("getrlimit failure: "
					"veos request error");
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_get_rlimit_ack(handle->veos_sock_fd,
					rlim);
		if (retval < 0) {
			PSEUDO_ERROR("getrlimit failure: "
				"veos acknowledgement error, return value %d",
				(int)retval);
			goto hndl_return;
		}
		break;
	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_MEMLOCK:
	case RLIMIT_MSGQUEUE:
	case RLIMIT_NOFILE:
	case RLIMIT_NPROC:
	case RLIMIT_RTTIME:
		/* call VH system call */
		retval = syscall(SYS_getrlimit, resource, rlim);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall getrlimit() failed %s",
					strerror(errno));
			goto hndl_return;
		} else
			PSEUDO_DEBUG("syscall getrlimit() returned %d",
					(int)retval);
		break;
	case RLIMIT_NICE:
	case RLIMIT_RTPRIO:
		PSEUDO_ERROR("Resource not supported");
		retval = -EINVAL;
		goto hndl_return;
	default:
		PSEUDO_ERROR("Invalid resource provided");
		retval = -EINVAL;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
/*
 * @brief Handles getrlimit() system call functionality for ve.
 *
 * @details
 * int getrlimit(int resource, struct rlimit *rlim);
 *
 * This function fetches the arguments (int resource) from VE and then
 * offload to VEOS or VH OS based on resource received. Updated
 * buffer(struct rlimit *rlim) will be send back to VE memory.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, -errno or negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_getrlimit(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct rlimit rlim = {0};
	int resource = -1;
	uint64_t args[2];

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("getrlimit() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments, "
				"return value: %di, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	resource = (int)args[0];

	retval = do_getrlimit(syscall(SYS_gettid), resource, &rlim, handle);
	if (retval != 0)
		goto hndl_return;

	PSEUDO_DEBUG("rlim_cur: %ld rlim_max: %ld", rlim.rlim_cur,
			rlim.rlim_max);

	/* send the filled rlimit buf */
	if (0 > ve_send_data(handle, args[1],
				sizeof(struct rlimit), (uint64_t *)(&rlim))) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles getrusage() system call functionality for ve.
 * @details
 * int getrusage(int who, struct rusage *usage);
 *
 * This function fetches the arguments from VE and then
 * offload to VHOS to get the resource usage and some
 * VE specific resource usage will be provided by VEOS.
 * Then the populated struct rusage will be send back
 * to VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call value to VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_getrusage(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct rusage r = {{0}};
	struct ve_rusage ve_r = {{0}};
	uint64_t args[2];
	struct ve_rusage_info rusage_task = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("getrusage() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("getrusage() failure: return value: %d,"
				" mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	rusage_task.who = (int)args[0];
	rusage_task.pid = syscall(SYS_gettid);
	if (rusage_task.who != RUSAGE_SELF &&
			rusage_task.who != RUSAGE_CHILDREN &&
			rusage_task.who != RUSAGE_THREAD) {
		PSEUDO_ERROR("Invalid argument 'who' provided.");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, rusage_task.who, &r);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall getrusage() failed %s",
				strerror(errno));
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}

	/* Get the VE specific rusage from VEOS.
	*/
	retval = pseudo_psm_send_get_rusage_req(handle->veos_sock_fd,
			rusage_task);
	if (retval < 0) {
		PSEUDO_ERROR("getrusage() failure: veos request error");
		PSEUDO_DEBUG("getrusage() failure: veos request error, "
				"return value: %d, mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_get_rusage_ack(handle->veos_sock_fd,
			&ve_r);
	if (retval < 0) {
		PSEUDO_ERROR("getrusage() failure: "
				"veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: "
				"veos acknowledgement error, "
				"return value: %di, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	PSEUDO_DEBUG("Max RSS: %ld CPU time (%ld sec %ld microsec)",
			ve_r.ru_maxrss,
			ve_r.ru_utime.tv_sec,
			ve_r.ru_utime.tv_usec);

	/* Update the value in struct rusage obtained from
	 * VEOS.
	 */
	r.ru_utime = ve_r.ru_utime;
	r.ru_maxrss = ve_r.ru_maxrss;
	r.ru_nvcsw = ve_r.nvcsw;
	r.ru_nivcsw = ve_r.nivcsw;
	r.ru_minflt = 0;
	r.ru_majflt = 0;

	/* In VE stime of process will be zero */
	r.ru_stime = (struct timeval){0,0};

	/* send the filled rusage buffer */
	if (0 > ve_send_data(handle, args[1],
				sizeof(struct rusage), (uint64_t *)(&r))) {
		retval = -EFAULT;
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handle's the sysinfo() system call request that will returns
 * information of overall system statistics.
 *
 * int sysinfo(struct sysinfo *info);
 *
 * @param[in] syscall_num system call number
 * @param[in] syscall_name system call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative or -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sysinfo(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1] = {0};
	struct sysinfo vh_sysinfo = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (0 > retval) {
		PSEUDO_ERROR("sysinfo() failure: "
				"failed to fetch system call aguments,");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	retval = pseudo_psm_send_sysinfo_req(handle->veos_sock_fd);
	if (-1 == retval) {
		PSEUDO_ERROR("sysinfo() failure: veos request error");
		PSEUDO_DEBUG("%s failure: veos request error,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_sysinfo_ack(handle->veos_sock_fd, &vh_sysinfo);
	if (0 > retval) {
		PSEUDO_ERROR("sysinfo() failure: "
				"veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: "
				"veos acknowledgement error,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	retval = 0;
	if (0 > ve_send_data(handle, args[0],
				sizeof(struct sysinfo),
				(uint64_t *)&vh_sysinfo)) {
		retval = -EFAULT;
		goto hndl_return;
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}


ret_t ve_ptrace(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

/**
 * @brief Handles the capget system call functionality for VE.
 *
 * int capget(cap_user_header_t hdrp, cap_user_data_t datap);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call value to VE process
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_capget(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	cap_user_header_t cap_header = NULL;
	cap_user_data_t cap_data = NULL;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_DEBUG("capget() failure: "
				"failed to fetch system call aguments");
		PSEUDO_ERROR("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return2;
	}

	if (NULL != (void *)args[0]) {
		cap_header = (void *)malloc(sizeof(struct __user_cap_header_struct));
		if (NULL == cap_header) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to allocate memory for "
					"cap header structure");
			goto hndl_return;
		}
		if (0 > ve_recv_data(handle, args[0],
					(sizeof(struct __user_cap_header_struct)),
					(uint64_t *)cap_header)) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return2;
		}
	}

	if (NULL != (void *)args[1]) {
		cap_data = (void *)malloc(sizeof(struct __user_cap_data_struct));
		if (NULL == cap_data) {
			retval = -EFAULT;
			PSEUDO_ERROR("Failed to allocate memory for "
					"cap data structure");
			goto hndl_return1;
		}
	}

	retval = syscall(syscall_num, cap_header, cap_data);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall capget() failed %s",
				strerror(errno));
		goto hndl_return2;
	}
	if (NULL != (void *)args[1])
		if (0 > ve_send_data(handle, args[1],
					sizeof(struct __user_cap_data_struct),
					(uint64_t *)cap_data)) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return2;
		}
hndl_return2:
	if (cap_data)
		free(cap_data);
hndl_return1:
	if (cap_header)
		free(cap_header);
hndl_return:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}

/**
 * @brief handles the functionality of capset system call for VE.
 *
 * int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_capset(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	cap_user_header_t cap_header = NULL;
	cap_user_data_t cap_data = NULL;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	cap_header = (void *)malloc(sizeof(struct __user_cap_header_struct));
	if (NULL == cap_header) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for "
				"cap header structure");
		goto hndl_return;
	}

	cap_data = (void *)malloc(sizeof(struct __user_cap_data_struct));
	if (NULL == cap_data) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate memory for "
				"cap data structure");
		goto hndl_return1;
	}

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_ERROR("capset() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return2;
	}
	if (NULL != (void *)args[0]) {
		if (0 > ve_recv_data(handle, args[0],
					(sizeof(struct __user_cap_header_struct)),
					(uint64_t *)cap_header)) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return2;
		}
	}
	else {
		retval = -EFAULT;
		goto hndl_return2;
	}
	if (NULL != (void *)args[1])
		if (0 > ve_recv_data(handle, args[1],
					sizeof(struct __user_cap_data_struct),
					(uint64_t *)cap_data)) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return2;
		}

	retval = syscall(syscall_num, cap_header, cap_data);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall %s failed %s", syscall_name,
				strerror(errno));
		goto hndl_return2;
	}
hndl_return2:
	free(cap_data);
hndl_return1:
	free(cap_header);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the getpriority functionality for ve.
 *
 * int getpriority(int which, int who);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_getpriority(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("getpriority() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief handles the setpriority system call functionality for ve
 *
 * int setpriority(int which, int who, int prio);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_setpriority(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("setpriority() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}


/**
 * @brief Handles the functionality of sched_setparam system call.
 *
 * int sched_getparam(pid_t pid, const struct sched_param *param);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_getparam(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_getparam() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/*
 * brief handles the functionality of sched_setparam system call.
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_setparam(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_setparam() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief handle the functionality of sched_setschedular system call
 *
 * int sched_setscheduler(pid_t pid, int policy,
 *                                 const struct sched_param *param);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_setscheduler(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_setscheduler() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief handle the functionality of sched_getschedular system call.
 *
 * int sched_getscheduler(pid_t pid);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_getscheduler(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_getscheduler() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief Handles the sched_get_priority_max functionality for VE.
 *
 * int sched_get_priority_max(int policy);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_get_priority_max(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_get_priority_max()"
			" is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief Handle the sched_get_priority_min system call functionality for VE
 *
 * int sched_get_priority_min(int policy);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_get_priority_min(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("sched_get_priority_max()"
			" is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;
}

/**
 * @brief Hanldes the functionality of sched_rr_get_interval system call
 *
 * int sched_rr_get_interval(pid_t pid, struct timespec * tp);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to VE process.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_rr_get_interval(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	struct timespec tp;
	pid_t pid;
	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > retval) {
		PSEUDO_ERROR("sched_rr_get_interval() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);

		retval = -EFAULT;
		goto hndl_return;
	}

	pid = args[0];
	if (pid < 0) {
		retval = -EINVAL;
		goto hndl_return;
	} else if (pid == 0)
		pid = syscall(SYS_gettid);

	retval = pseudo_psm_send_get_inr_req(handle->veos_sock_fd, pid);
	if (-1 == retval) {
		PSEUDO_ERROR("sched_rr_get_interval() failure: veos request error");
		PSEUDO_DEBUG("%s failure: veos request error,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_get_inr_ack(handle->veos_sock_fd, &tp);
	if (0 > retval) {
		PSEUDO_ERROR("sched_rr_get_interval() failure: "
				"veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: "
				"veos acknowledgement error, return value %d",
				syscall_name, (int)retval);
		goto hndl_return;
	}
	retval = 0;
	if (0 > ve_send_data(handle, args[1],
				sizeof(struct timespec),
				(uint64_t *)&tp)) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
hndl_return:
	/* write return value */
	return retval;
}

/**
 * @brief Handles prctl() system call functionality for ve.
 *
 * int prctl(int option, unsigned long arg2, unsigned long arg3,
 *		unsigned long arg4, unsigned long arg5);
 *
 * In VE environment this system call will return ENOTSUP.
 *
 * This function fetches the arguments from VE and then offload
 * to VEOS or VH OS based on the first argument option for
 * operation on VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -ENOTSUP.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_prctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");

	PSEUDO_INFO("prctl() is called which is not supported");
	PSEUDO_TRACE("Exiting");
	return -ENOTSUP;

}

ret_t ve_arch_prctl(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

/**
 * @brief Handles functionality of setrlimit() system call.
 *
 * int do_setrlimit(pid_t pid, int resource, struct rlimit rlim)
 *
 * This function sets the rlimit of the VE process based on
 * the type of resource function will offload the system
 * call to VEOS or VHOS.
 *
 * q
 * @param[in] pid PID of VE process
 * @param[in] resource Resource to set
 * @param[in] rlim Value of new resource limit
 *
 * @return 0 on success, negative on failure
 *
 * @internal
 * @author PSMG / Process management
 */
int do_setrlimit(pid_t pid, int resource, struct rlimit rlim, veos_handle *handle)
{
	int retval = -1;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("rlim_cur: %ld rlim_max: %ld", rlim.rlim_cur,
			rlim.rlim_max);

	if (rlim.rlim_cur > rlim.rlim_max) {
		retval = -EINVAL;
		PSEUDO_ERROR("soft limit is greater than hard limit");
		goto hndl_return;
	}

	switch (resource) {
	case RLIMIT_CPU:
	case RLIMIT_AS:
	case RLIMIT_CORE:
	case RLIMIT_DATA:
	case RLIMIT_SIGPENDING:
	case RLIMIT_RSS:
	case RLIMIT_STACK:
		/* interact with PSM to set the resource rlimit.
		*/
		if (pseudo_psm_send_set_rlimit_req(handle->veos_sock_fd,
					resource, rlim, pid) < 0) {
			retval = -errno;
			PSEUDO_ERROR("setrlimit() failure: "
					"veos request error, return value %d",
					(int)retval);
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_set_rlimit_ack(handle->veos_sock_fd);
		/* wait for acknowledgment from PSM */
		if (retval < 0) {
			PSEUDO_ERROR("setrlimit() failure: "
					"veos acknowledgement error, "
					"return value %d",
					(int)retval);
			goto hndl_return;
		}
		PSEUDO_DEBUG("setrlimit ack returned %d",
				(int)retval);
		break;
	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_MEMLOCK:
	case RLIMIT_MSGQUEUE:
	case RLIMIT_NOFILE:
	case RLIMIT_NPROC:
	case RLIMIT_RTTIME:
		/* call VH system call */
		retval = syscall(SYS_setrlimit, resource, &rlim);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("syscall setrlimit() failed %s",
					strerror(errno));
			goto hndl_return;
		} else
			PSEUDO_DEBUG("syscall setrlimit() returned %d",
					(int)retval);
		break;
	case RLIMIT_NICE:
	case RLIMIT_RTPRIO:
		PSEUDO_ERROR("Resource %d not supported", resource);
		retval = -EINVAL;
		goto hndl_return;
	default:
		PSEUDO_ERROR("Invalid resource provided.");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}
/*
 *
 * @brief Handles setrlimit() system call functionality for ve.
 *
 * @details
 * int setrlimit(int resource, const struct rlimit *rlim);
 *
 * This function fetches the arguments (int resource), (struct rlimit *rlim)
 * from VE and then offload to VEOS or VH OS based on resource received.
 * Return value is shared with VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_setrlimit(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct rlimit rlim = {0};
	uint64_t args[2] = {0};
	int resource = -1;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);


	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("setrlimit() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments, "
				"return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	resource = (int)args[0];

	/* get the rlimit buf */
	if (0 > ve_recv_data(handle, args[1],
				sizeof(struct rlimit), (uint64_t *)(&rlim))) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = do_setrlimit(syscall(SYS_gettid), resource, rlim, handle);

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles acct() system call functionality for VE.
 *
 * int acct(const char *filename);
 *
 * This system call is offloaded to VEOS for enabling/disabling process accounting.
 *
 * @param[in] syscall_num syscall_num System Call number
 * @param[in] syscall_name syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_acct(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1] = {0};
	struct stat sb = {0};
	char *path_buff = NULL;
	char *real_path = NULL;
	uint32_t cap_data_pres = -1;
	struct __user_cap_header_struct cap_header_data = {0};
	struct __user_cap_data_struct cap_data_data = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (0 > retval) {
		PSEUDO_ERROR("acct() failure: "
				"failed to fetch system call aguments");

		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	if ((void *)args[0] != NULL) {
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			retval = -errno;
			PSEUDO_ERROR("failed to allocate memory: %s",
					strerror(errno));
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);
		/* receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0],
				(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			PSEUDO_ERROR("Failure in recieving string");
			PSEUDO_DEBUG("Failure in recieving string "
					"(%s) returned: %d, mapped value: %d",
					syscall_name, (int)retval, -EFAULT);
			if (retval == -2)
				retval = -ENAMETOOLONG;
			else
				retval = -EFAULT;
			goto hndl_return1;
		}
		/*
		 * checking does pseudo having a CAP_SYS_PACCT
		 * capability.
		 */
		cap_user_header_t cap_header = &cap_header_data;
		cap_user_data_t cap_data = &cap_data_data;
		cap_header->pid = syscall(SYS_gettid);;
		cap_header->version = _LINUX_CAPABILITY_VERSION;

		/* Get the capabilities */
		if (capget(cap_header, cap_data) < 0) {
			PSEUDO_ERROR("failed capget error");
			retval = -EPERM;
			goto hndl_return1;
		}
		cap_data_pres = 1<<CAP_SYS_PACCT;
		if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
			PSEUDO_ERROR("pid %d don't have"
					" CAP_SYS_PACCT capability.",
					cap_header->pid);
			retval = -EPERM;
			goto hndl_return1;
		}
		/* First get the realpath of the filename received */
		real_path = realpath(path_buff, NULL);
		if (NULL == real_path) {
			retval = -errno;
			PSEUDO_ERROR("Fail(%s) to get realpath of:%s",
					strerror(errno),
					path_buff);
			goto hndl_return1;
		}

		PSEUDO_DEBUG("Realpath of filename: %s", real_path);

		retval = stat(real_path, &sb);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("File stat fail: %s",
					strerror(errno));
			goto hndl_return2;
		}

		if (S_ISDIR(sb.st_mode)) {
			PSEUDO_ERROR("acct() failure: Is a directory");
			PSEUDO_DEBUG("retval: %d, mapped value: %d",
					-errno, -EISDIR);
			retval = -EISDIR;
			goto hndl_return2;
		}

		if (!S_ISREG(sb.st_mode)) {
			PSEUDO_ERROR("Not a regular file");
			PSEUDO_DEBUG("retval: %d, mapped value: %d",
					-errno, -EACCES);
			retval = -EACCES;
			goto hndl_return2;
		}
	}

	/* Send veos request to enable/diable the accounting */
	retval = pseudo_psm_send_acct_req(handle->veos_sock_fd,	real_path);
	if (0 > retval) {
		PSEUDO_ERROR("acct() failure: veos request error");
		PSEUDO_DEBUG("%s failure: veos request error, return value %d",
				syscall_name, (int)retval);
		goto hndl_return2;
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_acct_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("acct() failure: "
				"veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: "
				"veos acknowledgement error, return value %d",
				syscall_name, (int)retval);
		goto hndl_return2;
	}
	retval = 0;

hndl_return2:
	free(real_path);
hndl_return1:
	free(path_buff);
hndl_return:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}

/*
 * @brief Handles settimeofday() system call functionality for ve.
 * @details
 * int settimeofday(const struct timeval *tv, const struct timezone *tz);
 *
 * In VE environment this system call will return EPERM.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -EPERM
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_settimeofday(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -EPERM;
	PSEUDO_TRACE("Entering");
	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	PSEUDO_INFO("settimeofday() is called returning %ld",
			retval);

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sched_yield() system call for ve.
 *
 * details
 * int sched_yield(void);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_yield(int syscall_num, char *syscall_name, veos_handle *handle)
{
	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("sched_yield() is called");

	/* This function always returns success. "sched_yield" system call
	 * does not require any handling since BLOCK_REQ is already send
	 * to VEOS which schedules new task on core hence relinquishing
	 * CPU. If this task is the only task on core then this task will
	 * continue to schedule on core after UNBLOCK request is served.
	 * */
	PSEUDO_TRACE("Exiting");
	return 0;
}

/**
 * @brief Handles functionality of time() system call for ve.
 * @details
 * time_t time(time_t *t);
 *
 * This function invokes VH OS time() system call. In case first
 * argument from VE is not NULL, received buffer from VH OS is
 * copied back to VEMVA using VE driver interface.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to Ve process
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_time(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	time_t ve_t = -1;
	uint64_t args[1] = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (retval < 0) {
		PSEUDO_ERROR("time() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, &ve_t);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("time() failed %s",
				strerror(errno));
		goto hndl_return;
	} else
		PSEUDO_DEBUG("syscall %s returned %lu",
				syscall_name, retval);

	/* send the time value stored in memory pointed to by ve_t */
	if (NULL != (void *)args[0]) {
		if (0 > ve_send_data(handle, args[0],
					sizeof(time_t), (uint64_t *)(&ve_t))) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
		}
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Pseudo side futex handler.
 *
 *      This function implements the futex() system call functionality. This
 *      handler interacts with veos and stops all ve cores to achieve atomicity
 *      requirement (i.e. copy data atomically from VE side to VH side).
 *      Once data is copied, this handler again interacts with veos to start
 *      all VE cores. The actual waiting and waking functionality is achieved
 *      by using VH host system call. Currently FUTEX_WAKE and FUTEX_WAIT are
 *      supported.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle ve driver handle to communicate between pseudo process and
 *		ve driver.
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_futex(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1, ret = -1;
	uint64_t futex_args[6] = {0};
	struct timespec *ts = NULL;
	unsigned long val2 = 0;
	int cmd = -1;
	unsigned int temp1 = -1, temp2 = -1;
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* fetching the arguments using handle obtained */
	retval = vedl_get_syscall_args(handle->ve_handle, futex_args, 6);
	if (retval < 0) {
		PSEUDO_ERROR("futex() failure: Failed to fetch system call "
				"arguments");
		PSEUDO_DEBUG("Failed to fetch the system call arguments, "
				"return value %d, mapped value %d",
				(int)retval, -EINVAL);
		retval = -EINVAL;
		goto hndl_return;
	}

	PSEUDO_DEBUG("futex_args[0](uaddr): %lx", futex_args[0]);
	PSEUDO_DEBUG("futex_args[1](op): %lx", futex_args[1]);
	PSEUDO_DEBUG("futex_args[2](val): %lx", futex_args[2]);
	PSEUDO_DEBUG("futex_args[3](utime): %lx", futex_args[3]);
	PSEUDO_DEBUG("futex_args[4](uaddr2): %lx", futex_args[4]);
	PSEUDO_DEBUG("futex_args[5](val3): %lx", futex_args[5]);

	/* copy VE requested operation(WAIT/WAKE/...) and
	 * type(PRIVATE/SHARED/...) of command.
	 */
	cmd = futex_args[1] & FUTEX_CMD_MASK;

	PSEUDO_DEBUG("Requested cmd : %u", cmd);
	if (FUTEX_FD == cmd || FUTEX_WAKE_OP == cmd || FUTEX_LOCK_PI == cmd ||
			FUTEX_UNLOCK_PI == cmd || FUTEX_CMP_REQUEUE_PI == cmd ||
			FUTEX_WAIT_REQUEUE_PI == cmd ||
			FUTEX_TRYLOCK_PI == cmd) {
		PSEUDO_INFO("futex() failure: Operation not supported");
		retval = -ENOSYS;
		goto hndl_return;
	}

	if (NULL == (void *)futex_args[0]) {
		PSEUDO_ERROR("futex() failure: NULL address(uaddr) "
				"received");
		retval = -EFAULT;
		goto hndl_return;
	}

	if (0 != futex_args[3] && (FUTEX_WAIT == cmd ||
				FUTEX_WAIT_BITSET == cmd)) {

		/* copy timespec value */
		ts = (struct timespec *)malloc(sizeof(struct timespec));
		if (NULL == ts) {
			PSEUDO_ERROR("futex() failure: Failed to allocate "
					"memory for timespec argument");
			PSEUDO_DEBUG("Failed to allocate memory, return "
					"value %d, mapped value %d",
					errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}

		if ((ve_recv_data(handle, futex_args[3],
						sizeof(struct timespec),
						(uint64_t *)ts)) < 0) {
			PSEUDO_ERROR("futex() failure: Failed to retrieve data "
					"of timespec structure");
			PSEUDO_DEBUG("Failed to retrieve data, return value "
					"%d, mapped value %d", errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* Change VH memory permission into READ and WRITE */
	retval = mprotect((void *)(futex_args[0] & ADDR_MASK),
			getpagesize(), PROT_WRITE|PROT_READ);
	if (retval != 0) {
		PSEUDO_ERROR("futex() failure: Failed to set protection "
				"on uaddr");
		PSEUDO_DEBUG("Failed to protect the address, return value %d, "
				"mapped value %d", errno, -EACCES);
		retval = -EACCES;
		goto hndl_return1;
	}

	if (FUTEX_REQUEUE == cmd || FUTEX_CMP_REQUEUE == cmd) {
		val2 = (unsigned long)futex_args[3];
		if (NULL == (void *)futex_args[4]) {
			PSEUDO_ERROR("futex() failure: NULL address(uaddr2) "
					"received");
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* Change VH memory permission into READ and WRITE */
		retval = mprotect((void *)(futex_args[4] & ADDR_MASK),
				getpagesize(), PROT_WRITE|PROT_READ);
		if (retval != 0) {
			PSEUDO_ERROR("futex() failure: Failed to set protection"
					" on uaddr2");
			PSEUDO_DEBUG("Failed to protect the address, return "
					"value %d, mapped value %d",
					errno, -EACCES);
			retval = -EACCES;
			goto hndl_return1;
		}
	}

	/* Atomic Read Data from VE to VH */
	do {
		/* Copy VE DATA to VH Memory */
		if ((ve_recv_data(handle, futex_args[0], sizeof(unsigned int),
						(uint64_t *)&temp1)) < 0) {
			PSEUDO_ERROR("futex() failure: Failed to retrieve data"
					" from uaddr");
			PSEUDO_DEBUG("Failed to get the data, return value %d,"
					" mapped value %d", errno, -EACCES);
			retval = -EACCES;
			goto hndl_return1;
		}

		/* *(unsigned int *)futex_args[0] = temp1; */
		__atomic_store((volatile int *)(futex_args[0]), &temp1,
				__ATOMIC_SEQ_CST);
		if ((ve_recv_data(handle, futex_args[0], sizeof(unsigned int),
						(uint64_t *)&temp2)) < 0) {
			PSEUDO_ERROR("futex() failure: Failed to retrieve data"
					" from uaddr");
			PSEUDO_DEBUG("Failed to retrieve the data, return value %d,"
					" mapped value %d", errno, -EACCES);
			retval = -EACCES;
			goto hndl_return1;
		}
	} while (temp1 != temp2);

	PSEUDO_DEBUG("Futex data at uaddr: %x",	*(unsigned int *)futex_args[0]);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");

	if (sigfillset(&signal_mask)) {
		PSEUDO_ERROR("futex() failure: Failed to fill signal set");
		retval = -EINVAL;
		goto hndl_return1;
	}

	retval = pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
	if (retval != 0) {
		PSEUDO_ERROR("futex() failure: Failed to change the "
				"signal mask");
		PSEUDO_DEBUG("Failed to set the signal mask, return value %d,"
				" mapped value %d", (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* call VH system call */
	if (FUTEX_REQUEUE == cmd || FUTEX_CMP_REQUEUE == cmd) {
		retval = syscall(syscall_num, futex_args[0],
				futex_args[1], futex_args[2], val2,
				futex_args[4], futex_args[5]);
	} else {
		retval = syscall(syscall_num, futex_args[0],
				futex_args[1], futex_args[2], ts,
				futex_args[4], futex_args[5]);
	}

	/* Post-processing of syscall started, blocking signals */
	ret = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (ret != 0) {
		PSEUDO_DEBUG("Blocked signals for post-processing");
		PSEUDO_ERROR("futex() failure: Failed to block the "
				"signal mask");
		PSEUDO_DEBUG("Failed to set the signal mask, return value %d,"
				" mapped value %d", (int)ret, -EFAULT);
		retval = -EFAULT;
		goto hndl_return1;
	}

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("futex() failure: syscall failed %s",
				strerror(errno));
		if (-EINTR == retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		PSEUDO_DEBUG("syscall %s success with retval: %lu",
				syscall_name, retval);
	}
	PSEUDO_DEBUG("futex_returned %ld", syscall(SYS_gettid));
	PSEUDO_DEBUG("Blocked signals for post-processing");

hndl_return1:
	if (NULL != ts)
		free(ts);
hndl_return:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}

/**
 * @brief Handles sched_setaffinity() system call for ve.
 *
 * int sched_setaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
 *
 * This function set the CPU affinity of the VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_setaffinity(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	pid_t pid = -1;
	size_t cpusetsize = -1;
	cpu_set_t mask;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("sched_setaffinity() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (0 == args[0])
		pid = syscall(SYS_gettid);
	else
		pid = (pid_t)args[0];


	cpusetsize = (size_t)args[1];

	if (cpusetsize > sizeof(cpu_set_t))
		cpusetsize = sizeof(cpu_set_t);

	/* get the mask provided by VE program
	*/
	if (0 > ve_recv_data(handle, args[2],
				cpusetsize,
				(cpu_set_t *)(&mask))) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* interact with PSM to set the affinity of the VE process.
	*/
	retval = pseudo_psm_send_setaffinity_req(handle->veos_sock_fd, pid, mask);
	if (-1 == retval) {
		PSEUDO_ERROR("sched_setaffinity() failure: veos request error");
		PSEUDO_DEBUG("%s failure: veos request error, "
				"return value %d, mapped value: %d",
				syscall_name, (int)retval, -EINVAL);

		retval = -EINVAL;
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_setaffinity_ack(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("sched_setaffinity() failure: "
				"veos acknowledgement error, return value %d",
				(int)retval);
		goto hndl_return;
	}

	/* In Success set retval to "0" */
	retval = 0;
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sched_getaffinity() system call for ve.
 *
 * int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
 *
 * This function get the CPU affinity of the VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return cpu set size on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_sched_getaffinity(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3] = {0};
	pid_t pid = -1;
	size_t cpusetsize = -1;
	cpu_set_t mask;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("sched_getaffinity() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (0 == args[0])
		pid = syscall(SYS_gettid);
	else
		pid = (pid_t)args[0];

	cpusetsize = (size_t)args[1];

	if (cpusetsize > sizeof(cpu_set_t))
		cpusetsize = sizeof(cpu_set_t);

	if ((uint64_t *)args[2] == NULL) {
		retval = -EFAULT;
		goto hndl_return;
	}

	/* interact with PSM to get the affinity of the VE process.
	*/
	retval = pseudo_psm_send_getaffinity_req(handle->veos_sock_fd, pid, cpusetsize);
	if (-1 == retval) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		PSEUDO_ERROR("sched_getaffinity() failure: "
				"veos request error, return value %d",
				(int)retval);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_getaffinity_ack(handle->veos_sock_fd, &mask);
	if (retval < 0) {
		PSEUDO_ERROR("sched_getaffinity() failure: "
				"veos acknowledgement error, return value %d",
				(int)retval);
		goto hndl_return;
	}

	/* VE CPU affinity is only 64 bits */
	retval = ve_send_data(handle, args[2], cpusetsize, &mask);
	if (0 > retval) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* In Success set retval to cpusetsize */
	retval = cpusetsize;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function will take care of the set_tid_address system call functionality.
 *
 * long set_tid_address(int *tidptr);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_set_tid_address(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t addr_rcvd = 0;
	ret_t retval = -1;
	int tid;
	int index = -1;

	tid = syscall(SYS_gettid);

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, &addr_rcvd, 1);
	if (retval < 0) {
		PSEUDO_ERROR("set_tid_address() failure: Failed to fetch "
				"system call aguments");
		PSEUDO_DEBUG("Failed to fetch system call arguments, return "
				"value %d", (int)retval);
		fprintf(stderr, "Failed to set pointer to thread ID\n");
		/* FATAL ERROR: Abort pseudo process */
		pseudo_abort();
	} else {
		/* We have two strategies to get the tid address on which the
		 * futex needs to be invoked and to find out whether the
		 * threads are detached or joinable.
		 *
		 * a) Maintain the tid address at veos side; which means
		 * doing an IPC call everytime we need tid address and detach
		 * state information.
		 *
		 * b) Maintain it in global tid array; which merely need 1
		 * member to be added to the array.
		 *
		 * We have chosen the second strategy.
		 *
		 * NOTE: we do not need to update the tid address in
		 * ve_task_struct maintained by veos as we are maintaining
		 * the same in global tid array. At this point of time, doing
		 * an IPC to veos seems useless and can be removed if do
		 * not find its any other use in future.
		 */

		/* Acquire mutex lock */
		retval = pthread_mutex_lock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("set_tid_address() failure: Failed to "
					"acquire mutex lock");
			PSEUDO_DEBUG("Failed to acquire lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		PSEUDO_DEBUG("tid_counter : %d, tid : %d",
				tid_counter, tid);
		PSEUDO_DEBUG("addr_rcvd : %lx",
				(unsigned long)addr_rcvd);

		index = find_global_array_index(tid);
		if (index == VEOS_MAX_VE_THREADS) {
			PSEUDO_ERROR("TID %d not found", tid);
			fprintf(stderr, "Inconsistent thread details\n");
			pseudo_abort();
		}

		PSEUDO_DEBUG("index : %d", index);
		global_tid_info[index].ctid_address = addr_rcvd;

		retval = pthread_mutex_unlock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("set_tid_address() failure: Failed to "
					"release mutex lock");
			PSEUDO_DEBUG("Failed to release lock, return "
					"value %d", -((int)retval));
			fprintf(stderr, "Internal resource usage error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		/* interact with PSM to set the clear_child_tid for the VE
		 * process
		 */
		retval = pseudo_psm_send_set_tidaddr_req(handle->veos_sock_fd,
				addr_rcvd);
		if (retval < 0) {
			PSEUDO_ERROR("set_tid_address() failure: veos "
					"request error");
			PSEUDO_DEBUG("Failed to send request to veos return "
					"value %d", (int)retval);
			fprintf(stderr, "Failed to set pointer to thread ID\n");
			/* FATAL ERROR: Abort pseudo process */
			pseudo_abort();
		}


		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_set_tidaddr_ack(handle->veos_sock_fd);
		if (retval < 0) {
			PSEUDO_ERROR("set_tid_address() failure: veos "
					"acknowledgement error");
			PSEUDO_DEBUG("Failed to get acknowledgement from veos, "
					"return value %d",
					(int)retval);
			fprintf(stderr, "Failed to set pointer to thread ID\n");
			/* FATAL ERROR: Abort pseudo process */
			pseudo_abort();
		}
	}
	retval = syscall(SYS_gettid);
	PSEUDO_TRACE("Exiting");
	return retval;
}

/*
 * @brief Handles clock_settime() system call functionality for ve.
 *
 * int clock_settime(clockid_t clk_id, struct timespec *tp);
 *
 * In VE environment this system call will return EPERM
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -EPERM
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_clock_settime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -EPERM;

	PSEUDO_TRACE("Entering");
	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	PSEUDO_INFO("clock_settime() is called returning EPERM");

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles clock_gettime() system call functionality for ve.
 * @details
 * int clock_gettime(clockid_t clk_id, struct timespec *tp);
 *
 * This function fetches the arguments (clockid_t clk_id) from VE and then
 * invokes the VH OS clock_gettime() system call. Returned values can be
 * fetched at VE side using struct timespec which is copied back by VH to
 * VE using VE driver interface.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_clock_gettime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	pid_t pid = -1;
	struct timespec time_buf = {0};
	struct ve_clockinfo clockinfo = {0};
	uint64_t args[2] = {0};
	clockid_t clockid = 0;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("clock_gettime() failure: "
				"failed to fetch system call arguments");
		PSEUDO_DEBUG("%s failure: "
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	clockid = (clockid_t)args[0];
	pid = (pid_t)~((clockid) >> 3);

	PSEUDO_DEBUG("Clock Id: %d, PID: %d", clockid, pid);

	if (pid < -1 || pid == 1) {
		retval = -EINVAL;
		goto hndl_return;
	} else if (pid > 1) {
		clockinfo.pid = pid;
		clockinfo.clockid = clockid;
		clockinfo.pid_flag = 1;
		clockinfo.current = syscall(186);

		retval = pseudo_psm_send_clk_cputime_req(handle->veos_sock_fd,
					clockinfo);
		if (retval < 0) {
			PSEUDO_ERROR("clock_gettime() failure: "
					"veos request error");
			PSEUDO_DEBUG("%s failure: veos request error,"
					" return value: %d, mapped value: %d",
					syscall_name, (int)retval, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}

		retval = pseudo_psm_recv_clk_cputime_ack(handle->veos_sock_fd,
					&time_buf);
		if (retval < 0) {
			PSEUDO_ERROR("clock_gettime() failure: "
					"veos acknowledgment error");
			if (retval == -ESRCH || retval == -EINVAL) {
				PSEUDO_DEBUG("return value: %d, mapped "
						"value: %d", (int)retval, -EINVAL);
				retval = -EINVAL;
			} else {
				PSEUDO_DEBUG("return value: %d, mapped "
						"value: %d", (int)retval, -EFAULT);
				retval = -EFAULT;
			}
			goto hndl_return;
		}
		retval = 0;
	} else {
		switch (clockid & CLOCKFD_MASK) {
			case CLOCK_REALTIME:
			case CLOCK_REALTIME_COARSE:
			case CLOCK_MONOTONIC:
			case CLOCK_MONOTONIC_COARSE:
			case CLOCK_MONOTONIC_RAW:
			case CLOCK_BOOTTIME:
				/* call VH system call */
				retval = syscall(syscall_num, args[0], &time_buf);
				if (-1 == retval) {
					retval = -errno;
					PSEUDO_ERROR("clock_gettime() failed %s",
							strerror(errno));
					goto hndl_return;
				} else
					PSEUDO_DEBUG("clock_gettime() returned %d",
							(int)retval);
				PSEUDO_DEBUG("timespec.tv_sec = %ld",
						time_buf.tv_sec);
				break;
			default:
				PSEUDO_ERROR("Invalid clock ID.");
				retval = -EINVAL;
				goto hndl_return;

			case CLOCK_PROCESS_CPUTIME_ID:
			case CLOCK_THREAD_CPUTIME_ID:
				/* interact with PSM to get the process cputime.
				*/
				clockinfo.pid = syscall(186);
				clockinfo.current = syscall(186);
				clockinfo.clockid = clockid;
				clockinfo.pid_flag = 0;

				if (pseudo_psm_send_clk_cputime_req(handle->veos_sock_fd,
							clockinfo) < 0) {
					PSEUDO_ERROR("clock_gettime() failure: veos request error");
					PSEUDO_DEBUG("%s failure: veos request error,"
							" return value: %d, mapped value: %d",
							syscall_name, (int)retval, -EFAULT);
					retval = -EFAULT;
					goto hndl_return;
				}

				if (pseudo_psm_recv_clk_cputime_ack(handle->veos_sock_fd,
							&time_buf) < 0) {

					PSEUDO_ERROR("clock_gettime() failure: "
							"veos acknowledgment error");
					if (retval == -ESRCH || retval == -EINVAL) {
						PSEUDO_DEBUG("return value: %d, mapped "
								"value: %d", (int)retval, -EINVAL);
						retval = -EINVAL;
					} else {
						PSEUDO_DEBUG("return value: %d, mapped "
								"value: %d", (int)retval, -EFAULT);
						retval = -EFAULT;
					}
					goto hndl_return;
				}
				retval = 0;
				break;
		}
	}
	/* send the filled timespec buf */
	if (0 > ve_send_data(handle, args[1],
				sizeof(struct timespec), (uint64_t *)(&time_buf))) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
	}
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles clock_getres() system call functionality for ve.
 * @details
 * int clock_getres(clockid_t clk_id, struct timespec *res);
 *
 * This function fetches the arguments (clockid_t clk_id) from VE and then
 * invokes the VH OS clock_getres() system call. Returned values can be
 * fetched at VE side using struct timespec which is copied back by VH to
 * VE using VE driver interface.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to VE process
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_clock_getres(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct timespec time_buf = {0};
	uint64_t args[2] = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("clock_getres() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0], &time_buf);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("syscall clock_getres() failed %s",
				strerror(errno));
		goto hndl_return;
	} else
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);

	PSEUDO_DEBUG("timespec.tv_sec = %ld timespec.tv_nsec %ld",
			time_buf.tv_sec, time_buf.tv_nsec);

	if (NULL != (void*)args[1]) {
		/* send the filled timespec buf */
		if (0 > ve_send_data(handle, args[1],
					sizeof(struct timespec), (uint64_t *)(&time_buf))) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
			retval = -EFAULT;
		}
	}

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief This function handles exit_group() system call functionality for ve.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to VE process.
 *
 * @internal
 * @author PSMG / MP-MT
 */
ret_t ve_exit_group(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args = 0;
	int retval = -1;
	int trace = (SIGTRAP | (PTRACE_EVENT_EXIT<<8));

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, &args, 1);
	if (retval < 0) {
		PSEUDO_ERROR("exit_group() failure: Failed to fetch system call "
				"arguments");
		PSEUDO_DEBUG("Failed to fetch arguments, return value %d",
				(int)retval);
	}

	/* Check whether PTRACE_O_TRACEEXIT is enabled */
	if (IS_VE_TRACED(handle->ve_handle) &&
			(VE_PTRACE_OPTION(handle->ve_handle) &
			 PTRACE_O_TRACEEXIT)) {
		PSEUDO_DEBUG("PID: %ld is traced and "
				"PTRACE_O_TRACEEXIT event"
				" is Enabled",
				syscall(SYS_gettid));

		ptrace_event_notify(handle, (args & BYTE_MASK)<<8);
		send_sig_to_itself(SIGTRAP, trace, NULL);
	}

	/* Send request to PSM for cleanup of VE process */
	retval = pseudo_psm_send_delete_ve_proc_req(handle->veos_sock_fd,
			EXIT_PROCESS, (args & BYTE_MASK) << 8, -1);
	if (retval < 0) {
		PSEUDO_ERROR("exit_group: veos request error");
		PSEUDO_DEBUG("Failed to send request to veos, return value %d",
				(int)retval);
	} else {
		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_delete_ack(handle->veos_sock_fd);
		if (retval < 0) {
			PSEUDO_ERROR("exit_group() failure:"
					" veos acknowledgement error");
			PSEUDO_DEBUG("Failed to get acknowledgement from veos,"
				" return value %d", (int)retval);
		} else {
			PSEUDO_DEBUG("return value received : %d",
					retval);
		}
	}

	if (-1 == ve_sync_vhva(handle)) {
		PSEUDO_ERROR("Failed to Sync Host Virtual addresses");
	}

	/* Invoking VH exit_group() syscall */
	retval = syscall(syscall_num, args);

	return retval;
}

/**
 * @brief This function handles waitid system call functionality for VE
 * @details
 * int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options,
 *			struct rusage *rusage);
 *
 * This function fetches the arguments from VEHVA/VEMVA and then invokes the
 * VH OS waitid() system call.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, -errno on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_waitid(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t waitid_args[5];
	ret_t retval = -1;
	ret_t pid = -1;
	siginfo_t ve_infop;
	struct rusage r = {{0}};
	struct ve_rusage ve_r = {{0}};
	struct ve_rusage_info rusage_task = {0};
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);
	retval = vedl_get_syscall_args(handle->ve_handle, waitid_args, 5);

	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for wait4 system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EINVAL);
		retval = -EINVAL;
		return retval;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");

	sigemptyset(&signal_mask);
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* zeroing out the field to distinguish the case of
	 * WNOHANG with the case without WNOHANG*/
	ve_infop.si_pid = 0;

	pid = retval = syscall(syscall_num, waitid_args[0], waitid_args[1],
			&ve_infop, waitid_args[3], &r);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		PSEUDO_ERROR("waitid failed: %s", strerror(errno));
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return;
	} else
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	PSEUDO_DEBUG("Blocked signals for post-processing");


	/* Get the VE specific rusage from VEOS.
	*/
	rusage_task.pid = ve_infop.si_pid;
	rusage_task.who = RUSAGE_SELF;

	/* Set child eligible to be reaped if:
	 * 1. value in si_pid field > 0
	 * 2. child has exited anyhow
	 * 3. WNOWAIT is not specified */
	if (rusage_task.pid > 0 && (ve_infop.si_code == CLD_EXITED
				|| ve_infop.si_code == CLD_KILLED
				|| ve_infop.si_code == CLD_DUMPED)
				&& !((waitid_args[3] & WNOWAIT) == WNOWAIT)) {
		PSEUDO_DEBUG("Child %d to be reaped now", rusage_task.pid);
		rusage_task.cleanup = true;
	}

	if (rusage_task.pid > 0) {
		retval = pseudo_psm_send_get_rusage_req(handle->veos_sock_fd,
				rusage_task);
		if (retval < 0) {
			PSEUDO_ERROR("Request for getting resource usage failed");
			PSEUDO_DEBUG("%s failure: rusage request returned %d",
					syscall_name, (int) retval);
			PSEUDO_DEBUG("Mapping retval %d to errno %d",
					(int) retval, -EINVAL);
			retval = -EINVAL;
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_get_rusage_ack(handle->veos_sock_fd,
				&ve_r);
		if (retval < 0) {
			PSEUDO_ERROR("Getting resource usage acknowledgement failed");
			PSEUDO_DEBUG("%s failure: rusage acknowledgement returned %d",
					syscall_name, (int)retval);
			/* In case of -ESRCH, task is not found on VE, but
			 * it is not a failure case */
			if (retval == -ESRCH) {
				PSEUDO_DEBUG("Task not found on VE");
			} else {
				PSEUDO_DEBUG("Mapping retval %d to errno %d",
						(int) retval, -EINVAL);
				retval = -EINVAL;
				goto hndl_return;
			}
		}
		/* Update the value in struct rusage obtained from
		 * VEOS.
		 */
		if (retval != -ESRCH) {
			r.ru_utime = ve_r.ru_utime;
			r.ru_maxrss = ve_r.ru_maxrss;
		}
		/* In VE stime is zero */
		r.ru_stime = (struct timeval){0,0};

		if (0 != (void *)waitid_args[4]) {
			if (0 > ve_send_data(handle, waitid_args[4],
						sizeof(struct rusage),
						(uint64_t *)(&r))) {
				PSEUDO_ERROR("Sending data to VE memory failed");
				PSEUDO_DEBUG("%s failure: veos send data "
						"error, return value %d",
						syscall_name, (int)retval);
				retval = -EINVAL;
				goto hndl_return;
			}
		}
	}

	if (NULL != (void *)waitid_args[2]) {
		if (0 > ve_send_data(handle, waitid_args[2],
					sizeof(siginfo_t),
					(uint64_t *)(&ve_infop))) {
			PSEUDO_ERROR("Sending data to VE memory failed");
			PSEUDO_DEBUG("%s failure: veos send data "
					"error, return value %d",
					syscall_name, (int)retval);
			retval = -EINVAL;
			goto hndl_return;
		}
	}
	retval = pid;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/*
 * @brief Handles functionality of prlimit64() system call for ve.
 *
 * @details
 * void prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
 *                     struct rlimit *old_limit);
 *
 * This function fetches the arguments from VE. If the new_limit argument is
 * a not NULL, then the rlimit structure to which it points is used to set
 * new values. If the old_limit argument is a not NULL, then a successful call
 * to prlimit64() places the previous soft and hard  limits  for  resource  in
 * the  rlimit  structure  pointed  to  by old_limit.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -errno on failure and 0 on success
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_prlimit64(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4] = {0};
	pid_t pid = -1;
	int resource = -1;
	struct rlimit new_limit = {0}, old_limit = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("prlimit64() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments, "
				"return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[0] == 0)
		pid = syscall(SYS_gettid);
	else
		pid = args[0];

	resource = args[1];

	/* checking for old_limit NULL or not */
	if (args[3] != 0) {
		retval = do_getrlimit(pid, resource, &old_limit, handle);
		if (0 != retval)
			goto hndl_return;

		/* set the obtained limit */
		if (0 > ve_send_data(handle, args[3],
					sizeof(struct rlimit),
					(uint64_t *)(&old_limit))) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d"
					, -errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* checking for new_limit NULL or not */
	if (args[2] != 0) {
		/* get the new limit */
		if (0 > ve_recv_data(handle, args[2],
					sizeof(struct rlimit),
					(uint64_t *)(&new_limit))) {
			PSEUDO_DEBUG("retval: %d, mapped value: %d",
					-errno, -EFAULT);
			retval = -EFAULT;
			goto hndl_return;
		}
		retval = do_setrlimit(pid, resource, new_limit, handle);
		if (0 != retval)
			goto hndl_return;
	}

	retval = 0;
hndl_return:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}

/*
 * @brief Handles clock_adjtime() system call functionality for ve.
 *
 * int clock_adjtime (clockid_t clock_id, struct timex * tx);
 *
 * In VE environment this system call will return EPERM.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return -EPERM
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_clock_adjtime(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -EPERM;
	PSEUDO_TRACE("Entering");

	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	PSEUDO_INFO("clock_adjtime() is called returning EPERM");

	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief handles the functionality of getcpu system call for VE
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @internal
 * @author PSMG / Process management
 */
ret_t ve_getcpu(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	unsigned int cpu = -1;
	unsigned int node = -1;
	struct ve_cpu_info cpu_info = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);
	/* get arguments
	 * third argument (tcache) is unused since Linux 2.6.24 */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("getcpu() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Send veos request to get cpu id and node id */
	retval = pseudo_psm_send_getcpu_req(handle->veos_sock_fd);
	if (-1 == retval) {
		PSEUDO_ERROR("getcpu() failure: veos request error");
		PSEUDO_DEBUG("%s failure: veos request error, "
				"return value: %d mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_getcpu_ack(handle->veos_sock_fd, &cpu_info);
	if (0 > retval) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		PSEUDO_ERROR("getcpu() failure: "
				"veos acknowledgement error, return value %d",
				(int)retval);
		goto hndl_return;
	} else {
		cpu = cpu_info.cpu;
		node = cpu_info.node;
		PSEUDO_DEBUG("cpu is %d node is %d", cpu, node);
		retval = 0;
		if (args[0] != 0)
			if (0 > ve_send_data(handle, args[0],
						sizeof(unsigned int),
						(unsigned int *)(&cpu))) {
				PSEUDO_DEBUG("retval: %d, mapped value: %d",
						-errno, -EFAULT);
				retval = -EFAULT;
				goto hndl_return;
			}
		if (args[1] != 0)
			if (0 > ve_send_data(handle, args[1],
						sizeof(unsigned int),
						(unsigned int *)(&node))) {
				PSEUDO_DEBUG("retval: %d, mapped value: %d",
						-errno, -EFAULT);
				retval = -EFAULT;
				goto hndl_return;
			}
	}
hndl_return:
	PSEUDO_TRACE("Exiting");
	/* write return value */
	return retval;
}
