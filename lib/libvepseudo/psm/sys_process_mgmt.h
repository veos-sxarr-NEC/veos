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
 * @file sys_process_mgmt.h
 * @brief Header file for "sys_process_mgmt.c" file.
 *
 * @internal
 * @author PSMG / Process management
 */
#ifndef __SYS_PROCESS_MGMT_H
#define __SYS_PROCESS_MGMT_H

#define DO_FORK_INIT 0
#define DO_FORK_SUCCESS 1
#define DO_FORK_FAIL -1

#define EXECVE_MAX_ARGS 513
#define EXECVE_MAX_ENVP 513

#define RESUME_PARENT_BIT 32768
#define CHILD_STATUS_BIT 16384
#define ERRNO_MASK 255

#define VE_EXEC_PATH getenv("VE_EXEC_PATH")
#define VE_EXECVE_ARGS 6

#define ADDR_MASK 0XFFFFFFFFFFFFF000

#define BYTE_MASK 0xff

#define VESHM_DIR_SIZE 32

/**
 * @brief Structure used for synchronization between parent pseudo process and
 * child pseudo thread.
 */
struct tid_info {
	int tid_val;		/*!< Thread ID of the newly created thread. */
	volatile short int flag;/*!<
				 * flag used to notify the status of child
				 * pseudo thread to parent pseudo process.
				 */
	pthread_mutex_t mutex;	/*!<
				 * Mutex lock for synchronization between
				 * parent pseudo process and child pseudo
				 * thread.
				 */
	pthread_cond_t cond;	/*!<
				 * Condition variable for synchronization
				 * between parent pseudo process and child
				 * pseudo thread.
				 */
	uint64_t ctid_address;	/*!<
				 * Child thread ID address (VEMVA) used for
				 * waking up a waiting thread.
				 */
	uint64_t guard_ptr;	/*!<
				 * Guard Pointer of the thread Stack
				 */
        unsigned long sas_ss_sp;	/*!<
				 * signal alternate stack address
				 */
        size_t sas_ss_size;	/*!<
				 * signal alternate stack size
				 */
	int vefd;		/*!<
				 * VE driver fd
				 */
	veos_handle *veos_hndl; /*!<
				 * VEOS handle
				 */
};

extern struct tid_info global_tid_info[VEOS_MAX_VE_THREADS];

extern pthread_mutex_t tid_counter_mutex;

extern pthread_rwlock_t sync_fork_dma;
extern void init_rwlock_to_sync_dma_fork();

extern int tid_counter;
/**
 * @brief Structure to be passed an an argument in thread (pseudo process thread)
 * start function.
 */
struct thread_func_args {
	veos_handle *parent_handle;	/*!<
					 * vedl handle of parent
					 * pseudo process.
					 */
	int tid_val_index;	/*!<
				 * Index of struct tid_info array assigned
				 * to thread.
				 */
	uint64_t flags;		/*!< Clone flags. */
	uint64_t stack_ptr;	/*!< Stack pointer for new thread. */
	uint64_t ctid;		/*!<
				 * VEMVA address used for CLONE_CHILD_CLEARTID
				 * clone flag.
				 */
	uint64_t ptid;		/*!<
				 * VEMVA address used for CLONE_PARENT_SETTID
				 * clone flag.
				 */
	pid_t parent_pid;	/*!< Thread ID of parent pseudo process. */
	sigset_t sigmask_var;	/*!< VE process signal mask. */
	void (*handler)(veos_handle *, void *); /*!< Exception handler loop function */
	void *extra_arg; /*!< Arguments for exception handler.*/
};

ret_t ve_do_fork(uint64_t *, char *, veos_handle *);
ret_t ve__do_clone(int, char *, veos_handle *,
		void (*)(veos_handle *, void *), void *);

int ve_premature_child_exit(pid_t);
int find_global_array_index(int tid);
#endif
