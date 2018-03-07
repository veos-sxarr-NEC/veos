/**
 * @file syscall_psmg.h
 * @brief Header file for "syscall_psmg.c" file.
 */
#ifndef SYSCALL_PSMG_H
#define SYSCALL_PSMG_H

#define DO_FORK_INIT 0
#define DO_FORK_SUCCESS 1
#define DO_FORK_FAIL -1

#define EXECVE_MAX_ARGS 256
#define EXECVE_MAX_ENVP 256

#define RESUME_PARENT 1
#define CHILD_STATUS 2

/**
 * @brief Structure used for synchronization between parent pseudo process and
 * child pseudo thread.
 */
struct tid_info {
	int tid_val;		/*!< Thread ID of the newly created thread. */
	short int flag;		/*!<
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
};

/**
 * @brief Structure to be passed an an argument in thread (pseudo process thread)
 * start function.
 */
struct thread_func_args {
	vedl_handle *parent_handle;	/*!<
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
};

void ve_do_fork(int, char *, vedl_handle *);
#endif
