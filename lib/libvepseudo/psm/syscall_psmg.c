/**
 * @file syscall.c
 * @brief Handles system calls encountered by VE process.
 *
 * This file contains system call handlers for the various system calls
 * encountered by VE process.
 */

#include <sys/types.h>
#include <sys/shm.h>
#include "syscall_common.h"
#include "pseudo_psmg_ipc.h"
#include "mem_xfer.h"
#include "syscall_psmg.h"
#include "syscall_amm.h"
#include "ve_futex.h"
#include "ve_signal.h"
#include "pseudo_veos_soc.h"
#include "velayout.h"

struct tid_info global_tid_info[VEOS_MAX_VE_THREADS];
extern char *sock_name;
int tid_counter = -1;
pthread_mutex_t tid_counter_mutex = PTHREAD_MUTEX_INITIALIZER;

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
 */
static int find_global_array_index(int tid)
{
	int index;

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
 */
static void clear_global_array_entry(int tid)
{
	int index;

	for (index = 0; index < VEOS_MAX_VE_THREADS; index++) {
		if (global_tid_info[index].tid_val == tid) {
			global_tid_info[index].tid_val = 0;
			global_tid_info[index].mutex =
				(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
			global_tid_info[index].cond =
				(pthread_cond_t)PTHREAD_COND_INITIALIZER;
			global_tid_info[index].flag = 0;
			global_tid_info[index].ctid_address = 0;

			/* Decrement global tid_counter */
			tid_counter--;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Clear entries for Thread index :"
					" %d & Available Threads are : %d\n",
					index, tid_counter);
			break;
		}
	}

	return;
}

/**
 * @brief deletion of task for VE side
 *
 * void process_thread_cleanup(vedl_handle *handle)
 *
 * @param handle[in] Handle for VE driver interface
 */
void process_thread_cleanup(vedl_handle *handle, int exit_code)
{
	int index_local, veos_sock_fd;
	pid_t tid = syscall(SYS_gettid);
	uint64_t ctid_status = 0;
	uint64_t tid_addr = (uint64_t)NULL;
	ret_t retval = -1;

	/*Syncing file backed data*/
	sync_at_exit(handle);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"tid_counter : %d, tid : %d\n", tid_counter,
			tid);

	index_local = find_global_array_index(tid);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"index_local : %d, ctid_address : %lx\n",
			index_local,
			(unsigned long)global_tid_info[index_local].ctid_address);

	tid_addr = (uint64_t)global_tid_info[index_local].ctid_address;

	/* clean up of the corresponding entry in the global tid array */
	clear_global_array_entry(tid);

	/* send FUTEX_WAKE on clear_child_tid address.*/
	if (tid_addr) {
		ve_send_data(handle, tid_addr, sizeof(uint64_t),
				(uint64_t *)(&ctid_status));
		/* Change VH memory permission into READ and WRITE */
		retval = mprotect((void *)(tid_addr & 0XFFFFFFFFFFFFF000),
				0X1000, PROT_WRITE|PROT_READ);
		if (retval != 0)
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Cannot access memory\n");
		else {
			memset((uint64_t *)tid_addr, 0, sizeof(uint64_t));
			syscall(SYS_futex, tid_addr, FUTEX_WAKE, 1,
					NULL, NULL, NULL);
		}
	}

	/* obtain socket for communication with PSM */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto thread_cleanup2;
	}

	/* Send request to PSM for cleanup of VE process */
	retval = pseudo_psm_send_delete_ve_proc_req(veos_sock_fd, 0, exit_code);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM cleanup fails\n");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"PSM cleanup fails\n");
		goto thread_cleanup2;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_delete_ack(veos_sock_fd);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_delete_ack() failed\n");
		goto thread_cleanup2;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"retval received : %ld\n", retval);
		goto thread_cleanup1;
	}
	close(veos_sock_fd);

thread_cleanup2:
	;
	/*
	   vedl_unassign_task_from_core(handle, syscall(SYS_gettid));
	   vedl_delete_ve_process(handle, syscall(SYS_gettid));
	   */

	/* TODO : Zombie process handling is not done yet at veos side */

thread_cleanup1:
	if (1 == retval) {
		/* for the following:
		 * 1. process
		 * 2. non-Zombie main thread
		 * 3. last thread whose main thread is in Zombie state
		 */
		vedl_close_ve(handle);
	} else if (2 == retval) {
		/* In case of Zombie thread, we are just freeing the handle
		 * and assuming that the corresponding FDs will get closed
		 * by kernel itself.
		 */
		vedl_release_ve(handle);
	} else {
		/* for threads other than main thread */
#ifdef __AUSIM_ENV
		vedl_close_ve(handle);
#else
		vedl_release_ve(handle);
#endif
	}

	return;
}

/**
 * @brief This function is invoked when VE process is exited.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 *
 */
void ve_exit(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args;
	ret_t retval = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);


	/* get arguments */
	retval = vedl_get_syscall_args(handle, &args, 1);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
		return;
	}

	process_thread_cleanup(handle, args);

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
 */
static void thread_dummy_func(void *thread_args)
{
	vedl_handle *child_handle;
	ret_t retval = -1;
	struct thread_func_args *thread_dummy_func_args =
		(struct thread_func_args *)thread_args;
	vedl_handle *parent_handle = thread_dummy_func_args->parent_handle;
	int index = thread_dummy_func_args->tid_val_index;
	int veos_sock_fd;
	struct pseudo_ve_clone_info ve_clone_info;
	struct clone_response clone_response_rcvd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"thread_dummy_func is called\n");

	/* update global_tid_info containing tid(s) */
	/* invoking gettid() system call to obtain pid */
	global_tid_info[index].tid_val = syscall(SYS_gettid);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"index: %d, global_tid_info[index].tid_val: %d\n",
			index, global_tid_info[index].tid_val);

	/* prepare structure to be sent to PSM */
	ve_clone_info.child_pid = global_tid_info[index].tid_val;
	ve_clone_info.flags = thread_dummy_func_args->flags;
	ve_clone_info.stack_ptr = thread_dummy_func_args->stack_ptr;
	ve_clone_info.ptid = thread_dummy_func_args->ptid;
	ve_clone_info.ctid = thread_dummy_func_args->ctid;
	ve_proc_sigmask = thread_dummy_func_args->sigmask_var;

	/* obtain socket for communication with PSM */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed.\n");
		goto hndl_return;
	}

	/* get a new handle for child thread */
	child_handle = vedl_request_new_handle(parent_handle);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"child_handle : %p\n", (void *)child_handle);
	if ((vedl_handle *)-1 == child_handle) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"child_handle for %d not obtained\n",
				global_tid_info[index].tid_val);
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* request PSM to perform cloning for VE side */
	retval = pseudo_psm_send_clone_req(veos_sock_fd, ve_clone_info,
			thread_dummy_func_args->parent_pid);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_clone_req failed."
				" Returned %d\n", (int)retval);
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_clone_ack(veos_sock_fd, &clone_response_rcvd);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_clone_ack failed."
				" Returned %ld\n", retval);
		close(veos_sock_fd);
		goto hndl_return;
	}

	close(veos_sock_fd);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"CLONE_RESPONSE core_id: %d node_id: %d\n",
			clone_response_rcvd.core_id,
			clone_response_rcvd.node_id);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "Offset: %d\n",
			clone_response_rcvd.offset);

	/* obtain socket for communication with PSM */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed.\n");
		goto hndl_return;
	}

	/* set the offset of VH Child corresponding to VE Child thread */
	vedl_set_syscall_area_offset(child_handle, clone_response_rcvd.offset);

	/* intimate PSM to schedule the newly created VE child thread */
	if (pseudo_psm_send_schedule_req(veos_sock_fd) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sending request to PSM "
				"for scheduling failed\n");
		close(veos_sock_fd);
		goto delete_ve_task_struct;
	}

	/* wait for the acknowledgement from PSM */
	if (pseudo_psm_recv_schedule_ack(veos_sock_fd) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"schedule acknowledgment "
				"from PSM not received\n");
		close(veos_sock_fd);
		goto delete_ve_task_struct;
	}

	close(veos_sock_fd);

	/* resume the functionality of parent VH process */
	/* attain mutex lock */
	retval = pthread_mutex_lock(&(global_tid_info[index].mutex));
	if (retval != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pthread_mutex_lock failed.");
		goto delete_ve_task_struct;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"index : %d, RESUME PARENT : %d\n",
			index, global_tid_info[index].flag & RESUME_PARENT);

	global_tid_info[index].flag |= RESUME_PARENT;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"index : %d, RESUME PARENT : %d\n",
			index, global_tid_info[index].flag & RESUME_PARENT);

	retval = pthread_cond_signal(&(global_tid_info[index].cond));
	if (retval != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pthread_cond_signal failed.");
	}

	/* release mutex lock */
	if (0 != pthread_mutex_unlock(&(global_tid_info[index].mutex))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pthread_mutex_unlock failed.");
		goto delete_ve_task_struct;
	}

	if (retval == 0) {
		sigprocmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		pse_exception_handler(child_handle);
	}

delete_ve_task_struct:
	global_tid_info[index].ctid_address = 0;
	process_thread_cleanup(child_handle, -1);

hndl_return:
	global_tid_info[index].flag |= CHILD_STATUS;
	global_tid_info[index].flag |= RESUME_PARENT;
	/* TODO: Action to be taken on pthread_cond_signal() failure */
	pthread_cond_signal(&(global_tid_info[index].cond));
	return;
}

/**
 * @brief Pseudo side clone handler.
 *
 *	This function implements the clone() system call functionality.
 *	ve_clone() interacts with the veos to create the new thread.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle ve driver handle to communicate between pseudo process and
 *		ve driver.
 */
void ve_clone(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	pthread_attr_t thread_attr;
	pthread_t new_thread;
	uint64_t clone_args[5];
	unsigned detach_flags , clone_flags;
	int index_local = -1;
	struct thread_func_args thread_dummy_func_args;

	detach_flags = clone_flags = CLONE_VM | CLONE_FS |
		CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
		CLONE_SYSVSEM | CLONE_SETTLS |
		CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID |
		CLONE_DETACHED;

	detach_flags -= CLONE_CHILD_CLEARTID;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* fetching the arguments using handle obtained*/
	retval = vedl_get_syscall_args(handle, clone_args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed."
				" (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"clone_args[0] : %lu\n", clone_args[0]);

	if ((clone_flags == clone_args[0]) || (detach_flags == clone_args[0])) {
		/* initialize attributes for new thread to be created */
		retval = pthread_attr_init(&thread_attr);
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_attr_init failed."
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -ENOMEM;
			goto hndl_return;
		}

		/* set detached attribute */
		retval = pthread_attr_setdetachstate(&thread_attr,
				PTHREAD_CREATE_DETACHED);
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_attr_setdetachstate failed."
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -EINVAL;
			goto hndl_return;
		}

		/* updating the tid_counter starts here */

		/* attain mutex lock */
		retval = pthread_mutex_lock(&tid_counter_mutex);
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_mutex_lock failed."
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -retval;
			goto hndl_return;
		}

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"tid_counter: %d, index_local: %d\n",
				tid_counter, index_local);

		index_local = find_global_array_index(0);
		if (index_local == VEOS_MAX_VE_THREADS) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"MAX(%d) threads created for VE process"
					". Cannot create more threads\n",
					VEOS_MAX_VE_THREADS);
			retval = pthread_mutex_unlock(&tid_counter_mutex);
			if (retval != 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"pthread_mutex_unlock failed."
						" (%s) returned %d\n",
						syscall_name, (int)retval);
				retval = -retval;
				goto hndl_return;
			}
			retval = -EAGAIN;
			goto hndl_return;
		}
		tid_counter++; /* Update tid_counter */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Creating new thread no. %d\n", tid_counter);

		global_tid_info[index_local].flag = 0;
		global_tid_info[index_local].mutex =
			(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		global_tid_info[index_local].cond =
			(pthread_cond_t)PTHREAD_COND_INITIALIZER;

		/* fill up the structure to be passed in the thread function */
		thread_dummy_func_args.parent_handle = handle;
		thread_dummy_func_args.tid_val_index = index_local;

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"index_local : %d\n", index_local);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"global_tid_info[index_local].tid_val: %d\n",
				global_tid_info[index_local].tid_val);

		thread_dummy_func_args.flags = clone_args[0];
		thread_dummy_func_args.stack_ptr = clone_args[1];
		thread_dummy_func_args.ptid = clone_args[2];
		global_tid_info[index_local].ctid_address =
			thread_dummy_func_args.ctid = clone_args[3];
		/* invoking gettid() system call to obtain pid */
		thread_dummy_func_args.parent_pid = syscall(SYS_gettid);
		thread_dummy_func_args.sigmask_var = ve_proc_sigmask;

		if (detach_flags == clone_args[0])
			global_tid_info[index_local].ctid_address = 0;

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"thread_dummy_func_args.flags : %lu\n",
				thread_dummy_func_args.flags);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"thread_dummy_func_args.stack_ptr : %lx\n",
				thread_dummy_func_args.stack_ptr);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"thread_dummy_func_args.ctid : %lx\n",
				thread_dummy_func_args.ctid);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"thread_dummy_func_args.parent_pid : %lu\n",
				(long int)thread_dummy_func_args.parent_pid);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"tid_counter : %d, index_local: %d\n",
				tid_counter, index_local);

		/* release mutex lock */
		retval = pthread_mutex_unlock(&tid_counter_mutex);
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_mutex_unlock failed."
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -retval;
			goto hndl_return;
		}

		/* tid_counter updation ends here */

		/* invoke pthread_create */
		retval = pthread_create(&new_thread, &thread_attr,
				(void *)&thread_dummy_func,
				(void *)&thread_dummy_func_args);

		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_create failed. "
					"(%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -retval;
			goto hndl_return;
		}

		/* wait till the child is done with its initialisation for VE
		 * side thread to be created.
		 */
		/* attain mutex lock */
		retval = pthread_mutex_lock(&(global_tid_info[index_local].
					mutex));
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_mutex_lock failed. "
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -retval;
			goto cancel_vh_thread;
		}

		while (0 == (global_tid_info[index_local].flag &
					RESUME_PARENT)) {
			retval = pthread_cond_wait(
					&(global_tid_info[index_local].
						cond),
					&(global_tid_info[index_local].
						mutex));
			if (retval != 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"pthread_cond_wait failed. "
						"(%s) returned %d\n",
						syscall_name, (int)retval);
				retval = -EFAULT;
				goto cancel_vh_thread;
			}
		}

		/* release mutex lock */
		retval = pthread_mutex_unlock(&(global_tid_info[index_local].
					mutex));
		if (retval != 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pthread_mutex_unlock failed."
					" (%s) returned %d\n", syscall_name,
					(int)retval);
			retval = -retval;
			goto cancel_vh_thread;
		}

		if (0 == (global_tid_info[index_local].flag & CHILD_STATUS)) {
			if (clone_args[0] & CLONE_PARENT_SETTID) {
				/* send the child tid to VE process */
				retval = ve_send_data(handle, clone_args[2],
						sizeof(pid_t), (uint64_t *)
						(&(global_tid_info[index_local]).
						 tid_val));
				if (retval < 0) {
					VE_LOG(CAT_PSEUDO_CORE,
							LOG4C_PRIORITY_ERROR,
							"ve_send_data failed. "
							"(%s) returned %d\n",
							syscall_name,
							(int)retval);
					retval = -EFAULT;
					goto cancel_vh_thread;
				}
			}

			retval = global_tid_info[index_local].tid_val;
			goto hndl_return;
		}
		retval = -EFAULT;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_WARN,
				"clone flags are not same as those of pthread_create flags\n");
		retval = -ENOTSUP;
		goto hndl_return;
	}

cancel_vh_thread:
	if (0 != pthread_cancel(new_thread)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pthread_cancel failed. (%s)\n",
				syscall_name);
		retval = -EFAULT;
	}

	/* clean up of the corresponding entry in the global tid array */
	clear_global_array_entry(global_tid_info[index_local].tid_val);

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles VE process creation once fork() and vfork() are offloaded on
 * VH.
 *
 * @param[in] clone_flags Clone flags differentiating between fork() and vfork()
 * @param[in] syscall_name System call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_do_fork(int clone_flags, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	pid_t pid;
	int veos_sock_fd;
	volatile int *shared_var = NULL;
	struct pseudo_ve_clone_info ve_fork_info;
	int offset;
	int shmid = 0;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	pthread_mutex_lock(&vemva_header.vhos_mmap_lock);
	shared_var = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pthread_mutex_unlock(&vemva_header.vhos_mmap_lock);
	*shared_var = 0;

	pid =  fork();
	if (0 < pid) {
		/* In Parent VH Context */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Child PID = %d Parent PID = %ld\n",
				pid, syscall(SYS_gettid));

		do {} while (DO_FORK_INIT == *shared_var);

		if (DO_FORK_SUCCESS != *shared_var) {
			kill(pid, SIGKILL);
			retval = -1;
		} else {
			retval = pid;
		}

	} else if (0 == pid) {
		/* In Child VH Context */
		pid = syscall(SYS_gettid);

		if (clone_flags & CLONE_VFORK) {
			/* Get new VEDL handle for vforked() child*/
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Requesting new handle "
					"for vforked child\n");
			offset = vedl_get_syscall_area_offset(handle);
			handle = vedl_request_new_handle(handle);
			if (handle == (void *)-1)
				goto hndl_fail3;

			/* Set the offset of VH Child */
			vedl_set_syscall_area_offset(handle, offset);
		} else {
#ifdef __PCIDEV_ENV
			shmdt(handle->lshm_addr);
#endif
			/* Closing parent VE process handler */
			vedl_close_ve(handle);

			/* Get new VEDL handle for forked child VH process */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Requesting new handle "
					"for forked child\n");
			handle = vedl_open_ve(sock_name, -1);
			if (handle == (void *)-1)
				goto hndl_fail3;

			/* Set offset to zero just in case */
			vedl_set_syscall_area_offset(handle, 0);
		}

		if (!(clone_flags & CLONE_VFORK)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Initialising lshm area for child\n");
			shmid = init_lhm_shm_area(handle);
			if (shmid < 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"init_lhm_shm_area failed.\n");
				retval = -1;
				goto hndl_fail1;
			}
		}

		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_fail2;
		}
		/* prepare structure to be sent to PSM */
		ve_fork_info.child_pid = pid;
		ve_fork_info.flags = clone_flags;
		ve_fork_info.stack_ptr = 0;
		ve_fork_info.ptid = 0;
		ve_fork_info.ctid = 0;
		ve_fork_info.shm_lhm_addr =
			(uint64_t)vedl_get_shm_lhm_addr(handle);
		ve_fork_info.shmid = shmid;

		/* Send veos request to create child VE process */
		retval = pseudo_psm_send_fork_req(syscall_name,
				ve_fork_info,
				veos_sock_fd);

		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send fork info to PSM\n");
			goto hndl_fail2;
		} else {
			/* Waiting for ACK from PSM */
			retval = pseudo_psm_recv_fork_ack(veos_sock_fd);
			if (-1 == retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"FORK_ACK not received\n");
				goto hndl_fail1;
			}
			retval = 0;
		}
		close(veos_sock_fd);

		/* Send veos request to schedule the newly
		 * created child VE process on VE core
		 * */
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_fail1;
		}
		retval = pseudo_psm_send_schedule_req(veos_sock_fd);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to send schedule request "
					"to PSM\n");
			goto hndl_fail1;
		} else {
			/* Waiting for ACK from PSM */
			retval = pseudo_psm_recv_schedule_ack(veos_sock_fd);
			if (-1 == retval) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"SCHEDULE_ACK not received\n");
				goto hndl_fail1;
			}
		}
		retval = 0;
		close(veos_sock_fd);
		*shared_var = DO_FORK_SUCCESS;

		/* Handle return of the fork/vfork system call
		 * Call exception handler with new handle
		 * TODO: To decide whether handle should be a
		 * global or be passed by reference
		 * */
		return_system_call(retval);
		pse_exception_handler(handle);
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"VH fork() failed for PID %ld\n",
				syscall(SYS_gettid));
		retval = -1;
	}

	/* write return value */
	return_system_call(retval);
	return;

hndl_fail1:
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
	} else {
		retval = pseudo_psm_send_delete_ve_proc_req(veos_sock_fd, 0, -1);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ERR: PSM cleanup failed\n");
			goto hndl_fail2;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_delete_ack(veos_sock_fd);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_delete_ack failed\n");
			close(veos_sock_fd);
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
					"retval received : %ld\n", retval);
		}
	}

hndl_fail2:
	vedl_close_ve(handle);

hndl_fail3:
	*shared_var = DO_FORK_FAIL;
	return;
}

/**
 * @brief Handles vfork() functionality for veos
 *
 * pid_t vfork(void);
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_vfork(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	int clone_flags;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	clone_flags = CLONE_VM|CLONE_VFORK;
	ve_do_fork(clone_flags, syscall_name, handle);

	return;
}

/**
 * @brief Handles fork() functionality for veos
 *
 * pid_t fork(void);
 *
 * @param syscall_num System call number
 * @param syscall_name System call name
 * @param handle Handle for VE driver interface
 */
void ve_fork(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	int clone_flags;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	clone_flags = 0;
	ve_do_fork(clone_flags, syscall_name, handle);

	return;
}

/**
 *
 * @brief Handles execve functionality for VE process.
 *
 * int execve(const char *filename, char *const argv[],
 *			char *const envp[]);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 *
 */
void ve_execve(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *exe_name;
	uint64_t args[3];
	/* To fetch VE pointers */
	char *execve_arg[EXECVE_MAX_ARGS] = {NULL};
	char *execve_envp[EXECVE_MAX_ENVP] = {NULL};
	/* To store VH pointers */
	char *execve_vh_arg[EXECVE_MAX_ARGS] = {NULL};
	char *execve_vh_envp[EXECVE_MAX_ENVP] = {NULL};
	int cntr = 0;
	int veos_sock_fd;

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
		goto hndl_fail;
	}

	/* allocate memory for storing VE binary name */
	exe_name = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == exe_name) {
		retval = -errno;
		goto hndl_fail;
	}
	memset(exe_name, '\0', PATH_MAX);

	/* receive contents of 1st argument(filename) */
	retval = ve_recv_string(handle, args[0], (char *)exe_name, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_recv_string failed with %d\n",
				(int)retval);
		retval = -EFAULT;
		goto hndl_fail1;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"execve() %s\n", exe_name);

	/* Receive arguments from VE memory */
	if (-1 == ve_recv_data(handle, args[1],
				EXECVE_MAX_ARGS *
				sizeof(char *), (void *)execve_arg)) {
		retval = -EFAULT;
		goto hndl_fail1;
	}
	for (cntr = 0; cntr < EXECVE_MAX_ARGS; cntr++) {
		if (0 == execve_arg[cntr])
			break;
		execve_vh_arg[cntr] = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == execve_vh_arg[cntr]) {
			retval = -errno;
			goto hndl_fail2;
		}
		memset(execve_vh_arg[cntr], '\0', PATH_MAX);

		/* receive contents of VE  arguments */
		retval = ve_recv_string(handle, (uint64_t)execve_arg[cntr],
				execve_vh_arg[cntr], PATH_MAX);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_recv_string failed %d\n",
					(int)retval);
			retval = -EFAULT;
			goto hndl_fail2;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				" VE ARGUMNET LIST\n");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ARG%d -> %s\n",
				cntr, execve_vh_arg[cntr]);
	}

	/* Receive environment from VE memory */
	if (-1 == ve_recv_data(handle, args[2],
				EXECVE_MAX_ENVP, (void *)execve_envp)) {
		retval = -EFAULT;
		goto hndl_fail2;
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

		/* receive contents of VE  arguments */
		retval = ve_recv_string(handle, (uint64_t)execve_envp[cntr],
				(char *)execve_vh_envp[cntr], PATH_MAX);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_recv_string failed %d\n",
					(int)retval);
			retval = -EFAULT;
			goto hndl_fail2;
		}
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				" VE ENVIRONMENT LIST\n");
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "ENV[%d] -> %s\n",
				cntr, execve_vh_envp[cntr]);
	}

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -errno;
		goto hndl_fail2;
	}

	/* start VE program and wait for exception */
	/* Send request to PSM for cleanup of VE process */
	retval = pseudo_psm_send_delete_ve_proc_req(veos_sock_fd, 2, -1);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"AuroraOS cleanup fails\n");
		retval = -errno;
		goto hndl_fail2;
	}
	retval = pseudo_psm_recv_delete_ack(veos_sock_fd);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_delete_ack Failed\n");
		retval = -EFAULT;
		goto hndl_fail;
	}

	close(veos_sock_fd);
	retval = vedl_close_ve(handle);
	if (retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_close_ve failed.\n");
	retval = execve(execve_vh_arg[0], execve_vh_arg, execve_vh_envp);
	if (-1 == retval) {
		/* TODO:
		 * In case of failure temporary workaround.
		 * Functionality will be added in loader to support this
		 * failure.
		 */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"execve failed %s\n", strerror(errno));
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		pseudo_psm_send_delete_ve_proc_req(veos_sock_fd, 0, -1);
		pseudo_psm_recv_delete_ack(veos_sock_fd);
		kill(getpid(), SIGKILL);
		return;
	}

hndl_fail2:
	/* Release all the buffers */
	cntr = 0;
	while (NULL != execve_vh_arg[cntr])
		free(execve_vh_arg[cntr++]);
	cntr = 0;
	while (NULL != execve_vh_arg[cntr])
		free(execve_vh_envp[cntr++]);
hndl_fail1:
	free(exe_name);
hndl_fail:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_wait4(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t wait4_args[4];
	ret_t retval = -1;
	int status;
	struct rusage r;
	struct ve_rusage ve_r;
	int veos_sock_fd;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	retval = vedl_get_syscall_args(handle, wait4_args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;

		/* write return value */
		return_system_call(retval);
		return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, wait4_args[0], &status,
			wait4_args[2], &r);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* Get the VE specific rusage from VEOS.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	if (pseudo_psm_send_get_rusage_req(veos_sock_fd,
				RUSAGE_CHILDREN) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_get_rusage_req failed.");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	if (pseudo_psm_recv_get_rusage_ack(veos_sock_fd,
				&ve_r) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_get_rusage_ack failed.");
		retval = -ECHILD;
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);

	/* Update the value in struct rusage obtained from
	 * VEOS.
	 */
	r.ru_stime = ve_r.ru_stime;
	r.ru_maxrss = ve_r.ru_maxrss;

	if (NULL != (void *)wait4_args[1]) {
		if (-1 == ve_send_data(handle, wait4_args[1],
					sizeof(int),
					(uint64_t *)(&status))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (NULL != (void *)wait4_args[3]) {
		if (-1 == ve_send_data(handle, wait4_args[3],
					sizeof(struct rusage),
					(uint64_t *)(&r))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}
hndl_return:
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_gettimeofday(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct timeval tval;
	struct timezone tzone;
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, &tval, &tzone);
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

	/* send the timeval values to VE */
	if (-1 == ve_send_data(handle, args[0],
				sizeof(struct timeval), (uint64_t *)(&tval))) {
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Timeval returned values = tval.tv_sec = %ld\n"
			"tval.tv_usec = %ld\n",
			(long)tval.tv_sec, (long)tval.tv_usec);

	/* send the timezone values to VE.
	 * The use of the timezone structure is obsolete according to linux,
	 * so will always return garbage in libc and glibc.
	 * We can pass NULL here.
	 */

	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct timezone),
				(uint64_t *)(&tzone))) {
		retval = -EFAULT;
		goto hndl_return;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Timezone returned values = tzone.tz_minuteswest = %d\n"
			"tzone.tz_dsttime = %d\n",
			tzone.tz_minuteswest, tzone.tz_dsttime);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}


/**
 * @brief This function get the rlimit based on resource recived.
 * It decides based on the resource to offload to VHOS or VEOS.
 *
 * int do_getrlimit(pid_t pid, int resource, struct rlimit *rlim)
 *
 * @return On success it will return 0 else -errno or -1.
 */
int do_getrlimit(pid_t pid, int resource, struct rlimit *rlim)
{
	int retval = -1;
	int veos_sock_fd;

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
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		if (pseudo_psm_send_get_rlimit_req(veos_sock_fd,
					resource, pid) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_get_rlimit_req "
					"failed.");
			retval = -errno;
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		if (pseudo_psm_recv_get_rlimit_ack(veos_sock_fd,
					rlim) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_get_rlimit_ack "
					"failed.");
			retval = -ESRCH;
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_MEMLOCK:
	case RLIMIT_MSGQUEUE:
	case RLIMIT_NICE:
	case RLIMIT_NOFILE:
	case RLIMIT_NPROC:
	case RLIMIT_RTPRIO:
	case RLIMIT_RTTIME:
		/* call VH system call */
		retval = syscall(SYS_getrlimit, resource, rlim);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall getrlimit failed %s\n",
					strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall getrlimit returned %d\n",
					(int)retval);
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid resource provided.\n");
		retval = -EINVAL;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_getrlimit(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct rlimit rlim;
	uint64_t args[2];
	int resource;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	resource = (int)args[0];

	retval = do_getrlimit(syscall(SYS_gettid), resource, &rlim);
	if (retval != 0)
		goto hndl_return;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"rlim_cur: %ld rlim_max: %ld\n", rlim.rlim_cur,
			rlim.rlim_max);

	/* send the filled rlimit buf */
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct rlimit), (uint64_t *)(&rlim))) {
		retval = -EFAULT;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_getrusage(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct rusage r;
	struct ve_rusage ve_r;
	uint64_t args[2];
	int veos_sock_fd;
	int who;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	who = (int)args[0];

	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
			who != RUSAGE_THREAD) {
		retval = -EINVAL;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid argument 'who' provided.\n");
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, who, &r);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}

	/* Get the VE specific rusage from VEOS.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	if (pseudo_psm_send_get_rusage_req(veos_sock_fd, who) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_get_rusage_req failed.");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	if (pseudo_psm_recv_get_rusage_ack(veos_sock_fd,
				&ve_r) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_get_rusage_ack failed.");
		retval = -EFAULT;
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"Max RSS: %ld CPU time (%ld sec %ld microsec)\n",
			ve_r.ru_maxrss,
			ve_r.ru_stime.tv_sec,
			ve_r.ru_stime.tv_usec);

	/* Update the value in struct rusage obtained from
	 * VEOS.
	 */
	r.ru_stime = ve_r.ru_stime;
	r.ru_maxrss = ve_r.ru_maxrss;

	/* send the filled rusage buffer */
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct rusage), (uint64_t *)(&r))) {
		retval = -EFAULT;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handle's the sysinfo() system call request that will returns
 * information of overall system statistics.
 *
 * int sysinfo(struct sysinfo *info);
 *
 * @param[in] syscall_num system call number
 * @param[in] syscall_name system call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sysinfo(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1];
	int veos_sock_fd;
	struct sysinfo vh_sysinfo;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"socket creation failed\n");
		retval = -EFAULT;
		goto hndl_return;
	}
	retval = pseudo_psm_send_sysinfo_req(veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"failed to send sysinfo request to PSM\n");
		retval = -EFAULT;
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_sysinfo_ack(veos_sock_fd, &vh_sysinfo);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"GET SYSINFO ACK not received\n");
		retval = -EFAULT;
		close(veos_sock_fd);
		goto hndl_return;
	}
	retval = 0;
	close(veos_sock_fd);
	if (-1 == ve_send_data(handle, args[0],
				sizeof(struct sysinfo),
				(uint64_t *)&vh_sysinfo)) {
		retval = -EFAULT;
		goto hndl_return;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}


void ve_ptrace(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles the capget system call functionality for VE.
 *
 * int capget(cap_user_header_t hdrp, cap_user_data_t datap);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_capget(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	cap_user_header_t cap_header;
	cap_user_data_t cap_data;

	cap_header = (void *)malloc(sizeof(struct __user_cap_header_struct));
	if (NULL == cap_header) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed for %s : %s\n",
				syscall_name, strerror(errno));
		retval = -errno;
		goto hndl_return;
	}

	cap_data = (void *)malloc(sizeof(struct __user_cap_data_struct));
	if (NULL == cap_data) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed for %s : %s\n",
				syscall_name, strerror(errno));
		retval = -errno;
		goto hndl_return1;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	if (NULL != (void *)args[0]) {
		if (-1 == ve_recv_data(handle, args[0],
					(sizeof(struct __user_cap_header_struct)),
					(uint64_t *)cap_header)) {
			retval = -EFAULT;
			goto hndl_return2;
		}
	}
	retval = syscall(syscall_num, cap_header, cap_data);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return2;
	}
	if (NULL != (void *)args[1])
		if (-1 == ve_send_data(handle, args[1],
					sizeof(struct __user_cap_data_struct),
					(uint64_t *)cap_data)) {
			retval = -EFAULT;
			goto hndl_return2;
		}
hndl_return2:
	free(cap_data);
hndl_return1:
	free(cap_header);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief handles the functionality of capset system call for VE.
 *
 * int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 *
 */
void ve_capset(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	cap_user_header_t cap_header;
	cap_user_data_t cap_data;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	cap_header = (void *)malloc(sizeof(struct __user_cap_header_struct));
	if (NULL == cap_header) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed for %s : %s\n",
				syscall_name, strerror(errno));
		retval = -errno;
		goto hndl_return;
	}
	cap_data = (void *)malloc(sizeof(struct __user_cap_data_struct));
	if (NULL == cap_data) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed for %s : %s\n",
				syscall_name, strerror(errno));
		retval = -errno;
		goto hndl_return1;
	}

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}
	if (NULL != (void *)args[0]) {
		if (-1 == ve_recv_data(handle, args[0],
					(sizeof(struct __user_cap_header_struct)),
					(uint64_t *)cap_header)) {
			retval = -EFAULT;
			goto hndl_return2;
		}
	}
	if (NULL != (void *)args[1])
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(struct __user_cap_data_struct),
					(uint64_t *)cap_data)) {
			retval = -EFAULT;
			goto hndl_return2;
		}

	retval = syscall(syscall_num, cap_header, cap_data);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return2;
	}
hndl_return2:
	free(cap_data);
hndl_return1:
	free(cap_header);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles the getpriority functionality for ve.
 *
 * int getpriority(int which, int who);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_getpriority(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	int veos_sock_fd;
	int which;
	pid_t pid;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	which = args[0];
	pid = args[1];

	switch (which) {
	case PRIO_PROCESS:
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (0 > veos_sock_fd) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		/* Send veos request to get priority */
		retval = pseudo_psm_send_getpriority_req(veos_sock_fd,
				pid);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send getpriority req "
					"to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_getpriority_ack(veos_sock_fd);
		if (-1 == retval) {
			retval = -ESRCH;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"GET PRIO ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	case PRIO_PGRP:
	case PRIO_USER:
		ve_generic_offload(syscall_num, syscall_name, handle);
		return;
	default:
		retval = -EINVAL;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy\n");
		break;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief handles the setpriority system call functionality for ve
 *
 * int setpriority(int which, int who, int prio);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_setpriority(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	int veos_sock_fd;
	int which;
	struct ve_prio_info prio_info;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	which = args[0];
	switch (which) {
	case PRIO_PROCESS:
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (0 > veos_sock_fd) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		/* Send request to veos for setpriority */
		prio_info.pid = args[1];
		prio_info.prio = args[2];
		if (prio_info.prio < -20)
			prio_info.prio = -20;
		if (prio_info.prio > 19)
			prio_info.prio = 19;

		retval = pseudo_psm_send_setpriority_req(veos_sock_fd,
				&prio_info);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send setpriority req "
					"to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_setpriority_ack(veos_sock_fd);
		if (-1 == retval) {
			retval = -ESRCH;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"GET PRIO ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		retval = 0;
		close(veos_sock_fd);
		break;
	case PRIO_PGRP:
	case PRIO_USER:
		ve_generic_offload(syscall_num, syscall_name, handle);
		return;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy\n");
		retval = -EINVAL;
		break;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}


/**
 * @brief Handles the functionality of sched_setparam system call.
 *
 * int sched_getparam(pid_t pid, const struct sched_param *param);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_getparam(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	int veos_sock_fd;
	struct sched_param vh_sched_param;
	struct ve_sched_info sched_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	sched_info.pid = args[0];
	if (sched_info.pid < 0) {
		retval = -EINVAL;
		goto hndl_return;
	}

	/* if kernel having a permission to access struct sched_param
	 * then only we offload the system call to veos else it will
	 * return EPERM
	 */

	retval = syscall(syscall_num, sched_info.pid, &vh_sched_param);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return;
	} else {
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}

		retval = pseudo_psm_send_sched_getparam_req(veos_sock_fd,
				&sched_info);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send getparam "
					"info to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_sched_getparam_ack(veos_sock_fd);
		if (-1 == retval) {
			retval = -ESRCH;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"GET PARAM ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}

		vh_sched_param.sched_priority = retval;
		retval = 0;
		close(veos_sock_fd);
	}
	if (NULL != (void *)args[1])
		if (-1 == ve_send_data(handle, args[1],
					sizeof(struct sched_param),
					(uint64_t *)&vh_sched_param)) {
			retval = -EFAULT;
			goto hndl_return;
		}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/*
 * brief handles the functionality of sched_setparam system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_setparam(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	pid_t pid;
	int veos_sock_fd;
	struct sched_param vh_sched_param;
	struct ve_sched_info sched_info;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Receive environment for sched_setparam from VE */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					(sizeof(struct sched_param)),
					(uint64_t *)(&vh_sched_param))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	pid = args[0];
	if (pid < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid PID %d\n", pid);
		retval = -EINVAL;
		goto hndl_return;
	}


	/* if kernel having a permission to access struct sched_param
	 * then only we offload the system call to veos else it will
	 * return EPERM
	 */

	retval = syscall(syscall_num, args[0], &vh_sched_param);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n", syscall_name,
				strerror(errno));
		goto hndl_return;
	} else {
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}

		sched_info.pid = args[0];
		sched_info.prio = vh_sched_param.sched_priority;

		/* Send veos request to set parameters */
		retval = pseudo_psm_send_sched_setparam_req(veos_sock_fd,
				&sched_info);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send setparam "
					"info to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_sched_setparam_ack(veos_sock_fd);
		if (-1 == retval) {
			retval = -ESRCH;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"GET SET_PARAM_ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		retval = 0;
		close(veos_sock_fd);
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief handle the functionality of sched_setschedular system call
 *
 * int sched_setscheduler(pid_t pid, int policy,
 *                                 const struct sched_param *param);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_setscheduler(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	int veos_sock_fd;
	struct ve_sched_info sched_info;
	struct sched_param vh_sched_param;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Receive environment for sched_setscheduler from VE */
	if (NULL != (void *)args[2]) {
		if (-1 == ve_recv_data(handle, args[2],
					(sizeof(struct sched_param)),
					(uint64_t *)(&vh_sched_param))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	sched_info.pid = args[0];
	sched_info.policy = args[1];
	sched_info.prio = vh_sched_param.sched_priority;

	/* Send veos request to set policy */
	retval = pseudo_psm_send_setscheduler_req(veos_sock_fd, &sched_info);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send setscheduler info to PSM\n");
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_setscheduler_ack(veos_sock_fd);
	if (-1 == retval) {
		retval = -ESRCH;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"SET_SCHED_ACK not received\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	retval = 0;
	close(veos_sock_fd);

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief handle the functionality of sched_getschedular system call.
 *
 * int sched_getscheduler(pid_t pid);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_getscheduler(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1];
	int veos_sock_fd;
	pid_t pid;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	pid = args[0];
	if (pid < 0) {
		retval = -EINVAL;
		goto hndl_return;
	}

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	/* Send veos request to get policy */
	retval = pseudo_psm_send_getscheduler_req(veos_sock_fd , pid);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send request for policy to PSM\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_getscheduler_ack(veos_sock_fd);
	if (-1 == retval) {
		retval = -ESRCH;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"GET SCHED ACK not received\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles the sched_get_priority_max functionality for VE.
 *
 * int sched_get_priority_max(int policy);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_get_priority_max(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1];
	int veos_sock_fd;
	int policy;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	policy = args[0];
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
	case SCHED_BATCH:
	case SCHED_IDLE:
		retval = -EINVAL;
		break;
	case SCHED_OTHER:
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		/* Send veos request to get priority */
		retval = pseudo_psm_send_get_priority_max_req
			(veos_sock_fd);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send get_priority_max  info to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_get_priority_max_ack
			(veos_sock_fd);
		if (-1 == retval) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PRIO MAX ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy\n");
		retval = -EINVAL;
		break;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handle the sched_get_priority_min system call functionality for VE
 *
 * int sched_get_priority_min(int policy);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_get_priority_min(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	int veos_sock_fd;
	int policy;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	policy = args[0];
	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
	case SCHED_BATCH:
	case SCHED_IDLE:
		retval = -EINVAL;
		break;
	case SCHED_OTHER:
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (0 > veos_sock_fd) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		/* Send veos request to get priority */
		retval = pseudo_psm_send_get_priority_min_req(veos_sock_fd);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed to send getpriority "
					"info to PSM\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_get_priority_min_ack(veos_sock_fd);
		if (-1 == retval) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PRIO MIN ACK not received\n");
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid policy\n");
		retval = -EINVAL;
		break;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Hanldes the functionality of sched_rr_get_interval system call
 *
 * int sched_rr_get_interval(pid_t pid, struct timespec * tp);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_rr_get_interval(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	int veos_sock_fd;
	struct timespec tp;
	pid_t pid;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	pid = args[0];
	if (pid < 0) {
		retval = -EINVAL;
		goto hndl_return;
	} else if (pid == 0)
		pid = syscall(SYS_gettid);

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}

	retval = pseudo_psm_send_get_inr_req(veos_sock_fd, pid);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send get interval info to PSM\n");
		goto hndl_return;
	}

	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_get_inr_ack(veos_sock_fd, &tp);
	if (-1 == retval) {
		retval = -ESRCH;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"GET INR ACK not received\n");
		goto hndl_return;
	}
	retval = 0;
	close(veos_sock_fd);
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct timespec),
				(uint64_t *)&tp)) {
		retval = -EFAULT;
		goto hndl_return;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles prctl() system call functionality for ve.
 *
 * int prctl(int option, unsigned long arg2, unsigned long arg3,
 *		unsigned long arg4, unsigned long arg5);
 *
 * This function fetches the arguments from VE and then offload
 * to VEOS or VH OS based on the first argument option for
 * operation on VE process.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */

void ve_prctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5];
	char pr_name_buff[16];
	int veos_sock_fd;
	int arg2 = 0;
	int option;
	int index_local = 0;
	uint64_t tid_addr = 0;
	uint32_t cap_data_pres;
	struct __user_cap_header_struct cap_header_data;
	struct __user_cap_data_struct cap_data_data;

	pid_t tid = syscall(SYS_gettid);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	option = (int)args[0];

	switch (option) {
	case PR_CAPBSET_READ:
	case PR_CAPBSET_DROP:
	case PR_SET_CHILD_SUBREAPER:
	case PR_SET_DUMPABLE:
	case PR_GET_DUMPABLE:
	case PR_SET_KEEPCAPS:
	case PR_GET_KEEPCAPS:
	case PR_SET_NO_NEW_PRIVS:
	case PR_GET_NO_NEW_PRIVS:
	case PR_SET_PDEATHSIG:
	case PR_GET_PDEATHSIG:
	case PR_SET_PTRACER:
	case PR_SET_SECCOMP:
	case PR_GET_SECCOMP:
	case PR_SET_SECUREBITS:
	case PR_GET_SECUREBITS:
	case PR_SET_TIMERSLACK:
	case PR_GET_TIMERSLACK:
	case PR_SET_TIMING:
	case PR_GET_TIMING:
	case PR_TASK_PERF_EVENTS_DISABLE:
	case PR_TASK_PERF_EVENTS_ENABLE:
	case PR_MCE_KILL:
	case PR_MCE_KILL_GET:
		/* call VH system call */
		retval = syscall(syscall_num, args[0],
				args[1], args[2], args[3], args[4]);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		break;
	case PR_SET_ENDIAN:
	case PR_GET_ENDIAN:
	case PR_SET_FPEXC:
	case PR_GET_FPEXC:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_GET_ENDIAN/PR_SET_ENDIAN/PR_SET_FPEXC/PR_GET_FPEXC"
				" for powerpc only.\n");
		retval = -EINVAL;
		goto hndl_return;
	case PR_SET_FPEMU:
	case PR_GET_FPEMU:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_SET_FPEMU/PR_GET_FPEMU only on ia64.\n");
		retval = -EINVAL;
		goto hndl_return;
	case PR_SET_TSC:
	case PR_GET_TSC:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_SET_TSC/PR_GET_TSC only for x86.\n");
		retval = -EINVAL;
		goto hndl_return;
	case PR_SET_UNALIGN:
	case PR_GET_UNALIGN:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_SET_UNALIGN/PR_GET_UNALIGN only for"
				" ia64, parisc, PowerPC, Alpha.\n");
		retval = -EINVAL;
		goto hndl_return;
	case PR_SET_NAME:
		if (args[1]) {
			/* get the name */
			if (0 > ve_recv_string(handle, args[1],
						pr_name_buff, 16)) {
				retval = -EFAULT;
				goto hndl_return;
			}
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"PR_SET_NAME: %s\n", pr_name_buff);
		} else {
			retval = -EFAULT;
			goto hndl_return;
		}

		/* call VH system call */
		retval = syscall(syscall_num, args[0],
				&pr_name_buff, args[2], args[3], args[4]);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		break;
	case PR_GET_NAME:
		/* call VH system call */
		retval = syscall(syscall_num, args[0],
				&pr_name_buff, args[2], args[3], args[4]);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_GET_NAME: %s\n", pr_name_buff);
		if (args[1]) {
			/* set the name */
			if (-1 == ve_send_data(handle, args[1],
						16, (uint64_t *)(pr_name_buff))) {
				retval = -EFAULT;
				goto hndl_return;
			}
		} else {
			retval = -EFAULT;
			goto hndl_return;
		}
		break;
	case PR_GET_TID_ADDRESS:
		/* TODO: This feature is available only if the VH kernel is
		 * built with the CONFIG_CHECKPOINT_RESTORE option enabled.
		 * How to check this option in userspace?
		 */
		index_local = find_global_array_index(tid);
		tid_addr = (uint64_t)global_tid_info[index_local].ctid_address;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"index_local: %d, ctid_address: %lx\n",
				index_local, tid_addr);

		if (args[1]) {
			/* send the tid_addr */
			if (-1 == ve_send_data(handle, args[1],
						sizeof(uint64_t),
						(uint64_t *)(&tid_addr))) {
				retval = -EFAULT;
				goto hndl_return;
			}
		} else {
			retval = -EFAULT;
			goto hndl_return;
		}
		break;
	case PR_GET_CHILD_SUBREAPER:
		/* call VH system call */
		retval = syscall(syscall_num, args[0],
				&arg2, args[2], args[3], args[4]);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"PR_GET_CHILD_SUBREAPER: %d\n", arg2);
		if (args[1]) {
			/* send the "PR_GET_CHILD_SUBREAPER */
			if (-1 == ve_send_data(handle, args[1],
						sizeof(int),
						(uint64_t *)(&arg2))) {
				retval = -EFAULT;
				goto hndl_return;
			}
		} else {
			retval = -EFAULT;
			goto hndl_return;
		}
		break;
	case PR_SET_MM:
		/* TODO: This feature is available only if the VH kernel is
		 * built with the CONFIG_CHECKPOINT_RESTORE option enabled.
		 */
		if (args[4] || (args[3] && args[1] != PR_SET_MM_AUXV)) {
			retval = -EINVAL;
			goto hndl_return;
		}

		/*
		 * checking does pseudo having a  CAP_SYS_RESOURCE
		 * capability.
		 */
		cap_user_header_t cap_header = &cap_header_data;
		cap_user_data_t cap_data = &cap_data_data;
		cap_header->pid = tid;
		cap_header->version = _LINUX_CAPABILITY_VERSION;

		/* Get the capabilities */
		if (capget(cap_header, cap_data) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"failed capget error\n");
			retval = -EPERM;
			goto hndl_return;
		}
		cap_data_pres = 1<<CAP_SYS_RESOURCE;
		if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pid %d don't have"
					" CAP_SYS_RESOURCE capability.\n",
					tid);
			retval = -EPERM;
			goto hndl_return;
		}
		/* interact with VEOS to set the memory map descriptor fields.
		*/
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			retval = -errno;
			goto hndl_return;
		}
		if (pseudo_psm_send_pr_set_mm_req(veos_sock_fd,
					args[1], args[2]) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_pr_set_mm_req "
					"failed.");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_pr_set_mm_ack(veos_sock_fd);
		if (0 > retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_pr_set_mm_ack "
					"failed.");
			retval = -EINVAL;
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	default:
		retval = -EINVAL;
		goto hndl_return;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;

}

void ve_arch_prctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
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
 * @param[in] pid PID of VE process
 * @param[in] resource Resource to set
 * @param[in] rlim Value of new resource limit
 *
 * @return 0 on success, negative on failure
 */
int do_setrlimit(pid_t pid, int resource, struct rlimit rlim)
{
	int retval = -1;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"rlim_cur: %ld rlim_max: %ld\n", rlim.rlim_cur,
			rlim.rlim_max);

	if (rlim.rlim_cur > rlim.rlim_max) {
		retval = -EINVAL;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"rlim_cur can't be greater than rlim_max\n");
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
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		if (pseudo_psm_send_set_rlimit_req(veos_sock_fd,
					resource, rlim, pid) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_set_rlimit_req "
					"failed.");
			retval = -errno;
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		retval = pseudo_psm_recv_set_rlimit_ack(veos_sock_fd);
		/* wait for acknowledgment from PSM */
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_set_rlimit_ack "
					"failed.");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		} else if (-2 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"No such process found\n");
			retval = -ESRCH;
			close(veos_sock_fd);
			goto hndl_return;
		} else if (-3 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"No permission to update rlimit\n");
			retval = -EPERM;
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		break;
	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_MEMLOCK:
	case RLIMIT_MSGQUEUE:
	case RLIMIT_NICE:
	case RLIMIT_NOFILE:
	case RLIMIT_NPROC:
	case RLIMIT_RTPRIO:
	case RLIMIT_RTTIME:
		/* call VH system call */
		retval = syscall(SYS_setrlimit, resource, &rlim);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall setrlimit failed %s\n",
					strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall setrlimit returned %d\n",
					(int)retval);
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid resource provided.\n");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;
hndl_return:
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_setrlimit(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct rlimit rlim;
	uint64_t args[2];
	int resource;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	resource = (int)args[0];

	/* get the rlimit buf */
	if (-1 == ve_recv_data(handle, args[1],
				sizeof(struct rlimit), (uint64_t *)(&rlim))) {
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = do_setrlimit(syscall(SYS_gettid), resource, rlim);

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_acct(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[1];
	int veos_sock_fd;
	char *path_buff = NULL;
	char *real_path = NULL;
	uint32_t cap_data_pacct;
	struct __user_cap_header_struct cap_header_data;
	struct __user_cap_data_struct cap_data_data;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/*
	 * Checking does the VE process having a permit
	 * to enable/disable the accounting by using capget system call
	 */
	cap_user_header_t cap_header = &cap_header_data;
	cap_user_data_t cap_data = &cap_data_data;
	cap_header->pid = syscall(SYS_gettid);
	cap_header->version = _LINUX_CAPABILITY_VERSION;

	/* Get the capabilities */
	if (capget(cap_header, cap_data) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"capget failed error\n");
		retval = -errno;
		goto hndl_return;
	}
	cap_data_pacct = 1<<CAP_SYS_PACCT;
	if (cap_data_pacct != (cap_data->permitted & cap_data_pacct)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pid %ld don't have"
				"sufficent privilege to enable accounting\n",
				syscall(SYS_gettid));
		retval = -EPERM;
		goto hndl_return;
	}

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	if ((void *)args[0] != NULL) {
		path_buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == path_buff) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc fail: %s\n",
					strerror(errno));
			retval = -errno;
			goto hndl_return;
		}
		memset(path_buff, '\0', PATH_MAX);
		/* receive contents of 1st argument */
		retval = ve_recv_string(handle, args[0],
				(char *)path_buff, PATH_MAX);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"ve_recv_string failed. "
					"(%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* First get the realpath of the filename received */
		real_path = realpath(path_buff, NULL);
		if (NULL == real_path) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Fail(%s) to get realpath of:%s\n",
					strerror(errno),
					path_buff);
			retval = -errno;
			goto hndl_return1;
		}

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Realpath of filename: %s\n", real_path);

		retval = access(real_path, F_OK|W_OK|R_OK);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"File access fail: %s\n",
					strerror(errno));
			retval = -errno;
			goto hndl_return2;
		}
	}

	/* Communicate with VEOS */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"socket creation failed\n");
		goto hndl_return2;
	}
	/* Send veos request to enable/diable the accounting */
	retval = pseudo_psm_send_acct_req(veos_sock_fd,	real_path);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"failed to send accounting info to PSM\n");
		close(veos_sock_fd);
		goto hndl_return2;
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_acct_ack(veos_sock_fd);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"acct() system call fail VEOS return: %ld\n",
				retval);
		close(veos_sock_fd);
		goto hndl_return2;
	}
	retval = 0;
	close(veos_sock_fd);

hndl_return2:
	free(real_path);
hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_settimeofday(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -EPERM;

	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called returning EPERM %ld\n",
			syscall_name, retval);

	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles sched_yield() system call for ve.
 *
 * details
 * int sched_yield(void);
 *
 * This function offloads the functionality to VH OS sched_yield() system call.
 * And request VEOS to relinquish the CPU of the calling VE process/thread.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_yield(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* call VH system call */
	retval = syscall(syscall_num);
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

	/*Inform VEOS to relinquish the core.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	if (pseudo_psm_send_sched_yield_req(veos_sock_fd) < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_sched_yield_req failed.");
		close(veos_sock_fd);
		goto hndl_return;
	}
	/* there is no need to wait for ACK from VEOS
	*/
	retval = 0;
	close(veos_sock_fd);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */

void ve_time(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	time_t ve_t;
	uint64_t args[1];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 1);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, &ve_t);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"sycall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	/* send the time value stored in memory pointed to by ve_t */
	if (NULL != (void *)args[0]) {
		if (-1 == ve_send_data(handle, args[0],
					sizeof(time_t), (uint64_t *)(&ve_t))) {
			retval = -EFAULT;
		}
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 */
void ve_futex(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t futex_args[6];
	struct timespec *ts = NULL;
	int veos_sock_fd;
	unsigned long val2 = 0;
	int cmd, retry_call = 3;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* fetching the arguments using handle obtained */
	retval = vedl_get_syscall_args(handle, futex_args, 6);

	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[0]( uaddr): %lx\n", futex_args[0]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[1]( op): %lu\n", futex_args[1]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[2]( val): %lu\n", futex_args[2]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[3]( utime): %lu\n", futex_args[3]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[4]( uaddr2): %lu\n", futex_args[4]);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"futex_args[5]( val3): %lu\n", futex_args[5]);

	/* copy VE requested operation(WAIT/WAKE/...) and
	 * type(PRIVATE/SHARED/...) of command.
	 */
	cmd = futex_args[1] & FUTEX_CMD_MASK;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "cmd : %u\n", cmd);

	if (0 != futex_args[3] && (FUTEX_WAIT == cmd || FUTEX_LOCK_PI == cmd ||
				FUTEX_WAIT_BITSET == cmd ||
				FUTEX_WAIT_REQUEUE_PI == cmd)) {

		/* copy timespec value */
		ts = (struct timespec *)malloc(sizeof(struct timespec));
		if (NULL == ts) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc for timespec failed\n");
			goto hndl_return;
		}

		if ((ve_recv_data(handle, futex_args[3],
						sizeof(struct timespec),
						(uint64_t *)ts)) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed. "
					"(%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* requeue parameter in futex_args[3] if cmd == FUTEX_*_REQUEUE_*.
	 * number of waiters to wake in 'futex_args[3]' if cmd == FUTEX_WAKE_OP.
	 * TODO: not used in prototype 2.0, but added for future use.
	 */
	if (FUTEX_REQUEUE == cmd || FUTEX_CMP_REQUEUE == cmd ||
			FUTEX_CMP_REQUEUE_PI == cmd || FUTEX_WAKE_OP == cmd)
		val2 = (unsigned long)futex_args[3];

	/* Change VH memory permission into READ and WRITE */
	retval = mprotect((void *)(futex_args[0] & 0XFFFFFFFFFFFFF000),
			0X1000, PROT_WRITE|PROT_READ);
	if (retval != 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Cannot access memory\n");
		goto hndl_return1;
	}

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = veos_sock_fd;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return1;
	}

	/* send halt VE node request to PSM
	 * VE_ALL_CORE : for all cores of current node.
	 */
	if ((pseudo_psm_halt_core_req(veos_sock_fd,
					VE_ALL_CORE, syscall(SYS_gettid))) < 0) {
		/* TODO  : Two approaches for failure of halt_core_re().
		 *		1. Retry to HALT.
		 *		2. Exit system call with error value.
		 *	Currently we are following Approach.2.
		 */
		/*TODO : set Appropriate error value. */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_halt_core_req failed"
				" (%s)\n", syscall_name);
		retval = -1;
		close(veos_sock_fd);
		goto hndl_return1;
	}

	/* wait for acknowledgment from PSM */
	if (pseudo_psm_recv_core_halt_ack(veos_sock_fd) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_core_halt_ack failed"
				" (%s)\n", syscall_name);
		/*TODO : set Appropriate error value. */
		retval = -1;
		close(veos_sock_fd);
		goto hndl_return1;
	}
	close(veos_sock_fd);

	/* Copy VE DATA to VH Memory */
	if ((ve_recv_data(handle, futex_args[0], sizeof(unsigned int),
					(uint64_t *)futex_args[0])) < 0) {

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_data failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
	}

	/* send start VE node request to PSM
	 * VE_MAX_CORE_PER_NODE : for all cores of current node.
	 */

retry_core:
	retry_call--;

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		if (retry_call > 0)
			goto retry_core;
		else {
			/*TODO : set Appropriate error value. */
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Critical error: "
					"failed to obtain socket.\n");
			goto hndl_return1;
		}
	}

	if ((pseudo_psm_core_start_req(veos_sock_fd,
					VE_ALL_CORE, syscall(SYS_gettid))) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_core_start_req failed. (%s)\n",
				syscall_name);
		/* TODO: Strategy need to be decide if start core req fail,
		 *	At this point all the cores are in HALT state. Even if
		 *	we return directly from here with return value,
		 *	VEOS will not be able to schedule process because
		 *	all cores are already in HALT state.
		 *	One of the approach is to retry starting of the core.
		 */
		close(veos_sock_fd);
		if (retry_call > 0)
			goto retry_core;
		else {
			/*TODO : set Appropriate error value. */
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Critical error: failed start core\n");
			goto hndl_return1;
		}
	}

	/* wait for acknowledgment from PSM
	 * TODO: handle failure cases gracefully.
	 */
	if (pseudo_psm_recv_core_started_ack(veos_sock_fd) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_core_started_ack failed."
				" (%s)\n", syscall_name);
		close(veos_sock_fd);
		if (retry_call > 0)
			goto retry_core;
		else {
			/*TODO : set Appropriate error value. */
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Critical error: failed start core\n");
			goto hndl_return1;
		}
	}

	close(veos_sock_fd);

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	if (retval >= 0) {
		if (val2) {
			retval = syscall(syscall_num, futex_args[0],
					futex_args[1], futex_args[2], val2,
					futex_args[4], futex_args[5]);
		} else {
			retval = syscall(syscall_num, futex_args[0],
					futex_args[1], futex_args[2], ts,
					futex_args[4], futex_args[5]);
		}

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"futex_returned %ld\n",
				syscall(SYS_gettid));
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s failed %s\n", syscall_name,
					strerror(errno));
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s success with retval: %lu\n",
					syscall_name, retval);
	}
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	if (NULL != ts)
		free(ts);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_setaffinity(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	pid_t pid;
	size_t cpusetsize;
	int64_t mask;
	int veos_sock_fd;

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

	if (0 == args[0])
		pid = syscall(SYS_gettid);
	else
		pid = (pid_t)args[0];


	cpusetsize = (size_t)args[1];

	if (cpusetsize > sizeof(uint64_t))
		cpusetsize = sizeof(uint64_t);

	/* get the mask provided by VE program
	*/
	if (-1 == ve_recv_data(handle, args[2],
				cpusetsize,
				(uint64_t *)(&mask))) {
		retval = -EFAULT;
		goto hndl_return;
	}

	/* interact with PSM to set the affinity of the VE process.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}

	retval = pseudo_psm_send_setaffinity_req(veos_sock_fd, pid, mask);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send set affinity request\n");
		retval = -EINVAL;
		goto hndl_return1;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_setaffinity_ack(veos_sock_fd);
	if (-1 == retval) {
		retval = -ESRCH;
		goto hndl_return1;
	} else if (-2 == retval) {
		retval = -EPERM;
		goto hndl_return1;
	}

	/* In Success set retval to "0" */
	retval = 0;
hndl_return1:
	close(veos_sock_fd);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_sched_getaffinity(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	pid_t pid;
	size_t cpusetsize;
	uint64_t mask;
	int veos_sock_fd;

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

	if (0 == args[0])
		pid = syscall(SYS_gettid);
	else
		pid = (pid_t)args[0];

	cpusetsize = (size_t)args[1];

	if (cpusetsize > sizeof(uint64_t))
		cpusetsize = sizeof(uint64_t);

	/* interact with PSM to get the affinity of the VE process.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}

	retval = pseudo_psm_send_getaffinity_req(veos_sock_fd, pid, cpusetsize);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send get affinity request\n");
		retval = -errno;
		goto hndl_return1;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_getaffinity_ack(veos_sock_fd, &mask);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"GETAFFINTIY ACK not received\n");
		retval = -EINVAL;
		goto hndl_return1;
	} else if (0 == retval) {
		/* VE CPU affinity is only 64 bits */
		if (-1 == ve_send_data(handle, args[2],
					cpusetsize,
					(uint64_t *)(&retval))) {
			retval = -EFAULT;
			goto hndl_return1;
		}
	} else if (-2 == retval)
		retval = -ESRCH;

hndl_return1:
	close(veos_sock_fd);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief This function will take care of the set_tid_address system call functionality.
 *
 * long set_tid_address(int *tidptr);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_set_tid_address(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t addr_rcvd;
	int veos_sock_fd;
	ret_t retval;
	int tid;
	int index;

	retval = tid = syscall(SYS_gettid);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	if (vedl_get_syscall_args(handle, &addr_rcvd, 1) < 0) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
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
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"tid_counter : %d, tid : %d\n",
				tid_counter, tid);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"addr_rcvd : %lx\n",
				(unsigned long)addr_rcvd);

		if (-1 == tid_counter) {
			tid_counter++;
			index = tid_counter;
			global_tid_info[index].tid_val = tid;
			global_tid_info[index].flag = 0;
			global_tid_info[index].mutex =
				(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
			global_tid_info[index].cond =
				(pthread_cond_t)PTHREAD_COND_INITIALIZER;
		} else {
			index = find_global_array_index(tid);
		}

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"index : %d\n", index);
		global_tid_info[index].ctid_address = addr_rcvd;

		/* interact with PSM to set the clear_child_tid for the VE
		 * process
		 */
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}

		if (pseudo_psm_send_set_tidaddr_req
				(veos_sock_fd, addr_rcvd) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_set_tidaddr_req "
					"failed.");
			retval = -errno;
			close(veos_sock_fd);
			goto hndl_return;
		}


		/* wait for acknowledgment from PSM */
		if (pseudo_psm_recv_set_tidaddr_ack(veos_sock_fd) < 0) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_set_tid_ack failed. "
					"(%s) returned %d\n",
					syscall_name, (int)retval);
		}

		close(veos_sock_fd);
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_clock_settime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -EPERM;

	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called returning -EPERM\n", syscall_name);

	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_clock_gettime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct timespec time_buf;
	uint64_t args[2];
	int veos_sock_fd;
	clockid_t clk_id;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	clk_id = (clockid_t)args[0];

	switch (clk_id) {
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
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"timespec.tv_sec = %ld\n",
				time_buf.tv_sec);
		break;
	case CLOCK_PROCESS_CPUTIME_ID:
		/* interact with PSM to get the process cputime.
		*/
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		if (pseudo_psm_send_clk_cputime_req(veos_sock_fd, 1) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_clk_cputime_req "
					"failed.");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}
		/* wait for acknowledgment from PSM */
		if (pseudo_psm_recv_clk_cputime_ack(veos_sock_fd,
					&time_buf) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_clk_cputime_ack "
					"failed.");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		retval = 0;
		break;
	case CLOCK_THREAD_CPUTIME_ID:
		/* interact with PSM to get the thread cputime.
		*/
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			goto hndl_return;
		}
		if (pseudo_psm_send_clk_cputime_req(veos_sock_fd, 0) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_send_clk_cputime_req "
					"failed\n");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}

		/* wait for acknowledgment from PSM */
		if (pseudo_psm_recv_clk_cputime_ack(veos_sock_fd,
					&time_buf) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"pseudo_psm_recv_clk_cputime_ack "
					"failed.");
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"(%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}
		close(veos_sock_fd);
		retval = 0;
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid clock ID.\n");
		retval = -EINVAL;
		goto hndl_return;
	}

	/* send the filled timespec buf */
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct timespec), (uint64_t *)(&time_buf))) {
		retval = -EFAULT;
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_clock_getres(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct timespec time_buf;
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0], &time_buf);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"timespec.tv_sec = %ld timespec.tv_nsec %ld\n",
			time_buf.tv_sec, time_buf.tv_nsec);

	/* send the filled timespec buf */
	if (-1 == ve_send_data(handle, args[1],
				sizeof(struct timespec), (uint64_t *)(&time_buf)))
		retval = -EFAULT;

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief This function handles exit_group() system call functionality for ve.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_exit_group(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args;
	int retval;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/*Syncing file backed data*/
	sync_at_exit(handle);

	/* TODO:
	 * need to set these flags in current threads
	 * exit_code = sig->group_exit_code;
	 * sig->group_exit_code = exit_code;
	 * sig->flags = SIGNAL_GROUP_EXIT;
	 * Also some extra handling to clears pending signals
	 * and jobs by other threads.
	 * */

	/* get arguments */
	retval = vedl_get_syscall_args(handle, &args, 1);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s)\n",
				syscall_name);
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "args : %d\n", (int)args);

	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
	} else {
		/* Send request to PSM for cleanup of VE process */
		retval = pseudo_psm_send_delete_ve_proc_req(veos_sock_fd, 1, args);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"PSM cleanup fails\n"
					"failed\n");
		} else {
			/* wait for acknowledgment from PSM */
			retval = pseudo_psm_recv_delete_ack(veos_sock_fd);
			if (retval < 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"pseudo_psm_recv_delete_ack "
						"failed\n");
				close(veos_sock_fd);
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"retval received : %d\n",
						retval);
			}
		}
	}

	syscall(syscall_num, args);
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
 * @param[in] handle Handle for VE driver interface
 */
void ve_waitid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t waitid_args[5];
	ret_t retval = -1;
	siginfo_t ve_infop;
	struct rusage r;
	struct ve_rusage ve_r;
	int veos_sock_fd;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	retval = vedl_get_syscall_args(handle, waitid_args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, waitid_args[0], waitid_args[1],
			&ve_infop, waitid_args[3], &r);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));

		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* Get the VE specific rusage from VEOS.
	*/
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	if (pseudo_psm_send_get_rusage_req(veos_sock_fd,
				RUSAGE_CHILDREN) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_get_rusage_req failed.");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	if (pseudo_psm_recv_get_rusage_ack(veos_sock_fd,
				&ve_r) < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_get_rusage_ack failed.");
		retval = -ECHILD;
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);

	/* Update the value in struct rusage obtained from
	 * VEOS.
	 */
	r.ru_stime = ve_r.ru_stime;
	r.ru_maxrss = ve_r.ru_maxrss;

	if (NULL != (void *)waitid_args[2]) {
		if (-1 == ve_send_data(handle, waitid_args[2],
					sizeof(siginfo_t),
					(uint64_t *)(&ve_infop))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (0 != (void *)waitid_args[4]) {
		if (-1 == ve_send_data(handle, waitid_args[4],
					sizeof(struct rusage),
					(uint64_t *)(&r))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return;
		}
	}
hndl_return:
	return_system_call(retval);
	return;
}

/*
 *
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
 * @param[in] handle Handle for VE driver interface
 *
 */
void ve_prlimit64(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	pid_t pid;
	int resource;
	struct rlimit new_limit, old_limit;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (0 == args[0])
		pid = syscall(SYS_gettid);
	else
		pid = args[0];

	resource = args[1];

	/* checking for old_limit NULL or not */
	if (args[3] != 0) {
		retval = do_getrlimit(pid, resource, &old_limit);
		if (0 != retval)
			goto hndl_return;

		/* set the obtained limit */
		if (-1 == ve_send_data(handle, args[3],
					sizeof(struct rlimit),
					(uint64_t *)(&old_limit))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/* checking for new_limit NULL or not */
	if (args[2] != 0) {
		/* get the new limit */
		if (-1 == ve_recv_data(handle, args[2],
					sizeof(struct rlimit),
					(uint64_t *)(&new_limit))) {
			retval = -EFAULT;
			goto hndl_return;
		}
		retval = do_setrlimit(pid, resource, new_limit);
		if (0 != retval)
			goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
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
 * @param[in] handle Handle for VE driver interface
 *
 */
void ve_clock_adjtime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -EPERM;

	/* For VE enviorment this system call will return EPERM to
	 * VE process.
	 */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"%s is called returning EPERM\n", syscall_name);

	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief handles the functionality of getcpu system call for VE
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_getcpu(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	unsigned int cpu = -1;
	unsigned int node = -1;
	struct ve_cpu_info cpu_info;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments
	 * third argument (tcache) is unused since Linux 2.6.24 */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		goto hndl_return;
	}
	/* Send veos request to get cpu id and node id */
	retval = pseudo_psm_send_getcpu_req(veos_sock_fd);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"failed to send cpu info to PSM\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_getcpu_ack(veos_sock_fd, &cpu_info);
	if (-1 == retval) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"GET CPU ACK not received\n");
		close(veos_sock_fd);
		goto hndl_return;
	} else {
		close(veos_sock_fd);
		cpu = cpu_info.cpu;
		node = cpu_info.node;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"cpu is %d node is %d\n", cpu, node);
		retval = 0;
		if (-1 == ve_send_data(handle, args[0],
					sizeof(unsigned int),
					(unsigned int *)(&cpu))) {
			retval = -EFAULT;
			goto hndl_return;
		}
		if (-1 == ve_send_data(handle, args[1],
					sizeof(unsigned int),
					(unsigned int *)(&node))) {
			retval = -EFAULT;
			goto hndl_return;
		}
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_set_robust_list(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_get_robust_list(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_get_thread_area(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_set_thread_area(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
