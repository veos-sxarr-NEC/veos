/**
 * @file  psm_clone_handler.c
 * @brief Handles VE Process fork/clone handling
 *
 * This contains the functions that are used to handle fork and
 * clone request from PSEUDO PROCESS for VE process.
 */

#include <unistd.h>
#include <search.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/shm.h>
#include "ve_hw.h"
#include "psm_main.h"
#include "psm_task_mgmt.h"
#include "psm_clone.h"
#include "amm_psm_if.h"
#include "psm_signal_handler.h"
#include "velayout.h"

/**
 * @brief Updates task thread_struct based on values received from
 * loader interface.
 *
 * @param[in] context_info Info recevied from loader interface
 * @param[in,out] thread_struct Task's thread_struct to which values are updated
 *
 * @return 0 on success, -1 on failure.
 */
int update_ve_thread_node(struct ve_context_info *context_info,
		struct ve_thread_struct *thread_struct)
{
	int retval = -1;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	if (!context_info || !thread_struct)
		goto hndl_return;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "\t%lx %lx %lx\n",
			context_info->IC,
			context_info->SP, context_info->SZ);

	thread_struct->IC = context_info->IC;
	thread_struct->SR[8] = context_info->SZ;
	thread_struct->SR[11] = context_info->SP;
	thread_struct->SR[01] = 0;

	/* Set arithmetic mode to nearest even*/
	SET_ARITHMETIC_MODE(thread_struct, PSW_AM_RN)
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Updates the thread area for the newly created task.
 *
 * @param[in] tsk Pointer to new task structure
 * @param[in] orig Pointer to original task structure
 */
void setup_ve_thread_stack(struct ve_task_struct *tsk,
		struct ve_task_struct *orig)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");
	/* TODO : setup thread area for the newly created task */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}

/**
 * @brief Copy the values of parent ve_task_struct into the newly created task.
 *
 * @param[out] dst Pointer to destination VE task struct
 * @param[in] src Pointer of source VE task struct
 *
 * @return 0 on success, -1 on failure.
 */
int arch_dup_ve_task_struct(struct ve_task_struct *dst,
		struct ve_task_struct *src)
{
	int retval = -1;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	if (!dst || !src)
		goto hndl_return;

	/* copy the values of orig into tsk */
	*dst = *src;
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return retval;
}

/**
 * @brief Copy the values of parent thread struct to newly created thread struct.
 *
 * @param[out] dst Pointer to destination thread struct
 * @param[in] src Pointer to source thread struct
 *
 * @return 0 on success, -1 on failure.
 */
int arch_dup_ve_thread_struct(struct ve_thread_struct *dst,
		struct ve_thread_struct *src)
{
	int retval = -1;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	if (!dst || !src)
		goto hndl_return;

	*dst = *src;
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return retval;
}

/**
 * @brief Duplicates the necessary attributes for ve_task_struct for VE process.
 *
 * @param[in] current Pointer to VE task struct
 *
 * @return Pointer to ve_taskk_struct on success, NULL on failure.
 */
struct ve_task_struct *dup_ve_task_struct(struct ve_task_struct *current)
{
	struct ve_task_struct *task;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!current)
		goto hndl_return;

	task = alloc_ve_task_struct_node();
	if (!task)
		goto hndl_return;

	/* populate the new ve_task_struct with the values of
	 * parent task_struct
	 */
	arch_dup_ve_task_struct(task, current);

	/* allocate ve_thread_struct structure */
	task->p_ve_thread = alloc_ve_thread_struct_node();
	if (!task->p_ve_thread)
		goto free_tsk;

	task->p_ve_sigcontext = alloc_ve_thread_struct_node();
	if (!task->p_ve_sigcontext)
		goto free_ts;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return task;

free_ts:
	free(task->p_ve_thread);
free_tsk:
	free(task);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return NULL;
}

/**
 * @brief Prepares ve_mm_struct of VE task struct for VE process.
 * @detail It copies the memory attributes needed for the new VE process
 * from the parent VE process.
 *
 * @param[in] current Pointer to current ve_task struct
 * @param[in] clone_flags lone_flags as received from system call
 * @param[in,out] new_tsk Pointer to new VE task struct
 *
 * @return 0 on success, -1 on failure.
 */
int copy_ve_mm(struct ve_task_struct *current, unsigned long clone_flags,
		struct ve_task_struct *new_tsk)
{
	int retval = -1;
	struct ve_mm_struct *mm, *oldmm;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!current || !new_tsk)
		goto hndl_return;

	new_tsk->p_ve_mm = NULL;
	oldmm = current->p_ve_mm;
	if (!oldmm)
		goto hndl_return;

	/* If CLONE_VM flag, use the same mm_struct as of the parent */
	if (clone_flags & CLONE_VM) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "CLONE_VM set\n");
		/* Share mm_struct between child and parent */
		amm_copy_mm_struct(oldmm, &mm, current->node_id,
					REQUEST_FOR_PROCESS_SHARED);
		new_tsk->p_ve_mm = mm;
		retval = 0;
		goto hndl_return;
	}

	/* Create mm_struct for child and copy data from parent */
	retval = amm_copy_mm_struct(oldmm, &mm, current->node_id,
			REQUEST_FOR_PROCESS_PRIVATE);
	if (-1 == retval)
		goto hndl_return;

	new_tsk->p_ve_mm = mm;
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Prepares ve_thread_struct of VE task struct for VE process.
 * @detail It copies the thread struct attributes needed for the new
 * VE process from the parent VE process.
 *
 * @param[in] current Pointer to current VE task struct
 * @param[in] clone_flags clone_flags as recevied in system call
 * @param[in] sp stack pointer for VE
 * @param[in] arg arg for VE task
 * @param[in,out] new_tsk Pointer to new VE task struct
 *
 * @return 0 on success, -1 on failure.
 */
int copy_ve_thread(struct ve_task_struct *current,
		unsigned long clone_flags,
		unsigned long sp,
		unsigned long arg,
		struct ve_task_struct *new_tsk)
{
	int retval = -1;
	struct ve_task_struct *task_on_core = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!current || !new_tsk)
		goto hndl_return;

	pthread_rwlock_rdlock(&(VE_CORE(current->node_id, current->core_id)
				->ve_core_lock));
	task_on_core = VE_CORE(current->node_id,
				 current->core_id)->curr_ve_task;

	if (current == task_on_core) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Task %d is currently scheduled on core\n",
				current->pid);
		/* Fetching Register values using VE driver handle */
		if (-1 == vedl_get_usr_reg_all(VE_HANDLE(current->node_id),
				VE_CORE_USR_REG_ADDR(current->node_id,
					current->core_id),
				(core_user_reg_t *)new_tsk->p_ve_thread)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_get_usr_reg_all failed\n");
			pthread_rwlock_unlock(&(VE_CORE(current->node_id,
							current->core_id)
						->ve_core_lock));
			goto hndl_return;
		}
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Copying parent's (%d) p_ve_thread\n",
				current->pid);
		arch_dup_ve_thread_struct(new_tsk->p_ve_thread,
				current->p_ve_thread);
	}
	pthread_rwlock_unlock(&(VE_CORE(current->node_id, current->core_id)
				->ve_core_lock));

	if (clone_flags & CLONE_SETTLS)
		new_tsk->p_ve_thread->SR[14] = new_tsk->p_ve_thread->SR[5];

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"IC : %lx \tSR08 : %lx\tSR11 : %lx\t"
				"SR10 : %lx SR12 : %lx SR13 : %lx SR14: %lx\n",
				new_tsk->p_ve_thread->IC,
				new_tsk->p_ve_thread->SR[8],
				new_tsk->p_ve_thread->SR[11],
				new_tsk->p_ve_thread->SR[10],
				new_tsk->p_ve_thread->SR[12],
				new_tsk->p_ve_thread->SR[13],
				new_tsk->p_ve_thread->SR[14]);
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Prepares VE task struct for signal handling related attributes.
 * @detail Signal handling related attributes are set based based upon
 * clone flags passed as an argument.
 *
 * @param[in] current Pointer to current VE task struct
 * @param[in] clone_flags clone_flags as recevied in system call
 * @param[in,out] new_task Pointer to new VE task struct
 *
 * @return 0 on success, -1 on failure.
 */
int copy_ve_sighand(struct ve_task_struct *current,
		unsigned long clone_flags,
		struct ve_task_struct *new_task)
{
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!current || !new_task)
		goto hndl_return;

	/* In case of thread signal handler structure will be shared.
	 * and reference count of sighand strcuture will be incremented.
	 * In case of process.Create  new signal handler strcuture and copy
	 * the sigaction structure of parent process
	 */
	if (clone_flags & CLONE_SIGHAND) {
		pthread_mutex_lock(&(current->sighand->siglock));
		current->sighand->ref_count++;
		new_task->sighand = current->sighand;
		pthread_mutex_unlock(&(current->sighand->siglock));
		retval = 0;
		goto hndl_return;
	}
	new_task->sighand = alloc_ve_sighand_struct_node();
	if (!new_task->sighand)
		goto hndl_return;

	memcpy(new_task->sighand->action, current->sighand->action,
			sizeof(new_task->sighand->action));
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Calculates the offset on the shared page to be assigned to a
 * newly created thread.
 *
 * @param[in] parent_struct VE task struct of the parent thread
 *
 * @return offset on success, -1 on failure.
 */
int find_shared_page_offset(struct ve_task_struct *parent_struct)
{
	int index = 0, temp = 0;
	struct ve_task_struct *child_task_struct = NULL;
	int offset_arr[VEOS_MAX_VE_THREADS];

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!parent_struct) {
		index = -1;
		goto hndl_return;
	}

	memset(offset_arr, 0, sizeof(int) * VEOS_MAX_VE_THREADS);
	list_for_each_entry(child_task_struct, &(parent_struct->thread_group),
			thread_group) {
	temp = child_task_struct->offset / VEOS_MAX_VE_THREADS;
		offset_arr[temp] = child_task_struct->pid;
	}

	for (index = 1; index <= (VEOS_MAX_VE_THREADS - 1); index++) {
		if (offset_arr[index] == 0)
			break;
	}

	if (index == VEOS_MAX_VE_THREADS) {
		index = -1;
		goto hndl_return;
	}

	index = index * VEOS_MAX_VE_THREADS;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return index;
}

/**
 * @brief Prepares task_struct for VE process.
 * @detail Copies the attributes needed for the new VE process from
 * the corresponding parent VE process.
 *
 * @param[in] clone_flags clone_flags as recevied in system call
 * @param[in] stack_start starting of VE process stack
 * @param[in] stack_size VE process stack size
 * @param[in] child_tidptr VE task child TID pointer
 * @param[in] fork_info fork/clone related information
 *
 * @return Pointer to VE task struct on success, NULL on failure.
 */
struct ve_task_struct *copy_ve_process(unsigned long clone_flags,
		unsigned long stack_start,
		unsigned long stack_size,
		int *child_tidptr,
		struct ve_fork_info *fork_info)
{
	/* TO-DO
	 * 1. Check for the illegal combination of clone_flags like, shared
	 * signal handlers imply shared VM i.e. if clone_flags have
	 * CLONE_SIGHAND then flag must have CLONE_VM flag also.
	 *
	 * 2. Check for the resource limits, whether creating a new process
	 * exceeds the limits set in PSM.
	 *
	 * 3. Set up the fields related to timers, and time
	 * statistics.
	 *
	 * 4. Invoke different functions to create new data structures and copy
	 * into them the values of the corresponding parent process data
	 * structures, unless specified differently by the clone_flags
	 * parameter.
	 *
	 * 5. If either CLONE_CHILD_SETTID or CLONE_CHILD_CLEARTID is set in the
	 * clone_flags parameter, it copies the value of the child_tidptr
	 * parameter in the ve_task_struct field set_chid_tid or clear_child_tid
	 * field, respectively. These flags specify that the value of the
	 * variable pointed to by child_tidptr in the User Mode address space of
	 * the child has to be changed, although the actual write operations
	 * will be done later
	 *
	 * 6. Initializes the fields that specify the parenthood relationships.
	 *
	 * 7. Initialize different fields of ve_task_struct like tgid.
	 *
	 * 8. Terminates by returning the child’s process descriptor pointer.
	 */
	struct ve_task_struct *new_task = NULL;
	struct ve_task_struct *current = NULL;
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!fork_info)
		goto hndl_return;

	/* To find Parent process current CORE and Node */
	current = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE,
			fork_info->parent_pid);
	if (NULL != current) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PARENT with PID %d is : %p"
				"Parent Node : %d"
				"Parent Core : %d\n",
				fork_info->parent_pid,
				current,
				current->node_id,
				current->core_id);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found\n",
				fork_info->parent_pid);
		goto hndl_return;
	}

	/* Call dup_ve_task_struct to allocate new ve_task_struct and
	 * ve_thread_struct. Duplicate its entry for the child
	 * VE process.
	 */
	new_task = dup_ve_task_struct(current);
	if (!new_task)
		goto hndl_return;

	/* Stores the PID of the Child VE process in the ve_task_struct
	 * just allocated.
	 */
	new_task->pid = fork_info->child_pid;

	/* Number of voluntary and involuntary context switches
	 * are reset to zero for child process/thread.
	 */
	new_task->nvcsw = new_task->nivcsw = 0;

	/* Initialize the list_head data structures to maintain list of
	 * childrens and siblings of the created child ve process.
	 */
	INIT_LIST_HEAD(&(new_task->children));
	INIT_LIST_HEAD(&(new_task->siblings));
	INIT_LIST_HEAD(&(new_task->tasks));
	ve_init_sigpending(&(new_task->pending));

	/* sigaltstack should be cleared when sharing the same VM
	 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		new_task->sas_ss_sp = new_task->sas_ss_size = 0;

	/* Create the new process signal handler structure
	 * based upon CLONE flags
	 */
	retval = copy_ve_sighand(current, clone_flags, new_task);
	if (-1 == retval)
		goto free_new_task;

	/* Creating the process address space by setting up all ATB entries
	 * and memory descriptors for the new VE process with the help of AMM.
	 */
	retval = copy_ve_mm(current, clone_flags, new_task);
	if (-1 == retval)
		goto free_sighand;

	/* Process Context creation for the child process */
	retval = copy_ve_thread(current,
				clone_flags,
				stack_start,
				stack_size,
				new_task);
	if (retval)
		goto free_mm_struct;

	if (clone_flags & CLONE_THREAD) {
		new_task->exit_signal = -1;
		new_task->group_leader = current->group_leader;
		new_task->tgid = current->tgid;
		new_task->parent = current->parent;
		new_task->p_ve_thread->SR[11] = stack_start;
		new_task->ve_traced = current->ve_traced;
	} else {
		new_task->flags |= PF_FORKNOEXEC;
		new_task->exit_signal = 0;
		new_task->group_leader = new_task;
		new_task->tgid = new_task->pid;
		new_task->parent = current;
		new_task->offset = 0;
	}

	new_task->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ?
					child_tidptr : NULL;
	INIT_LIST_HEAD(&new_task->thread_group);

	/* Initialize TASK state to WAIT
	 * Change it to RUNNING when TASK is created
	 * and ready to be scheduled
	 */
	new_task->ve_task_state = WAIT;

	/* Initialize block_status with BLOCK_RECVD, so that
	 * this process can be scheduled successfully after it
	 * is scheduled for the  first time by the scheduler.
	 */
	new_task->block_status = BLOCK_RECVD;

	new_task->exec_time = 0;
	new_task->syncsignal = 0;
	new_task->execed_proc = false;

	if (clone_flags & CLONE_THREAD) {
		/* Add an entry of this thread in the thread group
		 * maintained by main thread
		 */
		list_add_tail(&new_task->thread_group,
				&new_task->group_leader->thread_group);
	} else {
		/* Add an entry of this process in its parent's children list */
		list_add_tail(&new_task->siblings,
				&new_task->parent->children);
		/* Add an entry of this process in INIT task list */
		pthread_spin_lock(&init_task_lock);
		list_add_tail(&new_task->tasks, &ve_init_task.tasks);
		pthread_spin_unlock(&init_task_lock);
	}

	if (clone_flags & CLONE_THREAD) {
		/* updating thread count and offset starts here */
		pthread_mutex_lock(&new_task->group_leader->offset_lock);

		new_task->offset = find_shared_page_offset(new_task->
							group_leader);
		if (new_task->offset == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"No new thread creation is allowed\n");
			pthread_mutex_unlock(&new_task->group_leader->
						offset_lock);
			goto free_mm_struct;
		}

		pthread_mutex_unlock(&new_task->group_leader->offset_lock);
		/* updating thread count and offset ends here */
	}

	/* Set return value registers for new_task
	 * Set SR00 to "0" as new process gets return value as "0"
	 * Set SR01 to offset, this value is used by VE programs to
	 * store system call argument on SHM area
	 */
	new_task->p_ve_thread->SR[0] = 0;
	new_task->p_ve_thread->SR[1] = new_task->offset;
	fork_info->offset = new_task->offset;

	if (0 != pthread_mutex_init(&(new_task->ve_task_lock), NULL)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init failed\n");
		goto free_mm_struct;
	}
	if (0 != pthread_mutex_init(&(new_task->siglock), NULL)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init failed\n");
		goto free_mm_struct;
	}
	goto hndl_return;

free_mm_struct:
	amm_del_mm_struct(&new_task->p_ve_mm, current->node_id);
free_sighand:
	free(new_task->sighand);
free_new_task:
	free(new_task->p_ve_thread);
	free(new_task);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return NULL;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return new_task;
}

/**
 * @brief Handles fork/clone request for VE processes.
 * @detail Creates the new VE process as requested by the fork/clone
 * system call.
 *
 * @param[in] clone_flags clone_flags as recevied in system call
 * @param[in] stack_start starting of VE process stack
 * @param[in] stack_size VE process stack size
 * @param[in] parent_tidptr VE task child TID pointer
 * @param[in] child_tidptr VE task parent TID pointer
 * @param[in] fork_info fork/clone related information
 *
 * @return core id on success, -1 on failure.
 */
int do_ve_fork(unsigned long clone_flags,
		unsigned long stack_start,
		unsigned long stack_size,
		int *parent_tidptr,
		int *child_tidptr,
		struct ve_fork_info *fork_info)
{
	int retval = -1;
	struct ve_task_struct *new_task;
	int child_core_id = -1;
	int child_node_id = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!fork_info)
		goto hndl_return;

	/* prepare task_struct for VE */
	new_task = copy_ve_process(clone_flags,
				stack_start,
				stack_size,
				child_tidptr,
				fork_info);
	if (new_task) {
		if (clone_flags & CLONE_PARENT_SETTID) {
			/* we are tackling this from pseudo process as we don't
			 * have vedl handle here and we need to send tid on the
			 * address contained in parent_tidptr
			 */
		}

		retval = get_ve_core_n_node_new_ve_proc(new_task,
				&child_node_id,
				&child_core_id);
		if (-1 == retval) {
			/* Temporarily insert task to node "0" core "0"
			 * and invoke psm_handle_delete_ve_process()
			 */
			child_node_id = 0;
			child_core_id = 0;
			new_task->p_ve_core =
				VE_CORE(child_node_id, child_core_id);

			insert_ve_task(child_node_id, child_core_id, new_task);
			psm_handle_delete_ve_process(fork_info->child_pid,
							0, -1);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"do_ve_fork failed\n");
			return retval;
		}

		fork_info->node_id = new_task->node_id = child_node_id;
		fork_info->core_id = new_task->core_id = child_core_id;
		new_task->p_ve_core = VE_CORE(child_node_id, child_core_id);

		/* Inserting VE task into VE Node and Core */
		insert_ve_task(child_node_id, child_core_id, new_task);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"copy_ve_process failed\n");
		retval = -1;
		goto hndl_return;
	}

	/* Create VE process structure on driver server */
	retval = vedl_create_ve_process(VE_NODE(child_node_id)->handle,
					fork_info->child_pid);
	if (retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_create_ve_process failed.\n");
		/* Here the failure can be encountered for either process
		 * or thread; passing "0" in psm_handle_delete_ve_process
		 * means cleaning up that particular task and passing "1"
		 * means cleaning up all the tasks.
		 */
		psm_handle_delete_ve_process(fork_info->child_pid, 0, -1);
		retval = -1;
		goto hndl_return;
	}

	if (!(clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_VFORK)) {
		/* Get SHM/LHM area */
#ifdef __AUSIM_ENV
		retval = psm_init_shared_file_mmap(new_task);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"SHM/LHM area allocation failed\n");
			psm_handle_delete_ve_process(fork_info->child_pid, 0, -1);
			retval = -1;
			goto hndl_return;
		}
#else
		/* Attach to the above allocated shared memory segment */
		new_task->sighand->lshm_addr =
			(uint64_t)shmat(fork_info->shmid, NULL, 0);
		if ((void *)-1 == (void *)new_task->sighand->lshm_addr) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"shmat() %s\n", strerror(errno));
			retval = -1;
			psm_handle_delete_ve_process(fork_info->child_pid, 0, -1);
			goto hndl_return;
		}
#endif
		new_task->p_ve_mm->shm_lhm_addr = fork_info->shm_lhm_addr;
	}
	/* If all successful, return the core ID assigned
	 * to newly created VE process/VE thread */
	retval = child_core_id;

	if (clone_flags & CLONE_VFORK) {
		new_task->vforked_proc = true;
		new_task->parent->vfork_state = VFORK_ONGOING;
		new_task->p_ve_mm->shm_lhm_addr =
			new_task->parent->p_ve_mm->shm_lhm_addr;
	}

	VE_NODE(child_node_id)->total_forks++;
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
