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
 * @file  clone_handler.c
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

#include "task_mgmt.h"
#include "ve_clone.h"
#include "task_signal.h"
#include "velayout.h"
#include "task_sched.h"
#include "ve_mem.h"
#include "cr_api.h"
#include "locking_handler.h"

#include <veos_arch_defs.h>

/**
 * @brief Updates task thread_struct based on values received from
 * loader interface.
 *
 * @param[in] context_info Info recevied from loader interface
 * @param[in,out] thread_struct Task's thread_struct to which values are updated
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int update_ve_thread_node(const struct ve_context_info *context_info,
			struct ve_thread_struct *thread_struct)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!context_info || !thread_struct) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* set program counter, stack pointer and frame pointer */
	(*_veos_arch_ops->arch_psm_update_thread_struct)(thread_struct->arch_user_regs,
						context_info);

	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Copy the values of parent ve_task_struct into the newly created task.
 *
 * @param[out] dst Pointer to destination VE task struct
 * @param[in] src Pointer of source VE task struct
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int arch_dup_ve_task_struct(struct ve_task_struct *dst,
		struct ve_task_struct *src)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!dst || !src) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	/* copy parent task structure to child task structure */
	*dst = *src;
	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Copy the values of parent thread struct to newly created thread struct.
 *
 * @param[out] dst Pointer to destination thread struct
 * @param[in] src Pointer to source thread struct
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int arch_dup_ve_thread_struct(struct ve_thread_struct *dst,
				const struct ve_thread_struct *src)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!dst || !src) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}
	dst->EXS = src->EXS;
	(*_veos_arch_ops->arch_psm_copy_user_regs_in_thread_struct)(
				dst->arch_user_regs, src->arch_user_regs);
	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Duplicates the necessary attributes for ve_task_struct for VE process.
 *
 * @param[in] current Pointer to VE task struct
 *
 * @return Pointer to ve_task_struct on success, on failure, NULL is returned
 * 	and errno is set to indicate the error value.
 *
 * @internal
 * @author PSMG / MP-MT
 */
struct ve_task_struct *dup_ve_task_struct(struct ve_task_struct *current)
{
	struct ve_task_struct *task = NULL;
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!current) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	task = alloc_ve_task_struct_node();
	if (!task) {
		VEOS_ERROR("Failed to allocate memory to task structure");
		goto hndl_return;
	}

	/* populate the new ve_task_struct with the values of
	 * parent task_struct
	 */
	if (arch_dup_ve_task_struct(task, current) != 0) {
		VEOS_ERROR("Failed to duplicate task structure");
		goto free_tsk_1;
	}

	/* Allocate memory for pmc_pmmr and initial_pmc_pmmr variables
	 * of ve_task_struct */
	retval = alloc_pmc_pmmr(task);
	if (retval != 0) {
		VEOS_ERROR("Failed to allocate memory for PMC PMMR");
		goto free_tsk_1;
	}

	/* allocate ve_thread_struct structure */
	task->p_ve_thread = alloc_ve_thread_struct_node();
	if (!task->p_ve_thread) {
		VEOS_ERROR("Failed to allocate memory to thread structure");
		goto free_pmc_pmmr;
	}

	if (0 != pthread_mutex_init(&(task->offset_lock), NULL)) {
		VEOS_ERROR("Failed to initialize mutex");
		goto free_tsk_2;
	}

	VEOS_TRACE("Exiting");
	return task;
free_tsk_2:
	free_ve_thread_struct(task->p_ve_thread);
free_pmc_pmmr:
	(*_veos_arch_ops->arch_psm_free_pmc_pmmr)(task);
free_tsk_1:
	free(task);
hndl_return:
	VEOS_TRACE("Exiting");
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
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int copy_ve_mm(struct ve_task_struct *current, unsigned long clone_flags,
		struct ve_task_struct *new_tsk)
{
	int retval = -ENOMEM;
	struct ve_mm_struct *mm = NULL, *oldmm = NULL;

	VEOS_TRACE("Entering");

	if (!current || !new_tsk) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	new_tsk->p_ve_mm = NULL;
	oldmm = current->p_ve_mm;
	if (!oldmm) {
		VEOS_ERROR("NULL argument(oldmm) received");
		goto hndl_return;
	}

	if (clone_flags & CLONE_VFORK) {
		VEOS_DEBUG("CLONE_VFORK set");
		retval = amm_copy_mm_struct(oldmm, &mm,
				REQUEST_FOR_VFORK_PROCESS,
				current->numa_node);
		if (0 != retval) {
			VEOS_ERROR("Failed to copy memory structure from "
					"parent to child");
			retval = -ENOMEM;
			goto hndl_return;
		}
		new_tsk->p_ve_mm = mm;
		retval = 0;
		goto hndl_return;
	}

	/* If CLONE_VM flag, use the same mm_struct as of the parent */
	if (clone_flags & CLONE_VM) {
		VEOS_DEBUG("CLONE_VM set");
		/* Share mm_struct between child and parent */
		amm_copy_mm_struct(oldmm, &mm,
					REQUEST_FOR_PROCESS_SHARED,
					current->numa_node);
		new_tsk->p_ve_mm = mm;
		new_tsk->atb_dirty = 0xffffffff;
		new_tsk->crd_dirty = true;
		retval = 0;
		goto hndl_return;
	}

	/* Create mm_struct for child and copy data from parent */
	retval = amm_copy_mm_struct(oldmm, &mm,
			REQUEST_FOR_PROCESS_PRIVATE,
			current->numa_node);
	if (0 != retval) {
		VEOS_ERROR("Failed to copy memory structure from "
				"parent to child");
		retval = -ENOMEM;
		goto hndl_return;
	}

	new_tsk->p_ve_mm = mm;
	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
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
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int copy_ve_thread(struct ve_task_struct *current,
		unsigned long clone_flags,
		unsigned long sp,
		unsigned long arg,
		struct ve_task_struct *new_tsk)
{
	int retval = -ENOMEM;
	struct ve_task_struct *task_on_core = NULL;
	ve_reg_t pef_rst_mask = (*_veos_arch_ops->arch_psm_clear_PEF_in_PSW_mask)();
	ve_dma_status_t dma_status = 0;
	struct ve_node_struct *p_ve_node = NULL;
	pid_t veos_pid = getpid();

	VEOS_TRACE("Entering");

	if (!new_tsk || !current) {
		VEOS_ERROR("Either parent or child or node structure is NULL");
		goto hndl_return;
	}
	p_ve_node = VE_NODE(current->node_id);

	pthread_rwlock_lock_unlock(&(VE_CORE(current->node_id, current->core_id)
			->ve_core_lock), RDLOCK,
			"Failed to acquire core read lock");

	task_on_core = VE_CORE(current->node_id,
				 current->core_id)->curr_ve_task;
	if (current == task_on_core) {
		VEOS_DEBUG("Task %d is currently scheduled on core",
				current->pid);
		/* Fetching Register values using VE driver handle */
		dma_status = (*_veos_arch_ops
				->arch_psm_save_context_from_core_reg)(
					p_ve_node->dh,
					current->p_ve_core->phys_core_num,
					veos_pid,
					new_tsk->p_ve_thread->arch_user_regs);
		if (dma_status != VE_DMA_STATUS_OK) {
			VEOS_ERROR("Failed to get the register values");
			pthread_rwlock_lock_unlock(&(VE_CORE(current->node_id,
					current->core_id)->ve_core_lock),
					UNLOCK,	"Failed to release "
					"core lock");
			retval = -EAGAIN;
			goto hndl_return;
		} else {
			/*Setting PEF bits to 0 in child*/
			ve_reg_t oldpsw = (*_veos_arch_ops->
				arch_psm_get_PSW_from_thread_struct)(
					new_tsk->p_ve_thread->arch_user_regs);
			(*_veos_arch_ops->arch_psm_set_PSW_on_thread_struct)(
				new_tsk->p_ve_thread->arch_user_regs,
				oldpsw & pef_rst_mask);
			update_accounting_data(current, ACCT_TRANSDATA,
				(*_veos_arch_ops
					->arch_psm_get_context_size)() /
					(double)1024);
		}
	} else {
		VEOS_DEBUG("Copying parent's (%d) p_ve_thread",	current->pid);

		retval = arch_dup_ve_thread_struct(new_tsk->p_ve_thread,
				current->p_ve_thread);
		if (retval != 0) {
			VEOS_ERROR("Failed to duplicate the thread structure");
			retval = -EAGAIN;
			goto hndl_return;
		}
	}

	pthread_rwlock_lock_unlock(&(VE_CORE(current->node_id, current->core_id)
		->ve_core_lock), UNLOCK,
		"Failed to release core lock");

	if (clone_flags & CLONE_SETTLS)
		(*_veos_arch_ops->arch_psm_set_child_tls_desc)(
				new_tsk->p_ve_thread->arch_user_regs,
				new_tsk->p_ve_thread->arch_user_regs);

	if (sp)
		(*_veos_arch_ops->arch_psm_set_stack_pointer_on_thread_struct)(
				new_tsk->p_ve_thread->arch_user_regs, sp);

	VEOS_DEBUG("IC : %lx",
		(*_veos_arch_ops->
			arch_psm_get_program_counter_from_thread_struct)(
				new_tsk->p_ve_thread->arch_user_regs));
	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
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
 * @return 0 on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int copy_ve_sighand(struct ve_task_struct *current,
		unsigned long clone_flags,
		struct ve_task_struct *new_task)
{
	int retval = -ENOMEM;

	VEOS_TRACE("Entering");

	if (!current || !new_task) {
		VEOS_ERROR("Invalid(NULL) argument received");
		goto hndl_return;
	}

	/* In case of thread signal handler structure will be shared.
	 * and reference count of sighand strcuture will be incremented.
	 * In case of process.Create  new signal handler strcuture and copy
	 * the sigaction structure of parent process
	 */
	if (clone_flags & CLONE_SIGHAND) {
		pthread_mutex_lock_unlock(&(current->sighand->siglock), LOCK,
			"Failed to acquire task sighand lock [PID: %d]",
			current->pid);
		current->sighand->ref_count++;
		new_task->sighand = current->sighand;
		pthread_mutex_lock_unlock(&(current->sighand->siglock), UNLOCK,
			"Failed to release task sighand lock  [PID: %d]",
			current->pid);
		retval = 0;
		goto hndl_return;
	}

	new_task->sighand = alloc_ve_sighand_struct_node();
	if (!new_task->sighand) {
		retval = -errno;
		VEOS_ERROR("Failed to get address for sighand structure");
		goto hndl_return;
	}

	memcpy(new_task->sighand->action, current->sighand->action,
			sizeof(new_task->sighand->action));
	memcpy(new_task->sighand->rlim, current->sighand->rlim,
			sizeof(new_task->sighand->rlim));
	if (!(clone_flags & CLONE_THREAD)) {
		VEOS_DEBUG("Reinitialization for maximum threads");
		(*_veos_arch_ops->arch_psm_reinitialize_acct)(new_task);
	}

	retval = 0;

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Calculates the offset on the shared page to be assigned to a
 * newly created thread.
 *
 * @param[in] parent_struct VE task struct of the parent thread
 *
 * @return offset on success, -1 on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int find_shared_page_offset(struct ve_task_struct *parent_struct)
{
	int index = 0, temp = 0;
	struct ve_task_struct *child_task_struct = NULL;
	int offset_arr[VEOS_MAX_VE_THREADS] = {0};

	VEOS_TRACE("Entering");

	if (!parent_struct) {
		VEOS_ERROR("Invalid(NULL) argument received");
		index = -1;
		goto hndl_return;
	}

	memset(offset_arr, 0, sizeof(int) * VEOS_MAX_VE_THREADS);

	/* Hierarchy: offset_lock -> thread_group_mm_lock */
	VEOS_DEBUG("Acquiring thread group lock for PID %d",
			parent_struct->pid);
	pthread_mutex_lock_unlock(&parent_struct->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");

	list_for_each_entry(child_task_struct, &(parent_struct->thread_group),
			thread_group) {
		temp = child_task_struct->offset / VEOS_MAX_VE_THREADS;
		offset_arr[temp] = child_task_struct->pid;
	}

	pthread_mutex_lock_unlock(&parent_struct->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");

	for (index = 1; index <= (VEOS_MAX_VE_THREADS - 1); index++) {
		if (offset_arr[index] == 0)
			break;
	}

	if (index == VEOS_MAX_VE_THREADS) {
		VEOS_ERROR("Reached max limit, Cannot create more threads");
		index = -1;
		goto hndl_return;
	}

	index = index * VEOS_MAX_VE_THREADS;

hndl_return:
	VEOS_TRACE("Exiting");
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
 * @return Pointer to VE task struct on success, on failure, NULL is returned
 * 		and errno variable is set to appropriate negative error number.
 *
 * @internal
 * @author PSMG / MP-MT
 */
struct ve_task_struct *copy_ve_process(unsigned long clone_flags,
		unsigned long stack_start,
		unsigned long stack_size,
		int *child_tidptr,
		struct ve_fork_info *fork_info,
		struct ve_task_struct *current)
{
	struct ve_task_struct *new_task = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	ve_reg_t regdata = 0;
	int retval = -1, ret = -1;

	VEOS_TRACE("Entering");

	p_ve_core = VE_CORE(current->node_id, current->core_id);
	if (!fork_info) {
		VEOS_ERROR("Invalid(NULL) argument received");
		retval = -ENOMEM;
		goto hndl_return;
	}


	/*Copying veshm information into task struct of parent.*/
	if (fork_info->veshm) {
		pthread_mutex_lock_unlock(&current->p_ve_mm->thread_group_mm_lock,
				LOCK,
				"Failed to acquire thread-group-mm-lock [PID: %d]",
				current->pid);
		memcpy(&(current->p_ve_mm->veshm), fork_info->veshm,
				sizeof(current->p_ve_mm->veshm));
		pthread_mutex_lock_unlock(&current->p_ve_mm->thread_group_mm_lock,
				UNLOCK,
				"Failed to release thread-group-mm-lock [PID: %d]",
				current->pid);
	}

	/* Call dup_ve_task_struct to allocate new ve_task_struct and
	 * ve_thread_struct. Duplicate its entry for the child
	 * VE process.
	 */
	new_task = dup_ve_task_struct(current);
	if (!new_task) {
		VEOS_ERROR("Failed to duplicate task structure for child");
		retval = -ENOMEM;
		goto hndl_return;
	}

	/* Stores the PID of the Child VE process in the ve_task_struct
	 * just allocated.
	 */
	new_task->pid = fork_info->child_pid;
	new_task->namespace_pid = fork_info->child_namespace_pid;

	new_task->thread_execed = false;
	new_task->vforked_proc = false;
	new_task->wake_up_parent = false;
	new_task->rpm_preserve_task = 0;

	/* Initialize the data for VE worker thread */
	new_task->ve_set_next_thread_worker = false;
	new_task->ve_task_worker_belongs = NULL;
	new_task->ve_task_worker_belongs_chg = false;
	new_task->ve_task_have_worker = false;
	new_task->ve_worker_thread = NULL;

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
	INIT_LIST_HEAD(&(new_task->p_ve_mm->swapped_pages));
	ve_init_sigpending(&(new_task->pending));

	/*setting signal related fields in child process*/
	new_task->sigpending = 0;

	/* Allocate time slice to VE task, however when scheduled
	 * this value will be initialised again. We are initializing it
	 * so that it does not contain any junk value. */
	new_task->time_slice = VE_ATOMIC_GET(int64_t, &veos_time_slice);
	/* new_task is not created on driver yet, hence set flag to false*/
	new_task->is_crt_drv = false;
	new_task->is_dlt_drv = false;

	/* Save the parents's user context before copying the copy parent's
	 * PMC data to child process. */
	pthread_rwlock_lock_unlock
		(&(current->p_ve_core->ve_core_lock), WRLOCK,
		 "Failed to acquire core lock");
	if (current->reg_dirty == true) {
		psm_halt_ve_core(p_ve_core->node_num, p_ve_core->core_num,
				&regdata, false, true);
		psm_save_current_user_context(current);
	}
	pthread_rwlock_lock_unlock
		(&(current->p_ve_core->ve_core_lock), UNLOCK,
		 "Failed to release core lock");

	/*copy parent's PMMR,PMC data to child process*/
	//for(i = 0; i < PMC_REG; i++)
	//	new_task->initial_pmc_pmmr[i] =
	//		(*_veos_arch_ops->arch_get_parent_pmmr_pmc)(current->p_ve_thread->arch_user_regs, i);
		// new_task->initial_pmc_pmmr[i] = current->p_ve_thread->arch_user_regs->PMC[i];
	(*_veos_arch_ops->arch_psm_initialize_pmc)(new_task, current);

	if (!(clone_flags & CLONE_THREAD)) {
		VEOS_DEBUG("Setting private members in child to NULL");
		new_task->flags |= PF_FORKNOEXEC;
		new_task->tgid = new_task->pid;
		new_task->exit_signal = 0;
		new_task->group_leader = new_task;
		new_task->real_parent = current;
		new_task->parent = current->group_leader;
		new_task->offset = clone_flags & CLONE_VFORK ?
			current->offset : 0;
		new_task->udma_context = NULL;
		new_task->core_dma_desc = NULL;
		new_task->ived_resource = NULL;
		new_task->ipc_sync = NULL;
		new_task->thread_sched_count = NULL;
		new_task->thread_sched_bitmap = NULL;
		new_task->thread_core_bitmap = NULL;
	}

	if (clone_flags & CLONE_VFORK) {
		new_task->vforked_proc = true;
		new_task->wake_up_parent = true;
		new_task->real_parent->vfork_state = VFORK_ONGOING;
	}

	/* sigaltstack should be cleared when sharing the same VM
	 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		new_task->sas_ss_sp = new_task->sas_ss_size = 0;

	/* Create the new process signal handler structure
	 * based upon CLONE flags
	 */
	retval = copy_ve_sighand(current, clone_flags, new_task);
	if (0 > retval) {
		VEOS_ERROR("Failed to create sighand structure");
		goto free_new_task;
	}
	/* Creating the process address space by setting up all ATB entries
	 * and memory descriptors for the new VE process with the help of AMM.
	 */
	retval = copy_ve_mm(current, clone_flags, new_task);
	if (0 > retval) {
		VEOS_ERROR("Failed to create memory structure");
		goto free_sighand;
	}

	/* Process Context creation for the child process */
	retval = copy_ve_thread(current,
				clone_flags,
				stack_start,
				stack_size,
				new_task);
	if (0 > retval) {
		VEOS_ERROR("Failed to create context information");
		goto free_mm_struct;
	}

	if (clone_flags & CLONE_THREAD) {
		new_task->exit_signal = -1;
		new_task->group_leader = current->group_leader;
		new_task->ipc_sync = new_task->group_leader->ipc_sync;
		new_task->parent = current->parent;
		(*_veos_arch_ops->arch_psm_set_stack_pointer_on_thread_struct)(
			new_task->p_ve_thread->arch_user_regs, stack_start);
	} else {

		/*CR process dump file name*/
		sprintf(new_task->p_ve_mm->cr_dump_fname,
			"/tmp/cr_dump_task_%d", new_task->pid);

		/* In case of process creation allocate and intialize the
		 * memory for DMA descriptor, control register, core_dma_desc
		 * */
		retval = alloc_ve_task_data(new_task);
		if (0 > retval) {
			VEOS_ERROR("Failed to allocate memory");
			if (-EAGAIN == retval) {
				VEOS_DEBUG("Resource temporarily unavailable, return value %d"
						, retval);
			} else {
				VEOS_DEBUG("Failed to allocate memory, return value %d,"
						" mapped value %d", retval, -ENOMEM);
				retval = -ENOMEM;
			}
			goto free_mm_struct;
		}
	}

	new_task->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ?
					child_tidptr : NULL;
	new_task->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ?
					child_tidptr : NULL;
	INIT_LIST_HEAD(&new_task->thread_group);

	/* Initialize TASK state to WAIT
	 * Change it to RUNNING when TASK is created
	 * and ready to be scheduled
	 */
	new_task->ve_task_state = WAIT;

	new_task->ref_count = 0;
	new_task->exit_code = 0;
	new_task->exit_status = 0;
	new_task->exit_code_set = false;
	new_task->reg_dirty = false;
	new_task->invalidate_branch_history = true;

	/* Initialize block_status with BLOCK_RECVD, so that
	 * this process can be scheduled successfully after it
	 * is scheduled for the  first time by the scheduler.
	 */
	new_task->block_status = BLOCK_RECVD;

	new_task->exec_time = 0;
	new_task->syncsignal = 0;
	new_task->execed_proc = false;
	new_task->cpu_lim_exceed = false;

	new_task->ve_sched_state = VE_THREAD_STARTED;

	if (clone_flags & CLONE_THREAD) {
		/* Add an entry of this thread in the thread group
		 * maintained by main thread
		 * Take thread group lock to prevent any race
		 */
		VEOS_DEBUG("Acquiring tasklist_lock");
		pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
				"Failed to acquire tasklist_lock lock");

		VEOS_DEBUG("Acquiring thread group lock");
		pthread_mutex_lock_unlock(&new_task->p_ve_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");
		if (new_task->sighand->signal_flag
				== VE_SIGNAL_GROUP_COREDUMP) {
			VEOS_DEBUG("Coredumping is ongoing: %d",
					new_task->pid);
			retval = -EAGAIN;
			pthread_mutex_lock_unlock
				(&new_task->p_ve_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release"
				" thread-group-mm-lock");

			pthread_mutex_lock_unlock
				(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
					"Failed to release tasklist_lock"
					" lock");
			goto free_mm_struct;
		}

		pthread_mutex_lock_unlock(&new_task->p_ve_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release thread-group-mm-lock");

		pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
				"Failed to release tasklist_lock lock");

	}

	if (clone_flags & CLONE_THREAD) {
		/* updating thread count and offset starts here */
		pthread_mutex_lock_unlock(&new_task->group_leader->offset_lock,
				LOCK, "Failed to acquire task offset lock [PID: %d]",
				current->pid);
		new_task->offset = find_shared_page_offset(new_task->
							group_leader);
		if (new_task->offset == -1) {
			VEOS_ERROR("No new thread creation is allowed");
			pthread_mutex_lock_unlock(
				&new_task->group_leader->offset_lock,
				UNLOCK,
				"Failed to releaes task offset lock [PID: %d]",
				current->pid);
			retval = -EAGAIN;
			goto free_mm_struct;
		}

		pthread_mutex_lock_unlock(&new_task->group_leader->offset_lock,
			UNLOCK,	"Failed to releaes task offset lock [PID: %d]",
			current->pid);
		/* updating thread count and offset ends here */
	}

	/* Set return value registers for new_task
	 * Set SR00 to "0" as new process gets return value as "0"
	 */
	(*_veos_arch_ops->arch_psm_set_retval_on_thread_struct)(
			new_task->p_ve_thread->arch_user_regs, 0);
	new_task->p_ve_thread->EXS = 0;
	fork_info->offset = new_task->offset;

	if (0 != pthread_mutex_init(&(new_task->ve_task_lock), NULL)) {
		VEOS_ERROR("Failed to initialize task lock");
		retval = -ENOMEM;
		goto free_mm_struct;
	}
	if (0 != pthread_mutex_init(&(new_task->ptrace_lock), NULL)) {
		VEOS_ERROR("Failed to initialize ptrace lock");
		retval = -ENOMEM;
		goto destroy_mutex;
	}
	if (0 != pthread_cond_init(&(new_task->ref_lock_signal), NULL)) {
		VEOS_ERROR("Conditional lock initialization failed");
		retval = -errno;
		goto destroy_mutex2;
	}
	if (0 != pthread_mutex_init(&(new_task->ref_lock), NULL)) {
		VEOS_ERROR("Failed to intialize tast reference lock");
		retval = -errno;
		goto destroy_mutex2;
	}
	/* when VE Parent process is traced */
	if (current->ptraced == true) {
		VEOS_DEBUG("Parent pid: %d is traced", current->pid);

		current->p_ve_ptrace->ptrace_message = new_task->namespace_pid;

		VEOS_DEBUG("Child pid: %d is set untraced", new_task->pid);

		/* In VE enviornment if parent process is traced then
		 * tracing of child process will be initiated by VE tracer.
		 */
		new_task->ptraced = false;
		new_task->p_ve_ptrace = NULL;
	}
	goto hndl_return;

destroy_mutex2:
	ret = pthread_mutex_destroy(&(new_task->ptrace_lock));
	if (ret != 0) {
		VEOS_ERROR("Failed to destroy ptrace lock");
		VEOS_DEBUG("Failed to destroy ptrace lock, return value %d",
				-ret);
	}
destroy_mutex:
	ret = pthread_mutex_destroy(&(new_task->ve_task_lock));
	if (ret != 0) {
		VEOS_ERROR("Failed to destroy task lock");
		VEOS_DEBUG("Failed to destroy task lock, return value %d",
				-ret);
	}

free_mm_struct:
	amm_del_mm_struct(new_task);
free_sighand:
	psm_del_sighand_struct(new_task);
free_new_task:
	if((clone_flags & CLONE_VFORK) &&
			(new_task->real_parent->vfork_state == VFORK_ONGOING))
		new_task->real_parent->vfork_state = VFORK_C_INVAL;
	ret = pthread_mutex_destroy(&(new_task->offset_lock));
	if (ret != 0) {
		VEOS_ERROR("Failed to destroy offset lock");
		VEOS_DEBUG("Failed to destroy offset lock, return value %d",
				-ret);
	}
	free_ve_thread_struct(new_task->p_ve_thread);
	free(new_task);
	VEOS_TRACE("Exiting");
	errno = -retval;
	return NULL;
hndl_return:
	VEOS_TRACE("Exiting");
	errno = -retval;
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
 * @return core id on success, negative errno on failure.
 *
 * @internal
 * @author PSMG / MP-MT
 */
int do_ve_fork(unsigned long clone_flags,
		unsigned long stack_start,
		unsigned long stack_size,
		int *parent_tidptr,
		int *child_tidptr,
		struct ve_fork_info *fork_info)
{
	int retval = -1;
	struct ve_task_struct *new_task = NULL;
	struct ve_task_struct *current = NULL;
	struct ve_ipc_sync *ipc_sync = NULL;
	int child_core_id = -1;
	int child_node_id = -1;
	bool is_need_sync_pps = false;

	VEOS_TRACE("Entering");

	if (!fork_info) {
		VEOS_ERROR("Invalid(NULL) argument received "
				"from pseudo process");
		retval = -ENOMEM;
		goto hndl_return;
	}
	if (VE_NODE(0)->num_ve_proc >= MAX_TASKS_PER_NODE) {
		VEOS_ERROR("Reached maximum(%d) VEOS tasks limit",
				MAX_TASKS_PER_NODE);
		retval = -EAGAIN;
		goto hndl_return;
	}
	new_task = find_ve_task_struct(fork_info->child_pid);
	if (NULL != new_task) {
		VEOS_ERROR("Duplicate process with PID %d is : %p"
				" Core : %d binary : %s already exists. "
				"Failed to create new task due to PID conflict",
				fork_info->child_pid, new_task,
				new_task->core_id, new_task->ve_comm);
		put_ve_task_struct(new_task);
		/* PID conflict occurs at VEOS. This is a race scenario wherein VEOS
		 * contains entry for VE task but correponding pseudo was earlier freed
		 * */
		new_task = NULL;
		retval = -EAGAIN;
		goto hndl_return;
	}

	/* To find Parent process current CORE and Node */
	current = find_ve_task_struct(fork_info->parent_pid);
	if (NULL == current) {
		VEOS_ERROR("Failed to find task structure");
		VEOS_ERROR("Failed to fetch task structure for PID: %d",
				fork_info->parent_pid);
		retval = -ENOMEM;
		goto hndl_return;
	}
	VEOS_DEBUG("PARENT with PID %d is : %p "
			"Parent Node : %d Parent Core : %d",
			fork_info->parent_pid, current,
			current->node_id, current->core_id);

	ipc_sync = ve_get_ipc_sync(current);
	if (ipc_sync != NULL) {
		is_need_sync_pps = true;
		pthread_mutex_lock_unlock(
				&(ipc_sync->swap_exclusion_lock), LOCK,
				"Failed to aqcuire swap_exclusion_lock");
		while(ipc_sync->swapping != 0) {
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

	/* Duplicate task structure for new child process */
	new_task = copy_ve_process(clone_flags,	stack_start, stack_size,
					child_tidptr, fork_info, current);
	if (new_task == NULL) {
		retval = -errno;
		VEOS_ERROR("Failed to create new task structure");
		VEOS_DEBUG("Creation of task structure failed for PID: %d",
				fork_info->child_pid);
		goto hndl_return;
	}
	if (clone_flags & CLONE_PARENT_SETTID) {
		/* store child PID in parent memory */
		retval = amm_send_data(fork_info->parent_pid,
				(vemva_t)parent_tidptr, sizeof(pid_t),
				&(new_task->namespace_pid));
		if (0 != retval) {
			VEOS_ERROR("Failed to store child PID in "
					"parent memory");
			retval = -ENOMEM;
			goto hndl_return2;
		}
	}

	if (!(clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_VFORK)) {
		/* map the LHM/SHM area of pseudo process in veos */
		retval = psm_map_lhm_shm_area(new_task, fork_info->node_id,
				fork_info->sfile_name, fork_info->shm_lhm_addr);
		if (retval < 0) {
			VEOS_ERROR("Failed to map syscall args file");
			VEOS_DEBUG("Failed to map syscall args file return value "
					"%d, mapped value %d",
					retval, -ENOMEM);
			retval = -ENOMEM;
			goto hndl_return2;
		}
	}
	if (clone_flags & CLONE_VFORK) {
		new_task->p_ve_mm->shm_lhm_addr =
			new_task->parent->p_ve_mm->shm_lhm_addr;
		new_task->p_ve_mm->shm_lhm_addr_vhsaa =
			new_task->parent->p_ve_mm->shm_lhm_addr_vhsaa;
		new_task->sighand->lshm_addr =
			new_task->parent->sighand->lshm_addr;
	}
	/* #2274
	 * Acquire task reference to avoid its parallel deletion from polling
	 * thread if its pseudo process is killed before the clone/fork request
	 * is completed.
	 */
	VEOS_DEBUG("Getting the task reference lock of the new task");
	get_ve_task_struct(new_task);

	new_task->assign_task_flag = TSK_UNASSIGN;
	VEOS_DEBUG("Acquiring tasklist_lock");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
				"Failed to acquire tasklist_lock lock");
	if (clone_flags & CLONE_THREAD) {
		VEOS_DEBUG("Acquiring thread group lock");
		pthread_mutex_lock_unlock(&new_task->p_ve_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");
		pthread_mutex_lock_unlock(&(current->ve_task_lock), LOCK,
				"Failed to acquire ve_task lock [PID: %d]",
				current->pid);
		if (current->ve_task_state == STOP && current->sstatus == ACTIVE) {
			new_task->ve_task_state = STOP;
			new_task->sstatus = ACTIVE;
		}
		if (current->ve_sched_state != VE_THREAD_STARTED)
			new_task->ve_sched_state = VE_THREAD_STOPPED;

		pthread_mutex_lock_unlock(&(current->ve_task_lock), UNLOCK,
				"Failed to release ve_task lock [PID: %d]",
				current->pid);
		list_add_tail(&new_task->thread_group,
				&new_task->group_leader->thread_group);
		pthread_mutex_lock_unlock(&new_task->p_ve_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release thread-group-mm-lock");
	} else {
		/* Add an entry of this process in its parent's children list */
		list_add_tail(&new_task->siblings, &new_task->parent->children);
	}
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
				"Failed to release tasklist_lock lock");

	if (!(clone_flags & CLONE_THREAD)) {
		/* Add an entry of this process in INIT task list */
		pthread_rwlock_lock_unlock(&init_task_lock, WRLOCK,
					"Failed to acquire init_task write lock");
		list_add_tail(&new_task->tasks, &ve_init_task.tasks);
		pthread_rwlock_lock_unlock(&init_task_lock, UNLOCK,
					"Failed to release init_task lock");
	}
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), LOCK,
				"Failed to acquire VE node mutex lock");

	if ((clone_flags & CLONE_THREAD) &&
				(current->ve_set_next_thread_worker == true)) {
		/* Set data for VE worker thread
		 *
		 */
		pthread_mutex_lock_unlock(&(current->ve_task_lock), LOCK,
			"Failed to acquire ve_task lock [PID: %d]",
			current->pid);
		if ((current->ve_task_worker_belongs != NULL) ||
			(current->ve_task_worker_belongs_chg) ||
				current->ve_task_have_worker == true){
			pthread_mutex_lock_unlock(&(current->ve_task_lock),
			UNLOCK, "Failed to release ve_task lock [PID: %d]",
				current->pid);
			/* Temporarily insert task to node "0" core "0"
			 * and invoke psm_handle_delete_ve_process()
			 */
			child_node_id = 0;
			child_core_id = 0;
			new_task->p_ve_core =
				VE_CORE(child_node_id, child_core_id);

			insert_ve_task(child_node_id, child_core_id, new_task);
			VEOS_ERROR("Failed to get the core and node for "
				"new process");
			pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock),
				UNLOCK, "Failed to release VE node mutex lock");
			retval = -EAGAIN;
			goto hndl_return1;
		}
		new_task->ve_task_worker_belongs = current;
		child_node_id = current->node_id;
		child_core_id = current->core_id;
		current->ve_task_have_worker = true;
		current->ve_worker_thread = new_task;
		current->ve_set_next_thread_worker = false;
		pthread_mutex_lock_unlock(&(current->ve_task_lock), UNLOCK,
			"Failed to release ve_task lock [PID: %d]",
				current->pid);
	}else{
		retval = get_ve_core_n_node_new_ve_proc(new_task,
				&child_node_id, &child_core_id,	&new_task->numa_node);
		if (retval < 0) {
			child_node_id = 0;
			child_core_id = 0;
			new_task->p_ve_core = VE_CORE(child_node_id, child_core_id);

			insert_ve_task(child_node_id, child_core_id, new_task);

			VEOS_ERROR("Failed to get the core and node for new process");
			pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), UNLOCK,
					"Failed to release VE node mutex lock");
			retval = -EAGAIN;
			goto hndl_return1;
		}
	}
	fork_info->core_id = new_task->core_id = child_core_id;
	new_task->p_ve_core = VE_CORE(child_node_id, child_core_id);

	/* Inserting VE task into VE Node and Core */
	insert_ve_task(child_node_id, child_core_id, new_task);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_node_lock), UNLOCK,
		"Failed to release VE node mutex lock");

	/*Update the thread offset in the libc thread descriptor area (TP + 0x18)*/
	retval = (*_veos_arch_ops->
			arch_psm_set_thread_descriptor_area_on_stack)(
				getpid(),
				new_task->offset, fork_info->child_pid,
				new_task->p_ve_thread->arch_user_regs);
	if (0 > retval) {
		VEOS_ERROR("Failed to update TLS offset");
		VEOS_DEBUG("Updation of TLS offset for child(pid:%d) failed",
				fork_info->child_pid);
		retval = -ENOMEM;
		goto hndl_return1;
	} else {
		update_accounting_data(new_task, ACCT_TRANSDATA,
					sizeof(uint64_t) / (double)1024);
	}

	/* Create VE process structure on driver
	 * #2274
	 * The reason behind creating the driver entry at the end is that,
	 * even if the corresponding pseudo process is killed by this time,
	 * the driver won't write its pid into task_id_dead file. This in
	 * turn prevents a scenario of parallel cleanup of the task initiated
	 * from polling thread while it's creation is still not complete.
	 * */

	retval = vedl_create_ve_task(VE_NODE(child_node_id)->handle,
					fork_info->child_pid);
	if (0 > retval) {
		VEOS_ERROR("Failed to create task structure in driver");
		VEOS_DEBUG("Failed to create task structure in driver, return "
				"value %d, mapped value %d", -errno, -EAGAIN);
		retval = -EAGAIN;
		goto hndl_return1;
	}
	/* task created on driver, set flag to true */
	new_task->is_crt_drv = true;
	/* If all successful, return the core ID assigned
	 * to newly created VE process/VE thread */
	retval = child_core_id;

	VE_NODE(child_node_id)->total_forks++;
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif
	goto hndl_return;
hndl_return2:
	VEOS_ERROR("Failed to create new ve task. "
			"Cleanup the partially created task");
	if((clone_flags & CLONE_VFORK) && new_task->real_parent &&
			(new_task->real_parent->vfork_state == VFORK_ONGOING))
		new_task->real_parent->vfork_state = VFORK_C_INVAL;
	amm_del_mm_struct(new_task);
	psm_del_sighand_struct(new_task);
	free(new_task->p_ve_thread);
	free(new_task);
	new_task = NULL;
	goto hndl_return;
hndl_return1:
	VEOS_ERROR("Failed to create new ve task. "
			"Cleanup the partially created task");
	if((clone_flags & CLONE_VFORK) && new_task->real_parent &&
			(new_task->real_parent->vfork_state == VFORK_ONGOING))
		new_task->real_parent->vfork_state = VFORK_C_INVAL;
	/* set exiting status of the partially created task to EXITING to
	 * trigger its deletion put_ve_task_struct() */
	set_state(new_task);
hndl_return:
	if (is_need_sync_pps) {
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
	if (current)
		put_ve_task_struct(current);
	if (new_task)
		put_ve_task_struct(new_task);
	VEOS_TRACE("Exiting");
	return retval;
}
