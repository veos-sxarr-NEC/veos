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
* @file  task_exit.c
* @brief Handles VE task deletion activities
*
* This contains the functions that are used to handle VE task
* deletion.
*
* @author PSMG
*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/shm.h>
#include "task_mgmt.h"
#include "mm_common.h"
#include "ve_mem.h"
#include "mm_stat.h"
#include "cr_api.h"
#include "veos.h"
#include "task_sched.h"
#include "dmaatb_api.h"
#include "task_signal.h"
#include "velayout.h"
#include "libved.h"
#include "veos_ived.h"
#include "ptrace_req.h"
#include "locking_handler.h"
#include "task_mgmt.h"

/**
* @brief Set the status of VE task to Exiting and perform cleanup
* of VE task
*
* @param del_task Pointer to VE task structure
*/
void psm_do_execve_wait(struct ve_task_struct *del_task)
{
	VEOS_TRACE("Entering");

	set_state(del_task);

	pthread_mutex_lock_unlock(&del_task->ref_lock, LOCK,
			"Failed to acquire task reference lock");
	VEOS_DEBUG("Acquired ref_lock, waiting for conditional signal");
	if (!(del_task->ref_count == 1) &&
			pthread_cond_wait(&del_task->ref_lock_signal,
				&del_task->ref_lock)) {
		veos_abort("pthread_cond_wait failed %s",
				strerror(errno));
	}
	pthread_mutex_lock_unlock(&del_task->ref_lock, UNLOCK,
			"Failed to release task reference lock");

	/* Acquiring core's write lock and marking task
	 * as EXIT_DEAD regardless of whether it could be
	 * waited upon or not */
	pthread_rwlock_lock_unlock(&(del_task->p_ve_core->ve_core_lock),
			WRLOCK,
			"Failed to acquire delete task's core write lock");
	pthread_mutex_lock_unlock(&(del_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	psm_set_task_state(del_task, EXIT_DEAD);
	pthread_mutex_lock_unlock(&(del_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(del_task->p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core write lock");


	VEOS_TRACE("Exiting");
}

/**
* @brief Function performs the clenaup of threads of thread group or whole
* thread group when execve() syscall request is encountered.
*
* @param group_leader Pointer to VE task structure of thread group leader
* @param current Pointer to VE task structure of task which invoked execve()
* @param elf_type Flag to denote whether whole thread group is to be deleted
*		or only the threads
*/
void psm_do_process_cleanup(struct ve_task_struct *group_leader,
		struct ve_task_struct *current, int elf_type)
{
	struct list_head *p, *n, *prev;
	struct ve_task_struct *tmp = NULL;
	struct ve_sigqueue *pending_sig = NULL;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("elf_type set to %d", elf_type);

one:
	VEOS_DEBUG("Acquiring tasklist_lock in PID %d",
			group_leader->pid);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	if (!thread_group_empty(group_leader)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p, struct ve_task_struct,
					thread_group);
			if (tmp->pid != current->pid) {
				VEOS_DEBUG("Deleting thread %d",
						tmp->pid);
				if (!get_ve_task_struct(tmp)) {
					pthread_mutex_lock_unlock(
						&(VE_NODE(0)->ve_tasklist_lock),
						UNLOCK, "Failed to release tasklist_lock lock");
					psm_do_execve_wait(tmp);
					put_ve_task_struct(tmp);
				} else {
					pthread_mutex_lock_unlock(
						&(VE_NODE(0)->ve_tasklist_lock),
						UNLOCK, "Failed to release tasklist_lock lock");
				}
				goto one;
			}
		}
	} else {
		VEOS_DEBUG("Thread group empty");
	}
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist_lock lock");

	/* #789 : Setting "thread_execed" flag of current task as true.
	 * This flag will avoid deletion of zombie main thread,
	 * when current thread(being last thread in thread group)
	 * exits As zombie main thread will be alive again after thread
	 * performs execve()
	 * */
	if (group_leader != current) {
		VEOS_DEBUG("Deleting PID %d invoked execve()",
				current->pid);
		current->thread_execed = true;
		psm_do_execve_wait(current);
		/* Actually, the best place to update signal mask is inside
		 * clear_ve_task_struct() which is responsible for updating
		 * task struct members, but our plight is, we have limited
		 * information about exec task in clear_ve_task_struct()*/
		psm_set_current_blocked(group_leader, &current->blocked);
		/* As signal pending set is preserve across execve() so
		 * clean group leader pending signal list and update it
		 * with the signal pending list of task which has called
		 * execve().
		 * */
		if (!list_empty(&group_leader->pending.list)) {
			list_for_each_safe(p, n,
					&group_leader->pending.list) {
				pending_sig = list_entry(p, struct ve_sigqueue,
						list);
					free(pending_sig);
			}
			VEOS_DEBUG("Task[%d] Pending signal cleared",
					group_leader->pid);
			ve_init_sigpending(&group_leader->pending);
		}
		if (!list_empty(&current->pending.list)) {
			memcpy(&group_leader->pending.signal,
				&current->pending.signal, sizeof(sigset_t));
			group_leader->pending.list.next = current->pending.list.next;
			prev = current->pending.list.prev;
			current->pending.list.prev->next = &group_leader->pending.list;
			group_leader->pending.list.prev = prev;
			ve_init_sigpending(&current->pending);
			VEOS_DEBUG("Task[%d] Pending signal updated",
					group_leader->pid);
		}
		put_ve_task_struct(current);
	}

	if (elf_type == EXIT_EXECVE_VH) {
		VEOS_DEBUG("Deleting thread group leader %d",
				group_leader->pid);
		psm_do_execve_wait(group_leader);
		put_ve_task_struct(group_leader);
	} else if (elf_type == EXIT_EXECVE_VE) {
		VEOS_DEBUG("Clear task struct for group leader %d",
				group_leader->pid);
		clear_ve_task_struct(group_leader);
		put_ve_task_struct(group_leader);
	}
	VEOS_TRACE("Exiting");
}

/**
 * @brief It will delete the VE process signal handler structure.
 *
 * @param[in] p_ve_task pointer to VE process task struct
 *
 * @return 0 on success, -1 on failure.
 */
int psm_del_sighand_struct(struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	int ref_count = -1;
	struct sighand_struct *sighand = NULL;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	/* Decrement reference count for thread group */
	sighand = p_ve_task->sighand;
	pthread_mutex_lock_unlock(&(sighand->siglock), LOCK,
		"Failed to acquire task sighand lock");
	sighand->ref_count--;
	ref_count = sighand->ref_count;
	pthread_mutex_lock_unlock(&(sighand->siglock), UNLOCK,
		"Failed to release task sighand lock");

	VEOS_DEBUG("Sighand ref count %d", ref_count);
	if (ref_count <= 0) {
		pthread_mutex_destroy(&(sighand->siglock));
		pthread_mutex_destroy(&(sighand->del_lock));
		shmdt((void *)sighand->lshm_addr);
		/* One might wonder what will happen when a task dumping core
		 * has received SIGKILL signal and deleted while dupming core.
		 * To her surprise we don't do coredumping and deletion of
		 * same thread parallelly and synchronization is achieved
		 * using a combination of get_ve_task_struct and delete lock.
		 */
		if (p_ve_task->ived_resource != NULL)
			veos_clean_ived_proc_property(p_ve_task);
		veos_free_jid(p_ve_task);
		psm_free_udma_context_region(p_ve_task);
		free(p_ve_task->core_dma_desc);
		free(sighand);
		p_ve_task->sighand = NULL;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Traverse the children list for ZOMBIE child
 *
 * @param[in] ve_tsk pointer of current task whose cleanup is invoked
 *
 * @internal
 * @author PSMG / MP-MT
 */
void psm_traverse_children_for_zombie(struct ve_task_struct *ve_tsk)
{
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VEOS_TRACE("Entering");

	if (!ve_tsk)
		goto hndl_return;

	VEOS_DEBUG("Reaping ZOMBIE children of PID %d", ve_tsk->pid);
one:
	VEOS_DEBUG("Acquiring tasklist_lock");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	if (!list_empty(&ve_tsk->children)) {

		list_for_each_safe(p, n, &ve_tsk->children) {
			tmp = list_entry(p,
					struct ve_task_struct,
					siblings);
			VEOS_DEBUG("Child PID %d found",
					tmp->pid);

			if ((list_empty(&tmp->thread_group)) &&
					(ZOMBIE == tmp->ve_task_state)) {

				pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock),
					UNLOCK,	"Failed to release tasklist_lock lock");

				pthread_mutex_lock_unlock(&(tmp->sighand->del_lock),
					LOCK, "Failed to acquire thread group delete lock");
				tmp->ve_task_state = EXIT_DEAD;
				pthread_mutex_lock_unlock(&tmp->ref_lock, LOCK,
						"Failed to acquire task reference lock");
				tmp->ref_count++;
				if (!(tmp->ref_count == 1) &&
						pthread_cond_wait(&tmp->ref_lock_signal,
							&tmp->ref_lock)) {
					veos_abort("pthread_cond_wait failed %s",
							strerror(errno));
				}
				pthread_mutex_lock_unlock(&tmp->ref_lock, UNLOCK,
					"Failed to release task reference lock");
				delete_entries(tmp);
			} else {
				pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock),
					UNLOCK,	"Failed to release tasklist_lock lock");
			}
			goto one;
		}
	} else {
		VEOS_DEBUG("No child exists");
	}
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist_lock lock");

hndl_return:
	VEOS_TRACE("Exiting");
	return;
}

/**
 * @brief Reparent all the child processes of the exiting process/thread.
 *
 * @param[in] ve_tsk Task to be deleted
 *
 * @internal
 * @author PSMG / MP-MT
 */
void psm_reparent_children(struct ve_task_struct *ve_tsk)
{
	struct ve_task_struct *tmp = NULL;
	struct ve_task_struct *thread = NULL;
	struct list_head *p, *n;
	struct list_head *pth, *nth;

	VEOS_TRACE("Entering");

	if (!ve_tsk)
		goto hndl_return;

	/* Notify its children (children update their parent) */
	VEOS_DEBUG("Reparenting child processes of PID %d", ve_tsk->pid);
	if (!list_empty(&ve_tsk->children)) {
		list_for_each_safe(p, n, &ve_tsk->children) {
			tmp = list_entry(p, struct ve_task_struct,
					siblings);

			if (list_empty(&tmp->thread_group) &&
					tmp->ve_task_state == ZOMBIE)
				continue;

			list_del(p);

			VEOS_DEBUG("Notifying child PID %d to reparent",
					tmp->pid);
			pthread_mutex_lock_unlock(&(tmp->ve_task_lock), LOCK,
					"Failed to acquire task lock");

			list_add_tail(&tmp->siblings, &ve_init_task.children);

			tmp->parent = &ve_init_task;
			tmp->real_parent = &ve_init_task;

			pthread_mutex_lock_unlock(&(tmp->ve_task_lock), UNLOCK,
					"Failed to release task lock");

			VEOS_DEBUG("Acquiring thread group lock");
			pthread_mutex_lock_unlock(&tmp->p_ve_mm->
					thread_group_mm_lock, LOCK,
					"Failed to acquire thread-group-mm-lock");

			list_for_each_safe(pth, nth, &tmp->thread_group) {
				thread = list_entry(pth, struct ve_task_struct,
						thread_group);
				VEOS_DEBUG("Notifying thread PID %d to reparent",
						thread->pid);
				pthread_mutex_lock_unlock(&(thread->ve_task_lock), LOCK,
						"Failed to acquire task lock");

				thread->parent = &ve_init_task;
				thread->real_parent = &ve_init_task;

				pthread_mutex_lock_unlock(&(thread->ve_task_lock), UNLOCK,
						"Failed to release task lock");
			}

			pthread_mutex_lock_unlock(&tmp->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
		}
	} else {
		VEOS_DEBUG("No child exists");
	}

hndl_return:
	VEOS_TRACE("Exiting");
}

/**
* @brief Check if parent waits for child's exit status.
* If parent waits for child's exit status then set exiting child's
* task state to ZOMBIE else set it to EXIT_DEAD.
* Function also check if child is a vforked process. If yes then
* it notifies parent to wakeup by setting parent's task state to RUNNING
*
* @param del_task_curr Pointer to VE task struct of exiting VE process
*
* @return returns true if group leader's cleanup is to be done,
* else false if it has to be kept zombie.
*
* @internal
* @author PSMG / Process management
*/
bool psm_do_notify_parent(struct ve_task_struct *del_task_curr)
{
	struct sighand_struct *sighand = NULL;
	bool dead_state = false;

	VEOS_TRACE("Entering");

	sighand = del_task_curr->parent->sighand;

	/* Acquire parent's siglock */
	pthread_mutex_lock_unlock(
			&(sighand->siglock), LOCK,
			"Failed to acquire parent's siglock");
	if (((sighand->action[SIGCHLD - 1].sa_handler == SIG_IGN) ||
				((sighand->action[SIGCHLD - 1].sa_flags &
				  SA_NOCLDWAIT))) &&
			(del_task_curr->rpm_preserve_task == 0 ||
			 del_task_curr->rpm_preserve_task == 2)) {
		VEOS_DEBUG("SIGCHLD signal is disabled"
				" Set state to EXIT_DEAD for TID: %d",
				del_task_curr->pid);
		dead_state = true;
	} else {
		VEOS_DEBUG("SIGCHLD signal is enabled"
				" Set state to ZOMBIE for TID: %d",
				del_task_curr->pid);
		dead_state = false;
	}
	/* Release parent's siglock */
	pthread_mutex_lock_unlock(
			&(sighand->siglock), UNLOCK,
			"failed to release parent's siglock");

	/* Acquire task lock for task to be deleted
	 * Set the appropriate task state
	 * Release task lock
	 * */
	pthread_mutex_lock_unlock(
			&(del_task_curr->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	dead_state ? psm_set_task_state(del_task_curr, EXIT_DEAD):
		psm_set_task_state(del_task_curr, ZOMBIE);

	pthread_mutex_lock_unlock(
			&(del_task_curr->ve_task_lock), UNLOCK,
			"failed to release task lock");

	VEOS_TRACE("Exiting");
	return dead_state;
}

/**
* @brief Set the VE process task state of exiting VE process
* and notify its parent about its death
*
* @param del_task_curr Pointer to VE task struct of exiting VE process
*
* @internal
* @author PSMG / Process management
*/
void psm_set_state_and_notify_parent(struct ve_task_struct *del_task_curr)
{
	VEOS_TRACE("Entering");

	struct list_head *p, *n;
	struct ve_task_struct *group_leader = NULL;
	struct ve_task_struct *tmp = NULL;

	group_leader = del_task_curr->group_leader;

	/* task is getting deleted, its vforked child should not wake it up */
	if (!list_empty(&(group_leader->children))) {
		list_for_each_safe(p, n, &(group_leader->children)) {
			tmp = list_entry(p, struct ve_task_struct,
					siblings);
			VEOS_DEBUG("Found child PID %d", tmp->pid);
			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), LOCK,
					"Failed to acquire task lock");

			VEOS_DEBUG("Acquired task lock for PID %d", tmp->pid);
			if (tmp->ve_task_state == ZOMBIE) {
				pthread_mutex_lock_unlock(
						&(tmp->ve_task_lock), UNLOCK,
						"Failed to release task lock");
				continue;
			}
			if (tmp->real_parent == del_task_curr
					&& tmp->vforked_proc) {
				VEOS_DEBUG("Setting wake_up_parent in child %d"
						" false", tmp->pid);
				tmp->wake_up_parent = false;
			}

			pthread_mutex_lock_unlock(
					&(tmp->ve_task_lock), UNLOCK,
					"Failed to release task lock");
		}
	}

	pthread_mutex_lock_unlock(&del_task_curr->p_ve_mm->
			thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	if (thread_group_leader(del_task_curr) &&
			!thread_group_empty(del_task_curr)) {
		/* Mark state to zombie as child threads still exist */
		pthread_mutex_lock_unlock(
				&(del_task_curr->ve_task_lock), LOCK,
				"Failed to acquire task lock");
		psm_set_task_state(del_task_curr, ZOMBIE);
		pthread_mutex_lock_unlock(
				&(del_task_curr->ve_task_lock), UNLOCK,
				"Failed to release task lock");
	} else if (thread_group_leader(del_task_curr)
			&& thread_group_empty(del_task_curr)) {
		/* child thread does not exist but check if exiting
		 * task's parent will wait for exit status
		 * */
		psm_do_notify_parent(del_task_curr);
	} else {
		/* Mark task state to EXIT_DEAD */
		pthread_mutex_lock_unlock(
				&(del_task_curr->ve_task_lock), LOCK,
				"Failed to acquire task lock");
		psm_set_task_state(del_task_curr, EXIT_DEAD);
		pthread_mutex_lock_unlock(
				&(del_task_curr->ve_task_lock), UNLOCK,
				"Failed to release task lock");
	}
	/* all threads other than thread group leader update utime/exec time in
	 * sighand->utime */
	if (!thread_group_leader(del_task_curr))
		del_task_curr->sighand->utime += del_task_curr->exec_time;

	pthread_mutex_lock_unlock(&del_task_curr->p_ve_mm->thread_group_mm_lock,
			UNLOCK,
			"Failed to release thread-group-mm-lock");

	VEOS_TRACE("Exiting");
}

/**
* @brief Remove task entry from thread group list
*
* @param del_task Pointer to VE task struct
1*/
void psm_delete_entries_for_thread(struct ve_task_struct *del_task)
{
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	bool found = false;

	VEOS_TRACE("Entering");

	/* Acquire thread group lock as race may arise when multiple threads
	 * deletion is executing in parallel and all tries to access thread
	 * group list
	 * */
	VEOS_DEBUG("Acquiring tasklist_lock in PID %d", del_task->pid);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	VEOS_DEBUG("Acquiring thread group lock");
	pthread_mutex_lock_unlock(&del_task->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");

	/* Traverse thread group list and delete process entry from list */
	list_for_each_safe(p, n, &del_task->group_leader->thread_group) {
		tmp = list_entry(p,
				struct ve_task_struct,
				thread_group);
		if (tmp->pid == del_task->pid) {
			VEOS_DEBUG("Freeing thread with PID %d",
					tmp->pid);
			list_del(p);
			found = true;
			break;
		}
	}
	pthread_mutex_lock_unlock(&del_task->p_ve_mm->thread_group_mm_lock,
			UNLOCK,	"Failed to released thread-group-mm-lock");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist_lock lock");

	/* Release the resources allocated to VE task */
	if (found) {
		VEOS_DEBUG("Freeing resources for PID %d",
				del_task->pid);
		delete_entries(del_task);
	}

	VEOS_TRACE("Exiting");
}

/**
 * @brief Releases all the resources allocated to a VE process.
 *
 * @param[in] del_task_struct VE process to be deleted
 *
 * @internal
 * @author PSMG / MP-MT
 */
void delete_entries(struct ve_task_struct *del_task_struct)
{
	int pid = -1;
	int node_id = -1, core_id = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL, *group_leader = NULL;
	struct list_head *p, *n;
	struct ve_sigqueue *pending_sig;
	int ret = -1;

	VEOS_TRACE("Entering");

	if (!del_task_struct)
		goto hndl_return;

	/* Check if accounting is enabled, if yes the dump
	 * struct ve_acct in accounting file.
	 */
	if (veos_acct.active == true &&
			del_task_struct->sighand->ref_count == 1)
		veos_acct_ve_proc(del_task_struct);

	pid = del_task_struct->pid;
	node_id = del_task_struct->node_id;
	core_id = del_task_struct->core_id;
	group_leader = del_task_struct->group_leader;

	/* Delete this VE process node */
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
		WRLOCK,
		"Failed to acquire ve core write lock");

	ve_task_list_head = VE_CORE(node_id, core_id)->ve_task_list;

	if ((del_task_struct == ve_task_list_head) &&
		(del_task_struct->next == del_task_struct)) {
		/* Current task to be deleted is head of the list */
		VEOS_DEBUG("PID %d is to be deleted", pid);
		ve_task_list_head = NULL;
		VE_CORE(node_id, core_id)->ve_task_list = ve_task_list_head;

		ve_atomic_dec(&(VE_NODE(node_id)->num_ve_proc));
		ve_atomic_dec(&(VE_CORE(node_id, core_id)->num_ve_proc));

		pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
				UNLOCK,
				"Failed to release ve core lock");
		goto resume;
	}
	temp = del_task_struct->next;
	while (temp->next != del_task_struct)
		temp = temp->next;

	temp->next = del_task_struct->next;
	if (del_task_struct == ve_task_list_head) {
		ve_task_list_head = temp->next;
		VE_CORE(node_id, core_id)->ve_task_list = ve_task_list_head;
		VEOS_DEBUG("Now Head is %p", ve_task_list_head);
	}

	ve_atomic_dec(&(VE_NODE(node_id)->num_ve_proc));
	ve_atomic_dec(&(VE_CORE(node_id, core_id)->num_ve_proc));

	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
		UNLOCK,
		"Failed to release ve core lock");

resume:
	if (group_leader == del_task_struct) {
		/* No lock has been acquired now, it's safe to acquire
		 * global tasklist_lock.
		 * Hierarchy: tasklist_lock -> task_lock
		 */
		VEOS_DEBUG("Acquiring tasklist_lock in PID %d", group_leader->pid);
		pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
				"Failed to acquire tasklist_lock lock");
		VEOS_DEBUG("Delete process entry from its parent's"
				" children list");
		pthread_mutex_lock_unlock(&(del_task_struct->parent->ve_task_lock),
				LOCK, "Failed to acquire task lock");
		list_for_each_safe(p, n, &del_task_struct->parent->children) {
			struct ve_task_struct *tmp =
				list_entry(p,
						struct ve_task_struct,
						siblings);
			if (tmp->pid == del_task_struct->pid) {
				list_del(p);
				break;
			}
		}
		pthread_mutex_lock_unlock(&(del_task_struct->parent->ve_task_lock),
				UNLOCK, "Failed to release task lock");
		pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
				"Failed to release tasklist_lock lock");

		VEOS_DEBUG("Delete process entry from INIT list");
		pthread_rwlock_lock_unlock(&init_task_lock, WRLOCK,
			"Failed to acquire init_task write lock");
		list_for_each_safe(p, n, &ve_init_task.tasks) {
			struct ve_task_struct *tmp =
				list_entry(p,
						struct ve_task_struct,
						tasks);

			if (tmp->pid == del_task_struct->pid) {
				list_del(p);
				break;
			}
		}
		pthread_rwlock_lock_unlock(&init_task_lock, UNLOCK,
			"Failed to release init_task lock");
	}

	/* Remove the tracing information while exiting if task is
	 * still marked as traced.
	 */
	if (del_task_struct->ptraced &&
			-1 == psm_ptrace_detach(del_task_struct)) {
		VEOS_DEBUG("Removing tracing information for pid: %d",
				del_task_struct->pid);
		del_task_struct->ptraced = false;
		free(del_task_struct->p_ve_ptrace);
		del_task_struct->p_ve_ptrace = NULL;
	}

	/* If the thread to be deleted is the main thread, cleanup of all the ZOMBIE
	 * child processes */
	if (thread_group_leader(del_task_struct))
		psm_traverse_children_for_zombie(group_leader);
	if (!list_empty(&del_task_struct->pending.list)) {
		list_for_each_safe(p, n, &del_task_struct->pending.list) {
			pending_sig = list_entry(p, struct ve_sigqueue, list);
			free(pending_sig);
		}
		ve_init_sigpending(&del_task_struct->pending);
		VEOS_DEBUG("Task[%d] Pending signal cleared",
			del_task_struct->pid);
	}
	psm_del_sighand_struct(del_task_struct);

	amm_del_mm_struct(del_task_struct);

	if ((del_task_struct->is_crt_drv
				&& !del_task_struct->is_dlt_drv)) {
		VEOS_DEBUG("Deleting VE process structure with"
				" PID %d from Driver",
				pid);
		ret = vedl_delete_ve_task(VE_HANDLE(node_id), pid);
		if (ret) {
			VEOS_DEBUG("Fail(%s) to delete task with PID %d",
					strerror(errno),
					del_task_struct->pid);
			veos_abort("Failed to delete task with PID %d from driver",
					del_task_struct->pid);
		}
		del_task_struct->is_dlt_drv = true;
		del_task_struct->is_crt_drv = false;
	}

	if (NULL != del_task_struct->p_ve_thread)
		free(del_task_struct->p_ve_thread);
	if (NULL != del_task_struct) {
		pthread_mutex_destroy(&(del_task_struct->ptrace_lock));
		pthread_mutex_destroy(&(del_task_struct->ve_task_lock));
		pthread_mutex_destroy(&(del_task_struct->offset_lock));
		pthread_mutex_destroy(&(del_task_struct->ref_lock));
		pthread_cond_destroy(&(del_task_struct->ref_lock_signal));
		free(del_task_struct);
	}

	if (0 == VE_CORE(node_id, core_id)->num_ve_proc)
		VE_CORE(node_id, core_id)->ve_core_state = STOPPED;
hndl_return:
	VEOS_TRACE("Exiting");
}

/**
* @brief Delete's VE process
*
* @param del_task_curr Pointer to VE task struct
*
* @return -1 on failure and 0 on success
*/
int psm_handle_delete_ve_process(struct ve_task_struct *del_task_curr)
{
	int core_id = -1, node_id = -1;
	int retval = -1;
	bool leader_set_dead = false;
	struct ve_task_struct *group_leader = NULL, *real_parent = NULL;

	if (del_task_curr == NULL)
		veos_abort("Pointer to task to be deleted is NULL");

	bool thread_execed = del_task_curr->thread_execed;

	VEOS_TRACE("Entering");

	/* veos_polling_thread calls delete for a task
	 * more than once
	 * To check if the task is deleted from driver
	 * */
	if (del_task_curr->is_dlt_drv) {
		VEOS_ERROR("PID %d already deleted from driver",
				del_task_curr->pid);
		retval = -1;
		goto hndl_return;
	}

	group_leader = del_task_curr->group_leader;
	/* Collect accounting information */
	psm_acct_collect(del_task_curr->exit_code, del_task_curr);

	node_id = del_task_curr->node_id;
	core_id = del_task_curr->core_id;

	VEOS_DEBUG("DEL TASK %d CORE %d",
			del_task_curr->pid,
			core_id);

	/* This is thread group wide lock for deletion. At a time only
	 * one thread of a thread group could process its deletion */
	VEOS_DEBUG("Acquiring thread group delete lock");
	pthread_mutex_lock_unlock(&(group_leader->sighand->del_lock), LOCK,
			"Failed to acquire thread group delete lock");

	VEOS_DEBUG("Acquiring tasklist_lock");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist_lock lock");

	/* Acquire core's write lock.
	 * It's shifted above so that nr_active is not read using core's
	 * read lock while it is being decremented in parallel */
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			WRLOCK, "Failed to acquire delete task's core write lock");

	VEOS_DEBUG("Marking task's state as ZOMBIE or EXIT_DEAD");

	/* regardless of everything, if the task could not be created on driver,
	 * set its state to EXIT_DEAD */
	if (!del_task_curr->is_crt_drv) {
		VEOS_DEBUG("Setting task state to EXIT_DEAD");
		del_task_curr->ve_task_state = EXIT_DEAD;
	} else {
		psm_set_state_and_notify_parent(del_task_curr);
	}

	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
	                        "Failed to release tasklist_lock lock");

	del_task_curr->flags |= PF_EXITING;

	/* If task is current task on core then migrate */
	if (del_task_curr == VE_CORE(node_id, core_id)->curr_ve_task) {
		VEOS_DEBUG("Invoke psm_unassign_migrate_task");
		psm_unassign_migrate_task(del_task_curr);
	}

	if (del_task_curr->ve_task_state == ZOMBIE) {
		retval = vedl_delete_ve_task(VE_HANDLE(0),
				del_task_curr->pid);
		if (retval) {
			VEOS_DEBUG("Failed (%s) to delete task with PID %d",
					strerror(errno),
					del_task_curr->pid);
			veos_abort("Failed to delete task with PID %d from driver",
					del_task_curr->pid);
		}
		del_task_curr->is_dlt_drv = true;
		del_task_curr->is_crt_drv = false;

		pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
				UNLOCK, "Failed to release core write lock");
		/* Since only thread group leader can be ZOMBIE, further code
		 * is redundant in this context. Hence we jump from here.
		 * */
		goto hndl_reparent;
	}

	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			UNLOCK, "Failed to release core write lock");

	/* Remove task from thread_group list */
	if (!thread_group_empty(del_task_curr) &&
			!thread_group_leader(del_task_curr)) {
		VEOS_DEBUG("Remove task %d from thread group list",
				del_task_curr->pid);
		psm_delete_entries_for_thread(del_task_curr);
	}

	/* - Acquire thread group lock.
	 * - Check if main thread is ZOMBIE, thread group list is empty and thread
	 *   group is not empty due to invocation of execve() by a thread.
	 * - If yes then update the state of main thread from ZOMBIE to EXIT_DEAD
	 *   if main thread's parent does not tends to wait for main thread's
	 *   exit status.
	 * */
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
	                                "Failed to acquire tasklist lock");
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			WRLOCK, "Failed to acquire delete task's core write lock");
	pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");

	if ((group_leader->ve_task_state == ZOMBIE)
			&& (thread_group_empty(group_leader))
			&& !thread_execed) {
		/* Checking if group leader needs to remain zombie
		 */
		if (psm_do_notify_parent(group_leader) == false) {
			pthread_mutex_lock_unlock(&group_leader->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
			pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
				UNLOCK, "Failed to release core write lock");
			pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
	                                "Failed to release tasklist lock");
			goto hndl_reparent;
		}
	}
	pthread_rwlock_lock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock),
			UNLOCK, "Failed to release core write lock");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
	                                "Failed to acquire tasklist lock");

	if (group_leader->ve_task_state == EXIT_DEAD)
		leader_set_dead = true;

	pthread_mutex_lock_unlock(&group_leader->p_ve_mm->thread_group_mm_lock,
			UNLOCK,	"Failed to release thread-group-mm-lock");

hndl_reparent:
	/* do reparenting of child processes if no thread is alive */
	VEOS_DEBUG("Acquiring tasklist_lock in PID %d", group_leader->pid);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), LOCK,
			"Failed to acquire tasklist lock");
	if (thread_group_empty(group_leader) &&
			(group_leader->ve_task_state == ZOMBIE ||
			 group_leader->ve_task_state == EXIT_DEAD)) {

		VEOS_DEBUG("vforked process execution completed");

		/* If task is vforked child and its parent exists, then wake up parent */
		if (true == group_leader->vforked_proc &&
				group_leader->wake_up_parent == true) {
			real_parent = group_leader->real_parent;

			/* Acquire core lock as we can update number of active
			 * task on core */
			if (group_leader->core_id != real_parent->core_id)
				pthread_rwlock_lock_unlock(
						&(real_parent->p_ve_core->ve_core_lock),
						WRLOCK, "Failed to acquire core lock");
			pthread_mutex_lock_unlock(
					&(real_parent->ve_task_lock), LOCK,
					"Failed to acquire task lock");
			/* If parent process has not served UNBLOCK yet then
			 * do not change task state here let, UNBLOCK request
			 * make the decision.
			 */

			if (real_parent->ve_task_state != STOP
					&& real_parent->block_status == UNBLOCK_SERVED) {
				VEOS_DEBUG("vforked process waking up parent");
				psm_set_task_state(real_parent, RUNNING);
			}
			real_parent->vfork_state = VFORK_COMPLETED;

			pthread_mutex_lock_unlock(
					&(real_parent->ve_task_lock), UNLOCK,
					"failed to release task lock");
			if (group_leader->core_id != real_parent->core_id)
				pthread_rwlock_lock_unlock(
						&(real_parent->p_ve_core->ve_core_lock),
						UNLOCK, "Failed to acquire core lock");
		}

		/* task's children list and its children's thread group list
		 * will be accessed now. Hence task lock and thread group lock
		 * of child processes will be acquired inside
		 * Hierarchy: tasklist_lock -> task_lock
		 *	      tasklist_lock -> thread_group_mm_lock
		 */
		if (!thread_execed) {
			psm_reparent_children(group_leader);
		}
	}
	pthread_mutex_lock_unlock(&(VE_NODE(0)->ve_tasklist_lock), UNLOCK,
			"Failed to release tasklist lock");

	pthread_mutex_lock_unlock(&(group_leader->sighand->del_lock), UNLOCK,
			"Failed to release thread group delete lock");
	/* As main thread is going to exit, release its resources
	 * */
	if (leader_set_dead) {
		/* Wait until any other worker thread releases the reference.
		 * The reference could have taken when the TG was zombie
		 */
		pthread_mutex_lock_unlock(&group_leader->ref_lock, LOCK,
				"Failed to acquire task reference lock");
		VEOS_DEBUG("Acquired ref_lock, waiting for conditional signal");

		group_leader->ref_count++;

		if (!(group_leader->ref_count == 1) &&
				pthread_cond_wait(&group_leader->ref_lock_signal,
					&group_leader->ref_lock)) {
			veos_abort("pthread_cond_wait failed %s",
					strerror(errno));
		}
		pthread_mutex_lock_unlock(&group_leader->ref_lock, UNLOCK,
				"Failed to release task reference lock");

		delete_entries(group_leader);
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
