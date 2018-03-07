/**
* @file	psm_signal_handler.c
* @brief Handles and manages the signal request for VE process
* from Pseudo process.
*/

#include <unistd.h>
#include <stdio.h>
#include "ve_hw.h"
#include "psm_main.h"
#include "psm_task_mgmt.h"
#include "veos_ipc.h"
#include "amm_psm_if.h"
#include "psm_signal_handler.h"
#include "psm_pseudo_ipc.h"
#include "signal.h"
#include "velayout.h"

/**
* @brief Update signal pending flag of VE process
*
*	This function sets "sigpending" flag of VE process if there
*	exists a signal(which is not blocked by	VE process)in signal
*	pending queue.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
*
* @return 1 if signal pending flag is set else 0.
*/
static int recalc_sigpending(struct ve_task_struct *p_ve_task)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if ((p_ve_task->pending.signal.__val[0])
		&~(p_ve_task->blocked.__val[0])) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Signal is pending, "
				"Set the SIGNAL PENDING FLAG\n");
		p_ve_task->sigpending = SIGNAL_PENDING;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
		return 1;
	}
	p_ve_task->sigpending = 0;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return 0;
}

/**
* @brief Restore the VE process context after the execution of signal handler.
*
*	Function calculate the address of VE task's stack where the context was
*	stored before executing signal handler routine.
*	Function read the context from VE process task stack and copy it in
*	"ve_thread_struct" so that VE task can resume its execution in next
*	scheduling cycle.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
*
* @return 0 on success, -1 on failure.
*/
int psm_restore_ve_context(struct ve_task_struct *ve_task_curr)
{
	uint64_t curr_sp, frame_addrs;
	struct sigframe p_ve_sigframe;
	int retval = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"NULL argument received\n");
		retval = -1;
		goto ret;
	}
	memset(&p_ve_sigframe, 0, sizeof(struct sigframe));
	curr_sp = ve_task_curr->p_ve_thread->SR[11];

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SIGNAL HANDLER STACK ADDRESS : %lx\n",
			curr_sp);

	/* Find the physical address of stack where the process
	 * context is stored
	 * */
	frame_addrs = amm_addr_translation((char *)(curr_sp + HANDLER_STACK_FRAME),
			&(ve_task_curr->p_ve_mm->atb));
	if (-1 == frame_addrs) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Address translation failed\n");
		retval = -1;
		goto err_ret;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Frame address : %lx\n", frame_addrs);

	/* read the signal frame from VE process physical memory
	 * */
	retval = amm_dma_xfer(VE_DMA_VEMAA, (uint64_t)frame_addrs,
			ve_task_curr->pid, VE_DMA_VHVA,
			(uint64_t)&p_ve_sigframe,
			getpid(),
			(uint64_t)sizeof(struct sigframe),
			ve_task_curr->node_id);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"unable to retrieve context from stack\n");
		goto err_ret;
	}

	/* Copy the current hardware context from the sigframe
	 * */
	pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
	memset(ve_task_curr->p_ve_thread,
			0, sizeof(struct ve_thread_struct));
	memcpy(ve_task_curr->p_ve_thread,
		&p_ve_sigframe.uc.uc_mcontext,
			sizeof(struct ve_thread_struct));

	/* Copy current lshm context */
	memcpy((void *)(ve_task_curr->sighand->lshm_addr + ve_task_curr->offset),
			p_ve_sigframe.lshm_area,
			LSHM_SZ);

	/* Restore the signal mask
	 * */
	ve_task_curr->blocked = p_ve_sigframe.uc.uc_sigmask;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"\n\nSigreturn Context PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx\n\n",
			ve_task_curr->pid,
			ve_task_curr->p_ve_thread->IC,
			ve_task_curr->p_ve_thread->SR[10],
			ve_task_curr->p_ve_thread->SR[11],
			ve_task_curr->p_ve_thread->SR[12]);

	pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
	if (p_ve_sigframe.flag) {
		/* TODO:
		 * Generate Coredump
		 * */
		 VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Fatal flag set, terminating..\n");
		 kill(ve_task_curr->pid, p_ve_sigframe.signum);
		 retval = -1;
		 goto ret;
	}
	recalc_sigpending(ve_task_curr);
ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
err_ret:
	/* TODO:
	 * Generate Coredump
	 * */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Terminating Pseudo process\n");
	kill(ve_task_curr->pid, SIGKILL);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Allocate sigqueue data structure for the signal generated.
*
* @param[in] sig Signal number generated
*
* @return pointer to allocated ve_sigqueue on success and NULL in
* case of failure.
*/
struct ve_sigqueue *psm_ve_sigqueue_alloc(int sig)
{
	struct ve_sigqueue *ve_q;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_q = (struct ve_sigqueue *)malloc(sizeof(struct ve_sigqueue));
	if (!ve_q) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Siqueue allocation failed\n");
		return NULL;
	}
	INIT_LIST_HEAD(&ve_q->list);
	ve_q->flag = 0;
	ve_q->signo = sig;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ve_q;
}

/**
* @brief Set process state of VE process to "RUNNING".
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
*/
void psm_start_ve_process(struct ve_task_struct *p_ve_task)
{
	struct ve_core_struct *p_ve_core;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	p_ve_core = p_ve_task->p_ve_core;

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));

	/* Number of active task updated on core */
	if (RUNNING != p_ve_task->ve_task_state) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			" updated active task for core\n");
		ve_atomic_inc(&(p_ve_core->nr_active));
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Setting state RUNNING for pid %d\n",
			p_ve_task->pid);

	/* Change the State of VE process */
	if ((p_ve_task->p_ve_thread->EXS & VE_EXCEPTION) &&
			(p_ve_task->block_status == BLOCK_RECVD)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Setting state WAIT for pid %d "
				"due to MONC processing is in progress.\n",
				p_ve_task->pid);
		p_ve_task->ve_task_state = WAIT;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Setting state to RUNNING for pid %d",
				p_ve_task->pid);
		p_ve_task->ve_task_state = RUNNING;
	}
	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief Set the process state of VE process to "STOP".
*
*	This function set the VE process state to STOP. If the VE process
*	is the current task executing on VE core then re-scheduling occurs.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
*
* @return success always.
*/
int psm_stop_ve_process(struct ve_task_struct *p_ve_task)
{
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	p_ve_core = VE_CORE(p_ve_task->node_id, p_ve_task->core_id);
	pthread_mutex_lock(&(p_ve_task->ve_task_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Setting state STOP for pid %d\n", p_ve_task->pid);

	/* Number of active task updated on core */
	if (RUNNING == p_ve_task->ve_task_state) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			" updated active task for core\n");
		ve_atomic_dec(&(p_ve_core->nr_active));
	}

	/* Setting VE process state to STOP
	 * */
	p_ve_task->ve_task_state = STOP;
	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	/* If it is current process on core invoke re-scheduling
	 * */
	if (p_ve_core->curr_ve_task == p_ve_task) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Stopped process with pid %d,"
				" scheduling new VE process"
				" on Core %d\n",
				p_ve_task->pid,
				p_ve_core->core_num);
		psm_find_sched_new_task_on_core(p_ve_core, false);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return 0;
}

/**
* @brief Performs a specific action on a thread.
*
*	The action to be performed on thread depends on the "flag"
*	received as argument. "flag" received as argument and action
*	corresponding to it are:
*	FSIGCONTINUE - If any signal whose action is to stop VE process
*	is present in signal pending queue, it should be deleted and VE
*	process state is set to RUNNING.
*	FSIGSTOPPING - Set VE process state to STOP
*	FSIGMASKING - Remove the signal number "sig" from signal pending
*	queue.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] flag "flag" decides which action to be taken.
* @param[in] sig Signal number generated.
*
* @return 0 on success and -1 on failure.
*/
int ve_group_action(struct ve_task_struct *p_ve_task, int flag, int sig)
{
	int retval = 0;
	sigset_t mask;
	struct ve_sigpending *pending = &p_ve_task->pending;
	struct list_head *q, *n;
	struct ve_sigqueue *tmp = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	switch (flag) {
	case 0:
		/* 1. If any stopping signal SIGTSTP/ SIGTTIN/ SIGTTOU
		 * lies in signal pending list, dequeue it and
		 * remove it for pending signal set.
		 * 2. Set the VE process state to RUNNING.
		 * */
		sigemptyset(&mask);
		mask.__val[0] = VE_SIG_STOP_MASK;
		pthread_mutex_lock(&(p_ve_task->siglock));
		if (list_empty(&pending->list)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Empty pending list\n");
		} else {
			/* delete the signal from sigpending list */
			list_for_each_safe(q, n, &pending->list) {
				tmp = list_entry(q,
						struct ve_sigqueue,
						list);
				if (sigismember(&mask, tmp->signo)) {
					VE_LOG(CAT_OS_CORE,
						LOG4C_PRIORITY_DEBUG,
						"Deleting stopping signal %d\n",
						tmp->signo);
					sigdelset(&pending->signal, tmp->signo);
					list_del(q);
					free(tmp);
				}
			}
		}
		pthread_mutex_unlock(&(p_ve_task->siglock));
		psm_start_ve_process(p_ve_task);
		break;
	case 1:
	case 3:
		/* Set VE process state to STOP
		 * */
		psm_stop_ve_process(p_ve_task);
		break;
	case 2:
		/* Remove "sig" signal from signal pending list
		 * */
		pthread_mutex_lock(&(p_ve_task->siglock));
		if (list_empty(&pending->list)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Empty pending list\n");
		} else {
			list_for_each_safe(q, n, &pending->list) {
				tmp = list_entry(q,
						struct ve_sigqueue,
						list);
				if (tmp->signo == sig) {
					VE_LOG(CAT_OS_CORE,
						LOG4C_PRIORITY_DEBUG,
						"Deleting signal %d\n",
						tmp->signo);
					sigdelset(&pending->signal,
							tmp->signo);
					list_del(q);
					free(tmp);
					break;
				}
			}
		}
		pthread_mutex_unlock(&(p_ve_task->siglock));
		break;
	default:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Invalid flag provided\n");
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"You should never come here\n");
		retval = -1;
		break;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Traverse thread group list and perform an action on each thread.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] flag "flag" decides which action to be performed
* @param[in] sig Signal number generated
*/
void ve_do_group_action(struct ve_task_struct *p_ve_task, int flag, int sig)
{
	struct list_head *p, *n;
	struct ve_task_struct *group_leader = NULL, *tmp = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	group_leader = p_ve_task->group_leader;

	/* Take action of every thread of thread group
	 * */
	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {
			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Acting on thread with PID %d\n",
					tmp->pid);
			ve_group_action(tmp, flag, sig);
		}
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "No threads exists\n");
	}

	/* Take action on thread group leader.
	 * */
	ve_group_action(group_leader, flag, sig);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief Checks if "syncsignal" flag is set for VE process.
*
*	When a signal is generated for VE process, a check of whether
*	"syncsignal" flag is set is made. If set, check whether action
*	registered for signal is not set to default.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
* @param[in] sig Signal number generated
*
* @return 1 set when synchronous signal flag is set and current signal
*	action is not set to default, else 0.
*/
int psm_check_sync_signal_pending(struct ve_task_struct *ve_task_curr,
		int sig)
{
	int retval = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	/* If synchronous signal is pending then, check current
	 * signals action
	 * */
	if (SYNCHRONOUS_SIGNAL == ve_task_curr->syncsignal) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"SYNCHRONOUS_SIGNAL flag set\n");
		if (ve_task_curr->sighand->action[sig - 1].sa_handler
				!= SIG_DFL) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"SIG_DFL not set for the signal\n");
			retval = 1;
		}
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Sends the generated signal to the VE process.
*
*	Function allocates and updates the VE task data structure related
*	to the signal.
*	It checks if signal generated is already pending for VE process.
*	If signal is not in the pending list, function will add the signal
*	in pending list, allocates "ve_sigqueue" data structure and recalculate
*	the signal pending flag.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
* @param[in] ve_sig_info Stores generated signal information
* @param[in] signum Signal number generated
* @param[in] flag Set if signal generated from h/w exception.
*
* @return -1 on failure and a positive value on success.
*/
int psm_send_ve_signal(struct ve_task_struct *ve_task_curr,
		siginfo_t *ve_sig_info, int signum, int flag)
{
	int retval = -1;
	struct ve_sigpending *ve_pending = &ve_task_curr->pending;
	struct ve_sigqueue *ve_q;
	struct ve_task_struct *curr_task_on_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (SIGCONT == signum) {
		/* Remove all stop signal from pending queue,
		 * wake all threads
		 * */
		ve_do_group_action(ve_task_curr, FSIGCONTINUE, signum);
	} else if (ve_sig_stop(signum)) {
		/* This is STOP signal. Remove SIGCONT from
		 * queue if any.
		 * */
		ve_do_group_action(ve_task_curr, FSIGMASKING, SIGCONT);
	}
	pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
	/* Support queuing for exactly one non-rt signal(of each type)
	 * */
	if (legacy_queue(ve_pending, signum)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"SIGNAL(non-rt) %d already in pending queue\n",
				signum);
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		goto ret;
	}

	/* Add signal in pending queue
	 * */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Allocate sigqueue struct for the signal generated\n");
	ve_q = psm_ve_sigqueue_alloc(signum);
	if (NULL == ve_q) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sigqueue struct not allocated\n");
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		goto ret;
	}

	ve_q->flag = flag;
	/* Copy the siginfo received from Kernel for this signal
	 * into "to be queued node".
	 * */
	if (SEND_SIG_PRIV == ve_sig_info) {
		ve_q->info.si_signo = signum;
		ve_q->info.si_errno = 0;
		ve_q->info.si_code = SI_KERNEL;
		ve_q->info.si_pid = 0;
		ve_q->info.si_uid = 0;
	} else {
		memcpy(&(ve_q->info),
			ve_sig_info,
			sizeof(siginfo_t));
	}
	if (flag && (SEND_SIG_PRIV != ve_sig_info)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Populating si_addr for hw mapped signal\n");
		ve_q->info.si_addr = (void *)ve_task_curr->p_ve_thread->ICE;
	}

	/* Add the signal in pending signal list
	 * */
	list_add_tail(&ve_q->list, &ve_pending->list);

	/* Add the signal in the signal set for this task
	 * */
	sigaddset(&ve_pending->signal, signum);

	/* Recalculate SIGNAL PENDING flag
	 * */
	if (!recalc_sigpending(ve_task_curr)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"No signal pending\n");
		pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
		goto ret;
	}

	pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
	if (flag && (SEND_SIG_PRIV != ve_sig_info)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Start VE process, fatal signal occurred\n");
		psm_handle_un_block_request(ve_task_curr->pid);
	}

	if (SEND_SIG_PRIV != ve_sig_info) {
		pthread_rwlock_rdlock(&(ve_task_curr->p_ve_core->ve_core_lock));
		curr_task_on_core = VE_CORE(ve_task_curr->node_id,
				ve_task_curr->core_id)->curr_ve_task;


		/* If the signal is generated for a process currently
		 * executing on VE core, we stop the VE core and add the
		 * generated signal in the pending list of the VE process.
		 * We invoke the PSM scheduler, so that the generated
		 * signal can be handled immediately.
		 * */
		if (ve_task_curr == curr_task_on_core) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Signal generated for ve process"
					" currently scheduled on core\n");
			pthread_rwlock_unlock(&(ve_task_curr->p_ve_core->ve_core_lock));
			psm_find_sched_new_task_on_core(VE_CORE(ve_task_curr->node_id,
						ve_task_curr->core_id), false);
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Signal generated for ve process"
					" currently NOT scheduled on core\n");
			pthread_rwlock_unlock(&(ve_task_curr->p_ve_core->ve_core_lock));
		}

	}
	/* If all successful return 0 */
	retval = 0;
ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Prepare trampoline instruction.
*	This function generates sigreturn(2) instruction that will be
*	written to the VE process stack. These instructions will
*	be executed by the VE program while returning from signal
*	handler routine.
*
* @param[out] ve_sigframe Pointer to signal frame structure
*/
void psm_prepare_trampoline_ve(struct sigframe *ve_sigframe)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_sigframe->tramp[0] = 0x462eaeae00000000;
	ve_sigframe->tramp[1] = 0x012e008e00000018;
	ve_sigframe->tramp[2] = 0x45000f0000000000;
	ve_sigframe->tramp[3] = 0x310003ae00000000;
	ve_sigframe->tramp[4] = 0x3f00000000000000;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief Fetch next signal to be delivered from pending signal set.
*
* @param[in] pending Pending signals for the VE process
* @param[in] mask Blocking signal mask for the VE process.
*
* @return Signal number on success. Return 0 on failure.
*/
int psm_get_next_ve_signal(struct ve_sigpending *pending, sigset_t *mask)
{
	unsigned long *s, *m, x;
	int sig = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	s = pending->signal.__val;
	m = mask->__val;

	x = *s & ~(*m);
	if (x) {
		if (x & VE_SYNCHRONOUS_MASK) {
			/* If signal is one of synchronous signal,
			 * deliver it first
			 * */
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal lies in synchronous mask\n");
				x &= VE_SYNCHRONOUS_MASK;
		}
		sig = ffsl(x);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Signal number to be served : %d\n",
			sig);
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return sig;
}

/**
* @brief Fetch the signal information for the signal to be delivered.
*
* @param[out] ve_siginfo Stores signal information
* @param[in] pending Mask of pending signals
* @param[in] mask Mask of blocked signals
* @param[out] flag "flag" is set if signal is generated from h/w exception.
*/
void ve_collect_signal(siginfo_t *ve_siginfo,
		struct ve_sigpending *pending, int sig, int *flag)
{
	struct list_head *q, *n;
	struct ve_sigqueue *tmp = NULL;
	struct ve_sigqueue *first = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* delete the signal from sigpending list
	 * */
	list_for_each_safe(q, n, &pending->list) {
		tmp = list_entry(q,
				struct ve_sigqueue,
				list);
		if (tmp->signo == sig) {
			if (first)
				goto more_pending;
			first = tmp;
		}
	}

	/* Remove sig from the pending signal set
	 * */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Delete signum %d from pending sigset\n",
			sig);
	sigdelset(&pending->signal, sig);

	if (first) {
more_pending:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Delete signum %d from pending list\n",
				sig);
		list_del(&first->list);
		memcpy(ve_siginfo,
				&(first->info),
				sizeof(siginfo_t));
		memcpy(flag,
				&(first->flag),
				sizeof(int));
		free(first);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief Dequeue the signal to be delivered from pending signal list
*
* @param[out] ve_siginfo Stores signal information
* @param[in] pending Mask of pending signals
* @param[in] mask Mask of blocked signals
* @param[out] flag "flag" is set if signal is generated from h/w exception.
*
* @return Signal number on success. Return 0 on failure.
*/
int psm_dequeue_ve_signal(siginfo_t *ve_siginfo,
		struct ve_sigpending *pending, sigset_t *mask, int *flag)
{
	int sig = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	sig = psm_get_next_ve_signal(pending, mask);
	if (sig)
		ve_collect_signal(ve_siginfo, pending, sig, flag);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return sig;
}

/**
* @brief Check if VE process is using alternate signal stack.
*
* @param[in] current Pointer to "ve_task_struct"
*
* @return 1 if alternate signal stack is active else 0.
*/
int on_sig_stack(struct ve_task_struct *current)
{
	unsigned long sp = current->p_ve_thread->SR[11];

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	return sp > current->sas_ss_sp &&
		sp - current->sas_ss_sp <= current->sas_ss_size;
}

/**
* @brief Function calculate the VE task stack physical address for writing
*	the signal handler frame.
*
*	VE process signal handler frame (contain VE process current context)
*	can be saved while handling signal.
*	In case stack overflow occur, SIGSEGV is delivered to VE process.
*	If VE process had registered the SIGSEGV handler on alternate stack,
*	SIGSEGV handler will be execute	else VE task will terminate with core
*	dump and SIGKILL signal will be delivered to the corresponding pseudo
*	process.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] signum Signal Number getting served
* @param[out] vir_frame_addr Signal Frame virtual address
*
* @return physical address of stack when successful and -1 on failure.
*/
uint64_t ve_getframe(struct ve_task_struct *p_ve_task,
		int signum,
		uint64_t *vir_frame_addr)
{
	int onsigstack = on_sig_stack(p_ve_task);
	int flag = p_ve_task->sighand->action[signum - 1].sa_flags;
	uint64_t frame_phy_addrs, frame_vir_addrs;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!onsigstack) {
		/* Signal alternate stack not active
		 * */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Signal alternate stack inactive\n");

		if ((flag & SA_ONSTACK) && (p_ve_task->sas_ss_size)) {
			/* SA_ONSTACK is set, handle signal
			 * on alternate stack
			 * */
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"SA_ONSTACK flag set\n");
			frame_vir_addrs = p_ve_task->sas_ss_sp
				+ p_ve_task->sas_ss_size
				- sizeof(struct sigframe);

		} else {
			/* SA_ONSTACK not set
			 * */
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"either flag or size is invalid\n");

			frame_vir_addrs = p_ve_task->p_ve_thread->SR[11]
				- (sizeof(struct sigframe));
		}
	} else {
		/* Signal alternate stack active
		 * */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Signal alternate stack active\n");

		frame_vir_addrs = p_ve_task->p_ve_thread->SR[11]
			- sizeof(struct sigframe);
	}
	frame_phy_addrs = amm_addr_translation((char *)(frame_vir_addrs),
			&(p_ve_task->p_ve_mm->atb));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Frame Virtual address : %p\n",
			(void *)(frame_vir_addrs));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Frame Physical address : %lx\n",
			frame_phy_addrs);
	memcpy(vir_frame_addr, &frame_vir_addrs, sizeof(uint64_t));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return frame_phy_addrs;
}

/**
* @brief Sets the signal handler context and saves the process
*	context onto stack
*
*	This function prepares the signal handler frame on VE process stack
*	Save the current context of VE process on VE stack
*	Set the value of VE process registers for the execution	of signal
*	handler routine.
*
* @param[in] signum Signal Number being delivered.
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] ve_siginfo Stores the signal information.
* @param[in] flag "flag" is set when signal is generated from h/w exception.
*
* @return 0 in Success, -1 in Error.
*/
static int setup_ve_frame(int signum,
		struct ve_task_struct *p_ve_task,
		siginfo_t *ve_siginfo,
		int flag) {
	/*
	 *	      STACK IMAGE
	 *
	 *	high |		|
	 *	 ^   +----------+ <--- Current SP
	 *	 |   |  Current	|
	 *	 |   |	context |
	 *	 |   |	   +	|
	 *  512KB|   |	signal  |
	 *	 |   |  handler |
	 *	 |   |arguments	|
	 *	 |   |	   +	|
	 *	 |   |Trampoline|
	 *	 v   +----------+ <--- Address of frame
	 *	 ^   |  signal	|      saving current context
	 *   512B|   |  handler |
	 *	 |   |  stack   |
	 *	 |   |	frame   |
	 *	 v   +----------+ <--- New SP(signal handler)
	 *	     |		|
	 *	low
	 */
	int ret = 0;
	uint64_t frame_addrs, frame_vir_addr;
	struct sigframe ve_sigframe;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	memset(&ve_sigframe, '\0', sizeof(struct sigframe));

	/* Prepare sigreturn() instruction as trampoline code. */
	psm_prepare_trampoline_ve(&ve_sigframe);

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));

	frame_addrs = ve_getframe(p_ve_task, signum, &frame_vir_addr);
	if (-1 == frame_addrs) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ve_getframe() failed\n");
		pthread_mutex_unlock(&(p_ve_task->ve_task_lock));
		return -EFAULT;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Frame Virtual address : %p\n",
			(void *)(frame_vir_addr));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Frame Physical address : %lx\n", frame_addrs);

	memcpy(&ve_sigframe.ve_siginfo, ve_siginfo, sizeof(siginfo_t));

	ve_sigframe.flag = flag;
	ve_sigframe.signum = signum;
	/* Copy the current hardware context on the sigframe
	 * */
	memcpy(&(ve_sigframe.uc.uc_mcontext),
			p_ve_task->p_ve_thread,
			sizeof(struct ve_thread_struct));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Saving the current context\n");
	if (p_ve_task->mask_saved == true) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Saving the \"saved_sigmask\"\n");
		ve_sigframe.uc.uc_sigmask = p_ve_task->ve_saved_sigmask;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Saving the current signal mask\n");
		ve_sigframe.uc.uc_sigmask = p_ve_task->blocked;
	}
	ve_sigframe.uc.uc_flags = 0;
	ve_sigframe.uc.uc_link = 0;
	ve_sigframe.uc.uc_stack.ss_sp = (void *)(p_ve_task->sas_ss_sp);
	ve_sigframe.uc.uc_stack.ss_size = p_ve_task->sas_ss_size;
	ve_sigframe.uc.uc_stack.ss_flags =
			on_sig_stack(p_ve_task)
			? SS_ONSTACK : 0;

	/* Copy current lshm context */
	memcpy(ve_sigframe.lshm_area,
			(void *)(p_ve_task->sighand->lshm_addr + p_ve_task->offset),
			LSHM_SZ);

	/* Write the signal frame to VE process physical memory */
	ret = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&ve_sigframe, getpid(),
			VE_DMA_VEMAA, (uint64_t)frame_addrs,
			p_ve_task->pid, (uint64_t)sizeof(struct sigframe),
			p_ve_task->node_id);
	if (ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"unable to set trampoline\n");
		pthread_mutex_unlock(&(p_ve_task->ve_task_lock));
		return -EFAULT;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"\n\nSigreturn Context PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx\n\n",
			p_ve_task->pid,
			p_ve_task->p_ve_thread->IC,
			p_ve_task->p_ve_thread->SR[10],
			p_ve_task->p_ve_thread->SR[11],
			p_ve_task->p_ve_thread->SR[12]);

	/* SET THE SIGNAL HANDLER CONTEXT */

	/* set the instruction counter of VE process with
	 * signal handler routine address
	 */
	p_ve_task->p_ve_thread->IC = (reg_t)p_ve_task->sighand->
					action[signum - 1].sa_handler;

	/* update the value of outer register used to point the start
	 * address of calling function with the address of signal
	 * handler routine.
	 * */
	p_ve_task->p_ve_thread->SR[12] = p_ve_task->p_ve_thread->IC;

	/* set the value signal handler routine argument in SR[0],
	 * SR[1] and SR[2]
	 * */
	p_ve_task->p_ve_thread->SR[0] = signum;

	p_ve_task->p_ve_thread->SR[1] = frame_vir_addr + TRAMP_SIZE;
	p_ve_task->p_ve_thread->SR[2] = frame_vir_addr + TRAMP_SIZE + sizeof(siginfo_t);

	/* set the link register with the return address of signal handler
	 * routine, we have set link register with the address of trampoline
	 * instruction so that when signal handler routine return it will
	 * excute sigreturn instruction written as trampoline.
	 */
	p_ve_task->p_ve_thread->SR[10] = frame_vir_addr;

	/* update the value of stack pointer SR[11] for executing the signal
	 * handler routine
	 * */
	p_ve_task->p_ve_thread->SR[11] = frame_vir_addr - HANDLER_STACK_FRAME;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SIGNAL HANDLER STACK ADDRESS : %lx\n",
			p_ve_task->p_ve_thread->SR[11]);

	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");

	return ret;
}

/**
* @brief It returns the signal handler address registered
*	for signal "sig"
*
* @param[in] t Pointer to "ve_task_struct"
* @param[in] sig Signal number
*
* @return address of signal handler.
*/
static inline void *ve_sig_handler(struct ve_task_struct *t, int sig)
{
	return t->sighand->action[sig - 1].sa_handler;
}

/**
* @brief Send SIGSEGV to VE process
*
* @param signum SIGSEGV signal
* @param p_ve_task Pointer to ve_task_struct
*
* @return 0 on success
*/
int ve_force_sigsegv(int signum, struct ve_task_struct *p_ve_task)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));
	p_ve_task->sighand->action[signum - 1].sa_handler = SIG_DFL;
	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));
	psm_handle_hw_exception(p_ve_task, SEND_SIG_PRIV, SIGSEGV);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return 0;
}

/**
* @brief Dequeue the signal to be delivered from pending list.
*
* This function dequeue the signal from pending list.
* - If action is to ignore, signal is ignored and next signal
*   is dequeued from the list.
* - If the action is set to default then default action of ignore,
*   stop, terminate, or coredump is performed.
* - If the signal is being handled by the process the function
*   returns with signal number
*
* @param[in] p_ve_task p_ve_task Pointer to "ve_task_struct"
* @param[out] flag Hardware exception mapped signal
* @param[out] ve_siginfo Signal information
*
* @return 0 - when no signal is pending or signal action is to ignore
*	-1 - when signal with default action is to Stop, terminate or
*	coredump is being handled
*	>0 - when signal is being handled by VE process
*/
int ve_get_signal(struct ve_task_struct *p_ve_task, int *flag,
		siginfo_t *ve_siginfo)
{
	int signum = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pthread_mutex_lock(&(p_ve_task->siglock));
	for (;;) {
		/* Dequeue the signal */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Dequeue a signal from pending list\n");

		signum = psm_dequeue_ve_signal(ve_siginfo,
				&p_ve_task->pending,
				&p_ve_task->blocked, flag);
		if (!signum) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"No signal number\n");
			p_ve_task->sigpending = 0;
			break;
		}

		/* Signal handler registered */
		if (SIG_DFL !=
			p_ve_task->sighand->action[signum - 1].sa_handler) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal handler registered signr: %d\n",
					signum);
			p_ve_task->sigpending = 0;
			break;
		}
		/* Signals whose default action is to ignore */
		if (ve_sig_ignore(signum)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Default is IGNORE for signal %d\n",
					signum);
			signum = 0;
			continue;
		}
		/* Signal whose default action is to stop. Set the VE
		 * process state to STOP for every thread in thread group
		 * */
		if (ve_sig_stop(signum)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Default action STOP the VE process\n");
			ve_do_group_action(p_ve_task, FSIGSTOPPING, signum);
			signum = -2;
			p_ve_task->sigpending = 0;
			break;
		}

		/* Signal whose default action is generate dump + terminate */
		if (ve_sig_coredump(signum)) {
			/* TODO:
			 * Generate coredump for VE process
			 * */
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Generate Coredump\n");
			/* updating process flag when terminated by signal */
			p_ve_task->flags |= PF_DUMPCORE;
		}
		if (1 == *flag) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal generated from h/w exception\n");
			/* updating process flag when terminated by signal */
			p_ve_task->flags |= PF_SIGNALED;

			kill(p_ve_task->pid, signum);
		} else {
			/* Terminating signals
			 * */
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal Action is to Terminate\n");
			kill(p_ve_task->pid, SIGKILL);
		}
		signum = -1;
		goto hndl_ret;
	}
hndl_ret:
	pthread_mutex_unlock(&(p_ve_task->siglock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return signum;
}

/**
* @brief Execute signal handler for VE process.
*
* @param[in] p_ve_task Pointer to ve_task_struct
* @param[in] flag Hardware exception flag
* @param[in] signum Signal number to be handled
* @param[in] ve_siginfo Signal information
*
* @return -1 in case of failure and 0 in case of success.
*/
int ve_handle_signal(struct ve_task_struct *p_ve_task,
		int *flag, int signum, siginfo_t *ve_siginfo)
{
	int ret = -1;
	sigset_t blocked;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* If system call is interrupted due to system call */
	switch (p_ve_task->p_ve_thread->SR[00]) {
	case -VE_ENORESTART:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"system call is interrupted\n");
		p_ve_task->p_ve_thread->SR[00] = -EINTR;
		break;
	case -VE_ERESTARTSYS:
		if (p_ve_task->sighand->action[signum - 1].sa_flags
				& SA_RESTART) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"restarting syscall\n");
			p_ve_task->p_ve_thread->IC -= 8;
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"system call is interrupted\n");
			p_ve_task->p_ve_thread->SR[00] = -EINTR;
		}
		break;
	}

	/* Set signal handler context and save process context */
	ret = setup_ve_frame(signum, p_ve_task, ve_siginfo, *flag);
	if (0 > ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"setup_ve_frame failed\n");
		ve_force_sigsegv(SIGSEGV, p_ve_task);
		goto hndl_ret;
	}

	/* If "SA_RESETHAND" is set then reset the handler to SIG_DFL
	 * */
	if (p_ve_task->sighand->action[signum - 1].sa_flags
			& SA_RESETHAND) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"SA_RESETHAND flag set\n");
		p_ve_task->sighand->action[signum - 1].sa_handler
			= SIG_DFL;
	}
	sigorset(&blocked,
			&(p_ve_task->blocked),
			&(p_ve_task->sighand->action[signum - 1].sa_mask));

	/* If SA_NODEFER flag is not set, add the generated
	 * signal in block list
	 * */
	if (!(p_ve_task->sighand->action[signum - 1].sa_flags
				& SA_NODEFER)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"SA_NODEFER flag not set\n");
		sigaddset(&blocked, signum);
	}
	/* Clear the saved signal mask flag */
	p_ve_task->mask_saved = false;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Set the mask\n");
	psm_set_current_blocked(p_ve_task, &blocked);

hndl_ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief Deliver the generated signal.
*
* Function delivers signal to VE process.
* It dequeues a signal from signal pending list.
* If then checks the signal action:
* a. It terminates the VE process if signal action is to terminate
* or generate coredump
* b. Signal is ignored if default action is to ignore the signal.
* c. Signal handler is executed if VE process registers a signal
* handler for the signal.
*
* If restarts the system call if the signal has interrupted the
* execution of a system call.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
*
* @return -1 on error or VE process is terminated due to signal
* delivery and 0 on success.
*/
int psm_do_signal_ve(struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	int flag = 0;
	int signum = 0;
	siginfo_t ve_siginfo;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Get the signal(dequeue the signal). */
	signum = ve_get_signal(p_ve_task, &flag, &ve_siginfo);
	if (0 < signum) {
		/* Handle Signal */
		retval = ve_handle_signal(p_ve_task, &flag, signum, &ve_siginfo);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal handler stack setup has failed\n");
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal handler setup is complete\n");
			retval = 0;
		}
	} else if ((0 == signum) || (-2 == signum)) {
		/* Check if the signal interrupted the system call */
		switch (p_ve_task->p_ve_thread->SR[00]) {
		case -VE_ENORESTART:
		case -VE_ERESTARTSYS:
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Restarting syscall\n");
			p_ve_task->p_ve_thread->IC -= 8;
			break;
		}
		/* If no signal is delivered then put the saved sigmask back */
		p_ve_task->mask_saved = true;
		psm_set_current_blocked(p_ve_task,
				&(p_ve_task->ve_saved_sigmask));

		if (-2 == signum) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"VE process is stopped\n");
			retval = -1;
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Signal is ignored\n");
			retval = 0;
		}
	} else {
		/* VE process has been terminated */
		retval = -1;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief veos's handler for sigaction system call
*
* @param[in] p_ve_task_struct Pointer to "ve_task_struct"
* @param[in,out] sigaction_info Pointer to ve_signal_info containing
*	signal number and signal handler information
*
* @return: On failure, returns -1 and on success, returns a positive value
*/
void psm_do_sigaction_ve(struct ve_task_struct *p_ve_task_struct,
		struct ve_sigaction_info *sigaction_info)
{

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Sigaction for signal no = %d received\n",
			sigaction_info->signum);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "SA_MASK %ld\n",
			sigaction_info->ve_sigaction.sa_mask.__val[0]);

	/* Save the old action */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Save the oldact for signum %d\n"
			, sigaction_info->signum);
	sigaction_info->old_ve_sigaction = p_ve_task_struct->sighand->
		action[sigaction_info->signum - 1];

	/* Add new action for this signal */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"New Action added for signum %d\n"
			, sigaction_info->signum);
	p_ve_task_struct->sighand->
		action[sigaction_info->signum - 1] =
		sigaction_info->ve_sigaction;

	if (ve_sig_handler_ignored(ve_sig_handler(p_ve_task_struct,
					sigaction_info->signum),
				sigaction_info->signum)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"New Action added is to ignore the signal\n");
		ve_do_group_action(p_ve_task_struct,
				FSIGMASKING,
				sigaction_info->signum);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
* @brief Fetches current alternate signal stack information.
*
* @param[in] ve_task_curr[in] Pointer to "ve_task_struct"
* @param[out] old_sas Stores current alternate signal stack information
*/
void psm_getold_sas(struct ve_task_struct *ve_task_curr, stack_t *old_sas)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	old_sas->ss_sp = (void *)ve_task_curr->sas_ss_sp;
	old_sas->ss_size = ve_task_curr->sas_ss_size;
	if (!ve_task_curr->sas_ss_size) {
		old_sas->ss_flags = SS_DISABLE;
	} else {
		old_sas->ss_flags =
			on_sig_stack(ve_task_curr)
			? SS_ONSTACK : 0;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "old_sas->ss_sp : %p\n"
			"\t\told_sas->ss_size : %ld\n"
			"\t\told_sas->ss_flags : %d\n",
			old_sas->ss_sp,
			old_sas->ss_size,
			old_sas->ss_flags);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief Sets alternate signal stack.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
* @param[in] new_sas Alternate signal stack information.
*
* @return: Returns 0 for success, and negative value for failure.
*/
int psm_setnew_sas(struct ve_task_struct *ve_task_curr, stack_t *new_sas)
{
	int retval = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Verify the new stack pointer is valid or not
	 * */
	if (-1 == amm_addr_translation((char *)(new_sas->ss_sp),
			&(ve_task_curr->p_ve_mm->atb))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "new_sas->ss_sp : %p "
				"does not lie in process address space\n",
				new_sas->ss_sp);
		retval = -EFAULT;
		goto hndl_ret;
	}

	/* Verify whether alernate signal stack is active
	 * */
	if (on_sig_stack(ve_task_curr)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Attempt to change the alternate "
				"signal stack while it is active\n");
		retval = -EPERM;
		goto hndl_ret;
	}

	/* Verify the sas flags are valid or not
	 * */
	if (new_sas->ss_flags != SS_DISABLE &&
			new_sas->ss_flags != SS_ONSTACK &&
			new_sas->ss_flags != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Invalid SAS flag\n");
		retval = -EINVAL;
		goto hndl_ret;
	}

	/* Verify stack size is enough to execute signal handler
	 * */
	if (new_sas->ss_flags == SS_DISABLE) {
		new_sas->ss_size = 0;
		new_sas->ss_sp = NULL;
	} else {
		if (new_sas->ss_size < VE_MINSIGSTKSZ) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"New signal stack size is "
					"less than required\n");
			retval = -ENOMEM;
			goto hndl_ret;
		}
	}

	ve_task_curr->sas_ss_sp = (unsigned long) new_sas->ss_sp;
	ve_task_curr->sas_ss_size = new_sas->ss_size;
hndl_ret:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief Set the blocked signal mask for VE process.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] newset signal blocking mask
*/
void psm_set_current_blocked(struct ve_task_struct *p_ve_task,
		sigset_t *newset)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));
	p_ve_task->blocked = *newset;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Setting VE signal mask : %ld\n",
			p_ve_task->blocked.__val[0]);
	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}

/**
* @brief Sets new signal blocking mask and gets the old blocking signal mask
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] newset New signal blocking mask.
* @param[out] oldset Old signal blocking mask.
*/
void psm_do_sigprocmask(struct ve_task_struct *p_ve_task,
		sigset_t *newset,
		sigset_t *oldset)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));

	memcpy(oldset, &(p_ve_task->blocked), sizeof(sigset_t));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Old signal mask: %ld\n", oldset->__val[0]);

	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	/* Set new signal mask */
	psm_set_current_blocked(p_ve_task, newset);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}

/**
* @brief Handles the h/w exception
*
*	Check whether signal mapped to h/w exception is ignored or blocked.
*	If ignored, set signal action to default. If signal is blocked by
*	VE process unblock it. Deliver signal to VE process.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
* @param[in] signum Signal number mapped from h/w exception
*/
void psm_handle_hw_exception(struct ve_task_struct *ve_task_curr,
		siginfo_t *ve_siginfo, int signum)
{
	int blocked, ignored, flag = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");
	ignored = (ve_task_curr->sighand->action[signum - 1].sa_handler
			== SIG_IGN);
	blocked = sigismember(&(ve_task_curr->blocked), signum);
	pthread_mutex_lock(&(ve_task_curr->ve_task_lock));
	if (blocked || ignored) {
		ve_task_curr->sighand->action[signum - 1].sa_handler = SIG_DFL;
		if (blocked)
			sigdelset(&(ve_task_curr)->blocked, signum);
	}
	/* Set Synchronous signal flag */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Fatal signal occurred\n");
	flag = SYNCHRONOUS_SIGNAL;
	ve_task_curr->syncsignal = SYNCHRONOUS_SIGNAL;

	pthread_mutex_unlock(&(ve_task_curr->ve_task_lock));
	psm_send_ve_signal(ve_task_curr, ve_siginfo, signum, flag);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}

/**
* @brief Fetches the signals that are present in VE process signal
* pending list and are blocked by sigprocmask system call.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[out] veos_set Stores sigpending set.
*/
void psm_do_sigpending(struct ve_task_struct *p_ve_task,
		sigset_t *veos_set)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	pthread_mutex_lock(&(p_ve_task->ve_task_lock));
	sigandset(veos_set, &(p_ve_task->blocked), &(p_ve_task->pending.signal));
	pthread_mutex_unlock(&(p_ve_task->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}

/**
* @brief Replaces temporarily the signal mask of the calling
* process with the mask given by "mask_set"
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[out] mask_set Signal mask
*/
void psm_do_sigsuspend(struct ve_task_struct *p_ve_task, sigset_t *mask_set)
{
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	p_ve_task->ve_saved_sigmask = p_ve_task->blocked;
	psm_set_current_blocked(p_ve_task, mask_set);
	p_ve_task->mask_saved = true;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
}
