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
* @file	task_signal.h
* @brief Header file task_signal.c file
*
*	This file contains the macros and declaration of the functions
*	related to signal handling provided by veos.
*
* @internal
* @author Signal Handling
*/
#ifndef __PSM_SIGNAL_HANDLER_H
#define __PSM_SIGNAL_HANDLER_H

#include <signal.h>
#include "veos_handler.h"
/* Minimum stack size for alternate stack */
#define VE_MINSIGSTKSZ	533656
/* to set  signal pending flag */
#define SIGNAL_PENDING	1
/* Size of handler stack frame */
#define HANDLER_STACK_FRAME 512

/* Macro to decide if signal is synchronous */
#define SYNCHRONOUS_SIGNAL	1
/* to be used to avoid task list lock when core lock is already acquired*/
#define FORCE_SEGV		2

#define FSIGCONTINUE		0
#define FSIGMASKING		2
#define FSTOPPROC		3
#define FCLEANTHREAD		4
/* restart interrupted syscall */
#define VE_ERESTARTSYS		512
/* do not restart interrupted syscall */
#define VE_ENORESTART		513
/* path to read the format for core fie */
#define CORE_FILE		"/proc/sys/kernel/core_pattern"

#define SEND_SIG_PRIV   ((siginfo_t *) 1)

#define ve_rt_sigmask(sig) (1ULL << ((sig)-1))

#define vesiginmask(sig, mask) (ve_rt_sigmask(sig) & (mask))

#define VE_SIG_UNCATCHABLE_MASK (\
		ve_rt_sigmask(SIGKILL)   |  ve_rt_sigmask(SIGSTOP))

#define VE_SIG_STOP_MASK (\
		ve_rt_sigmask(SIGSTOP)   |  ve_rt_sigmask(SIGTSTP)   | \
		ve_rt_sigmask(SIGTTIN)   |  ve_rt_sigmask(SIGTTOU))

#define VE_SIG_COREDUMP_MASK (\
		ve_rt_sigmask(SIGQUIT)   |  ve_rt_sigmask(SIGILL)    | \
		ve_rt_sigmask(SIGTRAP)   |  ve_rt_sigmask(SIGABRT)   | \
		ve_rt_sigmask(SIGFPE)    |  ve_rt_sigmask(SIGSEGV)   | \
		ve_rt_sigmask(SIGBUS)    |  ve_rt_sigmask(SIGSYS)    | \
		ve_rt_sigmask(SIGXCPU)   |  ve_rt_sigmask(SIGXFSZ))

#define VE_SIG_IGNORE_MASK (\
		ve_rt_sigmask(SIGCHLD)   |  ve_rt_sigmask(SIGCONT)   |\
		ve_rt_sigmask(SIGWINCH)  |  ve_rt_sigmask(SIGURG))

#define ve_sig_uncatchable(sig) \
	(((sig) < SIGRTMIN) && vesiginmask(sig, VE_SIG_UNCATCHABLE_MASK))
#define ve_sig_coredump(sig) \
	(((sig) < SIGRTMIN) && vesiginmask(sig, VE_SIG_COREDUMP_MASK))
#define ve_sig_ignore(sig) \
	(((sig) < SIGRTMIN) && vesiginmask(sig, VE_SIG_IGNORE_MASK))
#define ve_sig_stop(sig) \
	(((sig) < SIGRTMIN) && vesiginmask(sig, VE_SIG_STOP_MASK))

#define VE_SYNCHRONOUS_MASK (\
		ve_rt_sigmask(SIGSEGV)	| ve_rt_sigmask(SIGBUS)   | \
		ve_rt_sigmask(SIGILL)	|  ve_rt_sigmask(SIGTRAP) | \
		ve_rt_sigmask(SIGFPE)	| ve_rt_sigmask(SIGSYS))

/* VE_EXCEPTION is a mask of exception/interrupts handled in VE
 * architecture, it must be in sync with exception/interrupts
 * handled in VE architecture to avoid unexpected behavior */
#define VE_EXCEPTION 0xF0FC7FF800800000ULL

/* Macro specifying size of LSHM area of a thread in bytes */
#define LSHM_SZ 64

/* Used to create buffer while performing dummy read in polling thread */
#define DUMMY_READ 10

#define SST_SIZE (_NSIG/8/sizeof(long))
/**
 * @brief  deletes the common signals from given signal set
 *
 *     Function update the destination set with the set obtained after
 *     deleting the signals which are common in left and right set.
 *
 * @param[out] dest Pointer to final set.
 * @param[in] left pointer to set for the reference.
 * @param[in] right pointer to signal set to be deleted.
 */
static inline void ve_sigandnsets(sigset_t *dest, const sigset_t *left
					 , const sigset_t *right)
{
	unsigned long i = 0, *d = (void *) dest, *l = (void *) left;
	unsigned long *r = (void *) right;

	for (; i < SST_SIZE; i++)
		d[i] = ((l[i]) & ~(r[i]));
}

/**
* @brief This structure saves the VE process execution context information
*/
struct ve_ucontext {
	unsigned long uc_flags;	/*!< flag */
	struct ve_ucontext *uc_link;	/*!< Pointer to process context */
	stack_t uc_stack;		/*!< stack used by this context */
	core_user_reg_t uc_mcontext;	/*!< Stores VE process context */
	sigset_t   uc_sigmask;	/*!< Signals mask while executing handler */
};

/**
* @brief This structure store the information of signal handler frame.
*
*	Signal handler frame will be written on VE task stack for saving
*	the current execution context of the VE task and executing the
*	signal handler routine.
*/
struct sigframe {
	uint64_t tramp[5];	/*!< Stores the trampoline for sigreturn() */
	char pad[256];          /*!< Pad of 256bytes for SPU coherrency */
	siginfo_t ve_siginfo;	/*!< Signal information */
	struct ve_ucontext uc;	/*!< Process context information*/
	int flag;		/*!< Flag, signal mapped from h/w signal */
	int signum;		/*!< Signal number being served */
	char lshm_area[LSHM_SZ]; /*!< Save lshm area */
};

/**
* @brief This structure store the information which is passed
* to coredumper thread
*/
struct dump_info {
	siginfo_t siginfo; /*!< Signal information*/
	struct ve_task_struct *ve_task; /*!< pointer to ve task struct */
	int flag; /*!< flag denote signal generated from h/w exception */
	int signum; /*!< signal number generating dump */
	volatile bool dumper_ready; /*!< to secure coredumper thread */
};

/**
* @brief This structure store information required during coredumping
*/
struct dump_params {
	siginfo_t siginfo; /*!< Signal information */
	struct ve_task_struct *tsk; /*!< pointer to ve task struct */
	struct rlimit limit; /*!< core file size limit */
	int fd; /*!< fd for the corefile */
	char *vaddr;   /*!< Malloc address */
	loff_t pos;  /*!<  file offset variable*/
	loff_t f_post;  /*!< file offset variable */
	pid_t hpid; /*!< helper process pid */
};

/**
* @brief This structure store the information which is passed
* to coredumper thread
*/
struct ve_corename {
	char *corename; /*!< ve core filename */
	size_t space_used; /*!< Space exhausted in corename buffer */
	size_t actual_space; /*!< memory allocated to corename buffer */
	int copy_pattern; /*!< copy updated corefile name for local use */
	int use_all; /*!< use full buffer */
	char *core_pattern; /*!< pattern contains in core_pattern file */
};

/**
* @brief Initialise signal pending list.
*
* @param[Out] sig Pointer to signal pending list.
*/
static inline void ve_init_sigpending(struct ve_sigpending *sig)
{
	sigemptyset(&sig->signal);
	INIT_LIST_HEAD(&sig->list);
}

/**
* @brief Checks whether signal is to be ignored
*
* @param[in] handler Signal handler address
* @param[in] sig signal number
*
* @return: Return 1 if signal is ignorable , else 0
*/
static inline int ve_sig_handler_ignored(void *handler, int sig)
{
	return handler == SIG_IGN ||
		(handler == SIG_DFL && ve_sig_ignore(sig));
}

/**
* @brief Checks if signal "sig" is already pending.
*
* @parami[in] signals Pending signal list
* @param[in] sig Signal number
*
* @return: Returns 1 if "sig" is member of pending queue.
*/
static inline int legacy_queue(struct ve_sigpending *signals, int sig)
{
	return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

int psm_restore_ve_context(struct ve_task_struct *);
struct ve_sigqueue *psm_ve_sigqueue_alloc(int, int, struct ve_task_struct *);
void psm_start_ve_process(struct ve_task_struct *);
void psm_stop_ve_process(struct ve_task_struct *, int, int *);
int ve_group_action(struct ve_task_struct *, int, int, int *);
void ve_do_group_action(struct ve_task_struct *, int, int);
int psm_send_ve_signal(struct ve_task_struct *,
		siginfo_t *, int, int);
void psm_prepare_trampoline_ve(struct sigframe *);
int psm_get_next_ve_signal(struct ve_sigpending *, sigset_t *);
void ve_collect_signal(siginfo_t *, struct ve_sigpending *, int, int *,
			struct ve_task_struct *);
int psm_dequeue_ve_signal(siginfo_t *, struct ve_sigpending *,  sigset_t *,
			int *, struct ve_task_struct *);
int on_sig_stack(struct ve_task_struct *);
int ve_getframe(struct ve_task_struct *, int, vemaa_t *, vemaa_t *, uint64_t *, int *);
void ve_force_sigsegv(int, struct ve_task_struct *);
int ve_format_core_filename(struct ve_corename *, struct ve_task_struct *);
int ve_get_signal(struct ve_task_struct *, int *, siginfo_t *);
int ve_handle_signal(struct ve_task_struct *, int *, int, siginfo_t *);
int psm_do_signal_ve(struct ve_task_struct *);
void psm_do_sigaction_ve(struct ve_task_struct *, struct ve_sigaction_info *);
void psm_getold_sas(struct ve_task_struct *, stack_t *);
int psm_setnew_sas(struct ve_task_struct *, stack_t *);
int psm_send_signal_ve(int, siginfo_t *, struct ve_task_struct *);
void psm_set_current_blocked(struct ve_task_struct *, sigset_t *);
void psm_do_sigprocmask(struct ve_task_struct *, struct ve_signal_mask *);
void psm_handle_hw_exception(struct ve_task_struct *, siginfo_t *, int);
void psm_do_sigpending(struct ve_task_struct *, sigset_t *);
void psm_do_sigsuspend(struct ve_task_struct *, sigset_t *);
void *do_ve_coredump(void *);
void veos_stopping_thread(void);
void veos_polling_thread(void);
int check_kill_permission(pid_t, struct ve_task_struct *, uint64_t, int);
int get_ve_corefile_fd(int);
bool is_actually_stopped(pid_t);
bool should_dump_core(struct ve_task_struct *);
#endif
