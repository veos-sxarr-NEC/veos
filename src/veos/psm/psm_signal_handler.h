/**
* @file	psm_signal_handler.h
* @brief Header file psm_signal_handler.c file
*/
#ifndef __PSM_SIGNAL_HANDLER_H
#define __PSM_SIGNAL_HANDLER_H

#include <signal.h>
#include "veos_ipc.h"
#include "amm_mem.h"

/* Minimum stack size for alternate stack */
#define VE_MINSIGSTKSZ	533400

#define SIGNAL_PENDING	1
/* Size of trampoline */
#define TRAMP_SIZE	40
#define HANDLER_STACK_FRAME 512

#define SYNCHRONOUS_SIGNAL	1

#define FSIGCONTINUE		0
#define FSIGSTOPPING		1
#define FSIGMASKING		2
#define FSTOPPROC		3

#define VE_ERESTARTSYS		512
#define VE_ENORESTART		513

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

#define VE_EXCEPTION 0xF0FC7E0000000000ULL

/* Macro specifying size of LSHM area of a thread in bytes */
#define LSHM_SZ 64

/**
* @brief This structure saves the VE process execution context information
*/
struct ve_ucontext {
	unsigned long uc_flags;	/*!< flag */
	struct ve_ucontext *uc_link;	/*!< Pointer to process context */
	stack_t uc_stack;		/*!< stack used by this context */
	struct ve_thread_struct uc_mcontext;	/*!< Stores VE process context */
	sigset_t   uc_sigmask;	/*!< Signals mask while executing signal handler */
};

/**
* @brief This structure store the information of signal handler frame.
*	Signal handler frame will be written on VE task stack for saving
*	the current execution context of the VE task and executing the
*	signal handler routine.
*/
struct sigframe {
	uint64_t tramp[5];	/*!< Stores the trampoline for sigreturn() */
	siginfo_t ve_siginfo;	/*!< Signal information */
	struct ve_ucontext uc;	/*!< Process context information*/
	int flag;		/*!< Flag to denote signal mapped from h/w signal */
	int signum;		/*!< Signal number being served */
	char lshm_area[LSHM_SZ]; /*!< Save lshm area */
};

/**
* @brief Initialise signal pending list.
*
* @param sig Pointer to signal pending list.
*/
static inline void ve_init_sigpending(struct ve_sigpending *sig)
{
	sigemptyset(&sig->signal);
	INIT_LIST_HEAD(&sig->list);
}

/**
* @brief Checks whether signal is to be ignored
*
* @param handler Signal handler address
* @param sig signal number
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
void psm_set_sigret_flag(struct ve_task_struct *);
int psm_restore_ve_context(struct ve_task_struct *);
int psm_send_ve_signal(struct ve_task_struct *,
		siginfo_t *, int, int);
void psm_do_sigaction_ve(struct ve_task_struct *, struct ve_sigaction_info *);
int psm_send_signal_ve(int, siginfo_t *, struct ve_task_struct *);
void psm_prepare_trampoline_ve(struct sigframe *);
int ve_handle_signal(struct ve_task_struct *, int *, int, siginfo_t *);
int ve_get_signal(struct ve_task_struct *, int *, siginfo_t *);
int psm_do_signal_ve(struct ve_task_struct *);
void psm_getold_sas(struct ve_task_struct *, stack_t *);
int psm_setnew_sas(struct ve_task_struct *, stack_t *);
void psm_set_current_blocked(struct ve_task_struct *, sigset_t *);
void psm_do_sigprocmask(struct ve_task_struct *, sigset_t *, sigset_t *);
int psm_check_sync_signal_pending(struct ve_task_struct *, int);
void psm_do_sigpending(struct ve_task_struct *, sigset_t *);
void psm_do_sigsuspend(struct ve_task_struct *, sigset_t *);
void ve_do_group_action(struct ve_task_struct *, int, int);
#endif
