/*
 * Copyright (C) 2017-2020 NEC Corporation
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
* @file	exception.c
* @brief Handles mapping of hardware exception into signal and delivers the
* signal to VE process
*
*	This file contains the function which are used to receive and handle
*	hardware exceptions.It also contains the Pseudo process signal
*	handling routine.
*
* @internal
* @author Signal Handling
*/

#include <sys/syscall.h>
#include <asm/siginfo.h>
#include <features.h>
#if  __GLIBC_PREREQ(2,26)
#define __siginfo_t_defined 1
#define __sigevent_t_defined 1
#define __sigval_t_defined 1
#define _BITS_SIGINFO_CONSTS_H 1
#define _BITS_SIGEVENT_CONSTS_H 1
#else
#define __have_siginfo_t 1
#define __have_sigval_t 1
#define __have_sigevent_t 1
#endif

#include <signal.h>
#include <veos_arch_defs.h>
#include "handle.h"
#include "exception.h"
#include "process_mgmt_comm.h"
#include "signal_comm.h"
#include "comm_request.h"
#include "velayout.h"
#include "pseudo_ptrace.h"
#include "sys_mm.h"

/* ve_proc_sigmask, stores the VE process
 * current signal mask. It will get updated after
 * every sigprocmask() and sigreturn() syscall
 * */

__thread bool pending_hw_signal = false;

/**
* @brief Pseudo process signal handler routine.
*
*	It receives multiple arguments. Using ve_send_signal_req(),
*	it will communicate with veos for sending VE process signal
*	information.
*
* @param[in] signum Signal Number
* @param[in] signal_info Pointer to siginfo_t structure
* @param[in] user_context Pointer to ucontext_t structure
*/
void ve_sa_sigaction_handler(int signum,
		siginfo_t *signal_info,
		void *user_context)
{
	int retval = -1;
	struct sigaction pseudo_act;
	sigset_t signal_mask, curr_sigmask;
	char buf[] = "Exception occured on Host\n";

	sigemptyset(&curr_sigmask);
	sigemptyset(&signal_mask);
	sigfillset(&signal_mask);

	/* Block all signals
	 * Fetch the pseudo process current signal mask
	 * */
	pthread_sigmask(SIG_BLOCK, NULL, &curr_sigmask);
	pthread_sigmask(SIG_SETMASK, &signal_mask, NULL);


	if (pending_hw_signal) {
		retval = pseudo_deliver_exception(signal_info, g_handle);
		if (0 > retval) {
			WRITE(2, "failed to deliver hardware"
					" exception request", 45);
			pseudo_abort();
		}
		pending_hw_signal = false;
		goto hndl_return;
	}

	if (((VE_MAX_SICODE >= (signal_info->si_code))
				&& ((signal_info->si_code) >= VE_MIN_SICODE))
			&& (ve_rt_sigmask(signum) & VE_SYNCHRONOUS_MASK)) {
		WRITE(2, buf, sizeof(buf));
		memset(&pseudo_act, 0, sizeof(pseudo_act));
		pseudo_act.sa_handler = SIG_DFL;
		sigaction(signum, &pseudo_act, NULL);
		return;
	}

	/* Send actual signal request to VEOS */
	ve_send_signal_req(syscall(SYS_gettid), signum, signal_info
						, user_context);
hndl_return:
	/* Unblock all signals
	 * */
	pthread_sigmask(SIG_SETMASK, &curr_sigmask, NULL);
}

/**
* @brief send the signal request to VEOS
*
*	This function is used to send and receive signal request/
*	acknowledgement to/from VE OS.
*
* @param[in] tid, target task id.
* @param[in] signum, signal number.
* @param[in] signal_info Pointer to siginfo_t structure
* @param[in] user_context Pointer to ucontext_t structure
*
*/
void ve_send_signal_req(pid_t tid, int signum, siginfo_t *signal_info
				, void *user_context)
{
	struct ve_signal_info ve_sig_info;
	int retval;


	memset(&ve_sig_info, 0, sizeof(struct ve_signal_info));
	ve_sig_info.signum = signum;
	ve_sig_info.tid = tid;
	memcpy(&(ve_sig_info.ve_siginfo), signal_info, sizeof(siginfo_t));

	retval = pseudo_psm_send_signal_req(&ve_sig_info
					, g_handle->veos_sock_fd);
	if (0 > retval) {
		WRITE(2, "Failed to communicate with VEOS\n", 33);
		pseudo_abort();
	}

	retval = pseudo_psm_recv_signal_ack(g_handle->veos_sock_fd);
	if (0 > retval) {
		WRITE(2, "Failed to communicate with VEOS\n", 33);
		pseudo_abort();
	}

}

/**
* @brief Unblock and set the default action for signal mapped from exception
*
*	This function unblocks the signal mapped from exception, it also
*	reset the signal handler to default.
*	As per requirement of #2012 this function also sets core file size
*	to zero, to avoid VH core file generation in case of VE exception.
*
* @param signum Signal number(mapped from h/w exception)
*
* @return: Returns 0 on success else -1/-errno is returned.
*/
int ve_set_sigaction_default(int signum)
{
	sigset_t mask;
	struct sigaction pseudo_act;
	int retval = -1;

	/*Added for #2012 to avoid generation of VH corefile*/
	struct rlimit core_lim;
	core_lim.rlim_cur = 0;
	core_lim.rlim_max = 0;
	if (-1 == setrlimit(RLIMIT_CORE, &core_lim)) {
		retval = -errno;
		return retval;
	}
	sigemptyset(&mask);
	sigaddset(&mask, signum);
	sigdelset(&ve_proc_sigmask, signum);
	if (-1 == sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
		retval = -errno;
		return retval;
	}

	memset(&pseudo_act, '\0', sizeof(pseudo_act));
	pseudo_act.sa_handler = SIG_DFL;
	retval = sigaction(signum, &pseudo_act, NULL);
	if (-1 == retval) {
		retval = -errno;
		return retval;
	}
	return retval;
}

/**
* @brief Deliver information of hardware exception to veos.
*
*	This function unblocks the signal mapped from hardware exception, also
*	reset the signal handler to default, then sends notification to VEOS to
*	deliver hardware mapped signal to VE process.
*
* @param ve_siginfo Hardware exception mapped signal's signal information.
*
* @return 0 on success and negative value on error.
*/
int pseudo_deliver_exception(siginfo_t *ve_siginfo, veos_handle *handle)
{
	int retval = -1;

	retval = ve_set_sigaction_default(ve_siginfo->si_signo);
	if (0 > retval)
		return retval;

	/* Send notification to veos about H/w mapped signal
	 * to be delivered to VE process
	 * */
	retval = pseudo_psm_send_exception_req(handle->veos_sock_fd
							, ve_siginfo);
	if (0 > retval)
		return retval;

	retval = pseudo_psm_recv_hw_exp_ack(handle->veos_sock_fd);
	if (0 > retval)
		return retval;

	return 0;
}

/**
* @brief Maps the hardware exception into appropriate signal.
*
*	This function after mapping the hardware exception to appropriate
*	signal communicate with veos to deliver signal to VE process.
*
* @param[in] exception Hardware exception
* @param[in] handle VEDL Handle
*
* @return: 0 on success, -1 on failure
*/
int ve_exception_handler(uint64_t exception, veos_handle *handle)
{
	int retval = 0;
	siginfo_t hw_siginfo;

	PSEUDO_TRACE("Entering");

	memset(&hw_siginfo, 0, sizeof(siginfo_t));

	/* Mapping H/w exception to signal */
	retval = _veos_arch_ops->arch_exception_to_signal(exception,
					&hw_siginfo);
	if (retval < 0)
		return retval;

	if (IS_VE_TRACED(handle->ve_handle)) {
		/* unblock signal if blocked */
		PSEUDO_DEBUG("Pseudo process is being traced");
		if (SIGTRAP != hw_siginfo.si_signo)
			pending_hw_signal = true;

		retval = prepare_and_send_signal(hw_siginfo, handle);
		if (0 > retval) {
			PSEUDO_ERROR("failed to send signal for traced process/thread");
			PSEUDO_DEBUG("sending signal to traced process/thread returned %d",
					retval);
			return retval;
		}
	} else {
		PSEUDO_DEBUG("pseudo process is not being traced");
		retval = pseudo_deliver_exception(&hw_siginfo, handle);
		if (0 > retval) {
			PSEUDO_ERROR("pseudo process failed to deliver"
					" exception");
			return retval;
		}
	}

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief This function handles the exceptions that occur at VE core.
*
*	Function waits for the exception to occur on VE core.
*	When exception occurs ,function checks the  EXS register bits
*	corresponding to exception.
*	Based upon the exception bits set in the EXS register,
*	function invokes appropriate exception handler.
*
* @param[in] handle VEOS handle
*/
void pse_exception_handler(veos_handle *handle, void *arg)
{
	int ret;
	uint64_t exs = -1;
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");
	/* Signal mask set. This set will be used to block the signal
	 * during system system call processing
	 */
	sigemptyset(&signal_mask);
	sigfillset(&signal_mask);

	while (1) {
again:
		/* After the syscall is served set the signal mask which
		 * is stored in "ve_proc_sigmask"*/
		PSEUDO_DEBUG("Task blocked set: %lx",
				ve_proc_sigmask.__val[0]);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* wait for exception and start program */
		errno = 0;
		ret = vedl_wait_exception(handle->ve_handle, &exs);
		/* Block the signal for system call processing*/
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		if (ret) {
			if (errno == EINTR) {
				goto again;
			} else {
				PSEUDO_ERROR("Failed to wait for exception: %s",
						strerror(errno));
				pthread_exit(NULL);
			}
		}
		PSEUDO_DEBUG("Task updated blocked set: %lx",
				signal_mask.__val[0]);

		_veos_arch_ops->arch_exception_handler(handle, exs);
	}
}
