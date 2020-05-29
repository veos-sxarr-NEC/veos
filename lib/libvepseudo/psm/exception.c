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
	switch (exception) {
	/* ILMP/ILSP/ILPV mapped to SIGSEGV */
	case EXS_ILMP:
	case EXS_HMILMP:
	case EXS_HMILMS:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		hw_siginfo.si_signo = SIGSEGV;
		hw_siginfo.si_code = SEGV_MAPERR;
		break;
	case EXS_ILSP:
	case EXS_HMILSP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		hw_siginfo.si_signo = SIGSEGV;
		hw_siginfo.si_code = SEGV_ACCERR;
		break;
	case EXS_ILMS:
	case EXS_HMILSA:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		hw_siginfo.si_signo = SIGSEGV;
		hw_siginfo.si_code = SEGV_MAPERR;
		break;
		/* ILSA is mapped onto SIGBUS */
	case EXS_ILSA:
		PSEUDO_DEBUG("Hardware exception mappped to SIGBUS");
		hw_siginfo.si_signo = SIGBUS;
		hw_siginfo.si_code = BUS_ADRALN;
		break;
	case EXS_IOAC:
		PSEUDO_DEBUG("Hardware exception mappped to SIGBUS");
		hw_siginfo.si_signo = SIGBUS;
		hw_siginfo.si_code = BUS_ADRERR;
		break;
		/* DIVE/FOFE/FUFE/XOFE/INVE/INEE mapped to SIGFPE */
	case EXS_DIVE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_FLTDIV;
		break;
	case EXS_FOFE:
		PSEUDO_DEBUG("Hardware exception  mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_FLTOVF;
		break;
	case EXS_FUFE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_FLTUND;
		break;
	case EXS_XOFE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_INTOVF;
		break;
	case EXS_INVE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_FLTINV;
		break;
	case EXS_INEE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		hw_siginfo.si_signo = SIGFPE;
		hw_siginfo.si_code = FPE_FLTRES;
		break;
		/* ILOP/ILDT mapped to SIGILL */
	case EXS_ILOP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGILL");
		hw_siginfo.si_signo = SIGILL;
		hw_siginfo.si_code = ILL_ILLOPC;
		break;
	case EXS_ILDT:
		PSEUDO_DEBUG("Hardware exception mappped to SIGILL");
		hw_siginfo.si_signo = SIGILL;
		hw_siginfo.si_code = ILL_ILLOPN;
		break;
		/* ADRM/BRTR/STEP mapped to SIGTRAP */
	case EXS_ADRM:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		hw_siginfo.si_signo = SIGTRAP;
		hw_siginfo.si_code = TRAP_HWBKPT;
		break;
	case EXS_BRTR:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		hw_siginfo.si_signo = SIGTRAP;
		hw_siginfo.si_code = TRAP_BRANCH;
		break;
	case EXS_STEP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		hw_siginfo.si_signo = SIGTRAP;
		hw_siginfo.si_code = TRAP_TRACE;
		break;
	case EXS_MONT:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		hw_siginfo.si_signo = SIGTRAP;
		hw_siginfo.si_code = TRAP_BRKPT;
		break;
	default:
		PSEUDO_ERROR("Anonymous Hardware exception received");
		return -1;
	}

	hw_siginfo.si_addr = NULL;
	hw_siginfo.si_errno = 0;

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
	uint64_t ve_hw_exception = -1;
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

		if (!(exs & NO_EXS)) {
			PSEUDO_DEBUG("No exception exs: %lx", exs);
			goto again;
		}

		/* Exceptions */
		if (exs & EXS_ILMP) {
			PSEUDO_INFO("exception EXS_ILMP");
			ve_hw_exception = EXS_ILMP;
		}
		if (exs & EXS_ILMS) {
			PSEUDO_INFO("exception EXS_ILMS");
			ve_hw_exception = EXS_ILMS;
		}
		if (exs & EXS_ILSP) {
			PSEUDO_INFO("exception EXS_ILSP");
			ve_hw_exception = EXS_ILSP;
		}
		if (exs & EXS_ILSA) {
			PSEUDO_INFO("exception EXS_ILSA");
			ve_hw_exception = EXS_ILSA;
		}
		if (exs & EXS_DIVE) {
			PSEUDO_INFO("exception EXS_DIVE");
			ve_hw_exception = EXS_DIVE;
		}
		if (exs & EXS_FOFE) {
			PSEUDO_INFO("exception EXS_FOFE");
			ve_hw_exception = EXS_FOFE;
		}
		if (exs & EXS_FUFE) {
			PSEUDO_INFO("exception EXS_FUFE");
			ve_hw_exception = EXS_FUFE;
		}
		if (exs & EXS_XOFE) {
			PSEUDO_INFO("exception EXS_XOFE");
			ve_hw_exception = EXS_XOFE;
		}
		if (exs & EXS_INVE) {
			PSEUDO_INFO("exception EXS_INVE");
			ve_hw_exception = EXS_INVE;
		}
		if (exs & EXS_INEE) {
			PSEUDO_INFO("exception EXS_INEE");
			ve_hw_exception = EXS_INEE;
		}
		if (exs & EXS_ILOP) {
			PSEUDO_INFO("exception EXS_ILOP");
			ve_hw_exception = EXS_ILOP;
		}
		if (exs & EXS_ILDT) {
			PSEUDO_INFO("exception EXS_ILDT");
			ve_hw_exception = EXS_ILDT;
		}
		if (exs & EXS_HMILMP) {
			PSEUDO_INFO("exception EXS_HMILMP");
			ve_hw_exception = EXS_HMILMP;
		}
		if (exs & EXS_HMILMS) {
			PSEUDO_INFO("exception EXS_HMILMS");
			ve_hw_exception = EXS_HMILMS;
		}
		if (exs & EXS_HMILSP) {
			PSEUDO_INFO("exception EXS_HMILSP");
			ve_hw_exception = EXS_HMILSP;
		}
		if (exs & EXS_HMILSA) {
			PSEUDO_INFO("exception EXS_HMILSA");
			ve_hw_exception = EXS_HMILSA;
		}
		if (exs & EXS_IOAC) {
			PSEUDO_INFO("exception EXS_IOAC");
			ve_hw_exception = EXS_IOAC;
		}

		if (exs & EXS_MONT) {
			PSEUDO_DEBUG("exception EXS_MONT");
			ve_hw_exception = EXS_MONT;
		} else if (exs & EXS_MONC) {
			PSEUDO_DEBUG("exception EXS_MONC");

			/* System call trace at entry */
			ve_syscall_trace(handle, true);


			/* call system call handler */
			ve_syscall_handler(handle,
					vedl_get_syscall_num
						(handle->ve_handle));

			/* System call trace at exit */
			ve_syscall_trace(handle, false);
		}
		if (exs & EXS_ADRM) {
			PSEUDO_DEBUG("exception EXS_ADRM");
			ve_hw_exception = EXS_ADRM;
		}
		if (exs & EXS_BRTR) {
			PSEUDO_DEBUG("exception EXS_BRTR");
			ve_hw_exception = EXS_BRTR;
		}
		if (exs & EXS_STEP) {
			PSEUDO_DEBUG("exception EXS_STEP");
			ve_hw_exception = EXS_STEP;
		}
		if (exs & EXS_RDBG) {
			PSEUDO_DEBUG("Fast sync debug interrupt received");
			ret = pseudo_stop_ve_process(handle);
			if (0 > ret) {
				PSEUDO_ERROR("fail to stop ve process");
				fprintf(stderr, "fail to stop ve process\n");
				pseudo_abort();
			}
		}


		/* return when the exception is uncorrectable or unknown */
		if ((exs & EXS_MONT) || (exs & (UNCORRECTABLE_ERROR)) ||
				((exs & (CORRECTABLE_ERROR))
				 && !(exs & (EXS_MONC|EXS_RDBG)))) {
			/* Send BLOCKING System call request to Aurora OS */
			ret = block_syscall_req_ve_os(handle);
			if (0 != ret) {
				PSEUDO_ERROR("veos failed to perform syscall"
						" pre-processing");
				fprintf(stderr
					, "Handling of exception failed.\n");
				pseudo_abort();
			}
			ret = ve_exception_handler(ve_hw_exception, handle);
			if (0 != ret) {
				PSEUDO_ERROR("failed to handle hardware"
						" exception");
				fprintf(stderr
					, "Handling of exception failed\n");
				pseudo_abort();
			}

			/* Send the unblock req to VEOS when a traced process
			 * got CORRECTABLE_ERROR.
			 */
			if ((exs & EXS_MONT) || (exs & EXS_ADRM) ||
				(exs & EXS_BRTR) || (exs & EXS_STEP)) {
				PSEUDO_DEBUG("Sending unblock when exs: %lx",
						exs);
				un_block_and_retval_req(handle,
						PTRACE_UNBLOCK_REQ, 0, true);
			}
		}
	}
}
