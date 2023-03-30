/*
 * Copyright (C) 2020 NEC Corporation
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
* @brief VE1-dependent part of exception handling
*
* @internal
* @author Signal Handling
*/
#include <string.h>
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
#include <ve_hw.h>

#define NO_EXS 0xFFFFFFFFFFFFFF00UL
#include "veos_arch_defs.h"
#include "sys_common.h"
#include "exception.h"
#include "process_mgmt_comm.h"
#include "pseudo_ptrace.h"

/**
* @brief Maps the hardware exception into appropriate signal.
*
*	This function after mapping the hardware exception to appropriate
*	signal communicate with veos to deliver signal to VE process.
*
* @param[in] exception Hardware exception
* @param[out] siginfo signal information corresponding to exception
*
* @return: 0 on success, -1 on failure
*/
int ve1_exception_to_signal(uint64_t exception, siginfo_t *siginfo)
{
	PSEUDO_TRACE("Entering");

	memset(siginfo, 0, sizeof(siginfo_t));

	/* Mapping H/w exception to signal */
	switch (exception) {
	/* ILMP/ILSP/ILPV mapped to SIGSEGV */
	case EXS_ILMP:
	case EXS_HMILMP:
	case EXS_HMILMS:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		siginfo->si_signo = SIGSEGV;
		siginfo->si_code = SEGV_MAPERR;
		break;
	case EXS_ILSP:
	case EXS_HMILSP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		siginfo->si_signo = SIGSEGV;
		siginfo->si_code = SEGV_ACCERR;
		break;
	case EXS_ILMS:
	case EXS_HMILSA:
		PSEUDO_DEBUG("Hardware exception mappped to SIGSEGV");
		siginfo->si_signo = SIGSEGV;
		siginfo->si_code = SEGV_MAPERR;
		break;
		/* ILSA is mapped onto SIGBUS */
	case EXS_ILSA:
		PSEUDO_DEBUG("Hardware exception mappped to SIGBUS");
		siginfo->si_signo = SIGBUS;
		siginfo->si_code = BUS_ADRALN;
		break;
	case EXS_IOAC:
		PSEUDO_DEBUG("Hardware exception mappped to SIGBUS");
		siginfo->si_signo = SIGBUS;
		siginfo->si_code = BUS_ADRERR;
		break;
		/* DIVE/FOFE/FUFE/XOFE/INVE/INEE mapped to SIGFPE */
	case EXS_DIVE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_FLTDIV;
		break;
	case EXS_FOFE:
		PSEUDO_DEBUG("Hardware exception  mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_FLTOVF;
		break;
	case EXS_FUFE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_FLTUND;
		break;
	case EXS_XOFE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_INTOVF;
		break;
	case EXS_INVE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_FLTINV;
		break;
	case EXS_INEE:
		PSEUDO_DEBUG("Hardware exception mappped to SIGFPE");
		siginfo->si_signo = SIGFPE;
		siginfo->si_code = FPE_FLTRES;
		break;
		/* ILOP/ILDT mapped to SIGILL */
	case EXS_ILOP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGILL");
		siginfo->si_signo = SIGILL;
		siginfo->si_code = ILL_ILLOPC;
		break;
	case EXS_ILDT:
		PSEUDO_DEBUG("Hardware exception mappped to SIGILL");
		siginfo->si_signo = SIGILL;
		siginfo->si_code = ILL_ILLOPN;
		break;
		/* ADRM/BRTR/STEP mapped to SIGTRAP */
	case EXS_ADRM:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		siginfo->si_signo = SIGTRAP;
		siginfo->si_code = TRAP_HWBKPT;
		break;
	case EXS_BRTR:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		siginfo->si_signo = SIGTRAP;
		siginfo->si_code = TRAP_BRANCH;
		break;
	case EXS_STEP:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		siginfo->si_signo = SIGTRAP;
		siginfo->si_code = TRAP_TRACE;
		break;
	case EXS_MONT:
		PSEUDO_DEBUG("Hardware exception mappped to SIGTRAP");
		siginfo->si_signo = SIGTRAP;
		siginfo->si_code = TRAP_BRKPT;
		break;
	default:
		PSEUDO_ERROR("Anonymous Hardware exception received");
		return -1;
	}

	siginfo->si_addr = NULL;
	siginfo->si_errno = 0;
	return 0;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_exception_to_signal, ve1_exception_to_signal)

/**
* @brief VE1-dependent part of exception handler
*
* @param[in] handle VEOS handle
* @param[in] exs exception register value set by vedl_wait_exception().
*/
void ve1_exception_handler(veos_handle *handle, uint64_t exs)
{
	uint64_t ve_hw_exception = -1;
	int64_t ret;

	PSEUDO_TRACE("Entering");

	if (!(exs & NO_EXS)) {
		PSEUDO_DEBUG("No exception exs: %lx", exs);
		return;
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
				vedl_get_syscall_num(handle->ve_handle));

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
			fprintf(stderr, "Handling of exception failed.\n");
			pseudo_abort();
		}
		ret = ve_exception_handler(ve_hw_exception, handle);
		if (0 != ret) {
			PSEUDO_ERROR("failed to handle hardware exception");
			fprintf(stderr, "Handling of exception failed\n");
			pseudo_abort();
		}

		/* Send the unblock req to VEOS when a traced process
		 * got CORRECTABLE_ERROR.
		 */
		if ((exs & EXS_MONT) || (exs & EXS_ADRM) ||
			(exs & EXS_BRTR) || (exs & EXS_STEP)) {
			PSEUDO_DEBUG("Sending unblock when exs: %lx", exs);
			un_block_and_retval_req(handle,
					PTRACE_UNBLOCK_REQ, 0, true);
		}
	}
}

VEOS_ARCH_DEP_FUNC(ve1, arch_exception_handler, ve1_exception_handler)
