/*
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
 * @file sys_ptrace.c
 * @brief Handlers to handles request for sys_ptrace system call.
 *
 * @internal
 * @author PTRACE
 */

#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "ve_ptrace.h"
#include "ptrace_comm.h"
#include "ptrace_log.h"
#include "internal.h"

/**
 * @brief Function will resume the tracee VE process.
 *
 * @param[in] request Ptrace request
 * @param[in] pid Tracee VE process pid
 * @param[in] data Pointer to data
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_resume(enum __ptrace_request request, pid_t pid, void *data)
{
	int retval = -1;

	VE_PTRACE_TRACE("Entering");

	/* Check that the given Signal is valid or not */
	if (!signal_is_valid((unsigned long)data)) {
		VE_PTRACE_ERR("Not a Valid signal number: %ld",
				(uint64_t)data);
		retval = -EIO;
		goto hndl_return;
	}

	 /* Handling when request is PTRACE_SYSCALL */
	if (request == PTRACE_SYSCALL) {
		/* Enable system call tracing */
		retval = ve_ptrace_syscall(pid, true);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to Enable Syscall Tracing");
			goto hndl_return;
		}
	} else {
		/* Disable system call tracing */
		retval = ve_ptrace_syscall(pid, false);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to Disable Syscall Tracing");
			goto hndl_return;
		}
	}

	/* Handling when request is PTRACE_SINGLESTEP */
	if (request == PTRACE_SINGLESTEP) {
		/* Enable singlestep tracing */
		retval = ve_ptrace_singlestep(pid, true);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to Enable Singlestep");
			goto hndl_return;
		}
	} else {
		/* Disable singlestep tracing */
		retval = ve_ptrace_singlestep(pid, false);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to Disable Singlestep");
			goto hndl_return;
		}
	}

	/* Start the VE process */
	retval = ve_start_process(pid);
	if (0 > retval) {
		VE_PTRACE_ERR("VEOS Failed to start VE process");
		goto hndl_return;
	}

	/* VH ptrace(PTRACE_CONT) system call is called to start
	 * pseudo process.
	 */
	retval = ptrace(PTRACE_CONT, pid, NULL, data);
	if (-1 == retval) {
		VE_PTRACE_ERR("VH ptrace(PTRACE_CONT, %d) failed: %s",
				pid, strerror(errno));
		retval = -errno;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Generic function of ptrace which process the ve_ptrace
 * system call request.
 *
 * @param[in] request Ptrace request
 * @param[in] pid VE tracee process pid
 * @param[in] addr Pointer to address
 * @param[in] data Pointer to data
 *
 * @return Requested data for PTRACE_PEEK* requests, while other requests
 * zero on success and on error, all requests return -1, and errno is set
 * appropriately.
 */
long __ve_ptrace(enum __ptrace_request request, pid_t pid,
		void *addr, void *data)
{
	int local_errno = 0;
	long retval = -1;
	long addr_data = -1;

	VE_PTRACE_TRACE("Entering");

	switch (request) {
	case PTRACE_ATTACH:
		VE_PTRACE_DEBUG("PTRACE_ATTACH, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Attach the VE process for tracing */
		retval = ve_ptrace_attach(pid);
		if (0 > retval) {
			VE_PTRACE_ERR("Fails in Attaching VE Process: %d",
					pid);
			errno = -retval;
			retval  = -1;
			goto hndl_return;
		}
		/* VH ptrace() system call is invoked. */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_ATTACH, %d) fails: %s",
					pid, strerror(errno));
			local_errno = errno;

			/* If VH host ptrace system call fails then corresponding
			 * cleanup regarding PTRACE_ATTACH needs to be done
			 * at VEOS.
			 */
			ve_ptrace_detach(pid);
			errno = local_errno;
			goto hndl_return;
		}

		VE_PTRACE_INFO("PID: %d is now attached successfully", pid);
		break;
	case PTRACE_CONT:
	case PTRACE_SYSCALL:
	case PTRACE_SINGLESTEP:
		VE_PTRACE_DEBUG("Continue, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Resume the tracee process */
		retval = ve_ptrace_resume(request, pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to resume VE process: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		VE_PTRACE_DEBUG("PTRACE_PEEKTEXT/PEEKDATA, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Read the content at an address from VE memory */
		retval = ve_ptrace_peekdata(pid, addr, &addr_data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_PEEKTEXT/PEEKDATA Failed for PID: %d",
					pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		retval = addr_data;
		break;
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		VE_PTRACE_DEBUG("PTRACE_POKETEXT/POKEDATA, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Write the content to an address on VE memory */
		retval = ve_ptrace_pokedata(pid, addr, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_POKETEXT/POKEDATA Failed for PID: %d",
					pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_PEEKUSER:
		VE_PTRACE_DEBUG("PTRACE_PEEKUSER, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the content of requested VE register */
		retval = ve_ptrace_peekuser(pid, addr, &addr_data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_PEEKUSER Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		retval = addr_data;
		break;
	case PTRACE_POKEUSER:
		VE_PTRACE_DEBUG("PTRACE_POKEUSER, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the given content of requested VE register */
		retval = ve_ptrace_pokeuser(pid, addr, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_POKEUSER Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_GETREGS:
		VE_PTRACE_DEBUG("PTRACE_GETREGS, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the content of VE process user register set */
		retval = ve_ptrace_getregs(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_GETREGS Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_SETREGS:
		VE_PTRACE_DEBUG("PTRACE_SETREGS, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the given content of VE process user register set */
		retval = ve_ptrace_setregs(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_SETREGS Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_GETFPREGS:
		VE_PTRACE_DEBUG("PTRACE_GETFPREGS, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the content of VE process vector register set */
		retval = ve_ptrace_getvregs(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_GETFPREGS Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_SETFPREGS:
		VE_PTRACE_DEBUG("PTRACE_SETFPREGS, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the content of VE process vector register set */
		retval = ve_ptrace_setvregs(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_SETFPREGS Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_GETREGSET:
		VE_PTRACE_DEBUG("PTRACE_GETREGSET, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the content of reqested VE register set */
		retval = ve_ptrace_getregset(pid, addr, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_GETREGSET Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_SETREGSET:
		VE_PTRACE_DEBUG("PTRACE_SETREGSET, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the content of reqested VE register set */
		retval = ve_ptrace_setregset(pid, addr, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_SETREGSET Failed for PID: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	case PTRACE_GETSIGINFO:
		VE_PTRACE_DEBUG("PTRACE_GETSIGINFO, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the signal information */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_GETSIGINFO, %d) failed: %s",
					pid, strerror(errno));
			goto hndl_return;
		}
		break;
	case PTRACE_SETSIGINFO:
		VE_PTRACE_DEBUG("PTRACE_SETSIGINFO, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the signal information */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_SETSIGINFO, %d) failed: %s",
					pid, strerror(errno));
			goto hndl_return;
		}
		break;
	case PTRACE_KILL:
		VE_PTRACE_DEBUG("PTRACE_KILL, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Send the SIGKILL to tracee process */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_KILL, %d) failed: %s",
					pid, strerror(errno));
			goto hndl_return;
		}

		VE_PTRACE_INFO("PID: %d is now Killed", pid);
		break;
	case PTRACE_DETACH:
		VE_PTRACE_DEBUG("PTRACE_DETACH, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Detach and the start the normal execution of VE process */
		retval = ve_ptrace_detach(pid);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to Detach VE process: %d",
					pid);
			errno = -retval;
			retval  = -1;
			goto hndl_return;
		}
		/* VH ptrace() system call is invoked. */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_DETACH, %d) failed: %s",
					pid, strerror(errno));
			goto hndl_return;
		}

		VE_PTRACE_INFO("PID: %d is now detached successfully", pid);
		break;
	case PTRACE_SEIZE:
		VE_PTRACE_DEBUG("PTRACE_SEIZE, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Attach the VE process for tracing */
		retval = ve_ptrace_seize(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("Fails in attaching VE process: %d",
					pid);
			errno = -retval;
			retval  = -1;
			goto hndl_return;
		}
		/* VH ptrace() system call is invoked. */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_SEIZE, %d) failed: %s",
					pid, strerror(errno));
			local_errno = errno;

			/* If VH host ptrace system call fails then corresponding
			 * cleanup regarding PTRACE_ATTACH needs to be done
			 * at VEOS.
			 */
			ve_ptrace_detach(pid);
			errno = local_errno;
			goto hndl_return;
		}

		VE_PTRACE_INFO("PID: %d is now attached successfully", pid);
		break;
	case PTRACE_INTERRUPT:
		VE_PTRACE_DEBUG("PTRACE_INTERRUPT, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Stop the tracee process */
		retval = ve_stop_process(pid, true);
		if (0 > retval) {
			VE_PTRACE_ERR("Failed to STOP VE process: %d", pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		/* VH ptrace() system call is invoked. */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_INTERRUPT, %d) failed: %s",
					pid, strerror(errno));
			goto hndl_return;
		}
		break;
	case PTRACE_LISTEN:
		VE_PTRACE_DEBUG("PTRACE_LISTEN, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* VH ptrace() system call is invoked. */
		retval = ptrace(request, pid, addr, data);
		if (-1 == retval) {
			VE_PTRACE_ERR("VH ptrace(PTRACE_LISTEN, %d) fails: %s",
					pid, strerror(errno));
			goto hndl_return;
		}
		break;
	case PTRACE_SETOPTIONS:
		VE_PTRACE_DEBUG("PTRACE_SETOPTIONS, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Set the ptrace options for VE process */
		retval = ve_ptrace_setoptions(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_SETOPTIONS Failed for PID: %d",
					pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}

		/* If PTRACE_O_EXITKILL option is given then VH ptrace()
		 * system call is invoked.
		 */
		if ((unsigned long)data & (unsigned long)PTRACE_O_EXITKILL) {
			retval = ptrace(request, pid, 0, PTRACE_O_EXITKILL);
			if (-1 == retval) {
				VE_PTRACE_ERR("VH ptrace(PTRACE_SETOPTIONS, %d)"
						" fails: %s", pid,
						strerror(errno));
				goto hndl_return;
			}
		}
		break;
	case PTRACE_GETEVENTMSG:
		VE_PTRACE_DEBUG("PTRACE_GETEVENTMSG, Pid: %d, Addr: %p, Data: %p",
				pid, addr, data);

		/* Get the Ptrace event that just happened */
		retval = ve_ptrace_geteventmsg(pid, data);
		if (0 > retval) {
			VE_PTRACE_ERR("PTRACE_GETEVENTMSG Failed for PID: %d",
					pid);
			errno = -retval;
			retval = -1;
			goto hndl_return;
		}
		break;
	default:
		if (PTRACE_STOP_VE == request) {
			VE_PTRACE_DEBUG("PTRACE_STOP_VE for PID: %d", pid);
			retval = ve_stop_process(pid, false);
			if (0 > retval) {
				VE_PTRACE_ERR("Failed to STOP VE process: %d", pid);
				errno = -retval;
				retval = -1;
				goto hndl_return;
			}
			VE_PTRACE_DEBUG("Stopping VE Process Success");
		} else {
			errno = EINVAL;
			VE_PTRACE_ERR("Ptrace Request not supported for VE");
			goto hndl_return;
		}
		break;
	}

	errno = 0;
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief VE Specific ptrace system call function.
 *
 * @param[in] request Type of ptrace request
 * @param[in] ...
 *
 * @return Requested data for PTRACE_PEEK* requests, while other requests
 * zero on success and on error, all requests return -1, and errno is set
 * appropriately.
 */
long ve_ptrace(enum __ptrace_request request, ...)
{
	long retval = -1;
	va_list ap;
	pid_t pid = -1;
	void *addr = NULL, *data = NULL;

	va_start(ap, request);
	pid = va_arg(ap, pid_t);
	addr = va_arg(ap, void *);
	data = va_arg(ap, void *);
	va_end(ap);

	/* VE specific generic ptrace handler is called */
	retval = __ve_ptrace(request, pid, addr, data);
	if (-1 == retval && errno != 0)
		VE_PTRACE_ERR("ve_ptrace failed: %s", strerror(errno));

	return retval;
}
