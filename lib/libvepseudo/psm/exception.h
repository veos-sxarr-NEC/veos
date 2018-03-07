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
* @file exception.h
* @brief Header file for "exception.c" file.
*
*	 This file contains the macros and declaration of functions used to
*	 handle hardware exceptions.
*
* @internal
* @author Signal Handling
*/
#ifndef __EXCEPTION_H
#define __EXCEPTION_H
#include <signal.h>
#include <stdbool.h>
#include <sys_common.h>
#include <unistd.h>
#include "libved.h"

#define NO_EXS	0xFFFFFFFFFFFFFF00
#define VE_ERESTARTSYS 512
#define VE_ENORESTART 513

#define RESTART_BIT 28
#define RESETHAND_BIT 31

#define VE_MAX_SICODE	8
#define VE_MIN_SICODE	1

#define ve_rt_sigmask(sig) (1ULL << ((sig)-1))

#define SPECIAL_SIGNAL(s) (( \
		(s == SIGKILL) || (s == SIGSTOP) || (s == SIGCHLD) ||\
		(s == SIGTSTP) || (s == SIGTTIN) || (s == SIGTTOU) ||\
		(s == SIGRTMIN-1) || (s == SIGRTMIN-2))?1:0)

#define VE_SYNCHRONOUS_MASK (\
		ve_rt_sigmask(SIGSEGV)  | ve_rt_sigmask(SIGBUS)   | \
		ve_rt_sigmask(SIGILL)	| ve_rt_sigmask(SIGFPE)   | \
		ve_rt_sigmask(SIGSYS))

#define IS_VE_TRACED(X)		(*(bool *)(PTRACE_PRIVATE_DATA + \
				vedl_get_syscall_area_offset(X)))

/* Verify if how argument received in sigprocmask() is valid or not */
#define valid_request(how) (((how != SIG_BLOCK) && (how != SIG_UNBLOCK)\
			&& (how != SIG_SETMASK)) ? 0 : 1)

/*Write macro to avoid rpm build failure */
#define WRITE(fd, data, size) \
	do {	\
		if (write(fd, data, size))\
		; \
	} while (0)
/**
* @brief Check whether signal number is valid or not.
*
* @param[in] sig Signal number being checked.
*
* @return: Returns 1 if valid else 0.
*/
static inline int valid_signal(unsigned long sig)
{
	return sig < _NSIG ? 1 : 0;
}

extern __thread sigset_t ve_proc_sigmask;

void pse_exception_handler(veos_handle *, void *);
int ve_exception_handler(uint64_t, veos_handle *);
void ve_sa_sigaction_handler(int, siginfo_t *, void *);
int pseudo_psm_send_exception_req(int, siginfo_t *);
int pseudo_deliver_exception(siginfo_t *, veos_handle *);
int ve_set_sigaction_default(int signum);
ret_t ve_hndl_int_p_sigset(int, char *, veos_handle *);
void ve_send_signal_req(pid_t tid, int signum, siginfo_t *signal_info
		, void *user_context);
#endif
