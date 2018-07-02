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
 * @file pseudo_ptrace.h
 * @brief Header file for "pseudo_ptrace.c" file
 *
 * @internal
 * @author PTRACE
 */

#ifndef __PSEUDO_PTRACE_H
#define __PSEUDO_PTRACE_H

#include <signal.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include "libved.h"

extern __thread bool sys_enter_trap;

#define PTRACE_UNBLOCK_REQ	(-1)
#define PTRACE_PRIVATE_DATA 	(0x5F0000000000)
#define SYSCALL_TRACE_OFFSET    (0x8)
#define PTRACE_OPTION_OFFSET	(0x10)

#define IS_VE_TRACED(X)		(*(bool *)(PTRACE_PRIVATE_DATA + \
				vedl_get_syscall_area_offset(X)))

#define IS_SYSCALL_TRACED(X)	(*(bool *)(PTRACE_PRIVATE_DATA + \
				vedl_get_syscall_area_offset(X) +\
				SYSCALL_TRACE_OFFSET))

#define VE_PTRACE_OPTION(X)	(*(uint64_t *)(PTRACE_PRIVATE_DATA + \
				vedl_get_syscall_area_offset(X) +\
				PTRACE_OPTION_OFFSET))

void send_sig_to_itself(int, int, void *);
void ve_syscall_trace(veos_handle *, bool);
int pseudo_psm_send_ptrace_event_req(int, uint64_t);
int pseudo_psm_recv_ptrace_event_ack(int);
int ptrace_event_notify(veos_handle *, uint64_t);
int pseudo_psm_send_get_regval_req(int);
int pseudo_psm_recv_get_regval_ack(int, uint64_t *);
int prepare_and_send_signal(siginfo_t, veos_handle *);
int pseudo_handle_traceme(veos_handle *);
int pseudo_psm_send_ve_stop_req(int);
int pseudo_psm_recv_ve_stop_ack(int);
int pseudo_stop_ve_process(veos_handle *);
#endif
