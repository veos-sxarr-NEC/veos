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
 * @file ptrace_comm.h
 * @brief VEOS interfaces for handling ptrace request for VE.
 *
 * @internal
 * @author PTRACE
 */
#ifndef __VEOS_PTRACE_REQ
#define __VEOS_PTRACE_REQ

#include <stdint.h>
#include "comm_request.h"

/**
 * @brief VE Ptrace requests
 */
enum ptrace_req_cmd {
	STOP_PROCESS = 0,	/*!< Stop the VE Tracee */
	START_PROCESS,		/*!< Start the VE Tracee */
	ATTACH,			/*!< Attach the VE process for tracing */
	PEEKDATA,               /*!< Get content of VE memory */
	POKEDATA,               /*!< Write content to VE memory */
	PEEKUSER,               /*!< Get content of VE user register */
	POKEUSER,               /*!< Store content of VE user register */
	GETREGS,                /*!< Get the VE user register set */
	SETREGS,                /*!< Store the VE user register set */
	GETVREGS,		/*!< Get the VE vector register set */
	SETVREGS,		/*!< Store the VE vector register set */
	DETACH,                 /*!< Detach the VE process from tracing */
	SEIZE,                  /*!< Attach(SEIZE) the VE process for tracing */
	SYSCALL,		/*!< Enable/disable System call tracing */
	SINGLESTEP,		/*!< Enable/disable Singlestep tracing */
	SETOPTIONS,             /*!< VE ptrace options */
	GETEVENTMSG,            /*!< Get ptrace event that message */
	CHECK_PID,              /*!< Check VE process exists or not */
	PTRACE_INVAL = -1	/*!< Invalid Request */
};

/**
 * @brief Communication structure contains ptrace system call arguments.
 */
typedef struct ptrace_req_struct {
	enum ptrace_req_cmd ptrace_cmd;	/*!< VE ptrace command */
	pid_t pid;			/*!< PID of VE Tracee */
	uint64_t addr;			/*!< Address to acces */
	uint64_t data;			/*!< Address to data */
} ptrace_req;

ssize_t veos_ptrace_write_buf(int, void *, ssize_t);
void veos_ptrace_send_cmd_response(int, uint8_t *, int64_t, int64_t);
int veos_ptrace_stop_process(struct veos_thread_arg *, pid_t, bool);
int veos_ptrace_start_process(struct veos_thread_arg *, pid_t);
int veos_ptrace_attach(struct veos_thread_arg *, pid_t);
int veos_ptrace_check_pid(struct veos_thread_arg *, pid_t);
int veos_ptrace_peekdata(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_pokedata(struct veos_thread_arg *, pid_t, uint64_t, uint64_t);
int veos_ptrace_peekuser(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_pokeuser(struct veos_thread_arg *, pid_t, uint64_t, uint64_t);
int veos_ptrace_getregs(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_setregs(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_getvregs(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_setvregs(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_detach(struct veos_thread_arg *, pid_t);
int veos_ptrace_seize(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_syscall(struct veos_thread_arg *, pid_t, bool);
int veos_ptrace_singlestep(struct veos_thread_arg *, pid_t, bool);
int veos_ptrace_setoptions(struct veos_thread_arg *, pid_t, uint64_t);
int veos_ptrace_geteventmsg(struct veos_thread_arg *, pid_t);
#endif
