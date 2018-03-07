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
 * @brief VE Ptrace Library interfaces/data structures for
 * communicating with VEOS.
 *
 * @internal
 * @author PTRACE
 */

#ifndef __PTRACE_COMM_H
#define __PTRACE_COMM_H

#include <stdint.h>
#include <sys/ptrace.h>

#define MAX_VE_NODE		16
#define MAX_PROTO_MSG_SIZE	4096
#define PTRACE_REQUEST		1
#define MIN(X, Y)		X < Y ? X:Y

/**
 * @brief VE Ptrace requests
 */
enum ptrace_req_cmd {
	STOP_PROCESS = 0,	/*!< Stop the VE Tracee */
	START_PROCESS,		/*!< Start the VE Tracee */
	ATTACH,			/*!< Attach the VE process for tracing */
	PEEKDATA,		/*!< Get content of VE memory */
	POKEDATA,		/*!< Write content to VE memory */
	PEEKUSER,		/*!< Get content of VE user register */
	POKEUSER,		/*!< Store content of VE user register */
	GETREGS,                /*!< Get the VE user register set */
	SETREGS,                /*!< Store the VE user register set */
	GETVREGS,		/*!< Get the VE vector register set */
	SETVREGS,		/*!< Store the VE vector register set */
	DETACH,			/*!< Detach the VE process from tracing */
	SEIZE,			/*!< Attach(SEIZE) the VE process for tracing */
	SYSCALL,		/*!< Enable/disable System call tracing */
	SINGLESTEP,		/*!< Enable/disable Singlestep tracing */
	SETOPTIONS,		/*!< VE ptrace options */
	GETEVENTMSG,		/*!< Get ptrace event that message */
	CHECK_PID,		/*!< Check VE process exists or not */
	PTRACE_INVAL = -1	/*!< Invalid Request */
};

/**
 * @brief Communication structure contains ptrace system call arguments.
 */
typedef struct ptrace_request_struct {
	enum ptrace_req_cmd ptrace_cmd;	/*!< VE ptrace command */
	pid_t pid;			/*!< PID of VE Tracee */
	uint64_t addr;			/*!< Address to access */
	uint64_t data;			/*!< Address to data */
} ptrace_req;

int veos_sock(int);
int get_veos_sock_fd(pid_t);
int check_ve_pid(int, pid_t);
int find_ve_process_node_number(pid_t);
ssize_t veos_write_buf(int, void *, ssize_t);
ssize_t veos_read_buf(int, void *);
int pack_and_send_cmd(int, ptrace_req);
int recv_and_unpack_cmd(int, ptrace_req *);
int ve_start_process(pid_t);
int ve_stop_process(pid_t, bool);
int ve_ptrace_attach(pid_t);
int ve_ptrace_peekdata(pid_t, void *, void *);
int ve_ptrace_pokedata(pid_t, void *, void *);
int ve_ptrace_peekuser(pid_t, void *, void *);
int ve_ptrace_pokeuser(pid_t, void *, void *);
int ve_ptrace_getregs(pid_t, void *);
int ve_ptrace_setregs(pid_t, void *);
int ve_ptrace_getvregs(pid_t, void *);
int ve_ptrace_setvregs(pid_t, void *);
int ve_ptrace_getregset(pid_t, void *, void *);
int ve_ptrace_setregset(pid_t, void *, void *);
int ve_ptrace_detach(pid_t);
int ve_ptrace_seize(pid_t, void *);
int ve_ptrace_syscall(pid_t, bool);
int ve_ptrace_singlestep(pid_t, bool);
int ve_ptrace_setoptions(pid_t, void *);
int ve_ptrace_geteventmsg(pid_t, void *);
#endif
