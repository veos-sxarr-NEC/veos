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
 * @file process_mgmt_comm.h
 * @brief Header file for "process_mgmt_comm.c" file.
 *
 * @internal
 * @author PSMG / Process management
 */
#ifndef __PROCESS_MGMT_COMM_H
#define __PROCESS_MGMT_COMM_H

#include <signal.h>
#include <sys/resource.h>
#include <stdbool.h>
#include "libved.h"
#include "handle.h"
#include "comm_request.h"
#include "sys_common.h"

int pseudo_psm_send_new_ve_process(int, struct new_ve_proc);
ret_t pseudo_psm_send_delete_ve_proc_req(int, int, int, int);
int pseudo_psm_recv_delete_ack(int);
int pseudo_psm_send_start_ve_proc_req(struct ve_start_ve_req_cmd *, int);
int pseudo_psm_recv_start_ve_proc(int);
int64_t pseudo_psm_send_set_tidaddr_req(int, uint64_t);
int64_t pseudo_psm_recv_set_tidaddr_ack(int);
int64_t pseudo_psm_send_clone_req(int, struct pseudo_ve_clone_info, pid_t);
int64_t pseudo_psm_recv_clone_ack(int, struct clone_response *);
int64_t pseudo_psm_send_schedule_req(int);
int64_t pseudo_psm_recv_schedule_ack(int);
ret_t pseudo_psm_send_fork_req(char *, struct pseudo_ve_clone_info, int);
int pseudo_psm_recv_fork_ack(int);
int pseudo_psm_recv_load_binary_req(int, int*, int*, int*);
int pseudo_version_compare(char *, char *);
int64_t pseudo_psm_send_clk_cputime_req(int, struct ve_clockinfo);
int64_t pseudo_psm_recv_clk_cputime_ack(int, struct timespec *);
int64_t pseudo_psm_send_get_rlimit_req(int, int, pid_t);
int64_t pseudo_psm_recv_get_rlimit_ack(int, struct rlimit *);
int64_t pseudo_psm_send_set_rlimit_req(int, int, struct rlimit, pid_t);
int64_t pseudo_psm_recv_set_rlimit_ack(int);
int64_t pseudo_psm_send_get_rusage_req(int, struct ve_rusage_info);
int64_t pseudo_psm_recv_get_rusage_ack(int, struct ve_rusage *);
int64_t pseudo_psm_send_get_times_req(int, struct ve_times_info);
int64_t pseudo_psm_recv_get_times_ack(int, struct ve_times *);

int64_t un_block_and_retval_req(veos_handle *, int, ret_t, bool);
int64_t block_syscall_req_ve_os(veos_handle *);
int64_t pseudo_psm_block_syscall_req(int);
int64_t pseudo_psm_recv_block_ack(int);

int64_t pseudo_psm_recv_core_started_ack(int);
int64_t pseudo_psm_core_start_req(int, int, pid_t);
int64_t pseudo_psm_recv_core_halt_ack(int);
int64_t pseudo_psm_halt_core_req(int, int, pid_t);
void process_thread_cleanup(veos_handle *, int);

int pseudo_psm_send_acct_req(int, char *);
int pseudo_psm_recv_acct_ack(int);

ret_t pseudo_psm_send_getcpu_req(int);
ret_t pseudo_psm_recv_getcpu_ack(int, struct ve_cpu_info *);
ret_t pseudo_psm_send_get_inr_req(int, pid_t);
ret_t pseudo_psm_recv_get_inr_ack(int, struct timespec *);
ret_t pseudo_psm_send_getaffinity_req(int, pid_t, size_t);
ret_t pseudo_psm_recv_getaffinity_ack(int, cpu_set_t *);
ret_t pseudo_psm_send_setaffinity_req(int, pid_t, cpu_set_t);
ret_t pseudo_psm_recv_setaffinity_ack(int);
ret_t pseudo_psm_send_sched_yield_req(int);
int pseudo_psm_send_sysinfo_req(int);
int pseudo_psm_recv_sysinfo_ack(int, struct sysinfo *);
ret_t pseudo_psm_send_vefd_req(int veos_sock_fd);
ret_t pseudo_psm_recv_vefd_ack(int veos_sock_fd);
int init_lhm_shm_area(veos_handle *, int *, char *);
int pseudo_psm_send_setuidgid_req(int, uint64_t, bool);
int pseudo_psm_recv_setuidgid_ack(int);
int ve_set_user_reg(veos_handle *, int, uint64_t, int64_t);
int pseudo_psm_send_get_mempolicy_req(int veos_sock_fd);
int pseudo_psm_recv_get_mempolicy_ack(int veos_sock_fd);
#endif
