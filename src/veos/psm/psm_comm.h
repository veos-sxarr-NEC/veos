/**
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
 * @file psm_comm.h
 * @brief Communication interfaces between pseudo and VEOS.
 *
 * @internal
 * @author PSMG / Process management
 */
#ifndef __PSM_PSEUDO_IPC_H
#define __PSM_PSEUDO_IPC_H
int psm_handle_send_pseudo_vefd_ack(struct veos_thread_arg *, int);
ssize_t psm_pseudo_send_cmd(int, void *, ssize_t);
int psm_pseudo_recv_cmd(int, void *, int);
int version_compare(char *, char *);
int psm_pseudo_send_start_ve(struct veos_thread_arg *, pid_t, int64_t);
int psm_pseudo_send_fork_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_fork_fail(struct veos_thread_arg *, pid_t);
int psm_pseudo_send_set_tidaddr_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_send_schedule_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_send_clone_ack(struct veos_thread_arg *,
		int64_t , struct ve_fork_info *);
int psm_pseudo_send_delete_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_block_ack(struct veos_thread_arg *, int);
int psm_pseudo_core_started_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_core_halted_ack(struct veos_thread_arg *, int64_t);
void psm_handle_hw_exception(struct ve_task_struct *, siginfo_t *, int);
int psm_pseudo_send_get_cpu_ack(struct veos_thread_arg *,
		int, struct ve_cpu_info *);
int psm_pseudo_send_getpriority_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_setpriority_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_getscheduler_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_setscheduler_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_sched_getparam_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_sched_setparam_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_sigreturn_ack(struct veos_thread_arg *, int, sigset_t *);
int psm_pseudo_send_signal_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_get_interval_ack(struct veos_thread_arg *,
		int, struct timespec *);
int psm_pseudo_clk_cputime_ack(struct veos_thread_arg *,
		int, struct timespec);
int psm_pseudo_get_rlimit_ack(struct veos_thread_arg *, int, struct rlimit);
int psm_pseudo_set_rlimit_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_setaffinity_ack(struct veos_thread_arg *, int ack_ret);
int psm_pseudo_send_getaffinity_ack(struct veos_thread_arg *pti,
		int64_t ack_ret, cpu_set_t mask, size_t cpusetsize);
int psm_pseudo_get_rusage_ack(struct veos_thread_arg *, int, struct ve_rusage);
int psm_pseudo_get_times_ack(struct veos_thread_arg *, int, struct ve_times);
int psm_pseudo_send_sysinfo_ack(struct veos_thread_arg *, int, struct sysinfo *);
int psm_pseudo_send_acct_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_get_regval_ack(struct veos_thread_arg *, int, uint64_t);
int psm_pseudo_send_sigaction_ack(struct sigaction *, struct veos_thread_arg *
									, int);
int psm_pseudo_send_sigsuspend_ack(struct veos_thread_arg *, int);
int psm_setnew_sas_ack(struct veos_thread_arg *, struct ve_sigalt_info *);
int psm_pseudo_send_sigprocmask_ack(struct ve_signal_mask *,
		struct veos_thread_arg *, int);
int psm_pseudo_send_sigpending_ack(sigset_t *, struct veos_thread_arg *, int);
int psm_pseudo_send_set_worker_ack(struct veos_thread_arg *, int ack_ret);
int psm_pseudo_send_stop_user_threads_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_start_user_threads_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_get_user_threads_state_ack(struct veos_thread_arg *, int);
int psm_handle_set_signal_mask_req(struct veos_thread_arg *pti);
int psm_pseudo_set_signal_mask_ack(struct veos_thread_arg *pti, int ack_ret);
#endif
