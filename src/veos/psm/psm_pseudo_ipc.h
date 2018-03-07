/**
 * @file psm_pseudo_ipc.h
 * @brief Communication interfaces between pseudo and VEOS.
 */
#ifndef __PSM_PSEUDO_IPC_H
#define __PSM_PSEUDO_IPC_H
ssize_t psm_pseudo_send_cmd(int, void *, int);
int psm_pseudo_recv_cmd(int, void *, int);
int psm_pseudo_send_start_ve(struct veos_thread_arg *, pid_t, int64_t);
int psm_pseudo_send_fork_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_fork_fail(struct veos_thread_arg *, pid_t);
int psm_pseudo_send_set_tidaddr_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_send_schedule_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_send_clone_ack(struct veos_thread_arg *,
		int64_t , struct ve_fork_info *);
int psm_pseudo_send_delete_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_block_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_un_block_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_syscall_ret_ack(struct veos_thread_arg *, int);
int psm_pseudo_core_started_ack(struct veos_thread_arg *, int64_t);
int psm_pseudo_core_halted_ack(struct veos_thread_arg *, int64_t);
void psm_handle_hw_exception(struct ve_task_struct *, siginfo_t *, int);
int psm_handle_sigpending_req(struct veos_thread_arg *);
int psm_pseudo_send_get_cpu_ack(struct veos_thread_arg *,
		int, struct ve_cpu_info *);
int psm_pseudo_send_getpriority_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_setpriority_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_getscheduler_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_setscheduler_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_sched_getparam_ack(struct veos_thread_arg *, int, int);
int psm_pseudo_send_sched_setparam_ack(struct veos_thread_arg *, int);
int psm_pseudo_pr_set_mm_ack(struct veos_thread_arg *, int);

int psm_pseudo_send_get_interval_ack(struct veos_thread_arg *,
		int, struct timespec *);
int psm_pseudo_clk_cputime_ack(struct veos_thread_arg *,
		int, struct timespec);
int psm_pseudo_get_rlimit_ack(struct veos_thread_arg *, int, struct rlimit);
int psm_pseudo_set_rlimit_ack(struct veos_thread_arg *, int);
int psm_pseudo_send_setaffinity_ack(struct veos_thread_arg *, int ack_ret);
int psm_pseudo_send_getaffinity_ack(struct veos_thread_arg *, int64_t ack_ret);
int psm_pseudo_get_rusage_ack(struct veos_thread_arg *, int, struct ve_rusage);
int psm_pseudo_send_sysinfo_ack(struct veos_thread_arg *, int, struct sysinfo *);
int psm_pseudo_send_acct_ack(struct veos_thread_arg *, int);

#endif
