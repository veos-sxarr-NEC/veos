/**
* @file pseudo_psmg_ipc.h
* @brief Header file for "pseudo_psmg_ipc.c" file.
*/
#ifndef __PSEUDO_PSMG_IPC_H
#define __PSEUDO_PSMG_IPC_H

#include <signal.h>
#include <sys/resource.h>
#include <stdbool.h>
#include "libved.h"
#include "syscall_common.h"
#include "veos_pseudo_interface.h"

#ifdef __PCIDEV_ENV
#define PSEUDO_VE_DEV_FILE "/dev/auve_sys0"
#endif

#ifdef __AUSIM_ENV
#define VE_SINGLE_CORE 1
#endif
#define VE_ALL_CORE 0

int pseudo_psm_send_new_ve_process(int, struct new_ve_proc);
ret_t pseudo_psm_send_delete_ve_proc_req(int, int, int);
int pseudo_psm_recv_delete_ack(int);
int pseudo_psm_send_start_ve_proc_req(struct ve_context_info*, int);
int pseudo_psm_recv_start_ve_proc(int);
int64_t pseudo_psm_send_set_tidaddr_req(int, uint64_t);
int64_t pseudo_psm_recv_set_tidaddr_ack(int);
int64_t pseudo_psm_send_clone_req(int, struct pseudo_ve_clone_info, pid_t);
int64_t pseudo_psm_recv_clone_ack(int, struct clone_response *);
int64_t pseudo_psm_send_schedule_req(int);
int64_t pseudo_psm_recv_schedule_ack(int);
ret_t pseudo_psm_send_fork_req(char *, struct pseudo_ve_clone_info, int);
int pseudo_psm_recv_fork_ack(int);
int pseudo_psm_recv_load_binary_req(int, int*, int*);
int64_t pseudo_psm_send_clk_cputime_req(int, int);
int64_t pseudo_psm_recv_clk_cputime_ack(int, struct timespec *);
int64_t pseudo_psm_send_get_rlimit_req(int, int, pid_t);
int64_t pseudo_psm_recv_get_rlimit_ack(int, struct rlimit *);
int64_t pseudo_psm_send_set_rlimit_req(int, int, struct rlimit, pid_t);
int64_t pseudo_psm_recv_set_rlimit_ack(int);
int64_t pseudo_psm_send_get_rusage_req(int, int);
int64_t pseudo_psm_recv_get_rusage_ack(int, struct ve_rusage *);

int64_t un_block_syscall_req_ve_os(void);
int64_t block_syscall_req_ve_os(void);
int64_t pseudo_psm_block_syscall_req(int);
int64_t pseudo_psm_recv_block_ack(int);
int64_t pseudo_psm_un_block_syscall_req(int);
int64_t pseudo_psm_recv_un_block_ack(int);

int ve_set_ve_reg(uint64_t, uint64_t);
int pseudo_psm_set_syscall_return_req(int , uint64_t, uint64_t);
int pseudo_psm_recv_syscall_return_ack(int);

int64_t pseudo_psm_recv_core_started_ack(int);
int64_t pseudo_psm_core_start_req(int, int, pid_t);
int64_t pseudo_psm_recv_core_halt_ack(int);
int64_t pseudo_psm_halt_core_req(int, int, pid_t);
void process_thread_cleanup(vedl_handle *, int);

ret_t pseudo_psm_send_get_priority_max_req(int);
int pseudo_psm_recv_get_priority_max_ack(int);
ret_t pseudo_psm_send_get_priority_min_req(int);
int pseudo_psm_recv_get_priority_min_ack(int);


int pseudo_psm_send_acct_req(int, char *);
int pseudo_psm_recv_acct_ack(int);
ret_t pseudo_psm_send_getpriority_req(int, pid_t);
int pseudo_psm_recv_getpriority_ack(int);
ret_t pseudo_psm_send_setpriority_req(int, struct ve_prio_info *);
ret_t pseudo_psm_recv_setpriority_ack(int);

ret_t pseudo_psm_send_getscheduler_req(int, pid_t);
int pseudo_psm_recv_getscheduler_ack(int);
ret_t pseudo_psm_send_setscheduler_req(int, struct ve_sched_info *);
ret_t pseudo_psm_recv_setscheduler_ack(int);

ret_t pseudo_psm_send_sched_getparam_req(int, struct ve_sched_info *);
int pseudo_psm_recv_sched_getparam_ack(int);
ret_t pseudo_psm_send_sched_setparam_req(int, struct ve_sched_info *);
ret_t pseudo_psm_recv_sched_setparam_ack(int);
ret_t pseudo_psm_send_getcpu_req(int);
ret_t pseudo_psm_recv_getcpu_ack(int, struct ve_cpu_info *);
ret_t pseudo_psm_send_get_inr_req(int, pid_t);
ret_t pseudo_psm_recv_get_inr_ack(int, struct timespec *);
ret_t pseudo_psm_send_getaffinity_req(int, pid_t, size_t);
ret_t pseudo_psm_recv_getaffinity_ack(int, uint64_t *);
ret_t pseudo_psm_send_setaffinity_req(int, pid_t, uint64_t);
ret_t pseudo_psm_recv_setaffinity_ack(int);
ret_t pseudo_psm_send_sched_yield_req(int);
ret_t pseudo_psm_send_pr_set_mm_req(int, uint64_t, uint64_t);
ret_t pseudo_psm_recv_pr_set_mm_ack(int);
int pseudo_psm_send_sysinfo_req(int);
int pseudo_psm_recv_sysinfo_ack(int, struct sysinfo *);
int init_lhm_shm_area(vedl_handle *);
#endif
