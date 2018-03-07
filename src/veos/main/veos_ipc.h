/**
 * @file veos_ipc.h
 * @brief Interfaces and data structures for communication with VEOS.
 */
#ifndef __VEOS_IPC_H
#define __VEOS_IPC_H
#include <stdio.h>
#include <search.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "libved.h"
#include "veos_pseudo_interface.h"

#define PID_FILE	"pid_file.txt"
#define VEOS_MAX_THREADS	16

#define PSEUDO_VEOS_MAX_MSG_NUM 56

int (*veos_pseudo_handler[PSEUDO_VEOS_MAX_MSG_NUM])(struct veos_thread_arg *);

int amm_send_mprotect_ack(struct veos_thread_arg *, int64_t);


/* AMM <------------> PSEUDO*/
int amm_handle_mmap(veos_thread_arg_t *);
int amm_handle_munmap(veos_thread_arg_t *);
int amm_handle_mprotect(veos_thread_arg_t *);
int amm_handle_shmat(veos_thread_arg_t *);
int amm_handle_shmdt(veos_thread_arg_t *);
int amm_handle_mremap(veos_thread_arg_t *);
int amm_handle_shmctl(veos_thread_arg_t *);
int amm_soc_write(int, void *, size_t);
int amm_handle_dma_req(veos_thread_arg_t *);

/*  PSM <--------------> PSEUDO*/
int init_psm(veos_thread_arg_t *);
int psm_handle_exec_ve_proc_req(veos_thread_arg_t *);
int psm_handle_delete_ve_proc_req(veos_thread_arg_t *);
int psm_handle_set_tid_addr_req(veos_thread_arg_t *);
int psm_handle_fork_ve_proc_req(veos_thread_arg_t *);
int psm_handle_clone_ve_proc_req(veos_thread_arg_t *);
int psm_handle_schedule_req(veos_thread_arg_t *);
int psm_pseudo_recv_start_ve_request(veos_thread_arg_t *);
int psm_handle_block_req(veos_thread_arg_t *);
int psm_handle_un_block_req(veos_thread_arg_t *);
int psm_handle_set_regval_req(struct veos_thread_arg *);
int psm_handle_start_core_req(struct veos_thread_arg *);
int psm_handle_halt_core_req(struct veos_thread_arg *);
int psm_handle_signal_req(struct veos_thread_arg *);
int psm_handle_sigreturn_req(struct veos_thread_arg *);
int psm_handle_sigaction_req(struct veos_thread_arg *);
int psm_handle_setnew_sas_req(struct veos_thread_arg *);
int psm_handle_sigprocmask_req(struct veos_thread_arg *);
int psm_handle_exception_req(struct veos_thread_arg *);
int psm_handle_sigsuspend_req(struct veos_thread_arg *);

int psm_handle_get_priority_max_req(struct veos_thread_arg *);
int psm_handle_get_priority_min_req(struct veos_thread_arg *);
int psm_handle_getpriority_req(struct veos_thread_arg *);
int psm_handle_setpriority_req(struct veos_thread_arg *);
int psm_handle_getscheduler_req(struct veos_thread_arg *);
int psm_handle_setscheduler_req(struct veos_thread_arg *);
int psm_handle_sched_getparam_req(struct veos_thread_arg *);
int psm_handle_sched_setparam_req(struct veos_thread_arg *);
int psm_handle_sigpending_req(struct veos_thread_arg *);
int psm_handle_clk_cputime_req(struct veos_thread_arg *);
int psm_handle_getcpu_req(struct veos_thread_arg *);
int psm_handle_get_interval_req(struct veos_thread_arg *);
int psm_handle_get_rlimit_req(struct veos_thread_arg *);
int psm_handle_set_rlimit_req(struct veos_thread_arg *);
int psm_handle_getaffinity_req(struct veos_thread_arg *);
int psm_handle_setaffinity_req(struct veos_thread_arg *);
int psm_handle_sched_yield_req(struct veos_thread_arg *);
int psm_handle_get_rusage_req(struct veos_thread_arg *);
int psm_handle_pr_set_mm_req(struct veos_thread_arg *);
int psm_handle_sysinfo_req(struct veos_thread_arg *);
int psm_handle_acct_req(struct veos_thread_arg *);
extern struct veos_cmd_entry pseudo_veos_cmd[PSEUDO_VEOS_MAX_MSG_NUM];

/* RPM <--------------> VEOS */
int veos_rpm_hndl_cmd_req(struct veos_thread_arg *);
#endif
