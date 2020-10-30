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
 * @file veos_handler.h
 * @brief Interfaces and data structures for communication with VEOS.
 *
 * @internal
 * @author PSMG / Process management
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
#include "comm_request.h"

#define PID_FILE	"pid_file.txt"
#define VEOS_MAX_THREADS	1056	/* 1024 + 32 */


int (*veos_pseudo_handler[PSEUDO_VEOS_MAX_MSG_NUM])(struct veos_thread_arg *);

int amm_send_mprotect_ack(struct veos_thread_arg *, int64_t);


/* AMM <------------> PSEUDO*/
int amm_handle_process_vm_rw_req(veos_thread_arg_t *);
int amm_handle_mmap(veos_thread_arg_t *);
int amm_handle_munmap(veos_thread_arg_t *);
int amm_handle_set_totol_process(veos_thread_arg_t *);
int amm_handle_mprotect(veos_thread_arg_t *);
int amm_handle_shmat(veos_thread_arg_t *);
int amm_handle_shmdt(veos_thread_arg_t *);
int amm_handle_shmctl(veos_thread_arg_t *);
int amm_handle_shmget(veos_thread_arg_t *);
int amm_soc_write(int, void *, size_t);
int amm_handle_dma_req(veos_thread_arg_t *);
int amm_handle_vemva_init_atb_req(veos_thread_arg_t *);
int amm_handle_vhva_sync_req(veos_thread_arg_t *);
int set_cr_rlimit_req(veos_thread_arg_t *);
int amm_dump_cr_req(veos_thread_arg_t *);

/*  PSM <--------------> PSEUDO*/
int psm_handle_get_pseudo_vefd_req(struct veos_thread_arg *);
int init_psm(veos_thread_arg_t *);
int psm_handle_exec_ve_proc_req(veos_thread_arg_t *);
int psm_handle_old_exec_ve_proc_req(veos_thread_arg_t *);
int psm_handle_delete_ve_proc_req(veos_thread_arg_t *);
int psm_handle_set_tid_addr_req(veos_thread_arg_t *);
int psm_handle_fork_ve_proc_req(veos_thread_arg_t *);
int psm_handle_clone_ve_proc_req(veos_thread_arg_t *);
int psm_handle_schedule_req(veos_thread_arg_t *);
int psm_pseudo_recv_start_ve_request(veos_thread_arg_t *);
int psm_handle_block_req(veos_thread_arg_t *);
int psm_handle_unblock_setregval_req(veos_thread_arg_t *);
int psm_handle_set_regval_req(struct veos_thread_arg *);
int psm_handle_signal_req(struct veos_thread_arg *);
int psm_handle_sigreturn_req(struct veos_thread_arg *);
int psm_handle_sigaction_req(struct veos_thread_arg *);
int psm_handle_setnew_sas_req(struct veos_thread_arg *);
int psm_handle_sigprocmask_req(struct veos_thread_arg *);
int psm_handle_exception_req(struct veos_thread_arg *);
int psm_handle_sigsuspend_req(struct veos_thread_arg *);
int psm_handle_get_regval_req(struct veos_thread_arg *);
int psm_handle_sigpending_req(struct veos_thread_arg *);
int psm_handle_clk_cputime_req(struct veos_thread_arg *);
int psm_handle_getcpu_req(struct veos_thread_arg *);
int psm_handle_get_interval_req(struct veos_thread_arg *);
int psm_handle_get_rlimit_req(struct veos_thread_arg *);
int psm_handle_set_rlimit_req(struct veos_thread_arg *);
int psm_handle_getaffinity_req(struct veos_thread_arg *);
int psm_handle_setaffinity_req(struct veos_thread_arg *);
int psm_handle_get_rusage_req(struct veos_thread_arg *);
int psm_handle_get_times_req(struct veos_thread_arg *);
int psm_handle_sysinfo_req(struct veos_thread_arg *);
int psm_handle_acct_req(struct veos_thread_arg *);
extern struct veos_cmd_entry pseudo_veos_cmd[PSEUDO_VEOS_MAX_MSG_NUM];
int psm_handle_giduid_req(struct veos_thread_arg *pti);
int psm_handle_send_pseudo_giduid_ack(struct veos_thread_arg *pti,
		int ack_ret);
int psm_handle_get_mempolicy_req(struct veos_thread_arg *);

/* IVED <--------------> PSEUDO*/
extern int veos_veshm_veshmctl(struct veos_thread_arg *);
extern int veos_shared_cr_crctl(struct veos_thread_arg *);
extern int veos_vhshm(veos_thread_arg_t *);

/* VEMM <--------------> PSEUDO */
int veos_handle_vemmctl(struct veos_thread_arg *);

/* RPM <--------------> VEOS */
int veos_rpm_hndl_cmd_req(struct veos_thread_arg *);
int veos_rpm_hndl_old_cmd_req(struct veos_thread_arg *);

/*  PSM <--------------> libveptrace*/
int veos_handle_ptrace_req(struct veos_thread_arg *);
int veos_handle_ptrace_event_req(struct veos_thread_arg *);
int veos_handle_stop_proc_req(struct veos_thread_arg *);

/* VEOS <--------------> PSEUDO */
int veos_handle_get_pci_sync_req(veos_thread_arg_t *);
int veos_handle_get_veos_pid_req(veos_thread_arg_t *);
extern int veos_handle_map_dmades(veos_thread_arg_t *);
extern int veos_handle_unmap_dmades(veos_thread_arg_t *);
int veos_handle_get_mns(veos_thread_arg_t *pti);

#endif
