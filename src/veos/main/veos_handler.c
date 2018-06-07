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
 * @file  veos_handler.c
 * @brief Initialization of hamdler HASH table.
 *
 * This file initializes handler HASH table for veos.
 *
 * @internal
 * @author PSMG / Process management
 */

#include "veos_handler.h"
struct veos_cmd_entry pseudo_veos_cmd[PSEUDO_VEOS_MAX_MSG_NUM] = {
	{"RPM_QUERY", veos_rpm_hndl_cmd_req},
	{"PTRACE_REQUEST", veos_handle_ptrace_req},
	{"NEW_VE_PROC", psm_handle_exec_ve_proc_req},
	{"START_VE_REQ", psm_pseudo_recv_start_ve_request},
	{"DEL_VE_PROC", psm_handle_delete_ve_proc_req},
	{"FORK_VE_PROC", psm_handle_fork_ve_proc_req},
	{"CLONE_VE_PROC", psm_handle_clone_ve_proc_req},
	{"SET_TID_ADDR", psm_handle_set_tid_addr_req},
	{"SCHEDULE", psm_handle_schedule_req},
	{"BLOCK", psm_handle_block_req},
	{"UNBLOCK_AND_SET_REGVAL", psm_handle_unblock_setregval_req},
	{"CMD_MMAP", amm_handle_mmap},
	{"CMD_MUNMAP", amm_handle_munmap},
	{"CMD_MPROTECT", amm_handle_mprotect},
	{"CMD_SHMAT", amm_handle_shmat},
	{"CMD_SHMDT", amm_handle_shmdt},
	{"CMD_SHMCTL", amm_handle_shmctl},
	{"DMA_REQ", amm_handle_dma_req},
	{"SET_USR_REG", psm_handle_set_regval_req},
	{"VE_SIGNAL_REQ", psm_handle_signal_req},
	{"SIGRETURN_REQ", psm_handle_sigreturn_req},
	{"SIGACTION_REQ", psm_handle_sigaction_req},
	{"SET_NEW_SAS", psm_handle_setnew_sas_req},
	{"SIGPROCMASK_REQ", psm_handle_sigprocmask_req},
	{"HW_EXP_REQ", psm_handle_exception_req},
	{"SIGPENDING_REQ", psm_handle_sigpending_req},
	{"CLK_CPUTIME", psm_handle_clk_cputime_req},
	{"GET_CPU_REQ", psm_handle_getcpu_req},
	{"GET_SCHED_INTRVL", psm_handle_get_interval_req},
	{"GET_RLIMIT", psm_handle_get_rlimit_req},
	{"SET_RLIMIT", psm_handle_set_rlimit_req},
	{"GET_AFFINITY", psm_handle_getaffinity_req},
	{"SET_AFFINITY", psm_handle_setaffinity_req},
	{"GET_RUSAGE", psm_handle_get_rusage_req},
	{"SYSINFO_REQ", psm_handle_sysinfo_req},
	{"ACCT_REQ", psm_handle_acct_req},
	{"VEFD_REQ", psm_handle_get_pseudo_vefd_req},
	{"SIGSUSPEND_REQ", psm_handle_sigsuspend_req},
	{"CMD_VMRW", amm_handle_process_vm_rw_req},
	{"VEMVA_INIT_ATB", amm_handle_vemva_init_atb_req},
	{"CMD_TPROC", amm_handle_set_totol_process},
	{"GET_REGVAL_REQ", psm_handle_get_regval_req},
	{"GIDUID_REQ", psm_handle_giduid_req},
#if 0
	{"CMD_CR_RLIM", set_cr_rlimit_req},
#endif
	{"CR_DUMP", amm_dump_cr_req},
	{"CMD_SHMGET", amm_handle_shmget},
	{"PTRACE_EVENT_MSG", veos_handle_ptrace_event_req},
	{"VE_STOP_PROC", veos_handle_stop_proc_req},
	{"CMD_VESHM", veos_veshm_veshmctl},
	{"GET_PCI_SYNC", veos_handle_get_pci_sync_req},
	{"CMD_CR", veos_shared_cr_crctl},
	{"CMD_VEMM", veos_handle_vemmctl},
	{"VHVA_SYNC", amm_handle_vhva_sync_req},
	{"CMD_VHSHM", veos_vhshm},
};
