/**
* Copyright (C) 2020 NEC Corporation
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
* @file task_mgmt_ve1.h
* @brief VE1-depende part of header for signal handling
*
* @internal
* @author Signal Handling
*/
#ifndef VEOS_VE1_PSM_TASK_MGMT_VE1_H
#define VEOS_VE1_PSM_TASK_MGMT_VE1_H

#define PMR_CONTEXT_LOOP_VE1 22
#define PMC_REG_VE1		16
#define VE1_ACCT_VERSION	15
#define VE1_ARCH_NUM	0
#define CHK_OVRFLW_VE1 0x8000000000000000
#define MAX_PMC_VALUE_52BIT 0xfffffffffffff
#define MAX_PMC_VALUE_56BIT 0xffffffffffffff
#define OVERFLOW_BIT 0x7fffffffffffffff
#define OVERFLOW_VALUE1_VE1(pmc_pmmr) ((pmc_pmmr & CHK_OVRFLW_VE1)?MAX_PMC_VALUE_52BIT:0)
#define OVERFLOW_VALUE_VE1(pmc_pmmr) ((pmc_pmmr & CHK_OVRFLW_VE1)?MAX_PMC_VALUE_56BIT:0)

struct ve_acct_v15 {
	char     ac_flag;                /*!< Flags */
	char     ac_version;             /*!< Always set to ACCT_VERSION */
	__u16    ac_tty;                 /*!< Control Terminal */
	__u32    ac_exitcode;            /*!< Exitcode */
	__u32    ac_uid;                 /*!< Real User ID */
	__u32    ac_gid;                 /*!< Real Group ID */
	__u32    ac_pid;                 /*!< Process ID */
	__u32    ac_ppid;                /*!< Parent Process ID */
	__u32    ac_btime;               /*!< Process Creation Time [sec]*/
	float    ac_etime;               /*!< Elapsed Time [10ms]*/
	comp_t   ac_utime;               /*!< User Time [10ms]*/
	comp_t   ac_stime;               /*!< System Time */
	comp_t   ac_mem;                 /*!< Average Memory Usage [kb]*/
	comp_t   ac_io;                  /*!< Chars Transferred */
	comp_t   ac_rw;                  /*!< Blocks Read or Written */
	comp_t   ac_minflt;              /*!< Minor Pagefaults */
	comp_t   ac_majflt;              /*!< Major Pagefaults */
	comp_t   ac_swaps;               /*!< Number of Swaps */
	char    ac_comm[ACCT_COMM];    /*!< Command Name */
	__u32   ac_sid;                /* session ID */
	__u32   ac_timeslice;         /* timeslice [μs] */
	__u16   ac_max_nthread;      /* Maximum number of threads in the thread group
					whose state are "RUNNING" or "WAIT" at the same time */
	__u16   ac_numanode;         /* the number of NUMA node */
	double   ac_total_mem;         /* VE's total memory usage in clicks */
	__u64 ac_maxmem;  /* VE's max memory usage [kb] */
	__u64 ac_syscall; /* the number of systemcall */
	double   ac_transdata;       /* data transfer amount between VE-VH [kb] */
	__u64 ac_ex;   /* Execution count */
	__u64 ac_vx;   /* Vector execution count */
	__u64 ac_fpec; /* Floating point data element count */
	__u64 ac_ve;   /* Vector elements count */
	__u64 ac_l1imc; /* L1 instruction cache miss count */
	__u64 ac_vecc;  /* Vector execution in microseconds */
	__u64 ac_l1mcc; /* L1 cache miss in microseconds */
	__u64 ac_l2mcc; /* L2 cache miss in microseconds */
	__u64 ac_ve2;       /* Vector elements count 2 */
	__u64 ac_varec; /* Vector arithmetic execution in microseconds */
	__u64 ac_l1imcc; /* L1 instruction cache miss in microseconds */
	__u64 ac_vldec;   /* Vector load execution in microseconds */
	__u64 ac_l1omcc; /* L1 operand cache miss in microseconds */
	__u64 ac_pccc;   /* Port conflict in microseconds */
	__u64 ac_ltrc;      /* Load instruction traffic count */
	__u64 ac_vlpc;  /* Vector load packet count */
	__u64 ac_strc;  /* Store instruction traffic count */
	__u64 ac_vlec;  /* Vector load element count */
	__u64 ac_llvml;   /* LLC vector load cache fill line count */
	__u64 ac_llvme;   /* LLC vector load cache miss element count */
	__u64 ac_fmaec;  /* Fused multiply add element count */
	__u64 ac_ptcc;  /* Power throttling in microseconds */
	__u64 ac_ttcc;  /* Thermal throttling in microseconds */
	__u64 ac_corebitmap;  /* core bitmap */
	__u64 padding_1[5];    /* PMC 16-20 */
	__u64 padding_2[5];    /* padding */
};

static inline struct ve_acct_v15 *TO_VE1_acct(struct ve_acct *p)
{
        return (struct ve_acct_v15 *)p;
}

#endif
