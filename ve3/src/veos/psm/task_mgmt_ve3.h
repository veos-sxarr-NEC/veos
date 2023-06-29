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
* @file task_mgmt_ve3.h
* @brief VE3-depende part of header for signal handling
*
* @internal
* @author Signal Handling
*/
#ifndef VEOS_VE3_PSM_TASK_MGMT_VE3_H
#define VEOS_VE3_PSM_TASK_MGMT_VE3_H

#define PMR_CONTEXT_LOOP_VE3 27
#define PMC_REG_VE3		21
#define VE3_ACCT_VERSION        16
#define VE3_ARCH_NUM	1
#define CHK_OVRFLW_VE3 0x8000000000000000
#define MAX_PMC_VALUE_VE3 0xfffffffffffffff
#define OVERFLOW_BIT_VE3 0x7fffffffffffffff
#define OVERFLOW_VALUE_VE3(pmc_pmmr) ((pmc_pmmr & CHK_OVRFLW_VE3)?MAX_PMC_VALUE_VE3:0)

struct ve_acct_v16 {
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
	comp_t   ac_mem;                 /*!< Average Memory Usage [kb] */
	comp_t   ac_io;                  /*!< Chars Transferred */
	comp_t   ac_rw;                  /*!< Blocks Read or Written */
	comp_t   ac_minflt;              /*!< Minor Pagefaults */
	comp_t   ac_majflt;              /*!< Major Pagefaults */
	comp_t   ac_swaps;               /*!< Number of Swaps */
	char    ac_comm[ACCT_COMM];    /*!< Command Name */
	__u32   ac_sid;                /* session ID */
	__u32   ac_timeslice;         /* timeslice [μs] */
	__u16 ac_max_nthread;	/* Maximum number of threads whose state are
				   "RUNNING" or "WAIT" at the same time */
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
	__u64 ac_llvml;       /* LLC vector load cache fill line count */
	__u64 ac_llvme;       /* LLC vector load cache miss element count */
	__u64 ac_fmaec;  /* Fused multiply add element count */
	__u64 ac_ptcc;	/* Power throttling in microseconds */
	__u64 ac_ttcc;	/* Thermal throttling in microseconds */
	__u64 ac_corebitmap;  /* core bitmap */
	__u64 ac_l3vsac;      /* VLD+SLD elements accessing L3 count */
	__u64 ac_l3vsme;      /* L3 VLD+SLD miss-hit element count */
	__u64 ac_l3vsml;      /* L3 VLD+SLD miss-hit cache line count */
	__u64 ac_llvsme;      /* LLC miss-hit element count */
	__u64 ac_llvsml;       /* LLC miss-hit cache line count */
	__u64 padding_2[5];    /* padding */
};


/* for delete temporary files of code modification */
#define MOD_DEL_LIST_PATH_MAX (PATH_MAX + NAME_MAX + 2)
#define MOD_DEL_LIST_NAME_MAX (NAME_MAX + 1)
struct del_list_data{ /* delete file information */
	time_t atime;
	char path[MOD_DEL_LIST_PATH_MAX];
	char fname[MOD_DEL_LIST_NAME_MAX];
	uid_t uid;
	int deleted;
};
struct del_list_dir{ /* delete directory information */
	time_t atime;
	char path[MOD_DEL_LIST_PATH_MAX];
	char dname[MOD_DEL_LIST_NAME_MAX];
};

struct del_list_user{ /* user information of delete files */
	uid_t uid;
	int num;
	int delete_num;
};


#endif
