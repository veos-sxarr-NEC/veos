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
 * @file  pmap.h
 * @brief header file for pmap
 *
 *       This file contains the prototype of structure & functions that help in
 *	 fetching the memory map of process and also dumping the same
 *       information of VE processs into the file.
 *
 * @internal
 * @author AMM
 */
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <linux/elf.h>
#include <string.h>
#include <signal.h>
#include "ve_shm.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "ve_memory.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "velayout.h"
#include "task_signal.h"
#include "ptrace_req.h"
#include "buddy.h"

#define SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SR_NUM    64               /* Number of Scalar Registers */
#define VR_NUM    64               /* Number of Vector Registers */
#define AUR_MVL   256              /* MAX Length of Vector */
#define NT_PRSTATUS    1	/* VE General Purpose Resister Set */
#define NT_PRFPREG     2	/* VE Vector register Set */
#define NT_PRPSINFO    3
#define NT_TASKSTRUCT  4
#define NT_AUXV        6
#define NT_SIGINFO     0x53494749
#define NT_FILE        0x46494c45
#define FILE_ELF	 127
#define NUL		 0x0
#define PAGE_SIZE	 0x200000
#define MAX_FILE_NOTE_SIZE (4*1024*1024)
#define PSN_MASK_2MB	0xFFFFFFF00000
#define PSN_MASK_64MB	0xFFFFFFF000000
#define PAGE_MASK_BIT	0x6
#define DIR_ENTRIES	256
#define EM_VE		251
#define ELF_NGREG (sizeof(struct ve_user_regs) / sizeof(elf_greg_t))
#define MAX_FREE_BLOCK	260
#define VMFLAGS_LENGTH	81
#define MAP_ADDR_SPACE	((uint64_t)1<<34)
#define ALIGNED_4BYTE	4
#define FILEINFO_IN_BYTES	64
#define BUF_2BYTES	2
#define BUF_3BYTES	3

typedef unsigned long elf_greg_t;
typedef uint64_t reg_t;

/**
 * @brief Structure For VE valid atb directories.
 *
 *      This will contain the list of valid atb dir
 *      with their begin and end addresses.
 */
typedef struct _valid_atbdir {
	unsigned long begin;
	unsigned long end;
	unsigned long pagesize;
	struct _valid_atbdir *next;
} valid_atbdir;
/**
 * @brief Structure For memory map of psuedo process.
 *
 *      This will contain the information about the memory
 *      mapping for VH and VE process.
 */
typedef struct _psuedo_pmap {
	int flag;
	unsigned long begin;
	unsigned long end;
	unsigned long size;
	unsigned long inode;
	unsigned long foo;
	char perm[5];
	char dev[6];
	char mapname[PATH_MAX];
	char vmflags[VMFLAGS_LENGTH];
	int prmsn;
	struct _psuedo_pmap *next;
} psuedo_map;

int get_vepmap(struct _psuedo_pmap **, struct ve_task_struct *);

int dump_core_info(struct dump_params *, const void *, loff_t, bool);

/**
 * @brief Structure For ELF note in memory.
 *
 *      This will contain the information about the signal
 *      number , extra code and error number maintained
 *      in veos.
 */
struct elf_siginfo {
	int     si_signo;                       /* signal number */
	int     si_code;                        /* extra code */
	int     si_errno;                       /* errno */
};

/**
 * @brief Structure For Note section.
 *
 *      This will contain the information about the name
 *      type , description and data of registers, signals
 *      auxv and file which will be dump in coredump
 */
struct memelfnote {
	const char *name;
	int type;
	uint64_t datasz;
	void *data;
};

#define roundups(x, y) (                                 \
{                                                       \
	const typeof(y) __y = y;                        \
	(((x) + (__y - 1)) / __y) * __y;                \
}							\
)

enum ve_regs {
	REGSET_GENERAL,
	REGSET_FP,
};

struct ve_task_struct;
struct user_regset;

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

#ifndef user_siginfo_t
#define user_siginfo_t siginfo_t
#endif

/**
 * @brief Structure For process status.
 *
 *      This will contain the information about the pending
 *      signals, pid , ppid,  user time and general purpose
 *      register of a VE process which will be dump in
 *      coredump.
 */
struct elf_prstatus {
	struct elf_siginfo pr_info;
	short   pr_cursig;              /* Current signal */
	unsigned long pr_sigpend;       /* Set of pending signals */
	unsigned long pr_sighold;       /* Set of held signals */
	pid_t   pr_pid;
	pid_t   pr_ppid;
	pid_t   pr_pgrp;
	pid_t   pr_sid;
	struct timeval pr_utime;        /* User time */
	struct timeval pr_stime;        /* System time */
	struct timeval pr_cutime;       /* Cumulative user time */
	struct timeval pr_cstime;       /* Cumulative system time */
	unsigned long pr_reg[ELF_NGREG];   /* GP registers */
	int pr_fpvalid;
};

/**
 * @brief Structure For availabe register set.
 * @name:       Identifier, e.g. UTS_MACHINE string.
 * @regsets:    Array of @n regsets available in this view.
 * @n:          Number of elements in @regsets.
 * @e_machine:  ELF header @e_machine %EM_* value written in core dumps.
 * @e_flags:    ELF header @e_flags value written in core dumps.
 * @ei_osabi:   ELF header @e_ident[%EI_OSABI] value written in core dumps.
 */
struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

/**
 * @brief Structure For accessible thred CPU state.
 *
 * @n:                  Number of slots (registers).
 * @size:               Size in bytes of a slot (register).
 * @align:              Required alignment, in bytes.
 * @bias:               Bias from natural indexing.
 * @core_note_type:     ELF note @n_type value used in core dumps.
 */
struct user_regset {
	unsigned int                    n;
	unsigned int                    size;
	unsigned int                    align;
	unsigned int                    bias;
	unsigned int                    core_note_type;
};

/**
 * @brief Structure For File Backed handling.
 *
 *      This will contain the information about the file
 *      to be mapped as. Global List of this will be
 *      maintained in veos.
 */
struct core_thread {
	struct ve_task_struct *task;
	struct core_thread *next;
};


#define ELF_PRARGSZ     (80)

/**
 * @brief Structure For process information.
 *
 *      This will contain the information about the state,
 *      priority, pid , name of executable etc which will be
 *	dump in core files.
 */
struct elf_prpsinfo {
	char    pr_state;       /* numeric process state */
	char    pr_sname;       /* char for pr_state */
	char    pr_zomb;        /* zombie */
	char    pr_nice;        /* nice val */
	unsigned long pr_flag;  /* flags */
	unsigned int  pr_uid;
	unsigned int  pr_gid;
	pid_t   pr_pid, pr_ppid, pr_pgrp, pr_sid;
	/* Lots missing */
	char    pr_fname[16];   /* filename of executable */
	char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

/**
 * @brief Structure For process status and it task.
 *
 *      This will contain the list about the task
 *      of process, register of process which will be
 *      dump in veos.
 */
struct elf_thread_core_info {
	struct elf_thread_core_info *next;
	struct ve_task_struct *task;
	struct elf_prstatus prstatus;
	struct memelfnote notes[0];
};

/**
 * @brief Structure For Note section for core dump.
 *
 *      This will contain the information about the file
 *      auxv, signal, process info of process in core dumps.
 */
struct elf_note_info {
	struct elf_thread_core_info *thread;
	struct memelfnote psinfo;
	struct memelfnote signote;
	struct memelfnote auxv;
	struct memelfnote files;
	user_siginfo_t csigdata;
	size_t size;
	int thread_notes;
	int map_count;
};

bool generate_core_dump(struct dump_params *);

int fill_ve_pmap(struct _psuedo_pmap *, struct _psuedo_pmap **, int);

int parse_psuedopmap(struct _psuedo_pmap *, struct _valid_atbdir *,
		struct _psuedo_pmap **, int, int,  struct ve_task_struct *);

int parse_valid_atbdir(struct _valid_atbdir **, atb_reg_t *);

int fill_maps(struct _psuedo_pmap **, pid_t);
