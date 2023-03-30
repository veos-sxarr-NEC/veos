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
#ifndef VEOS_AMM_PMAP_H
#define VEOS_AMM_PMAP_H
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
//#include "ve_memory.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "velayout.h"
//#include "task_signal.h"
//#include "ptrace_req.h"
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
#define DEFAULT_DUMP_SIZE	64 * 1024 * 1024

typedef unsigned long elf_greg_t;

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
	int	si_signo;			/* signal number */
	int	si_code;			/* extra code */
	int	si_errno;			/* errno */
};

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

#ifndef user_siginfo_t
#define user_siginfo_t siginfo_t
#endif


bool generate_core_dump(struct dump_params *);

int fill_ve_pmap(struct _psuedo_pmap *, struct _psuedo_pmap **, int);

int parse_pseudopmap(struct _psuedo_pmap *, struct _valid_atbdir *,
		struct _psuedo_pmap **, int, int,  struct ve_task_struct *);

int parse_valid_atbdir(struct _valid_atbdir **, atb_reg_t *);

int fill_maps(struct _psuedo_pmap **, pid_t);


#endif
