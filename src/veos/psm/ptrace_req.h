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
 * @file ptrace_req.h
 * @brief PSM interfaces for handling ptrace request for VE.
 *
 * @internal
 * @author PTRACE
 */

#ifndef __PSM_PTRACE_REQ_H
#define __PSM_PTRACE_REQ_H

#include <sys/ptrace.h>
#include <proc/readproc.h>
#include "task_mgmt.h"

#define PTRACE_PRIVATE_DATA     (0x5F0000000000)
#define SYSCALL_TRACE_OFFSET	(0x8)
#define PTRACE_OPTION_OFFSET	(0x10)
#define PSW_SINGLESTEP		(0x4000000000000000)
#define PROCES_UNDER_SWAPPING	(2)

#ifndef PTRACE_O_EXITKILL
/* Only defined in Linux Kernel 3.8 or later.  */
#define PTRACE_O_EXITKILL       0x00100000
#endif

/**
 * @brief VE Process user registers.
 */
struct ve_user_regs {
	/* Performance Counters */
	reg_t USRCC;			/*     0x0 -     0x7 */
	reg_t PMC[16];			/*     0x8 -    0x87 */
	uint8_t pad0[0x1000 - 0x88];	/*    0x88 -   0xFFF */
	/* Control Registers */
	reg_t PSW;			/*  0x1000 -  0x1007 */
	reg_t EXS;			/*  0x1008 -  0x100F */
	reg_t IC;			/*  0x1010 -  0x1017 */
	reg_t ICE;			/*  0x1018 -  0x101F */
	reg_t VIXR;			/*  0x1020 -  0x1027 */
	reg_t VL;			/*  0x1028 -  0x102F */
	reg_t SAR;			/*  0x1030 -  0x1047 */
	reg_t PMMR;			/*  0x1038 -  0x103F */
	reg_t PMCR[4];			/*  0x1040 -  0x105F */
	uint8_t pad1[0x1400 - 0x1060];	/*  0x1060 -  0x13FF */
	/* Scalar Registers */
	reg_t SR[SR_NUM];		/*  0x1400 -  0x15FF */
	uint8_t pad2[0x1800 - 0x1600];	/*  0x1600 -  0x17FF */
};

/**
 * @brief VE Process vector registers.
 */
struct ve_user_vregs {
        /* Vector Mask Registers */
        reg_t VMR[16][4];               /*  0x0 -  0x1FF */
        uint8_t pad3[0x40000 - 0x1A00]; /*  0x200 - 0x3E7FE */
        /* Vector Registers */
        reg_t VR[VR_NUM][AUR_MVL];      /* 0x3E800 - 0x5FFFF */
        uint8_t pad4[0x80000 - 0x60000];/* 0x5E800 - 0x7E7FF */
};

int psm_ve_start_process(struct ve_task_struct *);
int psm_ve_stop_process(struct ve_task_struct *);
int psm_attach_ve_process(struct ve_task_struct *, pid_t, uid_t, gid_t, bool);
int psm_ptrace_peekdata(struct ve_task_struct *, uint64_t, void *);
int psm_ptrace_pokedata(struct ve_task_struct *, uint64_t, uint64_t);
off_t psm_get_reg_offset(usr_reg_name_t);
int psm_ptrace_peekuser(struct ve_task_struct *, uint64_t, void *);
int psm_ptrace_pokeuser(struct ve_task_struct *, uint64_t, uint64_t);
int psm_ptrace_getregs(struct ve_task_struct *, uint64_t);
int psm_ptrace_setregs(struct ve_task_struct *, uint64_t);
int psm_ptrace_getvregs(struct ve_task_struct *, uint64_t);
int psm_ptrace_setvregs(struct ve_task_struct *, uint64_t);
int psm_ptrace_detach(struct ve_task_struct *);
int psm_ptrace_syscall(struct ve_task_struct *, bool);
int psm_get_ice_regval(int, uint64_t *);
int psm_ptrace_setoptions(struct ve_task_struct *, uint64_t);
int psm_get_ve_proc_info(pid_t, proc_t *);
#endif
