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
 *
 * @file ptrace_req_ve1.h
 * @brief VE3-dependent part of ptrace_req.c
 * @brief PSM interfaces for handling ptrace request for VE3.
 *
 * @internal
 * @author PTRACE
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <proc/readproc.h>

#include <libved.h>
#include <ve_hw.h>
#include <ve_hw_ve1.h>

#include "task_mgmt.h"

/* Structures for VE1: */
struct ve1_user_regs {
	/* Performance Counters */
	ve_reg_t USRCC;                         /*     0x0 -     0x7 */
	ve_reg_t PMC[16];                       /*     0x8 -    0x87 */
	uint8_t pad0[0x1000 - 0x88];            /*    0x88 -   0xFFF */
	/* Control Registers */
	ve_reg_t PSW;                           /*  0x1000 -  0x1007 */
	ve_reg_t EXS;                           /*  0x1008 -  0x100F */
	ve_reg_t IC;                            /*  0x1010 -  0x1017 */
	ve_reg_t ICE;                           /*  0x1018 -  0x101F */
	ve_reg_t VIXR;                          /*  0x1020 -  0x1027 */
	ve_reg_t VL;                            /*  0x1028 -  0x102F */
	ve_reg_t SAR;                           /*  0x1030 -  0x1047 */
	ve_reg_t PMMR;                          /*  0x1038 -  0x103F */
	ve_reg_t PMCR[4];                       /*  0x1040 -  0x105F */
	uint8_t pad1[0x1400 - 0x1060];          /*  0x1060 -  0x13FF */
	/* Scalar Registers */
	ve_reg_t SR[VE1_SR_NUM];                /*  0x1400 -  0x15FF */
	uint8_t pad2[0x1800 - 0x1600];          /*  0x1600 -  0x17FF */
};

/* VE process Vector regs for VE1*/
struct ve1_user_vregs
{
	/* Vector Mask Registers */
	ve_reg_t VMR[16][4];               /*  0x0 -  0x1FF */
	uint8_t pad3[0x40000 - 0x1A00]; /*  0x200 - 0x3E7FE */
	/* Vector Registers */
	ve_reg_t VR[VE1_VR_NUM][VE1_AUR_MVL];      /* 0x3E800 - 0x5FFFF */
	uint8_t pad4[0x80000 - 0x60000];/* 0x5E800 - 0x7E7FF */
};
