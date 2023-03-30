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
 * @file ptrace_req_ve3.h
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

#include "task_mgmt.h"

/* Structures for VE3: */
struct ve3_user_regs {
        /* Performance Counters */
        ve_reg_t USRCC;
        ve_reg_t PMC[24];
        uint8_t pad0[4096 - (8 * (1+24))];
        /* Control Registers */
        ve_reg_t PSW;
        ve_reg_t EXS;
        ve_reg_t IC;
        ve_reg_t ICE;
        ve_reg_t VIXR;
        ve_reg_t VL;
        ve_reg_t SAR;
        ve_reg_t PMMR;
        ve_reg_t PMCR[4];
        ve_reg_t PVL32;
        ve_reg_t PVL16;

        ve_reg_t pad1_0;
        uint8_t pad1[(5120-4096) - (8 * 15)];

        /* Scalar Registers */
        ve_reg_t SR[VE3_SR_NUM];
        uint8_t pad2[512];
        } ;

/* VE Process vector registers for VE3 */

struct ve3_user_vregs {
          /* Vector Mask Registers */
        ve_reg_t VM[16][4];
        uint8_t pad3[1024 + 512];
        uint8_t pad3_1[(256*1024) - (2*4096)] ;

        /* Vector Registers */
        ve_reg_t VR[VE3_VR_NUM][VE3_AUR_MVL];
        uint8_t pad4[0x80000 - 0x60000] ;
} ;
