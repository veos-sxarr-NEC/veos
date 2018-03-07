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
 * @file ve_ptrace.h
 * @brief VE Ptrace functions and data structures.
 *
 * @internal
 * @author PTRACE
 */

#ifndef __VE_PTRACE_H
#define __VE_PTRACE_H

#include <stdint.h>
#include <sys/ptrace.h>

typedef uint64_t reg_t;

/* VE Specific Ptrace Request which will
 * stop the VE Process.
 */
#define PTRACE_STOP_VE	25

#define SR_NUM  	64	/* Number of Scalar Registers */
#define VR_NUM		64	/* Number of Vector Registers */
#define AUR_MVL		256	/* MAX Length of Vector */
#define NT_VEGPUREGS	0x1	/* VE General Purpose Resister Set */
#define NT_VEFPREGS	0x2	/* VE Vector register Set */

/**
 * @brief VE Registers which can be used while using ve_ptrace
 * PTRACE_PEEKUSER and PTRACE_POKEUSER command in 'addr' field.
 */
typedef enum usr_reg {
	USRCC,
	PMC00, PMC01, PMC02, PMC03, PMC04, PMC05, PMC06, PMC07, PMC08, PMC09,
	PMC10, PMC11, PMC12, PMC13, PMC14, PMC15,
	PSW,
	EXS,
	IC,
	ICE,
	VIXR,
	VL,
	SAR,
	PMMR,
	PMCR00, PMCR01, PMCR02, PMCR03, PMCR04,
	SR00, SR01, SR02, SR03, SR04, SR05, SR06, SR07, SR08, SR09, SR10, SR11,
	SR12, SR13, SR14, SR15, SR16, SR17, SR18, SR19, SR20, SR21, SR22, SR23,
	SR24, SR25, SR26, SR27, SR28, SR29, SR30, SR31, SR32, SR33, SR34, SR35,
	SR36, SR37, SR38, SR39, SR40, SR41, SR42, SR43, SR44, SR45, SR46, SR47,
	SR48, SR49, SR50, SR51, SR52, SR53, SR54, SR55, SR56, SR57, SR58, SR59,
	SR60, SR61, SR62, SR63,
} usr_reg_name_t;

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

long ve_ptrace(enum __ptrace_request request, ...);
#endif
