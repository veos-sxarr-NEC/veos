/* Copyright (C) 2017-2018 by NEC Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
/**
 * @file   veos_defs.h
 * @brief  Header file for VE program, system libraries and VEOS
 */

#ifndef _VEOS_DEFS_H
#define _VEOS_DEFS_H

#include <sys/types.h>

/* VE specific system calls */
#define SYS_sysve	316

/* Address spaces */
#define VE_ADDR_VEMVA	((uint8_t)1 << 0)
#define VE_ADDR_VEHVA	((uint8_t)1 << 1)
#define VE_ADDR_PCI	((uint8_t)1 << 2)

/* CR flags */
#define VE_CR_THREAD	((uint64_t)1 << 36)
#define VE_CR_MPI	((uint64_t)1 << 37)

#define VE_VEHVA_SYS_COM_REG_PAGE0		0
#define VE_VEHVA_SYS_COM_REG_PAGE1		1
#define VE_VEHVA_DMACTL				2
#define VE_VEHVA_DMADES				3

#define VE_REGID_PSW	 0
#define VE_REGID_PMMR	 1
#define VE_REGID_PMCR0	 2
#define VE_REGID_PMCR1	 3
#define VE_REGID_PMCR2	 4
#define VE_REGID_PMCR3	 5
#define VE_REGID_PMC0	 6
#define VE_REGID_PMC1	 7
#define VE_REGID_PMC2	 8
#define VE_REGID_PMC3	 9
#define VE_REGID_PMC4	10
#define VE_REGID_PMC5	11
#define VE_REGID_PMC6	12
#define VE_REGID_PMC7	13
#define VE_REGID_PMC8	14
#define VE_REGID_PMC9	15
#define VE_REGID_PMC10	16
#define VE_REGID_PMC11	17
#define VE_REGID_PMC12	18
#define VE_REGID_PMC13	19
#define VE_REGID_PMC14	20
#define VE_REGID_PMC15	21

#endif
