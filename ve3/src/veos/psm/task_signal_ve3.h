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
* @file task_signal_ve3.h
* @brief VE3-depende part of header for signal handling
*
* @internal
* @author Signal Handling
*/
#ifndef VEOS_VE3_PSM_TASK_SIGNAL_H
#define VEOS_VE3_PSM_TASK_SIGNAL_H
#include <libved.h>
#include <ve_hw.h>
/**
* @brief This structure saves the VE process execution context information
*/
struct ve3_ucontext {
	unsigned long uc_flags;		/*!< flag */
	struct ve3_ucontext *uc_link;	/*!< Pointer to process context */
	stack_t uc_stack;		/*!< stack used by this context */
	ve3_core_user_reg_pre_t uc_mcontext;/*!< Stores VE process context */
	/* NOTE: EXS is set to Padding_exs in uc_mcontext for compatibility. */
	sigset_t uc_sigmask;	/*!< Signals mask while executing handler */
};

/**
* @brief This structure store the information of signal handler frame.
*
*       Signal handler frame will be written on VE task stack for saving
*       the current execution context of the VE task and executing the
*       signal handler routine. Struct member 'tramp[5]' is currently not
*       in use and this member should not be removed from this struct to
*       avoid regression issues.
*/

struct ve3_sigframe {
	uint64_t tramp[5];/*!< Member 'tramp[5]' is currently not in use */
	char pad[256];		/*!< Pad of 256bytes for SPU coherrency */
	siginfo_t ve_siginfo;	/*!< Signal information */
	struct ve3_ucontext uc;	/*!< Process context information*/
	int flag;		/*!< Flag, signal mapped from h/w signal */
	int signum;		/*!< Signal number being served */
	char lshm_area[LSHM_SZ];/*!< Save lshm area */
};

#endif
