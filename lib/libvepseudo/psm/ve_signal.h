/*
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
* @file ve_signal.h
* @brief Header file for "ve_signal.c" file
*/
#ifndef __VE_SIGNAL_H
#define __VE_SIGNAL_H
#include <signal.h>
#include <stdbool.h>
#include "libved.h"

#define NO_EXS	0xFFFFFFFFFFFFFF00
#define VE_ERESTARTSYS 512
#define VE_ENORESTART 513

#define RESTART_BIT 28
#define RESETHAND_BIT 31

#define VE_MAX_SICODE	8
#define VE_MIN_SICODE	1

#define ve_rt_sigmask(sig) (1ULL << ((sig)-1))

#define VE_SYNCHRONOUS_MASK (\
		ve_rt_sigmask(SIGSEGV)  | ve_rt_sigmask(SIGBUS)   | \
		ve_rt_sigmask(SIGILL)	| ve_rt_sigmask(SIGFPE)   | \
		ve_rt_sigmask(SIGSYS))


/**
* @brief Check whether signal number is valid or not
*
* @param sig Signal number being checked
*
* @return: Returns 1 if valid else 0
*/
static inline int valid_signal(unsigned long sig)
{
	return sig < _NSIG ? 1 : 0;
}
#endif
