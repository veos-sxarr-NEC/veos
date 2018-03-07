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
 * @file internal.h
 * @brief VE Ptrace internal functions and MACROS.
 *
 * @internal
 * @author PTRACE
 */

#ifndef __INTERNAL_H
#define __INTERNAL_H

#include <signal.h>
#include <sys/ptrace.h>

static inline int signal_is_valid(unsigned long sig)
{
        return ((sig < _NSIG) && (sig >= 0)) ? 1 : 0;
}

#ifndef PTRACE_O_EXITKILL
/* Only defined in Linux Kernel 3.8 or later.  */
#define PTRACE_O_EXITKILL       0x00100000
#endif

long __ve_ptrace(enum __ptrace_request, pid_t, void *, void *);
int ve_ptrace_resume(enum __ptrace_request, pid_t, void *);
#endif
