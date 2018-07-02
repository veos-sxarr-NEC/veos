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
* @file syscall_impl.h
* @brief Header file for "syscall.c" file.
*/

#ifndef __SYSCALL_IMPL_H
#define __SYSCALL_IMPL_H

#include "libved.h"

#define NR_ve_syscalls 317
#define MAX_SYSCALL_NAME_LEN 32

#define OPEN_FILE_PATH 256

#define MSYS_CALL_NAME(num)\
	ve_sys_call_hndl_arr[num].ve_sys_call_name
#define MSYS_CALL_FNPTR(num)\
	ve_sys_call_hndl_arr[num].sys_call_hndlr
#define MSYS_CALL_BLOCKFLAG(num)\
	ve_sys_call_hndl_arr[num].block_flag

ret_t ve_generic_offload(int, char *, veos_handle *);
ret_t ve_generic_dup(int, char *, veos_handle *);
#include "ve_syscall_handler.h"

struct ve_sys_call_hndl {
	char ve_sys_call_name[MAX_SYSCALL_NAME_LEN];
	ret_t (*sys_call_hndlr)(int, char *, veos_handle *);
	char *block_flag;
};

#define VE_SYSCALL(num, name, block, handler) \
			[num] = {#name, handler, #block},

struct ve_sys_call_hndl ve_sys_call_hndl_arr[NR_ve_syscalls] = {
#include "ve_syscall_no.h"
};
#endif
