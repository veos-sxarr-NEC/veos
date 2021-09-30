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
 * @file sys_offload.h
 * @brief Header file for "sys_offload.c" file.
 */
#ifndef __SYS_OFFLOAD_H
#define __SYS_OFFLOAD_H

#include "libved.h"

ret_t ve_hndl_readv_preadv(int, char *, veos_handle *);
ret_t ve_hndl_read_pread64(int, char *, veos_handle *);
ret_t ve_hndl_writev_pwritev(int, char *, veos_handle *);
ret_t ve_hndl_write_pwrite64(int, char *, veos_handle *);
ret_t ve_setuid(int, char *, veos_handle *);
ret_t ve_setgid(int , char *, veos_handle *);
ret_t ve_hndl_sethostname_setdomainname(int, char *, veos_handle *);
int sys_is_acc_io_enabled(veos_handle *);
#endif
