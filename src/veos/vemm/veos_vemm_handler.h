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
 * @file veos_vemm_handler.h
 * @brief handlers for VEMM agent to be registered
 */
#ifndef VE_VEOS_VEMM_HANDLER_H
#define VE_VEOS_VEMM_HANDLER_H
#include <stdint.h>
#include <sys/types.h>
int veos_vemm_check_pid(pid_t);
int veos_vemm_acquire(pid_t, uint64_t, size_t);
int veos_vemm_get_pages(uid_t, pid_t, uint64_t, size_t, int, uint64_t **,
			size_t *, unsigned char [16]);
int veos_vemm_put_pages(uid_t, pid_t, unsigned char [16]);
int veos_vemm_dmaattach(uid_t, pid_t, uint64_t, int, uint64_t *);
int veos_vemm_dmadetach(uid_t, pid_t, uint64_t);
#endif
