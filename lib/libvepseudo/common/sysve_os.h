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
 * @file sysve_os.h
 * @brief Header file for sysve functions in pseudo process side.
 */

#ifndef __VE_SYSVE_OS_H
#define __VE_SYSVE_OS_H

#include "sys_common.h"
#include <veos_defs.h>
#include "proto_buff_schema.pb-c.h"
#include "comm_request.h"

int ve_sys_get_pci_sync(veos_handle *, uint8_t, uint64_t *, uint64_t *);
int ve_sys_get_fixed_vehva(veos_handle *, uint64_t, uint64_t *);
int ve_sys_set_user_reg(veos_handle *, uint64_t, uint64_t);
ssize_t ve_sys_get_ve_info(veos_handle *, char *, char *, size_t);
int ve_sys_map_dmades(veos_handle *, uint64_t * ,uint64_t *);
int ve_sys_unmap_dmades(veos_handle *, uint64_t );
int ve_sys_get_veos_pid(veos_handle *);
int64_t ve_sys_get_mns(veos_handle *, uint64_t);
int ve_sys_set_next_thread_worker(veos_handle *);
int ve_sys_stop_user_threads(veos_handle *);
int ve_sys_start_user_threads(veos_handle *);
int ve_sys_get_user_threads_state(veos_handle *);
int ve_request_veos(veos_handle *, enum pseudo_veos_msg_id,
				ProtobufCBinaryData *, PseudoVeosMessage **);
int ve_sys_get_ve_product_name(veos_handle *, char *, size_t);
ssize_t get_ve_info(veos_handle *, char *, char *, char *, ssize_t *, size_t, size_t);

#endif
