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
 * @file mm_transfer.h
 * @brief Read/write content in VE memory from pseudo.
 *
 * @internal
 * @author AMM
 */
#ifndef __MM_TRANSFER_H
#define __MM_TRANSFER_H

#include "sys_common.h"
#include "mm_type.h"
#define NULLNTFND	-2
#define FAIL2RCV	-3
#define DSTSMLL		-4

int amm_dma_xfer_req(uint8_t *, veos_handle *);
int ve_send_data(veos_handle *, uint64_t, size_t, void *);
int ve_recv_data(veos_handle *, uint64_t, size_t, void *);
int ve_recv_string(veos_handle *, uint64_t, char *, size_t);
int _ve_recv_data_ipc(veos_handle *, uint64_t, size_t, void *);
int _ve_send_data_ipc(veos_handle *, uint64_t, size_t, void *);
int __ve_send_data(veos_handle *, uint64_t, size_t, void *);
int __ve_recv_data(veos_handle *, uint64_t, size_t, void *);
#endif
