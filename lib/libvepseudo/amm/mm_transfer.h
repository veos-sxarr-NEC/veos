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
#define VE_XFER_BLOCK_SIZE      (64 * 1024 * 1024UL) // 64MB
#define ALIGN_BUFF_SIZE		(8UL) // 8 byte

/**
 *@brief structure for calculating address offset and datasize.
 */
struct addr_struct {
        vemva_t top_address;
        vemva_t bottom_address;
        vemva_t aligned_top_address;
        vemva_t aligned_bottom_address;
        int top_offset;
        int bottom_offset;
        size_t new_datasize;
};

extern pthread_rwlock_t sync_fork_dma;

int amm_dma_xfer_req(uint8_t *, veos_handle *, pid_t);
int ve_send_data(veos_handle *, uint64_t, size_t, void *);
int ve_recv_data(veos_handle *, uint64_t, size_t, void *);
int ve_send_data_tid(veos_handle *, uint64_t, size_t, void *, pid_t);
int ve_recv_data_tid(veos_handle *, uint64_t, size_t, void *, pid_t);
int ve_recv_string(veos_handle *, uint64_t, char *, size_t);
int __ve_send_data(veos_handle *, uint64_t, size_t, void *, pid_t);
int __ve_recv_data(veos_handle *, uint64_t, size_t, void *, pid_t);
#endif
