/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file dma.h
 * @brief DMA API header
 */
#ifndef VE_VEOS_DMA_H
#define VE_VEOS_DMA_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <libved.h>

struct ve_dma_hdl_struct;
typedef struct ve_dma_hdl_struct ve_dma_hdl;

struct ve_dma_req_hdl_struct;
typedef struct ve_dma_req_hdl_struct ve_dma_req_hdl;

/**
 * @brief address space type for DMA API
 */
typedef enum ve_dma_addrtype {
	VE_DMA_VEMVA,/*!< VEMVA (virtual address for VE core) */
	VE_DMA_VEMVA_WO_PROT_CHECK,/*!< VEMVA (virtual address for VE core) without write protection check*/
	VE_DMA_VHVA,/*!< VHVA (virtual address for VH core) */
	VE_DMA_VEMAA,/*!< VEMAA (physical address on VE memory) */
	VE_DMA_VERAA,/*!< VERAA (physical address on VE registers) */
	VE_DMA_VHSAA,/*!< VHSAA (VH bus address; PCI memory address) */
	VE_DMA_ADDRTYPE_NUMBER,/*!< the number of types, not for arguments */
} ve_dma_addrtype_t;

/**
 * @brief status of DMA request handle
 */
typedef enum ve_dma_status {
	VE_DMA_STATUS_OK = 0,/*!< OK, finished normally */
	VE_DMA_STATUS_NOT_FINISHED,/*!< not finished yet */
	VE_DMA_STATUS_TIMEDOUT,/*!< request is timed out */
	VE_DMA_STATUS_CANCELED,/*!< request is canceled */
	VE_DMA_STATUS_ERROR,/*!< error occured */
} ve_dma_status_t;

#define VE_DMA_OPT_SYNC 0x0000000000000001 /* post DMA request with SYNC bit*/
#define VE_DMA_OPT_RO   0x0000000000000002 /* post DMA request with RO bit */
#define VE_DMA_OPT_IDO  0x0000000000000004 /* post DMA request with IDO bit */
#define VE_DMA_OPT_SYNC_API 0x0000000000000008 /* post DMA request from syncronous api*/

ve_dma_hdl *ve_dma_open_p(vedl_handle *);
int ve_dma_close_p(ve_dma_hdl *);

ve_dma_req_hdl *ve_dma_post_p_va_with_opt(ve_dma_hdl *, ve_dma_addrtype_t, pid_t,
                                 uint64_t, ve_dma_addrtype_t, pid_t, uint64_t,
                                 uint64_t, uint64_t, int);
ve_dma_req_hdl *ve_dma_post_p_va(ve_dma_hdl *, ve_dma_addrtype_t, pid_t,
				 uint64_t, ve_dma_addrtype_t, pid_t, uint64_t,
				 uint64_t);
ve_dma_status_t ve_dma_xfer_p_va(ve_dma_hdl *, ve_dma_addrtype_t, pid_t,
				 uint64_t, ve_dma_addrtype_t, pid_t, uint64_t,
				 uint64_t);

ve_dma_status_t ve_dma_test(ve_dma_req_hdl *);
ve_dma_status_t ve_dma_wait(ve_dma_req_hdl *);
ve_dma_status_t ve_dma_timedwait(ve_dma_req_hdl *, const struct timespec *);
int ve_dma_req_free(ve_dma_req_hdl *);
void ve_dma_terminate_all(ve_dma_hdl *);
#endif
