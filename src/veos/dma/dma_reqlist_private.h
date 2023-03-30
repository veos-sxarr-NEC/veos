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
 * @file dma_reqlist_private.h
 * @brief private header only for dma_reqlist.c
 */
#ifndef VE_VEOS_DMA_REQUEST_PRIVATE_H
#define VE_VEOS_DMA_REQUEST_PRIVATE_H
#include <libved.h>
#include <time.h>

#include <veos_arch_defs.h>

#include "ve_list.h"

#define BLOCK_LIMIT 256

/**
 * @brief status of DMA reqlist entry
 */
enum ve_dma_reqlist_entry_status {
	VE_DMA_ENTRY_NOT_POSTED = 0,/*!< request is not posted yet */
	VE_DMA_ENTRY_ONGOING,/*!< request is posted but not finished */
	VE_DMA_ENTRY_CANCELED,/*!< request is posted and canceled afterwards */
	VE_DMA_ENTRY_ERROR,/*!< request caused error */
	VE_DMA_ENTRY_COMPLETED,/*!< request is completed */
};

/**
 * @brief Address
 */
struct ve_dma__addr {
	uint64_t type_hw;/*!< address type on DMA descriptor */
	uint64_t addr;/*!< address value */
};
typedef struct ve_dma__addr ve_dma__addr;

struct ve_dma__block;
typedef struct ve_dma__block ve_dma__block;
struct ve_dma__block {
	struct list_head list;/*!< for chaining blocks */
	uint64_t vaddr;  /*!< start virtual address value */
	uint64_t length; /*!< length of block */
	uint64_t *paddr; /*!< array with physical address of pages */
	uint32_t npages;
	int pgsz;	 /*!< page size */
	void (*unpin)(vedl_handle *, ve_dma__block *);/*!< unpin function */
	struct timespec ts, te; /* block creation start and end times */
	ve_dma_addrtype_t type; /*!< memory type of this block */
};

/**
 * @brief DMA reqlist entry, a physical request to be put on a descriptor
 */
struct ve_dma_reqlist_entry {
	struct list_head list;/*!< sibling composing the DMA request */
	struct list_head waiting_list;/*!< for wait queue */
	struct ve_dma_req_hdl_struct *req_head;/*!< DMA request handle */
	struct ve_dma__addr src;/*!< source */
	struct ve_dma__addr dst;/*!< destination */
	uint32_t length;/*!< transfer length in byte */
	uint64_t status_hw;/*!< HW-dependent status */
	enum ve_dma_reqlist_entry_status status;/*!< status of this DMA reqlist entry */
	int entry;/* 0, 1, ..., VE_DMA_NUM_DESC - 1, or -1 (not posted) */
	uint64_t opt;
	int last;
	struct ve_dma__block *src_block;
	struct ve_dma__block *dst_block;
};

/**
 * @brief VEMVA TLB
 */
struct ve_dma_vemtlb {
	uint64_t vaddr;/*!< Virtual address (VEMVA) */
	int64_t paddr;/*!< Physical address (VEMAA) */
	int prot;/*!< protection attribute of the page */
};

#endif
