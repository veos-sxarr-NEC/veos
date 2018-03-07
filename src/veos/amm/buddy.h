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
 * @file buddy.h
 * @brief Header file for buddy.c
 *
 * @internal
 * @author AMM
 */
#ifndef _BUDDY_H
#define _BUDDY_H

#include "ve_list.h"
#include <assert.h>
#include <stdbool.h>
#include "mm_type.h"
#include <stdint.h>


#define BUDDY_FAILED ((void *)-1)
#define PB_SHIFT	21

/**
* @brief : This struct will represents buddy free list
*/
struct free_list {
	int *fr_cnt;	/*!< free block count*/
	bool *resv_compac; /*!< Indicating whether
				list is resr of compac or not*/
	struct list_head *free;	/*Free buddy list for each order*/
};


/**
* @brief :This struct represent the compac pattern
*/
struct compac_pattern {
	int ord;	/*!< Order of block*/
	uint64_t blk_cnt;	/*!< number of block available*/
};


/**
 * This structure stores the state of a buddy system memory allocator object.
 */
struct buddy_mempool {
	pthread_mutex_t buddy_mempool_lock;
	unsigned long    base_addr;    /*!< base address of the memory pool */
	unsigned long    pool_order;   /*!< size of memory pool = 2^pool_order */
	unsigned long    min_order;    /*!< minimum allocatable block size */
	unsigned long    num_blocks;   /*!< number of bits in tag_bits */
	struct free_list *frb;		/*!< free list with some extra info*/
	struct list_head *alloc_req_list; /*!< allocation list hold all block
				taken from buddy on one memory request*/
	unsigned long total_pages;	/*!< Total VE pages */
	unsigned long small_page_used;	/*!< Small page used*/
	unsigned long huge_page_used;	/*!< Huge page used*/
};


/**
 * Each free block has one of these structures at its head. The link member
 * provides linkage for the mp->frb->ree[order] free list, where order is the
 * size of the free block.
 */
struct block {
	struct list_head link;
	uint64_t start;	/*<!start address of block*/
	unsigned long order;	/*<! size of block = 2^order*/
};

struct buddy_mempool *
buddy_init(
	unsigned long base_addr,
	unsigned long pool_order,
	unsigned long min_order
);

#define ALIGN_RD(x, a)  (x & (~((typeof(x))(a) - 1)))

struct buddy_mempool *veos_buddy_init(uint64_t, size_t, size_t);
void buddy_deinit(struct buddy_mempool *mp);
void *buddy_alloc(struct buddy_mempool *mp, unsigned long order);
void buddy_free(struct buddy_mempool *mp, struct block  *block);
void buddy_dump_mempool(struct buddy_mempool *mp);

int __page_entry(struct buddy_mempool *mp, pgno_t pg_no, int pgmod, int order);
int __veos_init_small_page_entry(struct buddy_mempool *mp,
			struct block *block, pgno_t *map);
int __veos_init_huge_page_entry(struct buddy_mempool *mp,
			struct block *block, pgno_t *map);
int veos_page_entry(struct buddy_mempool *mp, uint64_t flag, pgno_t *map);
void *buddy_compac_alloc(struct buddy_mempool *mp,
	struct compac_pattern *alloc_pattern);
void *buddy_non_compac_alloc(struct buddy_mempool *mp, int order);
int __veos_alloc_memory(struct buddy_mempool *mp, int order, uint64_t pgmod);
int veos_alloc_memory(struct buddy_mempool *mp,
	size_t mem_size, uint64_t pgmod);
int veos_delloc_memory(uint64_t page_num, uint64_t pgmod);
int size_to_order(size_t x);
bool is_alloc_compac(struct buddy_mempool *, int, struct compac_pattern*, int);
void dump_free_count(struct buddy_mempool *);
bool is_pow_two(uint64_t);
uint64_t roundown_pow_of_two(uint64_t);
uint64_t roundup_pow_of_two(uint64_t);
void veos_dump_ve_pages(void);
size_t get_size_to_be_free(size_t extra_sz, int order, int count);
#endif
