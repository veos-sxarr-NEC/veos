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
/*
 * @file buddy.c
 * @brief Handle memory allcotion request.
 *
 * @internal
 * @author AMM
 */
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <math.h>
#include "buddy.h"
#include "ve_mem.h"
#include "ve_shm.h"
#include "memory.h"
#include "veos.h"


/**
* @brief This function will convert size into order.
*
* @param[in] x any integer value (value must be power of two).
*
* @return return order value(order of two).
*/
int size_to_order(size_t x)
{
	int count = 0, bit_count = 0;

	if (x <= 0)
		return 0;

	while (bit_count < (sizeof(size_t) * BITS_PER_BYTE)) {
		if (!(x & (uint64_t)1 << count))
			count++;
		else
			break;
		++bit_count;
	}

	return count;
}

/**
* @brief  This function will check whether value is power of two or not.
*
* @param[in] x value which to be check.
*
* @return  return true if value is power of two else false.
*/
bool is_pow_two(uint64_t x)
{
	return ((x & (x - 1)) == 0);
}

/**
* @brief  This function will roundown the value.
*
* @param[in] x value to be roundown
*
* @return  return roundowned size.
*/
uint64_t roundown_pow_of_two(uint64_t x)
{
	int i = 0, mx_msb_set = -1;

	for (i = 0 ; i < BITS_PER_WORD; i++) {
		if (x & ((uint64_t)1 << i))
			mx_msb_set = mx_msb_set > i ? mx_msb_set : i;
	}

	return ((uint64_t)1 << mx_msb_set);
}

/**
* @brief  This function will calcute how much size
* 	to be free from given block order.
*
* @param[in] extra_sz Extra size.
* @param[in] order order of block
* @param[in] count number of block.
*
* @return This fuction will return size to be free.
*/
size_t get_size_to_be_free(size_t extra_sz, int order, int count)
{
	size_t fr_sz = 0;
	size_t act_sz = (count * (1UL << order));
	size_t soford = 1LU << order;

	VEOS_DEBUG("extra_sz : 0x%lx order : %d  count :%d act_sz :0x%lx",
			extra_sz, order, count, act_sz);
	if (extra_sz <= act_sz)
		fr_sz = ALIGN_RD(extra_sz, soford);
	else
		fr_sz = act_sz;

	VEOS_DEBUG("returning free size(0x%lx)", fr_sz);
	return fr_sz;
}
/**
 * @brief  This function will roundown the value.
*
* @param[in] x value to be roundown.
*
* @return  return roundowned size.
*/
uint64_t roundup_pow_of_two(uint64_t x)
{
	int i = 0, mx_msb_set = -1;

	for (i = 0 ; i < BITS_PER_WORD; i++) {
		if (x & ((uint64_t)1 << i))
			mx_msb_set = mx_msb_set > i ? mx_msb_set : i;
	}
	++mx_msb_set;
	return ((uint64_t)1 << mx_msb_set);
}

/**
* @brief  This function will initialize ve_page entry
*
* @param[in] mp buddy memory pool.
* @param[in] pg_no page number.
* @param[in] pgmod page mode.
* @param[in] order Buddy order from which page belongs.
* @return  return 0 on success and negative of errno on failure.
*/
int __page_entry(struct buddy_mempool *mp, pgno_t pg_no, int pgmod, int order)
{
	struct ve_page *page = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(0);

	VEOS_TRACE("invoked");

	VEOS_DEBUG("add %s entry %ld of order %d from mempool(%p)",
			pgmod_to_pgstr(pgmod), pg_no, order, mp);

	page = (struct ve_page *)calloc(1, sizeof(struct ve_page));
	if (NULL == page) {
		 VEOS_CRIT("calloc error while allocating struct page");
		 return -ENOMEM;
	}

	page->page_start = (uint64_t)(mp->base_addr +
			(pg_no * (1UL << (mp->min_order))));

	page->pgsz = (size_t)pgmod_to_pgsz(pgmod);
	page->flag = PG_VE;
	page->perm = 0;
	page->ref_count = 0;
	page->dma_ref_count = 0;
	page->private_data = NULL;
	page->owner = NULL;
	page->buddy_order = order;

	if (vnode_info->ve_pages[pg_no] != NULL) {
		 VEOS_DEBUG("page %ld already allocated", pg_no);
		 free(page);
		 return -EINVAL;
	}

	vnode_info->ve_pages[pg_no] = page;

	VEOS_DEBUG("added entry for %s  page no(%ld) in node page array(%p)",
			pgsz_to_pgstr(page->pgsz), pg_no,
			vnode_info->ve_pages);
	VEOS_DEBUG("%s (%p) info start(%lx), flag(%ld) perm(%ld), refcnt(%ld)"
			"dma refcnt(%ld), private(%p), own(%p), order(%d)",
			pgsz_to_pgstr(page->pgsz), page, page->page_start,
			page->flag, page->perm, page->ref_count, page->dma_ref_count,
			page->private_data, page->owner, page->buddy_order);

	VEOS_TRACE("returned");
	return 0;
}

/**
* @brief  This will make entry according
*	to each buddy block.If block is allocated for small page.
*
* @param[in] mp buddy memory pool.
* @param[in] s_pg start page number.
* @param[in] t_pg total page number.
* @param[in] block buddy block.
* @param[out] mappage number array.
* @return  return 0 on success and negative of errno on failure.
*/
int __veos_init_small_page_entry(struct buddy_mempool *mp,
		struct block *block, pgno_t *map)
{
	uint64_t idx = 0;
	pgno_t s_pg = 0, t_pg = 0;
	int ret = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("page map(%p): block(%p) for mempool(%p)", map, block, mp);
	VEOS_DEBUG("mem blk start 0x%lx and order %ld", block->start, block->order);

	s_pg = (block->start >> PSSHFT);
	t_pg = ((1UL << block->order) >> PSSHFT);

	VEOS_DEBUG("iterate for page start %ld to end %ld", s_pg, t_pg);

	for (idx = 0; idx < t_pg; idx++) {
		VEOS_TRACE("start page %ld and current page %ld", s_pg, (s_pg + idx));
		ret = __page_entry(mp, (s_pg + idx), PG_2M, block->order);
		if (0 > ret) {
			VEOS_DEBUG("failed to update node page entry");
			return ret;
		}
		VEOS_TRACE("page map address(%p)", &map[idx]);
		map[idx] = (s_pg + idx);
		++mp->small_page_used;
		VEOS_TRACE("In node %ld %s in use",
			mp->small_page_used, pgmod_to_pgstr(PG_2M));
	}
	VEOS_DEBUG("page entry update itertation ends");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
* @brief  This will make entry according to each buddy block. If block is
*	allocated for huge page.
*
* @param[in] mp buddy memory pool.
* @param[in] s_pg start page number.
* @param[in] t_pg total page number.
* @param[in] block buddy block.
* @param[in] map page number array.
* @return  return 0 on success and negative of errno on failure.
*/
int __veos_init_huge_page_entry(struct buddy_mempool *mp,
	struct block *block, pgno_t *map)
{
	int idx = 0;
	int ret = 0;
	uint64_t s_pg = 0, t_pg = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);

	s_pg = (block->start >> PSSHFT);
	t_pg = ((1UL << block->order) >> PSSHFT_H);

	VEOS_TRACE("invoked");

	VEOS_DEBUG("page map(%p): block(%p) for mempool(%p)",
			map, block, mp);
	VEOS_DEBUG("mem blk start 0x%lx and order %ld", block->start, block->order);


	VEOS_DEBUG("iterate for page start %ld to end %ld",
			s_pg, t_pg);
	for (idx = 0; idx < (t_pg * HUGE_PAGE_IDX); idx++) {
		VEOS_TRACE("start page %ld and current page %ld",
					s_pg, (s_pg + idx));

		if (!(idx % HUGE_PAGE_IDX)) {
			VEOS_TRACE("updating actual huge page entry");
			ret = __page_entry(mp, (s_pg + idx), PG_HP,
						block->order);
			if (0 > ret) {
				VEOS_DEBUG("failed to update node page entry");
				return ret;
			}
			VEOS_TRACE("page map address(%p)", &map[(idx/HUGE_PAGE_IDX)]);
			map[(idx/HUGE_PAGE_IDX)] = (s_pg + idx);
			++mp->huge_page_used;
			VEOS_TRACE("In node %ld %s in use",
				mp->huge_page_used, pgmod_to_pgstr(PG_HP));
		} else {
			VEOS_TRACE("updating page entry for huge index");
			vnode_info->ve_pages[(s_pg + idx)] = (struct ve_page *)-1;
		}
	}
	VEOS_DEBUG("page entry update itertation ends");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}

/**
* @brief  This function will take each block from addr_alloc_list
*
* @param[in] mp buddy mempool.
* @param[in] pgmod page mode.
* @param[out] map page number array to store allocated page.
* @return  return 0 on success and  negative of errno on failure.
*/
int veos_page_entry(struct buddy_mempool *mp,
		uint64_t pgmod, pgno_t *map)
{
	int ret = 0;
	struct block *curr_blk = NULL, *tmp_blk = NULL;
	uint64_t idx = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("%s map(%p)", pgmod_to_pgstr(pgmod), map);

	/*make entries for each allocation*/
	VEOS_TRACE("traversing mempool allocation list");
	list_for_each_entry_safe(curr_blk,
			tmp_blk, mp->alloc_req_list, link) {

		if (pgmod == PG_2M) {
			VEOS_TRACE("map:%p, idx:%ld :: (map +idx):%p",
					map, idx, (map + idx));

			ret =  __veos_init_small_page_entry(mp, curr_blk, (map + idx));
			if (0 > ret) {
				VEOS_DEBUG("fail to update %s entry",
					pgmod_to_pgstr(pgmod));
				return ret;
			}
			idx += ((1UL << curr_blk->order) >> PSSHFT);
			VEOS_DEBUG("udpated idx(%ld)", idx);
		} else {
			VEOS_TRACE("map:%p, idx:%ld :: (map +idx):%p", map, idx, (map+idx));
			ret = __veos_init_huge_page_entry(mp, curr_blk, (map + idx));
			if (0 > ret) {
				VEOS_DEBUG("fail to update %s entry", pgmod_to_pgstr(pgmod));
				return ret;
			}
			idx += ((1UL << curr_blk->order) >> PSSHFT_H);
			VEOS_DEBUG("udpated idx(%ld)", idx);
		}
		/*Delete entry from allocation request list*/
		list_del(&curr_blk->link);
		free(curr_blk);
	}
	/*Check whether list is empty or not*/
	if (list_empty(mp->alloc_req_list)) {
		VEOS_DEBUG("mempool allocation list is clean after allocation");
		INIT_LIST_HEAD(mp->alloc_req_list);
	}

	VEOS_TRACE("returned");
	return  ret;
}

/**
* @brief  This function will allocate buddy for non compac allocation.
*
* @param[in] mp buddy mempool.
* @param[in] order[in] requested order .
*
* @return return vemaa on success and BUDDY_FAILED on failure.
*/
void *buddy_non_compac_alloc(struct buddy_mempool *mp, int order)
{
	vemaa_t *vemaa = NULL;
	struct block *alloc_block = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("allocate memory blk of order %d from mempool(%p)", order, mp);

	vemaa  = buddy_alloc(mp, order);
	if (BUDDY_FAILED == vemaa) {
		VEOS_DEBUG("failed to allocate memory blk from mempool");
		return BUDDY_FAILED;
	} else {
		/*add allocated block to alloc_req_list*/
		alloc_block = (struct block *) calloc(1, sizeof(struct block));
		if (NULL == alloc_block) {
			VEOS_CRIT("calloc error while allocating budy block");
			return BUDDY_FAILED;
		}
		alloc_block->order = order;
		alloc_block->start = (uint64_t)vemaa;
		VEOS_DEBUG("block allocated start %lx and order %ld",
			alloc_block->start, alloc_block->order);
		list_add_tail(&alloc_block->link, mp->alloc_req_list);
	}

	VEOS_TRACE("returned");
	return vemaa;
}

/**
* @brief  This function will free memory.
*
* @param[in] page_num page number to be free.
* @param[in] pgmod page mode(2MB/64MB).
*
* @return return 0 on suceess and negative of errno on failure.
*/
int veos_delloc_memory(uint64_t page_num, uint64_t pgmod)
{
	struct block *free_block = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	VEOS_DEBUG("freeing %s page %lx", pgmod_to_pgstr(pgmod), page_num);

	free_block = (struct block *)calloc(1, sizeof(struct block));
	if (NULL == free_block) {
		VEOS_CRIT("calloc error while allocating buddy blk");
		return -ENOMEM;
	}
	free_block->start = (uint64_t)(page_num << PB_SHIFT);
	if (pgmod == PG_2M) {
		free_block->order = size_to_order(PAGE_SIZE_2MB);
	} else {
		free_block->order = size_to_order(PAGE_SIZE_64MB);
	}
	VEOS_DEBUG("freeing buddy blk(%p) with start 0x%lx and order %ld",
			free_block, free_block->start, free_block->order);

	buddy_free(vnode->mp, free_block);
	VEOS_TRACE("returned");
	return 0;
}

/**
* @brief  This function will allocate memories per page size
*	till reach aquired size.
*
* @param[in] mp VE buddy mempool.
* @param[in] mem_size memory size to be requested.
*		This is expected multiple of page size.
* @param[in] pgmod page mode.
*
* @return  return 0 on success and negative of errno on failure.
*/
int veos_alloc_memory(struct buddy_mempool *mp,
	size_t mem_size, uint64_t pgmod)
{
	size_t r_size = 0;
	int order = 0;
	size_t pgsz = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("allocate %s mem blk of size %lx",
			pgmod_to_pgstr(pgmod), mem_size);
	if (mem_size <= 0) {
		VEOS_DEBUG("Invalid memory size");
		return -EINVAL;
	}

	if (NULL == mp) {
		VEOS_DEBUG("Invalid mempool");
		return -EINVAL;
	}

	if (pgmod == PG_2M)
		pgsz = PAGE_SIZE_2MB;
	else
		pgsz = PAGE_SIZE_64MB;

	if ((mem_size % pgsz) != 0) {
		VEOS_DEBUG("memory size is not multipule of page size");
		return -EINVAL;
	}

	r_size = mem_size;
	order = size_to_order(pgsz);
	VEOS_DEBUG("iteration starts till remaining size becomes zero");
	while (r_size > 0) {
		VEOS_TRACE("remaining size %lx mapped to order %d",
			   r_size, order);
		if (BUDDY_FAILED == buddy_non_compac_alloc(mp, order)) {
			VEOS_DEBUG("Error allocate memory");
			return -ENOMEM;
		}
		r_size -= pgsz;
	}
	VEOS_DEBUG("iteration ends");
	VEOS_TRACE("returned");

	return 0;
}

/**
* @brief This function will check whether this block is free or not.
*
* @param[in] free_list free buddy list.
* @param[in] block buddy block.
*
* @return if block is free then returns true and else false.
*/
bool is_free(struct list_head *free_list, struct block *block)
{
	struct block *free_blk = NULL;
	VEOS_TRACE("invoked for blk(%p) start %lx and order %ld",
				block, block->start, block->order);
	if (list_empty(free_list))
		return false;

	VEOS_DEBUG("traversing free list(%p) starts", free_list);
	list_for_each_entry(free_blk, free_list, link) {
		VEOS_TRACE("free blk(%p) with start %lx",
				free_blk, free_blk->start);
		if (free_blk->start == block->start)
			return true;
	}

	VEOS_TRACE("returned");
	return false;
}

/**
* @brief This function will give free count in every list.
*
* @param[in] mp VE buddy memory pool.
*/
void dump_free_count(struct buddy_mempool *mp)
{
	int order = 0;
	VEOS_TRACE("invoked for mempool %p", mp);
	VEOS_TRACE("iteration starts from order %ld to mempool order %ld",
					mp->min_order, mp->pool_order);
	for (order = mp->min_order; order <= mp->pool_order; order++)
		VEOS_DEBUG("order : %d total free block : %d",
				order, mp->frb->fr_cnt[order]);
	VEOS_TRACE("iteration ends");
}


/**
* @brief This function will find the buddy.
*
* @param[in] mp VE buddy memory pool.
* @param[in] self block whose buddy to be find.
* @param[in] order buddy order.
*
* @return returns buddy block on success else return BUDDY_FAILED.
*/
struct block *get_buddy(struct buddy_mempool *mp,
		struct block *self, int order)
{
	struct block *free_buddy = NULL;
	uint64_t self_start = 0;
	uint64_t _buddy = 0;
	VEOS_TRACE("invoked");
	VEOS_DEBUG("getting buddy blk from pool %p with self %p and order %d",
							mp, self, order);
	VEOS_DEBUG("mempool base %lx and self start %lx",
			mp->base_addr, self->start);
	self_start = (uint64_t)self->start - mp->base_addr;
	VEOS_DEBUG("self start after calc %lx", self->start);
	_buddy = self_start ^ (((uint64_t)1) << order);
	VEOS_DEBUG("_buddy %lx", _buddy);
	if (list_empty(&mp->frb->free[order]))
		return (void *)-1;
	VEOS_DEBUG("traversing free list(%p) of order %d",
			&mp->frb->free[order], order);
	list_for_each_entry(free_buddy, &mp->frb->free[order], link) {
		VEOS_TRACE("free_buddy(%p) and start %lx",
			free_buddy, free_buddy->start);
		if (free_buddy->start == _buddy)
			return free_buddy;
	}

	return BUDDY_FAILED;

}

/**
* @brief  This function will return buddy block to VE memory pool.
*
* @param[in] mp VE buddy_mempool.
* @param[in] block buddy block which is to be return.
*/
void buddy_free(struct buddy_mempool *mp, struct block *block)
{

	int order = 0;
	VEOS_TRACE("invoked");

	order = block->order;
	VEOS_DEBUG("freeing buddy block(%p) to mempool(%p)", block, mp);

	if (order < mp->min_order)
		order = mp->min_order;

	/*check whether block is already free or not*/
	if (is_free(&mp->frb->free[order], block))
		return;

	/* Coalesce as much as possible with adjacent free buddy blocks */
	VEOS_DEBUG("iterate from order %d to pool order %ld", order, mp->pool_order);
	while (order < mp->pool_order) {
		VEOS_TRACE("block %p of order %d from mempool(%p)", block, order, mp);

		struct block *buddy = get_buddy(mp, block, order);
		if (buddy == BUDDY_FAILED)
			break;

		list_del(&buddy->link);
		VEOS_TRACE("blk start %lx and buddy start %lx", block->start, buddy->start);
		if (buddy->start < block->start)
			block->start = buddy->start;
		VEOS_TRACE("before decrementing free blk cnt %d for order %d",
						mp->frb->fr_cnt[order], order);
		if (mp->frb->fr_cnt[order] != 0)
			--mp->frb->fr_cnt[order];

		++order;
		free(buddy);
		block->order = order;
		VEOS_TRACE("updated blk start %lx and order %ld",
				block->start, block->order);
	}

	VEOS_DEBUG("iteration ends");
	VEOS_DEBUG("add blk(%p) with start %lx of order %ld",
		block, block->start, block->order);

	/* Add the (possibly coalesced) block to the appropriate free list */
	list_add(&block->link, &mp->frb->free[block->order]);
	++mp->frb->fr_cnt[block->order];
	VEOS_DEBUG("updated free blk cnt is %d for order %ld",
		mp->frb->fr_cnt[block->order], block->order);
	VEOS_TRACE("returned");
}


/**
* @brief This function will intialize the buddy mempool.
*
* @param[in] start_addr starting address of memory.
* @param[in] mem_size size of memory.
*
* @return on success in returns mempool and of failure NULL.
*/
struct buddy_mempool *veos_buddy_init(uint64_t start_addr, size_t mem_size, size_t min_pgsz)
{
	uint64_t nr_pages = 0;
	size_t r_size = 0;
	size_t f_mx_size = 0;
	struct block *new_blk = NULL;
	struct buddy_mempool *mempool = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("buddy memory size is 0x%lx", mem_size);

	f_mx_size = roundown_pow_of_two(mem_size);

	VEOS_DEBUG("First max size : 0x%lx", f_mx_size);
	r_size = mem_size - f_mx_size;

	VEOS_DEBUG("remaining size : 0x%lx", r_size);

	mempool = buddy_init((start_addr + r_size), size_to_order(f_mx_size),
			size_to_order(min_pgsz));
	if (NULL == mempool) {
		VEOS_DEBUG("Error (%s) in buddy initailzaition",
				strerror(errno));
		return NULL;
	}

	new_blk = (struct block *)calloc(1, sizeof(struct block));
	if (NULL == new_blk) {
		VEOS_DEBUG("error(%s) while allocating memory to buddy block",
			strerror(errno));
		buddy_deinit(mempool);
		return NULL;
	}
	new_blk->start = (start_addr + r_size);
	new_blk->order = size_to_order(f_mx_size);

	buddy_free(mempool, new_blk);

	if (min_pgsz == PAGE_SIZE_2MB)
		nr_pages = f_mx_size >> PSSHFT;
	else
		nr_pages = f_mx_size >> PSSHFT_H;

	/*Now add remaining memory into buddy mempool according to the size*/
	while (r_size > 0) {
		new_blk = calloc(1, sizeof(struct block));
		if (new_blk == NULL) {
			VEOS_CRIT("Error (%s) while allocating memory for new_blk",
					strerror(errno));
			buddy_deinit(mempool);
			return NULL;
		}
		new_blk->order = size_to_order(roundown_pow_of_two(r_size));
		buddy_free(mempool, new_blk);
		if (min_pgsz == PAGE_SIZE_2MB)
			nr_pages = nr_pages + (roundown_pow_of_two(r_size) >> PSSHFT);
		else
			nr_pages = nr_pages + (roundown_pow_of_two(r_size) >> PSSHFT_H);

		r_size = (size_t)(r_size - roundown_pow_of_two(r_size));
		new_blk->start = start_addr + r_size;
		VEOS_TRACE("remaining size : 0x%lx", r_size);
	}
	mempool->base_addr = start_addr;
	mempool->total_pages = nr_pages;
	mempool->small_page_used = 0;
	mempool->huge_page_used = 0;

	VEOS_DEBUG("memory pool base address(0%lx)", mempool->base_addr);
	VEOS_DEBUG("total number of pages(%ld)", mempool->total_pages);

	VEOS_TRACE("returned");
	return mempool;
}
/**
* @brief Initializes a buddy system memory allocator object.
*
* @param[in] base_addr Base address of the memory pool.
* @param[in] pool_order Size of the memory pool (2^pool_order bytes).
* @param[in] min_order Minimum allocatable block size (2^min_order bytes).
*
* @return on sucesss Pointer to an initialized buddy mempool
*	and on failure it will return NULL.
*/
struct buddy_mempool *
buddy_init(
	unsigned long base_addr,
	unsigned long pool_order,
	unsigned long min_order
)
{
	struct buddy_mempool *mp = NULL;
	unsigned long i = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("Init memory pool with start %lx  pool order %lu and min order %lu",
						base_addr, pool_order, min_order);
	/* The minimum block order must be
	 * smaller than the pool order */
	if (min_order > pool_order)
		return NULL;

	mp = calloc(1, sizeof(struct buddy_mempool));
	if (NULL == mp) {
		VEOS_CRIT("calloc error wile allocating buddy mempool object");
		return NULL;
	}

	mp->base_addr  = base_addr;
	mp->pool_order = pool_order;
	mp->min_order  = min_order;

	VEOS_DEBUG("buddy mempool configured with base address %lx",
						mp->base_addr);
	VEOS_DEBUG("buddy mempool configured with pool order %lu and min order %lu",
						mp->pool_order, mp->min_order);

	/* Allocate a list for every order up to the maximum allowed order *
	 * Here we need  to allocate memoty for only defined type of order*/
	VEOS_DEBUG("Allocating free list object of size %lu", sizeof(struct free_list));
	mp->frb = calloc(1, sizeof(struct free_list));
	if (NULL == mp->frb) {
		VEOS_CRIT("Calloc error while allocating mempool free list object");
		free(mp);
		return NULL;
	}
	VEOS_DEBUG("free list object allocated is %p", mp->frb);

	VEOS_DEBUG("Allocating per order free list of size %lu and count %lu",
			sizeof(struct list_head), (pool_order + 1));
	mp->frb->free = calloc((pool_order + 1),
			 sizeof(struct list_head));
	if (NULL == mp->frb->free) {
		VEOS_CRIT("calloc error while allocating per order free list");
		free(mp->frb);
		free(mp);
		return NULL;
	}

	VEOS_DEBUG("free list object allocated is %p", mp->frb);

	/*free count each list*/
	mp->frb->fr_cnt = calloc((pool_order + 1), sizeof(int));
	if (NULL == mp->frb->fr_cnt) {
		VEOS_CRIT("calloc error while allocating per order free blk count");
		free(mp->frb->free);
		free(mp->frb);
		free(mp);
		return NULL;
	}
	mp->frb->resv_compac = calloc((pool_order + 1), sizeof(bool));
	if (NULL == mp->frb->resv_compac) {
		VEOS_CRIT("calloc error while allocating per order compact allocation info");
		free(mp->frb->fr_cnt);
		free(mp->frb->free);
		free(mp->frb);
		free(mp);
		return NULL;
	}


	/* Initially all lists are empty */
	for (i = 0; i <= pool_order; i++) {
		mp->frb->fr_cnt[i] = 0;
		mp->frb->resv_compac[i] = false;
		INIT_LIST_HEAD(&mp->frb->free[i]);
	}

	/*Initialize allocation list*/
	mp->alloc_req_list = calloc(1, sizeof(struct list_head));
	if (NULL == mp->alloc_req_list) {
		VEOS_CRIT("calloc error while allocating mempool req list");
		free(mp->frb->resv_compac);
		free(mp->frb->fr_cnt);
		free(mp->frb->free);
		free(mp->frb);
		free(mp);
		return NULL;
	}

	INIT_LIST_HEAD(mp->alloc_req_list);

	VEOS_TRACE("returned with pool %p", mp);
	return mp;
}


/**
* @brief This function will deintialize all VE buddy memory pool.
*
* @param[in] mp VE buddy memory pool.
*/
void buddy_deinit(struct buddy_mempool *mp)
{
	int order = 0;
	struct block *curr_blk = NULL, *tmp_blk = NULL;

	VEOS_TRACE("invoked for pool %p", mp);

	VEOS_DEBUG("Uninitialize buddy mempool");

	if (mp == NULL)
		return;
	/*free resv compac flag for all order*/
	VEOS_DEBUG("deallocating per order compac flag");
	if (mp->frb->resv_compac)
		free(mp->frb->resv_compac);

	mp->frb->resv_compac = NULL;

	/*free free_count*/
	VEOS_DEBUG("deallocating per order free block cnt");
	if (mp->frb->fr_cnt)
		free(mp->frb->fr_cnt);

	mp->frb->fr_cnt = NULL;

	VEOS_DEBUG("mempool order %lu and min order %lu", mp->pool_order, mp->min_order);
	/*make sure that all list memory should be free*/
	for (order = mp->min_order; order <= mp->pool_order; order++) {
		if (!list_empty(&mp->frb->free[order])) {
			list_for_each_entry_safe(curr_blk, tmp_blk,
					&mp->frb->free[order], link) {
				VEOS_DEBUG("mem order(%d): curr blk(%p) : free list(%p)",
						order, curr_blk, &mp->frb->free[order]);
				list_del(&curr_blk->link);
				free(curr_blk);
			}
		}
	}
	/*freeing all free list*/
	VEOS_DEBUG("deallocating free list object");
	if (mp->frb->free)
		free(mp->frb->free);

	mp->frb->free = NULL;

	/*freeing free block*/
	VEOS_DEBUG("deallocating free blk object");
	free(mp->frb);
	mp->frb = NULL;

	/*freeing  allocation request list*/
	VEOS_DEBUG("deallocating mempool req list");
	if (mp->alloc_req_list)
		free(mp->alloc_req_list);
	mp->alloc_req_list =  NULL;

	/*freeing complete memory pull*/
	free(mp);

	mp = NULL;

	VEOS_TRACE("returned");
}


/**
* @brief This function will allocate buddy block.
*
* @param[in] mp VE Buddy mempool.
* @param[in] order requested buddy order.
*
* @return return buddy start on success and BUDDY_FAILED on failure.
*/
void *
buddy_alloc(struct buddy_mempool *mp, unsigned long order)
{
	unsigned long j = 0;
	void *vemaa = NULL;
	struct list_head *list = NULL;
	struct block *block = NULL;
	struct block *buddy_block = NULL;

	VEOS_TRACE("invoked");

	if (mp == NULL) {
		VEOS_DEBUG("invalid buddy mempool");
		return BUDDY_FAILED;
	}

	VEOS_DEBUG("buddy mempool max order is %lu", mp->pool_order);
	VEOS_DEBUG("buddy mempool min order is %lu", mp->min_order);

	if (order > mp->pool_order) {
		VEOS_DEBUG("order greater than buddy max order");
		return BUDDY_FAILED;
	}

	/* Fixup requested order to be at least the minimum supported */
	if (order < mp->min_order)
		order = mp->min_order;

	VEOS_DEBUG("request to allocate mem blk of order %lu", order);

	for (j = order; j <= mp->pool_order; j++) {
		/* Try to allocate the first block in the order j list */
		list = &mp->frb->free[j];
		if (list_empty(list))
			continue;
		block = list_entry(list->next, struct block, link);
		list_del(&block->link);
		if (mp->frb->fr_cnt[j])
			--mp->frb->fr_cnt[j];

		/* spilt and add into free list if a higher order
		 * block than necessary was allocated */
		VEOS_DEBUG("free extra allocated memory block");
		while (j > order) {
			VEOS_DEBUG("order %ld greater than requested memory order %ld", j, order);
			--j;
			buddy_block = (struct block *)
				calloc(1, sizeof(struct block));
			if (NULL == buddy_block) {
				VEOS_CRIT("calloc error while allocating memory for buddy block");
				return BUDDY_FAILED;
			}
			buddy_block->start = (uint64_t)
					((block->start + (1UL << j)));
			buddy_block->order = j;
			list_add(&buddy_block->link, &mp->frb->free[j]);
			++mp->frb->fr_cnt[j];
			VEOS_TRACE("free blk start %lx and order %lu",
				buddy_block->start, buddy_block->order);
			VEOS_TRACE("pool free blk list %p and blk link %p",
					&buddy_block->link, &mp->frb->free[j]);
			VEOS_TRACE("mempool free blk count %d for order %ld",
				mp->frb->fr_cnt[j], j);
		}

		vemaa = (void *)block->start;
		VEOS_DEBUG("allocated blk start %lx and order %lu",
			block->start, block->order);
		free(block);
		VEOS_TRACE("returned");
		return vemaa;
	}

	return BUDDY_FAILED;
}
/**
* @brief  Dumps the state of a buddy system
*	memory allocator object to the log file.
*
* @param[in] mp VE buddy memory pool.
*/
void
buddy_dump_mempool(struct buddy_mempool *mp)
{
	unsigned long i = 0;
	struct block *free_block = NULL;

	VEOS_TRACE("---------------------------------------------------");
	VEOS_TRACE("ORDER       BUDDY_START       BUDDY_END        SIZE");
	for (i = mp->min_order; i <= mp->pool_order; i++) {
		/* Count the number of memory blocks in the list */
		list_for_each_entry(free_block, &mp->frb->free[i], link) {
			VEOS_TRACE("%5ld %15lx %15lx %13lx",
				free_block->order, free_block->start,
			(free_block->start + ((1UL << free_block->order) - 1)),
				(1UL << free_block->order));
		}
	}
	VEOS_DEBUG("TOTAL PAGES :%ld", mp->total_pages);
	VEOS_DEBUG("TOTAL SMALL PAGE USED :%ld", mp->small_page_used);
	VEOS_DEBUG("TOTAL HUGE PAGE USED :%ld", mp->huge_page_used);
	VEOS_TRACE("-------------------------------------------------");
}


/**
* @brief  This function will dump state of VE PAGE array.
*/
void veos_dump_ve_pages(void)
{
	int pg_idx = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	struct ve_page **ve_pages = vnode_info->ve_pages;

	if (!ve_pages) {
		VEOS_DEBUG("no dump inforamation available");
		return;
	}

	VEOS_DEBUG("================================== NODE VE PAGES DUMP ================================");
	VEOS_DEBUG("PAGE NO	PAGE START	AMM_COUNT      DMA_COUNT	BUDDY_ORDER	PG MODE");
	VEOS_DEBUG("--------------------------------------------------------------------------------------");
	for (pg_idx = 0; pg_idx < vnode_info->
				mp->total_pages; pg_idx++) {
		if ((ve_pages[pg_idx] != NULL) &&
				(ve_pages[pg_idx] != (struct ve_page *)-1)) {
				VEOS_DEBUG("%5d%15lx%15ld%15ld%15d%15s",
					pg_idx, ve_pages[pg_idx]->page_start,
				ve_pages[pg_idx]->ref_count,
				ve_pages[pg_idx]->dma_ref_count,
					ve_pages[pg_idx]->buddy_order,
				(ve_pages[pg_idx]->
					pgsz == PAGE_SIZE_2MB)
				? "SMALL":"HUGE");
		}
	}
	VEOS_DEBUG("--------------------------------------------------------------------------------------");
}

/**
 * @brief This function will calculate total size of free block.
 *
 * @param[in] mp VE Buddy mempool.
 * @param[in] pgmod page mode.
 *
 * @return return total size of free block.
 */
size_t calc_free_sz(struct buddy_mempool *mp, int pgmod)
{
	int j = 0;
	int order = 0;
	size_t sz = 0;
	struct list_head *list = NULL;
	struct block *curr_blk = NULL, *tmp_blk = NULL;

	if (mp == NULL) {
		VEOS_DEBUG("Invalid mempool.");
		return 0;
	}

	if (pgmod == PG_2M)
		order = size_to_order(PAGE_SIZE_2MB);
	else
		order = size_to_order(PAGE_SIZE_64MB);

	for (j = order; j <= mp->pool_order; j++) {
		list = &mp->frb->free[j];
		if (list_empty(list))
			continue;
		VEOS_TRACE("calc:fr_cnt[%d]=%d", j, mp->frb->fr_cnt[j]);
		list_for_each_entry_safe(curr_blk, tmp_blk, list, link) {
			sz += (1UL << curr_blk->order);
		}
	}
	return sz;
}
