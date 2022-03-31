/*
 * Copyright (C) 2021 NEC Corporation
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
 * @file vemmr_mgmt.c
 * @brief Management VEMMR usage
 */

#include <pthread.h>
#include <assert.h>
#include "vemva_mgmt.h"
#include "vemmr_mgmt.h"
#include "sysve_os.h"
#include "proto_buff_schema.pb-c.h"
#include "mm_transfer.h"

#define VEMMR_INFO_LEN  (VEMMR_SIZE / (sizeof(uint64_t) * 8 * CHUNK_16GB))
#define CHUNK_PER_INFO  (sizeof(uint64_t) * 8)

static struct vemmr_usage vemmr_info[VEMMR_INFO_LEN]; /*!< Protected by vemmr_lock */
static struct vemmr_index cached_index;
static pthread_mutex_t vemmr_lock; /*!< Lock for VEMMR info */
static int64_t rdma_offset_global; /*!< RDMA_OFFSET */

/**
 * @brief Print vemmr_info into Pseudo logs
 */
static void
dump_vemmr_info()
{
	int i, j;

	PSEUDO_DEBUG("Dumping vemmr_info");
	for (i = 0; i < VEMMR_INFO_LEN; i++) {
		if (vemmr_info[i].blocks_16GB != (uint64_t)-1)
			PSEUDO_DEBUG("vemmr_info[%d].blocks_16GB : 0x%lx",
						i, vemmr_info[i].blocks_16GB);
		for (j = 0; j < (sizeof(uint64_t) * 8); j++) {
			if (vemmr_info[i].blocks_512MB[j] != (uint32_t)-1)
				PSEUDO_DEBUG("vemmr_info[%d].blocks_512MB[%d]:"
						" 0x%x", i, j,
						vemmr_info[i].blocks_512MB[j]);
		}
	}
	PSEUDO_DEBUG("Dumped vemmr_info");
}

/**
 * @brief This function partitions VEMMR into 16GB blocks, and marks each block
 *        as UNUSED.
 *
 * @return 0 on success, -1 on failure.
 */
int
ve_init_vemmr(void)
{
	int i, j, ret;
	int retval = -1;

	PSEUDO_TRACE("Invoked");

	ret = pthread_mutex_init(&vemmr_lock, NULL);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to init vemmr_lock %s", strerror(ret));
		goto hndl_return;
	}
	for (i = 0; i < VEMMR_INFO_LEN; i++) {
		vemmr_info[i].blocks_16GB = (uint64_t)-1;
		for (j = 0; j < (sizeof(uint64_t) * 8); j++) {
			vemmr_info[i].blocks_512MB[j] = (uint32_t)-1;
		}
	}
	/* When mmap() is called without address,
	 * address for 64MB page is allocated from 0x6100 0000 0000 in order.
	 * When mmap() is called without address,
	 * address for 2MB page is allocated from 0x6f00 0000 0000 in order.
	 * This prevents fragmentation of VEMMR. */
	cached_index.idx_16GB = VEMMR_64MB_OFFSET / CHUNK_16GB;
	cached_index.idx_512MB = VEMMR_2MB_OFFSET / CHUNK_512MB;
	PSEUDO_DEBUG("cached_index.idx_16GB : %ld", cached_index.idx_16GB);
	PSEUDO_DEBUG("cached_index.idx_512MB : %ld", cached_index.idx_512MB);

	retval = 0;
hndl_return:
	PSEUDO_TRACE("returned");
	return retval;
}

/**
 * @brief Allocate fixed contiguous 512MB chunks from VEMMR.
 *
 * @param[in] address Base address of chunk
 * @param[in] chunk_num Number of required chunks
 *
 * @return Start address of chunks on success, -1 on failure and set errno.
 */
static uint64_t
allocate_fixed_contiguous_512MB_chunks(uint64_t address, int chunk_num)
{
	int64_t i, info_index, bit_16GB, bit_512MB, last_index;
	int count;
	int saved_errno = 0;
	uint64_t addr = (uint64_t)-1;

	if ((address < VEMMR_START) || (address >= VEMMR_BOTTOM)) {
		PSEUDO_ERROR("%s : Out of range address is specified",
								__func__);
		saved_errno = EINVAL;
		goto hndl_return;
	}
	i = (int64_t)(address - VEMMR_START) / CHUNK_512MB - 1;
	PSEUDO_DEBUG("%s : 0x%lx: start index : %ld",
						__func__, address, (i + 1));

	for (count = 0; count < chunk_num; count++) {
		i++;
		info_index = ((i * CHUNK_512MB) / CHUNK_16GB) / CHUNK_PER_INFO;
		bit_16GB = ((i * CHUNK_512MB) / CHUNK_16GB) % CHUNK_PER_INFO;
		bit_512MB = i % (sizeof(uint32_t) * 8);
		if (!vemmr_info[info_index].blocks_512MB[bit_16GB]) {
			 PSEUDO_DEBUG("Free contiguous 512MB chunks are not found at specified address 0x%lx", address);
			 saved_errno = ENOMEM;
			 goto hndl_return;
		} else if ((vemmr_info[info_index].blocks_512MB[bit_16GB]
					== (uint32_t)-1) &&
					!(vemmr_info[info_index].blocks_16GB &
					(1ULL << bit_16GB))) {
			PSEUDO_ERROR("inconsistency between blocks_16GB and blocks_512MB");
			saved_errno = ECANCELED;
			goto hndl_return;
		} else if (!(vemmr_info[info_index].blocks_512MB[bit_16GB]
							& (1 << bit_512MB))) {
			 PSEUDO_DEBUG("Free contiguous 512MB chunks are not found at specified address 0x%lx", address);
			 saved_errno = ENOMEM;
			 goto hndl_return;
		}
	}
	PSEUDO_DEBUG("%s : chunk_num: %d last index : %ld",
							__func__, chunk_num, i);
	last_index = i;
	for (count = 0; count < chunk_num; count++) {
		i = last_index - count;
		info_index = ((i * CHUNK_512MB) / CHUNK_16GB) / CHUNK_PER_INFO;
		bit_16GB = ((i * CHUNK_512MB) / CHUNK_16GB) % CHUNK_PER_INFO;
		bit_512MB = i % (sizeof(uint32_t) * 8);
		vemmr_info[info_index].blocks_16GB &= ~(1ULL << bit_16GB);
		vemmr_info[info_index].blocks_512MB[bit_16GB] &=
							~(1 << bit_512MB);
	}

	addr = VEMMR_START + i * CHUNK_512MB;
	PSEUDO_DEBUG("Start addres of allocated chunks is 0x%lx", addr);
hndl_return:
	PSEUDO_TRACE("returned");
	if (saved_errno)
		errno = saved_errno;
	return addr;
}

/**
 * @brief Allocate contiguous 512MB chunks from VEMMR.
 *
 * @param[in] chunk_num Number of required chunks
 * @param[in] start Chunk number at which last search ended.
 * @param[in] end Chunk number at which this search ends.
 * @param[in] update_index Flag to update cached_index.
 *
 * @return Start address of chunks on success, -1 on failure and set errno.
 */
static uint64_t
allocate_contiguous_512MB_chunks(
		int chunk_num, int64_t start, int64_t end, int update_index)
{
	int64_t i, info_index, bit_16GB, bit_512MB, tail;
	int count = 0;
	int saved_errno = 0;
	int tmp;
	uint64_t addr = (uint64_t)-1;

	i = start;
	PSEUDO_DEBUG("%s : search starts from %ld", __func__, i);
	do {
		if ((i >= end) || (i < 0)) {
			PSEUDO_DEBUG("No free contiguous 512MB chunks are found");
			saved_errno = ENOMEM;
			goto hndl_return;
		}
		info_index = ((i * CHUNK_512MB) / CHUNK_16GB) / CHUNK_PER_INFO;
		bit_16GB = ((i * CHUNK_512MB) / CHUNK_16GB) % CHUNK_PER_INFO;
		bit_512MB = i % (sizeof(uint32_t) * 8);
		if (!vemmr_info[info_index].blocks_512MB[bit_16GB]) {
			count = 0;
		} else if ((vemmr_info[info_index].blocks_512MB[bit_16GB]
					== (uint32_t)-1) &&
					!(vemmr_info[info_index].blocks_16GB &
					(1ULL << bit_16GB))) {
			PSEUDO_ERROR("inconsistency between blocks_16GB and blocks_512MB");
			count = 0;
		} else if (vemmr_info[info_index].blocks_512MB[bit_16GB]
							& (1 << bit_512MB)) {
			count++;
		} else
			count = 0;
		i++;
	} while (count != chunk_num);
	tail = i - 1;
	PSEUDO_DEBUG("%s : tail of free contiguous 512MB chunks is %ld",
								__func__, tail);

	if (update_index)
		cached_index.idx_512MB = tail;
	tmp = 0;
	do {
		i = tail - tmp;
		info_index = ((i * CHUNK_512MB) / CHUNK_16GB) / CHUNK_PER_INFO;
		bit_16GB = ((i * CHUNK_512MB) / CHUNK_16GB) % CHUNK_PER_INFO;
		bit_512MB = i % (sizeof(uint32_t) * 8);
		vemmr_info[info_index].blocks_16GB &= ~(1ULL << bit_16GB);
		vemmr_info[info_index].blocks_512MB[bit_16GB] &=
							~(1 << bit_512MB);
		tmp++;
	} while (tmp < chunk_num);
	PSEUDO_DEBUG("%s : head of free contiguous 512MB chunks is %ld",
								__func__, i);

	addr = VEMMR_START + i * CHUNK_512MB;
	PSEUDO_DEBUG("Start addres of allocated chunks is 0x%lx", addr);
hndl_return:
	PSEUDO_TRACE("returned");
	if (saved_errno)
		errno = saved_errno;
	return addr;
}

/**
 * @brief Allocate fixed contiguous 16GB chunks from VEMMR.
 *
 * @param[in] address Base address of chunk
 * @param[in] chunk_num Number of required chunks
 *
 * @return Start address of chunks on success, -1 on failure and set errno.
 */
static uint64_t
allocate_fixed_contiguous_16GB_chunks(uint64_t address, int chunk_num)
{
	int64_t i, bit, info_index, last_index;
	int count;
	int saved_errno = 0;
	uint64_t addr = (uint64_t)-1;

	if ((address < VEMMR_START) || (address >= VEMMR_BOTTOM)) {
		PSEUDO_ERROR("%s : Out of range address is specified",
								__func__);
		saved_errno = EINVAL;
		goto hndl_return;
	}
	i = (int64_t)(address - VEMMR_START) / CHUNK_16GB - 1;
	PSEUDO_DEBUG("%s : 0x%lx: start index : %ld",
						__func__, address, (i + 1));
	for (count = 0; count < chunk_num; count++) {
		i++;
		info_index = i / CHUNK_PER_INFO;
		bit = i % CHUNK_PER_INFO;
		if (!(vemmr_info[info_index].blocks_16GB & (1ULL << bit))) {
			PSEUDO_DEBUG("Free contiguous 16GB chunks are not found at specified address 0x%lx", address);
			saved_errno = ENOMEM;
			goto hndl_return;
		} else if (vemmr_info[info_index].blocks_512MB[bit] !=
								(uint32_t)-1) {
			PSEUDO_ERROR("inconsistency between blocks_16GB and blocks_512MB");
			saved_errno = ECANCELED;
			goto hndl_return;
		}
	}
	PSEUDO_DEBUG("%s : chunk_num: %d last index : %ld",
							__func__, chunk_num, i);
	last_index = i;
	for (count = 0; count < chunk_num; count++) {
		i = last_index - count;
		info_index = i / CHUNK_PER_INFO;
		bit = i % CHUNK_PER_INFO;
		vemmr_info[info_index].blocks_16GB &= ~(1ULL << bit);
		vemmr_info[info_index].blocks_512MB[bit] = 0;
	}

	addr = VEMMR_START + i * CHUNK_16GB;
	PSEUDO_DEBUG("Start addres of allocated chunks is 0x%lx", addr);
hndl_return:
	PSEUDO_TRACE("returned");
	if (saved_errno)
		errno = saved_errno;
	return addr;
}

/**
 * @brief Allocate contiguous 16GB chunks from VEMMR.
 *
 * @param[in] chunk_num Number of required chunks
 * @param[in] start Chunk number at which last search ended.
 * @param[in] end Chunk number at which this search ends.
 * @param[in] update_index Flag to update cached_index.
 *
 * @return Start address of chunks on success, -1 on failure and set errno.
 */
static uint64_t
allocate_contiguous_16GB_chunks(
	uint64_t chunk_num, int64_t start, int64_t end, int update_index)
{
	int64_t i, bit, info_index, tail;
	int count = 0;
	int saved_errno = 0;
	int tmp;
	uint64_t addr = (uint64_t)-1;

	PSEUDO_TRACE("invoked");

	i = start;
	PSEUDO_DEBUG("%s : search starts from %ld", __func__, i);
	do {
		if ((i >= end) || (i < 0)) {
			PSEUDO_DEBUG("No free contiguous 16GB chunks are found");
			saved_errno = ENOMEM;
			goto hndl_return;
		}
		info_index = i / CHUNK_PER_INFO;
		bit = i % CHUNK_PER_INFO;
		if (vemmr_info[info_index].blocks_16GB & (1ULL << bit)) {
			if (vemmr_info[info_index].blocks_512MB[bit] !=
								(uint32_t)-1) {
				PSEUDO_ERROR(
					"inconsistency between blocks_16GB and blocks_512MB");
				count = 0;
			} else
				count++;
		 } else
			count = 0;
		i++;
	} while (count != chunk_num);
	tail = i - 1;
	PSEUDO_DEBUG("%s : tail of free contiguous 16GB chunks is %ld",
								__func__, tail);

	if (update_index)
		cached_index.idx_16GB = tail;
	tmp = 0;
	do {
		i = tail - tmp;
		info_index = i / CHUNK_PER_INFO;
		bit = i % CHUNK_PER_INFO;
		vemmr_info[info_index].blocks_16GB &= ~(1ULL << bit);
		vemmr_info[info_index].blocks_512MB[bit] = 0;
		tmp++;
	} while (tmp < chunk_num);
	PSEUDO_DEBUG("%s : head of free contiguous 16GB chunks is %ld",
								__func__, i);

	addr = VEMMR_START + i * CHUNK_16GB;
	PSEUDO_DEBUG("Start addres of allocated chunks is 0x%lx", addr);
hndl_return:
	PSEUDO_TRACE("returned");
	if (saved_errno)
		errno = saved_errno;
	return addr;
}

/**
 * @brief Allocate chunks from VEMMR
 *
 * @param[in] address Base address of chunk, it should be aligned.
 * @param[in] chunk_num Number of required chunks
 * @param[in] flag flags specified at mmap().
 *
 * @remark Allocated chunks will be deallocated by free_chunk() or
 *         free_chunks().
 *
 * @return Start address of chunks on success, -1 on failure and set errno.
 */
uint64_t
allocate_chunk(uint64_t address, uint64_t chunk_num, uint64_t flag)
{
	uint64_t addr = (uint64_t)-1;
	int errno_save = errno;
	int update_index;
	int64_t start;

	PSEUDO_TRACE("invoked");

	pthread_mutex_lock(&vemmr_lock);

	if (!address) {
		assert(!(flag & MAP_ADDR_SPACE));
		assert(!(flag & MAP_ADDR_64GB_SPACE));
		update_index = 1;
		if (flag & MAP_64MB) {
			addr = allocate_contiguous_16GB_chunks(
					chunk_num, cached_index.idx_16GB,
					VEMMR_SIZE / CHUNK_16GB,
					update_index);
			if (addr == (uint64_t)-1)
				addr = allocate_contiguous_16GB_chunks(
					chunk_num,
					VEMMR_NONFIXED_OFFSET / CHUNK_16GB,
					VEMMR_SIZE / CHUNK_16GB,
					update_index);
		} else {
			addr = allocate_contiguous_512MB_chunks(
					chunk_num, cached_index.idx_512MB,
					VEMMR_SIZE / CHUNK_512MB,
					update_index);
			if (addr == (uint64_t)-1)
				addr = allocate_contiguous_512MB_chunks(
					chunk_num,
					VEMMR_NONFIXED_OFFSET / CHUNK_512MB,
					VEMMR_SIZE / CHUNK_512MB, 0);
		}
	} else if (flag & MAP_FIXED) {
		if (flag & MAP_64MB)
			addr = allocate_fixed_contiguous_16GB_chunks(
							address, chunk_num);
		else
			addr = allocate_fixed_contiguous_512MB_chunks(
							address, chunk_num);
	} else {
		assert(!(flag & MAP_ADDR_SPACE));
		assert(!(flag & MAP_ADDR_64GB_SPACE));
		update_index = 0;
		if (flag & MAP_64MB) {
			start = (address - VEMMR_START) / CHUNK_16GB;
			addr = allocate_contiguous_16GB_chunks(
						chunk_num, start,
						VEMMR_SIZE / CHUNK_16GB,
						update_index);
			if (addr == (uint64_t)-1)
				addr = allocate_contiguous_16GB_chunks(
					chunk_num,
					VEMMR_NONFIXED_OFFSET / CHUNK_16GB,
					VEMMR_SIZE / CHUNK_16GB,
					update_index);
		} else {
			start = (address - VEMMR_START) / CHUNK_512MB;
			addr = allocate_contiguous_512MB_chunks(
						chunk_num, start,
						VEMMR_SIZE / CHUNK_512MB,
						update_index);
			if (addr == (uint64_t)-1)
				addr = allocate_contiguous_512MB_chunks(
					chunk_num,
					VEMMR_NONFIXED_OFFSET / CHUNK_512MB,
					VEMMR_SIZE / CHUNK_512MB,
					update_index);
		}
	}
	if (addr == (uint64_t)-1)
		errno_save = errno;
	dump_vemmr_info();
	pthread_mutex_unlock(&vemmr_lock);

	PSEUDO_TRACE("returned");
	errno = errno_save;
	return addr;
}

/**
 * @brief Return unused chunk to VEMMR without lock.
 *
 * @param[in] type Type of unused chunk
 * @param[in] vemva_base Base address of unused chunk
 *
 * @return 0 on success, -errno on failure.
 */
static int
free_chunk_nolock(uint8_t type, void *vemva_base)
{
	int64_t i, bit, info_index, bit_512MB;
	int ret = 0;
	int pgsz;

	PSEUDO_TRACE("invoked");
	switch (type) {
	case ADDR_SPACE_2MB:
	case AS_WITHIN_64GB_2MB:
	case ANON_SPACE_2MB:
		pgsz = PAGE_SIZE_2MB;
		break;
	case ADDR_SPACE_64MB:
	case AS_WITHIN_64GB_64MB:
	case ANON_SPACE_64MB:
		pgsz = PAGE_SIZE_64MB;
		break;
	default:
		PSEUDO_ERROR("Invalid page size is detected while freeing chunk");
		ret = -EINVAL;
		goto hndl_return;
	}
	PSEUDO_DEBUG("pgsz : %d, Start addr : 0x%lx",
				pgsz / (1024 * 1024), (uint64_t)vemva_base);
	if (((uint64_t)vemva_base < VEMMR_START) ||
				((uint64_t)vemva_base >= VEMMR_BOTTOM)) {
		PSEUDO_ERROR("Invalid address is specified while freeing chunk");
		ret = -EINVAL;
		goto hndl_return;
	}
	if (pgsz == PAGE_SIZE_64MB) {
		i = (((uint64_t)vemva_base) - VEMMR_START) / CHUNK_16GB;
		info_index = i / CHUNK_PER_INFO;
		bit = i % CHUNK_PER_INFO;
		PSEUDO_DEBUG("i : %ld, info_index : %ld, bit : %ld",
							i, info_index, bit);
		if (vemmr_info[info_index].blocks_16GB & (1ULL << bit)) {
			PSEUDO_DEBUG("blocks_16GB has already been freed");
			PSEUDO_ERROR("This chunk has already been freed");
			ret = -EINVAL;
			goto hndl_return;
		} else if (vemmr_info[info_index].blocks_512MB[bit] != 0) {
			PSEUDO_DEBUG("blocks_512MB has already been freed");
			PSEUDO_ERROR("This chunk has already been freed");
			ret = -EINVAL;
			goto hndl_return;
		}
		vemmr_info[info_index].blocks_16GB |= (1ULL << bit);
		vemmr_info[info_index].blocks_512MB[bit] = (uint32_t)-1;
		if ((cached_index.idx_16GB > i) &&
					((VEMMR_64MB_OFFSET / CHUNK_16GB) <= i))
			cached_index.idx_16GB = i;
	} else {
		i = (((uint64_t)vemva_base) - VEMMR_START) / CHUNK_512MB;
		info_index = ((i * CHUNK_512MB) / CHUNK_16GB) / CHUNK_PER_INFO;
		bit = ((i * CHUNK_512MB) / CHUNK_16GB) % CHUNK_PER_INFO;
		bit_512MB = i % (sizeof(uint32_t) * 8);
		PSEUDO_DEBUG("i : %ld, info_index : %ld, bit : %ld, bit_512MB : %ld",
						i, info_index, bit, bit_512MB);
		if (vemmr_info[info_index].blocks_16GB & (1ULL << bit)) {
			PSEUDO_DEBUG("blocks_16GB has already been freed");
			PSEUDO_ERROR("This chunk has already been freed");
			ret = -EINVAL;
			goto hndl_return;
		} else if (vemmr_info[info_index].blocks_512MB[bit] &
							(1 << bit_512MB)) {
			PSEUDO_DEBUG("blocks_512MB has already been freed");
			PSEUDO_ERROR("This chunk has already been freed");
			ret = -EINVAL;
			goto hndl_return;
		}
		vemmr_info[info_index].blocks_512MB[bit] |= (1 << bit_512MB);
		if (vemmr_info[info_index].blocks_512MB[bit] == (uint32_t)-1)
			vemmr_info[info_index].blocks_16GB |= (1ULL << bit);
		if ((cached_index.idx_512MB > i) &&
				((VEMMR_2MB_OFFSET / CHUNK_512MB) <= i))
			cached_index.idx_512MB = i;
	}

hndl_return:
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief Return unused chunk to VEMMR without lock.
 *
 * @param[in] type Type of unused chunk
 * @param[in] vemva_base Base address of unused chunk
 *
 * @return 0 on success, -errno on failure.
 */
int
free_chunk(uint8_t type, void *vemva_base)
{
	int ret;

	PSEUDO_TRACE("invoked");
	pthread_mutex_lock(&vemmr_lock);
	ret = free_chunk_nolock(type, vemva_base);
	dump_vemmr_info();
	pthread_mutex_unlock(&vemmr_lock);
	PSEUDO_TRACE("returned");
	return ret;
}

/**
 * @brief Return unused chunks to VEMMR.
 *
 * @param[in] base_address Base address contiguous chunks
 * @param[in] size Total size of chunks
 * @param[in] flag Flags specified in allocation
 *
 * @return 0 on success, -errno on failure.
 */
int
free_chunks(uint64_t base_address, uint64_t size, uint64_t flag)
{
	uint8_t type;
	void *vemva_base;
	int count, i, ret;
	int retval = 0;
	uint64_t chunk_size;

	PSEUDO_TRACE("invoked");

	if (flag & MAP_64MB) {
		type = ANON_SPACE_64MB;
		chunk_size = CHUNK_16GB;
	} else {
		type = ANON_SPACE_2MB;
		chunk_size = CHUNK_512MB;
	}
	count = size / chunk_size;

	pthread_mutex_lock(&vemmr_lock);
	for (i = 0; i < count; i++) {
		vemva_base = (void *)(base_address + i * chunk_size);
		ret = free_chunk_nolock(type, vemva_base);
		if ((ret != 0) && (retval == 0))
			retval = ret;
	}
	dump_vemmr_info();
	pthread_mutex_unlock(&vemmr_lock);

	PSEUDO_TRACE("returned");
	return retval;
}

/**
 * @brief This function reserves RVR, calculates RDMA_OFFSET
 *        and send RDMA_OFFSET to VEOS.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] Start address of VEMMR, in other words, VEMVAR.
 *
 * @return 0 on success, Negative on failure.
 */
int
ve_init_rvr(veos_handle *handle, uint64_t vemmr_start)
{
	void *rvr = MAP_FAILED;
	uint64_t hint = RVR_LOWER_LIMIT;
	uint64_t scale = 0x100000000000ULL;
	int i;
	int retval;
	ProtobufCBinaryData data;

	PSEUDO_TRACE("invoked");

	for (i = 0; (hint + i * scale + RVR_SIZE) <= RVR_UPPER_LIMIT; i++) {
		rvr = mmap((void *)(hint + i * scale), RVR_SIZE,
			   PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (rvr == MAP_FAILED) {
			PSEUDO_DEBUG("Mapping RVR failed, Retry");
		} else if (((uint64_t)rvr < RVR_LOWER_LIMIT) ||
			(((uint64_t)rvr + RVR_SIZE) > RVR_UPPER_LIMIT)) {
			PSEUDO_DEBUG("Mapping is out of RVR, Retry");
			retval = munmap(rvr, RVR_SIZE);
			if (retval != 0) {
				PSEUDO_ERROR("Munmaping RVR failed %s",
							strerror(errno));
				goto hndl_return;
			}
			rvr = MAP_FAILED;
		} else {
			PSEUDO_DEBUG("RVR : %p", rvr);
			break;
		}
	}

	if (rvr == MAP_FAILED) {
		retval = -1;
		PSEUDO_ERROR("Mapping RVR failed");
		goto hndl_return;
	}

	rdma_offset_global = (uint64_t)rvr - vemmr_start;
	PSEUDO_DEBUG("RDMA_OFFSET : %ld", rdma_offset_global);

	data.len = sizeof(int64_t);
	data.data = (uint8_t *)&rdma_offset_global;
	PSEUDO_DEBUG("Request TELL_RDMAOFFSET from %ld", syscall(SYS_gettid));
	retval = ve_request_veos(handle, TELL_RDMAOFFSET, &data, NULL);
	if (retval != 0) {
		PSEUDO_ERROR("Failed to communicate VEOS about TELL_RDMAOFFSET %s",
							strerror(-retval));
		munmap(rvr, RVR_SIZE);
		goto hndl_return;
	}

hndl_return:
	PSEUDO_TRACE("returned");
	return retval;
}

/**
 * @brief This function gets RDMA_OFFSET, start address and size of VE memory
 *        virtual address region and return them to VE process.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] p_addr VEMVA of a variable which stores start address of VE memory
 *                   virtual address region.
 * @param[in] p_size VEMVA of a variable which stores size of VE memory virtual
 *                   address region.
 * @param[in] p_veoffset VEMVA of a variable which stores RDMA_OFFSET.
 *
 * @retval 0 on success.
 * @retval -EFAULT Arguments point invalid address.
 */
int
ve_sys_get_vemva_region(veos_handle *handle,
			uint64_t p_addr, uint64_t p_size, uint64_t p_veoffset)
{
	int retval = -EFAULT;
	int ret;
	uint64_t vemvar_start = VEMMR_START;
	size_t vemvar_size = VEMMR_SIZE;

	PSEUDO_TRACE("invoked");

	if (!p_addr || !p_size || !p_veoffset)
		goto hndl_return;

	PSEUDO_DEBUG("p_addr : 0x%lx, p_size : 0x%lx, p_veoffset : 0x%lx",
						p_addr, p_size, p_veoffset);

	ret = ve_send_data(handle, p_addr, sizeof(uint64_t), &vemvar_start);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to send start address of VEMVAR %s",
								strerror(-ret));
		goto hndl_return;
	}

	ret = ve_send_data(handle, p_size, sizeof(size_t), &vemvar_size);
	if (ret != 0) {
		PSEUDO_ERROR(
			"Failed to send size of VEMVAR %s", strerror(-ret));
		goto hndl_return;
	}

	ret = ve_send_data(handle, p_veoffset,  sizeof(int64_t),
							&rdma_offset_global);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to send RDMA_OFFSET %s", strerror(-ret));
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	PSEUDO_TRACE("returned");
	return retval;
}
