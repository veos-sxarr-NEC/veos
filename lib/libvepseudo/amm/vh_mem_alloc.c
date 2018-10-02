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
* @file  vh_mem_alloc.c
* @brief Memory allocation and release API's
*
* This file contains the routines that are used for allocating memory
* using mmap() with MAP_SHARED flag and then release the memory using
* munmap().
*
* @internal
* @author AMM
*/

#include "vh_mem_alloc.h"
#include "sys_common.h"
#include "vemva_mgmt.h"

#define MEM_ALLOC_HEADER	0x10
#define MEM_ALIGN_512		0x200
#define MAP_ADDR_OFFSET		0x8

/**
 * @brief Function will allocate the MAP_SHARED anonymous memory at
 * the pseudo process.
 *
 * @param[in] size Size of memory to allocate
 * @param[in] alignment whether 512 bytes aligned memory required or not
 *
 * @return Pointer to the memory on success and NULL on failure.
 */
void *vh_alloc_buf(size_t size, bool alignment)
{
	void *ptr = NULL;
	void *mapped_ptr = NULL;
	size_t aligned_size = 0;

	PSEUDO_TRACE("Entering");

	/* Storing allocation size in the header.
	 *
	 * If 512 bytes alignment is required then header will be of
	 * size 0x200 else header will be of size 0x10
	 */
	if (alignment)
		size += MEM_ALIGN_512;
	else
		size += MEM_ALLOC_HEADER;

	/* Align and rounup the size to 4KB boundary */
	aligned_size = ALIGN(size, PAGE_SIZE_4KB);

	mapped_ptr = (void *)mmap(NULL,
			aligned_size,
			PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_SHARED,
			-1,
			0);
	if (MAP_FAILED == mapped_ptr) {
		PSEUDO_ERROR("Internal memory allocation failed");
		PSEUDO_DEBUG("VH mmap() fails: %s", strerror(errno));
		goto hndl_return;
	}

	PSEUDO_DEBUG("Memory allocated : %p size: %ld", mapped_ptr, aligned_size);
	ptr = mapped_ptr;

	if (alignment)
		ptr += MEM_ALIGN_512;
	else
		ptr += MEM_ALLOC_HEADER;

	/* Save the allocation size and the mmap() address */
	*((int64_t *)(ptr - MAP_ADDR_OFFSET)) = (int64_t)mapped_ptr;
	*((size_t *)(ptr - MEM_ALLOC_HEADER)) = aligned_size;
hndl_return:
	PSEUDO_TRACE("Exiting");
	return ptr;
}

/**
 * @brief This interface will release the memory by reading the
 * information from header.
 *
 * @param[in] ptr Pointer to buffer to release the VH memory
 */
void vh_free_buf(void *ptr)
{
	size_t mem_size = 0;
	void *unmap_ptr = NULL;

	PSEUDO_TRACE("Entering");

	if (NULL == ptr)
		goto hndl_return;

	/* Fetch the size & address of where memory allocation done */
	unmap_ptr = (void *)*((int64_t *)(ptr - MAP_ADDR_OFFSET));
	mem_size = *((size_t *)(ptr - MEM_ALLOC_HEADER));

	PSEUDO_DEBUG("Releasing memory : %p size: %ld", unmap_ptr, mem_size);

	/* Unmap the mapped memory */
	if (munmap(unmap_ptr, mem_size)) {
		PSEUDO_ERROR("Internal memory release failed");
		PSEUDO_DEBUG("VH munmap() failed: %s", strerror(errno));
	}
hndl_return:
	PSEUDO_TRACE("Exiting");
	return;
}
