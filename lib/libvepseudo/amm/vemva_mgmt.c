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
 * @file vemva_mgmt.c
 * @brief Handles Virtual memory allocation for VE(VEMVA)
 *
 * @internal
 * @author AMM
 */

#include "vemva_mgmt.h"
#include "sys_common.h"
#include "sys_mm.h"

/**
 * @brief This function is used to obtain virtual memory for VE on VH side.
 *
 * @param[in] handle handle veos_handle
 * @param[out] addr Memory address for mapping
 * @param[in] size Memory length to map
 * @param[in] flag flag to control memory mapping
 * @param[in] prot Memory protection flag
 * @param[in] fd File descriptor for file backed mapping
 * @param[in] offset Offset to file
 *
 * @return Return virtual address on success, (void *)-1 on error and set
 * errno.
 */
void *ve_get_vemva(veos_handle *handle, uint64_t addr,
		uint64_t size, uint64_t flag, int prot, int fd,
		uint64_t offset)
{
	struct vemva_struct *vemva_tmp = NULL;
	void *vemva = (void *)-1;
	uint64_t count = 0;
	uint8_t reset_ve_page_info = 0;
	int64_t mmap_flag, ret = 0;

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("Invoked to allocate vemva with addr:%lx size:%lx flag:%lx\
			prot:%x fd:%x off:%lx",
			addr, size, flag, prot, fd, offset);

	/*update ve page info*/
	if (!ve_page_info.updated) {
		update_ve_page_info(&flag);
		reset_ve_page_info = 1;
	}
	pthread_mutex_lock(&vemva_header.vemva_lock);

	/*
	 * If addr is unaligned and map FIXED is
	 * Specified Return ERROR
	 */
	if (!IS_ALIGNED(addr, ve_page_info.page_size)) {
		if (flag & MAP_FIXED) {
			PSEUDO_DEBUG("Error (%s) vemva is unaligned with"
					" MAP_FIXED", strerror(EINVAL));
			errno = EINVAL;
			pthread_mutex_unlock(&vemva_header.vemva_lock);
			return MAP_FAILED;
		}

		addr = ALIGN(addr, ve_page_info.page_size) -
			ve_page_info.page_size;
		PSEUDO_DEBUG("Aligned address :%lu", addr);
	}

	/*
	 * Calculate the Number of pages Required
	 */
	count = size/ve_page_info.page_size;

	if (!addr && !(flag & MAP_FIXED)) {
		/*scan the list for free pages*/
		vemva = scan_vemva_dir_list(handle, count, flag);
		if (MAP_FAILED == vemva) {
			vemva_tmp = alloc_vemva_dir(handle, NULL,
					0, count, flag);
			if (NULL == vemva_tmp) {
				PSEUDO_DEBUG("Error (%s) while allocating "
						"directory", strerror(ENOMEM));
				pthread_mutex_unlock(&vemva_header.vemva_lock);
				errno = ENOMEM;
				goto err_exit;
			}
			/*
			 * Now the request can be fulfilled.
			 * As a new VEMVA is just allocated
			 */
			vemva = ve_get_free_vemva(handle, vemva_tmp,
					(uint64_t)NULL, count);
			if (MAP_FAILED == vemva) {
				PSEUDO_DEBUG("Error (%s) while allocating vemva \
						from directory",
						strerror(ENOMEM));
				pthread_mutex_unlock(&vemva_header.vemva_lock);
				errno = ENOMEM;
				goto err_exit;
			}
		}
	} else if (!addr && (flag & MAP_FIXED)) {
		PSEUDO_DEBUG("Error (%s)", strerror(ENOMEM));
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		errno = EPERM;
		goto err_exit;
	} else {
		vemva = avail_vemva(handle, addr, size, flag);
		if (MAP_FAILED == vemva) {
			PSEUDO_DEBUG("Error (%s) while availing vemva from "
					"existing directory", strerror(ENOMEM));
			pthread_mutex_unlock(&vemva_header.vemva_lock);
			errno = ENOMEM;
			goto err_exit;
		}
	}

	/* mmap the space with the permissions and flag given by the user
	 * Add MAP_NORESERVE if mmap is not file back or MAP_STACK as we are
	 * not accessing VH memory*/
	mmap_flag = (flag | MAP_FIXED) & (~(MAP_2MB | MAP_64MB | MAP_VESHM));
	if ((flag & MAP_ANON) && (!(flag & (MAP_VDSO | MAP_STACK))))
		mmap_flag |= MAP_NORESERVE;
	if (vemva != mmap(vemva, size, prot, mmap_flag, fd, offset)) {
		ret = errno;
		PSEUDO_DEBUG("Error (%s) while performing VH MMAP",
				strerror(errno));
		mark_vemva((uint64_t)vemva, size, MARK_UNUSED);
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		errno  = ret;
		goto err_exit;
	}

	if (flag & MAP_VESHM) {
		/*here we will set VESHM bitmap*/
		mark_vemva((uint64_t)vemva, size,
				MARK_USED | MARK_VESHM);
	}
	if (!(flag & MAP_ANON) && !(flag & MAP_PRIVATE)) {
		/*here we will set FILE bitmap*/
		mark_vemva((uint64_t)vemva, size,
				MARK_USED | MARK_FILE);
	}

	pthread_mutex_unlock(&vemva_header.vemva_lock);
	if (reset_ve_page_info)
		memset(&ve_page_info, '\0', sizeof(ve_page_info));

	PSEUDO_DEBUG("returned with : vemva %p", vemva);
	PSEUDO_TRACE("returned");
	return vemva;
err_exit:
	if (reset_ve_page_info)
		memset(&ve_page_info, '\0', sizeof(ve_page_info));
	return (void *)-1;
}

/**
 * @brief This function allocate the VEMVA memory.
 *
 *	if MAP_FIXED flag is passed by the user who calls
 *	mmap(). Also do unmap if requested VEMVA was already
 *	allocated to VE process.
 *
 * @param[in] handle Pointer to VEDL handle
 * @param[in] vemva_tmp Pointer to pseudo vemva list
 * @param[out] vaddr VEMVA to map
 * @param[in] entry Offset in the list where the inputed VEMVA lies
 * @param[in] count Number of 2MB virtual addreses required
 * @param[in] flag Additional map information.
 *
 * @return On Success,returns VEMVA address, (void *)-1 on failure and
 * set errno.
 */
void *ve_get_fixed_vemva(veos_handle *handle, struct vemva_struct *vemva_tmp,
		uint64_t vaddr, int64_t entry, int64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;

	PSEUDO_DEBUG("invoked");
	PSEUDO_DEBUG("invoked to get vemva %p", (void *)vaddr);

	if (check_bits(vemva_tmp, entry, count, MARK_UNUSED)) {
		mark_bits(vemva_tmp, entry, count, MARK_USED);
	} else {
		/*
		 * Check if we can expand the vemva if expanding is required
		 * then only go ahead with free vemva.
		 */
		entry = (vaddr & ve_page_info.chunk_mask) /
			ve_page_info.page_size;
		if ((entry+count) > ENTRIES_PER_DIR &&
				(vemva_tmp->consec_dir == 1)) {
			/*
			 * try expanding
			 */
			vemva_tmp = alloc_vemva_dir(handle, vemva_tmp, vaddr,
					count, flag | MAP_FIXED);
			if (NULL == vemva_tmp)
				goto err_exit;
		}
		if (free_vemva(handle, vemva_tmp, entry,
					count)) {
			PSEUDO_DEBUG("Error (%s) while getting free VEMVA",
					strerror(ENOMEM));
			errno = ENOMEM;
			goto err_exit;
		}
		mark_bits(vemva_tmp, entry, count, MARK_USED);
	}
	vemva = (void *)vaddr;

err_exit:
	PSEUDO_TRACE("returned");
	PSEUDO_DEBUG("returned with vemva: %p", vemva);
	return vemva;
}

/**
 * @brief This function allocate the VEMVA.
 *
 *	This function will allocate the VE memory
 *	if MAP_FIXED flag is not passed by the user who calls mmap().
 *
 * @param[in] vemva_tmp Pointer to pseudo vemva list
 * @param[out] vaddr VEMVA to map
 * @param[in] entry Offset in the list where the inputed VEMVA lies
 * @param[in] count Number of 2MB virtual addreses required
 * @param[in] flag Additional map information.
 *
 * @return On Success VEMVA, (void *)-1 on failure.
 */
void *ve_get_nearby_vemva(veos_handle *handle, struct vemva_struct *vemva_tmp,
		uint64_t vaddr, int64_t entry,
		int64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with to get vaddr: %p\n", (void *)vaddr);

	/*Check If VEMVA are available or not*/
	if (check_bits(vemva_tmp, entry, count, MARK_UNUSED)) {
		mark_bits(vemva_tmp, entry, count, MARK_USED);
		vemva = (void *)vaddr;
	} else {
		vemva = ve_get_free_vemva(handle, vemva_tmp, vaddr, count);
	}

	PSEUDO_DEBUG("returned with %p", vemva);
	PSEUDO_TRACE("returned");
	return vemva;
}

/**
 * @brief This function allocate the VE virtual address.
 *
 *	This function allocate the VE virtual address if address is
 *	given as a argument in mmap().
 *
 * @param[in] handle Pointer to VEDL handle
 * @param[mmap] vaddr VEMVA to map
 * @param[in] size Size of the memory to map
 * @param[in] flag Additional information for memory mapping
 *
 * @return On Success, return the request VEMVA, NULL on failure.
 */
void *avail_vemva(veos_handle *handle, uint64_t vaddr,
		uint64_t size, uint64_t flag)
{
	struct vemva_struct *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;
	void *vemva = (void *)-1;
	void *vemva_base = NULL;
	int64_t entry = 0;
	uint64_t count = 0;
	uint8_t required_type = 0;
	uint64_t required_dir_count = 0;

	count = size / ve_page_info.page_size;

	vemva_base = (void *)((uint64_t)vaddr &
			(~ve_page_info.chunk_mask));
	entry = ((uint64_t)vaddr &
			ve_page_info.chunk_mask)/
		ve_page_info.page_size;

	required_dir_count = (entry+count)/ENTRIES_PER_DIR;
	if ((entry+count) % ENTRIES_PER_DIR)
		required_dir_count++;

	if (flag & MAP_ADDR_SPACE)
		required_type = (uint8_t)((flag & MAP_64MB) ?
			ADDR_SPACE_64MB : ADDR_SPACE_2MB);
	else
		required_type = (uint8_t)((flag & MAP_64MB) ?
			ANON_SPACE_64MB : ANON_SPACE_2MB);

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with addr: %p Size: %lx flags: %lx req_type %d",
			(void *)vaddr, size, flag, required_type);
	/*Fetch the bitmap from vemva_start*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct vemva_struct, list);
		PSEUDO_DEBUG("fetched vemva_base = %p Type %d",
				vemva_tmp->vemva_base, vemva_tmp->type);

		if (vemva_tmp->type != required_type)
			continue;

		if (vemva_base == vemva_tmp->vemva_base &&
				(flag & MAP_FIXED)) {
			vemva = ve_get_fixed_vemva(handle, vemva_tmp,
					vaddr, entry, count, flag);
			break;
		} else if (vemva_base == vemva_tmp->vemva_base &&
				!(flag & MAP_FIXED)) {
			vemva = ve_get_nearby_vemva(handle, vemva_tmp,
					vaddr, entry, count, flag);
			break;
		}
	}

	/*
	 * Now the request could not be completed using existing list
	 */
	if ((void *)-1 == vemva) {
		vemva_tmp = alloc_vemva_dir(handle, NULL, vaddr, count, flag);
		if (NULL == vemva_tmp) {
			if (!(flag & MAP_FIXED))
				vemva = scan_vemva_dir_list(handle, count, flag);
			goto err_exit;
		}
		/*Check If the requested block of VEMVA lies in this chunk*/
		if (vemva_tmp->vemva_base == vemva_base) {
			mark_bits(vemva_tmp, entry, count,
					MARK_USED);
			vemva = (void *)vaddr;
		} else if (flag & MAP_FIXED) {
			if (dealloc_vemva_dir(vemva_tmp))
				PSEUDO_DEBUG("error while deallocating vemva directory.");
			goto err_exit;
		} else {
			/*Serve the request from this chunk*/
			vemva = ve_get_free_vemva(handle, vemva_tmp, vaddr,
						count);
		}
	}

err_exit:
	PSEUDO_DEBUG("returned with vemva: %p", vemva);
	PSEUDO_TRACE("returned");
	return vemva;
}

/**
 * @brief This function is used to find free VEMVA.
 *
 *	It will Calculate virtual address according to free bitmap Index and
 *	VEMVA Base,clear the corresponding bits(That will represent used
 *	VEMVA).
 *
 * @param[in] vemva_tmp Pointer to pseudo vemva list
 * @param[in] count Number of 2MB virtual address
 * @param[in] flag Additional information contained in flag.
 *
 * @return On Success return the available VEMVA, (void *)-1
 * on failure.
 */
void *ve_get_free_vemva(veos_handle *handle, struct vemva_struct *
		vemva_dir, uint64_t vaddr, int64_t count)
{
	void *vemva = NULL;
	int64_t entry = 0;
	int64_t contigious_free = 0;
	int64_t word = 0, index = 0;
	uint8_t word_index = 0, bit_index = 0;
	uint8_t entry_index = 0;
	int64_t word_count = 0;
	struct vemva_struct *vemva_tmp = NULL;

	vemva_tmp = vemva_dir;

	entry_index = (vaddr & ve_page_info.chunk_mask)/
		ve_page_info.page_size;
	word_index = entry_index/BITS_PER_WORD;
	bit_index = entry_index%BITS_PER_WORD;

	word_count = (WORDS_PER_BITMAP * vemva_tmp->consec_dir);

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with word count = %ld", word_count);

	for (index = word_index; index < word_count; index++, word_index++) {
		if (word_index >= WORDS_PER_BITMAP) {
			entry_index = word_index = 0;
			vemva_tmp = list_next_entry(vemva_tmp,
					list);
		}
		for (bit_index = entry_index;
				bit_index < BITS_PER_WORD;
				bit_index++) {
			if (vemva_tmp->bitmap[word_index] &
					((uint64_t)1<<bit_index)) {
				contigious_free++;
				/*
				 * Maintain vemva_dir from which free
				 * vemva has been found first
				 */
				if (1 == contigious_free) {
					vemva_dir = vemva_tmp;
					entry = bit_index;
					word = word_index;
				}
				if (contigious_free == count)
					goto out;
			} else
				contigious_free = 0;
		}
		entry_index = 0;
	}

	if (contigious_free) {
		/*Check if dir is expandable or not*/
		PSEUDO_DEBUG("Trying to expand vemva");
		vemva_dir = alloc_vemva_dir(handle, vemva_dir,
				0, (count-contigious_free),
				MAP_FIXED);
		if (!(NULL == vemva_dir)) {
			/*Request can be fulfilled*/
			goto out;
		}
	}

	PSEUDO_DEBUG("returned with failure");
	return (void *)-1;
out:
	mark_bits(vemva_dir, ((word*BITS_PER_WORD) + entry),
			count, MARK_USED);
	/*
	 * Calculate virtual address according to free
	 * Index and VEMVA Base
	 */
	vemva = vemva_dir->vemva_base + (ve_page_info.page_size *
			((word*BITS_PER_WORD) + entry));

	PSEUDO_DEBUG("returned with vemva: %p", vemva);
	PSEUDO_TRACE("returned");
	return vemva;
}

/**
 * @brief This interface is used to de-allocate VEMVA.
 *
 * @param[in] vemva_addr Virtual VE address to be de allocated.
 * @param[in] size Size to de-allocate VE memory.
 *
 * @return Returns 0 on succes, negative of errno on failure.
 */
int ve_free_vemva(void *vemva_addr, size_t size)
{
	ret_t ret = 0;
	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret =  __ve_free_vemva(vemva_addr, size, true);
	pthread_mutex_unlock(&vemva_header.vemva_lock);
	return ret;
}

/**
 * @brief This function is used to de allocate virtual memory for VE.
 *
 * @param[in] vemva_addr Virtual VE address to be de allocated.
 * @param[in] size Size to de-allocate VE memory.
 * @param[in] del_dir Specify directory to deleted or not.
 *
 * @return return 0 on success, -1 on failure and set errno.
 */
int __ve_free_vemva(void *vemva_addr, size_t size, bool del_dir)
{
	void *vemva_base = NULL;
	int64_t entry, ret = 0;
	ssize_t tmp_size = 0;
	uint64_t addr = 0;
	size_t page_size = 0;
	size_t chunk_size = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_tmp = NULL;
	struct vemva_struct *vemva_del = NULL;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva_addr %p size %lx",
			vemva_addr, size);

	tmp_size = size;
	addr = (uint64_t)vemva_addr;
	page_size = 0;

	while (0 < tmp_size) {
		/*update ve page info*/
		addr += page_size;
		page_size = __get_page_size(addr);
		if (0 == page_size) {
			PSEUDO_DEBUG("Page Size not recognised");
			page_size = PAGE_SIZE_2MB;
			tmp_size -= page_size;
			continue;
		}

		chunk_size = page_size * ENTRIES_PER_DIR;
		/*Calculate the VEMVA Base Address by Masking LSBs*/
		vemva_base = (void *)(addr & (~(chunk_size - 1)));
		/*Calculate entry using addr*/
		entry = (addr & (chunk_size - 1))/page_size;

		/*Scan VEMVA list for the matching vemva_base*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct vemva_struct, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}

		ret = check_vemva_mapped((void *)addr, page_size, MARK_USED);
		if (0 < ret) {
			ret = 0;
			/*
			 * Do VHOS mmap on the address space to free
			 * with PROT_NONE and MAP_ANON | MAP_FIXED
			 */
			if (addr != (uint64_t)mmap((void *)addr, page_size,
						PROT_NONE,
						MAP_PRIVATE|MAP_ANON|MAP_FIXED,
						-1, 0)) {
				ret = errno;
				PSEUDO_DEBUG("Error (%s) while performing \
						mmap with With \
						MAP_FIXED", strerror(errno));
				errno = ret;
				goto err_exit;
			}

			/*
			 * Set the corresponding bits in
			 * bitmap to make it available
			 */

			mark_bits(vemva_del, entry, 1, MARK_UNUSED);
			/*
			 * Set the corresponding bits in veshm bitmap
			 */
			mark_bits(vemva_del, entry, 1,
					MARK_UNUSED | MARK_VESHM);
			/* Set the corresponding bits in file bitmap */
			mark_bits(vemva_del, entry, 1,
					MARK_UNUSED | MARK_FILE);

			/*
			 * Check if the whole vemva_dir is unused
			 * del dir if yes
			 */
			if ((vemva_del->used_count == 0) && del_dir) {
				if (dealloc_vemva_dir(vemva_del)) {
					PSEUDO_DEBUG("dealloc_vemva_dir \
							failed.");
					goto err_exit;
				}
			}
		}
		tmp_size -= page_size;
	}

	PSEUDO_DEBUG("returned with %ld", ret);
	PSEUDO_TRACE("returned");
	return ret;
err_exit:
	return -1;
}

/**
 * @brief This function release the already allocated VEMVA to VE process.
 *
 * @param[in] handle Pointer to VEDL handle
 * @param[in] vemva_tmp Pointer to pseudo_vemva list
 * @param[in] entry Offset in the list
 * @param[in] count Number of 2MB virtual address to release
 *
 * @return On Success returns 0, -1 on failure.
 */
int free_vemva(veos_handle *handle, struct vemva_struct *vemva_tmp,
		int64_t entry, int64_t count)
{
	int64_t word = 0, bit = 0;
	int64_t ent = 0;
	int64_t ret = 0;
	uint64_t addr = 0;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva_tmp %p \
			entry %ld count %ld",
			vemva_tmp, entry, count);

	for (ent = 0; ent < count; ent++) {
		word = entry / BITS_PER_WORD;
		bit = entry % BITS_PER_WORD;
		if (word >= WORDS_PER_BITMAP) {
			if (1 >= vemva_tmp->consec_dir)
				goto err_out;
			entry = bit = word = 0;
			vemva_tmp = list_next_entry(vemva_tmp, list);
		}

		if (!(vemva_tmp->bitmap[word] & ((uint64_t)1<<bit))) {
			addr = (uint64_t)(vemva_tmp->vemva_base +
					(entry * ve_page_info.page_size));
			/*
			 * VEMVA Locking has to be enhanced
			 * For Now We will Release the lock here and
			 * after __ve_munmap we will get it back
			 */
			ret = __ve_munmap(handle, addr,
					ve_page_info.page_size, false);
			if (0 > ret) {
				PSEUDO_DEBUG("unable to UNMAP memory region");
			}
		}
		entry++;
	}
	PSEUDO_DEBUG("returned with success");
	PSEUDO_TRACE("returned");
	return 0;
err_out:
	PSEUDO_DEBUG("returned Failure");
	return -1;
}

/**
 * @brief This function sets(Marks as available) the bitmap
 * in pseudo vemva list corresponding to VEMVA given till the size.
 *
 * @param[out] vemva VEMVA whose bits to set
 * @param[in] size Size of the request
 * @param[in] flag Information about how the bits has to be
 * marked and which bitmap has to be marked.
 *
 * MARK_USED: Bits has to be marked used.
 * MARK_UNUSED: Bits has to be marked unused.
 * MARK_VESHM:  veshm bitmap has to be marked used
 * or unused depending upon other flag.
 *
 * @return On success return 0 and -1 on failure.
 */
int mark_vemva(uint64_t vemva, uint64_t size, int flag)
{
	int64_t entry = 0;
	int64_t count = 0;
	uint64_t vemva_base = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_tmp = NULL;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva %lx size %lx",
			vemva, size);
	vemva_base = (vemva & (~(ve_page_info.chunk_mask)));
	count = size / ve_page_info.page_size;

	/* Calculate entry using vemva */
	entry = (vemva & (ve_page_info.chunk_mask))/
		ve_page_info.page_size;

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct vemva_struct, list);
		if ((uint64_t)vemva_tmp->vemva_base == vemva_base)
			goto mark_bits;
	}

	PSEUDO_DEBUG("VEMVA not found in existing list");
	return -1;
mark_bits:
	mark_bits(vemva_tmp, entry, count, flag);
	PSEUDO_DEBUG("returned with vemva marked");
	PSEUDO_TRACE("returned");
	return 0;
}

/**
 * @brief This function marks the bits as unused in the
 * pseudo vemva bitmap at an entry till the count given.
 *
 * @param[out] vemva_dir Pseudo VEMVA directory.
 * @param[in] entry Position from which bits are set
 * @param[in] count Number of bits to set
 * @param[in] flag Information about how the bits has to be
 * marked and which bitmap has to be marked.
 *
 * MARK_USED: Bits has to be marked used.
 * MARK_UNUSED: Bits has to be marked unused.
 * MARK_VESHM: veshm bitmap has to be  marked used
 * or unused depending upon other flag.
 */
void mark_bits(struct vemva_struct *vemva_dir,
		int64_t entry, int64_t count, uint8_t flag)
{
	int64_t word = 0, bit = 0;
	int ent = 0;
	uint64_t *bitmap = NULL;

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;
	if (flag & MARK_FILE)
		bitmap = vemva_dir->file_bitmap;
	else
		bitmap = (flag & MARK_VESHM) ? vemva_dir->veshm_bitmap :
			vemva_dir->bitmap;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with count %ld func", count);

	for (ent = 0; ent < count; ent++) {
		if (flag & MARK_USED) {
			bitmap[word] = bitmap[word] &
				(~((uint64_t)1 << bit++));
			if (!(flag & MARK_VESHM) && !(flag & MARK_FILE))
				vemva_dir->used_count++;
		} else if (flag & MARK_UNUSED) {
			bitmap[word] = bitmap[word] |
				((uint64_t)1 << bit++);
			if (!(flag & MARK_VESHM) && !(flag & MARK_FILE))
				vemva_dir->used_count--;
		}
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
		if (word >= WORDS_PER_BITMAP) {
			if (1 >= vemva_dir->consec_dir)
				return;
			bit = word = 0;
			vemva_dir = list_next_entry(vemva_dir, list);
			if (flag & MARK_FILE)
				bitmap = vemva_dir->file_bitmap;
			else
				bitmap = (flag & MARK_VESHM) ?
					vemva_dir->veshm_bitmap :
					vemva_dir->bitmap;
		}
	}

	PSEUDO_TRACE("returned");
}

/**
 * @brief This functions check that request bits
 * are already used or not.
 *
 * @param[in] vemva_dir Pseudo VEMVA directory
 * @param[in] entry Offset in the list
 * @param[in] count Number of 2MB virtual address
 * @param[in] flag Information about which check has to
 * be made over which bitmap.
 *
 * MARK_USED: Check if the bits are marked used.
 * MARK_UNUSED: Check if the bits are marked unused.
 * MARK_VESHM: Check if veshm bitmap is marked used
 * or unused depending upon other flag.
 * MARK_FILE : check if entry is file backed or not.
 *
 * @return It returns 1 if the bits are marked as specified in flag.
 * else it returns 0.
 */
int check_bits(struct vemva_struct *vemva_dir,
		int64_t entry, int64_t count, uint8_t flag)
{
	int64_t word = 0, bit = 0;
	uint64_t *bitmap = NULL;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with count %ld func", count);

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;
	if (flag & MARK_FILE)
		bitmap = vemva_dir->file_bitmap;
	else
		bitmap = (flag & MARK_VESHM) ? vemva_dir->veshm_bitmap :
			vemva_dir->bitmap;

	while (count) {
		if ((flag & MARK_USED) && (bitmap[word] &
					((uint64_t)1 << bit))) {
			goto err_out;
		} else if ((flag & MARK_UNUSED) && (!(bitmap[word] &
					((uint64_t)1 << bit)))) {
			goto err_out;
		}

		if (!(--count))
			break;

		bit++;

		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}

		if (word >= WORDS_PER_BITMAP) {
			if (1 >= vemva_dir->consec_dir)
				goto err_out;
			word = 0;
			bit = 0;
			vemva_dir = list_next_entry(vemva_dir, list);
			if (flag & MARK_FILE)
				bitmap = vemva_dir->file_bitmap;
			else
				bitmap = (flag & MARK_VESHM) ?
					vemva_dir->veshm_bitmap :
					vemva_dir->bitmap;
		}
	}
	PSEUDO_DEBUG("returned with success");
	PSEUDO_TRACE("returned");
	return 1;
err_out:
	PSEUDO_DEBUG("returned with failure");
	PSEUDO_TRACE("returned");
	return 0;
}

/**
 * @brief This function scans all the already created VEMVA
 * list to get the available VEMVA's multiple of count of size 2MB.
 *
 * @param[in] count Multiple of 2MB Virtual Address required.
 * @param[in] flag Additional scan information contained in flag.
 *
 * @return On Success, return the VEMVA and on failure return (void *)-1
 */
void *scan_vemva_dir_list(veos_handle *handle, uint64_t count, uint64_t flag)
{
	void *vemva = (void *)-1;
	uint8_t required_type = 0;
	struct vemva_struct *vemva_tmp = NULL;
	struct list_head *temp_list_head = NULL;

	if (flag & MAP_ADDR_SPACE)
		required_type = (uint8_t)((flag & MAP_64MB) ?
			ADDR_SPACE_64MB : ADDR_SPACE_2MB);
	else
		required_type = (uint8_t)((flag & MAP_64MB) ?
			ANON_SPACE_64MB : ANON_SPACE_2MB);

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with count %ld", count);
	/*
	 * Scan the entire pseudo_vemva list to get the available
	 * VEMVA.
	 */
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct vemva_struct, list);

		if (vemva_tmp->type != required_type)
			continue;

		vemva = ve_get_free_vemva(handle, vemva_tmp, 0, count);
		if (vemva == (void *)-1)
			continue;
		else
			break;
	}

	if (vemva != (void *)-1)
		PSEUDO_DEBUG("returned with vemva %p\n", vemva);
	else
		PSEUDO_DEBUG("returned with vemva %p\n", vemva);

	PSEUDO_TRACE("returned");
	return vemva;
}


/**
 * @brief This Function Initialize vemva_header.
 *
 * @return Return 0 on Success -1 on failure.
 */
int init_vemva_header(void)
{
	PSEUDO_TRACE("invoked");
	/*init VEMVA lock*/
	if (0 != pthread_mutex_init(&vemva_header.vemva_lock, NULL)) {
		PSEUDO_DEBUG("Init vemva_lock failed");
		return -1;
	}

	PSEUDO_DEBUG("Return: Success");
	PSEUDO_TRACE("returned");
	return 0;
}

/**
 * @brief This function verify if the virtual address
 * has been mapped or not.
 *
 * @param[in] vemva_addr Virtual address to verify
 * @param[in] size size to verify
 * @param[in] flag Flags to chack
 *
 * @return Return 1 on success, 0 on failure.
 */
int vemva_mapped(void *vemva_addr, size_t size, uint8_t flag)
{
	void *vemva_base = NULL;
	int64_t entry = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_tmp = NULL;
	struct vemva_struct *vemva_del = NULL;

	int64_t count = 0;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva_addr %p size %lx",
			vemva_addr, size);

	count = size/ve_page_info.page_size;
	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vemva_addr &
			(~(ve_page_info.chunk_mask)));
	/*Calculate entry using vemva_addr*/
	entry = ((uint64_t)vemva_addr &
			(ve_page_info.chunk_mask))/ve_page_info.page_size;

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct vemva_struct, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}
		if (vemva_del == NULL) {
			PSEUDO_DEBUG("vemva %p not allocated",
					vemva_addr);
			return 0;
		}

		/*Check Bitmap If the VEMVA's were allocated or not*/
		if (check_bits(vemva_del, entry, count, flag)) {
			PSEUDO_DEBUG("vemva %p with size %lx allocated",
					vemva_addr, size);
			return 1;
		}

		PSEUDO_DEBUG("vemva %p with size %lx not allocated",
				vemva_addr, size);
		return 0;
	}

	PSEUDO_DEBUG("vemva %p with size %lx is invalid",
			vemva_addr, size);
	PSEUDO_TRACE("returned");
	return 0;
}

/**
 * @brief This function will allocate a VHVA chunk
 * which will be 512 GB  or 16 GB aligned as well.
 *
 * @return Will return base address of the chunk
 * on success and (void *)-1 on failure and set errno.
 */
void *get_aligned_chunk(uint64_t vaddr_req, uint8_t required_chunks,
		uint64_t flag)
{
	int64_t retval = 0;
	uint64_t vaddr = 0;
	uint64_t chunk_size = 0;
	int vh_page_size = 0;
	uint64_t size_align = 0, size_unmap = 0;
	uint64_t vaddr_unaligned = 0, vaddr_aligned = 0;
	uint64_t lflag = 0;

	chunk_size = ve_page_info.chunk_size * required_chunks;

	lflag = MAP_PRIVATE | MAP_ANON;
	lflag |= (flag & MAP_ADDR_SPACE) ? MAP_FIXED : 0;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with flag 0x%lx lflag 0x%lx",
			flag, lflag);

	vaddr = (uint64_t)mmap((void *)vaddr_req, chunk_size, PROT_NONE,
			lflag, -1, 0);
	if (MAP_FAILED == (void *)vaddr) {
		retval = errno;
		PSEUDO_DEBUG("Error (%s) while performing VH mmap",
				strerror(errno));
		errno = retval;
		return MAP_FAILED;
	}

	PSEUDO_DEBUG("vaddr_req %p : vaddr %p : ve_page_info.chunk_size 0x%lx",
		(void *)vaddr_req, (void *)vaddr, ve_page_info.chunk_size);

	if (!IS_ALIGNED(vaddr, ve_page_info.chunk_size)) {
		retval = munmap((void *)vaddr, chunk_size);
		if (-1 == retval) {
			retval = errno;
			PSEUDO_DEBUG("Error (%s) while performing VH munmap",
					strerror(errno));
			errno = retval;
			return MAP_FAILED;
		}
	} else {
		PSEUDO_DEBUG("addr already aligned: 0x%lx",
				vaddr);
		return (void *)vaddr;
	}

	/* New size calculation */
	vh_page_size = getpagesize();
	size_align = chunk_size + chunk_size - vh_page_size;

	/* mmap with new size */
	vaddr_unaligned = (uint64_t)mmap((void *)vaddr, size_align,
			PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (MAP_FAILED == (void *)vaddr_unaligned) {
		retval = errno;
		PSEUDO_DEBUG("Error (%s) while performing VH mmap",
				strerror(errno));
		errno = retval;
		return (void *)vaddr_unaligned;
	}

	/* Align the address to 512MB page boundary  */
	vaddr_aligned = ALIGN(vaddr_unaligned, chunk_size);
	/* Release additional mapped area */
	size_unmap = (vaddr_aligned - vaddr_unaligned);
	if (size_unmap > 0) {
		retval = munmap((void *)vaddr_unaligned, size_unmap);
		if (-1 == retval) {
			retval = errno;
			PSEUDO_DEBUG("Error (%s) while performing VH mmap",
					strerror(errno));
			PSEUDO_DEBUG("ArgsDump,arg1: %p arg2: %ld",
					(void *)(vaddr_unaligned), size_unmap);
			errno = retval;
			retval = -1;
			return (void *)retval;
		}
	}
	size_unmap = (vaddr_unaligned + chunk_size +
			chunk_size - vh_page_size) -
		(vaddr_aligned + chunk_size);
	/* Release additional mapped area */
	if (size_unmap > 0) {
		retval = munmap((void *)(vaddr_aligned + chunk_size),
				size_unmap);
		if (-1 == retval) {
			retval = errno;
			PSEUDO_DEBUG("Error (%s) while performing VH munmap",
					strerror(errno));
			PSEUDO_DEBUG("ArgsDump,arg1: %p arg2: %ld",
					(void *)(vaddr_aligned+chunk_size),
					size_unmap);
			errno = retval;
			retval = -1;
			return (void *)retval;
		}
	}

	PSEUDO_DEBUG("returned with 0x%lx", vaddr_aligned);
	PSEUDO_TRACE("returned");
	return (void *)vaddr_aligned;

}

/**
 * @brief get the page_size of given virtual address.
 *
 * @param[in] vaddr vemva address to get page size
 *
 * @return Returns 0 on success, -1 on failure.
 */
int get_page_size(vemva_t vaddr)
{
	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vaddr %p", (void *)vaddr);

	memset(&ve_page_info, '\0', sizeof(ve_page_info));

	ve_page_info.page_size = __get_page_size(vaddr);
	if (!ve_page_info.page_size)
		return -1;

	ve_page_info.page_mask = ve_page_info.page_size - 1;
	ve_page_info.chunk_size = ve_page_info.page_size *
		ENTRIES_PER_DIR;
	ve_page_info.chunk_mask = ve_page_info.chunk_size - 1;
	ve_page_info.updated = 1;

	PSEUDO_DEBUG("returned with Success");
	PSEUDO_TRACE("returned");
	return 0;
}

/**
 * @brief get the page_size of given virtual address.
 *
 * @param[in] vaddr vemva address to get page size
 *
 * @return Return page_size(2MB/64MB) on success, 0 on failure.
 */
uint64_t __get_page_size(vemva_t vaddr)
{
	void *vemva_base = NULL;
	void *vemva_base_h = NULL;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_tmp = NULL;
	struct vemva_struct *vemva_req = NULL;
	uint64_t page_size = 0;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vaddr %p", (void *)vaddr);

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vaddr &
			(~(CHUNK_512MB - 1)));
	vemva_base_h = (void *)((uint64_t)vaddr &
			(~(CHUNK_16GB - 1)));

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct vemva_struct, list);
			if ((vemva_tmp->vemva_base == vemva_base) ||
					(vemva_tmp->vemva_base == vemva_base_h)) {
				vemva_req = vemva_tmp;
				break;
			}
		}
		if (vemva_req == NULL) {
			PSEUDO_DEBUG("vaddr %lx not found in allocated DIR",
					vaddr);
			return 0;
		}

		if (vemva_req->type == ANON_SPACE_2MB) {
			PSEUDO_DEBUG("vaddr %lx lies in ANON_SPACE_2MB",
					vaddr);
			page_size = PAGE_SIZE_2MB;
		} else if (vemva_req->type == ANON_SPACE_64MB) {
			PSEUDO_DEBUG("vaddr %lx lies in ANON_SPACE_64MB",
					vaddr);
			page_size = PAGE_SIZE_64MB;
		} else if (vemva_req->type == ADDR_SPACE_2MB) {
			PSEUDO_DEBUG("vaddr %lx lies in ADDR_SPACE_2MB",
					vaddr);
			page_size = PAGE_SIZE_2MB;
		} else if (vemva_req->type == ADDR_SPACE_64MB) {
			PSEUDO_DEBUG("vaddr %lx lies in ADDR_SPACE_64MB",
					vaddr);
			page_size = PAGE_SIZE_64MB;
		} else {
			PSEUDO_DEBUG("vaddr %lx type not recognised",
					vaddr);
			PSEUDO_DEBUG("Return: Failure");
			return 0;
		}

	}

	PSEUDO_DEBUG("returned with %ld", page_size);
	PSEUDO_TRACE("returned");
	return page_size;
}

/**
 * @brief This function creates new VEMVA Chunks.
 *
 * @param[in] vemva_dir is the directory to which we need
 * other consective directories.
 * @param[in] vaddr Required virtual address in chunk.
 * @param[in] count Number of pages required.
 * @param[in] flag Additional information for required VEMVA.
 *
 * @return On Success, return pointer to struct vemva_struct and
 * NULL in case of failure.
 */
struct vemva_struct *alloc_vemva_dir(veos_handle *handle, struct vemva_struct *vemva_dir,
		uint64_t vaddr, uint16_t count, int64_t flag)
{
	uint64_t required_base = 0;
	uint64_t retval = 0;
	uint8_t req_dir_count = 0;
	void *vemva_base = NULL;
	struct vemva_struct *vemva_tmp = NULL;
	struct vemva_struct *vemva_ret = NULL;

	PSEUDO_TRACE("Invoked");
	PSEUDO_DEBUG("Invoked with flag 0x%lx, count %d", flag, count);

	req_dir_count = count / ENTRIES_PER_DIR;
	if (count % ENTRIES_PER_DIR)
		req_dir_count++;

	if (vaddr && !vemva_dir) {
		required_base = (vaddr & (~ve_page_info.chunk_mask));
		PSEUDO_DEBUG("********Required Base = %lx",
				required_base);
	} else if (vemva_dir) {
		required_base = (uint64_t)vemva_dir->vemva_base +
			ve_page_info.chunk_size;
		vemva_ret = vemva_dir;
		PSEUDO_DEBUG("---------Required Base = %lx",
				required_base);
	} else {
		required_base = 0;
	}

	/*
	 * Depending upon MAX_VEMVA_LIST if new pseudo_vemva
	 * list can be allocated or not.
	 */
	if ((vemva_header.vemva_count + req_dir_count)
			> MAX_VEMVA_LIST) {
		PSEUDO_DEBUG("(vemva_header.vemva_count = %ld "
			"req_dir_count = %d", vemva_header.vemva_count
			, req_dir_count);
		PSEUDO_DEBUG("Can not allocate more VEMVA.");
		vemva_ret = NULL;
		goto err_exit;
	}

	vemva_base = get_aligned_chunk(required_base, req_dir_count, flag);
	if (NULL == vemva_base) {
		PSEUDO_DEBUG("Can't get 512Mb Chunk.");
		vemva_ret = NULL;
		goto err_exit;
	}

	/*
	 * Check if the expansion is possible
	 */
	if (required_base && (vemva_base != (void *)required_base)) {
		PSEUDO_DEBUG("Unable to allocate required chunk.");
		if (flag & MAP_FIXED) {
			munmap(vemva_base, ve_page_info.chunk_size*
					req_dir_count);
			vemva_ret = NULL;
			goto err_exit;
		}
	}

	/*
	 * Allocate data structure to hold info
	 */
	do {
		vemva_tmp = (struct vemva_struct *)malloc(sizeof
				(struct vemva_struct));
		if (vemva_tmp == NULL) {
			/*
			 * Here is a possible memory leak for
			 * priviously allocated dir
			 */
			PSEUDO_DEBUG("malloc in alloc_vemva FAILED");
			return NULL;
		}
		memset(vemva_tmp, '\0', sizeof(struct vemva_struct));
		if (!vemva_ret)
			vemva_ret = vemva_tmp;

		vemva_tmp->vemva_base = vemva_base;

		/*SET bitmap to all 1's Indicating all the pages are unused*/
		memset(vemva_tmp->bitmap, 0xff,
				sizeof(vemva_tmp->bitmap));

		/*
		 * SET veshm_bitmap to all 1's
		 * Indicating all the pages are unused
		 */
		memset(vemva_tmp->veshm_bitmap, 0xff,
				sizeof(vemva_tmp->veshm_bitmap));

		memset(vemva_tmp->file_bitmap, 0xff,
				sizeof(vemva_tmp->file_bitmap));
		vemva_tmp->dir_size = ve_page_info.page_size *
			ENTRIES_PER_DIR;
		if (flag & MAP_ADDR_SPACE)
			vemva_tmp->type = (uint8_t)((ve_page_info.page_size ==
				PAGE_SIZE_2MB) ?
				ADDR_SPACE_2MB : ADDR_SPACE_64MB);
		else
			vemva_tmp->type = (uint8_t)((ve_page_info.page_size ==
				PAGE_SIZE_2MB) ?
				ANON_SPACE_2MB : ANON_SPACE_64MB);

		vemva_tmp->used_count = 0;

		/*
		 * Here we are initializing new ATB directory
		 * if new vemva chunk is allocatde.
		 * Below function will send request to veos to
		 * assing new ATB directory and initialize it.
		 */
		if (flag & MAP_VESHM) {
			retval = new_vemva_chunk_atb_init(handle,
					(uint64_t)vemva_base,
					ve_page_info.page_size);
			if (retval == -1) {
				PSEUDO_DEBUG("new_vemva_chunk_atn_init failed");
				free(vemva_tmp);
				errno = ENOMEM;
				goto err_exit;
			}
		}
		add_vemva_dir_in_list(vemva_tmp);
		PSEUDO_DEBUG("New VEMVA List %p created with base: 0x%p and type %d",
				vemva_tmp, vemva_base, vemva_tmp->type);

		PSEUDO_DEBUG("Total VEMVA dir count: %lx",
				vemva_header.vemva_count);

		vemva_base += (ve_page_info.chunk_size);
	} while (--req_dir_count);

#if DEBUG
	struct list_head *temp_list_head;

	list_for_each(temp_list_head,
			&vemva_header.vemva_list) {
		vemva_tmp = list_entry(temp_list_head,
				struct vemva_struct, list);
		PSEUDO_DEBUG("In list vemva_base : %p consec_dir = %d",
				vemva_tmp->vemva_base, vemva_tmp->consec_dir);
	}
#endif

err_exit:
	PSEUDO_DEBUG("returned with 0x%p", vemva_ret);
	PSEUDO_TRACE("returned");
	return vemva_ret;
}

/**
 * @brief This function adds newly allocated VEMVA Chunks
 * in VEMVA list in accending order and update consec dir
 * count as well.
 *
 * @param[in] vemva_dir VEMVA Directory which has to be added
 */
void add_vemva_dir_in_list(struct vemva_struct *vemva_add)
{
	struct list_head *add_after = NULL;
	struct vemva_struct *vemva_current = NULL;
	struct vemva_struct *vemva_next = NULL;
	struct vemva_struct *vemva_prev = NULL;
	struct list_head *temp_list_head = NULL;
	void *vemva_cur_base = NULL;
	void *vemva_cur_top = NULL;
	void *vemva_next_base = NULL;

	PSEUDO_TRACE("invoked");

	void *vemva_add_base = vemva_add->vemva_base;
	void *vemva_add_top = vemva_add->vemva_base +
		vemva_add->dir_size;
	/*
	 * Add vemva dir in list in decreasing order of vemva_base
	 */
	if (list_empty(&vemva_header.vemva_list)) {
		list_add_tail(&vemva_add->list,
				&vemva_header.vemva_list);
		goto added;
	}

	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		vemva_current = list_entry(temp_list_head,
				struct vemva_struct, list);
		if (list_is_last(temp_list_head,
					&vemva_header.vemva_list)) {
			vemva_cur_base = vemva_current->vemva_base;
			if (vemva_add_top <= vemva_cur_base)
				list_add(&vemva_add->list,
						temp_list_head->prev);
			else
				list_add_tail(&vemva_add->list,
						&vemva_header.vemva_list);
			goto added;
		} else {
			vemva_next = list_next_entry(vemva_current, list);
		}

		vemva_cur_base = vemva_current->vemva_base;
		vemva_cur_top = vemva_current->vemva_base +
			vemva_current->dir_size;
		vemva_next_base = vemva_next->vemva_base;

		if (vemva_add_top <= vemva_cur_base) {
			add_after = vemva_current->list.prev;
			break;
		} else if ((vemva_add_base >= vemva_cur_top) &&
				(vemva_add_top <= vemva_next_base)) {
			add_after = &vemva_current->list;
			break;
		}
	}

	list_add(&vemva_add->list, add_after);
added:
	/*
	 * Now update consec_dir count
	 */
	if (list_is_last(&vemva_add->list,
				&vemva_header.vemva_list)) {
		vemva_next = vemva_add;
		vemva_add->consec_dir = 1;
	} else
		vemva_next = list_next_entry(vemva_add, list);

	list_for_each_continue_reverse(temp_list_head,
			&vemva_header.vemva_list, &vemva_next->list) {
		vemva_current = list_entry(temp_list_head,
				struct vemva_struct, list);
		if (temp_list_head->prev == &vemva_header.vemva_list)
			break;
		vemva_prev = list_prev_entry(vemva_current, list);
		if ((vemva_current->vemva_base == (vemva_prev->vemva_base+
					vemva_prev->dir_size)) &&
				(vemva_current->type == vemva_prev->type))
			vemva_prev->consec_dir = vemva_current->consec_dir + 1;
		else
			vemva_prev->consec_dir = 1;
	}

	vemva_header.vemva_count++;
	PSEUDO_TRACE("returned");
}

/**
 * @brief This function removes the entry from pseudo vemvai list.
 *
 * @param[in] vemva_del Pointer to pseudo vemva
 *
 * @return On Success, returns 0 and negative of errno on failure.
 */
int dealloc_vemva_dir(struct vemva_struct *vemva_del)
{
	int ret = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_current = NULL;
	struct vemva_struct *vemva_prev = NULL;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva_del: %p",
			vemva_del);

	vemva_current = list_prev_entry(vemva_del, list);
	vemva_current->consec_dir = 1;

	/*
	 * Now update consec_dir count
	 */
	list_for_each_continue_reverse(temp_list_head,
			&vemva_header.vemva_list,
			&vemva_del->list) {
		vemva_prev = list_prev_entry(vemva_current, list);

		if ((vemva_current->vemva_base == (vemva_prev->vemva_base+
						vemva_prev->dir_size)) &&
				(vemva_current->type == vemva_prev->type))
			vemva_prev->consec_dir = vemva_current->consec_dir + 1;
		else
			vemva_prev->consec_dir = 1;

		vemva_current = vemva_prev;
	}

	/*unmap vemva_base*/
	ret = munmap(vemva_del->vemva_base, vemva_del->dir_size);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("VH OS munmap failed");
		return ret;
	}

	__list_del(vemva_del->list.prev,
			vemva_del->list.next);
	vemva_header.vemva_count--;

	free(vemva_del);
	PSEUDO_DEBUG("returned with 0x%x", ret);
	PSEUDO_TRACE("returned");

	return ret;
}
/**
 * @brief This function verify if the virtual address
 * has been mapped or not.
 *
 * @param[in] vemva_addr Virtual address to verify
 * @param[in] size size to verify
 * @param[in] flag Flags to chack
 *
 * @return Return 1 on success, 0 on failure.
 */
int check_vemva_mapped(void *vemva_addr, size_t page_size, uint8_t flag)
{
	void *vemva_base = NULL;
	int64_t entry = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *vemva_tmp = NULL;
	struct vemva_struct *vemva_del = NULL;

	int64_t count = 1;
	uint64_t chunk_size = page_size * ENTRIES_PER_DIR;
	uint64_t chunk_mask = chunk_size - 1;

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("invoked with vemva_addr %p page_size %lx",
			vemva_addr, page_size);

	/*Calculate the VEMVA Base Address by Masking LSBs*/
	vemva_base = (void *)((uint64_t)vemva_addr &
			(~(chunk_mask)));
	/*Calculate entry using vemva_addr*/
	entry = ((uint64_t)vemva_addr &
			(chunk_mask))/page_size;

	/*Scan VEMVA list for the matching vemva_base*/
	if (!list_empty(&vemva_header.vemva_list)) {
		/*First check vemva_base in vemva_start*/
		list_for_each(temp_list_head, &vemva_header.vemva_list) {
			vemva_tmp = list_entry(temp_list_head,
					struct vemva_struct, list);
			if (vemva_tmp->vemva_base == vemva_base) {
				vemva_del = vemva_tmp;
				break;
			}
		}
		if (vemva_del == NULL) {
			PSEUDO_DEBUG("vemva %p not allocated",
					vemva_addr);
			return 0;
		}

		/*Check Bitmap If the VEMVA's were allocated or not*/
		if (check_bits(vemva_del, entry, count, flag)) {
			PSEUDO_DEBUG("vemva %p with size %lx allocated",
					vemva_addr, page_size);
			return 1;
		}

		PSEUDO_DEBUG("vemva %p with size %lx not allocated",
				vemva_addr, page_size);
		return 0;
	}

	PSEUDO_DEBUG("vemva %p with size %lx is invalid",
			vemva_addr, page_size);
	PSEUDO_TRACE("returned");
	return 0;
}
