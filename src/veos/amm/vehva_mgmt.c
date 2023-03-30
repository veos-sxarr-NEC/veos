/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file vehva_mgmt.c
 * @brief Handle VEHVA management related function.
 *
 *	Allocate VEHVA requested by process.
 *
 * @internal
 * @author AMM
 */
#include <veos_arch_defs.h>
#include "vehva_mgmt.h"
#include "ve_memory.h"
/**
* @brief This function initialize vehva related data structure.
*
* @param[in] vm Process memory descriptor.
*
* @return on success return 0 and negative of errno on failure..
*/
int veos_vehva_init(struct ve_mm_struct *vm)
{
	/*
	 * This function will be called whenever a new
	 * VE process will be registered with VEOS.
	 * According to VEHVA layout we must Allocate few
	 * DMAATB entries at process init , there are some
	 * DMAATB entries which must be marked as reserved(used).
	 * VEHVA for those should be marked
	 * as used as well according to VEHVA layout.
	 */
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("In veos_vehva_init()");

	return (*_veos_arch_ops->arch_amm_vehva_init)(vm);
}

/**
* @brief This function allocates vehva for process with pid 'pid'
*
* @param[in] flag Specifies the type of vehva required.
* @param[in] size Specifies size required.
* @param[in] pid Process identifier of requesting process.
*
* @return returns VEHVA on success and negative of errno on error.
*/
int64_t veos_vehva_alloc(int flag, uint64_t size, struct ve_task_struct *tsk)
{
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with flag (%d) size (0x%lx) pid = %d",
			flag, size, tsk->pid);

	if (size <= 0) {
		VEOS_DEBUG("Invalid size (%ld)", size);
		return -EINVAL;
	}
	return (*_veos_arch_ops->arch_amm_vehva_alloc)(flag, size,
							tsk->p_ve_mm);
}

/**
 * @brief This function free vehva for process with pid 'pid'
 *
 * @param[in] vehva_start vehva to be free.
 * @param[in] size size to be free.
 * @param[in] pid process identifier of requesting process.
 *
 * @return returns pgmod for vehva on success and on failure negative of errno.
 */
int veos_vehva_free(vehva_t vehva_start, size_t size,
		struct ve_task_struct *tsk)
{
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with vehva %ld size:%ld Pid:%d",
			vehva_start, size, tsk->pid);

	return (*_veos_arch_ops->arch_amm_vehva_free)(vehva_start, size, tsk);
}


/**
 * @brief This function scans bitmaps and find free VEHVA.
 *
 * @param[in] bmap vehva bitmap to scan.
 * @param[in] sbit start Bit to be scaned.
 * @param[in] ebit end Bit to be scaned.
 * @param[in] count number of free vehva's required.
 *
* @return returns free bit index on success and negative of errno on failure.
*/
int64_t veos_get_free_vehva(uint64_t *bmap, int64_t sbit,
		int64_t ebit, int64_t count)
{
	int64_t contigious_free = 0;
	int16_t sword = -1, eword = -1;
	int16_t wsbit = -1, webit = -1;
	int64_t entry = -1, bit = -1;
	int64_t index = -1;
	int ret = 0;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with count %ld sbit %ld ebit %ld",
			count, sbit, ebit);

	sword = sbit/BITS_PER_WORD;
	eword = ebit/BITS_PER_WORD;

	VEOS_DEBUG("sword:%d eword:%d",
			sword, eword);

	wsbit = sbit%BITS_PER_WORD;
	webit = ebit%BITS_PER_WORD;

	VEOS_DEBUG("wsbit:%d webit:%d",
			wsbit, webit);

	for (index = sword; index <= eword; index++) {
		for (bit = wsbit; (bit < BITS_PER_WORD) &&
				((index < eword) || (bit <= webit));
				bit++) {
			if (bmap[index] & ((uint64_t)1<<bit)) {
				contigious_free++;
				/*
				 * Maintain from which free
				 * vehva has been found first
				 */
				if (1 == contigious_free)
					entry = bit + (index*BITS_PER_WORD);

				if (contigious_free == count)
					goto out;
			} else {
				contigious_free = 0;
			}
		}
		wsbit = 0;
	}

	ret = -ENOMEM;
	VEOS_DEBUG("returned with %d", ret);
	VEOS_TRACE("returned");
	return ret;
out:
	mark_bits(bmap, entry, count, MARK_USED);
	/*Calculate virtual address according to free Index and vehva Base*/
	VEOS_DEBUG("returned with %ld", entry);
	VEOS_TRACE("returned");
	return entry;
}

/**
* @brief  This function marks the bits as unused in the
*         pseudo vehva bitmap at an entry till the count given.
*
* @param[out] bmap pseudo vehva list bitmap
* @param[in] entry Position from which bits are set
* @param[in] count Number of bits to set
* @param[in] flag Information about how the bits has to be
*             marked and which bitmap has to be marked.
*          MARK_USED: Bits has to be marked used.
*          MARK_UNUSED: Bits has to be marked unused.
*                       or unused depending upon other flag.
*/
void mark_bits(uint64_t *bmap, int64_t entry, int64_t count,
		uint8_t flag)
{
	int64_t word = 0, bit = 0;
	int ent = 0;

	VEOS_TRACE("Invoked");
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	VEOS_DEBUG("word:%ld bit:%ld",
			word, bit);

	for (ent = 0; ent < count; ent++) {
		if (flag & MARK_USED)
			bmap[word] = bmap[word] &
				(~((uint64_t)1 << bit++));
		else if (flag & MARK_UNUSED)
			bmap[word] = bmap[word] |
				((uint64_t)1 << bit++);

		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	VEOS_TRACE("returned");
}

/**
* @brief  This function marks the bits as unused in the
*         pseudo vehva bitmap at an entry till the count given.
*
* @param[out] bmap pseudo vehva list bitmap
* @param[in] entry Position from which bits are set
* @param[in] count Number of bits to set
* @param[in] flag Information about how the bits has to be
*             marked and which bitmap has to be marked.
*          MARK_USED: Bits has to be marked used.
*          MARK_UNUSED: Bits has to be marked unused.
*                       or unused depending upon other flag.
*
* @return It returns 1 if the bits are marked as specified in flag.
* else it returns 0.
*/
int check_bits(uint64_t *bmap, int64_t entry, int64_t count,
		uint8_t flag)
{
	int64_t word = 0, bit = 0;

	VEOS_TRACE("Invoked");
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	VEOS_DEBUG("word:%ld bit:%ld", word, bit);

	while (count) {
		if ((flag & MARK_USED) && (bmap[word] &
					((uint64_t)1 << bit))) {
			goto err_out;
		} else if ((flag & MARK_UNUSED) && (!(bmap[word] &
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
	}

	VEOS_DEBUG("returned with success");
	VEOS_TRACE("returned");
	return 1;
err_out:
	VEOS_DEBUG("returned with failure");
	VEOS_TRACE("returned");
	return 0;
}
