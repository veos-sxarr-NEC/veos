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
 * @file vehva_mgmt.c
 * @brief Handle VEHVA management related function.
 *
 *	Allocate VEHVA requested by process.
 *
 * @internal
 * @author AMM
 */
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
	int ret = 0;
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

	vm->vehva_header.bmap_4k = (uint64_t *)calloc(1, DMA_BITMAP);
	if (vm->vehva_header.bmap_4k == NULL) {
		ret = -errno;
		VEOS_CRIT("Error (%s) whiel allocating bmap_4k", strerror(-ret));
		goto hndl_return;
	}
	memset(vm->vehva_header.bmap_4k, 0xff, DMA_BITMAP);

	vm->vehva_header.bmap_2m = (uint64_t *)calloc(1, DMA_BITMAP);
	if (vm->vehva_header.bmap_2m == NULL) {
		ret = -errno;
		VEOS_CRIT("Error (%s) whiel allocating bmap_2M", strerror(-ret));
		goto free_bmap_4k;
	}

	memset(vm->vehva_header.bmap_2m, 0xff, DMA_BITMAP);

	vm->vehva_header.bmap_64m = (uint64_t *)calloc(1, DMA_BITMAP);
	if (vm->vehva_header.bmap_64m == NULL) {
		ret = -errno;
		VEOS_CRIT("Error (%s) whiel allocating bmap_64M", strerror(-ret));
		goto free_bmap_2m;
	}

	memset(vm->vehva_header.bmap_64m, 0xff, DMA_BITMAP);
	/*
	 * FOR syscall [0-5]
	 * RFU [102-191]
		 */
	mark_bits(vm->vehva_header.bmap_4k, 0, 5, MARK_USED);
	mark_bits(vm->vehva_header.bmap_4k, RSRV_ENTRY, RSRV_CNT, MARK_USED);

	vm->shm_lhm_vehva = VEHVA_4K_START;

	pthread_mutex_init(&vm->vehva_header.vehva_4k_lock, NULL);
	pthread_mutex_init(&vm->vehva_header.vehva_2m_lock, NULL);
	pthread_mutex_init(&vm->vehva_header.vehva_64m_lock, NULL);

	VEOS_DEBUG("returned with %d", ret);
	VEOS_TRACE("returned");
	return 0;
free_bmap_2m:
	free(vm->vehva_header.bmap_2m);
free_bmap_4k:
	free(vm->vehva_header.bmap_4k);
hndl_return:
	VEOS_DEBUG("returned with %d", ret);
	VEOS_TRACE("returned");
	return ret;
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
	vehva_t vehva_addr = 0;
	vehva_t vehva_base = -1;
	int64_t sbit = -1;
	int64_t ebit = -1;
	uint64_t *bmap = NULL;
	pthread_mutex_t *vehva_lock = NULL; /*!< mutex lock*/
	int64_t count = -1;
	int pgsz = -1, ret = 0;
	int64_t entry = 0;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with flag (%d) size (0x%lx) pid = %d",
			flag, size, tsk->pid);

	if (size <= 0) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s)", strerror(-ret));
		return ret;
	}

	if (flag & VEHVA_4K) {
		pgsz = PAGE_SIZE_4KB;
		vehva_base = VEHVA_4K_START;

		if (flag & VEHVA_SYSCALL) {
			/*
			 * Nothing to do, As VEHVA_SYSCALL and Reserved VEHVAs
			 * has been marked Already
			 */
			VEOS_DEBUG("VEHVA request type SYSCALL");
			vehva_addr = VEHVA_4K_START;
			goto mape;
		} else if (flag & VEHVA_IB) {
			VEOS_DEBUG("VEHVA request type IB");
			sbit = IB_START_ENTRY;
			ebit = IB_END_ENTRY;
		} else if (flag & VEHVA_CR) {
			VEOS_DEBUG("VEHVA request type CR");
			sbit = CR_START_ENTRY;
			ebit = CR_END_ENTRY;
		} else if (flag & VEHVA_DMA_CNT_REG) {
			VEOS_DEBUG("VEHVA request for DMA control register");
			vehva_addr = DMA_CNT_START;
			goto mape;
		} else if (flag & VEHVA_DMA_DESC_E_REG) {
			VEOS_DEBUG("VEHVA request for VEHVA DMA descriptor E");
			vehva_addr = DMA_DESC_E_START;
			goto mape;
		} else if (flag & VEHVA_DMA_DESC_H_REG) {
			VEOS_DEBUG("VEHVA request for VEHVA DMA descriptor H");
			vehva_addr = DMA_DESC_H_START;
			goto mape;
		} else if (flag & VEHVA_SYSCOM_REG) {
			VEOS_DEBUG("VEHVA request for VEHVA DMA descriptor");
			vehva_addr = VEVHA_SYS_COM_START;
			goto mape;
		} else {
			ret = -EINVAL;
			VEOS_DEBUG("Error (%s) for small page vehva", strerror(-ret));
			goto error;
		}

		count = size/pgsz;
		/* scan IB area only */

		pthread_mutex_lock_unlock(&tsk->p_ve_mm->vehva_header.vehva_4k_lock,
				LOCK, "Failed to acquire VEHVA 4k lock");
		entry = veos_get_free_vehva(tsk->p_ve_mm->vehva_header.bmap_4k,
				sbit, ebit, count);
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->vehva_header.vehva_4k_lock,
				UNLOCK, "Failed to release VEHVA 4k lock");
		if (entry < 0) {
			ret = entry;
			goto error;
		}

	} else if (flag & VEHVA_VESHM) {
		if (flag & VEHVA_2MB) {
			VEOS_DEBUG("VEHVA request type VESHM_2MB");
			pgsz = PAGE_SIZE_2MB;
			vehva_base = VEHVA_2M_START;
			vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_2m_lock;
			bmap = tsk->p_ve_mm->vehva_header.bmap_2m;
		} else if (flag & VEHVA_64MB) {
			VEOS_DEBUG("VEHVA request type VESHM_64MB");
			pgsz = PAGE_SIZE_64MB;
			vehva_base = VEHVA_64M_START;
			vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_64m_lock;
			bmap = tsk->p_ve_mm->vehva_header.bmap_64m;
		} else {
			ret = -EINVAL;
			VEOS_DEBUG("Error (%s) for VESHM vehva", strerror(-ret));
			goto error;
		}

		count = size/pgsz;

		pthread_mutex_lock_unlock(vehva_lock, LOCK,
				"Failed to acquire VEHVA VESHM lock");
		entry = veos_get_free_vehva(bmap, VESHM_START_ENTRY,
				VESHM_END_ENTRY, count);
		pthread_mutex_lock_unlock(vehva_lock, UNLOCK,
				"Failed to release VEHVA VESHM lock");
		if (entry == -1)
			goto error;
	} else {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) for vehva", strerror(-ret));
		goto error;
	}

	vehva_addr = vehva_base + (entry * pgsz);
mape:
		VEOS_DEBUG("returned with 0x%lx", vehva_addr);
	VEOS_TRACE("returned");
	return vehva_addr;
error:
	VEOS_DEBUG("returned with 0x%lx", vehva_addr);
	VEOS_TRACE("returned");
	return ret;
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
	vehva_t vehva_end = 0;
	int64_t entry = -1;
	int64_t count = -1;
	uint64_t *bmap = NULL;
	int pgmod = 0, ret = 0;
	pthread_mutex_t *vehva_lock = NULL; /*!< mutex lock*/

	vehva_end = vehva_start + size;
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with vehva %ld size:%ld Pid:%d",
			vehva_start, size, tsk->pid);

	/* Find which region vehva lies in*/
	if ((vehva_start >= VEHVA_4K_START) &&
			(vehva_end <= VEHVA_4K_END)) {
		VEOS_DEBUG("Freeing VEHVA_4K Region");
		count = size/PAGE_SIZE_4KB;
		bmap = tsk->p_ve_mm->vehva_header.bmap_4k;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_4k_lock;
		entry = (vehva_start - VEHVA_4K_START)/PAGE_SIZE_4KB;
		pgmod = PG_4K;
	} else if ((vehva_start >= VEHVA_2M_START) &&
			(vehva_end <= VEHVA_2M_END)) {
		VEOS_DEBUG("Freeing VEHVA_2M Region");
		count = size/PAGE_SIZE_2MB;
		bmap = tsk->p_ve_mm->vehva_header.bmap_2m;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_2m_lock;
		entry = (vehva_start - VEHVA_2M_START)/PAGE_SIZE_2MB;
		pgmod = PG_2M;
	} else if ((vehva_start >= VEHVA_64M_START) &&
			(vehva_end <= VEHVA_64M_END)) {
		VEOS_DEBUG("Freeing VEHVA_64M Region");
		count = size/PAGE_SIZE_64MB;
		bmap = tsk->p_ve_mm->vehva_header.bmap_64m;
		vehva_lock = &tsk->p_ve_mm->vehva_header.vehva_64m_lock;
		entry = (vehva_start - VEHVA_64M_START)/PAGE_SIZE_64MB;
		pgmod = PG_HP;
	} else {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s)", strerror(-ret));
		return ret;
	}

	VEOS_DEBUG("vehva_start:%ld count:%ld entry:%ld pgmod:%d",
			vehva_start, count, entry, pgmod);
	pthread_mutex_lock_unlock(vehva_lock, LOCK,
			"Failed to acquire VEHVA VESHM lock");
	if (vehva_start)
		mark_bits(bmap, entry, count, MARK_UNUSED);
	pthread_mutex_lock_unlock(vehva_lock, UNLOCK,
			"Failed to release VEHVA VESHM lock");

	VEOS_DEBUG("returned with 0x%x", pgmod);
	VEOS_TRACE("returned");
	return pgmod;
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
