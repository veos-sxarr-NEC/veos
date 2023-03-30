/*
 * Copyright (C) 2020 NEC Corporation
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
 * @brief VE1 dependent part of VEHVA management related function.
 *
 * @internal
 * @author AMM
 */
#include <veos_arch_defs.h>
#include <vehva_mgmt.h>
#include "vehva_mgmt_ve1.h"
#include "ve_memory_ve1.h"

int ve1_amm_vehva_init(struct ve_mm_struct *vm)
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

	VEOS_TRACE("In");
	VEOS_DEBUG("In %s", __func__);

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
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_vehva_init, ve1_amm_vehva_init)

int64_t ve1_amm_vehva_alloc(int flag, uint64_t size, struct ve_mm_struct *mm)
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

	VEOS_TRACE("In");
	VEOS_DEBUG("In %s: %x, size: %ld", __func__, flag, size);

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

		pthread_mutex_lock_unlock(&mm->vehva_header.vehva_4k_lock,
				LOCK, "Failed to acquire VEHVA 4k lock");
		entry = veos_get_free_vehva(mm->vehva_header.bmap_4k,
				sbit, ebit, count);
		pthread_mutex_lock_unlock(&mm->vehva_header.vehva_4k_lock,
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
			vehva_lock = &mm->vehva_header.vehva_2m_lock;
			bmap = mm->vehva_header.bmap_2m;
		} else if (flag & VEHVA_64MB) {
			VEOS_DEBUG("VEHVA request type VESHM_64MB");
			pgsz = PAGE_SIZE_64MB;
			vehva_base = VEHVA_64M_START;
			vehva_lock = &mm->vehva_header.vehva_64m_lock;
			bmap = mm->vehva_header.bmap_64m;
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
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_vehva_alloc, ve1_amm_vehva_alloc)

int ve1_amm_vehva_free(vehva_t vehva_start, size_t size,
		struct ve_task_struct *tsk)
{
	vehva_t vehva_end = 0;
	int64_t entry = -1;
	int64_t count = -1;
	uint64_t *bmap = NULL;
	int pgmod = 0, ret = 0;
	pthread_mutex_t *vehva_lock = NULL; /*!< mutex lock*/

	VEOS_TRACE("In");
	VEOS_DEBUG("In %s", __func__);

	vehva_end = vehva_start + size;

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
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_vehva_free, ve1_amm_vehva_free)
