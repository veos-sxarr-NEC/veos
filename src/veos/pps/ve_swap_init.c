/*
 * Copyright (C) 2019 NEC Corporation
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
 * @file ve_swap_init.c
 * @brief Initialization of PPS
 *
 * This contains the functions that are used to initialize PPS data structures.
 * VEOS uses these data structures to handle Swap-out and Swap-in  requests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <log4c.h>
#include <pthread.h>
#include "velayout.h"
#include "ve_swap.h"
#include "veos.h"
#include "ve_mem.h"
#include "buddy.h"

#define LOCKSIZE_UNIT 64 * 1024 * 1024

log4c_category_t *cat_os_pps;
static void *pps_buffer_addr;

/*
Allocate                  Deallocate
veos_alloc_ppsbuf     <-> veos_free_ppsbuf
veos_pps_alloc_ppsbuf <-> veos_pps_dealloc_ppsbuf
veos_pps_init_buddy   <-> veos_pps_free_buddy
*/

/**
 * @brief Initialize category for PPS
 *
 * @retval 0 on success,
 * @retval -1 on failure
 */
int
veos_pps_log4c_init(void)
{
	cat_os_pps = log4c_category_get("veos.os_module.pps");
	if (cat_os_pps == NULL) {
		 return -1;
	}

	PPS_DEBUG(cat_os_pps, "Initialized log4c");

	return 0;
}

/**
 * @brief Allocation PPS buffer and lock it into RAM.
 *
 * @param[in] pps_buf_size Size of PPS buffer in MB.
 *
 * @return Pointer to PPS buffer on Success, NULL on failure.
 */
static void
*veos_pps_alloc_ppsbuf(size_t pps_buf_size)
{
	int ret;
	uint64_t tmp;
	void *ptr;
	void *retptr = NULL;
	size_t size, locked_size, remained;
	bool lock_on_going = true;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);
	PPS_DEBUG(cat_os_pps, "Buffer size is %ldMB", pps_buf_size);
	size = ((pps_buf_size + (PPS_BUFFPAGE_SIZE - 1)) /
					PPS_BUFFPAGE_SIZE) * PPS_BUFFPAGE_SIZE;
	PPS_DEBUG(cat_os_pps, "round up to %ldMB", size);
	size *= 1024 * 1024ULL;

	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE,
			MAP_POPULATE|MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB,
			-1, 0);
	if (ptr == MAP_FAILED) {
		PPS_ERROR(cat_os_pps, "Failed to allocate buffer for PPS"
						" due to %s", strerror(errno));
		goto hndl_return;
	}

	for (locked_size = 0, remained = size, tmp = (uint64_t)ptr;
				lock_on_going; remained -= LOCKSIZE_UNIT) {
		if (terminate_flag) {
			PPS_ERROR(cat_os_pps, "Interrupted by termination");
			goto hndl_unlock;
		}
		if (remained <= LOCKSIZE_UNIT) {
			lock_on_going = false;
			PPS_DEBUG(cat_os_pps,
				"remained lock size : %ld, lock addr 0x%lx",
				remained / (1024 * 1024), tmp);
			ret = mlock((void *)tmp, remained);
		} else {
			PPS_DEBUG(cat_os_pps,
					"lock size : %d, lock addr 0x%lx",
					LOCKSIZE_UNIT / (1024 * 1024), tmp);
			ret = mlock((void *)tmp, LOCKSIZE_UNIT);
		}
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to lock buffer for pps"
					" into RAM due to %s", strerror(errno));
			PPS_ERROR(cat_os_pps, "locked_size : 0x%lx, "
				  "remained : 0x%lx", locked_size, remained);
			goto hndl_unlock;
		}
		tmp += LOCKSIZE_UNIT;
		locked_size += LOCKSIZE_UNIT;
	}

	retptr = ptr;
	vnode->pps_buf_size = size;
	goto hndl_return;

hndl_unlock:
	if (locked_size > 0) {
		ret = munlock(ptr, locked_size);
		if (ret != 0) {
			PPS_ERROR(cat_os_pps, "Failed to unlock buffer for PPS"
						"due to %s", strerror(errno));
		}
	}

	ret = munmap(ptr, size);
	if (ret != 0)
		PPS_ERROR(cat_os_pps, "Failed to free buffer for PPS"
						" due to %s", strerror(errno));

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retptr;
}

/**
 * @brief Free PPS buffer
 *
 * @param[in] buffer Pointer to PPS buffer
 *
 * @retval None
 */
static void
veos_pps_dealloc_ppsbuf(void *buffer)
{
	int ret;
	struct ve_node_struct *vnode = VE_NODE(0);
	size_t size;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	size = vnode->pps_buf_size;
	ret = munlock(buffer, size);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to unlock buffer for PPS"
						" due to %s", strerror(errno));
	}

	ret = munmap(buffer, size);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to free buffer for PPS"
						" due to %s", strerror(errno));
	}

	vnode->pps_buf_size = 0;

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Initialize buddy of PPS buffer
 *
 * @param[in] buffer Pointer to PPS buffer
 *
 * @retval 0 on Success,
 * @retval -1 on failure.
 */
static int
veos_pps_init_buddy(void *buffer)
{
	int retval = -1;
	int i;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	vnode->pps_mp = veos_buddy_init((uint64_t)buffer,
					vnode->pps_buf_size, PAGE_SIZE_2MB);
	if (vnode->pps_mp == NULL) {
		PPS_ERROR(cat_os_pps, "Failed to init mempool for PPS");
		goto hndl_return;
	}
	pthread_mutex_init(&(vnode->pps_mp->buddy_mempool_lock), NULL);
	vnode->swap_request_pids_enable = true;
	vnode->resource_freed = false;
	for (i = 0; i < VE_MAX_NUMA_NODE; i++) {
		vnode->pps_mp_used[i] = 0;
	}
	retval = 0;
hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief Finalize buddy of PPS buffer
 *
 * @retval None
 */
static void
veos_pps_free_buddy(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int ret;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = pthread_mutex_destroy(&(vnode->pps_mp->buddy_mempool_lock));
	if (ret != 0)
		PPS_ERROR(cat_os_pps, "Failed to destroy buddy_mempool_lock"
						" due to %s", strerror(ret));
	buddy_deinit(vnode->pps_mp);

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}

/**
 * @brief Create swap thread
 *
 * @retval 0 on Success,
 * @retval -1 on failure.
 */
static int
veos_pps_create_swap_thread(void)
{
	int retval = -1;
	int ret = 0;
	pthread_t swap_thread;
	pthread_attr_t attr;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to init attribute for swap thread due to %s",
			strerror(ret));
		goto hndl_return;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to set DETACHED attribute for swap thread"
			" due to %s", strerror(ret));
		goto hndl_destroy;
	}

	ret = pthread_create(&swap_thread, &attr, &ve_swap_thread, NULL);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps, "Failed to create swap thread due to %s",
								strerror(ret));
	} else {
		retval = 0;
	}

hndl_destroy:
	ret = pthread_attr_destroy(&attr);
	if (ret != 0) {
		PPS_ERROR(cat_os_pps,
			"Failed to destroy attribute for swap thread due to %s",
			strerror(ret));
		retval = -1;
	}

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function allocates PPS buffer for PPS and locks all buffer into
 * RAM, and initializes management information of PPS buffer. And then, this
 * function creates "swap thread".
 *
 * @param[in] pps_buf_size Size of PPS buffer in MB
 *
 * @retval 0 on success,
 * @retval -1 on failure.
 */
int
veos_alloc_ppsbuf(size_t pps_buf_size)
{
	int retval = -1;
	int ret;
	struct ve_node_struct *vnode = VE_NODE(0);

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	INIT_LIST_HEAD(&(vnode->swap_request_pids_queue));
	pthread_mutex_init(&(vnode->swap_request_pids_lock), NULL);
	pthread_cond_init(&(vnode->swap_request_pids_cond), NULL);

	if (pps_buf_size == 0) {
		retval = 0;
		goto hndl_return;
	}

	pps_buffer_addr = veos_pps_alloc_ppsbuf(pps_buf_size);
	if (pps_buffer_addr == NULL)
		goto hndl_return;

	ret = veos_pps_init_buddy(pps_buffer_addr);
	if (ret != 0)
		goto hndl_dealloc;

	ret = veos_pps_create_swap_thread();
	if (ret != 0)
		goto hndl_free_buddy;

	retval = 0;
	goto hndl_return;

hndl_free_buddy:
	veos_pps_free_buddy();

hndl_dealloc:
	veos_pps_dealloc_ppsbuf(pps_buffer_addr);

hndl_return:
	PPS_TRACE(cat_os_pps, "Out %s", __func__);
	return retval;
}

/**
 * @brief This function clears all management information,
 * unlocks all buffer from RAM, and frees PPS buffer for PPS.
 *
 * @retval None
 */
void
veos_free_ppsbuf(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	size_t pps_buf_size;

	PPS_TRACE(cat_os_pps, "In %s", __func__);

	pps_buf_size = vnode->pps_buf_size;
	PPS_DEBUG(cat_os_pps, "pps_buf_size : 0x%lx", pps_buf_size);
	if (pps_buf_size > 0) {
		veos_pps_free_buddy();
		veos_pps_dealloc_ppsbuf(pps_buffer_addr);
	}

	PPS_TRACE(cat_os_pps, "Out %s", __func__);
}
