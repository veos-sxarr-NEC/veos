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
 * @file ve_shm.c
 * @brief API's which provides the shared memory related
 * system call functionality in veos.
 *
 * @internal
 * @author AMM
 */
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include "ve_shm.h"
#include <sys/shm.h>
#include <sys/mman.h>
#include "velayout.h"

/**
* @brief to get shared memory segment by key and shmid.
*
*	This function traverse the shm list maintained in
*	veos based on the key and shmid provided and return the pointer to
*	struct shm.If not found then create the shm segment and add in the
*	shm list.
*
* @param[in] key Shared memory unique key.
* @param[in] shmid Shared memory unique ID.
* @param[in] size Size of shared memory segment.
* @param[in] perm Permission for shared memory segment.
*
* @return On success it returns pointer to struct shm and NULL on failure.
*/
struct shm *amm_get_shm_segment(key_t key, int shmid, size_t size,
		int flag, bool create)
{
	struct shm *shm_ent;
	int ret = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	/* Traverse the SHM list and find the shared memory
	 * segment if already present.
	 */
	VEOS_TRACE("invoked for shm key(%d):id(%d) with size:%lx, flags:%x and create:%d",
			key, shmid, size, flag, create);

	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
		if (shm_ent->shmid == shmid) {
			pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
					"Failed to release node shm lock");
			VEOS_DEBUG("Shared memory segment with shmid %d found", shmid);
			VEOS_TRACE("returning with shm_ent:%p", shm_ent);
			return shm_ent;
		}
	}

	if (!create) {
		ret = EINVAL;
		goto err_exit;
	}
	/*create new shm_segment and add to list*/
	VEOS_DEBUG("Creating obj for shared memory segment for key(%d):id(%d)", key, shmid);
	shm_ent = (struct shm *)calloc(1, sizeof(struct shm));
	if (NULL == shm_ent) {
		ret = -errno;
		VEOS_CRIT("calloc error (%s) when allocating memory to shm object",
				strerror(-ret));
		goto err_exit;
	}


	shm_ent->key = key;
	shm_ent->shmid = shmid;
	shm_ent->size = size;
	shm_ent->nattch = 0;
	shm_ent->pgmod =  (flag & SHM_2MB) ? PG_2M : PG_HP;
	shm_ent->flag = flag;
	shm_ent->flag |= SHM_AVL;

	pthread_mutex_init(&shm_ent->shm_lock, NULL);
	/* Adding newly created shared memory segment to the list.
	*/
	list_add_tail(&(shm_ent->shm_list), &vnode->shm_head);
	VEOS_TRACE("returned shared memory object(%p)", shm_ent);
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	return shm_ent;
err_exit:
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	VEOS_TRACE("returned error in getting shared memory object");
	errno = ret;
	return NULL;
}

/**
* @brief This function will allocate VE physical pages ot shm segment.
*
* @param[in] shm reference to the structure which will contain all
*        information related to shm segment such as size page size etc.
*
* @return on success return 0 and negative of errno on failure.
*/
int alloc_shm_pages(struct shm *shm)
{
	int ret = 0;
	pgno_t *page_map = NULL;
	int count = -1;
	size_t pgsz = -1;
	size_t size = 0;
	int ent = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	if (NULL == shm) {
		VEOS_DEBUG("Invalid shared memory segment object");
		ret = -EINVAL;
		goto err_exit;
	}
	VEOS_DEBUG("Allocate pages for shared memory segment(%p) with shmid %d",
			shm, shm->shmid);
	size = shm->size;
	pgsz = (shm->flag & SHM_2MB) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB;
	count = (size)/(pgsz);

	VEOS_DEBUG("Allocating memory for page map to hold shm pages");
	page_map = (pgno_t *)calloc(count, sizeof(uint64_t));
	if (NULL == page_map) {
		ret = -errno;
		VEOS_CRIT("calloc error (%s) in allocating page map",
				strerror(-ret));
		goto err_exit;
	}

	VEOS_DEBUG("Allocating %d VE %s pages for shm id %d in page_map(%p)",
			count, pgmod_to_pgstr(shm->pgmod), shm->shmid, page_map);

	ret = alloc_ve_pages(count, page_map, shm->pgmod);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) during VE page allocation \
				to shm segment key(%d):id(%d)",
				strerror(-ret), shm->key, shm->shmid);
		goto err_exit;
	}

	shm->vemaa = page_map;

	for (ent = 0; ent < count; ent++) {
		VE_PAGE(vnode, page_map[ent])->flag |= PG_SHM|MAP_ANON;
		VE_PAGE(vnode, page_map[ent])->private_data =
			shm;
		VEOS_DEBUG("SHM segment[id :%d] at off %d with %s pgno:%lx flag:%lx private:%p",
			shm->shmid, ent, pgmod_to_pgstr(shm->pgmod), page_map[ent],
			VE_PAGE(vnode, page_map[ent])->flag,
			VE_PAGE(vnode, page_map[ent])->private_data);
	}

	VEOS_TRACE("returned");
	return ret;
err_exit:
	if (page_map)
		free(page_map);
	VEOS_TRACE("returned with error");
	return ret;
}

/**
* @brief This is core shmat handler which attached the shared memory segment to VE process.
*
* @param[in] key Shared memory unique key.
* @param[in] shmid Shared memory unique ID.
* @param[in] shmaddr vemva at which segment to attach.
* @param[in] size Size of shared memory segment.
* @param[in] perm Permission for shared memory segment.
* @param[in] tsk reference to VE process task struct.
*
* @return On success it returns 0 and negative of errno on failure.
*/
int amm_do_shmat(key_t key, int shmid, vemva_t shmaddr, size_t size,
		int64_t perm, struct ve_task_struct *tsk)
{
	int ret = 0;
	int ent = 0, count = 0;
	int pgmod = 0;
	atb_reg_t tmp_atb = { { { {0} } } };
	struct shm *shm_ent = NULL;
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	vemva_t shmaddr_tmp = 0;
	size_t pgsz = 0;
	vemaa_t *pgaddr = NULL;
	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	dir_t dir_num = 0;
	int i = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("attach shm key(%d):id(%d) \
		of size(%lx), perm(%lx) at vemva(%lx) for tsk:pid(%d)",
		key, shmid, size, perm, shmaddr, tsk->pid);

	memset(dirs, -1, sizeof(dirs));

	/*Shared memory segment write permission*/
	perm = (perm & PROT_WRITE) ? 1 : 0;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	memcpy(&tmp_atb, &(mm->atb), sizeof(atb_reg_t));

	if (tsk->sighand->rlim[RLIMIT_AS].rlim_cur <
			(rlim_t)(tsk->p_ve_mm->vm_size + size)) {
		VEOS_DEBUG("tsk address space limit exceeds current map"
				"request");
		ret = -ENOMEM;
		goto shmat_err;
	}

	/*
	 * This interface will first search the shared memory list
	 * based on the key and shmid and return the shm structure.
	 * If not found then create the new shared memory segment
	 * based on the key, shmid, size and permissions.
	 */
	shm_ent = amm_get_shm_segment(0, shmid, size, 0, false);
	if (NULL == shm_ent) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while attaching shm with key(%d):id(%d)",
				strerror(-ret), key, shmid);
		goto shmat_err;
	}

	/* Get page size */
	pgmod = shm_ent->pgmod;
	pgsz = (pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB;

	/* calculate the number of 2MB pages
	 */
	shmaddr_tmp = shmaddr;
	count = (shm_ent->size) / pgsz;

	/*
	 * Deffered allocation of shared memory pages
	 */

	pthread_mutex_lock_unlock(&shm_ent->shm_lock, LOCK,
			"Failed to acquire shm lock");
	if (NULL == shm_ent->vemaa) {
		VEOS_DEBUG("VE pages to shm segment with shmid(%d) not allocated",
				shm_ent->shmid);
		ret = alloc_shm_pages(shm_ent);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) in allocating VE pages",
					strerror(-ret));
			pthread_mutex_lock_unlock(&shm_ent->shm_lock, UNLOCK,
					"Failed to release shm lock");
			goto shmat_err;
		}
	} else {
		VEOS_DEBUG("VE pages already allocated to shared memory"
				"segment with shmid %d", shm_ent->shmid);
	}
	pthread_mutex_lock_unlock(&shm_ent->shm_lock, UNLOCK,
			"Failed to release shm lock");

	VEOS_DEBUG("Shared memory segment consist of %d VE %s pages",
			count, pgmod_to_pgstr(pgmod));

	pgaddr = (vemaa_t *)calloc((count + 1), (sizeof(uint64_t)));
	if (NULL == pgaddr) {
		ret = -ENOMEM;
		VEOS_CRIT("calloc error (%s) in allocating page map info",
			strerror(-ret));
		goto shmat_err;
	}

	for (ent = 0; ent < count; ent++) {
		dir_num = validate_vemva(shmaddr_tmp, perm,
				shm_ent->vemaa[ent], &tmp_atb, pgmod);
		if (0 > dir_num) {
			ret = dir_num;
			VEOS_DEBUG("Error (%s) in updating ATB for shm id(%d) attach",
					strerror(-ret), shmid);
			goto shmat_err;
		}

		if (prv_dir == -1 || prv_dir != dir_num)
			dirs[i++] = dir_num;
		prv_dir = dir_num;

		/*
		 * save physical address of page
		 */
		pgaddr[ent] = shm_ent->vemaa[ent] * PAGE_SIZE_2MB;

		shmaddr_tmp += pgsz;
	}

	ret = insert_shm_map_entry(shmaddr, shm_ent, mm);
	if (0 > ret) {
		VEOS_DEBUG("Error inserting shm to process mm(%p)", mm);
		goto shmat_err;
	}

	memcpy(&(mm->atb), &tmp_atb, sizeof(atb_reg_t));

	pthread_mutex_lock_unlock(&shm_ent->shm_lock, LOCK,
			"Failed to acquire shm lock");
	for (ent = 0; ent < count; ent++) {
		shm_ent->nattch += 1;
	}
	pthread_mutex_lock_unlock(&shm_ent->shm_lock, UNLOCK,
			"Failed to release shm lock");

	/*Increament the ref count of allocated pages */
	ret = amm_get_page(pgaddr);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while incrementing shm id(%d) ref count",
			strerror(-ret), shmid);
		goto shmat_err;
	}

	i = 0;
	while (0 <= dirs[i]) {
		psm_sync_hw_regs(tsk, ATB,
				(void *)&mm->atb,
				true, dirs[i++], 1);
	}
	VEOS_DEBUG("Shared memory key(%d):id(%d) and nattach:%ld",
			shm_ent->key, shm_ent->shmid,
			shm_ent->nattch);

	mm->shared_rss += shm_ent->size;
	mm->rss_cur += shm_ent->size;
	mm->vm_size += shm_ent->size;

	if (mm->rss_max < mm->rss_cur)
		mm->rss_max = mm->rss_cur;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	VEOS_TRACE("returned ret %d", ret);
	free(pgaddr);
	return ret;
shmat_err:
	free(pgaddr);
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned with error(%d)", ret);
	return ret;
}

/**
* @brief This function removes the shared memory segment
*         from shm list and release the physical pages.
*
* @param[in] shm_ent reference to the structure which contains information
*            related to shm segment suct size, page size etc.
*
* @return On success it returns 0 and negative errno on failure.
*/
int amm_release_shm_segment(struct shm *shm_ent)
{
	int ent = 0, count = 0;
	size_t pgsz = 0;
	pgno_t pgno = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked for shm segment(%p)", shm_ent);

	if (NULL == shm_ent)
		return -EINVAL;

	VEOS_DEBUG("Releasing shared memory segment key(%d):id(%d)",
			shm_ent->key, shm_ent->shmid);

	pgsz = shm_ent->pgmod == PG_2M ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB;

	count = shm_ent->size / pgsz;

	VEOS_DEBUG("Shared memory segment contains %d VE %s pages",
			count, pgsz_to_pgstr(pgsz));

	for (ent = 0; ent < count; ent++) {
		if (shm_ent->vemaa) {
			pgno = shm_ent->vemaa[ent];
			VE_PAGE(vnode, pgno)->flag |= PG_VE;
			VE_PAGE(vnode, pgno)->flag &= (~PG_SHM);
			VE_PAGE(vnode, pgno)->private_data = NULL;

			VEOS_DEBUG("Releasing %s VE page %lx allocated at shm offset %d",
					pgmod_to_pgstr(shm_ent->pgmod), pgno, ent);

			if ((0 == VE_PAGE(vnode, pgno)->ref_count) &&
					(0 == VE_PAGE(vnode, pgno)->dma_ref_count)) {
				pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
						"Fail to acquire ve page lock");
				veos_free_page(pgno);
				pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
						"Fail to release ve page lock");
			}

		} else
			VEOS_DEBUG("No physical pages allocated to shm segment(%d)", shm_ent->shmid);
	}

	list_del(&(shm_ent->shm_list));
	free(shm_ent->vemaa);
	free(shm_ent);
	VEOS_TRACE("returned");
	return 0;
}

/**
* @brief This is core shmctl handler which destroy the shared memory segment.
*
* @param[in] shmid shared memory unique ID.
* @param[in] tsk reference to the process task struct.
*
* @return on success return 0 and negative of errno on failure.
*/
int amm_do_shmctl(int shmid, struct ve_task_struct *tsk)
{
	int ret = -1;
	int found = 0;
	struct shm *shm_ent = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked by tsk(%p):pid(%d) for shmid(%d)",
			tsk, tsk->pid, shmid);

	/* Traverse the SHM list and find the shared memory
	 * segment.
	 */
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
		if (shm_ent->shmid == shmid) {
			VEOS_DEBUG("Shared memory segment(%p) for shmid(%d) found",
					shm_ent, shmid);
			found = 1;
			break;
		}
	}

	/* Mark the segment status as destroy */
	if (found)
		shm_ent->flag |= SHM_DEL;
	else {
		ret = -EINVAL;
		goto exit1;
	}
	/* If nattch of this segment is zero the remove the segment
	 * and release the physical pages.
	 */


	if (shm_ent->nattch == 0)
		amm_release_shm_segment(shm_ent);

	ret = 0;
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	return ret;
exit1:
	VEOS_TRACE("returned with error");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	return ret;
}

/**
* @brief This is core shmdt handler which detaches the shared
*		memory segment from VE process.
*
* @param[in] shmaddr VE virtual memory address of shared memory segment.
* @param[in] tsk reference to the VE process task struct.
* @param[in] shm_info reference to the structure which containing information
*	     related to shm segment such as page mode, vemva bitmap etc.
*
* @return on success returns o and negative of errno on failure.
*/
int amm_do_shmdt(vemva_t shmaddr, struct ve_task_struct *tsk,
		struct shm_seginfo *shm_info)
{
	int i = 0;
	int ret = -1, shmrm = 0;
	int ent = 0, count = 0, pgmod = 0;
	atb_reg_t tmp_atb = { { { {0} } } };
	uint64_t pgno = -1, pgsz = 0;
	vemaa_t pgaddr = 0;
	dir_t dir_num = 0;
	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	struct shm *shm_segment = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *mm = tsk->p_ve_mm;

	VEOS_TRACE("invoked by tsk(%p):pid(%d) for vemva %lx and shminfo(%p)",
			tsk, tsk->pid, shmaddr, shm_info);
	memset(dirs, -1, sizeof(dirs));

	/* Operation is done on copy of ATB to avoid any data
	 * loss.
	 */
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	memcpy(&tmp_atb, &(mm->atb), sizeof(atb_reg_t));

	/*check if shm page or not*/
	shm_segment = del_shm_map_entry(shmaddr, mm);
	if (NULL == shm_segment) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) on detaching shared memory from vemva %lx",
			strerror(-ret), shmaddr);
		shm_info->err = EINVAL;
		goto shmdt_ret;
	}

	pgmod = shm_segment->pgmod;
	pgsz = (pgmod == PG_2M) ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB;

	shm_info->size = shm_segment->size;
	count = shm_segment->size / pgsz;

	for (ent = 0; ent < count; ent++) {
		pgaddr = __veos_virt_to_phy(shmaddr,
				&tmp_atb, NULL, NULL);
		if (0 > pgaddr) {
			VEOS_DEBUG("NO physical mapping found");
			shmaddr += pgsz;
			continue;

		}

		pgno = pfnum(pgaddr, PG_2M);
		if (pgno == PG_BUS) {
			shmaddr += pgsz;
			continue;
		}

		if (VE_PAGE(vnode, pgno)->flag & PG_PTRACE) {
			VEOS_DEBUG("Detaching VE page: %ld marked as PG_PTRACE",
					pgno);
			goto detach_directly;
		}

		if (((VE_PAGE(vnode, pgno)->flag & PG_SHM) != PG_SHM) ||
				(shm_segment->vemaa[ent] != pgno)) {
			shmaddr += pgsz;
			continue;
		}
		mm->shared_rss -= pgsz;
		mm->rss_cur -= pgsz;
		mm->vm_size -= pgsz;

		/* Update shm_segment natach*/
		pthread_mutex_lock_unlock(&shm_segment->shm_lock, LOCK,
				"Failed to acquire shm lock");
		shm_segment->nattch -= 1;
		if (!shm_segment->nattch)
			shmrm = 1;
		pthread_mutex_lock_unlock(&shm_segment->shm_lock, UNLOCK,
				"Failed to release shm lock");

detach_directly:
		dir_num = invalidate_vemva(shmaddr, (void *)&tmp_atb);
		if (0 > dir_num) {
			VEOS_DEBUG("Not able to unset ATB of vemva:%lx\n",
					shmaddr);
			goto shmdt_ret;
		}

		if (prv_dir == -1 || prv_dir != dir_num)
			dirs[i++] = dir_num;
		prv_dir = dir_num;

		ret = amm_put_page(pgaddr);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) on decrementing shm page %lx",
				strerror(-ret), pgaddr);
			goto shmdt_ret;
		}

		shmaddr += pgsz;
		set_bit(shm_info->bitmap, ent);
	}

	/*
	 * On succcess update the ATB structure maintained in mm
	 */
	memcpy(&(mm->atb), &tmp_atb, sizeof(atb_reg_t));
	i = 0;
	while (0 <= dirs[i]) {
		psm_sync_hw_regs(tsk, ATB,
				(void *)&(mm->atb),
				true, dirs[i++], 1);
	}


	VEOS_DEBUG("Shared memory segment with id %d and current attach value %ld",
			shm_segment->shmid, shm_segment->nattch);

	/* Release the segment if flag is set as destroy.
	*/

	if ((shm_segment->flag & SHM_DEL) &&
			(shm_segment->nattch == 0)) {
		if (shmrm) {
			pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
					"Failed to acquire node shm lock");
			VEOS_DEBUG("Shared memory segment with id %d delete flag is set",
					shm_segment->shmid);
			amm_release_shm_segment(shm_segment);
			pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
					"Failed to release node shm lock");
		}
	}

	ret = 0;
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	return ret;
shmdt_ret:
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned with error");
	return ret;
}

/**
* @brief This function will add an entry of struct shm_mapping in list.
*
* @param[in] shmaddr VE virtual memory address of shm_segment.
* @param[in] seg reference to the structure which containing information related to shm segment .
* @param[in] mm reference to mm_struct to fetch shm_mapping list head.
*
* @return on success return 0 and negative of errno on failure.
*/
int insert_shm_map_entry(vemva_t shmaddr, struct shm *seg,
		struct ve_mm_struct *mm)
{
	struct shm_map *shm_tmp = NULL, *tmp = NULL;
	int pgmod = 0;
	uint64_t pgsz = 0;
	int ret = 0;

	VEOS_TRACE("invoked for vemva %lx and shm id(%d)",
			shmaddr, seg->shmid);

	list_for_each_entry_safe(shm_tmp, tmp, &(mm->shm_head), shm_list) {
		if ((shm_tmp->shmaddr == shmaddr) && (shm_tmp->shm_segment == seg)) {
			VEOS_DEBUG("Shared memory segment mapping found in process list");
			goto exit1;
		}
	}

	pgmod = seg->pgmod;
	pgsz = (pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB;

	/*create new shm_mapping and add to list*/
	shm_tmp = (struct shm_map *)calloc(1, sizeof(struct shm_map));
	if (NULL == shm_tmp) {
		ret = -errno;
		VEOS_CRIT("calloc error (%s) in creating shmmap object",
			strerror(-ret));
		goto err_exit;
	}

	shm_tmp->shmaddr = shmaddr;
	shm_tmp->count = (seg->size) / pgsz;
	shm_tmp->shm_segment = seg;

	list_add(&(shm_tmp->shm_list), &(mm->shm_head));

exit1:
	VEOS_TRACE("returned with shm mapping (%p) for vemva %lx",
			shm_tmp, shmaddr);
	return ret;
err_exit:
	VEOS_TRACE("returned with error");
	return ret;
}

/**
* @brief This Function will delete an entry of shm_map from shm_map_list
*	after comparing with shm VE virtual memory address.
*
* @param[in] shmaddr VE virtual memory address to match instance of
*            shm segment in list maintain in mm struct.
* @param[in] mm_struct Pointer to mm_struct to fetch shm_map list head.
*
* @return on success returns reference to shm segment and null on failure.
*/
struct shm *del_shm_map_entry(vemva_t shmaddr, struct ve_mm_struct *mm)
{
	struct shm_map *shm_tmp = NULL, *tmp = NULL;
	struct shm *shm_segment = NULL;

	VEOS_TRACE("invoked for vemva 0x%lx",
			 shmaddr);

	/**
	 * Traverse the SHM list and find the shared memory
	 * segment if already present.
	 */
	list_for_each_entry_safe(shm_tmp, tmp, &(mm->shm_head), shm_list) {
		VEOS_DEBUG("In shm list current mapping %p with vemva 0x%lx",
				shm_tmp, shm_tmp->shmaddr);
		if (shm_tmp->shmaddr == shmaddr) {
			VEOS_DEBUG("shm mapping for vemva 0x%lx found in shm list",
					shmaddr);
			goto done;
		}
	}

	VEOS_DEBUG("vemva 0x%lx not mapped to shm",
			shmaddr);
	errno = EINVAL;
	VEOS_TRACE("returned with error");
	return NULL;
done:
	shm_segment = shm_tmp->shm_segment;
	list_del(&(shm_tmp->shm_list));
	free(shm_tmp);
	VEOS_TRACE("returned with shm segment %p for shmaddr 0x%lx",
			shm_segment, shmaddr);
	return shm_segment;
}
