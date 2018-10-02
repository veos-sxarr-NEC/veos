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
	bool remv_segment = false;
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
			VEOS_DEBUG("shm segment with shmid %d found", shmid);
			remv_segment = true;
			goto noerr_exit;
		}
	}

	if (!create) {
		ret = EINVAL;
		goto err_exit;
	}
	/*create new shm_segment and add to list*/
	shm_ent = (struct shm *)calloc(1, sizeof(struct shm));
	if (NULL == shm_ent) {
		ret = errno;
		VEOS_CRIT("calloc error (%s) when allocating memory to shm object",
				strerror(-ret));
		goto err_exit;
	}

	shm_ent->key = key;
	shm_ent->shmid = shmid;
	shm_ent->size = size;
	shm_ent->nattch = 0;
	shm_ent->pgmod =  (flag & SHM_2MB) ? PG_2M : PG_HP;
	shm_ent->flag = (uint64_t)flag;
	shm_ent->flag |= SHM_AVL;

	pthread_mutex_init(&shm_ent->shm_lock, NULL);
	/* Adding newly created shared memory segment to the list*/
	VEOS_DEBUG("Added shm segment with key(%d) to global list", key);
	list_add_tail(&(shm_ent->shm_list), &vnode->shm_head);

noerr_exit:
	 /*Keeping shared memory segment statistics*/
	ret = shmctl(shmid, IPC_STAT, &shm_ent->ipc_stat);
	if (ret < 0) {
		ret = errno;
		VEOS_DEBUG("error(%s) while getting shm segment(%d) stat",
				strerror(errno), shmid);
		if (!remv_segment) {
			/*Removing segment*/
			list_del(&(shm_ent->shm_list));
			free(shm_ent);
		}
		goto err_exit;
	}

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
	pgsz = (size_t)((shm->flag & SHM_2MB) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB);
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
	pgsz = (size_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB);

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

	pgsz = (size_t)(shm_ent->pgmod == PG_2M ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB);

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
*
* @return on success return 0 and negative of errno on failure.
*/
int amm_do_shmctl(int shmid)
{
	int ret = 0;
	struct shm *shm_ent = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Entering");

	/* Traverse the SHM list and find the shared memory segment*/
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
		if (shm_ent->shmid == shmid) {
			VEOS_DEBUG("shm segment(%p) for shmid(%d) found",
					shm_ent, shmid);
			shm_ent->flag |= SHM_DEL;
			/* If nattch of this segment is zero the remove the segment
			 * and release the physical pages.
			 */
			if (shm_ent->nattch == 0)
				amm_release_shm_segment(shm_ent);
			else {
				ret = shmctl(shmid, IPC_STAT, &shm_ent->ipc_stat);
				if (ret < 0) {
					ret = -errno;
					VEOS_DEBUG("error(%s) while updating shm stats",
						strerror(-ret));
				}
			}
			goto func_return;
		}
	}
	VEOS_DEBUG("shm segment with shmid(%d) not found", shmid);
	ret = -EINVAL;
func_return:
	VEOS_TRACE("returned");
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
	int ret = 0, shmrm = 0, i = 0, found = 0;
	int ent = 0, count = 0, pgmod = 0;
	atb_reg_t tmp_atb = { { { {0} } } };
	uint64_t pgno = -1, pgsz = 0;
	vemaa_t pgaddr = 0;
	dir_t dir_num = 0;
	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	struct shm *shm_segment = NULL, *shm_ent = NULL;
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
	pgsz = (size_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB);

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
			ret = dir_num;
			VEOS_DEBUG("Not able to unset ATB of vemva:%lx",
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
	while (0 <= dirs[i])
		psm_sync_hw_regs(tsk, ATB, (void *)&(mm->atb), true, dirs[i++], 1);

	VEOS_DEBUG("Shared memory segment with id %d and current attach value %ld",
			shm_segment->shmid, shm_segment->nattch);

	/* Release the segment if flag is set as destroy.
	*/

	if (shmrm) {
		pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
				"Failed to acquire node shm lock");
		VEOS_DEBUG("Shared memory segment with id %d delete flag is set",
				shm_segment->shmid);
		list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
			if (shm_ent == shm_segment) {
				VEOS_DEBUG("Shared memory segment(%p) for shmid(%d) found",
						shm_ent, shm_ent->shmid);
				found = 1;
				break;
			}
		}

		if (found) {
			if ((shm_segment->flag & SHM_DEL) &&
					(shm_segment->nattch == 0))
				amm_release_shm_segment(shm_segment);
			else
				shm_segment->ipc_stat.shm_dtime = time(NULL);
		}
		pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
				"Failed to release node shm lock");
	}

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
	pgsz = (uint64_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB);

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

/**
* @brief This function is will compair the cuid and uid to insure
*	capability.
*
* @param[in] proc_info process information.
* @param[in] s_shm shm segment information
*
* @return if success it returns true else false.
*/
bool __is_capable(proc_t *proc_info, struct shmid_ds *s_shm)
{
	VEOS_TRACE("Entering");
	if ((s_shm->shm_perm.uid == proc_info->euid) ||
		(s_shm->shm_perm.cuid == proc_info->euid) ||
		(check_ve_proc_capability(proc_info->tid, CAP_SYS_ADMIN))) {
		VEOS_TRACE("returned");
		return true;
	}
	VEOS_TRACE("returned");
	return false;
}

/**
* @brief This function will check whether requestor is capable of
*        deleting shm segment or not.
*
* @param[in] pid process identifier of requestor.
* @param[in/out] key_id shmkey or shmid of segment to be deleted.
*	In case of shmid it is 'in' parameter only, but
*	in case of shmkey it is 'in/out' parameter.
* @param[in] is_key if true key_id contain shmkey else shmid.
*
* @return return 0 on success else negative of errno.
*/
int is_capable(pid_t pid, int *key_id, bool is_key)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	proc_t proc_info = {0};
	struct shm *s_shm = NULL;
	int ret = 0;
	VEOS_TRACE("Entering");
	/*Get proc info for given pid*/
	if (0 > psm_get_ve_proc_info(pid, &proc_info)) {
		VEOS_DEBUG("pid(%d) error unable to get proc info", pid);
		return -EFAULT;
	}

	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");

	list_for_each_entry(s_shm, &vnode->shm_head, shm_list) {
		if (is_key ? (s_shm->key == *key_id) : (s_shm->shmid == *key_id)) {
			VEOS_DEBUG("shm segment with %s %d found",
					is_key ? "shmkey" : "shmid", *key_id);
			/*check the capability*/
			if (__is_capable(&proc_info, &s_shm->ipc_stat)) {
				if (is_key)
					*key_id = s_shm->shmid;
				goto f_return;
			} else {
				VEOS_DEBUG("does not have required capability to delete the segment");
				if (is_key)
					*key_id = s_shm->shmid;
				ret = -EPERM;
				goto f_return;
			}
		}
	}

	VEOS_DEBUG("shm segment with shmid %d is not found", *key_id);
	ret = -EINVAL;
f_return:
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief Copy information from src to dest.
*
* @param[in] dest destination pointer.
* @param[in] src source pointer.
* @param[in] shm_cnt shm segment number.
*/
void copy_shm_info(void *dest, void *src, int shm_cnt)
{
	VEOS_TRACE("Entering");
	VEOS_DEBUG("Copying Info for shmid(%d) count(%d)",
			((struct shm *)src)->shmid, shm_cnt);
	((sdata_t *)dest + shm_cnt)->id =
		((struct shm *)src)->shmid;
	((sdata_t *)dest + shm_cnt)->key =
		((struct shm *)src)->key;
	((sdata_t *)dest + shm_cnt)->uid =
		((struct shm *)src)->ipc_stat.shm_perm.uid;
	((sdata_t *)dest + shm_cnt)->gid =
		((struct shm *)src)->ipc_stat.shm_perm.gid;
	((sdata_t *)dest + shm_cnt)->cuid =
		((struct shm *)src)->ipc_stat.shm_perm.cuid;
	((sdata_t *)dest + shm_cnt)->cgid =
		((struct shm *)src)->ipc_stat.shm_perm.cgid;
	((sdata_t *)dest + shm_cnt)->mode =
		((struct shm *)src)->ipc_stat.shm_perm.mode;
	((sdata_t *)dest + shm_cnt)->shm_nattch =
		((struct shm *)src)->ipc_stat.shm_nattch;
	((sdata_t *)dest + shm_cnt)->shm_segsz =
		((struct shm *)src)->ipc_stat.shm_segsz;
	((sdata_t *)dest + shm_cnt)->shm_atim =
		((struct shm *)src)->ipc_stat.shm_atime;
	((sdata_t *)dest + shm_cnt)->shm_dtim =
		((struct shm *)src)->ipc_stat.shm_dtime;
	((sdata_t *)dest + shm_cnt)->shm_ctim =
		((struct shm *)src)->ipc_stat.shm_ctime;
	((sdata_t *)dest + shm_cnt)->shm_cprid =
		((struct shm *)src)->ipc_stat.shm_cpid;
	((sdata_t *)dest + shm_cnt)->shm_lprid =
		((struct shm *)src)->ipc_stat.shm_lpid;
	((sdata_t *)dest + shm_cnt)->shm_rss =
		((struct shm *)src)->size;
	((sdata_t *)dest + shm_cnt)->shm_swp = 0;

	VEOS_TRACE("Returned");
}
/**
* @brief This function will delete the all segment present on veos or list
*        the segment.
* @param[in] pid process identifier of requestor.
* @param[in] is_ipcs if true then this function will list segment else
*         it will delete the segment.
* @param[out] header this will contain shmid and length of shared memory.
*
* @return if success returns o, else negative on errno.
*/
int rm_or_ls_segment(pid_t pid, bool is_ipcs, struct ve_mapheader *header)
{
	proc_t proc_info = {0};
	int shm_cnt = 0;
	int ret = 0;
	void *shm_data = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct shm *shm_trav = NULL, *shm_tmp = NULL;
	struct shm_summary summary = {0};
	size_t info_sz = 0;

	VEOS_TRACE("Entering");

	/*Get proc info for given pid*/
	if (0 > psm_get_ve_proc_info(pid, &proc_info)) {
		VEOS_DEBUG("pid(%d) error unable to get proc info", pid);
		ret = -EFAULT;
		goto f_return;
	}

	/*Get node specific shm memory information*/
	ve_shm_summary(&summary);

	VEOS_DEBUG("Total Number of shm segment on VE[%d]",
			summary.used_ids);

	if (!summary.used_ids) {
		VEOS_DEBUG("Total Number of shm segment on VE[%d]",
				summary.used_ids);
		header->shmid = 0;
		goto f_return;
	}

	info_sz = (!is_ipcs) ? sizeof(sinfo_t) : sizeof(sdata_t);

	/*create shared memory to provide info to requesting process*/
	ret = shmget(IPC_PRIVATE, (info_sz * summary.used_ids), IPC_CREAT|0660);
	if (ret < 0) {
		ret = -errno;
		VEOS_DEBUG("error(%s) while creating shared memory",
				strerror(errno));
		goto f_return;
	}

	shm_data = shmat(ret, NULL, 0);
	if ((void *) -1 == shm_data) {
		ret = -errno;
		shmctl(ret, IPC_RMID, NULL);
		VEOS_DEBUG("error(%s) while attaching shared memory",
				strerror(errno));
		goto f_return;
	}

	header->shmid = ret;
	header->length = summary.used_ids;

	VEOS_DEBUG("HEADER INFO header->shmid(%d) header->length(%u)",
			header->shmid, header->length);

	/* Traversing through the global shm list and deleting
	 * segment in case of ipcrm or listing the segment in case of ipcs*/
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry_safe(shm_trav, shm_tmp, &vnode->shm_head, shm_list) {
		/* As requestor process does not have required
		 * capability to delete the segment, returning
		 * segment id without deleting it*/
		if (__is_capable(&proc_info, &shm_trav->ipc_stat) && !is_ipcs) {
			/* Mark the segment status as destroy */
			((sinfo_t *)shm_data + shm_cnt)->shmid = shm_trav->shmid;
			((sinfo_t *)shm_data + shm_cnt)->shm_errno = 0;

			shm_trav->flag |= SHM_DEL;

			/* If none of the process attach to segment, destroying it
			 * else updating the shm segment stats*/
			if (shm_trav->nattch == 0) {
				shmctl(shm_trav->shmid, IPC_RMID, NULL);
				VEOS_DEBUG("deleted shm segment with shmid(%d)",
						shm_trav->shmid);
				amm_release_shm_segment(shm_trav);
			} else {
				shmctl(shm_trav->shmid, IPC_STAT, &shm_trav->ipc_stat);

				/* Here we are ignoring the error,
				 * because it might be possible that,
				 * segment is present on VE but not on VH*/
				shmctl(shm_trav->shmid, IPC_RMID, NULL);
			}
		} else if (!__is_capable(&proc_info, &shm_trav->ipc_stat) && !is_ipcs) {
			VEOS_DEBUG("can't delete shm segment with shmid (%d)",
					shm_trav->shmid);
			((sinfo_t *)shm_data + shm_cnt)->shmid = shm_trav->shmid;
			((sinfo_t *)shm_data + shm_cnt)->shm_errno = EPERM;
		} else {
			VEOS_DEBUG("found shm segment with shmid(%d) total found(%d)",
					shm_trav->shmid, shm_cnt);
			shmctl(shm_trav->shmid, IPC_STAT, (struct shmid_ds *)&shm_trav->ipc_stat);
			copy_shm_info(shm_data, shm_trav, shm_cnt);
		}
		++shm_cnt;
	}
	ret = shmdt(shm_data);
	if (ret < 0)  {
		ret = -errno;
		header->shmid = 0;
		shmctl(header->shmid, IPC_RMID, NULL);
		VEOS_DEBUG("can't detach shm segment shmid(%d)",
				header->shmid);
	}

	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
f_return:
	VEOS_TRACE("Returned");
	return ret;
}

/**
* @brief This function will give shm infomation for individual shm
*	segment.
*
* @param[in] shmid of shm segment whose information required.
* @param[out] header shm segment information to trasfer the info.
*
* @return if success returns 0 else negative of errno.
*/
int get_shm_info(int shmid, struct ve_mapheader *header)
{
	int ret = 0;
	struct shm *shm_trav = NULL;
	sdata_t *shm_data = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("Entering");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");

	list_for_each_entry(shm_trav, &vnode->shm_head, shm_list) {
		if (shm_trav->shmid == shmid) {
			ret = shmget(IPC_PRIVATE, sizeof(struct shm), IPC_CREAT|0660);
			if (0 > ret) {
				ret = -errno;
				VEOS_DEBUG("error(%s) while creating shm segment",
						strerror(errno));
				goto s_exit;
			}
			shm_data = shmat(ret, NULL, 0);
			if ((void *)shm_data == (void *)-1) {
				ret = -errno;
				shmctl(ret, IPC_RMID, NULL);
				VEOS_DEBUG("error(%s) while attaching shm segment",
						strerror(errno));
				goto s_exit;
			}
			header->shmid = ret;
			header->length = 1;
			VEOS_DEBUG("Copying Information for shm segment shmid(%d)",
					shm_trav->shmid);
			/*Copy information*/
			shmctl(shm_trav->shmid, IPC_STAT,
					(struct shmid_ds *)&shm_trav->ipc_stat);
			copy_shm_info(shm_data, shm_trav, 0);

			ret = shmdt(shm_data);
			if (0 > ret) {
				ret = -errno;
				shmctl(ret, IPC_RMID, NULL);
				VEOS_DEBUG("error(%s) while detaching shm segment",
						strerror(errno));
				goto s_exit;
			}
			goto s_exit;
		}
	}
	ret = -EINVAL;
	VEOS_DEBUG("error(%s) shmid not found(%d)", strerror(-ret), shmid);
s_exit:
	VEOS_TRACE("Returning");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	return ret;
}
/**
* @brief This function will give VEOS shm summary.
*
* @param[out] s_summary shared memory summary used on VEOS.
*/
void ve_shm_summary(struct shm_summary *s_summary)
{
	struct shm *shm_trav = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("Entering");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry(shm_trav, &vnode->shm_head, shm_list) {
		/*Total Number of shared memory segment used*/
		s_summary->used_ids += 1;

		/*Total Number pages used for shared memory*/
		s_summary->shm_tot += shm_trav->size >> LARGE_PSHFT;

		/*Total Number of resident shared memory pages*/
		if (shm_trav->vemaa)
			s_summary->shm_rss += shm_trav->size >> LARGE_PSHFT;

	}
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release node shm lock");
	VEOS_TRACE("Returned");
}


/**
* @brief This function will check whether given shmid is valid or not.
*
* @param[in] shmid whose validity to be checked.
* @param[out] shmid_valid is true if shmid is valid else false.
* @param[in] is_key will decide whether query is for shmid or shmkey.
*/
void veos_key_id_query(int key_id, bool *shmid_valid, bool is_key)
{
	struct shm *shm_trav = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("Entering");
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
			"Failed to acquire node shm lock");
	list_for_each_entry(shm_trav, &vnode->shm_head, shm_list) {
		if (is_key ? shm_trav->key == key_id : shm_trav->shmid == key_id) {
			VEOS_DEBUG("shm segment with %s [%d] is valid",
					is_key ? "shmkey" : "shmid", key_id);
			*shmid_valid = true;
			goto query_done;
		}
	}
	*shmid_valid = false;
query_done:
	pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
			"Failed to release  node shm lock");
	VEOS_TRACE("Returned");
}

/**
* @brief This function will decide how to remove shm segment or it will list
*        all segment currently present on veos.
*
* @param[in] pid process identifier of requestor.
* @param[in] shm_info infomation of segment to be deleted.
* @param[out] header will contain information of shared memory
*             segment created to convey information with requestor.
* @param[out] s_summary will contain shared memory segment summary of VEOS.
*
* @return if success return 0, else negative of errno.
*/
int veos_ipc_op(pid_t pid,
		struct ve_shm_info *shm_info,
		struct ve_mapheader *header,
		struct shm_summary *s_summary)
{
	int ret = 0;
	bool if_yes = false;
	VEOS_DEBUG("Entering");
	switch (shm_info->mode) {
	case SHMKEY:
		if_yes = true;
	case SHMID:
		VEOS_DEBUG("PID[%d] Request for IPCRM -m/IPCRM -M SHMID[%d]",
				pid, shm_info->key_id);
		ret = is_capable(pid, &shm_info->key_id, if_yes);
		if (ret < 0)
			return ret;

		/* Deleting segment from VE*/
		ret = amm_do_shmctl(shm_info->key_id);
		if (ret < 0)
			return ret;
		/* Here we are ignoring the error,
		 * because it might be possible that,
		 * segment is present on VE but not on VH*/
		shmctl(shm_info->key_id, IPC_RMID, NULL);
		break;
	case SHM_LS:
		if_yes =  true;
	case SHM_ALL:
		/*Delete all shm segment or list shm*/
		VEOS_DEBUG("PID[%d] Request for IPCRM -a/IPCS", pid);
		ret = rm_or_ls_segment(pid, if_yes, header);
		if (ret < 0)
			VEOS_DEBUG("pid(%d) error(%s) %s", pid, strerror(-ret),
					if_yes ? "ipcs" : "ipcrm -a");
		break;
	case SHMID_INFO:
		VEOS_DEBUG("PID[%d] Request for IPCS -i SHMID[%d]",
				shm_info->key_id, pid);
		ret = get_shm_info(shm_info->key_id, header);
		if (ret < 0)
			VEOS_DEBUG("error(%s) while getting info for shmid(%d)",
					strerror(-ret), shm_info->key_id);
		break;
	case SHM_SUMMARY:
		VEOS_DEBUG("PID[%d] Request for IPCS -u", pid);
		/*Give summary of all shared memory segment use by veos*/
		ve_shm_summary(s_summary);
		break;
	default:
		ret = -EINVAL;
		VEOS_DEBUG("No Such Option for IPCS/IPCRM");
	}

	return ret;
}
