/*
 * @file amm_shm.c
 * @brief API's which provides the shared memory related
 * system call functionality in veos.
 */
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include "amm_shm.h"
#include <sys/shm.h>
#include "velayout.h"

#if 0
/**
* @brief This routine detaches the SHM segment from VE
* process address space while releasing the ve_mm_struct.
*
* @param[in] shm_segment shm_structure of the VE process
* @param[in] node_id Node ID
*
* @return On success return 0 and -1 on failure
*/
int amm_shm_detach(struct shm *shm_segment, int node_id)
{
	uint64_t count, page_size;
	/* Get shared memroy segment page size */
	if (SHM_SEG_PAGE_SIZE_64MB ==
		(shm_segment->flag & SHM_SEG_PAGE_SIZE_64MB)) {
		page_size = PAGE_SIZE_64MB;
	} else
		page_size = PAGE_SIZE_2MB;

	/* Decrement the count */
	pthread_mutex_lock(&shm_segment->shm_lock);
	count = shm_segment->size / page_size;
	shm_segment->nattch -= count;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "shm_segment->nattch = %ld\n",
			shm_segment->nattch);

	if ((shm_segment->nattch == 0) &&
			(shm_segment->flag & SHM_DEL))
		amm_release_shm_segment(shm_segment, node_id);
	pthread_mutex_unlock(&shm_segment->shm_lock);

	return 0;
}
#endif

/**
* @brief to get shared memory segment by key and shmid.
*
*	This function traverse the shm list maintained in
*	veos based on the key and shmid provided and return the pointer to
*	struct shm.If not found then create the shm segment and add in the
*	shm list.
*
* @param[in] key Shared memory unique key
* @param[in] shmid Shared memory unique ID
* @param[in] size Size of shared memory segment
* @param[in] perm Permission for shared memory segment
* @param[in] node_id Node ID
*
* @return On success it returns pointer to struct shm and NULL on failure
*/
struct shm *amm_get_shm_segment(int64_t key, int64_t shmid, uint64_t size,
		int64_t perm, int node_id)
{
	struct shm *shm_ent;
	int retval;
	int count, ent;
	uint64_t *page_map, page_size;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	/* Traverse the SHM list and find the shared memory
	 * segment if already present.
	 */
	pthread_mutex_lock(&vnode_info->shm_node_lock);
	list_for_each_entry(shm_ent, &vnode_info->shm_head, shm_list) {
		if ((shm_ent->key == key) &&
				(shm_ent->shmid == shmid)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"SHM segment found!\n");
			goto exit1;
		}
	}

	/*create new shm_segment and add to list*/
	shm_ent = (struct shm *)malloc(sizeof(struct shm));
	if (NULL == shm_ent) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails in allocating\
				memory to shm segment\n");
		goto err_exit;
	}
	/* Get page size */
	if (SHM_HUGETLB == (perm & SHM_HUGETLB)) {
		page_size = PAGE_SIZE_64MB;
		shm_ent->flag |= SHM_SEG_PAGE_SIZE_64MB;
	} else {
		page_size = PAGE_SIZE_2MB;
		shm_ent->flag |= SHM_SEG_PAGE_SIZE_2MB;
	}
	shm_ent->key = key;
	shm_ent->shmid = shmid;
	shm_ent->perm = perm;
	shm_ent->size = size;
	shm_ent->nattch = 0;
	shm_ent->flag |= SHM_AVL;

	count = size/page_size;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Creating new shared memory segment key: %lx ID: %ld\n",
			key, shmid);
	page_map = (uint64_t *)malloc(sizeof(uint64_t) * count);
	if (NULL == page_map) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails in allocating memory.\n");
		free(shm_ent);
		goto err_exit;
	}
	/* Get the required number of free pages.
	 */
	retval = alloc_ve_pages(count, page_map, node_id, page_size);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VE page allocation fails.\n");
		free(shm_ent);
		free(page_map);
		goto err_exit;
	}

	shm_ent->vemaa = page_map;

	for (ent = 0; ent < count; ent++) {
		vnode_info->ve_pages[page_map[ent]].flag |= PG_SHM;
		vnode_info->ve_pages[page_map[ent]].private_data =
			shm_ent;
	}

	pthread_mutex_init(&shm_ent->shm_lock, NULL);
	/* Adding newly created shared memory segment to the list.
	 */
	list_add_tail(&(shm_ent->shm_list), &vnode_info->shm_head);
exit1:
	pthread_mutex_unlock(&vnode_info->shm_node_lock);
	return shm_ent;
err_exit:
	pthread_mutex_unlock(&vnode_info->shm_node_lock);
	return NULL;
}

/**
* @brief This is core shmat handler which attached the shared memory segment to VE process.
*
* @param[in] key Shared memory unique key
* @param[in] shmid Shared memory unique ID
* @param[out] shmaddr VEMVA at which segment to attach
* @param[in] size Size of shared memory segment
* @param[in] perm Permission for shared memory segment
* @param[in] p_ve_task Pointer to VE process task struct
*
* @return On success it returns 0 and -1 on failure
*/
int amm_do_shmat(int64_t key, int64_t shmid, uint64_t shmaddr, uint64_t size,
		int64_t perm, struct ve_task_struct *p_ve_task)
{
	int retval;
	int ent, count, node_id;
	atb_reg_t tmp_atb;
	struct shm *shm_segment = NULL;
	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;
	struct ve_node_struct *vnode_info;
	uint64_t shmaddr_tmp;
	uint64_t page_size;

	node_id = p_ve_task->node_id;
	vnode_info = VE_NODE(node_id);
	/* Get page size */
	if (SHM_HUGETLB == (perm & SHM_HUGETLB))
		page_size = PAGE_SIZE_64MB;
	else
		page_size = PAGE_SIZE_2MB;

	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));
	/*
	 * This interface will first search the shared memory list
	 * based on the key and shmid and return the shm structure.
	 * If not found then create the new shared memory segment
	 * based on the key, shmid, size and permissions.
	 *
	 * TODO: Page size should also be an argument to this function
	 * Shared memory refferd to by shmid and key should have the same
	 * page size as requestedshould have the same
	 * page size as requested.
	 */
	shm_segment = amm_get_shm_segment(key, shmid, size,
			perm, p_ve_task->node_id);
	if (NULL == shm_segment) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"veos fails in creating shared memory chunk.\n");
		retval = -1;
		goto shmat_ret;
	}

	/* calculate the number of 2MB pages
	 */
	shmaddr_tmp = shmaddr;
	count = (shm_segment->size) / page_size;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"shm segment page count is %d\n",
			count);

	for (ent = 0; ent < count; ent++) {
		retval = amm_set_atb(shmaddr_tmp, shm_segment->perm,
				shm_segment->vemaa[ent], &tmp_atb, page_size);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Fails in updating ATB.\n");
			goto shmat_ret;
		}
		shmaddr_tmp += page_size;
	}

	retval = insert_shm_mapping_entry((void *)shmaddr,
					shm_segment, mm_struct);
	if (retval == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"insert_shm_mapping_entry failed\n");
		goto shmat_ret;
	}
	/*
	 * On succcess update the ATB structure maintained in mm_struct
	 */
	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));

	for (ent = 0; ent < count; ent++) {
		/*Increase Page reference count*/
		vnode_info->ve_pages[(shm_segment->vemaa[ent])].ref_count++;
		pthread_mutex_lock(&shm_segment->shm_lock);
		shm_segment->nattch += 1;
		pthread_mutex_unlock(&shm_segment->shm_lock);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Key %lx SHMID %ld with attach now: %ld\n",
			shm_segment->key, shm_segment->shmid,
			shm_segment->nattch);

	pthread_mutex_unlock(&(mm_struct->mm_lock));


	return retval;
shmat_ret:
	pthread_mutex_unlock(&(mm_struct->mm_lock));
	return retval;
}

/**
* @brief This function removes the shared memory segment
* from shm list and release the physical pages.
*
* @param[in] shm_ent Pointer to struct shm
* @param[in] node_id Node ID
*
* @return On success it returns 0 and -1 on failure
*/
int amm_release_shm_segment(struct shm *shm_ent, int node_id)
{
	int ent, count;
	uint64_t pgno;
	uint64_t page_size;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	if (shm_ent == NULL)
		return -1;

	pthread_mutex_lock(&vnode_info->shm_node_lock);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Removing shared memory segment\
			Key: %lx ID: %ld\n",
			shm_ent->key, shm_ent->shmid);
	/* Get page size */
	if (SHM_SEG_PAGE_SIZE_64MB == (shm_ent->flag & SHM_SEG_PAGE_SIZE_64MB))
		page_size = PAGE_SIZE_64MB;
	else
		page_size = PAGE_SIZE_2MB;

	count = shm_ent->size / page_size;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"page count %d\n", count);
	for (ent = 0; ent < count; ent++) {
		pgno = shm_ent->vemaa[ent];
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"setting page %ld free\n", pgno);
		vnode_info->ve_pages[pgno].flag |= PG_VE;
		vnode_info->ve_pages[pgno].flag &= (~PG_SHM);
		vnode_info->ve_pages[pgno].private_data = NULL;
		set_page_free(pgno, node_id, page_size);
	}

	list_del(&(shm_ent->shm_list));
	free(shm_ent);
	pthread_mutex_unlock(&vnode_info->shm_node_lock);
	return 0;
}

/**
* @brief This is core shmctl handler which destroy the shared memory
* segment.
*
* @param[in] shmid Shared memory unique ID
* @param[in] p_ve_task Pointer to VE process task_struct
*
* @return On success it returns 0 and -1 on failure
*/
int amm_do_shmctl(int64_t shmid, struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	int found = 0;
	struct shm *shm_ent = NULL;
	struct ve_node_struct *vnode_info;
	int node_id;

	node_id = p_ve_task->node_id;
	vnode_info = VE_NODE(node_id);

	/* Traverse the SHM list and find the shared memory
	 * segment.
	 */
	pthread_mutex_lock(&vnode_info->shm_node_lock);
	list_for_each_entry(shm_ent, &vnode_info->shm_head, shm_list) {
		if (shm_ent->shmid == shmid) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"SHM segment found!\n");
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&vnode_info->shm_node_lock);

	/* Mark the segment status as destroy */
	if (found)
		shm_ent->flag |= SHM_DEL;
	else
		goto exit1;
	/* If nattch of this segment is zero the remove the segment
	 * and release the physical pages.
	 */
	if (shm_ent->nattch == 0)
		amm_release_shm_segment(shm_ent, p_ve_task->node_id);

	retval = 0;
	return retval;
exit1:
	retval = -1;
	return retval;
}

/**
* @brief This is core shmdt handler which detaches the shared memory
* segment from VE process.
*
* @param[in] shmaddr VEMVA of shared memory segment
* @param[in] p_ve_task Pointer to VE process task struct
*
* @return On success it returns 0 and -1 on failure
*/
int amm_do_shmdt(uint64_t shmaddr, struct ve_task_struct *p_ve_task,
		struct shmdt_info *dt_info)
{
	int retval = -1;
	int ent, count, page_mode;
	atb_reg_t tmp_atb;
	uint64_t pgno, page_size;
	uint8_t dir_num, pgoff;
	struct shm *shm_segment = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(p_ve_task->node_id);
	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;

	/* Operation is done on copy of ATB to avoid any data
	 * loss.
	 */
	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));

	/*check if shm page or not*/
	shm_segment = del_shm_mapping_entry((void *)shmaddr, mm_struct);
	if (shm_segment == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Can't detach, Envalid shmaddr\n");
		dt_info->err = EINVAL;
		goto shmdt_ret;
	}

	/* TODO: Multipage support has to be added yet in shm*/
	page_size = PAGE_SIZE_2MB;
	page_mode = PG_2M;

	dt_info->size = shm_segment->size;
	count = shm_segment->size / page_size;

	for (ent = 0; ent < count; ent++) {
		dir_num =  search_atb_ps((char *)shmaddr, page_mode, &tmp_atb);
		if (-1 == dir_num) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"ATB Directory not available"
					"for vaddr %p\n", (void *)shmaddr);
			retval = -1;
			goto shmdt_ret;
		}

		pgoff = (page_mode == PG_2M) ? pgnum(shmaddr):pgnum_h(shmaddr);

		if ((ps_isvalid(&(tmp_atb.dir[dir_num]))))/* &&
				(pg_isvalid(&(tmp_atb.entry[dir_num][pgoff]))))*/
			pgno = pg_getpb(&(tmp_atb.entry[dir_num][pgoff]),
					page_mode);
		else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"ATB Entry is not valid!\n");
			retval = -1;
			goto shmdt_ret;
		}

		if (((vnode_info->ve_pages[pgno].flag & PG_SHM) != PG_SHM) ||
				(shm_segment->vemaa[ent] != pgno)) {
			shmaddr += page_size;
			continue;
		}

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"VEMVA %lx Released.\n", shmaddr);
		/*Reset ATB Entry*/
		memset(&(tmp_atb.entry[dir_num][pgoff]), 0,
				sizeof(tmp_atb.entry[dir_num][pgoff]));
		/* TODO:
		 * munmap changes should be here or Not?
		 */
		pg_invalid(&(tmp_atb.entry[dir_num][pgoff]));
		/* Update shm_segment natach*/
		pthread_mutex_lock(&shm_segment->shm_lock);
		shm_segment->nattch -= 1;
		pthread_mutex_unlock(&shm_segment->shm_lock);
		/* Update Page Reference count*/
		vnode_info->ve_pages[pgno].ref_count--;
		shmaddr += page_size;
		set_bit(dt_info->bitmap, ent);
	}

	/*
	 * On succcess update the ATB structure maintained in mm_struct
	 */
	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));

	pthread_mutex_unlock(&(mm_struct->mm_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SHMID %ld with attach now: %ld\n",
			shm_segment->shmid, shm_segment->nattch);

	/* Release the segment if flag is set as destroy.
	*/
	if ((shm_segment->flag & SHM_DEL) &&
			(shm_segment->nattch == 0)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"SHM destroy flag is set, ready to remove\n");
		/* Finally release the segment */
		amm_release_shm_segment(shm_segment, p_ve_task->node_id);
	}

	retval = 0;
	return retval;
shmdt_ret:
	pthread_mutex_unlock(&(mm_struct->mm_lock));
	return retval;
}

/**
* @brief This function will add an entry of struct shm_mapping in list.
*
* @param[in] shmaddr VEMVA of shm_segment in process virtual address space.
* @param[out] shm_segment Pointer to struct shm_segment.
* @param[in] mm_struct Pointer to mm_struct to fetch shm_mapping list head.
*
* @return Will return 0 on success and -1 on error.
*/
int insert_shm_mapping_entry(void *shmaddr, struct shm *shm_segment,
		struct ve_mm_struct *mm_struct)
{
	struct shm_mapping *shm_tmp;
	uint64_t page_size;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "insert_shm_mapping_entry\n");
	/**
	 * Traverse the SHM list and find the shared memory
	 * segment if already present.
	 */
	pthread_mutex_lock(&mm_struct->shm_lock);
	list_for_each_entry(shm_tmp, &mm_struct->shm_head, shm_list) {
		if ((shm_tmp->shmaddr == shmaddr) &&
				(shm_tmp->shm_segment == shm_segment)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"SHM mapping already in list\n");
			/*
			 * TODO: shm->nattch has not to be updated here
			 */
			goto exit1;
		}
	}

	/* Get page size */
	if (SHM_SEG_PAGE_SIZE_64MB == (shm_segment->flag &
				SHM_SEG_PAGE_SIZE_64MB))
		page_size = PAGE_SIZE_64MB;
	else
		page_size = PAGE_SIZE_2MB;

	/*create new shm_mapping and add to list*/
	shm_tmp = (struct shm_mapping *)malloc(sizeof(struct shm_mapping));
	if (NULL == shm_tmp) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails in allocating memory to shm segment\n");
		goto err_exit;
	}
	memset(shm_tmp, '\0', sizeof(struct shm_mapping));

	shm_tmp->shmaddr = shmaddr;
	shm_tmp->count = (shm_segment->size) / page_size;
	shm_tmp->shm_segment = shm_segment;

	list_add(&(shm_tmp->shm_list), &(mm_struct->shm_head));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"shm_list->shmaddr %p added in list\n",
			shm_tmp->shmaddr);

exit1:
	pthread_mutex_unlock(&mm_struct->shm_lock);
	return 0;
err_exit:
	pthread_mutex_unlock(&mm_struct->shm_lock);
	return -1;
}

/**
* @brief This Function will delete an entry of shm_mapping
* from shm_mapping_list after comparing with shmaddr.
*
* @param[in] shmaddr shmaddr to match with every instance of list.
* @param[in] mm_struct Pointer to mm_struct to fetch shm_mapping list head.
*
* @return Will return pointer to struct shm on success and NULL on error.
*/
struct shm *del_shm_mapping_entry(void *shmaddr,
		struct ve_mm_struct *mm_struct)
{
	struct shm_mapping *shm_tmp;
	struct shm *shm_segment;

	/**
	 * Traverse the SHM list and find the shared memory
	 * segment if already present.
	 */
	pthread_mutex_lock(&mm_struct->shm_lock);
	list_for_each_entry(shm_tmp, &mm_struct->shm_head, shm_list) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"shm_list->shmaddr %p\n", shm_tmp->shmaddr);
		if (shm_tmp->shmaddr == shmaddr) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"SHM mapping found\n");
			goto done;
		}
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "No shm_mapping with"
			"shmaddr %p found in list\n",
			shmaddr);
	pthread_mutex_unlock(&mm_struct->shm_lock);
	return NULL;
done:
	shm_segment = shm_tmp->shm_segment;
	list_del(&shm_tmp->shm_list);
	free(shm_tmp);

	pthread_mutex_unlock(&mm_struct->shm_lock);
	return shm_segment;
}
