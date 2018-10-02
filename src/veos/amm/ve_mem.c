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
/**
 * @file ve_mem.c
 * @brief AMM core functions which manages the VE memory.
 *
 * @internal
 * @author AMM
 */
#include <unistd.h>
#include <sys/mman.h>
#include "ve_shm.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "task_signal.h"
#include "dmaatb_api.h"
#include "vehva_mgmt.h"
#include "cr_api.h"
#include "veos_ived.h"
#include "pciatb_api.h"
#include "pmap.h"
#include "buddy.h"

static bool mean_heap;
heap heap_min_array[MAX_JID_PROCESS];
int hash[MAX_JID_PROCESS];
struct jid_data jid_globl = {.mtx = PTHREAD_MUTEX_INITIALIZER};
static struct ve_dirty_page dirty_page;
static pthread_t clear_mem_th;

/**
 * @brief structure for dirty pages
 */
struct ve_dirty_pg_list {
	struct list_head head;	/*!< list head for dirty page */
	pgno_t pgno;		/*!< page number of dirty page */
	int pgmod;		/*!< page mode of dirty page */
	size_t pgsz;		/*!< page size of dirty page */
};

/**
 * @brief contain ve dirty page details
 */
struct ve_dirty_page {
	struct ve_dirty_pg_list dirty_pg_list;	/*!< list head for dirty page */
	pthread_mutex_t ve_dirty_pg_lock;	/*!< mutex lock for dirty_pg_list */
	pthread_cond_t ve_dirty_pg_cond;	/*!< Conditional lock for clearing dirty pages */
						/* protected by ve_dirty_pg_lock */
};

/**
* @brief coredump creation
* Function writes the coredump in elf format.
* Checks whther coredump is interrupted by SIGINT signal.
* Checks dump file size does not exceeds the core file limit.
*
* @param[in] ve_cprm Stores the dump information required for core dump
*
* @return true on success and false on failure.
*/
bool ve_elf_core_dump(struct dump_params *ve_cprm)
{
	bool ret = false;

	VEOS_TRACE("invoked");
	ret  = generate_core_dump(ve_cprm);
	VEOS_TRACE("returning: %s", ret ? "true":"flase");
	return ret;
}

/**
* @brief This routine create new ve_mm_struct to the VE process.
*
* @param mm_struct[out] Double pointer to mm_struct
*
* @return On success return 0 and negative of errno on failure.
*/
int amm_alloc_mm_struct(struct ve_mm_struct **mm)
{
	int ret = 0;

	VEOS_TRACE("invoked");
	/*
	 * Allocating memory for ve_mm_struct
	 */
	*mm = (struct ve_mm_struct *)calloc
			(1, sizeof(struct ve_mm_struct));
	if (NULL == *mm) {
		VEOS_CRIT("failed to allocate mm struct");
		return ret;
	}

	VEOS_DEBUG("mm struct(%p) allocated", *mm);

	ret =  __amm_alloc_mm_struct(mm);
	if (0 > ret) {
		VEOS_DEBUG("Fails to alloc mm struct");
		goto amm_alloc_mm_error;
	}
	/*
	 * Initializing pthread mutex for synchronization
	 */
	ret = pthread_mutex_init(&((*mm)->thread_group_mm_lock), NULL);
	if (0 != ret) {
		ret = -ret;
		VEOS_DEBUG("Error (%s) while initializing mm lock",
				strerror(-ret));
		goto amm_alloc_mm_error;
	}

	return ret;

amm_alloc_mm_error:
	free(*mm);
	return ret;
}

/**
* @brief This routine copies the old mm_struct to new mm_struct
*        based on the flag received.
*
* @param[in] mm_old Pointer to old mm_struct
* @param[in,out] mm_new Double pointer to new mm_struct
* @param[in] node_id Node ID
* @param[in] flag Distinguish b/w thread or process and type of memory mapping
*
* @return On success return 0 and and negative of errno on failure.
*/
int amm_copy_mm_struct(struct ve_mm_struct *mm_old,
		struct ve_mm_struct **mm_new,
		int flag)
{
	ret_t ret = 0;
	struct ve_mm_struct *mm = NULL;
	struct shm_map *shm_tmp = NULL, *tmp = NULL;

	VEOS_TRACE("invoked");
	VEOS_TRACE("copy mm from(%p) to (%p)",
		mm_old, mm_new);

	switch (flag) {
	/* THREAD mm descriptor handling*/
	case REQUEST_FOR_PROCESS_SHARED:
		VEOS_DEBUG("mm shared between thread tsks");
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				LOCK, "Failed to acquire mm-thread-group-lock");
		mm_old->ref_count++;
		*mm_new = mm_old;
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				UNLOCK, "Failed to release mm-thread-group-lock");
		VEOS_DEBUG("old mm(%p) refcnt(%lu)",
				mm_old, mm_old->ref_count);
		break;
	case REQUEST_FOR_PROCESS_PRIVATE:
		VEOS_DEBUG("request to replicate mm for new tsk");
		/*
		 * Allocation for new mm_struct
		 */
		ret = amm_alloc_mm_struct(mm_new);
		if (0 > ret) {
			VEOS_CRIT("fails to allocate mm struct");
			return ret;
		}
		mm = *mm_new;
		memcpy(mm->veshm, mm_old->veshm, sizeof(mm->veshm));
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				LOCK, "Failed to acquire mm-thread-group-lock");

		ret = copy_shm_list(mm_old, mm);
		if (ret) {
			VEOS_DEBUG("Error (%s) while copying shared segment list",
					strerror(-ret));
			pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
					UNLOCK,
					"Failed to release mm-thread-group-lock");
			return ret;
		}

		ret = amm_copy_atb_private(&(mm_old->atb),
				&(mm->atb), mm->veshm);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while copying process pgtables",
					strerror(-ret));
			/** Traverse the SHM list and delete list */
			list_for_each_entry_safe(shm_tmp, tmp, &(mm->shm_head), shm_list) {
				VEOS_DEBUG("In shm list current mapping %p with vemva 0x%lx",
						shm_tmp, shm_tmp->shmaddr);
				list_del(&(shm_tmp->shm_list));
				free(shm_tmp);
				shm_tmp = NULL;
			}
			pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
					UNLOCK,
					"Failed to release mm-thread-group-lock");
			return ret;
		}

		amm_copy_mm_data(mm_old, mm);


		VEOS_DEBUG("old atb(%p) and new atb(%p)",
				&(mm_old->atb),
				&(mm->atb));
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				UNLOCK, "Failed to release mm-thread-group-lock");
		break;
	case REQUEST_FOR_VFORK_PROCESS:
		VEOS_DEBUG("request to replicate mm for new tsk (vfork)");
		/*
		 * Allocation for new mm_struct
		 */
		ret = amm_alloc_mm_struct(mm_new);
		if (0 > ret) {
			VEOS_CRIT("fails to allocate mm struct");
			return ret;
		}
		mm = *mm_new;
		memcpy(mm->veshm, mm_old->veshm, sizeof(mm->veshm));
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				LOCK, "Failed to acquire mm-thread-group-lock");

		VEOS_DEBUG("old atb(%p) and new atb(%p)",
				&(mm_old->atb),
				&(mm->atb));
		amm_copy_atb_vfork(&(mm_old->atb),
				&(mm->atb), mm->veshm);
		amm_copy_mm_data(mm_old, mm);

		ret = copy_shm_list(mm_old, mm);
		if (ret) {
			VEOS_DEBUG("Error (%s) while copying shared segment list",
					strerror(-ret));
			pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
					UNLOCK,
					"Failed to release mm-thread-group-lock");
			return ret;
		}
		pthread_mutex_lock_unlock(&mm_old->thread_group_mm_lock,
				UNLOCK, "Failed to release mm-thread-group-lock");
		break;
	default:
		ret = -EINVAL;
		VEOS_DEBUG("Invalid mm copy operation");
		return ret;;
	}
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This routine delete the ve_mm_struct corresponding to pid when process ends
*
* @param[in] tsk process ve task struct.
*
* @return On success return 0 and negative errno on failure.
*/
int amm_del_mm_struct(struct ve_task_struct *tsk)
{
	ret_t ret = 0;
	struct ve_mm_struct *mm = NULL;

	VEOS_TRACE("invoked");

	mm = tsk->p_ve_mm;

	/*Get mm_struct_lock here*/
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire mm-thread-group-lock");
	/*
	 * Decrement the reference count.
	 */
	(mm->ref_count)--;
	VEOS_DEBUG("mm(%p) with refcnt(%lu)",
			mm, mm->ref_count);
	if (0 < mm->ref_count) {
		/*
		 * Since this mm_struct is used by other
		 * thread also, so just decrement the
		 * reference count and return successfully.
		 */
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release mm-thread-group-lock");
		return ret;
	}

	ret = __amm_del_mm_struct(tsk);
	if (0 > ret) {
		VEOS_DEBUG("Fails to del mm_struct");
		goto err_exit;
	}

	ret = 0;
	/*Release mm_struct_lock here*/
err_exit:
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release mm-thread-group-lock");
	free(mm);
	tsk->p_ve_mm = NULL;
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This routine clears the VE physical memory page of 2MB.
 *
 * @param[out] pgno Page number.
 * @paran[in] pgsz Size of the page.
 *
 * @return On success return 0 and and negative of errno on failure.
 */
ret_t amm_clear_page(uint64_t pgno, size_t pgsz)
{
	ret_t ret = 0;
#if 1
	struct ve_node_struct *vnode = VE_NODE(0);
	vemaa_t pb = 0;

	VEOS_TRACE("invoked");
	pb = pbaddr(pgno, PG_2M);

	VEOS_DEBUG("clearing vemaa 0x%lx size: %p Zeroed Page Addr: 0x%lx",
			pb, (void *)pgsz, vnode->zeroed_page_address);

	/* Request for DMA transfer, 2MB size at a time */
	ret = memcpy_petoe(vnode->zeroed_page_address, pb, pgsz);
	if (0 > ret)
		VEOS_DEBUG("DMA failed to send data to VE mem");
#endif
	return ret;
}

/**
* @brief This function is used to initilaize the given VE memory address to zero.
*
* @param[in] pb VE physical page base address.
*
* @return on success return 0 and negative of errno on failure.
*/
int amm_initialize_zeroed_page(vemaa_t pb)
{
	int ret = 0;
	int src_pid = getpid();
	vhva_t *hst_buff = NULL;

	VEOS_TRACE("invoked");
	hst_buff = calloc(1, PAGE_SIZE_64MB);
	if (NULL == hst_buff) {
		VEOS_CRIT("failed to allocate vehva of %s size",
			pgsz_to_pgstr(PAGE_SIZE_64MB));
		ret = -ENOMEM;
		return ret;
	}

	/* Request for DMA transfer, 2MB size at a time */
	ret = mlock(hst_buff, PAGE_SIZE_64MB);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) in host mlock() on vhva %p",
			strerror(-ret), hst_buff);
		free(hst_buff);
		return ret;
	}

	ret = amm_dma_xfer(VE_DMA_VHVA, (int64_t)hst_buff, src_pid,
			VE_DMA_VEMAA, pb, 0, PAGE_SIZE_64MB, 0);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in data from vhva %p and vemaa(0x%lx)",
				strerror(-ret), hst_buff, pb);
	}

	ret = munlock(hst_buff, PAGE_SIZE_64MB);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while mlock() vhva 0x%lx",
			strerror(-ret), pb);
		free(hst_buff);
		return ret;
	}
	free(hst_buff);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will free AMM resources.
*/
void veos_amm_fini(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int64_t pgmod = -1;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("freeing node mem resources");

	/*free page which  was reserved clearing VE memory*/
	veos_dump_cr(NULL, ALL);
	veos_dump_ve_pages();

	if (!vnode->ve_pages) {
		VEOS_DEBUG("no dump information available");
		return;
	}
	veos_delloc_memory(vnode->zeroed_pfn, PG_HP);
	--vnode->mp->huge_page_used;

	pgmod = pgsz_to_pgmod(vnode->ve_pages[vnode->vdso_pfn]->
		pgsz);

	if (pgmod == PG_2M)
		--vnode->mp->small_page_used;
	else
		--vnode->mp->huge_page_used;

	/*free page which was reserved for vdso*/
	veos_delloc_memory(vnode->vdso_pfn, pgmod);
	if (vnode->ve_cr_pages)
		free(vnode->ve_cr_pages);
	vnode->ve_cr_pages = NULL;

	if (vnode->node_cr_rlim)
		free(vnode->node_cr_rlim);
	vnode->node_cr_rlim = NULL;



	VEOS_DEBUG("================ PCI BUDDY DUMP =================");
	buddy_dump_mempool(vnode->pci_mempool);
	VEOS_DEBUG("================ AMM BUDDY DUMP =================");
	buddy_dump_mempool(vnode->mp);
	pthread_mutex_destroy(&vnode->mp->buddy_mempool_lock);
	pthread_mutex_destroy(&vnode->ve_pages_node_lock);

	/*Deinitialized VE buddy mempool*/
	buddy_deinit(vnode->mp);

	VEOS_DEBUG("mem resources freed");
}

/**
* @brief This function will clear whole VE physical memory .
*
* @param[in] memsz total ve phyical memory size.
*
* @return on success return 0 and negative of errno on failure.
*/
ret_t amm_mem_clear(size_t memsz)
{
	ret_t ret = 0;
	uint64_t index = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("Clearing VE memory of size 0x%lx", memsz);

	/*Considring memsz multiple of VE_DMA_DESC_LEN_MAX always*/
	for (index = 0; memsz > 0; index++) {
		/* check for terminate flag */
		if (terminate_flag) {
			ret = -EINTR;
			return ret;
		}

		/* Clear the physical pages */
		ret = dma_clear_page(index * HUGE_PAGE_IDX);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) in creating dma_clear_page",
					strerror(-ret));
			return ret;
		}
		memsz -= VE_DMA_DESC_LEN_MAX;
	}
	return ret;
}

/**
* @brief function to Clear a page of VE memory using DMA.
*
* @param[in] index page number.
*
*/
ret_t dma_clear_page(uint64_t index)
{
	return amm_clear_page(index, PAGE_SIZE_64MB);
}

/**
* @brief This routine enables paging in VE node and divide PHY memory
*        into chunks of pages.
*
* @param[in] handle VEDL handle.
*
* @return On success return 0 and negative of errno on failure.
*/
int veos_amm_init(vedl_handle *handle)
{
	int ret = 0;
	vemaa_t paddr = 0;
	int index = 0;
	struct file_stat stat = { {0} };
	struct ve_node_struct *vnode = VE_NODE(0);
	pgno_t *map = NULL;

	vnode->ve_pages = NULL;	/*set to NULL*/

	VEOS_TRACE("invoked");
	ret = vedl_get_mem_info(handle, &(vnode->mem));
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) fetching node memory info",
				strerror(-ret));
		return ret;
	}

	VEOS_DEBUG("VE Node: Physical Start ADDR: 0x%lx End ADDR: 0x%lx",
			(vnode->mem).ve_mem_addr,
			(vnode->mem).ve_mem_addr + (vnode->mem).ve_mem_size);

	/* Invalidate node DMAATB s/w image*/
	invalidate_dmaatb(&(vnode->dmaatb));

	/* SYNC DMATB with hardware */
	ret = vedl_update_dmaatb_all(handle, VE_CORE_CNT_REG_ADDR(0),
			&(vnode->dmaatb));
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while syncing node dmaatb",
				strerror(-ret));
		return ret;
	}

	VEOS_DEBUG("Paging init for "
			"VE memory of size 0x%lx",
			(vnode->mem).ve_mem_size);
	/*
	 * If some reserved area is allocated to NODE then VE node PHY
	 * MEM map start that will be really available for paging will
	 * be different this code assumes start from 0th address,
	 * Allocated nr_pages depends whether the usable memory size for
	 * paging needs to be 2MB divisble if not then remaining memory
	 * chunk will always be unused so that information also needs to
	 * be maintained in VE node instance (BUDDY ALLOCATOR will take care
	 * of this).
	 */
	vnode->mp = veos_buddy_init((uint64_t)(vnode)->mem.ve_mem_addr,
			(vnode)->mem.ve_mem_size, PAGE_SIZE_2MB);
	if (vnode->mp == NULL) {
		ret = -ENOMEM;
		VEOS_DEBUG("Error(%s) while initializing buddy mempool", strerror(-ret));
		return ret;
	}
	vnode->nr_pages = vnode->mp->total_pages;
	paddr = (vnode->mem).ve_mem_addr;

	/* One page of size 2MB is reserved whose content is zero
	 * and will be used as a reference to clear every page of
	 * VE memory.
	 * Yes, this method is wasting One physical page of size 64MB.
	 * Need to incorporate more efficient method.
	 */
	vnode->zeroed_page_address = paddr;

	VEOS_DEBUG("Physical address (0x%lx) for rsvd page to clean mem",
			vnode->zeroed_page_address);

	/* It will initialize to zeroed page.
	*/
	ret = amm_initialize_zeroed_page(
			vnode->zeroed_page_address);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while initializing zeroed page",
			strerror(-ret));
		goto err;
	}

	/*
	 * Info regarding the physical memory that is reserved from 0 to
	 * start address in term of 2MB page size.
	 */

	/*allocate memory for VE page array*/
	vnode->ve_pages = calloc(vnode->nr_pages, (sizeof(struct ve_page *)));
	if (NULL == vnode->ve_pages) {
		VEOS_DEBUG("calloc failed to allocate memory for VE page array");
		ret = -ENOMEM;
		return ret;
	}

	/*initialized whole ve_pages array with 0*/
	for (index = 0; index < vnode->nr_pages; index++)
			vnode->ve_pages[index] = NULL;


	pthread_mutex_init(&vnode->mp->buddy_mempool_lock, NULL);
	pthread_mutex_init(&vnode->ve_pages_node_lock, NULL);


	/* we will allocated first page to veos.
	 * Buddy allocator will alway give first
	 * page form start address on first request.
	 * Here we will reserve two pages.*/
	map = (pgno_t *)calloc(sizeof(uint64_t), 2);
	if (map == NULL) {
		ret = -errno;
		VEOS_CRIT("calloc failed (%s) to allocate rsvd page array",
			strerror(-ret));
		goto error;
	}

	/*Reserve Zeroed page*/
	ret = veos_alloc_memory(vnode->mp,
				PAGE_SIZE_64MB, PG_HP);
	if (0 > ret) {
		VEOS_DEBUG("Failed to reserve zeroed page for VEOS");
		free(map);
		goto error;
	}
	veos_page_entry(vnode->mp, PG_HP, map);
	vnode->zeroed_pfn = map[0];
	vnode->ve_pages[map[0]]->flag |= MAP_ANON;
	VEOS_DEBUG("VE page %ld rsvd as zeroed page", map[0]);
	map[0] = 0;
	/*Reserve VDSO*/
	if (0 != veos_alloc_memory(vnode->mp,
				PAGE_SIZE_2MB, PG_2M)) {
		VEOS_DEBUG("Failed to reserve page for VEOS");
		free(map);
		ret = -1;
		goto error;
	}
	veos_page_entry(vnode->mp, PG_2M, map);
	vnode->vdso_pfn = map[0];
	vnode->ve_pages[map[0]]->flag |= MAP_ANON;
	map[0] = pbaddr(map[0], PG_2M);
	map[1] = 0;
	amm_get_page(map);
	VEOS_DEBUG("VE page %ld rsvd for quick calls (VDSO)", map[0]);

	free(map);

	fprintf(stderr, "Clearing VE memory\n");
	fflush(stderr);
	/* Clear the physical pages */
	ret = amm_mem_clear((vnode->mem).ve_mem_size);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in clearing VE memory",
			strerror(-ret));
		goto err;
	}
	fprintf(stderr, "\rVE Memory Cleared\n");
	/*Init CR related data*/
	ret = amm_init_node_cr_data(vnode);
	if (0 > ret) {
		VEOS_DEBUG("Failed to initialize node CR data");
		goto error;
	}
	/*Initialise CR registors*/
	ret = amm_init_cr_reg();
	if (0 > ret) {
		VEOS_DEBUG("Failed to initialize CR cluster set");
		goto error;
	}

	/*Initialise PCIATB*/
	ret =  amm_init_pciatb(vnode);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in PCIATB invalidate",
				strerror(-ret));
		goto error;
	}

	/*Initialise dirty page struct and create thread*/
	ret = dirty_page_init(vnode, &clear_mem_th);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in initializing for dirty page",
			strerror(-ret));
		goto error;
	}

	/*Allocate pcientry for VDSO page*/
	ret = veos_alloc_vdso_pcientry(0, 1);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in allocating PCIATB entry for VDSO",
			strerror(-ret));
		goto error;
	}

	/*File Backed mmap global list initlization*/
	memset(&stat, '\0', sizeof(stat));
	vnode->file_desc_start = init_file_desc(&stat);
	INIT_LIST_HEAD(&vnode->file_desc_start->global_list);
	INIT_LIST_HEAD(&vnode->shm_head);

	memset(hw_dma_map, 0, sizeof(hw_dma_map));
	for (index = 0; index < DMAATB_DIR_NUM; index++) {
		hw_dma_map[index].count = 0;
	}
	/* intilize jid structure */
	ret = veos_jid_init();
	if (0 > ret) {
		VEOS_DEBUG("veos_jid_init() failed."
				"Exiting veos...");
		goto error;
	}

	/*Dump buddy mempool here*/
	VEOS_DEBUG("============== INIT VE MEMPOOL DUMP  =============");
	buddy_dump_mempool(vnode->mp);
	/*Dump pci buddy mempool here*/
	VEOS_DEBUG("============== INIT PCI MEMPOOL DUMP  =============");
	buddy_dump_mempool(vnode->pci_mempool);
	return ret;
error:
	buddy_deinit(vnode->mp);
	pthread_mutex_destroy(&vnode->mp->buddy_mempool_lock);
	pthread_mutex_destroy(&vnode->ve_pages_node_lock);
err:
	return ret;
}

/**
* @brief This is generic mmap handler which allocates VE PHY memory and maintains ATB.
*
* @param[in] vaddr VE virtual address for which physical page need to be mapped.
* @param[in] size total size to be mapped.
* @param[in] perm permission to be set after allocating VE physical memory.
* @param[in] flags specifying that which type of allocation is this(shared/private) and
*		also mapping is with huge page or large page.
* @param[in] tsk process tast struct.
* @param[in] file  file statastics in case of mapping is file backed .
*
* @return on success return 0 and negative of errno on failure.
*/
int amm_do_mmap(vemva_t vaddr, size_t size, prot_t perm,
		flag_t flags, struct ve_task_struct *tsk,
		struct file_stat *file)
{
	uint64_t bpc = 0, count = 0;
	uint64_t start = 0;
	size_t pgsz = 0;
	ret_t ret = 0, ret_err = 0;
	int pgmod = 0;
	int rw = 0, i = 0;
	pgno_t *map = NULL;
	atb_reg_t tmp_atb = { { { {0} } } };
	vemva_t taddr = 0;
	off_t off_s = 0;
	off_t off_e = 0;
	int64_t foe = 0;
	vemaa_t *pb = NULL;
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct file_desc *fdesc = NULL, *fdesc_t = NULL;
	dir_t dirs[ATB_DIR_NUM] = {0};
	dir_t dir_num = 0, prv_dir = -1;
	struct list_head *temp = NULL;
	bool found = false;

	VEOS_TRACE("invoked");

	memset(dirs, -1, sizeof(dirs));


	VEOS_DEBUG("map vemva(%lx) of size(%lu) with"
			"%s and flags %ld fstat(%p) for tsk:pid(%d)",
			vaddr, size, perm_to_str(perm), flags,
			file, tsk->pid);

	VEOS_DEBUG("tsk(%p):pid(%d): actual rss limit(%ld) and"
			"current rss limit(%ld)",
			tsk, tsk->pid,
			tsk->sighand->rlim[RLIMIT_RSS].rlim_cur,
			tsk->p_ve_mm->rss_cur);
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			LOCK, "Failed to acquire mm-thread-group-lock");
	if (tsk->sighand->rlim[RLIMIT_AS].rlim_cur <
			(rlim_t)(tsk->p_ve_mm->vm_size + size)) {
		VEOS_DEBUG("tsk address space limit exceeds current map"
				"request");
		ret = -ENOMEM;
		goto mmap_error;
	}

	if (flags & MAP_STACK) {
		if (tsk->sighand->rlim[RLIMIT_STACK].rlim_cur <
				(rlim_t)(tsk->p_ve_mm->rss_stack + size)) {
			VEOS_DEBUG("tsk stack limit exceeds");
			ret = -ENOMEM;
			goto mmap_error;
		}
	}

	if ((flags & MAP_ADDR_SPACE) && !(flags & MAP_STACK) &&
			(perm & PROT_WRITE) && (mm->brk)) {
		VEOS_DEBUG("vaddr = 0x%lx size = 0x%lx mm->brk = 0x%lx"
				"Align data segment = 0x%lx rlim_cur = %lx",
				vaddr, size,mm->brk,ALIGN((mm->end_data - mm->start_data), mm->pgsz)
				,tsk->sighand->rlim[RLIMIT_DATA].rlim_cur);
		if (tsk->sighand->rlim[RLIMIT_DATA].rlim_cur <
				RLIM_INFINITY) {
			if ((((vaddr + size) - mm->brk) +
					ALIGN((mm->end_data - mm->start_data), mm->pgsz)) >
					tsk->sighand->rlim[RLIMIT_DATA].rlim_cur) {
					VEOS_DEBUG("tsk data limit exceeds");
					ret = -ENOMEM;
					goto mmap_error;
				}
			}
	} else if ((flags & MAP_ADDR_SPACE) && !(flags & MAP_STACK) &&
			(perm & PROT_WRITE)) {
		if (tsk->sighand->rlim[RLIMIT_DATA].rlim_cur <
				(rlim_t)(tsk->p_ve_mm->rss_data + size)) {
			VEOS_DEBUG("tsk data limit exceeds");
			ret = -ENOMEM;
			goto mmap_error;
		}
	}

	if ((flags & MAP_64MB) && (flags & MAP_VDSO)) {
		VEOS_DEBUG("invalid argument");
		ret = -EINVAL;
		goto mmap_error;
	}
	memset(&tmp_atb, 0, sizeof(tmp_atb));
	/*
	 * size should be aligned as per the page size requested
	 */
	if (flags & MAP_64MB) {
		pgsz = PAGE_SIZE_64MB;
		pgmod = PG_HP;
	} else {
		pgsz = PAGE_SIZE_2MB;
		pgmod = PG_2M;
	}

	count = (size / pgsz);

	if (!(flags & MAP_ANON)) {
		VEOS_DEBUG("file size as per stat is %ld",
			file->stat.st_size);
		foe = file->stat.st_size/pgsz - 1;
		if (file->stat.st_size%pgsz)
			++foe;
		VEOS_DEBUG("end file offset is %ld", foe);
	}

	/*Is writable permission request received ? */
	if (perm & PROT_WRITE)
		rw = 1;
	else if (perm == PROT_NONE)
		rw = -1;

	VEOS_DEBUG("tsk:pid(%d) requested %lu %s for mmap with vemva (%lx)",
		tsk->pid, count, pgmod_to_pgstr(pgmod),
		vaddr);

	map = (pgno_t *)malloc(count * (sizeof(uint64_t)));
	if (NULL == map) {
		VEOS_CRIT("failed to allocate page map to hold VE pages");
		ret = -ENOMEM;
		goto mmap_error;
	}
	memset(map, 0xff, (count * (sizeof(uint64_t))));

	VEOS_TRACE("allocated map(%p) of count(%lu) pages",
			map, count);


	if (!(MAP_ANON & flags) && ((MAP_SHARED & flags) ||
				(!(perm & PROT_WRITE)))) {
		/*Scan Global file_mapping list*/
		off_s = file->offset_start;
		off_e = file->offset_end;
		if (foe < (int64_t)off_s)
			goto map_sigbus;
		else if ((int64_t)off_e > foe)
			off_e = (off_t)foe;

		pthread_mutex_lock_unlock(&vnode->pgcache_lock,
				LOCK, "Failed to acquire pgcache_lock");
		fdesc = scan_global_list(file, flags);
		if (NULL == fdesc) {
			VEOS_DEBUG("tsk:pid(%d) fails to get or alloc file desc",
				tsk->pid);
			pthread_mutex_lock_unlock(&vnode->pgcache_lock,
					UNLOCK, "Failed to release pgcache_lock");
			ret = -ENOMEM;
			goto mmap_error;
		}
		pthread_mutex_lock_unlock(&fdesc->f_desc_lock,
				LOCK, "Failed to acquire f_desc_lock");
		pthread_mutex_lock_unlock(&vnode->pgcache_lock,
				UNLOCK, "Failed to release pgcache_lock");

		ret = amm_do_file_back_handling(vaddr, fdesc, off_s,
				off_e, pgmod, tsk, map);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while handling file map req",
					strerror(-ret));
			pthread_mutex_lock_unlock(&fdesc->f_desc_lock,
					UNLOCK, "Failed to release f_desc_lock");

			/* Check if the failure is of new created file stat
			 * then remove the file stat.
			 */
			pthread_mutex_lock_unlock(&vnode->pgcache_lock,
					LOCK, "Failed to acquire pgcache_lock");
			list_for_each(temp, &vnode->file_desc_start->global_list) {
				fdesc_t = list_entry(temp, struct file_desc,
						global_list);
				if (fdesc_t == fdesc) {
					found = true;
					break;
				}
			}

			if (found) {
				pthread_mutex_lock_unlock(&fdesc->f_desc_lock,
						LOCK, "Failed to acquire f_desc_lock");

				if (!fdesc->in_mem_pages) {
					VEOS_DEBUG("Found and removing inode: %ld",
							fdesc->stat.st_ino);
					free_file_desc(fdesc);
				} else {
					pthread_mutex_lock_unlock(&fdesc->f_desc_lock,
							UNLOCK, "Failed to release f_desc_lock");
				}
			}
			pthread_mutex_lock_unlock(&vnode->pgcache_lock,
					UNLOCK, "Failed to release pgcache_lock");
			goto mmap_error;
		}
		pthread_mutex_lock_unlock(&fdesc->f_desc_lock,
				UNLOCK, "Failed to release f_desc_lock");
	} else {
		if (!(flags & MAP_ANON)) {
			off_s = file->offset_start;
			off_e = file->offset_end;
			if ((int64_t)off_e > foe)
				off_e = (off_t)foe;
			bpc = (off_e - off_s) + 1;
		} else
			bpc = count;

		VEOS_DEBUG("Back page count is %ld", bpc);
		if (!bpc) {
			VEOS_DEBUG("Back page count is %ld", bpc);
			goto map_sigbus;
		}

		/* VDSO handling */
		if (flags & MAP_VDSO) {
			map[0] = vnode->vdso_pfn;
			VEOS_DEBUG("%ld page number reserved for vdso",
				vnode->vdso_pfn);
		} else {
			/**
			 * When alloc_ve_pages fails to allocate VE
			 * physical page then it means VE node does
			 * not have enough memory at this time
			 * ENOMEM will be returned instead of EFAULT(TBD)
			 */
			ret = alloc_ve_pages(bpc, map, pgmod);
			if (0 > ret) {
				VEOS_DEBUG("Error (%s) while allocating VE mem",
						strerror(-ret));
				goto mmap_error;
			}
		}

		pb = (vemaa_t *)calloc((bpc + 1), (sizeof(uint64_t)));
		if (NULL == pb) {
			VEOS_CRIT("failed to allocate page base map for %ld pages",
					(bpc+1));
			ret = -ENOMEM;
			goto mmap_error;
		}
		/*Convert page number into physical address*/
		for (start = 0; start < bpc; start++)
			pb[start] = pbaddr(map[start], PG_2M);

		/*Increament the ref count of all newly allocate pages*/
		amm_get_page(pb);
	}

	/*Get mm_struct_lock here*/
map_sigbus:
	memcpy(&tmp_atb, &(mm->atb), sizeof(atb_reg_t));

	/**
	 * Below loops are only for assigning virtual address to
	 * VE PHY pages and certain calculations to fill ATB
	 */

	i = 0;
	for (start = 0; start < count; start++) {
		taddr = vaddr + (start * pgsz);
		VEOS_DEBUG("vemva %lx is heap or anon type",
				taddr);
		/*Here we are updating flag and perm field
		 * of struct ve_page as received from mmap
		 */
		if (0 <= map[start]) {
			mm->rss_cur += pgsz;
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
					LOCK, "Failed to acquire ve page lock");
			VE_PAGE(vnode, map[start])->flag = flags;
			VE_PAGE(vnode, map[start])->perm = perm;
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
					UNLOCK, "Failed to release ve page lock");
		}

		dir_num = validate_vemva(taddr, rw, map[start], &tmp_atb, pgmod);
		if (0 > dir_num) {
			ret = dir_num;
			VEOS_DEBUG("Error (%s) while validating vemva %lx",
				strerror(-ret), (taddr));
				goto mmap_error1;
		}

		VEOS_TRACE("prv pgd(%d) and pgd(%d)", prv_dir, dir_num);
		if (prv_dir == -1 || (prv_dir != dir_num))
			dirs[i++] = dir_num;
		prv_dir = dir_num;
	}


	/*for private file backed mappings*/
	if (!(flags & MAP_ANON) && (flags & MAP_PRIVATE) && bpc) {
		ret = send_file_data(vaddr,
				off_s, file->stat.st_size,
				tsk, size, pgsz, map);
		if (0 > ret) {
			VEOS_DEBUG("Error while syncing file data to ve mem");
			goto mmap_error1;
		}
	}

	memcpy(&(mm->atb), &tmp_atb, sizeof(atb_reg_t));
	i = 0;
	while (0 <= dirs[i]) {
		psm_sync_hw_regs(tsk, _ATB, (void *)&mm->atb,
				true, dirs[i++], 1);
	}

	if (flags & MAP_ADDR_SPACE) {
		if (flags & MAP_STACK)
			mm->rss_stack += size;
		if ((perm & PROT_WRITE) && !(flags & MAP_STACK))
			mm->rss_data += size;
	}
	if (flags & MAP_ANON)
		pgsz == PAGE_SIZE_2MB ? mm->anon++ :
			mm->anonhuge++;

	if (MAP_SHARED & flags)
		mm->shared_rss += size;

	mm->vm_size += size;
	if (mm->rss_max < mm->rss_cur)
		mm->rss_max =  mm->rss_cur;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			UNLOCK, "Failed to release mm-thread-group-lock");

	if (pb)
		free(pb);
	free(map);
	VEOS_TRACE("returned");
	return ret;
mmap_error1:
	ret_err = ret;
	for (i = 0; i < count ; i++) {
		if (0 < map[i]) {
			VEOS_DEBUG("freeing page %ld", map[i]);
			ret = amm_put_page(pbaddr(map[i], PG_2M));
			if (0 > ret)
				VEOS_DEBUG("Error (%s) while dropping \
						page(%ld)",
						strerror(-ret), map[i]);
		}
	}
	ret = ret_err;

mmap_error:
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			UNLOCK, "Failed to release mm-thread-group-lock");
	if (pb)
		free(pb);
	if (map)
		free(map);
	return ret;
}

/**
* @brief This function will unmaps the VE physical memory corresponding to given vemva.
*
* @param[in] vaddr VE virtual address to be unmapped.
* @param[in] size total size to be unmapped.
* @param[in] tsk process task struct.
* @param[in] veshm determines munmap from veshm or not.
*
* @return On success it returns 0 and negative of errno on failure.
*/
int amm_do_munmap(vemva_t vaddr, size_t size,
		struct ve_task_struct *tsk, bool veshm)
{
	dir_t dir_num = 0;
	ret_t ret = 0;
	int pgmod = -1;
	size_t pgsz = 0;
	vemaa_t pb = 0;
	atb_reg_t tmp_atb = { { { {0} } } };
	pgno_t pgno = 0;
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	struct ve_node_struct *vnode = VE_NODE(0);
	ssize_t tmp_size = 0;
	int i = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("unmap tsk:pid(%d) vemva 0x%lx of size %ld",
		tsk->pid, vaddr, size);
	VEOS_TRACE("tsk(%p) and mm(%p)", tsk, mm);

	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	memset(dirs, -1, sizeof(dirs));

	/*Get mm_struct_lock here*/
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");
	memcpy(&tmp_atb, &(mm->atb), sizeof(atb_reg_t));


	tmp_size = size;

	while (0 < tmp_size) {
		vaddr += pgsz;
		pb = (int64_t)__veos_virt_to_phy(vaddr,
				&tmp_atb, NULL, &pgmod);
		if (0 > pb) {
			VEOS_DEBUG("vemva 0x%lx not valid", vaddr);
			pgsz = (size_t)((pgmod == PG_HP) ?
				PAGE_SIZE_64MB : (pgmod == PG_2M) ?
				PAGE_SIZE_2MB : CHUNK_512MB);
			tmp_size -= pgsz;
			dir_num = invalidate_vemva(vaddr, &tmp_atb);
			if (0 > dir_num)
				VEOS_TRACE("fail to invalidate vemva 0x%lx",
						vaddr);
			continue;
		}
		pgsz = (size_t)pgmod_to_pgsz(pgmod);
		tmp_size -= pgsz;

		pgno = pfnum(pb, PG_2M);
		sync_vhva(pb, vaddr, tsk);

		dir_num = invalidate_vemva(vaddr, &tmp_atb);
		if (0 > dir_num) {
			VEOS_DEBUG("failed to invalidate vemva 0x%lx",
					vaddr);
			ret = dir_num;
			goto unmap_ret;
		}

		update_proc_shm_struct(vaddr, pgno, mm);

		if (((PG_SHM & VE_PAGE(vnode, pgno)->flag) ||
				(MAP_SHARED & VE_PAGE(vnode,
					pgno)->flag)) && !veshm)
			mm->shared_rss -= pgsz;

		if (VE_PAGE(vnode, pgno)->private_data == NULL) {
			if (pgsz == PAGE_SIZE_64MB)
				mm->anonhuge -= pgsz;
			else
				mm->anon -= pgsz;
		}

		if ((0 > prv_dir) || (prv_dir != dir_num))
			dirs[i++] = dir_num;
		prv_dir = dir_num;

		ret = amm_put_page(pb);
		if (0 > ret) {
			VEOS_DEBUG("Error in releasing VE page with pb(0x%lx)",
					pb);
			goto unmap_ret;
		}
		mm->vm_size -= pgsz;

		if (!veshm)
			mm->rss_cur -= pgsz;
	}

	/*
	 * On succcess update the ATB structure maintained in mm struct
	 */
	memcpy(&(mm->atb), &tmp_atb, sizeof(atb_reg_t));

	i = 0;
	while (0 <= dirs[i]) {
		VEOS_TRACE("syncing tsk(%p):pid(%d) atb(%p):pgd[%d]",
				tsk, tsk->pid, &mm->atb, dirs[i]);
		psm_sync_hw_regs(tsk, _ATB,
			(void *)&(mm->atb),
			true, dirs[i++], 1);
	}

unmap_ret:
	/*Release mm_struct_lock here*/
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will update shm segment related data into
*	list maintain in mm struct.
*
* @param[in] shmaddr VE virtaul memory address on which shm segment is mapped.
* @param[in] pgno page number of VE physical page.
* @param[in] mm reference to the mm struct of process.
*/
void update_proc_shm_struct(vemva_t shmaddr, pgno_t pgno,
	struct ve_mm_struct *mm)
{
	struct shm_map *shm = NULL;
	vemva_t shmaddr_beg = 0;
	vemva_t shmaddr_end = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	int shmrm = 0, found = 0;
	struct shm *shm_ent = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("mm(%p) vemva 0x%lx mapped to VE page %lu", mm, shmaddr, pgno);
	if (PG_SHM & VE_PAGE(vnode, pgno)->flag) {
		/*
		 * Iterate over the process specific shm list
		 */

		VEOS_TRACE("VE page %lu belongs to shm segment",
				pgno);
		list_for_each_entry(shm,
				&(mm->shm_head), shm_list) {
			shmaddr_beg = shm->shmaddr;
			shmaddr_end = shmaddr_beg +
				(shm->shm_segment->size);
			VEOS_TRACE("shmaddr(0x%lx) for shm map(%p): start(0x%lx) end(0x%lx)",
					shmaddr, (void *)shm, shm->shmaddr, shmaddr_beg +
					(shm->shm_segment->size));

			if ((shmaddr >= shmaddr_beg) &&
					(shmaddr <= shmaddr_end)) {
				pthread_mutex_lock_unlock(&shm->shm_segment->shm_lock,
						LOCK, "Failed to acquire shmsegment shmlock");
				shm->shm_segment->nattch--;
				if (!shm->shm_segment->nattch)
					shmrm = 1;
				pthread_mutex_lock_unlock(&shm->shm_segment->shm_lock,
						UNLOCK, "Failed to release shmsegment shmlock");
				shm->count--;
				VEOS_TRACE("shm seg:id(%d) curr nattch(%ld) and count(%d)",
					shm->shm_segment->shmid, shm->shm_segment->nattch,
					shm->count);
				break;
			}
		}

		if (!(shm->count)) {
			if (shmrm) {
				VEOS_DEBUG("deleting shm(%p) from shm list(%p)",
						(void *)shm, &shm->shm_list);
				pthread_mutex_lock_unlock(&vnode->shm_node_lock,
						LOCK, "Failed to acquire node lock");
				list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
					if (shm_ent == shm->shm_segment) {
						VEOS_DEBUG("Shared memory segment(%p) for shmid(%d) found",
								shm_ent, shm->shm_segment->shmid);
						found = 1;
						break;
					}
				}
				if (found) {
					if ((0 == shm->shm_segment->nattch) &&
							(shm->shm_segment->flag & SHM_DEL)) {
						amm_release_shm_segment(shm->shm_segment);
					}
					pthread_mutex_lock_unlock(&vnode->shm_node_lock,
							UNLOCK, "Failed to release node shm lock");
				}
			}
			list_del(&shm->shm_list);
			free(shm);
		}

	}
	VEOS_TRACE("returned");
}

/**
* @brief This is core mprotect handler which changes the permission
*         of PHY memory corresponding to virtual address.
*
* @param[in] vaddr VEMVA whose physical mapping protection needs to be change.
* @param[in] size Size of region till the memory protection to change.
* @param[in] perm Permission for PHY memory region.
* @param[in] tsk Pointer to ve_task_struct of VE process.
*
* @return On success it returns 0 and negative errno on failure.
*/
int amm_do_mprotect(vemva_t vaddr, ssize_t size, uint64_t perm,
		struct ve_task_struct *tsk)
{
	pgno_t pgno = 0;
	dir_t dir_num = 0;
	int16_t pgoff = 0;
	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	size_t pgsz = 0;
	ret_t ret = 0;
	dir_t dir_cnt = 0;
	atb_reg_t atb = { { { { 0 } } } };
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	struct ve_page *ve_page = NULL;

	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");
	memset(dirs, -1, sizeof(dirs));
	VEOS_DEBUG("mprotect() for vemva 0x%lx and size %ld of tsk:pid(%d)",
			vaddr, size, tsk->pid);

	/*Get mm_struct_lock here*/
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	memcpy(&atb, &(mm->atb), sizeof(atb_reg_t));

	VEOS_TRACE("iterate while permisisons changed for each page");
	while (0 < size) {
		dir_num =  get_pgd(vaddr, tsk);
		if (0 > dir_num) {
			VEOS_DEBUG("vemva 0x%lx not valid for tsk:pid(%d)",
					vaddr, tsk->pid);
			ret = -EINVAL;
			goto mprot_error;
		}
		pgsz = (size_t)pgmod_to_pgsz(ps_getpgsz(&mm->atb.dir[dir_num]));

		if (prv_dir == -1 || (prv_dir != dir_num))
			dirs[dir_cnt++] = dir_num;
		prv_dir = dir_num;

		if (ps_isvalid(&(atb.dir[dir_num])))
			VEOS_DEBUG("valid pgd[%d] for vemva 0x%lx",
					dir_num, vaddr);

		pgoff = pgentry(vaddr, ps_getpgsz(&mm->atb.dir[dir_num]));
		if (!pg_isvalid(&(atb.entry[dir_num][pgoff]))) {
			if (PG_BUS == pg_getpb(&(atb.entry[dir_num][pgoff]),
						PG_2M)) {
				goto next;
			} else if  (pg_getpb(&(atb.entry[dir_num][pgoff]),
						PG_2M))
				pg_valid(&(atb.entry[dir_num][pgoff]));
			else {
				VEOS_DEBUG("ATB ENTRY not yet allocated");
				goto mprot_error;
			}
		}

		pgno = pg_getpb(&(atb.entry[dir_num][pgoff]), PG_2M);
		if (PG_BUS == pgno) {
			goto next;
		}
		ve_page = VE_PAGE(vnode, pgno);

		if (PROT_NONE == perm) {
			VEOS_DEBUG("Setting permission: PROT_NONE");
			pg_invalid(&(atb.entry[dir_num][pgoff]));
		} else if (perm == PROT_READ) {
			VEOS_DEBUG("Setting permission: PROT_READ");
			pg_setprot(&(atb.entry[dir_num][pgoff]));
		} else if ((perm & PROT_WRITE)) {
			if (pg_isprot(&(atb.entry[dir_num][pgoff]))) {
				VEOS_DEBUG("changing %s vemva 0x%lx perm from read to write",
						pgsz_to_pgstr(pgsz), vaddr);
				if (((ve_page->ref_count > 1) ||
							!(ve_page->flag & MAP_ANON)) &&
						!(ve_page->flag & PG_SHM) &&
						!(ve_page->flag & MAP_SHARED)) {
					/* change_mapped_physical_page */
					if (0 > __replace_page(&atb.
							entry[dir_num][pgoff])) {
						 /*
						  * Here we will Copy ATB to mm_struct and sync with hardware
						  * explicitly to avoid VE memory leak.
						  */

						ret = -ENOMEM;
						VEOS_DEBUG("failed to replace page");
						goto done;
					}
				}
				pg_unsetprot(&(atb.entry[dir_num][pgoff]));
			} else
				VEOS_DEBUG("Permission already: PROT_WRITE");
		} else {
			VEOS_DEBUG("Invalid permmision %lx", perm);
			goto mprot_error;
		}
next:
		vaddr += pgsz;
		size -= pgsz;
	}
	/*
	 * On succcess update the ATB structure maintained in mm
	 */
done:
	memcpy(&(mm->atb), &atb, sizeof(atb_reg_t));
	int i = 0;

	while (0 <= dirs[i]) {
		psm_sync_hw_regs(tsk, _ATB,
				(void *)&(mm->atb),
				true, dirs[i++], 1);
	}

mprot_error:
	/*Release mm_struct_lock here*/
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned");
	return ret;

}

/**
* @brief This function will allocated VE physical pages according to count.
*
* @param[in] count Number of free pages.
* @param[out] map Holds page number that is allocated.
* @param[in] pgmod page mode for the memory allocation.
*
* @return On success retrun 0 and negative value on failure.
*/
int alloc_ve_pages(uint64_t count, pgno_t *map, int pgmod)
{
	int ret = 0;
	size_t mem_sz = 0;
	struct block *curr_blk = NULL, *tmp_blk = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	int is_wait = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("allocate %lu %s to map(%p)",
		count, pgmod_to_pgstr(pgmod),
		(void *)map);

	if (pgmod == PG_2M)
		mem_sz = (size_t)(count * PAGE_SIZE_2MB);
	else
		mem_sz = (size_t)(count * PAGE_SIZE_64MB);

	VEOS_DEBUG("allocating %lx size VE memory",
			mem_sz);

	/*Get buddy lock here*/
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Failed to acquire ve_page lock");

	while (is_wait != -1) {
		if (terminate_flag) {
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
					UNLOCK,
					"Failed to acquire ve_page lock");
			return -ENOMEM;
		}
		ret = veos_alloc_memory(vnode->mp, mem_sz, pgmod);
		if (ret == 0)
			break;
		else if (ret != -ENOMEM) {
			VEOS_DEBUG("Error (%s) while allocating %lx size VE memory",
				   strerror(-ret), mem_sz);
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
						  UNLOCK,
						  "Failed to release ve_page lock");
			return ret;
		}
		VEOS_DEBUG("Error (%s) while allocating %lx size VE memory",
				strerror(-ret), mem_sz);

		/*clear all allocated block*/
		list_for_each_entry_safe(curr_blk, tmp_blk,
			vnode->mp->alloc_req_list, link) {
			list_del(&curr_blk->link);
			/*returning allocated block to buddy mempool*/
			buddy_free(vnode->mp, curr_blk);
		}
		for (;;) {
			is_wait = calc_usable_dirty_page(vnode, mem_sz, pgmod);
			if (is_wait == 1)
				break; /* enough free block */
			else if (is_wait == -1) {
				VEOS_DEBUG("no enough memory");
				pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
						UNLOCK,
						"Failed to release ve_page lock");
				return ret;
			}
			VEOS_DEBUG("wait to clearing dirty page");
			pthread_cond_wait(&vnode->pg_allc_cond,
					&vnode->ve_pages_node_lock);
		}
	}

	/*make entries in ve page array*/
	ret = veos_page_entry(vnode->mp, pgmod, map);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in updating allocated page info",
				strerror(-ret));
		pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
				"Failed to release ve_page lock");
		return ret;
	}

	VEOS_DEBUG("Allocated %lx VE PHY memory", mem_sz);

	VEOS_DEBUG("================ AMM BUDDY DUMP =================");
	buddy_dump_mempool(vnode->mp);

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Failed to release ve_page lock");
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function will calculate usable memory size.
 *
 * @param[in] vnode struct of ve node.
 * @param[in] mem_sz requested memory size.
 * @param[in] pgmod page mode for the memory allocation.
 *
 * @return If usable page size more than requested size
 *         returns 0, else -1.
 */
int calc_usable_dirty_page(struct ve_node_struct *vnode,
			   size_t mem_sz, int pgmod)
{
	size_t usable_buddy_sz = 0;
	size_t usable_dirt_pgsz = 0;
	size_t usable_sz = 0;

	/*dirty page num*/
	usable_dirt_pgsz = vnode->dirty_pg_num_64M * PAGE_SIZE_64MB
		+ vnode->dirty_pg_num_2M * PAGE_SIZE_2MB;

	usable_buddy_sz = calc_free_sz(vnode->mp, pgmod);
	/*usable page size*/
	usable_sz = usable_dirt_pgsz + usable_buddy_sz;
	VEOS_DEBUG("usable size:%ld (buddy:%ld dirty:%ld)",
		   usable_sz, usable_buddy_sz, usable_dirt_pgsz);

	if (usable_sz < mem_sz)
		return -1;

	if (usable_buddy_sz >= mem_sz)
		return 1;

	return 0;
}

/**
 * @brief This function will wake up threads that are waiting
 * to allocate memory.
 */
void amm_wake_alloc_page(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
			LOCK, "Fail to acquire ve page lock");
	pthread_cond_broadcast(&vnode->pg_allc_cond);
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
			UNLOCK, "Fail to release ve page lock");
}

/**
 * @brief This function will entry dirty page list and
 *	wake up memory clearing thread.
 *
 * @param[in] pgno Page number whose status needs to be marked as free.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_free_page(pgno_t pgno)
{
	ret_t ret = 0;
	int pgmod = 0;
	size_t pgsz = 0;

	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	if (NULL == VE_PAGE(vnode, pgno)) {
		VEOS_DEBUG("freeing unallocated VE page %ld",
				pgno);
		ret = -EINVAL;
		return ret;
	}
	pgsz = VE_PAGE(vnode, pgno)->pgsz;
	pgmod = pgsz_to_pgmod(pgsz);

	/* Add entry to dirty page list. */
	ret = add_dirty_page(pgno, pgsz, pgmod);
	if (ret == 0) {
		if (pgmod == PG_2M)
			++vnode->dirty_pg_num_2M;
		else
			++vnode->dirty_pg_num_64M;
	}
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function will initialize dirty page list and create
 *	thread for clear memories.
 *
 * @param[in,out] vnode ve node struct.
 * @param[in,out] th thread ID will be stored in pointed by this.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int dirty_page_init(struct ve_node_struct *vnode, pthread_t *th)
{
	pthread_attr_t attr;
	int ret = 0;

	if ((vnode == NULL) || (th == NULL)) {
		VEOS_CRIT("Failed to init dirty page due to invalid argument.");
		return -EINVAL;
	}

	pthread_mutex_init(&dirty_page.ve_dirty_pg_lock, NULL);
	pthread_cond_init(&dirty_page.ve_dirty_pg_cond, NULL);
	pthread_cond_init(&vnode->pg_allc_cond, NULL);

	INIT_LIST_HEAD(&dirty_page.dirty_pg_list.head);

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		VEOS_CRIT("Faild to initialize pthread attribute: %s",
			strerror(ret));
		goto error;
	}
	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		VEOS_CRIT("Faild to set detach state of pthread attribute: %s",
			strerror(ret));
		goto error;
	}
	ret = pthread_create(th, &attr,
			(void *)&veos_amm_clear_mem_thread, NULL);
	if (ret != 0) {
		VEOS_CRIT("Failed to create thread. %s", strerror(ret));
		goto error;
	}
	return 0;

error:
	pthread_mutex_destroy(&dirty_page.ve_dirty_pg_lock);
	pthread_cond_destroy(&dirty_page.ve_dirty_pg_cond);
	pthread_cond_destroy(&vnode->pg_allc_cond);
	return -ret;
}

/**
 * @brief This function will add to tail of dirty page list and
 *	wake up thread of clearing memory.
 *
 * @param[in] pgno Page number. This will be registered as dirty
 *		list and will be need when the thread of clearing
 *		memory clear.
 * @param[in] pgsz Size of the page. This will be registered as
 *		dirty list and will be need to clear physical page.
 * @param[in] pgmod page mode(huge or large). This will be registerd as
 *		dirty list and will be need to free buddy.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int add_dirty_page(pgno_t pgno, size_t pgsz, int pgmod)
{
	struct ve_dirty_pg_list *dirty_pg_tmp;

	/*create entry data*/
	dirty_pg_tmp = calloc(1, sizeof(struct ve_dirty_pg_list));
	if (dirty_pg_tmp == NULL) {
		VEOS_CRIT("Failed to calloc() for dirty page entry");
		return -ENOMEM;
	}

	dirty_pg_tmp->pgno = pgno;
	dirty_pg_tmp->pgsz = pgsz;
	dirty_pg_tmp->pgmod = pgmod;

	pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, LOCK,
				  "Failed to acquire dirty_page lock");
	/*add to tail of list*/
	VEOS_DEBUG("Add to tail of dirty list: pgno=%ld", pgno);
	list_add_tail(&dirty_pg_tmp->head, &dirty_page.dirty_pg_list.head);
	pthread_cond_signal(&dirty_page.ve_dirty_pg_cond);
	pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, UNLOCK,
				  "Failed to release dirty_page lock");
	return 0;
}

/**
 * @brief This function will free the physical page and
 *	return freed page to buddy allocator and wake up
 *	threads are wating clearing memories.
 *
 * @author AMM
 */
void veos_amm_clear_mem_thread(void)
{
	int ret;
	pgno_t pgno;
	int pgmod = 0;
	size_t pgsz = 0;
	struct ve_dirty_pg_list *dirt_pg_head = NULL;

	VEOS_TRACE("invoked");
	pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, LOCK,
				  "Failed to qcuire dirty_page lock");
	while (terminate_flag == 0) {
		if (list_empty(&dirty_page.dirty_pg_list.head)) {
			VEOS_DEBUG("dirty list is empty, wait.");
			pthread_cond_wait(&dirty_page.ve_dirty_pg_cond,
					&dirty_page.ve_dirty_pg_lock);
			continue;
		}

		/* ve_dirty_pg_lock is locked in pthread_cond_wait()*/
		/* get info from dirty page list */
		dirt_pg_head = list_next_entry(&dirty_page.dirty_pg_list, head);
		pgno = dirt_pg_head->pgno;
		pgsz = dirt_pg_head->pgsz;
		pgmod = dirt_pg_head->pgmod;
		VEOS_DEBUG("Cleaning dirty page: pgno=%ld, pgsz=%ld, pgmod=%d",
			   pgno, pgsz, pgmod);
		/* delete entry */
		list_del(&dirt_pg_head->head);
		free(dirt_pg_head);

		pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, UNLOCK,
					  "Failed to release dirty_page lock");

		ret = pthread_rwlock_tryrdlock(&handling_request_lock);
		if (ret) {
			VEOS_ERROR("failed to acquire request lock");
			goto hndl_exit;
		}

		/* free page and wake up threads that waiting clearing
		 * dirty page.
		 * This thread ignore fail of clear_and_dealloc_page(),
		 * because this thread should continue to clear next
		 * dirty pages.
		 */
		clear_and_dealloc_page(pgno, pgsz, pgmod);

		pthread_rwlock_lock_unlock(&handling_request_lock, UNLOCK,
				"failed to release handling_request_lock");

		/*get lock for pthread_cond_wait()*/
		pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, LOCK,
				"Failed to qcuire dirty_page lock");
	}
	pthread_mutex_lock_unlock(&dirty_page.ve_dirty_pg_lock, UNLOCK,
				  "Failed to release dirty_page lock");
hndl_exit:
	VEOS_TRACE("Exiting");
	pthread_exit(NULL);
}

/**
 * @brief This function will free the physical page and
 *	return freed page to buddy allocator.
 *	If this function fail to free the page, abort to free
 *	this page, because dirty page should not be sent buddy
 *	allocator.
 *	This function wakes up all threads that waiting to free
 *	dirty page.
 *
 * @param[in] pgno Page nuber. This is need to clear memory.
 * @param[in] pgsz Size of the page. This is need to clear physical page.
 * @param[in] pgmod page mode(huge or large). This is need to free buddy.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int clear_and_dealloc_page(pgno_t pgno, size_t pgsz, int pgmod)
{
	int ret = 0, idx = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	ret = amm_clear_page(pgno, pgsz);
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
				  "Failed to acquire ve_page lock");
	if (ret < 0) {
		VEOS_CRIT("Error (%s) in clearing VE page %ld",
			  strerror(-ret), pgno);
		goto hndl_ret;
	}

	ret = veos_delloc_memory(pgno, pgmod);
	if (ret < 0) {
		VEOS_CRIT("Error (%s) in deallocating VE page %ld",
			  strerror(-ret), pgno);
		goto hndl_ret;
	}

	free(VE_PAGE(vnode, pgno));
	if (pgmod == PG_2M) {
		--vnode->mp->small_page_used;
		vnode->ve_pages[pgno] = NULL;
	} else {
		--vnode->mp->huge_page_used;
		for (idx = pgno; idx < (pgno + HUGE_PAGE_IDX); idx++)
			vnode->ve_pages[idx] = NULL;
	}

hndl_ret:
	/* The number of dirty page is decremented regardless of
	 * success or failure, because the this page was deleted from
	 * dirty list and never will be used.
	 */
	if (pgmod == PG_2M)
		--vnode->dirty_pg_num_2M;
	else
		--vnode->dirty_pg_num_64M;

	VEOS_DEBUG("dirty page num: 2M=%ld 64M=%ld",
		   vnode->dirty_pg_num_2M, vnode->dirty_pg_num_64M);
	VEOS_DEBUG("================ AMM BUDDY DUMP =================");
	buddy_dump_mempool(vnode->mp);

	/* wake up threads that waiting clearing dirty page*/
	pthread_cond_broadcast(&vnode->pg_allc_cond);
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
				  "Failed to release ve_page lock");

	return ret;
}


/**
* @brief This function will return total number of VE physical
*        pages used given node.
*
* @param[in] node_id node identifier.
*
* @return always returns total number of VE physical pages used by the node.
*/
uint64_t ve_node_page_used_count(int node_id)
{
	uint64_t used_cnt = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Fail to acquire buddy lock");

	/*
	 * Total used page means small page + huge page multiply by 32.
	 * As one huge page consist 32 small page.
	 */
	used_cnt =  ((vnode->mp->small_page_used +
				(vnode->mp->huge_page_used * HUGE_PAGE_IDX)));

	VEOS_DEBUG("total node pages in use %ld", used_cnt);

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release buddy lock");
	return used_cnt;
}

/**
* @brief This function will return total number of VE physical
*        pages are not used given node.
*
* @param[in] node_id node identifier.
*
* @return always returns total number of VE physical pages not used by node.
*/
int  ve_node_page_free_count(int node_id)
{
	int free_cnt = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Fail to acquire buddy lock");

	free_cnt =  (vnode->mp->total_pages -
			(vnode->mp->small_page_used +
			 (vnode->mp->huge_page_used * HUGE_PAGE_IDX)));

	VEOS_DEBUG("Total free page :%d", free_cnt);

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release buddy lock");

	VEOS_TRACE("returned");
	return free_cnt;
}

/**
* @brief This function will convert VE virtual address into VE physical address.
*
* @param[in] vaddr VE virtual address for which physical address to be obtain.
* @param[in] pid process pid.
* @param[in] inc_ref this will indicate whether to increase ref count or not.
* @param[out] prot this will contain protection set for given VE virtual address.
*
* @return on success return physical address and negative of errno on failure.
*/
int64_t veos_virt_to_phy(vemva_t vaddr, pid_t pid,
		bool inc_ref, int *prot)
{
	ret_t ret = 0;
	vemaa_t pb = 0;
	struct ve_task_struct *tsk = NULL;
	atb_reg_t atb = { { { {0} } } };

	VEOS_TRACE("invoked");

	VEOS_DEBUG("get vemaa for vemva %lx of tsk:pid(%d), inc(%d) prot(%p)",
		vaddr, pid, inc_ref, prot);

	/*Obtain the task struct using pid*/
	tsk = find_ve_task_struct((pid_t)pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting tsk with pid %d",
			strerror(-ret), pid);
		goto vp_ret;
	}
	/*Get atb structure of current process*/
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	atb = tsk->p_ve_mm->atb;
	/*convert virtual address into physical*/

	ret = (uint64_t)__veos_virt_to_phy(vaddr,
			&atb, prot, NULL);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in vemva to vemaa translation",
				strerror(-ret));
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK,
				"Failed to release thread-group-mm-lock");
		goto vp_ret;
	}

	if (inc_ref) {
		pb = ret;
		/*if inc_ref flag is TRUE then increament the ref count*/
		veos_get_page(pb);
	}

	VEOS_DEBUG("tsk:pid(%d) vemva 0x%lx mapped with vemaa 0x%lx",
		pid, vaddr, ret);

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
vp_ret:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will give page mode info given VE virtual address range.
*
* @param[in] vaddr VE virtual address.
* @param[in] tsk process task struct.
* @param[in] size total size for which page mode info required.
* @param[out] same flag to be set to true when pgmod is uniform else it is set to false
*
* @return on success returns buffer which contain page mode info
*        and negative of errno on failure.
*/
uint64_t *amm_get_pgmod_info(vemva_t vaddr,
		struct ve_task_struct *tsk, size_t size, bool *same)
{
	int pgmod = -1, start_pgmod = -1;
	uint64_t *pg_info1 = NULL, *pg_info = NULL;
	vemva_t tmp_addr = -1;
	int count = 0, idx = 0, act_count = 0;
	*same = true;
	dir_t dir_num = 0;

	VEOS_TRACE("invoked");

	/* Here we will check the pgmod for
	 * each 2MB address range.*/
	count = size >> LARGE_PSHFT;

	if ((size % PAGE_2MB) != 0)
		++count;

	act_count  = count;

	/*NOTE
	 * This mem blk should be free by function
	 * which is calling this function
	 */
	pg_info = calloc(sizeof(uint64_t), (count + 1));
	if (NULL == pg_info) {
		VEOS_CRIT("Calloc failed");
		errno = ENOMEM;
		return NULL;
	}

	tmp_addr = vaddr;
	while (count > 0) {
		dir_num = __get_pgd(tmp_addr, &tsk->p_ve_mm->atb,
				-1, false);
		if (0 > dir_num) {
			VEOS_DEBUG("Invalid vemva 0x%lx", tmp_addr);
			free(pg_info);
			errno = EINVAL;
			return NULL;
		}
		pgmod = ps_getpgsz(&tsk->p_ve_mm->atb.dir[dir_num]);

		if (!idx)
			start_pgmod = pgmod;

		if (pgmod == PG_HP) {
			tmp_addr = (vemva_t)(tmp_addr + PAGE_64MB);
			count = count - HUGE_PAGE_IDX;
		} else {
			tmp_addr = (vemva_t)(tmp_addr + PAGE_2MB);
			--count;
		}
		pg_info[idx] = (uint64_t)pgmod;
		++idx;
	}
	if (act_count != idx) {
		pg_info1 = realloc(pg_info,
				(sizeof(uint64_t) * (idx + 1)));
		if (pg_info1 == NULL) {
			VEOS_CRIT("failed to allocate memory for pgmod");
			free(pg_info);
			errno = ENOMEM;
			return NULL;
		}
	} else {
		pg_info1 = pg_info;
	}

	/*check whether pgmod is same for
	 * all address range and set same flag*/
	idx = 0;

	while (pg_info1[idx]) {
		if (start_pgmod != pg_info1[idx]) {
			VEOS_DEBUG("vemva 0x%lx and size %ld has different pgmodes",
				vaddr, size);
			same = false;
			break;
		}
		++idx;
	}

	VEOS_TRACE("returned");
	return pg_info1;
}

/**
* @brief This function will initialize file_descriptor.
*
* @param[in] file_stat Stats about the file to be mapped.
*
* @return Return pointer to the file_descrioptor on success and NULL on failure.
*/
struct file_desc *init_file_desc(struct file_stat *file)
{
	struct file_desc *file_desc_tmp = NULL;
	int ret = 0;
	VEOS_TRACE("invoked");

	file_desc_tmp = calloc(1, sizeof(struct file_desc));
	if (NULL == file_desc_tmp) {
		VEOS_CRIT("failed to allocated file desc");
		goto err_return;
	}

	file_desc_tmp->stat = file->stat;
	file_desc_tmp->pgsz = file->pgsz;
	file_desc_tmp->in_mem_pages = 0;

	VEOS_DEBUG("file desc(%p) stat(%p) hold %s and refcnt(%lu)",
			file_desc_tmp,
			&file_desc_tmp->stat,
			pgsz_to_pgstr(file_desc_tmp->pgsz),
			file_desc_tmp->in_mem_pages);

	INIT_LIST_HEAD(&file_desc_tmp->mapping_list);


	if (0 != pthread_mutex_init(&(file_desc_tmp->f_desc_lock), NULL)) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while initialzing file desc lock",
			strerror(-ret));
		VEOS_TRACE("freeing memory for file desc(%p)",
			file_desc_tmp);
		free(file_desc_tmp);
		file_desc_tmp = NULL;
		goto err_return;
	}

err_return:
	VEOS_TRACE("returned");
	return file_desc_tmp;
}

/**
* @brief This function scans the global list of file_desc to
*         find the file_desc with given file stat.
*
* @param[in] file_stat Stats about the file to be mapped.
* @param[in] flags memory mapping flags.
*
* @return on success returns pointer to the matching file_descriptor else NULL.
*/
struct file_desc *scan_global_list(struct file_stat *file, flag_t flags)
{
	struct list_head *temp = NULL;
	struct file_desc *file_desc_tmp = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");
	VEOS_TRACE("iterating node page cache list(%p) starts",
		&vnode->file_desc_start->global_list);

	/*
	 * Can use list for each entry safe
	 * instead list for each and then list
	 * entry
	 */
	list_for_each(temp, &vnode->file_desc_start->global_list)
	{
		VEOS_TRACE("reference of file desc list(%p) [prev(%p):next(%p)]",
			temp, temp->prev, temp->next);
		file_desc_tmp = list_entry(temp, struct file_desc,
				global_list);
		VEOS_TRACE("reference of file desc(%p)",
			file_desc_tmp);

		if (!stat_cmp(file_desc_tmp, file, flags)) {
			VEOS_DEBUG("matching file desc found in node page cache");
			goto sgl_ret;
		}
	}

	VEOS_TRACE("iterating node page cache end)");
	VEOS_DEBUG("matching file desc not found in node page cache");

	/* These interface must go out of scanning interface
	 * The reason it is kept here is locking*/
	file_desc_tmp = init_file_desc(file);
	if (NULL == file_desc_tmp) {
		VEOS_DEBUG("failed to get file desc");
		goto sgl_ret;
	}


	list_add_tail(&file_desc_tmp->global_list, &vnode->
			file_desc_start->global_list);

	VEOS_DEBUG("file desc(%p) added to page cache list(%p)",
			file_desc_tmp, &vnode->
			file_desc_start->global_list);
sgl_ret:
	VEOS_TRACE("returned");
	return file_desc_tmp;
}


/**
* @brief This function Updates the mapping list after merging and inserting the new
*      mapping list in existing mapping list.
*
* @param[in] vaddr
* @param[in] file_desc reference to thefile_descriptor with which the mapping is associated.
* @param[in] off_s starting file offset.
* @param[in] off_e ending file offset.
* @param[in] pgmod page mode(whethre mapping is with huge page or large page).
* @param[in] tsk process task struct.
* @param[out] map this will contain VE physical page number which are newly allocated.
*
* @return on success return 0 and negative of errno on failure.
*/
ret_t amm_do_file_back_handling(vemva_t vaddr, struct file_desc *
		file_desc, off_t off_s, off_t off_e,
		int pgmod, struct ve_task_struct *tsk, pgno_t *map)
{
	struct mapping_desc *map_desc = NULL;
	struct mapping_attri *map_attri = NULL;
	pgno_t *pgno = NULL;
	int64_t count = -1;
	int64_t index = -1;
	size_t mapping_size = 0;
	ret_t ret = 0;

	VEOS_TRACE("invoked");
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_DEBUG("tsk:pid(%d) mmaps file range "
		"[(%ld) -- (%ld)] with %ld %s"
		"at vemva(%lx)",
		tsk->pid, off_s, off_e, (off_e - off_s),
		pgmod_to_pgstr(pgmod), vaddr);

	VEOS_DEBUG("tsk(%p):pid(%d), file desc(%p)",
		tsk, tsk->pid, file_desc);

	/*
	 * This interface will scan the mapping list under file_descriptor
	 * and will decide from where to where the previous mapping will be
	 * merged and where the new mapping Should be inserted. All This
	 * Information will be populated in struct mapping_attribute
	 */
	map_attri = collect_map_attri(file_desc, off_s, off_e);
	if (NULL == map_attri) {
		VEOS_DEBUG("failed to get map attr for file");
		ret = -ENOMEM;
		goto err_exit;
	}

	/*
	 * This interface will initialize the mapping descriptor to be added
	 * in list.
	 */
	map_desc = init_mapping_desc(map_attri);
	if (NULL == map_desc) {
		VEOS_DEBUG("failed to init file map desc");
		VEOS_DEBUG("freeing map attri(%p)",
			map_attri);
		free(map_attri);
		ret = -ENOMEM;
		goto err_exit;
	}

	/*Update reverse reference*/
	map_desc->file_desc = file_desc;
	count = (off_e - off_s) + 1;

	pgno = map_desc->pg_array +
		(off_s - map_attri->offset_start);

	/*
	 * This interface will update the mapping_descriptor.
	 * This will allocate the new pages required for the mapping
	 * and will accordingly update the page array.
	 */
	ret = update_mapping_desc(vaddr, pgno,
			count, pgmod, tsk,
			file_desc, off_s, map);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in updating pg map of map desc",
			strerror(-ret));
		VEOS_TRACE("freeing: map attr(%p), pg arr(%p)"
			"map desc(%p)", map_attri, map_desc->pg_array,
			map_desc);
		free(map_attri);
		free(map_desc->pg_array);
		free(map_desc);
		goto err_exit;
	}

	/*Updating Reverese reference*/
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Fail to acquire ve page lock");
	mapping_size = map_attri->offset_end - map_attri->offset_start;
	pgno = map_desc->pg_array;

	for (index = 0; index <= mapping_size; index++) {
		VEOS_DEBUG("update VE page(%ld) map desc(%p)",
				pgno[index], map_desc);
		if (pgno[index] > 0)
			VE_PAGE(vnode, pgno[index])->
				private_data = (void *)map_desc;
	}
	/* This interface will add the mapping descriptor in the list */
	add_mapping_desc(file_desc, map_desc, map_attri);

	/*Release amm_node_lock here*/
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release ve page lock");

	free(map_attri);
	return ret;
err_exit:
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief Initialize the mapping descriptor with offset start, end and page_array etc.
*
* @param[out] map_attri Attributes of the new mapping.
*
* @return Return Pointer to the mapping descriptor.
*/
struct mapping_desc *init_mapping_desc(
		struct mapping_attri *map_attri)
{
	int64_t off_s = 0;
	int64_t off_e = 0;

	struct mapping_desc *map_desc = NULL;

	VEOS_TRACE("invoked");

	off_s = map_attri->offset_start;
	off_e = map_attri->offset_end;

	map_desc = calloc(1, sizeof(struct mapping_desc));
	if (NULL == map_desc) {
		VEOS_CRIT("failed to allocate map desc");
		return NULL;
	}

	map_desc->offset_start = map_attri->offset_start;
	map_desc->offset_end = map_attri->offset_end;

	VEOS_DEBUG("allocating page map to hold %ld pages",
			((off_e - off_s) + 1));

	map_desc->pg_array = (pgno_t *)calloc
		(((off_e - off_s) + 1), sizeof(pgno_t));
	if (NULL == map_desc->pg_array) {
		VEOS_CRIT("failed to allocate page map");
		free(map_desc);
		return NULL;
	}

	VEOS_DEBUG("map desc page map(%p)",
		map_desc->pg_array);

	memset(map_desc->pg_array, -1,
		((off_e - off_s) + 1) * sizeof(pgno_t));

	init_page_array(map_desc, map_attri);
	VEOS_TRACE("returned");
	return map_desc;
}

/**
* @brief This function will increase or decrease ref count depend on atomic_op.
*	 atomic_op == 1 then it will increase ref count;
*	 atomic_op == 0 then it will decrease ref count;
*
* @param[in] pgaddr VE physical address of page whose ref count is to be increase/decrease.
*
* @param[in] atomic_op this will decide whether to Increase/Decrease ref count.
* @return return 0 on success and negative of errno on failure.
*/
int common_get_put_page(vemaa_t pb, uint8_t atomic_op, bool is_amm)
{
	pgno_t pgnum = 0;
	/*
	 * Get the node info .
	 * here we are considering Node 0 hard coded.
	 */
	struct ve_node_struct *vnode = VE_NODE(0);
	ret_t ret = 0;

	VEOS_TRACE("invoked");

	/*Get lock on ve_node_struct*/
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Fail to acquire ve page lock");

	pgnum = pfnum(pb, PG_2M);

	/* If ve_page array contains -1,
	 * its means that it is tail of huge page*/
	if (NULL == vnode->ve_pages[pgnum]) {
		VEOS_DEBUG("get/put operation invoked on unallocated VE page %ld",
				pgnum);
		ret = -EINVAL;
		goto func_return;
	}
	if (vnode->ve_pages[pgnum] == (struct ve_page *)-1) {
		VEOS_DEBUG("VE page %ld is tailof huge page",
			pgnum);
		pgnum = ROUN_DN(pgnum, HUGE_PAGE_IDX);
		VEOS_DEBUG("Huge VE page is %ld", pgnum);
	}

	if (GET_PAGE == atomic_op) {
		/*
		 * Increament the ref count of page
		 * This is built in function given by GCC to perform
		 * atomic operation on memory*/
		if (is_amm)  {
			VEOS_DEBUG("VE page %ld refcnt before inc is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				ref_count);

			__sync_fetch_and_add(&vnode->
				ve_pages[pgnum]->ref_count, 1);

			VEOS_DEBUG("VE page %ld refcnt after inc is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				ref_count);
		} else {
			VEOS_DEBUG("VE page %ld dma refcnt before inc is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				dma_ref_count);

			__sync_fetch_and_add(&vnode->
				ve_pages[pgnum]->dma_ref_count, 1);

			VEOS_DEBUG("VE page %ld dma refcnt after inc is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				dma_ref_count);
		}
	} else {
		/*Decreament the ref count of page*/
		if (is_amm) {
			VEOS_DEBUG("VE page %ld refcnt before dec is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				ref_count);

			if (0 == vnode->ve_pages[pgnum]->ref_count) {
				VEOS_DEBUG("VE page ref count is zero and unavailable for DMA");
				ret = -EINVAL;
				goto func_return;
			}
			__sync_fetch_and_sub(&vnode->
				ve_pages[pgnum]->ref_count, 1);

			VEOS_DEBUG("VE page %ld refcnt after dec is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				ref_count);
			if ((0 == VE_PAGE(vnode, pgnum)->ref_count)
			    && !(VE_PAGE(vnode, pgnum)->flag & PG_SHM)
			    && !(VE_PAGE(vnode, pgnum)->flag & MAP_ANON)
			    && ((VE_PAGE(vnode, pgnum)->flag & MAP_SHARED)
				|| !(VE_PAGE(vnode, pgnum)->perm & PROT_WRITE))) {
				clear_page_array_entry(VE_PAGE(vnode, pgnum)->
						       private_data, pgnum);
			}
		} else {
			VEOS_DEBUG("VE page %ld dma refcnt before dec is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				dma_ref_count);

			if (vnode->ve_pages[pgnum]->dma_ref_count == 0) {
				VEOS_DEBUG("VE page dma refcnt is already zero");
				ret = -EINVAL;
				goto func_return;
			}
			__sync_fetch_and_sub(&vnode->
				ve_pages[pgnum]->dma_ref_count, 1);

			VEOS_DEBUG("VE page %ld dma refcnt after dec is %ld",
				pgnum, VE_PAGE(vnode, pgnum)->
				dma_ref_count);
		}

		/*if ref count page is zero then free that page*/
		if ((0 == VE_PAGE(vnode, pgnum)->ref_count) &&
			!(VE_PAGE(vnode, pgnum)->flag & PG_SHM) &&
			(0 == VE_PAGE(vnode, pgnum)->dma_ref_count))
				veos_free_page(pgnum);
	}

	/*Release lock from ve_node_struct*/
func_return:
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release ve page lock");
	VEOS_TRACE("returned");
	return ret;
}


/**
* @brief This function will increase the ref count of pages associated with DMA tranfer.
*
* @param[in] pb VE physical address of pages
*		whose ref count to be increase.
*
* @return on success returns 0 and negative of errno on failure.
*/
int veos_get_page(vemaa_t pb)
{
	int ret = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("page base map(0x%lx)", pb);

	ret = common_get_put_page(pb, GET_PAGE, false);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while getting page with address(%lx)",
				strerror(-ret), pb);
	}

	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will increase the ref count of pages associated with normal mapping.
*
* @param[in] pb null terminated of VE physical address of pages
*            whose ref count to be increase.
*
* @return on success returns 0 and negative of errno on failure.
*/
int amm_get_page(vemaa_t *pb)
{
	ret_t ret = 0;
	int idx = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("page base map(%p)", pb);

	/* Here we extract physical address one by one from array of
	 * and send it to increase ref count. */
	VEOS_TRACE("iterate when all the pages are get");
	while (pb[idx]) {
		VEOS_TRACE("pbmap[%d] with address(%lx)",
				idx, pb[idx]);
		ret = common_get_put_page(pb[idx],
				GET_PAGE, true);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while getting page with address(%lx)",
					strerror(-ret), pb[idx]);
			goto out;
		}
		idx++;
	}
	VEOS_TRACE("iteration ends");
	VEOS_DEBUG("total %d pages get", idx);
out:
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function will increase ref count of page which are associated with DMA xfer.
 *
 * @param[in] pb VE physical address of page whose ref count to be decrease.
 *
 * @return on success return 0 and negative of errno on failure.
 */
int veos_put_page(vemaa_t pb)
{
	return common_get_put_page(pb, PUT_PAGE, false);
}

/**
 * @brief This function will increase ref count of page which are associated with normal mapping.
 *
 * @param[in] pb VE physical address of page whose ref count to be decrease.
 *
 * @return on success return 0 and negative of errno on failure.
 */
int amm_put_page(vemaa_t pb)
{
	ret_t ret = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct file_desc *file_d = NULL;
	uint64_t pgflag = 0;
	uint64_t pgperm = 0;

	VEOS_TRACE("invoked");

	if (NULL == VE_PAGE(vnode, pfnum(pb, PG_2M))) {
		VEOS_CRIT("freeing unallocated VE page with vemaa 0x%lx",
				pb);
		ret = -EINVAL;
		return ret;
	}

	pgflag = VE_PAGE(vnode, pfnum(pb, PG_2M))->flag;
	pgperm = VE_PAGE(vnode, pfnum(pb, PG_2M))->perm;
	if (!(pgflag & MAP_ANON) && !(pgflag & PG_PTRACE) &&
			((pgflag & MAP_SHARED) || !(pgperm & PROT_WRITE))) {
		VEOS_DEBUG("VE vemaa 0x%lx is shared or read only mapped",
				pb);
		pthread_mutex_lock_unlock(&vnode->pgcache_lock, LOCK,
				"Fail to acquire pagecache lock");
		file_d = ((struct mapping_desc *)(VE_PAGE(vnode, pfnum(pb, PG_2M))
					->private_data))->file_desc;
		if (NULL == file_d) {
			pthread_mutex_lock_unlock(&vnode->pgcache_lock, UNLOCK,
					"Fail to release pagecache lock");
			VEOS_DEBUG("Invalid page private data");
			ret = -EINVAL;
			return ret;
		}
		pthread_mutex_lock_unlock(&file_d->f_desc_lock,
				LOCK, "Failed to acquire file desc lock");
	}

	ret =  common_get_put_page(pb, PUT_PAGE, true);
	if (0 > ret)
		VEOS_DEBUG("fail to put vemaa %lx ", pb);

	if (!(pgflag & MAP_ANON) && !(pgflag & PG_PTRACE) &&
			((pgflag & MAP_SHARED) || !(pgperm & PROT_WRITE))) {
		if (!file_d->in_mem_pages) {
			pthread_mutex_lock_unlock(&file_d->f_desc_lock,
					UNLOCK,
					"Failed to release file desc lock");
			free_file_desc(file_d);
		} else
			pthread_mutex_lock_unlock(&file_d->f_desc_lock,
					UNLOCK,
					"Failed to release file desc lock");

		pthread_mutex_lock_unlock(&vnode->pgcache_lock, UNLOCK,
				"Fail to release pagecache lock");
	}

	return ret;
}

/**
* @brief This function will share memory mapped by owner with valid requestor.
*
* @param[in] owner process identifier of owner process.
* @param[in] own_vemva VE virtual address of memory mapped by owner process.
* @param[in] req process identifier of requestor process.
* @param[in] req_vemva VE virtual address of memory which to be mapped by requestor process.
* @param[in] size total size of meomory which is to be share.
* @param[in] prot memory protection requested by requestor process.
* @param[in] access_ok this flag will decide whether to check memory protection or not.
*
* @return on success return 0 and negative of errno on failure.
*/
int veos_share_vemva_region(pid_t owner, vemva_t own_vemva,
		pid_t req, vemva_t req_vemva,
		size_t size, int prot, bool access_ok)
{
	struct ve_task_struct *own_tsk = NULL;
	struct ve_task_struct *req_tsk = NULL;
	struct ve_mm_struct *own_mm = NULL;
	struct ve_mm_struct *req_mm = NULL;
	atb_reg_t req_atb = { { { {0} } } };
	int own_pgmod = 0, req_pgmod = 0;
	ret_t ret = 0;
	unsigned long count = 0, tc = 0;
	size_t pgsz = 0;
	pgno_t page_num = 0, start = 0;
	pgno_t *pgno = NULL;
	dir_t dir_num = 0;
	int pgoff = 0;
	dir_t dirs[ATB_DIR_NUM] = {0}, prv_dir = -1;
	vemva_t temp_addr = 0;
	vemaa_t *pb = NULL;
	int rw = 0, i = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("invoked with owner = %d, owner vemva = 0x%lx req = %d"
			"requester vemva = 0x%lx, size = 0x%lx"
			"protection %s bool = %d", owner, own_vemva,
			req, req_vemva, size, perm_to_str(prot), access_ok);

	memset(dirs, -1, sizeof(dirs));

	own_tsk = find_ve_task_struct(owner);
	if (NULL == own_tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting tsk with pid %d",
			strerror(-ret), owner);
		goto hndl_return;
	}

	/*check whether requestor PID is valid or not*/
	req_tsk = find_ve_task_struct(req);
	if (NULL == req_tsk) {
		VEOS_DEBUG("Error (%s) while getting tsk with pid %d",
			strerror(-ret), req);
		ret = -ESRCH;
		goto hndl_return;
	}

	/* Get mm_struct of owner and Requestor*/
	own_mm = own_tsk->p_ve_mm;
	req_mm = req_tsk->p_ve_mm;
	pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");
	/*
	 * check page mode of owner
	 */
	dir_num = __get_pgd(own_vemva,
			&own_mm->atb, -1, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for owner vemva %lx",
			strerror(-ret), own_vemva);
		goto hndl_ownr;
	}

	own_pgmod = ps_getpgsz(&own_mm->atb.dir[dir_num]);

	pgsz = (size_t)pgmod_to_pgsz(own_pgmod);
	/*check whether requested size is available or not*/
	count = size / pgsz;
	tc = count;

	temp_addr = own_vemva;
	/*
	 * Here we will set the permissin of page
	 * which is to be set
	 */

	if (prot & PROT_WRITE)
		rw = 1;
	else if (prot == PROT_NONE)
		rw = -1;

	pgno = calloc(count, sizeof(unsigned long));
	if (NULL == pgno) {
		VEOS_CRIT("failed to allocate memory for page map");
		ret = -ENOMEM;
		goto hndl_ownr;
	}

	pb = calloc((count + 1), sizeof(uint64_t));
	if (NULL == pb) {
		VEOS_CRIT("failed to allocate memory for pb map");
		ret = -ENOMEM;
		goto hndl_ownr;
	}

	while (0 != tc) {
		/*check owner ATB dir is valid or not*/
		dir_num = __get_pgd(temp_addr, &own_mm->atb, -1, false);
		if (0 > dir_num) {
			ret = -EINVAL;
			VEOS_DEBUG("Error (%s) in getting pgd for vemva %lx",
				strerror(-ret), temp_addr);
			goto hndl_ownr;
		}
		/*Get the page offset from entry*/
		pgoff =	pgentry(temp_addr, own_pgmod);
		/* if access_ok is true then we need to
		 * verify permission for ATB entry.
		 * rm_prot set to 1 if PROT_WRITE.
		 * pg_isprot will return 1 if page is write protected*/
		if (access_ok) {
			if (rw == pg_isprot(&(own_mm->atb.entry[dir_num]
							[pgoff]))) {
				VEOS_DEBUG("VESHM permission mismatched with owner");
				ret = -EPERM;
				goto hndl_ownr;
			}
		}

		/*Get page number*/
		page_num = pg_getpb((&(own_mm->
				atb.entry[dir_num][pgoff])), PG_2M);

		VEOS_DEBUG("VE page %ld mapped to vemva %lx",
				page_num, temp_addr);

		pgno[start] = page_num;
		pb[start] = pbaddr(pgno[start], PG_2M);
		start++;
		tc--;
		temp_addr = own_vemva + (start * pgsz);
	}

	amm_get_page(pb);

	if (own_mm != req_mm) {
		VEOS_DEBUG("Owner and requestor are not same");
		pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock,
				UNLOCK, "Failed to release thread-group-mm-lock");
		pthread_mutex_lock_unlock(&req_mm->thread_group_mm_lock,
				LOCK, "Failed to acquire thread-group-mm-lock");
	}

	if (req_tsk->sighand->rlim[RLIMIT_AS].rlim_cur <
			(rlim_t)(req_tsk->p_ve_mm->vm_size + size)) {
		VEOS_DEBUG("tsk address space limit exceeds current map"
				"request");
		ret = -ENOMEM;
		goto hndl_req;
	}
	/*
	 * check page mode of requestor
	 */
	dir_num = __get_pgd(req_vemva, &req_mm->atb, -1, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for req vemva %lx",
				strerror(-ret), req_vemva);
		goto hndl_req;
	}
	req_pgmod = ps_getpgsz(&req_mm->atb.dir[dir_num]);

	if (own_pgmod != req_pgmod) {
		VEOS_DEBUG("VESHM req/owner page mode mismatched");
		ret = -EINVAL;
		goto hndl_req;
	}
	/*Now Update requestor ATB*/
	memcpy(&req_atb, &(req_mm->atb), sizeof(atb_reg_t));
	for (start = 0; start < count; start++) {
		temp_addr = req_vemva + (start * pgsz);
		dir_num = validate_vemva(temp_addr, rw,
				pgno[start], &req_atb,
				own_pgmod);
		if (dir_num < 0) {
			VEOS_DEBUG("failed to validate vemva %lx",
					temp_addr);
			ret = dir_num;
			goto hndl_req;
		}

		if (prv_dir == -1 || (prv_dir != dir_num))
			dirs[i++] = dir_num;
		prv_dir = dir_num;

	}


	memcpy(&(req_mm->atb),
			&req_atb, sizeof(atb_reg_t));

	i = 0;

	while (0 <= dirs[i]) {
		psm_sync_hw_regs(req_tsk, _ATB, &req_tsk->p_ve_mm->atb,
				true, dirs[i++], 1);
	}

	req_tsk->p_ve_mm->vm_size += size;
	pthread_mutex_lock_unlock(&req_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
	goto free_mem;
hndl_req:
	pthread_mutex_lock_unlock(&req_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
	for (i = 0; pb[i]; i++)
		amm_put_page(pb[i]);
	goto free_mem;
hndl_ownr:
	pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
free_mem:
	if (pgno)
		free(pgno);
	if (pb)
		free(pb);
hndl_return:
	if (req_tsk)
		put_ve_task_struct(req_tsk);
	if (own_tsk)
		put_ve_task_struct(own_tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will unshare the memory mapped by requestor.
*
* @param[in] req process identifier of requestor process.
* @param[in] req_vemva VE virtual address of memory mapped by requestor.
* @param[in] size total size of memory to be unshared.
*
* @return on success return 0 and negative of errno on failure.
*/
int veos_unshare_vemva_region(pid_t req, vemva_t req_vemva, size_t size)
{
	struct ve_task_struct *tsk = NULL;
	ret_t ret = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("unmap veshm vemva 0x%lx"
			"of size %ld for pid(%d)",
			req_vemva, size, req);

	tsk = find_ve_task_struct(req);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting tsk with pid %d",
			strerror(-ret), req);
		goto unshare_vemva;
       }


	ret = amm_do_munmap(req_vemva, size, tsk, true);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in unmap veshm vemva 0x%lx"
		"of size %ld for pid(%d)",
		strerror(-ret), req_vemva, size, req);
		goto unshare_vemva;
	}

unshare_vemva:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function initialize the page array within  mapping descriptor.
*
* @param[in] map_desc map_desc mapping descriptor page array of which has to be updated.
* @param[in] map_attri map_attri Pointer to struct mapping attributes.
*/
void init_page_array(struct mapping_desc *map_desc,
		struct mapping_attri *map_attri)
{
	struct list_head *list_tmp = NULL;
	struct list_head *list_start = NULL;
	struct list_head *list_end = NULL;
	struct mapping_desc *map_desc_tmp = NULL;
	int64_t cur_off_start = 0;
	int64_t cur_off_end = 0;
	int64_t off_s = 0;
	int64_t off_e = 0;
	pgno_t *cur_pgno = NULL;
	pgno_t *pgno = NULL;
	int64_t idx = 0, count = 0;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("map merge [start(%p) - end(%p)\n"
			"map off range [%ld -- %ld]\n"
			"insert after(%p)",
			map_attri->merge_start,
			map_attri->merge_end,
			map_attri->offset_start,
			map_attri->offset_end,
			map_attri->insert_after);

	pgno = map_desc->pg_array;

	list_start = map_attri->merge_start;
	list_end = map_attri->merge_end;
	off_s = map_attri->offset_start;
	off_e = map_attri->offset_end;

	if ((!list_start) || (!list_end)) {
		for (idx = off_s; idx <= off_e;
				idx++)
			pgno[idx-off_s] = -1;
		return;
	}

	idx = 0;
	list_tmp = list_start;
	count = off_e - off_s;

	/*Traverse from merge start to merge end*/
	while (idx <= count) {
		map_desc_tmp = list_entry(list_tmp,
				struct mapping_desc, mapping_list);
		cur_off_start = map_desc_tmp->offset_start;
		cur_off_end = map_desc_tmp->offset_end;
		cur_pgno = map_desc_tmp->pg_array;

		while ((off_s + idx) <= cur_off_end) {
			if ((off_s + idx) < cur_off_start)
				pgno[idx] = -1;
			else
				pgno[idx] =
					cur_pgno[idx -
					(cur_off_start - off_s)];

			idx++;
		}

		if (list_tmp == list_end) {
			while (idx <= count) {
				pgno[idx] = -1;
				idx++;
			}
		}
		list_tmp = list_tmp->next;
	}
	VEOS_TRACE("returned");
}

/**
 * @brief This function remove the redundant mapping_descriptor
 *        instances left after merging.
 *
 * @param[in] list_start Pointer to list_head to start.
 * @param[in] list_end Pointer to list_head to end.
 *
 * @return return pointer to the list_head to insert after on success.
 */
struct list_head *free_redundant_list(struct list_head *list_start,
		struct list_head *list_end)
{
	struct mapping_desc *fmap_desc = NULL;
	struct list_head *insert_after = NULL;
	struct list_head *insert_before = NULL;
	struct list_head *list_tmp = NULL;

	VEOS_TRACE("invoked");

	insert_after = list_start->prev;
	insert_before = list_end->next;

	VEOS_DEBUG("start(%p) and end(%p)", list_start, list_end);

	VEOS_TRACE("iterating for list start and end");
	for (list_tmp = list_start; list_tmp != insert_before;
			list_tmp = insert_after->next) {
		fmap_desc = list_entry(list_tmp,
				struct mapping_desc, mapping_list);

		VEOS_TRACE("map desc(%p) with pgarray(%p)",
				fmap_desc,
				fmap_desc->pg_array);

		__list_del(list_tmp->prev, list_tmp->next);
		free(fmap_desc->pg_array);
		free(fmap_desc);
	}
	VEOS_TRACE("iteration ends");
	VEOS_TRACE("returned");
	return insert_after;
}
/**
* @brief This function sets the page_array entry to null in case
*        the page offset becomes zero.
*
* @param[in] map_desc reference to the mapping_desc of particular mapping.
* @param[in] pg_num VE physical page number.
*/
void clear_page_array_entry(struct mapping_desc *map_desc,
		pgno_t pg_num)
{
	off_t off_start = 0;
	off_t off_end = 0;
	pgno_t *pgno = NULL;
	uint64_t i = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("clearing VE page %ld from map desc",
		pg_num);
	/*Get mapping_des c_lock here*/
	if (NULL == map_desc)
		return;

	off_start = map_desc->offset_start;
	off_end = map_desc->offset_end;
	pgno = map_desc->pg_array;

	VEOS_DEBUG("fmap(%p): off range[%ld - %ld] :pgarray(%p)",
		map_desc, off_start, off_end, pgno);

	VEOS_TRACE("iteration starts to find matching VE page");
	for (i = 0; i <= (off_end-off_start); i++) {
		if (pgno[i] == pg_num) {
			map_desc->file_desc->in_mem_pages--;
			pgno[i] = -1;
			VEOS_TRACE("fmap(%p) has %ld in memory VE pages",
				map_desc, map_desc->file_desc->in_mem_pages);
			break;
		}
	}
	VEOS_TRACE("iteration ends");

	/*Release mapping_desc_lock here*/
	VEOS_TRACE("returned");
	return;
}

/**
 * @brief This function sets the entry bit of within given bitmap.
 *
* @param[in] bitmap bitmap in which entry to be set.
* @param[in] entry entry for which bit to be set.
*/
void set_bit(uint64_t *bitmap, uint64_t entry)
{
	uint64_t word = 0, bit = 0;

	VEOS_TRACE("invoked");

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;
	bitmap[word] = bitmap[word] | ((uint64_t)1 << bit);

	VEOS_TRACE("returned");
}


/**
 * @brief This function sets the count bits in bitmap from entry index.
 *
 * @param[in] bitmap 256 bit bitmap.
 * @param[in] entry starting enrty number from which bit be set.
 * @param[in] count total entries to be set.
 */
void set_bits(uint64_t *bitmap, uint64_t entry, uint16_t count)
{
	int64_t word = 0, bit = 0;
	int ent = 0;

	VEOS_TRACE("invoked");
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		bitmap[word] = bitmap[word] |
			((uint64_t)1 << bit++);
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	VEOS_TRACE("returned");
}

/**
 * @brief This function dumps the contents of the mapping
 *	  descriptor for debuging purpose.
 *
 * @param[in] map_desc reference to the mapping descriptor which is to be dump.
 */
void dump_mapping_desc(struct mapping_desc *map_desc)
{
	off_t offset_start = 0;
	off_t off_e = 0;
	uint64_t i = 0;
	pgno_t *pgno = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");
	VEOS_DEBUG("dump map desc");
	offset_start = map_desc->offset_start;
	off_e = map_desc->offset_end;

	pgno = map_desc->pg_array;
	VEOS_TRACE("iteration starts for fmap pages");

	for (i = 0; i <= off_e-offset_start; i++) {
		VEOS_TRACE("offset(%ld) VE page %ld", i,
				 pgno[i]);
		if (pgno[i] != -1)
			VEOS_TRACE("VE page %ld with refcnt %ld",
			pgno[i],
			VE_PAGE(vnode, pgno[i])->ref_count);
	}

	VEOS_TRACE("returned");
}

/**
* @brief This function updates the mapping descriptor and page_array specifically.
*
* @param[in] vaddr VE virtual address of given mapping.
* @param[in] pgno array which containing page number allready allocated.
* @param[in] count total number of pages required.
* @param[in] pgmod page mode for given mapping.
* @param[in] tsk process task struct.
* @param[in] file file descriptor associated with the given mapping.
* @param[in] off_s staring offset withing file from where mapping is started.
* @param[out] map this array will contain page number of old and newly allocated VE papes.
*
* @return on success return 0 and negative of errno on failure.
*/
ret_t update_mapping_desc(vemva_t vaddr, pgno_t *pgno,
		uint64_t count, int pgmod, struct ve_task_struct *tsk,
		struct file_desc *file, off_t off_s, pgno_t *map)
{
	uint64_t idx = 0;
	size_t pgsz = 0;
	pgno_t pg_no[count];
	size_t sent_size = 0;
	uint64_t file_size = 0;
	ssize_t tmp_size = 0;
	ssize_t rest_size = 0;
	ret_t ret = 0;
	pgno_t *p_array = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	ve_dma_hdl *dh = vnode_info->dh;


	VEOS_TRACE("invoked");
	file_size = (uint64_t)file->stat.st_size;

	memset((void *)pg_no, 0xff, sizeof(pg_no));
	pgsz = pgmod_to_pgsz(pgmod);
	sent_size = off_s * pgsz;
	if (file_size > sent_size)
		rest_size = file_size - sent_size;
	else
		rest_size = 0;

	VEOS_DEBUG("file_size 0x%lx offset_start 0x%lx sent_size 0x%lx\
			rest_size 0x%lx pgsz 0x%lx", file_size, off_s,
			sent_size, rest_size, pgsz);

	for (idx = 0; idx < count; idx++) {
		if (0 > pgno[idx])	{
			/*We will allocate a new page here*/
			VEOS_DEBUG("allocating 1 %s at map(%p) and idx(%ld)",
				pgmod_to_pgstr(pgmod), map, idx);
			ret = alloc_ve_pages(1, map + idx, pgmod);
			if (0 > ret) {
				VEOS_DEBUG("failed to allocate VE mem");
				ret = -ENOMEM;
				goto err;
			}
			/**
			 * Init pgno element with pointer to
			 * struct ve_page
			 */
			pgno[idx] = map[idx];
			pg_no[idx] = map[idx];
			/* Update Number of In memory pages */
			file->in_mem_pages++;
			VEOS_DEBUG("index(%ld), pgno(%ld) and %ld in"
				"mem pages for file",
				idx, pgno[idx],
				file->in_mem_pages);
			if (rest_size < pgsz) {
				if (rest_size <= 0)
					continue;
				tmp_size = rest_size;
				if (tmp_size % 8)
					tmp_size = tmp_size -
						(tmp_size % 8) + 8;
			} else
				tmp_size = pgsz;

			VEOS_DEBUG("rest_size 0x%lx tmp_size 0x%lx",
					rest_size, tmp_size);

			if (VE_DMA_STATUS_OK != ve_dma_xfer_p_va(dh,
						VE_DMA_VHVA, tsk->pid,
						vaddr+(idx*pgsz),
						VE_DMA_VEMAA, 0,
						pbaddr(map[idx], PG_2M),
						tmp_size)) {
				VEOS_DEBUG("amm_dma_xfer failed");
				ret = -EFAULT;
				goto err;
			}
			rest_size -= tmp_size;
		} else {
			VEOS_DEBUG("when access pg map[%ld]: 0x%p", idx,
					&pgno[idx]);
			VEOS_DEBUG("page number = %lx", pgno[idx]);
			map[idx] = pgno[idx];

			VEOS_DEBUG("page_number when access: %lu",
					map[idx]);
			rest_size -= pgsz;
		}
	}

	p_array = calloc((count + 1), (sizeof(uint64_t)));
	if (NULL == p_array) {
		VEOS_CRIT("failed to allocate page map to hold %ld pages",
				(count+1));
		ret = -ENOMEM;
		goto err;
	}

	/*Convert page number into physical address*/
	for (idx = 0; idx < count; idx++) {
		p_array[idx] = pbaddr(map[idx], PG_2M);
		VEOS_DEBUG("Page is :%ld allocated for vemva :%lx",
				map[idx], vaddr);
	}

	/*Increament the ref count of all newly allocate pages*/
	amm_get_page(p_array);
	free(p_array);
	return ret;
err:
	for (idx = 0; idx < count; idx++) {
		VEOS_DEBUG("free page number 0x%lx", pg_no[idx]);
		if (0 < pg_no[idx]) {
			pthread_mutex_lock_unlock(&vnode_info->ve_pages_node_lock,
				LOCK, "Fail to acquire ve page lock");
			if (veos_free_page (pg_no[idx]))
				VEOS_DEBUG("fail to free page number 0x%lx",
						pg_no[idx]);
			pthread_mutex_lock_unlock(&vnode_info->ve_pages_node_lock,
				UNLOCK, "Fail to release ve page lock");
			if (file->in_mem_pages)
				file->in_mem_pages--;
		}
	}
	return ret;
}

/**
* @brief This function will compare elements of two file stats.
*
* @param[in] filed file descriptor to be compaire.
* @param[in] file file descriptor with which to be compaire.
* @param[in] flags memory mapping flags.
*
* @return if file descriptor of both file are identical the return 0 else return -1.
*/
int stat_cmp(struct file_desc *filed, struct file_stat *file, flag_t flags)
{
	int ret = -1;

	VEOS_TRACE("invoked");

	/* In case of file backed mmap() with MAP_PRIVATE, VEOS checks inode number,
	 * mtime and ctime, in order to load the latest content of the file.
	 */
	if ((flags & MAP_PRIVATE) &&
			(filed->stat.st_dev == file->stat.st_dev) &&
			(filed->stat.st_ino == file->stat.st_ino) &&
			(filed->pgsz == file->pgsz) &&
			(filed->stat.st_mtim.tv_sec == file->stat.st_mtim.tv_sec) &&
			(filed->stat.st_mtim.tv_nsec == file->stat.st_mtim.tv_nsec) &&
			(filed->stat.st_ctim.tv_sec == file->stat.st_ctim.tv_sec) &&
			(filed->stat.st_ctim.tv_nsec == file->stat.st_ctim.tv_nsec))
		ret = 0;

	/* In case of file backed mmap() with MAP_SHARED, VEOS checks only inode number,
	 * in order to share VE physical memory.
	 */
	if ((flags & MAP_SHARED) &&
			(filed->stat.st_dev == file->stat.st_dev) &&
			(filed->stat.st_ino == file->stat.st_ino) &&
			(filed->pgsz == file->pgsz)) {
		VEOS_DEBUG("Inode: %ld prev size: %ld new size: %ld in bytes",
				file->stat.st_ino,
				filed->stat.st_size,
				file->stat.st_size);
		ret = 0;
	}

	VEOS_TRACE("returned");

	return ret;
}

/**
* @brief This function collects the attibutes about new mapping like where
*	the new mapping will be added in list.
*
* @param[in] file_desc_t reference to the file descriptor.
* @param[in] offset_start start offset within file.
* @param[in] off_e end offset within file.
*
* @return on success returns mapping attribute and null on failure.
*/
struct mapping_attri *collect_map_attri(struct file_desc *file_desc_t,
		off_t offset_start, off_t off_e)
{
	struct list_head *temp_head = NULL;
	struct list_head *insert_after = NULL;
	struct list_head *merge_start = NULL;
	struct list_head *merge_end = NULL;
	struct mapping_attri *map_attri = NULL;
	struct mapping_desc *fmap_desc = NULL;
	struct mapping_desc *start_merge_desc = NULL;
	struct mapping_desc *end_merge_desc = NULL;
	off_t cur_offset_start = 0;
	off_t cur_offset_end = 0;
	off_t new_offset_start = 0;
	off_t new_offset_end = 0;

	VEOS_TRACE("invoked");
	/*
	 * Traverse through the existing mapping list.
	 * Here we will compare the offest start and end of the new mapping
	 * with offset start and end of existing mappings in the list and
	 * will decide which of the existing mappings will be merged with
	 * the new mapping.
	 */
	VEOS_TRACE("iterating file(%p) maps for s_off(%ld) e_off(%ld)",
			file_desc_t, offset_start, off_e);
	list_for_each(temp_head, &file_desc_t->mapping_list) {
		fmap_desc = list_entry(temp_head,
				struct mapping_desc, mapping_list);

		VEOS_TRACE("map(%p) with range[%ld -- %ld]",
			(void *)fmap_desc,
			fmap_desc->offset_start,
			fmap_desc->offset_end);

		cur_offset_start = fmap_desc->offset_start;
		cur_offset_end = fmap_desc->offset_end;
		if (!merge_start) {
			VEOS_TRACE("valid merge start(%p)",
					merge_start);

			VEOS_TRACE("start off(%ld) and curr end off(%ld)",
					offset_start, cur_offset_end);

			if (offset_start <= cur_offset_end + 1) {
				merge_start = temp_head;
				if (off_e <= cur_offset_end) {
					if (off_e < (cur_offset_start - 1)) {
						merge_start = NULL;
						merge_end = NULL;
						insert_after = temp_head->prev;
					} else {
						merge_end = temp_head;
					}
					break;
				}
			}
		} else if (!merge_end) {
			VEOS_TRACE("valid merge end(%p)",
					merge_end);
			VEOS_TRACE("end off(%ld) and curr end off(%ld)",
					off_e, cur_offset_end);
			if (off_e <= cur_offset_end) {
				if (off_e < cur_offset_start - 1)
					merge_end = temp_head->prev;
				else
					merge_end = temp_head;
				break;
			}
		}
	}
	VEOS_TRACE("iterating file maps end");

	VEOS_DEBUG("merge_start(%p) and merge_end(%p)",
			merge_start, merge_end);

	if (merge_start && (!merge_end))
		merge_end = merge_start;

	VEOS_DEBUG("merge_start(%p) and merge_end(%p)",
			merge_start, merge_end);

	/*We must have merge_start and merge_end by now*/
	if ((!merge_start) && (!merge_end)) {
		new_offset_start = offset_start;
		new_offset_end = off_e;
	} else {
		start_merge_desc = list_entry(merge_start, struct mapping_desc,
				mapping_list);
		end_merge_desc = list_entry(merge_end, struct mapping_desc,
				mapping_list);
		cur_offset_start = start_merge_desc->offset_start;
		cur_offset_end = end_merge_desc->offset_end;

		new_offset_start = cur_offset_start < offset_start ?
			cur_offset_start : offset_start;
		new_offset_end = cur_offset_end > off_e ?
			cur_offset_end : off_e;
	}

	VEOS_DEBUG("merge_start(%p) and merge_end(%p)",
			merge_start, merge_end);

	VEOS_DEBUG("offset start(%ld) and new start(%ld)",
			offset_start, new_offset_start);
	VEOS_DEBUG("offset end(%ld) and new end(%ld)",
			off_e, new_offset_end);

	map_attri = calloc(1, sizeof(struct mapping_attri));
	if (NULL == map_attri) {
		VEOS_CRIT("failed to allocate memory for mapping attribute");
		goto map_attr_end;
	}

	map_attri->merge_start = merge_start;
	map_attri->merge_end = merge_end;
	map_attri->offset_start = new_offset_start;
	map_attri->offset_end = new_offset_end;
	map_attri->insert_after = insert_after;

	VEOS_DEBUG("map merge [start(%p) - end(%p)\n"
			"map off range [%ld -- %ld]\n"
			"insert after(%p)",
			map_attri->merge_start,
			map_attri->merge_end,
			map_attri->offset_start,
			map_attri->offset_end,
			map_attri->insert_after);

	/* We Must have offset_start and offset end of the
	 * new descriptor till Now
	 */
map_attr_end:
	VEOS_TRACE("returned");
	return map_attri;
}

/**
* @brief This function add the new mapping descriptor in existing mapping list.
*
* @param[in] file_desc file_desc with which the mapping is associated.
* @param[in] map_desc mapping descriptor which is to be add.
* @param[in] map_attri mapping attibutes.
*/
void add_mapping_desc(struct file_desc *file_desc,
		struct mapping_desc *map_desc,
		struct mapping_attri *map_attri)
{
	struct list_head *merge_start = NULL;
	struct list_head *merge_end = NULL;
	struct list_head *insert_after = NULL;

	VEOS_TRACE("invoked");
	merge_start = map_attri->merge_start;
	merge_end = map_attri->merge_end;
	insert_after = map_attri->insert_after;

	if ((merge_start) && (merge_end)) {
		insert_after = free_redundant_list(merge_start, merge_end);
		list_add(&map_desc->mapping_list, insert_after);
	} else if (insert_after) {
		list_add(&map_desc->mapping_list, insert_after);
	} else {
		list_add_tail(&map_desc->mapping_list,
				&file_desc->mapping_list);
	}

	VEOS_TRACE("returned");
}

/**
 * @brief This functions check that request bits are already used or not.
 *
 * @param[in] bitmap pseudo vemva list bitmap.
 * @param[in] entry Offset in the list
 * @param[in] count total entries to be check.
 *
 * @return On Success, it returns 0 and -1 on failure.
 */
int check_bits_set(uint64_t *bitmap, uint64_t entry, uint64_t count)
{
	uint64_t word = 0, bit = 0;
	uint64_t ent = 0;

	VEOS_TRACE("invoked");
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		if (!(bitmap[word] & ((uint64_t)1 << bit++)))
			goto err_out;
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
	return 0;
err_out:
	return -1;
}

/**
* @brief This function copy the file data from VH memory to VE memory.
*
* @param[in] vaddr VE virtual address of on which file is mapped.
* @param[in] s_off start offset
* @param[in] f_sz file size
* @param[in] tsk process task struct.
* @param[in] map_sz total mapped size.
* @param[in] pgsz page size with which memory is mapped.
*
* @return on success returns 0 and negative of errno on failure.
*/
int send_file_data(vemva_t vaddr, off_t s_off, size_t f_sz,
		struct ve_task_struct *tsk, size_t map_sz,
		size_t pgsz, pgno_t *map)
{
	vemva_t ve_addr = vaddr;
	vhva_t vh_addr = vaddr;
	size_t rest_sz = 0;
	uint64_t sent_data = 0;
	int ret = 0, i = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	ve_dma_hdl *dh = vnode_info->dh;
	/*
	 * File content are read and send to VE memory
	 */

	VEOS_TRACE("invoked");

	VEOS_DEBUG("sync %s mapped vemva(%lx) of map sz(%ld) for"
			"tsk:pid(%d) from file off(%ld) and file size(%ld)",
			pgsz_to_pgstr(pgsz), vaddr, map_sz,
			tsk->pid, s_off, f_sz);

	f_sz -= (s_off*pgsz);
	while (f_sz && map_sz) {
		if (f_sz/pgsz) {
			VEOS_DEBUG("in if condition");
			sent_data = pgsz;
			f_sz -= pgsz;
		} else {
			VEOS_DEBUG("in else condition");
			rest_sz = f_sz%pgsz;
			if (rest_sz % 8) {
				VEOS_DEBUG("in if condition of else ");
				sent_data = (rest_sz -
						(rest_sz % 8)) + 8;
				VEOS_DEBUG("sent_data = %ld", sent_data);
			} else
				sent_data = rest_sz;
			f_sz -= rest_sz;
		}

		if (VE_DMA_STATUS_OK != ve_dma_xfer_p_va(dh,
					VE_DMA_VHVA, tsk->pid,
					vh_addr+(i*pgsz),
					VE_DMA_VEMAA, 0,
					pbaddr(map[i], PG_2M),
					sent_data)) {
			VEOS_DEBUG("data transfer failed from vhva(%lx)"
					"to vemva(%lx) of size(%ld) for tsk:pid(%d)",
					vh_addr, ve_addr, sent_data, tsk->pid);
			return -EFAULT;
		}
		map_sz -= pgsz;
		i++;
	}

	return ret;
}

/**
 * @brief This function calculates the total physical memory in kb
 *         taken by the VE process.
 *
 * @param[in] mm reference to struct ve_mm_struct of VE process.
 *
 * @return always return total memory mapped by process.
 */
uint64_t amm_get_rss_in_kb(struct ve_mm_struct *mm)
{
	uint64_t max_rss = 0;
	int type = 0;
	atb_reg_t *atb = &(mm->atb);
	int entry_cntr = -1, dir_cntr = -1;

	VEOS_TRACE("invoked");
	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			type = ps_getpgsz(&(atb->dir[dir_cntr]));
			for (entry_cntr = 0; entry_cntr < ATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(atb->entry[dir_cntr][entry_cntr]))) {
					if (type == PG_2M)
						max_rss += PAGE_SIZE_2MB;
					else if (type == PG_HP)
						max_rss += PAGE_SIZE_64MB;
				}
			} /* end entry loop */
		} /* end*/
	} /* end dir loop */

	/* converting in kb */
	max_rss = max_rss/1024;
	return max_rss;
}

/**
* @brief This function will extract file page offset from mapping descriptor by
*	comparing with input struct ve_page.
*
* @param[in] vemva VE virtual address of meomory on which file is mapped.
* @param[in] tsk process task struct.
* @param[in] file_size size of mapped file.
* @param[in] map_desc mapping file descriptor.
*
* @return return file page offset on success and negative of errno on failure.
*/
int64_t extract_file_pgoff(vemva_t vemva, struct ve_task_struct *tsk,
		size_t *file_size, struct mapping_desc **map_desc)
{
	uint64_t index = 0;
	pgno_t pgno = 0;
	vemaa_t pb = 0;
	struct ve_page *ve_page = NULL;
	struct file_desc *f_desc = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct mapping_desc *fmap_desc = NULL;
	atb_reg_t atb = { { { {0} } } };

	VEOS_TRACE("invoked");
	memset(&atb, 0, sizeof(atb_reg_t));

	memcpy(&atb, &tsk->p_ve_mm->atb, sizeof(atb_reg_t));

	pb = __veos_virt_to_phy(vemva, &atb, NULL, NULL);
	if (0 > pb) {
		VEOS_DEBUG("vemva 0x%lx not valid", vemva);
		return -EINVAL;
	}
	pgno = pfnum(pb, PG_2M);

	ve_page = VE_PAGE(vnode, pgno);
	if (NULL == ve_page) {
		VEOS_DEBUG("VE page %ld not allocated",
			pgno);
		return -EINVAL;
	}

	if ((ve_page->private_data) && !(ve_page->flag & PG_SHM)) {
		pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
				"Fail to acquire ve page lock");
		fmap_desc = (struct mapping_desc *)ve_page->private_data;
	} else {
		VEOS_DEBUG("vemva 0x%lx not file backed",
			vemva);
		return -EINVAL;
	}

	f_desc = (fmap_desc)->file_desc;
	if (file_size) {
		*file_size = f_desc->stat.st_size;
		VEOS_DEBUG("file size of desc is %ld",
			*file_size);
	}
	if (map_desc)
		*map_desc = fmap_desc;

	pgno_t *pgnum = fmap_desc->pg_array;
	off_t offset_start = fmap_desc->offset_start;
	off_t off_e = fmap_desc->offset_end;

	for (index = 0; index <= (off_e-offset_start);
			index++) {
		if (pgnum[index] != -1)
			if ((VE_PAGE(vnode, pgnum[index])) == ve_page) {
				pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
						UNLOCK,	"Fail to release"
						"ve page lock");
				return offset_start + index;
			}
	}

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Fail to release ve page lock");
	VEOS_TRACE("returned");
	return -EINVAL;
}

/**
* @brief This function will check whether mapping with
*        given address is file backed or not.
*
* @param[in] addr VE virtual memory address.
* @param[in] pid process identifier.
*
* @return always returns size of mapping which is file backed.
*/
size_t is_addr_file_backed(uint64_t addr, struct ve_task_struct *tsk)
{
	size_t file_size = 0;
	size_t rest_size = 0;
	size_t size_off = 0;
	uint64_t pgsz = 0;
	int64_t pgoff = 0;
	int8_t pgmod = 0;

	VEOS_TRACE("invoked");

	pgoff = extract_file_pgoff(addr, tsk, &file_size, NULL);
	if (0 > pgoff) {
		VEOS_DEBUG("extract_file_pgoff Return");
		/*Addr not file backed*/
		rest_size = 0;
		goto hndl_return;
	}

	pgmod = __veos_get_pgmode(VE_ADDR_VEMVA, tsk, addr);
	if (PG_2M == pgmod)
		pgsz = PAGE_SIZE_2MB;
	else if (PG_HP == pgmod)
		pgsz = PAGE_SIZE_64MB;

	size_off = (pgoff * pgsz);
	rest_size = file_size - size_off;

	/*Roundup rest_size by 8 Bytes*/
	if (rest_size % 8)
		rest_size = (rest_size & ~(size_t)(8-1)) + 8;

	VEOS_DEBUG("page offset %ld | page size %ld | file_ size %ld\n"
			"size_off %ld | rest_size %ld",
			pgoff, pgsz, file_size, size_off, rest_size);
hndl_return:
	return rest_size;
}

/**
 * @brief This is generic handler for process_vm_rw if will read/write
 *	operation to/from  specified pid.
 *
 * @param[in] task Pointer of ve_task_struct of the VE process
 * @param[in] ve_process_rw_info Structure which contain the information.
 *
 * @return On success return 0, -1 on failure.
 */
int amm_do_processs_vm_rw(struct ve_task_struct *tsk,
		struct ve_process_rw_info ve_process_rw_info)
{
	vemva_t l_vemva = 0, r_vemva = 0, b_rvemva = 0;
	uint64_t len = 0;

	VEOS_TRACE("invoked");
	l_vemva = ve_process_rw_info.lcov_offset +
		ve_process_rw_info.local_vemva;
	r_vemva = ve_process_rw_info.rcov_offest +
		ve_process_rw_info.remote_vemva;
	b_rvemva = ve_process_rw_info.base_rvemva;
	len = ve_process_rw_info.r_len;
	int ret;
	struct ve_rw_check_iovec rw_args;
	void *r_buff = NULL;

	/* check r/w permission on remote VEMVA */
	if (b_rvemva == r_vemva) {
		rw_args.vaddr = b_rvemva;
		rw_args.len = len;
		rw_args.pid = ve_process_rw_info.r_pid;
		rw_args.type = ve_process_rw_info.vm_rw;
		ret = amm_rw_check_permission(tsk, rw_args);
		if (0 > ret) {
			VEOS_DEBUG("Fail to check permission");
			return -1;
		}
	}
	rw_args.vaddr = l_vemva;
	rw_args.len = ve_process_rw_info.len;
	rw_args.pid = tsk->pid;
	rw_args.type = !(ve_process_rw_info.vm_rw);

	/*
	 * We Do not need to check protection here when
	 * DMA will check protection internally. Which will be done
	 * under task refs #230
	 */
	ret = amm_rw_check_permission(tsk, rw_args);
	if (0 > ret) {
		VEOS_DEBUG("Fail to check permission");
		return -1;
	}

	if (ve_process_rw_info.vm_rw) {
		/* Here we are first recv data from local vemva to
		 * VH buffer than we will write the data from VH buffer
		 * to remote VEMVA
		 */
		r_buff = malloc(len);
		if (NULL == r_buff) {
			ret = -ret;
			VEOS_CRIT("Error (%s) while allocting remote"
					"buff",	strerror(-ret));
			return -ret;
		}
		/*MEMSET*/
		memset(r_buff, '\0', len);
		ret = amm_recv_data(tsk->pid, l_vemva,
				ve_process_rw_info.len, r_buff);
		if (0 > ret) {
			VEOS_DEBUG("Failed to recv the data");
			free(r_buff);
			return ret;
		}
		ret = amm_send_data(ve_process_rw_info.r_pid, r_vemva,
				ve_process_rw_info.len,	r_buff);
		if (0 > ret) {
			VEOS_DEBUG("Failed to send the data");
			free(r_buff);
			return ret;
		}
	} else {
		/* Here we are first recv data from remote vemva to
		 * VH buffer than we will write data from VH buffer
		 * to local VEMVA
		 */
		r_buff = malloc(len);
		if (NULL == r_buff) {
			ret = -ret;
			VEOS_CRIT("Error (%s) while allocting remote"
					"buff",	strerror(-ret));
			return -ret;
		}
		/*MEMSET*/
		memset(r_buff, '\0', len);
		ret = amm_recv_data(ve_process_rw_info.r_pid, r_vemva,
				ve_process_rw_info.len, r_buff);
		if (0 > ret) {
			VEOS_DEBUG("Failed to recv the data");
			free(r_buff);
			return ret;
		}
		ret = amm_send_data(tsk->pid, l_vemva,
				ve_process_rw_info.len,	r_buff);
		if (0 > ret) {
			VEOS_DEBUG("Failed to send the data");
			free(r_buff);
			return ret;
		}
	}
	if (r_buff)
		free(r_buff);
	return 0;
}
/**
 * @brief This function check write permission of given address for specified
 *	process.
 *
 * @param[in] vaddr VEMVA address to check the permission
 * @param[in] pid Pid of process to check the permission.
 *
 * @return On success return 0, -1 on failure.
 */
int check_write_permisssion(vemva_t vaddr, pid_t pid)
{
	int ret = 0, pgmod_dir = 0;
	int32_t dir_num = 0, pgoff = 0;
	struct ve_task_struct *ve_task = NULL;
	atb_reg_t *atb = NULL;

	VEOS_TRACE("invoked for vemva %lx of pid(%d)", vaddr, pid);
	/* Get ve task struct */
	ve_task = find_ve_task_struct(pid);
	if (NULL == ve_task) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
			strerror(-ret), pid);
		goto err;
	}
	atb = &(ve_task->p_ve_mm->atb);

	dir_num = __get_pgd(vaddr, atb, -1, false);
	if (0 > dir_num) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in getting pgd for vemva %lx",
			strerror(-ret), vaddr);
		put_ve_task_struct(ve_task);
		return ret;
	}

	pgmod_dir = ps_getpgsz(&atb->dir[dir_num]);
	pgoff = pgentry(vaddr, pgmod_dir);

	if (!pg_isvalid(&(atb->entry[dir_num][pgoff]))) {
		VEOS_DEBUG("ATB ENTRY not yet allocated");
		put_ve_task_struct(ve_task);
		ret = -1;
		return ret;
	}
	/* Check VEMVA is write protected or not */
	if (pg_isprot(&(atb->entry[dir_num][pgoff]))) {
		VEOS_DEBUG("DIR %d PGOFF %d is write protected",
				dir_num, pgoff);
		put_ve_task_struct(ve_task);
		return -1;
	} else {
		VEOS_DEBUG("DIR %d PGOFF %d is not write protected",
				dir_num, pgoff);
	}
	put_ve_task_struct(ve_task);
	return 0;
err:
	VEOS_TRACE("returned with error");
	return ret;
}

/**
 * @brief Initialize jid struct
 */
int64_t veos_jid_init(void)
{
	int i = 0;

	VEOS_TRACE("invoked");
	jid_globl.max_jid = MAX_JID_PROCESS;
	mean_heap = 0;
	if (0 != pthread_mutex_init(&(jid_globl.mtx), NULL)) {
		VEOS_DEBUG("Mutex init failed ");
		return -1;
	}
	for (i = 0; i < MAX_JID_PROCESS; i++) {
		INIT_LIST_HEAD(&(jid_globl.jid_arr[i].pid));
		jid_globl.jid_arr[i].ref = 0;
	}

	for (i = 0; i < WORDS_PER_BITMAP; i++)
		jid_globl.bmap_jid_free[i] = 0;
	VEOS_TRACE("returned");
	return 0;
}
/**
 * @brief This function will assign Job id.
 *
 * @param[in,out] tsk reference to process task struct.
 *
 * @return On success return 0, -1 on error;
 */
int64_t veos_get_jid(struct ve_task_struct *tsk)
{
	uint64_t i = 0, cnt = 0, x = 0;
	jid_t jid = 0;

	VEOS_TRACE("invoked");
	pthread_mutex_lock_unlock(&jid_globl.mtx, LOCK,
			"Failed to acquire jid lock");
	struct pid_list *plist = (struct pid_list *)malloc(
			sizeof(struct pid_list));
	if (NULL == plist) {
		VEOS_DEBUG("malloc failed");
		goto handl_malloc;
	}
	memset(plist, '\0', sizeof(struct pid_list));

	INIT_LIST_HEAD(&plist->list);

	VEOS_TRACE("plist = %p", plist);
	if (-1 == jid_globl.max_jid) {
		errno = EBUSY;
		VEOS_DEBUG("invalid");
		goto handl_malloc;
	}
	if (!mean_heap) {
		if (jid_globl.max_jid ==  jid_globl.jid_total) {
			VEOS_DEBUG("can't allocate more JID");
			errno = ECANCELED;
			goto handl_malloc;
		}

		for (i = 0; i < WORDS_PER_BITMAP; i++)	{
			for (x = 0; x < BITS_PER_WORD; x++) {
				if (!((uint64_t)(((uint64_t)jid_globl.
						bmap_jid_free[i]) >> x) & (uint64_t)1)) {
					jid_globl.bmap_jid_free[i] |=
						(uint64_t)((uint64_t)1 << x);
					jid  =  (uint8_t)(cnt);
					goto done;
				}
				cnt++;
			}
		}
done:
		VEOS_DEBUG("returning jid = %d", jid);
		plist->tsk = tsk;
		jid_globl.jid_total++;
		jid_globl.jid_arr[jid].ref++;
		list_add_tail(&plist->list, &(jid_globl.jid_arr[jid]).pid);
	} else  {
		jid = heap_min_array[0].jid;
		VEOS_DEBUG("JID = %d", jid);
		plist->tsk = tsk;
		jid_globl.jid_total++;
		jid_globl.jid_arr[jid].ref++;
		list_add_tail(&plist->list, &(jid_globl.jid_arr[jid]).pid);
		/*
		 * purpose to allocate same jid for multiple ve
		 process considering below points
		 * allocate system call region using MAP_HUGETLB flag
		 * ASSIGN SYSTEM CALL OFFSET IN SIMILAR MANNER as
		 thread get offset for system call arguments
		 * configure dmaatb for system call with 2MB directory
		 because Linux huge page is 2MB sized
		 * VEOS will assign per process shm offset which is multiple
		 of 4KB and from this 4KB page of 2MB huge page thread
		 offset will be assigned
		 * 2MB/4KB process can be run with same jid
		 * cr pages can be managed via sysve library wrapped on
		 each cr access using lcr
		 */
		increaserefcnt(hash[jid]);
	}
	pthread_mutex_lock_unlock(&jid_globl.mtx, UNLOCK,
			"Failed to release jid lock");
	VEOS_TRACE("returning jid = %d", jid);
	return jid;
handl_malloc:
	pthread_mutex_lock_unlock(&jid_globl.mtx, UNLOCK,
			"Failed to release jid lock");
	if (plist) free(plist);
	return -1;
}
/**
 * @brief This function will delete the JID.
 *
 * @param[in] tsk reference to the process task struct.
 */
void veos_free_jid(struct ve_task_struct *tsk)
{

	int x = 0, shift = 0;
	jid_t jid = tsk->jid;
	VEOS_TRACE("invoked");

	pthread_mutex_lock_unlock(&jid_globl.mtx, LOCK,
			"Failed to acquire jid lock");

	x  = jid/BITS_PER_WORD;
	shift = jid % BITS_PER_WORD;
	struct pid_list *plist = NULL;
	struct list_head *temp = NULL, *tmp_list = NULL;

	if ((jid_globl.jid_arr[jid].pid.next == NULL)
			&& (jid_globl.jid_arr[jid].pid.prev ==  NULL)) {
		VEOS_DEBUG("JID LIST are not initialized!");
		pthread_mutex_lock_unlock(&jid_globl.mtx, UNLOCK,
				"Failed to release jid lock");
		return;
	}

	if (!mean_heap) {
		list_for_each_safe(temp, tmp_list,
				&(jid_globl.jid_arr[jid].pid)) {
			plist = list_entry(temp, struct pid_list, list);
			VEOS_DEBUG("JID %d", jid);
			VEOS_TRACE("plist %p", plist);
			if (NULL == plist) {
				pthread_mutex_lock_unlock(&jid_globl.mtx, UNLOCK,
						"Failed to release jid lock");
				return;
			}
			if (plist->tsk == tsk) {
				VEOS_DEBUG("JID %d to be deleted", jid);
				list_del(&plist->list);
				jid_globl.bmap_jid_free[x] &= ~((uint64_t)1 << shift);
				jid_globl.jid_arr[jid].ref--;
				jid_globl.jid_total--;
				free(plist);
			}
		}
	} else {
		VEOS_DEBUG("JID %d", jid);
		list_for_each_safe(temp, tmp_list,
				&(jid_globl.jid_arr[jid].pid)) {
			plist = list_entry(temp, struct pid_list, list);
			VEOS_TRACE("plist %p", plist);
			VEOS_DEBUG("pid of plist %d", plist->tsk->pid);
			if (plist->tsk == tsk) {
				list_del(&plist->list);
				free(plist);
				jid_globl.jid_total--;
				jid_globl.jid_arr[jid].ref--;
				decreaserefcnt(hash[tsk->jid]);

			}
		}
	}
	pthread_mutex_lock_unlock(&jid_globl.mtx, UNLOCK,
			"Failed to release jid lock");
	VEOS_TRACE("returned");
}

/**
 * @brief This function will set new limit for total JID
 *
 * @param[in] cmd Structure of  ve_jid_cmd to specify new JID lim.
 * @param[in] tsk refference to the process task struct.
 *
 * @return On success return 0, -1 on failure.
 */
int amm_do_set_tproc(struct ve_jid_cmd cmd, struct ve_task_struct *tsk)
{
	uid_t veos_uid = 0;

	VEOS_TRACE("invoked");

	veos_uid = getuid();
	if (cmd.uid != veos_uid) {
		VEOS_DEBUG("Operartion not permite");
		errno = EACCES;
		return -1;
	} else if (cmd.j_lim < jid_globl.jid_total) {
		VEOS_DEBUG("Invalid exchange");
		errno = EACCES;
		return -1;
	} else {
		jid_globl.jid_total = cmd.j_lim;
	}
	if (!mean_heap) {
		amm_init_heap_struct();
		mean_heap = 1;
	}
	VEOS_TRACE("returned");
	return 0;
}
/**
 * @brief This function will init array for heap min algorithm.
 */
void amm_init_heap_struct(void)
{
	int i = 0;

	/* Initilizing the geap_min_array */
	for (i = 0; i < MAX_JID_PROCESS; i++) {
		heap_min_array[i].jid = (jid_t)i;
		heap_min_array[i].ref = jid_globl.jid_arr[i].ref;
		hash[i] = i;
	}
	mean_heap = 1;
}

/**
 * @brief This function will increase reference count for gitven JID.
 *
 * @param[in] idx Array index to increase reference count.
 *
 * @return On success return 0, 1 on error.
 */
bool increaserefcnt(int idx)
{
	VEOS_TRACE("invoked");
	if (0 > idx || idx > MAX_JID_PROCESS) {
		VEOS_DEBUG("Invalid index");
		errno = EINVAL;
		return 1;
	}
	heap_min_array[idx].ref++;
	heapifydown(idx);

	VEOS_TRACE("returned");
	return 0;
}

/**
 * @brief This function will decrease reference count for given JID.
 *
 * @param[in] idx idx Array index to decrease refrence count.
 *
 * @return return On success return 0, 1 on error.
 */
bool decreaserefcnt(int idx)
{

	VEOS_TRACE("invoked");
	if (0 > idx || idx > MAX_JID_PROCESS) {
		VEOS_DEBUG("Invalid index");
		errno = EINVAL;
		return (bool)1;
	}

	--heap_min_array[idx].ref;
	heapifyup(idx);
	return (bool)0;
}

/**
 * @brief This function used sort array by recursively.
 *
 * @param[in] idx Index of array to sort.
 */
void heapifyup(int idx)
{

	VEOS_TRACE("invoked");
	int P = PARENT(idx);
	/* Maintain hash table and mean heap array*/
	if (P > 0 && P < MAX_JID_PROCESS && heap_min_array[P].ref >=
			heap_min_array[idx].ref) {
		hash[heap_min_array[P].jid] = idx;
		hash[heap_min_array[idx].jid] = P;
		swap(&heap_min_array[P], &heap_min_array[idx]);
		heapifyup(P);
	}
	if (P == idx)
		return;
	else if (heap_min_array[P].ref >= heap_min_array[idx].ref) {
		hash[heap_min_array[P].jid] = idx;
		hash[heap_min_array[idx].jid] = P;
		swap(&heap_min_array[P], &heap_min_array[idx]);
		heapifyup(P);
	}
}

/**
 * @brief This function used sort array by recursively.
 *
 * @param[in] idx Index of array to sort.
 */
void heapifydown(int idx)
{

	VEOS_TRACE("invoked");
	int min = LEFT(idx);
	int R = RIGHT(idx);

	if (min < MAX_JID_PROCESS && R < MAX_JID_PROCESS &&
			heap_min_array[R].ref <
			heap_min_array[min].ref) {
		min = R;
	}

	if (min < MAX_JID_PROCESS && heap_min_array[min].ref <
			heap_min_array[idx].ref) {
		hash[heap_min_array[min].jid] = idx;
		hash[heap_min_array[idx].jid] = min;
		swap(&heap_min_array[idx], &heap_min_array[min]);
		heapifydown(min);
	}
}

/**
* @brief This function used to Swap the data of two entry in array.
*
* @param[in] x reference to the first heap.
* @param[in] y reference to the second heap.
*/
void swap(heap *x, heap *y)
{
	heap temp = {0};

	VEOS_TRACE("invoked");
	temp.ref = x->ref;
	temp.jid = x->jid;

	x->ref = y->ref;
	x->jid = y->jid;

	y->ref = temp.ref;
	y->jid = temp.jid;
}

/**
 * @brief Allocate the new page if underlying page corresponding to
 *        VEMA received have Read-Only permission.
 *
 * @param[in] tsk reference to process task struct
 * @param[in] VE virtual memory address.
 *
 * @return On success 0, On failure, negative value.
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
int veos_handle_ptrace_poke_req(struct ve_task_struct *tsk, vemva_t vaddr)
{
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	vemaa_t pb = 0;
	vemva_t align_vaddr = 0;
	int prot = -1;
	int pgmod = 0;
	ret_t ret = -1;
	struct ve_page *ve_page_actual = NULL;
	pgno_t pgno = -1;
	pgno_t new_pgno = -1;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	VEOS_DEBUG("Aligned vaddr : %p", (void *)vaddr);
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	pb = __veos_virt_to_phy(vaddr, &tsk->p_ve_mm->atb,
			&prot, &pgmod);
	if ((vemaa_t)0 > pb) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) in vemva %lx to vemaa conversion",
				strerror(-ret), vaddr);
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
				UNLOCK,
				"Failed to release thread-group-mm-lock");
		return ret;
	}

	align_vaddr = ALIGN(vaddr, pgmod_to_pgsz(pgmod));
	if (align_vaddr != vaddr)
		vaddr = align_vaddr - pgmod_to_pgsz(pgmod);

	pgno = pfnum(pb, PG_2M);

	ve_page_actual = VE_PAGE(vnode, pgno);
	VEOS_DEBUG("Actual VE pgno %ld", pgno);
	/*
	 * ptrace poke request will update underlying physical page
	 * in case Page has been mapped as MAP_PRIVATE and PROT_READ
	 * PROT_READ mappings always needs to be replaced because
	 * in case of shared libraries text page is always shared
	 * if old page is provided then shared libraries may get
	 * impacted.
	 * Decrease the reference count of VE Page.
	 * ENHANCEMENT: If page type is not associated with any
	 * shared object or file and reference count of page is
	 * still '1' then no need to allocate new page because
	 * page will be locally to process only always
	 * MAP_SHARED | PROT_READ: Need to allocate new page
	 * MAP_SHARED |PROT_WRITE: No need to allocate new page
	 * MAP_PRIVATE | PROT_WRITE: No need to allocate new page
	 */
	if ((ve_page_actual->owner != tsk->group_leader ||
				!(ve_page_actual->flag & PG_PTRACE)) &&
			!(prot & PROT_WRITE)) {
		new_pgno = replace_page(vaddr, tsk);
		if (0 > new_pgno) {
			ret = -1;
			goto error;
		}
		ret = 0;
	} else {
		VEOS_DEBUG("No need to replace page %ld, already traced", pgno);
		ret = 0;
	}

error:
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
	return ret;
}

/**
* @brief This function will sync VE memory to VH memory.
*
* @param[in] tsk reference to process task struct.
*/
void sync_at_exit(struct ve_task_struct *tsk)
{
	int dirno = 0, pgmod = 0, ent = 0, pgno = 0;
	uint64_t psnum = 0;
	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;
	vemaa_t pb;
	vhva_t vhva;
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	atb_reg_t *tmp_atb = &(mm->atb);
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked for tsk(%p):pid(%d)", tsk, tsk->pid);
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		pgd = &(tmp_atb->dir[dirno]);
		if (ps_isvalid(pgd)) {
			pgmod =  ps_getpgsz(pgd);
			psnum = ps_getps(pgd, pgmod);
			for (ent = 0; ent < ATB_ENTRY_MAX_SIZE; ent++) {
				pte = &tmp_atb->entry[dirno][ent];
				if (pg_isvalid(pte)) {
					pgno = pg_getpb(pte, PG_2M);
					if (PG_BUS == pgno)
						continue;

					if (VE_PAGE(vnode, pgno)->flag & PG_SHM)
						continue;
					pb = pbaddr(pgno, PG_2M);
					vhva = psnum_to_vaddr(psnum, ent, pgmod);
					if (sync_vhva(pb, vhva, tsk))
						goto done;
				}
			}
		}
	}
done:
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned");
	return;
}

/**
 * @brief Sync VH memory with VE memory.
 *
 * @param[in] vemaa VE memory address.
 * @param[in] vhva VH virtual address to sync.
 * @param[in] pid pid of the process.
 *
 * @return On success return zero, -1 on error.
 */
int sync_vhva(vemaa_t vemaa, vhva_t vhva, struct ve_task_struct *tsk)
{
	uint64_t pgno = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_page *page = NULL;
	int ret = 0;

	VEOS_TRACE("invoked");
	VEOS_TRACE("invoked to sync vhva %lx with vemva %lx for task:pid(%d)",
			vhva, vemaa, tsk->pid);
	pgno = pfnum(vemaa, PG_2M);
	page = VE_PAGE(vnode, pgno);
	size_t sz = page->pgsz;

	VEOS_DEBUG("Syncing VE page %ld is of type %s and flag %lx",
			pgno, pgsz_to_pgstr(page->pgsz), page->flag);

	size_t size = 0;

	/*Check if dst_addr is mapped with a file*/
	size = is_addr_file_backed(vhva, tsk);
	if (!size)
		VEOS_DEBUG("src address is not file backed");
	else if (sz > size)
		sz = size;
	/*If file backed
	*/
	if ((MAP_SHARED & (page->flag)) && !(MAP_ANON & (page->flag))) {
		ret = amm_dma_xfer(VE_DMA_VEMAA, vemaa, 0,
				VE_DMA_VHVA, vhva, tsk->pid,
				sz, 0);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while syncing VHVA", strerror(-ret));
			VEOS_TRACE("returned with error");
			return ret;
		}
	}

	return ret;
}

/**
 * @brief This function will free the mapping descriptor.
 *
* @param[in] file mapping descriptor to be free.
*/
void free_file_desc(struct file_desc *file)
{
	struct mapping_desc *mapping = NULL, *tmp_map = NULL;

	VEOS_TRACE("invoked for file desc %p", file);
	list_for_each_entry_safe(mapping, tmp_map,
			&file->mapping_list, mapping_list) {
		VEOS_DEBUG("File desc(%p) mapping %p and its pgarray %p",
				file, mapping, mapping->pg_array);
		free(mapping->pg_array);
		list_del(&mapping->mapping_list);
		free(mapping);
	}

	list_del(&file->global_list);
	free(file);
	VEOS_TRACE("returned");
}
/**
 * @brief This function is used to send data from buffer to
 * 	specified process's addess.
 *
 * @param[in] pid Pid of the process
 * @param[in] address Virtual address to data send.
 * @param[in] len Length of data to be send/write.
 * @param[in] data Buffer from which data will send.
 *
 * @return On success returns  0, -1 on failure.
 */
int amm_send_data(pid_t pid, vemva_t address, size_t len, void *data)
{
	int ret = 0, v_pid = 0;
	struct addr_struct *as = NULL;
	uint64_t *buff = NULL;

	v_pid = getpid();

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with address = 0x%lx size 0x%lx data %p",
			address, len, data);

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		return ret;
	}
	/*MEMSET*/
	memset(as, '\0', sizeof(struct addr_struct));
	as->top_address = address;
	as->bottom_address = address + len;

	/* calc VEMVA addresses */
	calc_addr(as);
	buff = (uint64_t *)malloc(as->new_datasize);
	if (buff == NULL) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		goto ve_send_data_err_;
	}
	/*MEMSET*/
	memset(buff, '\0', as->new_datasize);

	/* receive top part of VE memory */
	if (as->top_offset != 0) {
		ret = amm_recv_data(pid, as->aligned_top_address, 8, buff);
		if (ret) {
			VEOS_DEBUG("error while receiving top part of"
					" VE data");
			goto ve_send_data_err;
		}
	}

	/* receive bottom part of VE memory */
	if (as->bottom_offset != 0) {
		ret = amm_recv_data(pid, as->aligned_bottom_address - 8, 8,
				(uint64_t *)((uint64_t)buff +
					as->new_datasize - 8));
		if (ret) {
			VEOS_DEBUG("error while receiving bottom part of"
					" VE data");
			goto ve_send_data_err;
		}
	}

	/* copy data to the buffer */
	memcpy((uint64_t *)((uint64_t)buff + as->top_offset), data, len);
	/* finally, send buff to VE memory */
	ret = memcpy_htoe((vemva_t)buff, as->aligned_top_address, v_pid, pid,
			as->new_datasize);
	if (ret)
		VEOS_DEBUG("error while sending request to data transfer");


ve_send_data_err:
	free(buff);
ve_send_data_err_:
	free(as);
	VEOS_DEBUG("returned with %d", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function is used to recv data from buffer to
 *	specified process's address.
 *
 * @param[in] pid Pid of the process.
 * @param[in] address Virtual address to data recv.
 * @param[in] len Length of the data to recv/read.
 * @param[in] data Buffer in which data will store.
 *
 * @return On success returns  0, -1 on failure.
 */
int amm_recv_data(pid_t pid, vemva_t address, size_t len, void *data)
{
	int ret = 0, v_pid = 0;
	struct addr_struct *as = NULL;
	uint64_t *buff = NULL;

	v_pid = getpid();
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with address = 0x%lx size 0x%lx data %p",
			address, len, data);

	as = (struct addr_struct *)malloc(sizeof(struct addr_struct));
	if (as == NULL) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while allocating memory",
				strerror(-ret));
		return ret;
	}
	/*MEMSET*/
	memset(as, '\0', sizeof(struct addr_struct));

	as->top_address = address;
	as->bottom_address = (vemva_t)(address + len);

	/* calc VEMVA addresses */
	calc_addr(as);

	/* allocate bigger buffer than data */
	buff = (uint64_t *)malloc(as->new_datasize);
	if (buff == NULL) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while allcating memory",
				strerror(-ret));
		goto ve_recv_data_err1;
	}
	/*MEMSET*/
	memset(buff, '\0', as->new_datasize);

	/* Receive buff from VE memory */
	ret = memcpy_etoh(as->aligned_top_address, (vemva_t)buff, pid, v_pid,
			as->new_datasize);
	if (0 > ret) {
		VEOS_DEBUG("_ve_recv_data_ipc failed");
		goto ve_recv_data_err1;
	}

	/* copy data to the data buffer */
	memcpy(data, (uint64_t *)((uint64_t)buff + as->top_offset), len);

ve_recv_data_err1:
	free(buff);
	free(as);
	VEOS_DEBUG("returned with %d", ret);
	VEOS_TRACE("returned");
	return ret;
}
/**
 * @brief calculate aligned addresses from top_address and bottom_address.
 *
 * @param[in/out] as structure for calculating address offset and datasize.
 */
void calc_addr(struct addr_struct *as)
{
	VEOS_TRACE("Invoked");
	as->aligned_top_address = (as->top_address & ~(8 - 1));
	as->top_offset = as->top_address - as->aligned_top_address;
	if (as->bottom_address % 8) {
		as->aligned_bottom_address =
			(as->bottom_address & ~(8 - 1)) + 8;
		as->bottom_offset =
			as->aligned_bottom_address - as->bottom_address;
	} else {
		as->aligned_bottom_address = as->bottom_address;
		as->bottom_offset = 0;
	}
	as->new_datasize = as->aligned_bottom_address - as->aligned_top_address;
	VEOS_DEBUG("top_address =            %016llx",
			(unsigned long long)(as->top_address));
	VEOS_DEBUG("aligned_top_address =    %016llx",
			(unsigned long long)(as->aligned_top_address));
	VEOS_DEBUG("top_offset =             %d", as->top_offset);
	VEOS_DEBUG("bottom_address =         %016llx",
			(unsigned long long)(as->bottom_address));
	VEOS_DEBUG("aligned_bottom_address = %016llx",
			(unsigned long long)(as->aligned_bottom_address));
	VEOS_DEBUG("bottom_offset =          %d", as->bottom_offset);
	VEOS_DEBUG("new_datasize =           %zd", as->new_datasize);

	VEOS_TRACE("Returned");
}
/**
 * @brief This interface copy private data from old mm struct to new mm struct.
 *
 * @param[in] mm_old New mm struct
 * @param[in/out] mm_new Old mm struct.
 */
void amm_copy_mm_data(struct ve_mm_struct *mm_old, struct ve_mm_struct *mm_new)
{
	mm_new->start_code = mm_old->start_code;
	mm_new->end_code = mm_old->end_code;
	mm_new->start_data = mm_old->start_data;
	mm_new->end_data = mm_old->end_data;
	mm_new->start_brk = mm_old->start_brk;
	mm_new->brk = mm_old->brk;
	mm_new->start_stack = mm_old->start_stack;
	mm_new->arg_start = mm_old->arg_start;
	mm_new->arg_end = mm_old->arg_end;
	mm_new->env_start = mm_old->env_start;
	mm_new->env_end = mm_old->env_end;
	mm_new->rss_max = mm_old->rss_max;
	mm_new->rsslim = mm_old->rsslim;
	mm_new->rss_cur = mm_old->rss_cur;
	mm_new->shared_rss = mm_old->shared_rss;
	mm_new->pgsz =mm_old->pgsz;
	mm_new->rss_data = mm_old->rss_data;
	mm_new->rss_stack = mm_old->rss_stack;
	mm_new->vm_size = mm_old->vm_size;
	mm_new->anon = mm_old->anon;
	mm_new->anonhuge = mm_old->anonhuge;
	mm_new->argc = mm_old->argc;
	mm_new->argv_addr = mm_old->argv_addr;
	mm_new->argv_size = mm_old->argv_size;
	mm_new->auxv_addr = mm_old->auxv_addr;
	mm_new->auxv_size = mm_old->auxv_size;

}

/**
 * @brief This interface copy shmlist from old to new mm_struct.
 *
 * @param[in] mm_old Old mm_struct.
 * @param[in/out] mm New mm_struct.
 *
 * @return on success return 0 and negative of errno on failure.
 */
ret_t copy_shm_list(struct ve_mm_struct *mm_old, struct ve_mm_struct *mm)
{
	ret_t ret = 0;
	VEOS_TRACE("invoked");
	INIT_LIST_HEAD(&(mm->shm_head));
	struct shm_map *shm_tmp = NULL, *shm_curr = NULL;
	list_for_each_entry(shm_tmp, &(mm_old->shm_head), shm_list) {
		shm_curr = (struct shm_map *)calloc (1, sizeof(struct shm_map));
		if (NULL == shm_curr) {
			ret = -errno;
			VEOS_CRIT("Failed to allocate memoery for shmlist");
			return ret;
		}
		shm_curr->shmaddr = shm_tmp->shmaddr;
		shm_curr->shm_segment = shm_tmp->shm_segment;
		shm_curr->count = shm_tmp->count;
		list_add(&(shm_curr->shm_list), &(mm->shm_head));
	}
	VEOS_TRACE ("Returned");
	return ret;
}
/**
* @brief This routine delete the ve_mm_struct corresponding to pid when process ends
*
* @param[in] tsk process ve task struct.
*
* @return On success return 0 and negative errno on failure.
*/
int __amm_del_mm_struct(struct ve_task_struct *tsk)
{
	dir_t dirno = 0, shmrm = 0;
	ent_t ent = 0;
	pgno_t pgno = 0;
	ret_t ret = 0;
	atb_reg_t *atb = NULL;
	vemaa_t pb = 0;
	bool shm_page = false;
	struct shm *seg = NULL, *shm_ent = NULL;
	struct ve_mm_struct *mm = NULL;
	struct shm_map *shm_tmp = NULL, *tmp = NULL;
	int found = 0;

	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	mm = tsk->p_ve_mm;

	/*Get mm_struct_lock here*/
	atb = &(mm->atb);

	/*
	 * Decrement the reference count.
	 */

	VEOS_TRACE("iterating tsk(%p):pid(%d) pgtables",
			tsk, tsk->pid);

	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		if (!ps_isvalid(&atb->dir[dirno]))
			continue;
		for (ent = 0; (ent < ATB_ENTRY_MAX_SIZE); ent++) {
			if ((PG_BUS == (pgno = pg_getpb(&atb->entry[dirno]
								[ent], PG_2M))) ||
					(!pg_isvalid(&atb->entry[dirno][ent])
					 && !pgno)) {
				VEOS_TRACE("pgd[%d][%d] with VE page %ld",
						dirno, ent, pgno);
				continue;
			}
			if (NULL == VE_PAGE(vnode, pgno)) {
				VEOS_DEBUG("double freeing VE page %ld", pgno);
				veos_abort("VE memory corruption occurred");
			}

			if ((VE_PAGE(vnode, pgno)->flag & PG_SHM) &&
				(!(VE_PAGE(vnode, pgno)->flag & PG_PTRACE)))
				shm_page = true;

			pb = pbaddr(pgno, PG_2M);
			/*Decreament the ref count*/
			ret = amm_put_page(pb);
			if (0 > ret) {
				VEOS_DEBUG("Error (%s) while releasing"
						"VE page address 0x%lx",
						strerror(-ret), pb);
				goto err_exit;
			}
			pg_invalid(&atb->entry[dirno][ent]);
			if (shm_page) {
				/*
				 * Page belong to shared
				 * memory segment
				 */
				VEOS_TRACE("pgd[%d][%d] with VE page %ld",
						dirno, ent, pgno);
				seg = VE_PAGE(vnode, pgno)->private_data;
				pthread_mutex_lock_unlock(&seg->shm_lock,
						LOCK,
						"Failed acquire shm segmnt lock");
				seg->nattch--;
				if (!seg->nattch)
					shmrm = 1;
				pthread_mutex_lock_unlock(&seg->shm_lock,
						UNLOCK,
						"Failed realease shm segmnt lock");
				if (shmrm) {
					pthread_mutex_lock_unlock(&vnode->shm_node_lock, LOCK,
							"Failed to acquire node shm lock");
					list_for_each_entry(shm_ent, &vnode->shm_head, shm_list) {
						if (shm_ent == seg) {
							VEOS_DEBUG("Shared memory segment(%p) for shmid(%d) found",
									shm_ent, shm_ent->shmid);
							found = 1;
							break;
						}
					}
					if (found) {
						if ((seg->flag & SHM_DEL) &&
								(seg->nattch == 0)){
							VEOS_DEBUG("Shared memory segment with id %d"
									"delete flag is set",
									seg->shmid);
							amm_release_shm_segment(seg);
						} else
							seg->ipc_stat.shm_dtime = time(NULL);
					}
					pthread_mutex_lock_unlock(&vnode->shm_node_lock, UNLOCK,
							"Failed to release node shm lock");
				}

			}
			shm_page = false;
		}
		ps_invalid(&atb->dir[dirno]);
	}

	/*Here we are releasing pindowed VH page*/
	ret = vedl_release_pindown_page(vnode->handle, mm->shm_lhm_addr_vhsaa);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in pindown vhsaa 0x%lx",
			strerror(-ret), mm->shm_lhm_addr_vhsaa);
	}

	amm_free_cr_data(mm);
	veos_free_dmaatb(&mm->dmaatb);
	ret = 0;

	/** Traverse the SHM list and delete list */
	list_for_each_entry_safe(shm_tmp, tmp, &(mm->shm_head), shm_list) {
		VEOS_DEBUG("In shm list current mapping %p with vemva 0x%lx",
				shm_tmp, shm_tmp->shmaddr);
		list_del(&(shm_tmp->shm_list));
		free(shm_tmp);
		shm_tmp = NULL;
	}
	mm->start_code = 0;
	mm->end_code = 0;
	mm->start_data = 0;
	mm->end_data = 0;
	mm->start_brk = 0;
	mm->brk = 0;
	mm->start_stack = 0;
	mm->arg_start = 0;
	mm->arg_end = 0;
	mm->env_start = 0;
	mm->env_end = 0;
	mm->rss_max = 0;
	mm->crss_max = 0;
	mm->rsslim = 0;
	mm->rss_cur = 0;
	mm->shared_rss = 0;
	mm->pgsz = 0;
	mm->rss_data = 0;
	mm->rss_stack = 0;
	mm->vm_size = 0;
	mm->anon = 0;
	mm->anonhuge = 0;
	mm->argc = 0;
	mm->argv_addr = 0;
	mm->argv_size = 0;
	mm->auxv_addr = 0;
	mm->auxv_size = 0;
err_exit:
	free(mm->vehva_header.bmap_4k);
	free(mm->vehva_header.bmap_64m);
	free(mm->vehva_header.bmap_2m);
	free(mm->dma_dump_file);
	pthread_mutex_destroy(&mm->vehva_header.vehva_4k_lock);
	pthread_mutex_destroy(&mm->vehva_header.vehva_2m_lock);
	pthread_mutex_destroy(&mm->vehva_header.vehva_64m_lock);
	VEOS_TRACE("returned");
	return ret;
}
/**
* @brief This routine create new ve_mm_struct to the VE process.
*
* @param mm_struct[out] Double pointer to mm_struct
*
* @return On success return 0 and negative of errno on failure.
*/
int __amm_alloc_mm_struct(struct ve_mm_struct **mm)
{
	int ret = 0;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("mm struct(%p) allocated", *mm);

	/* While allocating ve_mm_struct we will set
	 * udma_desc_bmap field for DMA_DESC_E.
	 */
	(*mm)->udma_desc_bmap = DMA_DESC_E;

	/*Allocate cr data for newly allocated mm_struct*/
	/*allocating cr data to newly created process*/
	ret = amm_alloc_cr_data(*mm);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while allocating CR data for tsk",
				strerror(-ret));
		return ret;
	}

	invalidate_atb(&((*mm)->atb));
	VEOS_DEBUG("invalidated pgd/pte of tsk");
	ret = veos_vehva_init(*mm);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while initializing tsk vehva",
				strerror(-ret));
		goto __amm_alloc_mm_error;
	}

	invalidate_dmaatb(&((*mm)->dmaatb));

	(*mm)->ref_count = 1;

	VEOS_DEBUG("mm ref cnt(%lu)", (*mm)->ref_count);
	(*mm)->dma_dump_file = malloc(50);
	if (NULL == (*mm)->dma_dump_file) {
		ret = -errno;
		VEOS_DEBUG("failed to allocate dma dump file info");
		goto __amm_alloc_mm_error;
	}
	/*MEMSET*/
	memset((*mm)->dma_dump_file, '\0', 50);

	INIT_LIST_HEAD(&((*mm)->shm_head));
__amm_alloc_mm_error:
	return ret;
}
