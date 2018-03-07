/**
 * @file amm_mem.c
 * @brief AMM core functions which manages the VE memory.
 */
#include <unistd.h>
#include <sys/mman.h>
#include "amm_shm.h"
#include "amm_mem.h"
#include "amm_psm_if.h"
#include "memory.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "velayout.h"

/**
 * @brief Fill memory related information in struct sysinfo
 *
 * @param[out] val Pointer to struct sysinfo
 */
void amm_sys_meminfo(struct sysinfo *val)
{
	val->totalram = 0;
	val->sharedram = 0;
	val->freeram = 0;
	val->bufferram = 0;
	val->totalhigh = 0;
	val->freehigh = 0;
	val->mem_unit = 0;
	val->totalswap = 0;
	val->freeswap = 0;
}

/**
* @brief  Dump the information present in ATB structure.
*
* @param[in] atb ATB structure pointer
*/
void amm_dump_atb(atb_reg_t *atb)
{
	int entry_cntr = -1, dir_cntr = -1;

	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"%d : Partial Space Offset %p\n",
					dir_cntr,
					(void *)atb->dir[dir_cntr].data);
			for (entry_cntr = 0; entry_cntr < ATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(atb->
						entry[dir_cntr][entry_cntr]))) {
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"%d : %d :PB"
					" Address %p\n",
					dir_cntr,
					entry_cntr,
					(void *)
					atb->entry[dir_cntr][entry_cntr].data);
				}
			} /* end entry loop */
		} /* end*/
		else
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"DIR: %d is invalid.\n", dir_cntr);
	} /* end dir loop */
}


/**
* @brief Initialize partial space directory.
*
* @param[out] atb pointer of ATB or DMAATB
* @param[in] sub subscript of a structure.
* @param[in] psnum  partial space number
* @param[in] jid  JID in partial space directory
* @param[in] page_sz page size of partial space
*
* @return On success 0, On failure, negative value.
*/
int init_atb_dir(atb_reg_t *atb, int sub, int psnum, int jid, int page_sz)
{
	int ps_entry;

	if (ps_isvalid(&(atb->dir[sub]))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"dir[%d] is already valid. (PS#%d)\n",
				sub, psnum);
		return -1;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"New partial space. dir[%d], PS#%d\n", sub, psnum);

	/* partial space directory */
	ps_setpsnum(&(atb->dir[sub]), psnum, page_sz);
	ps_setjid(&(atb->dir[sub]), jid);
	ps_setpgsz(&(atb->dir[sub]), page_sz);
	ps_valid(&(atb->dir[sub]));

	/* partial space page table (PSPT) */
	for (ps_entry = 0; ps_entry < ATB_ENTRY_MAX_SIZE; ps_entry++) {
		pg_settype(&(atb->entry[sub][ps_entry]), PG_VEMAA);
		pg_invalid(&(atb->entry[sub][ps_entry]));
	}

	return 0;
}

/**
* @brief Common function of search_atb_ps() and search_dmaatb_ps().
*
* @param[in] vaddr Virtual address
* @param[in] pgmode Page mode
* @param[in] atb Pointer of ATB's atb_reg_t
* @param[in] dmaatb Pointer of DMAATB's dmaatb_reg_t
* @param[in] jid JID of a process which uses the vaddr
*
* @return On success, positive number, On failure,returns -1.
*
*	this function returns a subscript i for array dir[i]
*	and entry[i][].
*	on failure, this function returns -1 and sets errno.
**/
int search_ps_common(char *vaddr, int pgmode, atb_reg_t *atb,
		dmaatb_reg_t *dmaatb, int jid)
{
	int ps_entry;
	int atb_num;
	int psnum;		/* partial space # generated from vaddr */
	int psnum_dir;		/* partial space # generated from dir[] entry */
	int pgmode_dir;		/* Page size flag from dir[] entry */
	atb_dir_t *atbp;
	int unused = -1;	/* unused partial space # */

	if (atb == NULL && dmaatb == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"atb and dmaatb are NULL.\n");
		return -1;
	}

	atb_num = (atb != NULL) ? ATB_DIR_NUM : DMAATB_DIR_NUM;
	atbp = (atb != NULL) ? atb->dir : dmaatb->dir;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"vaddr: %p, atb: %p, dmaatb: %p, atb_num=%d atbp=%p\n",
			vaddr, atb, dmaatb, atb_num, atbp);

	psnum = (pgmode == PG_2M) ? psnum(vaddr) : psnum_h(vaddr);

	for (ps_entry = 0; ps_entry < atb_num; ps_entry++) {
		/* Is atbp valid? */
		if (ps_isvalid(atbp)) {
			/* If atbp is DMAATB, check JID. */
			if (dmaatb != NULL) {
				if (ps_getjid(atbp) != jid) {
					atbp++;
					continue;
				}
			}
			/* pgmode check */
			pgmode_dir = ps_getpgsz(atbp);
			if (pgmode != pgmode_dir) {
				atbp++;
				continue;
			}
			/* psnum check */
			psnum_dir = ps_getps(atbp, pgmode_dir);
			if (psnum_dir == psnum)
				return ps_entry;
		} else {
			/* Is atbp valid? */
			if (unused == -1)
				unused = ps_entry;
		}
		atbp++;
	}
	if (unused == -1)
		errno = ENOMEM;
	return unused;
}

/**
* @brief Search a partial space directory of specified virtual address.
*
* @param[in] vaddr Virtual address
* @param[in] pgmode Page mode of the vaddr
* @param[in] atb Pointer of ATB's atb_reg_t
*
* @return On success, positive number, On failure,returns -1.
*
*	On success, this function returns a subscript i for array dir[i]
*	and entry[i][] in atb_reg_t.  dir[i] and entry[i][] are related to the
*	specified virtual address. If this function can't find the * structure,
*	it returns a pointer of a unused structure.
*	On failure, this function returns -1.
*/
int search_atb_ps(char *vaddr, int pgmode, atb_reg_t *atb)
{
	return search_ps_common(vaddr, pgmode, atb, NULL, -1);
}
/**
* @brief Search a partial space directory of specified virtual address.
*
* @param[in] vaddr Virtual address
* @param[in] pgmode Page mode of the vaddr
* @param[in] atb Pointer of DMAATB's dmaatb_reg_t
* @param[in] jid JID of a process which uses the vaddr
*
* @return On success, positive number, On failure,returns -1.
*
*	On success, this function returns a subscript i for array dir[i]
*	and entry[i][] in dmaatb_reg_t.  dir[i] and entry[i][]
*	are related to the specified virtual address. If this function can't
*	find the * structure,it returns a pointer of a unused structure.
*	On failure, this function returns -1.
*/
int search_dmaatb_ps(char *vaddr, int pgmode, dmaatb_reg_t *dmaatb, int jid)
{
	return search_ps_common(vaddr, pgmode, NULL, dmaatb, jid);
}

/**
* @brief This routine initialize the ATB structure.
*
*	This routine initialize the ATB structure for newly
*	created ve_mm_struct.
*
* @param[out] atb ATB structure of a process
*
* @return On success return 0
*/
int amm_init_atb(atb_reg_t *atb)
{
	int dirno, ps_entry;

	/*
	 * Initialize the ATB structure for new allocation
	 */
	memset(atb, 0, sizeof(atb_reg_t));
	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		ps_invalid(&(atb->dir[dirno]));
		for (ps_entry = 0; ps_entry < ATB_ENTRY_MAX_SIZE; ps_entry++)
			pg_invalid(&(atb->entry[dirno][ps_entry]));
	}
	return 0;
}

/**
* @brief This routine copies the content from one physical page(2MB) to another.
*
* @param[in] src_addr Source physical address
* @param[out] dest_addr Destination physical address
* @param[in] node_id Node ID
*
* @return On success return 0 and -1 on failure
*/
int amm_copy_phy_page(uint64_t src_addr, uint64_t dest_addr, int node_id)
{
	int retval = -1;
	/*
	 * Transfer data from VE physical page to VE physical page using DMA.
	 */
	retval = amm_dma_xfer(VE_DMA_VEMAA, src_addr, 0,
			VE_DMA_VEMAA, dest_addr, 0, PAGE_SIZE_2MB, node_id);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"DMA transfer failed data from/to VE PHY Address\n");
	}
	return retval;
}

/**
* @brief This routine copies old atb entries to new atb with same physical page.
*
* @param[in] old_atb Pointer to old atb structure
* @param[out] new_atb Pointer to new atb structure
* @param[in] node_id Node ID
*
* @return On success return 0 and -1 on failure
*/
int amm_copy_atb_private(atb_reg_t *old_atb, atb_reg_t *new_atb, int node_id)
{
	int dirno, ps_entry;
	int retval;
	uint64_t pgno_dest;
	uint64_t pgno_src;
	uint64_t src_addr, dest_addr;
	uint64_t page_size;
	int pgmode_dir;         /* Page size flag from dir[] entry */
	struct ve_node_struct *vnode_info;

	vnode_info = VE_NODE(node_id);

	memcpy(new_atb, old_atb, sizeof(atb_reg_t));
	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		/* Get the page size from ATB dir */
		pgmode_dir = ps_getpgsz(&new_atb->dir[dirno]);
		if (PG_HP == pgmode_dir)
			page_size = PAGE_SIZE_64MB;
		else
			page_size = PAGE_SIZE_2MB;

		if (ps_isvalid(&(new_atb->dir[dirno]))) {
			for (ps_entry = 0; ps_entry < ATB_ENTRY_MAX_SIZE;
					ps_entry++) {
				if (pg_isvalid(&(new_atb->
						entry[dirno][ps_entry]))) {
					pgno_src = pg_getpb(&(old_atb->
							entry[dirno][ps_entry]),
							pgmode_dir);
					/*Check if MAP_SHARED*/
					if (!((vnode_info->ve_pages[pgno_src].
						flag & MAP_SHARED) ||
						(vnode_info->ve_pages[pgno_src].
						 flag & PG_SHM))) {
						retval = alloc_ve_pages(1,
								&pgno_dest,
								node_id,
								page_size);
						if (retval == -1) {
							VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_ERROR,
							"Can't alloc Page\n");
							return -1;
						}
						VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_INFO,
							"ATB ENTRY %d "
							"with PGNO %ld\n",
							ps_entry, pgno_dest);

						/*Increase Ref count*/
						vnode_info->ve_pages[pgno_dest].ref_count =
							vnode_info->ve_pages[pgno_src].
							ref_count;
						/*Update perm*/
						vnode_info->ve_pages[pgno_dest].perm =
							vnode_info->ve_pages[pgno_src].	perm;
						/*Update flag*/
						vnode_info->ve_pages[pgno_dest].flag =
							vnode_info->ve_pages[pgno_src].	flag;

						pg_clearpfn(&(new_atb->entry[dirno][ps_entry]));
						pg_setpb(&(new_atb->entry[dirno][ps_entry]),
								pgno_dest, pgmode_dir);
						src_addr = pgaddr(&(old_atb->
									entry[dirno][ps_entry]));
						dest_addr = pgaddr(&(new_atb->
									entry[dirno][ps_entry]));
						retval = amm_copy_phy_page(
								src_addr, dest_addr,
								node_id);
						if (retval == -1) {
							VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_ERROR,
							"Data copy fails!\n");
							return -1;
						}
					} else {
						VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_INFO,
							"Page is Being Shared\n");
						if (vnode_info->ve_pages
								[pgno_src].flag &
								PG_SHM) {
							VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_DEBUG,
							"shared memory\n");
							((struct shm *)
							 (vnode_info->ve_pages[pgno_src]
							  .private_data))->nattch++;

						}
						vnode_info->ve_pages[pgno_src].
							ref_count++;
					}
				}
			}
		}
	}
	return 0;
}

/**
* @brief This routine create new ve_mm_struct to the VE process.
*
* @param mm_struct[out] Double pointer to mm_struct
*
* @return On success return 0 and -1 on failure
*/
int amm_alloc_mm_struct(struct ve_mm_struct **mm_struct)
{
	int retval = -1;
	struct ve_mm_struct *tmp_mm_struct;
	struct mm_thread_descriptor *tmp_mm_td;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Allocating memory for new mm_struct\n");
	/*
	 * Allocating memory for ve_mm_struct
	 */
	tmp_mm_struct =
		(struct ve_mm_struct *)malloc(sizeof(struct ve_mm_struct));
	if (tmp_mm_struct == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails while allocating memory "
				"to mm_struct\n");
		return retval;
	}
	/*
	 * Initializing pthread mutex for synchronization
	 */
	if (pthread_mutex_init(&(tmp_mm_struct->mm_lock), NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"\n Mutex init failed\n");
		goto amm_alloc_mm_error;
	}

	if (pthread_mutex_init(&(tmp_mm_struct->shm_lock), NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"\n Mutex init failed\n");
		goto amm_alloc_mm_error;
	}

	retval = amm_init_atb(&(tmp_mm_struct->atb));

	tmp_mm_struct->ref_count = 1;
	/*
	 * Allocating memory for thread structure.
	 */
	tmp_mm_td = (struct mm_thread_descriptor *)malloc(
			sizeof(struct mm_thread_descriptor));
	if (tmp_mm_td == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails in allocating memory!!\n");
		goto amm_alloc_mm_error;
	}
	INIT_LIST_HEAD(&(tmp_mm_struct->mm_td.mm_thread_head));
	/*
	 * TODO:Fill information regarding mm_thread_descriptor.
	 */

	list_add_tail(&(tmp_mm_td->mm_thread_head),
			&(tmp_mm_struct->mm_td.mm_thread_head));

	*mm_struct = tmp_mm_struct;

	INIT_LIST_HEAD(&(tmp_mm_struct->shm_head));

	return 0;

amm_alloc_mm_error:
	retval = -1;
	free(tmp_mm_struct);
	return retval;
}

/**
* @brief This routine copies the old mm_struct to new mm_struct
* based on the flag received.
*
* @param[in] mm_struct_old Pointer to old mm_struct
* @param[in,out] mm_struct_new Double pointer to new mm_struct
* @param[in] node_id Node ID
* @param[in] flag Distinguish b/w thread or process and type of memory mapping
*
* @return On success return 0 and -1 on failure
*/
int amm_copy_mm_struct(struct ve_mm_struct *mm_struct_old,
		struct ve_mm_struct **mm_struct_new, int node_id,
		int flag)
{
	int retval = -1;
	struct ve_mm_struct *tmp_mm_struct;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Copying one mm_struct to another\n");
	switch (flag) {
	case REQUEST_FOR_PROCESS_SHARED:
		pthread_mutex_lock(&(mm_struct_old->mm_lock));
		mm_struct_old->ref_count++;
		*mm_struct_new = mm_struct_old;
		pthread_mutex_unlock(&(mm_struct_old->mm_lock));
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"MM Struct %p ref_count : %d\n",
				mm_struct_old, mm_struct_old->ref_count);
		break;
	case REQUEST_FOR_PROCESS_PRIVATE:
		/*
		 * Allocation for new mm_struct
		 */
		retval = amm_alloc_mm_struct(mm_struct_new);
		if (retval == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"AMM allocation for "
					"mm_struct fails !!\n");
			return retval;
		}
		tmp_mm_struct = *mm_struct_new;
		pthread_mutex_lock(&(mm_struct_old->mm_lock));
		retval = amm_copy_atb_private(&(mm_struct_old->atb),
				&(tmp_mm_struct->atb), node_id);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PARENT ATB : %p CHILD ATB %p\n",
				&(mm_struct_old->atb),
				&(tmp_mm_struct->atb));
		pthread_mutex_unlock(&(mm_struct_old->mm_lock));
		if (retval == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"AMM fails in copying ATB !!\n");
			goto amm_copy_failure;
		}
		break;
	default:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid flag received !!\n");
		retval = -1;
		return retval;;
	}

	return 0;
amm_copy_failure:
	amm_del_mm_struct(mm_struct_new, node_id);
	return retval;
}

/**
* @brief This routine Updates the ATB, DMAATB and PCI ATB.
*
* @param[out] p_ve_task Pointer of ve_task_struct of the VE process
*
* @return On success return 0 and -1 on failure
*/
int amm_update_atb_all(struct ve_task_struct *p_ve_task)
{
	int retval;

	/* Updating ATB on a specific core
	*/
	retval = amm_update_atb(p_ve_task, p_ve_task->core_id);
	if (retval == -1)
		return retval;
	/* Updating DMAATB
	*/
	retval = amm_update_dmaatb(p_ve_task, p_ve_task->core_id);
	if (retval == -1)
		return retval;
	/*
	 * TODO: Add interface of updating and managing PCIATB
	 */
	return retval;
}

/**
* @brief This routine updates the DMAATB.
*
*	This routine updates the DMAATB for SHM/LHM area for placing system
*	call arguments.
*
* @param[out] p_ve_task Pointer of ve_task_struct of the VE process
* @param[in] core_num Core number
*
* @return On success return 0 and -1 on failure
*/
int amm_update_dmaatb(struct ve_task_struct *p_ve_task, uint64_t core_num)
{
	int retval;
	uint64_t addr = 0;
	vedl_handle *handle;
	dmaatb_reg_t dmaatb_t;
	system_common_reg_t *cnt_regs_addr;
	struct ve_node_struct *vnode = VE_NODE(p_ve_task->node_id);

	handle = VE_HANDLE(p_ve_task->node_id);
	cnt_regs_addr = VE_CORE_CNT_REG_ADDR(p_ve_task->node_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Updating DMAATB for SHM/LHM regarding core: %lx\n",
			core_num);
	/* Maintain the copy of DMAATB, will be restored back to
	 * original in case of failure.
	 */
	memcpy(&dmaatb_t, &(vnode->dmaatb), sizeof(dmaatb_reg_t));

	/* Job ID currently setting it to core_num
	*/
	ps_setjid(&(vnode->dmaatb.dir[core_num]), core_num);
	ps_valid(&(vnode->dmaatb.dir[core_num]));
	/* page size might vary for DMAATB */
	vnode->dmaatb.dir[core_num].bf.page_size = VE_PAGE_4K;

	/* Set LHM/SHM area */
	addr = (uint64_t)(p_ve_task->p_ve_mm->shm_lhm_addr);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Virtual address: %lx\n", addr);
#ifdef __PCIDEV_ENV
	uint64_t paddr = 0;

	paddr = vedl_get_vhsaa(handle, (void *)addr, p_ve_task->pid);
	if (paddr == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VHVA->VHSAA conversion failed for vaddr = %p\n",
				(void *)addr);
		return -1;
	}
	addr = paddr;
#endif
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Physical address: %lx\n", addr);

	addr = addr & pfn_mask;
	vnode->dmaatb.entry[core_num][0].data = 0;
	vnode->dmaatb.entry[core_num][0].data |= addr;
	pg_settype(&(vnode->dmaatb.entry[core_num][0]), DMAATB_VH_MEM_SPACE);

	/*
	 * Setting New DMAATB partial Space
	 * entry to access VE Registers using SHM/LHM
	 * instruction
	 */
	vnode->dmaatb.entry[core_num][1].data = 0;
	vnode->dmaatb.entry[core_num][1].data |= (core_num * (SIZE_512KB
				+ SIZE_512KB))
		+ USRCC_OFFSET;
	pg_settype(&(vnode->dmaatb.entry[core_num][1]), DMAATB_VE_REG_SPACE);

	vnode->dmaatb.entry[core_num][2].data = 0;
	vnode->dmaatb.entry[core_num][2].data |= (core_num *
			(SIZE_512KB + SIZE_512KB))
		+ PMC_OFFSET;
	pg_settype(&(vnode->dmaatb.entry[core_num][2]), DMAATB_VE_REG_SPACE);

	/* Updating the DMAATB
	*/
	retval = vedl_update_dmaatb_dir(handle, cnt_regs_addr,
			&(vnode->dmaatb), core_num);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEDL fails to update DMAATB\n");
		goto ret_dmaatb_failure;
	}

	/* Currently updating the JIDR register with the core number
	 * on which the task is going to be scheduled.
	 *
	 * TODO: veos gives a unique JID when a process is generated.
	 */
	retval = vedl_set_sys_reg(VE_HANDLE(p_ve_task->node_id),
			VE_CORE_SYS_REG_ADDR(p_ve_task->node_id, core_num),
			JIDR,
			core_num);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEDL fails to update JIDR\n");
		goto ret_dmaatb_failure;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "JIDR updated successfully\n");
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"DMAATB updated successfully\n");
	return retval;
ret_dmaatb_failure:
	/*
	 * On error restoring the original DMAATB.
	 */
	memcpy(&(vnode->dmaatb), &dmaatb_t, sizeof(dmaatb_reg_t));
	return retval;
}

/**
* @brief This routine restore ATBs of incoming VE process on core.
*
* @param[out] p_ve_task Pointer of ve_task_struct of the VE process
* @param[in] core_num Core number of the node
*
* @return On success return 0 and -1 on failure
*/
int amm_update_atb(struct ve_task_struct *p_ve_task, uint64_t core_num)
{
	int retval = -1;
	vedl_handle *handle;
	struct ve_mm_struct *mm_struct;
	atb_reg_t *tmp_atb;
	pthread_mutex_t *mtx;
	core_system_reg_t *core_sys_reg;

	mm_struct = p_ve_task->p_ve_mm;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Updating ATB of Core: %ld MM %p\n",
			core_num, mm_struct);
	handle = VE_HANDLE(p_ve_task->node_id);
	tmp_atb = &(mm_struct->atb);
	mtx = &(mm_struct->mm_lock);
	/*
	 * get the sys register map corresponding to the
	 * core specified.
	 */
	core_sys_reg = VE_CORE_SYS_REG_ADDR(p_ve_task->node_id, core_num);

	pthread_mutex_lock(mtx);
	retval = vedl_update_atb_all(handle, core_sys_reg, tmp_atb);
	pthread_mutex_unlock(mtx);
	if (retval == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEDL fails to update ATB of CORE NUM: %ld\n",
				core_num);
		return retval;
	}
	return retval;
}

/**
* @brief This routine delete the ve_mm_struct corresponding to pid when process ends.
*
* @param[in] mm_struct mm_struct of the VE process
* @param[in] node_id Node ID
*
* @return On success return 0 and -1 on failure
*/
int amm_del_mm_struct(struct ve_mm_struct **mm_struct, int node_id)
{
	int dirno, pgmod, ps_entry, pgno, ret;
	atb_reg_t *tmp_atb;
	uint64_t page_size;
	struct shm *shm_seg;
	struct ve_mm_struct *tmp_mm_struct;
	struct mm_thread_descriptor *tmp_mm_td;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	tmp_mm_struct = *mm_struct;
	tmp_atb = &(tmp_mm_struct->atb);

	/*Get mm_struct_lock here*/
	pthread_mutex_lock(&(tmp_mm_struct->mm_lock));

	/*
	 * Decrement the reference count.
	 */
	(tmp_mm_struct->ref_count)--;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"MM Struct %p ref_count : %d\n",
			tmp_mm_struct, tmp_mm_struct->ref_count);
	if (tmp_mm_struct->ref_count > 0) {
		/*
		 * Since this mm_struct is used by other
		 * thread also, so just decrement the
		 * reference count and return successfully.
		 */
		goto exit1;
	}

	list_for_each_entry(tmp_mm_td, &(tmp_mm_struct->mm_td.mm_thread_head),
			mm_thread_head) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Releasing thread with tid: %ld\n",
				tmp_mm_td->tid);
		free(tmp_mm_td);
	}

	for (dirno = 0; dirno < ATB_DIR_NUM; dirno++) {
		if (ps_isvalid(&(tmp_atb->dir[dirno]))) {
			pgmod =  ps_getpgsz(&(tmp_atb->dir[dirno]));
			if (PG_HP == pgmod)
				page_size = PAGE_SIZE_64MB;
			else
				page_size = PAGE_SIZE_2MB;

			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Page size is 0x%lx\n", page_size);

			for (ps_entry = 0; ps_entry <
					ATB_ENTRY_MAX_SIZE; ps_entry++) {
				if (pg_isvalid(&(tmp_atb->
						entry[dirno][ps_entry]))) {
					pgno = pg_getpb(&(tmp_atb->
							entry[dirno][ps_entry]),
							pgmod);
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
							"Releasing page: %d\n",
							pgno);
					if (vnode_info->ve_pages[pgno].flag
							& PG_SHM) {
						shm_seg = vnode_info->
							ve_pages[pgno].
							private_data;
						shm_seg->nattch--;
						vnode_info->ve_pages[pgno].
							flag |= PG_VE;
						vnode_info->ve_pages[pgno].
							flag &= (~PG_SHM);
						vnode_info->ve_pages[pgno].
							private_data = NULL;
						if ((shm_seg->nattch == 0) &&
							(shm_seg->flag &
								SHM_DEL))
							amm_release_shm_segment
								(shm_seg,
								 node_id);
					}
					ret = release_page(pgno, node_id,
							page_size);
					if (ret < 0) {
						VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_ERROR,
							"Releasing page "
							"failed\n");
						goto err_exit;
					}
				}
			}
		}
	}

	free(tmp_mm_struct);
	*mm_struct = NULL;
exit1:
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(tmp_mm_struct->mm_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	pthread_mutex_destroy(&(tmp_mm_struct->mm_lock));
	return 0;
err_exit:
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(tmp_mm_struct->mm_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func With Error\n");
	pthread_mutex_destroy(&(tmp_mm_struct->mm_lock));
	return -1;
}

/**
 * @brief This routine clears the VE physical memory page of 2MB.
 *
 * @param[out] pgno Page number
 * @param[in] node_id NODE ID
 * @paran[in] pgsize Size of the page
 *
 * @return On success return 0 and -1 on failure
 */
int amm_clear_page(uint64_t pgno, int node_id, uint64_t pgsize)
{
	int i, retval = -1;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);
	uint64_t paddr = 0;

	paddr = pgno * PAGE_SIZE_2MB;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"MEM Clear for PHY Addr: 0x%lx size: %p Zeroed Page Addr: 0x%lx\n",
			paddr, (void *)pgsize, vnode_info->zeroed_page_address);

	/* Request for DMA transfer, 2MB size at a time */
	if (PAGE_SIZE_2MB == pgsize) {
		retval = amm_dma_xfer(VE_DMA_VEMAA, vnode_info->
				zeroed_page_address, 0,
				VE_DMA_VEMAA, paddr, 0,
				PAGE_SIZE_2MB, node_id);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"DMA failed to send data\
					to VE PHY Memory\n");
		}
	} else {
		for (i = 0; i < BITS_PER_BLOCK; i++) {
			retval = amm_dma_xfer(VE_DMA_VEMAA, vnode_info->
					zeroed_page_address, 0,	VE_DMA_VEMAA,
					paddr + (i*PAGE_SIZE_2MB),
					0, PAGE_SIZE_2MB, node_id);
			if (-1 == retval) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"DMA failed to send \
						data to VE PHY Memory\n");
			}
		}
	}

	return retval;
}

/**
* @brief This function is used to initilaize the given VE memory address to zero.
*
* @param[out] addr VE Physical Address
* @param[in] node_id Node ID
*
* @return On Success return 0 and -1 on failure.
*/
int amm_initialize_zeroed_page(uint64_t addr, int node_id)
{
	int retval = -1;
	int src_pid = getpid();
	char *buff;

	buff = calloc(PAGE_SIZE_2MB, sizeof(char));
	if (NULL == buff) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VH calloc fails!!\n");
		return retval;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"MEM Clear for PHY Addr: 0x%lx Size: %p\n",
			(long unsigned int)addr, (void *)PAGE_SIZE_2MB);

	/* Request for DMA transfer, 2MB size at a time */
#ifdef __PCIDEV_ENV
	if (mlock(buff, PAGE_SIZE_2MB)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "VH mlock fails!!\n");
		perror("mlock");
		return retval;
	}

#endif
	retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)buff, src_pid,
			VE_DMA_VEMAA, addr, 0, PAGE_SIZE_2MB, node_id);
#ifdef __PCIDEV_ENV
	if (munlock(buff, PAGE_SIZE_2MB)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VH munlock fails!!\n");
		perror("munlock");
		return retval;
	}
#endif
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"DMA failed to send data to VE PHY Memory\n");
	}
	free(buff);
	return retval;
}
/**
* @brief This routine enables paging in VE node and divide PHY memory
* into chunks of pages.
*
* @param[in] handle VEDL handle
* @param[in] node_id Node ID
*
* @return On success return 0 and -1 on failure
*/
int amm_paging_init(vedl_handle *handle, int node_id)
{
	int ret = 0;
	uint64_t paddr = 0;
	unsigned long  nr_pages;
	int index;
	int reserved_pages = 0;
	struct stat file_stat;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	vnode_info->ve_pages = NULL;	/*set to NULL*/

	ret = vedl_get_mem_info(handle, &(vnode_info->mem));
	if (ret < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEDL fails to provide node memory info !!!\n");
		return -1;
	}

	/* Initilaizing DMAATB to Zero
	*/
	memset(&(vnode_info->dmaatb), 0, sizeof(dmaatb_reg_t));
	/**
	 * During paging initialization if due to any H/W fault the memory map
	 * seems to be faulty then AMM will terminate
	 */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Initializing Paging for "
			"Available VE memory size: 0x%lx\n",
			(vnode_info->mem).ve_mem_size);
	if (((vnode_info->mem).ve_mem_size == 0) &&
			(((vnode_info->mem).ve_mem_addr) < 0)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VE HW FAULT, Physical MEM MAP error\n");
		ret = -1;
		goto error;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"VE Physical Start ADDR: 0x%lx End ADDR: 0x%lx\n",
			(vnode_info->mem).ve_mem_addr,
			(vnode_info->mem).ve_mem_addr + (vnode_info->mem).ve_mem_size);
	/*
	 * veos will exit in case VE physical memory start
	 * and end is not 2MB aligned.
	 */
	if ((!IS_ALIGNED((vnode_info->mem).ve_mem_size, PAGE_SIZE_2MB)) ||
			(!IS_ALIGNED((vnode_info->mem).ve_mem_addr, PAGE_SIZE_2MB))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VE HW FAULT, Physical MEM MAP "
				"Not 2MB Aligned\n");
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Exiting veos...\n");
		ret = -1;
		goto error;
	}
	/*
	 * TODO:
	 * If some reserved area is allocated to NODE then VE node PHY
	 * MEM map start that will be really available for paging will
	 * be different this code assumes start from 0th address,
	 * Allocated nr_pages depends whether the usable memory size for
	 * paging needs to be 2MB divisble if not then remaining memory
	 * chunk will always be unused so that information also needs to
	 * be maintained in VE node instance (BUDDY ALLOCATOR will take care
	 * of this).
	 */
	nr_pages = (((vnode_info->mem).ve_mem_addr) +
			((vnode_info->mem).ve_mem_size)) / (PAGE_SIZE_2MB);
	paddr = (vnode_info->mem).ve_mem_addr;
	/* One page of size 2MB is reserved whose content is zero
	 * and will be used as a reference to clear every page of
	 * VE memory.
	 * TODO: Yes, this method is waisting One physical page of size 2MB.
	 * Need to incorporate more efficient method to save this waiste.
	 */
	vnode_info->zeroed_page_address = paddr;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Reserved Zerored Page address: 0x%lx\n",
			vnode_info->zeroed_page_address);
	paddr += PAGE_SIZE_2MB;
	/*
	 * Info regarding the physical memory that is reserved from 0 to
	 * start address in term of 2MB page size.
	 */
	reserved_pages = paddr/PAGE_SIZE_2MB;
	vnode_info->nr_pages = nr_pages;
	vnode_info->mapsize = nr_pages/BITS_PER_BLOCK;

	/*
	 * Since bits per Block is 32. If nr_pages counts less than 32
	 * mapsize will be zero and Behaviour will be unexpected.
	 */
	if (!vnode_info->mapsize) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"mem_size can not be less than "
				"64MB or 0x4000000\n");
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Exiting veos...\n");
		ret = -1;
		goto error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Reserved pages: %u nr_pages:%lu map size:%lu\n",
			reserved_pages, nr_pages, vnode_info->mapsize);

	vnode_info->bitmap = (uint32_t *)malloc(
			(vnode_info->mapsize) * sizeof(uint32_t));
	if (vnode_info->bitmap == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Paging Init, Cant allocate memory for bitmap\n");
		ret = -1;
		goto error;
	}
	memset(vnode_info->bitmap, 0, ((vnode_info->mapsize)*sizeof(int)));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Total number of pages associated with VE node is %lu\n",
			nr_pages);
	vnode_info->ve_pages = (struct ve_page *)malloc
		((sizeof(struct ve_page))*nr_pages);
	if (vnode_info->ve_pages == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Error in allocating memory for page structures\n");
		ret = -1;
		goto error;
	}
	memset(vnode_info->ve_pages, 0, (sizeof(struct ve_page))*nr_pages);

	if (ve_mem_clear) {
		/* It will initialize to zeroed page.
		*/
		ret = amm_initialize_zeroed_page(
				vnode_info->zeroed_page_address,
				node_id);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Can't able to initialize zeored page.\n");
			goto error;
		}
		fprintf(stderr, "Clearing VE memory\n");
		fflush(stderr);
	}

	for (index = 0; index < nr_pages; index++) {
		/*
		 * if start address is not zero then marking the page
		 * as reserved so that veos never use that page.
		 */
		if (index < reserved_pages) {
			set_page_used(index, node_id, PAGE_SIZE_2MB);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Page %d marked as reserved\n", index);
			continue;
		}
		/*
		 * Clear the physical pages
		 */
		if (ve_mem_clear) {
			ret = amm_clear_page(index, node_id, PAGE_SIZE_2MB);
			if (-1 == ret) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Fails in initializing VE memory\n");
				goto error;
			}
			fprintf(stderr, "\r%d%% complete",
					(int)((index * 100/nr_pages)));
			fflush(stderr);
		}

		vnode_info->ve_pages[index].page_start = paddr;
		vnode_info->ve_pages[index].page_size = PAGE_SIZE_2MB;
		vnode_info->ve_pages[index].flag |= PG_VE;
		paddr = paddr +  PAGE_SIZE_2MB;
		vnode_info->ve_pages[index].flag = 0;
		vnode_info->ve_pages[index].perm = 0;
		vnode_info->ve_pages[index].ref_count = 0;
		vnode_info->ve_pages[index].private_data = NULL;
	}

	if (ve_mem_clear)
		fprintf(stderr, "\rVE Memory Cleared\n");

	/*File Backed mmap global list initlization*/
	memset(&file_stat, '\0', sizeof(file_stat));
	vnode_info->file_desc_start = init_file_map_desc(file_stat);
	INIT_LIST_HEAD(&vnode_info->file_desc_start->global_list);
	INIT_LIST_HEAD(&vnode_info->shm_head);

	return ret;
error:
	if (NULL != vnode_info->bitmap)
		free(vnode_info->bitmap);
	if (NULL != vnode_info->ve_pages)
		free(vnode_info->ve_pages);
	return ret;
}


/**
* @brief Function to set ATB for 2MB pages.
*
* @param[in] vaddr vemva for which ATB needs to be set
* @param[in] rw_prot whether write permission needs to be set in ATB
* @param[in] pgno page number
* @param[out] tmp_atb ATB of the VE process
*
* @return On success return 0, negative value on failure
*/
int amm_set_atb(uint64_t vaddr, int rw_prot, int pgno,
		atb_reg_t *tmp_atb, uint64_t page_size)
{
	int ret = -1;
	int pgmod;
	uint64_t  psoff;
	int16_t dir_num;
	uint64_t pgoff;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Setting PSPT to accommodate 2MB PAGES for: %lx\n",
			vaddr);

	psoff = (page_size == PAGE_SIZE_2MB) ? psnum(vaddr) : psnum_h(vaddr);
	pgmod = (page_size == PAGE_SIZE_2MB) ? PG_2M : PG_HP;

	dir_num =  search_atb_ps((char *)vaddr, pgmod, tmp_atb);
	if (-1 == dir_num) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB Directory not available"
				"for vaddr %p\n", (void *)vaddr);
		ret = -1;
		goto error;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"dir_num:%d psoff:%lx\n", dir_num, psoff);
	/*
	 * Setting ATB Directory entries
	 */
	if (!ps_isvalid(&(tmp_atb->dir[dir_num]))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB Directory Entry %d not in USE\n", dir_num);
		init_atb_dir(tmp_atb, dir_num, psoff, 0, pgmod);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB directory entry %d already valid\n", dir_num);
	}

	/**
	 * Update PAGE entries in ATB directory
	 */
	pgoff = (page_size == PAGE_SIZE_2MB) ? pgnum(vaddr) : pgnum_h(vaddr);
	/**
	 * TODO:
	 * Page Base address as per free page availability
	 * Multiple return value is to specify error value that can
	 * be sent to pseudo on which errno is decided
	 */
	if (pg_isvalid(&(tmp_atb->entry[dir_num][pgoff]))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ATB ENTRY %ld is already available to user\n",
				pgoff);
		ret =  -1;
		goto error;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB ENTRY %ld is free to update with page number %d\n",
				pgoff, pgno);
		pg_setpb(&(tmp_atb->entry[dir_num][pgoff]), pgno, pgmod);
		pg_valid(&(tmp_atb->entry[dir_num][pgoff]));

		/* Is the memory write protected ? */
		if (rw_prot == 0)
			pg_setprot(&(tmp_atb->entry[dir_num][pgoff]));

		pg_settype(&(tmp_atb->entry[dir_num][pgoff]), PG_VEMAA);
	}
	ret = 0;
error:
	return ret;
}

/**
* @brief This is generic mmap handler which allocates VE PHY memory and maintains ATB.
*
* @param[out] vaddr This is VEMVA for which VE PHY pages needs to be mapped
* @param[in] size Size of PHY memory needs to be mapped
* @param[in] permissions Permission for PHY memory region
* @param[in] flags Type of mapping (GROWUP|GROWDOWN)
* @param[in] p_ve_task Pointer of ve_task_struct of the VE process
*
* @return return 0 on success and negative value on failure
*/
int amm_do_mmap(uint64_t vaddr, uint64_t size, uint64_t permissions,
		uint64_t flags, struct ve_task_struct *p_ve_task,
		struct file_map_stat *file_map_stat)
{
	uint64_t count;
	uint64_t start = 0;
	uint64_t ps_entry;
	uint64_t page_size = 0;
	int ret = 0;
	int node_id;
	int rw_prot = 0;
	uint64_t *map;
	atb_reg_t tmp_atb;
	uint64_t taddr = 0;
	int64_t offset_start = 0;
	int64_t offset_end;
	/*TODO: Need to be updated for dynamic size*/
	uint64_t bitmap[4];
	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;
	struct ve_node_struct *vnode_info;
	struct file_map_desc *file_desc_tmp = NULL;

	node_id = p_ve_task->node_id;

	vnode_info = VE_NODE(node_id);

	memset(bitmap, '\0', sizeof(bitmap));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"MMAP arguments -: vemva:%lx size:%lu "
			"perm:%lu flags:%lu\n",
			vaddr, size, permissions, flags);

	/*
	 * size should be aligned as per the page size requested
	 */
	if (MAP_HUGETLB == (flags & MAP_HUGETLB))
		page_size = PAGE_SIZE_64MB;
	else
		page_size = PAGE_SIZE_2MB;

	count = (size / page_size);

	/*Is writable permission request received ? */
	if (permissions & VE_PROT_WRITE)
		rw_prot = 1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Pages Required for mmap: %lu\n", count);

	/**
	 * Check if the mapping is file_backed or not
	 */
	if (!(MAP_ANON & flags) && (MAP_SHARED & flags)) {
		/*Scan Global file_mapping list*/
		file_desc_tmp = scan_global_list(
				file_map_stat->file_stat, node_id);
		if (file_desc_tmp == (void *)-1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"scan global list failed\n");
			return -1;
		}

		offset_start = file_map_stat->offset_start;
		offset_end = file_map_stat->offset_end;

		map = amm_do_file_back_handling(file_desc_tmp, offset_start,
				offset_end, bitmap, node_id, page_size);

		if ((void *)-1 == map) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"amm_do_file_back_handling failed\n");
			return -1;
		}
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "bitmap[0] = %lx\n",
					bitmap[0]);
	} else {
		/*Init send_data bitmap*/
		if (!(flags & MAP_ANON)) {
			offset_start = file_map_stat->offset_start;
			offset_end = file_map_stat->offset_end;
			set_bits(bitmap, 0, count);
		}

		map = (uint64_t *)malloc(count * (sizeof(uint64_t)));
		if (NULL == map) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Error in allocating hold page info\n");
			return -1;
		}
		memset(map, '\0', (count * (sizeof(uint64_t))));

		/**
		 * When alloc_ve_pages fails to allocate VE physical page
		 * then it means VE node does not have enough memory
		 * at this time ENOMEM will be returned instead of EFAULT(TBD)
		 */
		ret = alloc_ve_pages(count, map, node_id, page_size);
		if (ret == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"VE page allocation failed\n");
			free(map);
			return ret;
		}
	}


	/*Get mm_struct_lock here*/
	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));

	/**
	 * Below loops are only for assigning virtual address to
	 * VE PHY pages and certain calculations to fill ATB
	 * TODO:
	 * The loops needs to be optimized.
	 */

	for (start = 0; start < count; start++) {
		if ((flags & VE_MMAP_GROWSDOWN)) {
			/*
			 * As stack grows downward so virtual
			 * address assigned to pages must be
			 * decremented
			 */
			taddr = vaddr - ((start + 1) * page_size);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"vemva for mapping for stack: %lx\n",
					taddr);
		} else {
			/*
			 * Address assignment to VE PHY pages
			 * is same for heap and anonymous
			 * mapping therefore below condition
			 * works for anonymous as well as heap
			 * mapping
			 */
			taddr = vaddr + (start * page_size);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"heap or anon map, for vemva: %lx\n",
					taddr);
		}
		/*
		 * TBD: Here we are updating flag and perm field
		 * of struct ve_page as received from mmap
		 * */
		pthread_mutex_lock(&(vnode_info->amm_node_lock));
		vnode_info->ve_pages[map[start]].flag = flags;
		vnode_info->ve_pages[map[start]].perm = permissions;
		vnode_info->ve_pages[map[start]].ref_count++;
		pthread_mutex_unlock(&(vnode_info->amm_node_lock));

		ret = amm_set_atb(taddr, rw_prot,
				map[start], &tmp_atb, page_size);
		if (ret < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Not able to set ATB of vemva:%lx\n",
					taddr);
			ret = -1;
			goto mmap_error;
		}
	}

	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));

	if (!(flags & MAP_ANON)) {
		ret = send_file_data(vaddr, bitmap, file_map_stat->file_stat,
				offset_start, p_ve_task, size, page_size);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"send_file_data failed\n");
			goto mmap_error;
		}
	}

	free(map);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"MMAP Done\n");
	return ret;

mmap_error:
	/**
	 * TODO:
	 * Proper cleanup if any issue comes in between MMAP handling then
	 * clear ATB's updated before that and need to be tracked properly.
	 * Restore ATB, File backed Data structures and Page bitmap required
	 * here
	 */
	pthread_mutex_unlock(&(mm_struct->mm_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "In LABEL MMAP ERROR\n");
	for (ps_entry = 0; ps_entry < count; ps_entry++) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Freeing pageno:%lu\n",	*(map + ps_entry));
		set_page_free(*(map + ps_entry), node_id, page_size);
	}

	free(map);
	return ret;
}

/**
* @brief This is core unmap handler which unmaps the PHY mapping
* corresponding to virtual address.
*
* @param[in] vaddr VEMVA whose physical mapping needs to be removed
* @param[in] size Size of region that needs to be unmapped
* @param[in] p_ve_task Pointer to ve_task_struct of VE process
*
* @return On success it returns 0 and -1 on failure
*/
int amm_do_munmap(uint64_t vaddr, size_t size,
		struct ve_task_struct *p_ve_task)
{
	unsigned long pageno = 0;
	unsigned long  tc, count = 0;
	uint64_t calc_addr;
	int16_t dir_num, pgoff;
	unsigned long start = 0;
	int ret = -1;
	int pgmode_dir;
	uint64_t page_size;
	atb_reg_t tmp_atb;
	unsigned long *pgno = NULL;
	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;
	struct shm_mapping *shm_tmp;
	void *shmaddr_start;
	void *shmaddr_end;
	struct ve_node_struct *vnode_info;

	vnode_info = VE_NODE(p_ve_task->node_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In AMM unmap handler\n");

	/*Get mm_struct_lock here*/
	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));
	/* Retrive the page size of the VE memory to be released */
	pgmode_dir = get_page_size(vaddr, &tmp_atb);
	if (-1 == pgmode_dir) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Page size not found\n");
		pthread_mutex_unlock(&(mm_struct->mm_lock));
		return -1;
	} else if (PG_2M == pgmode_dir) {
		page_size = PAGE_SIZE_2MB;
	} else
		page_size = PAGE_SIZE_64MB;

	count = size / page_size;
	tc = count;
	calc_addr = vaddr;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"AMM UNMAP, vemva:%lx size:%lu count:%lu\n",
			vaddr, size, count);
	pgno = (unsigned long *)malloc(count*sizeof(unsigned long));
	if (NULL == pgno)  {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc fails in allocating memory\n");
		goto error_1;
	}
	while (tc != 0) {
		/**
		 * TODO:
		 * Currently no such data structure is decided that
		 * can tell whether the vaddr is mapped with HUGE page
		 * or normal page but this logic needs to be added
		 * currently the normal page size(2M) is supported by
		 * AMM so it is hard coded for now but later on, during
		 * unmap it must be required to calculate whether the page
		 * is HUGE or not
		 */
		dir_num =  search_atb_ps((char *)calc_addr,
				(page_size == PAGE_SIZE_2MB ? PG_2M : PG_HP),
				&tmp_atb);
		if (-1 == dir_num) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"ATB Directory not available"
					"for vaddr %p\n", (void *)calc_addr);
			ret = -1;
			goto error;
		}

		/**
		 * TODO:
		 * Check Validity of ATB directory entry whether
		 * it is valid or not
		 * Also check entries which lies in current ATB
		 * directory corresponding to address for unmap
		 * When all entries for current ATB directory
		 * becomes invalid then mark the ATB directory
		 * itself invalid
		 * if single entry in directory is valid then
		 * don't mark ATB directory as invalid
		 * May be BITMAPS are required per ATB directory
		 * entry in order. TBD ERRNO needs to be discussed
		 * ATB ENTRY is valid if not then it is
		 * MEM FAULT (probably programmers mistake),
		 * Its not required to check here because
		 * __ve_unmap verifies this but for AMM stability
		 * it needs to perform this type of ERROR HANDLING
		 */
		if (ps_isvalid(&(tmp_atb.dir[dir_num]))) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"ATB Directory entry is valid\n");
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"ATB DIRCETORY ENTRY %d is not valid\n",
					dir_num);
			goto error;
		}

		pgoff = (page_size == PAGE_SIZE_2MB) ?
			pgnum(calc_addr) : pgnum_h(calc_addr);
		if (!pg_isvalid(&(tmp_atb.entry[dir_num][pgoff]))) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB ENTRY not yet allocated, can't unmap\n");
			goto error;
		}

		pageno = pg_getpb(&(tmp_atb.entry[dir_num][pgoff]), pgmode_dir);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Physical page number: %lu mapped with VEMVA: %lx\n",
				pageno, calc_addr);
		pg_unsettype(&(tmp_atb.entry[dir_num][pgoff]));
		pg_clearpfn(&(tmp_atb.entry[dir_num][pgoff]));
		pg_invalid(&(tmp_atb.entry[dir_num][pgoff]));
		pg_unsetprot(&(tmp_atb.entry[dir_num][pgoff]));

		pgno[start] = pageno;
		start++;
		tc--;
		calc_addr = vaddr + (start * page_size);
	}

	/*
	 * On succcess update the ATB structure maintained in mm_struct
	 */
	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));

	for (tc = 0; tc < count; tc++) {
		if (PG_SHM & vnode_info->ve_pages[pgno[tc]].flag) {
			calc_addr = vaddr + (tc * page_size);
			list_for_each_entry(shm_tmp,
					&mm_struct->shm_head, shm_list) {
				shmaddr_start = shm_tmp->shmaddr;
				shmaddr_end = shmaddr_start +
					(shm_tmp->shm_segment->size);
				if (((void *)calc_addr >= shmaddr_start) &&
						((void *)calc_addr <= shmaddr_end)) {
					shm_tmp->shm_segment->nattch--;
					shm_tmp->count--;
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
							"nattch"
							"is : %ld\n",
							shm_tmp->shm_segment->nattch);
					break;
				}
			}

			if (0 == shm_tmp->count) {
				pthread_mutex_lock(&mm_struct->shm_lock);
				list_del(&shm_tmp->shm_list);
				free(shm_tmp);
				pthread_mutex_unlock(&mm_struct->shm_lock);
			}

			ret = 0;
			continue;
		}
		/* Set Page Free */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Releasing page: %ld\n", pgno[tc]);
		ret = release_page(pgno[tc], p_ve_task->node_id, page_size);
		if (ret < 0)
			break;
	}

	free(pgno);
	return ret;
error:
	free(pgno);
error_1:
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));
	return ret;
}

/**
* @brief This is core mprotect handler which changes the permission
* of PHY memory corresponding to virtual address.
*
* @param[out] vaddr VEMVA whose physical mapping protection needs to be change
* @param[in] size Size of region till the memory protection to change
* @param[in] permissions Permission for PHY memory region
* @param[in] p_ve_struct Pointer to ve_task_struct of VE process
*
* @return On success it returns 0 and -1 on failure
*/
int amm_do_mprotect(uint64_t vaddr, uint64_t size, uint64_t permissions,
		struct ve_task_struct *p_ve_task)
{
	unsigned long pageno = 0;
	unsigned long  tc, count = 0;
	uint64_t calc_addr;
	int16_t dir_num, pgoff;
	uint64_t start = 0;
	uint64_t page_size;
	int ret = -1;
	int pgmode_dir;
	atb_reg_t tmp_atb;
	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In AMM mprotect handler\n");

	/*Get mm_struct_lock here*/
	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));
	/* Get VE memory page size */
	pgmode_dir = get_page_size(vaddr, &tmp_atb);
	if (-1 == pgmode_dir) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Page size not found\n");
		pthread_mutex_unlock(&(mm_struct->mm_lock));
		return -1;
	} else if (PG_2M == pgmode_dir) {
		page_size = PAGE_SIZE_2MB;
	} else
		page_size = PAGE_SIZE_64MB;
	/* Number of VE phy pages to operate on */
	count = size / page_size;
	tc = count;
	calc_addr = vaddr;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"AMM MPROTECT ARGS, VEMVA:%lx Size:%lu PERM:%lx\n",
			vaddr, size, permissions);

	while (tc != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Inside while loop\n");
		dir_num =  search_atb_ps((char *)calc_addr,
				(page_size == PAGE_SIZE_2MB ? PG_2M : PG_HP),
				&tmp_atb);
		if (-1 == dir_num) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"ATB Directory not available"
					"for vaddr %p\n", (void *)calc_addr);
			ret = -1;
			goto mprot_error;
		}

		if (ps_isvalid(&(tmp_atb.dir[dir_num])))
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"ATB Directory entry is valid\n");
		else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"ATB DIRCETORY ENTRY: %d is not valid\n",
					dir_num);
			goto mprot_error;
		}

		pgoff = (page_size == PAGE_SIZE_2MB) ?
			pgnum(calc_addr) : pgnum_h(calc_addr);
		if (!pg_isvalid(&(tmp_atb.entry[dir_num][pgoff]))) {
			if (pg_getpb(&(tmp_atb.entry[dir_num][pgoff]),
				pgmode_dir))
				pg_valid(&(tmp_atb.entry[dir_num][pgoff]));
			else {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"ATB ENTRY not yet allocated\n");
				goto mprot_error;
			}
		}

		pageno = pg_getpb(&(tmp_atb.entry[dir_num][pgoff]), pgmode_dir);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Physical page number: %lu "
				"mapped with VEMVA: %lx\n",
				pageno, calc_addr);
		if (permissions == VE_PROT_NONE) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Setting permission: VE_PROT_NONE\n");
			pg_invalid(&(tmp_atb.entry[dir_num][pgoff]));
		} else if (permissions == VE_PROT_READ) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Setting permission: VE_PROT_READ\n");
			pg_setprot(&(tmp_atb.entry[dir_num][pgoff]));
		} else if ((permissions & VE_PROT_WRITE) ==
				VE_PROT_WRITE) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Setting permission: VE_PROT_WRITE\n");
			pg_unsetprot(&(tmp_atb.entry[dir_num][pgoff]));
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Invalid permmision: %lx\n", permissions);
			goto mprot_error;
		}

		start++;
		tc--;
		calc_addr = vaddr + (start * page_size);
	}

	/*
	 * On succcess update the ATB structure maintained in mm_struct
	 */
	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));
	ret = 0;
mprot_error:
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));
	return ret;
}

/**
* @brief From VE PAGE MAP it allocated free pages.
*
* @param[in] count Number of free pages
* @param[out] map Holds page number that is allocate
* @param[in] node_id Node ID
* @param[in] page_size page used for the memory allocation
*
* @return On success retrun 0 or positive value and negative value on failure
*/
int alloc_ve_pages(uint64_t count, uint64_t *map,
		int node_id, uint64_t page_size)
{
	int tmp_ve_mem_clear;
	int ret = 0;
	int itr, i;
	struct ve_node_struct *vnode_info;

	vnode_info = VE_NODE(node_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Allocating %lu VE PHY Pages\n", count);
	for (itr = 0; itr < count; itr++) {
		/*Get amm_bitmap_lock here*/
		pthread_mutex_lock(&(vnode_info->amm_bitmap_lock));
		ret = get_free_pages(node_id, page_size);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"NO VE PHY Page is free\n");
			/*Release ve_node_bitmap_lock here*/
			pthread_mutex_unlock(&(vnode_info->
						amm_bitmap_lock));
			goto error;
		}
		*(map + itr) = ret;
		set_page_used(ret, node_id, page_size);
		/*Release amm_bitmap_lock here*/
		pthread_mutex_unlock(&(vnode_info->amm_bitmap_lock));
	}
	return ret;
error:
	tmp_ve_mem_clear = ve_mem_clear;
	ve_mem_clear = 0;
	for (i = 0; i < itr; i++) {
		set_page_free(map[i], node_id, page_size);
	}
	ve_mem_clear = tmp_ve_mem_clear;
	return ret;
}

/**
* @brief Check page status whether used or not.
*
* @param[in] pageno Page number whose status needs to check
* @param[in] node_id NODE ID
* @paran[in] pgsize Size of page
*
* @return Return 1 if page is used and 0 if it is free
*/
int is_page_used(uint64_t pageno, int node_id, uint64_t pgsize)
{
	int status = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In is_page_used\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	if (pgsize == PAGE_SIZE_2MB) {
		if (pageno < BITS_PER_BLOCK) {
			status = ((vnode_info->bitmap[0] >> pageno) & 1);
			return status;
		}
		status = ((vnode_info->bitmap[pageno/BITS_PER_BLOCK] >>
					pageno % BITS_PER_BLOCK) & 1);
	} else {
		if (!(pageno % BITS_PER_BLOCK)) {
			if (~0U == vnode_info->
					bitmap[pageno/BITS_PER_BLOCK])
				return 1;
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Invalid 64MB page number\n");
			return 0;
		}
	}
	return status;
}

/**
* @brief From VE PAGE MAP it allocates page that is free.
*
* @param node_id node_id Node ID
* @param page_size size of the page 2MB or 64MB
*
* @return On success returns page number(positive) and -1 on failure
*/
int get_free_pages(int node_id, uint64_t page_size)
{
	uint64_t i, x;
	int ret = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "get_free_pages\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	/* Get 2MB page size else try to find contiguous 32 2MB pages */
	if (PAGE_SIZE_2MB == page_size) {
		for (i = 0; i < vnode_info->mapsize; i++)
			for (x = 0; x < BITS_PER_BLOCK; x++)
				if (!((vnode_info->bitmap[i] >> x) & 1))
					return (i * BITS_PER_BLOCK) + x;
		return ret;
	} else {
		for (i = 0; i < vnode_info->mapsize; i++)
			if (!(vnode_info->bitmap[i]))
				return i*BITS_PER_BLOCK;
	}

	return ret;
}

/**
* @brief Marks page status as used.
*
* @param[in] pageno Page number which needs to be marked as used
* @param[in] node_id Node ID
* @paran[in] pgsize Size of the page
*
* @return On success returns 0 and -1 on failure
*/
int set_page_used(uint64_t pageno, int node_id, uint64_t pgsize)
{
	int ret = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "IN SET PAGE USED\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	if (is_page_used(pageno, node_id, pgsize))
		return ret;

	if (PAGE_SIZE_2MB == pgsize) {
		vnode_info->bitmap[pageno/BITS_PER_BLOCK] |=
			1 << (pageno % BITS_PER_BLOCK);
	} else {
		if (!(pageno % BITS_PER_BLOCK))
			vnode_info->bitmap[pageno/BITS_PER_BLOCK]
				= ~0U;
		else
			return ret;
	}
	return 0;
}

/**
* @brief Marks Page status as free.
*
* @param[in] pageno Page number whose status needs to be marked as free
* @param[in] node_id Node ID
*
* @return On success returns 0 and -1 on failure
*/
int set_page_free(uint64_t pageno, int node_id, uint64_t pgsize)
{
	int ret = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In set page free routine\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	if (!is_page_used(pageno, node_id, pgsize))
		return ret;

	if (PAGE_SIZE_2MB == pgsize) {
		vnode_info->bitmap[pageno / BITS_PER_BLOCK] &=
			~(1 << (pageno % BITS_PER_BLOCK));
	} else {
		if (!(pageno % BITS_PER_BLOCK))
			vnode_info->bitmap[pageno/BITS_PER_BLOCK]
				= 0U;
		else
			return ret;
	}

	if (ve_mem_clear) {
		ret = amm_clear_page(pageno, node_id, pgsize);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Page %ld is released but fails"
					" to clear it's content\n",
					pageno);
		}
	} else {
		ret = 0;
	}
	return ret;
}

/**
* @brief Provide total count of VE PHY pages that are in use by all VE process.
*
* @param[in] node_id Node ID
*
* @return On success returns count and -1 on failure
*/
int ve_node_page_used_count(int node_id)
{
	int i, x, cpt = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"In VE Node Used Page Count\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);
	/*
	 * TODO:
	 * page bit map is protected by lock so it will be atomically updated
	 * this function can fail if the bit map is not accessible at that
	 * moment currently the locks are not maintained.
	 */
	/*Get amm_bitmap_lock here*/
	pthread_mutex_lock(&(vnode_info->amm_bitmap_lock));
	for (i = 0; i < vnode_info->mapsize; i++)
		for (x = 0; x < BITS_PER_BLOCK; x++)
			cpt += (vnode_info->bitmap[i] >> x) & 1;
	/*Release ve_node_bitmap_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_bitmap_lock));
	return cpt;
}

/**
* @brief Provide Total count of VE PHY pages that are not in use.
*
* @param[in] node_id Node ID
*
* @return On success returns count and -1 on failure
*/
int  ve_node_page_free_count(int node_id)
{
	int i, x, cpt = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"In VE Node Free Page Count\n");
	struct ve_node_struct *vnode_info = VE_NODE(node_id);
	/*
	 * TODO:
	 * page bit map is protected by lock so it will be atomically updated
	 * this function can fail if the bit map is not accessible at that
	 * moment currently the locks are not maintained.
	 */
	/*Get amm_bitmap_lock here*/
	pthread_mutex_lock(&(vnode_info->amm_bitmap_lock));
	for (i = 0; i < vnode_info->mapsize; i++)
		for (x = 0; x < BITS_PER_BLOCK; x++)
			cpt += !((vnode_info->bitmap[i] >> x) & 1);
	/*Release ve_node_bitmap_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_bitmap_lock));
	return cpt;
}


/**
* @brief : This function will convert virtual address into physical;
*
* @param[in] vaddr : virtual address which is to be converted into physical.
* @param[in] pid : pid of process.
* @param[in] inc_ref : flag to indicate whether to increase ref count or not.
*
* @return : return physical address on success and -1 on failure.
*/
uint64_t veos_virt_to_phy(uint64_t vaddr, pid_t pid, bool inc_ref)
{
	uint64_t retval;
	uint64_t *pgaddr;
	struct ve_task_struct *current_task;
	atb_reg_t atb;

	/*Obtain the task struct using pid*/
	current_task = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
				MAX_VE_CORE_PER_VE_NODE, (pid_t)pid);
	if (NULL == current_task) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Invalid pid\n");
		retval = -1;
		errno = ESRCH;
		goto func_return;
	}
	/*Get atb structure of current process*/
	pthread_mutex_lock(&current_task->p_ve_mm->mm_lock);
	atb = current_task->p_ve_mm->atb;
	pthread_mutex_unlock(&current_task->p_ve_mm->mm_lock);

	/*convert virtual address into physical*/
	retval = (uint64_t)amm_addr_translation((char *)vaddr, &atb);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"amm_addr_translation failed\n");
		retval = -1;
		errno = EINVAL;
		goto func_return;

	}

	if (inc_ref) {
		pgaddr = (uint64_t *)malloc(sizeof(uint64_t)*2);
		if (NULL == pgaddr) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"can't allocate memory using malloc\n");
			retval = -1;
			goto func_return;
		}
		pgaddr[0] = retval;
		pgaddr[1] = 0;
		/*if inc_ref flag is TRUE then increament the ref count*/
		if (-1 == veos_get_page(pgaddr)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"veos_get_page failed\n");
			retval = -1;
			errno = EINVAL;
			free(pgaddr);
			goto func_return;
		}
		free(pgaddr);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		"PHYSICAL ADDRESS = 0x%lx\n", retval);

func_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"OUT func\n");
	return retval;
}

/**
* @brief This function translate's the VE Virtual address to
* Physical address based on the ATB.
*
* @param[in] vaddr VE Virtual address
* @param[in] atb ATB of the VE process
*
* @return On Success, it returns the Physical address or -1 on failure.
*/
int64_t amm_addr_translation(char *vaddr, atb_reg_t *atb)
{
	int pgmode_dir;
	int16_t dir_num, pgoff;
	int64_t ret = -1;

	pgmode_dir = get_page_size((uint64_t)vaddr, atb);
	dir_num = search_ps_common(vaddr, pgmode_dir, atb, NULL, -1);
	if (-1 == dir_num) {
		 VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				 "Invalid dir_num\n");
		 return ret;
	} else if (!ps_isvalid(&(atb->dir[dir_num]))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"ATB directory entry %d not valid\n",
				dir_num);
		return ret;
	}

	pgoff = (pgmode_dir == PG_2M) ? pgnum(vaddr) : pgnum_h(vaddr);

	if (!pg_isvalid(&(atb->entry[dir_num][pgoff]))) {

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"ATB ENTRY not yet allocated\n");
		return ret;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"DIR %d PGOFF = %d PB = 0x%lx\n",
			dir_num, pgoff, atb->entry[dir_num][pgoff].data);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"PAGE OFFSET = %lx PAGE BASE ADDRESS = %lx\n",
			((reg_t)vaddr & 0x1fffff),
			(atb->entry[dir_num][pgoff].data >> 21));
	ret = ((reg_t)vaddr & 0x1fffff) |
		((atb->entry[dir_num][pgoff].data >> 21) << 21);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"PHYSICAL ADDRESS = 0x%lx\n", ret);

	return ret;
}

/**
* @brief This Function initialize file_map_descriptor.
*
* @param[in] file_stat Stats about the file to be mapped.
*
* @return Return pointer to the file_map_descrioptor on success.
*/
struct file_map_desc *init_file_map_desc(struct stat file_stat)
{
	struct file_map_desc *file_desc_tmp = (void *)-1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	file_desc_tmp = malloc(sizeof(struct file_map_desc));
	if (NULL == file_desc_tmp) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc init_file_map_desc failed\n");
		goto err_return;
	}
	memset(file_desc_tmp, '\0', sizeof(struct file_map_desc));

	file_desc_tmp->file_stat = file_stat;

	INIT_LIST_HEAD(&file_desc_tmp->mapping_list);

	if (pthread_mutex_init(&(file_desc_tmp->file_desc_lock), NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"\n Mutex init failed\n");
		free(file_desc_tmp);
		goto err_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return file_desc_tmp;
err_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func with err\n");
	return (void *)-1;
}

/**
* @brief This function scans the global list of file_map_desc
* to find the same file mapping.
*
* @param[in] file_stat Stats about the file to be mapped.
* @param[in] node_id Node Id of node on which process is running.
*
* @return Return pointer to the matching file_map_descriptor.
*/
struct file_map_desc *scan_global_list(struct stat file_stat, int node_id)
{
	struct list_head *temp;
	struct file_map_desc *file_desc_tmp;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	/*Get amm_node_lock here*/
	pthread_mutex_lock(&(vnode_info->amm_node_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	list_for_each(temp, &vnode_info->file_desc_start->global_list)
	{
		file_desc_tmp = list_entry(temp, struct file_map_desc,
				global_list);
		if (!stat_cmp(&file_desc_tmp->file_stat, &file_stat)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Out Func:file_stat found\n");
			goto done_exit;
		}
	}

	/* TODO: These interface must go out of scanning interface
	 * The reason it is kept here is locking*/
	file_desc_tmp = init_file_map_desc(file_stat);
	if ((void *)-1 == file_desc_tmp) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"init_file_map_desc failed\n");
		goto err_exit;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Adding File_map_desc\n");
	list_add_tail(&file_desc_tmp->global_list, &vnode_info->
			file_desc_start->global_list);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Out Func:file_stat Created and added\n");
done_exit:
	/*Release amm_node_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_node_lock));
	return file_desc_tmp;
err_exit:
	/*Release amm_node_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_node_lock));
	return (void *)-1;
}

/**
* @brief This function Updates the mapping list after merging
* and inserting the new mapping list in existing mapping list.
*
* @param[in] file_desc Pointer to the file_map_descriptor with which the mapping
* is associated.
* @param[in] offset_start offset start of mapping.
* @param[in] offset_end offset end of mapping.
* @param[out] bitmap 256 bit bitmap.
* @param[in] node_id Node id of the the node on which process is running.
*
* @return: Return pointer to the map array which contain physical page number
* to map with virtual address at each index.
*/
uint64_t *amm_do_file_back_handling(struct file_map_desc *file_desc,
		int64_t offset_start, int64_t offset_end,
		uint64_t *bitmap, int node_id, uint64_t page_size)
{
	struct mapping_desc *map_desc_t;
	struct mapping_attri *map_attri;
	uint64_t *tmp_pg_array;
	uint64_t *map;
	int64_t count;
	int64_t index;
	int64_t mapping_size;

	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	/*Get file_map_desc_lock here*/
	pthread_mutex_lock(&(file_desc->file_desc_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/*
	 * This interface will scan the mapping list under file_map_descriptor
	 * and will decide from where to where the previous mapping will be
	 * merged and where the new mapping Should be inserted. All This
	 * Information will be populated in struct mapping_attribute
	 */
	map_attri = collect_map_attri(file_desc, offset_start, offset_end);
	if ((void *)-1 == map_attri) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"collect_map_attri failed\n");
		goto err_exit;
	}

	/*
	 * This interface will initialize the mapping descriptor to be added
	 * in list.
	 */
	map_desc_t = init_mapping_desc(map_attri);
	if ((void *)-1 == map_desc_t) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"init_mapping_desc failed\n");
		free(map_attri);
		goto err_exit;
	}

	count = offset_end -  offset_start;
	tmp_pg_array = map_desc_t->page_array +
		(offset_start - map_attri->offset_start);

	/*
	 * This interface will update the mapping_descriptor.
	 * This will allocate the new pages required for the mapping
	 * and will accordingly update the page array.
	 */
	map = update_mapping_desc(tmp_pg_array,
			count, bitmap, node_id, page_size);
	if ((void *)-1 == map) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"update_page_array failed\n");
		free(map_attri);
		free(map_desc_t->page_array);
		free(map_desc_t);
		goto err_exit;
	}

	/*Updating Reverese reference*/
	/*Get amm_node_lock here*/
	pthread_mutex_lock(&(vnode_info->amm_node_lock));
	mapping_size = map_attri->offset_end - map_attri->offset_start;
	tmp_pg_array = map_desc_t->page_array;
	for (index = 0; index <= mapping_size; index++) {
		if (tmp_pg_array[index]) {
			((struct ve_page *)tmp_pg_array[index])->
				private_data = (void *)map_desc_t;
			map_desc_t->file_desc = file_desc;
		}
	}
	/*Release amm_node_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_node_lock));

	/* This interface will add the mapping descriptor in the list */
	add_mapping_desc(file_desc, map_desc_t, map_attri);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	/*Release file_map_desc_lock here*/
	pthread_mutex_unlock(&(file_desc->file_desc_lock));
	return map;
err_exit:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func with err\n");
	/*Release file_map_desc_lock here*/
	pthread_mutex_unlock(&(file_desc->file_desc_lock));
	return (void *)-1;
}

/**
* @brief Initialize the mapping descriptor with offset start end
* and page_array.
*
* @param[out] map_attri Attributes of the new mapping.
*
* @return Return Pointer to the mapping descriptor.
*/
struct mapping_desc *init_mapping_desc(
		struct mapping_attri *map_attri)
{
	int64_t offset_start;
	int64_t offset_end;

	struct mapping_desc *map_desc_t = (void *)-1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	offset_start = map_attri->offset_start;
	offset_end = map_attri->offset_end;

	map_desc_t = malloc(sizeof(struct mapping_desc));
	if (NULL == map_desc_t) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc_init_mapp_desc failed\n");
		return (void *)-1;
	}
	memset(map_desc_t, '\0', sizeof(struct mapping_desc));

	map_desc_t->offset_start = map_attri->offset_start;
	map_desc_t->offset_end = map_attri->offset_end;

	map_desc_t->page_array = (uint64_t *)malloc
		((offset_end-offset_start+1)*sizeof(uint64_t));
	if (NULL == map_desc_t->page_array) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc page array failed\n");
		free(map_desc_t);
		return (void *)-1;
	}
	memset(map_desc_t->page_array, '\0', offset_end-offset_start+1);

	if (pthread_mutex_init(&(map_desc_t->map_desc_lock), NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"\n Mutex init failed\n");
		free(map_desc_t->page_array);
		free(map_desc_t);
		goto err_return;
	}

	init_page_array(map_desc_t, map_attri);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return map_desc_t;
err_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func with error\n");
	return (void *)-1;
}


/**
* @brief :This function deallocates VE physical pages.
*
* @param[in] ve_page structure containing page info.
*
* @return This function will not return any value.
*/

void veos_free_page(struct ve_page *page)
{
	/**
	 * Todo
	 * This function deallocates VE physical pages of
	 * the specific order for the requesting VE task/thread.
	 * Buddy memory scheme used for the VE physical
	 * page allocation/deallocation.
	 * When one block of memory is freed then it will
	 * check whether its associated block is free
	 * then merge the two blocks else add the block in
	 */
}
/**
* @brief : This function will increase or
*   decrease ref count depend on atomic_op
*   if
*	atomic_op == 1 then it will increase ref count;
*	atomic_op == 0 then it will decrease ref count;
*
* @param pgaddr[in] : Physical address of page
*       whose ref count is to be increase/decrease
*
* @param atomic_op[in] : Will decide whether to Increase/Decrease
*		 ref count.
* @return : Return 0 on success and -1 of failure.
*/
int common_get_put_page(uint64_t pgaddr, uint8_t atomic_op)
{
	int pgnum;
	struct ve_node_struct *vnode_info;
	struct ve_page *ve_page_info;
	int retval = 0;


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "IN func");


	if (!pgaddr) {
		retval = -1;
		errno = EINVAL;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"pgaddr is invalid :%lx\n", pgaddr);
		goto func_return;
	}

	/*
	 * Get the node info .
	 * here we are considering Node 0 hard coded.
	 * */
	vnode_info = VE_NODE(0);

	/*Get lock on ve_node_struct*/
	if (pthread_mutex_lock(&vnode_info->amm_node_lock) != 0) {
		errno = EINVAL;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"pthread_mutex_lock failed\n");
		goto func_return;
	}

	/*First obtain the page number from physical address*/
	pgnum = pnum(pgaddr);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"pgaddr %lx is belogs to page number %d\n", pgaddr, pgnum);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"Page number ref count before atomic %s : %d\n",
			(atomic_op == 1) ? "increament" : "decreament",
			(int)vnode_info->ve_pages[pgnum].ref_count);

	if (GET_PAGE & atomic_op) {
		/*
		 * Increament the ref count of page
		 * This is built in function given by GCC to perform
		 * atomic operation on memory*/

		__sync_fetch_and_add(&vnode_info->
			ve_pages[pgnum].ref_count, 1);
	} else {
		/*Decreament the ref count of page*/
		__sync_fetch_and_sub(&vnode_info->
			ve_pages[pgnum].ref_count, 1);
		/*if ref count page is zero then free that page*/
		if (0 == vnode_info->ve_pages[pgnum].ref_count)
			veos_free_page(ve_page_info);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"Page number ref count after atomic %s : %d\n",
			(atomic_op == 1) ? "increament" : "decreament",
			(int)vnode_info->ve_pages[pgnum].ref_count);


	/*Release lock from ve_node_struct*/
	if (pthread_mutex_unlock(&vnode_info->amm_node_lock) != 0) {
		errno = EINVAL;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"pthread_mutex_lock failed\n");
		goto func_return;
	}

func_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"Out func\n");
	return retval;
}


/**
* @brief : This function will increase the ref count of page.
*
* @param pgaddr[in] : array physical address of pages
*		whose ref count to be increase.
*
* @return : It return 0 on success and -1 on failure.
*/
int veos_get_page(uint64_t *pgaddr)
{
	int retval = 0;
	int addr_index = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"IN func\n");
	/* Here we extract physical address one by one from array of
	 * and send it to increase ref count. */
	while (pgaddr[addr_index]) {
		retval = common_get_put_page(pgaddr[addr_index], GET_PAGE);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"physical address %lx ref count not increamented.\n",
			pgaddr[addr_index]);
			goto func_return;
		}
		addr_index++;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"ref count of %d pages increament\n", addr_index);
func_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"IN func\n");
	return retval;
}


/**
* @brief : This function will ref count of page.
*
* @param pgaddr[in] : Physical address of page
*		whose ref count to be decrease.
*
* @return : It returns 0 on success and -1 on failure
*/
int veos_put_page(uint64_t pgaddr)

{
	return common_get_put_page(pgaddr, PUT_PAGE);
}

/**
* @brief This function initialize the page array within  mapping descriptor.
*
* @param[out] map_desc mapping descriptor page array of which has to be updated.
* @param[in] map_attri Pointer to struct mapping attributes.
*
* @return Return 0 on success and -1 on error.
*/
int init_page_array(struct mapping_desc *map_desc,
		struct mapping_attri *map_attri)
{
	struct list_head *list_tmp;
	struct list_head *list_start;
	struct list_head *list_end;

	struct mapping_desc *map_desc_t;

	int64_t cur_off_start = 0;
	int64_t cur_off_end = 0;
	int64_t offset_start = 0;
	int64_t offset_end = 0;
	uint64_t *cur_page_array;
	uint64_t *page_array;

	int64_t cur_index, count;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	page_array = map_desc->page_array;

	list_start = map_attri->merge_start;
	list_end = map_attri->merge_end;
	offset_start = map_attri->offset_start;
	offset_end = map_attri->offset_end;

	if ((!list_start) || (!list_end)) {
		for (cur_index = offset_start; cur_index <= offset_end;
				cur_index++)
			page_array[cur_index-offset_start] = 0;
		goto exit;
	}

	cur_index = 0;
	list_tmp = list_start;
	count = offset_end - offset_start;

	/*Traverse from merge start to merge end*/
	while (cur_index <= count) {
		map_desc_t = list_entry(list_tmp,
				struct mapping_desc, mapping_list);
		cur_off_start = map_desc_t->offset_start;
		cur_off_end = map_desc_t->offset_end;
		cur_page_array = map_desc_t->page_array;

		while ((offset_start+cur_index) <= cur_off_end) {
			if ((offset_start+cur_index) < cur_off_start)
				page_array[cur_index] = 0;
			else
				page_array[cur_index] =
					cur_page_array[cur_index -
					(cur_off_start-offset_start)];

			cur_index++;
		}

		if (list_tmp == list_end) {
			while (cur_index <= count) {
				page_array[cur_index] = 0;
				cur_index++;
			}
		}
		list_tmp = list_tmp->next;
	}

exit:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return 0;
}

/**
* @brief  This function remove the redundant mapping_descriptor
* instances left after merging.
*
* @param[in] list_start Pointer to list_head to start.
* @param[in] list_end Pointer to list_head to end
*
* @return Return pointer to the list_head to insert after on success.
*/
struct list_head *free_redundant_list(struct list_head *list_start,
		struct list_head *list_end)
{
	struct mapping_desc *mapping_desc_tmp;
	struct list_head *insert_after;
	struct list_head *insert_before;
	struct list_head *list_tmp;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	insert_after = list_start->prev;
	insert_before = list_end->next;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"list_start == %p\n", list_start);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "list_end == %p\n", list_end);

	for (list_tmp = list_start; list_tmp != insert_before;
			list_tmp = insert_after->next) {
		mapping_desc_tmp = list_entry(list_tmp,
				struct mapping_desc, mapping_list);

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"In free_redundant page_array is %p\n",
				mapping_desc_tmp->page_array);

		__list_del(list_tmp->prev, list_tmp->next);
		free(mapping_desc_tmp->page_array);
		free(mapping_desc_tmp);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return insert_after;
}

/**
* @brief This function sets the page_array entry to Null
* in case the page offset becomes zero.
*
* @param[out] map_desc Pointer to the mapping_desc repersps_entryng the
* particular mapping.
* @param[in] ve_page Pointer to the struct ve_page.
*
* @return Return 0 on success and -1 in case the ve_page not found in
* page_array
*/
int clear_page_array_entry(struct mapping_desc *map_desc,
		struct ve_page *ve_page)
{
	int64_t off_start;
	int64_t off_end;
	uint64_t *page_array;
	uint64_t i;

	/*Get mapping_desc_lock here*/
	pthread_mutex_lock(&map_desc->map_desc_lock);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	off_start = map_desc->offset_start;
	off_end = map_desc->offset_end;
	page_array = map_desc->page_array;

	for (i = 0; i <= off_end-off_start; i++) {
		if ((struct ve_page *)page_array[i] == ve_page) {
			page_array[i] = (uint64_t)NULL;
			goto done;
		}
	}
	/* ve_page entry not found in page_array
	 * Release mapping_desc_lock here*/
	pthread_mutex_unlock(&map_desc->map_desc_lock);
	return -1;
done:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	/*Release mapping_desc_lock here*/
	pthread_mutex_unlock(&map_desc->map_desc_lock);
	return 0;
}

/**
* @brief This function sets the entry bit of bitmap
*
* @param[out] *bitmap 256 bit bitmap.
* @param[in] entry bit number from the bitmap
*/
void set_bit(uint64_t *bitmap, uint64_t entry)
{
	uint64_t word, bit;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;
	bitmap[word] = bitmap[word] | ((uint64_t)1 << bit);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}


/**
* @brief This function sets the count bits in bitmap from entry index.
*
* @param[out] *bitmap 256 bit bitmap..
* @param[in] entry first bit to start setting.
* @param[in] count Number of bits to set.
*/
void set_bits(uint64_t *bitmap, uint64_t entry, uint16_t count)
{
	int64_t word, bit;
	int ent;

	word = entry / BITS_PER_WORD;
	bit = entry % BITS_PER_WORD;

	for (ent = 0; ent < count; ent++) {
		bitmap[word] = bitmap[word] | ((unsigned long)1 << bit++);
		if (bit >= BITS_PER_WORD) {
			word++;
			bit = 0;
		}
	}
}

/**
* @brief This function dumps the contents of the mapping
* descriptor for debuging purpose.
*
* @param[in] map_desc Pointer to struct mapping_descriptor.
*/
void dump_mapping_desc(struct mapping_desc *map_desc)
{
	int64_t offset_start;
	int64_t offset_end;
	uint64_t i;
	uint64_t *page_array;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	offset_start = map_desc->offset_start;
	offset_end = map_desc->offset_end;
	page_array = map_desc->page_array;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Dumping Offset_start: %ld\n", offset_start);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Dumping Offset_end: %ld\n", offset_end);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Dumping page_array: %p\n",
			(void *)page_array);
	for (i = 0; i <= offset_end-offset_start; i++) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Dumping page_array[%ld]: %p\n", i,
				(void *)page_array[i]);
		if (page_array[i])
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Reference_count: %ld\n",
					((struct ve_page *)page_array[i])->ref_count);
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
* @brief This function release the physical page.
*
* @param[in] page_num Page Number to be released
* @param[in] node_id node id on which the process is running.
* @paran[in] pgsize Size of the page
*
* @return Return 0 on success and -1 on error
*/
int release_page(uint64_t page_num, int node_id, uint64_t pgsize)
{
	int ret = -1;
	uint64_t ref;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	/*Get amm_node_lock here*/
	pthread_mutex_lock(&(vnode_info->amm_node_lock));
	ref = --(vnode_info->ve_pages[page_num].ref_count);

	if (ref == 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"doing clean up for page_num %lu\n",
				page_num);
		/*if(file_backed)*/
		if ((!((vnode_info->ve_pages[page_num].flag) & MAP_ANON)) &&
				(vnode_info->ve_pages[page_num].flag) & MAP_SHARED) {
			/* update page_array entry = NULL
			 * in map_descriptor as well*/
			ret = clear_page_array_entry(vnode_info->
					ve_pages[page_num].private_data,
					&vnode_info->ve_pages[page_num]);
			if (ret < 0)
				goto err;
			/*
			 * TODO: Split of mapping_descriptor should
			 * be implemented here
			 * */
		}

		/*
		 * vnode_info->ve_pages[page_num].flag = 0;
		 */
		vnode_info->ve_pages[page_num].perm = 0;
		vnode_info->ve_pages[page_num].private_data = NULL;

		/*Set page free here*/
		ret = set_page_free(page_num, node_id, pgsize);
		if (ret < 0)
			goto err;
	}

	/*Release amm_node_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_node_lock));
	return 0;
err:
	/*Release amm_node_lock here*/
	pthread_mutex_unlock(&(vnode_info->amm_node_lock));
	return ret;
}

/**
* @brief This function updates the mapping descriptor
* and page_array specifically.
*
* @param[out] page_array page_array to update.
* @param[in] count number of pages to update.
* @param[out] bitmap send data bitmap.
* @param[in] node_id node id of the node on which process is running.
*
* @return Return pointer to the map array which contain physical page number
* to map with virtual address at each index.
*/
uint64_t *update_mapping_desc(uint64_t *page_array, uint64_t count,
		uint64_t *bitmap, int node_id,
		uint64_t page_size)
{
	uint64_t *map;
	uint64_t cur_index;
	int ret;
	uint64_t page_number;
	uint64_t page_base;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	map = (uint64_t *)malloc((count+1) * (sizeof(uint64_t)));
	if (NULL == map) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Error in allocating hold page info\n");
		return (void *)-1;
	}
	memset(map, '\0', (count * (sizeof(uint64_t))));

	for (cur_index = 0; cur_index <= count; cur_index++) {
		if (0 == page_array[cur_index])	{
			/*We will allocate a new page here*/
			ret = alloc_ve_pages(1, map + cur_index,
					node_id, page_size);
			if (ret == -1) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"VE page allocation failed\n");
				free(map);
				return (void *)-1;
			}
			/**
			 * Init page_array element with pointer to
			 * struct ve_page
			 */
			page_array[cur_index] = (uint64_t)(&(vnode_info->
						ve_pages[map[cur_index]]));
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"when init page_array[%ld]: %p\n",
					cur_index, (void *)page_array[cur_index]);

			/* TODO: Set send_data bitmap*/
			/* This handling can be removed in future*/
			/* Note: set means send data should be done
			 * over it*/

			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"page_number when init: %lu\n",
					map[cur_index]);
			set_bit(bitmap, cur_index);
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"when access page_array[%ld]: %p\n",
					cur_index,
					(void *)page_array[cur_index]);
			/*find page_number from struct ve_page*/
			page_base = ((struct ve_page *)page_array[cur_index])->
				page_start;

			page_number = GET_PAGE_NUMBER(page_base);
			map[cur_index] = page_number;
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"page_number when access: %lu\n",
					map[cur_index]);
		}
	}

	return map;
}

/**
* @brief This function compare some constant elements of file stats.
*
* @param[in] file1 file1 to compare.
* @param[in] file2 file2 to compare.
*
* @return will return 0 on match and -1 on mismatch.
*/
int stat_cmp(struct stat *file1, struct stat *file2)
{
	int ret = -1;
	/* TBD: The fields we are going to compare here may change
	 * with disccussion
	 */
	if ((file1->st_dev == file2->st_dev) &&
			(file1->st_ino == file2->st_ino))
		ret = 0;

	return ret;
}

/**
* @brief This function collects the attibutes about new mapping,
* like where the new mapping will be added in list.
*
* @param[in] file_desc_t pointer to the file_map_descriptor.
* @param[in] offset_start start offset of mapping.
* @param[in] offset_end end offset of mapping.
*
* @return Will return the pointer to map_attributes structure on success
* and (void *)-1 on error.
*/
struct mapping_attri *collect_map_attri(struct file_map_desc *file_desc_t,
		int64_t offset_start, int64_t offset_end)
{
	struct list_head *temp_head;
	struct list_head *insert_after = NULL;
	struct list_head *merge_start = NULL;
	struct list_head *merge_end = NULL;
	struct mapping_attri *map_attri;
	struct mapping_desc *mapping_desc_tmp;
	struct mapping_desc *start_merge_desc;
	struct mapping_desc *end_merge_desc;
	int64_t cur_offset_start;
	int64_t cur_offset_end;
	int64_t new_offset_start;
	int64_t new_offset_end;

	/*
	 * Traverse through the existing mapping list.
	 * Here we will compare the offest start and end of the new mapping
	 * with offset start and end of existing mappings in the list and
	 * will decide which of the existing mappings will be merged with
	 * the new mapping.
	 */
	list_for_each(temp_head, &file_desc_t->mapping_list) {
		mapping_desc_tmp = list_entry(temp_head,
				struct mapping_desc, mapping_list);
		cur_offset_start = mapping_desc_tmp->offset_start;
		cur_offset_end = mapping_desc_tmp->offset_end;
		if (!merge_start) {
			if (offset_start <= cur_offset_end + 1) {
				merge_start = temp_head;
				if (offset_end <= cur_offset_end) {
					if (offset_end < cur_offset_start - 1) {
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
			if (offset_end <= cur_offset_end) {
				if (offset_end < cur_offset_start - 1)
					merge_end = temp_head->prev;
				else
					merge_end = temp_head;
				break;
			}
		}
	}

	if (merge_start && (!merge_end))
		merge_end = merge_start;

	/*We must have merge_start and merge_end by now*/
	if ((!merge_start) && (!merge_end)) {
		new_offset_start = offset_start;
		new_offset_end = offset_end;
	} else {
		start_merge_desc = list_entry(merge_start, struct mapping_desc,
				mapping_list);
		end_merge_desc = list_entry(merge_end, struct mapping_desc,
				mapping_list);
		cur_offset_start = start_merge_desc->offset_start;
		cur_offset_end = end_merge_desc->offset_end;

		new_offset_start = cur_offset_start < offset_start ?
			cur_offset_start : offset_start;
		new_offset_end = cur_offset_end > offset_end ?
			cur_offset_end : offset_end;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"merge_start %p\n", merge_start);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "merge_end %p\n", merge_end);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"New Offset_Start %ld\n", new_offset_start);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"New Offset_End %ld\n", new_offset_end);

	map_attri = malloc(sizeof(struct mapping_attri));
	if (map_attri == NULL) {
		perror("malloc");
		return (void *)-1;
	}
	memset(map_attri, '\0', sizeof(struct mapping_attri));

	map_attri->merge_start = merge_start;
	map_attri->merge_end = merge_end;
	map_attri->offset_start = new_offset_start;
	map_attri->offset_end = new_offset_end;
	map_attri->insert_after = insert_after;

	/* We Must have offset_start and offset end of the
	 * new descriptor till Now
	 */
	return map_attri;
}

/**
* @brief This function add the new mapping descriptor in existing
* mapping list.
*
* @param[in] file_desc file_map_desc with which the mapping is associated.
* @param[in] map_desc map_desc to add in list.
* @param[out] map_attri mapping attibutes.
*
* @return Return 0 on success and -1 on error.
*/
int add_mapping_desc(struct file_map_desc *file_desc,
		struct mapping_desc *map_desc,
		struct mapping_attri *map_attri)
{
	struct list_head *merge_start;
	struct list_head *merge_end;
	struct list_head *insert_after;

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

	return 0;
}

/**
* @brief This functions check that request bits are already used
* or not.
*
* @param[in] *bitmap Pseudo VEMVA list bitmap
* @param[in] entry Offset in the list
* @param[in] count Number of 2MB virtual address
*
* @return On Success, it returns 0 and -1 on failure.
*/
int check_bits_set(uint64_t *bitmap, uint64_t entry, uint64_t count)
{
	uint64_t word, bit;
	uint64_t ent;

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
* @param[in] vaddr VEMVA on which the file is mapped
* @param[in] bitmap bitmap for partial send data.
* @param[in] file_stat file statistics
* @param[in] p_ve_task ve_task_struct for current process.
* @param[in] size size of mapping.
* @paran[in] pgsize Size of the page
*
* @return return 0 on success and -1 on error.
*/
int send_file_data(uint64_t vaddr, uint64_t *bitmap,
		struct stat file_stat, int64_t offset_start,
		struct ve_task_struct *p_ve_task, uint64_t size,
		 uint64_t page_size)
{
	uint64_t count;
	int node_id, index, ret;
	uint64_t ve_addr;
	uint64_t vh_addr;
	uint64_t file_size;
	uint64_t tmp_size;
	uint64_t sent_data = 0;
	pid_t ve_pid, pseudo_pid;

	node_id = p_ve_task->node_id;
	struct ve_node_struct *ve_node = VE_NODE(node_id);

	ve_pid = p_ve_task->pid;
	pseudo_pid = p_ve_task->pid;

	ve_addr = vaddr;
	vh_addr = vaddr;

	file_size = file_stat.st_size;

	/*
	 * File content are read and send to VE memory
	 */
	pthread_mutex_lock(&(ve_node->amm_node_lock));
	count = size/page_size;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "bitmap[0] = %lx\n",
					bitmap[0]);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "file_size = %ld\n",
					file_size);
	if (check_bits_set(bitmap, 0, count)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Performing partial amm_xfer_data\n");
		/*
		 * Check if all the bits are zero
		 * No need to do any transfer
		 *
		 * if (check_bits_zero(bitmap, 0, count))
		 *	return success;
		 * else
		 *	go ahead;
		 */

		/*This Loop can be modified for Optimisation purpose*/
		for (index = 0;; index++) {
			sent_data += page_size;
			if (sent_data > file_size) {
				tmp_size = file_size%page_size;
				if (tmp_size == 0) {
					break;
				} else if (tmp_size%8) {
					tmp_size = (tmp_size -
							(tmp_size%8)) + 8;
				}
			} else {
				tmp_size = page_size;
			}
			if (!check_bits_set(bitmap, index, 1)) {
				if (-1 == amm_dma_xfer(VE_DMA_VHVA,
							(uint64_t)vh_addr + (index*page_size),
							pseudo_pid, VE_DMA_VEMVA,
							ve_addr + (index*page_size), ve_pid,
							tmp_size, node_id)) {
					VE_LOG(CAT_OS_CORE,
							LOG4C_PRIORITY_ERROR,
							"amm_dma_xfer failed\n");
					errno = EFAULT;
					ret = -1;
					goto err;
				}
			}
			if ((tmp_size < page_size) || (sent_data >=
						(size + (offset_start*page_size))))
				break;
		}
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Performing complete amm_xfer_data\n");
		sent_data = offset_start*page_size;
		if ((sent_data + size) > file_size) {
			tmp_size = file_size-sent_data;
			if (tmp_size%8) {
				tmp_size = (tmp_size -
						(tmp_size%8)) + 8;
			}
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"file_size = %ld , offset_start %ld, "
					"page_size %lx, size %lx, "
					"expected tmp_size %ld\n",
					file_size, offset_start, page_size,
					size, tmp_size);
		} else {
			tmp_size = size;
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"tmp_size %ld\n", tmp_size);
		}

		if (-1 == amm_dma_xfer(VE_DMA_VHVA,
					(uint64_t)vh_addr, pseudo_pid,
					VE_DMA_VEMVA, ve_addr, ve_pid, tmp_size,
					node_id)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"VE mapped area update failed in %s\n",
					__func__);
			errno = EFAULT;
			ret = -1;
			goto err;
		}
	}
	/*Release Lock Here*/
	pthread_mutex_unlock(&(ve_node->amm_node_lock));

	return 0;
err:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Returning Failure\n");
	pthread_mutex_unlock(&(ve_node->amm_node_lock));
	return ret;
}

/**
 * @brief : This function returns the page size corresponding to the
 * VEMVA.
 * @param[in] vaddr VEMVA of VE process/thread.
 * @param[in] atb ATB corresponding to VE process/thread.
 *
 * @return : returns page size on success and -1 on error.
 */
int get_page_size(uint64_t vaddr, atb_reg_t *atb)
{
	int ps_entry;
	int atb_num;
	int psnum;		/* partial space # generated from vaddr */
	int psnum_h;		/* partial space # generated from vaddr */
	int psnum_dir;		/* partial space # generated from dir[] entry */
	int pgmode_dir;		/* Page size flag from dir[] entry */
	atb_dir_t *atbp;

	if (atb == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "atb are NULL.\n");
		return -1;
	}

	atb_num = ATB_DIR_NUM;
	atbp = atb->dir;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"vaddr: %p, atb: %p, atb_num=%d atbp=%p\n",
			(void *)vaddr, (void *)atb, atb_num, (void *)atbp);

	psnum = psnum(vaddr);
	psnum_h = psnum_h(vaddr);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			" vaddr = %p psnum = 0x%x psnum_h 0x%x\n",
			(void *)vaddr, psnum, psnum_h);
	for (ps_entry = 0; ps_entry < atb_num; ps_entry++) {
		/* Is atbp valid? */
		if (ps_isvalid(atbp)) {
			/* pgmode check */
			pgmode_dir = ps_getpgsz(atbp);
			/* psnum check */
			psnum_dir = ps_getps(atbp, pgmode_dir);
			if ((psnum_dir == psnum) ||
					(psnum_dir == psnum_h))
				return pgmode_dir;
		}
		atbp++;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Invalid address.\n");
	return -1;
}
/**
 * @brief  This function calculates the total physical memory in kb
 * taken by the VE process.
 *
 * @param[in] mm Pointer to struct ve_mm_struct of VE process.
 *
 * @return: Always Success it return process physical memory size.
 */
uint64_t amm_get_rss_in_kb(struct ve_mm_struct *mm)
{
	uint64_t max_rss = 0;
	int type;
	atb_reg_t *atb = &(mm->atb);
	int entry_cntr = -1, dir_cntr = -1;

	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			type = ps_getpgsz(&(atb->dir[dir_cntr]));
			for (entry_cntr = 0; entry_cntr < ATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(atb->
								entry[dir_cntr][entry_cntr]))) {
					if (type == PG_2M)
						max_rss += PAGE_SIZE_2MB;
					else if (type == PG_HP)
						max_rss += PAGE_SIZE_64MB;
				}
			} /* end entry loop */
		} /* end*/
		else
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"DIR: %d is invalid.\n", dir_cntr);
	} /* end dir loop */

	/* converting in kb */
	max_rss = max_rss/1024;
	return max_rss;
}
/**
* @brief This is generic mremap handler which allocates
* VE PHY memory and maintains ATB.
*
* @param[in] vaddr_old This is VEMVA for which VE PHY pages needs
* to be remapped
* @param[in] size_old: Size of PHY memory needs to be remapped
* @param[in] size_new: Size of PHY memory needs to be remapped
* @param[in] vaddr_new: This is VEMVA to which VE PHY pages needs
* to be remapped
* @param[in] p_ve_task: Pointer of ve_task_struct of the VE process
*
* @return return 0 on success and negative value on failure
*/

int amm_do_mremap(uint64_t vaddr_old, size_t size_old, size_t size_new,
		uint64_t vaddr_new, struct ve_task_struct *p_ve_task)
{
	uint64_t count = 0;
	uint64_t start = 0;
	uint64_t ps_entry;
	int ret = 0;
	int node_id;
	int rw_prot = 0;
	uint64_t *map = NULL;
	atb_reg_t tmp_atb;
	uint64_t vaddr = 0;
	uint64_t taddr = 0;
	uint64_t aaddr = 0;
	int64_t offset_start = 0;
	int64_t offset_end = 0;

	struct ve_mm_struct *mm_struct = p_ve_task->p_ve_mm;
	struct ve_node_struct *vnode_info;

	struct file_map_desc *file_desc_tmp = NULL;
	struct mapping_desc *map_desc;
	struct shm *shm_seg = NULL;
	struct ve_page *ve_page;

	uint64_t count_old;
	uint64_t count_new, page_size;
	int i, pgmode_dir;

	/*TODO: size of bitmap should be dynamic as per the request*/
	uint64_t bitmap[4];
	memset(bitmap, '\0', sizeof(bitmap));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));
	/* Retrive the page size of the VE memory to be released */
	pgmode_dir = get_page_size(vaddr_old, &tmp_atb);
	if (-1 == pgmode_dir) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Page size not found\n");
		return -1;
	} else if (PG_2M == pgmode_dir) {
		page_size = PAGE_SIZE_2MB;
	} else
		page_size = PAGE_SIZE_64MB;
	/*
	 * size always 2MB aligned
	 */
	count_old = (size_old / (page_size));
	count_new = (size_new / (page_size));

	if (count_old > count_new) {
		/*
		 * As we are handling shrinking on pseudo side it self
		 * control should not reach here
		 */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Something went wrong\n"
				"veos will not handle shrinking here\n");
		return -1;
	}

	uint64_t pgnum[count_new];
	memset(pgnum, '\0', sizeof(pgnum));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"MREMAP arguments -: vemva_old: %lx size_old: %lu,"
			"size_new: %lu , vaddr_new: %lx\n",
			vaddr_old, size_old, size_new, vaddr_new);

	node_id = p_ve_task->node_id;
	vnode_info = VE_NODE(node_id);

	aaddr = amm_addr_translation((void *)vaddr_old, &tmp_atb);
	if (-1 == aaddr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Addr translation failed for vemva: %lx",
				vaddr_old);
		ret = -1;
		goto mremap_error;
	}

	pgnum[0] = GET_PAGE_NUMBER(aaddr);
	/*Get mm_struct_lock here*/
	pthread_mutex_lock(&(mm_struct->mm_lock));
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));
	ve_page = (&(vnode_info->ve_pages[pgnum[0]]));

	if (ve_page->private_data) {
		if (ve_page->flag & PG_SHM) {
			shm_seg = (struct shm *)(ve_page->private_data);
			file_desc_tmp = NULL;
		} else if (!(ve_page->flag & MAP_ANON)) {
			file_desc_tmp = ((struct mapping_desc *)(ve_page->
						private_data))->file_desc;
			shm_seg = NULL;
		}
	}

	if (file_desc_tmp) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"VEMVA: %p is file_backed\n",
				(void *)vaddr_old);
		/*Get mapping desc lock here*/
		map_desc = (struct mapping_desc *)(ve_page->private_data);
		pthread_mutex_lock(&map_desc->map_desc_lock);
		offset_start = extract_file_pgoff(map_desc, ve_page);
		pthread_mutex_unlock(&map_desc->map_desc_lock);
		offset_end = offset_start + count_new - 1;
		if (vaddr_old == vaddr_new)
			offset_start = offset_start + count_old;
		/*
		 * This has to be done if mapping referred by vaddr file_backed
		 */
		map = amm_do_file_back_handling(file_desc_tmp, offset_start,
				offset_end, bitmap, node_id, page_size);
		if ((void *)-1 == map) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"amm_do_file_back_handling failed\n");
			return -1;
		}
	} else if (shm_seg) {
		pthread_mutex_lock(&shm_seg->shm_lock);
		map = segment_expandable(shm_seg, pgnum[0], count_new);
		pthread_mutex_unlock(&shm_seg->shm_lock);
		if ((void *)-1 == map) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"expanding shared memory"
					"segment failed\n");
			/*TBD: This scenario have to be discussed: BUS_ERROR*/
			return -1;
		}
		if (vaddr_old == vaddr_new)
			map = map + count_old;
	} else {
		/*This case is for flag = MAP_SHARED, fd = -1*/
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"VEMVA: %p not file_backed"
				"or shared memory mapped\n", (void *)vaddr_old);
		/*virtual to physical translation*/
		for (i = 0; i < count_old; i++) {
			aaddr = amm_addr_translation((void *)vaddr_old+
					(i*PAGE_SIZE_2MB), &tmp_atb);
			if (-1 == aaddr) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Addr translation failed"
						" for vemva: %lx",
						vaddr_old);
				ret = -1;
				goto mremap_error;
			}
			pgnum[i] = GET_PAGE_NUMBER(aaddr);
		}

		/*
		 * If we do maintain data structures for MAP_SHARED fd = -1
		 * mappings, we will extract the pages from data structure
		 * otherwise we will allocate new pages
		 */
		ret = alloc_ve_pages(count_new - count_old,
				pgnum + count_old, node_id, page_size);
		if (ret == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"VE page allocation failed\n");
			return ret;
		}
		map = pgnum;
	}

	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));

	/*
	 * Check if mapping has to be moved or simply expanded
	 */
	if (vaddr_old == vaddr_new) {
		/*
		 * mapping will not move simply expand
		 */
		if (size_old == size_new)
			/*Nothing to do here*/
			return 0;
		vaddr = vaddr_old + size_old;
		count = count_new - count_old;
	} else {
		vaddr = vaddr_new;
		count = count_new;
		/*
		 * munmap existing mapping if mapping has to be moved
		 */
		ret = amm_do_munmap(vaddr_old, size_old, p_ve_task);
		if (ret == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to do munmap\n");
			ret = -1;
			goto mremap_error;
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"amm_do_munmap Success\n");
		}
	}

	/*
	 * TODO: read/write permission has to be same as privious
	 * mapping (vaddr_old + size_old)
	 */
	rw_prot = 1;

	pthread_mutex_lock(&(mm_struct->mm_lock));
	/*Fetch Updated ATB*/
	memcpy(&tmp_atb, &(mm_struct->atb), sizeof(atb_reg_t));

	/*
	 * Below loops are only for assigning virtual address to
	 * VE PHY pages and certain calculations to fill ATB
	 */
	for (start = 0; start < count; start++) {
		taddr = vaddr + (start * page_size);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"remapping vemva: %lx to page: %ld\n",
				taddr, map[start]);
		ret = amm_set_atb(taddr, rw_prot,
				map[start], &tmp_atb, page_size);
		if (ret < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Not able to set ATB of vemva:%lx\n",
					taddr);
			ret = -1;
			goto mremap_error;
		}
		/*
		 * Here we will update flag and perm field of struct ve_page of
		 * newly allocated pages same as old pages.
		 */
		pthread_mutex_lock(&(vnode_info->amm_node_lock));
		vnode_info->ve_pages[map[start]].ref_count++;
		pthread_mutex_unlock(&(vnode_info->amm_node_lock));

		/*update shared memory nattach also*/
		if (shm_seg) {
			pthread_mutex_lock(&shm_seg->shm_lock);
			shm_seg->nattch += 1;
			pthread_mutex_unlock(&shm_seg->shm_lock);
		}
	}

	memcpy(&(mm_struct->atb), &tmp_atb, sizeof(atb_reg_t));
	/*Release mm_struct_lock here*/
	pthread_mutex_unlock(&(mm_struct->mm_lock));

	if (!((ve_page->flag & MAP_ANON) && (ve_page->flag & MAP_PRIVATE))) {
		ret = send_file_data(vaddr, bitmap, file_desc_tmp->file_stat,
				offset_start, p_ve_task, count*page_size,
				page_size);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"send_file_data failed\n");
			goto mremap_error;
		}
	}

	return ret;

mremap_error:
	/**
	 * TODO:
	 * Proper cleanup if any issue comes in between MMAP handling then
	 * clear ATB's updated before that and need to be tracked properly.
	 */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "In LABEL MMAP ERROR\n");
	for (ps_entry = 0; ps_entry < count; ps_entry++) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Freeing pageno:%lu\n",	*(map + ps_entry));
		set_page_free(*(map + ps_entry), node_id, page_size);
	}
	pthread_mutex_unlock(&(mm_struct->mm_lock));

	return -1;
}
/**
* @brief This function Extarct file page offset from mapping
* descriptor. by comparing with input struct ve_page.
*
* @param[in] map_desc Reference to the mapping descriptor.
* @param[in] ve_page Reference to struct ve_page.
*
* @return Return file page offset on success, and -1 on error.
*/
int64_t extract_file_pgoff(struct mapping_desc *map_desc,
		struct ve_page *ve_page)
{
	uint64_t index;
	uint64_t *pgnum = map_desc->page_array;
	int64_t offset_start = map_desc->offset_start;
	int64_t offset_end = map_desc->offset_end;

	for (index = 0; index < (offset_end-offset_start); index++) {
		if ((struct ve_page *)pgnum[index] == ve_page)
			return (int64_t)(offset_start+index);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Invalid mapping_desc or ve_page\n");
	return -1;
}
/**
* @brief This function checks if the shared memory segment
* referred by shm_seg is expandable or not.
*
* @param[in] shm_seg Reference to the shared memory segment to check.
* @param[in] pgnum Page of segment from which mapping has to be extended.
* @param[in] count Count of the pages to extend.
*
* @return Return pointer to map on success and (void *)-1 on error.
*/
uint64_t *segment_expandable(struct shm *shm_seg, uint64_t pgnum,
		uint64_t count)
{
	uint64_t index;
	uint64_t seg_count = shm_seg->size/PAGE_SIZE_2MB;
	uint64_t *vemaa = shm_seg->vemaa;

	for (index = 0; index < seg_count; index++) {
		if (vemaa[index] == pgnum) {
			if ((index + count) < seg_count) {
				vemaa = vemaa + index;
				return vemaa;
			} else {
				return (void *)-1;
			}
		}
	}
	return (void *)-1;
}
