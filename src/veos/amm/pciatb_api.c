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
 * @file  pciatb_api.c
 * @brief PCIATB realated function which manage PCIATB.
 *
 * @internal
 * @author AMM
 */
#include "ve_memory.h"
#include "ve_mem.h"
#include "veos.h"
#include "pciatb_api.h"
#include "velayout.h"
#include <sys/mman.h>
#include "buddy.h"
#include "mm_type.h"

/**
* @brief This function will dump all PCIATB.
*
* @return return 0 on success and negative of errno on failure.
*/
int pciatb_dump(void)
{
	struct ve_node_struct *vnode_info = VE_NODE(0);
	pciatb_entry_t *pci_entry = NULL;
	int ret = 0;

	VEOS_TRACE("invoked to dump PCIATB");

	pci_entry = (pciatb_entry_t *)calloc(PCIATB_VLD_SIZE,
			(sizeof(pciatb_entry_t)));
	if (NULL == pci_entry) {
		ret = -ENOMEM;
		VEOS_CRIT("error (%s) in allocating pci entry obj",
			strerror(-ret));
		return ret;
	}

	ret = vedl_get_pciatb_all(vnode_info->handle,
		vnode_info->cnt_regs_addr, pci_entry);
	if (ret < 0) {
		free(pci_entry);
		veos_abort("unable to read pciatb hardware reg values");
	}

	for (int pci_ent = 0; pci_ent < PCIATB_VLD_SIZE; pci_ent++)
		VEOS_DEBUG("PCIATB[%d] : 0x%lx", pci_ent, pci_entry[pci_ent].data);

	free(pci_entry);
	VEOS_TRACE("returned(%d)", ret);
	return  ret;
}

/**
* @brief This function will control the attributes of PCIATB.
*
* @param[in] attr This function will control the attributes of PCIATB.
*
* @param[in] val Value of attribute i.e. 0, 1 etc.
*
* @return On success returns 0 and negative of errno on failure.
*/
void veos_set_pciatb_attr(uint64_t attr, uint64_t val)
{
	pci_attr_t p_attr = {0};
	int64_t ret = 0;
	off_t offset = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	vedl_handle *handle = VE_HANDLE(0);

	VEOS_TRACE("invoked to set pciatb attribute");

	offset = offsetof(system_common_reg_t, PCIATBA);

	memset(&p_attr, 0, sizeof(pci_attr_t));

	/*GET pgmod in PCIATBA registor*/
	ret = vedl_get_cnt_reg_word(handle, vnode_info->cnt_regs_addr,
		offset, (reg_t *)&p_attr);
	if (ret < 0)
		veos_abort("unable to read pciatb attr hardware reg");

	/*If attribute is size*/
	if (attr == PCIATTR_SIZE) {
		p_attr.data = val;
		VEOS_DEBUG("PCIATB attribute set to :%ld",
		p_attr.data);
	}

	/*SET pgmod in PCIATBA registor*/
	ret = vedl_set_cnt_reg_word(handle, vnode_info->cnt_regs_addr,
		 offset, p_attr.data);
	if (ret < 0)
		veos_abort("unable to update pciatb attr hardware reg");

	/*Get pciattr register and store it in node struct*/
	ret =  vedl_get_cnt_reg_word(handle, vnode_info->cnt_regs_addr,
			offset, (reg_t *)&p_attr);
	if (ret < 0)
		veos_abort("unable to read pciatb attr hardware reg");

	vnode_info->pciattr = p_attr.data;

	VEOS_DEBUG("PCI PAGE MODE SET TO :%s",
			(vnode_info->pciattr == 0) ?
				"2MB PGMODE" : "64MB PGMODE");

	VEOS_TRACE("returned(%ld)", ret);
}

/**
* @brief This function will initialize the all PCIATB related data.
*
* @param vnode_info node info.
*
* @return return 0 on success and negative of errno on failure.
*/
int amm_init_pciatb(struct ve_node_struct *vnode_info)
{
	int ret = 0;
	size_t bar0_size = 0;
	uint64_t base_addr = 0;
	struct buddy_mempool *pci_mempool = NULL;
	uint64_t entry_cnt = 0;
	int pgmod, reg_cnt = 0;
	pciatb_entry_t pci_entry = {0};

	vedl_handle *handle = VE_HANDLE(0);

	VEOS_TRACE("invoked");
	/*Get BAR0 size*/
	ret = vedl_get_pci_bar0_size(handle, &bar0_size);
	if (ret < 0)
		veos_abort("unable to read pciatb bar0 size");

	vnode_info->pci_bar01_sz = bar0_size;

	VEOS_DEBUG("PCI BAR0 size is %lx",
				vnode_info->pci_bar01_sz);

	if (bar0_size < PCIBAR_128MB) {
		VEOS_DEBUG("BAR01 size %lx is small", bar0_size);
		return -EINVAL;
	} else if (bar0_size == PCIBAR_128MB) {
		vnode_info->pci_bar01_pgsz = PAGE_2MB;
		pgmod = PGMOD_2MB;
	} else {
		pgmod = PGMOD_64MB;
		vnode_info->pci_bar01_pgsz = PAGE_64MB;
	}

	/*INIT pci  buddy mempool, here we are
	 * assuming PCI base address as ZERO*/
	pci_mempool = veos_buddy_init(base_addr, vnode_info->pci_bar01_sz,
			vnode_info->pci_bar01_pgsz);
	if (NULL == pci_mempool) {
		ret = -ENOMEM;
		VEOS_DEBUG("Error (%s) while initializing PCI memory pool",
			strerror(-ret));
		return ret;
	}
	vnode_info->pci_mempool = pci_mempool;
	ret = pthread_mutex_init(&vnode_info->pci_mempool->buddy_mempool_lock, NULL);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) while initializing PCI memory pool",
				strerror(-ret));
		return ret;
	}

	VEOS_DEBUG("PCI MEMPOOL STAT: => pool_order : %ld min_order : %ld",
		pci_mempool->pool_order, pci_mempool->min_order);


	veos_set_pciatb_attr(PCIATTR_SIZE, (pgmod == PGMOD_2MB) ?
				(uint64_t)0 : (uint64_t)1);

	pci_entry.data = INVALID_ENTRY;
	/*Mark all pciatb entries as invalid
	 *in s/w as well as h/w */
	for (entry_cnt = 0; entry_cnt <
			PCIATB_VLD_SIZE; entry_cnt++) {
		vnode_info->pciatb[entry_cnt].data = pci_entry.data;
		ret = vedl_update_pciatb_entry(handle,
			vnode_info->cnt_regs_addr, &pci_entry, entry_cnt);
		if (ret < 0)
			veos_abort("unable to update pciatb hardware entries");
	}

	/* SET PCISYARX with val 0*/
	for (reg_cnt = 0; reg_cnt < PCISYAR_MAX; reg_cnt++) {
		ret = veos_amm_set_pcisyar(reg_cnt, 0);
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) to set PCISYAR%d",
				strerror(-ret), reg_cnt);
			goto init_failed;
		} else {
			VEOS_DEBUG("Initialized PCISYAR%d to zero", reg_cnt);
		}
	}

	/* SET PCISYMRX with val 0*/
	for (reg_cnt = 0; reg_cnt < PCISYMR_MAX; reg_cnt++) {
		ret = veos_amm_set_pcisymr(reg_cnt, 0);
		if (ret < 0) {
			VEOS_DEBUG("Error (%s) to set PCISYMR(%d)",
				strerror(-ret), reg_cnt);
			goto init_failed;
		} else {
			VEOS_DEBUG("Initialized PCISYMR%d to zero", reg_cnt);
		}
	}

	/*Dump  all entries*/
	ret = pciatb_dump();
	if (ret < 0) {
		VEOS_DEBUG("Error(%s) int pciatb dump",	strerror(-ret));
		goto init_failed;
	}

	VEOS_DEBUG("returned(%d)", ret);
	return ret;

init_failed:
	VEOS_DEBUG("returned(%d)", ret);
	return ret;
}

/**
 * @brief This function used to set address translation into PCIATB registers
 *	of the VE node to access VE memory space from VH memory space.
 * @param[in] reg PCIATB register software image.
 * @param[in] entry_no start entry number.
 * @param[in] count Number of entry to be set.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
void veos_set_pciatb(pciatb_entry_t *reg, int entry_no, int count)
{
	int idx = 0, ret = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	vedl_handle *handle = VE_HANDLE(0);

	VEOS_TRACE("invoked to set pciatb with entry no(%d)  count(%d)",
		entry_no, count);

	/* here we will set pciatb_entries
	 * from entry_no to (entry_no + count)*/
	for (idx = entry_no; idx < (entry_no + count); idx++) {
		VEOS_TRACE("Updating PCIATB entry :%d", idx);
		ret = vedl_update_pciatb_entry(handle,
			vnode_info->cnt_regs_addr, &reg[idx], idx);
		if (ret < 0)
			veos_abort("unable to update pciatb hardware entries");
	}
	VEOS_TRACE("returned");
}
/**
 * @brief This function reads page descriptor from the data structure of PCIATB
 *	and then obtains page base address VEMAA and compares it with the page
 *	base address of received VEMAA as an argument.
 *
 * @param[in] addr_vemaa Absolute memory address of VE (VEMAA).
 * @param[in] pid VE process Identification.
 *
 * @return On success returns VHSAA and negative of errno on failure.
 */
int64_t veos_get_vhsaa_pciatb(vemaa_t vemaa, pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	uint64_t pg_mode = -1;
	pgno_t page_no = -1;
	uint64_t entry_num = -1, vhsaa = -1, idx = 0;
	uint64_t entry_max = -1, page_base = -1;
	bool found = false;

	VEOS_TRACE("invoked with vemva (0x%lx) pid (%d)", vemaa, pid);
	if (vemaa <= 0) {
		VEOS_DEBUG("Invalid argument(vemaa :0%lx)",
			vemaa);
		return -EINVAL;
	}

	/* Find the task struct. If task struct found it means process
	 * is valid else process with given pid is not available.*/
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("task struct not found for pid(%d)", pid);
		return -ESRCH;
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");

	/*Get Total valid entry count*/
	entry_max = vnode_info->pci_mempool->total_pages;

	pg_mode = (uint64_t)((vnode_info->pci_bar01_pgsz == PAGE_2MB)
		? PGMOD_2MB : PGMOD_64MB);

	page_no = pfnum(vemaa, PGMOD_2MB);
	if ((page_no > vnode_info->mp->total_pages) ||
			(NULL == VE_PAGE(vnode_info, page_no))) {
		pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, UNLOCK,
				"Failed to release pci lock");
		put_ve_task_struct(tsk);
		VEOS_DEBUG("Invalid vemva(0x%lx)", vemaa);
		return -EINVAL;
	}

	for (idx = 0; idx < entry_max; idx++) {
		if (!(vnode_info->pciatb[idx].data == INVALID_ENTRY)) {
			page_base = GET_PCIATB_PB(&vnode_info->pciatb[idx]);
			VEOS_DEBUG("page base obtain 0x%lx", page_base);
			if (page_base == page_no) {
				VEOS_DEBUG("VEMAA (0x%lx) mapped PCIATB entry is :%ld",
				vemaa, idx);
				found = true;
				entry_num = idx;
				break;
			}
		}
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, UNLOCK,
			"Failed to release pci lock");
	if (!found) {
		VEOS_DEBUG("VEMAA :0x%lx is not mapped with PCIATB entry",
			vemaa);
		if (tsk)
			put_ve_task_struct(tsk);
		return -EINVAL;
	}

	if (pg_mode == PGMOD_2MB)
		vhsaa = entry_num << LARGE_PSHFT;
	else
		vhsaa = entry_num << HUGE_PSHFT;

	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_DEBUG("VHSAA is :0x%lx obtained from PCIATB", vhsaa);
	VEOS_TRACE("returned(0x%lx)", vhsaa);
	return vhsaa;
}

/**
* @brief This function will set pci entries.
* @param[in] start_entry Start entry number.
* @param[in] count Number entries to be set.
* @param[in] page_base array of page base to be set int entry.
*
* @return It will return entry count on success and negative of errno on failure.
*/
int alloc_pcientry(uint64_t start_entry,
		uint64_t count, uint64_t *page_base)
{
	int idx = 0, entry_cnt = 0;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	int ret = 0;

	VEOS_TRACE("invoked with start_entry(0x%lx) count(%ld) page_base(%p)",
			start_entry, count, page_base);

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");

	for (idx = start_entry; idx <
			(start_entry + count); idx++, entry_cnt++) {
		vnode_info->pciatb[idx].data =
			page_base[entry_cnt] & PCIATB_PAGE_BASE_MASK;
		VEOS_DEBUG("Setting PCIATB[%d] with PAGE_BASE (0x%lx)",
			idx, vnode_info->pciatb[idx].data);
		/*Increament ref count*/

		ret = common_get_put_page(page_base[entry_cnt],
				GET_PAGE, true);
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) to inc ref count",
				strerror(-ret));
			pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, UNLOCK,
					"Failed to release pci lock");
			return ret;
		}
	}

	/*Sync entry to the hardware*/
	veos_set_pciatb(vnode_info->pciatb, start_entry, entry_cnt);

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, UNLOCK,
			"Failed to release pci lock");
	VEOS_TRACE("returned(%d)", entry_cnt);
	return entry_cnt;
}
/**
* @brief This function will free the allocated PCI entries
*
* @param[in] start_entry start entry number among all allocated entries.
* @param[in] size size of entries.
*
* @return return 0 on success and negative of errno on failure.
*/
int veos_free_pcientry(uint64_t start_entry, uint64_t size)
{
	struct block *pci_block = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	int ret = 0;

	VEOS_TRACE("invoked with start_entry(%ld) size(0x%lx)",
		start_entry, size);

	pci_block = (struct block *)calloc(1, sizeof(struct block));
	if (NULL == pci_block) {
		ret = -ENOMEM;
		VEOS_CRIT("Error(%s) while allocating mem for pci_block",
		strerror(-ret));
		return ret;
	}

	if (vnode_info->pci_bar01_pgsz == PAGE_2MB)
		pci_block->start = (start_entry << LARGE_PSHFT);
	else
		pci_block->start = (start_entry << HUGE_PSHFT);

	pci_block->order = size_to_order(size);


	/*free pci entries*/
	buddy_free(vnode_info->pci_mempool, pci_block);

	VEOS_TRACE("returned(0)");
	return 0;
}

/**
* @brief This function will check whether allocation is possible or not.
*
* @param[in] pgmod_info pgmode info for ve memory.
* @param[in] same This flag will indicate
*	whether pgmod is uniform or different.
*
* @return return true if allocation is possible else false.
*/
int get_pci_req_type(uint64_t *pgmod_arr, bool *comm)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	size_t page_size = 0;

	VEOS_TRACE("invoked with pgmod arr(%p) comm(%s)",
		pgmod_arr, (*comm) ? "true" : "false");

	if (*comm) {
		page_size = (size_t)((pgmod_arr[0] == PGMOD_2MB) ?
					PAGE_2MB : PAGE_64MB);
		if (page_size < vnode->pci_bar01_pgsz) {
			VEOS_DEBUG("Process pgsz incomaptible with PCIATB pgsz");
			return PCI_ALLOC_ERROR;
		}
		VEOS_DEBUG("Process pgsz comaptible with PCIATB pgsz");
		if ((PAGE_64MB == vnode->pci_bar01_pgsz)
				&& (PAGE_64MB == vnode->pci_bar01_pgsz)) {
			VEOS_DEBUG("Process pgsz 0x%lx PCIATB pgsz: 0x%lx",
				page_size, vnode->pci_bar01_pgsz);
			VEOS_TRACE("returned(%d)", PCI_ALLOC_HUGE);
			return PCI_ALLOC_HUGE;
		} else if (page_size > vnode->pci_bar01_pgsz) {
			VEOS_DEBUG("Process pgsz 0x%lx PCIATB pgsz: 0x%lx",
				page_size, vnode->pci_bar01_pgsz);
			VEOS_TRACE("returned(%d)", PCI_ALLOC_PARTIAL);
			return PCI_ALLOC_PARTIAL;
		} else if ((page_size == vnode->pci_bar01_pgsz)
				&& (PAGE_2MB == vnode->pci_bar01_pgsz)) {
			VEOS_DEBUG("Process pgsz 0x%lx PCIATB pgsz: 0x%lx",
				page_size, vnode->pci_bar01_pgsz);
			VEOS_TRACE("returned(%d)", PCI_ALLOC_NORMAL);
			return PCI_ALLOC_NORMAL;
		}
	}

	if (vnode->pci_bar01_pgsz == PAGE_2MB) {
		VEOS_TRACE("returned(%d)", PCI_ALLOC_HYBRID);
		return PCI_ALLOC_HYBRID;
	}
	VEOS_TRACE("returned(%d)", PCI_ALLOC_ERROR);
	return PCI_ALLOC_ERROR;
}

/**
* @brief This interface will free unused pciatb entries from entry given by buddy.
*
* @param[in] start_entry First entry number from
*		where entries are allocated.
* @param[in] req_size Actual requested size by user.
* @param[in] alloc_size Size of entries allocated by buddy.
*
* @return return 0 on success and negative of errno on failure.
*/
int free_unused_entry(uint64_t start_entry,
		size_t req_size, size_t alloc_size)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t total_entry = 0, req_entry = 0, extra_entry = 0;
	uint64_t idx = 0;
	int ret = 0;

	VEOS_TRACE("invoked to free unused entry with "
		"start_entry(%ld) req_size(0x%lx) alloc_size(0x%lx)",
		start_entry, req_size, alloc_size);

	total_entry = alloc_size/vnode->pci_bar01_pgsz;
	req_entry = req_size/vnode->pci_bar01_pgsz;
	extra_entry = total_entry - req_entry;

	VEOS_DEBUG("PCIATB(%ld) extra entries", extra_entry);
	VEOS_DEBUG("PCIATB(%ld) req entries", req_entry);
	VEOS_DEBUG("PCIATB(%ld) total_entry entries", total_entry);

	pthread_mutex_lock_unlock(&vnode->pci_mempool->buddy_mempool_lock,
			LOCK, "Failed to acquire pci buddy lock");
	if (extra_entry) {
		for (idx = (start_entry + req_entry);
				idx < (start_entry + total_entry); idx++) {
			ret = veos_free_pcientry(idx, vnode->pci_bar01_pgsz);
			if (ret < 0) {
				VEOS_DEBUG("Error(%s) in freeing pciatb entry(%ld)",
					strerror(-ret), idx);
				pthread_mutex_lock_unlock(&vnode->pci_mempool->buddy_mempool_lock,
						UNLOCK, "Failed to release pci buddy lock");
				return ret;
			}
		}
		VEOS_DEBUG("PCIATB(%ld)extra entries are freed", extra_entry);
	} else {
		VEOS_DEBUG("PCIATB : NO extra entries are allocated");
	}

	VEOS_DEBUG("============= ALLOC PCI DUMP ===========");
	buddy_dump_mempool(vnode->pci_mempool);
	pthread_mutex_lock_unlock(&vnode->pci_mempool->buddy_mempool_lock,
			UNLOCK, "Failed to release pci buddy lock");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}


/**
* @brief This function will delete pcientry allocated for vdso page.
*
* @param[in] entry_number pciatb entry number to be deleted which is allocated for vdso page..
*
* @return return 0 on success and negative of errno on failure.
*/
int veos_delete_vdso_pcientry(uint64_t entry_number)
{
	struct ve_node_struct *vnode = VE_NODE(0);

	return veos_delete_pciatb(entry_number, vnode->pci_bar01_pgsz);
}

/*
* @brief This function will allocate pcientry for quick call area.
*
* @param[in] pairnum PCISYAR0 and PCISYMR0 pair number.
* @param[in] sync sync bit to be set.
* @return return 0 on success and negative of errno on failure.
*/
int veos_alloc_vdso_pcientry(uint8_t pairnum, uint64_t sync)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	vedl_handle *handle = VE_HANDLE(0);
	uint64_t pcientry = -1, pci_addr = -1;
	pciatb_entry_t *p_entry = NULL;
	uint64_t vdso_pgno = (uint64_t)vnode->vdso_pfn;
	uint64_t vdso_addr = -1;
	int ret = 0;

	VEOS_TRACE("invoked to allocate pcientry "
		"for vdso with pairnum(%u) sync(%ld)",
		pairnum, sync);

	/*If PCIATB page size is 64MB then free prev*/
	if (vnode->pci_bar01_pgsz == PAGE_64MB) {
		VEOS_DEBUG("Allocating VDSO page 64MB");
		/*First Release vdso 2MB page*/
		pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
					LOCK,
					"Fail to acquire ve page lock");
		ret = veos_free_page(vdso_pgno);
		pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
					UNLOCK,
					"Fail to release ve page lock");
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) to free old vdso page :%ld",
			strerror(-ret), vdso_pgno);
			return ret;
		}
		/* Required if this fails then old VDSO page
		 * may be used by VE process
		 */
		vnode->vdso_pfn = -1;
		/*Now allocate 64MB page*/
		vdso_addr = (uint64_t)buddy_alloc(vnode->mp,
				size_to_order(PAGE_64MB));
		if ((void *)vdso_addr == BUDDY_FAILED) {
			ret = -ENOMEM;
			VEOS_ERROR("Error(%s) pciatb entry not available",
					strerror(-ret));
			return ret;
		}
		vdso_pgno = vdso_addr >> LARGE_PSHFT;
		ret = __page_entry(vnode->mp, vdso_pgno,
			PGMOD_64MB, size_to_order(PAGE_64MB));
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) can't make entry in page array",
				strerror(-ret));
			veos_delloc_memory(vdso_pgno, PGMOD_64MB);
			return ret;
		}
		/*Increament the ref count of vdso*/
		ret = common_get_put_page(vdso_addr, GET_PAGE, true);
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) in inc page(%ld) ref count",
				strerror(-ret), vdso_pgno);
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
						LOCK,
						"Fail to acquire ve page lock");
			veos_free_page(vdso_pgno);
			pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock,
						UNLOCK,
						"Fail to release ve page lock");
			return ret;
		}

		VEOS_DEBUG("new page(%ld) allocated for vdso", vdso_pgno);

		/*Save newly allocated page to vnode struct*/
		vnode->vdso_pfn = vdso_pgno;
		++vnode->mp->huge_page_used;
	}


	pci_addr = (uint64_t)buddy_alloc(vnode->pci_mempool,
			size_to_order(vnode->pci_bar01_pgsz));
	if ((void *)pci_addr == BUDDY_FAILED) {
		ret = -ENOMEM;
		VEOS_DEBUG("No free PCIATB entries available");
		goto ve_buddy_delloc;
	}

	if (vnode->pci_bar01_pgsz == PAGE_2MB)
		pcientry = pci_addr >> LARGE_PSHFT;
	else
		pcientry = pci_addr >> HUGE_PSHFT;

	VEOS_DEBUG("PCIENTRY(%ld) allocated for VDSO", pcientry);

	pthread_mutex_lock_unlock(&vnode->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	vnode->pciatb[pcientry].data =
		(vdso_pgno << LARGE_PSHFT) & PCIATB_PAGE_BASE_MASK;

	/*Increament the ref count of page*/
	ret = common_get_put_page((vdso_pgno << LARGE_PSHFT),
			GET_PAGE, true);
	if (ret < 0) {
		VEOS_DEBUG("Error(%s) in inc page(%ld) ref count",
				strerror(-ret), vdso_pgno);
		goto pci_buddy_delloc;
	}

	/* Setting PCISYAR0 and PCISYMR0
	 * and Enable synchronization.*/
	p_entry = &vnode->pciatb[pcientry];

	SET_SYNC(p_entry);
	SET_PCISY_PAIR(p_entry, pairnum);

	VEOS_DEBUG("For entry(%ld) pairnum(%u) sync(%ld) are set",
		pcientry, pairnum, sync);

	/*NOW update this entry to H/w */
	ret = vedl_update_pciatb_entry(handle, vnode->cnt_regs_addr,
			&vnode->pciatb[pcientry], pcientry);
	if (ret < 0)
		veos_abort("unable to update pciatb hardware entry");

	if (vnode->pci_bar01_pgsz == PAGE_64MB)
		++vnode->pci_mempool->huge_page_used;
	else
		++vnode->pci_mempool->small_page_used;

	/*Save vdso pcientry into ve_node struct*/
	vnode->vdso_pcientry = pcientry;

	pthread_mutex_lock_unlock(&vnode->pciatb_lock, UNLOCK,
			"Failed to release pci lock");

	VEOS_DEBUG("returned(%ld)", pcientry);
	return pcientry;

pci_buddy_delloc:
	pthread_mutex_lock_unlock(&vnode->pciatb_lock, UNLOCK,
			"Failed to release pci lock");
	if (vnode->pci_bar01_pgsz == PAGE_64MB)
		veos_delloc_memory(pcientry, PGMOD_64MB);
	else
		veos_delloc_memory(pcientry, PGMOD_2MB);
ve_buddy_delloc:
	if (vnode->pci_bar01_pgsz == PAGE_64MB)
		amm_put_page((vdso_pgno << LARGE_PSHFT));
	VEOS_DEBUG("returned(%d)", ret);
	return ret;
}
/**
* @brief This function will find the physical address for given vemva.
*
* @param[in] vaddr VEMVA address on which entry to be mapped.
* @param[in] page_cnt Number of entries required.
* @param[in] mm_struct refs to the memory struct.
* @param[in] size size of VEMVA address range.
* @param[in] req_type PCIATB allocation type.
* @param[out] page_base Out buffer to store physical address.
* @param[in] perm Access permission
* @param[in] access_ok Access ok flag indicate whether to check permission or not.
*
* @return return 0 on success and negative of errno on failure.
*/
int mk_pci_pgent(uint64_t vaddr, uint64_t page_cnt,
	struct ve_mm_struct *mm_struct, size_t size, int req_type,
	uint64_t *page_base, uint64_t perm, bool access_ok)
{
	uint64_t tmp_addr = -1;
	size_t tmp_size = 0;
	int prot = -1;
	int idx = 0;

	VEOS_TRACE("invoked to set pciatb entry");
	/* Translating virt address to
	 * physical and simultaneouly
	 * checking access permission */
	pthread_mutex_lock_unlock(&mm_struct->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");
	tmp_addr = vaddr;
	while (tmp_size < size) {
		page_base[idx] = __veos_virt_to_phy(tmp_addr,
			&mm_struct->atb, (access_ok) ? &prot : NULL, NULL);
			if (-1 == page_base[idx]) {
				VEOS_DEBUG("Error in physical address translation");
				pthread_mutex_lock_unlock(&mm_struct->thread_group_mm_lock,
						UNLOCK, "Failed to release thread-group-mm-lock");
				return -EFAULT;
			}
			VEOS_DEBUG("vemva(0x%lx) <-----> vemaa(0x%lx) =  entry(%d)",
				tmp_addr, page_base[idx], idx);
		/*check protection whether it is matching or not*/
		if (access_ok) {
			if (perm == (PROT_READ | PROT_WRITE))
				perm = PROT_WRITE;
			if (prot != perm) {
				VEOS_DEBUG("Access permission doesn't match");
				pthread_mutex_lock_unlock(&mm_struct->thread_group_mm_lock,
						UNLOCK, "Failed to release thread-group-mm-lock");
				return -EPERM;
			}
		}
		switch (req_type) {
		case PCI_ALLOC_NORMAL:
		case PCI_ALLOC_PARTIAL:
		case PCI_ALLOC_HYBRID:
			tmp_addr = tmp_addr + PAGE_2MB;
			tmp_size = tmp_size + PAGE_2MB;
			break;
		case PCI_ALLOC_HUGE:
			tmp_addr = tmp_addr + PAGE_64MB;
			tmp_size = tmp_size + PAGE_64MB;
			break;
		}
		idx++;
		prot = -1;
	}
	pthread_mutex_lock_unlock(&mm_struct->thread_group_mm_lock,
			UNLOCK, "Failed to release thread-group-mm-lock");
	VEOS_TRACE("returned(0)");
	return 0;
}

/**
* @brief This function will check whether entries are contigous or not.
*
* @param[in] pci_mp pciatb buddy allocator mempool.
* @param[in] size required size.
* @param[in] pci_entry start entry of pciatb.
*
* @return It will return true on success else false.
*/
bool is_contiguos(struct buddy_mempool *pci_mp,
		size_t size, uint64_t *pci_entry)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	struct block *curr_blk = NULL, *tmp_blk = NULL;
	bool pci_map[PCIATB_VLD_SIZE] = {0};
	uint64_t idx = 0, contiguous = 0, count = 0;
	uint64_t tmp_addr = -1, entry_start = -1;
	size_t tmp_size = 0;

	VEOS_TRACE("invoked to check contiguity");

	memset(pci_map, false, (sizeof(bool) * PCIATB_VLD_SIZE));

	count = size/vnode->pci_bar01_pgsz;

	/*make entries for each allocation*/
	list_for_each_entry_safe(curr_blk,
			tmp_blk, pci_mp->alloc_req_list, link) {
		tmp_addr = curr_blk->start;
		while (tmp_size < ((uint64_t)1 << curr_blk->order)) {
			if (vnode->pci_bar01_pgsz == PAGE_2MB)
				idx = tmp_addr >> LARGE_PSHFT;
			else
				idx = tmp_addr >> HUGE_PSHFT;
			pci_map[idx] = true;
			tmp_addr = tmp_addr + vnode->pci_bar01_pgsz;
			tmp_size = tmp_size + vnode->pci_bar01_pgsz;
		}
		tmp_addr = -1;
		tmp_size = 0;
		/*clear all allocated block*/
	}
	/*Cheking whether all entries are contiguous or not*/
	for (idx = 0; idx < PCIATB_VLD_SIZE; idx++) {
		if (pci_map[idx] == true) {
			contiguous++;

			/*save the start entry*/
			if (1 == contiguous)
				entry_start = idx;

			if (contiguous == count) {
				*pci_entry = entry_start;
				/*Delete all block from alloc_req_list*/
				list_for_each_entry_safe(curr_blk,
					tmp_blk, pci_mp->alloc_req_list, link) {
					list_del(&curr_blk->link);
				}
				INIT_LIST_HEAD(vnode->pci_mempool->alloc_req_list);
				VEOS_TRACE("returned (true)");
				return true;
			}
		} else {
			contiguous = 0;
		}
	}

	/* If entries are not contigous then
	 * return all entries to buddy allocator*/
	list_for_each_entry_safe(curr_blk,
			tmp_blk, pci_mp->alloc_req_list, link) {
		if (vnode->pci_bar01_pgsz == PAGE_2MB)
			idx = curr_blk->start >> LARGE_PSHFT;
		else
			idx = curr_blk->start >> HUGE_PSHFT;

		tmp_size = (uint64_t)1 << curr_blk->order;
		if (0 > veos_free_pcientry(idx, tmp_size)) {
			VEOS_DEBUG("PCI Entries are not marked as free");
			veos_abort("PCI buddy mempool inconsistent");
		}
		list_del(&curr_blk->link);
		idx = -1;
		tmp_size = 0;
	}
	INIT_LIST_HEAD(vnode->pci_mempool->alloc_req_list);

	VEOS_DEBUG("returned(false)");
	return false;
}

/**
 * @brief This function used to set address translation into PCIATB registers of
 *	 the VE node to access VE memory space from VH memory space.
 *
 * @param[in] pid PID of VE process VEMAA will be updated in PCIATB.
 * @param[in] vaddr VE process virtual address (VEMVA)
 * @param[in] size Size of virtual memory.
 * @param[in] perm Requestor permissions.
 * @param[in] access_ok Whether it is required to verify requestor permission
 *	flags match with owner or not.
 *
 * @return On success returns statring PCIATB entry and negative of errno on failure.
 */
int64_t veos_alloc_pciatb(pid_t pid, uint64_t vaddr,
		size_t size, uint64_t perm, bool access_ok)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	size_t buddy_size = 0, pci_pgsize = 0;
	uint64_t *page_base = NULL, tmp_addr = 0, *pgmod_info = NULL;
	uint64_t pci_entry = -1, page_cnt = 0;
	uint64_t pg_mode = -1;
	int req_type = -1;
	int64_t ret = 0, count = 0;
	bool same = false;

	pci_pgsize = vnode_info->pci_bar01_pgsz;

	VEOS_TRACE("invoked with pid :%d vaddr : 0x%lx "
		"size : 0x%lx perm :0x%lx access_ok :%u",
		pid, vaddr, size, perm, access_ok);

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error(%s) process task struct not found",
			strerror(-ret));
		return ret;
	}

	/*check whether given size is valid or not*/
	if ((int64_t)size <= 0) {
		VEOS_DEBUG("Size(0x%lx) is not valid", size);
		ret = -EINVAL;
		put_ve_task_struct(tsk);
		return ret;
	}

	/*check whether given vaddr is aligned or not*/
	if ((!vaddr) || !IS_ALIGNED(vaddr, pci_pgsize)) {
		VEOS_DEBUG("vaddr is not aligned(0x%lx) with pci page size(0x%lx)",
			vaddr, pci_pgsize);
		ret = -EINVAL;
		put_ve_task_struct(tsk);
		return ret;
	}

	/*Aligning the size according to PCI page size*/
	if (!IS_ALIGNED(size, pci_pgsize)) {
		size = ALIGN(size, pci_pgsize);
		VEOS_DEBUG("Alingned Size with(0x%lx) pci page size(0x%lx)",
			size, pci_pgsize);
	}

	/*Get the pagmod info for input address,
	 * Here we will get NULL terminated array about
	 * page size of each request address that may lie in
	 * multiple ATB dirs
	 */
	pgmod_info = amm_get_pgmod_info(vaddr, tsk, size, &same);
	if (NULL == pgmod_info) {
		ret = -EINVAL;
		VEOS_DEBUG("Error(%s)to get page mode info",
			strerror(-ret));
		goto pci_failed;
	}

	/*
	 * Get the required type for pciatb allocation
	 * There are four type of allocation possible
	 * according to PCI page size and VE page size*/
	req_type = get_pci_req_type(pgmod_info, &same);

	/*Freeing buffer allocated to take pgmod info*/
	free(pgmod_info);

	/* Depending upon type of PCIATB we
	 * need to allocate the PCIATB entries
	 */
	switch (req_type) {
	case PCI_ALLOC_NORMAL:
	case PCI_ALLOC_PARTIAL:
	case PCI_ALLOC_HYBRID:
		VEOS_DEBUG("PCI: Allocation in 2MB boundary");
		page_cnt = size >> LARGE_PSHFT;
		break;
	case PCI_ALLOC_HUGE:
		VEOS_DEBUG("PCI: Allocation in 64MB boundary");
		page_cnt = size >> HUGE_PSHFT;
		break;
	case PCI_ALLOC_ERROR:
		VEOS_DEBUG("PCI: Allocation request is invalid");
		ret = -EINVAL;
		goto pci_failed;
	default:
		VEOS_DEBUG("PCI: Invalid request type");
		ret = -EINVAL;
		goto pci_failed;
	}

	VEOS_DEBUG("page count is(%ld)", page_cnt);

	/* If size is not power of to then
	 * bring it up and then allocate entries
	 * because buddy will always
	 * allocate size in power of two*/
	buddy_size = size;
	if (!is_pow_two(size)) {
		buddy_size = roundup_pow_of_two(size);
		VEOS_DEBUG("Round up size for buddy(0x0x%lx)", buddy_size);
	}

	page_base = (uint64_t *)calloc((page_cnt + 1), (sizeof(uint64_t)));
	if (NULL == page_base) {
		ret = -ENOMEM;
		VEOS_CRIT("Error(%s) while allocating mem for page_base",
			 strerror(-ret));
		put_ve_task_struct(tsk);
		return ret;
	}
	memset(page_base, -1, (sizeof(uint64_t) * (page_cnt + 1)));

	ret = mk_pci_pgent(vaddr, page_cnt, tsk->p_ve_mm, size,
			req_type, page_base, perm, access_ok);
	if (ret < 0) {
		VEOS_DEBUG("Error(%s) in setting pciatb entry",
			strerror(-ret));
		goto pci_failed;
	}

	pg_mode = (uint64_t)((vnode_info->pci_bar01_pgsz == PAGE_2MB) ?
			PGMOD_2MB : PGMOD_64MB);
	/*Get free entry from buddy*/
	/*if requested size is power of two*/
	pthread_mutex_lock_unlock(&vnode_info->pci_mempool->buddy_mempool_lock,
			LOCK, "Failed to acquire pci buddy lock");
	tmp_addr = (uint64_t)buddy_alloc(vnode_info->
			pci_mempool, size_to_order(buddy_size));
	if ((void *)tmp_addr == BUDDY_FAILED) {
		VEOS_ERROR("failed to allocate mem blk from mempool for PCI entries");
		pthread_mutex_lock_unlock(&vnode_info->pci_mempool->buddy_mempool_lock,
					  UNLOCK,
					  "Failed to release pci buddy lock");
		ret = -ENOMEM;
		goto pci_failed;
	}
	pthread_mutex_lock_unlock(&vnode_info->pci_mempool->buddy_mempool_lock,
			UNLOCK,	"Failed to release pci buddy lock");

	pci_entry = pfnum(tmp_addr, pg_mode);
	VEOS_DEBUG("Allocated pciatb VHVA is(0x%lx)", tmp_addr);
	VEOS_DEBUG("Allocated pciatb entry is(%ld)", pci_entry);

	/* Set the entry to s/w image and
	 * also increament the ref count
	 * of VE pages*/
	count = alloc_pcientry(pci_entry, page_cnt, page_base);
	if (count < 0) {
		VEOS_DEBUG("PCI entries not contiguous");
		ret = -ENOMEM;
		goto pci_failed;
	}

	/* As buddy allocator always size which is
	 * power of two.But when pci entry size is
	 * not power of two we will round up the size.
	 * Due to this some PCI entry will remained unused.
	 * So here we are freeing that unused entries*/
	ret = free_unused_entry(pci_entry, size, buddy_size);
	if (ret < 0) {
		VEOS_ERROR("Error(%s) in freeing unused pciatb entry",
			strerror(-ret));
		/*
		 * Here it is required to invoke veos_abort()
		 * because state of PCIATB buddy mem pool becomes
		 * inconsistent because of calloc() failure and it is not
		 * good to retry multiple times to free the required chunk.
		 * inconsistent state means that pci memory leak occurs
		 * and will impact further PCI allocation requests
		 */
		veos_abort("pciatb buddy mempool inconsistency");
	}

	/*Update total entries used in VE node struct*/
	if (vnode_info->pci_bar01_pgsz == PAGE_SIZE_2MB)
		vnode_info->pci_mempool->small_page_used += count;
	else
		vnode_info->pci_mempool->huge_page_used += count;


	put_ve_task_struct(tsk);

	free(page_base);
	VEOS_DEBUG("returned(%ld)", pci_entry);
	return pci_entry;

pci_failed:
	put_ve_task_struct(tsk);
	if (page_base)
		free(page_base);
	VEOS_TRACE("returned(%ld)", ret);
	return ret;
}
/**
 * @brief This function used to set address translation into PCIATB registers of
 *	the VE node to invalidate VE memory space from VH memory space.
 *
 * @param[in] entry Start of PCIATB entry number.
 * @param[in] size Start of PCIATB entry number.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t veos_delete_pciatb(uint64_t entry, size_t size)
{
	uint64_t entry_cnt = 0, idx = 0;
	uint64_t page_base = -1;
	size_t pci_pgsize = -1;
	struct ve_node_struct *vnode_info = VE_NODE(0);
	int64_t ret = 0;

	VEOS_DEBUG("invoked to detete pcientry(%ld)"
		"with size(0x%lx)", entry, size);

	pci_pgsize = vnode_info->pci_bar01_pgsz;

	if (((int64_t)size <= 0) || ((int64_t)entry < 0)) {
		ret = -EINVAL;
		VEOS_DEBUG("Error(%s) entry(%ld) size(0x%lx)",
			strerror(-ret), entry, size);
		return ret;
	}

	if (!IS_ALIGNED(size, pci_pgsize)) {
		size = ALIGN(size, pci_pgsize);
		VEOS_DEBUG("aligned size with 0x%lx pci page size: 0x%lx",
			size, pci_pgsize);
	}

	if (pci_pgsize == PAGE_2MB)
		entry_cnt = size >> LARGE_PSHFT;
	else
		entry_cnt = size >> HUGE_PSHFT;


	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	/* Calculate the page bage from PCI
	 * entry and decrement the ref count*/
	for (idx = entry; idx < (entry + entry_cnt); idx++) {
		/* First check whether entries
		 * is already allocated or not*/
		if (idx > vnode_info->pci_mempool->total_pages) {
			ret = -EINVAL;
			VEOS_DEBUG("Error(%s)invalid pciatb entry",
					strerror(ret));
			pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
					UNLOCK,	"Failed to release pci lock");
			return ret;
		}
		if (vnode_info->pciatb[idx].data == INVALID_ENTRY) {
			VEOS_DEBUG("Entry :%ld is Invalid", idx);
			continue;
		}
		/*Decreament the ref count of VE page*/
		page_base = GET_PCIATB_PB(&vnode_info->pciatb[idx]);
		/*Invalidating pci s/w entry*/
		vnode_info->pciatb[idx].data = INVALID_ENTRY;
		ret = amm_put_page(page_base * PAGE_SIZE_2MB);
		if (ret < 0) {
			VEOS_DEBUG("Error(%s) in inc ref count",
					strerror(-ret));
			pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
					UNLOCK,	"Failed to release pci lock");
			return ret;
		}
		/*free the perticuler entry*/
		pthread_mutex_lock_unlock(&vnode_info->pci_mempool->buddy_mempool_lock,
				LOCK, "Failed to acquire pci buddy lock");
		ret = veos_free_pcientry(idx, vnode_info->pci_bar01_pgsz);
		if (ret < 0) {
			pthread_mutex_lock_unlock(&vnode_info->pci_mempool->
					buddy_mempool_lock, UNLOCK,
					"Failed to release pci buddy lock");
			veos_abort("pci buddy mempool inconsistent due to calloc failure");
		}

		pthread_mutex_lock_unlock(&vnode_info->pci_mempool->
				buddy_mempool_lock, UNLOCK,
				"Failed to release pci buddy lock");
		VEOS_TRACE("PCI Entries %ld has been free", idx);
	}

	/*update H/w PCI entries*/
	veos_set_pciatb(vnode_info->pciatb, entry, entry_cnt);
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");

	pthread_mutex_lock_unlock(&vnode_info->pci_mempool->
			buddy_mempool_lock, LOCK,
			"Failed to acquire pci buddy lock");

	/*Decreament the count of total used entry*/
	if (vnode_info->pci_bar01_pgsz == PAGE_SIZE_2MB)
		vnode_info->pci_mempool->small_page_used -= entry_cnt;
	else
		vnode_info->pci_mempool->huge_page_used -= entry_cnt;

	VEOS_DEBUG("============= DELETE PCI DUMP ===========");
	buddy_dump_mempool(vnode_info->pci_mempool);

	pthread_mutex_lock_unlock(&vnode_info->pci_mempool->
			buddy_mempool_lock, UNLOCK,
			"Failed to release pci buddy lock");


	VEOS_TRACE("returned(%ld)", ret);
	return ret;

}

/**
 * @brief This function sets the PCISYMR value.
 *
 * @param[in] num PCISYMR number.
 * @param[in] val value to be set.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_amm_set_pcisymr(uint8_t num, uint64_t val)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode_info = VE_NODE(0);
	off_t offset = offsetof(system_common_reg_t,
			pciatb_sync_addr_mask[num]);
	VEOS_TRACE("invoked to set pcisymr(%u) val(%ld)", num, val);
	/*Check for PCISYMR number*/
	if (((int8_t)num < 0) || (num > PCISYMR_MAX)) {
		VEOS_DEBUG("Invalid PCISYMR number(%u)", num);
		ret = -EINVAL;
		return ret;
	}
	/*Set pciatb_sync_addr_mask to h/w */
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	ret = vedl_set_cnt_reg_word(handle,
			vnode_info->cnt_regs_addr, offset, val);
	if (ret < 0) {
		pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
				UNLOCK,	"Failed to release pci lock");
		veos_abort("unable to set pcisymr hardware reg");
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
 * @brief This function gets the PCISYMR value.
 *
 * @param[in] num PCISYMR number.
 * @param[Out] val value to be get.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_amm_get_pcisymr(uint8_t num, uint64_t *val)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode_info = VE_NODE(0);
	off_t offset = offsetof(system_common_reg_t,
			pciatb_sync_addr_mask[num]);

	VEOS_TRACE("invoked to get pcisymr(%u) in val(%p)", num, val);
	/*Check foi PCISYMR number*/
	if (((int8_t)num < 0) || (num > PCISYMR_MAX) || !(val)) {
		VEOS_DEBUG("inval PCISYMR no(%u) or val(%p)",
			num, val);
		ret = -EINVAL;
		return ret;
	}
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	/*Set pciatb_sync_addr_mask to h/w */
	ret = vedl_get_cnt_reg_word(handle,
			vnode_info->cnt_regs_addr, offset, val);
	if (ret < 0) {
		pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
				UNLOCK,	"Failed to release pci lock");
		veos_abort("unable to read pcisymr hardware reg");
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
 * @brief This function sets the PCISYAR value.
 *
 * @param[in] num PCISYAR number.
 * @param[in] val value to be set.
 *
 * @return On success returns 0 and negative of errno on failure..
 */
int veos_amm_set_pcisyar(uint8_t num, uint64_t val)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode_info = VE_NODE(0);
	off_t offset = offsetof(system_common_reg_t,
			pciatb_sync_addr[num]);

	VEOS_TRACE("invoked to set pcisyar(%u) with val(%ld)", num, val);
	/*Check for PCISYAR number*/
	if (((int8_t)num < 0) || (num > PCISYAR_MAX)) {
		VEOS_DEBUG("Invalid PCISYAR number(%u) (val :%ld)", num, val);
		ret = -EINVAL;
		return ret;
	}
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	/*Set pciatb_sync_addr_mask to h/w */
	ret = vedl_set_cnt_reg_word(handle,
			vnode_info->cnt_regs_addr, offset, val);
	if (ret < 0) {
		pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
				UNLOCK,	"Failed to release pci lock");
		veos_abort("unable to pcisyar hardware reg");
	}
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
 * @brief This function gets the PCISYAR value.
 *
 * @param[in] num num PCISYAR number.
 * @param[in] val value to be get.
 *
 * @return On success returns 0 and negative of errno on failure..
 */
int veos_amm_get_pcisyar(uint8_t num, uint64_t *val)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode_info = VE_NODE(0);
	off_t offset = offsetof(system_common_reg_t,
			pciatb_sync_addr[num]);

	VEOS_TRACE("invoked to get pcisyar(%u)", num);

	/*Check foi PCISYAR number*/
	if (((int8_t)num < 0) || (num > PCISYAR_MAX) || !(val)) {
		VEOS_DEBUG("Invalid PCISYAR(%u) or val(%p)", num, val);
		ret = -EINVAL;
		return ret;
	}
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	/*Set pciatb_sync_addr_mask to h/w */
	ret = vedl_get_cnt_reg_word(handle,
			vnode_info->cnt_regs_addr, offset, val);
	if (ret < 0) {
		pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
				UNLOCK,	"Failed to release pci lock");
		veos_abort("unable to read pcisyar hardware reg");
	}
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");
	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
 * @brief This function will set the different synchronization bits of PCIATB
 *	page descriptor.
 *
 * @param[in] pid PID of requestor process.
 * @param[in] pairnum PCISYAR/PCISYMR pair number <0-3>.
 * @param[in] entry PCIATB entry number.
 * @param[in] sync bit.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_set_pciatb_pgdesc(pid_t pid, uint8_t pairnum, uint64_t entry,
		uint64_t sync)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode_info = VE_NODE(0);
	pciatb_entry_t *p_entry = NULL;

	VEOS_TRACE("invoked to set pciatb pgdesc with pid(%d)"
			"pairnum(%u) entry(%ld) sync(%ld)",
			pid, pairnum, entry, sync);

	if ((int8_t)pairnum < 0 || (int64_t)entry < 0 || (int64_t)sync < 0) {
		VEOS_DEBUG("Invalid argument (pairnum :%u)(entry :%ld)(sync:%ld)",
			pairnum, entry, sync);
		ret = -EINVAL;
		return ret;
	}

	if ((entry > vnode_info->pci_mempool->total_pages) || (pairnum > PAIR_MAX)) {
		VEOS_DEBUG("Invalid PCIATB entry(%ld)", entry);
		ret = -EINVAL;
		return ret;
	}

	if (vnode_info->pciatb[entry].data == INVALID_ENTRY) {
		VEOS_DEBUG("Invalid PCIATB entry(%ld)", entry);
		ret = -EINVAL;
		return ret;
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	p_entry = &vnode_info->pciatb[entry];

	if (sync)
		SET_SYNC(p_entry);
	else
		UNSET_SYNC(p_entry);

	SET_PCISY_PAIR(p_entry, pairnum);

	VEOS_DEBUG("For entry(%ld) pairnum(%u) sync(%ld) set",
			entry, pairnum, sync);
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");

	/*Now update this entry to H/w */
	ret = vedl_update_pciatb_entry(handle, vnode_info->cnt_regs_addr,
			&vnode_info->pciatb[entry], entry);
	if (ret < 0)
		veos_abort("unable to update pciatb hardware entries");

	VEOS_TRACE("returned(%d)", ret);
	return ret;
}
/**
 * @brief This function will get the different fields of PCIATB page descriptor.
 *
 * @param[in] pid PID of requestor process.
 * @param[in] pair PCISYAR/PCISYMR pair num.
 * @param[in] sync sync bit.
 * @param[in] entry Address of PCIATB page descriptor entry mapped with VEOS.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_get_pciatb_pgdes(pid_t pid, uint8_t *pair, uint64_t *sync,
		uint64_t entry)
{
	struct ve_node_struct *vnode_info = VE_NODE(0);
	pciatb_entry_t *p_entry = NULL;

	VEOS_TRACE("invoked to get pciatb pgdes for entry(%ld)", entry);

	if (((int64_t)entry < 0) || !(pair) || !(sync)) {
		VEOS_DEBUG("Invalid argument (entry :%ld) (pair:%p)(sync:%p)",
				entry, pair, sync);
		return -EINVAL;
	}

	if (entry > vnode_info->pci_mempool->total_pages ||
			(vnode_info->pciatb[entry].data == INVALID_ENTRY)) {
		VEOS_DEBUG("Invalid PCIATB entry(%ld)", entry);
		return -EINVAL;
	}

	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock, LOCK,
			"Failed to acquire pci lock");
	p_entry = &vnode_info->pciatb[entry];

	*(sync) = GET_SYNC(p_entry);
	*(pair) = GET_PCISY_PAIR(p_entry);

	VEOS_DEBUG("For entry(%ld) pairnum(%u) sync(%ld) obtained",
			entry, *(pair), *(sync));
	pthread_mutex_lock_unlock(&vnode_info->pciatb_lock,
			UNLOCK,	"Failed to release pci lock");

	VEOS_TRACE("returned(0)");
	return 0;
}
