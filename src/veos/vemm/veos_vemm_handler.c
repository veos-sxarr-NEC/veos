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
 * @file veos_vemm_handler.c
 * @brief functions for VEMM agent
 */
#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>

#include <uuid/uuid.h>

#include <libved.h>
#include "task_mgmt.h"
#include "ve_mem.h"
#include "ve_memory.h"
#include "dmaatb_api.h"
#include "vehva_mgmt.h"
#include "veos_veshm.h"
#include "veos.h"
#include "veshm_defs.h"
#include "vemva_layout.h"

#include "veos_vemm_log.h"
#include "veos_vemm_handler.h"

#define VADDR(va) ((va) & 0xffffffffffffUL)
#define USE_PCISYNC(va) (((va) & 0x4000000000000000UL) != 0)
#define SYNCNUM(va) (((va) & 0x3000000000000000UL) >> 60)

/**
 * @brief Remove RDMA_OFFSET from requested address.
 *
 * @param[in] pid Process ID
 * @param[in] vaddr Requested address
 *
 * @return VEMVA on success, 0 on failure.
 */
static uint64_t
veos_vemm_remove_rdmaoffset(pid_t pid, uint64_t vaddr)
{
	struct ve_task_struct *tsk = NULL;
	uint64_t retval = 0;

	VEMM_AGENT_TRACE("%s(%d, 0x%lx)", __func__, (int)pid, vaddr);

	tsk = find_ve_task_struct(pid);
	if (tsk == NULL) {
		VEMM_AGENT_ERROR("pid %d %s", pid, strerror(ESRCH));
		goto hndl_return;
	}
	retval = VADDR(vaddr);
	if ((retval < VEMMR_START) || (retval > VEMMR_BOTTOM))
		retval = retval - tsk->p_ve_mm->rdma_offset;
	put_ve_task_struct(tsk);
	VEMM_AGENT_DEBUG("PID %d : 0x%lx -> 0x%lx", pid, vaddr, retval);

hndl_return:
	VEMM_AGENT_TRACE("%s() returns 0x%lx", __func__, retval);
	return retval;
}

/**
 * @brief Check process ID
 *
 * Check whether a process with a specified PID exists.
 *
 * @param pid process ID
 *
 * @return non-zero if the process exists; zero unless the process exists.
 *
 */
int veos_vemm_check_pid(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;

	VEMM_AGENT_DEBUG("check pid %d\n", (int)pid);
	tsk = find_ve_task_struct(pid);
	if (tsk)
		put_ve_task_struct(tsk);

	return (tsk != NULL);
}

static int pgmode_to_page_size(int pgmode)
{
	VEMM_AGENT_TRACE("%s(0x%x)", __func__, pgmode);
	switch (pgmode) {
	case PG_2M:
		return 2 * 1024 * 1024;
	case PG_HP:
		return 64 * 1024 * 1024;
	default:
		VEMM_AGENT_DEBUG("page mode 0x%x is invalid.", pgmode);
		return -1;
	}
}

/**
 * @brief Check presense and size of page
 *
 * @param pid process ID
 * @param vaddr VEMVA to check
 *
 * @return the page size when page frame mapped from vaddr is present,
 *         -EFAULT when vaddr is not mapped.
 */
static int veos_vemm_get_page_size(pid_t pid, uint64_t vaddr)
{
	int pgmode, page_size;

	VEMM_AGENT_TRACE("%s(%d, %p)", __func__, (int)pid, (void *)vaddr);
	pgmode = veos_get_pgmode(VE_ADDR_VEMVA, pid, vaddr);
	VEMM_AGENT_DEBUG("pgmode (pid=%d, addr=%p) = %x", (int)pid,
		(void *)vaddr, (unsigned int)pgmode);
	page_size = pgmode_to_page_size(pgmode);

	return (page_size > 0) ? page_size : -EFAULT;
}

/**
 * @brief Check a VE memory area
 *
 * Check a VE memory area as acquire operation of VEMM agent.
 *
 * @param pid process ID
 * @param encoded_vaddr start address of VE memory area to check
 * @param size size of the area in bytes
 *
 * @return PCIATB page size upon success;
 *         zero if one or more virtual pages are not mapped or
 *              if the area cannot be mapped due to page size.
 */
int veos_vemm_acquire(pid_t pid, uint64_t encoded_vaddr, size_t size)
{
	VEMM_AGENT_TRACE("%s(%d, %p, %lu)", __func__, (int)pid,
		(void *)encoded_vaddr, size);
	VEMM_AGENT_DEBUG("acquire: pid=%d, addr=%p, size=%lu", (int)pid,
		(void *)encoded_vaddr, size);

	uint64_t start_vaddr;
	int page_size;
	int min_page_size;

	/* check the first page */
	start_vaddr = veos_vemm_remove_rdmaoffset(pid, encoded_vaddr);
	if (!start_vaddr) {
		VEMM_AGENT_ERROR("cannot remove RDMA_OFFSET : pid=%d, addr=%p",
			(int)pid, (void *)encoded_vaddr);
		return 0;
	}
	page_size = veos_vemm_get_page_size(pid, start_vaddr);
	min_page_size = page_size;

	VEMM_AGENT_DEBUG("pid=%d, addr=%p: page size = %d", (int)pid,
		(void *)start_vaddr, page_size);
	if (page_size < 0) {
		VEMM_AGENT_DEBUG("cannot get page size: pid=%d, addr=%p",
			(int)pid, (void *)start_vaddr);
		return 0;
	}
	/* check the 2nd to the last pages */
	for (uint64_t addr = ROUN_DN(start_vaddr, page_size) + page_size;
		addr < start_vaddr + size; addr += page_size) {
		page_size = veos_vemm_get_page_size(pid, addr);

		VEMM_AGENT_DEBUG("pid=%d, addr=%p: page size = %d",
			(int)pid, (void *)addr, page_size);
		if (page_size <= 0) {
			VEMM_AGENT_DEBUG("cannot get page size: "
				"pid=%d, addr=%p", (int)pid, (void *)addr);
			return 0;
		}
		if (page_size < min_page_size)
			min_page_size = page_size;

	}
	/* get PCIATB page size */
	int pciatb_page_size = veos_ived_get_pciatb_pgmode(pid);

	VEMM_AGENT_DEBUG("PCIATB page size for PID %d = %d", (int)pid,
		pciatb_page_size);
	if (pciatb_page_size < 0) {
		VEMM_AGENT_ERROR("failed to get PCIATB page size (pid=%d)",
			pid);
		return 0;
	}
	VEMM_AGENT_TRACE("%s() returns %d", __func__, pciatb_page_size);
	return pciatb_page_size;
}

/**
 * @brief Map a VE memory area from PCI memory address space.
 *
 * @param euid effective user ID of process
 * @param pid process ID
 * @param encoded_vaddr start address of VE memory area to map from PCI space
 * @param size size of the area in bytes
 * @param writable 1 if write permission is required; 0 if unnecessary.
 * @param[out] arrayp pointer to an array storing VHSAAs mapped to the area
 * @param[out] sizep pointer to the number of elements of *arrayp
 * @param[out] veshm_id VESHM ID (UUID) of the mapped area
 *
 * @return the number of elements of *arrayp, addresses in BAR01 window.
 */
int veos_vemm_get_pages(uid_t euid, pid_t pid, uint64_t encoded_vaddr,
			size_t size, int writable,
			uint64_t **arrayp, size_t *sizep,
			unsigned char veshm_id[16])
{
	VEMM_AGENT_TRACE("%s(%d, %d, %p, %lu, %d, ...)", __func__,
		(int)euid, (int)pid, (void *)encoded_vaddr, size, writable);

	uint64_t vaddr;
	int pciatb_page_size;
	uint64_t *pci_address = NULL;

	vaddr = veos_vemm_remove_rdmaoffset(pid, encoded_vaddr);
	if (!vaddr) {
		VEMM_AGENT_ERROR("cannot remove RDMA_OFFSET : pid=%d, addr=%p",
			(int)pid, (void *)encoded_vaddr);
		return -ESRCH;
	}
	pciatb_page_size = veos_ived_get_pciatb_pgmode(pid);

	VEMM_AGENT_DEBUG("PCIATB page size for PID %d = %d", (int)pid,
		pciatb_page_size);
	if (pciatb_page_size < 0) {
		VEMM_AGENT_ERROR("failed to get PCIATB page size (pid=%d)",
			pid);
		return -EFAULT;
	}
	if (size % pciatb_page_size != 0) {
		VEMM_AGENT_ERROR("size %ld is unaligned to PCIATB page size",
			size);
		VEMM_AGENT_ERROR("PCIATB page size = %d", pciatb_page_size);
		return -EINVAL;
	}
	if (vaddr % pciatb_page_size != 0) {
		VEMM_AGENT_ERROR("vaddr %p is unaligned to PCIATB page size",
			(void *)vaddr);
		VEMM_AGENT_ERROR("PCIATB page size = %d", pciatb_page_size);
		return -EINVAL;
	}

	uint64_t mode_flag = (writable ? 0 : VE_SHM_RO) |
		(USE_PCISYNC(encoded_vaddr) ? VE_PCISYNC : 0) | VE_REGISTER_PCI;
	int syncnum = SYNCNUM(encoded_vaddr);

	VEMM_AGENT_TRACE("veshm_open_internal(%d, %d, %p, %ld, %d, 0x%lx, ..)",
		(int)euid, (int)pid, (void *)vaddr, size, syncnum, mode_flag);

	uint64_t len = veshm_open_internal(euid, pid, vaddr, size, syncnum,
				mode_flag, (unsigned char (*)[16])veshm_id,
				&pci_address);
	if (len == (uint64_t)-1) {
		VEMM_AGENT_ERROR("veshm_open_internal() failed.");
		return -EFAULT;
	}

	int npages = size / pciatb_page_size;
	if (npages + 1 != len) {
		int failed;
		char uuid_str[37] = "deadbeef-dead-beef-dead-beefdeadbeef";
		uuid_unparse(veshm_id, uuid_str);
		VEMM_AGENT_ERROR("unexpected length: %lu; %d expected",
			len, npages + 1);
		VEMM_AGENT_TRACE("veshm_close_internal(%s, %d)",
			uuid_str, (int)pid);
		failed = veshm_close_internal(veshm_id, pid);
		if (failed) {
			VEMM_AGENT_ERROR("veshm_close_internal(%s, %d) failed.",
				uuid_str, (int)pid);
		}
		free(pci_address);
		return -EFAULT;
	}

	VEMM_AGENT_DEBUG("# of pages = %d", npages);

	*sizep = npages;
	*arrayp = pci_address;
	VEMM_AGENT_TRACE("%s() returns %d", __func__, npages);
	return npages;
}

/**
 * @brief Unmap a VE memory area from PCI memory address space.
 *
 * @param euid effective user ID of requester
 * @param pid process ID who allocated mapping by get_pages()
 * @param[in] veshm_id VESHM ID (UUID) of a mapped area
 *
 * @return zero upon success; negative upon failure.
 */
int veos_vemm_put_pages(uid_t euid, pid_t pid, unsigned char veshm_id[16])
{
	char uuid_str[37] = "deadbeef-dead-beef-dead-beefdeadbeef";
	uuid_unparse(veshm_id, uuid_str);
	VEMM_AGENT_TRACE("%s(%d, %d, %s)", __func__, (int)euid, (int)pid,
		uuid_str);
	VEMM_AGENT_TRACE("veshm_close_internal(%s, %d)", uuid_str, (int)pid);
	int failed = veshm_close_internal(veshm_id, pid);

	if (failed != 0) {
		VEMM_AGENT_DEBUG("veshm_close_internal(%s, %d) failed.",
			uuid_str, (int)pid);
		/*
		 * When this VE OS does not serve the specified VESHM area,
		 * veshm_close_internal() sets errno to EINVAL.
		 * Hence, EINVAL needs to be substituted with ESRCH.
		 *
		 * The function veos_veshm_close_common(), called from
		 * veshm_close_internal(), first searches the
		 * process with the specified PID, finding no process.
		 * Without a process found, veshm_close_common() next tries
		 * to find the specified area using
		 * search_all_owned_veshm_uuid() with the UUID and
		 * with ived_resource set to NULL because the VE task
		 * specified by PID is not found.
		 * The function search_all_owned_veshm_uuid() cannot find
		 * the VESHM area specified by UUID and returns NULL.
		 */
		return errno == EINVAL ? -ESRCH : -errno;
	}
	VEMM_AGENT_TRACE("%s() returns 0", __func__);
	return 0;
}

/**
 * @brief Map a PCI memory area from VEHVA space
 *
 * @param euid effective user ID of a process
 * @param pid process ID
 * @param vhva VH virtual address of area to be mapped from VE
 * @param writable 1 if write permission is required; 0 if unnecessary
 * @param[out] pointer to VEHVA mapping to a specified PCI memory area
 *
 * @return zero upon success; negative upon failure.
 *
 */
int veos_vemm_dmaattach(uid_t euid, pid_t pid, uint64_t vhva, int writable,
			uint64_t *vehvap)
{
	int pfnmap;
	uint64_t vhsaa;
	int64_t vehva;

	VEMM_AGENT_TRACE("%s(%d, %d, %p, %d, ..)", __func__, (int)euid,
		(int)pid, (void *)vhva, writable);
	/*
	 * the area is not pinned since the area is likely to be on
	 * PCI MMIO, PFN map, area.
	 */
	vhsaa = vedl_get_dma_address(VE_HANDLE(0), (void *)vhva,
				pid, 0, writable, &pfnmap);
	VEMM_AGENT_DEBUG("PID %d, VHVA=%p (write=%d) -> VHSAA=%p (pfnmap=%d)",
		(int)pid, (void *)vhva, writable, (void *)vhsaa, pfnmap);
	if (vhsaa == (uint64_t)-1) {
		VEMM_AGENT_ERROR("translation failed (pid=%d, addr=%p)",
			(int)pid, (void *)vhva);
		return -EFAULT;
	}
	if (!pfnmap)
		VEMM_AGENT_DEBUG("VHSAA %p is not PFN-map.", (void *)vhsaa);
	vehva = veos_aa_to_vehva(pid, vhsaa, VE_ADDR_VHSAA);
	VEMM_AGENT_DEBUG("VHSAA=%p -> VEHVA=%p (pid=%d)", (void *)vhsaa,
		(void *)vehva, (int)pid);
	if (vehva < 0) {
		VEMM_AGENT_DEBUG("DMAATB entry is not found: create now.");
		uint64_t addr_array[] = {vhsaa, 0};
		int prot = writable ? PROT_WRITE | PROT_READ : PROT_READ;

		vehva = veos_alloc_dmaatb_entry_for_aa(pid, addr_array,
				prot, VE_ADDR_VHSAA, VEHVA_IB | VEHVA_4K);
		VEMM_AGENT_DEBUG("veos_alloc_dmaatb_entry_for_aa() -> %p",
			(void *)vehva);
		if (vehva < 0)
			goto error_alloc_new;
	} else {
		VEMM_AGENT_ERROR("PID %d, VHVA=%p (VHSAA=%p) is mapped.\n",
			(int)pid, (void *)vhva, (void *)vhsaa);
		return -EACCES;
	}
	*vehvap = vehva;
	VEMM_AGENT_TRACE("%s(): vehva=%p.", __func__, (void *)vehva);
	return 0;

error_alloc_new:
	VEMM_AGENT_ERROR("DMAATB entry allocation failed (errno=%ld)", -vehva);
	return vehva;
}

/**
 * @brief Unmap a PCI memory area from VEHVA space
 *
 * @param euid effective user ID of a process
 * @param pid process ID
 * @param vehva VEHVA to be unmapped
 *
 * @return zero upon success; negative upon failure.
 *
 */
int veos_vemm_dmadetach(uid_t euid, pid_t pid, uint64_t vehva)
{
	int rv;

	VEMM_AGENT_TRACE("%s(%d, %d, %p)", __func__, (int)euid, (int)pid,
		(void *)vehva);

	rv = veos_free_dmaatb_entry(pid, vehva, 4096);
	if (rv < 0) {
		VEMM_AGENT_ERROR("Detach from VEHVA failed (%d)", rv);
		return rv;
	}
	VEMM_AGENT_TRACE("%s() succeeded.", __func__);
	return 0;
}
