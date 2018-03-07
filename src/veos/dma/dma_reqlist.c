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
 * @file dma_reqlist.c
 * @brief operation of DMA reqlist entries
 */
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include "dma.h"
#include "dma_private.h"
#include "dma_hw.h"
#include "dma_reqlist.h"
#include "dma_reqlist_private.h"
#include "dma_log.h"
#include "vedma_hw.h"

#include "ve_mem.h"

static void unpin_ve(vedl_handle *, uint64_t);
static void unpin_ve_dma__addr(vedl_handle *, const ve_dma__addr *, uint32_t);

/**
 * @brief page size of a specified type of address space
 *
 * @param t type of address space
 *
 * @return page size on success; negative on failure.
 */
static int32_t addrtype_to_pagesize(ve_dma_addrtype_t t)
{
	switch (t) {
	case VE_DMA_VEMVA:
	case VE_DMA_VEMVA_WO_PROT_CHECK:
		return VE_PAGE_SIZE;
	case VE_DMA_VHVA:
		return VH_PAGE_SIZE;
	case VE_DMA_VEMAA:
	case VE_DMA_VERAA:
	case VE_DMA_VHSAA:
		/*
		 * It is unnecessary to divide when a physical address is used.
		 */
		return VE_DMA_DESC_LEN_MAX;
	default:
		VE_DMA_ERROR("Address type is invalid (%d)", t);
		return -EINVAL;
	}
}

/**
 * @brief translate VHVA into VHSAA
 *
 * @param vh VEDL handle to query address translation
 * @param pid process ID
 * @param vaddr virtual address (VHVA) to translate
 * @param[out] paddrp pointer to store physical address (VHSAA)
 * @param wr Check the page writable:
 *           When writable = 0, the function does not check.
 *           When writable = 1, the function checks the page is writable.
 *           If writable is 1 and the page is unwritable, this function fails.
 *
 * @return 0 on success, non-zero value on failure.
 */
static int dma_vhva_to_vhsaa(vedl_handle *vh, pid_t pid, uint64_t vaddr,
			     uint64_t *paddrp, int wr)
{
	int ret;
	uint64_t paddr_base;
	VE_DMA_TRACE("called (pid=%d, vaddr=%p, writable? = %d)", (int)pid,
		     (void *)vaddr, wr);
	int pfnmapped;
	paddr_base = vedl_get_dma_address(vh, (void *)VH_PAGE_ALIGN(vaddr), pid,
					  1, wr, &pfnmapped);
	if (paddr_base == (uint64_t)-1) {
		ret = -errno;
		VE_DMA_ERROR("VHVA address translation failed.(%d) "
			     "PID %d Addr %p", errno, pid, (void *)vaddr);
		return ret;
	}
	*paddrp = paddr_base + (vaddr & ~VH_PAGE_MASK);
	VE_DMA_TRACE("VH pid = %d, vaddr = %lx -> VHSAA 0x%016lx",
		     (int)pid, vaddr, *paddrp);
	return 0;
}

/**
 * @brief translate VEMVA into VEMAA
 *
 * @param pid process ID
 * @param vaddr virtual address (VEMVA) to translate
 * @param[out] paddrp pointer to store physical address (VEMAA)
 * @param wr Check the page writable:
 *           When writable = 0, the function does not check.
 *           When writable = 1, the function checks the page is writable.
 *           If writable is 1 and the page is unwritable, this function fails.
 * @param tlb TLB for VEMVA address translation
 *
 * @return 0 on success, non-zero value on failure.
 */
static int dma_vemva_to_vemaa(pid_t pid, uint64_t vaddr, uint64_t *paddrp,
			      int wr, struct ve_dma_vemtlb *tlb)
{
	int ret;
	int64_t paddr;
	int prot;
	VE_DMA_TRACE("called (pid=%d, vaddr=%p, writable? = %d)", (int)pid,
		     (void *)vaddr, wr);

	int tlb_hit = tlb->vaddr != (uint64_t)NULL &&
		      tlb->vaddr == (vaddr & VE_PAGE_MASK);
	if (tlb_hit) {
		paddr = tlb->paddr | (vaddr & ~VE_PAGE_MASK);
		prot = tlb->prot;
		VE_DMA_TRACE("VEMVA tlb hit vaddr %lx paddr %lx",
			     vaddr, paddr);
		ret = veos_get_page(paddr);
		if (ret < 0) {
			VE_DMA_ERROR("VEMVA get page failed(%d) "
				     "PID %d vddr %lx paddr %lx", -ret, pid,
				      vaddr, paddr);
			return ret;
		}
	} else {
		paddr = veos_virt_to_phy(vaddr, pid, 1, &prot);
		if (paddr < 0) {
			ret = paddr;
			VE_DMA_ERROR("VEMVA address translation failed.(%d) "
				     "PID %d Addr %p", -ret, pid,
				     (void *)vaddr);
			return ret;
		}
		if ((prot == PROT_WRITE) || (prot == PROT_READ)) {
			tlb->vaddr = vaddr & VE_PAGE_MASK;
			tlb->paddr = paddr & VE_PAGE_MASK;
			tlb->prot = prot;
		}
	}

	switch (prot) {
	case PROT_WRITE:
		break;
	case PROT_READ:
		if (wr) {
			VE_DMA_ERROR("The page can not be written: PID %d %p",
				     pid, (void *)vaddr);
			unpin_ve(NULL, paddr);
			return -EACCES;
		}
		break;
	case PROT_NONE:
		VE_DMA_ERROR("The page can not be accessed: PID %d %p",
			     pid, (void *)vaddr);
		unpin_ve(NULL, paddr);
		return -EACCES;
	default:
		VE_DMA_ERROR("Unknown page attribute: PID %d %p",
			pid, (void *)vaddr);
		return -EINVAL;
	}
	*paddrp = paddr;
	VE_DMA_TRACE("VE pid = %d, vaddr = %lx -> VEMAA 0x%016lx",
		     (int)pid, vaddr, *paddrp);
	return 0;
}

/**
 * @brief unpin VH page
 *
 * @param h VEDL handle
 * @param paddr address (VHSAA)
 */
static void unpin_vh(vedl_handle *h, uint64_t paddr)
{
	int err;
	VE_DMA_TRACE("called (address=%p)", (void *)paddr);
	err = vedl_release_pindown_page(h, paddr);
	if (err < 0) {
		VE_DMA_ERROR("VH page unpin failed. (addr=%lx, errno=%d)",
			     paddr, errno);
	}
}

/**
 * @brief unpin VE page
 *
 * @param h VEDL handle (ignored)
 * @param paddr address (VEMAA)
 */
static void unpin_ve(vedl_handle *h, uint64_t paddr)
{
	int err;
	VE_DMA_TRACE("called (address=%p)", (void *)paddr);
	err = veos_put_page(paddr);
	if (err < 0) {
		VE_DMA_ERROR("VE page unpin failed. (addr=%lx, errno=%d)",
			     paddr, -err);
	}
}

/**
 * @brief translate virtual address to physical address for DMA descriptor
 *
 * @param vh VEDL handle
 * @param pid process ID.
 *        If address type is physical (VEMAA, VERAA or VHSAA), pid is ignored.
 * @param t address type
 * @param vaddr address to be translated
 * @param[out] addr address translated
 * @param wr Check the page writable.
 * @param vemtlb TLB for VEMVA address translation
 *
 * @return 0 on success. Non-zero on failure.
 */
static int translate_addr(vedl_handle *vh, pid_t pid, ve_dma_addrtype_t t,
			  uint64_t vaddr, struct ve_dma__addr *addr, int wr,
			  struct ve_dma_vemtlb *vemtlb)
{
	VE_DMA_TRACE("called (pid=%d, addrtype=%d, vaddr=%p)", (int)pid, t,
		     (void *)vaddr);
	switch (t) {
	case VE_DMA_VHVA:
		VE_DMA_TRACE("addr type is VHVA (pid = %d, vaddr = %p)",
			  (int)pid, (void *)vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VHSAA;
		addr->unpin = unpin_vh;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return dma_vhva_to_vhsaa(vh, pid, vaddr, &addr->addr, wr);
	case VE_DMA_VEMAA:
		VE_DMA_TRACE("addr type is VEMAA (addr = 0x%016lx)", vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VEMAA;
		/* pid is ignored */
		addr->addr = vaddr;
		addr->unpin = NULL;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return 0;
	case VE_DMA_VERAA:
		VE_DMA_TRACE("addr type is VERAA (addr = 0x%016lx)", vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VERAA;
		/* pid is ignored */
		addr->addr = vaddr;
		addr->unpin = NULL;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return 0;
	case VE_DMA_VHSAA:
		VE_DMA_TRACE("addr type is VHSAA (addr = 0x%016lx)", vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VHSAA;
		/* pid is ignored */
		addr->addr = vaddr;
		addr->unpin = NULL;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return 0;
	case VE_DMA_VEMVA:
		VE_DMA_TRACE("addr type is VEMVA (pid = %d, vaddr = 0x%016lx",
			     (int)pid, vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VEMAA;
		addr->unpin = unpin_ve;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return dma_vemva_to_vemaa(pid, vaddr, &addr->addr, wr, vemtlb);
	case VE_DMA_VEMVA_WO_PROT_CHECK:
		VE_DMA_TRACE("addr type is VEMVA(WO_PROT_CHECK) "
			     "(pid = %d, vaddr = 0x%016lx",
			     (int)pid, vaddr);
		addr->type_hw = VE_DMA_DESC_ADDR_VEMAA;
		addr->unpin = unpin_ve;
		addr->unpin_pgsz = addrtype_to_pagesize(t);
		return dma_vemva_to_vemaa(pid, vaddr, &addr->addr, 0, vemtlb);
	default:
		VE_DMA_ERROR("Invalid address type: %d", t);
		return -EINVAL;
	}
}

/**
 * @brief Create a DMA reqlist entry
 *
 * @param[in] hdl DMA request handle
 * @param srctype address type of source
 * @param srcpid process ID of source.
 *        If srctype is physical, srcpid is ignored.
 * @param srcaddr source address
 * @param vemtlb_src TLB for VEMVA source address translation
 * @param dsttype address type of destination
 * @param dstpid process ID of destination.
 *        If dsttype is physical, dstpid is ignored.
 * @param dstaddr destination address
 * @param vemtlb_dst TLB for VEMVA destination address translation
 * @param length transfer length in byte
 *
 * @return pointer to a DMA reqlist entry created. NULL on failure.
 */
static ve_dma_reqlist_entry *mkrequest(ve_dma_req_hdl *hdl,
				       ve_dma_addrtype_t srctype, pid_t srcpid,
				       uint64_t srcaddr,
				       struct ve_dma_vemtlb *vemtlb_src,
				       ve_dma_addrtype_t dsttype, pid_t dstpid,
				       uint64_t dstaddr,
				       struct ve_dma_vemtlb *vemtlb_dst,
				       uint64_t length)
{
	struct ve_dma_reqlist_entry *e;
	int err;
	VE_DMA_TRACE("called (src: type = %d, pid = %d, addr = %016lx; "
		 "dst: type = %d, pid = %d, addr = %016lx; length = 0x%lx)",
		 srctype, srcpid, srcaddr, dsttype, dstpid, dstaddr, length);
	vedl_handle *vh = hdl->engine->vedl_handle;
	if (length > 0x100000000UL) {
		VE_DMA_ERROR("Too large transfer length");
		errno = EINVAL;
		return NULL;
	}
	e = malloc(sizeof(*e));
	if (e == NULL) {
		VE_DMA_ERROR("malloc for reqlist entry failed");
		errno = ENOMEM;
		return e;
	}
	/* source need not be writable. */
	err = translate_addr(vh, srcpid, srctype, srcaddr, &e->src, 0,
			     vemtlb_src);
	if (err != 0) {
		VE_DMA_ERROR("Error in source address translation");
		free(e);
		errno = -err;
		return NULL;
	}
	/* destination shall be writable. */
	err = translate_addr(vh, dstpid, dsttype, dstaddr, &e->dst, 1,
			     vemtlb_dst);
	if (err != 0) {
		VE_DMA_ERROR("Error in dest address translation");
		unpin_ve_dma__addr(vh, &e->src, 1);
		free(e);
		errno = -err;
		return NULL;
	}
	e->length = length;
	e->entry = -1;
	e->status_hw = 0;
	e->status = VE_DMA_ENTRY_NOT_POSTED;
	e->req_head = hdl;
	INIT_LIST_HEAD(&e->list);
	INIT_LIST_HEAD(&e->waiting_list);
	return e;
}

/**
 * @brief Determine contiguous address or not
 *
 * @param addr_pre address of preceding reqlist element
 * @param length transfer length of preceding reqlist element
 * @param addr_fol address of following reqlist element
 *
 * @return 1 on contiguous accesses. 0 on non-contiguours accesses.
 */
static int addr_cont(const ve_dma__addr *addr_pre, uint32_t length,
		     const ve_dma__addr *addr_fol)
{
	return addr_pre->type_hw == addr_fol->type_hw &&
	       (addr_pre->addr + length) == addr_fol->addr;
}

/**
 * @brief Divide a DMA request into one or more physical requests
 *
 *        Divide a specified DMA request at page boundaries into
 *        one or more DMA reqlist entries.
 *
 * @param[in,out] hdl DMA request handle
 *        hdl->reqlist is updated when returning this function.
 * @param srctype address type of source
 * @param srcpid process ID of source.
 *        If srctype is physical, srcpid is ignored.
 * @param srcaddr source address
 * @param dsttype address type of destination
 * @param dstpid process ID of destination.
 *        If dsttype is physical, dstpid is ignored.
 * @param dstaddr destination address
 * @param length transfer length in byte
 *
 * @return the number of DMA request entries on success.
 *         Zero or a negative value on failure.
 */
int64_t ve_dma_reqlist_make(ve_dma_req_hdl *hdl, ve_dma_addrtype_t srctype,
 			    pid_t srcpid, uint64_t srcaddr,
			    ve_dma_addrtype_t dsttype, pid_t dstpid,
			    uint64_t dstaddr, uint64_t length)
{
	VE_DMA_TRACE("called (src: type = %d, pid = %d, addr = 0x%016lx; "
		     "dst: type = %d, pid = %d, addr = 0x%016lx; "
		     "length = 0x%lx)",
		     srctype, srcpid, srcaddr, dsttype, dstpid, dstaddr,
		     length);
	VE_DMA_ASSERT(list_empty(&hdl->reqlist));
	vedl_handle *vh = hdl->engine->vedl_handle;
	struct ve_dma_vemtlb vemtlb_src = { .vaddr = (uint64_t)NULL };
	struct ve_dma_vemtlb vemtlb_dst = { .vaddr = (uint64_t)NULL };

	int32_t pgsz_src = addrtype_to_pagesize(srctype);
	if (pgsz_src < 0) {
		VE_DMA_ERROR("Source type %d is invalid.", srctype);
		return -EINVAL;
	}
	int32_t pgsz_dst = addrtype_to_pagesize(dsttype);
	if (pgsz_dst < 0) {
		VE_DMA_ERROR("Dest type %d is invalid.", dsttype);
		return -EINVAL;
	}
	VE_DMA_TRACE("src page size = 0x%x, dst page size = 0x%x",
		 (unsigned int)pgsz_src, (unsigned int)pgsz_dst);

	/* the offset of the next page boundary */
	uint64_t off_next_pg_bound_src, off_next_pg_bound_dst;
	if (length <= (uint64_t)pgsz_src && 
	    ROUN_DN(srcaddr, pgsz_src) == ROUN_DN(srcaddr + length, pgsz_src)) {
		/* in one page */
		off_next_pg_bound_src = length;
	} else {
		off_next_pg_bound_src = pgsz_src - (srcaddr % pgsz_src);
	}
	if (length <= (uint64_t)pgsz_dst &&
	    ROUN_DN(dstaddr, pgsz_dst) == ROUN_DN(dstaddr + length, pgsz_dst)) {
		off_next_pg_bound_dst = length;
	} else {
		off_next_pg_bound_dst = pgsz_dst - (dstaddr % pgsz_dst);
	}

	uint64_t offset = 0;
	int64_t count = 0;
	ve_dma_reqlist_entry *e_last = NULL;
	while (offset < length) {
		ve_dma_reqlist_entry *e;
		uint64_t next_bound, e_length;

		if (off_next_pg_bound_src < off_next_pg_bound_dst) {
			next_bound = off_next_pg_bound_src;
			off_next_pg_bound_src += pgsz_src;
		} else if (off_next_pg_bound_src > off_next_pg_bound_dst) {
			next_bound = off_next_pg_bound_dst;
			off_next_pg_bound_dst += pgsz_dst;
		} else {
			next_bound = off_next_pg_bound_src;
			off_next_pg_bound_src += pgsz_src;
			off_next_pg_bound_dst += pgsz_dst;
		}
		e_length = (next_bound < length ? next_bound : length) - offset;
		e = mkrequest(hdl,
			      srctype, srcpid, srcaddr + offset, &vemtlb_src,
			      dsttype, dstpid, dstaddr + offset, &vemtlb_dst,
			      e_length);
		if (e == NULL) {
			VE_DMA_ERROR("mkrequest error (errno = %d). "
				     "request is canceled.", errno);
			ve_dma_reqlist_free(hdl);
			INIT_LIST_HEAD(&hdl->reqlist);
			return -errno;
		}
		VE_DMA_TRACE("request %p is created", e);

		if (e_last != NULL &&
		    addr_cont(&e_last->src, e_last->length, &e->src) &&
		    addr_cont(&e_last->dst, e_last->length, &e->dst) &&
		    ((e_last->length + e->length) <= VE_DMA_DESC_LEN_MAX)) {
			/* Merged. Extend e_last and delete e. */
			e_last->length += e->length;
			offset += e_length;
			/*
			 * When the address of e is not aligned with the page
			 * size, e accesses the same page with e_last. In that
			 * case, unpin is needed because the page is already
			 * pinned by e_last.
			 */
			if (!IS_ALIGNED(e->src.addr, e->src.unpin_pgsz)) {
				unpin_ve_dma__addr(vh, &e->src, 1);
			}
			if (!IS_ALIGNED(e->dst.addr, e->dst.unpin_pgsz)) {
				unpin_ve_dma__addr(vh, &e->dst, 1);
			}
			free(e);
		} else {
			/* Not merged. Add a new reqlist entry. */
			list_add_tail(&e->list, &hdl->reqlist);
			e_last = e;
			offset += e_length;
			++count;
		}
	}
	VE_DMA_TRACE("returns %ld", count);
	return count;
}

/**
 * @brief Unpin used page
 *
 * @param vh VEDL handle
 * @param dadr unpin address
 * @param length unpin length
 */
static void unpin_ve_dma__addr(vedl_handle *vh, const ve_dma__addr *dadr,
			       uint32_t length)
{
	uint64_t unpin_addr;
	if (dadr->unpin) {
		unpin_addr = ROUN_DN(dadr->addr, dadr->unpin_pgsz);
		while (unpin_addr < (dadr->addr + length)) {
			dadr->unpin(vh, unpin_addr);
			unpin_addr += dadr->unpin_pgsz;
		}
	}
}

/**
 * @brief Free a DMA request handle
 *
 * @param hdl DMA request handle
 */
void ve_dma_reqlist_free(ve_dma_req_hdl *hdl)
{
	VE_DMA_TRACE("called (%p)", hdl);
	struct list_head *lh;
	struct list_head *tmp;
	vedl_handle *vh = hdl->engine->vedl_handle;
	list_for_each_safe(lh, tmp, &hdl->reqlist) {
		list_del(lh);
		ve_dma_reqlist_entry *e;
		e = list_entry(lh, ve_dma_reqlist_entry, list);
		unpin_ve_dma__addr(vh, &e->src, e->length);
		unpin_ve_dma__addr(vh, &e->dst, e->length);
		free(e);
	}
}

/**
 * @brief Test status of all DMA reqlist entries in a DMA request
 *
 * @param[in,out] hdl DMA request handle
 *
 * @return status of DMA request.
 */
ve_dma_status_t ve_dma_reqlist_test(ve_dma_req_hdl *hdl)
{
	ve_dma_status_t ret = VE_DMA_STATUS_OK;
	VE_DMA_TRACE("called (%p)", hdl);
	int found_error = 0;
	int found_canceled = 0;
	int found_ongoing = 0;

	struct list_head *p;
	list_for_each(p, &hdl->reqlist) {
		ve_dma_reqlist_entry *e;
		e = list_entry(p, ve_dma_reqlist_entry, list);
		switch (e->status) {
		case VE_DMA_ENTRY_NOT_POSTED:
		case VE_DMA_ENTRY_ONGOING:
			VE_DMA_TRACE("request %p is still ongoing.", e);
			found_ongoing = 1;
			continue;
		case VE_DMA_ENTRY_COMPLETED:
			/* OK. it is unnecessary to change ret. */
			VE_DMA_TRACE("request %p is completed.", e);
			continue;
		case VE_DMA_ENTRY_ERROR:
			VE_DMA_TRACE("request %p caused error.", e);
			found_error = 1;
			continue;
		case VE_DMA_ENTRY_CANCELED:
			VE_DMA_TRACE("request %p is canceled.", e);
			found_canceled = 1;
			continue;
		default:
			VE_DMA_CRIT("request %p is in "
				    "unexpected status %d.", e, e->status);
			continue;
		}
	}
	if (found_error) {
		ret = VE_DMA_STATUS_ERROR;
	} else if (found_canceled) {
		ret = VE_DMA_STATUS_CANCELED;
	} else if (found_ongoing) {
		ret = VE_DMA_STATUS_NOT_FINISHED;
	}
	VE_DMA_TRACE("returns %d", ret);
	return ret;
}

/**
 * @brief Post a DMA reqlist entry on a free DMA descriptor
 *
 * @param[in,out] e DMA reqlist entry
 *
 * @return 0 on success. Non-zero on failure.
 *         When no free descriptors available remain, return -EBUSY.
 *         If an error occurs, return neither 0 nor -EBUSY.
 *
 */
int ve_dma_reqlist__entry_post(ve_dma_reqlist_entry *e)
{
	ve_dma_hdl *hdl;
	int entry;
	int ret;
	int is_last;
	VE_DMA_TRACE("called (%p)", e);

	hdl = e->req_head->engine;
	if (hdl->should_stop) {
		VE_DMA_ERROR("DMA engine is now closing");
		return -ENXIO;
	}

	VE_DMA_TRACE("%d entries are used", hdl->desc_num_used);
	if (hdl->desc_num_used >= (VE_DMA_NUM_DESC - 1)) {
		VE_DMA_TRACE("DMA descriptor is full");
		return -EBUSY;
	}
	entry = (hdl->desc_used_begin + hdl->desc_num_used) % VE_DMA_NUM_DESC;
	VE_DMA_TRACE("DMA request %p is posted as entry %d", e, entry);
	hdl->req_entry[entry] = e;
	e->entry = entry;

	is_last = (e->req_head->reqlist.prev == &e->list);

	ret = ve_dma_hw_post_dma(hdl->vedl_handle, hdl->control_regs, entry,
				 e->src.type_hw, e->src.addr, e->dst.type_hw,
				 e->dst.addr, e->length, is_last);

	if (ret != 0) {
		VE_DMA_ERROR("DMA post error (entry = %d, request = %p)",
			     entry, e);
		/* cancel this entry */
		e->entry = -1;
		hdl->req_entry[entry] = NULL;
	} else {
		e->status = VE_DMA_ENTRY_ONGOING;
		++hdl->desc_num_used;
	}

	return ret;
}

/**
 * @brief Post DMA requests
 *
 * @param[in] req DMA request handle
 *
 * @return 0 on success, Non-zero on failure.
 */
int ve_dma_reqlist_post(ve_dma_req_hdl *req)
{
	/*
	 * note: a caller shall hold req->engine->mutex.
	 */
	struct list_head *p;
	int rv = 0;
	VE_DMA_TRACE("called (%p)", req);
	list_for_each(p, &req->reqlist) {
		struct ve_dma_reqlist_entry *e;
		e = list_entry(p, ve_dma_reqlist_entry, list);
		rv = ve_dma_reqlist__entry_post(e);
		if (rv < 0) {
			if (rv != -EBUSY)
				VE_DMA_ERROR("DMA request %p post error (%d).",
					     e, rv);
			break;
		}
	}
	if (rv == -EBUSY) {
		ve_dma_hdl *hdl = req->engine;
		VE_DMA_TRACE("Unposted reqlist entries are added to "
			     "waiting_list.");
		for (; p != &req->reqlist; p = p->next) {
			struct ve_dma_reqlist_entry *e;
			e = list_entry(p, ve_dma_reqlist_entry, list);
			list_add_tail(&e->waiting_list, &hdl->waiting_list);
		}
		rv = 0;
	}
	return rv;
}

/**
 * @brief Remove DMA request from request queue and post on free descriptors
 *
 * @param[in,out] hdl DMA handle
 *
 * @return the number of DMA requests posted. Negative value on failure.
 */
int ve_dma_reqlist_drain_waiting_list(ve_dma_hdl *hdl)
{
	int posted = 0;
	struct list_head *p, *tmp;
	VE_DMA_TRACE("called");
	list_for_each_safe(p, tmp, &hdl->waiting_list) {
		int ret;
		ve_dma_reqlist_entry *e;
		e = list_entry(p, ve_dma_reqlist_entry, waiting_list);
		VE_DMA_TRACE("Post DMA request %p from the wait queue", e);
		ret = ve_dma_reqlist__entry_post(e);
		if (ret == 0) {
			list_del(p);
			++posted;
		} else if (ret == -EBUSY) {
			/* DMA descriptor is full */
			VE_DMA_TRACE("DMA descriptor is full. "
				     "%d requests posted", posted);
			return posted;
		} else {
			VE_DMA_ERROR("Error on posting DMA request "
				     "%p (%d)", e, ret);
			return -1;
		}
	}
	VE_DMA_TRACE("%d requests posted.", posted);
	return posted;
}

/**
 * @brief Free DMA descriptor between desc_used_begin and readptr
 *
 * @param[in,out] dh DMA handle
 * @param readptr Read pointer value of DMA control register
 */
void ve_dma_free_used_desc(ve_dma_hdl *dh, int readptr)
{
	while (dh->req_entry[dh->desc_used_begin] == NULL &&
	       dh->desc_num_used > 0 &&
	       dh->desc_used_begin != readptr) {
		VE_DMA_TRACE("DMA descriptor #%d is freed.",
			     dh->desc_used_begin);
		--dh->desc_num_used;
		++dh->desc_used_begin;
		if (dh->desc_used_begin == VE_DMA_NUM_DESC)
			dh->desc_used_begin = 0;
	}
}

/**
 * @brief Finish a DMA request specified by DMA reqlist entry
 *
 *        Finish a DMA reqlist entry, updating its status, and DMA handle.
 *        After this function, desc_num_used and desc_used_begin in
 *        DMA handle can be updated.
 *
 * @param[in,out] e DMA reqlist entry
 * @param status Word 0 in the corresponding DMA descriptor
 * @param readptr Read pointer value of DMA control register
 */
void ve_dma_finish_reqlist_entry(ve_dma_reqlist_entry *e, uint64_t status,
				 int readptr)
{
	/* note: a caller shall hold dh->mutex */
	int entry = e->entry;
	ve_dma_hdl *dh = e->req_head->engine;
	VE_DMA_TRACE("called");
	VE_DMA_TRACE("request %p (on #%d): status = 0x%lx", e, entry, status);
	e->status_hw = status;
	if (status & VE_DMA_DESC_EXCEPTION_MASK) {
		e->status = VE_DMA_ENTRY_ERROR;
	} else if (status & VE_DMA_DESC_STATUS_COMPLETED) {
		e->status = VE_DMA_ENTRY_COMPLETED;
	} else {
		e->status = VE_DMA_ENTRY_CANCELED;
	}
	VE_DMA_TRACE("Status of request %p <- %d", e, e->status);
	e->entry = -1;
	dh->req_entry[entry] = NULL;
	VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
		     dh->desc_used_begin, dh->desc_num_used);
	ve_dma_free_used_desc(dh, readptr);
	VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
		     dh->desc_used_begin, dh->desc_num_used);
}

/**
 * @brief Cancel a DMA request
 *
 *        Remove correspond DMA reqlist entries from wait queue,
 *        and also cancel DMA requests on DMA descriptors.
 *
 * @param[in,out] req DMA request handle
 */
void ve_dma_reqlist__cancel(ve_dma_req_hdl *req)
{
	/*
	 * note: a caller shall hold req->engine->mutex and
	 *  the DMA engine shall be stopped.
	 */
	struct list_head *p, *tmp;
	ve_dma_hdl *hdl = req->engine;

	VE_DMA_TRACE("called");
	int readptr;
	readptr = ve_dma_hw_get_readptr(hdl->vedl_handle, hdl->control_regs);

	/* similar to ve_dma_reqlist_test with a little difference */
	list_for_each_safe(p, tmp, &req->reqlist) {
		ve_dma_reqlist_entry *e;

		e = list_entry(p, ve_dma_reqlist_entry, list);
		if (e->status < VE_DMA_ENTRY_ONGOING) {
			VE_DMA_TRACE("request %p is not posted yet.", e);
			list_del(&e->waiting_list);
			e->status = VE_DMA_ENTRY_CANCELED;
		} else if (e->status == VE_DMA_ENTRY_ONGOING) {
			/* already posted: cancel it. */
			VE_DMA_TRACE("request %p is on descriptor #%d",
				     e, e->entry);
			if (e->entry < 0 || e->entry >= VE_DMA_NUM_DESC) {
				VE_DMA_CRIT("descriptor #%d is invalid",
					    e->entry);
				return;
			}
			uint64_t status_hw;
			status_hw = ve_dma_hw_desc_status(hdl->vedl_handle,
							  hdl->control_regs,
							  e->entry);
			if (status_hw & VE_DMA_DESC_STATUS_PREPARED) {
				ve_dma_hw_nullify_dma(hdl->vedl_handle,
					hdl->control_regs, e->entry);
			}
			ve_dma_finish_reqlist_entry(e, status_hw, readptr);
		} else {
			VE_DMA_TRACE("request %p has been already finished "
				     "(status = %d).", e, e->status);
		}
	}
}

/**
 * @brief Get DMA request handle which includes a specified DMA reqlist entry
 *
 * @param[in] e DMA reqlist entry
 *
 * @return DMA request handle
 */
ve_dma_req_hdl *ve_dma_reqlist_entry_to_req_hdl(ve_dma_reqlist_entry *e)
{
	return e->req_head;
}

/**
 * @brief Get DMA request handle from list head.
 *
 * @param[in] lh list_head embedded in ve_dma_reqlist_entry
 *
 * @return DMA request handle including the DMA reqlist entry.
 */
ve_dma_req_hdl *ve_dma_waiting_list_head_to_req_hdl(const struct list_head *lh)
{
	ve_dma_reqlist_entry *e;
	e = list_entry(lh, ve_dma_reqlist_entry, waiting_list);
	return ve_dma_reqlist_entry_to_req_hdl(e);
}
