/*
 * Copyright (C) 2017-2020 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
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
#include <veos_arch_defs.h>
#include <align.h>
#include <poll.h>
#include "dma.h"
#include "dma_private.h"
#include "dma_hw.h"
#include "dma_reqlist.h"
#include "dma_reqlist_private.h"
#include "dma_log.h"
#include "vesync.h"
#include "amm_api.h"
#include "ve_atomic.h"

#define MIN(a, b) ((a) <= (b) ? (a) : (b))
#define DMABLK 64
#define MAXBLK_PAGES 100

static void unpin_ve(vedl_handle *h, uint64_t paddr);
static int ve_dma_post_start(ve_dma_req_hdl *req); 

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
	default:
		return (*_veos_arch_ops->arch_dma_addrtype_to_pagesize)(t);
	}
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
 * @brief Unpin VH pages of a block
 *
 * @param h VEDL handle
 * @param paddr array of addresses (VHSAA)
 * @param naddr number of addresses
 */
static void unpin_vh_block(vedl_handle *h, ve_dma__block *blk)
{
	int err;
	VE_DMA_TRACE("called (blk start va=%p length=%lu)",
		     (void *)blk->vaddr, blk->length);
	err = vedl_release_pindown_page_blk(h, blk->paddr, blk->npages);
	if (err < 0) {
		VE_DMA_ERROR("VH bulk page unpin failed. (va=%lx, errno=%d)",
			     blk->vaddr, errno);
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
 * @brief unpin VE page
 *
 * @param h VEDL handle (ignored)
 * @param blk block pointer
 */
static void unpin_ve_block(vedl_handle *h, ve_dma__block *blk)
{
	int i, err;
	VE_DMA_TRACE("called (block va=%p)", (void *)blk->vaddr);
	for (i = 0; i < blk->npages; i++) {
		err = veos_put_page(blk->paddr[i]);
		if (err < 0) {
			VE_DMA_ERROR("VE page unpin failed. (addr=%lx, errno=%d)",
				     blk->paddr[i], -err);
		}
	}
}

/**
 * @brief Free VE DMA Block
 *
 * @param h VEDL handle (ignored)
 * @param blk block pointer
 */
void ve_dma__block_free(vedl_handle *vh, ve_dma__block *blk)
{
	VE_DMA_TRACE("freeing block va=%p len=%lu", (void *)blk->vaddr, blk->length);
	if (blk->unpin){
		blk->unpin(vh, blk);
		blk->unpin = NULL;
	}
	free(blk->paddr);
	free(blk);
}

static inline int addr_type_hw(ve_dma_addrtype_t t)
{
	return _veos_arch_ops->arch_dma_addrtype_to_hwtype(t);
}

/**
 * @brief translate virtual addresses to physical addresses for DMA descriptor
 *
 * @param vh VEDL handle
 * @param pid process ID.
 *        If address type is physical (VEMAA, VERAA or VHSAA), pid is ignored.
 * @param t address type
 * @param vaddr array of addresses to be translated
 * @param naddr number of addresses to be translated
 * @param[out] addr array with physical addresses on output
 * @param wr Check the page writable.
 * @param vemtlb TLB for VEMVA address translation
 *
 * @return 0 on success. Non-zero on failure.
 */
static ve_dma__block *
trans_addr_pin_blk(vedl_handle *vh, pid_t pid, ve_dma_addrtype_t t,
		   uint64_t vaddr, uint64_t length, int *error,
		   int wr, struct ve_dma_vemtlb *vemtlb)
{
	int err = -EINVAL;
	uint32_t maxpages = MAXBLK_PAGES;
	uint64_t va, offs = 0UL;
	ve_dma__block *blk = malloc(sizeof(ve_dma__block));

	VE_DMA_TRACE("called (pid=%d, addrtype=%d, addr=%p len=%lu)",
		     (int)pid, t, (void *)vaddr, length);
	if (!blk) {
		VE_DMA_ERROR("no memory for dma block!?");
		*error = -ENOMEM;
		return NULL;
	}
	blk->vaddr = vaddr;
	blk->length = length;
	blk->npages = 0;
	blk->paddr = NULL;
	blk->unpin = NULL;
	blk->type = t;
	INIT_LIST_HEAD(&blk->list);
	switch (t) {
	case VE_DMA_VHVA: /* obsolete, done above */
		VE_DMA_TRACE("addr type is VHVA (pid=%d, vaddr=%p)",
			     (int)pid, (void *)vaddr);
		blk->unpin = unpin_vh_block;
		blk->paddr = malloc(MAXBLK_PAGES * sizeof(uint64_t));
		if (!blk->paddr) {
			VE_DMA_ERROR("failed to allocate blk->paddr");
			err = -ENOMEM;
			break;
		}
		err = vedl_get_addr_pin_blk(vh, pid, vaddr, &blk->length,
					    blk->paddr, maxpages,
					    &blk->npages, &blk->pgsz, 1, wr);
		VE_DMA_DEBUG("VHVA translation received: vaddr=%p len=%lu npages=%d pgsize=%d errno(%s)",
			     (void *)blk->vaddr, blk->length, blk->npages, blk->pgsz, strerror(errno));
		if (err != 0 && errno != 0)
			err = -errno;
		break;
	case VE_DMA_VEMAA:
	case VE_DMA_VHSAA:
		blk->unpin = NULL;
		blk->pgsz = addrtype_to_pagesize(t);
		blk->paddr = NULL; /* special, it means addr[i] = vaddr[i] */
		err = 0;
		break;
	case VE_DMA_VEMVA:
		VE_DMA_TRACE("addr type is VEMVA (pid = %d, vaddr = 0x%016lx",
			     (int)pid, vaddr);
		blk->unpin = unpin_ve_block;
		blk->pgsz = addrtype_to_pagesize(t);
		maxpages = length / blk->pgsz + 2;
		blk->paddr = malloc(maxpages * sizeof(uint64_t));
		if (!blk->paddr) {
			VE_DMA_ERROR("failed to allocate blk->paddr");
			err = -ENOMEM;
			break;
		}
		va = vaddr & ~(blk->pgsz - 1); /* page align */
		while (va + offs < vaddr + length) {
			err = dma_vemva_to_vemaa(pid, va + offs,
						 &blk->paddr[blk->npages],
						 wr, vemtlb);
			if (err)
				break;
			blk->npages++;
			offs += blk->pgsz;
		}
		break;
	case VE_DMA_VEMVA_WO_PROT_CHECK:
		VE_DMA_TRACE("addr type is VEMVA(WO_PROT_CHECK) "
			     "(pid = %d, vaddr = 0x%016lx",
			     (int)pid, vaddr);
		blk->unpin = unpin_ve_block;
		blk->pgsz = addrtype_to_pagesize(t);
		maxpages = length / blk->pgsz + 2;
		blk->paddr = malloc(maxpages * sizeof(uint64_t));
		if (!blk->paddr) {
			VE_DMA_ERROR("failed to allocate blk->paddr");
			err = -ENOMEM;
			break;
		}
		va = vaddr & ~(blk->pgsz - 1); /* page align */
		while (va + offs < vaddr + length) {
			err = dma_vemva_to_vemaa(pid, va + offs,
						 &blk->paddr[blk->npages],
						 0, vemtlb);
			if (err)
				break;
			blk->npages++;
			offs += blk->pgsz;
		}
		break;
	default:
		err = (*_veos_arch_ops->arch_dma_pin_blk)(vh, pid, t, wr, blk);
	}
	if (err) {
		VE_DMA_ERROR("translate error: vaddr =%p errno(%s)", (void *)blk->vaddr, strerror(-err));
		ve_dma__block_free(vh, blk);
		blk = NULL;
	}
	*error = err;
	return blk;
}

static uint64_t trans_addr_to_dma(uint64_t vaddr, ve_dma__block *blk)
{
	uint64_t indx;

	if (blk->paddr == NULL)
		return vaddr;
	indx = (vaddr - ROUND_DN(blk->vaddr, blk->pgsz)) / blk->pgsz;
	if (indx >= blk->npages) {
		VE_DMA_ERROR("va %p not in block! Good luck...", (void *)vaddr);
		VE_DMA_ERROR("blk vaddr=%p len=%lu", (void *)blk->vaddr, blk->length);
	}
	return blk->paddr[indx] + (vaddr % blk->pgsz);
}
/**
 * @brief add ve_dma_req_hdl for list of pin waiting request in ve_dma_hdl.
 */
static void add_pin_waiting_list(ve_dma_req_hdl *req_hdl,
			ve_dma_addrtype_t srctype, pid_t srcpid, uint64_t srcaddr, ve_dma__block *src_blk,
			ve_dma_addrtype_t dsttype, pid_t dstpid, uint64_t dstaddr, ve_dma__block *dst_blk,
			uint64_t length, uint64_t opt, int vh_sock_fd)
{
	ve_dma_hdl *hdl = req_hdl->engine;

	req_hdl->waiting_src.type = srctype;
	req_hdl->waiting_src.pid = srcpid;
	req_hdl->waiting_src.addr = srcaddr;
	req_hdl->waiting_dst.type = dsttype;
	req_hdl->waiting_dst.pid = dstpid;
	req_hdl->waiting_dst.addr = dstaddr;
	req_hdl->src_blk = src_blk;
	req_hdl->dst_blk = dst_blk;
	req_hdl->length = length;
	req_hdl->opt = opt;
	req_hdl->vh_sock_fd = vh_sock_fd;

	pthread_mutex_lock(&hdl->pin_wait_list_mutex);
	list_add_tail(&req_hdl->pin_waiting_list, &hdl->pin_waiting_request);
	pthread_cond_signal(&hdl->pin_wait_list_cond);
	pthread_mutex_unlock(&hdl->pin_wait_list_mutex);
}

/**
 * @brief Check a connection to the target OS
 */
static int check_socket(int vh_sock_fd)
{
	int test_socket = 0, pollval;
	struct pollfd pollfd;

	pollfd.fd = vh_sock_fd;
	pollfd.events  = POLLRDHUP;
	pollfd.revents = 0;

	pollval = poll(&pollfd, 1, 0);

	if (pollval == 0){
		/* timeout and no events */
		test_socket = 0;
	} else if (pollval < 0){
		VE_DMA_ERROR("socket test failed %s", strerror(errno));
		test_socket = -1;
	} else if (pollval > 0){
		if (pollfd.revents & POLLNVAL){
			VE_DMA_DEBUG("socket test: Socket not open");
			test_socket = -1;
		}
		if (pollfd.revents & POLLERR){
			VE_DMA_ERROR("socket test: Error condition");
			test_socket = -1;
		}
		if (pollfd.revents & (POLLRDHUP | POLLHUP)){
			test_socket = -1;
		}
	}
	return test_socket;
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
 * @return 1: All of DMA request entries are posted. success.
 *         0: BLOCK_LIMIT. a lot of VHVA block is used. dma request is postporned. success.
 *         -1: error.
 */
int64_t ve_dma_reqlist_make(ve_dma_req_hdl *hdl,
			      ve_dma_addrtype_t srctype, pid_t srcpid,
			      uint64_t srcaddr, ve_dma__block *src_block,
			      ve_dma_addrtype_t dsttype, pid_t dstpid,
			      uint64_t dstaddr, ve_dma__block *dst_block,
			      uint64_t length, uint64_t opt, int vh_sock_fd)
{
	VE_DMA_TRACE("called (src: type = %d, pid = %d, addr = 0x%016lx; "
		     "dst: type = %d, pid = %d, addr = 0x%016lx; "
		     "length = 0x%lx)",
		     srctype, srcpid, srcaddr, dsttype, dstpid, dstaddr,
		     length);

	VE_DMA_ASSERT(((opt & VE_DMA_OPT_SYNC_API) == 0)
		      || list_empty(&hdl->reqlist));

	ve_dma_hdl *dma_hdl = hdl->engine; 
	vedl_handle *vh = dma_hdl->vedl_handle;
	struct ve_dma_vemtlb vemtlb_src = { .vaddr = (uint64_t)NULL };
	struct ve_dma_vemtlb vemtlb_dst = { .vaddr = (uint64_t)NULL };
	uint64_t offset = 0;
	int64_t count = 0;
	int err = 0, ret = 0;
	int src_type_hw, dst_type_hw;
	int32_t pgsz_src, pgsz_dst;
	uint64_t next_vsrc = srcaddr, next_vdst = dstaddr;
	ve_dma__block *src_blk = src_block, *dst_blk = dst_block;
	struct list_head local_reqlist; 
	struct list_head *lh, *tmp;
	struct ve_dma_reqlist_entry *lh_e, *tmp_e; 
	int vhblk_count = 0;

	if (length == 0) {
		VE_DMA_ERROR("Invalid value, length = 0");
		return -1;
	}

	INIT_LIST_HEAD(&local_reqlist);

	if ((opt & VE_DMA_OPT_SYNC_API) == 0) {
		if ((srctype == VE_DMA_VHVA) && (src_blk == NULL))
			vhblk_count++;
		if ((dsttype == VE_DMA_VHVA) && (dst_blk == NULL))
			vhblk_count++;

		/*check the number of used block*/
		if (VE_ATOMIC_FETCH_ADD(int, &dma_hdl->blk_count, vhblk_count) + vhblk_count > BLOCK_LIMIT) {
			VE_ATOMIC_FETCH_SUB(int, &dma_hdl->blk_count, vhblk_count);
			add_pin_waiting_list(hdl,
					srctype, srcpid, srcaddr, src_blk,
					dsttype, dstpid, dstaddr, dst_blk,
					length,	opt, vh_sock_fd);
			VE_DMA_DEBUG("blk limit. blk_count %d", dma_hdl->blk_count);
			return 0;
		}
		/*count the pin downed VHVA block*/
		VE_DMA_DEBUG("blk_count %d", dma_hdl->blk_count);
	}
	if (!src_blk) {
		src_blk = trans_addr_pin_blk(vh, srcpid, srctype, srcaddr,
					length, &err, 0, &vemtlb_src);
		if (!src_blk) {
			VE_ATOMIC_FETCH_SUB(int, &dma_hdl->blk_count, vhblk_count);
			VE_DMA_ERROR("pin failed, blk_count %d", dma_hdl->blk_count);
			goto err_with_nolock;
		}
		if (((opt & VE_DMA_OPT_SYNC_API) != 0) || (srctype != VE_DMA_VHVA))
			list_add_tail(&src_blk->list, &hdl->ptrans_src);
	}
	pgsz_src = src_blk->pgsz;
	next_vsrc = src_blk->vaddr + src_blk->length;
	if (!dst_blk) {
		dst_blk = trans_addr_pin_blk(vh, dstpid, dsttype, dstaddr,
					length,	&err, 1, &vemtlb_dst);
		if (!dst_blk) {
			if (((opt & VE_DMA_OPT_SYNC_API) == 0) && (dsttype == VE_DMA_VHVA))
				ve_atomic_dec(&dma_hdl->blk_count);
			VE_DMA_ERROR("pin failed, blk_count %d", dma_hdl->blk_count);
			goto err_with_nolock;
		}
		if (((opt & VE_DMA_OPT_SYNC_API) != 0) || (dsttype != VE_DMA_VHVA))
			list_add_tail(&dst_blk->list, &hdl->ptrans_dst);
	}
	pgsz_dst = dst_blk->pgsz;
	next_vdst = dst_blk->vaddr + dst_blk->length;

	VE_DMA_TRACE("src page size = 0x%x, dst page size = 0x%x",
		 (unsigned int)pgsz_src, (unsigned int)pgsz_dst);

	/* the offset of the next page boundary */
	uint64_t off_next_pg_bound_src, off_next_pg_bound_dst;
	off_next_pg_bound_src = pgsz_src - (srcaddr % pgsz_src);
	off_next_pg_bound_dst = pgsz_dst - (dstaddr % pgsz_dst);

	src_type_hw = addr_type_hw(srctype);
	dst_type_hw = addr_type_hw(dsttype);

	while (offset < length) {
		ve_dma_reqlist_entry *e = NULL;

		if ((opt & VE_DMA_OPT_SYNC_API) == 0) {
			vhblk_count = 0;
			if ((srctype == VE_DMA_VHVA) && (srcaddr + offset >= next_vsrc))
				vhblk_count++;
			if ((dsttype == VE_DMA_VHVA) && (dstaddr + offset >= next_vdst))
				vhblk_count++;

			/*check the number of used block*/
			if (VE_ATOMIC_FETCH_ADD(int, &dma_hdl->blk_count, vhblk_count) + vhblk_count > BLOCK_LIMIT) {
				VE_ATOMIC_FETCH_SUB(int, &dma_hdl->blk_count, vhblk_count);
				if (srcaddr + offset >= next_vsrc)
					src_blk = NULL;
				if (dstaddr + offset >= next_vdst)
					dst_blk = NULL;
				add_pin_waiting_list(hdl,
					srctype, srcpid, srcaddr + offset, src_blk,
					dsttype, dstpid, dstaddr + offset, dst_blk,
					length - offset, opt, vh_sock_fd);
				VE_DMA_DEBUG("blk limit. blk_count %d", dma_hdl->blk_count);
				return 0;
			}
			/*count the pin downed VHVA block*/
			VE_DMA_DEBUG("blk_count %d", dma_hdl->blk_count);
		}

		if (srcaddr + offset >= next_vsrc) {
			src_blk =
				trans_addr_pin_blk(vh, srcpid, srctype, next_vsrc,
						length - next_vsrc + srcaddr,
						&err, 0, &vemtlb_src);
			if (!src_blk) {
				VE_ATOMIC_FETCH_SUB(int, &dma_hdl->blk_count, vhblk_count);
				VE_DMA_ERROR("pin failed, blk_count %d", dma_hdl->blk_count);
				goto err_with_nolock;
			}
			pgsz_src = src_blk->pgsz;
			next_vsrc = src_blk->vaddr + src_blk->length;
			/*count the pin downed VHVA block*/
			if (((opt & VE_DMA_OPT_SYNC_API) != 0) || (srctype != VE_DMA_VHVA))
				list_add_tail(&src_blk->list, &hdl->ptrans_src);
		}

		if (dstaddr + offset >= next_vdst) {
			dst_blk =
				trans_addr_pin_blk(vh, dstpid, dsttype, next_vdst,
						length - next_vdst + dstaddr,
						&err, 1, &vemtlb_dst);
			if (!dst_blk) {
				if (((opt & VE_DMA_OPT_SYNC_API) == 0) && (dsttype == VE_DMA_VHVA))
					ve_atomic_dec(&dma_hdl->blk_count);
				VE_DMA_ERROR("pin failed, blk_count %d", dma_hdl->blk_count);
				goto err_with_nolock;
			}
			pgsz_dst = dst_blk->pgsz;
			next_vdst = dst_blk->vaddr + dst_blk->length;
			/*count the pin downed VHVA block*/
			if (((opt & VE_DMA_OPT_SYNC_API) != 0) || (dsttype != VE_DMA_VHVA))
				list_add_tail(&dst_blk->list, &hdl->ptrans_dst);
		}

		if (vh_sock_fd != -1) {
			ret = check_socket(vh_sock_fd);
			if (ret == -1)
				goto err_with_nolock;
		}

		int naddr = 0;
		while (naddr < DMABLK && offset < length &&
		       srcaddr + offset < next_vsrc &&
		       dstaddr + offset < next_vdst) {
			uint64_t next_bound, e_length;
			uint64_t src_phys, dst_phys;

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
			e_length = MIN(next_bound, length) - offset;
			//
			// translate addresses
			//
			src_phys = trans_addr_to_dma(srcaddr + offset, src_blk);
			dst_phys = trans_addr_to_dma(dstaddr + offset, dst_blk);

			//
			// create DMA request
			//
			
			if ((e != NULL) &&
				(*_veos_arch_ops->arch_dma_request_mergeable)(
					e, src_phys, dst_phys, e_length)) {
				/* Merged. Extend e. */
				e->length += e_length;
				VE_DMA_DEBUG("req merged. length=%d", e->length);
			} else {
				/* Not merged. Add a new reqlist entry. */
				e = malloc(sizeof(ve_dma_reqlist_entry));
				if (e == NULL) {
					VE_DMA_ERROR("malloc for reqlist entry failed");
					errno = ENOMEM;
					goto err_malloc;
				}
				e->src.type_hw = src_type_hw;
				e->src.addr = src_phys;
				e->dst.type_hw = dst_type_hw;
				e->dst.addr = dst_phys;
				e->length = e_length;
				e->entry = -1;
				e->status_hw = 0;
				e->status = VE_DMA_ENTRY_NOT_POSTED;
				e->req_head = hdl;
				e->opt = opt;
				e->last = 0;
				e->src_block = NULL;
				e->dst_block = NULL;
				INIT_LIST_HEAD(&e->list);
				INIT_LIST_HEAD(&e->waiting_list);
				VE_DMA_TRACE("request %p is created", e);
				VE_DMA_DEBUG("req created: vasrc=%p vadst=%p pasrc=%p padst=%p",
						(void *)(srcaddr + offset),
						(void *)(dstaddr + offset),
						(void *)src_phys, (void *)dst_phys);
				list_add_tail(&e->list, &local_reqlist);
				++count;
			}
			offset += e_length;
			if (offset >= length)
				e->last = 1;
			naddr++;

		}

		if ((opt & VE_DMA_OPT_SYNC_API) == 0) {
			if ((srctype == VE_DMA_VHVA) && (srcaddr + offset >= next_vsrc)) {
				e->src_block = src_blk;
				src_blk = NULL;
			}
			if ((dsttype == VE_DMA_VHVA) && (dstaddr + offset >= next_vdst)) {
				e->dst_block = dst_blk;
				dst_blk = NULL;
			}
		}

		pthread_mutex_lock(&dma_hdl->mutex);
		/*
		 * Accessing hdl->cancel is safe.
		 * * When an upper layer calls ve_dma_reqlist_make(),
		 *   the caller can not call ve_dma_req_free().
		 * * When the interrupt helper calls
		 *   ve_dma_reqlist_make(), an upper layer does not
		 *   call ve_dma_req_free() until ve_dma_reqlist_make()
		 *   set posting to 0.
		 */
		if (hdl->cancel) {
			/*
			 * The interrupt helper cancels the request
			 * when an exception occurs.
			 * In this case, the entries already posted
			 * have been canceled. All blockes referenced
			 * by entries have been freed.
			 * So, we free entries we allocated. We free
			 * blockes we allocated.
			 */
			list_for_each_entry_safe(lh_e, tmp_e, &local_reqlist, list){
				if (lh_e->src_block) {
					if (lh_e->src_block->type == VE_DMA_VHVA) {
						ve_atomic_dec(&dma_hdl->blk_count);
						VE_DMA_DEBUG("blk_count %d", dma_hdl->blk_count);
					}
					ve_dma__block_free(vh, lh_e->src_block);
					lh_e->src_block = NULL;
				}
				if (lh_e->dst_block) {
					if (lh_e->dst_block->type == VE_DMA_VHVA) {
						ve_atomic_dec(&dma_hdl->blk_count);
						VE_DMA_DEBUG("blk_count %d", dma_hdl->blk_count);
					}
					ve_dma__block_free(vh, lh_e->dst_block);
					lh_e->dst_block = NULL;
				}
				list_del(&lh_e->list);
				free(lh_e);
			}
			hdl->posting = 0;
			pthread_cond_broadcast(&hdl->cond);
			goto cancel;
		}
		list_for_each_safe(lh, tmp, &local_reqlist){
			list_del(lh);
			list_add_tail(lh, &hdl->reqlist);
		}
		err = ve_dma_post_start(hdl);
		if (err)
			goto err_with_lock;
		if (offset >= length)
			hdl->posting = 0;
		pthread_mutex_unlock(&dma_hdl->mutex);
	}

	VE_DMA_TRACE("returns %ld", count);
	return 1;

err_malloc:
	list_for_each_entry_safe(lh_e, tmp_e, &local_reqlist, list){
		list_del(&lh_e->list);
		free(lh_e);
	}
err_with_nolock:
	pthread_mutex_lock(&dma_hdl->mutex);
err_with_lock:
	hdl->posting = 0;
	ve_dma__terminate_nolock(hdl);
	veos_commit_rdawr_order();
cancel:
	pthread_mutex_unlock(&dma_hdl->mutex);
	if ((opt & VE_DMA_OPT_SYNC_API) == 0) {
		vhblk_count = 0;
		if (src_blk && (srctype == VE_DMA_VHVA)){
			ve_dma__block_free(vh, src_blk);
			vhblk_count++;
		}
		if (dst_blk && (dsttype == VE_DMA_VHVA)){
			ve_dma__block_free(vh, dst_blk);
			vhblk_count++;
		}
		VE_ATOMIC_FETCH_SUB(int, &dma_hdl->blk_count, vhblk_count);
		pthread_mutex_lock(&dma_hdl->pin_wait_list_mutex);
		pthread_cond_signal(&dma_hdl->pin_wait_list_cond);
		pthread_mutex_unlock(&dma_hdl->pin_wait_list_mutex);
	}
	return -1;
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
	ve_dma__block *blk;
	vedl_handle *vh = hdl->engine->vedl_handle;

	list_for_each_safe(lh, tmp, &hdl->reqlist) {
		list_del(lh);
		ve_dma_reqlist_entry *e;
		e = list_entry(lh, ve_dma_reqlist_entry, list);
		free(e);
	}
	list_for_each_safe(lh, tmp, &hdl->ptrans_src) {
		list_del(lh);
		blk = list_entry(lh, ve_dma__block, list);
		ve_dma__block_free(vh, blk);
	}
	list_for_each_safe(lh, tmp, &hdl->ptrans_dst) {
		list_del(lh);
		blk = list_entry(lh, ve_dma__block, list);
		ve_dma__block_free(vh, blk);
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

	if (hdl->comp == 0 || hdl->posting != 0)
		return VE_DMA_STATUS_NOT_FINISHED;

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
	if (hdl->comp && found_ongoing)
		veos_abort("DMA request is invalid.");

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

static int ve_dma_reqlist__entry_post(ve_dma_reqlist_entry *e)
{
	return (*_veos_arch_ops->arch_dma_reqlist__entry_post)(e);
}

/**
 * @brief Post DMA requests
 *
 * @param[in] req DMA request handle
 *
 * @return 0 on success, Non-zero on failure.
 */
static int ve_dma_reqlist_post(ve_dma_req_hdl *req)
{
	/*
	 * note: a caller shall hold req->engine->mutex.
	 */
	struct list_head *p;
	int rv = 0;
	ve_dma_hdl *hdl = req->engine;
	struct ve_dma_reqlist_entry *e;
	VE_DMA_TRACE("called (%p)", req);

	if(req->cancel){
		list_for_each(p, &req->reqlist) {
			e = list_entry(p, ve_dma_reqlist_entry, list);
			e->status = VE_DMA_ENTRY_CANCELED;
		}
		return rv;
	}

 	/*If hdl->waiting_list is not empty, do not post.*/
	if(list_empty(&hdl->waiting_list)){
		list_for_each(p, &req->reqlist) {
			e = list_entry(p, ve_dma_reqlist_entry, list);
			if (e->status != VE_DMA_ENTRY_NOT_POSTED)
				continue;
			rv = ve_dma_reqlist__entry_post(e);
			if (rv < 0) {
				if (rv != -EBUSY)
					VE_DMA_ERROR("DMA request %p post error (%d).",
						     e, rv);
				break;
			}
			list_del(&e->waiting_list);
		}
	}else{
		p = req->reqlist.next;
		rv = -EBUSY;
	}
	if (rv == -EBUSY) {
		VE_DMA_TRACE("Unposted reqlist entries are added to "
			     "waiting_list.");
		for (; p != &req->reqlist; p = p->next) {
			e = list_entry(p, ve_dma_reqlist_entry, list);
			// ignore if already enqueued
			if (e->waiting_list.next != &(e->waiting_list))
				continue;
			list_add_tail(&e->waiting_list, &hdl->waiting_list);
			VE_DMA_TRACE("request %p added to waiting_list", e);
		}
		rv = 0;
	}
	return rv;
}

/**
 * @brief post requests from reqlist and start the engine
 *
 * @param[in] req DMA request handle
 *
 * @return 0 on success, Non-zero on failure.
 */
static int ve_dma_post_start(ve_dma_req_hdl *req)
{
	int rv_post = -1;
	ve_dma_hdl *hdl = req->engine;

	/*
	 * post DMA requests
	 */
	if (hdl->should_stop) {
		VE_DMA_ERROR("DMA post failed because DMA engine is now "
			     "closing");
		goto err_post;
	}
	
	rv_post = ve_dma_reqlist_post(req);
	if (rv_post < 0) 
		goto err_post;

	/* start DMA engine */
	ve_dma_hw_start(hdl->control_regs);

err_post:
	veos_commit_rdawr_order();
	return rv_post;
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
	int ret;

	VE_DMA_TRACE("called");

	list_for_each_safe(p, tmp, &hdl->waiting_list) {
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
 * @brief Cancel a DMA request
 *
 *        Remove correspond DMA reqlist entries from wait queue,
 *        and also cancel DMA requests on DMA descriptors.
 *
 * @param[in,out] req DMA request handle
 */
void ve_dma_reqlist__cancel(ve_dma_req_hdl *req)
{
	(*_veos_arch_ops->arch_dma_reqlist_cancel)(req);
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

/**
 * @brief Terminate a DMA request
 *
 * @param req DMA request handle
 *
 * Stop DMA engine, remove descriptors corresponding to the specified
 * request, and restart DMA engine.
 */
void ve_dma__terminate_nolock(ve_dma_req_hdl *req)
{
	ve_dma_hdl *hdl = req->engine;

	VE_DMA_TRACE("called");
	/* stop DMA engine */
	ve_dma__stop_engine(hdl);
	ve_dma_reqlist__cancel(req);

	/* if one or more free descriptors exist, use them. */
	ve_dma_reqlist_drain_waiting_list(hdl);
	/* restart */
	if (hdl->should_stop == 0 && ve_dma_is_busy(hdl))
		ve_dma_hw_start(hdl->control_regs);
	pthread_cond_broadcast(&req->cond);
}

/**
 * @brief Decrement IPC sync in a DMA request
 *
 * @param req DMA request handle
 *
 * Caller of this function needs to acquire DMA handle lock
 * */
void ve_dma__dec_ipc_sync_nolock(ve_dma_req_hdl *req)
{
	struct ve_ipc_sync *ipc_sync=req->ipc_sync;
	if (ipc_sync) {
                req->ipc_sync = NULL;
                pthread_mutex_lock(&(ipc_sync->swap_exclusion_lock));
                ipc_sync->handling_request--;
                VE_DMA_DEBUG("ipc_sync(%p) : handling_request %d",
                                ipc_sync, ipc_sync->handling_request);
                if (ipc_sync->handling_request == 0)
                        pthread_cond_signal(&(ipc_sync->handling_request_cond));
                pthread_mutex_unlock(&(ipc_sync->swap_exclusion_lock));
                ve_put_ipc_sync(ipc_sync);
        }
	return;
}
