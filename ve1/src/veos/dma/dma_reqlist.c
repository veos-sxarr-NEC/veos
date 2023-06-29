/*
 * Copyright (C) 2017-2019 NEC Corporation
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
#include "dma.h"
#include "dma_ve1.h"
#include "dma_private.h"
#include "dma_ve1_private.h"
#include "dma_hw.h"
#include "dma_hw_ve1.h"
#include "dma_reqlist.h"
#include "dma_reqlist_private.h"
#include "dma_reqlist_ve1.h"
#include "dma_log.h"
#include "ve1dma_hw.h"
#include "vesync.h"

#define MIN(a, b) ((a) <= (b) ? (a) : (b))
#define DMABLK 64
#define MAXBLK_PAGES 100


/**
 * @brief page size of a specified type of address space
 *
 * @param t type of address space
 *
 * @return page size on success; negative on failure.
 */
int ve1_dma_addrtype_to_pagesize(ve_dma_addrtype_t t)
{
	VE_DMA_TRACE("%s(%d)", __func__, t);
	switch (t) {
	case VE_DMA_VEMAA:
	case VE_DMA_VHSAA:
	case VE1_DMA_VERAA:
		/*
		 * It is unnecessary to divide when a physical address is used.
		 */
		return VE_DMA_DESC_LEN_MAX;
	default:
		VE_DMA_ERROR("Address type is invalid (%d)", t);
		return -EINVAL;
	}
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_addrtype_to_pagesize, ve1_dma_addrtype_to_pagesize)

int ve1_dma_addrtype_to_hwtype(ve_dma_addrtype_t t)
{
	switch (t) {
	case VE_DMA_VHVA:
	case VE_DMA_VHSAA:
		return VE_DMA_DESC_ADDR_VHSAA;
	case VE_DMA_VEMVA:
	case VE_DMA_VEMVA_WO_PROT_CHECK:
	case VE_DMA_VEMAA:
		return VE_DMA_DESC_ADDR_VEMAA;
	case VE1_DMA_VERAA:
		return VE_DMA_DESC_ADDR_VERAA;
	default:
		veos_abort("unexpected addrtype %d", t);
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_addrtype_to_hwtype, ve1_dma_addrtype_to_hwtype)

/**
 * @brief translate virtual addresses to physical addresses for DMA descriptor
 *
 * @param vh VEDL handle
 * @param pid process ID.
 *        If address type is physical (VEMAA, VERAA or VHSAA), pid is ignored.
 * @param t address type
 * @param wr Check the page writable.
 * @param blk translated and pinned block, set in this function.
 *
 * @return 0 on success. -errno on failure.
 */
int ve1_dma_pin_blk(vedl_handle *vh, pid_t pid, ve_dma_addrtype_t t, int wr,
			struct ve_dma__block *blk)
{
	switch (t) {
	case VE1_DMA_VERAA:
		blk->unpin = NULL;
		blk->pgsz = ve1_dma_addrtype_to_pagesize(t);
		blk->paddr = NULL; /* special, it means addr[i] = vaddr[i] */
		return 0;
		break;
	default:
		VE_DMA_ERROR("Invalid address type: %d", t);
		return -EINVAL;
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_pin_blk, ve1_dma_pin_blk)

/**
 * @brief Determine if next request is mergeable
 *
 * @param e First DMA request
 * @param next_src_phys source physical address of the next request
 * @param next_dst_phys destination physical address of the next request
 * @param next_len length of the next request
 *
 * @return Non-zero if the two requests are mergeable;
 *         zero if the two are not mergeable.
 */
int ve1_dma_request_mergeable(const ve_dma_reqlist_entry *e,
		uint64_t next_src_phys, uint64_t next_dst_phys,
		uint64_t nextlen)
{
	return	e->src.addr + e->length == next_src_phys &&
		e->dst.addr + e->length == next_dst_phys &&
		e->length + nextlen <= VE_DMA_DESC_LEN_MAX;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_request_mergeable, ve1_dma_request_mergeable)

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
int ve1_dma_reqlist__entry_post(ve_dma_reqlist_entry *e)
{
	ve_dma_hdl *hdl;
	int entry;
	int ret;
	int is_last;
	int is_sync, is_ro, is_ido;
	VE_DMA_TRACE("called (%p)", e);

	hdl = e->req_head->engine;
	if (hdl->should_stop) {
		VE_DMA_ERROR("DMA engine is now closing");
		return -ENXIO;
	}

	struct ve1_dma_engine_usage *usage = VE1_DMA_HDL_USAGE(hdl);
	VE_DMA_TRACE("%d entries are used", usage->desc_num_used);
	if (usage->desc_num_used >= (VE1_DMA_NUM_DESC - 1)) {
		VE_DMA_TRACE("DMA descriptor is full");
		return -EBUSY;
	}
	entry = (usage->desc_used_begin + usage->desc_num_used)
			% VE1_DMA_NUM_DESC;
	VE_DMA_TRACE("DMA request %p is posted as entry %d", e, entry);
	usage->req_entry[entry] = e;
	e->entry = entry;
	is_sync = (e->opt && VE_DMA_OPT_SYNC);
        is_ro   = (e->opt && VE_DMA_OPT_RO);
        is_ido  = (e->opt && VE_DMA_OPT_IDO);


	is_last = (e->req_head->reqlist.prev == &e->list);

	ret = ve1_dma_hw_post_dma(hdl->vedl_handle, hdl->control_regs, entry,
				 e->src.type_hw, e->src.addr, e->dst.type_hw,
				 e->dst.addr, e->length, is_last && is_sync,
				 is_ro, is_ido);

	if (ret != 0) {
		VE_DMA_ERROR("DMA post error (entry = %d, request = %p)",
			     entry, e);
		/* cancel this entry */
		e->entry = -1;
		usage->req_entry[entry] = NULL;
	} else {
		e->status = VE_DMA_ENTRY_ONGOING;
		++usage->desc_num_used;
	}

	return ret;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_reqlist__entry_post, ve1_dma_reqlist__entry_post)

/**
 * @brief Free DMA descriptor between desc_used_begin and readptr
 *
 * @param[in,out] dh DMA handle
 * @param readptr Read pointer value of DMA control register
 */
void ve1_dma_free_used_desc(ve_dma_hdl *hdl, int readptr)
{
	struct ve1_dma_engine_usage *u = VE1_DMA_HDL_USAGE(hdl);
	while (u->req_entry[u->desc_used_begin] == NULL &&
	       u->desc_num_used > 0 &&
	       u->desc_used_begin != readptr) {
		VE_DMA_TRACE("DMA descriptor #%d is freed.",
			     u->desc_used_begin);
		--u->desc_num_used;
		++u->desc_used_begin;
		if (u->desc_used_begin == VE1_DMA_NUM_DESC)
			u->desc_used_begin = 0;
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
void ve1_dma_finish_reqlist_entry(ve_dma_reqlist_entry *e, uint64_t status,
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
	struct ve1_dma_engine_usage *usage = VE1_DMA_HDL_USAGE(dh);
	usage->req_entry[entry] = NULL;
	VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
		     usage->desc_used_begin, usage->desc_num_used);
	ve1_dma_free_used_desc(dh, readptr);
	VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
		     usage->desc_used_begin, usage->desc_num_used);
}

/**
 * @brief Cancel a DMA request
 *
 *        Remove correspond DMA reqlist entries from wait queue,
 *        and also cancel DMA requests on DMA descriptors.
 *
 * @param[in,out] req DMA request handle
 */
void ve1_dma_reqlist__cancel(ve_dma_req_hdl *req)
{
	/*
	 * note: a caller shall hold req->engine->mutex and
	 *  the DMA engine shall be stopped.
	 */
	struct list_head *p, *tmp;
	ve_dma_hdl *hdl = req->engine;
	vedl_handle *vh = hdl->vedl_handle;

	VE_DMA_TRACE("called");
	int readptr;
	readptr = ve1_dma_hw_get_readptr(vh, hdl->control_regs);

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
			if (e->entry < 0 || e->entry >= VE1_DMA_NUM_DESC) {
				VE_DMA_CRIT("descriptor #%d is invalid",
					    e->entry);
				return;
			}
			uint64_t status_hw;
			status_hw = ve1_dma_hw_desc_status(vh,
							  hdl->control_regs,
							  e->entry);
			if (status_hw & VE_DMA_DESC_STATUS_PREPARED) {
				ve1_dma_hw_nullify_dma(hdl->vedl_handle,
					hdl->control_regs, e->entry);
			}
			ve1_dma_finish_reqlist_entry(e, status_hw, readptr);
		} else {
			VE_DMA_TRACE("request %p has been already finished "
				     "(status = %d).", e, e->status);
		}
		if (e->src_block) {
			if (e->src_block->type == VE_DMA_VHVA) {
				/* If there is a block structure, unpin is always done.
				 * so decriment the count.*/
				ve_atomic_dec(&hdl->blk_count);
				VE_DMA_DEBUG("blk_count %d", hdl->blk_count);
			}
			ve_dma__block_free(vh, e->src_block);
			e->src_block = NULL;
		}
		if (e->dst_block) {
			if (e->dst_block->type == VE_DMA_VHVA) {
				/* If there is a block structure, unpin is always done.
				 * so decriment the count.*/
				ve_atomic_dec(&hdl->blk_count);
				VE_DMA_DEBUG("blk_count %d", hdl->blk_count);
			}
			ve_dma__block_free(vh, e->dst_block);
			e->dst_block = NULL;
		}
	}
	ve_dma__dec_ipc_sync_nolock(req);
	req->comp = 1;
	req->cancel = 1;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_reqlist_cancel, ve1_dma_reqlist__cancel)
