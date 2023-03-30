/*
 * Copyright (C) 2020 NEC Corporation
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
 * @file dma_intr.c
 * @brief DMA helper thread handling interrupts
 */
#include <errno.h>
#include <stdlib.h>

#include "dma.h"
#include "dma_private.h"
#include "dma_ve1_private.h"
#include "dma_hw.h"
#include "dma_hw_ve1.h"
#include "dma_reqlist.h"
#include "dma_reqlist_ve1.h"
#include "dma_log.h"
#include "veos.h"
#include "vesync.h"

/**
 * @brief DMA descriptor finalize function
 *
 * @param dh DMA handle
 * @param entry DMA descriptor entry to be finalized
 * @param status Word 0 in the corresponding DMA descriptor
 * @param readptr Read poiter value of DMA control register
 */
static ve_dma_reqlist_entry *ve1_dma_intr__finish_descriptor(struct ve1_dma_engine_usage *usage,
			int entry, uint64_t status, int readptr)
{
	/*
	 * note: a caller must stop DMA engine before calling this function
	 * if exception field of the status is not 0.
	 */
	ve_dma_reqlist_entry *e, *ret = NULL;
	ve_dma_req_hdl *r;
	VE_DMA_TRACE("Finalize DMA descriptor #%d", entry);

	e = usage->req_entry[entry];
	VE_DMA_TRACE("descriptor #%d -> request %p", entry, e);
	/* e can be NULL when DMA request is terminated	 */
	if (e != NULL) {
		r = ve_dma_reqlist_entry_to_req_hdl(e);
		if (status & VE_DMA_DESC_EXCEPTION_MASK) {
			/* it caused some errors */
			VE_DMA_TRACE("DMA descriptor #%d "
				     "caused exceptions: status=%016lx",
				     entry, status);
			ve_dma_reqlist__cancel(r);
		} else {
			ve1_dma_finish_reqlist_entry(e, status, readptr);
			if (e->last)
				r->comp = 1;
			ret = e;
		}
		/*
		 * wake up the thread waiting for r,
		 * The waiter checks the status with
		 * ve_dma_reqlist_test().
		 */
		VE_DMA_TRACE("pthread_cond_signal");
		pthread_cond_signal(&r->cond);
	} else {
		VE_DMA_TRACE("descriptor #%d has been already finished.",
			     entry);
	}
	return ret;
}

/**
 * @brief VE3 DMA interrupt handler
 *
 * @param dh DMA handle
 *
 * Note: In architecture-dependent DMA interrupt handler,
 *  dh->mutex is held by the caller.
 *
 */
void ve1_dma_intr(ve_dma_hdl *dh)
{
	int exc, entry, readptr,count,i;
	uint64_t ctlword1;
	vedl_handle *handle = dh->vedl_handle;
	ve_dma_reqlist_entry *e;
        ve_dma__block *b[VE1_DMA_NUM_DESC * 2];
	
	pthread_mutex_lock(&dh->mutex);
	VE_DMA_TRACE("DMA control register status = 0x%x",
		     ve1_dma_hw_get_ctlstatus(handle, dh->control_regs));

	/* get exc and readptr */
	exc = 0;
	ctlword1 = ve1_dma_hw_get_ctlword1(handle, dh->control_regs);
	if (ctlword1 & VE_DMA_CTL_EXCEPTION_MASK) {
		exc = 1;
	};
	readptr = ctlword1 & VE_DMA_CTL_READ_PTR_MASK;
	VE_DMA_TRACE("DMA control register word1: exc = %d, readptr = %d",
			exc, readptr);

	struct ve1_dma_engine_usage *usage = VE1_DMA_HDL_USAGE(dh);
	/*
	 * desc_used_begin and desc_num_used can be changed
	 * while finishing request entries.
	 */
	int current_begin = usage->desc_used_begin;
	int current_used = usage->desc_num_used;
	VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
			current_begin, current_used);
	count = 0;
	if (exc == 0) {
		/*
		 * When exc = 0, descriptors between desc_used_begin and
		 * readptr must be completed without exception.
		 */
		for (entry = current_begin; entry != readptr;
		     entry = (entry + 1) % VE1_DMA_NUM_DESC) {
			e = ve1_dma_intr__finish_descriptor(usage,
				entry, VE_DMA_DESC_STATUS_COMPLETED, readptr);
			if (e) {
				if (e->src_block) {
					b[count++] = e->src_block;
					e->src_block = NULL;
				}
				if (e->dst_block) {
					b[count++] = e->dst_block;
					e->dst_block = NULL;
				}
			}
			usage->req_entry[entry] = NULL;
		}
		ve1_dma_free_used_desc(dh, readptr);
	} else { /* exc == 1 */
		/*
		 * When exc = 1, descriptors between desc_used_begin and
		 * readptr must be completed and any of these caused
		 * exception.
		 */
		/* stop DMA engine and refresh readptr */
		ve_dma__stop_engine(dh);
		ctlword1 = ve1_dma_hw_get_ctlword1(handle, dh->control_regs);
		VE_DMA_ASSERT(ctlword1 & VE_DMA_CTL_EXCEPTION_MASK);
		readptr = ctlword1 & VE_DMA_CTL_READ_PTR_MASK;
		VE_DMA_TRACE("DMA control register word1: exc = %d, "
			     "readptr = %d", exc, readptr);
		for (entry = current_begin; entry != readptr;
		     entry = (entry + 1) % VE1_DMA_NUM_DESC) {
			uint64_t status;
			status = ve1_dma_hw_desc_status(dh->vedl_handle,
					dh->control_regs, entry);
			VE_DMA_ASSERT(status & VE_DMA_DESC_STATUS_COMPLETED);
			e = ve1_dma_intr__finish_descriptor(usage, entry, status,
							readptr);
			if (e) {
				if (e->src_block) {
					b[count++] = e->src_block;
					e->src_block = NULL;
				}
				if (e->dst_block) {
					b[count++] = e->dst_block;
					e->dst_block = NULL;
				}
			}
			usage->req_entry[entry] = NULL;
		}
		ve1_dma_free_used_desc(dh, readptr);
		/* clear exc bit */
		ve1_dma_hw_set_readptr(handle, dh->control_regs,
				      readptr);
		/* restart DMA engine */
		if (dh->should_stop == 0 && usage->desc_num_used > 0) {
			ve_dma_hw_start(dh->control_regs);
		}
		veos_commit_rdawr_order();
	}
	/* post requests to free descriptors */
	ve_dma__drain_waiting_list(dh);
	pthread_mutex_unlock(&dh->mutex);
	for (i=0; i<count; i++) {
		/* unpin block is always done.
		 * so decriment the count.*/
		if (b[i]->type == VE_DMA_VHVA) {
			ve_atomic_dec(&dh->blk_count);
			VE_DMA_DEBUG("blk_count %d", dh->blk_count);
		}
		ve_dma__block_free(dh->vedl_handle, b[i]);
	}

	pthread_mutex_lock(&dh->pin_wait_list_mutex);
	pthread_cond_signal(&dh->pin_wait_list_cond);
	pthread_mutex_unlock(&dh->pin_wait_list_mutex);
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_intr, ve1_dma_intr)
