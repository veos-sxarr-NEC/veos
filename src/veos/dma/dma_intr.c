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
 * @file dma_intr.c
 * @brief DMA helper thread handling interrupts
 */
#include <errno.h>
#include <stdlib.h>

#include "dma.h"
#include "dma_private.h"
#include "dma_reqlist.h"
#include "dma_reqlist_private.h"
#include "dma_hw.h"
#include "dma_log.h"
#include "vedma_hw.h"
#include "veos.h"
#include "vesync.h"
#include <time.h>
#include "ve_atomic.h"

static ve_dma_reqlist_entry *ve_dma_intr__finish_descriptor(ve_dma_hdl *, int, uint64_t, int);

/**
 * @brief DMA descriptor finalize function
 *
 * @param dh DMA handle
 * @param entry DMA descriptor entry to be finalized
 * @param status Word 0 in the corresponding DMA descriptor
 * @param readptr Read poiter value of DMA control register
 */
static ve_dma_reqlist_entry *ve_dma_intr__finish_descriptor(ve_dma_hdl *dh, int entry,
					   uint64_t status, int readptr)
{
	/*
	 * note: a caller must stop DMA engine before calling this function
	 * if exception field of the status is not 0.
	 */
	ve_dma_reqlist_entry *e, *ret = NULL;
	ve_dma_req_hdl *r;
	VE_DMA_TRACE("Finalize DMA descriptor #%d", entry);

	e = dh->req_entry[entry];
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
			ve_dma_finish_reqlist_entry(e, status, readptr);
			if (e->last)
				r->comp = 1;
			ret = e;
		}
		pthread_cond_signal(&r->cond);
	} else {
		VE_DMA_TRACE("descriptor #%d has been already finished.",
			     entry);
	}
	return ret;
}

/**
 * @brief DMA interrupt handler thread function
 *
 * @param arg DMA handle
 *
 * @return Current implementation always returns 0.
 */
void *ve_dma_intr_helper(void *arg)
{
	ve_dma_hdl *dh = arg;
	int i, count;
	ve_dma_reqlist_entry *e;
	ve_dma__block *b[VE_DMA_NUM_DESC * 2];

	VE_DMA_DEBUG("DMA interrupt helper thread starts");
	vedl_handle *handle = dh->vedl_handle;
	while (!dh->should_stop) {
		int ret_intr;
		int entry;
		int current_begin, current_used;
		uint64_t ctlword1;
		int exc = 0;
		int readptr;
		struct timespec timo = { .tv_sec = 1, .tv_nsec = 0};
		ret_intr = vedl_wait_interrupt(handle, VE_INTR_P_DMA,
					      &timo);
		VE_DMA_TRACE("vedl_wait_dma_intr returned %d", ret_intr);
		if (ret_intr < 0) {
			switch (errno) {
			case ETIMEDOUT:
				VE_DMA_TRACE(
				"vedl_wait_interrupt() is timedout");
				break;
			case EINTR:
				VE_DMA_DEBUG(
				"vedl_wait_interrupt() is aborted by signal");
				break;
			default:
				VE_DMA_FATAL(
				"vedl_wait_interrupt() returned error %d",
				ret_intr);
				veos_abort(
				"DMA manager interrupt helper failed.");
			}
			continue;
		}
		/* which request is finished? */
		pthread_mutex_lock(&dh->mutex);
		VE_DMA_TRACE("DMA control register status = 0x%x",
			     ve_dma_hw_get_ctlstatus(handle,
						     dh->control_regs));

		/* get exc and readptr */
		ctlword1 = ve_dma_hw_get_ctlword1(handle, dh->control_regs);
		if (ctlword1 & VE_DMA_CTL_EXCEPTION_MASK) {
			exc = 1;
		};
		readptr = ctlword1 & VE_DMA_CTL_READ_PTR_MASK;
		VE_DMA_TRACE("DMA control register word1: exc = %d, "
			     "readptr = %d",
			     exc, readptr);

		/*
		 * desc_used_begin and desc_num_used can be changed
		 * while finishing request entries.
		 */
		current_begin = dh->desc_used_begin;
		current_used = dh->desc_num_used;
		VE_DMA_TRACE("desc_used_begin = %d, desc_num_used = %d",
			     current_begin, current_used);
		count = 0;
		if (exc == 0) {
			/*
			 * When exc = 0, descriptors between desc_used_begin and
			 * readptr must be completed without exception.
			 */
			for (entry = current_begin; entry != readptr;
			     entry = (entry + 1) % VE_DMA_NUM_DESC) {
				e = ve_dma_intr__finish_descriptor(
					dh, entry, VE_DMA_DESC_STATUS_COMPLETED,
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
				dh->req_entry[entry] = NULL;
			}
			ve_dma_free_used_desc(dh, readptr);
		} else { /* exc == 1 */
			/*
			 * When exc = 1, descriptors between desc_used_begin and
			 * readptr must be completed and any of these caused
			 * exception.
			 */
			/* stop DMA engine and refresh readptr */
			ve_dma__stop_engine(dh);
			ctlword1 = ve_dma_hw_get_ctlword1(handle,
							  dh->control_regs);
			VE_DMA_ASSERT(ctlword1 & VE_DMA_CTL_EXCEPTION_MASK);
			readptr = ctlword1 & VE_DMA_CTL_READ_PTR_MASK;
			VE_DMA_TRACE("DMA control register word1: exc = %d, "
				     "readptr = %d", exc, readptr);
			for (entry = current_begin; entry != readptr;
			     entry = (entry + 1) % VE_DMA_NUM_DESC) {
				uint64_t status;
				status = ve_dma_hw_desc_status(dh->vedl_handle,
							       dh->control_regs,
							       entry);
				VE_DMA_ASSERT(status &
					      VE_DMA_DESC_STATUS_COMPLETED);
				e = ve_dma_intr__finish_descriptor(
					dh, entry, status, readptr);
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
				dh->req_entry[entry] = NULL;
			}
			ve_dma_free_used_desc(dh, readptr);
			/* clear exc bit */
			ve_dma_hw_set_readptr(handle, dh->control_regs,
					      readptr);
			/* restart DMA engine */
			if (dh->should_stop == 0 && dh->desc_num_used > 0) {
				ve_dma_hw_start(dh->vedl_handle,
						dh->control_regs);
			}
			veos_commit_rdawr_order();
		}
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
	return (void *)0L;
}

void *ve_dma_pindown_helper(void *arg)
{
	ve_dma_hdl *dh = arg;
	ve_dma_req_hdl *req;
	ve_dma__block *src_blk, *dst_blk;
	int ret;
	while(1) {
		pthread_mutex_lock(&dh->pin_wait_list_mutex);
		while (!dh->should_stop && (list_empty(&dh->pin_waiting_request) ||
			 	VE_ATOMIC_GET(int, &dh->blk_count) >= BLOCK_LIMIT))
			pthread_cond_wait(&dh->pin_wait_list_cond,
						&dh->pin_wait_list_mutex);
		if (dh->should_stop) {
			pthread_mutex_unlock(&dh->pin_wait_list_mutex);
			break;
		}
		req = list_entry((&dh->pin_waiting_request)->next, ve_dma_req_hdl, pin_waiting_list);
		list_del_init((&dh->pin_waiting_request)->next);
		src_blk = req->src_blk;
		dst_blk = req->dst_blk;
		req->src_blk = NULL;
		req->dst_blk = NULL;
		pthread_mutex_unlock(&dh->pin_wait_list_mutex);

		ret = ve_dma_reqlist_make(req,
				req->waiting_src.type, req->waiting_src.pid, req->waiting_src.addr, src_blk,
				req->waiting_dst.type, req->waiting_dst.pid, req->waiting_dst.addr, dst_blk,
				req->length, req->opt, req->vh_sock_fd);
		if (ret == 0)
			VE_DMA_TRACE("BLOCK_LIMIT. Request is postporned.");
		else if (ret < 0)
			VE_DMA_ERROR("ve_dma_reqlist_make return error %s", strerror(errno));
		else
			VE_DMA_TRACE("Request is posted.");
	}
	return (void *)0L;
}
