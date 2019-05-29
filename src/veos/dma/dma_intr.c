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
#include "dma_hw.h"
#include "dma_log.h"
#include "vedma_hw.h"
#include "veos.h"
#include "vesync.h"

static void ve_dma_intr__finish_descriptor(ve_dma_hdl *, int, uint64_t, int);

/**
 * @brief DMA descriptor finalize function
 *
 * @param dh DMA handle
 * @param entry DMA descriptor entry to be finalized
 * @param status Word 0 in the corresponding DMA descriptor
 * @param readptr Read poiter value of DMA control register
 */
static void ve_dma_intr__finish_descriptor(ve_dma_hdl *dh, int entry,
					   uint64_t status, int readptr)
{
	/*
	 * note: a caller must stop DMA engine before calling this function
	 * if exception field of the status is not 0.
	 */
	ve_dma_reqlist_entry *e;
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
		if (exc == 0) {
			/*
			 * When exc = 0, descriptors between desc_used_begin and
			 * readptr must be completed without exception.
			 */
			for (entry = current_begin; entry != readptr;
			     entry = (entry + 1) % VE_DMA_NUM_DESC) {
				ve_dma_intr__finish_descriptor(
				dh, entry, VE_DMA_DESC_STATUS_COMPLETED,
				readptr);
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
				ve_dma_intr__finish_descriptor(dh, entry,
							       status, readptr);
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
		/* post requests to free descriptors */
		ve_dma__drain_waiting_list(dh);
		pthread_mutex_unlock(&dh->mutex);
	}
	return (void *)0L;
}
