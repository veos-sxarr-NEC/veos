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
#include <pthread.h>

#include <libved.h>

#include "dma.h"
#include "dma_private.h"
#include "dma_reqlist.h"
#include "dma_intr.h"
#include "dma_log.h"
#include "dma_reqlist_private.h"
#include "veos.h"
#include "vesync.h"
#include <time.h>
#include "ve_atomic.h"

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
		struct timespec timo = { .tv_sec = 1, .tv_nsec = 0};
		ret_intr = vedl_wait_for_interrupt(handle, VE_INTR_P_DMA,
							&timo);
		VE_DMA_TRACE("vedl_wait_for_interrupt returned %d", ret_intr);
		if (ret_intr < 0) {
			switch (errno) {
			case ETIMEDOUT:
				VE_DMA_TRACE(
				"vedl_wait_for_interrupt() is timedout");
				break;
			case EINTR:
				VE_DMA_DEBUG(
				"vedl_wait_for_interrupt() is interrupted by signal");
				break;
			default:
				VE_DMA_FATAL(
				"vedl_wait_for_interrupt() returned error %d",
				ret_intr);
				veos_abort(
				"DMA manager interrupt helper failed.");
			}
			continue;
		}
		(*_veos_arch_ops->arch_dma_intr)(dh);
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
