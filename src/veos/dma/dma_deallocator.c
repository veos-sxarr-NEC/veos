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
 * @file dma_deallocator.c
 * @brief Free a DMA request
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

/**
 * @brief Unpin address used by DMA request handle
 *
 * @param hdl DMA request handle
 */
void ve_dma_unpin_reqlist_addr(ve_dma_req_hdl *hdl)
{
	VE_DMA_TRACE("called (%p)", hdl);
	VE_DMA_DEBUG("ve_dma_unpin_reqlist_addr");
	struct list_head *lh;
	struct list_head *tmp;
	vedl_handle *vh = hdl->engine->vedl_handle;
	list_for_each_safe(lh, tmp, &hdl->reqlist) {
		list_del(lh);
		ve_dma_reqlist_entry *e;
		e = list_entry(lh, ve_dma_reqlist_entry, list);
		ve_dma_unpin_addr(vh, &e->src, e->length);
		ve_dma_unpin_addr(vh, &e->dst, e->length);
		free(e);
	}
}

/**
 * @brief Free a DMA request thread function
 *
 * @param arg DMA handle
 */
void *ve_dma_req_deallocator(void *arg)
{
	ve_dma_hdl *dh = arg;
	VE_DMA_TRACE("called");
	struct list_head *req_lh;
	struct timespec timeout;

	while(1){
		pthread_mutex_lock(&dh->deallocate_list_mutex);
		while(list_empty(&dh->deallocate_list)){
			if(dh->should_stop){
				pthread_mutex_unlock(&dh->deallocate_list_mutex);
				goto stop;
			}
			clock_gettime(CLOCK_REALTIME, &timeout);
			timeout.tv_sec += 1;
			pthread_cond_timedwait(&dh->deallocator_cond, &dh->deallocate_list_mutex, &timeout);
		}
		req_lh = dh->deallocate_list.next;
		/* Don't use list_for_each_safe because minimal mutex lock*/
		list_del(req_lh);
		pthread_mutex_unlock(&dh->deallocate_list_mutex);
		ve_dma_req_hdl *hdl;
		hdl = list_entry(req_lh, ve_dma_req_hdl, deallocate_list);
		ve_dma_unpin_reqlist_addr(hdl);
		pthread_cond_destroy(&hdl->cond);
		free(hdl);
	}
stop:
	return (void *)0L;
}
