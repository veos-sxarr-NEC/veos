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
 * @file dma_api.c
 * @brief VE1-dependent part of DMA manager API
 */
#include <stdlib.h>
#include <string.h>

#include <libved.h>

#include "dma.h"
#include "dma_ve1.h"
#include "dma_ve1_private.h"
#include "dma_private.h"
#include "dma_hw_ve1.h"
#include "dma_reqlist.h"
#include "dma_log.h"
#include "ve1dma_hw.h"

int ve1_dma_addr_type_is_valid(const char *msg, ve_dma_addrtype_t t)
{
	VE_DMA_TRACE("called");
	switch (t) {
	case VE1_DMA_VERAA:
		VE_DMA_TRACE("%s addr type is VE3 VERAA", msg);
		return 0;
	default:
		VE_DMA_ERROR("%s unsupported addr type (%d)", msg, t);
		return -EINVAL;
	}
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_addr_type_is_valid, ve1_dma_addr_type_is_valid)

#define TO_VE1_USAGE(u_) ((struct ve1_dma_engine_usage *)u_)

void ve1_dma_cancel_all_posted(struct ve_dma_engine_usage *u)
{
	struct ve1_dma_engine_usage *usage = TO_VE1_USAGE(u);
	for (int i = 0; i < VE1_DMA_NUM_DESC; ++i) {
		if (usage->req_entry[i] != NULL) {
			ve_dma_req_hdl *dh;
			VE_DMA_TRACE("Cancel DMA descriptor %d (request %p)",
				i, usage->req_entry[i]);
			dh = ve_dma_reqlist_entry_to_req_hdl(usage->req_entry[i]);
			ve_dma_reqlist__cancel(dh);
			pthread_cond_broadcast(&dh->cond);
		} else {
			VE_DMA_TRACE("DMA descriptor %d is unused.", i);
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_cancel_all_posted, ve1_dma_cancel_all_posted)

struct ve_dma_engine_usage *ve1_dma_alloc_usage(vedl_handle *hdl,
		vedl_common_reg_handle *creg)
{
	struct ve1_dma_engine_usage *ret;
	VE_DMA_TRACE("called");
	ret = malloc(sizeof(*ret));
	return (struct ve_dma_engine_usage *)ret;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_alloc_usage, ve1_dma_alloc_usage);

void ve1_dma_init_usage(vedl_handle *vh, vedl_common_reg_handle *creg,
		struct ve_dma_engine_usage *u)
{
	struct ve1_dma_engine_usage *usage = TO_VE1_USAGE(u);
	VE_DMA_TRACE("called");
	usage->desc_used_begin = ve1_dma_hw_get_readptr(vh, creg);
	usage->desc_num_used = 0;
	memset(usage->req_entry, 0, sizeof(usage->req_entry));
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_init_usage, ve1_dma_init_usage);

void ve1_dma_free_usage(vedl_handle *vh, vedl_common_reg_handle *creg,
		struct ve_dma_engine_usage *p)
{
	VE_DMA_TRACE("called");
	free(p);
}

VEOS_ARCH_DEP_FUNC(ve1, arch_dma_free_usage, ve1_dma_free_usage);

int ve1_dma_engine_is_busy(const struct ve_dma_engine_usage *u)
{
	const struct ve1_dma_engine_usage *usage = TO_VE1_USAGE(u);
	return usage->desc_num_used != 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_engine_is_busy, ve1_dma_engine_is_busy);
