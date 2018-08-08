/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file dma_reqlist.h
 * @brief Header for functions in dma_reqlist.c
 */
#ifndef VE_VEOS_DMA_REQUEST_H
#define VE_VEOS_DMA_REQUEST_H
#include <libved.h>

struct ve_dma_reqlist_entry;
typedef struct ve_dma_reqlist_entry ve_dma_reqlist_entry;

int64_t ve_dma_reqlist_make(ve_dma_req_hdl *, ve_dma_addrtype_t, pid_t,
			    uint64_t, ve_dma_addrtype_t, pid_t, uint64_t,
			    uint64_t);
void ve_dma_free_used_desc(ve_dma_hdl *, int);
void ve_dma_reqlist_free(ve_dma_req_hdl *);
ve_dma_status_t ve_dma_reqlist_test(ve_dma_req_hdl *);
int ve_dma_reqlist_post(ve_dma_req_hdl *);
int ve_dma_reqlist_drain_waiting_list(ve_dma_hdl *);
void ve_dma_reqlist__cancel(ve_dma_req_hdl *);
void ve_dma_finish_reqlist_entry(ve_dma_reqlist_entry *, uint64_t, int);
ve_dma_req_hdl *ve_dma_reqlist_entry_to_req_hdl(ve_dma_reqlist_entry *);
ve_dma_req_hdl *ve_dma_waiting_list_head_to_req_hdl(const struct list_head *);
#endif
