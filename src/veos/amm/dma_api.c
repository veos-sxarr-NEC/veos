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
 * @file dma_api.c
 * @brief handle the dma request from pseudo process
 *
 * @internal
 * @author AMM
 */
#include <unistd.h>
#include <sys/mman.h>
#include "veos.h"
#include <libved.h>
#include "dma.h"
#include "velayout.h"

/**
* @brief DMA transfer request to DMA library.
*
* @param[in] srctype source address type.
* @param[in] src_addr source address.
* @param[in] src_pid process identifier.
* @param[in] dsttype destination type.
* @param[out] dst_addr destination address.
* @param[in] dst_pid destination process identifier.
* @param[in] length Length of the data to DMA.
* @param[in] node_id Node ID.
*
* @return On success returns 0 and -1 on error.
*
* @internal
* @note Invoked by other modules i.e. PTRACE
*/
int amm_dma_xfer(int srctype, uint64_t src_addr, int src_pid,
		int dsttype, uint64_t dst_addr, int dst_pid,
		size_t sz, int node_id)
{
	int retval = 0;
	ve_dma_hdl *dh = NULL;
	ve_dma_status_t st = 0;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	dh = vnode_info->dh;

	VEOS_DEBUG("DMA Transfer From(PID:%d): 0x%lx "
			"To(PID:%d): 0x%lx of Size: %ld",
			src_pid, src_addr, dst_pid, dst_addr, sz);

	st = ve_dma_xfer_p_va(dh, srctype, src_pid,
			src_addr, dsttype, dst_pid, dst_addr, sz);
	if (st != VE_DMA_STATUS_OK) {
		VEOS_DEBUG("DMA error (%d)", st);
		retval = -1;
	}

	return retval;
}
