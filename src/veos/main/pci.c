/**
 * enum pseudo_veos_msg_id msg_id
 *
 * Copyright (C) 2018 by NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see * <http://www.gnu.org/licenses/>.
 */
/**
 * @file pci.c
 * @brief Hahndle PCI operation on VEOS
 *
 * @internal
 * @author VEPCI
 */

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/capability.h>
#include "ve_mem.h"
#include "veos_handler.h"
#include "veos.h"
#include "task_mgmt.h"
#include "psm_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "task_sched.h"
#include <sys/ipc.h>
#include "pciatb_api.h"
#include "vesync.h"
#include "veos.h"
#include "veos_ipc.h"
#include "vehva_mgmt.h"

#define REGISTER_TO_PCI_OP     1
#define UNREGISTER_FROM_PCI_OP 2
#define REGISTER_TO_DMA_OP     3
#define UNREGISTER_FROM_DMA_OP 4

/**
 * @brief This function operates each request specified by 'op'
 *
 * @param[in] pti veos_arg_t
 * @param[in] op Request specifier
 *
 * @return 0 on success, negative value on failure
 */
static int veos_handle_pci_common(veos_thread_arg_t *pti, int op)
{
	int ret=0;
	int64_t result=-1;
	struct pcicmd req = {0};
	pid_t pid = -1;
	int length = -1;
	struct ve_node_struct *current_node = NULL;
	int64_t pciatb_pagesize;
	int64_t request_pagesize;

	int i, slot, num;
	int vemva_pg_mode;
	int pciatb_pgsize_flag=-1;
	int8_t vehva_type = 0;
	uint64_t *target_addr = NULL;

	VEOS_TRACE("Invoked with pti (%p)", pti);

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		result = -EINVAL;
		goto hndl_return;
	}
	VEOS_DEBUG("pci request length received from protobuf:%d", length);

	if (length > sizeof(struct pcicmd)) {
		VEOS_DEBUG("Invalid message length");
		result = -EINVAL;
		goto hndl_return;
	}
	memcpy(&req, (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).data, length);

	if (req.addr == (uint64_t)NULL || req.size == 0){
		VEOS_DEBUG("pci request common handling: Invalid address or size");
		result = -EINVAL;
		goto hndl_return;
	}

	current_node = VE_NODE(VE_NODE_ID(0));
	if (NULL == current_node) {
		VEOS_ERROR("BUG Node ID: %d struct is NULL",
				VE_NODE_ID(0));
		result = -ESRCH;
		goto hndl_return;
	}

	pciatb_pagesize = (int64_t)current_node->pci_bar01_pgsz;
	if (pciatb_pagesize != 64*1024*1024 &&
			pciatb_pagesize != 2*1024*1024) {
		VEOS_DEBUG("pci request common handling: Invalid pciatb size %ld",
				pciatb_pagesize);
		result = -EINVAL;
		goto hndl_return;
	}

	if ((req.size & POFFMASK_H) == 0 &&
			(req.addr & POFFMASK_H) == 0) {
		vehva_type = VEHVA_VESHM | VEHVA_64MB;
		request_pagesize = 64 * 1024 * 1024;
	} else if ((req.size & POFFMASK) == 0 &&
			(req.addr & POFFMASK) == 0) {
		vehva_type = VEHVA_VESHM | VEHVA_2MB;
		request_pagesize = 2 * 1024 * 1024;
	} else {
		VEOS_DEBUG("pci request common handling: Invalid request [addr:%lx size:%lx]",
				req.addr, req.size);
		result = -EINVAL;
		goto hndl_return;
	}

	if (op == REGISTER_TO_PCI_OP || op == UNREGISTER_FROM_PCI_OP) {
		if ((request_pagesize % pciatb_pagesize) != 0) {
			VEOS_DEBUG("pci request common handling: Invalid alignment with pciatb page size(0x%lx)",
					pciatb_pagesize);
			result = -EINVAL;
			goto hndl_return;
		}
	}

	/* do each operation */
	switch(op) {
	case REGISTER_TO_PCI_OP:
		vemva_pg_mode = veos_get_pgmode(VE_ADDR_VEMVA,
						pid,
						req.addr);
		if (vemva_pg_mode < 0){
			VEOS_DEBUG("Register to PCI: Check of page size failed (err:%d)",
					vemva_pg_mode);
			result = -EINVAL;
			goto hndl_return;
		}

		pciatb_pgsize_flag = (pciatb_pagesize == 2*1024*1024)?
					PG_2M : PG_HP;
		if (vemva_pg_mode == PG_2M
				&& pciatb_pgsize_flag == PG_HP){
			VEOS_DEBUG("Register to PCI: Not allowed page mode");
			result = -EINVAL;
			goto hndl_return;
		}

		veos_sync_r_bar01_bar3();
		slot = veos_alloc_pciatb
			(pid, req.addr, req.size, PROT_READ|PROT_WRITE, true);
		veos_sync_r_bar2();
		if (slot < 0){
			VEOS_DEBUG("Register to PCI: Fail to map address to PCIATB  0x%lx, size:%zd",
					req.addr, req.size);
			result = slot;
		} else {
			VEOS_DEBUG("Register to PCI: Success to map address to PCIATB  0x%lx, size:%zd",
					req.addr, req.size);
			result = current_node->pci_bar01_vhsaa +
					(uint64_t)slot *
					(uint64_t)pciatb_pagesize;
		}
		break;

	case UNREGISTER_FROM_PCI_OP:
		slot = (req.addr - current_node->pci_bar01_vhsaa) /
				pciatb_pagesize;

		veos_sync_r_bar01_bar3();
		result = veos_delete_pciatb(slot, req.size);
		veos_sync_r_bar2();
		if (result) {
			VEOS_DEBUG("Unregister from PCI: Fail to delete pciatb [entry:%d, addr:0x%lx, size:%zd]",
					slot, req.addr, req.size);
		}
		break;

	case REGISTER_TO_DMA_OP:
		if (pti->cred.uid != 0) {
                	VEOS_DEBUG("Invalid credential");
                	result = -EPERM;
                	goto hndl_return;
                }
		num = req.size / request_pagesize;

		target_addr = (uint64_t *)malloc((num+1) * sizeof(uint64_t));
		if (target_addr == NULL) {
			VEOS_DEBUG("Register to DMA: Fail to allocate buffer for mapping");
			result = -ENOMEM;
			goto hndl_return;
		}
		memset(target_addr, '\0', (num+1) * sizeof(uint64_t));

		for (i=0; i<num; i++)
			target_addr[i] = req.addr + i * pciatb_pagesize;

		veos_sync_r_bar01_bar3();
		result = veos_alloc_dmaatb_entry_for_aa
			(pid, target_addr, PROT_READ|PROT_WRITE, VE_ADDR_VHSAA,
				vehva_type);
		veos_sync_r_bar2();
		if (result < 0){
			VEOS_DEBUG("Register to DMA: Fail to map 0x%lx to DMAATB, size:%zd",
					req.addr, req.size);
		}
		break;

	case UNREGISTER_FROM_DMA_OP:
		veos_sync_r_bar01_bar3();
		result = veos_free_dmaatb_entry(pid, req.addr, req.size);
		if (result) {
			VEOS_ERROR("Unregister from DMA: Fail to unmap 0x%lx from DMAATB, size:%zd.",
					req.addr, req.size);
		}
		veos_sync_r_bar2();
		break;
	default:
		VEOS_DEBUG("pci request common handling: Invalid operation is specified:%d",
				op);
	}

hndl_return:
	ret = veos_reply(pti, result, NULL);
	if (ret != 0) {
		VEOS_DEBUG("PID:%d:Failed to communicate with Pseudo: %s",
			pid, strerror(-ret));
		ret = -1;
	}

	VEOS_TRACE("returned");
	return ret;
}

int veos_handle_register_vemva_to_pciatb(veos_thread_arg_t *pti)
{
	return veos_handle_pci_common(pti, REGISTER_TO_PCI_OP);
}

int veos_handle_unregister_vhsaa_from_pciatb(veos_thread_arg_t *pti)
{
	return veos_handle_pci_common(pti, UNREGISTER_FROM_PCI_OP);
}

int veos_handle_register_vhsaa_to_dmaatb(veos_thread_arg_t *pti)
{
	return veos_handle_pci_common(pti, REGISTER_TO_DMA_OP);
}

int veos_handle_unregister_vehva_from_dmaatb(veos_thread_arg_t *pti)
{
	return veos_handle_pci_common(pti, UNREGISTER_FROM_DMA_OP);
}
