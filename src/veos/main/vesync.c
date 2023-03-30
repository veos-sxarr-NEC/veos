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
/*
 * @file vesync.c
 * @brief Functions for VE sync operation
 */
#include <sys/mman.h>
#include "veos.h"
#include "ve_drv.h"
#include "libved.h"
#include "task_mgmt.h"

#include <veos_arch_defs.h>

/**
 * @brief Allocate address for pci bar01 sync.
 *
 * @return 0 on success, -1 on failure.
 *
 * This function must be called after pci_bar01_pgsz and vdso_pcientry are
 * initialized by AMM.
 */
int veos_alloc_pci_bar01_sync_addr(void)
{
	vedl_handle *vh = VE_HANDLE(0);
	struct ve_node_struct *ve_node = VE_NODE(0);

	ve_node->pci_bar01_sync_addr = (*_veos_arch_ops->
		arch_vesync_map_pci_memory_window_sync_area)(vh, ve_node);
	if (ve_node->pci_bar01_sync_addr == MAP_FAILED)
		return -1;

	return 0;
}

/**
 * @brief Close pci bar01 sync address.
 */
void veos_free_pci_bar01_sync_addr(void)
{
	struct ve_node_struct *ve_node = VE_NODE(0);

	if (ve_node->pci_bar01_sync_addr != MAP_FAILED &&
	    ve_node->pci_bar01_sync_addr != NULL) {
		(*_veos_arch_ops->
			arch_vesync_unmap_pci_memory_window_sync_area)(
				ve_node->pci_bar01_sync_addr);
	}
	ve_node->pci_bar01_sync_addr = NULL;
}

/**
 * @brief commit_rdawr_order
 *
 * @return always 0
 */
int veos_commit_rdawr_order(void)
{
/*
 * As an optimization for HW behavior, the followings help VEOS to ensure
 * the order of read after write rapidly.
 */
	return (*_veos_arch_ops->arch_vesync_commit_rdawr_order)();
}

/**
 * @brief Invalidate branch history to avoid HW Bug
 *
 * @return 0 on success, -1 on failure.
 */
int veos_invalidate_branch_history(int core_id)
{
	return (*_veos_arch_ops->
			arch_vesync_invalidate_branch_history)(core_id);
}

/**
 * @brief Write serialize function for register area
 *
 * @return always 0
 */
int veos_sync_w_bar2(void)
{
	return (*_veos_arch_ops->arch_vesync_sync_w_pci_register_area)();
}

/**
 * @brief Memory access serialize function for bar01.
 *
 * @return always 0
 */
int veos_sync_r_bar01_bar_cr(void)
{
	veos_commit_rdawr_order();
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to transfer any data completely to any resources over bar01 or bar with CR(VE1:bar3,VE3:bar4).
 */
	struct ve_node_struct *ve_node = VE_NODE(0);

	volatile uint64_t data __attribute__((unused));
	data = *(volatile uint64_t *)ve_node->pci_bar01_sync_addr;
	asm volatile ("":::"memory");
	return 0; /* always successful */
}

/**
 * @brief Memory access serialize function for bar2.
 *
 * @return always 0
 */
int veos_sync_r_bar2(void)
{
	return (*_veos_arch_ops->arch_vesync_sync_r_pci_register_area)();
}

