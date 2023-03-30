/*
 * Copyright (C) 2020 NEC Corporation
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
 * @brief VE3 dependent part of VE sync operations
 */
#include <sys/mman.h>
#include <ve_drv.h>
#include <libved.h>
#include <ve_hw.h>

#include <veos_arch_defs.h>

#include <veos.h>

#define VE3_VESYNC_CREG_OFFSET_SYNC \
	(offsetof(ve3_system_common_reg_nonpre_t, SYNC))
#define VE3_VESYNC_CREG_OFFSET_DMYWR 0x00000408
#define VE3_VESYNC_BAR01_SYNC_ADDR_SIZE 4096

/**
 * @brief Allocate address for pci bar01 sync.
 *
 * @return address for BAR01 sync area on success, MAP_FAILURE on failure.
 *
 * This function must be called after pci_bar01_pgsz and vdso_pcientry are
 * initialized by AMM.
 */
void *ve3_vesync_map_bar01_sync_area(vedl_handle *hdl,
				struct ve_node_struct *venode)
{
	return mmap(NULL, VE3_VESYNC_BAR01_SYNC_ADDR_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED, vedl_get_fd(hdl),
			VEDRV_VE3_MAP_BAR0_OFFSET + venode->pci_bar_mem_pgsz
			* venode->vdso_pcientry);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_map_pci_memory_window_sync_area, ve3_vesync_map_bar01_sync_area)

void ve3_vesync_unmap_bar01_sync_area(void *ptr)
{
	munmap(ptr, VE3_VESYNC_BAR01_SYNC_ADDR_SIZE);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_unmap_pci_memory_window_sync_area, ve3_vesync_unmap_bar01_sync_area)

/**
 * @brief commit_rdawr_order
 *
 * @return always 0
 */
int ve3_vesync_commit_rdawr_order(void)
{
	/* VE3 is not supposed to require the workaround. */
	return 0; /* always successful */
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_commit_rdawr_order, ve3_vesync_commit_rdawr_order)

/**
 * @brief Invalidate branch history to avoid HW Bug
 *
 * @return 0 on success, -1 on failure.
 */
int ve3_vesync_invalidate_branch_history(int core_id)
{
	/* VE3 is not supposed to require the workaround. */
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_invalidate_branch_history, ve3_vesync_invalidate_branch_history)

/**
 * @brief Write serialize function for bar2.
 *
 * @return always 0
 */
int ve3_vesync_sync_w_bar2(void)
{
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to write any data completely to any resources over bar2.
 */
	vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
			VE3_VESYNC_CREG_OFFSET_SYNC, 0);
	/* mfence is not needed because memory type is UC */
	return 0; /* always successful */
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_sync_w_pci_register_area, ve3_vesync_sync_w_bar2)

/**
 * @brief Memory access serialize function for bar2.
 *
 * @return always 0
 */
int ve3_vesync_sync_r_bar2(void)
{
	ve3_vesync_commit_rdawr_order();
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to transfer any data completely to any resources over bar2.
 */
	ve_reg_t data;

	vedl_get_cnt_reg_word(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
			VE3_VESYNC_CREG_OFFSET_SYNC, &data);
	/* mfence is not needed because memory type is UC */
	return 0; /* always successful */
}
VEOS_ARCH_DEP_FUNC(ve3, arch_vesync_sync_r_pci_register_area, ve3_vesync_sync_r_bar2)
