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

#define VESYNC_CREG_OFFSET_SYNC (offsetof(system_common_reg_t, SYNC))
#define VESYNC_CREG_OFFSET_DMYWR 0x00000408
#define VESYNC_BAR01_SYNC_ADDR_SIZE 4096

#define VE_CORE_OFFSET_OF_HCR 0x10a00
#define VE_RSA_DISABLE_BIT_ON 0xf000000000000000
#define VE_RSA_DISABLE_BIT_OFF 0x0000000000000000

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

	ve_node->pci_bar01_sync_addr = mmap(NULL, VESYNC_BAR01_SYNC_ADDR_SIZE,
					    PROT_READ | PROT_WRITE, MAP_SHARED,
					    vh->vefd,
					    VEDRV_MAP_BAR0_OFFSET
					    + ve_node->pci_bar01_pgsz
					    * ve_node->vdso_pcientry);
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
		munmap(ve_node->pci_bar01_sync_addr,
		       VESYNC_BAR01_SYNC_ADDR_SIZE);
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
	for (int i = 0; i < 20; i++) {
		vedl_set_cnt_reg_word(VE_HANDLE(0), VE_CORE_CNT_REG_ADDR(0),
				      VESYNC_CREG_OFFSET_DMYWR, 0);
	}
	/* mfence is not needed because memory type is UC */
	return 0; /* always successful */
}

/**
 * @brief Invalidate branch history to avoid HW Bug
 *
 * @return 0 on success, -1 on failure.
 */
int veos_invalidate_branch_history(int core_id)
{
	reg_t regdata = 0;
	if (core_id < 0 || VE_NODE(0)->nr_avail_cores <= core_id)
		return -1;

	regdata = VE_RSA_DISABLE_BIT_ON;
	vedl_set_sys_reg_words(VE_HANDLE(0),
			       VE_CORE_SYS_REG_ADDR(0, core_id),
			       VE_CORE_OFFSET_OF_HCR,
			       &regdata, sizeof(reg_t));
	regdata = VE_RSA_DISABLE_BIT_OFF;
	vedl_set_sys_reg_words(VE_HANDLE(0),
                               VE_CORE_SYS_REG_ADDR(0, core_id),
                               VE_CORE_OFFSET_OF_HCR,
                               &regdata, sizeof(reg_t));
	return 0;
}

/**
 * @brief Write serialize function for bar2.
 *
 * @return always 0
 */
int veos_sync_w_bar2(void)
{
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to write any data completely to any resources over bar2.
 */
	vedl_set_cnt_reg_word(VE_HANDLE(0), VE_CORE_CNT_REG_ADDR(0),
			      VESYNC_CREG_OFFSET_SYNC, 0);
	/* mfence is not needed because memory type is UC */
	return 0; /* always successful */
}

/**
 * @brief Memory access serialize function for bar01.
 *
 * @return always 0
 */
int veos_sync_r_bar01_bar3(void)
{
	veos_commit_rdawr_order();
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to transfer any data completely to any resources over bar01 or bar3.
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
	veos_commit_rdawr_order();
/*
 * As VE-HW specifications, the followings are necessary for VEOS
 * to transfer any data completely to any resources over bar2.
 */
	reg_t data;

	vedl_get_cnt_reg_word(VE_HANDLE(0), VE_CORE_CNT_REG_ADDR(0),
			      VESYNC_CREG_OFFSET_SYNC, &data);
	/* mfence is not needed because memory type is UC */
	return 0; /* always successful */
}

