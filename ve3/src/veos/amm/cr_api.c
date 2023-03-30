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
/**
 * @file cr_api.c
 * @brief VE3 dependent part of cr management related function.
 *
 * @internal
 * @author AMM
 */
#include <string.h>
#include <libved.h>
#include <ve_hw.h>
#include <libved_ve3.h>

#include <veos.h>
#include <task_mgmt.h>
#include <cr_api.h>

#include <veos_arch_defs.h>

#define VE3_CR_CLUSTER_OFFSET(i) (offsetof(ve3_system_common_reg_pre_t, CR[i]))
#define VE3_CRD_OFFSET(i) (offsetof(ve3_core_system_reg_pre_t, CRD[i]))

int ve3_amm_init_cr_reg(void)
{
	ve3_cr_cluster_t cr_arr[32];
	off_t offset = VE3_CR_CLUSTER_OFFSET(0);
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	VEOS_TRACE("invoked");

	memset(cr_arr, 0, sizeof(cr_arr));
	int ret = vedl_set_cnt_reg_words(cnt_regs, LIBVED_VE3_AREA_BAR23,
				offset, cr_arr, sizeof(cr_arr));
	if (ret < 0) {
		VEOS_DEBUG("Failed in initializing CR cluster (%d)", ret);
		veos_abort("Failed to initialize CR data");
	}
	VEOS_TRACE("returned %d", ret);
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_init_cr_reg, ve3_amm_init_cr_reg)

int ve3_amm_set_crd(crd_t *crd, int crd_entry, int core_id, size_t size)
{
	VEOS_TRACE("invoked with crd (%p) crd_entry (%d) core (%d) size (%ld)",
			crd, crd_entry, core_id, size);
	off_t offset = VE3_CRD_OFFSET(crd_entry);
	vedl_sys_reg_handle *sys_regs = VE_CORE_SYS_REG(0, core_id);
	int ret = vedl_set_sys_reg_words(sys_regs, LIBVED_VE3_AREA_BAR23,
			offset, &crd[crd_entry], size);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) to set crd entry", strerror(-ret));
	}
	VEOS_TRACE("returned %d", ret);
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_set_crd, ve3_amm_set_crd)

int ve3_amm__clear_cr_cluster(uint64_t cr_page)
{
	VEOS_TRACE("invoked with cr_page %ld", cr_page);
	ve3_cr_cluster_t cr_data;
	memset(&cr_data, 0, sizeof(cr_data));
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = VE3_CR_CLUSTER_OFFSET(cr_page);
	return vedl_set_cnt_reg_words(cnt_regs, LIBVED_VE3_AREA_BAR23,
				offset, &cr_data, sizeof(cr_data));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__clear_cr_cluster, ve3_amm__clear_cr_cluster)

#define ASSERT_CR_CLUSTER_SIZE do { \
		if (sizeof(ve3_cr_cluster_t) != sizeof(cr_cluster_t)) \
			veos_abort("sizeof ve3_cr_cluster_t (%ld) " \
			"!= sizeof cr_cluster_t (%ld)", \
			sizeof(ve3_cr_cluster_t), sizeof(cr_cluster_t)); \
	} while (0)

int ve3_amm__save_cr_cluster(uint64_t cr_page, cr_cluster_t *buffer)
{
	ASSERT_CR_CLUSTER_SIZE;
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = VE3_CR_CLUSTER_OFFSET(cr_page);

	VEOS_DEBUG("save CR contents (%lx, size %ld)", offset,
			sizeof(ve3_cr_cluster_t));
	return vedl_get_cnt_reg_words(cnt_regs, LIBVED_VE3_AREA_BAR23,
				offset, buffer, sizeof(*buffer));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__save_cr_cluster, ve3_amm__save_cr_cluster)

int ve3_amm__restore_cr_cluster(uint64_t cr_page, const cr_cluster_t *buffer)
{
	ASSERT_CR_CLUSTER_SIZE;
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = VE3_CR_CLUSTER_OFFSET(cr_page);

	VEOS_DEBUG("restore CR contents (%lx, size %ld)", offset,
			sizeof(ve3_cr_cluster_t));
	return vedl_set_cnt_reg_words(cnt_regs, LIBVED_VE3_AREA_BAR23,
				offset, buffer, sizeof(*buffer));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm__restore_cr_cluster, ve3_amm__restore_cr_cluster)

int ve3_amm_get_pci_crarea_address(uint64_t *addrp)
{
	return vedl_ve3_get_pci_bar4_crarea_address(VE_HANDLE(0), addrp);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_amm_get_pci_crarea_address, ve3_amm_get_pci_crarea_address)
