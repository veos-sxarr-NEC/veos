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
 * @file  pciatb_api.c
 * @brief VE1 dependent part of  PCIATB realated functions
 *
 * @internal
 * @author AMM
 */
#include <stdlib.h>
#include <string.h>

#include <libved.h>
#include <ve_hw.h>
#include <libved_ve1.h>

#include <veos_arch_defs.h>

#include <veos.h>

#include <pciatb_api.h>

size_t ve1_amm_get_PCIATB_VLD_SIZE(void)
{
	return VE1_PCIATB_VLD_SIZE;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_get_number_of_pci_pte, ve1_amm_get_PCIATB_VLD_SIZE)

int ve1_amm_pciatb_dump(void)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
        ve1_pciatb_entry_t *pci_entry = NULL;
        int ret = 0;

        VEOS_TRACE("invoked to dump PCIATB");
        pci_entry = calloc(VE1_PCIATB_VLD_SIZE, (sizeof(ve1_pciatb_entry_t)));
        if (NULL == pci_entry) {
                ret = -ENOMEM;
                VEOS_CRIT("error (%s) in allocating pci entry obj",
                        strerror(-ret));
                return ret;
        }

        ret = vedl_ve1_get_pciatb_all(cnt_regs, pci_entry);
        if (ret < 0) {
                free(pci_entry);
                veos_abort("unable to read pciatb hardware reg values");
        }

        for (int pci_ent = 0; pci_ent < VE1_PCIATB_VLD_SIZE; pci_ent++)
                VEOS_DEBUG("PCIATB[%d] : 0x%lx", pci_ent, pci_entry[pci_ent].data);

        free(pci_entry);
        VEOS_TRACE("returned(%d)", ret);
        return  ret;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_pciatb_dump, ve1_amm_pciatb_dump)

int ve1_amm_set_pciatb_attr(uint64_t attr, uint64_t val)
{
	pci_attr_t p_attr;
	int ret;

	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	VEOS_TRACE("invoked to set pciatb attribute");
	off_t offset = offsetof(ve1_system_common_reg_t, PCIATBA);

	memset(&p_attr, 0, sizeof(p_attr));

	/* get pgmod in PCIATBA register */
	ret = vedl_get_cnt_reg_word(cnt_regs, 0, offset, (ve_reg_t *)&p_attr);
	if (ret < 0) {
		VEOS_ERROR("unable to read pciatb attr register (%d)", ret);
		return ret;
	}

	/* If PCIATB page size is specified, set; ignore otherwise */
	if (attr == PCIATTR_SIZE) {
		p_attr.data = val;
		VEOS_DEBUG("PCIATB attribute is set to %ld", p_attr.data);
	}
	/* set PCIATBA */
	ret = vedl_set_cnt_reg_word(cnt_regs, 0, offset, p_attr.data);
	if (ret < 0) {
		VEOS_ERROR("unable to update pciatb attr register (%d)", ret);
		return ret;
	}
	/* Read PCIATBA again and store in node struct */
	ret = vedl_get_cnt_reg_word(cnt_regs, 0, offset, (ve_reg_t *)&p_attr);
	if (ret < 0) {
		VEOS_ERROR("unable to read pciatb attr register (%d)", ret);
		return ret;
	}
	struct ve_node_struct *vnode = VE_NODE(0);
	vnode->pciattr = p_attr.data;

	VEOS_DEBUG("PCI PAGE MODE SET TO :%s",
		(vnode->pciattr == 0) ?  "2MB PGMODE" : "64MB PGMODE");

        VEOS_TRACE("returned");

	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_set_pciatb_attr, ve1_amm_set_pciatb_attr)

int ve1_amm_get_pci_BAR01_size(size_t *sizep)
{
	return vedl_ve1_get_pci_bar0_size(VE_HANDLE(0), sizep);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_get_pci_memory_window_size, ve1_amm_get_pci_BAR01_size)

int ve1_amm_get_pci_BAR01_addr(uint64_t *addrp)
{
	return vedl_ve1_get_pci_bar0_address(VE_HANDLE(0), addrp);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_get_pci_memory_window_address, ve1_amm_get_pci_BAR01_addr)

int ve1_amm_invalidate_all_pciatb_entries(void)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	/* Mark all PCIATB entries as invalid
	 * in both S/W status and in H/W registers. */
	for (int entry_cnt = 0; entry_cnt < VE1_PCIATB_VLD_SIZE; ++entry_cnt) {
		vnode->pciatb[entry_cnt].data = INVALID_ENTRY;
		ve1_pciatb_entry_t e = {.data = INVALID_ENTRY};
		int ret = vedl_ve1_update_pciatb_entry(cnt_regs, &e, entry_cnt);
		if (ret < 0) {
			VEOS_ERROR("unable to update PCIATB entry %d (%d)",
				entry_cnt, ret);
			return ret;
		}
	}
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_invalidate_all_pciatb_entries, ve1_amm_invalidate_all_pciatb_entries)

int ve1_amm_set_pciatb(const veos_pciatb_entry_t *reg, int entry_no, int count)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);

	VEOS_TRACE("invoked to set pciatb with entry#(%d), count(%d)",
			entry_no, count);

	for (int idx = entry_no; idx < entry_no + count; ++idx) {
		VEOS_TRACE("Updating PCIATB entry %d", idx);
		int ret = vedl_ve1_update_pciatb_entry(cnt_regs,
				(const ve1_pciatb_entry_t *)&reg[idx], idx);
		if (ret < 0) {
			VEOS_ERROR("unable to update PCIATB entry %d (%d)",
					idx, ret);
			return ret;
		}
	}
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_set_pciatb, ve1_amm_set_pciatb)

int ve1_amm_update_pciatb_entry(const veos_pciatb_entry_t *reg, int e)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);

	VEOS_TRACE("invoked to set pciatb entry#(%d)", e);
	return vedl_ve1_update_pciatb_entry(cnt_regs,
				(const ve1_pciatb_entry_t *)reg, e);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm_update_pciatb_entry, ve1_amm_update_pciatb_entry)

int ve1_amm__set_pcisymr(uint8_t num, uint64_t val)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = offsetof(ve1_system_common_reg_t,
				pciatb_sync_addr_mask[num]);

	return vedl_set_cnt_reg_word(cnt_regs, 0, offset, val);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm__set_pcisymr, ve1_amm__set_pcisymr)

int ve1_amm__get_pcisymr(uint8_t num, uint64_t *valp)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = offsetof(ve1_system_common_reg_t,
				pciatb_sync_addr_mask[num]);

	return vedl_get_cnt_reg_word(cnt_regs, 0, offset, valp);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm__get_pcisymr, ve1_amm__get_pcisymr)

int ve1_amm__set_pcisyar(uint8_t num, uint64_t val)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = offsetof(ve1_system_common_reg_t, pciatb_sync_addr[num]);

	return vedl_set_cnt_reg_word(cnt_regs, 0, offset, val);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm__set_pcisyar, ve1_amm__set_pcisyar)

int ve1_amm__get_pcisyar(uint8_t num, uint64_t *valp)
{
	vedl_common_reg_handle *cnt_regs = VE_NODE_CNT_REG(0);
	off_t offset = offsetof(ve1_system_common_reg_t, pciatb_sync_addr[num]);

	return vedl_get_cnt_reg_word(cnt_regs, 0, offset, valp);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_amm__get_pcisyar, ve1_amm__get_pcisyar)
