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
 * @file sysve_os.c
 * @brief VE1-dependent part of sysve functions in pseudo process side.
 */
#include "veos_defs.h"
#include "veos_arch_defs.h"
#include "sysve_os.h"

#define VE1_VEHVA_SYS_COM_REG_PAGE0_ADDR       0x000000001000
#define VE1_VEHVA_SYS_COM_REG_PAGE1_ADDR       0x000000002000
#define VE1_VEHVA_DMACTL_E_ADDR                0x000000003010
#define VE1_VEHVA_DMADES_E_ADDR                0x000000004000

#define REG_MASK_PSW 0x8000000000000000          /* bitmask for VE1 hardware */

/**
 * @brief This function gets fixed VEHVA mapping.
 *
 * @param[in] handle VEOS handle of pseudo process.
 * @param[in] region A region specified by macros.
 * @param[out] vehva VEMVA of a variable to store the start address in VEHVA
 * space of the specified region.
 *
 * @return 0 on Success, an negative error number on Failure.
 *
 * @retval -EINVAL on Region is invalid.
 * @retval -EFAULT on Pointer is invalid.
 *
 * @internal
 *
 * @author libsysve
 */
int ve1_get_fixed_vehva(uint64_t region, uint64_t *mapping_p)
{
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	switch (region) {
	case VE_VEHVA_SYS_COM_REG_PAGE0:
		*mapping_p = VE1_VEHVA_SYS_COM_REG_PAGE0_ADDR;
		break;
	case VE_VEHVA_SYS_COM_REG_PAGE1:
		*mapping_p = VE1_VEHVA_SYS_COM_REG_PAGE1_ADDR;
		break;
	case VE_VEHVA_DMACTL_E:
		*mapping_p = VE1_VEHVA_DMACTL_E_ADDR;
		break;
	case VE_VEHVA_DMADES_E:
		*mapping_p = VE1_VEHVA_DMADES_E_ADDR;
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
							"Invalid region");
		return -EINVAL;
		break;
	}
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_get_fixed_vehva, ve1_get_fixed_vehva)

int64_t ve1_set_PSW_bitmask(void)
{
	return REG_MASK_PSW;

}
VEOS_ARCH_DEP_FUNC(ve1, arch_set_PSW_bitmask, ve1_set_PSW_bitmask)
