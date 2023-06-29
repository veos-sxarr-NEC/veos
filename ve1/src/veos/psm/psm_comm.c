/**
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
 * @file udma.c
 * @brief user DMA resource for VE3
 */
#include <stdlib.h>

#include <veos_arch_defs.h>
#include <veos.h>
#include <string.h>

/**
 * @brief This function is used to compare the versions.
 *
 * @param veos_ver[in] version number of VEOS
 * @param recvd_ver[in] version number received
 *
 * @return,
 * -1 if veos version is smallar than received version number
 * 1 if veos version is greater than received version number
 * 0 if both veos and received version is same.
 */
int ve1_psm_comm_version_compare(char *veos_ver, char *recvd_ver)
{
	int veos_len = 0, recvd_len = 0;
	int veos_num = 0, recvd_num = 0;
	int vlv = 0, lv = 0;

	veos_len = strlen(veos_ver);
	VEOS_DEBUG("VEOS version: %s  length: %d", veos_ver, veos_len);
	recvd_len = strlen(recvd_ver);
	VEOS_DEBUG("Received version: %s  length: %d", recvd_ver,  recvd_len);

	for (vlv = 0, lv = 0; (vlv < veos_len || lv < recvd_len);) {
		/* Store each digit of 'veos_ver' in 'veos_num' one by one */
		while (vlv < veos_len && veos_ver[vlv] != '.') {
			veos_num = veos_num * 10 + (veos_ver[vlv] - '0');
			vlv++;
		}

		/* Store each digit of 'recvd_ver' in 'recvd_num' one by one */
		while (lv < recvd_len && recvd_ver[lv] != '.') {
			recvd_num = recvd_num * 10 + (recvd_ver[lv] - '0');
			lv++;
		}

		/* Now compare each digit of veos version with received version */

		if (veos_num < recvd_num) {
			VEOS_DEBUG("veos version is older than received version");
			return -1;
		}
		if (recvd_num < veos_num) {
			VEOS_DEBUG("veos version is newer than received version");
			return 1;
		}

		veos_num = recvd_num = 0;
		vlv++;
		lv++;
	}
	VEOS_DEBUG("veos version is equal to received version");
	return 0;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_psm_comm_version_compare, ve1_psm_comm_version_compare)
