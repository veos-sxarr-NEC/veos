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
 * @file pseudo_vemm.c
 * @brief Function for libraries using VEMM
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include "libvepseudo.h"
#include "ived_common.h"
#include "pseudo_ived_common.h"
#include "comm_request.h"

int64_t ve_vhva_to_vehva(veos_handle *handle, const void *vhva)
{
	PseudoVeosMessage req_msg = PSEUDO_VEOS_MESSAGE__INIT;
	PseudoVeosMessage *reply_msg = NULL;
	int64_t retval;

	ProtobufCBinaryData pseudo_msg = {
		.len = sizeof(vhva),
		.data = (uint8_t *)&vhva,
	};

	req_msg.pseudo_veos_cmd_id = CMD_VEMM;
	/**
	 * No sub command ID is defined currently.
	 * If adding new functions regarding VEMM,
	 * DEFINE sub commands for all function including THIS.
	 */
	req_msg.has_pseudo_pid = true;
	req_msg.pseudo_pid = syscall(SYS_gettid);
	req_msg.has_pseudo_msg = true;
	req_msg.pseudo_msg = pseudo_msg;

	int ret = exchange_request(handle, &req_msg, &reply_msg);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
			   "Failed to communicate with VEOS");
		/**
		 * Do not exit to make VH call library possible
		 * to handle this error.
		 */
		errno = -ret;
		pseudo_veos_message__free_unpacked(reply_msg, NULL);
		return -1;
	}
	retval = reply_msg->syscall_retval;
	pseudo_veos_message__free_unpacked(reply_msg, NULL);

	IVED_DEBUG(log4cat_pseudo_ived, "return: %#lx", (unsigned long)retval);
	if (retval < 0 && -4096 < retval) {
		IVED_DEBUG(log4cat_pseudo_ived, "set errno = %ld", -retval);
		errno = -retval;
		retval = -1;
	}
	return retval;
}
