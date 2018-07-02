/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file  pseudo_cr.c
 * @brief CR functions (Pseudo process)
 *
 * @internal
 * @author CR
 */

#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "handle.h"
#include "ived_common.h"
#include "pseudo_ived_common.h"
#include "sys_common.h"
#include "comm_request.h"
#include "ived_request.h"
#include "pseudo_cr.h"

/**
 * @brief The entry function for CR
 *
 * @param [in]  handle  veos_handle
 * @param [in]  args    Array of system call arguments.
 *                      The size is NR_CR_ARGS.
 *
 * @return return value of system call
 */
ret_t ve_cr(veos_handle *handle, uint64_t *args)
{
	PseudoVeosMessage req_msg = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData bin_data;
	PseudoVeosMessage *reply_msg = NULL;
	struct cr_args cr_args;
	reg_t retval = 0;
	int ret;

	cr_args.subcmd = args[0];
	memcpy(cr_args.args, &args[1], sizeof(uint64_t) * NR_CR_ARGS);
	IVED_DEBUG(log4cat_pseudo_ived, "CR request: %d", cr_args.subcmd);

	bin_data.len = sizeof(struct cr_args);
	bin_data.data = (uint8_t *)&cr_args;

	req_msg.pseudo_veos_cmd_id = CMD_CR;
	req_msg.has_pseudo_pid = true;
	req_msg.pseudo_pid = syscall(SYS_gettid);
	req_msg.has_pseudo_msg = true;
	req_msg.pseudo_msg = bin_data;

	ret = exchange_request(handle, &req_msg, &reply_msg);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Failed to communicate with VEOS: %s", strerror(-ret));
		fprintf(stderr, "Failed to communicate with VEOS\n");
		pseudo_abort();
	} else {
		retval = reply_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(reply_msg, NULL);

	IVED_DEBUG(log4cat_pseudo_ived,	"retval:%"PRIi64, retval);
	return retval;
}
