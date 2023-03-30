/*
 * Copyright (C) 2017-2022 NEC Corporation
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
 * @file pseudo_devmem.c
 * @brief VE-GPU data transfer functions (Pseudo process side)
 *
 * @internal
 * @author VE-GPU
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/shm.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <unistd.h>

#include "proto_buff_schema.pb-c.h"
#include "pseudo_devmem.h"
#include "veos_defs.h"
#include "devmem_defs.h"
#include "pseudo_ived_common.h"
#include "ived_common.h"
#include "ived_request.h"
#include "comm_request.h"
#include "mm_transfer.h"

/**
 * @brief This function sends DEVMEM request and receives responce.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] args Pointer to dev_mem_args structure which is going to be sent.
 *
 * @retval A return value which is corresponding to sub command of args.
 */
static int64_t sys_devmem_exchange_request(veos_handle *handle,
						const struct dev_mem_args *args)
{
	int ret = 0;
	int64_t retval = 0;
	PseudoVeosMessage devmem_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData devmem_req_msg;
	struct dev_mem_args arguments;
	PseudoVeosMessage *ret_msg = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&devmem_req_msg, '\0', sizeof(ProtobufCBinaryData));
	memcpy(&arguments, args, sizeof(struct dev_mem_args));
	devmem_req_msg.len = sizeof(struct dev_mem_args);
	devmem_req_msg.data = (uint8_t *)&arguments;

	devmem_req.pseudo_veos_cmd_id = CMD_DEV_MEM;
	devmem_req.has_pseudo_pid = true;
	devmem_req.pseudo_pid = syscall(SYS_gettid);
	devmem_req.has_pseudo_msg = true;
	devmem_req.pseudo_msg = devmem_req_msg;

	ret = exchange_request(handle, &devmem_req, &ret_msg);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Failed to excahnge DEVMEM request(%d) with VEOS",
			arguments.subcmd);
		fprintf(stderr, "Failed to communicate with VEOS\n");
		pseudo_abort();
	} else {
		retval = ret_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function excanges sys_attach_dev_mem() request with VEOS.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] devmem_id Identifier of gpu memory.
 *
 * @retval VEHVA on success, -errno on failure.
 *
 * @note Before calling this function, check all arguments.
 */
static int64_t sys_devmem_exchange_attach_request(veos_handle *handle, int devmem_id)
{
	uint64_t retval = 0;
	struct dev_mem_args arguments;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&arguments, '\0', sizeof(struct dev_mem_args));
	arguments.subcmd = DEVMEM_AT;
	arguments.atg_arg.devmem_id = (uint64_t)devmem_id;

	retval = sys_devmem_exchange_request(handle, &arguments);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;
}

/**
 * @brief This function exchanges sys_detach_dev_mem() request with VEOS.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] VEHVA An address is related GPU memory which is registered with DMAATB
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Before calling this function, check all arguments.
 */
static int sys_devmem_exchange_detach_request(veos_handle *handle, uint64_t vehva)
{
	int retval = 0;
	struct dev_mem_args arguments;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&arguments, '\0', sizeof(struct dev_mem_args));
	arguments.subcmd = DEVMEM_DT;
	arguments.dtg_arg.vehva = vehva;

	retval = (int)sys_devmem_exchange_request(handle, &arguments);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;
}

/**
 * @brief This function attaches on VH and requests VEOS
 * to.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] devmem_id Identifer of GPU memory.
 *
 * @retval VEHVA(The address of the attached GPU memory)
 * on success, -errno on failure.
 *
 * @note Before calling this function, ensure that argument "handle" is not
 * NULL.
 */
int64_t sys_attach_dev_mem(veos_handle *handle, int devmem_id)
{
	int64_t retval = -EINVAL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	IVED_DEBUG(log4cat_pseudo_ived, "Attaching device memory. ID:%hd", devmem_id);
	
	retval = sys_devmem_exchange_attach_request(handle, devmem_id);
	if (retval < 0) {
		IVED_ERROR(log4cat_pseudo_ived,
				"VEOS returned error(%s) to attach_dev_mem() request",
				strerror(-(int)retval));
	}

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function sends a request to VEOS to release attached address with
 * DAMATB and detaches GPU memory
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] vehva An address which is attached to GPU memory
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Before calling this function, ensure that argument "handle" is not
 * NULL.
 */
int sys_detach_dev_mem(veos_handle *handle, const uint64_t vehva)
{
	int retval = -EINVAL;
	int ret = 0;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	IVED_DEBUG(log4cat_pseudo_ived, "Dettaching device memory. VEHVA:%lx", vehva);

	ret = sys_devmem_exchange_detach_request(handle, vehva);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
				"VEOS returned error(%s) to detach_dev_mem() request",
				strerror(-ret));
		retval = ret;
		goto hndl_return;
	}

	retval = 0;

hndl_return:
	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function is an entry point of sysve system call for DEVMEM
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] args Pointer to system call arguments
 *
 * @retval Any positive value on success, -errno on failure.
 */
ret_t sys_dev_mem(veos_handle *handle, uint64_t *args)
{
	int subcmd = 0;
	ret_t retval = -ECANCELED;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	if ((handle == NULL) || (args == NULL)) {
		IVED_DEBUG(log4cat_pseudo_ived,
					"Internal error: Argument is NULL");
		goto hndl_return;
	}

	subcmd = (int)args[0];
	IVED_DEBUG(log4cat_pseudo_ived, "subcmd of DEVMEM : %d", subcmd);

	switch (subcmd) {
	case DEVMEM_AT:
		retval = sys_attach_dev_mem(handle, args[1]);
		break;
	case DEVMEM_DT:
		retval = sys_detach_dev_mem(handle, (const uint64_t)args[1]);
		break;
	default:
		IVED_ERROR(log4cat_pseudo_ived,
			   "Internal error: Invalid command %d", subcmd);
	}

hndl_return:
	IVED_DEBUG(log4cat_pseudo_ived, "Return with %ld", retval);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;
}
