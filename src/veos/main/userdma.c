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
 * @file userdma.c
 * @brief Handling IPC messages with VEOS.
 */
#include "proto_buff_schema.pb-c.h"
#include "task_mgmt.h"
#include "psm_comm.h"
#include "dmaatb_api.h"
#include "veos_ipc.h"

/*
 * @brief This function packs a message and sends it to a client.
 *
 * @param[in] pti	veos_thread_arg_t
 * @param[in] msg	message
 *
 * @return 0 on Success, an negative error number on Failure
 *
 * @retval -ECANCELED on IPC message error.
 * @retval -ENOMEM on memory allocation error.
 *
 * @author user DMA
 */
int userdma_reply(veos_thread_arg_t *pti, int result,
	ProtobufCBinaryData *data)
{
	return veos_reply(pti, result, data);
}

/*
 * @brief This function comunicates with VEOS to map DMA descriptor H.
 *
 * @param[in] pti	veos_thread_arg_t
 *
 * @return 0 on Success, -1 on Failure
 *
 * @author user DMA
 */
int veos_handle_map_dmades(veos_thread_arg_t *pti)
{
	int ret,result = -1;
	int err = 0;
	struct userdma dma;
	ProtobufCBinaryData reply_data;
	pid_t pid;

	assert(pti);

	VEOS_TRACE("Entering");

	pid = pti->cred.pid;

	/* call map function */
	memset(&dma, 0x0, sizeof(struct userdma));
	result = veos_map_dmades(pid, &dma.dmades, &dma.dmactl);
	VEOS_DEBUG("PID:%d:veos_map_dmades: ret=%d des=0x%lx ctl=0x%lx",
			pid, result,dma.dmades,dma.dmactl);

	/* set up a replied message */
	reply_data.len = sizeof(struct userdma);
	reply_data.data = (uint8_t *)&dma;

	/* reply data */
	ret = userdma_reply(pti, result, &reply_data);
	if (ret != 0) {
		VEOS_ERROR("PID:%d:Failed to communicate with Pseudo: %s",
			pid, strerror(-ret));
		err++;
	}

	if (err > 0)
		ret = -1; 

	VEOS_TRACE("Exiting");
	return ret;
}

/*
 * @brief This function comunicates with VEOS to unmap DMA descriptor H.
 *
 * @param[in] pti	veos_thread_arg_t
 *
 * @return 0 on Success, -1 on Failure
 */
int veos_handle_unmap_dmades(veos_thread_arg_t *pti)
{
	int ret,result = -1;
	int err = 0;
	struct userdma *dma;
	ProtobufCBinaryData *data;
	pid_t pid;

	assert(pti);

	VEOS_TRACE("Entering");

	pid = pti->cred.pid;

	/* get data */
	data = (ProtobufCBinaryData *)
		&((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg;
	if (data->len != sizeof(struct userdma)) {
		VEOS_ERROR("PID:%d:Invalid data length: %d",
			pid, (int)data->len);
		err++;
		goto err_ret;
	}
	if (data->data == NULL) {
		VEOS_ERROR("PID:%d:Invalid data", pid);
		err++;
		goto err_ret;
	}
	dma = (struct userdma *)data->data;

	/* call unmap function */
	result = veos_unmap_dmades(pid, dma->dmades);
	VEOS_DEBUG("PID:%d:veos_unmap_dmades: ret=%d des=0x%lx\n",
			pid, result, dma->dmades);

err_ret:
	/* reply data */
	ret = userdma_reply(pti, result, NULL);
	if (ret != 0) {
		VEOS_ERROR("PID:%d:Failed to communicate with Pseudo: %s",
			pid, strerror(-ret));
		err++;
	}

	if (err > 0)
		ret = -1;

	VEOS_TRACE("Exiting");
	return ret;
}
