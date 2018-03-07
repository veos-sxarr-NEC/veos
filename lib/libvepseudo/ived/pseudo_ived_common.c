/**
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
 * @file pseudo_ived_common.c  
 * @brief IVED related common function at pseudo process.
 * @brief Header for VESHM
 *
 * @internal
 * @author VESHM
 */

#include <errno.h>
#include <error.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <log4c.h>

#include "pseudo_ived_common.h"
#include "ived_common.h"
#include "pseudo_ived_common.h"
#include "ve_socket.h"

#define CMD_BUFFER_SIZE (4*1024)

log4c_category_t *log4cat_pseudo_ived = NULL;

/**
 * @brief Initialize log4cat_pseudo_ived.
 *
 * @return 0 on success, -1 on failure
 */
int
pseudo_ived_log4c_init(void)
{
	log4cat_pseudo_ived = log4c_category_get("veos.pseudo_process.ived");
	if (log4cat_pseudo_ived == NULL) {
		return -1;
	}
	IVED_DEBUG(log4cat_pseudo_ived, "Initialized log4c.");
	return 0;
}

/**
 * @brief Send a request to VEOS and receive a response.
 *
 * @param [in]     handle      veos handle
 * @param [in]     ve_ived_req request command 
 * @param [out]    ret_buf     reply buffer
 *
 * @return 0 on success, -errno on failure
 */
int
exchange_request(veos_handle *handle,
		 PseudoVeosMessage *ve_ived_req, PseudoVeosMessage **ret_buf)
{

	/* Use ve_shm_request() as a reference for 
	 * exchanging messages.
	 */
	int ret, retval = -1, sv_errno = 0;
	int read_num = 0;
	void *cmd_buf_req;			/* Packed message */
	size_t pseudo_msg_len;
	char cmd_buf_ack[CMD_BUFFER_SIZE];	/* Packed ack */
	PseudoVeosMessage *pseudo_ret_msg;	/* Unpacked ack */

	if (handle == NULL || ve_ived_req == NULL || ret_buf == NULL){
		IVED_CRIT(log4cat_pseudo_ived, "Internal error: Argument is NULL");
		return(-ECANCELED);
	}

	pseudo_ret_msg   = NULL;

	/* Set up a message */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(ve_ived_req);
	if (pseudo_msg_len == 0){
		sv_errno = -ECANCELED;
		IVED_ERROR(log4cat_pseudo_ived, "IPC message error: %s",
			   strerror(sv_errno));
		goto err_ret_nofree;
	}
	cmd_buf_req = malloc(pseudo_msg_len);
	if (cmd_buf_req == NULL) {
		sv_errno = -errno;
		IVED_CRIT(log4cat_pseudo_ived, "Buffer allocation failed");
		goto err_ret_nofree;
	}
	memset(cmd_buf_req, '\0', pseudo_msg_len);
	ret = pseudo_veos_message__pack(ve_ived_req, cmd_buf_req);
	if (ret <= 0){
		sv_errno = -ECANCELED;
		IVED_ERROR(log4cat_pseudo_ived, "IPC message error: %s",
			   strerror(sv_errno));
		goto err_ret;
	}

	/* Socket id to communicate with VEOS */
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req,
				   pseudo_msg_len);
	if (ret < 0) {
		sv_errno = -ECANCELED;
		IVED_ERROR(log4cat_pseudo_ived, "IPC message error(send): %s",
			   strerror(sv_errno));
		goto err_ret;
	}

	read_num = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
					CMD_BUFFER_SIZE);
	if (read_num < 0){
		sv_errno = -ECANCELED;
		IVED_ERROR(log4cat_pseudo_ived, "IPC message error (recv): %s",
			   strerror(sv_errno));
		goto err_ret;
	}
	pseudo_ret_msg = pseudo_veos_message__unpack
		(NULL, read_num, (const uint8_t *)(cmd_buf_ack));
	if (pseudo_ret_msg == NULL) {
		sv_errno = -ECANCELED;
		IVED_ERROR(log4cat_pseudo_ived, "IPC message error: %s",
			   strerror(sv_errno));
		goto err_ret;
	}
	*ret_buf = pseudo_ret_msg;
	retval = 0;

err_ret:
	free(cmd_buf_req);
err_ret_nofree:
	IVED_DEBUG(log4cat_pseudo_ived, "PASS: retval:%d, errno=%d", 
		   retval, sv_errno);
	if (sv_errno != 0)
		retval = sv_errno;
	return (retval);
}
