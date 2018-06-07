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
 * @file  ived_ipc.c
 * @brief Common RPC functions 
 *
 * @internal
 * @author VESHM
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <pthread.h>
#include "libved.h"
#include "ived_common.h"
#include "ived_ipc.h"
#include "ived.pb-c.h"

#define RETRY			3

/**
 * @brief allocate a buffer for protocol buffer (uint8_t *)
 *
 * @param [in, out] buf   Pointer of buffer
 * @param [in]      size  Size of buffer
 *
 * @return : return 0 and set valid address to buf parameter on success, 
 * reutn 1 and set NULL to buf parameter on failure. 
 * */
int 
get_rpc_buf(uint8_t **buf, size_t size){

	if (size == 0){
		IVED_DEBUG(log4cat_lib, "Requested size is 0.");
		*buf = NULL;
		return(1);
	}

	uint8_t *tmp = (uint8_t *)malloc(size);
	if (tmp == NULL){
		IVED_CRIT(log4cat_lib, "Buffer allocation failed");
		*buf = NULL;
		return(1);
	}
	*buf = tmp;
	return(0);
}

/**
 * @brief This function create a socket.
 * (Copy from pseudo process code)
 *
 * @param sockpath: socket file path name
 *
 * @return: Returns socket file descriptor on success and -1
 * on errors
 */
int 
ived_create_soc(char *sockpath)
{
	struct sockaddr_un sa = {0};
	int sockfd = -1;
	char *sock_path = sockpath;
	int sun_path_len = 0;

	IVED_DEBUG(log4cat_lib, "SOCKPATH:%s", sockpath);

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* Create a socket */
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		IVED_ERROR(log4cat_lib, 
			   "Failed to create socket: %s\n", sockpath);
		return -1;
	}

	/* It seems like we don't use UNIX_PATH_MAX, because sys/un.h
	 * changed UNIX_PATH_MAX to constant number. */
	sun_path_len = sizeof(sa.sun_path);
	if (strlen(sockpath) > (sun_path_len-1) ){
		IVED_ERROR(log4cat_lib, 
			   "Socket path is too long.: %s\n", sockpath);
		return -1;
	}
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sock_path, sun_path_len);
	sa.sun_path[sun_path_len-1] = '\0';

	/* connect */
	if (-1 == connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		IVED_ERROR(log4cat_lib, 
			   "Connection to veos socket failed %s\n", sock_path);
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/**
 * @brief Shutdown and close a socket
 *
 * @param [in] sock	Sockeet FD
 *
 * @return 0 on success, -1 and set errno of shutdown or close on error
 */
int
ived_finish_soc(int sock)
{
	int ret;
	IVED_TRACE(log4cat_lib, "PASS");

	ret = shutdown(sock, SHUT_WR);
	if (ret != 0){
		return (-1);
	}
	errno = 0;
	ret = close(sock);

	return(ret);
}

/**
 * @brief  It receives a telegram.
 *
 * This function receives a telegram and store it to a buffer.
 * If *reply_buf == NULL, allocate a buffer before receiving a message.
 * A caller function must free the buffer.
 *
 * If *reply_buf != NULL, skip buffer allocation in this function 
 * and use *reply_buf.
 *
 * @param [in]     soc_fd     Socket file descriptor
 * @param [in,out] reply_buf  Save a received message 
 *
 * @return Result of receiving
 * @retval Length_of_message The length of a recieved message on success
 * @retval IVED_RPC_ERR_RECV and set errno of library call on failure
 */
int 
ived_rpc_receive(int soc_fd, uint8_t **reply_buf)
{
	int ret;
	int retval=0;
	int sv_err = 0;
	uint8_t *ret_buff = NULL;
	ssize_t read_size;		/* size of recieved message */
	ssize_t write_pos;		/* write position on ret_buff */
	int32_t telegram_size = 0;

	IVED_TRACE(log4cat_lib, "PASS");

	assert (sizeof(int32_t) == IVED_PROTO_BUF_POS);

	if (reply_buf == NULL){
		sv_err = ECANCELED;
		retval = IVED_RPC_ERR_RECV;
		IVED_CRIT(log4cat_lib, "Invalid argument");
		assert(reply_buf != NULL);
		goto err_ret;
	}

	write_pos = 0;
	while (write_pos < IVED_PROTO_BUF_POS) {
		ret = read(soc_fd, (char *)&telegram_size + write_pos,
			   IVED_PROTO_BUF_POS - write_pos);
		if (ret < 0){
			if (errno == EINTR){
				/* Retry */
				continue;
			}
			sv_err = errno;
			retval = IVED_RPC_ERR_RECV;
			IVED_ERROR(log4cat_lib, 
				   "Receiving a message failed.(err:%d)",
				   sv_err);
			goto err_ret;
		}
		if (ret == 0){
			sv_err = errno;
			retval = IVED_RPC_ERR_RECV;
			IVED_DEBUG(log4cat_lib, 
				   "Socket of a peer is closed.");
			goto err_ret;
		}
		write_pos += ret;
	}
	IVED_TRACE(log4cat_lib, "Received telegram_size =%d",telegram_size);

	if (telegram_size > IVED_BUF_MAX_SIZE){
		retval = IVED_RPC_ERR_RECV;
		IVED_ERROR(log4cat_lib, "Message is larger than predictable size:%d",
			   (int)telegram_size);
		goto err_ret;
	}

	if (*reply_buf == NULL){
		if ( get_rpc_buf(reply_buf, telegram_size) ){
			retval = IVED_RPC_ERR_RECV;
			goto err_ret;
		}
	}
	ret_buff = *reply_buf;

	write_pos = 0;
	while (write_pos < telegram_size) {

		read_size = read(soc_fd, ret_buff + write_pos, 
				 telegram_size - write_pos);
		if (read_size == 0) {
			sv_err = errno;
			retval = IVED_RPC_ERR_RECV;
			IVED_DEBUG(log4cat_lib, "Socket of a peer is closed.");
			goto err_ret;
		}
		if (read_size == -1) {
			if ( errno == EINTR ){
				IVED_TRACE(log4cat_lib,
					   "read: %s", strerror(errno));
				continue;
			} else {
				sv_err = errno;
				retval = IVED_RPC_ERR_RECV;
				IVED_ERROR(log4cat_lib, "%s", strerror(errno));
				goto err_ret;
			}
		}

		IVED_TRACE(log4cat_lib, "read_size:%zd write_pos:%zd", 
			   read_size, write_pos);

		write_pos += read_size;

	}
	if ( write_pos > telegram_size){
		IVED_ERROR(log4cat_lib, 
			  "Received telegram is too big.size =%d, write:%zd",
			  telegram_size, write_pos);
		retval = IVED_RPC_ERR_RECV;
		sv_err = ECANCELED;
		goto err_ret;
	}
	retval = write_pos;
err_ret:
	IVED_TRACE(log4cat_lib, "retval (received size) =%d",retval);
	errno = sv_err;
	return(retval);
}

/**
 * @brief  It sends a telegram.
 *
 * This function send a telegram and shutdown(SHUT_WR).
 *
 * @param [in]     soc_fd     Socket file descriptor
 * @param [in]     telegram   Packed telegram to send
 * @param [in]     size       Size of telegram
 *
 * @return Result of sending
 * @retval 0 on success
 * @retval IVED_RPC_ERR      and set errno of cause on failure
 * @retval IVED_RPC_ERR_SEND and set errno of cause on failure
 */
static int
ived_rpc_send(int soc_fd, uint8_t *telegram, size_t size)
{
	int ret;
	int retval=0, sv_err = 0;
	size_t remainder;
	int32_t telegram_size = size;

	IVED_TRACE(log4cat_lib, "PASS");
	assert (telegram != NULL);
	assert (sizeof(int32_t) == IVED_PROTO_BUF_POS);

	remainder = IVED_PROTO_BUF_POS;
	while (remainder > 0) {
		ret = write(soc_fd, &telegram_size, remainder);
		if (ret == -1) {
			if ( errno == EINTR ){
				IVED_WARN(log4cat_lib, "Send: %s", 
					  strerror(errno));
				continue;
			} else {
				/* EPIPE or etc. */
				sv_err = errno;
				retval = IVED_RPC_ERR_SEND;
				IVED_ERROR(log4cat_lib, "Send: %s", 
					   strerror(errno));
				goto err_out;
			}
		} else {
			remainder -= ret;
		}
	}

	remainder = size;
	while (remainder > 0) {
		ret = write(soc_fd, telegram, remainder);
		if (ret == -1) {
			if ( errno == EINTR ){
				IVED_WARN(log4cat_lib, "Send: %s", 
					  strerror(errno));
				continue;
			} else {
				/* EPIPE or etc. */
				sv_err = errno;
				retval = IVED_RPC_ERR_SEND;
				IVED_ERROR(log4cat_lib, "Send: %s", 
					   strerror(errno));
				break;
			}
		} else {
			remainder -= ret;
		}
	}
err_out:
	if (remainder != 0)
		retval = IVED_RPC_ERR;	/* Failed before sending */
	IVED_TRACE(log4cat_lib, "[%d] retval =%d, errno=%d",
		   (uint)pthread_self(), retval, sv_err);
	errno = sv_err;
	return (retval);
}

/**
 * @brief  Send a RPC request to a server.
 *
 * This function updates ret_msg_size to actual received buffer size.
 *
 * @param [in]     socket_fd	Socket file id of destination
 * @param [in]     request	Request message
 *
 * @return  Result of RPC 
 * @retval  0 and a valid packed reply on success
 * @retval  IVED_RPC_ERR on failure before sending a message
 * @retval  IVED_RPC_ERR_SEND on failure during sending request
 */

static int
ived_client_send_request(int socket_fd, RpcCommand *request)
{
	int ret;
	int retval = 0;
	uint8_t *telegram = NULL;	/* Buffer for transmission */
	uint32_t telegram_size = 0;

	telegram_size = rpc_command__get_packed_size(request);

	if ( get_rpc_buf(&telegram, telegram_size) ){
		retval = IVED_RPC_ERR;
		goto err_ret;
	}

	/* Make a telegram */
	IVED_DEBUG(log4cat_lib, "telegram_size: %d", telegram_size);

	ret = rpc_command__pack(request, telegram);
	if ( ret <= 0 ){
		IVED_ERROR(log4cat_lib, 
			   "RPC request: Packing failed.");
		retval = IVED_RPC_ERR;
		goto err_ret;
	}

	/* Send the telegram */
	ret = ived_rpc_send(socket_fd, telegram, telegram_size);
	if ( ret != 0 ){
		retval = ret;
		goto err_ret;
	}

	retval = 0;
err_ret:
	IVED_DEBUG(log4cat_lib, "PASS: retval =%d",retval);
	if (telegram != NULL){
		free(telegram);
	}
	return(retval);
}


/**
 * @brief Send a message to a remote node.
 * Add telegram size in a message.
 *
 * @param [in]     socket_fd	Socket file id of destination
 * @param [in]     payload	Packed payload of RPC message
 * @param [in]     payload_size Size of a payload of RPC message
 *
 * @return  Result of RPC 
 * @retval  0 on success
 * @retval  IVED_RPC_ERR on failure before sending a message
 * @retval  IVED_RPC_ERR_SEND on failure (from a low level function)
 *
 * */

int
ived_server_send_reply_common(int socket_fd, 
			      uint8_t *payload, size_t payload_size)
{
	int retval;

	/* Write a reply data */
	retval = ived_rpc_send(socket_fd, payload, payload_size);
	return(retval);
}


/**
 * @breif Send a reply
 *
 * @param [in]    reply_msg	Reply message
 *
 * @return  Result of RPC 
 * @retval  0 on success
 * @retval  IVED_RPC_ERR on failure before sending a message
 * @retval  IVED_RPC_ERR_SEND on failure (from a low level function)
 */
int
ived_send_reply_msg(int socket_fd, IvedReturn *reply_msg)
{
	int ret, retval;
	uint8_t *payload_buf = NULL;
	size_t payload_size;

	assert(reply_msg != NULL);

	IVED_TRACE(log4cat_lib, "[%u] PASS", (uint)pthread_self());

	/* Make a payload */
	payload_size = ived_return__get_packed_size(reply_msg);
	if (payload_size > INT_MAX){
		retval = IVED_FUNC_ERR;
		goto err_ret;
	}
	get_rpc_buf(&payload_buf, payload_size);
	if(payload_buf == NULL){
		retval = IVED_FUNC_ERR;
		goto err_ret;
	}
	ret = ived_return__pack(reply_msg, payload_buf);
	if (ret == 0){
		IVED_ERROR(log4cat_lib, "Fail to pack a message.");
		retval = IVED_FUNC_ERR;
		goto err_ret;
	}
	ret = ived_server_send_reply_common(socket_fd, payload_buf, 
					    payload_size);
	if ( ret != 0 ){
		IVED_WARN(log4cat_lib, "Sending message failed.");
	}
	retval = ret;
err_ret:
	if (payload_buf != NULL)
		free(payload_buf);
	IVED_DEBUG(log4cat_lib, "[%u] retval:%d", (uint)pthread_self(), retval);
	return(retval);
}

/**
 * @brief Send retval and error by ived_return type.
 * 
 * @param [in] socket_fd	Socket
 * @param [in] retval		Return value
 * @param [in] error		Error
 *
 * @return  Result of RPC 
 * @retval  0 on success
 * @retval  IVED_RPC_ERR on failure before sending a message
 * @retval  IVED_RPC_ERR_SEND on failure (from a low level function)
 */
int
ived_send_int64(int socket_fd, int64_t rpc_retval, int error)
{
	int retval = IVED_RPC_ERR;
	int length;
	uint8_t *buf;
	IvedReturn reply = IVED_RETURN__INIT;

	reply.retval = rpc_retval;
	reply.error = error;

	IVED_DEBUG(log4cat_lib, "[%u] rpc_retval=%#"PRIx64" rpc_reterr=%d", 
		   (uint)pthread_self(), rpc_retval, error);
	length = ived_return__get_packed_size(&reply);
	get_rpc_buf(&buf, length);
	if (buf == NULL){
		goto err_ret;
	}
	length = ived_return__pack(&reply, buf);
	if (length == 0){
		IVED_ERROR(log4cat_lib, "Packing a reply failed.");
		goto err_ret;
	}

	retval = ived_server_send_reply_common(socket_fd, buf, length);

err_ret:
	if (buf != NULL){
		free(buf);
	}

	IVED_TRACE(log4cat_lib, "[%u] retval:%d", (uint)pthread_self(), retval);
	return (retval);
}


/**
 * @brief Common function for ived_exchange_ived_msg, 
 * ived_exchange_veshm_msg and ived_exchange_cr_msg.
 * Those functions differ a message type of protocol buffers only.
 * NOTE: A Caller must free reply.
 *
 * @param [in]     socket_fd	 Socket file id of destination
 * @param [in]     request	Request message
 * @param [out]    reply	 Stored a reply from IVED
 *
 * @return  Result of RPC 
 * @retval  0 and a valid UNPACKED reply on success
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 */
static int
ived_exchange_message(int socket_fd, RpcCommand *request,
		      IvedReturn **reply)
{
	IvedReturn *result = NULL;	/* IVED returns the type */
	int retval = 0;
	uint8_t *reply_buf = NULL;	/* buffer for reply */
	int64_t received_size;

	IVED_TRACE(log4cat_lib, "PASS");

	assert(reply != NULL);

	retval = ived_client_send_request(socket_fd, request);
	if (retval != 0){
		goto err_ret;
	}
	received_size = ived_rpc_receive(socket_fd, &reply_buf);
	if (received_size < 0 || received_size > INT_MAX){
		retval = received_size;
		goto err_ret;
	}
	result = ived_return__unpack(NULL, received_size, reply_buf);
	if (result == NULL){
		IVED_ERROR(log4cat_lib, "Unpacking data failed.");
		retval = IVED_RPC_ERR_RECV;
		goto err_ret;
	}
	*reply = result;

err_ret:
	if (reply_buf != NULL)
		free(reply_buf);

	IVED_TRACE(log4cat_lib, "retval:%d", retval);
	return(retval);
}


/**
 * @brief Pack and send a IVED request, receive and unpack a reply.
 * NOTE: A Caller must free reply.
 *
 * @param [in]    socket_fd	Socket file id of destination
 * @param [in]    ived_arg	IVED request
 * @param [out]   reply		Stored a reply from IVED
 *
 * @return  Result of RPC 
 * @retval  0 and a valid UNPACKED reply on success
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 *
 */
int
ived_exchange_ived_msg(int socket_fd, RpcIvedArg *ived_arg, 
		       IvedReturn **reply)
{
	RpcCommand request = RPC_COMMAND__INIT;
	int retval = 0;

	IVED_TRACE(log4cat_lib, "PASS");

	assert(ived_arg != NULL);
	assert(reply != NULL);

	request.cmd = IVED_COMMON;
	request.ived = ived_arg;
	/* Send and receive message */
	retval = ived_exchange_message(socket_fd, &request, reply);

	if (retval != 0){
		IVED_DEBUG(log4cat_lib, "Abort.");
	}

	IVED_TRACE(log4cat_lib, "PASS");
	return(retval);
}


/**
 * @brief Pack and send a VESHM request, receive and unpack a reply.
 * NOTE: A Caller must free reply.
 *
 * @param [in]    socket_fd	Socket file id of destination
 * @param [in]    veshm_arg	VESHM request
 * @param [out]   reply		Stored a reply from IVED
 *
 * @return  Result of RPC 
 * @retval  0 and a valid UNPACKED reply on success
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 *
 */
int
ived_exchange_veshm_msg(int socket_fd, RpcVeshmArg *veshm_arg, 
			IvedReturn **reply)
{
	RpcCommand request = RPC_COMMAND__INIT;
	int retval = 0;

	assert(veshm_arg != NULL);
	assert(reply != NULL);

	request.cmd = IVED_VESHM;
	request.veshm = veshm_arg;

	/* Send a message and receive a reply */
	retval = ived_exchange_message(socket_fd, &request, reply);

	if (retval != 0){
		IVED_ERROR(log4cat_lib, "Abort.");
	}

	IVED_DEBUG(log4cat_lib, "retval:%d", retval);
	return (retval);
}

/**
 * @brief Pack and send a CR request, receive and unpack a reply.
 * NOTE: A Caller must free reply.
 *
 * @param [in]    socket_fd	Socket file id of destination
 * @param [in]    cr_arg	CR request
 * @param [out]   reply		Stored a reply from IVED
 *
 * @return  Result of RPC 
 * @retval  0 and a valid UNPACKED reply on success
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 *
 */
int
ived_exchange_cr_msg(int socket_fd, RpcCrArg *cr_arg, IvedReturn **reply)
{
	RpcCommand request = RPC_COMMAND__INIT;
	int retval = 0;

	assert(cr_arg != NULL);
	assert(reply != NULL);

	request.cmd = IVED_CR;
	request.cr = cr_arg;

	/* Send a message and receive a reply */
	retval = ived_exchange_message(socket_fd, &request, reply);

	if (retval != 0){
		IVED_ERROR(log4cat_lib, "Abort.");
	}

	IVED_DEBUG(log4cat_lib, "retval:%d", retval);
	return (retval);
}
