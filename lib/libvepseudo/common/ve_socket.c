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
* @file  ve_socket.c
* @brief Socket Creation.
*
* This file contains the routines that are used for creation of socket
* to be used for communication with VEOS modules i.e AMM/PSM.
*
* @internal
* @author Pseudo/System Call Handling
*/

#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include "sys_common.h"
#include "ve_socket.h"
#include "exception.h"
#include "libved.h"
#include "velayout.h"

/**
 * @brief Socket creation routine.
 *
 *	This routine creates socket for communication with VEOS modules
 *	AMM/PSM.
 *
 * @param[in] sockpath Socket file path name.
 *
 * @return: -1 on FAILURE, socket file descriptor on SUCCESS.
 */
int pseudo_veos_soc(char *sockpath)
{
	struct sockaddr_un sa = {0};
	int sockfd = -1;
	char *sock_path = sockpath;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("SOCKPATH:%s", sockpath);

	/* Create a socket */
	sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockfd < 0) {
		PSEUDO_ERROR("Failed to create socket");
		PSEUDO_INFO("socket path :%s", sockpath);
		goto handle_failure;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);
	sa.sun_path[sizeof(sa.sun_path)-1] = '\0';

	/* connect */
	if (-1 == connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		PSEUDO_ERROR("Connection to veos socket failed");
		PSEUDO_INFO("socket path :%s", sockpath);
		close(sockfd);
		sockfd = -1;
		goto handle_failure;
	}

handle_failure:
	PSEUDO_TRACE("Exiting");
	return sockfd;
}

/**
 * @brief This Function is used to send signal request to VEOS
 *
 * @param socket_fd Descriptor used to communicate with VE OS
 * @param buff contain req info to be sent to VE OS
 * @param max_len size of packed structure
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ssize_t pseudo_veos_send_signal_req(int socket_fd, void *buff, ssize_t max_len)
{
	ssize_t transferred = 0;
	ssize_t sent_byte = 0;


	if (!buff) {
		transferred = -1;
		goto send_error;
	}

	while ((sent_byte =
		send(socket_fd, buff + transferred,
		     max_len - transferred, MSG_NOSIGNAL)) != 0) {
		if (sent_byte == -1) {
			if (EINTR == errno || EAGAIN == errno) {
				continue;
			} else if (EPIPE == errno) {
				WRITE(2, "Connection has been shut down\n", 30);
				pseudo_abort();
			} else {
				WRITE(2, "Connection lost\n", 16);
				pseudo_abort();
			}
		}
		transferred += sent_byte;
		if (transferred == max_len)
			break;
	}

send_error:
	return transferred;
}

/**
 * @brief This Function is used to communicate with PSM
 *
 * @param socket_fd Descriptor used to communicate with PSM
 * @param buff contain req info to be sent to PSM
 * @param max_len size of packed structure
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
ssize_t pseudo_veos_send_cmd(int socket_fd, void *buff, ssize_t max_len)
{
	ssize_t transferred = 0;
	ssize_t sent_byte = 0;

	PSEUDO_TRACE("Entering");

	if (!buff) {
		transferred = -1;
		PSEUDO_ERROR("NULL argument recieved");
		goto send_error;
	}

	while ((sent_byte =
		send(socket_fd, buff + transferred,
		     max_len - transferred, MSG_NOSIGNAL)) != 0) {
		if (sent_byte == -1) {
			if (EINTR == errno || EAGAIN == errno) {
				continue;
			} else if (EPIPE == errno) {
				PSEUDO_ERROR("Failed to communicate with "
						"veos: %s", strerror(errno));
				fprintf(stderr, "Error: %s\n", strerror(errno));
				pseudo_abort();
			} else {
				PSEUDO_ERROR("Sending Command from Pseudo "
					"to VEOS failed :%s", strerror(errno));
				fprintf(stderr, "Connection lost: %s\n",
						strerror(errno));
				pseudo_abort();
			}
		}
		transferred += sent_byte;
		if (transferred == max_len)
			break;
		PSEUDO_DEBUG("transferred = %ld, sent_byte = %ld",
				transferred, sent_byte);
	}

send_error:
	PSEUDO_TRACE("Exiting");
	return transferred;
}
/**
 * @brief This function is used to communicate with VEOS
 *
 * @param sock_fd veos_sock_fd Descriptor used to communicate with VEOS
 * @param buff Response returned from VEOS
 * @param bufsize Size of Packed strcuture
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ssize_t pseudo_veos_recv_signal_ack(int sock_fd,
		void *buff, ssize_t bufsize)
{
	ssize_t ret = -1;

	if (!buff)
		goto recv_error;

	while ((ret = recv(sock_fd, buff, bufsize, 0)) == -1) {
		if (errno == EINTR || errno == EAGAIN) {
			continue;
		} else {
			WRITE(2, "Connection lost\n", 16);
			pseudo_abort();
		}
	}

	if (!ret)
		ret = -1;

recv_error:
	return ret;
}

/**
 * @brief This function is used to communicate with PSM
 *
 * @param sock_fd veos_sock_fd Descriptor used to communicate with PSM
 * @param buff Response returned from PSM
 * @param bufsize Size of Packed strcuture
 *
 * @return On failure, returns -1 and on success, returns any positive value
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
ssize_t pseudo_veos_recv_cmd(int sock_fd,
		void *buff, ssize_t bufsize)
{
	ssize_t ret = -1;
	PSEUDO_TRACE("Entering");

	if (!buff) {
		PSEUDO_ERROR("NULL argument recieved");
		goto recv_error;
	}

	while ((ret = recv(sock_fd, buff, bufsize, 0)) == -1) {
		if (errno == EINTR || errno == EAGAIN) {
			PSEUDO_ERROR("Received Command from VEOS"
					"to Pseudo failed :%s",
					strerror(errno));
			continue;
		} else {
			PSEUDO_ERROR("Received Command from VEOS"
					"to Pseudo failed :%s",
					strerror(errno));
			fprintf(stderr, "Connection lost: %s\n",
					strerror(errno));
			pseudo_abort();
		}
	}

	if (!ret) {
		ret = -1;
		PSEUDO_ERROR("Recieved EOF from VEOS");
	}

recv_error:
	PSEUDO_TRACE("Exiting");
	return ret;
}
