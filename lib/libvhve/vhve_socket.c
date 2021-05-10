/*
 * Copyright (C) 2020-2021 NEC Corporation
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
 * @file  vhve_socket.c
 * @brief Socket Creation.
 *
 * This file contains the routines that are used for creation of socket
 * to be used for communication with VEOS modules i.e AMM/PSM.
 *
 * @internal
 * @author VHVE
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <poll.h>
#include "vhve_common.h"
#include "vhve_socket.h"

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
int vhve_veos_soc(char *sockpath)
{
	struct sockaddr_un sa = {0};
	int sockfd = -1;
	char *sock_path = sockpath;
	struct pollfd pfd = {0};
	int pret;
	int errv = EBUSY;
	char c;

	VHVE_TRACE("Entering");

	VHVE_DEBUG("SOCKPATH:%s", sockpath);

	/* Create a socket */
	sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sockfd < 0) {
		VHVE_ERROR("Failed to create socket:%s",
				strerror(errno));
		VHVE_INFO("socket path :%s", sockpath);
		goto handle_return;
	}

	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);
	sa.sun_path[sizeof(sa.sun_path)-1] = '\0';

	/* connect */
	if (-1 == connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		VHVE_ERROR("Connection to veos socket failed:%s",
				strerror(errno));
		VHVE_INFO("socket path :%s", sockpath);
		errv = EINVAL;
		goto handle_failure;
	}

	pfd.fd = sockfd;
	pfd.events = POLLIN;
	/* receive message from worker */
	pret = poll(&pfd, 1, 1000);
	if (pret <= 0) {
		if (pret == 0)
			VHVE_ERROR("Time out of polling VEOS worker");
		else
			VHVE_ERROR("Fail to poll VEOS worker(%s)",
					strerror(errno));
		VHVE_INFO("socket path :%s", sockpath);
		goto handle_failure;
	}
	if (pfd.revents != POLLIN) {
		VHVE_ERROR("No message from worker");
		VHVE_INFO("socket path :%s", sockpath);
		goto handle_failure;
	}
	if (vhve_recv_cmd(sockfd, &c, 1) != 1) {
		VHVE_ERROR("Unexpected reply from worker");
		VHVE_INFO("socket path :%s", sockpath);
		goto handle_failure;
	}

	goto handle_return;

handle_failure:
	close(sockfd);
	sockfd = -1;
handle_return:
	VHVE_TRACE("Exiting");
	if (sockfd == -1)
		errno = errv;
	else
		errno = 0;
	return sockfd;
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
ssize_t vhve_send_cmd(int socket_fd, void *buff, ssize_t max_len)
{
	ssize_t sent_byte = 0;

	VHVE_TRACE("Entering");

	if (!buff) {
		VHVE_ERROR("NULL argument recieved");
		return sent_byte;
	}

	while ((sent_byte =
			send(socket_fd, buff, max_len, MSG_NOSIGNAL)) == -1) {
		if (EINTR == errno || EAGAIN == errno) {
			VHVE_ERROR("Failed to communicate with veos: %s",
					strerror(errno));
			continue;
		} else {
			VHVE_ERROR("Failed to send cmd to VEOS: %s",
					strerror(errno));
			break;
		}
	}

	VHVE_DEBUG("sent_byte = %ld", sent_byte);

	VHVE_TRACE("Exiting");
	return sent_byte;
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
ssize_t vhve_recv_cmd(int sock_fd, void *buff, ssize_t bufsize)
{
	ssize_t ret = -1;
	VHVE_TRACE("Entering");

	if (!buff) {
		VHVE_ERROR("NULL argument recieved");
		goto recv_error;
	}

	while ((ret = recv(sock_fd, buff, bufsize, 0)) == -1) {
		if (errno == EINTR || errno == EAGAIN) {
			VHVE_ERROR("Failed to communicate with veos: %s",
					strerror(errno));
			continue;
		} else {
			VHVE_ERROR("Failed to recv cmd from VEOS: %s",
					strerror(errno));
			break;
		}
	}

	if (!ret) {
		ret = -1;
		VHVE_ERROR("Recieved EOF from VEOS");
	} else {
		VHVE_DEBUG("recv_byte = %ld", ret);
	}

recv_error:
	VHVE_TRACE("Exiting");
	return ret;
}
