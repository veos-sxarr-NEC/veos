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
* @file	ve_coredump_helper.c
*
* @brief Helps in VE core file formation
*
*	This file contains the functions which provides support to create
*	VE core file. It opens ve core file and communicate file descriptor
*	to VE OS over socket.
*
* @internal
* @author Signal Handling
*/

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define COREDUMP_FAILED 1

static int status;

/**
* @brief Send VE core file fd to VE OS.
*
* 	This function will communicate ve core file fd
* 	to VE OS,VE OS will dump ve core data into file
* 	pointed by fd.
*
* @param[in] sockfd, fd to communicate with veos.
* @param[] ve_cffd, VE core file fd to be sent.
*/
void send_ve_corefile_fd(int sockfd, int ve_cffd)
{
	struct msghdr msg;
	char buf[CMSG_SPACE(sizeof(int))];
	int data = 1234;
	struct iovec dummy_data;
	struct cmsghdr *cmsg;
	int *cffd;

	memset(&msg, '\0', sizeof(struct msghdr));
	memset(buf, '\0', sizeof(buf));
	memset(&dummy_data, '\0', sizeof(struct iovec));

	/* Transmit at least 1 byte of real data in order to send ancillary
	 * data */
	dummy_data.iov_base = &data;
	dummy_data.iov_len = sizeof(int);
	msg.msg_iov = &dummy_data;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	/* Set message header to describe ancillary data that we want to
	 * send */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (NULL == cmsg) {
		status = COREDUMP_FAILED;
		return;
	}

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(ve_cffd));
	cffd = (int *) CMSG_DATA(cmsg);
	memcpy(cffd, &ve_cffd, sizeof(int));

	/* Do the actual send */
	if (sendmsg(sockfd, &msg, 0) <= 0) {
		status = COREDUMP_FAILED;
		return;
	}
}

/**
 * @brief main() for coredump helper
 *
 *	This fucntion will create a fd for ve core file, it send this
 *	fd to VE OS.
 *
 * @param[in] argc Received argument count
 * @param[in] argv Argument buffers received
 *
 * @return exit() 0 on success, positive number on failure.
 */
int main(int argc, const char *argv[])
{
	int ve_cffd, sockfd;
	int ret_status = COREDUMP_FAILED;

	errno = 0;
	/* Get socket fd */
	sockfd = strtol(argv[2], NULL, 10);
	if (errno)
		goto handle_exit;

	/* Get file descriptor of ve core file */
	ve_cffd = open(argv[1], O_CREAT | O_NOFOLLOW | O_LARGEFILE |
			O_RDWR, 0600);
	if (-1 == ve_cffd)
		goto close_socket;

	/* Send VE core file fd so that VE OS can perform elf dumping */
	send_ve_corefile_fd(sockfd, ve_cffd);

	close(ve_cffd);
	ret_status = status;

close_socket:
	close(sockfd);
handle_exit:
	_exit(ret_status);
}
