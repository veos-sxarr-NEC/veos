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
 * @file ptrace_comm.c
 * @brief Handlers for communication with VEOS
 *
 * @internal
 * @author PTRACE
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdbool.h>
#include "ptrace_comm.h"
#include "ve_ptrace.h"
#include "ptrace_log.h"
#include "veos_ptrace_comm.h"
#include "proto_buff_schema.pb-c.h"

int *ve_node_num = NULL;

/**
 * @brief It will create socket for communication with VEOS.
 *
 * @param[in] node Node number to communicate with
 *
 * @return socket file descriptor on success, -1 on failure.
 */
int veos_sock(int node)
{
	struct sockaddr_un sa = {0};
	char veos_sock_name[PATH_MAX] = {0};
	int sockfd = -1;

	VE_PTRACE_TRACE("Entering");

	sprintf(veos_sock_name, "%s/veos%d.sock", VEOS_SOC_PATH, node);

	if (ve_node_num == NULL)
		VE_PTRACE_INFO("VEOS Socket Path: %s", veos_sock_name);
	else
		VE_PTRACE_DEBUG("VEOS Socket Path: %s", veos_sock_name);

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* Create a socket */
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket: %s",
				strerror(errno));
		goto hndl_return;
	}

	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, veos_sock_name, strlen(veos_sock_name)+1);

	/* Connect with VEOS */
	if (-1 == connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		VE_PTRACE_DEBUG("Connection to VEOS failed: %s",
				strerror(errno));
		close(sockfd);
		VE_PTRACE_DEBUG("Closed Socket fd: %d", sockfd);
		sockfd = -1;
		goto hndl_return;
	}

hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return sockfd;
}

/**
 * @brief Function will return the socket file descriptor of VEOS.
 *
 * @param[in] pid PID of the tracee
 *
 * @return socket file descriptor on success and -1 in case of failure.
 */
int get_veos_sock_fd(pid_t pid)
{
	int node = -1;
	int veos_sock_fd = -1;

	VE_PTRACE_TRACE("Entering");

	/* When this function is called first time, then we
	 * need to find the node number on which the given
	 * pid exists.
	 */
	if (NULL == ve_node_num) {
		node = find_ve_process_node_number(pid);
		if (-1 == node) {
			errno = ESRCH;
			goto out;
		}

		ve_node_num = (int *)malloc(sizeof(int));
		if (NULL == ve_node_num) {
			VE_PTRACE_ERR("Internal Memory Allocation Failed");
			VE_PTRACE_DEBUG("malloc fails: %s",
					strerror(errno));
			goto out;
		}

		/* Node number is maintained and this node number is
		 * used to communicate with VEOS.
		 */
		*ve_node_num = node;
	}

	veos_sock_fd = veos_sock(*ve_node_num);
	if (-1 == veos_sock_fd) {
		VE_PTRACE_ERR("Failed to connect with VEOS");
		goto out;
	}

	VE_PTRACE_DEBUG("Socket fd obtained: %d", veos_sock_fd);
out:
	VE_PTRACE_TRACE("Exiting");
	return veos_sock_fd;
}

/**
 * @brief It will communicates with VEOS ans check whether the pid
 * exists or not.
 *
 * @param[in] sock_fd VEOS socket file descriptor
 * @param[in] pid PID of the tracee
 *
 * @return 0 if pid found and -1 on failure.
 */
int check_ve_pid(int veos_sock_fd, pid_t pid)
{
	int retval = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(CHECK_PID) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = CHECK_PID;
	pt_req.pid = pid;

	/* Command send to VEOS for starting VE process */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(CHECK_PID) Communication Fails");
		goto hndl_return;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("Request(CHECK_PID) fails for PID: %d", pid);
		retval = -1;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;

}

/**
 * @brief This function will find the node number on which the pid exists.
 * It will communicate with all the running VEOS in the system.
 *
 * @param[in] pid PID of the tracee
 *
 * @return Node number on success and -1 on failure.
 */
int find_ve_process_node_number(pid_t pid)
{
	int retval = -1;
	int node = 0;
	int sock_fd = 0;
	bool found = false;

	VE_PTRACE_TRACE("Entering");

	/* Communicate with all the VEOS to check pid
	 * exists or not.
	 */
	for (node = 0; node < MAX_VE_NODE; node++) {
		/* Obtain VEOS socket fd corresponding
		 * to node number.
		 */
		sock_fd = veos_sock(node);
		if (-1 == sock_fd)
			continue;

		VE_PTRACE_DEBUG("Socket fd obtained: %d", sock_fd);

		/* check pid by communicating with specific VEOS */
		retval = check_ve_pid(sock_fd, pid);
		if (0 == retval) {
			VE_PTRACE_DEBUG("Closed Socket fd: %d", sock_fd);
			close(sock_fd);
			found = true;
			break;
		} else {
			VE_PTRACE_DEBUG("Closed Socket fd: %d", sock_fd);
			close(sock_fd);
			continue;
		}
	}

	/* If pid is not found on all the running VEOS then return
	 * failure.
	 */
	if (false == found) {
		node = -1;
		VE_PTRACE_ERR("VE PID: %d not found", pid);
		goto out;
	}

	VE_PTRACE_INFO("PID: %d belongs to VE Node: %d", pid, node);
out:
	VE_PTRACE_TRACE("Exiting");
	return node;
}

/**
 * @brief Write the buffer on the file descriptor.
 *
 * @param[in] socket_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to buffer to send
 * @param[in] max_len Size of buffer
 *
 * @return positive value on success, -1 on failure.
 */
ssize_t veos_write_buf(int socket_fd, void *buf, ssize_t max_len)
{
	ssize_t transferred = 0;
	ssize_t write_byte = 0;

	VE_PTRACE_TRACE("Entering");

	VE_PTRACE_DEBUG("Send REQ on fd: %d, buffer: %p, length: %ld",
			socket_fd, buf, max_len);

	if (!buf) {
		transferred = -1;
		goto hndl_return;
	}

	while ((write_byte =
		send(socket_fd, buf + transferred,
		      max_len - transferred, MSG_NOSIGNAL)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VE_PTRACE_DEBUG("Sending Command failed %s",
						strerror(errno));
				VE_PTRACE_ERR("Failed to communicate with VEOS");
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;

		VE_PTRACE_DEBUG("transferred = %ld, write_byte = %ld",
			  transferred, write_byte);
	}

hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return transferred;

}

/**
 * @brief Read the buffer on the file descriptor.
 *
 * @param[in] socket_fd Socket descriptor used to communicate
 * @param[in] buf Pointer to buffer to send
 *
 * @return positive value on success, -1 on failure.
 */
ssize_t veos_read_buf(int socket_fd, void *buf)
{
	ssize_t read_bytes = -1;

	VE_PTRACE_TRACE("Entering");

	if (!buf)
		goto hndl_return;

	read_bytes = recv(socket_fd, buf, MAX_PROTO_MSG_SIZE, 0);
	if (-1 == read_bytes) {
		VE_PTRACE_DEBUG("recv() fail: %s", strerror(errno));
		VE_PTRACE_ERR("Failed to communicate with VEOS");
		goto hndl_return;
	}

	VE_PTRACE_DEBUG("Recv REQ on fd: %d, buffer: %p, Received length: %ld",
			socket_fd, buf, read_bytes);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return read_bytes;
}

/**
 * @brief Function will pack the message buffer and send to VEOS.
 *
 * @param[in] veos_soc_fd Socket descriptor used to communicate
 * @param[in] pt_req Ptrace request structure
 *
 * @return 0 on success, -1 on failure.
 */
int pack_and_send_cmd(int veos_soc_fd, ptrace_req pt_req)
{
	int retval = -1;
	PseudoVeosMessage ptrace_cmd = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ptrace_req_buf = {0};
	ssize_t ptrace_msg_len = 0, msg_pack_len = 0, write_len = 0;
	void *buf = NULL;

	VE_PTRACE_TRACE("Entering");

	ptrace_cmd.pseudo_veos_cmd_id = PTRACE_REQUEST;

	ptrace_cmd.has_pseudo_pid = true;
	ptrace_cmd.pseudo_pid = syscall(SYS_gettid);

	ptrace_req_buf.len = sizeof(ptrace_req);
	ptrace_req_buf.data = (uint8_t *)&pt_req;

	ptrace_cmd.has_pseudo_msg = true;
	ptrace_cmd.pseudo_msg = ptrace_req_buf;

	ptrace_msg_len = pseudo_veos_message__get_packed_size(&ptrace_cmd);

	buf = malloc(ptrace_msg_len);
	if (NULL == buf) {
		VE_PTRACE_DEBUG("malloc fails: %s", strerror(errno));
		VE_PTRACE_ERR("Internal Memory Allocation Failed");
		goto hndl_return;
	}

	VE_PTRACE_DEBUG("IPC message length prepared of size: %ld",
			ptrace_msg_len);

	/* Pack the messgae */
	msg_pack_len = pseudo_veos_message__pack(&ptrace_cmd, buf);
	if (ptrace_msg_len != msg_pack_len) {
		VE_PTRACE_DEBUG("pseudo_veos_message__pack fail"
				"returns: %ld, but required %ld",
				msg_pack_len, ptrace_msg_len);
		VE_PTRACE_ERR("Protocol Buffers Internal Error");
		goto hndl_return1;
	}

	/* Write the packed buffer to socket */
	write_len = veos_write_buf(veos_soc_fd, buf, ptrace_msg_len);
	if (write_len < ptrace_msg_len) {
		VE_PTRACE_DEBUG("veos_write_buf wrote: %ld, req: %ld",
				write_len, ptrace_msg_len);
		goto hndl_return1;
	}

	retval = 0;
hndl_return1:
	free(buf);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will read the buffer from socket and unpack the buffer.
 *
 * @param[in] veos_soc_fd Socket descriptor used to communicate
 * @param[in] pt_req Pointer to structure ptrace_req
 *
 * @return 0 on success, -errno on failure.
 */
int recv_and_unpack_cmd(int veos_soc_fd, ptrace_req *pt_req)
{
	int retval = -1;
	char buf[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage *ptrace_cmd = NULL;
	ssize_t read_len = 0;

	VE_PTRACE_TRACE("Entering");

	memset(buf, 0, MAX_PROTO_MSG_SIZE);

	/* Read the buffer from scoket */
	read_len = veos_read_buf(veos_soc_fd, buf);
	if (-1 == read_len) {
		VE_PTRACE_DEBUG("Read from veos socket fail: %s",
				strerror(errno));
		retval = -errno;
		goto hndl_return;
	}

	/* Unpack the read buffer */
	ptrace_cmd = pseudo_veos_message__unpack(NULL, read_len,
			(const uint8_t *)buf);
	if (NULL == ptrace_cmd) {
		VE_PTRACE_DEBUG("pseudo_veos_message__unpack fails read length: %ld",
			read_len);
		VE_PTRACE_ERR("Protocol Buffers Internal Error");
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Check the success/failure from VEOS */
	if (ptrace_cmd->syscall_retval < 0) {
		VE_PTRACE_DEBUG("VEOS returned value: %ld",
				ptrace_cmd->syscall_retval);
		VE_PTRACE_ERR("Failure Received from VEOS");
		retval = ptrace_cmd->syscall_retval;
		goto hndl_return1;
	}

	if (pt_req)
		memcpy(pt_req, ptrace_cmd->pseudo_msg.data, sizeof(ptrace_req));

	retval = 0;
hndl_return1:
	pseudo_veos_message__free_unpacked(ptrace_cmd, NULL);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and start the VE process
 * for the given pid.
 *
 * @param[in] pid PID of the tracee
 *
 * @return 0 on success, -errno on failure.
 */
int ve_start_process(pid_t pid)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(START_PROCESS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = START_PROCESS;
	pt_req.pid = pid;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for starting VE process */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(START_PROCESS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("Request(START_PROCESS) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("VEOS(START_PROCESS) Success for PID: %d", pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and stop the VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] seized_stop Determines the stop of seized procces
 *
 * @return 0 on success, -errno on failure.
 */
int ve_stop_process(pid_t pid, bool seized_stop)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(STOP_PROCESS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = STOP_PROCESS;
	pt_req.pid = pid;
	pt_req.data = seized_stop;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for stopping VE process */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(STOP_PROCESS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(STOP_PROCESS) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("VEOS(STOP_PROCESS) Success for PID: %d", pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to attach the VE process.
 *
 * @param[in] pid PID of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_attach(pid_t pid)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(ATTACH) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = ATTACH;
	pt_req.pid = pid;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for stopping VE process */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(ATTACH) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(ATTACH) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("VEOS(ATTACH) Success for PID: %d", pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to get the content
 * from the VE memory from tracee's address space.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr Pointer to tracee virtual address
 * @param[out] data Data from VE memory address
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_peekdata(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");

	if (!data)
		goto hndl_return;

	VE_PTRACE_DEBUG("Requesting VEOS(PEEKDATA) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = PEEKDATA;
	pt_req.pid = pid;
	pt_req.addr = (uint64_t)addr;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for reading content at the given VEMVA */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(PEEKDATA) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	memset(&pt_req, 0, sizeof(pt_req));

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, &pt_req);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(PEEKDATA) fails for PID: %d", pid);
		goto hndl_return1;
	}

	*((long *)data) = pt_req.data;

	VE_PTRACE_DEBUG("PEEKDATA at Address: %p is 0x%lx for PID: %d",
			addr, pt_req.data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to stores the content in
 * data to VE memory at the given address (VEMVA).
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr Pointer to tracee virtual address
 * @param[in] data Pointer to data to store
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_pokedata(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(POKEDATA) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = POKEDATA;
	pt_req.pid = pid;
	pt_req.addr = (uint64_t)addr;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for writing content at the given VEMVA */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(POKEDATA) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(POKEDATA) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("POKEDATA at Address: %p is %p for PID: %d",
			addr, data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to obtain the content
 * of a VE user register from tracee’s user register set.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr VE user register to get
 * @param[out] data Content of VE user register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_peekuser(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");

	if (!data)
		goto hndl_return;

	VE_PTRACE_DEBUG("Requesting VEOS(PEEKUSER) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = PEEKUSER;
	pt_req.pid = pid;
	pt_req.addr = (uint64_t)addr;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for reading content at
	 * the given VE user register */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(PEEKUSER) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	memset(&pt_req, 0, sizeof(pt_req));

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, &pt_req);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(PEEKUSER) fails for PID: %d", pid);
		goto hndl_return1;
	}

	*((long *)data) = pt_req.data;

	VE_PTRACE_DEBUG("PEEKUSER at Register ID: %p is 0x%lx for PID: %d",
			addr, pt_req.data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to stores the content
 * in VE process USER area at given register offset.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr VE user register to access
 * @param[in] data Data to update in requested register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_pokeuser(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(POKEUSER) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = POKEUSER;
	pt_req.pid = pid;
	pt_req.addr = (uint64_t)addr;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for writing content at
	 * the given VE user register */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(POKEUSER) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(POKEUSER) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("POKEKUSER at Register ID: %p is %p for PID: %d",
			addr, data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and gets the
 * content of user registers set of VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Pointer to data to fill the set of user register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_getregs(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(GETREGS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = GETREGS;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to get the VE user register set */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(GETREGS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(GETREGS) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("GETREGS success for PID: %d at Tracer Address: %p",
			pid, data);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and sets the
 * content of user registers of VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Pointer to data to fill the set of user register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_setregs(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(SETREGS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SETREGS;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to set the given content
	 * of VE user register set */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SETREGS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SETREGS) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("SETREGS success for PID: %d from Tracer Address: %p",
			pid, data);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and gets the
 * content of vector registers set of VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Pointer to data to fill the set of vector register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_getvregs(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(GETVREGS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = GETVREGS;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to get the VE vector register set */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(GETVREGS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(GETVREGS) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("GETVREGS success for PID: %d at Tracer Address: %p",
			pid, data);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and sets the
 * content of vector registers of VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Pointer to data to fill the set of vector register
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_setvregs(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(SETVREGS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SETVREGS;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to set the given content
	 * of VE vector register set */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SETVREGS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SETVREGS) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("SETVREGS success for PID: %d from Tracer Address: %p",
			pid, data);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS and gets the
 * content of requested VE register based upon the given type.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr Contain's the type of register set
 * @param[in] data Pointer to fill iovec with the register set
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_getregset(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	struct iovec *rs_iov = data;
	struct ve_user_regs ve_u_regs;
	struct ve_user_vregs ve_u_vregs;
	int64_t min_size = 0;

	VE_PTRACE_TRACE("Entering");

	/* Check whether valid pointer of iovec is received
	 * or not by debugger.
	 */
	if (!rs_iov) {
		VE_PTRACE_ERR("NULL is received in 'data' field");
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_PTRACE_DEBUG("Command (GETREGSET) for PID: %d", pid);

	switch((int64_t)addr) {
	case NT_VEGPUREGS:
		VE_PTRACE_DEBUG("Getting VE User register set");

		/* Check 'data' argument received is valid or not */
		if ((rs_iov->iov_len % sizeof(struct ve_user_regs)) != 0) {
			VE_PTRACE_ERR("Invalid data argument received");
			retval = -EINVAL;
			goto hndl_return;
		}
		memset(&ve_u_regs, 0, sizeof(struct ve_user_regs));
		retval = ve_ptrace_getregs(pid, &ve_u_regs);
		if (0 > retval) {
			VE_PTRACE_DEBUG("ve_ptrace_getregs failed");
			goto hndl_return;
		}
		min_size = MIN(rs_iov->iov_len, sizeof(struct ve_user_regs));
		rs_iov->iov_len = min_size;

		/* Write the register set content in the iovec
		 * provided by tracer */
		memcpy(rs_iov->iov_base, &ve_u_regs, min_size);
		break;
	case NT_VEFPREGS:
		VE_PTRACE_DEBUG("Getting VE Vector register set");

		/* Check 'data' argument received is valid or not */
		if ((rs_iov->iov_len % sizeof(struct ve_user_vregs)) != 0) {
			VE_PTRACE_ERR("Invalid data argument received");
			retval = -EINVAL;
			goto hndl_return;
		}

		memset(&ve_u_vregs, 0, sizeof(struct ve_user_vregs));
		retval = ve_ptrace_getvregs(pid, &ve_u_vregs);
		if (0 > retval) {
			VE_PTRACE_DEBUG("ve_ptrace_getvregs failed");
			goto hndl_return;
		}
		min_size = MIN(rs_iov->iov_len, sizeof(struct ve_user_vregs));
		rs_iov->iov_len = min_size;

		/* Write the register set content in the iovec
		 * provided by tracer */
		memcpy(rs_iov->iov_base, &ve_u_vregs, min_size);
		break;
	default:
		VE_PTRACE_ERR("Invalid Register Set Type Received");
		retval = -EINVAL;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to set the
 * content of requested VE register based upon the given type.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] addr Contain's the type of register set
 * @param[in] data Pointer to fetch iovec with the register set
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_setregset(pid_t pid, void *addr, void *data)
{
	int retval = -1;
	struct iovec *rs_iov = data;
	struct ve_user_regs ve_u_regs;
	struct ve_user_vregs ve_u_vregs;
	int64_t min_size = 0;

	VE_PTRACE_TRACE("Entering");

	/* Check whether valid pointer of iovec is received
	 * or not by debugger.
	 */
	if (!rs_iov) {
		VE_PTRACE_ERR("NULL is received in 'data' field");
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_PTRACE_DEBUG("Command (SETREGSET) for PID: %d", pid);

	switch((int64_t)addr) {
	case NT_VEGPUREGS:
		VE_PTRACE_DEBUG("Setting VE User register set");

		/* Check 'data' argument received is valid or not */
		if ((rs_iov->iov_len % sizeof(struct ve_user_regs)) != 0) {
			VE_PTRACE_ERR("Invalid data argument received");
			retval = -EINVAL;
			goto hndl_return;
		}
		min_size = MIN(rs_iov->iov_len, sizeof(struct ve_user_regs));
		rs_iov->iov_len = min_size;
		memset(&ve_u_regs, 0, sizeof(struct ve_user_regs));

		/* Fetch the register set content from the iovec
		 * provided by tracer */
		memcpy(&ve_u_regs, rs_iov->iov_base, min_size);

		retval = ve_ptrace_setregs(pid, &ve_u_regs);
		if (0 > retval) {
			VE_PTRACE_DEBUG("ve_ptrace_setregs failed");
			goto hndl_return;
		}
		break;
	case NT_VEFPREGS:
		VE_PTRACE_DEBUG("Setting VE Vector register set");

		/* Check 'data' argument received is valid or not */
		if ((rs_iov->iov_len % sizeof(struct ve_user_vregs)) != 0) {
			VE_PTRACE_ERR("Invalid data argument received");
			retval = -EINVAL;
			goto hndl_return;
		}
		min_size = MIN(rs_iov->iov_len, sizeof(struct ve_user_vregs));
		rs_iov->iov_len = min_size;
		memset(&ve_u_vregs, 0, sizeof(struct ve_user_vregs));

		/* Fetch the register set content from the iovec
		 * provided by tracer */
		memcpy(&ve_u_vregs, rs_iov->iov_base, min_size);

		retval = ve_ptrace_setvregs(pid, &ve_u_vregs);
		if (0 > retval) {
			VE_PTRACE_DEBUG("ve_ptrace_setvregs failed");
			goto hndl_return;
		}
		break;
	default:
		VE_PTRACE_ERR("Invalid Register Set Type Received");
		retval = -EINVAL;
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to detach the
 * VE process and start its normal execution.
 *
 * @param[in] pid PID of VE tracee process
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_detach(pid_t pid)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(DETACH) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = DETACH;
	pt_req.pid = pid;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to detach the VE process from
	 * tracing.
	 */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(DETACH) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(DETACH) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("VEOS(DETACH) Success for PID: %d", pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;

}

/**
 * @brief Function is used to communicate with VEOS to attach(SEIZE)
 * the VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Ptrace options to activate
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_seize(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(SEIZE) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SEIZE;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS for attaching VE process using PTRACE_SEIZE */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SEIZE) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SEIZE) fails for PID: %d", pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("VEOS(SEIZE) Success for PID: %d", pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to handle the ptrace
 * syscall request from tracer.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] on Determines the enable/disable of syscall tracing
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_syscall(pid_t pid, bool on)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(SYSCALL) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SYSCALL;
	pt_req.pid = pid;
	pt_req.data = on;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to enable/disable syscall tracing */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SYSCALL) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SYSCALL) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("SYSCALL Tracing Now: %s for PID: %d",
			(char *)((on)?"Enabled":"Disabled"), pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to handle the ptrace
 * singlestep request from tracer.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] on Determines the enable/disable of singlestep tracing
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_singlestep(pid_t pid, bool on)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");
	VE_PTRACE_DEBUG("Requesting VEOS(SINGLESTEP) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SINGLESTEP;
	pt_req.pid = pid;
	pt_req.data = on;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to enable/disable singlestep tracing */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SINGLESTEP) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SINGLESTEP) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("SINGLESTEP Tracing Now: %s for PID: %d",
			(char *)((on)?"Enabled":"Disabled"), pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to set the given
 * ptrace options to VE process.
 *
 * @param[in] pid PID of VE tracee process
 * @param[in] data Bit mask of ptrace options
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_setoptions(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");

	/* If no options are provided by debugger, then
	 * EINVAL is returned.
	 */
        if (!data) {
		VE_PTRACE_DEBUG("NULL is received in 'data' field");
		retval = -EINVAL;
                goto hndl_return;
	}

	VE_PTRACE_DEBUG("Requesting VEOS(SETOPTIONS) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = SETOPTIONS;
	pt_req.pid = pid;
	pt_req.data = (uint64_t)data;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to set ptrace options for VE process */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(SETOPTIONS) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, NULL);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(SETOPTIONS) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	VE_PTRACE_DEBUG("SETOPTIONS %lx for PID: %d", (uint64_t)data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function is used to communicate with VEOS to get the ptrace
 * event that just happened.
 *
 * @param[in] pid PID of VE tracee process
 * @param[out] data Fill the ptrace event message
 *
 * @return 0 on success, -errno on failure.
 */
int ve_ptrace_geteventmsg(pid_t pid, void *data)
{
	int retval = -1;
	int veos_sock_fd = -1;
	ptrace_req pt_req;

	VE_PTRACE_TRACE("Entering");

	/* EFAULT is returned if event buffer is provided
	 * as NULL by debugger.
	 */
	if (!data) {
		VE_PTRACE_DEBUG("NULL is received in 'data' field");
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_PTRACE_DEBUG("Requesting VEOS(GETEVENTMSG) for PID: %d", pid);

	memset(&pt_req, 0, sizeof(ptrace_req));
	pt_req.ptrace_cmd = GETEVENTMSG;
	pt_req.pid = pid;

	/* Unix domain socket used as IPC */
	veos_sock_fd = get_veos_sock_fd(pid);
	if (veos_sock_fd < 0) {
		VE_PTRACE_DEBUG("Failed to create socket with VEOS");
		retval = -errno;
		goto hndl_return;
	}

	/* Command send to VEOS to get the ptrace event
	 * message for VE process.
	 */
	retval = pack_and_send_cmd(veos_sock_fd, pt_req);
	if (-1 == retval) {
		VE_PTRACE_DEBUG("VEOS(GETEVENTMSG) Communication Fails");
		retval = -EFAULT;
		goto hndl_return1;
	}

	memset(&pt_req, 0, sizeof(pt_req));

	/* Get the response from VEOS */
	retval = recv_and_unpack_cmd(veos_sock_fd, &pt_req);
	if (0 > retval) {
		VE_PTRACE_DEBUG("VEOS(GETEVENTMSG) fails for PID: %d",
				pid);
		goto hndl_return1;
	}

	*((uint64_t *)data) = pt_req.data;
	VE_PTRACE_DEBUG("GETEVENTMSG: %ld for PID: %d", pt_req.data, pid);
	retval = 0;
hndl_return1:
	VE_PTRACE_DEBUG("Closed Socket fd: %d", veos_sock_fd);
	close(veos_sock_fd);
hndl_return:
	VE_PTRACE_TRACE("Exiting");
	return retval;
}
