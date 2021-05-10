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
 * @file  vhve_common.c
 * @brief This file contains functions for IPC with VEOS
 *
 * @internal
 * @author VHVE
 */
/**
 * @file  vhve_request.h
 * @brief This file contains structures used in IPC
 *
 * @internal
 * @author VHVE
 */
#ifndef __VEOS_VHVE_INTERFACE_H
#define __VEOS_VHVE_INTERFACE_H
#include <stdint.h>
#include <dhash.h>
#include <sys/socket.h>

#define MAX_VHVE_MSG_SIZE (4*1024)

typedef struct veos_vhve_thread_arg {
	int socket_descriptor;  /*!< descriptor to read/write */
	hash_table_t *dma_req_hdl_list;
	void *vh_proc_msg;
	ssize_t vh_proc_size;
	struct ucred cred;      /*!< credential */
} veos_vhve_thread_arg_t;

struct veos_vhve_cmd_entry {
	char *cmdname;
	int (*handler)(struct veos_vhve_thread_arg *);
};

/**
 * @brief Structure to store the setting of DMA from VHVE.
 */
struct vhve_dma_args {
	uint64_t cmd; /* VHVE_DMA_REQ */
	int ret;
	uint64_t srcaddr;
	uint64_t dstaddr;
	uint64_t size;
	uint64_t reqid;
	uint64_t vepid;
	int is_wait;
	int is_write;
	uint64_t opt;
};

struct vhve_result {
	uint64_t cmd; /* VHVE_RESULT */
	int ret;
	uint64_t val;
};

enum vhve_veos_msg_id {
	VHVE_DMA_REQ = 0,
	VHVE_RESULT,
	VHVE_VEOS_MAX_MSG_NUM,
	VHVE_CMD_INVALID = -1,
};

#endif
