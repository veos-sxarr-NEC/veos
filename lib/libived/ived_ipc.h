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
 * @file  ived_ipc.h
 * @brief Header for IVED RPC 
 *
 * @internal
 * @author VESHM
 */
#ifndef __IVED_IPC_H
#define __IVED_IPC_H

#include "ived.pb-c.h"
#include "ived_common.h"
#include "veos_defs.h"

#define IVED_BUF_MAX_SIZE       0x4200	/* PCI address array (16KB) + other */

/* RPC responces and function error code */
enum IVED_responce{
	IVED_REQ_OK	= 0,
	IVED_REQ_NG	= -1,
	ERR_RET		= -1,
	IVED_FUNC_ERR	= -2, 

	/* For RPC */
	IVED_RPC_ERR      = -3, /*!< RPC failed BEFORE sending or receiving */
	IVED_RPC_ERR_SEND = -4, /*!< Sending a request failed. */
	IVED_RPC_ERR_RECV = -5, /*!< Error occured during sending a request.*/
	IVED_RPC_ERR_ACK  = -6, /*!< Error occured during receiving a req. */
};

/*
 * Memo:
 * To aboid confusion and make a bug, IVED_command/IVED_common_func/
 * VESHM_command use different numbers.
 */
/* RPC commands */
enum IVED_command {
	IVED_COMMON = 0x0,
	IVED_VESHM,
	IVED_CR,
};

/* RPC sub commands for IVED common */
enum IVED_common_func{
	IVED_OS_REG = 0x20,
	IVED_OS_STOP,
	IVED_PROC_REG,
	IVED_PROC_ERASE,
};

/* RPC sub commands for VESHM */
enum VESHM_sys_command {
	VESHM_DETACH_AREA  = 0x40,
};


enum system_mode_flag {
	/* Mask */
	VE_SYS_FLAG_MASK	= 0xFFFFFFFF00000000LL, /* Mask for system flag */
	/* specified by veos */
	VE_REQ_PROC		= 0x0000000100000000LL, /* Request by VE process */
	VE_REQ_DEV		= 0x0000000400000000LL, /* Request by IB */
	VE_REQ_PPS		= 0x0000000800000000LL, /* Request by PPS */
	VESHM_MODE_INVALID	= 0x0000001000000000LL, /* Invalidated VESHM */
	VE_MEM_RENEW		= 0x0000002000000000LL, /* IPC req. VESHM renewal*/
	VE_REQ_INVALID_PCI_ADDR	= 0x0000004000000000LL, /* Invalidated PCI address */
	VE_REQ_NON_OWNER_INFO	= 0x0000008000000000LL, /* Owner info is non-existent */
	/* MACRO_FOR_CR		= 0x0000XX0000000000LL, */
	IVED_PROC_EXIT		= 0x0001000000000000LL, /* Process exit */
	IVED_VEOS_EXIT		= 0x0002000000000000LL, /* VEOS exit */
};

/* 
 * A telegram is composed of the following:
 * - Length of its telegram (sizeof(uint32_t)) 
 * - RpcCommand (fixed length)
 * - Payload of each request 
 */
#define IVED_PROTO_BUF_POS           (sizeof(uint32_t))

enum CR_command_ived_specific {
	CR_ATTACH	= 0x80,
	CR_ATTACHED,
	CR_CANCEL_ATTACH,
	CR_NOT_REFERENCED,
};

extern int get_rpc_buf(uint8_t **, size_t);
extern int ived_create_soc(char *);
extern int ived_finish_soc(int);

extern int ived_rpc_receive(int, uint8_t **);

extern int ived_server_send_reply_common(int, uint8_t *, size_t);

extern int ived_send_reply_msg(int, IvedReturn *);
extern int ived_send_int64(int, int64_t, int);

extern int ived_exchange_ived_msg(int, RpcIvedArg *, IvedReturn **);
extern int ived_exchange_veshm_msg(int, RpcVeshmArg *, IvedReturn **);
extern int ived_exchange_cr_msg(int, RpcCrArg *, IvedReturn **);

#endif
