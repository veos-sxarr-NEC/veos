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
* @file  ve_socket.h
* @brief Socket Creation.
*
* This file contains the routines declaration that are used for creation of socket
* to be used for communication with VEOS modules i.e AMM/PSM.
*
* @internal
* @author Pseudo/System Call Handling
*/
#ifndef __VE_SOCKET_H
#define __VE_SOCKET_H

int pseudo_veos_soc(char *);
ssize_t pseudo_veos_recv_cmd(int, void *, ssize_t);
ssize_t pseudo_veos_send_cmd(int, void *, ssize_t);
ssize_t pseudo_veos_recv_signal_ack(int, void *, ssize_t);
ssize_t pseudo_veos_send_signal_req(int, void *, ssize_t);
#endif
