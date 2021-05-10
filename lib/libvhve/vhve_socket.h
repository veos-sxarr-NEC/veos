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
* @file  vhve_socket.h
* @brief Socket Creation.
*
* This file contains the routines declaration that are used for creation of socket
* to be used for communication with VEOS modules i.e AMM/PSM.
*
* @internal
* @author VHVE
*/
#ifndef __VHVE_SOCKET_H
#define __VHVE_SOCKET_H

int vhve_veos_soc(char *);
ssize_t vhve_recv_cmd(int, void *, ssize_t);
ssize_t vhve_send_cmd(int, void *, ssize_t);
#endif
