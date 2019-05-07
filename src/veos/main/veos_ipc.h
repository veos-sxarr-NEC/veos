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
/*
 * @file veos_ipc.h
 * @brief Header for IPC of VEOS
 */

#include "proto_buff_schema.pb-c.h"

#ifndef __VEOS_IPC_H
#define __VEOS_IPC_H

int veos_reply(veos_thread_arg_t *, int64_t, ProtobufCBinaryData *);

#endif
