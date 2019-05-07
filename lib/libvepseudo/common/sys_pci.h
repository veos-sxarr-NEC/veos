/**
 * Copyright (C) 2018 NEC Corporation
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/**
 * @file pseudo_vepci.h
 * @brief Header for VEPCI in psedo process
 *
 * @internal
 * @author VEPCI
 */

#ifndef __PSEUDO_VEPCI_H
#define __PSEUDO_VEPCI_H

#include <sys/types.h>
#include "sys_common.h"
#include "comm_request.h"

int64_t ve_sys_pcireq(veos_handle *, uint64_t, size_t, enum pseudo_veos_msg_id);
int ve_sys_pciunmap(veos_handle *, uint64_t, size_t);
int64_t ve_sys_map_pciatb(veos_handle *, uint64_t, size_t);
int ve_sys_unmap_pciatb(veos_handle *, uint64_t, size_t);

#endif
