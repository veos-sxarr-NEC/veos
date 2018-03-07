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
 * @file pseudo_veshm_pgmode.h  
 * @brief Header for VESHM (get page mode)
 *
 * @internal
 * @author VESHM
 */


#ifndef __PSEUDO_VESHM_PGMODE_H
#define __PSEUDO_VESHM_PGMODE_H

#include <inttypes.h>
#include "handle.h"

int pseudo_veshm_get_pgmode(veos_handle *, uint8_t, pid_t, uint64_t);
int pseudo_get_pgsize(uint64_t *, veos_handle *);

#endif
