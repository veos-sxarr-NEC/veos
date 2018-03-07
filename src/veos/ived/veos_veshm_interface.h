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
 * @file veos_veshm_interface.h  
 * @brief Header for VESHM interfaces
 *
 * @internal
 * @author VESHM
 */


#ifndef __VEOS_VESHM_INTERFACE_H
#define __VEOS_VESHM_INTERFACE_H

#include "comm_request.h"

int veos_veshm_veshmctl(veos_thread_arg_t *);

#endif
