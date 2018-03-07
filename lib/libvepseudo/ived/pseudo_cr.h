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
 * @file pseudo_cr.h  
 * @brief A handler of CR related command of sysve() system call.
 *
 * @internal
 * @author CR
 */

#ifndef __PSEUDO_CR_H
#define __PSEUDO_CR_H

#include <inttypes.h>
#include "sys_common.h"
#include "handle.h"

ret_t ve_cr(veos_handle *handle, uint64_t *);

#endif
