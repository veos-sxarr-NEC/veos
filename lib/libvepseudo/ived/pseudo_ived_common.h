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
 * @file pseudo_ived_common.h  
 * @brief IVED related common function at pseudo process.
 *
 * @internal
 * @author VESHM
 */

#ifndef __PSEUDO_IVED_COMMON_H
#define __PSEUDO_IVED_COMMON_H

#include <log4c.h>
#include "proto_buff_schema.pb-c.h"
#include "handle.h"

extern log4c_category_t *log4cat_pseudo_ived;

int pseudo_ived_log4c_init(void);
int exchange_request(veos_handle *, PseudoVeosMessage *, PseudoVeosMessage **);

#endif
