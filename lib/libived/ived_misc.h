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
 * @file   ived_misc.h
 * @brief  Header file for IVED/VESHM/CR library
 *
 * @internal
 * @author VESHM
 */

#ifndef _IVED_LIB_MISC_H
#define _IVED_LIB_MISC_H

#include <uuid/uuid.h>

int ived_check_mutex_locked(pthread_mutex_t *);
int ived_pgsize_byte2flag(int64_t, int);
int ived_pci_pgsize_flag2byte(int);

/* debug */
int dump_uuid(char *, uuid_t);


#endif
