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
 * @file veos_ived_misc.h  
 * @brief IVED/VESHM/CR functions in VEOS (helper functions)
 *
 * @internal
 * @author VESHM
 */

#ifndef _VEOS_IVED_MISC_H
#define _VEOS_IVED_MISC_H

#include "comm_request.h"
#include "ived_request.h"
#include "veos_ived.h"
#include "veos_veshm_core.h"

extern int dump_ived_shared_resource_data(struct ived_shared_resource_data *);
extern int dump_own_veshm(struct owned_veshm_info *);
extern int dump_attach_veshm(struct attaching_veshm_info *);

extern int dump_pciatb_entry(int, int);
extern int dump_dmaatb_entry(int, int, int);

 
#endif /* _VEOS_IVED_MISC_H */
