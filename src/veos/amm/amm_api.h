/*
 * Copyright (C) 2020 NEC Corporation
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
 * @file ve_mem.h
 * @brieaf Memory management functions
 *
 * @internal
 * @author AMM
 */
#ifndef __AMM_AMM_API_H
#define __AMM_AMM_API_H
#include <mm_type.h>
int veos_get_page(vemaa_t);
int veos_put_page(vemaa_t);
int64_t veos_virt_to_phy(vemva_t, pid_t, bool, int *);
#endif
