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
 * @file pagetable.h
 * @brief VEOS page table structure
 *
 * @internal
 * @author AMM
 */
#ifndef __AMM_PAGETABLE_H
#define __AMM_PAGETABLE_H

#include <libved.h>

/* FIXME: architecture-dependent */
/*
 * Since page table directory and entry structures of VE1 and VE3 are same,
 * defined here, in architecture-independent code.
 *
 * TODO: abstract address translation.
 */
#define VEOS_ATB_DIR_NUM (32)
#define VEOS_ATB_ENTRY_MAX_SIZE (256)

#ifndef veos__atb_entry_defined
#define veos__atb_entry_defined
union veos_atb_entry {
	ve_reg_t data;
	struct { ve_reg_t reg_;} bf;
};
typedef union veos_atb_entry veos_atb_entry_t;
#endif

#ifndef veos__atb_dir_defined
#define veos__atb_dir_defined
union veos_atb_dir {
	ve_reg_t data;
	struct { ve_reg_t reg_;} bf;
};
typedef union veos_atb_dir veos_atb_dir_t;
#endif

typedef struct veos_atb_reg {
	union veos_atb_entry entry[VEOS_ATB_DIR_NUM][VEOS_ATB_ENTRY_MAX_SIZE];
	union veos_atb_dir dir[VEOS_ATB_DIR_NUM];
} atb_reg_t;

#endif
