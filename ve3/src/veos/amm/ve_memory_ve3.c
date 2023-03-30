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
/*
 * @file ve_memory_ve3.c
 * @brief VE3 dependent part of related functions that manage memory parameters 
 * and flags.
 *
 * @internal
 * @author AMM
 */

#include <stdlib.h>
#include <string.h>
#include <ve_hw.h>
#include <errno.h>

#include <veos_arch_defs.h>
#include <ve_memory.h>
#include "ve_memory_ve3.h"

int ve3_pg_getpb(veos_atb_entry_t *pte, int pgmod)
{
	return (pg_getpb(pte, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pg_getpb, ve3_pg_getpb)

void ve3_pg_setpb(veos_atb_entry_t *pte, pgno_t pgno, int pgmod)
{
        pg_setpb(pte, pgno, pgmod);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pg_setpb, ve3_pg_setpb)

void ve3_ps_setpsnum(veos_atb_dir_t *pgd, pgno_t pgno, int pgmod)
{
        ps_setpsnum(pgd, pgno, pgmod);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_ps_setpsnum, ve3_ps_setpsnum)

int ve3_ps_getps(veos_atb_dir_t *pgd, int pgmod)
{
        return (ps_getps(pgd, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_ps_getps, ve3_ps_getps)

int64_t ve3_psnum(int64_t vaddr, int pgmod)
{
        return (psnum(vaddr, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psnum, ve3_psnum)

int64_t ve3_pgentry(int64_t vaddr, int pgmod)
{
        return (pgentry(vaddr, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pgentry, ve3_pgentry)

int64_t ve3_psnum_to_vaddr(uint64_t psnum, int ent, int pgmod)
{
        return (psnum_to_vaddr(psnum, ent, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psnum_to_vaddr, ve3_psnum_to_vaddr)

pgno_t ve3_pfnum(int64_t vaddr, int pgmod)
{
        return (pfnum(vaddr, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pfnum, ve3_pfnum)

uint64_t ve3_pbaddr(pgno_t pgno, int pgmod)
{
        return (pbaddr(pgno, pgmod));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_pbaddr, ve3_pbaddr)

