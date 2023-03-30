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
 * @file ve_memory.c
 * @brief Related functions that manage memory parameters and flags.
 *
 * @internal
 * @author AMM
 */

#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>

#include <mman_ve.h>

#include <veos_arch_defs.h>

#include <ve_memory.h>

int pg_getpb(veos_atb_entry_t *pte, int pgmod)
{
	return (*_veos_arch_ops->arch_pg_getpb)(pte, pgmod);
}

void pg_setpb(veos_atb_entry_t *pte, pgno_t pgno, int pgmod)
{
	(*_veos_arch_ops->arch_pg_setpb)(pte, pgno, pgmod);
}

void ps_setpsnum(veos_atb_dir_t *pgd, pgno_t pgno, int pgmod)
{
	(*_veos_arch_ops->arch_ps_setpsnum)(pgd, pgno, pgmod);
}

int ps_getps(veos_atb_dir_t *pgd, int pgmod)
{
	return (*_veos_arch_ops->arch_ps_getps)(pgd, pgmod);
}

int64_t psnum(int64_t vaddr, int pgmod)
{
	return (*_veos_arch_ops->arch_psnum)(vaddr, pgmod);
}

int64_t pgentry(int64_t vaddr, int pgmod)
{
	return (*_veos_arch_ops->arch_pgentry)(vaddr, pgmod);
}

int64_t psnum_to_vaddr(uint64_t psnum, int ent, int pgmod)
{
	return (*_veos_arch_ops->arch_psnum_to_vaddr)(psnum, ent, pgmod);
}

pgno_t pfnum(int64_t vaddr, int pgmod)
{
	return (*_veos_arch_ops->arch_pfnum)(vaddr, pgmod);
}

uint64_t pbaddr(pgno_t pgno, int pgmod)
{
	return (*_veos_arch_ops->arch_pbaddr)(pgno, pgmod);
}
