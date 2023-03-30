/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file ve_memory_ve1.h
 * @brief VE1 dependent parameters and flags for memory management
 *
 * @internal
 * @author AMM
 */
#include <ve_hw.h>
#include <ve_memory.h>

#ifndef VEOS_VE1_VE_MEMORY_VE1_H
#define VEOS_VE1_VE_MEMORY_VE1_H

#define DMA_BITMAP      ((BITS_PER_WORD*ENTRIES_PER_DIR)/BLOCKS_PER_BITMAP)

#define VEOS_VER0
/*
 * Page Descriptor (Table) & Partial Space Directory Entry
 *
 * These structures are defined in ve_hw.h
 */

/* Partial space  directory entry for VE
 *
 * +------+--------------------+-----+----+-----+--+
 * | rfu0 |    psnum	       | jid |rfu1| pgsz|v |
 * +------+--------------------+-----+----+-----+--+
 *    16       28                8     9     2   1
 *
 *	psnum: Partial space number
 *        jid: JID (for DMAATB)
 *       pgsz: Page size flag
 *          v: Valid bit (0=invalid)
 */

/* Partial Space Page Table
 *
 * Page descriptor (table) entry for VE
 *
 * +------+--------------------+----+-----+--+--+--+
 * | rfu0 |    pfn	       | ty | rfu |w |b |ua|
 * +------+--------------------+----+-----+--+--+--+
 *    16       36                3     6   1  1  1
 *
 *	  pfn: Page frame number
 *	   ty: Type bit
 *	    w: Write Inhibit (1=inhibit)
 *	    b: Cache Bypass bit (1=cache bypass)
 *	   ua: UnAvailable (1=unavailable)
 *
 */

/* Get page base. */
#define pg_getpb(P, pgmode) \
	(((pgmode) == PG_4K) ? pg_getpb4(P) : \
	 ((pgmode) == PG_HP) ? pg_getpb_h(P) : \
	 pg_getpb_l(P))

/* Set page base. */
#define pg_setpb(P, pfn, pgmode) \
	(((pgmode) == PG_4K) ? pg_setpb4(P, pfn) : \
	 ((pgmode) == PG_HP) ? pg_setpb_h(P, pfn) : \
	 pg_setpb_l(P, pfn))

/*
 * PSD (Partial Space Directory)
 */
#define ps_setpsnum(PD, psnum, pgmode) \
	(((pgmode) == PG_4K) ? ps_setps4(PD, psnum) : \
	 ((pgmode) == PG_HP) ? ps_setps_h(PD, psnum) : \
	 ps_setps(PD, psnum))

/* get physical page address in PSD descriptor */
#define ps_getps(PD, pgmode)	(((pgmode) == PG_4K) ? ps_getps4k(PD) : \
		((pgmode) == PG_2M) ? ps_getps2m(PD) : \
		((pgmode) == PG_HP) ? ps_getps_h(PD) : -1)

/*
 *      The following routines are used to convert
 *      virtual address to some parts.
 */

/*
 * Virtual address
 *
 * example: LP (2MB page)
 * 0                                              63
 * +------+--------------------+-----+-------------+
 * | rfu  |    psnum	       | pg  |    offset   |
 * +------+--------------------+-----+-------------+
 *    16       19                8          21
 *
 *	psnum: Partial space number
 *         pg: Page number
 *     offset: offset address in a page
 */

/* virtual address to psnum */
#define psnum(v, pgmode)	(((pgmode) == PG_4K) ? psnum4k(v) :\
		((pgmode) == PG_2M) ? psnum_l(v) :\
		((pgmode) == PG_HP) ? psnum_h(v) : -1)

/* virtual address to pgentry */
#define pgentry(v, pgmode)	(((pgmode) == PG_4K) ? pgentry4k(v) :\
		((pgmode) == PG_2M) ? pgentry_l(v) :\
		((pgmode) == PG_HP) ? pgentry_h(v) : -1)

/* psnum to virtual address */
#define psnum_to_vaddr(psnum, pgoff, pgmod) (pgmod == PG_4K) ?\
			psnum_to_vaddr4k(psnum, pgoff) : ((pgmod == PG_2M) ?\
			psnum_to_vaddr_l(psnum, pgoff) :\
			psnum_to_vaddr_h(psnum, pgoff))

/*
 *      The following routines are used to convert
 *      physical address to some parts.
 */

/*
 * Physical address
 *
 * example: LP (2MB page)
 * 0                                              63
 * +------+--------------------------+-------------+
 * | rfu  |         PageBase         |    offset   |
 * +------+--------------------------+-------------+
 *    16                27                  21
 *
 *	Page Base : first address of page
 *          offset: offset address in a page
 */

/* physical address to page frame number (page base) */
#define pfnum(X, pgmode)	(((pgmode) == PG_4K) ? pfnum4k(X) :\
		((pgmode) == PG_2M) ? pfnum_l(X) :\
		((pgmode) == PG_HP) ? pfnum_h(X) : -1)

/*page frame number (page base) to physical address */
#define pbaddr(X, pgmode)	(((pgmode) == PG_4K) ? pbaddr4k(X) :\
		((pgmode) == PG_2M) ? pbaddr_l(X) :\
		((pgmode) == PG_HP) ? pbaddr_h(X) : -1)

#endif				/* _SYS_MEMORY_ */
