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
 * @file ve_memory_ve3.h
 * @brief VE3 dependent parameters and flags for memory management
 *
 * @internal
 * @author AMM
 */
#include <ve_hw.h>
#include <ve_memory.h>

#ifndef VEOS_VE3_VE_MEMORY_VE3_H
#define VEOS_VE3_VE_MEMORY_VE3_H

#define DMA_BITMAP	((VE3_DMAATB_DIR_NUM * ENTRIES_PER_DIR) / BLOCKS_PER_BITMAP)

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
#define PG_NS		0x0000000000000020LL	/* PCIe attr:No snoop */
#define PG_IDO		0x0000000000000080LL	/* PCIe attr:ID based */

#define pg_setido(P)		((P)->data |=  PG_IDO)
/* Set memory ido. */
#define pg_unsetido(P)		((P)->data &= ~PG_IDO)
/* Unset memory ido */

#define NBPSHP		0x10000000	/* bytes of SHP */

#define BPSHPSHFT	28

/*
 * PSPT
 */

#define PSSHFT_SH	28	/* page field (256MB) */

/* page type */
#define VE_ADDR_VERAA_NONPRE 0x4	/* VE Register Absolute Address for control */
#define VE_ADDR_VERAA_PRE 0x0	/* VE Register Absolute Address */

#define pg_getpb_sh(P)		(((P)->data >> PSSHFT_SH) & PGFNMASK_SH)

#define pg_getpb(P, pgmode) \
	(((pgmode) == PG_4K) ? pg_getpb4(P) : \
	 ((pgmode) == PG_HP) ? pg_getpb_h(P) : \
	 ((pgmode) == PG_SHP) ? pg_getpb_sh(P) : \
	pg_getpb_l(P))

#define pg_setpb_sh(P, pfn)	((P)->data |= (((uint64_t)pfn <<\
				PSSHFT_SH)) & PG_ADDR)

/* Set page base. */
#define pg_setpb(P, pfn, pgmode) \
	(((pgmode) == PG_4K) ? pg_setpb4(P, pfn) : \
	 ((pgmode) == PG_HP) ? pg_setpb_h(P, pfn) : \
	 ((pgmode) == PG_SHP) ? pg_setpb_sh(P, pfn) : \
	 pg_setpb_l(P, pfn))

/*
 * PSD (Partial Space Directory)
 */

#define ps_shft_sh	36	/* PS# field (256MB) */

#define ps_setps_sh(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft_sh))

#define ps_setpsnum(PD, psnum, pgmode) \
	(((pgmode) == PG_4K) ? ps_setps4(PD, psnum) : \
	 ((pgmode) == PG_HP) ? ps_setps_h(PD, psnum) : \
	 ((pgmode) == PG_SHP) ? ps_setps_sh(PD, psnum) : \
	 ps_setps(PD, psnum))

/* get physical page address in PSD descriptor */
#define ps_getps_sh(PD) ((uint64_t)(((PD)->data) & PS_ADDR) >> ps_shft_sh)

#define ps_getps(PD, pgmode)	(((pgmode) == PG_4K) ? ps_getps4k(PD) : \
		((pgmode) == PG_2M) ? ps_getps2m(PD) : \
		((pgmode) == PG_HP) ? ps_getps_h(PD) : \
		((pgmode) == PG_SHP) ? ps_getps_sh(PD) : -1)

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

/*
 * shift bits
 */

/* pgentry + offset */
#define PSNMSHFT_SH	36

/* page offset  */
#define POFFMASK_SH	0x000000000FFFFFFFULL

/* virtual address to psnum */
#define psnum_sh(v)	((uint64_t)(v) >> PSNMSHFT_SH)

#define psnum(v, pgmode)	(((pgmode) == PG_4K) ? psnum4k(v) :\
		((pgmode) == PG_2M) ? psnum_l(v) :\
		((pgmode) == PG_HP) ? psnum_h(v) :\
		((pgmode) == PG_SHP) ? psnum_sh(v) : -1)

/* virtual address to pgentry */
#define pgentry_sh(v)	(((uint64_t)(v) >> PSSHFT_SH) & PTMASK)

#define pgentry(v, pgmode)	(((pgmode) == PG_4K) ? pgentry4k(v) :\
		((pgmode) == PG_2M) ? pgentry_l(v) :\
		((pgmode) == PG_HP) ? pgentry_h(v) :\
		((pgmode) == PG_SHP) ? pgentry_sh(v) : -1)

/* virtual address to page offset */
#define poff_sh(v)	((uint64_t)(v) & POFFMASK_SH)

/* psnum to virtual address */
#define psnum_to_vaddr_sh(psnum, pgoff)  ((uint64_t)psnum\
		<< PSNMSHFT_SH) | ((uint64_t)pgoff<<PSSHFT_SH)
#define psnum_to_vaddr(psnum, pgoff, pgmod) (pgmod == PG_4K) ?\
			     psnum_to_vaddr4k(psnum, pgoff) : ((pgmod == PG_2M) ?\
			     psnum_to_vaddr_l(psnum, pgoff) : ((pgmod == PG_HP) ?\
			     psnum_to_vaddr_h(psnum, pgoff) : \
			     psnum_to_vaddr_sh(psnum, pgoff)))

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

#define PGFNMASK_SH	(uint64_t)(0x0000000FFFFF)	/* Mask page frame # after shift. */

/* physical address to page frame number (page base) */
#define pfnum_sh(X)	(((uint64_t)(X) >> PSSHFT_SH) & PGFNMASK_SH)

#define pfnum(X, pgmode)	(((pgmode) == PG_4K) ? pfnum4k(X) :\
		((pgmode) == PG_2M) ? pfnum_l(X) :\
		((pgmode) == PG_HP) ? pfnum_h(X) :\
		((pgmode) == PG_SHP) ? pfnum_sh(X) : -1)

/*page frame number (page base) to physical address */
#define pbaddr_sh(X)	((uint64_t)(X) << PSSHFT_SH)

#define pbaddr(X, pgmode)	(((pgmode) == PG_4K) ? pbaddr4k(X) :\
		((pgmode) == PG_2M) ? pbaddr_l(X) :\
		((pgmode) == PG_HP) ? pbaddr_h(X) :\
		((pgmode) == PG_SHP) ? pbaddr_sh(X) : -1)

/*
 *	Miscellaneous macros.
 */

/* Pages to bytes */
#define shptob(x)	((uint64_t)(x)<<BPSHPSHFT)

/* Bytes to pages */
#define btoshp(x)	(((x)+(NBPSHP-1))>>BPSHPSHFT)	/* round up   (SHP) */
#define btoshpt(x)	((x)>>BPSHPSHFT)		/* round down (SHP) */

#endif				/* _SYS_MEMORY_ */
