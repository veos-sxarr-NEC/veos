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
 * @file ve_memory.h
 * @brief This file contains flags for partial space Directory entry
 *
 * @internal
 * @author AMM
 */

#ifndef _SYS_MEMORY_
#define _SYS_MEMORY_

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

#define NPGPPS		256	/* Nbr of pages per PSPT */

#define NBPLP		0x200000	/* bytes of LP */
#define NBPHP		0x4000000	/* bytes of HP */
#define NBPSP		0x1000		/* bytes of SP */

#define BPSPSHFT	12	/* Shift for bytes per small page */
#define BPLPSHFT	21
#define BPHPSHFT	26

/*
 * PSPT
 */

#define PG_ADDR		0x0000FFFFFFFFF000LL	/* physical page frame number. */
#define PG_TYPE		0x0000000000000E00LL	/* type */

#define PG_RO		0x0000000000000040LL	/* PCIe attr:Relaxed ordering */

#define PG_BYPS		0x0000000000000002LL	/* cache bypass bit. */
#define PG_WRITI	0x0000000000000004LL	/* write protection bit. */
#define	PG_NP		0x0000000000000001LL	/* invalid bit. */
#define JIDCLR		0x00000000000FF000LL

#define PG_BUS		(PG_ADDR >> 21)

#define	type_shft	9	/* type field */
#define	prot_shft	2	/* write protection field */
#define	bypass_shft	1	/* cache bypass field */

#define PSSHFT4K	12	/* page field (4KB)  */
#define PSSHFT		21	/* page field (2MB)  */
#define PSSHFT_H	26	/* page field (64MB) */

/* page type */
#define VE_ADDR_VECRAA 0x5	/* VE CR Absolute Address */
#define VE_ADDR_VEMAA 0x6	/* VE Memory Absolute Address */
#define VE_ADDR_VERAA 0x4	/* VE Register Absolute Address for control */
#define VE_ADDR_VHSAA 0x2	/* VH System Absolute Address */


#define pg_getpb4(P)		(((P)->data >> PSSHFT4K) & PGFNMASK4K)
#define pg_getpb_l(P)		(((P)->data >> PSSHFT) & PGFNMASK)
#define pg_getpb_h(P)		(((P)->data >> PSSHFT_H) & PGFNMASK_H)

#define	pg_setpb4(P, pfn)	((P)->data |= (((uint64_t)pfn <<\
				PSSHFT4K)) & PG_ADDR)
#define	pg_setpb_l(P, pfn)	((P)->data |= (((uint64_t)pfn <<\
				PSSHFT)) & PG_ADDR)
#define	pg_setpb_h(P, pfn)	((P)->data |= (((uint64_t)pfn <<\
				PSSHFT_H)) & PG_ADDR)
/* Set page base. */

#define pg_gettype(P)		(((P)->data & PG_TYPE) >> type_shft)
#define	pg_settype(P, type)	((P)->data |= (type << type_shft))
/* Set memory type. */

#define pg_unsettype(P)		((P)->data &= ~PG_TYPE)
/* Unset memory Type */

#define pg_setro(P)		((P)->data |=  PG_RO)
/* Set memory ro. */

#define pg_unsetro(P)		((P)->data &= ~PG_RO)
/* Unset memory ro */

#define pg_setprot(P)		((P)->data |=  PG_WRITI)
/* Set write protection bit. */

#define pg_unsetprot(P)		((P)->data &= ~PG_WRITI)
/* Clear write protection bit. */

#define pg_valid(P)		((P)->data &= ~PG_NP)
/* Set valid bit. */

#define	pg_invalid(P)		((P)->data |= PG_NP)
/* Clear valid bit. */

#define pg_isprot(P)		(((P)->data & PG_WRITI)>>prot_shft)
/* Check: If P is write inhibit, return 1  */

#define pg_isvalid(P)		(!((P)->data & PG_NP))
/* Check: If P is valid, return 1  */

#define	pg_setbypass(P)		((P)->data |= PG_BYPS)
/* Set cache bypass bit. */

#define	pg_unsetbypass(P)	((P)->data &= ~PG_BYPS)
/* Unset cache bypass bit. */

#define pg_isbypass(P)		(((P)->data & PG_BYPS)>>bypass_shft)
/* Check: If P is cache bypassbit, return 1  */

/* physical page address in page descriptor */
#define pgaddr(P)	((uint64_t)(((P)->data) & PG_ADDR))

#define pg_clearpfn(P)	(((P)->data) &= ~PG_ADDR) /* clear page frame number */

/*
 * PSD (Partial Space Directory)
 */

#define PS_ADDR		0x0000FFFFFFF00000LL	/*  partial space number. */
#define PS_JID		0x00000000000FF000LL	/*  JID */
#define PS_PGSZ		0x0000000000000006LL	/*  page size */
#define PS_V		0x0000000000000001LL	/*  valid */

#define	ps_shft4	20	/* PS# field (4KB)  */
#define	ps_shft		29	/* PS# field (2MB)  */
#define	ps_shft_h	34	/* PS# field (64MB) */
#define jid_shft	12	/* jid field */
#define pgsz_shft	1	/* page size field */

#define	PG_4K	0
#define	PG_2M	1
#define	PG_HP	2
#define PG_SHP	3

#define	ps_setps4(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft4))
#define	ps_setps(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft))
#define	ps_setps_h(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft_h))

/* Set pertial space number */
#define ps_clrdir(PD)          ((PD)->data &= 0ULL)
/* Set JID */
#define ps_clrjid(PD, jid)	((PD)->data &= ~JIDCLR)
#define ps_setjid(PD, jid)	((PD)->data |= (jid << jid_shft))

#define	ps_setpgsz(PD, pgsz)	((PD)->data |= (pgsz << pgsz_shft))
/* Set page size */

#define	ps_valid(PD)		((PD)->data |= PG_NP)
/* Clear valid bit. */

#define	ps_invalid(PD)		((PD)->data &= ~PG_NP)
/* Clear valid bit. */

#define ps_isvalid(PD)		(((PD)->data & PG_NP))
/* Check: If PD is valid, return 1  */

/* get physical page address in PSD descriptor */
#define	ps_getps4k(PD)	((uint64_t)(((PD)->data) & PS_ADDR) >> ps_shft4)
#define	ps_getps2m(PD)	((uint64_t)(((PD)->data) & PS_ADDR) >> ps_shft)
#define	ps_getps_h(PD)	((uint64_t)(((PD)->data) & PS_ADDR) >> ps_shft_h)

/* get JID in PSD descriptor */
#define	ps_getjid(PD)	((uint64_t)(((PD)->data) & PS_JID) >> jid_shft)

/* get Page size in PSD descriptor */
#define	ps_getpgsz(PD)	((uint64_t)(((PD)->data) & PS_PGSZ) >> pgsz_shft)

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
#define	PSNMSHFT	29
#define PSNMSHFT_H	34
#define PSNMSHFT4K	20

/* page number */
#define PTSHFT		8

/*  page number after shift */
#define PTMASK		0xFFULL

/* page offset  */
#define POFFMASK	0x00000000001FFFFFULL
#define POFFMASK_H	0x0000000003FFFFFFULL
#define POFFMASK4K	0x0000000000000FFFULL

/* virtual address to psnum */
#define	psnum4k(v)	((uint64_t)(v) >> PSNMSHFT4K)
#define	psnum_l(v)	((uint64_t)(v) >> PSNMSHFT)
#define	psnum_h(v)	((uint64_t)(v) >> PSNMSHFT_H)

/* virtual address to pgentry */
#define	pgentry4k(v)	(((uint64_t)(v) >> PSSHFT4K) & PTMASK)
#define	pgentry_l(v)	(((uint64_t)(v) >> PSSHFT) & PTMASK)
#define	pgentry_h(v)	(((uint64_t)(v) >> PSSHFT_H) & PTMASK)

/* virtual address to page offset */
#define poff(v)		((uint64_t)(v) & POFFMASK)
#define poff_h(v)	((uint64_t)(v) & POFFMASK_H)
#define poff4k(v)	((uint64_t)(v) & POFFMASK4K)

/* psnum to virtual address */
#define	psnum_to_vaddr_l(psnum, pgoff)	((uint64_t)psnum\
		<< PSNMSHFT) | ((uint64_t)pgoff<<PSSHFT)
#define	psnum_to_vaddr_h(psnum, pgoff)	((uint64_t)psnum\
		<< PSNMSHFT_H) | ((uint64_t)pgoff<<PSSHFT_H)
#define	psnum_to_vaddr4k(psnum, pgoff)	((uint64_t)psnum\
		<< PSNMSHFT4K) | ((uint64_t)pgoff<<PSSHFT4K)

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

#define PGFNMASK        (uint64_t)(0x000007FFFFFF)	/* Mask page frame # after shift. */
#define PGFNMASK_H      (uint64_t)(0x0000003FFFFF)	/* Mask page frame # after shift. */
#define PGFNMASK4K      (uint64_t)(0x000FFFFFFFFF)	/* Mask page frame # after shift. */

/* physical address to page frame number (page base) */
#define pfnum4k(X)	(((uint64_t)(X) >> PSSHFT4K) & PGFNMASK4K)
#define pfnum_l(X)	(((uint64_t)(X) >> PSSHFT) & PGFNMASK)
#define pfnum_h(X)	(((uint64_t)(X) >> PSSHFT_H) & PGFNMASK_H)

/*page frame number (page base) to physical address */
#define pbaddr4k(X)	((uint64_t)(X) << PSSHFT4K)
#define pbaddr_l(X)	((uint64_t)(X) << PSSHFT)
#define pbaddr_h(X)	((uint64_t)(X) << PSSHFT_H)

/*
 *	Miscellaneous macros.
 */

/* Pages to bytes */
#define sptob(x)	((uint64_t)(x)<<BPSPSHFT)
#define lptob(x)	((uint64_t)(x)<<BPLPSHFT)
#define hptob(x)	((uint64_t)(x)<<BPHPSHFT)

/* Bytes to pages */
#define btosp(x)	(((x)+(NBPSP-1))>>BPSPSHFT)	/* round up   (SP) */
#define btospt(x)	((x)>>BPSPSHFT)			/* round down (SP) */

#define btolp(x)	(((x)+(NBPLP-1))>>BPLPSHFT)	/* round up   (LP) */
#define btolpt(x)	((x)>>BPLPSHFT)			/* round down (LP) */

#define btohp(x)	(((x)+(NBPHP-1))>>BPHPSHFT)	/* round up   (HP) */
#define btohpt(x)	((x)>>BPHPSHFT)			/* round down (HP) */

#endif				/* _SYS_MEMORY_ */
