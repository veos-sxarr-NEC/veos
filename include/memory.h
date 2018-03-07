#include "ve_hw.h"

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
 *    16       36                2     7   1  1  1
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
#define NBPSP		0x1000	/* bytes of SP */

#define BPSPSHFT	12	/* Shift for bytes per small page */
#define BPLPSHFT	21
#define BPHPSHFT	26

/*
 * PSPT
 */

#define PG_ADDR		0x0000FFFFFFFFF000LL	/* physical page frame number. */
#define PG_TYPE		0x0000000000000C00LL	/* type */
#define PG_BYPS		0x0000000000000002LL	/* cashe bypass bit. */
#define PG_WRITI	0x0000000000000004LL	/* write protection bit. */
#define	PG_NP		0x0000000000000001LL	/* invalid bit. */

#define pfn_mask	0xFFFFFFFFFFFFF000LL	/* RFU + Page Base */
#define	type_shft	10	/* type field */
#define	prot_shft	2	/* write protection field */

#define PSSHFT4K	12	/* page field (4KB)  */
#define PSSHFT		21	/* page field (2MB)  */
#define PSSHFT_H	26	/* page field (64MB) */

/* page type */
#define	PG_VHSAA	1	/* VH System Absolute Address */
#define	PG_VERAA	2	/* VE Register Absolute Address */
#define	PG_VEMAA	3	/* VE Memory Absolute Address */

#define	pg_getpb4(P)		((P)->data >> PSSHFT4K)
#define	pg_getpb_l(P)		((P)->data >> PSSHFT)
#define	pg_getpb_h(P)		((P)->data >> PSSHFT_H)
#define pg_getpb(P, pgmode) \
	(((pgmode) == PG_4K) ? pg_getpb4(P) : \
	 ((pgmode) == PG_HP) ? pg_getpb_h(P) : \
	 pg_getpb_l(P))

#define	pg_setpb4(P, pageframenum)	((P)->data |= ((uint64_t)pageframenum << PSSHFT4K))
#define	pg_setpb_l(P, pageframenum)	((P)->data |= ((uint64_t)pageframenum << PSSHFT))
#define	pg_setpb_h(P, pageframenum)	((P)->data |= ((uint64_t)pageframenum << PSSHFT_H))
/* Set page base. */
#define pg_setpb(P, pageframenum, pgmode) \
	(((pgmode) == PG_4K) ? pg_setpb4(P, pageframenum) : \
	 ((pgmode) == PG_HP) ? pg_setpb_h(P, pageframenum) : \
	 pg_setpb_l(P, pageframenum))

#define	pg_settype(P, type)	((P)->data |= (type << type_shft))
/* Set memory type. */
#define pg_unsettype(P)		((P)->data &= ~PG_TYPE)
/* Unset memory Type */
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

#define psn_mask	0xFFFFFFFFFFF00000LL	/* RFU + Partial Space Number */
#define	ps_shft4	20	/* PS# field (4KB)  */
#define	ps_shft		29	/* PS# field (2MB)  */
#define	ps_shft_h	34	/* PS# field (64MB) */
#define jid_shft	12	/* jid field */
#define pgsz_shft	1	/* page size field */

#define	PG_4K	0
#define	PG_2M	1
#define	PG_HP	2

#define	ps_setps4(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft4))
#define	ps_setps(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft))
#define	ps_setps_h(PD, psnum)	((PD)->data |= ((uint64_t)psnum << ps_shft_h))
#define ps_setpsnum(PD, psnum, pgmode) \
	(((pgmode) == PG_4K) ? ps_setps4(PD, psnum) : \
	 ((pgmode) == PG_HP) ? ps_setps_h(PD, psnum) : \
	 ps_setps(PD, psnum))
/* Set pertial space number */
#define	ps_setjid(PD, jid)	((PD)->data |= (jid << jid_shft))
/* Set JID */
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

#define ps_getps(PD, pgmode)	(((pgmode) == PG_4K) ? ps_getps4k(PD) : \
		((pgmode) == PG_2M) ? ps_getps2m(PD) : \
		((pgmode) == PG_HP) ? ps_getps_h(PD) : -1)

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

/* pgnum + offset */
#define	PSNMSHFT	29
#define PSNMSHFT_H	34
#define PSNMSHFT4K	20

/* page number */
#define PTSHFT		8

/*
 * mask
 */

/* page space number after shift */
#define PSNMMASK	0x7FFFFULL
#define PSNMMASK_H	0x3FFFULL
#define PSNMMASK4K	0xFFFFFFFULL

/*  page number after shift */
#define PTMASK		0xFFULL

/* page offset  */
#define POFFMASK	0x00000000001FFFFFULL
#define POFFMASK_H	0x0000000003FFFFFFULL
#define POFFMASK4K	0x0000000000000FFFULL

/* virtual address to psnum */
#define	psnum(v)	((uint64_t)(v) >> PSNMSHFT)
#define	psnum_h(v)	((uint64_t)(v) >> PSNMSHFT_H)
#define	psnum4k(v)	((uint64_t)(v) >> PSNMSHFT4K)

/* virtual address to pgnum */
#define	pgnum(v)	(((uint64_t)(v) >> PSSHFT) & PTMASK)
#define	pgnum_h(v)	(((uint64_t)(v) >> PSSHFT_H) & PTMASK)
#define	pgnum4k(v)	(((uint64_t)(v) >> PSSHFT4K) & PTMASK)

/* virtual address to page offset */
#define poff(v)		((uint64_t)(v) & POFFMASK)
#define poff_h(v)	((uint64_t)(v) & POFFMASK_H)
#define poff4k(v)	((uint64_t)(v) & POFFMASK4K)

/* psnum to virtual address */
#define	psnum_to_vaddr(n)	(((uint64_t)(n) & PSNMMASK) << PSNMSHFT)
#define	psnum_to_vaddr_h(n)	(((uint64_t)(n) & PSNMMASK_H) << PSNMSHFT_H)
#define	psnum_to_vaddr4k(n)	(((uint64_t)(n) & PSNMMASK4K) << PSNMSHFT4K)

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
#define pnum(X)		(((uint64_t)(X) >> PSSHFT) & PGFNMASK)
#define pnum_h(X)	(((uint64_t)(X) >> PSSHFT_H) & PGFNMASK_H)
#define pnum4k(X)	(((uint64_t)(X) >> PSSHFT4K) & PGFNMASK4K)

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
