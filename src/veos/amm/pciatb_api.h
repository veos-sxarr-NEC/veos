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
/*
 * @file pciatb_api.h
 * @brief PCIATB management functions.
 *
 * @internal
 * @author AMM
 */
#ifndef __PCIATB_API_H
#define __PCIATB_API_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "ve_list.h"
#include "libved.h"
#include "mm_common.h"
#include "ve_mem.h"

/*
 * PCI_ALLOC_NORMAL: PCIATB page size and VE page size is 2MB
 * PCI_ALLOC_HUGE: PCIATB page size and VE page size is 64MB
 * PCI_ALLOC_PARTIAL: PCIATB page size is 2MB and
 * VE page size is 64MB.
 * PCI_ALLOC_HYBRID: PCIATB page size is 2MB and VE page size
 * for requested address is 2MB or 64MB
 * PCI_ALLOC_ERROR: PCIATB page size is 64MB and VE page
 * size is 2MB
 */
enum pci_req_type {PCI_ALLOC_NORMAL = 0, PCI_ALLOC_PARTIAL,
	PCI_ALLOC_HUGE, PCI_ALLOC_HYBRID, PCI_ALLOC_ERROR};


/*
 * This enumaration is to define pciatb attibutes
 * currently there is only one attr "SIZE".
 */
enum pciattr {PCIATTR_SIZE = 1};

#define PAGE_2MB	(2 * 1024 * 1024)
#define PAGE_64MB	(64 * 1024 * 1024)
#define PCIBAR_128MB	(128 * 1024 * 1024)

/*PCIATB attribute structure*/
typedef union pci_attr {
	reg_t data;
	struct {
		reg_t rfu0:63, size:1;
	} bf;
} pci_attr_t;

#define PCIENTRY_PER_MAP 64

/*PCISYAR and PCISYMR max lim*/
#define PCISYAR_MAX	4
#define PCISYMR_MAX	4
#define PAIR_MAX	4

#define SYR_PAIR_SHIFT		5
#define SYNC_SHIFT		4
#define PB_SHIFT		21

#define SYNC_SET	1
#define SYNC_UNSET	0

#define PB_MASK		(((uint64_t)1 << 27) - 1)
#define SYR_MASK	(((uint64_t)1 << 2) - 1)

#define PGMOD_2MB	1
#define PGMOD_64MB	2

/*PCISYAR/PCISYMR pair*/
#define PCISY_PAIR_0 0
#define PCISY_PAIR_1 1
#define PCISY_PAIR_2 2
#define PCISY_PAIR_3 3

#define SET_PCISY_PAIR_BF(p, q) \
do {\
	if (PCISY_PAIR_0 == q) \
		p->bf.num |= PCISY_PAIR_0; \
	else if (PCISY_PAIR_1 == q) \
		p->bf.num |= PCISY_PAIR_1; \
	else if (PCISY_PAIR_2 == q) \
		p->bf.num |= PCISY_PAIR_2; \
	else \
		p->bf.num |= PCISY_PAIR_3; \
} while (0)

#define SET_PCISY_PAIR(p, q) \
do {\
	if (PCISY_PAIR_0 == q) \
		p->data |= (PCISY_PAIR_0 << SYR_PAIR_SHIFT); \
	else if (PCISY_PAIR_1 == q) \
		p->data |= (PCISY_PAIR_1 << SYR_PAIR_SHIFT); \
	else if (PCISY_PAIR_2 == q) \
		p->data |= (PCISY_PAIR_2 << SYR_PAIR_SHIFT); \
	else \
		p->data |= (PCISY_PAIR_3 << SYR_PAIR_SHIFT); \
} while (0)

#define SET_SYNC(p)		(p->data |= (SYNC_SET << SYNC_SHIFT))
#define UNSET_SYNC(p)		(p->data &= ~(SYNC_SET << SYNC_SHIFT))
#define GET_SYNC(p)		((p->data >> SYNC_SHIFT) & (uint64_t)1)
#define GET_PCISY_PAIR(p)	((p->data >> SYR_PAIR_SHIFT) & SYR_MASK)

#define SET_SYNC_BF(p) (p->bf.sync |= SYNC_SET)
#define UNSET_SYNC_BF(p) (p->bf.sync |= SYNC_UNSET)
#define GET_SYNC_BF(p) (p->bf.sync)
#define GET_PCISY_PAIR_BF(p) (p->bf.num)


#define PCIATB_PAGE_BASE_MASK   0x0000FFFFFFE00000LL    /* PCIATB: Page base */
#define INVALID_ENTRY ((uint64_t)-1 & PCIATB_PAGE_BASE_MASK) /*Invalid entry*/

#define GET_PCIATB_PB_BF(entry)   ((entry)->bf.page_base_address)

#define GET_PCIATB_PB(entry)   (((entry)->data >> PB_SHIFT) & PB_MASK)

int amm_init_pciatb(struct ve_node_struct *);
void veos_set_pciatb(pciatb_entry_t *, int, int);
int64_t veos_get_vhsaa_pciatb(vemaa_t, pid_t);
int64_t veos_alloc_pciatb(pid_t, uint64_t, size_t, uint64_t, bool);
int64_t veos_delete_pciatb(uint64_t, size_t);
void veos_set_pciatb_attr(uint64_t, uint64_t);
int veos_amm_set_pcisyar(uint8_t, uint64_t);
int veos_amm_get_pcisyar(uint8_t, uint64_t *);
int veos_amm_set_pcisymr(uint8_t, uint64_t);
int veos_amm_get_pcisymr(uint8_t, uint64_t *);
int veos_set_pciatb_pgdesc(pid_t, uint8_t, uint64_t, uint64_t);
int veos_get_pciatb_pgdes(pid_t, uint8_t *, uint64_t *, uint64_t);

int pciatb_dump(void);
int alloc__pcientry(uint64_t start_entry,
		uint64_t count, uint64_t *page_base);
int veos_free_pcientry(uint64_t start_entry, size_t size);
int mk_pci_pgent(uint64_t, uint64_t, struct ve_mm_struct *, size_t, int,
			uint64_t *, uint64_t, bool);
int free_unused_entry(uint64_t, size_t, size_t);
int veos_alloc_vdso_pcientry(uint8_t, uint64_t);
int veos_delete_vdso_pcientry(uint64_t);
#endif
