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
 * @file vehva_mgmt.h
 * @brief Header file for vehva_mgmt.c
 *
 * @internal
 * @author AMM
 */
#include<pthread.h>
#include<stdint.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>
#include"ve_mem.h"

/*VEHVA region flags*/
#define VEHVA_CR	((uint64_t)1 << 0)	/*!< Use 4K page mode*/
#define VEHVA_VESHM	((uint64_t)1 << 1)	/*!< Use 2MB, 64MB page mode*/
#define VEHVA_IB	((uint64_t)1 << 2)	/*!< VEHVA_TYPE and use
							page mode 4K*/
#define VEHVA_SYSCALL	((uint64_t)1 << 3)	/*!< System call and use
							4K page mode*/
#define VEHVA_2MB       ((uint64_t)1 << 4)	/*!< PAGE MODE for VESHM 2MB*/
#define VEHVA_64MB      ((uint64_t)1 << 5)	/*!< PAGE MODE for VESHM 64MB*/
#define VEHVA_4K	((uint64_t)1 << 6)	/*!< PAGE MODE for VESHM 64MB*/

#define VEHVA_DMA_CNT_REG ((uint64_t)1 << 7)	/*!< vehva for DMA control
							register */
#define VEHVA_DMA_DESC_REG ((uint64_t)1 << 8)	/*!< vehva for DMA descriptive
							table*/
#define VEHVA_SYSCOM_REG	((uint64_t)1 << 9)	/*!< sysstem common reg*/
#define VEHVA_MAP_FIXED		((uint64_t)1 << 10)	/*!< Overwrite DMAATB entry*/

/*VEHVA Layout*/
#define VEHVA_4K_START		0x000000000000	/*!< Start of 4K region*/
#define VEHVA_4K_END		0x000003ffffff	/*!< End of 4K region*/
#define VEVHA_SYS_COM_START	0x000000001000	/*!< Start of system commmon
							register region.*/
#define VEVHA_SYS_COM_END	0x000000002fff	/*!< End of system commmon
							register  region.*/
#define DMA_CNT_START		0x000000003000	/*!< Start of DMA control
							engine region.*/
#define DMA_CNT_END		0x000000003fff	/*!< End of DMA control
							engine region.*/
#define DMA_DESC_START		0x000000004000	/*!< Start of DMA descriptor
							table region. */
#define DMA_DESC_END		0x000000004fff	/*!< End of DMA descriptor
							table region. */
#define VEHVA_2M_START		0x008800000000	/*!< Start of 2M region*/
#define VEHVA_2M_END		0x008fffffffff	/*!< End of 2M region*/
#define VEHVA_64M_START		0x070000000000	/*!< Start of 64M region*/
#define VEHVA_64M_END		0x07ffffffffff	/*!< End of 64M region*/
#define VEHVA_DIR0_END		0x0000000fffff	/*!< END of 4K region*/

/* Conversion macros */
#define VEHVA_TO_DMADIR(VEHVA)		/* Used by veos_set_dmaatb()
						to identify the type*/
#define VEHVA_TO_DMAENT(VEHVA, DIR)	/* Used by veos_set_dmaatb()
						to identify the type*/
#define VEHVA_PGMODE(VEHVA)		/* Used by veos_set_dmaatb() */

/* Macros for handling the IB & CR */
#define IB_START_ENTRY		6
#define IB_END_ENTRY		101
#define RSRV_ENTRY		102
#define RSRV_CNT		90
#define CR_START_ENTRY		192
#define CR_END_ENTRY		255

#define VESHM_START_ENTRY	0
#define VESHM_END_ENTRY		(DMAATB_ENTRY_MAX_SIZE*DMAATB_DIR_NUM)
/**
* @brief This flag is used to specify,
* if bits have to be marked in VEHVA handling or not.
*/
#define MARK_USED               (((uint8_t)1)<<0)
#define MARK_UNUSED             (((uint8_t)1)<<1)

int veos_vehva_init(struct ve_mm_struct *);
int64_t veos_vehva_alloc(int, uint64_t, struct ve_task_struct *);
int veos_vehva_free(vehva_t, size_t, struct ve_task_struct *);

int64_t veos_get_free_vehva(uint64_t *, int64_t, int64_t, int64_t);
void mark_bits(uint64_t *, int64_t, int64_t, uint8_t);
