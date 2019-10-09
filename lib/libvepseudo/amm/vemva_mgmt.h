/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file vemva_mgmt.h
 * @brief Header file for "vemva_mgmt.c".
 *
 *	Include MACRO and data structure for VE
 *	specific Virtual memory management.
 *
 * @internal
 * @author AMM
 */
#ifndef __VEMVA_MGMT_H
#define __VEMVA_MGMT_H

#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <error.h>
#include "list.h"
#include "libved.h"
#include "comm_request.h"
#include "sys_common.h"
#include "mm_type.h"

/* AMM specific macros and function prototype */
#define PAGE_SIZE_4KB		(2 * 2 * 1024)
#define PAGE_SIZE_2MB		(2 * 1024 * 1024)
#define PAGE_SIZE_64MB		(64 * 1024 * 1024)
#define MASK_2MB_ALIGN		(PAGE_SIZE_2MB - 1)
#define MASK_64MB_ALIGN		(PAGE_SIZE_64MB - 1)

/* Macro For Address alignment */
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ALIGN_RD(x, a)  (x & (~((typeof(x))(a) - 1)))
/* Macro For VEMVA Support */
#define ENTRIES_PER_DIR		256
#define MAX_VEMVA_LIST		32
#define BITS_PER_WORD		64
#define WORDS_PER_BITMAP	4

#define CHUNK_512GB	0x8000000000
#define CHUNK_512MB	0x20000000
#define CHUNK_16GB	0x400000000
#define CHUNK_512MB_MASK      (CHUNK_512MB - 1)
#define CHUNK_16GB_MASK      (CHUNK_16GB - 1)

#define ANON_SPACE_2MB		((uint8_t)1 << 0)
#define ADDR_SPACE_2MB		((uint8_t)1 << 1)
#define ANON_SPACE_64MB		((uint8_t)1 << 2)
#define ADDR_SPACE_64MB		((uint8_t)1 << 3)

#define AS_WITHIN_64GB_2MB	((uint8_t)1 << 4)
#define AS_WITHIN_64GB_64MB	((uint8_t)1 << 5)

/* Mapping control flags
 * Note : MAP_2MB, MAP_64MB, MAP_ADDR_SPACE, MAP_VDSO flags are also
 * defined in file 've_mem.h'. There puropose is same in noth file.
 * please take care while modifying these flag value.
 *
 * Note : MAP_ADDR_64GB_FIXED and MAP_ADDR_64GB_SPACE these both
 * flags are also defined in file 'loader.c' and glibc please take
 * before modifying the value of these flag
 * */

#define MAP_VESHM		((uint64_t)1<<21)
#define MAP_2MB			((uint64_t)1<<22)
#define MAP_64MB		((uint64_t)1<<23)
#define MAP_ADDR_64GB_FIXED     ((uint64_t)1<<36)
#define MAP_ADDR_64GB_SPACE     ((uint64_t)1<<35)
#define MAP_ADDR_SPACE		((uint64_t)1<<34)
#define MAP_VDSO		((uint64_t)1<<32)


/**
* @brief This flag is used to specify,
* if bits have to be marked in VEMVA handling or not.
*/
#define MARK_USED		(((uint8_t)1)<<0)
#define MARK_UNUSED		(((uint8_t)1)<<1)
#define ALL_CONSEC		(((uint8_t)1)<<3)
#define MARK_VESHM		(((uint8_t)1)<<4)
#define MARK_FILE		(((uint8_t)1)<<5)


/**
* @brief These macro are related to mapping that comes under first 64GB
*        of process address space.
*/
#define HEAP_START			0x601000000000
#define ADDR_SPACE_2MB_START		0x600000000000
#define ADDR_SPACE_64MB_START		0x600000000000
#define ADDR_SPACE_2MB_END		0x600400000000
#define ADDR_SPACE_64MB_END		0x600c00000000
#define TRAMP_2MB                       0x6003ffe00000
#define TRAMP_64MB                      0x600fffe00000

extern uint64_t default_page_size;
/**
 * @brief Structure to store ve page info
 */
struct _ve_page_info {
	uint64_t page_size;	/*!< page size */
	uint64_t chunk_size;	/*!< chunk size */
	uint64_t page_mask;     /*!< page size mask*/
	uint64_t chunk_mask;	/*!< chunk size mask*/
	int updated;
};
extern __thread struct _ve_page_info ve_page_info;

/**
* @brief structure to manage vemva address space.
*/
struct vemva_header {
	pthread_mutex_t vemva_lock;	/*!< pthread_mutex lock  for VEMVA*/
	uint64_t vemva_count;		/*!< VEMVA dir count*/
	uint64_t ve_text;		/*!< ve text section address */
	uint64_t ve_heap;		/*!< ve heap section address */
	uint64_t ve_stack;		/*!< ve stack section address */
	struct list_head vemva_list;	/*!< list head for vemva list*/
};
extern struct vemva_header vemva_header;

/**
 * * @brief structure to specify executable and shared libraries address
 *          mapping withing first 64GB of total address space.
 * */
typedef struct addr_space_attribute {
	vemva_t addr_space_2mb_next;	/*!< starting address for 2MB
					 * page aligned mapping*/
	vemva_t addr_space_64mb_next;	/*!< starting address for 64MB
					 * page aligned mapping */
	union trampoline {
		vemva_t tramp_2MB;
		vemva_t tramp_64MB;
	}tramp;
	pthread_mutex_t as_attr_lock; /*!< pthread_mutex lock to access
                                           address space mapping attributes*/
} as_attr_t;

extern as_attr_t as_attributes;

/**
 * @brief Data Structure for VEMVA List
 */
struct vemva_struct {
	struct list_head list;			/*!< structure to contain
						 * list entry*/
	void *vemva_base;			/*!< pointer to vemva base
						 *  address */
	uint64_t bitmap[WORDS_PER_BITMAP];	/*!< bitmap which is used*/
	uint64_t veshm_bitmap[WORDS_PER_BITMAP];/*!< bitmap which is VESHM */
	uint64_t file_bitmap[WORDS_PER_BITMAP];	/*!< bitmap which is fileback
						 * or not*/
	uint8_t type;				/*!< dir type (2MB or 64MB)*/
	uint64_t dir_size;			/*!< dir size*/
	uint64_t used_count;			/*!< Number of used pages*/
	uint8_t consec_dir;			/*!< consective dir count*/
	pthread_mutex_t vemva_bitmap_lock;	/*!< pthread_mutex lock for
						 * VEMVA*/
};

/* VEMVA supported functions prototypes */
void *ve_get_vemva(veos_handle *, uint64_t, uint64_t,
		uint64_t, int, int, uint64_t);
void *ve_get_vemva_under_64GB(veos_handle *, vemva_t, uint64_t,
		uint64_t, int, int, uint64_t);
void *ve_get_nearby_vemva(veos_handle *, struct vemva_struct *,
		uint64_t, int64_t, int64_t, uint64_t);
void *ve_get_fixed_vemva(veos_handle *, struct vemva_struct *,
		uint64_t, int64_t, int64_t, uint64_t);
void *ve_get_free_vemva(veos_handle *, struct vemva_struct *,
		uint64_t, int64_t);

void *avail_vemva(veos_handle *, uint64_t, uint64_t, uint64_t);
void *get_aligned_chunk(uint64_t, uint8_t, uint64_t);
int ve_free_vemva(void *, size_t);
int __ve_free_vemva(void *, size_t, bool);
int free_vemva(veos_handle *, struct vemva_struct *, int64_t,
		int64_t);
void *scan_vemva_dir_list(veos_handle *, uint64_t, uint64_t);
struct vemva_struct *alloc_vemva_dir(veos_handle *, struct vemva_struct *,
		uint64_t, uint16_t, int64_t);
int dealloc_vemva_dir(struct vemva_struct *);
void add_vemva_dir_in_list(struct vemva_struct *);
int mark_vemva(uint64_t, uint64_t, int);
int check_bits(struct vemva_struct *, int64_t, int64_t, uint8_t);
void mark_bits(struct vemva_struct *, int64_t, int64_t, uint8_t);
int init_vemva_header(void);
void init_as_attr(void);
void continous_free(struct vemva_struct *, int64_t, int64_t *);
int get_page_size(vemva_t);
uint64_t __get_page_size(vemva_t vaddr);

int vemva_mapped(void *, size_t, uint8_t);
int check_vemva_mapped(void *, size_t, uint8_t);
#endif
