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
 * @file mm_common.h
 * @brief Interfaces and data structures related VEHVA management.
 *
 * @internal
 * @author AMM
 */
#ifndef __AMM_PSM_IF_H
#define __AMM_PSM_IF_H

#include <pthread.h>
#include "ve_list.h"
#include "ve_hw.h"
#include "task_mgmt.h"
#include "mm_type.h"

#define REQUEST_FOR_PROCESS_SHARED     1
#define REQUEST_FOR_PROCESS_PRIVATE    2
#define REQUEST_FOR_VFORK_PROCESS      3

#define PARENT(X)       ((X-1)/2)
#define LEFT(X)         (2*X+1)
#define RIGHT(X)        (2*X+2)

#define DMA_DESC_E	(uint8_t)0x1
#define DMA_DESC_H	(uint8_t)0x2
#define DMA_DESC_E_H	(uint8_t)0x3

/*
 * Data Structures
 */
typedef struct vehva_header {
	uint64_t *bmap_4k;
	uint64_t *bmap_2m;
	uint64_t *bmap_64m;
	pthread_mutex_t vehva_4k_lock; /*!< mutex lock*/
	pthread_mutex_t vehva_2m_lock; /*!< mutex lock*/
	pthread_mutex_t vehva_64m_lock; /*!< mutex lock*/
} vehva_header_t;

struct ve_mm_struct {
	uint8_t udma_desc_bmap;	/* !< Determines DMA Descriptor table E & H */
	/* ATB structure*/
	atb_reg_t atb;
	/* DMAATB structure */
	dmaatb_reg_t dmaatb;
	/* Mutex lock */
	pthread_mutex_t thread_group_mm_lock;
	/* SHM/LHM area address for maintaining system call VHSAA and VHVA */
	vhsaa_t shm_lhm_addr_vhsaa;
	uint64_t shm_lhm_vehva;
	uint64_t shm_lhm_addr_vehva;

	/* Count for number of threads that are sharing this mm_struct */
	uint64_t ref_count;
	/* SHM/LHM area address */
	uint64_t shm_lhm_addr;
	/* Info regarding threads under process */
	/*List of shm segments attached in Process Virtual Address Space*/
	struct list_head shm_head;
	/*bitmap information related to veshm*/
	struct veshm_struct veshm[ATB_DIR_NUM];
	vehva_header_t vehva_header;
	/* Will be used by CR module to take decision
	 * while allocating CR thread page
	 */
	bool is_sched;
	crd_t *crd; /*!< CR registor page*/
	uint64_t crd_type[MAX_CRD_PER_CORE];/*Is crd thread type*/
	cr_cluster_t cr_data[MAX_CRD_PER_CORE]; /*!<
						 * Buffer of size 256 bytes, data used for
						 * context switch for VE_CR_THREAD
						 */
	struct tsk_cr_pg *tsk_cr_pg_acc; /*!< accounting data for CR*/
	struct ve_cr_rlim *p_cr_rlim; /*!< CR rlimit*/

	char *dma_dump_file;
	uint64_t start_code, end_code,
		start_data, end_data,
		start_brk, brk,
		start_stack, arg_start,
		arg_end, env_start,
		env_end, rss_max, crss_max,
		rsslim, rss_cur,
		shared_rss, pgsz,
		rss_data, rss_stack,
		vm_size;
	uint64_t anon;
	uint64_t anonhuge;
	int	argc;	/* argc of VE */
	char	cr_dump_fname[FILENAME_MAX];
        uint64_t argv_addr;	/* argv of VE */
        uint64_t argv_size;	/* aux of VE */
        uint64_t auxv_addr;	/* aux of VE */
        uint64_t auxv_size;	/* aux of VE */
};


/* <------ AMM Interfaces ------> */
extern int amm_alloc_mm_struct(struct ve_mm_struct **);
extern int __amm_alloc_mm_struct(struct ve_mm_struct **);
extern int amm_copy_mm_struct(struct ve_mm_struct *,
				struct ve_mm_struct **, int);
extern int amm_update_atb(struct ve_task_struct *, uint64_t);
extern int amm_update_dmaatb(struct ve_task_struct *, uint64_t);
extern int amm_update_atb_all(struct ve_task_struct *);
extern int amm_del_mm_struct(struct ve_task_struct *);
extern int __amm_del_mm_struct(struct ve_task_struct *);
extern vemaa_t __veos_virt_to_phy(vemva_t, atb_reg_t *, int *, int *);
uint64_t amm_get_rss_in_kb(struct ve_mm_struct *);
int64_t veos_jid_init(void);
int64_t veos_get_jid(struct ve_task_struct *);

struct pid_list {
	struct list_head list;	/*!< list head for pid_list*/
	struct ve_task_struct *tsk;	/*!< Pointer to task struct */
};

/**
 * @brief Structer conatin reference count for jid and pid corrensponding.
 */
struct jid {
	struct list_head pid;	/*!< Pointer to list of pid. */
	unsigned int ref;	/*!< number of process corresponding Jid. */
};
typedef struct jid jid_struct_t;

#define MAX_JID_PROCESS   256

typedef uint64_t  jid_map_t;

/**
 * @brief Structure to maintain JID.
 */
struct jid_data {
	jid_struct_t jid_arr[256];	/*!< Array of struct JID. */
	pthread_mutex_t mtx;		/*!< Mutex lock synchronization */
	jid_map_t bmap_jid_free[4];	/*!< Bitmap to maintain JID */
	jid_t curr;		/*!< This will indicate the current jid to
				 * be consider */
	int64_t max_jid;	/*!< Max_jid will be 256 initially but privilege
				 * user can chang it*/
	uint64_t jid_total;	/*!< Represnt total jid allocated in node*/
};

typedef struct heap_data {
	jid_t jid;
	uint64_t ref;
} heap;

extern struct jid_data jid_globl;
void amm_init_heap_struct(void);
void veos_free_jid(struct ve_task_struct *tsk);
void swap(heap *x, heap *y);
void heapifyup(int idx);
void heapifydown(int idx);
bool increaserefcnt(int idx);
bool decreaserefcnt(int idx);
#endif
