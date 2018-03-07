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
 * @file cr_api.h
 * @brief This header file contains declaration
 * of CR management related function and data structure.
 *
 * @internal
 * @author AMM
 */
#ifndef __CR_API_H
#define __CR_API_H

#include<stdint.h>
#include<stdbool.h>
#include "ve_list.h"
#include "veos_defs.h"

#define CR_PAGE_BMAP_MAX 0xffffffff
#define MAX_CRD_PER_CORE 4
#define CR_REG_PER_PAGE 32
#define THREAD_CRDNO 0

#define CR_PAGE_SHIFT 0
#define CR_VALID_SHIFT 63

#define mode_flag_to_str(p) ((p == VE_CR_THREAD) ? "VE_CR_THREAD" : "VE_CR_MIP")

enum cr_page_type {THREAD = 0, MPI, ALL, NONE, DELAYED};

#define IS_EQUAL(type, a, b) ((type)a ^ (type)b)
#define SET_CR_BIT(type, bitmap, bit)  (bitmap |= (type)1 << bit)
#define UNSET_CR_BIT(type, bitmap, bit)  (bitmap &= ~((type)1 << bit))

#define VALID_MASK	0x8000000000000000LL
#define CR_PAGE_MASK	0x000000000000001FLL
#define cr_clearpg(p)	((p)->data &= (~CR_PAGE_MASK))
#define cr_setpg(p, q)	((p)->data |= ((q << CR_PAGE_SHIFT) & CR_PAGE_MASK))
#define cr_getpg(p)	(((p)->data >> CR_PAGE_SHIFT) & CR_PAGE_MASK)

#define crdisvalid(p)		(((p)->data & VALID_MASK) >> CR_VALID_SHIFT)
#define setcrdinvalid(p)	((p)->data &= (~VALID_MASK))
#define setcrdvalid(p)		((p)->data |= VALID_MASK)
#define CR_INIT_VAL 0x00UL

#define tot_cr_res(p) (p->nr_avail_cores)

/*CR page manipulation*/
struct tsk_cr_pg {
	int t_th_pg;	/*!< Number of cr_thread_page allocated*/
	int t_mpi_pg;	/*!< Number of cr_mip page allocated */
	int t_cr_pg;	/*!< Total cr page allocated*/
};

/* CR resource limit for Node/Process*/
struct ve_cr_rlim {
	int cr_th_pg_mx;	/*!< maximum CR page of type VE_CR_THREAD*/
	int cr_mpi_pg_mx;	/*!< maximum CR page of type VE_CR_MIP*/
	int cr_pg_mx;	/*!< maximum cr page */
};

/*CR page attribute*/
struct ve_cr_page {
	uint64_t page_attr;	/*!< VE_CR_THREAD or VE_CR_MPI */
	uint64_t ref_count;	/*!< Reference count
				increased on every remote attach */
	uint64_t cr_page_no;	/*!< CR page number*/
	struct ve_task_struct *tsk;	/*back ref to the task struct*/
};

/*
 * This cr share task list structure
 * This structure will be used to track CR page usage
 * between inter/intra node VE process. This information
 * will be used to manage CR page usage more effectively.
 * For now this data structure will dump information about
 * the processes using CR page*/
struct cr_stl {
	pid_t pid;	/*!< pid of process*/
	int node_id;	/*! node id no which process exist*/
	struct list_head *stl; /*!< share task list*/
};

/*Function to alloc and free cr data*/
int amm_alloc_cr_data(struct ve_mm_struct *);
int amm_init_node_cr_data(struct ve_node_struct *);
void amm_free_cr_data(struct ve_mm_struct *);
int amm_set_crd(crd_t *, int, int, size_t);
int amm_init_cr_reg(void);

/*Internal functions*/
int val_cra(int, int, int);
void update_ve_cr_page(struct ve_node_struct *, uint64_t,
			int, struct ve_task_struct *);
int common_get_put_cr_page(int, int);

/*CR related functions*/
int veos_get_free_cr_page(uint64_t);
int veos_allocate_cr_page(uint64_t mode_flag, pid_t pid);
int64_t veos_attach_cr_page(uint64_t, pid_t, pid_t);
int veos_get_cr_page(uint64_t, pid_t);
int veos_detach_cr_page(uint64_t, pid_t);
int __veos_do_detach_cr_page(uint64_t, struct ve_task_struct *, bool);
int veos_do_detach_cr_page(uint64_t, pid_t, bool);
int veos_free_cr_page(uint64_t);
int veos_put_cr_page(uint64_t);
void veos_set_crd(struct ve_task_struct *, uint8_t, int, bool, bool);
int veos_save_cr(struct ve_task_struct *);
int veos_restore_cr(struct ve_task_struct *);
void veos_set_crd_context(struct ve_task_struct *);
int set_cr_rlimit(pid_t, uint64_t, int, int);
void dump_cr(pid_t, uint64_t);

/*CR Dump functions*/
int veos_dump_cr(struct ve_task_struct *, uint64_t);
int amm_dump_cr_reg_process(char *, int);
int amm_dump_cr_reg_node(char *);

#endif
