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
 * @file ve_shm.h
 * @brief Header file for "ve_shm.c" file
 *
 * @internal
 * @author AMM
 */

#ifndef __AMM_SHM_H
#define __AMM_SHM_H

#include "ve_list.h"
#include "ve_mem.h"
#include <sys/mman.h>
#include "ve_memory.h"
#include "task_mgmt.h"
#include "task_signal.h"

#define	PG_SHM		(0x200000000)	/*!< Flag represent Shared memory page*/
/* Flag represent VE Anonymous page */
#define PG_VE		(0x400000000|MAP_ANON)	/*!< Flag represent VE Anonymous page*/
#define PG_PTRACE	(0x800000000)	/*!< Flag represent VE Anonymous page*/

#define SHM_DEL		(0x1)		/*!< SHM Segemnt Destroy Flag*/
/* SHM Segment Available Flag */
#define	SHM_AVL				(0x0)	/*!< SHM Segment Available
						 * Flag*/
#define SHM_2MB         ((uint32_t)1 << 22)
#define SHM_64MB        ((uint32_t)1 << 23)

/**
* @brief Shared memory data structure maintained in veos.
*/
struct shm {
	key_t key;	/*!< key for shared memory segment*/
	int shmid;	/*!< id for shared memory segment*/
	int64_t perm;	/*!< permissions for shared memory segment*/
	size_t size;	/*!< size of shared memory segment*/
	uint64_t nattch; /*!< number of vemva attched to shared memory segment*/
	vemaa_t *vemaa; /*!< physical pages corresponding to shared
			  * memory segment*/
	uint64_t flag;	/*!< flag for shared memory segment*/
	int pgmod;	/*!< Page mode for shared memory segment*/
	pthread_mutex_t shm_lock;  /*!< lock fot shared memory segment*/
	struct list_head shm_list; /*!< global list for shared memory segment*/
};

/**
* @brief List of shm segments attached in Process Virtual Address Space
*/
struct shm_map {
	vemva_t shmaddr;	/*!< vemva at which shared memory is attached*/
	struct shm *shm_segment; /*!< reverse reference to shared memory
				  * segment*/
	int count;	/*!< number of ve pages for shared memory segment*/
	struct list_head shm_list;/*!< process specific list for shm_map*/
};

/* Shared memory related API's in veos */
int amm_do_shmat(key_t, int, vemva_t, size_t,
		int64_t, struct ve_task_struct *);
int amm_do_shmctl(int, struct ve_task_struct *);
int amm_do_shmdt(vemva_t, struct ve_task_struct *,
			struct shm_seginfo *);
int amm_shm_detach(struct shm*, int);
int amm_release_shm_segment(struct shm *);

struct shm *del_shm_map_entry(vemva_t, struct ve_mm_struct *);
int insert_shm_map_entry(vemva_t, struct shm *, struct ve_mm_struct *);
struct shm *amm_get_shm_segment(key_t, int, size_t, int, bool);
#endif
