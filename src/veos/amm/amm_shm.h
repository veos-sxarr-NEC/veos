/*
* @file amm_shm.h
* @brief Header file for "amm_shm.c" file
*/

#ifndef __AMM_SHM_H
#define __AMM_SHM_H

#include "veos_list.h"
#include "amm_mem.h"
#include "memory.h"
#include "psm_task_mgmt.h"

#define	PG_SHM		(0x200000000)	/*!< Flag represent Shared memory page*/
/* Flag represent VE Anonymous page */
#define PG_VE		(0x400000000)	/*!< Flag represent VE Anonymous page*/

#define SHM_DEL		(0x1)		/*!< SHM Segemnt Destroy Flag*/
/* SHM Segment Available Flag */
#define	SHM_AVL				(0x0)	/*!< SHM Segment Available
						 * Flag*/
#define	SHM_SEG_PAGE_SIZE_64MB		(0x4)	/*!< flag represent 64MB page
						 * size segment*/
#define	SHM_SEG_PAGE_SIZE_2MB		(0x8)	/*!< flag represent 2MB page
						 * size segment*/

/**
* @brief Shared memory data structure maintained in veos.
*/
struct shm {
	int64_t key;	/*!< key for shared memory segment*/
	int64_t shmid;	/*!< id for shared memory segment*/
	int64_t perm;	/*!< permissions for shared memory segment*/
	uint64_t size;	/*!< size of shared memory segment*/
	uint64_t nattch; /*!< number of vemva attched to shared memory segment*/
	uint64_t *vemaa; /*!< physical pages corresponding to shared
			  * memory segment*/
	uint64_t flag;	/*!< flage for shared memory segment*/
	pthread_mutex_t shm_lock;  /*!< lock fot shared memory segment*/
	struct list_head shm_list; /*!< global list for shared memory segment*/
};

/**
* @brief List of shm segments attached in Process Virtual Address Space
*/
struct shm_mapping {
	void *shmaddr;	/*!< vemva at which shared memory is attached*/
	struct shm *shm_segment; /*!< reverse reference to shared memory
				  * segment*/
	int count;	/*!< number of ve pages for shared memory segment*/
	struct list_head shm_list;/*!< process specific list for shm_mapping*/
};

/* Shared memory related API's in veos */
int amm_do_shmat(int64_t, int64_t, uint64_t, uint64_t,
		int64_t, struct ve_task_struct *);
int amm_do_shmctl(int64_t, struct ve_task_struct *);
int amm_do_shmdt(uint64_t, struct ve_task_struct *,
			struct shmdt_info *);
int amm_shm_detach(struct shm*, int);
int amm_release_shm_segment(struct shm *, int);

struct shm *del_shm_mapping_entry(void *, struct ve_mm_struct *);
int insert_shm_mapping_entry(void *, struct shm *, struct ve_mm_struct *);
struct shm *amm_get_shm_segment(int64_t, int64_t, uint64_t,
		int64_t, int);
#endif
