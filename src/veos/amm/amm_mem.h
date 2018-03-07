/**
* @file amm_mem.h
* @brieaf Header file for "amm_mem.c".
*/
#ifndef __AMM_MEM_H
#define __AMM_MEM_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include "veos_list.h"
#include "libved.h"
#include "amm_psm_if.h"

#define SIZE_512KB (512*1024)
#define USRCC_OFFSET 0x00000
#define PMC_OFFSET 0x01000

#define BUFFER_SIZE	256
#define PAGE_SIZE_4KB	(2 * 2 * 1024)
#define PAGE_SIZE_2MB	(2 * 1024 * 1024)
#define PAGE_SIZE_64MB	(64 * 1024 * 1024)
#define READ_ONLY	1
#define WRITE_ONLY	2
#define RD_WR		4
#define EXEC		8

#define VE_MAP_STACK       VE_MMAP_GROWSDOWN

/* Protection flag */
#define VE_PROT_READ       (0x1)
#define VE_PROT_WRITE      (0x2)
#define VE_PROT_NONE       (0x0)

/* Mapping control flags */
#define VE_MAP_ANONYMOUS   (0x20)
#define VE_MAP_FIXED       (0x10)
#define VE_MMAP_GROWSDOWN  (0x0100)
#define VE_MMAP_GROWS_UP   (0x0200)
#define VE_MMAP_HUGEPAGE   (0x0400)

/* Macro For Address alignment */
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define SET_ATB			1
#define UNSET_ATB		0
#define BITS_PER_BLOCK		32
#define BITS_PER_WORD		64
#define BLOCKS_PER_BITMAP	8
#define WORDS_PER_BITMAP	4

#define GET_PAGE_NUMBER(page_base) ((page_base)>>21)

#define GET_PAGE ((uint8_t)1 << 0)
#define PUT_PAGE ((uint8_t)1 << 1)


/**
 * @brief Structure For File Backed handling.
 *
 *	This will contain the information about the file
 *	to be mapped as. Global List of this will be
 *	maintained in veos.
 */
struct file_map_desc {
	struct list_head global_list;	/*!< list head for global file
					 * descriptors*/
	struct list_head mapping_list;	/*!< list head for file specific map*/
	struct stat file_stat;		/*!< file specific information */
	pthread_mutex_t file_desc_lock; /*!< mutex lock*/
};

struct shm;
/*
 * Structure For File Backed handling.
 * This will contain the information about the mappings
 * over the file. List of mappings will be maintained under
 * each struct file_map_desc.
 */
/**
* @brief  Structure For File Backed handling.
*
*	This will contain the information about the mappings
*	over the file. List of mappings will be maintained under
*	each struct file_map_desc.
*/
struct mapping_desc {
	struct list_head mapping_list;	/*!< list head for file specific map*/
	int64_t offset_start;		/*!< file offset start for mapping*/
	int64_t offset_end;		/*!< file offset end for mapping*/
	uint64_t *page_array;		/*!< page array*/
	struct file_map_desc *file_desc;/*!< reverse reference to the file
					 *   corresponding to mapping*/
	pthread_mutex_t map_desc_lock;	/*!< mutex lock*/
};

/*
 * @brief Structure For File Backed handling.
 *
 *	This is used temporarily for merging
 *	functionality.
 */
struct mapping_attri {
	struct list_head *insert_after;	/*!< specify the mapping address after
					 * which current mapping descriptor to
					 * added*/
	struct list_head *merge_start;	/*!< specify the address of mapping from
					 * where to start merging*/
	struct list_head *merge_end;	/*!< specify the address of mapping from
					 * where to end merging*/
	int64_t offset_start;		/*!< offset start for new mapping*/
	int64_t offset_end;		/*!< offset end  for new mapping*/
};

/**
* @brief contain ve page details
*/
struct ve_page {
	uint64_t page_start;	/*!< page start address */
	uint64_t page_size;	/*!< page size (2MB or 64MB)*/
	uint64_t perm;		/*!< permission of page*/
	uint64_t flag;		/*!< flag specify type of mapping*/
	uint64_t ref_count;	/*!< Reference count for Number of VEMVA
				 * Mapped to this Physical page.*/
	void *private_data;	/*!< private data for ve page*/
	pthread_mutex_t ve_page_lock; /*!< mutex lock*/
};

/*File Backed Handling Related APIs*/
uint64_t *amm_do_file_back_handling(struct file_map_desc *,
		int64_t, int64_t, uint64_t *bitmap, int, uint64_t);
struct file_map_desc *init_file_map_desc(struct stat);
struct file_map_desc *scan_global_list(struct stat file_stat, int);
struct mapping_desc *init_mapping_desc(struct mapping_attri *);
int init_page_array(struct mapping_desc *, struct mapping_attri *);
uint64_t *update_mapping_desc(uint64_t *, uint64_t, uint64_t *bitmap, int, uint64_t);
struct list_head *free_redundant_list(struct list_head *,
		struct list_head *);
void dump_mapping_desc(struct mapping_desc *);
int release_page(uint64_t, int, uint64_t);
int stat_cmp(struct stat *, struct stat *);
struct mapping_attri *collect_map_attri(struct file_map_desc *, int64_t,
		int64_t);
int add_mapping_desc(struct file_map_desc *,
		struct mapping_desc *, struct mapping_attri *);
void set_bit(uint64_t *, uint64_t);
void set_bits(uint64_t *, uint64_t, uint16_t);
int check_bits_set(uint64_t *, uint64_t, uint64_t);
int send_file_data(uint64_t , uint64_t *, struct stat, int64_t,
			struct ve_task_struct *, uint64_t,
			uint64_t);
int64_t extract_file_pgoff(struct mapping_desc *, struct ve_page *);
uint64_t *segment_expandable(struct shm *, uint64_t , uint64_t);

/*Split functionality will update this*/
int clear_page_array_entry(struct mapping_desc *, struct ve_page *);

/* VE memory controlling APIs */
int amm_do_mmap(uint64_t, uint64_t, uint64_t, uint64_t,
		struct ve_task_struct *,
		struct file_map_stat *);
int amm_do_munmap(uint64_t, size_t, struct ve_task_struct *);
int amm_do_mprotect(uint64_t, uint64_t, uint64_t,
				struct ve_task_struct *);
int amm_do_mremap(uint64_t, size_t, size_t, uint64_t,
		  struct ve_task_struct *);

int ve_node_page_free_count(int);
int ve_node_page_used_count(int);
int set_page_free(uint64_t, int, uint64_t);
int set_page_used(uint64_t, int, uint64_t);
int get_free_pages(int, uint64_t);
int get_page_size(uint64_t, atb_reg_t *);
int is_page_used(uint64_t, int, uint64_t);
int alloc_ve_pages(uint64_t, uint64_t *, int, uint64_t);
int amm_init_atb(atb_reg_t *);
int amm_copy_atb_private(atb_reg_t *, atb_reg_t *, int);
int amm_copy_phy_page(uint64_t, uint64_t, int);
int amm_clear_page(uint64_t, int, uint64_t);
int amm_dma_xfer(int, uint64_t, int, int, uint64_t, int, uint64_t, int);
int vemva_to_vemaa(pid_t, uint64_t, uint64_t *);
int amm_initialize_zeroed_page(uint64_t, int);

int veos_get_page(uint64_t *);
int veos_put_page(uint64_t);
int common_get_put_page(uint64_t, uint8_t);
void veos_free_page(struct ve_page *);
uint64_t veos_virt_to_phy(uint64_t, pid_t, bool);

/*
 * TODO:
 * Merge ATB set functions(TBD)
 */
int amm_set_atb(uint64_t, int, int, atb_reg_t *, uint64_t);

/*
 * API moved from loader to AMM
 */
int search_atb_ps(char *, int, atb_reg_t *);
int search_dmaatb_ps(char *, int, dmaatb_reg_t *, int);
int init_atb_dir(atb_reg_t *, int, int, int, int);
void amm_dump_atb(atb_reg_t *);
void amm_sys_meminfo(struct sysinfo *);
#endif
