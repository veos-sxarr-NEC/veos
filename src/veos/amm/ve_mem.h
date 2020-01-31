/*
 * Copyright (C) 2017-2019 NEC Corporation
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
 * @file ve_mem.h
 * @brieaf Header file for "ve_mem.c".
 *
 * @internal
 * @author AMM
 */
#ifndef __AMM_MEM_H
#define __AMM_MEM_H

#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <malloc.h>
#include "ve_list.h"
#include "libved.h"
#include "locking_handler.h"
#include "task_sched.h"
#include "mm_common.h"
#include "task_signal.h"
#include "veos_defs.h"
#include "ve_memory.h"
#include "velayout.h"
#include "mm_type.h"
#include "dma_private.h"

#define SIZE_512KB (512*1024)
#define USRCC_OFFSET 0x00000
#define PMC_OFFSET 0x01000
#define EDMACTL_OFF     0x22000
#define EDMADESC_E_OFF    0x21000
#define EDMADESC_H_OFF    0x20000
#define USRCC_OFFSET 0x00000
#define PMC_OFFSET 0x01000

#define VERAA(a)        (a * (SIZE_512KB +SIZE_512KB))
#define SYSPROT_OFF     SIZE_512KB
#define SYSCOM_ADD      0x1000000
#define SYSSTM_OFFSET	0x000000
#define SYSCRPM_OFFSET	0x001000
#define SYSPCI_OFFSET	0x007000
#define ATB		1
#define DMAATB		2
#define CRDIR		3

#define BUFFER_SIZE	256
#define PAGE_SIZE_4KB	(2 * 2 * 1024)
#define PAGE_SIZE_2MB	(2 * 1024 * 1024)
#define PAGE_SIZE_64MB	(64 * 1024 * 1024)
#define READ_ONLY	1
#define WRITE_ONLY	2
#define RD_WR		4
#define EXEC		8

#define CHUNK_512MB	0x20000000

#define SMALL_PSHFT	12      /*<!Shift for small page*/
#define LARGE_PSHFT	21	/*<!Shift for large page*/
#define HUGE_PSHFT	26	/*<!Shift for huge page*/

/* Mapping control flags
 * Note : MAP_2MB, MAP_64MB, MAP_ADDR_SPACE, MAP_VDSO flags are also
 * defined in file 've_mem.h'. There puropose is same in both files.
 * please take care while modifying these flag value
 */
#define MAP_2MB			((uint64_t)1<<22)
#define MAP_ADDR_SPACE          ((uint64_t)1<<34)
#define MAP_64MB		((uint64_t)1<<23)
#define MAP_VDSO                ((uint64_t)1<<32)

/* Macro for judging the type of pages */
#define FILE_DESC(flags, perm) (!(PG_PTRACE & flags) && !(MAP_ANON & flags) && \
	!(PG_SHM & flags) && ((MAP_SHARED & flags) || (!(perm & PROT_WRITE))))

#define MMAP_DESC_PRIVATE(flag, perm) (MMAP_DESC(flag, perm) &&\
			(perm & PROT_WRITE) && (flag & MAP_PRIVATE))
#define MMAP_DESC(flag, perm) (!__MMAP_DESC_VDSO(flag) &&\
				!__MMAP_DESC_SHM(flag) &&\
	(__MMAP_DESC_ANON(flag) || __MMAP_DESC_FILE_BACKED(flag, perm)))

#define __MMAP_DESC_VDSO(flag) (MAP_VDSO & flag)
#define __MMAP_DESC_SHM(flag)  (PG_SHM & flag)
#define __MMAP_DESC_ANON(flag) (MAP_ANON & flag)
#define __MMAP_DESC_FILE_BACKED(flag, perm) \
		((!(MAP_ANON & flag) && (PG_PTRACE & flag)) ||\
		(!(MAP_ANON & flag) && (MAP_PRIVATE & flag) && (PROT_WRITE & perm)))


/* Macro For Address alignment */
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ROUN_DN(x, y)	((x) & ~(((typeof(x))y) - 1))

#define HUGE_PAGE_IDX 32
#define VE_PAGE(vnode, pgnum) ((((struct ve_page *)-1 ==\
				vnode->ve_pages[pgnum]) ?\
			vnode->ve_pages[ROUN_DN(pgnum, HUGE_PAGE_IDX)] :\
			vnode->ve_pages[pgnum]))

#define BITS_PER_BLOCK		32
#define BLOCKS_PER_BITMAP	8
#define BITS_PER_WORD		64
#define WORDS_PER_BITMAP	4
#define ENTRIES_PER_DIR		256
#define DMA_BITMAP	((BITS_PER_WORD*ENTRIES_PER_DIR)/BLOCKS_PER_BITMAP)

#define GET_PAGE_NUMBER(page_base) ((page_base)>>21)

#define GET_PAGE ((uint8_t)1 << 0)
#define PUT_PAGE ((uint8_t)1 << 1)

#define memcpy_htoe(src, dst, spid, dpid, len) amm_dma_xfer(VE_DMA_VHVA, src, spid,\
		VE_DMA_VEMVA, dst, dpid, len, 0)
#define memcpy_etoh(src, dst, spid, dpid, len) amm_dma_xfer(VE_DMA_VEMVA, src, spid,\
		VE_DMA_VHVA, dst, dpid, len, 0)
#define memcpy_petoe(src, dst, len) amm_dma_xfer(VE_DMA_VEMAA, src, 0,\
		VE_DMA_VEMAA, dst, 0, len, 0)
/**
 * Macro for Physical address to array number of ve_numa_struct(mempool number)
 * paddr2mpnum : physical address to array number of ve_numa_struct(mempool
 *		number)
 **/
#define paddr2mpnum(paddr, blksz, fma) \
		(((uint64_t)paddr / blksz + fma) % VE_NODE(0)->numa_count)

#define VE_DMA_NUM_DESC (128)

#define PARENT(X)       ((X-1)/2)
#define LEFT(X)         (2*X+1)
#define RIGHT(X)        (2*X+2)

/* For judgement the contents of private_data*/
#define PRIVATE_FILE	2
#define PRIVATE_MMAP	3

/**
 * @brief Structure For File Backed handling.
 *
 *	This will contain the information about the file
 *	to be mapped as. Global List of this will be
 *	maintained in veos.
 */
struct file_desc {
	struct list_head global_list;	/*!< list head for global file
					 * descriptors*/
	struct list_head mapping_list;	/*!< list head for file specific map*/
	struct stat stat;		/*!< file specific information*/
	uint64_t pgsz;          	/*!< information of page size*/
	uint64_t in_mem_pages;		/*!< Number of pages in memory*/
	uint64_t sum_virt_pages;	/*!< Sum of mapped pages*/
	pthread_mutex_t f_desc_lock; 	/*!< mutex lock*/
	int numa_num;                   /*!< numa node number*/
	flag_t flags;                   /*!< mapping flag*/
};

/**
 * @brief structure for calculating the sum of mapped file backed memory
 * 		pages by a process. 
 */
struct file_backed_mem{
	struct list_head list_map_pages;/*!< list of
						the file_backed_mem struct */
	struct file_desc* file_descripter;	/*!< fd mapped by a process*/
	uint64_t virt_pages;		/*!< Sum of mapped pages*/
};

/**
 * @brief structure for calculating address offset and datasize.
 */

struct addr_struct {
	uint64_t top_address;
	uint64_t bottom_address;
	uint64_t aligned_top_address;
	uint64_t aligned_bottom_address;
	int top_offset;
	int bottom_offset;
	size_t new_datasize;
};

struct shm;
/*
 * Structure For File Backed handling.
 * This will contain the information about the mappings
 * over the file. List of mappings will be maintained under
 * each struct file_desc.
 */
/**
* @brief  Structure For File Backed handling.
*
*	This will contain the information about the mappings
*	over the file. List of mappings will be maintained under
*	each struct file_desc.
*/
struct mapping_desc {
	uint64_t header;		/*!< the header for judgement 
					 * the private_data's contents*/
	struct list_head mapping_list;	/*!< list head for file specific map*/
	off_t offset_start;		/*!< file offset start for mapping*/
	off_t offset_end;		/*!< file offset end for mapping*/
	pgno_t *pg_array;	/*!< page array*/
	struct file_desc *file_desc;	/*!< reverse reference to the file
					 *   corresponding to mapping*/
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
	off_t offset_start;		/*!< offset start for new mapping*/
	off_t offset_end;		/*!< offset end  for new mapping*/
};

/* Mmaped page structure */
struct mmap_desc{
	uint64_t header;		/*!< the header for judgement 
					 * the private_data's contents*/
	uint64_t pgsz; /*!< information of page size*/
	uint64_t in_mem_pages; /*!< Number of pages in memory*/
	uint64_t reference_count; /*!< For PPS, Number for judgement 
						to delete this structure.*/
	uint64_t sum_virt_pages; /*!<Sum of mapped pages*/
	pthread_mutex_t mmap_desc_lock; 
};

/* The list of mmaped page structure*/
struct mmap_mem{
	struct list_head list_mmap_pages; /*!< list of the mmapped pages */
	struct mmap_desc* mmap_descripter; /*!< pointer to
							mmaped page structure*/
	uint64_t virt_page; /*!< size of mapped pages*/
};

/**
* @brief contain ve page details
*/
struct ve_page {
	uint64_t page_start;	/*!< page start address */
	size_t pgsz;		/*!< page size (2MB or 64MB)*/
	uint64_t perm;		/*!< permission of page*/
	uint64_t flag;		/*!< flag specify type of mapping*/
	uint64_t ref_count;	/*!< Reference count for Number of VEMVA
				 * Mapped to this Physical page.*/
	uint64_t dma_ref_count;	/*!< Reference count for Number of VEMVA
				 * Mapped for DMA xfer to this Physical page.*/
	void *private_data;	/*!< private data for ve page*/
	struct ve_task_struct *owner;/*!< It will be Used in PG_PTRACE case*/
	int buddy_order;	/*!< order of buddy in which page belongs*/
	pthread_mutex_t ve_page_lock; /*!< mutex lock*/
	uint64_t pci_count;     /*!< Registration counter for PCIATB */
	struct ve_swapped_physical *swapped_info;
				/*!< Information about Swapped-out VE page */
};

/* for NUMA */
/**
 * @brief contain numa sysfs informations
 */
struct numa_sysfs_info {
	size_t numa_mem_blk_sz;	/*!< memory block size of divided physical memory*/
	int first_mem_node;	/*!< NUMA node of first physical memory unit*/
};

extern struct numa_sysfs_info numa_sys_info;
/* ATB update API*/
int amm_update_atb_dir(vedl_handle *, int,
			struct ve_task_struct *, int);

/*File Backed Handling Related APIs*/
ret_t amm_do_file_back_handling(vemva_t, struct file_desc *,
		off_t, off_t, int, struct ve_task_struct *,
		pgno_t *, uint64_t);
struct file_desc *init_file_desc(struct file_stat *);
struct file_desc *scan_global_list(struct file_stat *file, flag_t, int);
struct mapping_desc *init_mapping_desc(struct mapping_attri *);
void init_page_array(struct mapping_desc *, struct mapping_attri *);
ret_t update_mapping_desc(vemva_t, pgno_t *,
		uint64_t, int, struct ve_task_struct *,
		struct file_desc *, off_t, pgno_t *);
struct list_head *free_redundant_list(struct list_head *,
		struct list_head *);
void dump_mapping_desc(struct mapping_desc *);
int stat_cmp(struct file_desc *, struct file_stat *, flag_t, int);
struct mapping_attri *collect_map_attri(struct file_desc *, int64_t,
		int64_t);
void add_mapping_desc(struct file_desc *,
		struct mapping_desc *, struct mapping_attri *);
void set_bit(uint64_t *, uint64_t);
void set_bits(uint64_t *, uint64_t, uint16_t);
int check_bits_set(uint64_t *, uint64_t, uint64_t);
int send_file_data(vemva_t, off_t, size_t,
		struct ve_task_struct *, size_t, size_t, pgno_t *);
int64_t extract_file_pgoff(vemva_t, struct ve_task_struct *,
			size_t *, struct mapping_desc **);
size_t is_addr_file_backed(uint64_t, struct ve_task_struct *);
void clear_page_array_entry(struct mapping_desc *, pgno_t);
void free_file_desc(struct file_desc *file);

/* VE memory controlling APIs */
int amm_do_mmap(vemva_t, size_t, prot_t, flag_t,
		struct ve_task_struct *,
		struct file_stat *);
int amm_do_munmap(vemva_t, size_t, struct ve_task_struct *, bool);
int amm_do_mprotect(vemva_t, ssize_t, uint64_t,
				struct ve_task_struct *);
int amm_do_processs_vm_rw(struct ve_task_struct *task,
		struct ve_process_rw_info ve_process_rw_info);
int check_write_permisssion(vemva_t va_addr, pid_t pid);
int amm_rw_check_permission(struct ve_task_struct *tsk,
		struct ve_rw_check_iovec rw_agrs);
int ve_node_page_free_count(int);
uint64_t ve_node_page_used_count(int);
int alloc_ve_pages_for_swapin(uint64_t, pgno_t *, int, int, int, int *);
int alloc_ve_pages(uint64_t, pgno_t *, int, int, int, int *);
int calc_usable_dirty_page(struct ve_node_struct *vnode,
			   size_t mem_sz, int pgmod,
			   int mempolicy, int numa_node);
void amm_wake_alloc_page(void);
void invalidate_atb(atb_reg_t *atb);
void invalidate_dmaatb(dmaatb_reg_t *atb);
int amm_copy_atb_private(struct ve_mm_struct *, struct ve_mm_struct *, int);
void amm_copy_atb_vfork(atb_reg_t *, atb_reg_t *, struct veshm_struct *);
int amm_copy_phy_page(uint64_t, uint64_t, uint64_t);
ret_t amm_clear_page(uint64_t, size_t);
int amm_dma_xfer(int, uint64_t, int, int, uint64_t, int, uint64_t, int);
int vemva_to_vemaa(pid_t, uint64_t, uint64_t *);
int amm_initialize_zeroed_page(vemaa_t);
bool ve_elf_core_dump(struct dump_params *);
int amm_do_vemva_init_atb(vemva_t, int, struct ve_task_struct *);
int veos_get_page(vemaa_t);
int veos_put_page(vemaa_t);
int amm_get_page(vemaa_t *);
int amm_put_page(vemaa_t);
int amm_do_get_page(vemaa_t, bool);
int amm_do_put_page(vemaa_t, bool);
int veos_free_page(vemaa_t);
int64_t veos_virt_to_phy(vemva_t, pid_t, bool, int *);
void veos_amm_fini(void);
void sync_at_exit(struct ve_task_struct *);
int sync_vhva(vemaa_t, vhva_t, struct ve_task_struct *);
void update_proc_shm_struct(vemva_t, pgno_t, struct ve_mm_struct *);
int amm_send_data(pid_t, vemva_t, size_t, void *);
int amm_recv_data(pid_t, vemva_t, size_t, void *);
void calc_addr(struct addr_struct *);
void amm_copy_mm_data(struct ve_mm_struct *, struct ve_mm_struct *);
ret_t copy_shm_list(struct ve_mm_struct *, struct ve_mm_struct *);
ret_t copy_list_map_page(struct ve_mm_struct *, struct ve_mm_struct *, int);
void amm_atb_cleanup(atb_reg_t *, int, int);
int dirty_page_init(struct ve_node_struct *vnode, pthread_t *th);
int add_dirty_page(pgno_t pgno, size_t pgsz, int pgmod);
void veos_amm_clear_mem_thread(void);
int clear_and_dealloc_page(pgno_t pgno, size_t pgsz, int pgmod);
struct mmap_desc *init_mmap_desc(void);
struct mmap_mem *init_mmap_mem(void);
int amm_do_mmap_handling(struct ve_mm_struct *, size_t, flag_t, prot_t,
			uint64_t, pgno_t *);
int decrement_virt_page(struct ve_page *,struct ve_mm_struct *);

/*VEMVA share*/
int veos_share_vemva_region(pid_t, vemva_t, pid_t,
				vemva_t, size_t, int, bool);
int veos_unshare_vemva_region(pid_t, vemva_t, size_t);

void invalidate_veshm_pte(atb_reg_t *, struct veshm_struct *);

dir_t validate_vehva(vemva_t, int, pgno_t, void *, int,
		uint8_t, jid_t, uint16_t, int);

dir_t invalidate_vehva(vemva_t, void *, jid_t);
dir_t validate_vemva(vemva_t, int, pgno_t, void *, int);
dir_t invalidate_vemva(vemva_t, void *);

void __validate_pgd(void *, dir_t, int, int, int);
void validate_pgd(atb_reg_t *, dir_t, int, int);
void validate_dmapgd(dmaatb_reg_t *,  dir_t, int, int, int);

void invalidate_pgd(atb_reg_t *, dir_t);

dir_t get_pgd(vemva_t, struct ve_task_struct *);
dir_t __get_pgd(vemva_t, void *, int, bool);
dir_t get_dmapgd(vehva_t, struct ve_task_struct *);

int veos_get_pgmode(uint8_t, pid_t, uint64_t);
int __veos_get_pgmode(uint8_t, struct ve_task_struct *, uint64_t);
uint64_t *amm_get_pgmod_info(vemva_t, struct ve_task_struct *,
		size_t, bool *);

/*
 * API moved from loader to AMM
 */
void amm_dump_atb(struct ve_task_struct *);
int amm_do_set_tproc(struct ve_jid_cmd cmd, struct ve_task_struct *tsk);
int veos_handle_ptrace_poke_req(struct ve_task_struct *, vemva_t);
int copy_entry(atb_entry_t *, atb_entry_t *, int, int, int, struct ve_mm_struct *);
pgno_t __replace_page(atb_entry_t *, struct ve_mm_struct *, int);
int64_t replace_page(vemva_t, struct ve_task_struct *);

ret_t amm_mem_clear(size_t);
ret_t dma_clear_page(uint64_t);
int amm_update_atb_dir(vedl_handle *, int, struct ve_task_struct *, int);

/*
 * For Partial Process Swapping
 */
int amm_update_rss_swapin(struct ve_page *);
int amm_free_private_data(void *, uint64_t , uint64_t );
#endif
