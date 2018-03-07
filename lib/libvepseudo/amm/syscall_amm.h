/**
 * @file syscall_amm.h
 * @brief Header file for "syscall_amm.c".
 *
 *	Include MACRO and data structure for AURORA
 *	specific memory management.
 */
#ifndef __SYSCALL_AMM_H
#define __SYSCALL_AMM_H

#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libved.h"
#include "veos_list.h"
#include "veos_pseudo_interface.h"
#include <sys/syscall.h>

/* Size values */
#define SIZE_1MB		(1 * 1024 * 1024)
#define SIZE_1KB		(1 * 1024)

/* Protection flag */
#define VE_PROT_READ	(0x1)
#define VE_PROT_WRITE	(0x2)
#define VE_PROT_NONE	(0x0)

/* Mapping control flags */
#define VE_MAP_ANONYMOUS	(0x20)
#define VE_MAP_FIXED	(0x10)
#define VE_MMAP_GROWSDOWN	(0x0100)
#define VE_MMAP_GROWS_UP	(0x0200)
#define VE_MMAP_HUGEPAGE	(0x0400)
#define VE_MAP_STACK	VE_MMAP_GROWSDOWN

/* AMM specific macros and function prototype */
#define PAGE_SIZE_4KB		(2 * 2 * 1024)
#define PAGE_SIZE_2MB		(2 * 1024 * 1024)
#define PAGE_SIZE_64MB		(64 * 1024 * 1024)
#define MASK_2MB_ALIGN		(PAGE_SIZE_2MB - 1)
#define MASK_64MB_ALIGN		(PAGE_SIZE_64MB - 1)
#define MAP_GROWSUP		0x20

#define STACK_BOTTOM		0x1FFFFFF0LL    /*!< 512MB-0xF */

#define SET_ATB			1
#define UNSET_ATB		0
#define MAX_BUFFER_SIZE		256

/* Macro For Address alignment */
#define IS_ALIGNED(x, a)	(((x) & ((typeof(x))(a) - 1)) == 0)
#define ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

/* Macro For VEMVA Support */
#define MAX_VEMVA_PER_LIST	256
#define MAX_VEMVA_LIST		32
#define BITS_PER_WORD		64
#define WORDS_PER_BITMAP	4

#define CHUNK_512GB	0x8000000000
#define CHUNK_512MB	0x20000000
#define CHUNK_16GB	0x400000000
#define CHUNK_512MB_MASK      (CHUNK_512MB - 1)
#define CHUNK_16GB_MASK      (CHUNK_16GB - 1)

#define ANON_SPACE_2MB 0
#define ADDR_SPACE_2MB 1
#define ANON_SPACE_64MB 2
#define ADDR_SPACE_64MB 3

/* command buffer */
#define CMD_BUFFER_SIZE (4*1024)

/**
* @brief This flag is used to specify, if bits have to be marked in VEMVA handling or not.
*/
#define MARK_BITS ((uint64_t)1<<33)
#define SYNC_ONLY ((uint64_t)1<<32)

/**
* @brief structure to manage vemva address space.
*/
struct vemva_header {
	pthread_mutex_t vemva_lock; /*!< pthread_mutex lock  for VEMVA*/
	pthread_mutex_t vhos_mmap_lock;/*!< pthread_mutex lock for VH mmap*/
	uint64_t ve_text;	/*!< ve text section address */
	uint64_t ve_heap;	/*!< ve heap section address */
	uint64_t ve_stack;	/*!< ve stack section address */
	uint64_t ve_anon_start; /*!< start of vemva address*/
	uint64_t base_large;	/*!< 2MB address space base */
	uint64_t top_large;	/*!< 2MB address space top */
	uint64_t base_huge;	/*!< 64MB address space base */
	uint64_t top_huge;	/*!< 64MB address space top */
	struct list_head vemva_list; /*!< list head for vemva list*/
} vemva_header;

/**
 * @brief Data Structure for VEMVA List
 */
struct pseudo_vemva {
	struct list_head list;	/*!< structure to contain list entry */
	void *vemva_base;	/*!< pointer to vemva base address */
	uint64_t bitmap[WORDS_PER_BITMAP];	/*!< contain how many pages are
						 *  used if 0th bit is 1 then
						 *  1st is used or wise versa
						 */
	uint64_t sync_bitmap[WORDS_PER_BITMAP];/*!< bitmap which is  syncable*/
	unsigned char type;			/*!< dir type (2MB or 64MB)*/
};
/**
 * @brief Structure to store ve page info
 */
struct _ve_page_info {
	uint64_t page_size;	/*!< page size */
	uint64_t chunk_size;	/*!< chunk size */
	uint64_t page_mask;     /*!< page size mask*/
	uint64_t chunk_mask;	/*!< chunk size mask*/
};

struct pseudo_proc_request;

/* mmap syscall function prototypes */
void ve_mmap(int syscall_num, char *syscall_name, vedl_handle *handle);
void ve_munmap(int syscall_num, char *syscall_name,
		vedl_handle *handle);
void ve_mprotect(int syscall_num, char *syscall_name, vedl_handle *handle);
void ve_brk(int syscall_num, char *syscall_name, vedl_handle *handle);
void ve_grow(int syscall_num, char *syscall_name, vedl_handle *handle);
void ve_msync(int syscall_num, char *syscall_name, vedl_handle *handle);
void *__ve_mmap(vedl_handle *handle, uint64_t addr, uint64_t size,
		int prot, int flag, int filedes,
		uint64_t offset, int atb_flag);
int64_t ve_file_mmap(vedl_handle *handle, int filedes,
		uint64_t size, off_t offset, void *ret_addr);
int64_t __ve_munmap(vedl_handle *handle, uint64_t addr,
		uint64_t size, int flag, int atb_flag);
int64_t amm_request_mprotect(vedl_handle *handle, uint64_t ret_addr,
		uint64_t size, int prot, int atb_flag);
int64_t ve_heap_reduce(vedl_handle *handle, uint64_t old_top_address,
		uint64_t size);
void *ve_heap_extend(vedl_handle *handle, uint64_t old_top_address,
		uint64_t size);
int64_t command_parse(struct pseudo_proc_request *cmd, char *buff);
int64_t amm_request_mmap(vedl_handle *, uint64_t, uint64_t, int, int,
					int, struct file_map_stat *);
int ve_mem_unlock(void *data);
int ve_mem_lock(void *data);
int get_page_size(uint64_t vaddr);

/* VEMVA supported functions prototypes */
void *pseudo_vemva_allocation(vedl_handle *, uint64_t, uint64_t,
					int, int, int, uint64_t);
void *vemva_not_map_fixed(struct pseudo_vemva *,
				uint64_t, int64_t, int64_t, uint64_t);
void *vemva_map_fixed(vedl_handle *, struct pseudo_vemva *,
				uint64_t, int64_t, int64_t, uint64_t);
void *avail_vemva(vedl_handle *, uint64_t, uint64_t, uint64_t);
struct pseudo_vemva *init_pseudo_vemva(uint64_t, uint64_t);
int fini_pseudo_vemva(struct pseudo_vemva *);
void *get_512GB_aligned_vemva();
void *get_aligned_vemva(uint64_t);
void *pseudo_get_free_vemva(struct pseudo_vemva *, int64_t, uint64_t);
void mark_bits_used(unsigned long *, int64_t, int64_t);
int release_vemva(vedl_handle *, void *, size_t, int);
int check_bits_used(unsigned long *, int64_t, int64_t);
int check_bits_unused(unsigned long *, int64_t, int64_t);
int free_vemva(vedl_handle *, struct pseudo_vemva *, int64_t,
		int64_t, uint64_t);
void mark_bits_unused(unsigned long *, int64_t, int64_t);
void *scan_pseudo_vemva(uint64_t, uint64_t);
struct pseudo_vemva *create_pseudo_vemva(uint64_t, uint64_t);
int init_vemva_addr_space(void);
int64_t __ve_msync(vedl_handle *, void *, uint64_t, int);
int init_vemva_header(void);

int vemva_mark_used(uint64_t, uint64_t);
int vemva_mark_unused(uint64_t, uint64_t);
int vemva_mark_syncable(uint64_t, uint64_t);
int vemva_mark_unsyncable(uint64_t, uint64_t);

void sync_at_exit(vedl_handle *);
void sync_data(vedl_handle *, void *,
		uint64_t bitmap[WORDS_PER_BITMAP]);
void sync_syncable_data(vedl_handle *, void *, uint64_t);

/*mremap related interfaces*/
void ve_mremap(int syscall_num, char *syscall_name,
		vedl_handle *handle);
int64_t __ve_mremap(vedl_handle *, void *, uint64_t, uint64_t,
		uint64_t, void *);
void *update_vemva(vedl_handle *, void *, uint64_t, uint64_t,
		uint64_t, void *);
int vemva_mapped(void *, size_t);
int vemva_syncable(void *, size_t);
int vemva_is_expandable(void *, uint64_t, uint64_t);
int64_t amm_request_mremap(vedl_handle *, uint64_t,
		uint64_t, uint64_t, uint64_t);
#endif
