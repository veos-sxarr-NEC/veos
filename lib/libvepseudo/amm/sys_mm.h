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
 * @file sys_mm.h
 * @brief Header file for "sys_mm.c".
 *
 *	Include MACRO and data structure for AURORA
 *	specific memory management.
 *
 * @internal
 * @author AMM
 */
#ifndef __SYS_MM_H
#define __SYS_MM_H

#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libved.h>
#include "list.h"
#include "vemva_mgmt.h"
#include "comm_request.h"
#include "mm_type.h"
#include <sys/syscall.h>
#include <sys/uio.h>

/*
 * A definition of the size of stack area for signal handling
 * 3 signal handlers can be cascaded
 */
#define STACK_AREA_FOR_SIGNAL ((524952 + 512) * 3)

#define MIN_2(type, x, y) ({\
		type __min1 = (x);\
		type __min2 = (y);\
		__min1 < __min2 ? __min1 : __min2; })

/* command buffer */
#define CMD_BUFFER_SIZE (4*1024)
#if 0
#define pgsz_to_pgstr(p) ((p == PAGE_SIZE_2MB) ? "LARGE" :\
	       ((p == PAGE_SIZE_64MB) ? "HUGE" : "SMALL"))\

#define pgmod_to_pgstr(p) ((p == PG_4K) ? "SMALL" :\
	((p == PG_2M) ? "LARGE" : "HUGE"))
#endif
struct pseudo_proc_request;

/**
* @brief This structure contains the VE process stack and heap limit
* related information.
*/
struct ve_address_space_info {
	uint64_t heap_start;		/*!< Start address of heap */
	uint64_t heap_top;		/*!< Heap top of VE Process */
	uint64_t stack_limit;		/*!< Max stack limit for a VE Process.
					 * value = 0 in case of UNLIMITED,
					 * value = 'X' in case of User-Defined
					 * or default(Currently 10MB).
					 */
	uint64_t stack_bottom;		/*!< Stack bottom of a VE Process */
	uint64_t stack_pointer_aligned;	/*!< Page size aligned actual stack
					 * pointer of a VE process. */
};
extern struct ve_address_space_info ve_info;


typedef enum ve_grow_err_t
{
       VE_GROW_INVALID_REQUEST,
       VE_GROW_IN_ALT_STACK,
       VE_GROW_STACK_LIMIT,
       VE_GROW_IN_GUARD_AREA,
       VE_GROW_MEM_ALLOC,	
       VE_GROW_NO_ERR
}ve_grow_err;

typedef uint64_t ve_mem_offset_t;

/**
* @brief structure to manage temporary file.
*/
struct mod_file_info {
	int fd;			/*!< file descriptor of temporary file */
	char *file_path;	/*!< file path of temporary file */
	void *vemva;		/*!< VEMVA to map temporary file */
	uint64_t size;		/*!< size to map temporary file */
	ino_t org_ino;		/*!< inode number of original binary file */
	off_t org_sz;		/*!< size of original binary file */
	time_t org_mtime;	/*!< modified time of original binary file */
	dev_t org_dev;		/*!< device number of original binary file */
	struct file_stat f_stat;	/*!< file information of temporary file */
};

/**
* @brief structure to manage and control temporary files.
*/
struct tmp_file_info {
	int lock_fd;		/* file descriptor of exclusive control file */
	char *lock_file_path;	/* file path of exclusive control file */
	struct mod_file_info mod;	/* information of modified code */
	struct mod_file_info org;	/* information of original code */
	struct mod_file_info tbl;	/* information of address conversion table */
};

/**
* @brief structure of address conversion table
*/
struct ve_xtbl_adr {
	uint64_t org;	/*!< The start address of .text section in original code */
	uint64_t *xtbl;	/*!< The address of address conversion table */
	uint64_t xtbl_size;	/*!< The size of address conversion table */
};

/**
* @brief structure of address conversion table header
*/
struct ve_xtbl_adr_hdr {
	size_t num;	/*!< The number of address conversion table */
	struct ve_xtbl_adr ve_xtbl_addrtbl[((PAGE_SIZE_2MB - sizeof(size_t)) / sizeof(struct ve_xtbl_adr))];
			/*!< The list of address conversiontable */
};

/**
* @brief structure to manage address conversion table header
*/
struct ve_xtbl_adr_hdr_info {
	struct ve_xtbl_adr_hdr *xtbl_hdr;	/*!< The pointer to address conversion table header */
	pthread_mutex_t xtbl_adr_hdr_lock;
			/*!< pthread mutex lock for address conversion table header */
};

/* Information for relative address recalculation */
struct d_info{
	unsigned long mod_code_addr;
	unsigned long org_code_addr;
	unsigned long diff_org_code_addr;
	int sabun;
	int out_bound;
};

/**
* @brief structure of address and temporary files
*/
struct ve_tmpfile {
	vemva_t addr;
	size_t  sz;
	char fname[PATH_MAX + NAME_MAX];
};

/**
* @brief structure of temporary file set
*/
struct ve_tmpfile_set {
	char lock_fname[PATH_MAX + NAME_MAX];
	struct ve_tmpfile mod;
	struct ve_tmpfile org;
	struct ve_tmpfile tbl;
	struct list_head list;
};

/**
* @brief structure to manage address and temporary files
*/
struct ve_tmpfile_info {
	pthread_mutex_t modcode_tmpfile_lock;
	struct ve_tmpfile_set tmpfiles;
};

/* mmap syscall function prototypes */
ret_t ve_mmap(int syscall_num, char *syscall_name, veos_handle *handle);
ret_t ve_munmap(int syscall_num, char *syscall_name,
		veos_handle *handle);
ret_t ve_mprotect(int syscall_num, char *syscall_name, veos_handle *handle);
ret_t ve_brk(int syscall_num, char *syscall_name, veos_handle *handle);
ret_t ve_grow(int syscall_num, char *syscall_name, veos_handle *handle);
ret_t ve_msync(int syscall_num, char *syscall_name, veos_handle *handle);
int64_t __ve_msync(veos_handle *, vemva_t, size_t, int);
ret_t ve_process_vm_readv(int syscall_num, char *syscall_name,
		veos_handle *handle);
ret_t ve_process_vm_writev(int syscall_num, char *syscall_name,
		veos_handle *handle);
void *__ve_mmap(veos_handle *handle, vemva_t vemva, size_t size,
		int prot, uint64_t flag, int filedes,
		off_t offset);
int64_t __ve_munmap(veos_handle *, vemva_t, size_t, bool);
int64_t amm_request_mprotect(veos_handle *handle, vemva_t ret_addr,
		uint64_t size, int prot);
int64_t ve_heap_reduce(veos_handle *handle, vemva_t old_top_address,
		uint64_t size);
void *ve_heap_extend(veos_handle *handle, vemva_t old_top_address,
		uint64_t size);
int64_t __ve_process_vm_rw(veos_handle *handle, struct iovec *local_iovec,
		uint64_t liovcnt, struct iovec *remote_iovec, uint64_t riovcnt,
		pid_t pid, int type);
int64_t ve_process_vm_rw_single_iov(veos_handle *handle, struct iovec *r_iovec,
		struct iovec *local_iovec, size_t liovcnt,
		size_t *curr_lcnt, size_t *curr_l_offset, pid_t r_pid,
		int type);
int64_t amm_send_proc_vm_rw_req(veos_handle *handle,
		struct ve_process_rw_info *cmd_buf);
int64_t ve_check_iovec(struct iovec *iovec, uint64_t iovcnt);
int64_t amm_request_mmap(veos_handle *, vemva_t, size_t, int, uint64_t,
					struct file_stat *);

int new_vemva_chunk_atb_init(veos_handle *, vemva_t, size_t);
int ve_sync_vhva(veos_handle *);
void copy_vemva_dir_info(struct veshm_struct *);
void update_ve_page_info(uint64_t *);
int reserve_signal_trampoline(veos_handle *handle);
int update_xtbl_adr_info(veos_handle *);
int search_ve_xtbl_addrtbl(struct ve_xtbl_adr_hdr* , uint64_t, size_t*);
int search_mod_addr(struct ve_xtbl_adr*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
void get_original_addr_from_xtbl_adr(uint64_t, uint64_t*);
void ve_modcode_init(void);
#endif
