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
* @file header file for loader.c
* @brief declearation of all structrure and function related to loader.
*
* @internal
* @author PSEUDO
*/

#include <elf.h>
#include "ve_memory.h"
#include "handle.h"
#include "comm_request.h"

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;

typedef unsigned long long offset_t;
#define CHUNK_512_GB		0x8000000000
#define CHUNK_1TB              0x10000000000
#define VE_ADDRESS_SPACE_SIZE  CHUNK_1TB

#define DEFAULT_STACK_LIMIT	0x0L	/*!< Indicates unlimited Stack */
#define AT_QUICKCALL_VADDR	AT_SYSINFO_EHDR
#define RANDOM_BYTE		16
#define AUX_BYTE		2
#define ALIGNED_8BYTE		7

/**
* @brief data structer for Auxilary vector information.
*/
struct auxv_info {
	Elf64_Addr    e_entry;		/*!< Entry point virtual
					 * address = AT_ENTRY */
	Elf64_Half    e_phnum;		/*!< Program header table
					 * entry count = AT_PHNUM */
	Elf64_Half    e_phentsize;	/*!< Program header table
					 * entry size = AT_PHENT */
	Elf64_Addr    p_vaddr;		/*!< Segment virtual address
					 * = AT_PHDR */
	Elf64_Addr    e_phdr;		/*!< Elf program header pointer*/
	Elf64_Addr    e_base;		/*!< ELf base*/
	Elf64_Xword	p_align;	/*!< Segment alignment*/
};

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

/**
* @brief Contain information for executable and library to load.
*/
struct ve_elf_load_stat  {
	Elf_Ehdr *elf_ex;	/*!< ELF header for ELF executable itself*/
	Elf_Ehdr *elf_interp;	/*!< ELF header for interpreter */
	char *file_exec;	/*!< Executable file name */
	char *file_interp;	/*!< interp file name */
	char *file_interp_end;	/*!< interp file name end addr */
	int interp_set;		/*!< Change to bool when not available */
	int fd;                 /*!< file descriptor for VE_EXE */
	int fd_dyn;             /*!< file descriptor for INTERP */
	char *start_section;	/*!< start of section header */
	char *start_string;	/*!< start of string of section header */
	char *start_section_dyn;/*!< start of section header */
	char *start_string_dyn;	/*!< start of string of section header */
	offset_t start_bss;	/*!< start of BSS section */
	offset_t start_bss_dyn;	/*!< start of BSS section in INTERP */
	uint64_t size_bss;	/*!< size of BSS section */
	uint64_t size_bss_dyn;	/*!< size of BSS section in INTERP */
};

/**
* @brief Conatins information of segments to load from vh to ve.
*/
struct ve_vh_segmap {
	int perm;	/*!< PROT_WRITE, PROT_READ, PROT_EX*/
	int is_fixed;	/*!< When mapping required is fixed*/
	unsigned long vh_addr; /*!< host vitual address*/
	unsigned long ve_addr; /*!< ve virtual address*/
	size_t length;	/*!< length of the segment */
	int is_interp;  /*!< 1 if it is interp block else 0*/
	size_t ve_map_size;/*!< size of segment to map*/
	size_t ve_file_size;/*!< filesize of segment to map*/
	off_t off;	/*!< offset */
	off_t offset;   /*!< offset for ve_mmap*/
	int is_data;    /* segment is data or not */
	char *data_loadarea; /* store data segment image */
	uint64_t flag;       /* FLAGS for ve_mmap */
};

/**
* @brief Contains data to load on VE memory.
*/
struct ve_load_data {
	struct ve_elf_load_stat stat;	/*!< Information for executable and
					 * library to load*/
	struct ve_vh_segmap *seg;	/*!< Information of segments to load*/
	unsigned long loadable_segnum;	/*!< Sum of elf & interp segments */
	char *ve_interp_map;		/*!< VE Address at which interp has
					 * been mapped*/
	uint64_t pagesize;
};
extern struct ve_load_data load_elf;

void ve_set_stack_limit(void);
int ve_address_space_reserve(uint64_t);
int pse_load_binary(char *, veos_handle *, struct ve_start_ve_req_cmd *);
int pse_load_interp(char *, veos_handle *);
Elf_Shdr *get_shdr(Elf_Ehdr *, int);
Elf_Shdr *search_shdr(Elf_Ehdr *, char *);
int clear_bss(char *, Elf_Ehdr *, Elf_Phdr *, char *);
int init_stack(veos_handle *, int, char **,
		      char **, struct ve_start_ve_req_cmd *);
void *vh_map_elf(char *);
char *vh_map_elf_dyn(char *);
int chk_elf_consistency(Elf_Ehdr *);
void fill_ve_elf_data(char *);
void fill_ve_vh_segmap(veos_handle *);
void *load_elf_phdr_on_vemem(veos_handle *, Elf_Ehdr *);
char * open_bin_file (char *, int *);
