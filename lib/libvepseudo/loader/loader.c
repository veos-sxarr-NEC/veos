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
 * @file  loader.c
 * @brief Handles loading of ELF from VH to VE memory.
 *
 *	This contains the handler functions realated to loading  that
 *	are invoked based on the request from the pseudo process.
 *
 * @internal
 * @author Pseudo/ELF Loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "libved.h"
#include "syscall.h"
#include "loader.h"
#include <elf.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/statvfs.h>
#include "ve_memory.h"
#include "sys_mm.h"
#include "ve_socket.h"
#include "handle.h"
#include "mm_transfer.h"
#include "velayout.h"
#include "sys_mm.h"

static struct auxv_info auxv;

#define VEOS_VER0

/**
* @brief mcheck for checking memory leaks
*/
#include <mcheck.h>

/* ELF */
#define ELF_CLASS       ELFCLASS64
#define ELF_VE	251
/**
* @brief from sys/elf_common.
*/
#define IS_ELF(ehdr)    ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
		(ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
		(ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
		(ehdr).e_ident[EI_MAG3] == ELFMAG3)
#define TRANS_MAX       (MMAP_SIZE - 0x20)   /*!< address, datasize
					      * and buffer */
#define TRANS_SZ_SHFT   3	/*!< make a size of multiples of 8. */
#define EXECVE_MAX_ARGS 513
#define EXECVE_MAX_ENVP 513
reg_t inst_intr; /*!< In pse_load_interp = ehdr->e_entry */
reg_t inst_main; /*!< In pse_load_binary  ehdr->e_entry */
unsigned long long dyn_seg_addr_main; /*!< PT_DYN(main) phdr->p_vaddr */
unsigned long long dyn_seg_addr_interp; /*!< PT_DYN: phdr->p_vaddr */

/**
 * @brief This function will reserve the VE process address
 * space in pseudo process.
 *
 * @param[in] ve_text_page ve address to start reserving the space
 *
 * @return On Success it returns 0 or -1 on failure.
 */
int ve_address_space_reserve(uint64_t ve_text_page)
{
	void *ret_addr;
	int ret = 0;

	/* VH mmap is called to reserve VE address space
	 * VE_TEXT + VE_DATA + VE_HEAP + VE_STACK
	 */
	PSEUDO_DEBUG("Reserving Space for VE_TEXT + VE_DATA "
			"+ VE_HEAP + VE_STACK");
	ret_addr = mmap((void *)ve_text_page, VE_ADDRESS_SPACE_SIZE,
			PROT_NONE, MAP_PRIVATE|MAP_ANON|MAP_FIXED,
			-1, 0);
	if ((void *)-1 == ret_addr) {
		ret = -errno;
		PSEUDO_ERROR("Failed to reserve VE address"
				" space %s", strerror(-ret));
		fprintf(stderr, "Failed to reserve VE address"
			" space %s\n", strerror(-ret));
		goto err;
	}
	PSEUDO_DEBUG("VE Address space reserved successfuly, "
			"Map address: %p", ret_addr);
err:
	return ret;
}

/**
 * @brief This function gets the stack limit.
 *
 *	This function gets the stack limit from enviorment
 *	variable VE_STACK_LIMIT.If the value is NULL then
 *	set the default limit i.e 10MB.
 *
 */
void ve_set_stack_limit(void)
{
	uint64_t tmp_stack_limit = DEFAULT_STACK_LIMIT;
	char *endptr =  NULL;
	char *env_stack_limit = getenv("VE_STACK_LIMIT");

	if (NULL == env_stack_limit) {
		PSEUDO_INFO("Setting default stack limit as unlimited");
		/*Setting Default limit as unlimited */
		ve_info.stack_limit = tmp_stack_limit;
	} else {
		tmp_stack_limit = strtol(env_stack_limit, &endptr, 10);
		if (0 == strcmp(env_stack_limit, "unlimited") ||
				0 == strcmp(env_stack_limit, "UNLIMITED")) {
			/* Handling for stack limit from ulimit command
			 * Currenlty when stack limit is set to unlimited
			 * then stack can grow till heap top.
			 */
			PSEUDO_INFO("STACK LIMIT IS SET TO UNLIMITED");
			/* Stack is unlimited, so stack limit will be set
			 * as zero and can grow till heap top.
			 */
			tmp_stack_limit = DEFAULT_STACK_LIMIT;
		} else if (0 >= tmp_stack_limit || '\0' != *endptr) {
			/* Default stack unlimited */
			PSEUDO_INFO("Setting default stack limit as unlimited");
			tmp_stack_limit = DEFAULT_STACK_LIMIT;
		} else {
			PSEUDO_DEBUG("From env(VE_STACK_LIMIT): %ld KB",
					tmp_stack_limit);
			/* convert kb to bytes and calculate stack limit
			 * from stack bottom.
			 */
			/* If user ask's for X MB stack then actually it gets
			 * (X-(16/1024*1024))MB. Because stack bottom is at
			 * 4GB-0x10.
			 */
			tmp_stack_limit = (ve_info.stack_bottom + 0x10) -
				(tmp_stack_limit * (1024));
			if (0 >= tmp_stack_limit) {
				PSEUDO_WARN("Stack limit is going beyond"
						"the VE Process Address Space.");
				/* As stack limit is beyond the
				 * VE process address space.
				 * Now set stack limit to zero, means stack
				 * is unlimited.
				 */
				tmp_stack_limit = DEFAULT_STACK_LIMIT;
				PSEUDO_INFO("Stack limit set to UNLIMITED.");
			}
			if (!IS_ALIGNED(tmp_stack_limit, load_elf.pagesize)) {
				tmp_stack_limit &= ~(load_elf.pagesize - 1);
				PSEUDO_DEBUG("Stack limit aligned to VE page"
						"size: %lx", tmp_stack_limit);
			}
		}
		ve_info.stack_limit = tmp_stack_limit;
	}
	PSEUDO_DEBUG("VE STACK LIMIT SET: 0x%lx", ve_info.stack_limit);
}

/**
 * @brief Load a ELF file and make VE memory images and ATBs.
 *
 * @param[in] filename  ELF file name
 * @param[in] handle    VEDL handler
 * @param[in] reg_t   regisrer
 *
 * @return On success,0 will be returned. negative value on failure.
 */
int pse_load_binary(char *filename, veos_handle *handle,
		struct ve_start_ve_req_cmd *start_ve_req)
{
	reg_t *instr_cntr = &(start_ve_req->context_info.IC);
	int segnum = 0;             /* number of segments */
	char *head = NULL;      /* elf */
	char *head_interp = NULL;
	Elf_Ehdr *ehdr  = NULL;
	uint64_t ve_text_page = 0;
	uint64_t addr[2];
	uint64_t end_addr[2];
	int executeonce = 1;
	int ret = 0;

	PSEUDO_TRACE("In Func");
	PSEUDO_DEBUG("LOADING STARTS");
	errno = 0;
	load_elf.stat.file_exec = filename;
	load_elf.stat.fd = -1;
	load_elf.stat.fd_dyn = -1;
	PSEUDO_DEBUG("VE ELF(type: ET_EXEC) name: %s", load_elf.stat.file_exec);

	/* get elf header */
	head = (char *)vh_map_elf(load_elf.stat.file_exec);
	if (!head) {
		ret = -errno;
		goto err_ret;
	}
	/* check file type (magic, class, data and type) */
	ehdr = (Elf_Ehdr *)head;
	load_elf.stat.elf_ex = (Elf_Ehdr *)head;
	ret = chk_elf_consistency(load_elf.stat.elf_ex);
	if ( 0 > ret) goto err_ret;

	/* Parse segments and fill information */
	load_elf.pagesize = -1;
	fill_ve_elf_data(head);
	if (load_elf.stat.file_interp != NULL) {
		/* get elf header for dynamic linker*/
		head_interp = vh_map_elf_dyn(load_elf.stat.file_interp);
		if (!head_interp) {
			ret = -errno;
			goto err_ret;
		}
		load_elf.stat.elf_interp = (Elf_Ehdr *)head_interp;
		ret = chk_elf_consistency(load_elf.stat.elf_interp);
		if (0 > ret) goto err_ret;
		/* Parse segments and fill information for dynamic linker*/
		fill_ve_elf_data(head_interp);
	}

	PSEUDO_DEBUG("Page size for binary: 0x%lx",
			load_elf.pagesize);

	/* Filling information for auxillary vector */
	auxv.e_entry = ehdr->e_entry;
	auxv.e_phnum = ehdr->e_phnum;
	auxv.e_phentsize = ehdr->e_phentsize;
	auxv.p_align = load_elf.pagesize;

	ve_text_page = ehdr->e_entry & ~(auxv.p_align - 1);
	default_page_size = auxv.p_align;
	PSEUDO_INFO("default page size is : 0x%lx",
			default_page_size);
	/* 0x800000 + sizeof EPHDR*/

	auxv.e_phdr = (Elf64_Addr)(char *)ve_text_page + sizeof(Elf64_Ehdr);

	/* Default stack information for the VE Program */
	ve_info.stack_bottom = VE_ADDRESS_SPACE_SIZE +
		ve_text_page - 0x10;/* 512GB-0x10 */

	/* Read the stack limit from enviorment variable VE_STACK_LIMIT */
	ve_set_stack_limit();

	ret = ve_address_space_reserve(ve_text_page);
	if (0 > ret) goto err_ret;
	fill_ve_vh_segmap(handle);
	auxv.e_base = (Elf64_Addr)load_elf.ve_interp_map;
	static int count = 0;
	struct ve_vh_segmap *seg_addr = NULL;
	for (segnum = 0; segnum < load_elf.loadable_segnum; segnum++) {
		seg_addr = load_elf.seg + segnum;
		if ((seg_addr->is_fixed == 1) && !(seg_addr->is_interp == 1)) {
			/* addr[0] = code_start
			 * addr[1] = data_start
			 */
			end_addr[count] = seg_addr->ve_addr + seg_addr->ve_map_size;
			addr[count] = seg_addr->ve_addr + seg_addr->off;
			count++;
		}
	}
	start_ve_req->start_code = addr[0];
	start_ve_req->start_data = addr[1];
	start_ve_req->end_code = end_addr[0];
	start_ve_req->end_data = end_addr[1];
	start_ve_req->pgsz = auxv.p_align;
	seg_addr = NULL;

	for (segnum = 0; segnum < load_elf.loadable_segnum; segnum++) {
		seg_addr = load_elf.seg + segnum;
		if (seg_addr->perm & PROT_WRITE) {
			if (!seg_addr->is_interp) {
				ve_info.heap_start = (uint64_t)(seg_addr->ve_addr +
						seg_addr->ve_map_size);
				if (!IS_ALIGNED((uint64_t)ve_info.heap_start,
							default_page_size)) {
					ve_info.heap_start =
						(((uint64_t)ve_info.heap_start
						  & ~(default_page_size - 1))
						 + default_page_size);
				}
				ve_info.heap_top = ve_info.heap_start;
				PSEUDO_DEBUG("VE process heap start : %lx"
						", ve_info.heap_top: %lx",
						ve_info.heap_start,
						ve_info.heap_top);
			}
		}
		if ((seg_addr->perm & PROT_EXEC) && executeonce) {
			if (!(load_elf.stat.file_interp)) {
				*instr_cntr = (reg_t)
					(((Elf_Ehdr *)head)->e_entry);
				PSEUDO_DEBUG("VE program "
						"start IC : %lx",
						*instr_cntr);
				executeonce = 0;
			} else {
				PSEUDO_DEBUG("VE program "
						"start IC(interpreter) :"
						"%lx, interp_map_addr : %lx",
						(Elf_Ehdr *)head_interp ?
						(((Elf_Ehdr *)head_interp)->e_entry)
						: 0, (uint64_t)load_elf
						.ve_interp_map);

				*instr_cntr = (reg_t)((char *)
						(((Elf_Ehdr *)head_interp)->e_entry) +
						(uint64_t)load_elf.ve_interp_map);
				executeonce = 0;
			}
		}
	}
	PSEUDO_DEBUG("IC set : %lx", *instr_cntr);
	PSEUDO_TRACE("Out Func");

err_ret:
	return ret;
}

/**
 * @brief get size of bss section. (Set all 0).
 *
 * @param[in] ehdr  ELF header
 * @param[in] phdr  Program header
 * @param[in] bss_size size of a bss image.
 *
 * @return VE memory where bss start else NULL on error
 */
void ve_bss_info(Elf_Ehdr *ehdr, uint64_t p_vaddr, char *name)
{
	char *sec_string = NULL;
	int i = 0;
	int flag = 0;
	offset_t offset = 0;
	Elf_Shdr *shdr = NULL;

	if (ehdr->e_type == ET_EXEC) {
		shdr = (Elf64_Shdr *)load_elf.stat.start_section;
		sec_string = load_elf.stat.start_string;
		load_elf.stat.start_bss = 0;
	} else if (ehdr->e_type == ET_DYN) {
		shdr = (Elf64_Shdr *)load_elf.stat.start_section_dyn;
		sec_string = load_elf.stat.start_string_dyn;
		load_elf.stat.start_bss_dyn = 0;
	}

	if (!shdr)
		return;

	for (i = 0; i < ehdr->e_shnum; i++) {
		if (0 == (strcmp((char *)sec_string + shdr->sh_name,
						name))) {
			flag = 1;
			PSEUDO_DEBUG("BSS Section: offset %p, size: %p",
					(void *)shdr->sh_offset,
					(void *)shdr->sh_size);
			break;
		}
		shdr++;
	}

	if ((shdr) && (flag)) {
		offset = shdr->sh_addr - p_vaddr;
		PSEUDO_DEBUG("VE phdr->p_vaddr: %p, bss_offset: %p,"
				" bss_start: %p",
				(void *)p_vaddr, (void *)offset,
				(void *)shdr->sh_addr);
		if (ehdr->e_type == ET_EXEC) {
			load_elf.stat.start_bss = p_vaddr + offset;
			load_elf.stat.size_bss = shdr->sh_size;
			load_elf.stat.start_bss_dyn = 0;
		} else if (ehdr->e_type == ET_DYN) {
			load_elf.stat.start_bss_dyn = offset;
			load_elf.stat.size_bss_dyn = shdr->sh_size;
		}
	}
}

/**
* @brief Allocation of memory for VDSO page.
*
* @param[in] handle VEDL handler
* @return On success, return the addr of VDSO. On failure, NULL will be returned.
*/
void *get_vdso_addr(veos_handle *handle)
{
	void *ret_addr = NULL;

	ret_addr = __ve_mmap(handle, (uint64_t)0, PAGE_SIZE_2MB,
			PROT_READ|PROT_WRITE,
			MAP_VDSO|MAP_2MB|MAP_ANON|MAP_PRIVATE,
			-1, 0);
	if ((void *)-1 == ret_addr) {
		PSEUDO_WARN("mmap for VDSO page fails");
		return NULL;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"|\t\tAT_QUICKCALL_VADDR: %p",
			(void *)ret_addr);
	return ret_addr;
}

/**
* @brief Make a stack region.
*
* @param[in] handle VEDL handler
* @param[in] argc Number of arguments variables for VE.
* @param[in] argv Pointer of argument variables for VE.
* @param[in] envp Pointer of environment variables for VE.
* @param[in] sp Stack limit [S8].
* @param[in] sz Stack pointer [S11].
* @return On success, a 0 will be returned. On failure, a -ve will be returned.
*/
int init_stack(veos_handle *handle, int argc,
		char **argv, char **envp,
		struct ve_start_ve_req_cmd *start_ve_req)
{
	char *new_area = NULL;		/* stack image area */
	int img_size = 0;		/* size of initial stack */
	char *strings_start = NULL;	/* start address of argument string area */
	char *strings_end = NULL;	/* end address of environment string area */
	int strings_size = 0;		/* size of arguments and environments */
	char *ve_string_addr = 0;	/* address of strings on VE  */
	unsigned long long ve_stack_addr = 0; /* VE stack address */
	uint64_t mmap_addr = 0;
	long long *areap_8b = 0;	/* count & write pointers */
	char *areap_1b = NULL;		/* count & write characters */
	char **arg_p = NULL;
	int len = 0;
	int ret = 0;
	char *ret_addr = NULL;
	char *stackbottom = NULL;
	int indx = 0;
	uint64_t l_argc = 0;
	uint64_t p = 0;
	uint64_t vdso = 0;
	int cnt_env = 0;
	reg_t *sp = NULL;
	reg_t *sz = NULL;

	PSEUDO_TRACE("In Func");
	sp = &(start_ve_req->context_info.SP);
	sz = &(start_ve_req->context_info.SZ);

	stackbottom = (char *)ve_info.stack_bottom;
	PSEUDO_DEBUG("bottom: %llx, argc:%d, argv[]:%llx, envp[]:%llx",
			(long long)stackbottom, argc, (long long)argv,
			(long long)envp);

	/* stack size count */

	/* argc + pointers */
	areap_8b += 1;		/* argc */
	areap_8b += argc + 1;	/* argv + NULL */
	if (argc >= EXECVE_MAX_ARGS) {
		PSEUDO_ERROR("Argument count exceeded: %d", argc);
		fprintf(stderr, "Argument count exceeded: %d (max %d)\n",
			argc, EXECVE_MAX_ARGS-1);
		ret = -E2BIG;
		goto stack_err;
        }

	arg_p = envp;		/* envp */
	while (NULL != *arg_p) {
		areap_8b++;
		arg_p++;
		cnt_env++;
	}
	if (cnt_env >= EXECVE_MAX_ENVP) {
                PSEUDO_ERROR("Environment variable exceeded: %d", cnt_env);
                fprintf(stderr, "Environment variable count exceeded"
			" %d (max %d)\n", cnt_env,  EXECVE_MAX_ENVP-1);
		ret = -E2BIG;
                goto stack_err;
        }
	areap_8b++;		/* + NULL */

	arg_p++;		/* auxv */
	while (AT_NULL != ((Elf64_auxv_t *)arg_p)->a_type) {
		switch (((Elf64_auxv_t *)arg_p)->a_type) {
			/* List of auxv that will be placed
			 * in VE process stack.
			 */
		case AT_EXECFD:
		case AT_PHDR:
		case AT_PHENT:
		case AT_PHNUM:
		case AT_PAGESZ:
		case AT_BASE:
		case AT_FLAGS:
		case AT_ENTRY:
		case AT_UID:
		case AT_EUID:
		case AT_GID:
		case AT_EGID:
		case AT_PLATFORM:
		case AT_CLKTCK:
		case AT_SECURE:
		case AT_RANDOM:
		case AT_EXECFN:
		case AT_QUICKCALL_VADDR:
			areap_8b += AUX_BYTE;
			arg_p += AUX_BYTE;
			break;
		default:
			arg_p += AUX_BYTE;
			break;
		}
	}
	areap_8b += AUX_BYTE;	/* + NULL */

	/* strings */
	areap_1b = (char *)areap_8b;
	strings_start = areap_1b;
	arg_p = argv;		/* argv */

	while (NULL != *arg_p) {
		areap_1b += strlen(*arg_p) + 1;
		arg_p++;
	}

	arg_p = envp;		/* envp */
	while (NULL != *arg_p) {
		areap_1b += strlen(*arg_p) + 1;
		arg_p++;
	}

	arg_p++;		/* auxv */
	do {
		switch (((Elf64_auxv_t *)arg_p)->a_type) {
		case AT_RANDOM:
			/* Reserving space in stack for storing
			 * sixteen random bytes.
			 */
			areap_1b += RANDOM_BYTE;
			break;
		case AT_EXECFN:
			areap_1b += strlen(argv[0]) + 1;
			break;
		case AT_PLATFORM:
			areap_1b += strlen("VE") + 1;
			break;
		default:
			break;
		}
		arg_p += AUX_BYTE;
	} while (AT_NULL != ((Elf64_auxv_t *)arg_p)->a_type);

	strings_end = (char *)areap_1b;
	img_size = ((long long)(areap_1b + ALIGNED_8BYTE) >> TRANS_SZ_SHFT)
		<< TRANS_SZ_SHFT;
	strings_size = (int)(strings_end - strings_start);


	/* make stack image */
	new_area = malloc(img_size);
	if (NULL == new_area) {
		ret = -errno;
		PSEUDO_ERROR("Stack for VE allocation failed: %s",
				strerror(-ret));
		fprintf(stderr, "Out of VH memory for VE stack image creation\n");
		goto stack_err;
	}
	PSEUDO_DEBUG("Stack image size: %d"
			" bytes at Address: %p", img_size, new_area);
	PSEUDO_DEBUG("Strings size: %d bytes", strings_size);

	ve_string_addr = (char *)((unsigned long long)stackbottom -
			(unsigned long long)strings_size);
	PSEUDO_DEBUG("ve_string_addr: %p",
			(void *)ve_string_addr);
	/* write data to the new_area */
	/* argc */
	PSEUDO_DEBUG("|--------------------------------------"
			"STACK DUMP--------------------------------------|");
	areap_8b = (long long *)new_area;
	PSEUDO_DEBUG("|\tVE ADDR\t\tVALUE");
	PSEUDO_DEBUG("|\t%llu\t%d",
			(unsigned long long)areap_8b, argc);
	*areap_8b++ = (long long)argc;

	/* pointers & strings */
	areap_1b = (char *)new_area + img_size - strings_size;
	arg_p = argv;		/* argv */
	while (NULL != *arg_p) {
		*areap_8b++ = (long long)ve_string_addr;
		len = strlen(*arg_p);
		strncpy(areap_1b, *arg_p, len + 1);
		PSEUDO_DEBUG(
		 "|\t%llu\t%s", (unsigned long long)ve_string_addr, areap_1b);
		ve_string_addr += len + 1;
		areap_1b += len + 1;
		arg_p++;
	}
	*areap_8b++ = (long long)NULL;
	PSEUDO_DEBUG("|\tNULL\t\tNULL");

	arg_p = envp;		/* envp */
	while (NULL != *arg_p) {
		*areap_8b++ = (long long)ve_string_addr;
		len = strlen(*arg_p);
		strncpy(areap_1b, *arg_p, len + 1);
		PSEUDO_DEBUG("|\t%p\t%s",
				ve_string_addr, areap_1b);
		ve_string_addr += len + 1;
		areap_1b += len + 1;
		arg_p++;
	}
	*areap_8b++ = (long long)NULL;
	PSEUDO_DEBUG("|\tNULL\t\tNULL");

	arg_p++;		/* auxv */
	do {
		switch (((Elf64_auxv_t *)arg_p)->a_type) {
		case AT_EXECFD:
		case AT_BASE:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%p\tAT_BASE: %p",
					(void *)areap_8b, (void *)auxv.e_base);
			*areap_8b++ = (long long)auxv.e_base;
			break;

		case AT_FLAGS:
		case AT_SECURE:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			*areap_8b++ = (long long)0;
			break;
		case AT_UID:
		case AT_EUID:
		case AT_GID:
		case AT_EGID:
		case AT_CLKTCK:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_un.a_val);
			break;
		case AT_RANDOM:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			*areap_8b++ = (long long)ve_string_addr;
			memcpy(areap_1b, (void *)(((Elf64_auxv_t *)
						arg_p)->a_un.a_val), RANDOM_BYTE);
			PSEUDO_DEBUG("|\t%p\tAT_RANDOM: %p",
					ve_string_addr, areap_1b);
			ve_string_addr += RANDOM_BYTE;
			areap_1b += RANDOM_BYTE;
			break;
		case AT_EXECFN:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			*areap_8b++ = (long long)ve_string_addr;
			len = strlen(argv[0]);
			strncpy(areap_1b, argv[0], len + 1);
			PSEUDO_DEBUG("|\t%p\t%s",
					ve_string_addr, areap_1b);
			ve_string_addr += len + 1;
			areap_1b += len + 1;
			break;
		case AT_PLATFORM:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			*areap_8b++ = (long long)ve_string_addr;
			len = strlen("VE");
			strncpy(areap_1b, "VE", len + 1);
			PSEUDO_DEBUG("|\t%p\t%s",
					ve_string_addr, areap_1b);
			ve_string_addr += len + 1;
			areap_1b += len + 1;
			break;
		case AT_ENTRY:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%p\tAT_ENTRY: %p",
					(void *)areap_8b, (void *)auxv.e_entry);
			*areap_8b++ = (long long)auxv.e_entry;
			break;
		case AT_PHNUM:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%llu\tAT_PHNUM: %d",
					(unsigned long long)areap_8b,
					auxv.e_phnum);
			*areap_8b++ = (long long)auxv.e_phnum;
			break;
		case AT_PHENT:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%p\tAT_PHENT: %d",
					(void *)areap_8b,
					auxv.e_phentsize);
			*areap_8b++ = (long long)auxv.e_phentsize;
			break;
		case AT_PHDR:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%p\tAT_PHDR: %p",
					(void *)areap_8b,
					(void *)auxv.e_phdr);
			*areap_8b++ = (long long)auxv.e_phdr;
			break;
		case AT_PAGESZ:
			*areap_8b++ = (long long)(((Elf64_auxv_t *)
						arg_p)->a_type);
			PSEUDO_DEBUG("|\t%p\tAT_PAGESZ: %ld",
					(void *)areap_8b, load_elf.pagesize);
			*areap_8b++ = load_elf.pagesize;
			break;
		case AT_QUICKCALL_VADDR:
			vdso = (uint64_t)get_vdso_addr(handle);
			if (vdso) {
				*areap_8b++ = (long long)(((Elf64_auxv_t *)
							arg_p)->a_type);
				*areap_8b++ = (long long)vdso;
				break;
			}
		default:
			break;
		}
		arg_p += AUX_BYTE;
	} while (AT_NULL != ((Elf64_auxv_t *)arg_p)->a_type);
	*areap_8b++ = (long long)NULL;
	*areap_8b++ = (long long)NULL;

	ve_stack_addr = (uint64_t)stackbottom - img_size;

	PSEUDO_DEBUG("VE stack address %p", (void *)ve_stack_addr);
	mmap_addr = (uint64_t)(ve_stack_addr & (~(load_elf.pagesize - 1)));
	PSEUDO_DEBUG("Aligned VE stack address (mmap_addr) %p",
			(void *)mmap_addr);
	ret_addr = __ve_mmap(handle, mmap_addr, img_size,
			PROT_WRITE,
			MAP_ADDR_SPACE | MAP_ANON | MAP_PRIVATE |
			MAP_STACK | MAP_FIXED,
			-1, 0);
	if ((void *)-1 == ret_addr) {
		ret = -errno;
		PSEUDO_ERROR("Failed(%s) to handle memory mapping",
				strerror(-ret));
		fprintf(stderr, "VE stack memory mapping failed\n");
		goto stack_err_ret;
	}

	/* send the stack image to VE */
	PSEUDO_DEBUG("ARGC In image %d",
			*(int *)new_area);
	ret = ve_send_data(handle, ve_stack_addr, img_size,
			(uint64_t *)new_area);
	if (ret) {
		PSEUDO_ERROR("Failed to send data. (stack): %s",
				strerror(errno));
		fprintf(stderr, "Failed to send data. (stack): %s\n",
				strerror(errno));
		goto stack_err_ret;
	}
	PSEUDO_DEBUG("FROM VH: 0x%llx\tTO VE: 0x%llx",
			(long long)new_area, (long long)ve_stack_addr);
	PSEUDO_DEBUG("Stack image size to send: 0x%x Byte", img_size);

	PSEUDO_DEBUG("heap_start %p", (void *)ALIGN(ve_info.heap_start,
				load_elf.pagesize));

	PSEUDO_DEBUG("STACK VE DUMP");
	areap_8b = NULL;
	areap_8b = (long long *)ve_stack_addr;

	ret = ve_recv_data(handle, (uint64_t)areap_8b,
				sizeof(uint64_t),
				(void *)&l_argc);
	if (ret) {
		PSEUDO_ERROR("Failed(%s) to receive data", strerror(errno));
		fprintf(stderr, "Failed(%s) to receive stack dump\n",
			strerror(errno));
		goto stack_err_ret;
	}
	PSEUDO_DEBUG("ARGC_ADDR: %p ARGC: %ld", (void *)areap_8b,  l_argc);

	areap_8b++;
	start_ve_req->argv_addr = (uint64_t)areap_8b;
	start_ve_req->argv_size = (uint64_t)argc;
	indx = (int)l_argc;
	while (indx--) {
		if (NULL != (void *)areap_8b) {
			ret = ve_recv_data(handle, (uint64_t)areap_8b,
						sizeof(uint64_t),
						(uint64_t *)(&p));
			 if (ret) {
				PSEUDO_ERROR("Failed(%s) to"
						" receive data (ARG)",
						 strerror(errno));
				fprintf(stderr, "Failed(%s) to receive"
						" ARG data\n",
						 strerror(errno));
				goto stack_err_ret;
			}
		}
		PSEUDO_DEBUG("ARGV_ADDR: %p, %p",
				(void *)areap_8b, (void *)p);
		areap_8b++;
	}
	areap_8b++;

	while (p) {
		if (NULL != (void *)areap_8b) {
			ret = ve_recv_data(handle, (uint64_t)areap_8b,
						sizeof(uint64_t),
						(uint64_t *)(&p));
			if (ret) {
				PSEUDO_ERROR("Failed(%s) to "
						"receive data (ENV)",
						strerror(errno));
				fprintf(stderr, "Failed(%s) to receive"
						" ENV data\n",
						 strerror(errno));
				goto stack_err_ret;
			}
		}
		PSEUDO_DEBUG("ENV_ADDR: %p, %ld", (void *)areap_8b, p);
		areap_8b++;
	}

	start_ve_req->auxv_addr = (uint64_t)areap_8b;
	PSEUDO_DEBUG("AUXV_ADDR(start addr): %p",
			(void *)start_ve_req->auxv_addr);
	arg_p = NULL;
	indx = 0;
	do {
		if (NULL != (void *)areap_8b) {
			ret = ve_recv_data(handle, (uint64_t)areap_8b,
						sizeof(long long),
						(uint64_t *)(&arg_p));
			if (ret) {
				PSEUDO_ERROR("Failed(%s) to"
					     " receive data ARGV",
					     strerror(errno));
				fprintf(stderr, "Failed(%s) to receive"
					" ARG data\n",
					strerror(errno));
				goto stack_err_ret;
			}
		}
		PSEUDO_DEBUG("AUXV_ADDR: %p, %p",
				(void *)areap_8b, (void *)arg_p);
		areap_8b++;
		indx++;
	} while (NULL != (void *)arg_p);
	PSEUDO_DEBUG("TOTAL AUXV: %d", indx-1);
	start_ve_req->auxv_size = (uint64_t)(indx-1);

	ve_info.stack_pointer_aligned = mmap_addr;

	/* set registers for stack */
	*sz = (unsigned long long)mmap_addr + STACK_AREA_FOR_SIGNAL;
	*sp = (unsigned long long)ve_stack_addr;

	PSEUDO_DEBUG("LOADING FINISH");
	PSEUDO_TRACE("Out Func");

stack_err_ret:
	free(new_area);
stack_err:
	errno = -ret;
	return ret;
}


/**
* @brief Parse segments and fill information.
*
* @param[in] head ELF file mmaped address.
* @param[in] ehdr Address of ELF header.
*
* @return No return value, on failure call exit.
*/
void fill_ve_elf_data(char *head)
{
	static bool is_interp;
	int segnum = 0;
	char *buf = NULL;
	void *align_addr = NULL;
	Elf_Ehdr *ehdr = NULL;
	Elf_Phdr *phdr = NULL;

	ehdr = (Elf_Ehdr *)head;
	PSEUDO_DEBUG("Parsing segment from file");
	for (segnum = 0; segnum < ehdr->e_phnum; segnum++) {
		phdr = (Elf_Phdr *)(head + ehdr->e_phoff +
				ehdr->e_phentsize * segnum);

		switch (phdr->p_type) {
		case PT_INTERP:
			PSEUDO_DEBUG("VE interpreter, name: %p",
					(void *)head+phdr->p_offset);

			if (0 > (lseek(load_elf.stat.fd,
						phdr->p_offset, SEEK_SET))) {
				PSEUDO_ERROR("failed to reposition offset"
						": %s", strerror(errno));
				fprintf(stderr, "Failed to load executable\n"
					"Reposition offset: %s\n",
					strerror(errno));
				pseudo_abort();
			}
			buf = (char *)calloc(1, phdr->p_filesz);
			if(!buf) {
				PSEUDO_ERROR("failed to allocate buffer: %s",
						strerror(errno));
				fprintf(stderr, "Failed to load executable\n"
					"Allocate interpreter buffer: %s\n",
					strerror(errno));
				pseudo_abort();
			}
			if (0 > (read(load_elf.stat.fd, buf,
							phdr->p_filesz))) {
				PSEUDO_ERROR("failed to read data: %s",
						strerror(errno));
				fprintf(stderr, "Failed to load executable\n"
					"Read interpreter data: %s",
					strerror(errno));
				pseudo_abort();
			}
			is_interp = 1;

			/* copying INTERP in mapped area */
			(void)memcpy((char *)load_elf.stat.file_interp,
					(char *)buf, phdr->p_filesz);

			load_elf.stat.file_interp_end = (char *)
					load_elf.stat.file_interp
					+ phdr->p_filesz;

			align_addr = (char *)((((uint64_t)
					(load_elf.stat.file_interp_end))
					& ~(((uint64_t)1 << BPSPSHFT) - 1))
					+ (1 << BPSPSHFT));

			memset(load_elf.stat.file_interp_end, 0,
				 ((char *)align_addr - load_elf.stat.file_interp_end));
			free(buf);
			break;
		case PT_LOAD:
			PSEUDO_DEBUG("VE load,  name: %p",
					head+phdr->p_offset);
			if ((phdr->p_flags & PF_X) && (load_elf.pagesize == -1 )) {
				load_elf.pagesize = phdr->p_align;
				PSEUDO_DEBUG("load_elf.pagesize: %p",
						(void *)load_elf.pagesize);
			}
			load_elf.loadable_segnum += 1;
			break;
		default:
			break;
		}
	}
	if (!is_interp)
		load_elf.stat.file_interp = NULL;
}

/**
* @brief open_bin_file in VH memory space.
*
* @param[in] filename ELF file name.
* @param[out] pointer pfd to store file fd
*
* @return On success returns header and fd
* and on failure return NULL.
*/
char * open_bin_file (char *filename, int *pfd)
{
	char *buf = NULL;
	int fd = -1;
	int retval = 0;
	struct statvfs st = {0};
        struct stat sb = {0};

	filename = realpath(filename, NULL);
        if (NULL == filename) {
                retval = -errno;
                PSEUDO_ERROR("Failed to get realpath");
                PSEUDO_DEBUG("Fail(%s) to get realpath of:%s",
                                strerror(-retval),
                                filename);
                fprintf(stderr, "Failed to get binary realpath: %s\n",
			filename);
                goto end;
        }

        PSEUDO_DEBUG("Realpath of binary is %s", filename);
	retval = statvfs(filename, &st);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("File stat fail");
		PSEUDO_DEBUG("File stat fail: %s",
			     strerror(-retval));
		fprintf(stderr, "VE binary stat failed: %s\n",
			strerror(-retval));
		goto end;
	}

	/* Check if noexec flag was set when the directory was mounted */
	if (st.f_flag & ST_NOEXEC) {
		retval = -EACCES;
		PSEUDO_ERROR("Executing from a directory mounted with noexec: %s"
				, strerror(-retval));
		fprintf(stderr, "VE binary in directory mounted"
			" with noexec %s\n", strerror(-retval));
		goto end;
	}

	/* Check if realpath has search permissions
	 * If not, then EACCES should be returned */
	retval = access(filename, F_OK);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("Path of binary inaccessible");
		PSEUDO_DEBUG("Accessing real_path to binary failed, "
			     "errno %s", strerror(-retval));
		fprintf(stderr, "Path of VE binary inaccessible: %s\n",
			strerror(-retval));
		goto end;
	}

	retval = stat(filename, &sb);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("File stat fail");
		PSEUDO_DEBUG("File stat fail: %s",
				strerror(-retval));
		fprintf(stderr, "VE binary stat failed: %s\n",
			strerror(-retval));
		goto end;
	}

	if (S_ISDIR(sb.st_mode)) {
		PSEUDO_ERROR("File is a directory");
		fprintf(stderr, "VE binary path is a directory\n");
		retval = -EISDIR;
		goto end;
	}

	if (!S_ISREG(sb.st_mode)) {
		PSEUDO_ERROR("Not a regular file");
		fprintf(stderr, "VE binary is not a regular file\n");
		retval = -EACCES;
		goto end;
	}

	/* Check if the file has execute permissions */
	if (!(sb.st_mode & S_IXUSR)) {
		PSEUDO_ERROR("File doesn't have executable permissions");
		fprintf(stderr, "VE binary has no exec permissions\n");
		retval = -EACCES;
		goto end;
	}

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (0 > fd) {
		retval = -errno;
		PSEUDO_ERROR("Failed to open ELF file name");
		PSEUDO_DEBUG("Failed(%s) to open ELF file name",
				strerror(-retval));
		fprintf(stderr, "Failed to open VE binary file: %s\n",
			     strerror(-retval));
		goto end;
	}
	buf = (char *)calloc(1, sizeof(Elf64_Ehdr));
	if(!buf) {
		retval = -errno;
		PSEUDO_ERROR("Failed to allocate buffer to read ELF file");
		PSEUDO_DEBUG("Failed(%s) to allocate buffer to read ELF file",
				strerror(-retval));
		fprintf(stderr, "Failed to allocate buffer for VE binary:"
			" %s\n", strerror(-retval));
		close(fd);
		goto end;
	}

	if (0 > (read(fd, buf, sizeof(Elf64_Ehdr)))) {
		retval = -errno;
		close(fd);
		free(buf);
		buf = NULL;
		PSEUDO_ERROR("Failed to read ELF file");
		PSEUDO_DEBUG("Failed(%s) to read ELF file", strerror(-retval));
		fprintf(stderr, "Failed to read VE ELF file: %s\n",
			strerror(-retval));
		goto end;
	}
end:
	if(filename != NULL)
		free(filename);
	*pfd = fd;
	errno = -retval;
	return buf;
}

/**
* @brief Read ELF file in VH memory space.
*
* @param[in] filename ELF file name.
*
* @return On success returns VH memory address
* and on failure return NULL.
*/
char *vh_map_elf_dyn(char *filename)
{
	char *buf = NULL;
	char *head = NULL;
	int fd = -1;
	int ret = 0;
	size_t map_size = 0;
	Elf64_Ehdr *ehdr = NULL;
	Elf64_Shdr *nhdr = NULL;

	PSEUDO_DEBUG("INTERP: %s", load_elf.stat.file_interp);
	buf = open_bin_file(filename, &fd);
	if (!buf) {
		ret = -errno;
		goto err_ret;
	}
	ehdr = (Elf64_Ehdr *)buf;
	map_size = ehdr->e_ehsize + (ehdr->e_phentsize * ehdr->e_phnum);

	if (0 > (lseek(fd, 0, SEEK_SET))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to repositions file offset: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed to repositions ELF file offset:"
			" dynamic: %s\n", strerror(-ret));
		goto err_ret1;
	}

	free(buf);

	buf = (char *)calloc(1, map_size);
	if(!buf) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to create buffer: "
				"dynamic", strerror(-ret));
		fprintf(stderr, "Failed to create buffer for ELF file: "
				"dynamic: %s\n", strerror(-ret));
		goto err_ret;
	}

	if (0 > (read(fd, buf, map_size))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to read data: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed to read ELF file data:"
			" dynamic: %s\n", strerror(-ret));
		goto err_ret1;
	}

	(void)memcpy(load_elf.stat.file_interp_end, buf, map_size);
	/* Saving fd  for reference */
	load_elf.stat.fd_dyn = fd;

	PSEUDO_DEBUG("INTERP_START: %p",
			(void *)load_elf.stat.file_interp_end);

	ehdr = (Elf64_Ehdr *)buf;
	if (0 > (lseek(fd, ehdr->e_shoff, SEEK_SET))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to reposition file offset: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed(%s) to reposition ELF file offset:"
			" dynamic\n", strerror(-ret));
		goto err_ret1;
	}
	map_size = ((ehdr->e_shentsize) * (ehdr->e_shnum));
	load_elf.stat.start_section_dyn = (char *)calloc(1,
			map_size);
	if(!load_elf.stat.start_section_dyn) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to allocated buffer to read start"
				" section: dynamic", strerror(-ret));
		fprintf(stderr, "Failed to allocated buffer to read start"
				" section: dynamic: %s\n", strerror(-ret));
		goto err_ret1;
	}
	if (0 > (read(fd, load_elf.stat.start_section_dyn, map_size))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to read start section: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed to read ELF file start section:"
			" dynamic: %s\n", strerror(-ret));
		free(load_elf.stat.start_section_dyn);
		goto err_ret1;
	}

	nhdr = (Elf64_Shdr *)load_elf.stat.start_section_dyn;
	nhdr += ehdr->e_shstrndx;
	PSEUDO_DEBUG("Section: offset %p, size: %p",
			(void *)nhdr->sh_offset,
			(void *)nhdr->sh_size);

	if (0 > (lseek(fd, nhdr->sh_offset, SEEK_SET))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to reposition file offset: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed to reposition ELF file offset:"
			" dynamic: %s\n", strerror(-ret));
		free(load_elf.stat.start_section_dyn);
		goto err_ret1;
	}

	load_elf.stat.start_string_dyn = (char *)calloc(1, nhdr->sh_size);
	if(!load_elf.stat.start_string_dyn) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to allocate buffer to read start"
				" string: dynamic", strerror(-ret));
		fprintf(stderr, "Failed to allocate buffer to read ELF"
			" file start string: dynamic: %s\n", strerror(-ret));
		free(load_elf.stat.start_section_dyn);
		goto err_ret1;
	}

	if (0 > (read(fd, load_elf.stat.start_string_dyn, nhdr->sh_size))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to read start string: dynamic",
				strerror(-ret));
		fprintf(stderr, "Failed to read ELF file start string:"
			" dynamic: %s\n", strerror(-ret));
		free(load_elf.stat.start_section_dyn);
		free(load_elf.stat.start_string_dyn);
		goto err_ret1;
	}
	head = load_elf.stat.file_interp_end;

err_ret1:
	free(buf);
err_ret:
	errno = -ret;
	return head;
}

/**
* @brief Map ELF file in VH memory space.
*
* @param[in] filename ELF file name.
*
* @return On success returns VH memory address
* and on failure return NULL.
*/
void *vh_map_elf(char *filename)
{
	char *buf = NULL;
	int fd = -1;
	int ret = 0;
	size_t map_size = 0;
	size_t size = 0;
	void *map_addr = NULL;
	void *head = NULL;
	Elf64_Ehdr *ehdr = NULL;
	Elf64_Shdr *nhdr = NULL;

	PSEUDO_DEBUG("For mapping the ELF file: %s", filename);

	buf = open_bin_file(filename, &fd);
	if (!buf) {
		ret = -errno;
		goto err_ret;
	}
	ehdr = (Elf64_Ehdr *)buf;

	map_size = ehdr->e_ehsize + (ehdr->e_phentsize * ehdr->e_phnum);

	map_addr = mmap(NULL, map_size,
			PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (MAP_FAILED == map_addr) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to create virtual address space"
				" mapping", strerror(-ret));
		fprintf(stderr, "Failed to create virtual address space"
				" mapping: %s\n", strerror(-ret));
		goto err_ret1;
	}
	PSEUDO_DEBUG("For mapping the ELF file: %p", (void *)map_addr);

	/* Saving fd to get reference of INTERP*/
	load_elf.stat.file_interp = map_addr + map_size;
	load_elf.stat.fd = fd;

	if (0 > (lseek(fd, ehdr->e_shoff, SEEK_SET))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to reposition file offset",
				strerror(-ret));
		fprintf(stderr, "Failed to reposition ELF file offset: %s\n",
			strerror(-ret));
		(void)munmap(map_addr, map_size);
		goto err_ret1;
	}
	size = ((ehdr->e_shentsize) * (ehdr->e_shnum));
	load_elf.stat.start_section = (char *)calloc(1,
			size);
	if(!load_elf.stat.start_section) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to create buffer to read start"
				" section", strerror(-ret));
		fprintf(stderr, "Failed to alloc buffer for ELF start"
				" section: %s\n", strerror(-ret));
		(void)munmap(map_addr, map_size);
		goto err_ret1;
	}
	if (0 > (read(fd, load_elf.stat.start_section, size))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to read start section",
				strerror(-ret));
		fprintf(stderr, "Failed to read ELF start section: %s\n",
			strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.stat.start_section);
		goto err_ret1;
	}

	nhdr = (Elf64_Shdr *)load_elf.stat.start_section;
	nhdr += ehdr->e_shstrndx;
	PSEUDO_DEBUG("Section: offset %p, size: %p",
			(void *)nhdr->sh_offset,
			(void *)nhdr->sh_size);

	if (0 > (lseek(fd, nhdr->sh_offset, SEEK_SET))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to reposition file offset",
				strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.stat.start_section);
		goto err_ret1;
	}

	load_elf.stat.start_string = (char *)calloc(1, nhdr->sh_size);
	if(!load_elf.stat.start_string) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to create buffer to read start"
				" string", strerror(-ret));
		fprintf(stderr, "Failed to alloc buffer to read ELF start"
				" string: %s\n", strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.stat.start_section);
		goto err_ret1;
	}
	if (0 > (read(fd, load_elf.stat.start_string, nhdr->sh_size))) {
		ret = -errno;
		close(fd);
		PSEUDO_ERROR("Failed(%s) to read start string", strerror(-ret));
		fprintf(stderr, "Failed to read ELF start string: %s\n",
			strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.stat.start_section);
		free(load_elf.stat.start_string);
		goto err_ret1;
	}
	head = map_addr;

err_ret1:
	free(buf);
err_ret:
	errno = -ret;
	return head;
}

/**
* @brief Check validity of ELF file.
*
* @param[in] ehdr ELF header address.
*
* @return On success returns 0 on failure return -ive values.
*/
int chk_elf_consistency(Elf_Ehdr *ehdr)
{
	int ret = 0;

	if (!IS_ELF(*ehdr)) {
		ret = -ENOEXEC;
		PSEUDO_ERROR("This is not an ELF file: %s", strerror(-ret));
		goto err_ret;
	}
	if (ELF_VE != ehdr->e_machine) {
		ret = -ENOEXEC;
		PSEUDO_ERROR("This is not VE ELF file: %s", strerror(-ret));
		goto err_ret;
	}
	if (ELF_CLASS != ehdr->e_ident[EI_CLASS]) {
		ret = -ENOEXEC;
		PSEUDO_ERROR("This is not 64 bit object: %s", strerror(-ret));
		fprintf(stderr, "This is not 64 bit object: %s\n",
			strerror(-ret));
		goto err_ret;
	}
	if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) {
		ret = -ENOEXEC;
		PSEUDO_ERROR("This is not little endian: %s", strerror(-ret));
		fprintf(stderr, "ELF data is not little endian: %s\n",
			strerror(-ret));
		goto err_ret;
	}
	if ((ET_EXEC != ehdr->e_type) && (ET_DYN != ehdr->e_type)) {
		ret = -ENOEXEC;
		PSEUDO_ERROR("This is not an executable or shared file: %s", strerror(-ret));
		fprintf(stderr, "This is not an executable or a shared file:"
			" %s\n", strerror(-ret));
		goto err_ret;
	}

err_ret:
	return ret;
}

/**
 * @brief map ELF contents to VE mmeory.
 *
 * @param[in] handle VE Driver handle.
 *
 * @return return nothing.
 */
void fill_ve_vh_segmap(veos_handle *handle)
{
	int total_segnum = 0;
	int segnum = 0;
	int ret = 0;
	Elf_Ehdr *ehdr = NULL;
	Elf_Phdr *phdr = NULL;
	long segment_size = 0;
	char *align_addr = NULL;
	uint64_t align_exe = 0;
	uint64_t align_dyn = 0;
	char *buf_bss = NULL;
	long rest_size = 0;	/* memory data transfer */
	int fixed = -1;
	int interp = -1;
	char *ret_addr;
	struct ve_vh_segmap *seg_addr = NULL;
	uint64_t page_algn = 0;
	uint64_t diff = 0;
	uint64_t gap = 0;

	PSEUDO_TRACE("In func");
	PSEUDO_DEBUG("Total count for VE segments: %ld", load_elf.loadable_segnum);

	load_elf.seg = calloc((sizeof(struct ve_vh_segmap))*
			(load_elf.loadable_segnum), 1);

	if (NULL == load_elf.seg) {
		PSEUDO_ERROR("failed to load segments: %s",
				strerror(errno));
		fprintf(stderr, "Failed to load ELF segments: %s\n",
			strerror(errno));
		pseudo_abort();
	}
	PSEUDO_DEBUG("Return address for ve_vh_segmap: %p",
			(void *)load_elf.seg);

	ehdr = load_elf.stat.elf_ex; /* Exceutable file header */

	for (total_segnum = 0; total_segnum < load_elf.loadable_segnum;)  {
		if (ehdr->e_type != ET_EXEC) {
			PSEUDO_DEBUG("VE ELF type is ET_DYN");
			fixed = 0;
			interp = 1;
		} else  {
			PSEUDO_DEBUG("VE ELF type is ET_EXEC");
			fixed = 1;
			interp = 0;
		}

		for (segnum = 0; segnum < ehdr->e_phnum; segnum++) {
			phdr = (Elf_Phdr *)((char *)ehdr + ehdr->e_phoff +
					ehdr->e_phentsize * segnum);
			seg_addr = load_elf.seg + total_segnum;

			switch (phdr->p_type) {
			case PT_LOAD:
				if ((ehdr->e_type == ET_DYN)) {
					PSEUDO_DEBUG("PT_LOAD count for "
							"interpreter num: %d"
							" seg_addr: %p",
							total_segnum,
							(void *)
							(seg_addr+
							total_segnum));
					/* Reading page alignment */
					page_algn =
						(PAGE_SIZE_2MB == phdr->p_align)
						? MAP_2MB : MAP_64MB;

				} else {
					PSEUDO_DEBUG("PT_LOAD count for exec: %d"
						" seg_addr: %p", total_segnum,
						(void *)(seg_addr+total_segnum));
				}

				segment_size = ((phdr->p_memsz + ALIGNED_8BYTE) >>
						TRANS_SZ_SHFT) << TRANS_SZ_SHFT;
				PSEUDO_DEBUG("p_type (LOAD), loadarea "
						"size: 0x%lx "
						"(p_memsz: 0x%lx)",
						segment_size, phdr->p_memsz);

				(seg_addr)->offset = (uint64_t)(phdr->p_offset);

				if (!IS_ALIGNED((uint64_t)(seg_addr)->offset,
							phdr->p_align)) {
					align_addr = (char *)
						((uint64_t)(seg_addr)->offset
						 & ~(phdr->p_align - 1));
					(seg_addr)->offset = (unsigned long)align_addr;
				}
				PSEUDO_DEBUG("VE OFFSET "
					"aligned %lx, File offset(p_offset) %lx",
					(uint64_t)(seg_addr)
					->offset, phdr->p_offset);

				(seg_addr)->length = segment_size;
				(seg_addr)->is_interp = interp;
				(seg_addr)->is_fixed = fixed;
				PSEUDO_DEBUG("PT_LOAD: VE ELF address"
						" %lx",
						(uint64_t)phdr
						->p_vaddr);
				if (!IS_ALIGNED((uint64_t)phdr->p_vaddr,
							phdr->p_align)) {
					align_addr = (char *)
						((uint64_t)phdr->p_vaddr
						 & ~(phdr->p_align - 1));
					gap = (char *)phdr->p_vaddr - align_addr;
				} else {
					align_addr = (char *)phdr->p_vaddr;
				}

				PSEUDO_DEBUG("VE ELF aligned address: %p, gap: %p",
						(void *)align_addr, (void *)gap);

				if (ehdr->e_type == ET_EXEC) {
					if (phdr->p_flags & PF_W)
						align_exe = (uint64_t)
							phdr->p_align;
					(seg_addr)->flag |=
						MAP_PRIVATE|MAP_FIXED|
						MAP_ADDR_SPACE;
				}
				if (phdr->p_flags & PF_W) {
					ve_bss_info(ehdr,
							(uint64_t)align_addr,
							".bss");
					(seg_addr)->perm |=
						PROT_READ|PROT_WRITE;
					if (ehdr->e_type == ET_DYN) {
						align_dyn = (uint64_t)
							phdr->p_align;
						(seg_addr)->flag |=
							MAP_PRIVATE|MAP_FIXED
							|page_algn;
					}
				} else {
					(seg_addr)->perm |= PROT_READ|PROT_EXEC;
					if (ehdr->e_type == ET_DYN) {
						(seg_addr)->flag |= MAP_PRIVATE
								|page_algn;
					}
				}

				/* For MMAP */
				(seg_addr)->ve_file_size = (uint64_t)phdr->p_filesz + gap;
				(seg_addr)->ve_addr = (unsigned long)align_addr;
				(seg_addr)->off = (off_t)((uint64_t)phdr->p_vaddr
						- (uint64_t)align_addr);
				rest_size = segment_size;
				/* Mapping size */
				(seg_addr)->ve_map_size = rest_size +
					(uint64_t)(seg_addr->off);
				(seg_addr)->length = rest_size;
				if ((ehdr->e_type == ET_DYN))
					fixed = 1;
				total_segnum++;
				break;
			default:
				break;
				/* While loop termination */
			}
			/* For loop termination */
		}
		if ((ehdr->e_type == ET_EXEC)) {
			if (load_elf.stat.file_interp != NULL)
				/* Dynamic linker file header */
				ehdr = load_elf.stat.elf_interp;
			else
				break;
		}
	}

	PSEUDO_DEBUG("Dump contents of VE ELF and "
			"INTERP segment Before MMAP");
	seg_addr = NULL;
	PSEUDO_DEBUG("seg num\tseg_addr   is_fixed   "
			"is_interp   offset(host)\tve_addr"
			"(VE)\tlength\tve_map_size\t"
			"offset");
	for (segnum = 0; segnum < load_elf.loadable_segnum; segnum++) {
		seg_addr = ((struct ve_vh_segmap *)load_elf.seg + segnum);
		PSEUDO_DEBUG("%d\t%p\t\t%d\t%d\t%lx\t%lx\t\t%lx\t%lx\t\t%lx",
				segnum, (void *)seg_addr,
				seg_addr->is_fixed, seg_addr->is_interp,
				seg_addr->offset, seg_addr->ve_addr,
				seg_addr->length, seg_addr->ve_map_size,
				seg_addr->off);
	}

	PSEUDO_DEBUG("Going to MAP the segment");
	seg_addr = NULL;
	for (segnum = 0; segnum < load_elf.loadable_segnum; segnum++) {
		seg_addr = ((struct ve_vh_segmap *)load_elf.seg + segnum);
		if (seg_addr->is_fixed) {
			if (1 == seg_addr->is_interp) {
				align_addr = seg_addr->ve_addr +
					load_elf.ve_interp_map;
				ret_addr = (char *)__ve_mmap(handle,
						(uint64_t)align_addr,
						seg_addr->ve_map_size,
						seg_addr->perm,
						seg_addr->flag|MAP_ANON,
						-1,
						0);
				if ((void *)-1 == ret_addr) {
					PSEUDO_DEBUG("VE mmap fail to load"
							" DATA (fixed): %s",
							strerror(errno));
					PSEUDO_ERROR("failed to load dyn DATA");
					fprintf(stderr, "VE mmap failed to load"
						" dyn DATA (fixed): %s\n",
						strerror(errno));
					pseudo_abort();
				}
				seg_addr->ve_addr = (uint64_t)ret_addr;
				PSEUDO_DEBUG("Mapping file: INTERP "
						"- Mapping type: FIXED "
						"Load segment: %p",
						(void *)ret_addr);
				if(load_elf.stat.start_bss_dyn)
					load_elf.stat.start_bss_dyn +=
							 (uint64_t)ret_addr;
				ret_addr = (char *)__ve_mmap(handle,
						seg_addr->ve_addr,
						seg_addr->ve_file_size,
						seg_addr->perm,
						seg_addr->flag,
						load_elf.stat.fd_dyn,
						seg_addr->offset);
				PSEUDO_DEBUG("Fileback Mapping file: INTERP "
						"- Mapping type: FIXED "
						"Load segment: %p",
						(void *)ret_addr);
				if ((void *)-1 == ret_addr) {
					PSEUDO_DEBUG("VE mmap fail to load dyn DATA"
						" (fixed), fileback: %s",
						strerror(errno));
					PSEUDO_ERROR("failed to load dyn DATA");
					fprintf(stderr, "VE mmap failed to load"
						" dyn DATA (fixed, fileback):"
						" %s\n", strerror(errno));
					pseudo_abort();
				}
			} else {
				if (seg_addr->perm & PF_W) {
					ret_addr = (char *)__ve_mmap(handle,
						(uint64_t)seg_addr->ve_addr,
						seg_addr->ve_map_size,
						seg_addr->perm,
						seg_addr->flag|MAP_ANON,
						-1, 0);
					if ((void *)-1 == ret_addr) {
						PSEUDO_DEBUG("VE mmap EXEC:"
							" DATA(fixed):%s",
							strerror(errno));
						PSEUDO_ERROR("failed to load"
								" EXEC DATA");
						fprintf(stderr, "failed to load"
							" EXEC DATA(fixed):%s\n",
							strerror(errno));
						pseudo_abort();
					}
					PSEUDO_DEBUG("Mapping file: EXEC - Mapping"
						" type: FIXED "
						"DATA segment: %p",
						(void *)ret_addr);
					ret_addr = (char *)__ve_mmap(handle,
						(uint64_t)ret_addr,
						seg_addr->ve_file_size,
						seg_addr->perm,
						seg_addr->flag,
						load_elf.stat.fd,
						seg_addr->offset);
					PSEUDO_DEBUG("Fileback Mapping file: EXEC - Mapping "
						" type: FIXED "
						"DATA segment: %p",
						(void *)ret_addr);
					if ((void *)-1 == ret_addr) {
						PSEUDO_DEBUG("VE mmap EXEC: "
							"DATA(fixed):"
							"Fileback %s",
							strerror(errno));
						PSEUDO_ERROR("failed to load"
							" EXEC data");
						fprintf(stderr, "failed to load"
							" EXEC DATA (fixed,"
							" fileback): %s\n",
							strerror(errno));
                                                pseudo_abort();
					}
				} else {
					ret_addr = (char *)__ve_mmap(handle,
							(uint64_t)seg_addr->ve_addr,
							seg_addr->ve_map_size,
							seg_addr->perm,
							seg_addr->flag,
							load_elf.stat.fd,
							seg_addr->offset);
					if ((void *)-1 == ret_addr) {
						PSEUDO_DEBUG("VE mmap fails TEXT (fixed):"
							" %s", strerror(errno));
						PSEUDO_ERROR("failed to load"
								" exec text"
								" data");
						fprintf(stderr, "VE mmap failed"
							" on TEXT (fixed): %s\n",
							strerror(errno));
						pseudo_abort();
					}
					PSEUDO_DEBUG("Mapping file: EXEC - Mapping "
							" type: FIXED "
							"TEXT segment: %p",
							(void *)ret_addr);
				}
			}
		} else {
			ret_addr = (char *)__ve_mmap(handle,
					(uint64_t)0, seg_addr->ve_map_size,
					seg_addr->perm, seg_addr->flag,
					load_elf.stat.fd_dyn, seg_addr->offset);
			if ((void *)-1 == ret_addr) {
				PSEUDO_DEBUG("VE mmap fail, INTERP - TEXT"
						": %s",
						strerror(errno));
				PSEUDO_ERROR("failed to load INTERP data");
				fprintf(stderr, "VE mmap failed on INTERP - TEXT"
						": %s\n", strerror(errno));
				pseudo_abort();
			}
			PSEUDO_DEBUG("Mapping file: INTERP "
					"- Mapping type: NOT FIXED "
					"Text segment: %p", (void *)ret_addr);
			load_elf.ve_interp_map = (char *)ret_addr;
			seg_addr->ve_addr = (uint64_t)ret_addr;
		}
	}

	PSEUDO_DEBUG("Dump contents of VE ELF and "
			"INTERP segment After MMAP");
	seg_addr = NULL;
	PSEUDO_DEBUG("seg num\tseg_addr   is_fixed   "
			"is_interp   offset(host)\tve_addr"
			"(VE)\tlength\tve_map_size\t"
			"offset");
	for (segnum = 0; segnum < load_elf.loadable_segnum; segnum++) {
		seg_addr = ((struct ve_vh_segmap *)load_elf.seg + segnum);
		PSEUDO_DEBUG("%d\t%p\t\t"
				"%d\t%d\t%lx\t%lx\t\t%lx\t%lx\t\t%lx",
				segnum, (void *)seg_addr,
				seg_addr->is_fixed, seg_addr->is_interp,
				seg_addr->offset, seg_addr->ve_addr,
				seg_addr->length, seg_addr->ve_map_size,
				seg_addr->off);
	}
	/* Clear BSS */
	if (load_elf.stat.start_bss) {
		PSEUDO_DEBUG("Going to clear BSS(EXE)");
		if (!IS_ALIGNED((uint64_t)load_elf.stat.start_bss,
					align_exe)) {
			align_addr = (char *)
				(((uint64_t)load_elf.stat.start_bss
				  & ~(align_exe - 1)) + align_exe);
			diff = align_addr - (char *)load_elf.stat.start_bss;
			PSEUDO_DEBUG("B.start: %p, algin: %p, diff. %p",
					(void *)load_elf.stat.start_bss,
					(void *)align_addr,
					(void *)diff);
		}
		if (diff) {
			buf_bss = (char *)calloc(1, diff);
			if (!buf_bss) {
				PSEUDO_ERROR("fails for clearing BSS(EXE)");
				fprintf(stderr,	"failed"
						" to load VE binary");
				pseudo_abort();
			}
			PSEUDO_DEBUG("Src: %p, Dest: %p",
					(void *)buf_bss,
					(void *)load_elf.stat.start_bss);
			ret = ve_send_data(handle,
					(uint64_t)load_elf.stat.start_bss,
					diff,
					(uint64_t *)buf_bss);
			if (ret) {
				PSEUDO_ERROR("failed to send data from VH to"
						" VE memory");
				fprintf(stderr, "failed to send data from"
					" VH to VE memory\n");
				pseudo_abort();
			}
			PSEUDO_DEBUG("CLEAR BSS: VE send data pass");
			free(buf_bss);
		}
	} else {
		PSEUDO_DEBUG("NO BSS SECTION(EXE)");
	}
	if (load_elf.stat.start_bss_dyn) {
		PSEUDO_DEBUG("Going to clear BSS(DYN)");
		if (!IS_ALIGNED((uint64_t)load_elf.stat.start_bss_dyn,
                                        align_dyn)) {
                        align_addr = (char *)
                                (((uint64_t)load_elf.stat.start_bss_dyn
                                  & ~(align_dyn - 1)) + align_dyn);
                        diff = align_addr - (char *)load_elf.stat.start_bss_dyn;
                        PSEUDO_DEBUG("start: %p, algin: %p, diff. %p",
                                        (void *)load_elf.stat.start_bss_dyn,
                                        (void *)align_addr,
                                        (void *)diff);
                }
		if (diff) {
			buf_bss = (char *)calloc(1, diff);
			if (!buf_bss) {
				PSEUDO_ERROR("Calloc fails for clearing"
						" BSS(DYN)");
				fprintf(stderr, "Failed to alloc BSS(DYN)\n");
				pseudo_abort();
			}
			PSEUDO_DEBUG("Src: %p, Dest: %p",
					(void *)buf_bss,
					(void *)load_elf.stat.start_bss_dyn);
			ret = ve_send_data(handle,
					(uint64_t)load_elf.stat.start_bss_dyn,
					diff,
					(uint64_t *)buf_bss);
			if (ret) {
				PSEUDO_DEBUG("failed to send data from VH to VE"
						" memory");
				fprintf(stderr, "Failed to send data from VH to VE"
						" memory\n");
				pseudo_abort();
			}
			PSEUDO_DEBUG("CLEAR BSS: LIBC, VE send data pass");

			free(buf_bss);
		}
	} else {
		PSEUDO_DEBUG("NO BSS SECTION(DYN)");
	}
	close(load_elf.stat.fd);
	close(load_elf.stat.fd_dyn);

}
