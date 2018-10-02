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
 * @file  elf_dump.c
 * @brief To generate coredump.
 *
 *       This file contains the functions that help in dumping the
 *	 core information of VE processs into the file.
 *
 * @internal
 * @author Pseudo/Core Dump
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "veos.h"
#include "pmap.h"

static __thread int isnote;
static __thread int doalign = 1;
static __thread void *free_mem[MAX_FREE_BLOCK];
static __thread int blockIdx;

/**
 * @brief Creating the ELF header.
 *
 * @param[out] dumpImage to store the ELF header.
 * @param[in] number of program headers.
 */
void create_ehdr(char *dumpImage,
		int count)
{
	char buf[] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 16};
	(void)strncpy((char *)((Elf64_Ehdr *)dumpImage)->e_ident,
			buf, sizeof(buf));
	((Elf64_Ehdr *)dumpImage)->e_type = ET_CORE;
	((Elf64_Ehdr *)dumpImage)->e_machine = EM_VE;
	((Elf64_Ehdr *)dumpImage)->e_version = EV_CURRENT;
	((Elf64_Ehdr *)dumpImage)->e_entry = NUL;
	((Elf64_Ehdr *)dumpImage)->e_phoff = sizeof(Elf64_Ehdr);
	((Elf64_Ehdr *)dumpImage)->e_shoff = NUL;
	((Elf64_Ehdr *)dumpImage)->e_flags = NUL;
	((Elf64_Ehdr *)dumpImage)->e_ehsize = sizeof(Elf64_Ehdr);
	((Elf64_Ehdr *)dumpImage)->e_phentsize = sizeof(Elf64_Phdr);
	((Elf64_Ehdr *)dumpImage)->e_phnum = (uint16_t)count;
	((Elf64_Ehdr *)dumpImage)->e_shentsize = NUL;
	((Elf64_Ehdr *)dumpImage)->e_shnum = NUL;
	((Elf64_Ehdr *)dumpImage)->e_shstrndx = NUL;
}

/**
 * @brief Creating program headers.
 *
 * @param[out] phdrImage used to store the Phdr.
 * @param[in] memroy map of VE process.
 * @param[in] idx is index for Phdr.
 * @param[in] count for Note header offset.
 * @param[in] note_size is the size of note section.
 *
 * @On success return 0, else -ve value
 */
int create_phdr(struct dump_params *cprm,
		char *phdrImage,
		struct _psuedo_pmap *ve_pmap,
		int idx, int count, int note_size)
{
	int ret = 0;
	char *buf = NULL;
	uint64_t offset = 0;
	ssize_t tlen = 0;
	ssize_t tret = 0;
	uint64_t memsize = 0;
	uint64_t buffer_size = 0;
	uint64_t default_dump_size = 0;
	uint64_t start = 0;

	if (!isnote) {
		((Elf64_Phdr *)phdrImage)->p_type = PT_NOTE;
		((Elf64_Phdr *)phdrImage)->p_flags = NUL;
		((Elf64_Phdr *)phdrImage)->p_offset = sizeof(Elf64_Ehdr) +
			(sizeof(Elf64_Phdr) * count);
		((Elf64_Phdr *)phdrImage)->p_vaddr = NUL;
		((Elf64_Phdr *)phdrImage)->p_paddr = NUL;
		((Elf64_Phdr *)phdrImage)->p_filesz = note_size;
		((Elf64_Phdr *)phdrImage)->p_memsz = NUL;
		((Elf64_Phdr *)phdrImage)->p_align = NUL;
		isnote = 1;
		VEOS_DEBUG("Note initialized: offset: %p, size: %d, isnote: %d",
				(void *)(sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * count)),
				note_size, isnote);
	} else {
		if (!IS_ALIGNED(cprm->f_post, PAGE_SIZE))
			offset = (cprm->f_post & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
		else
			offset = (uint64_t)cprm->f_post;
		((Elf64_Phdr *)phdrImage)->p_type = PT_LOAD;
		((Elf64_Phdr *)phdrImage)->p_flags = (uint32_t)ve_pmap->prmsn;
		((Elf64_Phdr *)phdrImage)->p_offset = offset;
		((Elf64_Phdr *)phdrImage)->p_vaddr = ve_pmap->begin;
		((Elf64_Phdr *)phdrImage)->p_paddr = NUL;
		((Elf64_Phdr *)phdrImage)->p_filesz = ve_pmap->end - ve_pmap->begin;
		((Elf64_Phdr *)phdrImage)->p_memsz = ve_pmap->end - ve_pmap->begin;
		((Elf64_Phdr *)phdrImage)->p_align = PAGE_SIZE;

		tlen = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * idx);
		if ((cprm->pos + sizeof(Elf64_Phdr)) > cprm->limit.rlim_cur) {
			VEOS_ERROR("Prog coredump size %p is greater than limit %p",
					(void *)(cprm->pos + sizeof(Elf64_Phdr)),
					(void *)(cprm->limit.rlim_cur));
			ret = -1;
			goto end;
		}
		tret = lseek(cprm->fd, tlen, SEEK_SET);
		if (tret == -1) {
			VEOS_ERROR("Failed to seek to specified length: %ld"
					" and return val is %ld", tlen, tret);
			ret = -1;
			goto end;
		}
		tret = write(cprm->fd, phdrImage, (sizeof(Elf64_Phdr)));
		if (tret <= 0) {
			ret = -errno;
			VEOS_ERROR("Failed to dump Ehdr/Phdr: %ld: %s",
					tret, strerror(-ret));
			ret = -1;
			goto end;
		}
		if (-1 == fsync(cprm->fd)) {
			ret = -errno;
			VEOS_ERROR("Failed to sync data into core file: %s",
					strerror(-ret));
			ret = -1;
			goto end;
		}
		VEOS_DEBUG("DUMPING %d Program header complete", idx);

		memsize = ((Elf64_Phdr *)phdrImage)->p_memsz;
		default_dump_size = DEFAULT_DUMP_SIZE;
		start = (uint64_t)ve_pmap->begin;

		do {
			/* Segement size could be as big as memory
			 * allocated to VE card. To avoid large memory
			 * request to VH, always dump segment information
			 * in size of less than or equal to 64MB.
			 */
			if (memsize >= default_dump_size)
				buffer_size = default_dump_size;
			else
				buffer_size = memsize;

			buf = (char *)calloc(1, buffer_size);
			if (NULL == buf) {
				ret = -errno;
				VEOS_CRIT("Failed to allocate buffer for"
					"creating segment: %s",
					strerror(-ret));
				goto end;
			}
			if ((void *)start && (ve_pmap->prmsn)) {
				if (-1 == amm_dma_xfer(
					VE_DMA_VEMVA_WO_PROT_CHECK,
						(uint64_t)start,
						cprm->tsk->pid,
						VE_DMA_VHVA,
						(uint64_t)(buf),
						(int)getpid(),
						buffer_size,
						0)) {
					VEOS_ERROR("failed to "
							"get segment data");
					ret = -1;
					goto end1;
				}
			}
			VEOS_DEBUG("GOING TO DUMP: pos: %p, begin: %p,"
					" memsize: %p perm: %d",
					(void *)cprm->f_post, (void *)start,
					(void *)buffer_size,
					(ve_pmap->prmsn));

			if (!(dump_core_info(cprm, buf,
						buffer_size, doalign))) {
				VEOS_ERROR("Dumping LOAD segments fail");
				ret = -1;
				goto end1;
			}
			doalign = 0;
			start += buffer_size;
			free(buf);
			buf = NULL;

			if (memsize >= default_dump_size)
				memsize -= default_dump_size;
			else
				break;
		} while (memsize > 0);
	}
end1:
	if (buf)
		free(buf);
end:
	return ret;
}

/**
 * @brief Size of note section.
 *
 * @param[in] en is memory ELF of note.
 *
 * @return the size of note section.
 */
static int notesize(struct memelfnote *en)
{
	int sz = 0;

	sz = sizeof(struct elf64_note);
	sz += roundups((en->name ? strlen(en->name) : 0) + 1, 4);
	sz += roundups(en->datasz, 4);

	return sz;
};

/**
 * @brief fill the note section.
 *
 * @param[in] note is the memory ELf of note.
 * @param[in] name is the note name
 * @param[in] type is type of process
 * @param[in] sz is the size of note section
 * @param[in] data is the informatio of the that note
 */
static void fill_note(struct memelfnote *note,
			const char *name, int type,
			unsigned int sz, void *data)
{
	note->name = name;
	note->type = type;
	note->datasz = sz;
	note->data = data;
}

static struct user_regset ve_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct ve_user_regs) / sizeof(uint64_t),
		.size = sizeof(uint64_t), .align = sizeof(uint64_t),
	},
	[REGSET_FP] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct ve_user_vregs) / sizeof(uint64_t),
		.size = sizeof(uint64_t), .align = sizeof(uint64_t),
	},
};


static const struct user_regset_view user_ve_view = {
	.name = "ve", .e_machine = EM_VE,
	.regsets = ve_regsets, .n = SIZE(ve_regsets)
};

	const struct user_regset_view *
task_user_regset_view(
		struct ve_task_struct *task)
{
	return &user_ve_view;
}

/**
 * @brief To get size of Note section.
 *
 * @param[in] info Information of ELF note section.
 *
 * @return size of whole ELF note section.
 */
static int  get_note_info_size(struct elf_note_info *info)
{
	return info->size;
}

/**
 * @brief Dumping the information into the file.
 *
 * @param[in] cprm pointer to dump_params.
 * @param[in] addr data to be dump.
 * @param[in] nr size to be dump.
 * @param[in] check true for Phdr, false for Note.
 *
 * @return On success 1, On failure 0.
 */
int dump_core_info(struct dump_params *cprm,
		const void *addr,
		loff_t nr, bool check)
{

	int fd = -1;
	ssize_t n = -1;
	ssize_t tret = 0;
	loff_t tlen = cprm->f_post;
	uint64_t offdiff = 0;
	char *loc_buf = NULL;

	VEOS_DEBUG("Dump emit size to write nr: %p "
			"offset in file %p", (void *)nr, (void *)tlen);

	tret = lseek(cprm->fd, tlen, SEEK_SET);
	if (tret == -1) {
		VEOS_ERROR("Failed to seek to specified length: %ld"
				" and return val is %ld", tlen, tret);
		return 0;
	}

	if ((cprm->f_post + nr) > cprm->limit.rlim_cur) {
		VEOS_ERROR("coredump size %p is greater than limit %p",
				(void *)(cprm->f_post + nr),
				(void *)(cprm->limit.rlim_cur));
		return 0;
	}
	fd = cprm->fd;
	if (check) {
		if (!IS_ALIGNED(tlen, PAGE_SIZE)) {
			offdiff = ((tlen & ~(PAGE_SIZE - 1))
					+ PAGE_SIZE) - tlen;
			loc_buf = calloc(1, offdiff);
			if (NULL == loc_buf) {
				VEOS_CRIT("Failed to allocate buffer %s",
				strerror(errno));
				return 0;
			}
			if (0 > write(fd, loc_buf, offdiff)) {
				VEOS_ERROR("Failed to Initialize core file "
						"with zero");
				free(loc_buf);
				return 0;
			}
			if (-1 == fsync(fd)) {
				VEOS_ERROR("Failed to sync data into core file,"
						" %s", strerror(errno));
				free(loc_buf);
				return 0;
			}
			VEOS_DEBUG("Initialize with zero, bytes: %p, len: %p"
					, (void *)offdiff, (void *)cprm->f_post);
			cprm->f_post += offdiff;
			cprm->pos += offdiff;
		}
		if (loc_buf)
			free(loc_buf);
	}
	VEOS_DEBUG("Before dumping: %p", (void *)cprm->f_post);
	while (nr > 0) {
		n = write(fd, addr, nr);
		if (n <= 0) {
			VEOS_ERROR("Failed to dump data in core file,"
					"ret: %ld", n);
			return 0;
		}
		if (-1 == fsync(fd)) {
			VEOS_ERROR("Failed to sync data into core file,"
					" %s", strerror(errno));
			return 0;
		}

		VEOS_DEBUG("Writes no of bytes: %ld", n);
		cprm->f_post += n;
		cprm->pos += n;
		addr += n;
		nr -= n;
	}
	return 1;
}

/**
 * @brief Core dumping helper function.
 *
 * @param[in] cprm pointer to dump_params.
 * @param[in] nr size to be dump.
 *
 * @return On success 1, On failure 0.
 */
int dump_skip(struct dump_params *cprm,
		loff_t nr)
{
	static char zeroes[PAGE_SIZE];

	while (nr > PAGE_SIZE) {
		if (!dump_core_info(cprm, zeroes, PAGE_SIZE, 0))
			return 0;
		nr -= PAGE_SIZE;
	}

	return dump_core_info(cprm, zeroes, nr, 0);
}

/**
 * @brief Core dumping helper function.
 *
 * @param[in] cprm pointer to dump_params.
 * @param[in] align used to mask.
 *
 * @return On success 1, On failure 0.
 */
int dump_align(struct dump_params *cprm,
		int align)
{
	unsigned mod = cprm->f_post & (align - 1);
	if (align & (align - 1))
		return 0;
	return mod ? dump_skip(cprm, align - mod) : 1;
}

/**
 * @brief Note section in temporary image.
 *
 * @param[in] men pointer to struct memelfnote.
 * @param[in] cprm pointer to struct dump_params.
 *
 * @return On success 1, On failure 0.
 */
static int writenote(struct memelfnote *men,
		struct dump_params *cprm)
{
	struct elf64_note en = {0};

	en.n_namesz = strlen(men->name) + 1;
	en.n_descsz = men->datasz;
	en.n_type = (uint32_t)men->type;

	return dump_core_info(cprm, &en, sizeof(en), 0) &&
		dump_core_info(cprm, men->name, en.n_namesz, 0) &&
		dump_align(cprm, ALIGNED_4BYTE) &&
		dump_core_info(cprm, men->data, men->datasz, 0) &&
		dump_align(cprm, ALIGNED_4BYTE);
}

/**
 * @brief Remove the white spaces from end of string.
 *
 * @param[in] str is pointer to string.
 */
int trim_space(char *str)
{
	int i = 0;
	int len = strlen(str);

	if (str[len-1] == ' ') {
		str[len-1] = 0;
		i = trim_space(str);
		return i;
	} else
		return 0;
}

/**
 * @brief Initialize the VE process information.
 *
 * @param[out] psinfo pointer to Process information
 * @param[in] p pointer to ve_task_struct.
 */
void fill_psinfo(struct elf_prpsinfo *psinfo,
		struct ve_task_struct *p)
{
	unsigned int i = 0;
	unsigned int len = 0;
	uint64_t addr = 0;
	uint64_t addr_align = 0;
	int offset = 0;
	int psarg_off = 0;
	long long *areap_8b = 0;
	int argc = 0;
	char temp[ELF_PRARGSZ] = {0};

	memset(psinfo, 0, sizeof(struct elf_prpsinfo));
	areap_8b = (long long *)p->p_ve_mm->argv_addr;

	VEOS_DEBUG("fill_psinfo: arg_addr: %lx, dest_addr: %p",
			p->p_ve_mm->argv_addr,
			(void *)&(psinfo->pr_psargs));

	len = ELF_PRARGSZ-1;
	argc = p->p_ve_mm->argv_size;
	while (argc--) {
		if (NULL != (void *)areap_8b) {
			if (-1 == amm_dma_xfer(VE_DMA_VEMVA_WO_PROT_CHECK,
						(uint64_t)areap_8b,
						p->pid,
						VE_DMA_VHVA,
						(uint64_t)(&addr),
						(int)getpid(),
						sizeof(uint64_t), 0)) {
				VEOS_WARN("ve_recv_data failed to "
						"receive argv");
				break;
			}
			VEOS_DEBUG("fill_psinfo: ARGV: %p", (void *)addr);

			addr_align = (addr & ~(8 - 1)); /* 8 byte align */
			offset = addr - addr_align;

			if (-1 == amm_dma_xfer(VE_DMA_VEMVA_WO_PROT_CHECK,
						(uint64_t)addr_align,
						p->pid,
						VE_DMA_VHVA,
						(uint64_t)(&temp),
						(int)getpid(), ELF_PRARGSZ, 0)) {
				VEOS_WARN("ve_recv_data failed to "
						"receive argv2");
				break;
			}

			if ((len > 0) &&
					((psarg_off + strlen(temp+offset))
					 < ELF_PRARGSZ)) {
				memcpy(psinfo->pr_psargs + psarg_off,
						temp+offset, strlen(temp+offset));
				len -= (strlen(temp+offset) + 1);
				psarg_off += strlen(temp+offset) + 1;
			} else
				break;

		}
		areap_8b++;
	}

	len = ELF_PRARGSZ-1;
	/* Changes as per #427 */
	argc = p->p_ve_mm->argv_size;
	if (argc)
		for (i = 0; i < len; i++)
			if (psinfo->pr_psargs[i] == 0) {
				psinfo->pr_psargs[i] = ' ';
				argc--;
				if (argc == 0)
					break;
			}
	psinfo->pr_psargs[i] = 0;
	VEOS_DEBUG("len : %d, ARGC: %d ARGV %s"
			, i, argc, psinfo->pr_psargs);

	(void)trim_space(psinfo->pr_psargs);

	VEOS_DEBUG("After removing space, ARGV: %s", psinfo->pr_psargs);

	psinfo->pr_ppid = (p->parent)->pid;
	psinfo->pr_pid = p->pid;
	psinfo->pr_pgrp = 0;
	psinfo->pr_sid = 0;

	switch (p->ve_task_state) {
	case WAIT:
		psinfo->pr_sname = 'S';
		break;
	case RUNNING:
		psinfo->pr_sname = 'R';
		break;
	case ZOMBIE:
		psinfo->pr_sname = 'Z';
		break;
	case STOP:
		psinfo->pr_sname = 'T';
		break;
	case EXIT_DEAD:
		psinfo->pr_sname = 'D';
		break;
	case P_INVAL:
		psinfo->pr_sname = 'I';
		break;
	}
	psinfo->pr_state = p->ve_task_state;
	psinfo->pr_zomb = (psinfo->pr_state == ZOMBIE) ? 'Z' : ' ';
	psinfo->pr_nice = p->priority;
	psinfo->pr_flag = p->flags;
	psinfo->pr_uid = p->uid;
	psinfo->pr_gid = p->gid;
	strncpy(psinfo->pr_fname, p->ve_comm, sizeof(psinfo->pr_fname));
}

/**
 * @brief Initialize VE process status except VE registers.
 *
 * @param[out] prstatus pointer to status of process
 * @param[in] p pointer to ve_task_struct
 * @param[in] signr signal number
 */
static void fill_prstatus(struct elf_prstatus *prstatus,
		struct ve_task_struct *p, long signr)
{

	struct timeval tp = {0};

	tp.tv_sec = p->exec_time/SECS_TO_MICROSECONDS;
	tp.tv_usec = p->exec_time%SECS_TO_MICROSECONDS;

	prstatus->pr_info.si_signo = prstatus->pr_cursig = signr;
	prstatus->pr_sigpend = (unsigned long)p->sigpending;
	prstatus->pr_sighold = (unsigned long)p->sigpending;
	prstatus->pr_ppid = p->parent->pid;
	prstatus->pr_pid = p->pid;
	prstatus->pr_pgrp = 0;
	prstatus->pr_sid = 0;
	prstatus->pr_utime = (struct timeval){0};
	(void)memcpy((void *)&prstatus->pr_stime, (void *)&tp, sizeof(struct timeval));
	prstatus->pr_cutime = (struct timeval){0};
	prstatus->pr_cstime = (struct timeval){0};
}

/**
 * @brief Initialize signal information of VE process.
 *
 * @param[out] note pointer to memory ELf of note.
 * @param[in] csigdata pointer to user_siginfo_t structure.
 * @param[in] siginfo pointer to siginfo_t structure.
 */
static void fill_siginfo_note(struct memelfnote *note,
		user_siginfo_t *csigdata,
		const siginfo_t *siginfo)
{
	(void)memcpy((char *)(user_siginfo_t *) csigdata, siginfo, sizeof(*csigdata));
	fill_note(note, "CORE", NT_SIGINFO, sizeof(*csigdata), csigdata);
}

/**
 * @brief Initialize auxv of VE process.
 *
 * @param[out] note pointer to memory ELf of note.
 * @param[in] p pointer to ve_task_struct
 * @return On success 0. On failure, negative value
 */
static int fill_auxv_note(struct memelfnote *note,
		struct ve_task_struct *p)
{
	int len = 0;
	int ret = 0;

	len = (p->p_ve_mm->auxv_size) * (sizeof(Elf64_Off) * 2);
	Elf64_Off *auxv = (Elf64_Off *)calloc(len, sizeof(Elf64_Off));
	if (NULL == auxv) {
		VEOS_CRIT("auxv: cal memory fails %s", strerror(errno));
		ret = -1;
		goto end;
	}
	free_mem[blockIdx++] = (void *)auxv;
	VEOS_DEBUG("fill_auxv: len: %d,  auxv_addr: %lx",
			len, p->p_ve_mm->auxv_addr);

	fill_note(note, "CORE", NT_AUXV, len, auxv);

	if (NULL != (void *)p->p_ve_mm->auxv_addr) {
		if (-1 == amm_dma_xfer(VE_DMA_VEMVA_WO_PROT_CHECK,
					(uint64_t)p->p_ve_mm->auxv_addr,
					p->pid,
					VE_DMA_VHVA,
					(uint64_t)(auxv),
					(int)getpid(), len, 0)) {
			VEOS_WARN("ve_recv_data failed to "
					"receive auxv");
		}
	}
end:
	return ret;
}

/**
 * @brief Initialize the file information of VE process.
 *
 * @param[out] note pointer to memory ELf of note.
 * @param[in] p pointer to ve_task_struct
 * @param[in] ve_pmap pointer to memory map of VE.
 * @param[in] map_count number of ve pmap entries.
 *
 * @return On success 0. On failure, negative value
 */
static int fill_files_note(struct memelfnote *note,
		struct ve_task_struct *p_ve_task,
		struct _psuedo_pmap *ve_pmap,
		int map_count)
{
	long *data = NULL;
	unsigned int count = 0;
	unsigned int size = 0;
	unsigned int names_ofs = 0;
	unsigned int remaining = 0;
	unsigned int n = 0;
	struct _psuedo_pmap *pmap = NULL;
	long *start_end_ofs = NULL;
	char *name_curpos = NULL, *name_base = NULL;
	const char *filename = NULL;

	pmap = ve_pmap;
	count = (unsigned int)map_count;
	size = count * FILEINFO_IN_BYTES;
	names_ofs = (BUF_2BYTES + BUF_3BYTES * count) * sizeof(data[0]);

	if (size >= MAX_FILE_NOTE_SIZE) { /* paranoia check */
		VEOS_ERROR("files fill: size is greater than MAX_FILE_NOTE_SIZE");
		return -EINVAL;
	}
	size = roundups(size, PAGE_SIZE);
	data = malloc(size);
	if (NULL == data) {
		VEOS_CRIT("files fill: mal memory fails: %s", strerror(errno));
		return -ENOMEM;
	}
	/*MEMSET*/
	memset(data, '\0', size);
	free_mem[blockIdx++] = (void *)data;
	start_end_ofs = data + BUF_2BYTES;
	name_base = name_curpos = ((char *)data) + names_ofs;
	remaining = size - names_ofs;

	count = 0;
	while (pmap != NULL) {
		if ((!(strcmp(pmap->mapname, "[stack]"))) ||
				(!(strcmp(pmap->mapname, "[heap]"))) ||
				(!(strcmp(pmap->mapname, "[anon]"))) ||
				(!(strcmp(pmap->mapname, "")))) {
			pmap = pmap->next;
			continue;
		}
		int length = 0;
		length = strlen(pmap->mapname) + 1;
		filename = (char *)calloc(1, length);
		if (NULL == filename) {
			VEOS_CRIT("files fill: cal memory fails, %s",
			strerror(errno));
			return -ENOMEM;
		}
		(void)memcpy((void *)filename, pmap->mapname, length);

		remaining -= length ;
		(void)memcpy((void *)name_curpos, (void *)filename, length);
		name_curpos += length;

		*start_end_ofs++ = pmap->begin;
		*start_end_ofs++ = pmap->end;
		*start_end_ofs++ = pmap->foo; /* Page Offset of files */
		pmap = pmap->next;
		count++;
		free((void *)filename);
	}

	/* Now we know exact count of files, can store it */
	data[0] = count;
	data[1] = PAGE_SIZE;

	/*
	 * Count usually is less than map_count,
	 * we need to move filenames down.
	 */
	n = map_count - count;
	if (n != 0) {
		unsigned shift_bytes = n * BUF_3BYTES * sizeof(data[0]);
		memmove(name_base - shift_bytes, name_base,
				name_curpos - name_base);
		name_curpos -= shift_bytes;
	}

	size = name_curpos - (char *)data;
	fill_note(note, "CORE", NT_FILE, size, data);
	return 0;
}

/**
 * @brief Initialize the thread core register.
 *
 * @param[out] t pointer to elf_thread_core_info
 * @param[out] total size of Note section
 * @param[in] p pointer to ve_task_struct
 * @param[in] sub subscript of a structure.
 * @param[in] signr sigal number
 *
 * @return On success 1, 0 on failure.
 */
static int fill_thread_core_info(struct elf_thread_core_info *t,
		const struct user_regset_view *view,
		long signr, size_t *total)
{
	int retval = 1;
	int i = 1;

	fill_prstatus(&t->prstatus, t->task, signr);

	VEOS_DEBUG("fill_prstatus() finish size: "
			"pr_reg: %ld, ve_thread: %ld",
			sizeof(t->prstatus.pr_reg),
			sizeof(struct ve_user_regs));

	(void)memcpy(t->prstatus.pr_reg, t->task->p_ve_thread,
			sizeof(struct ve_user_regs));

	fill_note(&t->notes[0], "CORE", NT_PRSTATUS,
			sizeof(t->prstatus), &t->prstatus);
	*total += notesize(&t->notes[0]);

	for (i = 1; i < view->n; ++i) {
		const struct user_regset *regset = &view->regsets[i];
		VEOS_DEBUG("no of VREGS: %d, regset->size: %d",
				regset->n, regset->size);
		size_t size = regset->n * regset->size;
		void *data = malloc(size);
		if (NULL == data) {
			VEOS_CRIT("Failed to alloc memory: %s",
				strerror(errno));
			return 0;
		}
		/*MEMSET*/
		memset(data, '\0', size);
		free_mem[blockIdx++] = data;
		VEOS_DEBUG("fill_prstatus()"
				"pr_fpreg: %ld, ve_thread: %ld",
				size,
				sizeof(struct ve_user_vregs));
		(void)memcpy(data,
				(void *)(t->task->p_ve_thread) +
				sizeof(struct ve_user_regs),
				sizeof(struct ve_user_vregs));
		if (regset->core_note_type != NT_PRFPREG)
			fill_note(&t->notes[i], "LINUX",
					regset->core_note_type,
					size, data);
		else {
			t->prstatus.pr_fpvalid = 1;
			fill_note(&t->notes[i], "CORE",
					NT_PRFPREG, size, data);
		}
		*total += notesize(&t->notes[i]);
	}

	return retval;
}

/**
 * @brief Initialize the Note section.
 *
 * @param[out] info pointer to elf_note_info.
 * @param[in] siginfo pointer to siginfo_t.
 * @param[in] p_ve_task pointer to ve_task_struct.
 * @param[in] ve_pmap pointer to memory map of VE.
 *
 * @return On success 0, On failure, -ve value.
 */
int fill_note_info(struct elf_note_info *info,
		const siginfo_t *siginfo,
		struct ve_task_struct *p_ve_task,
		struct _psuedo_pmap *ve_pmap)
{
	struct ve_task_struct *group_leader = NULL, *tmp = NULL;
	struct ve_task_struct *head = NULL;
	struct list_head *p = NULL, *n = NULL;
	const struct user_regset_view *view = task_user_regset_view(p_ve_task);
	struct elf_thread_core_info *t = NULL;
	struct elf_thread_core_info *temp_thread = NULL;
	struct elf_prpsinfo *psinfo = NULL;
	unsigned int i = 0;
	int ret = 0;

	info->size = 0;
	info->thread = NULL;
	group_leader = p_ve_task->group_leader;
	head = group_leader;

	psinfo = (struct elf_prpsinfo *)malloc(sizeof(*psinfo));
	if (NULL == psinfo) {
		ret = -errno;
		VEOS_CRIT("Failed(%s) to create buffer to store process"
			" info", strerror(-ret));
		info->psinfo.data = NULL; /* So we don't free this wrongly */
		goto end;
	}

	/*MEMSET*/
	memset(psinfo, '\0', sizeof(*psinfo));
	free_mem[blockIdx++] = (void *)psinfo;
	fill_note(&info->psinfo, "CORE", NT_PRPSINFO,
				 sizeof(*psinfo), psinfo);

	/*
	 * Figure out how many notes we're going to need for each thread.
	 */
	info->thread_notes = 0;
	for (i = 0; i < view->n; ++i)
		if (view->regsets[i].core_note_type != 0)
			++info->thread_notes;

	VEOS_DEBUG("thread notes: %d, number of regsets: %d",
			 info->thread_notes, view->n);
	/*
	 * Allocate a structure for each thread.
	 */

	if (!list_empty(&group_leader->thread_group)) {
		list_for_each_safe(p, n, &group_leader->thread_group) {

			tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);

			t = (struct elf_thread_core_info *)malloc(
					offsetof(struct elf_thread_core_info,
						notes[info->thread_notes]));
			if (NULL == t) {
				VEOS_CRIT(
					"Failed(%s) to allocate buffer to"
					" store thread structure",
					strerror(errno));
				ret = -1;
				goto end;
			}

			/*MEMSET*/
			memset(t, '\0', offsetof(struct elf_thread_core_info, notes[info->thread_notes]));
			t->task = tmp;
			if (tmp == head || !info->thread) {
				t->next = info->thread;
				info->thread = (struct elf_thread_core_info *)malloc(
						offsetof(struct elf_thread_core_info,
							notes[info->thread_notes]));
				if (NULL == info->thread) {
					VEOS_CRIT("Failed to allocate buffer to store"
						" thread information: %s", strerror(errno));
					ret = -1;
					goto end;
				}
			/*MEMSET*/
			memset(info->thread, '\0',
				offsetof(struct elf_thread_core_info, notes[info->thread_notes]));
				info->thread->task = head;
				info->thread->next = t;
			} else {
				/*
				 * Make sure to keep the original task at
				 * the head of the list.
				 */
				t->next = NULL;
				temp_thread =  info->thread;
				while (temp_thread->next != NULL)
					temp_thread = temp_thread->next;
				temp_thread->next = t;
			}
		}
	} else {
		info->thread = (struct elf_thread_core_info *)malloc(
				offsetof(struct elf_thread_core_info,
					notes[info->thread_notes]));
		if (NULL == info->thread) {
			VEOS_CRIT("Failed to allocate buffer to store"
					" thread information %s", strerror(errno));
			ret = -1;
			goto end;
		}
		/*MEMSET*/
		memset(info->thread, '\0', offsetof(struct elf_thread_core_info, notes[info->thread_notes]));
		info->thread->task = head;
		info->thread->next = NULL;
	}

	for (t = info->thread; t != NULL; t = t->next) {
		if (!fill_thread_core_info(t, view,
				 siginfo->si_signo, &info->size)) {
			VEOS_ERROR("Fail to initialize the thread core"
					" register");
			ret = -1;
			goto end;
		}
	}
	VEOS_DEBUG("fill_thread_core_info() finish %ld", info->size);
	fill_psinfo(psinfo, p_ve_task);
	info->size += notesize(&info->psinfo);

	VEOS_DEBUG("fill_psinfo() finish: %ld", info->size);

	fill_siginfo_note(&info->signote, &info->csigdata, siginfo);
	info->size += notesize(&info->signote);
	VEOS_DEBUG("fill_siginfo_note() finish: %ld", info->size);

	if (fill_auxv_note(&info->auxv, p_ve_task) == 0) {
		info->size += notesize(&info->auxv);
		VEOS_DEBUG("fill_auxv_note() finish: %ld", info->size);
	} else {
		VEOS_ERROR("filling auxv fails: %ld", info->size);
		ret = -1;
		goto end;
	}

	if (fill_files_note(&info->files, p_ve_task, ve_pmap, info->map_count) == 0) {
		info->size += notesize(&info->files);
		VEOS_DEBUG("fill_files_note() finish: %ld", info->size);
	} else {
		VEOS_ERROR("filling files notes fail");
		ret = -1;
	}
end:
	VEOS_DEBUG("fill_note_info() return :%d", ret);
	return ret;
}

/**
 * @brief Initialize the note for each thread.
 *
 * @param[in] info pointer to elf_note_info.
 * @param[in] cprm pointer to dump_params.
 *
 * @return On success 0, On failure, 1.
 */
static int write_note_info(struct elf_note_info *info,
		struct dump_params *cprm)
{
	bool first = true;
	int i = 1;
	int ret = 0;

	struct elf_thread_core_info *t = info->thread;

	do {
		VEOS_DEBUG("In loop, t: %p", (void *)t);

		if (!writenote(&t->notes[0], cprm))
			return -1;
		VEOS_DEBUG("NOTE[0], : %p", (void *)&t->notes[0]);

		if (first && !writenote(&info->psinfo, cprm))
			return -1;

		VEOS_DEBUG("PSINFO, : %p", (void *)&info->psinfo);

		if (first && !writenote(&info->signote, cprm))
			return -1;

		VEOS_DEBUG("SIG, : %p", (void *)&info->signote);

		if (first && !writenote(&info->auxv, cprm))
			return -1;

		VEOS_DEBUG("AUXV");

		if (first && info->files.data &&
				!writenote(&info->files, cprm))
			return -1;

		VEOS_DEBUG("Files");

		for (i = 1; i < info->thread_notes; ++i) {
			if (t->notes[i].data &&
					!writenote(&t->notes[i], cprm))
				return -1;
			VEOS_DEBUG("NOTE[%d], : %p", i,
					(void *)&t->notes[i]);
		}

		first = false;
		t = t->next;
	} while (t);

	return ret;
}

/**
 * @brief Initialize the core ELF information.
 *
 * @param[in] ve_pmap pointer to memory map of VE.
 * @param[in] ve_cprm pointer to dump_params.
 * @param[in] map_count count of ve pmap.
 *
 * @return On success 1, On failure, 0.
 */
int fill_ve_core_data(struct _psuedo_pmap *ve_pmap,
		struct dump_params *ve_cprm,
		int map_count)
{
	int fd = -1;
	int idx = 1;
	int count = 0;
	int retval = 0;
	int sz = 0;
	char buf[2] = {0};
	char fname[PATH_MAX] = {0};
	char *phdrImage = NULL;
	struct _psuedo_pmap *head = NULL;
	struct elf_note_info info = { };

	VEOS_TRACE("In Func");
	VEOS_DEBUG("Segments to be dump:");
	head = ve_pmap;
	while (NULL != ve_pmap) {
		if (!(strcmp(ve_pmap->mapname, ""))) {
			ve_pmap = ve_pmap->next;
			continue;
		}
		if ((!(strcmp(ve_pmap->mapname, "[stack]"))) ||
				(!(strcmp(ve_pmap->mapname, "[heap]"))) ||
				(!(strcmp(ve_pmap->mapname, "[anon]")))) {
			ve_pmap->flag = 1;
			count++;
			ve_pmap = ve_pmap->next;
			continue;
		}
		if ((strcmp(ve_pmap->mapname, fname)) != 0) {
			memset(buf, 0, sizeof(buf));
			fd = open((char *)ve_pmap->mapname, O_RDONLY);
			if (0 > fd) {
				retval = -errno;
				VEOS_ERROR("Failed to get VE ELF file"
						" descriptor");
				VEOS_DEBUG("%s: %s", ve_pmap->mapname,
						strerror(-retval));
				goto end;
			}
			VEOS_DEBUG("filename: %s, fd: %d", ve_pmap->mapname, fd);
			if (0 > (pread(fd, buf, 1, 0))) {
				retval = -errno;
				VEOS_ERROR("Failed to read VE ELF");
				VEOS_DEBUG("%s: %s", ve_pmap->mapname,
						strerror(-retval));
				close(fd);
				goto end;
			}
			(void)strncpy(fname, (char *)ve_pmap->mapname,
					sizeof(fname));
			close(fd);

		}
		/* 127 ensure that the file is ELF */
		if (FILE_ELF == buf[0]) {
			VEOS_DEBUG(
					"%p - %p, %s, %s",
					(void *)ve_pmap->begin,
					(void *)ve_pmap->end,
					ve_pmap->perm,
					ve_pmap->mapname);
			ve_pmap->flag = 1;
			count++;
		}
		ve_pmap = ve_pmap->next;
	}
	ve_pmap = head;

	VEOS_DEBUG("Total load segments: %d, vepmap count: %d", count, map_count);
	if (0 == count) {
		VEOS_ERROR("No load segment to be dump");
		retval = -1;
		goto end;
	}

	count++;		/* Increment for Note section */
	ve_cprm->f_post = 0;	/* File position is set to zero */
	ve_cprm->pos = 0;	/* File position is set to zero */

	/* Creating ELF & Program Header */
	ve_cprm->vaddr = (char *)calloc(1, (sizeof(Elf64_Ehdr)+(sizeof(Elf64_Phdr) * (count))));

	if (NULL == ve_cprm->vaddr) {
		retval = -errno;
		VEOS_CRIT("Failed(%s) to allocate internal buffer",
			strerror(-retval));
		VEOS_DEBUG("%s: %s", "Failed to create buffer to store"
			" ELF and program header",
				strerror(-retval));
		goto end;
	}

	create_ehdr(ve_cprm->vaddr, count);
	if(!(dump_core_info(ve_cprm, ve_cprm->vaddr, sizeof(Elf64_Ehdr), 0))) {
		VEOS_ERROR("Dumping LOAD segments fail");
		retval = -1;
		goto end;

	}
	VEOS_DEBUG("Dumping ELF header complete");

	/*
	 * Collect all the non-memory information about the process for the
	 * notes.  This also sets up the file header.
	 */
	info.map_count = map_count;
	if (fill_note_info(&info, &(ve_cprm->siginfo), (ve_cprm->tsk), ve_pmap)) {
		VEOS_ERROR("Failed to fill Note section");
		retval = -1;
		goto end;
	}

	/* Return error if SIGINT occur */
	if (ve_cprm->tsk->sighand->got_sigint || terminate_flag) {
		VEOS_ERROR("got SIGINT, coredump stopped");
		retval = -EINVAL;
		goto end;
	}

	/* Write notes phdr entry */
	sz = get_note_info_size(&info);

	VEOS_DEBUG("create_note_segment, note size: %d", sz);

	/* Insert "Note" Section in Phdr */
	phdrImage = (ve_cprm->vaddr + sizeof(Elf64_Ehdr));
	(void)create_phdr(ve_cprm, phdrImage, ve_pmap, idx, count, sz);
	if(!(dump_core_info(ve_cprm, phdrImage, sizeof(Elf64_Phdr), 0))) {
		    VEOS_ERROR("Dumping LOAD segments fail");
                        retval = -1;
                        goto end;
	}
	VEOS_DEBUG("Dumping Program Header for NOTE complete");

	/* Setting file position to write Note section */
	ve_cprm->f_post = (sizeof(Elf64_Ehdr)+(sizeof(Elf64_Phdr) * (count)));

	/* write out the notes section */
	if (write_note_info(&info, ve_cprm)) {
		VEOS_ERROR("Note section writing fails");
		retval = -1;
		goto end;
	}
	VEOS_DEBUG("Dumping NOTE section complete");

	/* Return error if SIGINT occur */
	if (ve_cprm->tsk->sighand->got_sigint || terminate_flag) {
		VEOS_ERROR("got SIGINT, coredump stopped");
		retval = -EINVAL;
		goto end;
	}


	/* Create and dump the Phdr */
	head = ve_pmap;
	phdrImage = NULL;
	while (NULL != ve_pmap) {
		if (1 == ve_pmap->flag) {
			phdrImage = (ve_cprm->vaddr + sizeof(Elf64_Ehdr) +
					(sizeof(Elf64_Phdr) * (idx)));
			if ((create_phdr(ve_cprm, phdrImage,
					ve_pmap, idx, count, sz))) {
				retval = -1;
				goto end;
			}
			VEOS_DEBUG("Dumping %d Program Segment Data complete", idx);
			idx++;
		}
		ve_pmap = ve_pmap->next;
		/* Return error if SIGINT occur */
		if (ve_cprm->tsk->sighand->got_sigint || terminate_flag) {
			VEOS_ERROR("got SIGINT, coredump stopped");
			retval = -EINVAL;
			goto end;
		}
	}
	ve_pmap = head;
end:
	/* Work done, now free the dynamic memory */
	if (!ve_cprm->vaddr)
		free(ve_cprm->vaddr);
	struct elf_thread_core_info *thd = info.thread;
	struct elf_thread_core_info *temp = NULL;
	while (thd != NULL) {
		temp = thd;
		thd = thd->next;
		free(temp);
	}
	VEOS_TRACE("Out Func");
	return retval;
}

/**
 * @brief Initialize the structure for core dump.
 *
 * @param[in] ve_cprm pointer to dump_params.
 * @return On success 1, On failure, 0.
 */
bool generate_core_dump(struct dump_params *ve_cprm)
{
	bool retval = true;
	struct _psuedo_pmap *ve_pmap = NULL;
	struct _psuedo_pmap *temp_vemap = NULL;
	int pmapcount = 0;
	int idx = 0;

	VEOS_TRACE("In Func");
	pmapcount = get_vepmap(&ve_pmap, ve_cprm->tsk);
	if (0 >= pmapcount) {
		VEOS_ERROR("No LOAD segment to be dump");
		retval = false;
		goto end;
	}
	/* Return error if SIGINT occur */
	if (ve_cprm->tsk->sighand->got_sigint || terminate_flag) {
		VEOS_ERROR("got SIGINT, coredump stopped");
		retval = false;
		goto end;
	}

	if ((fill_ve_core_data(ve_pmap, ve_cprm, pmapcount))) {
		VEOS_ERROR("Fail to initialise core ELF information");
		retval = false;
		goto end;
	}
	VEOS_DEBUG("Coredump generated, retval: %d", retval);
end:
	while (ve_pmap != NULL) {
		temp_vemap = ve_pmap;
		ve_pmap = ve_pmap->next;
		free(temp_vemap);
	}
	for (idx = 0; idx < blockIdx; idx++)
		if ((free_mem[idx]) && (blockIdx < MAX_FREE_BLOCK))
			free(free_mem[idx]);

	VEOS_TRACE("Out Func");
	return retval;
}
