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
 * @file sys_mm.c
 * @brief Handles AMM related system calls encountered by VE process.
 *
 * This file contains AMM system call handlers for the various system calls
 * encountered by VE process.
 *
 * @internal
 * @author AMM
 */
#include <sys/shm.h>
#include <libgen.h>
#include <ctype.h>
#include "sys_common.h"
#include <libved.h>
#include "sys_mm.h"
#include "sys_process_mgmt.h"
#include "vemva_mgmt.h"
#include "mm_transfer.h"
#include "ve_socket.h"
#include "process_mgmt_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "comm_request.h"
#include "velayout.h"
#include "sys_process_mgmt.h"
#include "exception.h"
#include "align.h"

#include "loader.h"
#include <elf.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <sys/file.h>
#include <proc/readproc.h>

char * const ve_grow_err_str[VE_GROW_NO_ERR] =
{
       "Requested Stack grow with invalid agruement\n" /* VE_GROW_INVALID_REQUEST */ ,
       "Requested Stack grow in alternate stack\n" /* VE_GROW_IN_ALT_STACK */,
       "Stack Limit Reached\n" /* VE_GROW_STACK_LIMIT */,
       "Requested Stack grow in guard area\n" /* VE_GROW_IN_GUARD_AREA */,
       "Memory allocation for requested stack failed\n" /* VE_GROW_MEM_ALLOC */,
};

static int ve_node_num = -1;

struct ve_xtbl_adr_hdr_info  ve_xtbl_adr_hdr_info;
static struct ve_xtbl_adr_hdr ve_xtbl_adr_hdr;
extern struct ve_load_data load_elf;

#define MODIFY_OVER_SIZE (1024*1024*1024)
#define	EF_VE_ARCH_MASK 0x0000000F
#define	EF_VE_ARCH_VE1 0x00000000
#define	EF_VE_EXT_VE3 0x00000100

#define CONF_FILE_PATH "/etc/opt/nec/ve/veos/vemodcode.conf"
#define DEFAULT_FILE_PATH "/var/opt/nec/ve/veos"
static char vemodcode_file_path[PATH_MAX] = "";

static struct ve_tmpfile_info ve_tmpfile_info;

ssize_t code_modify_read(int fd, void *buf, ssize_t max_len)
{
	ssize_t read_byte = 0;
	ssize_t readed_byte = 0;
	char *buffer = buf;
	char *endp = buf + max_len;

	while((read_byte = read(fd, buffer, endp - buffer)) != 0){
		if (read_byte < 0){
			if (errno == EINTR || errno == EAGAIN){
				continue;
			}
			return (-1);
		}
		readed_byte += read_byte;
		if(readed_byte >= max_len){
			break;
		}
		buffer += read_byte;
	}
	return readed_byte;
}
ssize_t code_modify_write(int fd, void *buf, ssize_t max_len)
{
	ssize_t write_byte = 0;
	ssize_t writed_byte = 0;
	char *buffer = buf;
	char *endp = buf + max_len;
	while((write_byte = write(fd, buffer, endp - buffer)) != 0){
		if (write_byte < 0){
			if (errno == EINTR || errno == EAGAIN){
				continue;
			}
			return (-1);
		}
		writed_byte += write_byte;
		if(writed_byte >= max_len){
			break;
		}
		buffer += write_byte;
	}
	return writed_byte;
}

int elf_text_offset_size(int fd, uint64_t *text_offset, uint64_t *text_size)
{
	int ret = -1;
	unsigned char *org_ehdr_mem;
	unsigned char *o_org_ehdr_mem;
	unsigned char *org_shdr_mem;
	unsigned char *o_org_shdr_mem;
	unsigned char *str_sect_mem;
	unsigned char *o_str_sect_mem;
	int fr_ret = 0;

	Elf64_Ehdr *ehdr = NULL;
	Elf64_Shdr *shdr = NULL;
	Elf64_Shdr *str_shdr = NULL;

	lseek(fd,0,SEEK_SET);
	o_org_ehdr_mem = malloc(sizeof(Elf64_Ehdr));
	if (o_org_ehdr_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		return(-1);
	}
	org_ehdr_mem = o_org_ehdr_mem;
	fr_ret = code_modify_read(fd, org_ehdr_mem, sizeof(Elf64_Ehdr));
	if (fr_ret != sizeof(Elf64_Ehdr)){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_org_ehdr_mem;
	}
	ehdr = (Elf64_Ehdr *)(org_ehdr_mem);

	lseek(fd, ehdr->e_shoff, SEEK_SET);
	o_org_shdr_mem = malloc(sizeof(Elf64_Shdr) * ehdr->e_shnum);
	if (o_org_shdr_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_org_ehdr_mem;
	}
	org_shdr_mem = o_org_shdr_mem;
	fr_ret = code_modify_read(fd, org_shdr_mem,sizeof(Elf64_Shdr) * ehdr->e_shnum);
	if (fr_ret != (sizeof(Elf64_Shdr) * ehdr->e_shnum)){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_org_shdr_mem;
	}

	str_shdr = (Elf64_Shdr *)(org_shdr_mem + (sizeof(Elf64_Shdr)*ehdr->e_shstrndx));
	lseek(fd,str_shdr->sh_offset,SEEK_SET);
	o_str_sect_mem = malloc(str_shdr->sh_size);
	if (o_str_sect_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_org_shdr_mem;
	}
	str_sect_mem = o_str_sect_mem;
	fr_ret = code_modify_read(fd, str_sect_mem,str_shdr->sh_size);
	if (fr_ret != str_shdr->sh_size){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_str_sect_mem;
	}

	int i;
	shdr = (Elf64_Shdr *)(org_shdr_mem);
	for(i=0; i < ehdr->e_shnum; i++){
		if(strcmp((char *)(str_sect_mem+shdr->sh_name),".text") == 0){
			*text_offset = shdr->sh_offset;
			*text_size = shdr->sh_size;
			ret = 0;
			goto free_o_str_sect_mem;
		}
		org_shdr_mem += sizeof(Elf64_Shdr);
		shdr = (Elf64_Shdr *)(org_shdr_mem);
	}
free_o_str_sect_mem:
	free(o_str_sect_mem);
free_o_org_shdr_mem:
	free(o_org_shdr_mem);
free_o_org_ehdr_mem:
	free(o_org_ehdr_mem);
	lseek(fd,0,SEEK_SET);
	return(ret);

}

int elf_dyn_offset_size(int fd, uint64_t *rela_offset, uint64_t *rela_size, uint64_t *dynamic_offset, uint64_t *dynamic_size, uint64_t *dynstr_offset, uint64_t *dynstr_size, int *is_exec)
{
	int ret = -1;
	unsigned char *org_ehdr_mem;
	unsigned char *o_org_ehdr_mem;
	unsigned char *org_shdr_mem;
	unsigned char *o_org_shdr_mem;
	unsigned char *str_sect_mem;
	unsigned char *o_str_sect_mem;
	int fr_ret = 0;

	Elf64_Ehdr *ehdr = NULL;
	Elf64_Shdr *shdr = NULL;
	Elf64_Shdr *str_shdr = NULL;

	lseek(fd,0,SEEK_SET);
	o_org_ehdr_mem = malloc(sizeof(Elf64_Ehdr));
	if (o_org_ehdr_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		return(-1);
	}
	org_ehdr_mem = o_org_ehdr_mem;
	fr_ret = code_modify_read(fd, org_ehdr_mem, sizeof(Elf64_Ehdr));
	if (fr_ret != sizeof(Elf64_Ehdr)){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_org_ehdr_mem;
	}
	ehdr = (Elf64_Ehdr *)(org_ehdr_mem);

	if (ehdr->e_type == ET_EXEC) {
		*is_exec = 1;
	}else{
		*is_exec = 0;
	}

	lseek(fd, ehdr->e_shoff, SEEK_SET);
	o_org_shdr_mem = malloc(sizeof(Elf64_Shdr) * ehdr->e_shnum);
	if (o_org_shdr_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_org_ehdr_mem;
	}
	org_shdr_mem = o_org_shdr_mem;
	fr_ret = code_modify_read(fd, org_shdr_mem,sizeof(Elf64_Shdr) * ehdr->e_shnum);
	if (fr_ret != (sizeof(Elf64_Shdr) * ehdr->e_shnum)){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_org_shdr_mem;
	}

	str_shdr = (Elf64_Shdr *)(org_shdr_mem + (sizeof(Elf64_Shdr)*ehdr->e_shstrndx));
	lseek(fd,str_shdr->sh_offset,SEEK_SET);
	o_str_sect_mem = malloc(str_shdr->sh_size);
	if (o_str_sect_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_org_shdr_mem;
	}
	str_sect_mem = o_str_sect_mem;
	fr_ret = code_modify_read(fd, str_sect_mem,str_shdr->sh_size);
	if (fr_ret != str_shdr->sh_size){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		ret = -1;
		goto free_o_str_sect_mem;
	}

	int i;
	shdr = (Elf64_Shdr *)(org_shdr_mem);
	for(i=0; i < ehdr->e_shnum; i++){
		if(strcmp((char *)(str_sect_mem+shdr->sh_name),".rela.dyn") == 0){
			*rela_offset = shdr->sh_offset;
			*rela_size = shdr->sh_size;
		}
		if(strcmp((char *)(str_sect_mem+shdr->sh_name),".dynamic") == 0){
			*dynamic_offset = shdr->sh_offset;
			*dynamic_size = shdr->sh_size;
		}
		if(strcmp((char *)(str_sect_mem+shdr->sh_name),".dynstr") == 0){
			*dynstr_offset = shdr->sh_offset;
			*dynstr_size = shdr->sh_size;
		}
		org_shdr_mem += sizeof(Elf64_Shdr);
		shdr = (Elf64_Shdr *)(org_shdr_mem);
	}
	ret = 0;
free_o_str_sect_mem:
	free(o_str_sect_mem);
free_o_org_shdr_mem:
	free(o_org_shdr_mem);
free_o_org_ehdr_mem:
	free(o_org_ehdr_mem);
	lseek(fd,0,SEEK_SET);
	return(ret);

}
#define R_VE_HI32           4
#define R_VE_LO32           5
#define R_VE_CALL_HI32      35
#define R_VE_CALL_LO32      36

void *get_rela_info(int fd, int rela_offset, int rela_size)
{
	void *o_rela_mem;
	int fr_ret;
	int rela_exist=0;
	Elf64_Rela *rela = NULL;

	lseek(fd,rela_offset,SEEK_SET);
	o_rela_mem = malloc(rela_size);
	if (o_rela_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		return((void *)(-1));
	}
	fr_ret = code_modify_read(fd, o_rela_mem,rela_size);
	if (fr_ret != rela_size){
		PSEUDO_DEBUG("Error(%s) while read",strerror(errno));
		free(o_rela_mem);
		return((void *)-1);
	}
	int j;
	uint64_t r_type;
	rela = (Elf64_Rela *)o_rela_mem;
	for(j = 0; j < (rela_size / sizeof(Elf64_Rela)); j++){
		r_type = ELF64_R_TYPE (rela->r_info);
		switch(r_type){
		case R_VE_HI32:
		case R_VE_CALL_HI32:
			rela_exist = 1;
			break;
		case R_VE_LO32:
		case R_VE_CALL_LO32:
			rela_exist = 1;
			break;
		}
		rela++;
	}
	if(rela_exist == 0){
		free(o_rela_mem);
		return((void *)0);
	}
	return(o_rela_mem);
}
int is_rela(uint64_t addr, uint64_t ld_addr, unsigned char *o_rela_mem, uint64_t rela_size)
{
	uint64_t r_type;
	Elf64_Rela *rela = NULL;
	rela = (Elf64_Rela *)o_rela_mem;
	int j;
	long offset;
	offset = addr - ld_addr;
	for(j = 0; j < (rela_size / sizeof(Elf64_Rela)); j++){
		if(rela->r_offset == offset){
			r_type = ELF64_R_TYPE (rela->r_info);
			switch(r_type){
			case R_VE_HI32:
			case R_VE_CALL_HI32:
				return(1);
				break;
			case R_VE_LO32:
			case R_VE_CALL_LO32:
				return(2);
				break;
			}
		}
		rela++;
	}
	return(0);
}

int dynamic_so_name(int fd, char *so_name, uint64_t dynamic_offset, uint64_t dynamic_size, uint64_t dynstr_offset, uint64_t dynstr_size)
{
	int ret = -1;
	Elf64_Dyn *dynamic = NULL;
	unsigned char *o_dynamic_mem;
	unsigned char *o_dynstr_mem;
	int fr_ret;
	lseek(fd,dynamic_offset,SEEK_SET);

	o_dynamic_mem = malloc(dynamic_size);
	if (o_dynamic_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		return(-1);
	}
	fr_ret = code_modify_read(fd, o_dynamic_mem,dynamic_size);
	if (fr_ret != dynamic_size){
		PSEUDO_DEBUG("Error(%s) while fread",strerror(errno));
		ret = -1;
		goto free_o_dynamic_mem;
	}

	lseek(fd,dynstr_offset,SEEK_SET);
	o_dynstr_mem = malloc(dynstr_size);
	if (o_dynstr_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_dynamic_mem;
	}
	fr_ret = code_modify_read(fd,o_dynstr_mem,dynstr_size);
	if (fr_ret != dynstr_size){
		PSEUDO_DEBUG("Error(%s) while fread",strerror(errno));
		ret = -1;
		goto free_o_dynstr_mem;
	}
	dynamic = (Elf64_Dyn *)o_dynamic_mem;
	int j;
	for(j = 0; j < (dynamic_size / sizeof(Elf64_Dyn)); j++){
		if(dynamic->d_tag == 0xe){
			strcpy(so_name, (char *)o_dynstr_mem+dynamic->d_un.d_ptr);
			ret = 0;
			goto free_o_dynstr_mem;
		}
		dynamic++;
	}
	ret = 1;
free_o_dynstr_mem:
	free(o_dynstr_mem);
free_o_dynamic_mem:
	free(o_dynamic_mem);
	return(ret);
}

void modify_new_code(unsigned char *org_code_mem, unsigned char **o_mod_code_mem, uint64_t *o_n_addr, struct d_info **o_recalc_info_br_mem, int *o_recalc_info_br_mem_cnt, struct d_info **o_recalc_info_b_mem, int *o_recalc_info_b_mem_cnt, uint64_t start_addr, uint64_t end_addr, uint64_t d_addr, uint64_t addr, uint64_t mod_code_addr_diff, int rela_flag){


	uint64_t start_addr_hi;
	uint64_t start_addr_lo;
	uint64_t end_addr_hi;
	uint64_t end_addr_lo;
	int64_t d_addr_hi;
	int64_t d_addr_lo;
	int tmp_reg = 13;
	uint64_t addline;
	int BC_D;
	int sabun;
	uint64_t n_addr;
	int recalc_info_br_mem_cnt;
	int recalc_info_b_mem_cnt;
	unsigned char *mod_code_mem;
	struct d_info *recalc_info_br_mem;
	struct d_info *recalc_info_b_mem;
	n_addr = *o_n_addr;
	recalc_info_br_mem_cnt = *o_recalc_info_br_mem_cnt;
	recalc_info_b_mem_cnt = *o_recalc_info_b_mem_cnt;
	mod_code_mem = *o_mod_code_mem;
	recalc_info_br_mem = *o_recalc_info_br_mem;
	recalc_info_b_mem = *o_recalc_info_b_mem;

	if(rela_flag == 1){
		if(org_code_mem[7] == 0x06){
			d_addr_hi = addr >> 32;
			d_addr_lo = addr & 0x00000000FFFFFFFF;
			mod_code_mem[0]=(d_addr_lo & 0xFF);mod_code_mem[1]=((d_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((d_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((d_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(d_addr_hi & 0xFF);mod_code_mem[1]=((d_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((d_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((d_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x02;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=org_code_mem[0];mod_code_mem[1]=org_code_mem[1];mod_code_mem[2]=org_code_mem[2];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=org_code_mem[4];mod_code_mem[5]=(tmp_reg | 0x80);mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=org_code_mem[7];
		}else{
			rela_flag = 0;
		}
	}

	if(rela_flag == 2){
		if(org_code_mem[7] == 0x06){
			d_addr_hi = addr >> 32;
			d_addr_lo = addr & 0x00000000FFFFFFFF;
			mod_code_mem[0]=(d_addr_lo & 0xFF);mod_code_mem[1]=((d_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((d_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((d_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(d_addr_hi & 0xFF);mod_code_mem[1]=((d_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((d_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((d_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x03;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=org_code_mem[0];mod_code_mem[1]=org_code_mem[1];mod_code_mem[2]=org_code_mem[2];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=org_code_mem[4];mod_code_mem[5]=(tmp_reg | 0x80);mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=org_code_mem[7];
		}else{
			rela_flag = 0;
		}
	}

	switch(org_code_mem[7]){
	case 0x81: // VLD
	case 0x82: // VLDU
	case 0x83: // VLDL
	case 0x80: // VLD2B/PFCHV
	case 0xc1: // VLD2D
	case 0xc2: // VLDU2D
	case 0xc3: // VLDL2D
	case 0xa1: // VGT
	case 0xa2: // VGTU
	case 0xa3: // VGTL
	case 0x9c: // VMV
	case 0xa9: // VRSC
	case 0xe9: // VDIV
	case 0xeb: // VDVS
	case 0xfb: // VDVX
	case 0xdd: // VFDV
	case 0xed: // VFSQRT
	case 0xce: // VFIA
	case 0xde: // VFIS
	case 0xcf: // VFIM
	case 0xee: // VFIAM
	case 0xfe: // VFISM
	case 0xef: // VFIMA
	case 0x8d: // VCP
	case 0x9d: // VEX
	case 0xff: // VFIMS
		memcpy(mod_code_mem,org_code_mem,8);
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=0x00;mod_code_mem[1]=org_code_mem[3];mod_code_mem[2]=org_code_mem[3];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=0x00;mod_code_mem[7]=0xc5;
		break;
	case 0xe2: // VFMAD
	case 0xf2: // VFMSB
	case 0xe3: // VFNMAD
	case 0xf3: // VFNMSB
		memcpy(mod_code_mem,org_code_mem,8);
		/* cs == 0 && cs2 == 0 (use 4 vector registers) */
		if (!(org_code_mem[6] & 0x10) && !(org_code_mem[6] & 0x20)){
			if ((org_code_mem[0] != org_code_mem[1]) & (org_code_mem[0] != org_code_mem[2]) & (org_code_mem[0] != org_code_mem[3]) & (org_code_mem[1] != org_code_mem[2]) & (org_code_mem[1] != org_code_mem[3]) & (org_code_mem[2] != org_code_mem[3])){
				mod_code_mem += 8; n_addr += 8;
				mod_code_mem[0]=0x00;mod_code_mem[1]=org_code_mem[3];mod_code_mem[2]=org_code_mem[3];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=0x00;mod_code_mem[7]=0xc5;
			}
		}
		break;
	case 0x08: // BSIC
		start_addr_hi = start_addr >> 32;
		start_addr_lo = start_addr & 0x00000000FFFFFFFF;
		end_addr_hi = end_addr >> 32;
		end_addr_lo = end_addr & 0x00000000FFFFFFFF;
		d_addr_hi = d_addr >> 32;
		d_addr_lo = d_addr & 0x00000000FFFFFFFF;

		mod_code_mem[0]=org_code_mem[0];mod_code_mem[1]=org_code_mem[1];mod_code_mem[2]=org_code_mem[2];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=org_code_mem[4];mod_code_mem[5]=org_code_mem[5];mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=0x06;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(start_addr_lo & 0xFF);mod_code_mem[1]=((start_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((start_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((start_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(start_addr_hi & 0xFF);mod_code_mem[1]=((start_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((start_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((start_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=0x38;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=(org_code_mem[6] | 0x80);mod_code_mem[6]=0x02;mod_code_mem[7]=0x18;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(end_addr_lo & 0xFF);mod_code_mem[1]=((end_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((end_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((end_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(end_addr_hi & 0xFF);mod_code_mem[1]=((end_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((end_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((end_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=0x20;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=(org_code_mem[6] | 0x80);mod_code_mem[6]=0x35;mod_code_mem[7]=0x18;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(d_addr_lo & 0xFF);mod_code_mem[1]=((d_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((d_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((d_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=(d_addr_hi & 0xFF);mod_code_mem[1]=((d_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((d_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((d_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=(org_code_mem[6] | 0x80);mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=0x01;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=0x00;mod_code_mem[5]=(org_code_mem[6] | 0x80);mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=0x08;
		break;
	case 0x19: // BC
	case 0x1b: // BCS
	case 0x1c: // BCF
		addline = *(uint64_t *)org_code_mem;
		BC_D = addline & 0xFFFFFFFF;
		start_addr_hi = (start_addr - BC_D) >> 32;
		start_addr_lo = (start_addr - BC_D) & 0x00000000FFFFFFFF;
		end_addr_hi = (end_addr - BC_D) >> 32;
		end_addr_lo = (end_addr - BC_D) & 0x00000000FFFFFFFF;
		d_addr_hi = (d_addr + BC_D) >> 32;
		d_addr_lo = (d_addr + BC_D) & 0x00000000FFFFFFFF;
		if((org_code_mem[4]) == 0x00){
			memcpy(mod_code_mem,org_code_mem,8);
			sabun = *(int *)org_code_mem;
			recalc_info_b_mem->mod_code_addr = (n_addr + mod_code_addr_diff);
			recalc_info_b_mem->org_code_addr = (addr);
			recalc_info_b_mem->diff_org_code_addr = sabun;
			recalc_info_b_mem->sabun = sabun;
			recalc_info_b_mem->out_bound = 0;
			if ((sabun > (MODIFY_OVER_SIZE)) || (sabun < -(MODIFY_OVER_SIZE))){
				mod_code_mem[0]=(BC_D & 0xFF);mod_code_mem[1]=((BC_D >> 8) & 0xF);mod_code_mem[2]=((BC_D >> 16) & 0xFF);mod_code_mem[3]=((BC_D >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
				mod_code_mem += 8; n_addr += 8;
				mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
				mod_code_mem += 8; n_addr += 8;
				mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=org_code_mem[5];mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=org_code_mem[7];

				recalc_info_b_mem->out_bound = 1;
			}
			recalc_info_b_mem += 8;
			recalc_info_b_mem_cnt++;
		}else{
			mod_code_mem[0]=(start_addr_lo & 0xFF);mod_code_mem[1]=((start_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((start_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((start_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(start_addr_hi & 0xFF);mod_code_mem[1]=((start_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((start_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((start_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x40;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=org_code_mem[4];mod_code_mem[6]=0x02;mod_code_mem[7]=0x18;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(end_addr_lo & 0xFF);mod_code_mem[1]=((end_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((end_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((end_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(end_addr_hi & 0xFF);mod_code_mem[1]=((end_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((end_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((end_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x28;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=org_code_mem[4];mod_code_mem[6]=0x35;mod_code_mem[7]=0x18;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(d_addr_lo & 0xFF);mod_code_mem[1]=((d_addr_lo >> 8) & 0xFF);mod_code_mem[2]=((d_addr_lo >> 16) & 0xFF);mod_code_mem[3]=((d_addr_lo >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=(d_addr_hi & 0xFF);mod_code_mem[1]=((d_addr_hi >> 8) & 0xFF);mod_code_mem[2]=((d_addr_hi >> 16) & 0xFF);mod_code_mem[3]=((d_addr_hi >> 24) & 0xFF);mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=org_code_mem[4];mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x01;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=org_code_mem[5];mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=org_code_mem[7];
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=org_code_mem[0];mod_code_mem[1]=org_code_mem[1];mod_code_mem[2]=org_code_mem[2];mod_code_mem[3]=org_code_mem[3];mod_code_mem[4]=org_code_mem[4];mod_code_mem[5]=org_code_mem[5];mod_code_mem[6]=org_code_mem[6];mod_code_mem[7]=org_code_mem[7];
		}
		break;
	case 0x28: // SIC
		mod_code_mem[0]=((addr + 8) & 0xFF);mod_code_mem[1]=(((addr  + 8) >> 8) & 0xFF);mod_code_mem[2]=(((addr + 8) >> 16) & 0xFF);mod_code_mem[3]=(((addr + 8) >> 24) & 0xFF);mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(org_code_mem[6] & 0x7F);mod_code_mem[7]=0x07;
		mod_code_mem += 8; n_addr += 8;
		mod_code_mem[0]=((addr + 8) >> 32 & 0xFF);mod_code_mem[1]=(((addr + 8) >> 40) & 0xFF);mod_code_mem[2]=(((addr + 8) >> 48) & 0xFF);mod_code_mem[3]=(((addr + 8) >> 56) & 0xFF);mod_code_mem[4]=(org_code_mem[6] | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(org_code_mem[6] | 0x80);mod_code_mem[7]=0x06;
		break;

	case 0x18: // BR
		memcpy(mod_code_mem,org_code_mem,8);
		//sabun = org_code_mem[3]; sabun = (sabun << 8) + org_code_mem[2]; sabun = (sabun << 8) + org_code_mem[1]; sabun = (sabun << 8) + org_code_mem[0];
		sabun = *(int *)org_code_mem;
		recalc_info_br_mem->mod_code_addr = (n_addr + mod_code_addr_diff);
		recalc_info_br_mem->org_code_addr = (addr);
		recalc_info_br_mem->diff_org_code_addr = (addr + sabun);
		recalc_info_br_mem->sabun = sabun;
		recalc_info_br_mem->out_bound = 0;
		if ((sabun > (MODIFY_OVER_SIZE)) || (sabun < -(MODIFY_OVER_SIZE)) || ((addr + sabun) < start_addr) || ((addr + sabun) >= end_addr)){
			mod_code_mem[0]=0x01;mod_code_mem[1]=0x02;mod_code_mem[2]=0x03;mod_code_mem[3]=0x04;mod_code_mem[4]=0x00;mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg & 0x7F);mod_code_mem[7]=0x07;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x05;mod_code_mem[1]=0x06;mod_code_mem[2]=0x07;mod_code_mem[3]=0x08;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=(tmp_reg | 0x80);mod_code_mem[7]=0x06;
			mod_code_mem += 8; n_addr += 8;
			mod_code_mem[0]=0x00;mod_code_mem[1]=0x00;mod_code_mem[2]=0x00;mod_code_mem[3]=0x00;mod_code_mem[4]=(tmp_reg | 0x80);mod_code_mem[5]=0x00;mod_code_mem[6]=0x3f;mod_code_mem[7]=0x19;

			recalc_info_br_mem->out_bound = 1;
		}
		recalc_info_br_mem += 8;
		recalc_info_br_mem_cnt++;
		break;
	default:
		if(rela_flag == 0){
			memcpy(mod_code_mem,org_code_mem,8);
		}
	}
	*o_n_addr = n_addr;
	*o_recalc_info_br_mem_cnt = recalc_info_br_mem_cnt;
	*o_recalc_info_b_mem_cnt = recalc_info_b_mem_cnt;
	*o_mod_code_mem = mod_code_mem;
	*o_recalc_info_br_mem = recalc_info_br_mem;
	*o_recalc_info_b_mem = recalc_info_b_mem;
}

int code_modify(int fd, int mod_fd, uint64_t mod_ld_addr, int adr_fd, uint64_t adr_cnv_ld_addr, int org_fd, uint64_t org_ld_addr, int64_t mod_text_size)
{
	int ret = -1;
	unsigned char *org_code_mem;
	unsigned char *o_org_code_mem;
	unsigned char *mod_code_mem;
	unsigned char *o_mod_code_mem;
	unsigned char *adr_conv_mem;
	unsigned char *o_adr_conv_mem;
	struct d_info *recalc_info_br_mem;
	struct d_info *o_recalc_info_br_mem;
	int recalc_info_br_mem_cnt = 0;
	struct d_info *recalc_info_b_mem;
	struct d_info *o_recalc_info_b_mem;
	int recalc_info_b_mem_cnt = 0;
	uint64_t addr;
	uint64_t n_addr;
	uint64_t adr_conv_addr_diff;
	uint64_t mod_code_addr_diff;
	uint64_t start_addr;
	uint64_t end_addr;
	uint64_t mod_code_start_addr;
	uint64_t adr_conv_start_addr;
	uint64_t d_addr;

	int i;
	uint64_t text_offset = 0;
	uint64_t text_size =0;
	int tmp_reg = 13;
	int fr_ret = 0;

	fr_ret = elf_text_offset_size(fd, &text_offset, &text_size);
	if (fr_ret < 0){
		PSEUDO_DEBUG("Error(%s) while read offset & size of text in ELF :%d",strerror(errno), fr_ret);
		lseek(fd,0,SEEK_SET);
		return(-1);
	}

	start_addr = org_ld_addr + text_offset;
	end_addr = org_ld_addr + text_offset + text_size;
	mod_code_start_addr = mod_ld_addr;
	adr_conv_start_addr = adr_cnv_ld_addr;

	lseek(fd,text_offset,SEEK_SET);

	o_org_code_mem = malloc(text_size);
	if (o_org_code_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		lseek(fd,0,SEEK_SET);
		return(-1);
	}
	org_code_mem = o_org_code_mem;
	o_mod_code_mem = malloc(mod_text_size+10240);
	if (o_mod_code_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_org_code_mem;
	}
	mod_code_mem = o_mod_code_mem;
	o_adr_conv_mem = malloc(text_size);
	if (o_adr_conv_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_mod_code_mem;
	}
	adr_conv_mem = o_adr_conv_mem;
	o_recalc_info_br_mem = malloc(sizeof(struct d_info)*text_size);
	if (o_recalc_info_br_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_adr_conv_mem;
	}
	recalc_info_br_mem = o_recalc_info_br_mem;

	o_recalc_info_b_mem = malloc(sizeof(struct d_info)*text_size);
	if (o_recalc_info_b_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_recalc_info_br_mem;
	}
	recalc_info_b_mem = o_recalc_info_b_mem;

	fr_ret = code_modify_read(fd, org_code_mem,text_size);
	if (fr_ret != text_size){
		PSEUDO_DEBUG("Error(%s) while fread",strerror(errno));
		ret = -1;
		goto free_o_recalc_info_b_mem;
	}

	addr = start_addr;
	n_addr = addr;
	mod_code_addr_diff = mod_code_start_addr - start_addr;
	adr_conv_addr_diff = adr_conv_start_addr - start_addr;
	d_addr = adr_conv_addr_diff;

	int rela_flag = 0;
	int rela_include_flag = 0;

	unsigned char *o_rela_mem;

	uint64_t rela_offset = 0;
	uint64_t rela_size = 0;
	uint64_t dynamic_offset = 0;
	uint64_t dynamic_size = 0;
	uint64_t dynstr_offset = 0;
	uint64_t dynstr_size = 0;

	int is_exec;

	fr_ret = elf_dyn_offset_size(fd, &rela_offset, &rela_size, &dynamic_offset, &dynamic_size, &dynstr_offset, &dynstr_size, &is_exec);
	if (fr_ret < 0){
		PSEUDO_DEBUG("Error(%s) while read offset & size of dyn in ELF :%d",strerror(errno), fr_ret);
		ret = -1;
		goto free_o_recalc_info_b_mem;
	}

	o_rela_mem = get_rela_info(fd, rela_offset, rela_size);
	if ((int64_t)o_rela_mem < 0){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		ret = -1;
		goto free_o_recalc_info_b_mem;
	}
	if (o_rela_mem != 0){
		rela_include_flag = 1;
	}

	for(; addr < end_addr;){
		*(uint64_t *)adr_conv_mem = (n_addr + mod_code_addr_diff);
		if(rela_include_flag){
			rela_flag = is_rela(addr, org_ld_addr, o_rela_mem, rela_size);
		}



		if(((org_code_mem[7] == 0x11) && (org_code_mem[6] == 0x09) && (org_code_mem[5] == 0x00) && (org_code_mem[4] == 0x8b)) || ((is_exec) && (addr == start_addr))){
			// Function Prologue(st %fp,0x0(,%sp)) or Entry Point
			int n_add_lo;
			int n_add_hi;
			n_add_lo = (n_addr + mod_code_addr_diff) & 0x00000000FFFFFFFF;
			n_add_hi = (n_addr + mod_code_addr_diff) >> 32;
				modify_new_code(org_code_mem, &mod_code_mem, &n_addr, &recalc_info_br_mem, &recalc_info_br_mem_cnt, &recalc_info_b_mem, &recalc_info_b_mem_cnt, start_addr, end_addr, d_addr, addr , mod_code_addr_diff, rela_flag);
			org_code_mem[7]=0x07;org_code_mem[6]=(tmp_reg & 0x7F);org_code_mem[5]=0x00;org_code_mem[4]=0x00;org_code_mem[3]=(n_add_lo >> 24) & 0x000000FF;org_code_mem[2]=(n_add_lo >> 16) & 0x000000FF;org_code_mem[1]=(n_add_lo >> 8) & 0x000000FF;org_code_mem[0]=(n_add_lo) & 0x000000FF;
			org_code_mem += 8; mod_code_mem += 8; addr += 8; n_addr += 8; adr_conv_mem += 8;
			*(uint64_t *)adr_conv_mem = (n_addr + mod_code_addr_diff);
				modify_new_code(org_code_mem, &mod_code_mem, &n_addr, &recalc_info_br_mem, &recalc_info_br_mem_cnt, &recalc_info_b_mem, &recalc_info_b_mem_cnt, start_addr, end_addr, d_addr, addr , mod_code_addr_diff, rela_flag);
			org_code_mem[7]=0x06;org_code_mem[6]=(tmp_reg | 0x80);org_code_mem[5]=0x00;org_code_mem[4]=(tmp_reg | 0x80);org_code_mem[3]=(n_add_hi >> 24) & 0x000000FF;org_code_mem[2]=(n_add_hi >> 16) & 0x000000FF;org_code_mem[1]=(n_add_hi >> 8) & 0x000000FF;org_code_mem[0]=(n_add_hi) & 0x000000FF;
			org_code_mem += 8; mod_code_mem += 8; addr += 8; n_addr += 8; adr_conv_mem += 8;
			*(uint64_t *)adr_conv_mem = (n_addr + mod_code_addr_diff);
				modify_new_code(org_code_mem, &mod_code_mem, &n_addr, &recalc_info_br_mem, &recalc_info_br_mem_cnt, &recalc_info_b_mem, &recalc_info_b_mem_cnt, start_addr, end_addr, d_addr, addr , mod_code_addr_diff, rela_flag);
			org_code_mem[7]=0x19;org_code_mem[6]=0x3f;org_code_mem[5]=0x00;org_code_mem[4]=(tmp_reg | 0x80);org_code_mem[3]=0x00;org_code_mem[2]=0x00;org_code_mem[1]=0x00;org_code_mem[0]=0x00;
		}else{
			modify_new_code(org_code_mem, &mod_code_mem, &n_addr, &recalc_info_br_mem, &recalc_info_br_mem_cnt, &recalc_info_b_mem, &recalc_info_b_mem_cnt, start_addr, end_addr, d_addr, addr , mod_code_addr_diff, rela_flag);
		}

		org_code_mem += 8;
		mod_code_mem += 8;
		addr += 8;
		n_addr += 8;
		adr_conv_mem += 8;
	}

	uint64_t h_d_addr, now_org_addr;
	int64_t h_dis;
	int in_text;

	recalc_info_br_mem = o_recalc_info_br_mem;
	for(i = 0; i < recalc_info_br_mem_cnt; i++){
		if ((recalc_info_br_mem->diff_org_code_addr >= start_addr) && (recalc_info_br_mem->diff_org_code_addr < end_addr)){
			h_d_addr = *(uint64_t *)(o_adr_conv_mem + (recalc_info_br_mem->diff_org_code_addr - start_addr));
			h_dis = h_d_addr - recalc_info_br_mem->mod_code_addr;
			in_text = 1;
		}else{
			h_dis = recalc_info_br_mem->diff_org_code_addr;
			in_text = 0;
		}
		if(recalc_info_br_mem->out_bound == 1){
			mod_code_mem = o_mod_code_mem+(*(uint64_t *)(o_adr_conv_mem + (recalc_info_br_mem->org_code_addr - start_addr)) - (mod_code_addr_diff + start_addr));
			if(in_text){
				now_org_addr = *(uint64_t *)(o_adr_conv_mem + (recalc_info_br_mem->org_code_addr - start_addr));
				h_dis = h_dis + now_org_addr;
			}
			*(int *)mod_code_mem=(uint64_t)(h_dis & 0xFFFFFFFF);
			mod_code_mem+=8;
			*(int *)mod_code_mem=(uint64_t)(h_dis >> 32);
		}else{
			*(int *)(o_mod_code_mem + (recalc_info_br_mem->mod_code_addr - mod_code_addr_diff -start_addr)) = h_dis;
		}
		recalc_info_br_mem += 8;
	}
	recalc_info_b_mem = o_recalc_info_b_mem;
	for(i = 0; i < recalc_info_b_mem_cnt; i++){
		if ((recalc_info_b_mem->diff_org_code_addr >= start_addr) && (recalc_info_b_mem->diff_org_code_addr < end_addr)){
			h_d_addr = *(uint64_t *)(o_adr_conv_mem + (recalc_info_b_mem->diff_org_code_addr - start_addr));
			h_dis = h_d_addr;
		}else{
			continue;
		}
		if(recalc_info_b_mem->out_bound == 1){
			mod_code_mem = o_mod_code_mem+(*(uint64_t *)(o_adr_conv_mem + (recalc_info_b_mem->org_code_addr - start_addr)) - (mod_code_addr_diff + start_addr));
			*(int *)mod_code_mem=(uint64_t)(h_dis & 0xFFFFFFFF);
			mod_code_mem+=8;
			*(int *)mod_code_mem=(uint64_t)(h_dis >> 32);
		}else{
			*(int *)(o_mod_code_mem + (recalc_info_b_mem->mod_code_addr - mod_code_addr_diff -start_addr)) = h_dis;
		}
		recalc_info_b_mem += 8;
	}

	lseek(fd,0,SEEK_SET);
	unsigned char tmp_buf[4096];
	ssize_t read_sz;
	ssize_t write_sz = 0;
	while((read_sz = read(fd, tmp_buf, 4096)) > 0){
		write_sz = code_modify_write(org_fd,tmp_buf, read_sz);
		if (write_sz != read_sz){
			PSEUDO_DEBUG("Error(%s) while fread",strerror(errno));
			ret = -1;
			goto free_o_rela_mem;
		}
	}
	addr = start_addr;
	org_code_mem= o_org_code_mem;
	lseek(org_fd,text_offset,SEEK_SET);
	write_sz = code_modify_write(org_fd, org_code_mem, end_addr-start_addr);
	if (write_sz != (end_addr-start_addr)){
		PSEUDO_DEBUG("Error(%s) while write",strerror(errno));
		ret = -1;
		goto free_o_rela_mem;
	}

	addr = start_addr;
	mod_code_mem= o_mod_code_mem;
	write_sz = code_modify_write(mod_fd,  mod_code_mem, n_addr-start_addr);
	if (write_sz != (n_addr-start_addr)){
		PSEUDO_DEBUG("Error(%s) while write",strerror(errno));
		ret = -1;
		goto free_o_rela_mem;
	}

	addr = start_addr;
	adr_conv_mem= o_adr_conv_mem;
	write_sz = code_modify_write(adr_fd, adr_conv_mem, end_addr-start_addr);
	if (write_sz != (end_addr-start_addr)){
		PSEUDO_DEBUG("Error(%s) while write",strerror(errno));
		ret = -1;
		goto free_o_rela_mem;
	}


	if (rela_include_flag){
		char so_name[NAME_MAX]={""};
		int is_so_name_exist;
		is_so_name_exist = dynamic_so_name(fd, so_name, dynamic_offset, dynamic_size, dynstr_offset, dynstr_size);
		if(is_so_name_exist == 0){
			PSEUDO_INFO("RELA type relocation information included in %s (map addres:%lx)\n",so_name,org_ld_addr);
		}else{
			PSEUDO_INFO("RELA type relocation information included in ?? (map addres:%lx)\n",org_ld_addr);
		}
	}
	ret = 0;
free_o_rela_mem:
	if(o_rela_mem != NULL){
		free(o_rela_mem);
		o_rela_mem = NULL;
	}
free_o_recalc_info_b_mem:
	free(o_recalc_info_b_mem);
free_o_recalc_info_br_mem:
	free(o_recalc_info_br_mem);
free_o_adr_conv_mem:
	free(o_adr_conv_mem);
free_o_mod_code_mem:
	free(o_mod_code_mem);
free_o_org_code_mem:
	free(o_org_code_mem);
	lseek(fd,0,SEEK_SET);
	return(ret);
}

int64_t code_modify_size(int fd)
{
	int ret = -1;
	unsigned char *org_code_mem;
	unsigned char *o_org_code_mem;

	uint64_t addr = 0;
	int64_t n_addr = 0;
	uint64_t end_addr = 0;

	uint64_t text_offset = 0;
	uint64_t text_size =0;
	int sabun = 0;
	int fr_ret = 0;

	int vor_num = 0;

	fr_ret = elf_text_offset_size(fd, &text_offset, &text_size);
	if (fr_ret < 0){
		PSEUDO_DEBUG("Error(%s) while read offset & size of text in ELF :%d",strerror(errno), fr_ret);
		lseek(fd,0,SEEK_SET);
		return(-1);
	}

	lseek(fd,text_offset,SEEK_SET);

	o_org_code_mem = malloc(text_size);
	if (o_org_code_mem == NULL){
		PSEUDO_DEBUG("Error(%s) malloc",strerror(errno));
		lseek(fd,0,SEEK_SET);
		return(-1);
	}
	org_code_mem = o_org_code_mem;

	fr_ret = code_modify_read(fd, org_code_mem,text_size);
	if (fr_ret != text_size){
		PSEUDO_DEBUG("Error(%s) while fread",strerror(errno));
		ret = -1;
		goto free_o_org_code_mem;
	}

	end_addr = text_size;

	uint64_t rela_offset = 0;
	uint64_t rela_size = 0;
	uint64_t dynamic_offset = 0;
	uint64_t dynamic_size = 0;
	uint64_t dynstr_offset = 0;
	uint64_t dynstr_size = 0;

	int is_exec = 0;

	fr_ret = elf_dyn_offset_size(fd, &rela_offset, &rela_size, &dynamic_offset, &dynamic_size, &dynstr_offset, &dynstr_size, &is_exec);
	if (fr_ret < 0){
		PSEUDO_DEBUG("Error(%s) while read offset & size of dyn in ELF :%d",strerror(errno), fr_ret);
		ret = -1;
		goto free_o_org_code_mem;
	}

	char so_name[NAME_MAX]={""};
	int is_so_name_exist;
	is_so_name_exist = dynamic_so_name(fd, so_name, dynamic_offset, dynamic_size, dynstr_offset, dynstr_size);
	if(is_so_name_exist == 0){
		if (strncmp(so_name, "libc.so",7) == 0){
			ret = 0;
			goto free_o_org_code_mem;
		}
		if (strncmp(so_name, "ld-linux-ve.so",14) == 0){
			ret = 0;
			goto free_o_org_code_mem;
		}
	}

	for(; addr < end_addr;){
		switch(org_code_mem[7]){
		case 0x81: // VLD
		case 0x82: // VLDU
		case 0x83: // VLDL
		case 0x80: // VLD2B/PFCHV
		case 0xc1: // VLD2D
		case 0xc2: // VLDU2D
		case 0xc3: // VLDL2D
		case 0xa1: // VGT
		case 0xa2: // VGTU
		case 0xa3: // VGTL
		case 0x9c: // VMV
		case 0xa9: // VRSC
		case 0xe9: // VDIV
		case 0xeb: // VDVS
		case 0xfb: // VDVX
		case 0xdd: // VFDV
		case 0xed: // VFSQRT
		case 0xce: // VFIA
		case 0xde: // VFIS
		case 0xcf: // VFIM
		case 0xee: // VFIAM
		case 0xfe: // VFISM
		case 0xef: // VFIMA
		case 0x8d: // VCP
		case 0x9d: // VEX
		case 0xff: // VFIMS
			n_addr += 8;
			vor_num++;
			break;
		case 0xe2: // VFMAD
		case 0xf2: // VFMSB
		case 0xe3: // VFNMAD
		case 0xf3: // VFNMSB
			/* cs == 0 && cs2 == 0 (use 4 vector registers) */
			if (!(org_code_mem[6] & 0x10) && !(org_code_mem[6] & 0x20)){
				if ((org_code_mem[0] != org_code_mem[1]) & (org_code_mem[0] != org_code_mem[2]) & (org_code_mem[0] != org_code_mem[3]) & (org_code_mem[1] != org_code_mem[2]) & (org_code_mem[1] != org_code_mem[3]) & (org_code_mem[2] != org_code_mem[3])){
					n_addr += 8;
					vor_num++;
				}
			}
			break;
		case 0x08: // BSIC
			n_addr += 80;
			break;
		case 0x19: // BC
		case 0x1b: // BCS
		case 0x1c: // BCF
			n_addr += 80;
			break;
		case 0x28: // SIC
			n_addr += 8;
			break;
		case 0x18: // BR
			sabun = *(int *)org_code_mem;
			if ((sabun > (MODIFY_OVER_SIZE)) || (sabun < -(MODIFY_OVER_SIZE)) || ((addr + sabun) < 0) || ((addr + sabun) >= end_addr)){
				n_addr += 24;
			}
			break;
		}
		org_code_mem += 8;
		addr += 8;
		n_addr += 8;
	}
	n_addr += ((rela_size / sizeof(Elf64_Rela)) * 32);
	if(vor_num == 0){
		ret = 0;
	}else{
		ret = n_addr;
	}
free_o_org_code_mem:
	free(o_org_code_mem);
	lseek(fd,0,SEEK_SET);
	return(ret);
}

/* TODO: move reserve_signal_trampoline() to architecture-dependent part */
/**
 * @brief This interface will reserve the space for "signal trampoline' code and
 *        store the trampoline code at reserve space.There will be different
 *        location for 2MB or 64MB compiled binary.
 *        2MB VE page : signal trampoline at location TRAMP_2MB.
 *        64MB VE page : signal trampoline at location TRAMP_64MB.
 *
 * @param[in] handle VEOS handle.
 *
 * @return This interface will return 0 on success and negative of
 * errno on failure.
 */
int reserve_signal_trampoline(veos_handle *handle)
{
	int ret = 0;
	const uint64_t flags = MAP_2MB|MAP_ANON|MAP_PRIVATE
					|MAP_FIXED|MAP_ADDR_64GB_SPACE;
	vemva_t tramp = (default_page_size == PAGE_SIZE_2MB) ?
						TRAMP_2MB : TRAMP_64MB;
	uint64_t tramp_buf[5];

	/*copy trampoline code*/
	tramp_buf[0] = 0x462eaeae00000000;
	tramp_buf[1] = 0x012e008e00000018;
	tramp_buf[2] = 0x45000f0000000000;
	tramp_buf[3] = 0x310003ae00000000;
	tramp_buf[4] = 0x3f00000000000000;


	/*Reserve VE page for signal trampoline code*/
	PSEUDO_DEBUG("Signal Trampoline address 0x%lx", tramp);
	if (MAP_FAILED == __ve_mmap(handle, tramp, PAGE_SIZE_2MB,
				PROT_WRITE|PROT_READ, flags, -1, 0)) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while mapping trampoline code",
							 strerror(errno));
		return ret;
	} else
		PSEUDO_DEBUG("Signal Trampoline mapped at 0x%lx", tramp);

	if (default_page_size == PAGE_SIZE_2MB)
		as_attributes.tramp.tramp_2MB = tramp;
	else
		as_attributes.tramp.tramp_64MB = tramp;

	/*Copy the trampoline code to VE memory*/
	ret = ve_send_data(handle, tramp, sizeof(tramp_buf), tramp_buf);
	if (ret < 0) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Failed to write data to VE memory");
		return ret;
	}
	/*Change the access permission of reserved memory for trampoline*/
	/* Call VH mprotect system call */
	ret = syscall(SYS_mprotect, tramp, PAGE_SIZE_2MB, PROT_READ);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while off loading syscall on VH",
				strerror(-ret));
		return ret;
	}

	/*sending request*/
	ret = amm_request_mprotect(handle, tramp, PAGE_SIZE_2MB, PROT_READ);
	if (0 > ret)
		PSEUDO_DEBUG("Error(%s) for syscall", strerror(-ret));

	return ret;
}

/**
 * @brief This interface will send request to veos to sync vhva.
 *
 * @param[in] handle VEOS handle.
 *
 * @return This interface will return 0 on success and negative of
 * errno on failure.
 */
int ve_sync_vhva(veos_handle *handle)
{
	int ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	PseudoVeosMessage *pseudo_msg = NULL;
	PseudoVeosMessage vhva_sync_cmd = PSEUDO_VEOS_MESSAGE__INIT;

	PSEUDO_TRACE("invoked");

	vhva_sync_cmd.pseudo_veos_cmd_id = VHVA_SYNC;
	vhva_sync_cmd.has_pseudo_pid = true;
	vhva_sync_cmd.pseudo_pid = syscall(SYS_gettid);

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vhva_sync_cmd);

	msg_len = pseudo_veos_message__pack(&vhva_sync_cmd,
			(uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}
	/* Command send to VEOS for ATB init*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while sending IPC command\
				VHVA_SYNC to VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while sending request to VE OS",
				strerror(-ret));
		goto error_return;
	}

	/* Receiving ACK for command ATB init*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
							MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for VHVA_SYNC\
				 from VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS",
				strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while syncing vhva",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) occurred on VE OS while synching data",
				strerror(-ret));
	} else {
		PSEUDO_DEBUG("vhva sync operation successful on VE OS");
		ret = pseudo_msg->syscall_retval;
	}

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This interface will send request to veos to initialize ATB dir.
 *
 * @param[in] handle VEOS handle.
 * @param[in] vemva Base address of new VEMVA chunk allocated
 * from ve_get_vemva().
 * @param[in] page_size  page size of allocated chunk 2MB/64MB.
 *
 * @return This interface will return 0 on success and negative of errno
 * value on failure.
 */
int new_vemva_chunk_atb_init(veos_handle *handle, vemva_t vemva,
							size_t page_size)
{
	int ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	struct vemva_init_atb_cmd *cmd = NULL;

	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage vemva_init_atb = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData vemva_init_atb_msg = {0};

	PSEUDO_TRACE("invoked with vaddr(0x%lx) and size(0x%lx)",
							vemva, page_size);

	cmd = (struct vemva_init_atb_cmd *)calloc(1,
					sizeof(struct vemva_init_atb_cmd));
	if (NULL == cmd) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating mem"\
			" for vemva_init_atb_cmd",
				strerror(-ret));
		goto error_return;
	}
	/*
	 * Populating struct vemva_init_atb_cmd buffer
	 * to Generate IPC Command
	 */
	cmd->vaddr = vemva;
	cmd->page_size = page_size;

	vemva_init_atb.pseudo_veos_cmd_id = VEMVA_INIT_ATB;

	vemva_init_atb.has_pseudo_pid = true;
	vemva_init_atb.pseudo_pid = syscall(SYS_gettid);

	vemva_init_atb_msg.len = sizeof(struct vemva_init_atb_cmd);
	vemva_init_atb_msg.data = (uint8_t *)cmd;

	vemva_init_atb.has_pseudo_msg = true;
	vemva_init_atb.pseudo_msg = vemva_init_atb_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vemva_init_atb);

	msg_len = pseudo_veos_message__pack(&vemva_init_atb,
			(uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* Command send to VEOS for ATB init*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while sending IPC command\
				VEMVA_INIT_ATB to VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while sending request\
				 to VE OS", strerror(-ret));
		goto error_return;
	}

	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for \
				VEMVA_INIT_ATB from VE OS", strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS",
				strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}
	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while initialing ATB",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) occurred on VE OS while initialing ATB",
				strerror(-ret));
	} else {
		PSEUDO_DEBUG("ATB intialization for vemva(0x%lx) successful\
				 on VE OS", vemva);
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This function will copy the base address of dir
 * veshm bitmap into the structure veshm_struct.
 *
 * @param[out] veshm Address of array where all information will be copied.
 */
void copy_vemva_dir_info(struct veshm_struct *veshm)
{
	int count = 0;
	struct list_head *temp_list_head = NULL;
	struct vemva_struct *veshm_data = NULL;

	PSEUDO_TRACE("invoked");
	/*Scan VEMVA list for the matching vemva_base*/
	list_for_each(temp_list_head, &vemva_header.vemva_list) {
		veshm_data = list_entry(temp_list_head,
				struct vemva_struct, list);
		veshm[count].vemva_base = (uint64_t)veshm_data->vemva_base;
		PSEUDO_DEBUG("copied dir with vemva base(0x%lx)",
				veshm[count].vemva_base);
		memcpy(&veshm[count].bitmap,
				&veshm_data->veshm_bitmap,
				sizeof(veshm_data->veshm_bitmap));
		count++;
	}
	PSEUDO_TRACE("returned");
}

/**
 * @brief This function will update ve page info.
 *
 * @param[in/out] flag This flag will indicate page size.
 */
void update_ve_page_info(uint64_t *flag)
{
	uint64_t pgsz = *flag;

	PSEUDO_TRACE("invoked");
	if (pgsz & MAP_64MB) {
		ve_page_info.page_size = PAGE_SIZE_64MB;
		ve_page_info.page_mask = PAGE_SIZE_64MB-1;
		ve_page_info.chunk_size = CHUNK_16GB;
		ve_page_info.chunk_mask = CHUNK_16GB-1;
		PSEUDO_DEBUG("Updating info for (%s) page",
				pgsz_to_pgstr(PAGE_SIZE_64MB));
	} else if (pgsz & MAP_2MB) {
		ve_page_info.page_size = PAGE_SIZE_2MB;
		ve_page_info.page_mask = PAGE_SIZE_2MB-1;
		ve_page_info.chunk_size = CHUNK_512MB;
		ve_page_info.chunk_mask = CHUNK_512MB-1;
		PSEUDO_DEBUG("Updating info for (%s) page",
				pgsz_to_pgstr(PAGE_SIZE_2MB));
	} else {
		ve_page_info.page_size = default_page_size;
		ve_page_info.page_mask = default_page_size-1;
		ve_page_info.chunk_size = default_page_size *
			ENTRIES_PER_DIR;
		ve_page_info.chunk_mask = ve_page_info.chunk_size-1;
		pgsz |= (default_page_size == PAGE_SIZE_2MB) ?
			MAP_2MB : MAP_64MB;
		*flag |= pgsz;
		PSEUDO_DEBUG("Updating info for default page size(0x%lx)",
				default_page_size);
	}
	/*set update flag*/
	ve_page_info.updated = 1;
	PSEUDO_TRACE("returned");
}

/**
 * @brief This function to handle mmap system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return On success returns mapped address, on returns negative of
 * errno on failure.
 */
ret_t ve_mmap(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0;
	size_t size = 0;
	off_t offset = 0;
	ret_t ret = 0;
	int prot = 0;
	uint64_t flag = 0;
	int filedes = 0;
	void *ret_addr = NULL;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("invoked");

	/* Get argument provided by user */
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (ret < 0) {
		PSEUDO_DEBUG("Error while fetching syscall(%s) argument",
				syscall_name);
		ret = -EFAULT;
		goto error_return;
	}

	/* Read mmap system call arguments */
	vemva    = args[0];
	size    = args[1];
	prot    = (int)args[2];
	flag    = (uint64_t)args[3];
	filedes = (int)args[4];
	offset  = args[5];

	PSEUDO_DEBUG("syscall(%s) argc vemav(0x%lx) size(0x%lx) "
			"prot(0x%x) flag(0x%lx) fd(0x%x) offset(0x%lx)",
			syscall_name, vemva, size, prot, flag, filedes, offset);

	/* Request for mmap */
	ret_addr = __ve_mmap(handle, vemva, size, prot, flag, filedes, offset);
	if (MAP_FAILED == ret_addr) {
		ret = -errno;
		PSEUDO_ERROR("Error(%s) for syscall(%s)", strerror(errno), syscall_name);
	} else {
		PSEUDO_DEBUG("(%s) syscall success (vemva:%p)", syscall_name, ret_addr);
		ret = (ret_t)ret_addr;
	}

error_return:
	PSEUDO_TRACE("returned(0x%lx)", ret);
	return ret;
}

/* return number of digits*/
static int get_digits(int num)
{
	int cnt = 0;
	if (num == 0)
		return 1;
	while ( num > 0 ) {
		num /= 10;
		cnt++;
	}
	return cnt;
}
/* success 0, recovered 1, failure negative number */
static int get_tmp_dir_path(int venum)
{
	FILE *fp = NULL;
        char buf[PATH_MAX + 14], *tmp_opath, *tmp_upath,  *tmp_usr_setting;
	char *s1, *c1;
	struct stat st;
	int ret = -1, cnt = 0;
	int retval = 0;
	DIR *dp = NULL;
	uid_t euid = geteuid();

	PSEUDO_TRACE("Invoked");

	tmp_upath = (char *)calloc(PATH_MAX, sizeof(char));
	if (tmp_upath == NULL) {
		PSEUDO_ERROR("faild to calloc():%s", strerror(errno));
		return -1;
	}
	tmp_opath = (char *)calloc(PATH_MAX, sizeof(char));
	if (tmp_opath == NULL) {
		PSEUDO_ERROR("faild to calloc():%s", strerror(errno));
		free(tmp_upath);
		return -1;
	}
	tmp_usr_setting = (char *)calloc(PATH_MAX, sizeof(char));
	if (tmp_usr_setting == NULL) {
		PSEUDO_ERROR("faild to calloc():%s", strerror(errno));
		retval = 1;
		goto set_path;
	}
	if (strlen(vemodcode_file_path) == 0) {
	        if ((fp = fopen(CONF_FILE_PATH, "r")) == NULL) {
			PSEUDO_DEBUG("failed to open conf file:%s",
				     strerror(errno));
			retval = 1;
			goto set_path;
		}

		while((fgets(buf, sizeof(buf), fp)) != NULL) {
			if ( buf[0] == '#' )
				continue;

			if (strstr(buf, "TMP_FILE_DIR=") != NULL) {
				if ((c1 = strchr(buf, '\n')) != NULL)
				  *c1 = '\0';
				s1 = (char *)&buf[0] + strlen("TMP_FILE_DIR=");
				/* 11 is (strlen("/veos-tmp") + '\0'+ strlen('/'). */
				if (strlen(s1) >= (PATH_MAX - 11
					   - get_digits(venum)
					   - get_digits(euid))) {
					PSEUDO_DEBUG("the specified path to "
						     "store temporary files is "
						     "too long.");
					retval = 1;
					continue;
				}
				ret = snprintf(tmp_usr_setting, PATH_MAX,
					       "%s/veos%d-tmp", s1, venum);
				if (ret < 0) {
					PSEUDO_DEBUG("failed to  snprintf(), "
						     "ret=%d, errno=%d",
						     ret, errno);
					retval = 1;
					continue;
				}
				/* check the specified directory.
				   Pseudo library expects veosN-tmp directory
				   is created by VEOS main. */
				ret = stat(tmp_usr_setting, &st);
				if (ret != 0) {
					PSEUDO_DEBUG("failed to get stat of %s. "
						     ": %s", tmp_usr_setting,
						     strerror(errno));
					retval = 1;
					continue;
				}
				if ((st.st_uid != 0) || (st.st_gid != 0)) {
					PSEUDO_DEBUG("%s is not owned by root.",
						     tmp_usr_setting);
					retval = 1;
					continue;
				}
				if (!S_ISDIR(st.st_mode)) {
					PSEUDO_DEBUG("%s is not directory",
						     tmp_usr_setting);
					retval = 1;
					continue;
				}
				retval = 0;
				cnt++;
			}
		}
	} else {
		strncpy(tmp_usr_setting, vemodcode_file_path, PATH_MAX);
		cnt = 1;
	}
 set_path:
	/* If the setting is not found or the path is invalid, use default path. */
	if (cnt == 0)
		ret = snprintf(tmp_upath, PATH_MAX, "%s/veos%d-tmp/%d",
			       DEFAULT_FILE_PATH, venum, euid);
	else
		ret = snprintf(tmp_upath, PATH_MAX, "%s/%d",
			       tmp_usr_setting, euid);
	if (ret < 0) {
		PSEUDO_ERROR("failed to snprintf(). ret=%d, errno=%d",
			     ret, errno);
		retval = -1;
		goto ret;
	}
	if (cnt == 0)
		ret = snprintf(tmp_opath, PATH_MAX, "%s/veos%d-tmp",
			       DEFAULT_FILE_PATH, venum);
	else
		ret = snprintf(tmp_opath, PATH_MAX, "%s",
			       tmp_usr_setting);
	if (ret < 0) {
		PSEUDO_ERROR("failed to snprintf(). ret=%d, errno=%d",
			     ret, errno);
		retval = -1;
		goto ret;
	}

	/* do stat(), if failed create to dir.*/
	dp = opendir(tmp_upath);
	if (dp == NULL) {
		ret = mkdir(tmp_upath, 0700);
		if ((ret != 0) && (errno != EEXIST)){
			PSEUDO_DEBUG("failed to create %s : %s", tmp_upath,  strerror(errno));
			if (cnt > 0) {
				cnt = 0;
				retval = 1;
				goto set_path;
			}
			PSEUDO_DEBUG("failed to use default file path");
			retval = -1;
			goto ret;
		}
		ret = chmod(tmp_upath, 0700);
		if (ret != 0) {
			PSEUDO_ERROR("failed to chmod():%s", strerror(errno));
			if (cnt > 0) {
				cnt = 0;
				retval = 1;
				goto set_path;
			}
			PSEUDO_DEBUG("failed to use default file path");
			retval = -1;
			goto ret;
		}
	} else {
		closedir(dp);
		ret = stat(tmp_upath, &st);
		if (ret != 0) {
			PSEUDO_DEBUG("failed to get stat of %s. : %s",
				     tmp_upath, strerror(errno));
			if (cnt > 0) {
				PSEUDO_DEBUG("use default file path");
				cnt = 0;
				retval = 1;
				goto set_path;
			}
			PSEUDO_DEBUG("failed to use default path");
			retval = -1;
			goto ret;
		}
		/* checking owner and permission */
		if (((st.st_gid != getegid()) && (st.st_uid != geteuid()) &&
		     (st.st_mode & S_IRWXO) != (S_IROTH | S_IWOTH | S_IXOTH)) ||
		    ((st.st_gid == getegid()) && (st.st_uid != geteuid()) &&
		     ((st.st_mode & S_IRWXG) != (S_IRGRP | S_IWGRP | S_IXGRP))) ||
		    ((st.st_uid == geteuid()) &&
		     ((st.st_mode & S_IRWXU) != (S_IRUSR | S_IWUSR | S_IXUSR)))) {
			PSEUDO_DEBUG("%s is not permitted", tmp_upath);
			if (cnt > 0) {
				PSEUDO_DEBUG("use default file path");
				cnt = 0;
				retval = 1;
				goto set_path;
			}
			PSEUDO_DEBUG("failed to use default path");
			retval = -1;
			goto ret;
		}
	}
	if (snprintf(vemodcode_file_path, PATH_MAX, "%s", tmp_opath) < 0) {
		PSEUDO_ERROR("failed to snprintf() for vemodcode_file_path");
		retval = -1;
		goto ret;
	}
	PSEUDO_DEBUG("temporary files for code modification "
		      "are stored in \"%s\".", vemodcode_file_path);
 ret:
	if (fp != NULL)
		fclose(fp);
	if (tmp_upath != NULL)
		free(tmp_upath);
	if (tmp_opath != NULL)
		free(tmp_opath);
	if (tmp_usr_setting != NULL)
		free(tmp_usr_setting);
	PSEUDO_TRACE("Returned(%d)", retval);
	return retval;
}


// 0 is successed, 1 is already exists, negative errno is failure.
static int create_inter_file(struct mod_file_info *info, char **inter_file_path,
			     time_t t)
{
	int ret = 0;
	char *file_path = NULL;
	char *fname = NULL, *file_name = NULL;

	PSEUDO_TRACE("Invoked");

	if (inter_file_path == NULL) {
		PSEUDO_ERROR("2nd argument is NULL");
		return -EINVAL;
	}
	file_path = calloc(PATH_MAX + NAME_MAX, sizeof(char));
	if (file_path == NULL) {
		ret = -errno;
		PSEUDO_ERROR("failed to allocate VH memory:%s", strerror(errno));
		return ret;
	}
	fname = calloc(PATH_MAX + NAME_MAX, sizeof(char));
	if(fname == NULL) {
		ret = -errno;
		PSEUDO_ERROR("failed to allocate VH memory:%s", strerror(errno));
		free(file_path);
		return ret;
	}
	strncpy(fname, info->file_path, PATH_MAX + NAME_MAX);
	file_name = basename(fname);
	ret = snprintf(file_path, PATH_MAX + NAME_MAX,
		"%s/%u/.inter_%d_%ld_%s",
		vemodcode_file_path, geteuid(), getpid(), t, file_name + 1);
	if (ret < 0) {
		PSEUDO_ERROR("failed to snprintf(), ret=%d, errno=%d",
			     ret, errno);
		ret = -EFAULT;
		goto hndl_free;
	}

	info->fd = open(file_path, O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);
	if (info->fd < 0) {
		ret = -errno;
		PSEUDO_ERROR("failed to open tmp file %s errno=%d\n",
			     file_path, errno);
		goto hndl_free;
	}

	ret = fstat(info->fd, &info->f_stat.stat);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_ERROR("Error(%s) while getting file stat", strerror(errno));
		goto hndl_close;
	}

	/* do not close intermediate file.
	 Pseudo library keeps intermediate file open until the code modificatoin
	is completed.*/
	*inter_file_path = file_path;
	free(fname);
	PSEUDO_TRACE("Returned");
	return 0;

 hndl_close:
	close(info->fd);
	info->fd = -1;
	unlink(file_path);
 hndl_free:
	free(fname);
	free(file_path);
	PSEUDO_TRACE("Returned(%d)", ret);
	return ret;
}

/* return 0 on success, return negative errno on failure*/
static int reopen_mod_file(struct mod_file_info *info)
{
	int ret = 0;
	int tmp_inter_fd = -1, tmp_fd = -1;
	struct stat st;

	PSEUDO_TRACE("Invoked");

	if (info->fd >= 0)
		tmp_inter_fd = info->fd;

	tmp_fd = open(info->file_path, O_RDONLY | O_CLOEXEC);
	if (tmp_fd < 0) {
		ret = -errno;
		PSEUDO_ERROR("failed to open tmp file %s : %s",
			     info->file_path, strerror(errno));
		goto hndl_close;
	}
	ret = fstat(tmp_fd, &st);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_ERROR("Error(%s) while getting file stat(fd:%d)",
			     strerror(errno), tmp_fd);
		goto hndl_close;
	}
	info->fd = tmp_fd;
	memcpy(&info->f_stat.stat, &st, sizeof(struct stat));
	/* close previously opened writable file*/
	if (tmp_inter_fd >= 0)
		close(tmp_inter_fd);

	PSEUDO_TRACE("Returned");
	return 0;

hndl_close:
	if (info->fd >= 0) {
		close(info->fd);
		info->fd = -1;
	}
	if (tmp_fd >= 0)
		close(tmp_fd);
	PSEUDO_TRACE("Returned(%d)", ret);
	return ret;
}

/* return the lagest address of elf */
static uint64_t check_addr_in_loadable_seg(uint64_t addr)
{
	int seg_num = 0;
	struct ve_vh_segmap *seg_addr;
	uint64_t tmp_seg_addr = 0;
	uint64_t tmp_seg_sz = 0;
	/* uint64_t tmp_seg_addr_min = 0, tmp_seg_addr_max = VEMMR_BOTTOM; */
	uint64_t tmp_seg_addr_min = 0;
	uint64_t aligned_seg_addr_min = 0;

	PSEUDO_TRACE("Invoked");

	PSEUDO_TRACE("seg_num\tseg_addr\tis_fixed\tis_interp\toffset\tve_addr\t"
		     "length\tve_map_sz\tve_file_sz\tis_data\toff\tflag");
	for (seg_num = 0; seg_num < load_elf.loadable_segnum; seg_num++) {
		seg_addr = ((struct ve_vh_segmap *)load_elf.seg + seg_num);
		PSEUDO_TRACE("seg_addr:%d\t%p\t\t%d\t%d\t%lx\t%lx\t\t%lx\t%lx\t"
			     "\t%lx\t%d\t%lx\t%lx",
			     seg_num, (void *)seg_addr,
			     seg_addr->is_fixed, seg_addr->is_interp,
			     seg_addr->offset, seg_addr->ve_addr,
			     seg_addr->length, seg_addr->ve_map_size,
			     seg_addr->ve_file_size, seg_addr->is_data,
			     seg_addr->off, seg_addr->flag);
		tmp_seg_sz = ALIGN(seg_addr->ve_map_size, ve_page_info.page_size);
		tmp_seg_addr = seg_addr->ve_addr + tmp_seg_sz;
		if (tmp_seg_addr_min < tmp_seg_addr )
			tmp_seg_addr_min = tmp_seg_addr;
	}

	/* avoid bss */
	if (tmp_seg_addr_min < (load_elf.stat.start_bss + load_elf.stat.size_bss))
		tmp_seg_addr_min
		  = load_elf.stat.start_bss + load_elf.stat.size_bss;
	if (tmp_seg_addr_min < (load_elf.stat.start_bss_dyn + load_elf.stat.size_bss_dyn))
		tmp_seg_addr_min
		  = load_elf.stat.start_bss_dyn + load_elf.stat.size_bss_dyn;

	PSEUDO_TRACE("avoided address: 0x%lx", tmp_seg_addr_min);

	aligned_seg_addr_min = tmp_seg_addr_min;
	if (!IS_ALIGNED(tmp_seg_addr_min, ve_page_info.page_size)) {
		aligned_seg_addr_min = ALIGN(tmp_seg_addr_min,
					     ve_page_info.page_size);
		PSEUDO_DEBUG("Given avoided addr aligned to (0x%lx)",
			     aligned_seg_addr_min);
	}
	PSEUDO_TRACE("Returned(%lx)", aligned_seg_addr_min);
	return aligned_seg_addr_min;
}

/* return VE node number on success, return -1 on failure*/
static int get_ve_node_num(veos_handle *hndl)
{
	char *sock_name = NULL;
	char *sock_dir_name = NULL;
	char *tmp_sock_path0 = NULL;
	char *tmp_sock_path1 = NULL;
	int c_cnt = 0;
	char *tmp_c = NULL;

	PSEUDO_TRACE("Invoked");

	tmp_sock_path0 = (char *)calloc(NAME_MAX + PATH_MAX, sizeof(char));
	if (tmp_sock_path0 == NULL) {
		PSEUDO_ERROR("failed to allocate memory:%s", strerror(errno));
		return -1;
	}
	tmp_sock_path1 = (char *)calloc(NAME_MAX + PATH_MAX, sizeof(char));
	if (tmp_sock_path1 == NULL) {
		PSEUDO_ERROR("failed to allocate memory:%s", strerror(errno));
		free(tmp_sock_path0);
		return -1;
	}
	strncpy(tmp_sock_path0, hndl->veos_sock_name, NAME_MAX + PATH_MAX);
	strncpy(tmp_sock_path1, hndl->veos_sock_name, NAME_MAX + PATH_MAX);
	sock_name = basename(tmp_sock_path0);
	sock_dir_name = dirname(tmp_sock_path1);
	PSEUDO_TRACE("veos_sock_name:%s", hndl->veos_sock_name);
	PSEUDO_TRACE("sock_name:%s, sock_dir_name:%s", sock_name, sock_dir_name);

	tmp_c = sock_name;
	while (*tmp_c != '\0') {
		if(isdigit(*tmp_c))
			c_cnt = 10 * c_cnt + (*tmp_c - '0');
		else if (*tmp_c == '.' )
			break;
		tmp_c++;
	}
	if (tmp_sock_path0)
		free(tmp_sock_path0);
	if (tmp_sock_path1)
		free(tmp_sock_path1);

	PSEUDO_TRACE("Returned(%d)", c_cnt);
	return c_cnt;
}

/* On success return 0, return 1 when pid is not found,
   on failure return -1 */
static int get_proc_status(pid_t pid, char *status)
{
	PROCTAB* proc = NULL;
	proc_t *procinfo = NULL;
	char path[PATH_MAX]="";
	struct stat st;

	proc = openproc(PROC_FILLSTAT | PROC_PID, &pid);
	if (proc == NULL) {
		PSEUDO_DEBUG("failed to open proc interface for pid:%d", pid);
		snprintf(path, PATH_MAX, "/proc/%d/stat", pid);
		if (stat(path, &st) != 0) {
			if (errno == ENOENT) {
				PSEUDO_DEBUG("PID:%d may be terminated", pid);
				return 1;
			}
		}
		return -1;
	}
	procinfo = readproc(proc, NULL);
	if (procinfo == NULL) {
		PSEUDO_DEBUG("failed to read proc info for pid:%d", pid);
		return -1;
	}
	*status = procinfo->state;
	freeproc(procinfo);
	closeproc(proc);

	return 0;
}

/* On success return 0, on failure return -1 */
static int write_owner_pid_to_lockfile(int fd)
{
	ssize_t  write_sz;
	char buf[20];

	lseek(fd, 0, SEEK_SET);
	if (snprintf(buf, 20, "PID:%u", getpid()) < 0) {
		PSEUDO_ERROR("failed to snprintf for owner pid of lock file");
		return -1;
	}
	write_sz = code_modify_write(fd, buf, sizeof(buf));
	if (write_sz != sizeof(buf)) {
		PSEUDO_ERROR("failed to write owner pid (fd:%d): %s",
			     fd, strerror(errno));
		return -1;
	}
	if (fsync(fd) != 0) {
		PSEUDO_ERROR("failed to fsync for (fd:%d): %s",
			     fd, strerror(errno));
		return -1;
	}
	return 0;
}
/* On success return 0, on failure return -1 */
static int delete_owner_pid_from_lockfile(int fd)
{
	char buf[20] = "";
	ssize_t w_sz;
	memset(buf, '\0', 20);
	lseek(fd, 0, SEEK_SET);
	w_sz = code_modify_write(fd, buf, sizeof(buf));
	if (w_sz != sizeof(buf)) {
		PSEUDO_ERROR("failed to write to fd:%d :%s",
			     fd, strerror(errno));
		return -1;
	}
	if (fsync(fd) != 0) {
		PSEUDO_ERROR("failed to fsync for fd:%d : %s",
			     fd, strerror(errno));
		return -1;
	}
	return 0;
}
/* On success returns 0, on failure returns -1, no found pid info returns 1 */
static int get_owner_pid_from_lockfile(struct tmp_file_info *info,
				       pid_t *pid)
{
	char tmp_buf[20];
	ssize_t read_sz;
	uint64_t tmp_pid;
	lseek(info->lock_fd, 0, SEEK_SET);
	read_sz = code_modify_read(info->lock_fd, tmp_buf, sizeof(tmp_buf));
	if (read_sz < 0) {
		PSEUDO_ERROR("failed to read from %s: %s", info->lock_file_path,
			     strerror(errno));
		return -1;
	} else if (read_sz != sizeof(tmp_buf)) {
		PSEUDO_TRACE("No enough data in %s", info->lock_file_path);
		return 1;
	}
	if(strstr(tmp_buf, "PID:") == NULL) {
		PSEUDO_TRACE("No owner PID in %s", info->lock_file_path);
		return 1;
	} else {
		/* add 4 to exclude "PID:" */
		tmp_pid = strtoul((char *)&tmp_buf[0] + 4, NULL, 10);
		if (tmp_pid == ULLONG_MAX) {
			PSEUDO_ERROR("failed to get PID from %s: %s",
				     info->lock_file_path, strerror(errno));
			return -1;
		}
		PSEUDO_TRACE("pid of lock owner is %lu (%s)", tmp_pid,
			     info->lock_file_path);
		*pid = (pid_t)tmp_pid;
	}
	return 0;
}

/* return 0 on succsess, return -1 on failure.
   NOTE: This function do not close lock file because lock file
   is used until completion of code modification */
static int open_lock_file_and_try_to_get(struct tmp_file_info *info, int timeout)
{
	int ret = 0;
	int retval = 0;
	int tmp_fd = 0;
	pid_t tmp_owner_pid = 0;
	char owner_stat;
	struct timespec req, rem;
	uint64_t tmout = timeout * 1e+9; //ns

	req.tv_sec = 0;
	req.tv_nsec = 1e+6; //1ms

	if (info == NULL) {
		PSEUDO_ERROR("invalid argument");
		return -1;
	}

	if (info->lock_fd >= 0) {
		PSEUDO_DEBUG("%s is opened already, close and re-open this file",
			     info->lock_file_path);
		close(info->lock_fd);
		info->lock_fd = -1;
	}

	while(1) {
		tmp_fd = open(info->lock_file_path, O_CREAT|O_RDWR,
			      S_IRUSR | S_IWUSR);
		if (tmp_fd < 0) {
			PSEUDO_ERROR("failed to open %s: %s",
				     info->lock_file_path, strerror(errno));
			return -1;
		}
		info->lock_fd = tmp_fd;
		ret = flock(info->lock_fd, LOCK_EX | LOCK_NB);
		if ( ret != 0 ) {
			if ( errno != EWOULDBLOCK ) {
				PSEUDO_ERROR("failed to lock %s: %s",
					     info->lock_file_path,
					     strerror(errno));
				retval = -1;
				goto hndl_close;
			} else {
				PSEUDO_TRACE("failed to lock %s, "
					     "this already locked.",
					     info->lock_file_path);
				ret = get_owner_pid_from_lockfile(
						info, &tmp_owner_pid);
				close(info->lock_fd);
				info->lock_fd = -1;
				tmp_fd = -1;
				if (ret == -1) {
					PSEUDO_ERROR("failed to get owner pid");
					return -1;
				} else if (ret == 1) {
					PSEUDO_TRACE("no owner pid in lock file");
					/* may be locked by VEOS, retry */
					continue;
				}
				ret = get_proc_status(tmp_owner_pid, &owner_stat);
				if (ret == -1) {
					PSEUDO_ERROR("failed to get status of "
						     "PID:%d", tmp_owner_pid);
					return -1;
				} else if (ret == 1) {
					PSEUDO_DEBUG("PID:%d may be in "
						     "terminating. retry",
						     tmp_owner_pid);
					continue;
				} else {
					PSEUDO_TRACE("STATUS:%c", owner_stat);
				}
				/* If state of owner process is STOP by swap-out, etc...,
				 delete file for exlusive control */
				if (owner_stat == 'T') {
					PSEUDO_DEBUG("status of owner process(%u)"
						     " is STOP. unlink %s",
						     tmp_owner_pid,
						     info->lock_file_path);
					unlink(info->lock_file_path);
				}
			}
		} else {
			PSEUDO_TRACE("success to aquire exclusive lock of %s",
				     info->lock_file_path);
			if (write_owner_pid_to_lockfile(info->lock_fd) != 0) {
				PSEUDO_ERROR("failed to write owner pid to %s",
					     info->lock_file_path);
				retval = -1;
				goto hndl_unlock;
			}
			retval = 0;
			break;
		}
		if (nanosleep(&req, &rem) != 0) {
			PSEUDO_ERROR("failed to nanosleep(), errno=%d",
				     errno);
			retval = -1;
			goto hndl_close;
		}
		tmout = tmout - req.tv_sec * 1e+9 - req.tv_nsec;
		if (tmout <= 0) {
			 PSEUDO_ERROR("failed to waiting unlock of %s,"
				     " time out occured",
				     info->lock_file_path);
			 retval = -1;
			 goto hndl_close;
		}
	}
	return retval;
 hndl_unlock:
	flock(info->lock_fd, LOCK_UN);
 hndl_close:
	close(info->lock_fd);
	info->lock_fd = -1;
	return retval;
}

/* return 0 when file already exists, return 1 is not found,
   return -1 on failure */
static int check_file_exist(const char *path)
{
	struct stat st;
	int ret = 0;

	PSEUDO_TRACE("Invoked");
	ret = stat(path, &st);
	if (ret != 0) {
		if (errno == ENOENT) {
			PSEUDO_TRACE("%s is not found", path);
			return 1;
		} else {
			PSEUDO_ERROR("failed to stat():%s",strerror(errno));
			return -1;
		}
	}

	if (st.st_uid != geteuid()){
		errno = EPERM;
		PSEUDO_DEBUG("%s is not owned by %d", path, geteuid());
		return 1;
	}
	PSEUDO_TRACE("%s is found", path);
	return 0;
}

/* return 0 when file already exists or  modifing now,
   return -ENOENT when mod file is not exist,
   return negative errno on failure */
static int check_mod_file_exist(struct tmp_file_info *info)
{
	int ret_mod, ret_org, ret_tbl;

	PSEUDO_TRACE("Invoked");
	ret_mod = check_file_exist(info->mod.file_path);
	ret_org = check_file_exist(info->org.file_path);
	ret_tbl = check_file_exist(info->tbl.file_path);

	if ((ret_mod == 0) && (ret_org == 0) && (ret_tbl == 0)) {
		PSEUDO_DEBUG("temporary files is exist");
		return 0;
	} else if ( (ret_mod == 1) || (ret_org == 1) || (ret_tbl == 1)) {
		PSEUDO_DEBUG("temporary files are not found");
		return -ENOENT;
	} else {
		PSEUDO_ERROR("temporary files existence check failed."
			"(mod:%d org:%d tbl:%d)", ret_mod, ret_org, ret_tbl);
		return -ECANCELED;
	}

	PSEUDO_ERROR("Failed to check of temporary file existance");
	return -ECANCELED;
}

/*return 0 on success, return -1 on failure*/
static int init_mod_file_info(struct mod_file_info *info,
			      const char *prefix, uint64_t addr, uint64_t size,
			      struct file_stat *f_stat)
{
  	char *tmp_file_name = NULL;
	int ret = 0;

	PSEUDO_TRACE("Invoked");
	if (info == NULL) {
		PSEUDO_ERROR("mod_file_info is NULL");
		return -1;
	}

	/* !!need to check path length!! */
	tmp_file_name = (char *)calloc(NAME_MAX + PATH_MAX, sizeof(char));
	if (tmp_file_name == NULL) {
		PSEUDO_ERROR("failed to allocate memory for tmp_file_name: %s",
			     strerror(errno));
		return -1;
	}

	ret = snprintf(tmp_file_name, NAME_MAX + PATH_MAX,
		       "%s/%u/%s_%lu_%lu_%ld_%ld_%lx",
		       vemodcode_file_path, geteuid(), prefix,
		       f_stat->stat.st_ino, f_stat->stat.st_dev,
		       f_stat->stat.st_size, f_stat->stat.st_mtime, addr);
	if (ret < 0) {
		PSEUDO_ERROR("Failed to copy file path, ret=%d, errno=%d",
			     ret, errno);
		free(tmp_file_name);
		return -1;
	}

	info->fd = -1;
	info->file_path = tmp_file_name;
	info->size = size;
	info->vemva = (void *)addr;
	info->f_stat.pgsz = f_stat->pgsz;
	info->org_ino = f_stat->stat.st_ino;
	info->org_sz = f_stat->stat.st_size;
	info->org_mtime = f_stat->stat.st_mtime;
	info->org_dev = f_stat->stat.st_dev;

	PSEUDO_TRACE("Returned");
	return 0;
}


/* return 0 on success, return -1 on failure*/
static int init_all_tmp_file_info(struct tmp_file_info **info, uint64_t org_addr,
				  uint64_t mod_addr, uint64_t tbl_addr,
				  uint64_t org_sz, uint64_t mod_sz,
				  struct file_stat *f_stat)
{
	char *lock_file_name = NULL;
	int ret = 0, ret_mod = 0, ret_org = 0, ret_tbl =0;

	PSEUDO_TRACE("Invoked");
	*info = calloc(1, sizeof(struct tmp_file_info));
	if (*info == NULL) {
		PSEUDO_ERROR("failed to allocate memory for mod_file_info: %s",
			     strerror(errno));
		return -1;
	}
	lock_file_name = (char *)calloc(NAME_MAX + PATH_MAX, sizeof(char));
	if (lock_file_name == NULL) {
		PSEUDO_ERROR("failed to allocate memory for lock_file_name:%s",
			     strerror(errno));
		free(*info);
		*info = NULL;
		return -1;
	}
	ret = snprintf(lock_file_name, NAME_MAX + PATH_MAX,
		       "%s/%u/%s_%lu_%lu_%ld_%ld_%lx_%lx_%lx",
		       vemodcode_file_path, geteuid(), ".lock",
		       f_stat->stat.st_ino, f_stat->stat.st_dev,
		       f_stat->stat.st_size, f_stat->stat.st_mtime, mod_addr,
		       org_addr, tbl_addr);
	if (ret < 0) {
		PSEUDO_ERROR("Failed to snprintf() for copying file path."
			     " ret=%d, errno=%d", ret, errno);
		free(*info);
		*info = NULL;
		free(lock_file_name);
		return -1;
	}
	(*info)->lock_file_path = lock_file_name;
	(*info)->lock_fd = -1;

	ret_mod = init_mod_file_info(&(*info)->mod, ".tmpModCode",
				     mod_addr, mod_sz, f_stat);
	ret_org = init_mod_file_info(&(*info)->org, ".tmpCode",
				     org_addr, org_sz, f_stat);
	ret_tbl = init_mod_file_info(&(*info)->tbl, ".tmpTable",
				     tbl_addr, org_sz, f_stat);
	if ((ret_mod != 0) || (ret_org != 0) || (ret_tbl != 0)) {
		if ((*info)->mod.file_path != NULL)
			free((*info)->mod.file_path);
		if ((*info)->tbl.file_path != NULL)
			free((*info)->tbl.file_path);
		if ((*info)->org.file_path != NULL)
			free((*info)->org.file_path);
		free(*info);
		*info = NULL;
		free(lock_file_name);
		PSEUDO_DEBUG("failed to init tmporary file info");
		return -1;
	}
	PSEUDO_TRACE("Returned");
	return 0;
}

/* return 0 on success, return negative errno on failure*/
static int create_all_mod_file_and_open(struct tmp_file_info *info,
					int fd, size_t mod_sz)
{
	int ret = 0;
	int retval = -1;
	time_t tm;
	char *mod_inter_file = NULL, *org_inter_file = NULL, *tbl_inter_file = NULL;

	PSEUDO_TRACE("Invoked");

	tm = time(NULL);
	/* open file with write mode if there is no modified files*/
	retval =  create_inter_file(&info->mod, &mod_inter_file, tm);
	if (retval != 0) {
		PSEUDO_DEBUG("failed to create inter file for modified code: %s",
			     strerror(errno));
		goto hndl_free;
	}

	retval =  create_inter_file(&info->tbl, &tbl_inter_file, tm);
	if (retval != 0) {
		PSEUDO_DEBUG("failed to create inter file for "
			     "address translation table: %s", strerror(errno));
		goto hndl_del_mod;
	}

	retval =  create_inter_file(&info->org, &org_inter_file, tm);
	if (retval != 0) {
		PSEUDO_DEBUG("failed to create inter file for "
			     "original code: %s", strerror(errno));
		goto hndl_del_tbl;
	}

	/* Modification Code */
	ret = code_modify(fd, info->mod.fd, (unsigned long)info->mod.vemva,
			  info->tbl.fd, (unsigned long)info->tbl.vemva,
			  info->org.fd, (unsigned long)info->org.vemva, mod_sz);
	if (ret < 0) {
		PSEUDO_ERROR("failed to code modification");
		retval = -ECANCELED;
		goto hndl_del_org;
	}

	/* rename intermediate file */
	if (rename(tbl_inter_file, info->tbl.file_path) != 0) {
		PSEUDO_DEBUG("failed to rename %s to %s: %s",
			     tbl_inter_file, info->tbl.file_path,
			     strerror(errno));
		retval = -errno;
		goto hndl_del_org;
	}
	if (rename(mod_inter_file, info->mod.file_path) != 0) {
		PSEUDO_DEBUG("failed to rename %s to %s: %s",
			     mod_inter_file, info->mod.file_path,
			     strerror(errno));
		retval = -errno;
		goto hndl_del_tmptbl;
	}
	if (rename(org_inter_file, info->org.file_path) != 0) {
		PSEUDO_DEBUG("failed to rename %s to %s: %s",
			     org_inter_file, info->org.file_path,
			     strerror(errno));
		retval = -errno;
		goto hndl_del_tmpmod;
	}

	retval = 0;

 hndl_free:
	if (org_inter_file != NULL)
		free(org_inter_file);
	if (tbl_inter_file != NULL)
		free(tbl_inter_file);
	if (mod_inter_file != NULL)
		free(mod_inter_file);

	PSEUDO_TRACE("Returned(%d)", retval);
	return retval;

 hndl_del_tmpmod:
	close(info->mod.fd);
	info->mod.fd = -1;
	unlink(info->mod.file_path);
 hndl_del_tmptbl:
	close(info->tbl.fd);
	info->tbl.fd = -1;
	unlink(info->tbl.file_path);
 hndl_del_org:
	if (info->org.fd >= 0) {
		close(info->org.fd);
		info->org.fd = -1;
	}
	if (org_inter_file != NULL) {
		unlink(org_inter_file);
		free(org_inter_file);
	}
 hndl_del_tbl:
	if (info->tbl.fd >= 0) {
		close(info->tbl.fd);
		info->tbl.fd = -1;
	}
	if (tbl_inter_file != NULL) {
		unlink(tbl_inter_file);
		free(tbl_inter_file);
	}
 hndl_del_mod:
	if (info->mod.fd >= 0) {
		close(info->mod.fd);
		info->mod.fd = -1;
	}
	if (mod_inter_file != NULL) {
		unlink(mod_inter_file);
		free(mod_inter_file);
	}
	return retval;
}

// err -1, need to modify 1, other 0
static int check_to_elf_flag(int fd)
{
	int cpy_fd = 0;
	FILE *fp = NULL;
	Elf64_Ehdr *ehdr = NULL;
	int retval = 0;
	size_t ret = 0;
	char *buf = 0;

	PSEUDO_TRACE("Invoked");
	cpy_fd = dup(fd);
	if (cpy_fd < 0) {
		PSEUDO_DEBUG("Failed to duplicate file descripter: fd=%d: %s",
			     fd, strerror(errno));
		return -1;
	}
	fp = fdopen(cpy_fd,"r");
	if (fp == NULL) {
		PSEUDO_DEBUG("Failed to open file stream.(fd:%d, org_fd:%d): %s",
			     cpy_fd, fd, strerror(errno));
		return -1;
	}
	fseek(fp, 0, SEEK_SET);
	buf = (char *)calloc(1, sizeof(Elf64_Ehdr));
	if (buf == NULL) {
		retval = -1;
		PSEUDO_DEBUG("Failed to allocate VH memory: %s", strerror(errno));
		goto hndl_close;
	}
	ret = fread(buf, sizeof(Elf64_Ehdr), 1, fp);
	if (ret < 1) {
		retval = -1;
		PSEUDO_DEBUG("failed to read file stream.(fd=%d org_fd=%d): %s",
			     cpy_fd, fd, strerror(errno));
		goto hndl_free;
	}
	ehdr = (Elf64_Ehdr *)(buf);

	if (((ehdr->e_flags & EF_VE_ARCH_MASK) == EF_VE_ARCH_VE1)
	    && ((ehdr->e_flags & EF_VE_EXT_VE3) == 0 )) {
		PSEUDO_DEBUG("This needs to modify code");
		retval = 1;
	}

hndl_free:
	free(buf);
 hndl_close:
	fseek(fp, 0, SEEK_SET);
	if (fclose(fp) < 0) 
		PSEUDO_TRACE("failed to close. fd=%d org_fd=%d errno=%d",
			    cpy_fd, fd, errno);
	PSEUDO_TRACE("Returned(%d)", retval);
	return retval;
}

static struct ve_tmpfile_set *remove_tmpfile_info(vemva_t addr)
{
	struct ve_tmpfile_set *tmp = NULL, *cur = NULL;
	struct ve_tmpfile_set *ret = NULL;
	pthread_mutex_lock(&ve_tmpfile_info.modcode_tmpfile_lock);
	list_for_each_entry_safe(cur, tmp, &ve_tmpfile_info.tmpfiles.list, list) {
		if (cur->org.addr == addr) {
			ret = cur;
			list_del(&ret->list);
			break;
		}
	}
	pthread_mutex_unlock(&ve_tmpfile_info.modcode_tmpfile_lock);
	return ret;
}

static int add_tmpfile_info(struct tmp_file_info *info)
{
	struct ve_tmpfile_set *tmp = NULL;

	tmp = calloc(sizeof(struct ve_tmpfile_set), 1);
	if (tmp == NULL) {
		PSEUDO_ERROR("failed to allocate memory: %s", strerror(errno));
		return -1;
	}
	if (snprintf(tmp->lock_fname, PATH_MAX + NAME_MAX, "%s",
		     info->lock_file_path) < 0) {
		PSEUDO_ERROR("faield to snprintf : %s", strerror(errno));
		goto hndl_err;
	}
	tmp->mod.addr = (vemva_t)info->mod.vemva;
	tmp->mod.sz = (size_t)info->mod.size;
	if (snprintf(tmp->mod.fname, PATH_MAX + NAME_MAX, "%s",
		     info->mod.file_path) < 0) {
		PSEUDO_ERROR("faield to snprintf : %s", strerror(errno));
		goto hndl_err;
	}
	tmp->org.addr = (vemva_t)info->org.vemva;
	tmp->org.sz = (size_t)info->org.size;
	if (snprintf(tmp->org.fname, PATH_MAX + NAME_MAX, "%s",
		     info->org.file_path) < 0) {
		PSEUDO_ERROR("faield to snprintf : %s", strerror(errno));
		goto hndl_err;
	}
	tmp->tbl.addr = (vemva_t)info->tbl.vemva;
	tmp->tbl.sz = (size_t)info->tbl.size;
	if (snprintf(tmp->tbl.fname, PATH_MAX + NAME_MAX, "%s",
		     info->tbl.file_path) < 0) {
		PSEUDO_ERROR("faield to snprintf : %s", strerror(errno));
		goto hndl_err;
	}
	INIT_LIST_HEAD(&tmp->list);

	pthread_mutex_lock(&ve_tmpfile_info.modcode_tmpfile_lock);
	list_add_tail(&tmp->list, &ve_tmpfile_info.tmpfiles.list);
	pthread_mutex_unlock(&ve_tmpfile_info.modcode_tmpfile_lock);
	return 0;
 hndl_err:
	free(tmp);
	return -1;
}

static int delete_tmpfiles(struct ve_tmpfile_set **tmp)
{
	int fd = -1;
	int ret = 0;
	int retval = -1;
	int skip_del_lock = 1;

	fd = open((*tmp)->lock_fname, O_RDWR);
	if (fd < 0) {
		PSEUDO_ERROR("failed to open %s: %s",
			     (*tmp)->lock_fname, strerror(errno));
		goto hndl_ret;
	}
	ret = flock(fd, LOCK_EX | LOCK_NB);
	if (ret < 0) {
		PSEUDO_DEBUG("failed to aquire %s: %s",
			     (*tmp)->lock_fname, strerror(errno));
		close(fd);
		goto hndl_ret;
	}
	retval = 0;
	/* Ignore all errors because VEOS will erase tmporary files*/
	if (write_owner_pid_to_lockfile(fd) < 0)
		PSEUDO_DEBUG("failed to write owner pid to %s",
			     (*tmp)->lock_fname);
	if (unlink((*tmp)->mod.fname) < 0) {
		PSEUDO_DEBUG("failed to unlink(%s):%s",
			     (*tmp)->mod.fname, strerror(errno));
		skip_del_lock = 0;
	}
	if (unlink((*tmp)->org.fname) < 0) {
		PSEUDO_DEBUG("failed to unlink(%s):%s",
			     (*tmp)->org.fname, strerror(errno));
		skip_del_lock = 0;
	}
	if (unlink((*tmp)->tbl.fname) < 0) {
		PSEUDO_DEBUG("failed to unlink(%s):%s",
			     (*tmp)->tbl.fname, strerror(errno));
		skip_del_lock = 0;
	}
	if (delete_owner_pid_from_lockfile(fd) < 0)
		PSEUDO_DEBUG("failed to delete owner pid from %s",
			     (*tmp)->lock_fname);
	if (skip_del_lock == 1) {
		if (unlink((*tmp)->lock_fname) < 0)
			PSEUDO_DEBUG("failed to unlink(%s):%s",
				     (*tmp)->lock_fname, strerror(errno));
	}
	if (flock(fd, LOCK_UN) < 0)
		PSEUDO_DEBUG("failed to unlock %s", (*tmp)->lock_fname);
	close(fd);
 hndl_ret:
	free(*tmp);
	*tmp = NULL;
	return retval;
}

static int delete_xtbl(veos_handle *handle, uint64_t tbl_addr)
{
	size_t idx = 0;
	int ret = 0;
	struct ve_xtbl_adr *cur;

	pthread_mutex_lock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
	for (idx = 0; idx < ve_xtbl_adr_hdr.num; idx++) {
		cur = &(ve_xtbl_adr_hdr.ve_xtbl_addrtbl[idx]);
		if (tbl_addr == (uint64_t)cur->xtbl) {
			PSEUDO_TRACE("fill zero ve_xtbl_addr(%p) idx=%ld",
				     cur, idx);
			memset(cur, '\0', sizeof(struct ve_xtbl_adr));
			if (ve_xtbl_adr_hdr_info.xtbl_hdr != NULL) {
				memcpy(ve_xtbl_adr_hdr_info.xtbl_hdr,
				       &ve_xtbl_adr_hdr, PAGE_SIZE_2MB);
				ret = ve_send_data(handle,
					(uint64_t)ve_xtbl_adr_hdr_info.xtbl_hdr,
					PAGE_SIZE_2MB, &ve_xtbl_adr_hdr);
				if (ret < 0) {
					PSEUDO_ERROR("failed to send data : %s",
						     strerror(-ret));
					ret = -1;
					goto hndl_ret;
				}
				ret = 0;
				goto hndl_ret;
			}
			PSEUDO_DEBUG("xtbl_hdr is not ready");
			ret = -1;
			goto hndl_ret;
		}
	}
	PSEUDO_DEBUG("not found tbl_addr(%lx) in ve_xtbl_addr_dhdr", tbl_addr);
	ret = -1;
 hndl_ret:
	pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
	return ret;
}

/**
 * @brief Function to handle memory mapping request.
 *
 * @param[in] handle VEOS handle
 * @param[in] addr Memory mapping is to be done at this address
 * @param[in] size Size of the memory to map
 * @param[in] prot Permission to set on mapped memory
 * @param[in] flag Additional information for memory mapping
 * @param[in] filedes File descriptor in case of file backed mapping
 * @param[in] offset Offset of the file
 *
 * @return On success returns virtual address* on failure returns MAP_FAILED
 * and set errno.
 */

int this_file_is_modified=0;
void *__ve_mmap(veos_handle *handle, vemva_t addr, size_t size,
		int prot, uint64_t flag, int filedes, off_t offset)
{
	int64_t ret = 0;
	int ve_prot = 0;
	int64_t errno_ret = 0, mmap_flag = 0;
	size_t aligned_sz = 0, align_fsz = 0;
	off_t off_s = 0;
	off_t off_e = 0;
	void *ret_addr = NULL;
	struct file_stat *f_stat = NULL;
	int is_modify = 0;
	size_t mod_sz = 0, aligned_mod_sz = 0;

	struct tmp_file_info *info = NULL;
	struct ve_xtbl_adr xtbl;
	void *mod_addr = NULL, *tbl_addr = NULL;
	void *tmp = NULL;
	uint64_t toff = 0, tsz = 0;
	uint64_t req_flg = 0;
	uint64_t req_mod_addr = 0;
	uint64_t aligned_seg_addr_min = 0;
	struct file_stat *exec_stat = NULL;
	int open_retry_cnt = 100;

	PSEUDO_TRACE("invoked with vemva(0x%lx) size(0x%lx) prot(%x) "
			"flag(0x%lx) fd(%d) offset(0x%lx)",
			addr, size, prot, flag, filedes, offset);

	ve_prot = prot;
	/* If file back mmap than add PROT_READ in protection bit
	 * to enble VHVA translation by DMA engine
	 */
	if (!(flag & MAP_ANON)) {
		prot |= PROT_READ;
	}

	/* Check for the validity of flag */
	if (flag & (MAP_GROWSDOWN | MAP_HUGETLB | MAP_LOCKED | MAP_NONBLOCK
				| MAP_POPULATE | MAP_32BIT)) {
		PSEUDO_DEBUG("Error(%s) flag(0x%lx)", strerror(EINVAL), flag);
		errno = EINVAL;
		return MAP_FAILED;
	}

	/* Update ve page info*/
	update_ve_page_info(&flag);

	/*
	 * Check for alignment (VE_PAGE_SIZE Alignment) of
	 * file offset received
	 */
	if (!(MAP_ANON & flag)) {
		if (!IS_ALIGNED(offset, ve_page_info.page_size)) {
			PSEUDO_DEBUG("Offset is not aligned to page boundary");
			errno = EINVAL;
			return MAP_FAILED;
		}
		f_stat = (struct file_stat *)calloc(1, sizeof(struct file_stat));
		if (f_stat == NULL) {
			ret = errno;
			PSEUDO_DEBUG("Error(%s) while allocating mem for f_stat",
					strerror(ret));
			return MAP_FAILED;
		}
		ret = fstat(filedes, &f_stat->stat);
		if (0 > ret) {
			ret = errno;
			PSEUDO_DEBUG("Error(%s) while getting file stat", strerror(ret));
			free(f_stat);
			return MAP_FAILED;
		}

	}

	/* Is size zero ?*/
	if (!size) {
		PSEUDO_DEBUG("Error(%s) size(0x%lx)", strerror(EINVAL), size);
		free(f_stat);
		errno = EINVAL;
		return MAP_FAILED;
	}

	/*align size with page size*/
	aligned_sz = size;
	if (!IS_ALIGNED(size, ve_page_info.page_size)) {
		aligned_sz = ALIGN(size, ve_page_info.page_size);
		PSEUDO_DEBUG("Given size aligned to (0x%lx)", aligned_sz);
		if (!aligned_sz) {
			free(f_stat);
			errno = ENOMEM;
			return MAP_FAILED;
		}
	}
	/*calculate start and end offset*/
	if (!(MAP_ANON & flag)) {
		off_s = (off_t)(offset / ve_page_info.page_size);
		off_e = (off_t)(((offset + aligned_sz) / ve_page_info.page_size) - 1);

		f_stat->offset_start = off_s;
		f_stat->offset_end = off_e;
		f_stat->pgsz = ve_page_info.page_size;
		PSEUDO_DEBUG("file backed mmap request off_s(0x%lx) "
				"to off_e(0x%lx) with (%s) page", off_s, off_e,
				pgsz_to_pgstr(f_stat->pgsz));

	}

	/* Check whether mapping is not related to heap/stack  */
	if ((flag & MAP_SHARED) && ((flag & MAP_STACK) ||
				(flag & MAP_ADDR_SPACE))) {
		PSEUDO_DEBUG("Error(%s) flag(0x%lx)", strerror(EINVAL), flag);
		errno = EINVAL;
		free(f_stat);
		return MAP_FAILED;
	}
	/*addr should not be null if MAP_ADDR_SPACE flag is set*/
	if ((NULL == (void *)addr) && (flag & MAP_ADDR_SPACE)) {
		PSEUDO_DEBUG("Error(%s) addr should not(0x%lx)"
				"if MAP_ADDR_SPACE flag is set", strerror(EINVAL), addr);
		errno = EINVAL;
		free(f_stat);
		return MAP_FAILED;
	}

	/*get arch*/
	const char *name = vedl_get_arch_class_name(handle->ve_handle);
	PSEUDO_TRACE("ARCH is %s", name);
	if(strncmp(name, "ve3", 3) == 0) {
		if (( prot & PROT_EXEC ) && (!(MAP_ANON & flag))) {
			if (check_to_elf_flag(filedes) == 1) {
				PSEUDO_DEBUG("This is ve1 binary. It needs to modify code.");
				is_modify = 1;
				this_file_is_modified = 1;
			}
		}
	}

        if(is_modify == 1){
                if(filedes > 0){
                	mod_sz = code_modify_size(filedes);
                	if(mod_sz == 0){
                        	is_modify = 0;
                        	this_file_is_modified = 0;
                	}
                }else{
                        is_modify = 0;
                        this_file_is_modified = 0;
                }
        }

	if (is_modify != 1) {
		if (flag & MAP_ADDR_64GB_SPACE)
			/*Get vemva within first 64GB of process address space*/
			ret_addr = ve_get_vemva_under_64GB(handle, addr,
				aligned_sz, flag, prot, filedes, offset);
		else
			ret_addr = ve_get_vemva(handle, addr, aligned_sz,
						flag, prot, filedes, offset);
		if (MAP_FAILED == ret_addr) {
			ret = errno;
			PSEUDO_DEBUG("Error(%s) while getting free vemva", strerror(ret));
			free(f_stat);
			errno = ret;
			return ret_addr;
		}
	} else if (is_modify == 1) {
		/* code modification required */
		if (ve_node_num == -1) {
			ve_node_num = get_ve_node_num(handle);
			if(ve_node_num == -1) {
				PSEUDO_ERROR("failed to get ve node number");
				return MAP_FAILED;
			}
			PSEUDO_DEBUG("VE_NODE_NUMBER=%d",ve_node_num);
		}
		if (get_tmp_dir_path(ve_node_num) < 0) {
			PSEUDO_ERROR("failed to setting for storing "
				     "temporary file ");
			return MAP_FAILED;
		}

		/* Avoid reserved address */
		aligned_seg_addr_min = check_addr_in_loadable_seg((uint64_t)addr);

		/*align size with page size*/
		aligned_mod_sz = mod_sz;
		if (!IS_ALIGNED(mod_sz, ve_page_info.page_size)) {
			aligned_mod_sz = ALIGN(mod_sz, ve_page_info.page_size);
			PSEUDO_DEBUG("Given size aligned to (0x%lx)", aligned_mod_sz);
			if (!aligned_mod_sz) {
				errno = ENOMEM;
				return MAP_FAILED;
			}
		}

		req_flg = flag;
		if (flag & MAP_ADDR_64GB_SPACE)
			req_flg = flag & ~MAP_ADDR_64GB_FIXED;
		else
			req_flg = flag & ~MAP_FIXED;

		/* if addr is set, get vemva for mmap at first, get vemva for
		   temp file at 2nd. */
		/* if addr is not set, get vemva for temp file at first,
		   get vemva for mmap at 2nd. */
		if (addr == 0) {
			/* If inode number from file descripter that specified
			    as argument of this function, same to it  from file
			    path of load_elf.stat.file_exec, tmpCode should be
			    mapped at first.*/
			if (strlen(load_elf.stat.file_exec) != 0) {
				exec_stat = (struct file_stat *)calloc(1,
						       sizeof(struct file_stat));
				if (exec_stat == NULL) {
					PSEUDO_ERROR("Error(%s) while allocating"
						     " mem for exec_stat",
						     strerror(errno));
					free(f_stat);
					return MAP_FAILED;
				}
				ret = stat(load_elf.stat.file_exec,
					   &exec_stat->stat);
				if (0 > ret) {
					PSEUDO_TRACE("Error(%s) while getting"
						" file stat", strerror(errno));
					free(exec_stat);
					exec_stat = NULL;
				}
			}

			/* If f_stat is same to stat in exec_stat, pseudo judges
			 it was called from loader.*/
			if ((exec_stat != NULL) &&
			    (f_stat->stat.st_ino == exec_stat->stat.st_ino) &&
			    (f_stat->stat.st_rdev == exec_stat->stat.st_rdev)) {
				free(exec_stat);
				exec_stat = NULL;
				if (flag & MAP_ADDR_64GB_SPACE) 
					ret_addr = ve_get_vemva_for_mod_code_under_64GB(
								handle, addr, aligned_sz,
								flag, prot, offset);
				else
					ret_addr = ve_get_vemva_for_mod_code(
								handle, addr,
								aligned_sz, flag,
								prot, offset);
				if (ret_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva for"
						" original code: %s",
						strerror(errno));
					goto hndl_failure;
				}
				struct ve_vh_segmap *tmp_seg_addr = 0;
				/* if it is loading first segment, modified code
				   and address translation table shouled be
				   needed to skip 2nd segment. */
				/* get address of 1st segment */
				tmp_seg_addr = ((struct ve_vh_segmap *)load_elf.seg);
				if (tmp_seg_addr->ve_addr == (uint64_t)ret_addr)
					req_mod_addr = aligned_seg_addr_min;
				PSEUDO_TRACE("req_mod_addr=%lx", req_mod_addr);
				if (flag & MAP_ADDR_64GB_SPACE) {
					/* req_flg |= MAP_ADDR_64GB_FIXED; */
					mod_addr = ve_get_vemva_for_mod_code_under_64GB(
							handle, req_mod_addr,
							aligned_mod_sz,	req_flg,
							prot, 0);
				} else {
					mod_addr = ve_get_vemva_for_mod_code(
								handle, req_mod_addr,
								aligned_mod_sz,
								req_flg, prot, 0);
				}
				if (mod_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva "
						     "for modified code: %s",
						     strerror(errno_ret));
					ret = ve_free_vemva((void *)ret_addr,
							    size);
					if (0 > ret)
						PSEUDO_DEBUG("Error(%s) while "
							     "freeing vemva(%p)",
							     strerror(-ret),
							     ret_addr);
					goto hndl_failure;
				}

				if (flag & MAP_ADDR_64GB_SPACE) {
					tbl_addr = ve_get_vemva_for_mod_code_under_64GB(
							handle,
							(uint64_t)mod_addr + aligned_mod_sz,
							aligned_sz, req_flg,
							prot, 0);
				} else {
					tbl_addr = ve_get_vemva_for_mod_code(
								handle,
								(uint64_t)mod_addr + aligned_mod_sz,
								aligned_sz,
								req_flg, prot, 0);
				}
				if (tbl_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva "
						     "for modified code: %s",
						     strerror(errno_ret));
					ret = ve_free_vemva((void *)ret_addr,
							    size);
					if (0 > ret)
						PSEUDO_DEBUG("Error(%s) while "
							     "freeing vemva(%p)",
							     strerror(-ret),
							     ret_addr);
					ret = ve_free_vemva((void *)mod_addr,
							    mod_sz);
					if (0 > ret)
					  PSEUDO_DEBUG("Error(%s) while freeing"
						       " vemva(%p)",
						       strerror(-ret), mod_addr);
					goto hndl_failure;
				}
			} else {
				/* shared library*/
				if (flag & MAP_ADDR_64GB_SPACE) {
					mod_addr = ve_get_vemva_for_mod_code_under_64GB(
								handle, addr,
								aligned_mod_sz,
								flag, prot, 0);
				} else {
					mod_addr = ve_get_vemva_for_mod_code(
								handle, addr,
								aligned_mod_sz,
								req_flg, prot, 0);
				}
				if (mod_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva "
						     "for modified code: %s",
						     strerror(errno_ret));
					goto hndl_failure;
				}
				if (flag & MAP_ADDR_64GB_SPACE) {
					tbl_addr = ve_get_vemva_for_mod_code_under_64GB(
								handle,
								(uint64_t)mod_addr + aligned_mod_sz,
								aligned_sz,
								req_flg, prot, 0);
				} else {
					tbl_addr = ve_get_vemva_for_mod_code(
								handle,
								(uint64_t)mod_addr + aligned_mod_sz,
								aligned_sz,
								req_flg, prot, 0);
				}
				if (tbl_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva for "
						"address conversion table: %s",
						strerror(errno_ret));
					ret = ve_free_vemva((void *)mod_addr,
							    mod_sz);
					if (0 > ret)
						PSEUDO_DEBUG("Error(%s) while "
							"freeing vemva(%p)",
							strerror(-ret), mod_addr);
					goto hndl_failure;
				}
				if (flag & MAP_ADDR_64GB_SPACE) {
					ret_addr = ve_get_vemva_for_mod_code_under_64GB(
								handle,
								(uint64_t)tbl_addr + aligned_sz,
								aligned_sz,
								req_flg, prot,
								offset);
				} else {
					ret_addr = ve_get_vemva_for_mod_code(
								handle,
								(uint64_t)tbl_addr + aligned_sz,
								aligned_sz,
								req_flg, prot,
								offset);
				}
				if (ret_addr == MAP_FAILED) {
					errno_ret = errno;
					PSEUDO_ERROR("failed to get vemva for "
						"address conversion table: %s",
						strerror(errno_ret));
					ret = ve_free_vemva((void *)mod_addr,
							    mod_sz);
					if (0 > ret)
						PSEUDO_DEBUG("Error(%s) while "
							"freeing vemva(%p)",
							strerror(-ret), mod_addr);
					ret = ve_free_vemva((void *)tbl_addr,
							    size);
					if (0 > ret)
						PSEUDO_DEBUG("Error(%s) while "
							"freeing vemva(%p)",
							strerror(-ret), tbl_addr);
					goto hndl_failure;
				}
			}
		} else {
			/* specified address*/
			/* It will not run this condition when called from
			   loader or dlopen(). However, it does not guarantee
			   that address is not specified. So, following
			   processing is just in case.*/
			if (flag & MAP_ADDR_64GB_SPACE)
				/*Get vemva within first 64GB of process address space*/
				ret_addr = ve_get_vemva_for_mod_code_under_64GB(
						handle, addr, aligned_sz, flag,
						prot, offset);
			else
				ret_addr = ve_get_vemva_for_mod_code(handle, addr,
						aligned_sz, flag, prot, offset);
			if (ret_addr == MAP_FAILED) {
				errno_ret = errno;
				PSEUDO_ERROR("failed to get vemva for modified"
					     " code: %s", strerror(errno));
				goto hndl_failure;
			}

			/*get vemva*/
			/* if ret_addr is included segment, modified code and
			   address translation table needs to map avoid
			   loadable segment. */
			req_mod_addr = (uint64_t)ret_addr + aligned_sz;
			if ((aligned_seg_addr_min > req_mod_addr) &&
			    ( aligned_seg_addr_min < req_mod_addr + aligned_mod_sz + aligned_sz)) {
				if (flag & MAP_ADDR_64GB_SPACE) {
					req_flg = flag | MAP_ADDR_64GB_FIXED;
				} else
					req_flg = flag | MAP_FIXED;
				req_mod_addr = aligned_seg_addr_min;
			}

			if (flag & MAP_ADDR_64GB_SPACE) {
				mod_addr = ve_get_vemva_for_mod_code_under_64GB(
						handle,
						req_mod_addr,
						aligned_mod_sz, req_flg, prot, 0);
			} else {
				mod_addr = ve_get_vemva_for_mod_code(
						handle,
						req_mod_addr,
						aligned_mod_sz,	req_flg, prot, 0);
			}
			if (mod_addr == MAP_FAILED) {
				errno_ret = errno;
				PSEUDO_ERROR("failed to get vemva for modified code");
				ret = ve_free_vemva((void *)ret_addr, size);
				if (0 > ret)
					PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
						     strerror(-ret), ret_addr);
				goto hndl_failure;
			}
			if (flag & MAP_ADDR_64GB_SPACE) {
				tbl_addr = ve_get_vemva_for_mod_code_under_64GB(
						handle,
						(uint64_t)mod_addr + aligned_mod_sz,
						aligned_sz, req_flg, prot, 0);
			} else {
				tbl_addr = ve_get_vemva_for_mod_code(
						handle,
						(uint64_t)mod_addr + aligned_mod_sz,
						aligned_sz, req_flg, prot, 0);
			}
			if (tbl_addr == MAP_FAILED) {
				errno_ret = errno;
				PSEUDO_ERROR("failed to get vemva for address"
					     " conversion table");
				ret = ve_free_vemva((void *)ret_addr, size);
				if (0 > ret)
					PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
						     strerror(-ret), ret_addr);
				ret = ve_free_vemva((void *)mod_addr, mod_sz);
				if (0 > ret)
					PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
						     strerror(-ret), mod_addr);
				goto hndl_failure;
			}
		}
		PSEUDO_DEBUG("mod_addr: %ld, tbl_addr:%ld",
			     (uint64_t)mod_addr, (uint64_t)tbl_addr);
		ret = init_all_tmp_file_info(&info, (uint64_t)ret_addr,
					     (uint64_t)mod_addr,
					     (uint64_t)tbl_addr,
					     aligned_sz, aligned_mod_sz,
					     f_stat);
		if (ret < 0) {
			PSEUDO_ERROR("failed to initialize struct tmp_file_info");
			errno_ret = EFAULT;
			goto hndl_free_info;
		}

		ret = elf_text_offset_size(filedes, &toff, &tsz);
		if (ret < 0) {
			PSEUDO_ERROR("failed to get offset size of text from elf");
			errno_ret = EFAULT;
			goto hndl_free_info;
		}

		while (open_retry_cnt) {
			open_retry_cnt--;
			/* get exclusive lock for other pseudo process */
			ret = open_lock_file_and_try_to_get(info, 1000);
			if (ret == -1) {
				PSEUDO_ERROR("failed to open/lock");
				errno_ret = EFAULT;
				goto hndl_free_info;
			} else {
				/* Check modified files already exist */
				ret = check_mod_file_exist(info);
				if (ret == -ENOENT) {
					/* create and rename and open */
					ret = create_all_mod_file_and_open(info,
								filedes, mod_sz);
					if (ret == -ENOENT) {
						PSEUDO_DEBUG("failed to "
							     "create file, retry");
						if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
							PSEUDO_DEBUG("failed to "
								"delete owner "
								"pid from %s",
								info->lock_file_path);
						if (flock(info->lock_fd,
							  LOCK_UN) != 0)
							PSEUDO_DEBUG("failed to "
								"unlock %s: %s",
								info->lock_file_path,
								strerror(errno));
						close(info->lock_fd);
						info->lock_fd = -1;
						continue;
					} else if (ret != 0) {
						errno_ret = -ret;
						PSEUDO_ERROR("failed to create"
							     " file: %s",
							     strerror(-ret));
						if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
							PSEUDO_DEBUG("failed to "
								"delete owner "
								"pid from %s",
								info->lock_file_path);
						flock(info->lock_fd, LOCK_UN);
						goto hndl_close_lock;
					}
				} else if (ret != 0) {
					errno_ret = -ret;
					PSEUDO_ERROR("failed to check existing "
						     "temporary files");
					if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
						PSEUDO_DEBUG("failed to delete "
							     "owner pid from %s",
							     info->lock_file_path);
					flock(info->lock_fd, LOCK_UN);
					goto hndl_close_lock;
				}
			}

			/* open modified files with readonly and executable
			   option */
			ret = reopen_mod_file(&info->mod);
			if (ret == -ENOENT) {
				PSEUDO_DEBUG("mod file is not found,"
					     " retry code modification");
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				close(info->lock_fd);
				info->lock_fd = -1;
				continue;
			} else if (ret != 0) {
				PSEUDO_ERROR("failed to reopen mod file");
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				errno_ret = EFAULT;
				goto hndl_close_lock;
			}
			off_s = (off_t)(0 / ve_page_info.page_size);
			off_e = (off_t)(((0 + aligned_mod_sz) / ve_page_info.page_size) - 1);
			info->mod.f_stat.offset_start = off_s;
			info->mod.f_stat.offset_end = off_e;
			info->mod.f_stat.pgsz = ve_page_info.page_size;

			ret = reopen_mod_file(&info->tbl);
			if (ret == -ENOENT) {
				PSEUDO_DEBUG("tbl file is not found,"
					     " retry code modification");
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				close(info->lock_fd);
				info->lock_fd = -1;
				continue;
			} else if (ret != 0) {
				PSEUDO_DEBUG("failed to reopen tbl\n");
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				errno_ret = EFAULT;
				goto hndl_close_lock;
			}
			off_s = (off_t)(0 / ve_page_info.page_size);
			off_e = (off_t)(((0 + aligned_sz) / ve_page_info.page_size) - 1);
			info->tbl.f_stat.offset_start = off_s;
			info->tbl.f_stat.offset_end = off_e;
			info->tbl.f_stat.pgsz = ve_page_info.page_size;

			ret = reopen_mod_file(&info->org);
			if (ret == -ENOENT) {
				PSEUDO_DEBUG("org file is not found,"
					     " retry code modification");
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				close(info->lock_fd);
				info->lock_fd = -1;
				continue;
			} else if (ret != 0) {
				PSEUDO_DEBUG("failed to reopen org");
				errno_ret = EFAULT;
				if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
					PSEUDO_DEBUG("failed to delete owner pid"
						     " from %s",
						     info->lock_file_path);
				flock(info->lock_fd, LOCK_UN);
				goto hndl_close_lock;
			}
			off_s = (off_t)(offset / ve_page_info.page_size);
			off_e = (off_t)(((offset + aligned_sz) / ve_page_info.page_size) - 1);
			info->org.f_stat.offset_start = off_s;
			info->org.f_stat.offset_end = off_e;
			info->org.f_stat.pgsz = ve_page_info.page_size;

			if (delete_owner_pid_from_lockfile(info->lock_fd) != 0)
				PSEUDO_DEBUG("failed to delete owner pid from %s",
					     info->lock_file_path);
			if (flock(info->lock_fd, LOCK_UN) != 0) {
				PSEUDO_ERROR("failed to unlock %s: %s",
					     info->lock_file_path,
					     strerror(errno));
				errno_ret = EFAULT;
				goto hndl_close_lock;
			}
			close(info->lock_fd);
			info->lock_fd = -1;
			break;
		}
		if (open_retry_cnt <= 0) {
			PSEUDO_ERROR("failed to code modification,"
				     " exceeded number of retries");
			errno_ret = EFAULT;
			goto hndl_close_tmpfile;
		}
		/* map files on VH and mark used to vemva */
		tmp = vh_map_for_mod_code (handle,
					   (uint64_t)mod_addr,
					   aligned_mod_sz,
					   flag & ~MAP_FIXED, prot,
					   info->mod.fd, 0);
		if (tmp == MAP_FAILED) {
			errno_ret = errno;
			PSEUDO_ERROR("failed to map modified code: %s",
				     strerror(errno));
			goto hndl_close_tmpfile;
		}
		tmp = vh_map_for_mod_code(handle,
					  (uint64_t)tbl_addr, aligned_sz,
					  flag & ~MAP_FIXED, prot,
					  info->tbl.fd, 0);
		if (tmp == MAP_FAILED) {
			errno_ret = errno;
			PSEUDO_ERROR("failed to map address conversion table: %s",
				     strerror(errno));
			goto hndl_close_tmpfile;
		}
		tmp = vh_map_for_mod_code(handle,
					  (uint64_t)ret_addr, aligned_sz,
					  flag & ~MAP_FIXED, prot,
					  info->org.fd, offset);
		if (tmp == MAP_FAILED) {
			errno_ret = errno;
			PSEUDO_ERROR("failed to map original code: %s",
				     strerror(errno));
			goto hndl_close_tmpfile;
		}
	}

	/*
	 * In case of MAP_STACK do not have to allocate
	 * any physical page, virtual address will not
	 * be backed by any page physically
	 */
	prot = ve_prot;
	if (!(flag & MAP_STACK) ||
			((flag & MAP_STACK) && (flag & MAP_FIXED))) {

		/* Removing the fixed 64GB address space related flag*/
		flag &= ~(MAP_ADDR_64GB_SPACE|MAP_ADDR_64GB_FIXED);

		/* AMM communication */
		if (is_modify != 1) {
			ret = amm_request_mmap(handle, (uint64_t)ret_addr,
					aligned_sz, prot, flag, f_stat);
			if (0 > ret) {
				PSEUDO_DEBUG("Error(%s) while sending mmap request to VE OS",
					     strerror(-ret));
				errno_ret = -ret;
				goto hndl_free_vemva;
			}
		} else {
			/* AMM communication */
			ret = amm_request_mmap(handle, (uint64_t)ret_addr,
					aligned_sz, prot, flag, &info->org.f_stat);
			if (0 > ret) {
				PSEUDO_DEBUG("Error(%s) while sending mmap request "
					     "for modified original code to VE OS",
					     strerror(-ret));

				errno_ret = -ret;
				goto hndl_close_tmpfile;
			}
			ret = amm_request_mmap(handle, (uint64_t)mod_addr,
					       aligned_mod_sz, prot, flag, &info->mod.f_stat);
			if (0 > ret) {
				PSEUDO_DEBUG("Error(%s) while sending mmap request "
					     "for modified code to VE OS",
					     strerror(-ret));
				errno_ret = -ret;
				goto hndl_close_tmpfile;
			}

			ret = amm_request_mmap(handle, (uint64_t)tbl_addr,
					       aligned_sz, prot, flag, &info->tbl.f_stat);
			if (0 > ret) {
				PSEUDO_DEBUG("Error(%s) while sending mmap request "
					     "for conversion table to VE OS",
					     strerror(-ret));
				errno_ret = -ret;
				goto hndl_close_tmpfile;
			}
		}
	}

	/* if file back mmap than do mprotect with user provided flag
	 * to avoid any mis-match between vhva and VEMVA
	 */
	if (!(flag & MAP_ANON) && (is_modify != 1)) {
		ret = mprotect(ret_addr, aligned_sz, ve_prot);
		if (0 > ret) {
			errno_ret = errno;
			PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
					strerror(errno));
			goto hndl_free_vemva;
		}
		/*
		 * As per #948 we are mmaping the SIG_BUS region of file with
		 * MAP_ANON|MAP_FIXED to access the futex varible stored in the
		 * this region.
		 */
		align_fsz = ALIGN(f_stat->stat.st_size, PAGE_SIZE_4KB);
		if (offset < align_fsz)
			align_fsz -= offset;
		if ((offset < f_stat->stat.st_size) && (0 < (int64_t)(aligned_sz - align_fsz))) {
			PSEUDO_DEBUG("offset %ld f_stat->stat.st_size  %ld",
					offset, align_fsz);
			mmap_flag = (flag | MAP_FIXED | MAP_ANON) &
				(~(MAP_2MB | MAP_64MB | MAP_VESHM | MAP_ADDR_SPACE | MAP_ADDR_64GB_SPACE));
			if (MAP_FAILED == mmap((void*)((uint64_t)ret_addr + align_fsz),
						aligned_sz - align_fsz,
						ve_prot,
						mmap_flag,
						-1, 0)) {
				errno_ret = errno;
				PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
						strerror(errno_ret));
				goto hndl_free_vemva;
			}
		}
	}

	if (!(flag & MAP_ANON) && (is_modify == 1)) {
		ret = mprotect(ret_addr, aligned_sz, ve_prot);
		if (0 > ret) {
			errno_ret = errno;
			PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
					strerror(errno));
			goto hndl_close_tmpfile;
		}
		align_fsz = ALIGN(info->org.f_stat.stat.st_size, PAGE_SIZE_4KB);
		if (offset < align_fsz)
			align_fsz -= offset;
		if ((offset < info->org.f_stat.stat.st_size) && (0 < (int64_t)(aligned_sz - align_fsz))) {
			PSEUDO_DEBUG("org: offset %ld f_stat->stat.st_size  %ld",
					offset, align_fsz);
			mmap_flag = (flag | MAP_FIXED | MAP_ANON) &
				(~(MAP_2MB | MAP_64MB | MAP_VESHM | MAP_ADDR_SPACE | MAP_ADDR_64GB_SPACE));
			if (MAP_FAILED == mmap((void*)((uint64_t)ret_addr + align_fsz),
						aligned_sz - align_fsz,
						ve_prot,
						mmap_flag,
						-1, 0)) {
				errno_ret = errno;
				PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
						strerror(errno_ret));
				goto hndl_close_tmpfile;
			}
		}

		ret = mprotect(mod_addr, aligned_mod_sz, ve_prot);
		if (0 > ret) {
			errno_ret = errno;
			PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
				     strerror(errno));
			goto hndl_close_tmpfile;
		}
		align_fsz = ALIGN(info->mod.f_stat.stat.st_size, PAGE_SIZE_4KB);
		if (0 < (int64_t)(aligned_mod_sz - align_fsz)) {
			PSEUDO_DEBUG("mod: f_stat->stat.st_size  %ld",
					align_fsz);
			PSEUDO_DEBUG("mod: mmap addr:%lx sz:%lx",
				     (uint64_t)mod_addr + align_fsz, aligned_mod_sz - align_fsz);
			mmap_flag = (flag | MAP_FIXED | MAP_ANON) &
				(~(MAP_2MB | MAP_64MB | MAP_VESHM | MAP_ADDR_SPACE | MAP_ADDR_64GB_SPACE));
			if (MAP_FAILED == mmap((void*)((uint64_t)mod_addr + align_fsz),
					       aligned_mod_sz - align_fsz,
					       ve_prot,
					       mmap_flag,
					       -1, 0)) {
				errno_ret = errno;
				PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
					     strerror(errno_ret));
				goto hndl_close_tmpfile;
			}
		}

		ret = mprotect(tbl_addr, aligned_sz, ve_prot);
		if (0 > ret) {
			errno_ret = errno;
			PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
				     strerror(errno));
			goto hndl_close_tmpfile;
		}
		align_fsz = ALIGN(info->tbl.f_stat.stat.st_size, PAGE_SIZE_4KB);
		if (0 < (int64_t)(aligned_sz - align_fsz)) {
			PSEUDO_DEBUG("tbl: f_stat->stat.st_size  %ld",
					align_fsz);
			PSEUDO_DEBUG("tbl: mmap addr:%lx sz:%lx",
				     (uint64_t)tbl_addr + align_fsz, aligned_sz - align_fsz);
			mmap_flag = (flag | MAP_FIXED | MAP_ANON) &
				(~(MAP_2MB | MAP_64MB | MAP_VESHM | MAP_ADDR_SPACE | MAP_ADDR_64GB_SPACE));
			if (MAP_FAILED == mmap((void*)((uint64_t)tbl_addr + align_fsz),
						aligned_sz - align_fsz,
						ve_prot,
						mmap_flag,
						-1, 0)) {
				errno_ret = errno;
				PSEUDO_DEBUG("Error(%s) while off loading mprotect on VH",
						strerror(errno_ret));
				goto hndl_close_tmpfile;
			}
		}
	}

	if (is_modify == 1) {
		pthread_mutex_lock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
		if (ve_xtbl_adr_hdr.num <
		    ((PAGE_SIZE_2MB - sizeof(size_t)) / sizeof(struct ve_xtbl_adr)))
			ve_xtbl_adr_hdr.num++;
		else {
			pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
			PSEUDO_ERROR("address translation table header is overflow");
			errno_ret = ENOMEM;
			goto hndl_close_tmpfile;
		}
		xtbl.org = (uint64_t)ret_addr + (uint64_t)toff;
		xtbl.xtbl = (uint64_t *)tbl_addr;
		xtbl.xtbl_size = (uint64_t)tsz;
		memcpy(&ve_xtbl_adr_hdr.ve_xtbl_addrtbl[ve_xtbl_adr_hdr.num - 1],
		       &xtbl, sizeof(struct ve_xtbl_adr));

		if (ve_xtbl_adr_hdr_info.xtbl_hdr != NULL) {
			memcpy(ve_xtbl_adr_hdr_info.xtbl_hdr, &ve_xtbl_adr_hdr,
			       PAGE_SIZE_2MB);
			ret = ve_send_data(handle,
					(uint64_t)ve_xtbl_adr_hdr_info.xtbl_hdr,
					PAGE_SIZE_2MB, &ve_xtbl_adr_hdr);
			if (ret < 0) {
				pthread_mutex_unlock(
					&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
				PSEUDO_ERROR("failed to send data : %s",
					     strerror(-ret));
				errno_ret = -ret;
				goto hndl_close_tmpfile;
			}
		}
		pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
		/* add temporary file info */
		ret = add_tmpfile_info(info);
		if (ret != 0) {
			PSEUDO_ERROR("failed to add list for tmpfile");
			errno_ret = ECANCELED;
			delete_xtbl(handle, (uint64_t)tbl_addr);
			goto hndl_close_tmpfile;
		}
	}

	/*Clearing ve page info*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%p)", ret_addr);
	free(f_stat);
	if ((is_modify == 1) && (info != NULL)) {
		if (info->lock_file_path != NULL)
			free(info->lock_file_path);
		if (info->mod.fd >= 0)
			close(info->mod.fd);
		if (info->org.fd >= 0)
			close(info->org.fd);
		if (info->tbl.fd >= 0)
			close(info->tbl.fd);
		if (info->mod.file_path != NULL)
			free(info->mod.file_path);
		if (info->org.file_path != NULL)
			free(info->org.file_path);
		if (info->tbl.file_path != NULL)
			free(info->tbl.file_path);
		free(info);
	}
	return ret_addr;

 hndl_close_lock:
	if ((is_modify == 1) && (info != NULL)) {
		if(info->lock_fd >= 0)
			close(info->lock_fd);
	}
 hndl_close_tmpfile:
	if ((is_modify == 1) && (info != NULL)) {
		if (info->org.fd >= 0)
			close(info->org.fd);
		if (info->mod.fd >= 0)
			close(info->mod.fd);
		if (info->tbl.fd >= 0)
			close(info->tbl.fd);
	}
 hndl_free_info:
	if ((is_modify == 1) && (info != NULL)) {
		if (info->lock_file_path != NULL)
			free(info->lock_file_path);
		if (info->mod.file_path != NULL)
			free(info->mod.file_path);
		if (info->org.file_path != NULL)
			free(info->org.file_path);
		if (info->tbl.file_path != NULL)
			free(info->tbl.file_path);
		free(info);
	}
 hndl_free_vemva:
	ret = ve_free_vemva((void *)ret_addr, size);
	if (0 > ret)
		PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
			     strerror(-ret), ret_addr);
	if (is_modify == 1) {
		ret = ve_free_vemva((void *)tbl_addr, size);
		if (0 > ret)
			PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
				     strerror(-ret), tbl_addr);
		ret = ve_free_vemva((void *)mod_addr, mod_sz);
		if (0 > ret)
			PSEUDO_DEBUG("Error(%s) while freeing vemva(%p)",
				     strerror(-ret), mod_addr);
	}
 hndl_failure:
	free(f_stat);
	errno = errno_ret;
	return MAP_FAILED;
}

/**
 * @brief This function is used to communicate with AMM module.
 *
 * @param[in] handle VEOS handle
 * @param[in] vemva mapped virtual address
 * @param[in] size Size of the memory to map
 * @param[in] prot Protection control bits
 * @param[in] flag mapping control flags
 * @param[in] f_stat file stats to be mapped if file backed
 * otherwise NULL.
 *
 * @return returns 0 on success and negative of errno on failure.
 */
int64_t amm_request_mmap(veos_handle *handle, vemva_t vemva, size_t size,
		int prot, uint64_t flag, struct file_stat *f_stat)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	struct ve_mmap_cmd *cmd = NULL;
	PseudoVeosMessage *pseudo_msg = NULL;
	PseudoVeosMessage ve_mmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_mmap_msg = {0};

	PSEUDO_TRACE("invoked");

	cmd = (struct ve_mmap_cmd *)calloc(1, sizeof(struct ve_mmap_cmd));
	if (NULL == cmd) {
		PSEUDO_DEBUG("Fail to allocate memory for "
				"amm request block\n");
		goto error_return;
	}

	/* Populating struct ve_mmap_cmd buffer to Generate IPC Command */
	cmd->vaddr = vemva;
	cmd->perm = prot;
	cmd->flags = flag;
	cmd->size = size;

	if (!(MAP_ANON & flag)) {
		/*copy file specific Information in cmd buffer*/
		memcpy(&(cmd->f_stat), f_stat, sizeof(struct file_stat));
	}

	PSEUDO_DEBUG("Sending request for MMAP with vemva(0x%lx) "
			"size(0x%lx) perm(0x%x) flags(0x%lx)",
			cmd->vaddr, cmd->size, cmd->perm, cmd->flags);

	/* Populate parameters for ve_mmap req */
	ve_mmap.pseudo_veos_cmd_id = CMD_MMAP;

	ve_mmap.has_pseudo_pid = true;
	ve_mmap.pseudo_pid = syscall(SYS_gettid);

	ve_mmap_msg.len = sizeof(struct ve_mmap_cmd);
	ve_mmap_msg.data = (uint8_t *)cmd;

	ve_mmap.has_pseudo_msg = true;
	ve_mmap.pseudo_msg = ve_mmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mmap);

	msg_len = pseudo_veos_message__pack(&ve_mmap, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* Sending command CMD_MMAP to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while sending IPC request for CMD_MMAP to VE OS");
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}
	/* Receiving ACK for command CMD_MMAP*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (-1 == ret) {
		PSEUDO_DEBUG("Error while getting ACk for CMD_MMAP from VE OS");
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}

	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while mapping vemva(0x%lx)",
				strerror(-ret), vemva);
	} else {
		PSEUDO_DEBUG("vemva(0x%lx) mapping operation successfully done on VE", vemva);
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function is used to handle memory unmap request.
 *
 * @param[in] handle VEOS handle
 * @param[in] vemva Start of the virtual address from where memory to unmap
 * @param[in] size size of the memory to unmap
 * @param[in] del_dir bool to decide dir should be deleted or not.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t __ve_munmap(veos_handle *handle, vemva_t vemva,
		size_t size, bool del_dir)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	size_t pg_size = 0;
	struct ve_munmap_cmd *cmd = NULL;

	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage ve_munmap = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_munmap_msg = {0};

	PSEUDO_TRACE("invoked");

	/* Check for tha validity of address */
	if (vemva < 0) {
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		ret = -EINVAL;
		goto error_return;
	} else if (!vemva) {
		PSEUDO_DEBUG("vemva(0x%lx) nothing to do", vemva);
		ret = 0;
		goto error_return;
	} else {
		ret = get_page_size(vemva);
		if (ret < 0) {
			PSEUDO_DEBUG("vemva(0x%lx) is not mapped", vemva);
			ret = 0;
			goto error_return;
		} else {
			pg_size = ve_page_info.page_size;
			PSEUDO_DEBUG("vemva(0x%lx) was mapped with (%s) page",
					vemva, pgsz_to_pgstr(pg_size));
		}
	}

	/* Check is address is aligned to pagesize or not*/
	if (!IS_ALIGNED(vemva, pg_size)) {
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		ret = -EINVAL;
		goto error_return;
	}

	/* Check is size is aligned to pagesize or not*/
	if (!IS_ALIGNED(size, pg_size)) {
		size = ALIGN((uint64_t)size, pg_size);
		PSEUDO_DEBUG("Aligned size (0x%lx) with page size", size);
	}

	/* Popluate parameters for ve_munmap req */
	ve_munmap.pseudo_veos_cmd_id = CMD_MUNMAP;

	ve_munmap.has_pseudo_pid = true;
	ve_munmap.pseudo_pid = syscall(SYS_gettid);

	cmd = (struct ve_munmap_cmd *)calloc(1, sizeof(struct ve_munmap_cmd));
	if (NULL == cmd) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for ve_munmap_cmd",
				strerror(-ret));
		goto error_return;
	}

	cmd->vaddr = vemva;
	cmd->size = size;

	PSEUDO_DEBUG("sending request to munmap for vemva(0x%lx) with size(0x%lx)",
			cmd->vaddr, cmd->size);

	ve_munmap_msg.len = sizeof(struct ve_munmap_cmd);
	ve_munmap_msg.data = (uint8_t *)cmd;

	ve_munmap.has_pseudo_msg = true;
	ve_munmap.pseudo_msg = ve_munmap_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_munmap);

	msg_len = pseudo_veos_message__pack(&ve_munmap, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	/* sending CMD_MUNMAP to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd,
			cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while sending ICP command CMD_MUNMAP to VE OS");
		ret = -EFAULT;
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}

	/* receiving ACK for CMD_MUNMAP from VE OS*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
			MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while getting ACK for CMD_MUNMAP from VE OS");
		ret = -EFAULT;
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while unmapping vemva(0x%lx)",
				strerror(-ret), vemva);
	} else
		PSEUDO_DEBUG("vemva(0x%lx) unmapping operation successfully done on VE", vemva);

	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

	/*Freeing vemva*/
	ret = __ve_free_vemva((void *)vemva, size, del_dir);
	if (0 > ret)
		PSEUDO_DEBUG("Error(%s) while freeing vemva(0x%lx)",
				strerror(-ret), vemva);

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function is to handle munmap request.
 *
 * @param[in] syscall_num Syscall number
 * @param[in] syscall_name Syscall name
 * @param[in] handle VEOS handle
 *
 * @return On success return 0, returns negative of errno on failure.
 */
ret_t ve_munmap(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0;
	size_t size = 0;
	ret_t ret = 0;
	ret_t unmap_ret = 0;
	uint64_t args[2];
	struct ve_tmpfile_set *info;

	PSEUDO_TRACE("invoked");

	/*Fetch system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argument",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	vemva = (vemva_t)args[0];
	size = (size_t)args[1];

	/* length should not be zero or negative */
	if ((int64_t)size <= 0) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) size(0x%lx)", strerror(-ret), size);
		goto error_return;
	}

	PSEUDO_DEBUG("syscall(%s) argc vemav(0x%lx) size(0x%lx)", syscall_name, vemva, size);

	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = __ve_munmap(handle, vemva, size, true);
	if (0 > ret) {
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_DEBUG("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}
	pthread_mutex_unlock(&vemva_header.vemva_lock);
	/* for code modification */
	info = remove_tmpfile_info(vemva);
	if (info != NULL) {
		pthread_mutex_lock(&vemva_header.vemva_lock);
		unmap_ret = __ve_munmap(handle, info->mod.addr, info->mod.sz, true);
		if (0 > unmap_ret) {
			PSEUDO_ERROR("error(%s) for syscall(%s):"
				     " failed unmap modified code",
				     strerror(-ret), syscall_name);
			PSEUDO_DEBUG("error(%s) for syscall(%s):"
				     " failed unmap modified code",
				     strerror(-ret), syscall_name);
		}
		unmap_ret = __ve_munmap(handle, info->tbl.addr, info->tbl.sz, true);
		if (0 > unmap_ret) {
			PSEUDO_ERROR("error(%s) for syscall(%s): failed unmap "
				     "address table for modified code",
				     strerror(-ret), syscall_name);
			PSEUDO_DEBUG("error(%s) for syscall(%s): failed unmap "
				     "address table for modified code",
				     strerror(-ret), syscall_name);
		}
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		if (delete_xtbl(handle, info->tbl.addr) != 0)
			PSEUDO_ERROR("failed to delete xtbl");
		if (delete_tmpfiles(&info) < 0)
			PSEUDO_DEBUG("failed to delete tmporary files");
	}
error_return:
	/* Initialize ve_page_info struct to zero while returning*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
* @brief This function is used to handle Heap space extension/reduction request.
*
* @param[in] syscall_num System call number.
* @param[in] syscall_name System call name.
* @param[in] handle VEOS handle.
*
* @return returns new program break on success else old program break.
*/
ret_t ve_brk(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t ret = 0;
	void *ret_addr = NULL;
	vemva_t old_top = 0;
	vemva_t new_top = 0;
	size_t size = 0;
	uint64_t args[1] = {0};
	uint64_t flag = 0;

	PSEUDO_TRACE("invoked");
	/* Get the previous heap top */
	old_top = ve_info.heap_top;
	PSEUDO_DEBUG("current unaligned heap top(0x%lx)", old_top);

	/*Fetching syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 1);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argument",
				strerror(-ret), syscall_name);
        ret = old_top;
		goto error_return;
	}

	PSEUDO_DEBUG("syscall(%s) args heap top(0x%lx)", syscall_name, args[0]);

	/*Updating ve page info with default page*/
	flag = 0;
	update_ve_page_info(&flag);

	/* Check if previous heap is aligned */
	if (!IS_ALIGNED(old_top, ve_page_info.page_size))
		old_top = ALIGN(old_top, ve_page_info.page_size);


	PSEUDO_DEBUG("current aligned heap top(0x%lx)", old_top);

	PSEUDO_DEBUG("new unaligned heap top(0x%lx)", args[0]);

	new_top = ALIGN((uint64_t)args[0], ve_page_info.page_size);

	PSEUDO_DEBUG("new aligned heap top(0x%lx)", new_top);

	/* If brk syscall argument received is NULL
	 * then current heap top is sent to VE program */
	if (0 == new_top) {
		PSEUDO_DEBUG("requesting for current heap top");
		ret = old_top;
		goto error_return;
	}

	/* Check if requested value is same as current heap top */
	if (new_top == old_top) {
		PSEUDO_DEBUG("old heap top (0x%lx) and new heap top(0x%lx) are same",
				old_top, new_top);
		ret = old_top;
		goto error_return;
	}

	/* Calculate Heap size to change */
	size = new_top - old_top;
	PSEUDO_DEBUG("heap size to be changed(0x%lx)", size);

	if ((int64_t)size > 0) {
		/* check that while increasing the heap it doesn't overlap the
		 * stack region.
		 */
		if ((old_top + size) > ve_info.stack_pointer_aligned) {
			PSEUDO_DEBUG("Current aligned stack pointer(0x%lx)",
					ve_info.stack_pointer_aligned);
			PSEUDO_DEBUG("heap overlapping the stack");
			ret = old_top;
			goto error_return;
		}
		/* Request for Heap extension */
		ret_addr = ve_heap_extend(handle, old_top, size);
		if (MAP_FAILED == ret_addr) {
			PSEUDO_DEBUG("Error while extending the heap");
			ret = old_top;
			goto error_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	} else {
		size = -size;
		/* Req for Heap release , check whether release request
		 * goes beyond the heap starting point */
		if (new_top < ALIGN(ve_info.heap_start,
					ve_page_info.page_size)) {
			PSEUDO_DEBUG("Error while decreasing heap to new heap top(0x%lx)", new_top);
			ret = old_top;
			goto error_return;
		}
		ret = ve_heap_reduce(handle, new_top, size);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while decreasing heap to new heap top(0x%lx)",
					strerror(-ret), new_top);
			ret = old_top;
			goto error_return;
		}
		/* Update Heap position */
		ve_info.heap_top = args[0];
	}
	ret = ve_info.heap_top;

error_return:
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returnig heap top(0x%lx)", ret);
	return ret;
}

/**
 * @brief This function handles heap space extension request.
 *
 * @param[in] handle VEOS handle
 * @param[in] old_top_address VE virtual address to unmap
 * @param[in] size size of the heap space to release
 *
 * @return On success returns mapped address* and (void *)-1 on failure.
 */
void *ve_heap_extend(veos_handle *handle, vemva_t old_top,
		size_t size)
{
	void *ret = NULL;
	uint64_t flag = MAP_FIXED | MAP_ADDR_SPACE | MAP_ANON | MAP_PRIVATE;

	PSEUDO_TRACE("invoked to exend heap top(0x%lx) by size(0x%lx)", old_top, size);

	/* Request to extend VE program Heap space */
	ret = __ve_mmap(handle, old_top, size, PROT_WRITE|PROT_READ, flag, -1, 0);
	if (MAP_FAILED == ret)
		PSEUDO_DEBUG("Error while mapping the heap to new limit");

	PSEUDO_DEBUG("heap top (%p) extented by size(0x%lx)", ret, size);
	PSEUDO_TRACE("returned(%p)", ret);
	return ret;
}

/**
 * @brief This function handles heap space reduction request.
 *
 * @param[in] handle VEOS handle
 * @param[in] new_top_address VE virtual address to map
 * @param[in] size size of the space to map
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t ve_heap_reduce(veos_handle *handle, vemva_t new_top, size_t size)
{
	int ret = 0;

	PSEUDO_TRACE("invoked to reduce heap top(0x%lx) by size(0x%lx)", new_top, size);

	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = __ve_munmap(handle, new_top, size, true);
	if (0 > ret) {
		PSEUDO_DEBUG("Error while unmapping the heap to new limit");
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		return ret;
	}

	pthread_mutex_unlock(&vemva_header.vemva_lock);
	PSEUDO_DEBUG("heap top (0x%lx) reduce by size(0x%lx)", new_top, size);
	PSEUDO_TRACE("returned(%d)", ret);
	return ret;
}

/**
 * @brief This function handles grow system call
 * from VE process to make request to AMM for VE stack space extension.
 *
 * @param[in] syscall_num grow syscall number
 * @param[in] syscall_name syscall name
 * @param[in] handle VEOS handle
 *
 * @return SR00 is not updtaed as grow does not return anything.
 * However, new stack limit is always set in SR08 in case of success as
 * well as in failure.
 *
 */
ret_t ve_grow(int syscall_num, char *syscall_name, veos_handle *handle)
{
	int prot = 0;
	uint64_t flag = 0;
	size_t size = 0;
	int idx = 0;
	vemva_t old_bottom = 0;
	vemva_t new_bottom = 0;
	vemva_t actual_new_bottom;
	vemva_t requested_new_bottom;
	vemva_t new_stack_limit = 0;
	int64_t ret = 0;
	void *ret_addr = NULL;
	uint64_t args[2] = {0};
	vemva_t guard_addr = 0;
	pid_t tid = syscall(SYS_gettid);
	pid_t pid = getpid();
	unsigned long alt_stk_sp = 0;
	size_t alt_stk_sz = 0;
	ve_grow_err grow_err = VE_GROW_NO_ERR;

	PSEUDO_TRACE("invoked");

	/* Fetching the system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching the syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto out;
	}

	PSEUDO_DEBUG("syscall(%s) args old stack bottom(0x%lx) "
			"new stack bottom(0x%lx)", syscall_name, args[0], args[1]);

	ret = pthread_mutex_lock(&tid_counter_mutex);
	if (ret != 0) {
		PSEUDO_ERROR("Failed to acquire mutex lock");
		PSEUDO_DEBUG("Failed to acquire lock, return value %d",
				-((int)ret));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	/* Finding guard address from global array*/
	idx = find_global_array_index(tid);
	if (VEOS_MAX_VE_THREADS == idx) {
		PSEUDO_ERROR("Failed to get thread index");
		fprintf(stderr, "Internal thread resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}


	/*Check pid and tid, update guard_addr accordingly*/

	if (pid != tid) {
		guard_addr = global_tid_info[idx].
			guard_ptr;
	} else {
		guard_addr = 0;
		flag |= MAP_ADDR_SPACE;
	}

	/* Fetch alternate stack details from global tid structure */
	alt_stk_sp =  global_tid_info[idx].sas_ss_sp;
	alt_stk_sz = global_tid_info[idx].sas_ss_size ;

	PSEUDO_DEBUG("Current Stack limit(0x%lx) Alternate stack SP (0x%lx)"
			"Alt stack size %d",
			old_bottom, alt_stk_sp, (int)alt_stk_sz);

	ret = pthread_mutex_unlock(&tid_counter_mutex);
	if (ret!= 0) {
		PSEUDO_ERROR("Failed to release mutex lock");
		PSEUDO_DEBUG("Failed to release lock, return value %d",
				-((int)ret));
		fprintf(stderr, "Internal resource usage "
				"error\n");
		/* FATAL ERROR: abort current process */
		pseudo_abort();
	}

	old_bottom = args[0];
	new_bottom = args[1];

	if (new_bottom >= old_bottom) {
		PSEUDO_DEBUG("new_bottom(0x%lx) is greater than old_bottom(0x%lx)",
				new_bottom, old_bottom);
		grow_err = VE_GROW_INVALID_REQUEST;
		goto out;
	}

	/* Check if grow is invoked while alternate stack is active.
	 * If yes, we simply return the new stack limit.
	 * */
	if ((old_bottom >= alt_stk_sp) && (old_bottom - alt_stk_sp <= alt_stk_sz)) {
		PSEUDO_ERROR("Alternate stack active. Behaviour will be undesirable");
		grow_err = VE_GROW_IN_ALT_STACK;
		goto out;
	}

	/*update ve page info*/
	update_ve_page_info(&flag);

	requested_new_bottom = new_bottom;
	/*
	 * Stack area for signal handling is required.
	 */
	actual_new_bottom = requested_new_bottom - STACK_AREA_FOR_SIGNAL;

	new_bottom = ROUND_DN(new_bottom, ve_page_info.page_size);
	actual_new_bottom = ROUND_DN(actual_new_bottom, ve_page_info.page_size);
	old_bottom = ROUND_DN(old_bottom, ve_page_info.page_size);

	if (pid == tid) {
		/*
		 * While changing the stack limit Check:
		 * 1. If it overlaps the process heap or not.
		 * 2. If STACK LIMIT is defined, then check if it is
		 * going beyond the limit or not.
		 *
		 * If stack grows and goes beyond in both the cases,
		 * we just return the new stack limit.
		 * Let hardware exception occur.
		 */
		if (new_bottom < ve_info.stack_limit) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing stack limit(0x%lx)",
				new_bottom, ve_info.stack_limit);
			grow_err = VE_GROW_STACK_LIMIT;
			goto out;
		}
		if (new_bottom < ve_info.heap_top) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing heap top(0x%lx)",
				new_bottom, ve_info.heap_top);
			goto out;
		}

		if (actual_new_bottom < ve_info.stack_limit) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing stack limit(0x%lx)",
				new_bottom, ve_info.stack_limit);
			actual_new_bottom = ve_info.stack_limit;
		}
		if (actual_new_bottom < ve_info.heap_top) {
			PSEUDO_DEBUG("new stack(0x%lx) is crossing heap top(0x%lx)",
				new_bottom, ve_info.heap_top);
			actual_new_bottom = ve_info.heap_top;
		}
	}

	/*
	 * We try to allocate physical pages including area for signal handling.
	 */
	size = (old_bottom - actual_new_bottom);
	if (guard_addr && (actual_new_bottom < guard_addr)) {
		size -= (guard_addr - actual_new_bottom);

		/* As aligned requested new bottom + stack area for signal
		 * handling is falling at the next page after guard addr
		 * hence we will check if there is still space beyond the
		 * aligned old_bottom.
		 */
		if ((int64_t)size <= 0)
		{
			/* This is the case where old bottom and guard addr
			 * are aligned at same page boundary. Hence we can
			 * not allocate further stack area. Now we will check
			 * for the aligned requested stack bottom(i.e new bottom)
			 * if it is beyond the guard address then we should
			 * abort otherwise we can continue as we are left with
			 * stack till guard address.
			 */
			if(new_bottom < guard_addr)
			{
				grow_err = VE_GROW_IN_GUARD_AREA;
			}
			goto out;
		}
		else
		{
			/* Although there is a space left beyond old_bottom but
			 * as our new_bottom is beyond guard address hence we
			 * can not allocate memory.
			 */
			if(new_bottom < guard_addr)
			{
				grow_err = VE_GROW_IN_GUARD_AREA;
				goto out;
			}
			/* This is clear till now that memory cannot be allocated
			 * for signal handler but there are still pages left for
			 * ve stack to grow till guard address.
			 */
			actual_new_bottom = guard_addr;
		}

	}

	/*
	 * Check if actual_new_bottom address >= page aligned old_bottom address
	 */
	if (actual_new_bottom >= old_bottom)
	{
		goto out;
	}

	PSEUDO_DEBUG("actual new stack bottom(0x%lx)", actual_new_bottom);
	PSEUDO_DEBUG("old stack bottom(0x%lx)", old_bottom);
	PSEUDO_DEBUG("stack to be increase by size(0x%lx)", size);

	/* Set the protection */
	prot = PROT_WRITE;
	/* Set flag to indicate this is for stack space allocation */
	flag |= MAP_FIXED | MAP_ANON | MAP_PRIVATE | MAP_STACK;

	/* Request for memory map */
	ret_addr = __ve_mmap(handle, actual_new_bottom, size, prot,
			flag, -1, 0);
	if (MAP_FAILED != ret_addr) {
		/*
		 * After succesfull grow, update the value of new stack
		 * pointer aligned.
		 */
		if (pid == tid)
			ve_info.stack_pointer_aligned = (uint64_t)actual_new_bottom;
		/*
		 * Update new_bottom to return value exclude stack area for
		 * signal. But, update new_bottom to return actual value if
		 * we have failed to allocate stack area for signal.
		 */
		if ((requested_new_bottom - actual_new_bottom)
				> STACK_AREA_FOR_SIGNAL)
			new_bottom = actual_new_bottom + STACK_AREA_FOR_SIGNAL;
		else
			new_bottom = actual_new_bottom;
	} else if (new_bottom != actual_new_bottom) {
		PSEUDO_DEBUG("Error while mapping new stack including area for signal handling");
		/*
		 * VEOS fails to allocate physical pages including a
		 * area for signal_handling. So, we try to allocate
		 * physical pages excluding a area for
		 * signal_handling.
		 */
		size = (old_bottom - new_bottom);
		if (new_bottom >= old_bottom)
			goto out;

		if (guard_addr && (new_bottom < guard_addr)) {
			grow_err = VE_GROW_INVALID_REQUEST;
			goto out;
		}

		PSEUDO_DEBUG("new stack bottom(0x%lx)", new_bottom);
		PSEUDO_DEBUG("old stack bottom(0x%lx)", old_bottom);
		PSEUDO_DEBUG("stack to be increase by size(0x%lx)", size);
		ret_addr = __ve_mmap(handle, new_bottom, size, prot,
				flag, -1, 0);
		if (MAP_FAILED != ret_addr) {
			/*
			 * After succesfull grow, update the value of new stack
			 * pointer aligned.
			 */
			if (pid == tid)
				ve_info.stack_pointer_aligned = (uint64_t)new_bottom;
		} 
		else
		{
			PSEUDO_DEBUG("Error while mapping new stack");
			grow_err = VE_GROW_MEM_ALLOC;
			goto out;
		}
	}
	else if(MAP_FAILED == ret_addr)
	{
		grow_err = VE_GROW_MEM_ALLOC;
		goto out;
	} 
out:
	if(VE_GROW_NO_ERR != grow_err)
	{
	        PSEUDO_DEBUG("%s",ve_grow_err_str[grow_err]);
		fprintf(stderr, "Unable to grow stack\n");
                /* Disabling core dump at VH side */
                struct rlimit core_lim;
                core_lim.rlim_cur = 0;
                core_lim.rlim_max = 0;
                if (-1 == setrlimit(RLIMIT_CORE, &core_lim)) {
                        PSEUDO_DEBUG("Disabling of coredump failed, setrlimit failed %d", errno);
                }
		pseudo_abort();
	}

	new_stack_limit = new_bottom;

	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returning new stack(0x%lx)", new_stack_limit);
	return new_stack_limit;
}

/**
 * @brief This function is used to
 * communicate with AMM module for updating memory protection.
 *
 * @param[in] handle VEOS handle
 * @param[out] ret_addr mapped virtual address
 * @param[in] size Size of the memory to map
 * @param[in] prot Protection control bits
 *
 * @return returns 0 on success and negative of errno on failure.
 */
int64_t amm_request_mprotect(veos_handle *handle, vemva_t vemva,
		size_t size, int prot)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	PseudoVeosMessage ve_mprotect_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData mprotect_ve_proc_msg = {0};
	ssize_t pseudo_msg_len = 0, msg_len = -1;
	PseudoVeosMessage *mprotect_ack = NULL;
	struct pseudo_mprotect_req mprotect_request = {0};

	PSEUDO_TRACE("invoked");

	/* Populate mprotect_request structure */
	mprotect_request.ret_addr = vemva;
	mprotect_request.size = size;
	mprotect_request.prot = prot;

	/* prepare request to be sent to AMM */
	ve_mprotect_req.pseudo_veos_cmd_id = CMD_MPROTECT;

	ve_mprotect_req.has_pseudo_pid = true;
	ve_mprotect_req.pseudo_pid = syscall(SYS_gettid);

	ve_mprotect_req.has_pseudo_msg = true;
	mprotect_ve_proc_msg.len = sizeof(struct pseudo_mprotect_req);
	mprotect_ve_proc_msg.data = (uint8_t *)&mprotect_request;
	ve_mprotect_req.pseudo_msg = mprotect_ve_proc_msg;

	/* Pack ve_mprotect_req before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mprotect_req);

	msg_len = pseudo_veos_message__pack(&ve_mprotect_req, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_ERROR("Packing message protocol buffer error");
		PSEUDO_DEBUG("Expected length: %ld, Returned length: %ld",
				pseudo_msg_len, msg_len);
		fprintf(stderr, "Internal message protocol buffer error\n");
		/*FATAL ERROR: abort current process */
		abort();
	}

	PSEUDO_DEBUG("sending request to mprotect with vemva(0x%lx) "
			"pid(%ld) size(0x%lx) prot(%d)",
			mprotect_request.ret_addr, syscall(SYS_gettid),
			mprotect_request.size, mprotect_request.prot);

	/* sending CMD_MPROTECT to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req,
			pseudo_msg_len);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while sending IPC command CMD_MPROTECT to VE OS");
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(-ret));
		goto error_return;
	}
	/* receiving ACK for CMD_MPROTECT from VE OS*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack,
				     MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while getting ACK for CMD_MPROTECT to VE OS");
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(-ret));
		goto error_return;
	}

	/* Unpack the structure */
	mprotect_ack = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(cmd_buf_ack));
	if (NULL == mprotect_ack) {
		PSEUDO_ERROR("Unpacking message protocol buffer error");
		fprintf(stderr, "Internal message protocol buffer error\n");
		/* FATAL ERROR: abort current process */
		abort();
	}
	if (mprotect_ack->syscall_retval < 0) {
		ret = mprotect_ack->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS while mprotect vemva(0x%lx)",
			strerror(-ret), vemva);
	} else {
		PSEUDO_DEBUG("mprotect operation on vemva(0x%lx)"
			"successfully done on VE", vemva);
		ret = mprotect_ack->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(mprotect_ack, NULL);

error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function to handle mprotect system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success returns zero, returns negative of errno on failure.
 */
ret_t ve_mprotect(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0, addr_end = 0;
	size_t len = 0;
	int prot;
	ret_t ret = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("invoked");

	/*Fetching system call argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (ret < 0) {
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) argumnets",
				strerror(-ret), syscall_name);
		ret = -EFAULT;
		goto error_return;
	}

	vemva	= (vemva_t)args[0];
	len	= (size_t)args[1];
	prot	= (int)args[2];

	PSEUDO_DEBUG("syscall(%s) args vemav(0x%lx) size(0x%lx) prot(0x%x)",
			syscall_name, vemva, len, prot);

	/* check if address is aligned or not*/
	if (!IS_ALIGNED(vemva, PAGE_SIZE_2MB)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx)", strerror(EINVAL), vemva);
		goto error_return;
	}

	/* Is length zero */
	if (!len) {
		ret = 0;
		PSEUDO_DEBUG("length is invalid\n");
		goto error_return;
	}

	/* align length with 2 MB page size temparaly*/
	len = ALIGN(len, PAGE_SIZE_2MB);

	/*
	 * ending address should be greather than starting
	 * if not it that such mapping is not available.
	 */
	addr_end = vemva + len;
	if (addr_end <= vemva) {
		PSEUDO_DEBUG("address is NULL\n");
		ret = -ENOMEM;
		goto error_return;
	}

	/* Get the actual page size */
	if (vemva) {
		ret = get_page_size(vemva);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while getting page size", strerror(-ret));
			ret = -ENOMEM;
			goto error_return;
		}
	} else {
		PSEUDO_DEBUG("address is NULL\n");
		ret = -ENOMEM;
		goto error_return;
	}


	/*check whether memory ref by addr is mapped or not*/
	ret = vemva_mapped((void *)vemva, len, MARK_USED);
	if (0 >= ret) {
		ret = -ENOMEM;
		PSEUDO_DEBUG("vemav(0x%lx) is not mapped", vemva);
		goto error_return;
	}

	/*
	 * if page size is not 2MB then check
	 * whether len and addr is aligned with actual page size
	 */
	if (ve_page_info.page_size != PAGE_SIZE_2MB) {
		len = ALIGN(len, ve_page_info.page_size);
		if (!IS_ALIGNED(vemva, ve_page_info.page_size)) {
			ret = -EINVAL;
			PSEUDO_DEBUG("Error(%s) vemav(0x%lx) is not alinged",
					strerror(-ret), vemva);
			goto error_return;
		}
	}

	/* Call VH mprotect system call */
	ret = syscall(syscall_num, vemva, len, prot);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while off loading syscall(%s) on VH",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	/*sending request*/
	ret = amm_request_mprotect(handle, vemva, len, prot);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		goto error_return;
	}

error_return:
	/*initialize ve_page_info to zero struct while returning*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function to handle msync system call.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return On success return zero, returns negative of errno on failure.
 */
ret_t ve_msync(int syscall_num, char *syscall_name, veos_handle *handle)
{
	vemva_t vemva = 0, ve_end = 0;
	size_t size = 0;
	ret_t ret = 0;
	int flag = 0;
	uint64_t args[3] = {0};

	PSEUDO_TRACE("invoked");

	/* Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (ret < 0) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error while fetching syscall(%s) arguments",
				syscall_name);
		goto error_return;
	}

	vemva = (vemva_t)args[0];
	size = (size_t)args[1];
	flag    = (int)args[2];

	PSEUDO_DEBUG("syscall(%s) args vemva(0x%lx) size(0x%lx) flag(0x%x)",
			syscall_name, vemva, size, flag);

	 /* check whether addr is aligned or not*/
	if (!IS_ALIGNED(vemva, PAGE_SIZE_2MB)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx) is not aligned",
			strerror(-ret), vemva);
		goto error_return;
	}

	size = ALIGN(size, PAGE_SIZE_2MB);

	/* Check is size is negative or not*/
	ve_end = vemva + size;
	if (ve_end < vemva) {
		ret = -ENOMEM;
		goto error_return;
	}
	/*
	 * if start and end are equal its mean that length is zero
	 * there is nothing to do.
	 */
	if (vemva == ve_end) {
		ret = 0;
		goto error_return;
	}

	/*Align the size*/
	PSEUDO_DEBUG("aligned size(0x%lx) with page size", size);

	/* Get the actual page size */
	if (vemva) {
		ret = get_page_size(vemva);
		if (0 > ret) {
			PSEUDO_DEBUG("Error(%s) while getting page size", strerror(-ret));
			ret = -ENOMEM;
			goto error_return;
		}
	} else {
		PSEUDO_DEBUG("Error(%s) vemav(0x%lx)", strerror(-ret), vemva);
		ret = -ENOMEM;
		goto error_return;
	}

	/* check whether memory referrence by ve_addr is mapped or not */
	pthread_mutex_lock(&vemva_header.vemva_lock);
	ret = vemva_mapped((void *)vemva, size, MARK_USED);
	if (0 >= ret) {
		ret = -ENOMEM;
		PSEUDO_DEBUG("Error(%s) vemva(0x%lx) is not mapped", strerror(-ret), vemva);
		pthread_mutex_unlock(&vemva_header.vemva_lock);
		goto error_return;
	}
	/*
	 * if actual page size is not 2MB, then align
	 * size with actual page size
	 */
	if (ve_page_info.page_size != PAGE_SIZE_2MB) {
		size = ALIGN(size, ve_page_info.page_size);
		/*check if ve_addr is aligned or not*/
		if (!IS_ALIGNED(vemva, ve_page_info.page_size)) {
			ret = -EINVAL;
			PSEUDO_DEBUG("Error(%s) vemav(0x%lx) is not aligned",
				strerror(-ret), vemva);
			pthread_mutex_unlock(&vemva_header.vemva_lock);
			goto error_return;
		}
	}

	ret = __ve_msync(handle, vemva, size, flag);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}

	pthread_mutex_unlock(&vemva_header.vemva_lock);
error_return:
	/*initiale ve_page_info to zero struct while returning.*/
	memset(&ve_page_info, '\0', sizeof(ve_page_info));
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function handles the sync functionality.
 *
 * @param[in] handle veos_handle
 * @param[in] vemva Virtual Address of VE Process to be synced.
 * @param[in] size size of data to be synced.
 * @param[in] flag msync flags.
 *
 * @return Return 0 on Success and negative of errno on failure.
 */
int64_t __ve_msync(veos_handle *handle, vemva_t vemva, size_t size, int flag)
{
	vemva_t vemva_ve = vemva;
	vemva_t vemva_vh = vemva;
	int64_t ret = 0, count = 0, pgsize = 0;

	PSEUDO_TRACE("invoked");

	/*
	 * If any bit other than MS_ASYNC | MS_INVALIDATE | MS_SYNC
	 * is set Return EINVAL
	 * */
	if (flag & ~(MS_SYNC | MS_ASYNC)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) flag(0x%x)", strerror(-ret), flag);
		goto error_return;
	}

	/*If MS_ASYNC and MS_SYNC Both flags are provided then Return EINVAL*/
	if ((flag & MS_ASYNC) && (flag & MS_SYNC)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) flag(0x%x)", strerror(-ret), flag);
		goto error_return;
	}

	/*Check if the address received is VE Page aligned or not.*/
	if (!IS_ALIGNED((uint64_t)vemva_ve, ve_page_info.page_size)) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) vemva_ve(%lx) is not aligned",
				strerror(-ret), vemva_ve);
		goto error_return;
	}
	pgsize = ve_page_info.page_size;
	count = size/pgsize;
	while (count) {
		/*
		 * check is vemva is file backed
		 * before accessing vh memory
		 */
		if (vemva_mapped((void *)vemva, pgsize, MARK_FILE|MARK_USED)) {
			/* receive the data from VE memory*/
			ret = __ve_recv_data(handle, (uint64_t)vemva_ve, pgsize, (void *)vemva_vh, 0);
			if (0 > ret) {
				PSEUDO_TRACE("Error(%s) while receiving date from VE",
						strerror(-ret));
				goto error_return;
			}

			/*off loading syscall on VH*/
			if (flag & (MS_SYNC | MS_ASYNC | MS_INVALIDATE)) {
				ret = msync((void *)vemva_vh, pgsize, flag);
				if (0 > ret) {
					ret = -errno;
					PSEUDO_DEBUG("Error(%s) while off loading the syscall(msync) on VH",
							strerror(-ret));
				}
			}
		}
		vemva_vh += pgsize;
		vemva_ve += pgsize;
		count--;
	}
error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function does the data transfer to a VE process from
 * another VE process.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return 0 on success, returns negative of errno on failure.
 */
ret_t ve_process_vm_readv(int syscall_num, char *syscall_name, veos_handle *handle)
{
	pid_t pid = 0;
	uint64_t l_iovec = 0;
	struct iovec *vhremote_iovec = NULL;
	uint64_t riovcnt = 0;
	struct iovec *vhlocal_iovec = NULL;
	uint64_t r_iovec = 0;
	uint64_t liovcnt = 0;
	uint64_t flags = 0;
	int64_t ret = -1;
	uint64_t args[6] = {0};

	/*Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	pid = (pid_t)args[0];
	l_iovec = args[1];
	liovcnt = args[2];
	r_iovec = args[3];
	riovcnt = args[4];
	flags = args[5];

	PSEUDO_DEBUG("syscall(%s) args pid(%d) l_iovec(0x%lx) liovcnt(0x%lx) "
			"r_iovec(0x%lx) riovcnt(0x%lx) flags(0x%lx)", syscall_name,
			pid, l_iovec, liovcnt, r_iovec, riovcnt, flags);

	/* Check the iovec count is valid or not */
	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) liovcnt(0x%lx)", strerror(-ret), liovcnt);
		goto error_return;
	}
	/*If local iovec count or remote iovec count is zero
	 * means we have nothing to read, so return success
	 */
	if (!liovcnt || !riovcnt) {
		ret = 0;
		goto error_return;
	}

	/*If pointer to local iovec or remote iovec is NULL than return failure.*/
	if (!l_iovec || !r_iovec) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) l_iovec(0x%lx) r_iovec(0x%lx)",
				strerror(-ret), l_iovec, r_iovec);
		goto error_return;
	}

	vhremote_iovec = (struct iovec *)calloc(1, sizeof(struct iovec)
			* riovcnt);
	if (NULL == vhremote_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	vhlocal_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * liovcnt);
	if (NULL == vhlocal_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	/*Read from ve memory and store to local buff for manipulation*/
	ret = ve_recv_data(handle, l_iovec, sizeof(struct iovec) * liovcnt,
			(void *)vhlocal_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	/*Read from ve memory and store to local buff for manipulation*/
	ret = ve_recv_data(handle, r_iovec, sizeof(struct iovec) * riovcnt,
			(void *)vhremote_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for r_iovec",
				strerror(-ret));
		goto error_return;
	}

	/* Call VH process_vm_readv for checking access and capability*/
	ret = process_vm_readv(pid, vhlocal_iovec, 1, vhremote_iovec, 1,
			flags);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while transferring data from the remote"
				"process to the local process on VH", strerror(-ret));
		goto error_return;
	}

	/*Check the validation of local iovec*/
	ret = ve_check_iovec(vhlocal_iovec, liovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhremote_iovec, riovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = __ve_process_vm_rw(handle, vhlocal_iovec, liovcnt,
			vhremote_iovec, riovcnt, pid, 0);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}

error_return:
	if (vhlocal_iovec)
		free(vhlocal_iovec);
	if (vhremote_iovec)
		free(vhremote_iovec);

	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function does the data transfer from  a VE process to
 * another VE process.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle  VEOS handle
 *
 * @return 0 on success, returns negative of errno on failure.
 */
ret_t ve_process_vm_writev(int syscall_num, char *syscall_name, veos_handle *handle)
{
	pid_t pid = 0;
	uint64_t l_iovec = 0;
	struct iovec *vhremote_iovec = NULL;
	uint64_t riovcnt = 0;
	struct iovec *vhlocal_iovec = NULL;
	uint64_t r_iovec = 0;
	uint64_t liovcnt = 0;
	uint64_t flags = 0;
	int64_t ret = -1;
	uint64_t args[6] = {0};

	PSEUDO_TRACE("invoked");

	/*Fetching the syscall argument from shared memory*/
	ret = vedl_get_syscall_args(handle->ve_handle, args, 6);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while fetching syscall(%s) arguments",
				strerror(-ret), syscall_name);
		goto error_return;
	}

	pid = (pid_t)args[0];
	l_iovec = args[1];
	liovcnt = args[2];
	r_iovec = args[3];
	riovcnt = args[4];
	flags = args[5];

	PSEUDO_DEBUG("syscall(%s) args pid(%d) l_iovec(0x%lx) liovcnt(0x%lx) "
			"r_iovec(0x%lx) riovcnt(0x%lx) flags(0x%lx)", syscall_name,
			pid, l_iovec, liovcnt, r_iovec, riovcnt, flags);

	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		ret = -EINVAL;
		PSEUDO_DEBUG("Error(%s) liovcnt(0x%lx)", strerror(-ret), liovcnt);
		goto error_return;
	}

	if (!liovcnt || !riovcnt) {
		ret = 0;
		goto error_return;
	}

	if (!l_iovec || !r_iovec) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) l_iovec(0x%lx) r_iovec(0x%lx)",
				strerror(-ret), l_iovec, r_iovec);
		goto error_return;
	}

	vhremote_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * riovcnt);
	if (NULL == vhremote_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhremote_iovec",
				strerror(-ret));
		goto error_return;
	}

	vhlocal_iovec = (struct iovec *)calloc(1, sizeof(struct iovec) * liovcnt);
	if (NULL == vhlocal_iovec) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while allocating memory for vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_recv_data(handle, l_iovec, sizeof(struct iovec) * liovcnt,
			(void *)vhlocal_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_recv_data(handle, r_iovec, sizeof(struct iovec) * riovcnt,
			(void *)vhremote_iovec);
	if (0 > ret) {
		ret = -EFAULT;
		PSEUDO_DEBUG("Error(%s) while receiving date from VE for l_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhlocal_iovec, liovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}

	ret = ve_check_iovec(vhremote_iovec, riovcnt);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while checking validity of vhlocal_iovec",
				strerror(-ret));
		goto error_return;
	}
	ret = process_vm_writev(pid, vhlocal_iovec, 1, vhremote_iovec, 1,
			flags);
	if (0 > ret) {
		ret = -errno;
		PSEUDO_DEBUG("Error(%s) while transferring data from the local"
				"process to the remote process on VH", strerror(-ret));
		goto error_return;
	}

	ret = __ve_process_vm_rw(handle, vhlocal_iovec, liovcnt,
			vhremote_iovec, riovcnt, pid, 1);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) for syscall(%s)", strerror(-ret), syscall_name);
		PSEUDO_ERROR("error(%s) for syscall(%s)", strerror(-ret), syscall_name);
	}
error_return:
	if (vhlocal_iovec)
		free(vhlocal_iovec);
	if (vhremote_iovec)
		free(vhremote_iovec);

	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief This function do read/write operation to/from specified process
 * memory to/from calling process memory.
 *
 * @param[in] handle VEOS handle.
 * @param[in] local_iovec iovec array specifying where to copy to/from locally.
 * @param[in] liovcnt number of elements in local iovec array.
 * @param[in] remote_iovec iovec array specifying where to copy to/from
 * remote process.
 * @param[in] riovcnt Number of elements in local iovec array.
 * @param[in] pid Pid of process to/from read/write.
 * @param[in] type Type of operation read/write.
 * 0 for read from remote process, 1 for write to remote process.
 *
 * @return On success return number of bytes read/write to/from remote process
 * and negative of errno on failure.
 */
int64_t __ve_process_vm_rw(veos_handle *handle, struct iovec *local_iovec,
		uint64_t liovcnt, struct iovec *remote_iovec, uint64_t riovcnt,
		pid_t pid, int type)
{
	size_t cur_lcnt = 0, curr_l_offset = 0;
	int64_t total_rw = 0, ret = 0, idx = 0;

	PSEUDO_TRACE("invoked");

	for (idx = 0; idx < riovcnt; idx++) {
		ret = ve_process_vm_rw_single_iov(handle,
				(remote_iovec + idx),
				local_iovec, liovcnt, &cur_lcnt,
				&curr_l_offset,	pid, type);
		if (0 > ret) {
			if (!total_rw) {
				total_rw = -1;
				break;
			}
			break;
		}
		total_rw += ret;
		PSEUDO_DEBUG("total byte %s (%ld) riovcnt %ld",
				(type) ? "written":"read", total_rw, idx);
	}

	PSEUDO_TRACE("returned(%ld)", total_rw);
	return total_rw;

}

/**
 * @brief This function check the validity of each iovec.
 *
 * @param[in] iovec Pointer to check the iovec.
 * @param[in] iovcnt Number of iovec to check.
 *
 * @return On success return 0 and negative of errno on failure.
 */
int64_t ve_check_iovec(struct iovec *iovec, uint64_t iovcnt)
{
	ssize_t len = 0;
	int idx = 0;

	PSEUDO_TRACE("invoked");

	for (idx = 0; idx < iovcnt; idx++) {
		len = (ssize_t)iovec[idx].iov_len;
		if (0 > len) {
			PSEUDO_DEBUG("Error(%s) len(0x%lx)", strerror(EINVAL), len);
			return -EINVAL;
		}
		PSEUDO_DEBUG("iovec[%d].iov_length(0x%lx)", idx, len);
	}

	PSEUDO_TRACE("returned(0)");
	return 0;
}

/**
 * @brief This function do read/write operation to/from specified process
 * memory to/from calling process memory for each iovec.
 *
 * @param[in] handle Handle VEOS handle.
 * @param[in] r_iovec remote_iovec iovec array specifying where to copy
 * to/from remotelly.
 * @param[in] local_iovec local_iovec iovec array specifying where to copy
 * to/from locally.
 * @param[in] liovcnt number of elements in local iovec array
 * @param[in] curr_lcnt Current numeber local_iovev to/from read/write.
 * @param[in,out] curr_l_offset Current offset on local iovec to read/write.
 * @param[in] r_pid Pid of process to/from read/write
 * @param[in] type Type of operation read/write.
 * 0 for read from remote process, 1 for write to remote process.
 *
 * @return On success return number of bytes read/write to/from remote process.
 * and negative of errno on failure.
 */
int64_t ve_process_vm_rw_single_iov(veos_handle *handle, struct iovec *r_iovec,
		struct iovec *local_iovec, size_t liovcnt,
		size_t *curr_lcnt, size_t *curr_l_offset, pid_t r_pid,
		int type)
{
	vemva_t addr = 0, nr_pages = 0, nr_page_copied = 0;
	ve_mem_offset_t start_offset = 0;
	size_t pg_size = 0, min = 0;
	int64_t data_loops = 0, ret = -1;
	struct ve_process_rw_info *cmd = NULL;
	pg_size = PAGE_SIZE_2MB;

	PSEUDO_TRACE("invoked");

	/* Getting the base address for checking read/write permission */
	if (!IS_ALIGNED((uint64_t)(r_iovec[0].iov_base),
				ve_page_info.page_size)) {
		PSEUDO_DEBUG("Offset is not aligned to page boundary");
		addr = ROUND_DN((uint64_t)(r_iovec[0].iov_base), pg_size);
	} else
		addr = (vemva_t)(r_iovec[0].iov_base);

	nr_pages = (r_iovec[0].iov_len)/pg_size;

	if (!nr_pages)
		nr_pages = 1;
	PSEUDO_DEBUG("addr  = 0x%lx, rbase vemva = %p", addr,
			r_iovec[0].iov_base);

	nr_page_copied = 0;
	start_offset = (ve_mem_offset_t)r_iovec[0].iov_base - addr;

	cmd = (struct ve_process_rw_info *)calloc(1, sizeof(struct
				ve_process_rw_info));
	if (NULL == cmd) {
		PSEUDO_DEBUG("Error(%s) while allocating mem for ve_process_rw_info",
				strerror(errno));
		return -errno;
	}
	cmd->base_rvemva = (uint64_t)(r_iovec[0].iov_base);
	cmd->r_len = r_iovec[0].iov_len;

	/* This for loop will read/write from/to one remote iovec
	 * to/from local iovecs base on iovec length*/
	for (; *curr_lcnt < liovcnt && nr_page_copied < nr_pages;) {
		while ((0 == local_iovec[*curr_lcnt].iov_len))
			(*curr_lcnt)++;
		if (*curr_lcnt == liovcnt || 0 == r_iovec[0].iov_len)
			break;

		min = (size_t)MIN_2(uint64_t, pg_size - start_offset,
				(r_iovec[0].iov_len - data_loops));
		if (start_offset >= pg_size)
			min = r_iovec[0].iov_len - data_loops;
		PSEUDO_DEBUG("first  min  = 0x%lx", min);
		min = (size_t)MIN_2(uint64_t, min, (local_iovec[*curr_lcnt].iov_len -
					*curr_l_offset));
		PSEUDO_DEBUG("second min  = 0x%lx", min);

		cmd->r_pid = r_pid;
		cmd->lcov_offset = *curr_l_offset;
		cmd->rcov_offest = start_offset;
		cmd->local_vemva = (vemva_t)(local_iovec[*curr_lcnt].iov_base);
		cmd->remote_vemva = (vemva_t)(addr + (pg_size * nr_page_copied));
		cmd->len = min;
		cmd->vm_rw = type;

		/*sending request veos*/
		ret = amm_send_proc_vm_rw_req(handle,
				(struct ve_process_rw_info *)cmd);
		if (0 > ret) {
			if (!data_loops) {
				data_loops = -1;
				PSEUDO_DEBUG("Error(%s) while sending proc vm (read/write) req",
						strerror(-ret));
				goto error_return;
			} else {
				PSEUDO_DEBUG("Error(%s) while sending proc vm (read/write) req",
						strerror(-ret));
				goto error_return;

			}
		}
		data_loops += min;
		*curr_l_offset = (*curr_l_offset) + min;
		/* Moving to next local iovec */
		if (((*curr_l_offset) >= (local_iovec[*curr_lcnt].iov_len))) {
			(*curr_lcnt)++;
			*curr_l_offset = 0;
		}
		start_offset += min;
		if (data_loops >= pg_size)
			nr_page_copied++;
		/* Check if one remote iovec is completed or not */
		if (data_loops >= r_iovec[0].iov_len)  {
			PSEUDO_DEBUG("data_loops >= r_iovec[0].iov_len");
			break;
		}
	}

error_return:
	if (cmd)
		free(cmd);
	PSEUDO_TRACE("returned(%ld)", data_loops);
	return	data_loops;
}

/**
 * @brief This function is used to communicate with AMM module.
 *
 * @param[in] handle VEOS handle.
 * @param[in] cmd_buf Pointer to the data_buf that contain information to send.
 *
 * @return returns positive number on success and negative of errno on failure.
 */
int64_t amm_send_proc_vm_rw_req(veos_handle *handle,
		struct ve_process_rw_info *cmd_buf)
{
	int64_t ret = 0;
	char cmd_buf_req[MAX_PROTO_MSG_SIZE] = {0};
	char cmd_buf_ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = 0, msg_len = 0;
	PseudoVeosMessage *pseudo_msg = NULL;

	PseudoVeosMessage ve_vm_rw = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData ve_vm_rw_msg = {0};

	PSEUDO_TRACE("invoked");
	PSEUDO_DEBUG("base_rvemva = 0x%lx, r_len = 0x%lx, len = 0x%lx"
			" lcov_offeset = 0x%lx, rcov_offest = 0x%lx"
			" remote_vemva = 0x%lx local_vemva = 0x%lx"
			"vm_rw = %d",
			cmd_buf->base_rvemva, cmd_buf->r_len,
			cmd_buf->len, cmd_buf->lcov_offset,
			cmd_buf->rcov_offest, cmd_buf->remote_vemva,
			cmd_buf->local_vemva, cmd_buf->vm_rw);


	ve_vm_rw.pseudo_veos_cmd_id = CMD_VMRW;

	ve_vm_rw.has_pseudo_pid = true;
	ve_vm_rw.pseudo_pid = syscall(SYS_gettid);

	ve_vm_rw_msg.len = sizeof(struct ve_process_rw_info);
	ve_vm_rw_msg.data = (uint8_t *)cmd_buf;

	ve_vm_rw.has_pseudo_msg = true;
	ve_vm_rw.pseudo_msg = ve_vm_rw_msg;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_vm_rw);

	msg_len = pseudo_veos_message__pack(&ve_vm_rw, (uint8_t *)cmd_buf_req);
	if (msg_len != pseudo_msg_len) {
		PSEUDO_DEBUG("internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error, "
				"message length : %ld", pseudo_msg_len);
		abort();
	}

	/* sending CMD_VMRW to VE OS*/
	ret = pseudo_veos_send_cmd(handle->veos_sock_fd, cmd_buf_req, pseudo_msg_len);
	if (0 > ret) {
		PSEUDO_DEBUG("failed to send request to veos (transferred %ld bytes)", ret);
		PSEUDO_ERROR("error(%s) while sending request to VE OS", strerror(ret));
		goto error_return;
	}
	/*receiving ACK for CMD_VMRW from veos*/
	ret = pseudo_veos_recv_cmd(handle->veos_sock_fd, cmd_buf_ack, MAX_PROTO_MSG_SIZE);
	if (0 > ret) {
		PSEUDO_DEBUG("Error(%s) while receiving ACK for CMD_VMRW from VE OS",
				strerror(-ret));
		PSEUDO_ERROR("error(%s) while receiving ack from VE OS", strerror(ret));
		goto error_return;
	}
	pseudo_msg = pseudo_veos_message__unpack(NULL, ret,
			(const uint8_t *)(&cmd_buf_ack));
	if (NULL == pseudo_msg) {
		PSEUDO_ERROR("internal message protocol buffer error");
		fprintf(stderr, "internal message protocol buffer error");
		abort();
	}

	if (pseudo_msg->syscall_retval < 0) {
		ret = pseudo_msg->syscall_retval;
		PSEUDO_DEBUG("Error(%s) occurred on VE OS for system call(process_vm_%sv)",
				strerror(-ret), (cmd_buf->vm_rw) ? "write" : "read");
		PSEUDO_ERROR("Error(%s) occurred on VE OS for system call(process_vm_%sv)",
				strerror(-ret), (cmd_buf->vm_rw) ? "write" : "read");
	} else {
		PSEUDO_DEBUG("process vm %sv operation successfully done on VE",
				(cmd_buf->vm_rw) ? "write" : "read");
		ret = pseudo_msg->syscall_retval;
	}
	pseudo_veos_message__free_unpacked(pseudo_msg, NULL);

error_return:
	PSEUDO_TRACE("returned(%ld)", ret);
	return ret;
}

/**
 * @brief Handles the functionality of get_mempolicy system call for VE
 *
 * int get_mempolicy(int *mode, unsigned long *nodemask,
 * 		unsigned long maxnode, unsigned long addr,
 * 		unsigned long flags);
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 *
 * @author AMM / Memory Management
 */
ret_t ve_get_mempolicy(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[5] = {0};

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 5);
	if (retval < 0) {
		PSEUDO_ERROR("get_mempolicy() failure: "
				"failed to fetch system call aguments");
		PSEUDO_DEBUG("%s failure: "
				"failed to fetch system call aguments,"
				" return value: %d, mapped value: %d",
				syscall_name, (int)retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if ((int *)args[0] == NULL) {
		PSEUDO_DEBUG("get_mempolicy mode is NULL");
		retval = 0;
		goto hndl_return;
	}

	/* Currently we only support flag = 0 for get_mempolicy() */
	if (args[4] != 0) {
		PSEUDO_DEBUG("Invalid get_mempolicy argument flags %ld",
				args[4]);
		retval = -EINVAL;
		goto hndl_return;
	}

	/* interact with PSM to get the mempolicy of the VE process
	 * */
	retval = pseudo_psm_send_get_mempolicy_req(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d",
				(int)retval, -EFAULT);
		retval = -EFAULT;
		PSEUDO_ERROR("get_mempolicy() failure: "
				"veos request error, return value %d",
				(int)retval);
		goto hndl_return;
	}

	/* wait for acknowledgment from PSM */
	retval = pseudo_psm_recv_get_mempolicy_ack(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("get_mempolicy() failure: "
				"veos acknowledgement error, return value %d",
				(int)retval);
		goto hndl_return;
	}

	retval = ve_send_data(handle, args[0], sizeof(int),
			(uint64_t *)&retval);
	if (0 > retval) {
		PSEUDO_DEBUG("retval: %d, mapped value: %d", -errno, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

ret_t ve_remap_file_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_mbind(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_set_mempolicy(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_move_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

ret_t ve_migrate_pages(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return 0;
}

/**
 * @brief This function updates address transfer table header on VE/VH memory.
 *
 * @param[in] handle VEOS handle
 *
 * @retval returns 0 on success and -1 on failure.
 */
int update_xtbl_adr_info(veos_handle *handle)
{
	int ret = 0;
	PSEUDO_TRACE("Invoked");
	pthread_mutex_lock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);

	if (ve_xtbl_adr_hdr_info.xtbl_hdr != NULL) {
		memcpy(ve_xtbl_adr_hdr_info.xtbl_hdr, &ve_xtbl_adr_hdr,
		       PAGE_SIZE_2MB);
		ret = ve_send_data(handle,
				(uint64_t)ve_xtbl_adr_hdr_info.xtbl_hdr,
				PAGE_SIZE_2MB, &ve_xtbl_adr_hdr);
		pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
		if (ret < 0) {
			PSEUDO_ERROR("failed to send xtbl data to VE");
			return -1;
		}
		PSEUDO_TRACE("Returned");
		return 0;
	}
	PSEUDO_DEBUG("xtbl_hdr is not ready");
	pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
	return -1;
}


/**
 * @brief search ve_xtbl_adr by binary tree 
 *
 * @param[in] xtbl_adr top address
 * @param[in] mod_vemva Address of modified code
 * @param[in] start  start index of searching range
 * @param[in] end    end  index of searching range
 * @param[in] table_num addr_hdr table size
 * @param[out] xtbl_index the index of xtbl_adr corresponding to mod_vemva
 *
 * @retval 0>  hit index.
 * @retval -1<= -ERRNO
 */
int search_mod_addr(struct ve_xtbl_adr *xtbl_adr, uint64_t mod_vemva, uint64_t start, uint64_t end, uint64_t table_num, uint64_t* xtbl_idx) 
{
	uint64_t idx = (end - start) / 2 + start;

	PSEUDO_TRACE("search_mod_addr: mod_veva = %#lx, start = %ld, end = %ld, table_num = %ld", mod_vemva, start, end, table_num);
	if (table_num <= 0 || xtbl_adr == NULL) {
		PSEUDO_ERROR("no ve_xtbl_adr table");
		return -EFAULT;
	}
	PSEUDO_TRACE("search_mod_addr: xtbl[start] = %#lx, xtbl[end] = %#lx, xtbl[idx]  = %#lx",
			xtbl_adr->xtbl[start], xtbl_adr->xtbl[end], xtbl_adr->xtbl[idx]);

	if (xtbl_adr->xtbl[idx] == mod_vemva) {
		PSEUDO_DEBUG("found xtbl mod_vemva = %#lx, index = %ld, xtbl = %#lx",
					mod_vemva, idx, xtbl_adr->xtbl[idx]);
		*xtbl_idx = idx;
		return 0;
	} else if (xtbl_adr->xtbl[idx] > mod_vemva) {
		if (idx == start) {
			PSEUDO_DEBUG("no found xtbl(not in table top), mod_vemva = %#lx", mod_vemva);
			return -EFAULT;
		}
		return search_mod_addr(xtbl_adr, mod_vemva, start, idx - 1, table_num, xtbl_idx);
	} else {
                if (idx + 1 == table_num) {
			PSEUDO_DEBUG("found xtbl mod_vemva = %#lx, index = %ld, xtbl = %#lx, next_xtbl = none",
					mod_vemva, idx, xtbl_adr->xtbl[idx]);
			*xtbl_idx = idx;
                        return 0;
                }
                if (idx + 1 <= table_num && xtbl_adr->xtbl[idx + 1] > mod_vemva) {
			PSEUDO_DEBUG("found xtbl mod_vemva = %#lx, index = %ld, xtbl = %#lx, next_xtbl = %#lx",
					mod_vemva, idx, xtbl_adr->xtbl[idx], xtbl_adr->xtbl[idx + 1]);
			*xtbl_idx = idx;
                        return 0;
                }
                if (idx + 1 > table_num) {
			PSEUDO_DEBUG("no found xtbl(reached table end), mod_vemva = %#lx", mod_vemva);
                        return -EFAULT;
                }
		return search_mod_addr(xtbl_adr, mod_vemva, idx + 1, end, table_num, xtbl_idx);
	}
	//no reachable.
	PSEUDO_ERROR("no reachable ve_xtbl_adr info table");
	return -EFAULT;
}

/**
 * @brief search ve_xtbl_adr_hdr 
 *
 * @param[in] adr_hdr  top address
 * @param[in] mod_vemva Address of modified code
 * @param[out] addrtbl_idx the index of ve_xtbl_adr_hdr which contains mod_vemva
 *
 * @retval 0>  hit index.
 * @retval -1<= -ERRNO
 */
int search_ve_xtbl_addrtbl(struct ve_xtbl_adr_hdr *adr_hdr, uint64_t mod_vemva, size_t* addrtbl_idx) 
{
	size_t idx;
	uint64_t table_num;
	struct ve_xtbl_adr* cur;
	if (adr_hdr == NULL) {
		PSEUDO_ERROR("no ve_xtbl_adr_hdr table, adr_hdr is none, mod_vemva = %#lx", mod_vemva);
		return -EFAULT;
	}
	if (adr_hdr->num <= 0 || adr_hdr->ve_xtbl_addrtbl == NULL) {
		PSEUDO_ERROR("no ve_xtbl_adr table, xtbl_addrtbl is none, mod_vemva = %#lx", mod_vemva);
		return -EFAULT;
	}
	for (idx = 0; idx < adr_hdr->num; idx++) {
		cur = &(adr_hdr->ve_xtbl_addrtbl[idx]);
		if (cur->xtbl == NULL)
			continue;
		table_num = cur->xtbl_size / sizeof(uint64_t);
		if (cur->xtbl[0] <= mod_vemva && cur->xtbl[table_num - 1] >= mod_vemva) {
			PSEUDO_DEBUG("found addrtbl mod_vemva = %#lx, index = %ld, xtbl,start = %#lx, xtbl.end = %#lx",
					mod_vemva, idx, cur->xtbl[0], cur->xtbl[table_num - 1]);
			*addrtbl_idx = idx;
			return 0;
		}
	}
	PSEUDO_ERROR("no found addrtbl index, mod_vemva = %#lx", mod_vemva);
	return -EFAULT;
}

/**
 * @brief This function gets address of original code corresponding specified address recursively
 *
 * @param[in] mod_vemva Address of modified code
 * @param[out] result Address of original code
 *
 */
void get_original_addr_from_xtbl_adr(uint64_t mod_vemva, uint64_t* result)
{
	int ret = -1;
	size_t addrtbl_idx = 0;
	uint64_t xtbl_idx = 0;
	uint64_t table_num;
	struct ve_xtbl_adr* xtbl_addr;

	pthread_mutex_lock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);

	//table search
	ret  = search_ve_xtbl_addrtbl(ve_xtbl_adr_hdr_info.xtbl_hdr, mod_vemva, &addrtbl_idx);
	if (ret < 0) {
		/* if not found, return mod_vemva in success */
		*result = mod_vemva;
		goto done;
	}

	//mod address search
	xtbl_addr = &(ve_xtbl_adr_hdr_info.xtbl_hdr->ve_xtbl_addrtbl[addrtbl_idx]);
	table_num = xtbl_addr->xtbl_size / sizeof(uint64_t);
 	ret = search_mod_addr(xtbl_addr, mod_vemva, 0, table_num - 1, table_num, &xtbl_idx);
	if (ret < 0) {
		/* if not found, return mod_vemva in success */
		*result = mod_vemva;
		goto done;
	}
	*result = xtbl_addr->org + 0x08 * xtbl_idx;

	PSEUDO_DEBUG("searched mod_vemva = %#lx, addrtbl_idx = %zu, xtbl_idx = %lu, org =  %#lx, xtbl = %#lx, original address = %#lx", 
			mod_vemva, addrtbl_idx, xtbl_idx, xtbl_addr->org, xtbl_addr->xtbl[xtbl_idx], *result);
done:
	pthread_mutex_unlock(&ve_xtbl_adr_hdr_info.xtbl_adr_hdr_lock);
}

/**
 * @brief This function initialize structure and lock for code modification
 */
void ve_modcode_init(void) {
	struct ve_tmpfile_set *tmp = NULL;
	pthread_mutex_init(&ve_tmpfile_info.modcode_tmpfile_lock, NULL);
	tmp = &ve_tmpfile_info.tmpfiles;
	INIT_LIST_HEAD(&tmp->list);
	tmp->org.addr = 0;
	tmp->org.sz = 0;
	tmp->mod.addr = 0;
	tmp->mod.sz = 0;
	tmp->tbl.addr = 0;
	tmp->tbl.sz = 0;
}
