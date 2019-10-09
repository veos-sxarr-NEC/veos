#ifndef __VE_VALIDATE_HEADER_H
#define __VE_VALIDATE_HEADER_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/mount.h>
#include <getopt.h>
#include <string.h>


#define ELF_CLASS       ELFCLASS64
#define ELF_VE  251
#define DIFF_SECT 0x400
#define VE_AX 0x6
#define VE_WA 0x3
#define VE_WAT 0x403

#define IF_ELF(ehdr)    ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
                (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
                (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
                (ehdr).e_ident[EI_MAG3] == ELFMAG3)


typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef unsigned long long offset_t;

int option_arg;

/*Structure to store the elf file information*/
struct ve_elf_load_stat  {
        Elf_Ehdr *elf_ex;       /*!< ELF header for ELF executable itself*/
	size_t elf_ex_size;	/**/
        char *start_section;    /*!< start of section header */
        char *start_string;     /*!< start of string of section header */
	char *filename;         /*!< filename */
}load_elf;

int ve_validate_gap(Elf_Ehdr *);
int check_binary(char *);
char *get_elhdr(char *);
int chk_elf_consistency(Elf_Ehdr *);
char *open_bin_file (char *filename, int *pfd);

#endif
