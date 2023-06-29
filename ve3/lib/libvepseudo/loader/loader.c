#include <string.h>
#include <libved.h>
#include <loader.h>
#include <veos_arch_defs.h>
#include <sys_common.h>

#define EF_VE_ARCH_MASK (0x0000000f)
#define EF_VE_ARCH_VE1 (0x0)
#define EF_VE_ARCH_VE3 (0x1)
#define EF_VE_ABI_MASK (0x000f0000)
#define EF_VE_ABI_VER1 (0x0)
#define EF_VE_ABI_VER2 (0x00010000)
#define VH_PAGE_SHIFT (12)
#define VE3_LINKER_PATH "/opt/nec/ve3/lib/ld-linux-ve.so.1"
#define EF_VE_DYNAMIC_CD (0x00000000)
#define EF_VE_NO_DYNAMIC_CD   (0x00000100)
#define EF_VE_DYNAMIC_CD_MASK (0x00000f00)

/* #1410 Used to compare with size(256B) and flags */
#define DIFF_SECT 0x100
#define VE_AX 0x6
#define VE_WA 0x3
#define VE_WAT 0x403

/**
 * @brief To Validate the gap between data and text section.
 *
 * @param[in] ehdr  ELF header
 *
 * @Output: Program proceed further in success else abort.
 */
void ve3_validate_gap(Elf_Ehdr *ehdr)
{
       char *sec_string = NULL;
       int i = 0;
       Elf_Shdr *shdr = NULL;
       ve_mem_offset_t diff_offset = 0;
       Elf64_Addr sh_addr_ax = (long unsigned int)NULL;
       Elf64_Addr sh_addr_wa = (long unsigned int)NULL;

       if(NULL == ehdr)
               return;

       if (ehdr->e_type == ET_EXEC) {
               shdr = (Elf64_Shdr *)load_elf.stat.start_section;
               sec_string = load_elf.stat.start_string;
       } else if (ehdr->e_type == ET_DYN) {
               shdr = (Elf64_Shdr *)load_elf.stat.start_section_dyn;
               sec_string = load_elf.stat.start_string_dyn;
       }

       if (!shdr)
               return;

       for (i = 0; i < ehdr->e_shnum; i++) {
               if ((shdr->sh_flags == VE_AX)) {
                       /* Get the address for end of text segment */
                       sh_addr_ax = shdr->sh_addr;
                       PSEUDO_DEBUG("Section name is %s,"
                                       "flags(AX): %p, address: %p\n",
                                       (char *)sec_string + shdr->sh_name,
                                       (void *)shdr->sh_flags,
                                       (void *)sh_addr_ax);
               }
               if ((shdr->sh_flags == VE_WA)|| (shdr->sh_flags == VE_WAT)) {
                       /* Get the address for start of data segment */
                       sh_addr_wa = shdr->sh_addr;
                       PSEUDO_DEBUG("Section name is %s,"
                                       "flags(WA/WAT): %p,"
                                       "address: %p\n",
                                       (char *)sec_string + shdr->sh_name,
                                       (void *)shdr->sh_flags,
                                       (void *)sh_addr_wa);
                       break;
               }
               shdr++;
       }
       /* To check binary/ld.so, gap is less than 256 byte or not */
       diff_offset = sh_addr_wa - sh_addr_ax;
       if(diff_offset < DIFF_SECT) {
               PSEUDO_ERROR("TEXT/DATA gap segment is less than 256B\n");
               fprintf(stderr, "TEXT/DATA segment gap is less than 256B\n");
               pseudo_abort();
       }

       PSEUDO_DEBUG("The diff between AX and WA/WAT is %p\n\n",
                       (void *)diff_offset);
}

VEOS_ARCH_DEP_FUNC(ve3, arch_ve_validate_gap , ve3_validate_gap)


/**
* @brief Enables the capability bits of VE3 hardware.
*
* @param[in] Full Hardware capability mask HWCAP_VE_MASK.
*
* @return Unsigned int value of hardware Capability for VE3.
*/
uint64_t ve3_get_hardware_capability(uint32_t p_hw_cap_mask)
{
	Elf64_Xword hw_cap = 0;
	hw_cap = p_hw_cap_mask & HWCAP_VE_VE3;
	return hw_cap;
}

VEOS_ARCH_DEP_FUNC(ve3, arch_get_hardware_capability , ve3_get_hardware_capability)

/**
* @brief Parse segments and fill information.
*
* @param[in] head ELF file mmaped address.
* @param[in] ehdr Address of ELF header.
*
* @return No return value, on failure call exit.
*/
void ve3_fill_ve_elf_data(char *head)
{
	static bool is_interp;
	int segnum = 0;
	char *buf = NULL;
	void *align_addr = NULL;
	Elf_Ehdr *ehdr = NULL;
	Elf_Phdr *phdr = NULL;
	bool switch_to_ve3_linker = false;
	char *linker_type = NULL;
	uint32_t e_flags = 0;
	size_t filesz = 0;

	ehdr = (Elf_Ehdr *)head;
	PSEUDO_DEBUG("Parsing segment from file");
	for (segnum = 0; segnum < ehdr->e_phnum; segnum++) {
		phdr = (Elf_Phdr *)(head + ehdr->e_phoff +
				ehdr->e_phentsize * segnum);

		switch (phdr->p_type) {
		case PT_INTERP:
			e_flags = ehdr->e_flags;

			 /* A blank e_flags implies a binary created on old VE1 compiler
			  * Otherwise get the architecture of Executable */
			if (0 == e_flags || EF_VE_ARCH_VE1 == (e_flags & EF_VE_ARCH_MASK)) {

				PSEUDO_DEBUG("VE1 Executable on VE3 device");

				/* Get Environment Variable "VE_LINKER_VERSION" */
				linker_type = getenv("VE_LINKER_VERSION");

				PSEUDO_DEBUG("VE_LINKER_VERSION=%s",linker_type);

				/* #2152-If Environment Variable is set to ve3 or VE3 then switch to VE3 linker */
				if(NULL != linker_type &&
						 (0 == strcmp(linker_type,"VE3") || 0 == strcmp(linker_type,"ve3") ||
						  0 == strcmp(linker_type,"Ve3")))
				{
					switch_to_ve3_linker = true;
				}

			}
			PSEUDO_DEBUG("VE interpreter, name: %p",
					(void *)head+phdr->p_offset);

			if(switch_to_ve3_linker)
				PSEUDO_DEBUG("Switch to VE3 interpreter, name: %s",
						VE3_LINKER_PATH);

			if (0 > (lseek(load_elf.stat.fd,
						phdr->p_offset, SEEK_SET))) {
				PSEUDO_ERROR("failed to reposition offset"
						": %s", strerror(errno));
				fprintf(stderr, "Failed to load executable\n"
					"Reposition offset: %s\n",
					strerror(errno));
				pseudo_abort();
			}

			/* Get the size of linker path string from INTERP or Standard VE3 path */
			if(!switch_to_ve3_linker)
				filesz = phdr->p_filesz;
			else
				filesz = sizeof(VE3_LINKER_PATH);

			buf = (char *)calloc(1, filesz);

			if(!buf) {
				PSEUDO_ERROR("failed to allocate buffer: %s",
						strerror(errno));
				fprintf(stderr, "Failed to load executable\n"
					"Allocate interpreter buffer: %s\n",
					strerror(errno));
				pseudo_abort();
			}
			/* Read regular filesize from fd even if the linker is switched */
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

			if(switch_to_ve3_linker)
				strcpy(buf,VE3_LINKER_PATH);

			/* copying INTERP in mapped area */
			(void)memcpy((char *)load_elf.stat.file_interp,
					(char *)buf, filesz);

			load_elf.stat.file_interp_end = (char *)
					load_elf.stat.file_interp
					+ filesz;

			align_addr = (char *)((((uint64_t)
					(load_elf.stat.file_interp_end))
					& ~(((uint64_t)1 << VH_PAGE_SHIFT) - 1))
					+ (1 << VH_PAGE_SHIFT));

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

VEOS_ARCH_DEP_FUNC(ve3, arch_fill_ve_elf_data , ve3_fill_ve_elf_data)

int libvepseudo_ve3_probe(vedl_handle *handle, void *arg)
{
	Elf_Ehdr *ehdr = arg;
        if( NULL == arg )
        {
                PSEUDO_DEBUG("loader(ve3): Invalid binary ELF"
			       	"header is NULL");
                return 0;
        }
	const char *ve_arch_class = vedl_get_arch_class_name(handle);
	if (0 != strcmp(ve_arch_class, "ve3")) {
		PSEUDO_DEBUG("loader(ve3): unsupported arch class %s",
			ve_arch_class);
		return 0;
	}
	/* check ELF header */
	uint32_t e_flags = ehdr->e_flags;
#if 0 /* disable binary checking for old VE1 */
        char *ve_no_dynamic_cd = NULL;
	ve_no_dynamic_cd = getenv("VE_NO_DYNAMIC_CD");
	if(!ve_no_dynamic_cd) {
		if(EF_VE_ARCH_VE1 == (e_flags & EF_VE_ARCH_MASK) &&
				EF_VE_DYNAMIC_CD == (e_flags & EF_VE_DYNAMIC_CD_MASK)) {
			PSEUDO_DEBUG("loader(ve3): ELF file Flag value invalid : 0x%08x",
					e_flags);
			fprintf(stderr, "ELF file Flag value invalid : 0x%08x\n",
					e_flags);

			return -1;
		}
		if(EF_VE_ARCH_VE3 == (e_flags & EF_VE_ARCH_MASK) &&
				EF_VE_DYNAMIC_CD == (e_flags & EF_VE_DYNAMIC_CD_MASK)) {
			PSEUDO_DEBUG("loader(ve3): ELF file Flag value invalid : 0x%08x",
					e_flags);
			fprintf(stderr, "ELF file Flag value invalid : 0x%08x\n",
					e_flags);
			return -1;
		}
        }
#endif

	/* Old VE1 arch binary on VE3 machine */
	if(0 == e_flags)
		return 1;

	/* If binary does not belong to VE1 or VE3 arch then return false */
	if (EF_VE_ARCH_VE3 != (e_flags & EF_VE_ARCH_MASK) &&
			EF_VE_ARCH_VE1 != (e_flags & EF_VE_ARCH_MASK)) {
		PSEUDO_DEBUG("loader(ve3): unsupported architecture : 0x%08x",
			e_flags & EF_VE_ARCH_MASK);
		fprintf(stderr, "Unsupported architecture type on VE3 : 0x%08x\n",
-                       e_flags & EF_VE_ARCH_MASK);
		return -1;
	}

	if (EF_VE_ABI_VER2 != (e_flags & EF_VE_ABI_MASK) &&
			EF_VE_ABI_VER1 != ((e_flags & EF_VE_ABI_MASK))) {
		PSEUDO_DEBUG("loader(ve3): unsupported ABI version 0x%08x",
			e_flags & EF_VE_ABI_MASK);
		fprintf(stderr, "Unsupported ABI version on VE3 : 0x%08x\n",
			e_flags & EF_VE_ABI_MASK);
		return -1;
	}

	/* Binary with VE1 arch/ABIv1, VE3 arch/ABIv2 and VE3 arch/ABIv1 are allowed
	 * on VE3 device but not the combination VE1 arch/ABIv2 */
	if(EF_VE_ARCH_VE1 == (e_flags & EF_VE_ARCH_MASK) &&
			EF_VE_ABI_VER2 == (e_flags & EF_VE_ABI_MASK)) {
		PSEUDO_DEBUG("loader(ve3): unsupported combination of architecture and ABI 0x%08x",
				e_flags);
		fprintf(stderr, "Unsupported combination of architecture type and ABI on VE3 : 0x%08x\n",
				e_flags);
		return -1;
	}

	return 1;
}
extern struct veos_arch_ops _pseudo_ve3_arch_ops;
VEOS_ARCH_DEF(ve3, _pseudo_ve3_arch_ops, libvepseudo_ve3_probe)
