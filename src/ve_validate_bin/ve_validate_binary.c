#include "ve_validate_header.h"


int dir = 0, file = 0;
/*@brief usage function to display usage */
void usage(void)
{
	fprintf(stdout, "Usage: [OPTION] -f,--file=<path> "
			"-d,--directory=<path> \n"
			"Options\n"
			"  -h,--help Display help version information\n\n");
}

/**
 * @brief To Validate the gap between data and text section.
 *
 * @param[in] ehdr  ELF header
 *
 * return On success returns 0 on failure return -1 values.
 */
int ve_validate_gap(Elf_Ehdr *ehdr)
{
	int i = 0, ret = 0;
	Elf_Shdr *shdr = NULL;
	offset_t diff_offset = 0;
	Elf64_Addr sh_addr_ax = NULL;
	Elf64_Addr sh_addr_wa = NULL;

	shdr = (Elf64_Shdr *)load_elf.start_section;
	if (!shdr){
		fprintf(stderr, "ELF section headers missing\n");
		ret = -1;
		goto cleanup;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		if ((shdr->sh_flags == VE_AX)) {
			/* Get the address for end of text segment */
			sh_addr_ax = shdr->sh_addr;
		}
		if ((shdr->sh_flags == VE_WA)||
				(shdr->sh_flags == VE_WAT)) {
			/* Get the address for start of data segment */
			sh_addr_wa = shdr->sh_addr;
			break;
		}
		shdr++;
	}
	/* To check binary, gap is less than 1024 byte or not */
	diff_offset = sh_addr_wa - sh_addr_ax;
	if(diff_offset < DIFF_SECT) {
		fprintf(stderr, "DATA/TEXT gap is less: "
			"%d\nFile: %s\n\n", diff_offset, load_elf.filename);
		ret = -1;
		goto cleanup;
	}
	ret = 0;

	/*cleanup for all the dynamically allocated memory*/
cleanup:
	if (load_elf.start_section) {
		free(load_elf.start_section);
		load_elf.start_section = NULL;
	}

	if (load_elf.start_string) {
		free(load_elf.start_string);
		load_elf.start_string = NULL;
	}
	if (load_elf.elf_ex != MAP_FAILED) {
		munmap(load_elf.elf_ex, load_elf.elf_ex_size);
		load_elf.elf_ex = MAP_FAILED;
	}

	return ret;
}

/*
 * @brief open_bin_file opens bin file.
 *
 *  @param[in] filename ELF file name.
 *  @param[out] pointer pfd to store file fd
 *
 *  @return On success returns header and fd
 *  and on failure return NULL.
 */
char * open_bin_file (char *filename, int *pfd)
{
	char *buf = NULL;
	int fd = -1;
	int retval = 0;
	struct stat sb = {0};
	struct statvfs st = {0};
	char *file_path = NULL;
	Elf64_Ehdr *ehdr = NULL;

	file_path = realpath(filename, NULL);
	if (NULL == file_path) {
		retval = -errno;
		fprintf(stderr, "%s: Failed to get binary realpath: %s\n",
				filename, strerror(errno));
		if (errno == EACCES)
			fprintf(stdout,"Current user has no permission to"
			" access file : %s\nPlease execute with sudo\n",
				filename);
		goto end;
	}
	retval = statvfs(file_path, &st);
	if (-1 == retval) {
		retval = -errno;
		fprintf(stderr, "VE binary statvfs failed: %s\nFile: %s\n",
				strerror(-retval), file_path);
		goto end;
	}

	/* Check if noexec flag was set when the directory was mounted */
	if (st.f_flag & ST_NOEXEC) {
		retval = -EACCES;
		fprintf(stderr, "VE binary in directory mounted"
				" with noexec %s\nFile: %s\n",
				strerror(-retval), file_path);
		goto end;
	}
	/* Check if realpath has search permissions
	 * If not, then EACCES should be returned */
	retval = access(file_path, F_OK);
	if (-1 == retval) {
		retval = -errno;
		fprintf(stderr, "Path of VE binary inaccessible: %s\n"
			"File: %s\n",strerror(-retval), file_path);
		goto end;
	}

	retval = stat(file_path, &sb);
	if (-1 == retval) {
		retval = -errno;
		fprintf(stderr, "VE binary stat failed: %s\nFile: %s\n",
				strerror(-retval), file_path);
		goto end;
	}

	if (S_ISDIR(sb.st_mode)) {
		if(option_arg == 'f'){
			retval = -EISDIR;
		} else {
			dir++ ;
			errno = 0;
			retval = 0;
		}
		goto end;
	}
	if (!S_ISREG(sb.st_mode)) {
		if(option_arg == 'f'){
                        fprintf(stderr, "This is not a regular file\n");
                        retval = -EACCES;
                } else {
                        file++ ;
			errno = EACCES;
                        retval = 0;
                        }
                goto end;
	}

	/* Check if the file has execute permissions */
	if (((sb.st_mode & (S_IWOTH))) || !(sb.st_mode & S_IXUSR)) {
		if(option_arg == 'f'){
			fprintf(stderr, "This is not a bin file: \n");
			retval = -EACCES;
		} else {
			file++ ;
			errno = EACCES;
			retval = 0;
			}
		goto end;
	}
	fd = open(file_path, O_RDONLY | O_CLOEXEC);
	if (0 > fd) {
		retval = -errno;
		fprintf(stderr, "Failed to open VE binary file: %s\n",
				strerror(-retval));
		goto end;
	}

	buf = (char *)calloc(1, (sizeof(Elf64_Ehdr)+1));
	if(!buf) {
		retval = -errno;
		fprintf(stderr, "Failed to allocate buffer for VE binary:"
			" %s\nFile: %s\n", strerror(-retval), file_path);
		close(fd);
		goto end;
	}

	if (0 > (read(fd, buf, sizeof(Elf64_Ehdr)))) {
		retval = -errno;
		close(fd);
		free(buf);
		buf = NULL;
		fprintf(stderr, "Failed to read VE ELF file: %s\n"
				"File: %s\n",strerror(-retval), file_path);
		goto end;
	}
	ehdr = (Elf64_Ehdr *)buf;
	if (!IF_ELF(*ehdr)) {
                if (option_arg == 'f'){
                        retval = -ENOEXEC;
                        fprintf(stderr, "This is not an ELF file: %s\n",
                                        strerror(-retval));
                } else {
                        file++ ;
                        errno = ENOEXEC;
                        retval = 0;
                }
		close(fd);
		free(buf);
		buf = NULL;
		goto end;
	}


end:
	if(file_path != NULL)
		free(file_path);
	*pfd = fd;
	errno = -retval;
	return buf;

}

/**
 * @brief Map ELF file in memory space.
 *
 * @param[in] filename ELF file name.
 *
 * @return On success returns mapped memory address
 * and on failure return NULL.
 */
char *get_elhdr(char *filename)
{
	char *buf = NULL, *head = NULL;
	int fd = -1;
	int ret = 0;
	size_t map_size = 0;
	size_t size = 0;
	void *map_addr = NULL;
	Elf64_Ehdr *ehdr = NULL;
	Elf64_Shdr *nhdr = NULL;
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
		fprintf(stderr, "Failed to create virtual address space"
				" mapping: %s\nFile: %s\n\n", strerror(-ret),
				 filename);
		goto err_ret1;
	}
	load_elf.elf_ex_size = map_size;
	size = ((ehdr->e_shentsize) * (ehdr->e_shnum));

	if (0 > (lseek(fd, ehdr->e_shoff, SEEK_SET))) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed to reposition ELF file offset: "
			"%s\nFile: %s\n\n",strerror(-ret), filename);
		(void)munmap(map_addr, map_size);
		goto err_ret1;
	}
	load_elf.start_section = (char *)calloc(1,
			(size+1));
	if(!load_elf.start_section) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed to alloc buffer for ELF start"
				"section: %s\nFile: %s\n\n", strerror(-ret),
				filename);
		(void)munmap(map_addr, map_size);
		goto err_ret1;
	}

	if (0 > (read(fd, load_elf.start_section, size))) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed to read ELF start section: %s\n"
				"File: %s\n\n",strerror(-ret), filename);
		(void)munmap(map_addr, map_size);
		free(load_elf.start_section);
		goto err_ret1;
	}
#if DEBUG
	nhdr = (Elf64_Shdr *)load_elf.start_section;
	nhdr += ehdr->e_shstrndx;
	fprintf(stderr, "File: %s\nSection: offset %p, size: %p\n\n",
			filename,
			(void *)nhdr->sh_offset,
			(void *)nhdr->sh_size);

	if (0 > (lseek(fd, nhdr->sh_offset, SEEK_SET))) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed(%s) to reposition file offset",
				strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.start_section);
		goto err_ret1;
	}

	load_elf.start_string = (char *)calloc(1, nhdr->sh_size);
	if(!load_elf.start_string) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed to alloc buffer to read ELF start"
				" string: %s\n", strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.start_section);
		goto err_ret1;
	}
	if (0 > (read(fd, load_elf.start_string, nhdr->sh_size))) {
		ret = -errno;
		close(fd);
		fprintf(stderr, "Failed to read ELF start string: %s\n",
				strerror(-ret));
		(void)munmap(map_addr, map_size);
		free(load_elf.start_section);
		free(load_elf.start_string);
		goto err_ret1;
	}
#endif

	head = (char*)map_addr;
	close(fd);

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
	int ret = 0 ;

	if (ELF_VE != ehdr->e_machine) {
		if (option_arg == 'f'){
			ret = -ENOEXEC;
			fprintf(stderr," This is not VE ELF file: %s\n",
					strerror(-ret));
		} else {
                        file++ ;
			errno = ENOEXEC;
                        ret = 0;
                }
                goto err_ret;
	}
	if (ELF_CLASS != ehdr->e_ident[EI_CLASS]) {
		if (option_arg == 'f'){
			ret = -ENOEXEC;
			fprintf(stderr, "This is not 64 bit object: %s\n",
					strerror(-ret));
		} else {
                        file++ ;
			errno = ENOEXEC;
                        ret = 0;
                }
                goto err_ret;
	}
	if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) {
		if (option_arg == 'f'){
			ret = -ENOEXEC;
			fprintf(stderr, "ELF data is not little endian: %s\n",
					strerror(-ret));
		} else {
                        file++ ;
			errno = ENOEXEC;
                        ret = 0;
                }
                goto err_ret;
	}
	if ((ET_EXEC != ehdr->e_type) && (ET_DYN != ehdr->e_type)) {
		if (option_arg == 'f'){
			ret = -ENOEXEC;
			fprintf(stderr, "This is not an executable or a"
				"  shared file: %s\n", strerror(-ret));
		} else {
			file++ ;
			errno = ENOEXEC;
		        ret = 0;
		}
		goto err_ret;
	}


err_ret:
	return ret;
}


/**
 * @brief Checking/Handling the ELF file.
 *
 * @param[in] filename  ELF file name
 *
 * @return On success,0 will be returned. negative value on failure.
 */
int check_binary(char *filename)
{
	char *head = NULL;
	int ret = 0;
	load_elf.filename = filename;
	head = get_elhdr(filename);
	if (!head) {
		ret = -errno;
		goto err_ret;
	}

	/* check file type (magic, class, data and type) */
	load_elf.elf_ex = (Elf_Ehdr *)head;
	ret = chk_elf_consistency(load_elf.elf_ex);
	if ( 0 > ret) {
		goto err_ret;
	}

	/*Checking padding of 1024 bytes between data and text segments*/
	ret = ve_validate_gap(load_elf.elf_ex);
err_ret:
	return ret;
}

int main(int argc, char *argv[])
{
	int option_index = 0;
	DIR *dirp = {0};
	struct dirent *dp = {0};
	struct stat status = {0}, sb = {0};
	FILE *fp = 0;
	int retval = 0;
	int count = 0 ;

	char path[PATH_MAX] = {0}, temp[PATH_MAX] = {0};
	int flag = 0;

	if (argc == 1)
		option_arg = 'c';
	static struct option long_options[] = {
		{"file", required_argument, NULL, 'f'},
		{"directory", required_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};


	while (1) {
		flag = 0;
		if (option_arg != 'c'){
			option_arg = getopt_long(argc, argv, "hf:d:",
					long_options, &option_index);
		}
		if (option_arg == -1 ){
			break;
		}
		switch (option_arg) {
			case 'f':
				strncpy(path, optarg, (strlen(optarg)+1));
				if((retval = check_binary(path)) != 0){
					flag = 1;
					if(errno == EISDIR)
						usage();

				}
				if(flag == 0)
					fprintf(stdout, "**VE BINARY/SHARED"
					" LIBRARY IS VALIDATED SUCCESSFULLY!!**\n\n");

				memset((void *)path, 0, sizeof(path));
				break;

			case 'd':
				if (stat(optarg, &status) == -1) {
					fprintf(stderr, "stat failed: %s\n", strerror(errno));
					if (errno == EACCES)
						fprintf(stdout,"Current user"
								" has no permission to access"
								" file: %s\nPlease"
								" execute with sudo\n"
								, optarg );
					retval = -1;
					break;
				}
				if(!S_ISDIR(status.st_mode)){
					usage();
					retval = -1;
					break;
				}
				strncpy(path, optarg, strlen(optarg));
			case 'c':
				if(option_arg == 'c'){
					strncpy(path, ".", 1);
					option_arg = -1;
				}
				count = 0;
				file = 0, dir = 0;
				strncat(path, "/", (strlen("/")+1));
				strncpy(temp, path, (strlen(path)+1));
				if((dirp = opendir(path)) == NULL){
					fprintf(stderr,"opendir failed: %s\n",
							strerror(errno));
					if (errno == EACCES)
						fprintf(stdout, "Current user"
							" has no permission"
							" to execute file:"
							" %s\nPlease execute"
							"  with sudo\n", path);
					retval = -1;
					break;
				}
				/*Reading the directory*/
				while((dp = readdir(dirp))!= NULL) {
					count++;
					if((!strcmp(dp->d_name, ".")) ||
						(!strcmp(dp->d_name, ".."))) {
						continue;
					}
					/*lenght path + d_name < PATH_MAX */
					if ((strlen(path) + strlen(dp->d_name)) < PATH_MAX)
						strncat(path, dp->d_name, sizeof(dp->d_name));
					else {
						fprintf(stderr, "File path is too long\n");
						memset((void *)path, 0, sizeof(path));
						memset((void *)temp, 0, sizeof(temp));
						closedir(dirp);
						break;
					}

					if((retval = check_binary(path))!= 0){
						flag = 1;
						retval = 0;
					}
					memset((void *)path, 0, sizeof(path));
					strncpy(path, temp, (strlen(temp)+1));
				}

				/*If the directory is empty*/
				if (count == 2){
					fprintf(stdout, "**Empty directory**\n\n");
					retval = 0;
				}
				else if (count == (file+dir+2))
					fprintf(stdout, "**No VE binary and"
						" shared library found**\n\n");

				else if (flag == 0)
					fprintf(stdout, "**ALL VE BINARY/SHARED LIBRARIES"
					" ARE VALIDATED SUCCESSFULLY!!**\n\n");

				memset((void *)path, 0, sizeof(path));
				memset((void *)temp, 0, sizeof(temp));
				closedir(dirp);
				break;

			case 'h':
				usage();
				break;

			default:
				fprintf(stderr, "Invalid "
						"command line argument\n");
				usage();
				break;
		}
	}
	if (optind < argc){
		fprintf(stderr, "Please refer usage of options\n");
		usage();
	}
	return retval;
}
