#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libved.h>
#include <veos.h>
#include <veos_ve3.h>
#include <veos_arch_defs.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>

/* Size of 'type' in sysfs. It has a natural number which indicates kinds of HW. */
#define SIZE_OF_TYPE_SYSFS 64 

int veos_ve3_probe(vedl_handle *handle, void *unused)
{
	const char *arch_class = vedl_get_arch_class_name(handle);
	return strcmp(arch_class, "ve3") == 0;
}

VEOS_ARCH_DEF(ve3, _veos_ve3_arch_ops, veos_ve3_probe)

int ve3_construct_node_arch_dep_data(struct ve_node_struct *venode)
{
	char filename[PATH_MAX], type_buf[SIZE_OF_TYPE_SYSFS];
	FILE *fp = NULL;
	int retval = -1;

	venode->arch_dep_data = calloc(1,
					sizeof(struct ve3_node_arch_dep_data));
	if (venode->arch_dep_data == NULL) {
		return -errno;
	}

	venode->ve_type = VE_TYPE_VE3;

	snprintf(filename, sizeof(filename), "%s/type", venode->ve_sysfs_path);
	fp = fopen(filename, "r");
	if (fp == NULL) {
		VEOS_ERROR("Failed to open %s %s", filename, strerror(errno));
		return -1;
	}
	memset(type_buf, 0, SIZE_OF_TYPE_SYSFS);
	if ((fread(type_buf, 1, SIZE_OF_TYPE_SYSFS - 1, fp) == 0) || ferror(fp)) {
		VEOS_ERROR("Failed to read %s", filename);
		goto hndl_return;
	}
	errno = 0;
	((struct ve3_node_arch_dep_data *)(venode->arch_dep_data))->type = 
						(int)strtol(type_buf, NULL, 10);
	if (errno != 0) {
		VEOS_ERROR("Failed to convert %s", type_buf);
		goto hndl_return;
	}
	VEOS_DEBUG("type is %d", ((struct ve3_node_arch_dep_data *)
						(venode->arch_dep_data))->type);

	retval = 0;
hndl_return:
	if (fp != NULL) {
		if (fclose(fp) != 0)
			VEOS_WARN("fclose : %s", strerror(errno));
	}
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_main_construct_node_arch_dep_data, ve3_construct_node_arch_dep_data)

void ve3_free_node_arch_dep_data(struct ve_node_struct *venode)
{
	free(venode->arch_dep_data);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_main_free_node_arch_dep_data, ve3_free_node_arch_dep_data)

void ve3_turn_on_clock_gating(void)
{
	int retry = CHECK_STATE_RETRY_CNT;
	int ret;
	uint64_t state = 0;
	struct timespec retry_delay = {};
	struct ve3_node_arch_dep_data *data =
		(struct ve3_node_arch_dep_data *)(VE_NODE(0)->arch_dep_data);

	if (data->type == QTYPE)
		goto hndl_return;

	retry_delay.tv_sec = 0;
	retry_delay.tv_nsec = CHECK_STATE_RETRY_DELAY;

	VEOS_DEBUG("Turning on core clock gating");
	ret = vedl_handle_clock_gating(VE_NODE(0)->handle, CLOCK_GATING_ON);
	if (__builtin_expect((ret != 0), 0))
		veos_abort("Faild to turn ON core clock gating %s",
							strerror(errno));

	do {
		ret = vedl_get_clock_gating_state(VE_NODE(0)->handle, &state);
		if (__builtin_expect((ret != 0), 0))
			veos_abort("Faild to get clock gating state %s",
							strerror(errno));
		if (((state & CLOCK_GATING_STATE_MASK)
			>> (63 - CLOCK_GATING_STATE_BIT)) == CLOCK_GATING_ON)
			break;

		retry--;
		if (__builtin_expect((retry < 1), 0))
			veos_abort("Cannot turn ON core clock gating");

		VEOS_DEBUG("Re-try to get clock gating state");
		nanosleep(&retry_delay, NULL);
	} while (1);
hndl_return:
	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_turn_on_clock_gating, ve3_turn_on_clock_gating)


#define CONF_FILE_PATH "/etc/opt/nec/ve/veos/vemodcode.conf"

int ve3_init_code_modification_file_info(char *file_path, int max_file_num,
		int per_usr_max_file_num, int alive_day_inter_file, int node_num)
{
	int retval = 0;
	int ret = -1;
	struct ve_node_struct *vnode = VE_NODE(0);

        char str[PATH_MAX - 11 + 14];
	char *s1, *c1;
        FILE *ve_mod_conf = NULL;
	DIR *ve_mod_file_dirp = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	if(file_path == NULL){
		retval = -1;
		goto hndl_return;
	}

	/* Set info to ve_node_struct */
	snprintf(vnode->code_modification_file.path, PATH_MAX, "%s/veos%d-tmp",
					file_path, node_num);
	if ((ve_mod_conf = fopen(CONF_FILE_PATH, "r")) != NULL) {
		while((fgets(str, sizeof(str), ve_mod_conf)) != NULL) {
			if ( str[0] == '#' ){
				continue;
			}
			if (strstr(str, "TMP_FILE_DIR=") != NULL) {
				if ((c1 = strchr(str, '\n')) != NULL)
					*c1 = '\0';
				s1 = (char *)&str[0] + strlen("TMP_FILE_DIR=");
				if (strlen(s1) > (PATH_MAX - 11)){
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Path of Code Modification is too long");
					retval = -1;
					fclose(ve_mod_conf);
					return retval;
				}
                                ret = snprintf(vnode->code_modification_file.path, PATH_MAX,
						"%s/veos%d-tmp", s1, node_num);
				if (ret < 0) {
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to snprintf(), ret=%d, "
						" due to %s", ret, strerror(errno));
					retval = -1;
					fclose(ve_mod_conf);
					return retval;
				}
				ve_mod_file_dirp = opendir(vnode->code_modification_file.path);
				if (ve_mod_file_dirp == NULL) {
					if(mkdir(vnode->code_modification_file.path, S_IRWXU) == -1) {
						VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
							"Failed to mkdir for Code Modification"
							" due to %s", strerror(errno));
						retval = -1;
						fclose(ve_mod_conf);
						return retval;
					}
					ret = chmod(vnode->code_modification_file.path, 01777);
					if (ret < 0) {
						VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
							"Failed to chmod dir for Code Modification(), " 
							"ret=%d, due to %s", ret, strerror(errno));
						retval = -1;
						fclose(ve_mod_conf);
						return retval;
					}
				}else{
					closedir(ve_mod_file_dirp);
				}
                                break;
                        }
                }
                fclose(ve_mod_conf);
        }

	if(strlen(vnode->code_modification_file.path) > PATH_MAX) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		"Path of Code Modification is too long");
		retval = -1;
		goto hndl_return;
	}

	vnode->code_modification_file.max_file_num = max_file_num;
	vnode->code_modification_file.per_usr_max_file_num = per_usr_max_file_num;
	vnode->code_modification_file.alive_day_inter_file = alive_day_inter_file*24*60*60;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_init_code_modification_file_info, ve3_init_code_modification_file_info)
