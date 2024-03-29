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
* @file  pseudo_process.c
* @brief Handles Pseudo Process and its corresponding VE process creation.
*
*	This file contains the functions that are used for creation of pseudo
*	process and its corresponding VE process.
*
* @internal
* @author Pseudo/System Call Handling
*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <log4c.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <mempolicy.h>
#include <libgen.h>
#include "config.h"
#include "libved.h"
#include "loader.h"
#include "list.h"
#include "process_mgmt_comm.h"
#include "exception.h"
#include "sys_mm.h"
#include "vemva_mgmt.h"
#include "ve_socket.h"
#include "velayout.h"
#include "pseudo_ptrace.h"
#include "pseudo_ived_common.h"
#include "sys_process_mgmt.h"
#include "handle.h"
#include <libudev.h>
#include <libved.h>
#include "vemmr_mgmt.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sched.h>
#include <math.h>
#include "signal_comm.h"

#define PROGRAM_NAME "ve_exec"
#define ISDIGIT(c)      ((unsigned)c-'0' < 10)
#define VE_ST_UNAVAILABLE 4	/*value of ve_state when it is unavailable as specified in vesysinit*/

__thread sigset_t ve_proc_sigmask;
__thread veos_handle *g_handle = NULL;
__thread struct _ve_page_info ve_page_info;

struct tid_info global_tid_info[VEOS_MAX_VE_THREADS];
pthread_mutex_t tid_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t sync_fork_dma;

bool ve_trace_me;
log4c_category_t *cat_pseudo_core;
log4c_appender_t *app_pseudo_core;
FILE *pseudo_fp;

struct ve_address_space_info ve_info;
uint64_t default_page_size;
struct ve_load_data load_elf;
struct vemva_header vemva_header;
cpu_set_t ve_affinity_mask;

/**
 * @brief Fetches the node number from VEOS socket file.
 *
 * @param[in] s string contains the veos socket file path
 *
 * @return node number on which this ve process will run
 */
static int get_ve_node_num(char *s)
{
	int n = 0;

	while (*s != '\0') {
		if (ISDIGIT(*s))
			n = 10*n + (*s - '0');
		else if (*s == '.')
			break;

		s++;
	}
	return n;
}

/**
* @brief Function to abort Pseudo Process.
*/
void pseudo_abort()
{
	struct sigaction act = { {0} };
	int fd = 0, ve_state_val = -1;
	char filename[PATH_MAX] = {"ve_state"};
	char filepath[PATH_MAX] = {0};
	int ret = -1;
	char buf[PATH_MAX];
	int readlen = 0, node_num = -1;
	struct rlimit core_limit;/*Added for #2121 to disable core dump of ve_exec when VE NODE is unavailable*/
	/* Set SIGABRT action to DEFAULT */
	act.sa_handler = SIG_DFL;
	sigaction(SIGABRT, &act, NULL);
	memset(&buf, -1, sizeof(buf));
	if(g_handle){
	node_num = get_ve_node_num(g_handle->veos_sock_name);
	const char *sysfs_path = vedl_get_sysfs_path(g_handle->ve_handle);
	if(sysfs_path){
		ret = snprintf(filepath, PATH_MAX, "%s/%s", sysfs_path,
								filename);
		/*  ret doesn't include null termination. */
		if (ret < 0 || ret > (sizeof(filepath) - 1)) {
			PSEUDO_DEBUG("filename is too long");
			goto err_abort;
		}else {
			fd = open(filepath, O_RDONLY);
			if(fd < 0){
				PSEUDO_ERROR("Failed to open %s: %s",
						filepath, strerror(errno));
				fprintf(stderr, "Failed to open %s: %s",
						filepath, strerror(errno));
				goto err_abort;
			}
			readlen = read(fd, buf, sizeof(buf));
			if(readlen == -1){
				PSEUDO_ERROR("Failed to read from file %s: %s",
						filepath, strerror(errno));
				fprintf(stderr, "Failed to read from file %s: %s",
						filepath, strerror(errno));
				close(fd);
				goto err_abort;
			}
			ve_state_val = atoi(buf);
			if(ve_state_val == VE_ST_UNAVAILABLE){
				PSEUDO_ERROR("VE Node %d is UNAVAILABLE",
								node_num);
				fprintf(stderr, "VE Node %d is UNAVAILABLE\n",
								node_num);
				core_limit.rlim_cur = 0;
                                core_limit.rlim_max = 0;
                                if (-1 == setrlimit(RLIMIT_CORE, &core_limit)) {
					PSEUDO_ERROR("Seting core file size to zero failed");
					goto err_abort;
                                }

			}
			close(fd);
		}
	} else
		PSEUDO_ERROR("Failed to get sysfs path for node %d: %s",
						node_num, strerror(errno));
	} else
		PSEUDO_DEBUG("VEOS handle is not initialized");

	/* Abort Pseudo Process */
err_abort:
	abort();
}

/**
 * @brief Convert 'string' to 'unsigned long long' and also handle
 * out of range value of 'unsigned long long'
 *
 * @param limit_optarg [in] String value
 * @param lim_val [out] Converted value in 'unsigned long long'
 *
 * @return 0 on success and -1 on failure
 */
int get_value(char *lim_optarg, unsigned long long *lim_val)
{
       int retval = 0;
	if(!lim_optarg)
	        return -1;

       char *optstr = lim_optarg;
       PSEUDO_TRACE("Entering");

       if (strncmp(optstr, "unlimited", sizeof("unlimited")) == 0) {
	       *lim_val = RLIM_INFINITY;
	       return retval;
       }
       while (*optstr >= '0' && *optstr <= '9')
               *lim_val = (*lim_val) * 10 + (*optstr++ - '0');

       PSEUDO_DEBUG("Limit value spcified: %llu", *lim_val);
       if (*optstr != '\0') {
               PSEUDO_ERROR("Invalid limit value in VE_LIMIT_OPT: %s", optstr);
               retval = -1;
       }
       PSEUDO_TRACE("Exiting");
       return retval;
}

/**
 * @brief Parse VE_LIMIT_OPT and fetch the resource limit
 *
 * @param limit_opt [in] Resource limit passed by user as environment
 * variable in "VE_LIMIT_OPT"
 * @param ve_rlim [out] To set the resource limit
 *
 * @return 0 on success and -1 on failure.
 */

int get_ve_limit_opt(char *limit_opt, struct rlimit *ve_rlim)
{
	int arg_c = 0;
	int opt = 0, limit = 0;
	int len_optind_arg = 0, len_optarg = 0;
	int retval = -1;
	bool repeat_lim[VE_RLIM_CNT] = {0};
	unsigned long long lim_val = 0;
	char *arg_v[512] = {NULL};
	if(!limit_opt)
               goto out;

	char *token = strtok(limit_opt, " ");

	static const struct option longopts[] = {
		{ "hardc",        required_argument, NULL, 1 },
		{ "softc",     required_argument, NULL, 2 },
		{ "hardd",      required_argument, NULL, 3 },
		{ "softd",       required_argument, NULL, 4 },
		{ "hardi",        required_argument, NULL, 5 },
		{ "softi",       required_argument, NULL, 6 },
		{ "hardm",      required_argument, NULL, 7 },
		{ "softm",      required_argument, NULL, 8 },
		{ "hards",    required_argument, NULL, 9 },
		{ "softs",   required_argument, NULL, 10 },
		{ "hardt",       required_argument, NULL, 11 },
		{ "softt",     required_argument, NULL, 12 },
		{ "hardv",      required_argument, NULL, 13 },
		{ "softv",        required_argument, NULL, 14 },
		{ NULL, 0, NULL, 0 }
	};

	PSEUDO_TRACE("Entering");

	arg_v[arg_c] = strndup("error", strlen("error"));
	if (!arg_v[arg_c]) {
		PSEUDO_ERROR("Failed to allocate memory");
		fprintf(stderr, "Failed to allocate memory\n");
		goto out;
	}
	arg_c++;

	/* Tokenize the value of VE_LIMIT_OPT environment variable */
	while (token != NULL) {
		arg_v[arg_c] = strndup(token, strlen(token));
		if (!arg_v[arg_c]) {
			PSEUDO_ERROR("Failed to allocate memory");
			fprintf(stderr, "Failed to allocate memory\n");
			goto out;
		}
		token = strtok(NULL, " ");
		arg_c++;
	}
	arg_v[arg_c] = '\0';
	optind = 1;
	/* Check the option specified with VE_LIMIT_OPT */
	while ((opt = getopt_long(arg_c, arg_v, "+:c:d:i:m:s:t:v:",
					longopts, NULL)) != -1) {
		/* If valid option is specified and no option
		 * argument is missing */
		if (opt != '?' && opt != ':') {
			lim_val = 0;
			retval = get_value(optarg, &lim_val);
			if (0 > retval) {
				PSEUDO_ERROR("VE_LIMIT_OPT: Error in parsing resource limit value");
				fprintf(stderr, "VE_LIMIT_OPT: Error in parsing resource limit value\n");
				goto out_err;
			}
		}
		/* Validate RLIMIT_CPU resource limit's minimum value*/
		if(((opt == 't') || (opt == SOFTT)) && lim_val == 0){
                        lim_val = 1;
                }
		/* Validate the resource limit values*/
		if (opt == 'c' || opt == 'd' || opt == 'i' ||
				opt == 'm' || opt == 's' ||
				opt == 't' || opt == 'v') {
			len_optind_arg = strlen(arg_v[optind - 1]);
			len_optarg = strlen(optarg);
			if (strncmp(arg_v[optind-1], optarg,
						(len_optind_arg > len_optarg ?
						len_optind_arg : len_optarg)))
				goto out_err;
		}
		/*Resource limit value should not be greater than
		* than MAX_RESOURCE_LIMIT for c, d, m, s and
		* v resources */
		if (opt != HARDI && opt != SOFTI &&
			opt != HARDT && opt != SOFTT &&
			opt != 'i' && opt != 't' &&
			(optarg != NULL && strncmp(optarg, "unlimited", sizeof("unlimited")))) {
			if (lim_val > MAX_RESOURCE_LIMIT) {
				PSEUDO_ERROR("VE_LIMIT_OPT: Resource limit out of range");
				fprintf(stderr, "VE_LIMIT_OPT: Resource limit out of range\n");
				goto out_err;
			}
			lim_val = lim_val * KB;
		}
		/* Only consider the first value if the same resource limit
		 * mentioned repeatedly */
		if (opt < VE_RLIM_CNT) {
			if (!repeat_lim[opt])
				repeat_lim[opt] = 1;
			else
				continue;
		}
		switch (opt) {
		case 1:
			ve_rlim[RLIMIT_CORE].rlim_max = lim_val;
			break;
		case 2:
			ve_rlim[RLIMIT_CORE].rlim_cur = lim_val;
			break;
		case 3:
			ve_rlim[RLIMIT_DATA].rlim_max = lim_val;
			break;
		case 4:
			ve_rlim[RLIMIT_DATA].rlim_cur = lim_val;
			break;
		case 5:
			ve_rlim[RLIMIT_SIGPENDING].rlim_max = lim_val;
			break;
		case 6:
			ve_rlim[RLIMIT_SIGPENDING].rlim_cur = lim_val;
			break;
		case 7:
			ve_rlim[RLIMIT_RSS].rlim_max = lim_val;
			break;
		case 8:
			ve_rlim[RLIMIT_RSS].rlim_cur = lim_val;
			break;
		case 9:
			ve_rlim[RLIMIT_STACK].rlim_max = lim_val;
			break;
		case 10:
			ve_rlim[RLIMIT_STACK].rlim_cur = lim_val;
			break;
		case 11:
			ve_rlim[RLIMIT_CPU].rlim_max = lim_val;
			break;
		case 12:
			ve_rlim[RLIMIT_CPU].rlim_cur = lim_val;
			break;
		case 13:
			ve_rlim[RLIMIT_AS].rlim_max = lim_val;
			break;
		case 14:
			ve_rlim[RLIMIT_AS].rlim_cur = lim_val;
			break;
		case 'c':
			if (!repeat_lim[SOFTC]) {
				ve_rlim[RLIMIT_CORE].rlim_cur = lim_val;
				repeat_lim[SOFTC] = 1;
			}
			if (!repeat_lim[HARDC]) {
				ve_rlim[RLIMIT_CORE].rlim_max = lim_val;
				repeat_lim[HARDC] = 1;
			}
			break;
		case 'd':
			if (!repeat_lim[SOFTD]) {
				ve_rlim[RLIMIT_DATA].rlim_cur = lim_val;
				repeat_lim[SOFTD] = 1;
			}
			if (!repeat_lim[HARDD]) {
				ve_rlim[RLIMIT_DATA].rlim_max = lim_val;
				repeat_lim[HARDD] = 1;
			}
			break;
		case 'i':
			if (!repeat_lim[SOFTI]) {
				ve_rlim[RLIMIT_SIGPENDING].rlim_cur = lim_val;
				repeat_lim[SOFTI] = 1;
			}
			if (!repeat_lim[HARDI]) {
				ve_rlim[RLIMIT_SIGPENDING].rlim_max = lim_val;
				repeat_lim[HARDI] = 1;
			}
			break;
		case 'm':
			if (!repeat_lim[SOFTM]) {
				ve_rlim[RLIMIT_RSS].rlim_cur = lim_val;
				repeat_lim[SOFTM] = 1;
			}
			if (!repeat_lim[HARDM]) {
				ve_rlim[RLIMIT_RSS].rlim_max = lim_val;
				repeat_lim[HARDM] = 1;
			}
			break;
		case 's':
			if (!repeat_lim[SOFTS]) {
				ve_rlim[RLIMIT_STACK].rlim_cur = lim_val;
				repeat_lim[SOFTS] = 1;
				if( -1 == setenv("VE_STACK_LIMIT", optarg, 1))
					PSEUDO_DEBUG("setting env VE_STACK_LIMIT failed: %s", strerror(errno));
					
			}
			if (!repeat_lim[HARDS]) {
				ve_rlim[RLIMIT_STACK].rlim_max = lim_val;
				repeat_lim[HARDS] = 1;
			}
			break;
		case 't':
			if (!repeat_lim[SOFTT]) {
				ve_rlim[RLIMIT_CPU].rlim_cur = lim_val;
				repeat_lim[SOFTT] = 1;
			}
			if (!repeat_lim[HARDT]) {
				ve_rlim[RLIMIT_CPU].rlim_max = lim_val;
				repeat_lim[HARDT] = 1;
			}
			break;
		case 'v':
			if (!repeat_lim[SOFTV]) {
				ve_rlim[RLIMIT_AS].rlim_cur = lim_val;
				repeat_lim[SOFTV] = 1;
			}
			if (!repeat_lim[HARDV]) {
				ve_rlim[RLIMIT_AS].rlim_max = lim_val;
				repeat_lim[HARDV] = 1;
			}
			break;
		case '?':
			PSEUDO_ERROR("VE_LIMIT_OPT: Unrecognized option");
			fprintf(stderr, "VE_LIMIT_OPT: Unrecognized option\n");
			goto out_err;
		case ':':
			PSEUDO_ERROR("VE_LIMIT_OPT: Missing option argument");
			fprintf(stderr, "VE_LIMIT_OPT: Missing option argument\n");
			goto out_err;
		}
	}
	/* For error checking, if any value is specified without any option */
	if (arg_v[optind]) {
		PSEUDO_ERROR("arg_v[optind] - [address]: %p, [value]: %s",
			arg_v[optind], arg_v[optind]);
		fprintf(stderr, "VE_LIMIT_OPT: invalid input\n");
		goto out_err;
	}
	/* To validate that hard limit should be greater than its soft limit */
	for (limit = 0; limit < RLIM_NLIMITS; limit++) {
		if (ve_rlim[limit].rlim_cur > ve_rlim[limit].rlim_max) {
			PSEUDO_DEBUG("lim: %d, soft lim: %llu, hard lim: %llu",
				limit,
				(unsigned long long)ve_rlim[limit].rlim_cur,
				(unsigned long long)ve_rlim[limit].rlim_max);
			PSEUDO_ERROR("Soft limit is greater than hard limit");
			fprintf(stderr, "VE_LIMIT_OPT: soft limit cannot exceed hard limit\n");
			goto out_err;
		}
		PSEUDO_DEBUG("limit: %d, soft lim: %llu, hard lim: %llu", limit,
				(unsigned long long)ve_rlim[limit].rlim_cur,
				(unsigned long long)ve_rlim[limit].rlim_max);
	}
	retval = 0;
	goto out;
out_err:
	retval = -1;
	PSEUDO_ERROR("Invalid input in VE_LIMIT_OPT");
out:
	arg_c--;
	while (arg_c >= 0) {
		free(arg_v[arg_c]);
		arg_c--;
	}
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Fetch the resource limit as set by VE_LIMIT_OPT environment or
* "ulimit" command, giving VE_LIMIT_OPT the higher priority.
* Function gets the resource limit as set by "ulimit" command for
* pseudo process. When pseudo process creates VE process, resource
* limit of pseudo process is copied for VE process. As VE process
* created from "ve_exec" command does not have a real parent.
*
* For VE process created from fork()/clone() syscall, resource
* limit is copied from parent VE process.
*
* @param ve_rlim resource limit
*/
void ve_get_rlimit(struct rlimit *ve_rlim)
{
	int resource = 0;
	char *endptr =  NULL;
	char *env_stack_limit = getenv("VE_STACK_LIMIT");
	uint64_t tmp_stack_limit = DEFAULT_STACK_LIMIT;
	int limit_opt_length = 0;
	int retval = 0;
	char *limit_opt = NULL;
	struct rlimit *limit = ve_rlim;

	PSEUDO_TRACE("Entering");
	while (resource < RLIM_NLIMITS) {
		switch (resource) {
		case RLIMIT_CPU:
		case RLIMIT_AS:
		case RLIMIT_CORE:
		case RLIMIT_DATA:
		case RLIMIT_SIGPENDING:
		case RLIMIT_RSS:
		case RLIMIT_FSIZE:
		case RLIMIT_LOCKS:
		case RLIMIT_MEMLOCK:
		case RLIMIT_MSGQUEUE:
		case RLIMIT_NOFILE:
		case RLIMIT_NPROC:
		case RLIMIT_RTTIME:
			getrlimit(resource, ve_rlim);
			break;
		case RLIMIT_STACK:
			if (NULL == env_stack_limit) {
				PSEUDO_INFO("Setting default stack limit as unlimited");
				/*Setting Default limit as unlimited */
			} else {
				tmp_stack_limit = strtol(env_stack_limit, &endptr, 10);
				if (0 == strcmp(env_stack_limit, "unlimited")){
					PSEUDO_INFO("STACK LIMIT IS SET TO UNLIMITED");
					tmp_stack_limit = DEFAULT_STACK_LIMIT;

				} else if (0 >= tmp_stack_limit || '\0' != *endptr) {
					/* Default stack unlimited */
					PSEUDO_INFO("Setting default stack limit as unlimited");
					tmp_stack_limit = DEFAULT_STACK_LIMIT;
				} else {
					PSEUDO_DEBUG("From env(VE_STACK_LIMIT): %ld KB",
							tmp_stack_limit);
					tmp_stack_limit = (tmp_stack_limit * (1024));
					struct rlimit lim = {
						tmp_stack_limit,
						tmp_stack_limit
					};
					memcpy(ve_rlim, &lim, sizeof(struct rlimit));
				}
			}
			break;
		default:
			break;
		}
	ve_rlim++;
	resource++;
	}
	ve_rlim = limit;
	/* Check for VE_LIMIT_OPT environment variable */
	limit_opt = getenv("VE_LIMIT_OPT");
	if (limit_opt) {
		limit_opt_length = strlen(limit_opt);
		char tmp[limit_opt_length+1];
		memcpy(tmp, limit_opt, limit_opt_length);
		tmp[limit_opt_length] = '\0';

		/* Parse the VE_LIMIT_OPT environment variable */
		retval = get_ve_limit_opt(tmp, ve_rlim);
		if (retval < 0) {
			PSEUDO_ERROR("VE_LIMIT_OPT parsing failed");
			fprintf(stderr, "ve process setup failed\n");
			pseudo_abort();
		}
	}
	PSEUDO_TRACE("Exiting");
}

/*@brief usage function to display ve_exec usage */
void usage(char *ve_exec_path)
{
	fprintf(stderr, "Usage: %s [OPTION] -d,--driver=<path> "
			"-s,--socket=<path> <binary> [arguments]\n"
			"Options\n"
			"  -c,--core=core		set core value\n"
			"  --cpunodebind=<NUMA node ID> NUMA node number on which"
							"VE process is to be"
							"executed\n"
			"  --localmembind	Memory policy is set MPOL_BIND\n"
			"  --show-limit         Display the applicable soft and hard\n"
						"resource limits of VE process supported\n"
						"by VE_LIMIT_OPT environment variable\n"
			"  -h,--help		Display help version information\n"
			"  -V,--version		Display ve_exec version information\n"
			"   --			End of options (Requires if binary name "
						"starts with ‘-’)\n",
			ve_exec_path);
}

/**
* @brief Creates shared memory region used as lhm/shm area
*
* @param[in] handle Pointer to handler structure for using library functions
* @param[out] node_id Provide the node_id on which this ve process will run
* @param[out] sfile_name randaomly generated file name with complete path
*
* @return fd on success, -1 on failure
*/
int init_lhm_shm_area(veos_handle *handle, int *node_id, char *sfile_name)
{
	int retval = -1, fd = -1;
	char *base_name = NULL, *dir_name = NULL;
	char *tmp_sock0 = NULL, *tmp_sock1 = NULL;
	char *shared_tmp_file = NULL;
	uint64_t shm_lhm_area = 0;

	PSEUDO_TRACE("Entering");

	tmp_sock0 = (char *)calloc(NAME_MAX+PATH_MAX, sizeof(char));
	if (NULL == tmp_sock0) {
		PSEUDO_DEBUG("failed to create buffer to store veos socket"
				" name");
		PSEUDO_ERROR("failed to create internal buffer");
		goto hndl_return;
	}

	tmp_sock1 = (char *)calloc(NAME_MAX+PATH_MAX, sizeof(char));
	if (NULL == tmp_sock1) {
		PSEUDO_DEBUG("failed to create buffer to store veos socket"
				" name");
		PSEUDO_ERROR("failed to create internal buffer");
		goto hndl_return;
	}

	shared_tmp_file = (char *)calloc(NAME_MAX+PATH_MAX, sizeof(char));
	if (NULL == shared_tmp_file) {
		PSEUDO_DEBUG("failed to create buffer to store shared file"
				" name");
		PSEUDO_ERROR("failed to create internal buffer");
		goto hndl_return;
	}

	strncpy(tmp_sock0, handle->veos_sock_name, NAME_MAX+PATH_MAX);
	strncpy(tmp_sock1, handle->veos_sock_name, NAME_MAX+PATH_MAX);

	base_name = basename(tmp_sock0);
	dir_name = dirname(tmp_sock1);

	/* get node number from veos socket file basename */
	*node_id = get_ve_node_num(base_name);

	sprintf(shared_tmp_file, "%s/veos%d-tmp/ve_exec_XXXXXX",
			dir_name, *node_id);

	PSEUDO_DEBUG("Shared file path: %s", shared_tmp_file);

	/* create a unique temporary file and opens it */
	fd =  mkstemp(shared_tmp_file);
	if (fd < 0) {
		PSEUDO_DEBUG("mkstemp fails: %s", strerror(errno));
		goto hndl_return;
	}

	/* truncate file to size PAGE_SIZE_4KB */
	retval = ftruncate(fd, PAGE_SIZE_4KB);
	if (-1 == retval) {
		PSEUDO_DEBUG("ftruncate fails: %s", strerror(errno));
		goto hndl_return;
	}

	/* map the file in shared mode */
	shm_lhm_area = (uint64_t)mmap(NULL, PAGE_SIZE_4KB,
			PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void *)-1 == (void *)(shm_lhm_area)) {
		PSEUDO_DEBUG("Failed to map file, return value %s",
				strerror(errno));
		retval = -1;
		goto hndl_return;
	}

	PSEUDO_DEBUG("shm_lhm_area: %lx", shm_lhm_area);
	memset((void *)shm_lhm_area, 0, PAGE_SIZE_4KB);
	vedl_set_shm_lhm_addr(handle->ve_handle, (void *)shm_lhm_area);

	strncpy(sfile_name, shared_tmp_file, NAME_MAX+PATH_MAX);
	PSEUDO_DEBUG("Unique syscall args filename: %s", sfile_name);
	retval = fd;
hndl_return:
	if (tmp_sock0)
		free(tmp_sock0);
	if (tmp_sock1)
		free(tmp_sock1);
	if (shared_tmp_file)
		free(shared_tmp_file);

	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief This function initiazes a lock which will be used to synchronize
* request related to DMA(reading data from VE memory) and creating new
* process(fork/vfork). Execution of both requests parallely leads to
* memory curruption.
*
* @return abort on failure.
*/
void init_rwlock_to_sync_dma_fork()
{
	int ret = -1;
	pthread_rwlockattr_t sync_fork_dma_attr;

	ret = pthread_rwlockattr_init(&sync_fork_dma_attr);
	if (ret) {
		PSEUDO_ERROR("Failed to initialize attribute %s",
				strerror(ret));
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	ret = pthread_rwlockattr_setkind_np(&sync_fork_dma_attr,
			PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	if (ret) {
		PSEUDO_ERROR("Failed to set rwlock attribute: %s",
				strerror(ret));
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	ret = pthread_rwlock_init(&sync_fork_dma, &sync_fork_dma_attr);
	if (ret) {
		PSEUDO_ERROR("Failed to init rwlock %s", strerror(ret));
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	ret = pthread_rwlockattr_destroy(&sync_fork_dma_attr);
	if (ret) {
		PSEUDO_ERROR("Failed to destroy rwlock attribute: %s",
				strerror(ret));
	}
}

/**
* @brief close the fd of syscall args file and remove the file.
*
* @param[in] fd, contains the fd of syscall args file.
* @param[in] sfile_name string contains the syscall args file path.
*/
void close_syscall_args_fille(int fd, char *sfile_name)
{
	PSEUDO_TRACE("Entering");

	close(fd);
	unlink(sfile_name);
	free(sfile_name);

	PSEUDO_TRACE("Exiting");
}
void get_ve_core_limit(veos_handle *handle)
{
	int num_of_core = 0, i = 0;
	unsigned long long affinity_mask = 0;
	char *affinity_mask_string = NULL;
	CPU_ZERO(&ve_affinity_mask);

	affinity_mask_string = getenv("VE_CORE_LIMIT");
	if (affinity_mask_string == NULL)
		return;
	errno = 0;
	affinity_mask =	strtoll(affinity_mask_string, NULL, 10);
	if (ERANGE == errno) {
		PSEUDO_ERROR("Error parsing VE_CORE_LIMIT env variable\n");
		fprintf(stderr, "Error parsing VE_CORE_LIMIT env variable\n");
		goto handl_error;
	}
	num_of_core = vedl_get_num_of_core(handle->ve_handle);
	if (0 > num_of_core) {
		PSEUDO_ERROR("failed to get number of VE cores");
		fprintf(stderr, "failed to get number of VE cores");
		goto handl_error;
	}
	for(i=0; affinity_mask > 0 ; i++) {
		if (i == num_of_core) {
			PSEUDO_ERROR("Core %d in VE_CORE_LIMIT "
							"doesn't exist\n", i);
			fprintf(stderr, "Core %d in VE_CORE_LIMIT "
							"doesn't exist\n", i);
			goto handl_error;
		}
		if (affinity_mask & 1) {
			CPU_SET(i, &ve_affinity_mask);
		}
		affinity_mask >>= 1;
	}
	return;
handl_error:
	/* FATAL ERROR: Exiting pseudo process */
	fprintf(stderr, "VE process setup failed\n");
	pseudo_abort();
}

void get_numa_node_from_affinity_mask(veos_handle *handle,
						int *numa_node, int core_id)
{
	char string[PATH_MAX] = {0};
	int i = 0, retval = -1, ve_numa_list = -1;
	char *ve_nama_list_string = NULL, *affinity_mask_string= NULL;
	int numa0_cores = 0, numa0_cores_count = 0;
	int numa1_cores = 0, numa1_cores_count = 0;
	int partitioning_mode = 0, numa0_set = 0, numa1_set = 0;

	ve_nama_list_string = getenv("_VENUMALIST");
	if (ve_nama_list_string != NULL) {
		errno = 0;
		ve_numa_list = strtoll(ve_nama_list_string, NULL, 10);
		if (ERANGE == errno) {
			PSEUDO_ERROR("Error: invalid numa node set "
							"by job scheduler\n");
			goto handl_error;
		}
	}
	retval = vedl_read_from_sysfs(handle->ve_handle,
					"partitioning_mode", string, PATH_MAX);
	if (retval) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		fprintf(stderr, "failed to get VE node partitioning mode");
		goto handl_error;
	}
	errno = 0;
	partitioning_mode = strtol(string, NULL, 0);
	if ((errno == ERANGE && (retval == LONG_MAX || retval == LONG_MIN))
			|| (errno != 0 && retval == 0)) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		fprintf(stderr, "failed to get VE node partitioning mode");
		goto handl_error;
	}
	/* verify that numa node from _VENUMALIST and VE_NUMA_OPT are in sync*/
	if (*numa_node != -1 && ve_numa_list != -1
			&& *numa_node != ve_numa_list) {
		PSEUDO_ERROR("invalid numa node number given\n");
		fprintf(stderr, "Error: numa node %d not allowed "
					"by job scheduler\n", *numa_node);
		goto handl_error;
	}
	if (partitioning_mode == 0)
		return;
	/* verify that core given as '-c' is allowed by VE_CORE_LIMIT
	 * and the job scheduler */
	affinity_mask_string = getenv("VE_CORE_LIMIT");
	if (affinity_mask_string != NULL && core_id != -1
			&& !CPU_ISSET(core_id, &ve_affinity_mask)) {
		fprintf(stderr, "Error: Core in '-c|--core' is not permitted "
					"by VE_CORE_LIMIT or job scheduler\n");
		goto handl_error;
	}
	/* verify that the affinity mask from VE_CORE_LIMIT or the job
	 * scheduler doesn't span across multiple numa nodes */
	memset(string, '\0', PATH_MAX);
	retval = vedl_read_from_sysfs(handle->ve_handle,
					"numa0_cores", string, PATH_MAX);
	if (retval) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		goto handl_error;
	}
	errno = 0;
	numa0_cores = strtol(string, NULL, 16);
	if ((errno == ERANGE && (retval == LONG_MAX || retval == LONG_MIN))
			|| (errno != 0 && retval == 0)) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		goto handl_error;
	}
	memset(string, '\0', PATH_MAX);
	retval = vedl_read_from_sysfs(handle->ve_handle,
					"numa1_cores", string, PATH_MAX);
	if (retval) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		goto handl_error;
	}
	errno = 0;
	numa1_cores = strtol(string, NULL, 16);
	if ((errno == ERANGE && (retval == LONG_MAX || retval == LONG_MIN))
			|| (errno != 0 && retval == 0)) {
		PSEUDO_ERROR("failed to get VE node partitioning mode");
		goto handl_error;
	}
	while(numa0_cores) {
		numa0_cores_count += numa0_cores & 1;
		numa0_cores >>= 1;
	}
	for (i = 0; i < numa0_cores_count; i++) {
		if (CPU_ISSET(i, &ve_affinity_mask)) {
			numa0_set = 1;
		}
	}
	while(numa1_cores) {
		numa1_cores_count += numa1_cores & 1;
		numa1_cores >>= 1;
	}
	for (; i < numa0_cores_count + numa1_cores_count; i++) {
		if (CPU_ISSET(i, &ve_affinity_mask)) {
			numa1_set = 1;
		}
	}
	if (numa0_set && numa1_set) {
		fprintf(stderr, "Error: VE_CORE_LIMIT has cores "
					"across different numa nodes\n");
		goto handl_error;
	} else if (numa0_set) {
		if(*numa_node == 1) {
			fprintf(stderr, "Error: invalid input for "
					"VE_CORE_LIMIT or numa node number\n");
			goto handl_error;
		}
		*numa_node = 0;
	}
	else if (numa1_set) {
		if(*numa_node == 0) {
			fprintf(stderr, "Error: invalid input for "
					"VE_CORE_LIMIT or numa node number\n");
			goto handl_error;
		}
		*numa_node = 1;
	}

	/* verify that core given as '-c' belongs to _VENUMALIST */
	if (ve_numa_list != -1) {
		if (*numa_node != -1 && *numa_node != ve_numa_list) {
			fprintf(stderr, "Error: invalid input for "
						"cpu mask or numa node number\n");
			goto handl_error;
		} else if (core_id != -1
			&& ((ve_numa_list == 0 && core_id >= numa0_cores_count)
			|| (ve_numa_list == 1 && core_id < numa0_cores_count))) {
			fprintf(stderr, "Error: core %d not allowed "
						"by job scheduler\n", core_id);
			goto handl_error;
		}
	}
	return;
handl_error:
	fprintf(stderr, "VE process setup failed\n");
	pseudo_abort();
}
/**
* @brief Main function of  pseudo process.
*	Function performs the following:
*	Reads command line arguments required for execution of pseudo process
*	and VE process.
*	Establishes communication with VEOS and AUSIM/FPGA.
*	Requests VEOS to create new VE process.
*	Initializes DMA ATB directory for  new VE process.
*	Request VEOS for loading the VE binary.
*	Initializes Stack for the VE process.
*	Requests VEOS to start the VE process.
*	Wait for exception occurring at VE core.
*
*
* @param[in] argc Number of command line arguments passed to the program.
* @param[in] argv[] Array of character pointers containing command line
*	arguments.
* @param envp[] Array of character pointer containing environment variables
*	and its values.
*
* @return Non-zero on FAILURE, 0 on SUCCESS.
*/
int main(int argc, char *argv[], char *envp[])
{
	int s = 0;
	int option_index = 0;
	int i = 0, retval = -1, vefd = 0;
	int ret = -1;
	char *file_name = NULL;
	char *sfile_name = NULL;
	char *exe_name = NULL;
	char *exe_base_name = NULL;
	char **ve_argv = NULL;
	int ve_argc = -1;
	int core_id = -1;
	int node_id = -1;
	char *endptr = NULL;
	int veos_sock_fd = 0;
	veos_handle *handle = NULL;
	struct sigaction pseudo_act = { {0} };
	sigset_t ve_signal_mask = { {0} };
	struct new_ve_proc ve_proc = {0};
	char *veos_sock_name = NULL;
	char exec_path[PATH_MAX] = {'\0'};
	char *sock_name = NULL;
	struct rlimit ve_rlim[RLIM_NLIMITS] = { {0} };
	void *ptrace_private = NULL;
	struct  ve_start_ve_req_cmd start_ve_req = { {0} };
	sigset_t set =  { {0} }, curr_ve_mask = { {0} };
	char *app_file_name = NULL;
	char log4c_file_path[NAME_MAX] = {0};
	char log4c_home_file_path[NAME_MAX] = {0};
	char log4c_curr_file_path[NAME_MAX] = {0};
	const struct log4c_appender_type *type;
	int numa_node = -1;
	int mem_policy = MPOL_DEFAULT;
	char *io_type = NULL;
	char *envp_sig = getenv("VE_SIGPROCMASK");
	long mask = 0;
	int signum = 0;

	/* Block all the signals till we successfully create VE process
	 * also store the previous mask, storing previous mask will
	 * make sense across exec() call*/
	sigemptyset(&curr_ve_mask);
	sigfillset(&ve_signal_mask);
	sigprocmask(SIG_BLOCK, &ve_signal_mask, &curr_ve_mask);

	/* Log4c appender initialization for pseudo core logs */
	app_pseudo_core = log4c_appender_get("ve_exec_appender");
	if (NULL == app_pseudo_core) {
		fprintf(stderr, "VE process setup failed, failure getting "
				"log4c appender\n");
		pseudo_abort();
	}

	/* fetch the log4c layout type */
	type = log4c_appender_get_type(app_pseudo_core);
	if (!type || strcmp(type->name, "stream")) {
		fprintf(stderr, "VE process setup failed,"
				" log4c configuration file error\n");
		pseudo_abort();
	}

	/* fetching the log4c file */
	snprintf(log4c_file_path, sizeof(log4c_file_path) - 1, "%s/log4crc",
			getenv("LOG4C_RCPATH"));

	snprintf(log4c_home_file_path, sizeof(log4c_home_file_path) - 1,
			"%s/.log4crc", getenv("HOME"));

	snprintf(log4c_curr_file_path, sizeof(log4c_curr_file_path) - 1,
			"%s/log4crc", getenv("PWD"));

	/* Create file only when configuration file is present
	 * && also log path is valid */
	if ((!access(log4c_file_path, F_OK) || !access(log4c_home_file_path, F_OK)
				|| !access(log4c_curr_file_path , F_OK))) {
		/* allocate memory to store log file name */
		app_file_name = (char *)malloc(NAME_MAX * sizeof(char));
		if (NULL == app_file_name) {
			fprintf(stderr, "VE process setup failed, memory allocation "
					"for log file name failed\n");
			pseudo_abort();
		}
		memset(app_file_name, '\0', NAME_MAX * sizeof(char));

		/* create a name for log file */
		sprintf(app_file_name, "ve_exec.log.%d", getpid());

		/* open a log file to print logs */
		pseudo_fp = fopen(app_file_name, "a+");
		if (NULL == pseudo_fp)
			pseudo_fp = stderr;

		/* unbuffered mode */
		setbuf(pseudo_fp, NULL);

		/* Replace the default appender data with the user data,
		 * This api returns the previous user data. If there is
		 * no previous user data then it returns NULL, which is
		 * not an error */
		log4c_appender_set_udata(app_pseudo_core, pseudo_fp);

		/* free the memory created for file name as it is no more required */
		free(app_file_name);
	}

	/* Log4c initialization */
	/* If using explicit initialization (as opposed to implicit via the
	 * init phase of the library) it's important to initialize the custom
	 * appenders and layouts before calling log4c_init().
	 */
	if (log4c_init()) {
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* Log4c category initialization for pseudo core logs */
	cat_pseudo_core = log4c_category_get("veos.pseudo_process.core");
	if (NULL == cat_pseudo_core) {
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* Log4c category initialization for pseudo ived logs */
	if (pseudo_ived_log4c_init()) {
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* Configure if atomic io is enabled/disabled */
	if((io_type = getenv("VE_ATOMIC_IO")))
		ve_atomic_io = atoi(io_type);
	if(ve_atomic_io)
		PSEUDO_DEBUG("PSEUDO-ATOMIC-IO-MODE-ENABLED");
	else
		PSEUDO_DEBUG("PSEUDO-ATOMIC-IO-MODE-DISABLED");

	/* Copy arguments for ve program */
	if ((argc * sizeof(char*)) > UINT_MAX) {
		PSEUDO_ERROR("To many command line arguments");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	ve_argv = (char **)malloc(argc * sizeof(char *));
	if (NULL == ve_argv) {
		PSEUDO_DEBUG("failed to create buffer to copy arguments"
				" of VE program");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	memset(ve_argv, 0x00, argc * sizeof(char *));
	/* Default initialization of "ve_trace_me" flag */
	ve_trace_me = false;

	/* Parse argumets */
	exe_name = (char *)malloc((NAME_MAX + PATH_MAX) * sizeof(char));
	if (NULL == exe_name) {
		PSEUDO_DEBUG("failed to create buffer to store Executable"
				" name");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	sock_name = (char *)malloc((NAME_MAX + PATH_MAX) * sizeof(char));
	if (NULL == sock_name) {
		PSEUDO_DEBUG("failed to create buffer to store socket"
				" name");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	veos_sock_name = (char *)malloc((NAME_MAX+PATH_MAX)*sizeof(char));
	if (NULL == veos_sock_name) {
		PSEUDO_DEBUG("failed to create buffer to store veos socket"
					" name");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	sfile_name = (char *)malloc((NAME_MAX+PATH_MAX)*sizeof(char));
	if (NULL == sfile_name) {
		PSEUDO_DEBUG("failed to create buffer for syscall args"
					" file");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/*MEMSET */
	memset(exe_name, '\0', (NAME_MAX + PATH_MAX) * sizeof(char));
	memset(sock_name, '\0', (NAME_MAX + PATH_MAX) * sizeof(char));
	memset(veos_sock_name, '\0', (NAME_MAX + PATH_MAX) * sizeof(char));
	memset(sfile_name, '\0', (NAME_MAX + PATH_MAX) * sizeof(char));
	static struct option long_options[] = {
		{"driver", required_argument, NULL, 'd'},
		{"socket", required_argument, NULL, 's'},
		{"core", optional_argument, NULL, 'c'},
		{"dump", optional_argument, NULL, 0},
		{"localmembind", optional_argument, NULL, 0},
		{"cpunodebind", optional_argument, NULL, 0},
		{"traceme", no_argument, 0, 0},
		{"version", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};
	while (1) {
		s = getopt_long(argc, argv, "+Vhd:s:c:", long_options,
				&option_index);
		if (s == -1)
			break;
		switch (s) {
			case 'd':
				snprintf(sock_name, NAME_MAX + PATH_MAX,
						"%s", optarg);
				PSEUDO_DEBUG("OPTARG:%s SOCK NAME:%s\n",
						optarg, sock_name);
				break;
			case 's':
				snprintf(veos_sock_name, NAME_MAX+PATH_MAX,
						"%s", optarg);
				PSEUDO_DEBUG("OPTARG:%s SOCK NAME:%s\n",
						optarg, veos_sock_name);
				break;
			case 'c':
				core_id = strtol(optarg, &endptr, 0);
				if (optarg == endptr) {
					fprintf(stderr, "invalid core ID");
				}
				break;
			case 0:
				if (strcmp("traceme",
					long_options[option_index].name) == 0) {
					ve_trace_me = true;
					PSEUDO_TRACE("traceme\n");
				}
				if (strcmp("localmembind",
					long_options[option_index].name) == 0) {
					mem_policy = MPOL_BIND;
				}
				if (strcmp("cpunodebind",
					long_options[option_index].name) == 0) {
					numa_node = strtol(optarg, &endptr, 0);
					if (optarg == endptr) {
						fprintf(stderr,
							"invalid numa node ID");
					}
				}
				break;
			case 'h':
				usage(argv[0]);
				exit(0);
			case 'V':
				PSEUDO_INFO("%s (%s) %s\n",
						PROGRAM_NAME, PACKAGE,
						PACKAGE_VERSION);
				fprintf(stderr, "%s (%s) %s\n",
					PROGRAM_NAME, PACKAGE, PACKAGE_VERSION);
				exit(0);
			default:
				usage(argv[0]);
				PSEUDO_ERROR("Invalid command line argument received");
				fprintf(stderr, "Invalid command line argument\n");
				pseudo_abort();
		}
	}

	if (optind < argc) {
		snprintf(exe_name, NAME_MAX + PATH_MAX, "%s", argv[optind]);
		optind++;
		for (i = 0, ve_argc = 1; optind < argc; i++, optind++) {
			if (((strlen(argv[optind]) + 1) * sizeof(char)) > UINT_MAX) {
				PSEUDO_ERROR("input string is too long\n");
				fprintf(stderr, "VE process setup failed\n");
				pseudo_abort();
			}

			ve_argv[ve_argc] =
				(char *)malloc((strlen(argv[optind]) + 1)
					* sizeof(char));
			if (ve_argv[ve_argc] == NULL) {
				PSEUDO_ERROR("failed to create internal buffer");
				fprintf(stderr, "VE process setup failed\n");
				pseudo_abort();
			}
			/*MEMSET*/
			memset(ve_argv[ve_argc], '\0', (strlen(argv[optind]) + 1) * sizeof(char));
			memcpy(ve_argv[ve_argc], argv[optind],
					strlen(argv[optind]) + 1);
			ve_argc++;
		}
	}

	if (exe_name[0] == '\0' ||
			sock_name[0] == '\0' ||
			veos_sock_name[0] == '\0') {
		usage(argv[0]);
		exit(1);
	}

	ve_argv[0] = (char *)malloc((strlen(exe_name) + 1) *
				sizeof(char));
	if (NULL == ve_argv[0]) {
		PSEUDO_DEBUG("Failed to create buffer to copy VE"
				" executable name");
		PSEUDO_ERROR("failed to create internal buffer");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	/*MEMSET*/
	memset( ve_argv[0], '\0', (strlen(exe_name) + 1) * sizeof(char));
	memcpy(ve_argv[0], exe_name, strlen(exe_name) + 1);
	for (i = 0; i < ve_argc; i++)
		PSEUDO_DEBUG("ve_argv[%d] = %s\n", i, ve_argv[i]);

	/* Reserve the chunk in pseudo for maintaining private information
	 * regarding the attaching/detaching.
	 */
	ptrace_private = mmap((void *)PTRACE_PRIVATE_DATA, 4096,
			PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED,
			-1, 0);
	if (MAP_FAILED == ptrace_private) {
		PSEUDO_DEBUG("Fail to alloc chunk for ptrace private: %s",
				strerror(errno));
		PSEUDO_ERROR("Failled to allocate ptrace related data");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	if (ve_init_vemmr()) {
		PSEUDO_ERROR("Failled to initialize VE memory manegement region");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* Check if the request address is obtained or not */
	if (ptrace_private != (void *)PTRACE_PRIVATE_DATA) {
		PSEUDO_DEBUG("Request: %lx but got: %p for ptrace data.",
				PTRACE_PRIVATE_DATA, ptrace_private);
		PSEUDO_ERROR("Failled to allocate ptrace related data");
		fprintf(stderr, "VE process setup failed\n");
		munmap(ptrace_private, 4096);
		pseudo_abort();
	}

	/* Obtain ve driver fd which was maintained earlier in
	 * VE task struct during the processing of ve_execve()
	 * system call.
	 *
	 * If it is VE execed process a valid fd is returned,
	 * otherwise -1 will be returned from veos.
	 */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		PSEUDO_ERROR("socket creation failed.");
		fprintf(stderr, "socket creation failed\n");
		pseudo_abort();
	}

	retval = pseudo_psm_send_vefd_req(veos_sock_fd);
	if (-1 == retval) {
		PSEUDO_ERROR("VEOS request error");
		PSEUDO_DEBUG("Failed to send PSEUDO VEFD REQ to PSM, retval:"
				" %d", retval);
	} else {
		/* Waiting for ACK from PSM */
		/* return already opned ve_driver fd */
		retval = pseudo_psm_recv_vefd_ack(veos_sock_fd);
		if (-2 == retval) {
			PSEUDO_ERROR("VEOS acknowledgement error");
			PSEUDO_DEBUG("Failed in receiving VEFD ACK, retval: %d",
					retval);
			fprintf(stderr, "connection lost\n");
			close(veos_sock_fd);
			pseudo_abort();
		} else if (retval == 0) {
			PSEUDO_ERROR("Duplicate process with PID %d already exists at VEOS.", getpid());
			fprintf(stderr, "VE process setup failed as pid duplication detected\n");
			pseudo_abort();
		}
	}

	vefd = retval;
	PSEUDO_DEBUG("vefd is %d", vefd);
	close(veos_sock_fd);

	/* Acquire The VE handler */
	handle = veos_handle_create(sock_name, veos_sock_name, NULL, vefd);
	if (handle == NULL) {
		PSEUDO_ERROR("failed to acquire VE handler");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	g_handle = handle; /* update global handle */

	free(sock_name);
	free(veos_sock_name);

	/* Update global tid array for main thread with vefd */
	global_tid_info[0].vefd = vedl_get_fd(g_handle->ve_handle);
	global_tid_info[0].veos_hndl = g_handle;
	tid_counter=0;
	global_tid_info[0].tid_val = getpid();
	global_tid_info[0].flag = 0;
	global_tid_info[0].mutex =
		(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	global_tid_info[0].cond =
		(pthread_cond_t)PTHREAD_COND_INITIALIZER;

	init_rwlock_to_sync_dma_fork();

	PSEUDO_DEBUG("TID struct vefd : %d, VE driver fd %d",
			global_tid_info[0].vefd,
			vedl_get_fd(g_handle->ve_handle));

	/* Get the basename of the VE executable */
	exe_base_name = basename(exe_name);

	/* Get rlimit of pseudo process set from bash "ulimit" command
	 * and check for VE_LIMIT_OPT environment variable */
	memset(ve_rlim, -1, sizeof(ve_rlim));
	ve_get_rlimit(ve_rlim);

	/* Get the path of ve_exec */
	if(NULL == getcwd(exec_path, PATH_MAX)) { /* Trac# 383 */
		PSEUDO_ERROR("failed to get ve_exec path.");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	ret = init_lhm_shm_area(handle, &node_id, sfile_name);
	if (ret < 0) {
		PSEUDO_ERROR("failed to create temporary file");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* get cpu affinity mask as set by the job scheduler
	 * from VE_CORE_LIMIT */
	get_ve_core_limit(handle);
	get_numa_node_from_affinity_mask(handle, &numa_node, core_id);

	ve_proc.namespace_pid = syscall(SYS_gettid);
	ve_proc.shm_lhm_addr = (uint64_t)vedl_get_shm_lhm_addr(handle->ve_handle);
	ve_proc.core_id = core_id;
	ve_proc.node_id = node_id;
	ve_proc.traced_proc = ve_trace_me;
	ve_proc.tracer_pid = getppid();
	ve_proc.exec_path = (uint64_t)&exec_path[0];
	ve_proc.numa_node = numa_node;
	ve_proc.mem_policy = mem_policy;
	ve_proc.real_parent_pid = getppid();

	file_name = basename(sfile_name);
	memset(&(ve_proc.exe_name), '\0', ACCT_COMM);
	strncpy(ve_proc.exe_name, exe_base_name, ACCT_COMM-1);
	memcpy(ve_proc.lim, ve_rlim, sizeof(ve_rlim));
	memcpy(ve_proc.sfile_name, file_name, strlen(file_name)+1);

	/* Request to veos to create new VE process.
	 * veos also create VE process task structure on VE driver
	 * by invoking VEDL interface vedl_create_ve_task()
	 * */
	retval = pseudo_psm_send_new_ve_process(handle->veos_sock_fd, ve_proc);
	if (0 > retval) {
		PSEUDO_ERROR("VEOS request error");
		PSEUDO_DEBUG("Failed to send NEW VE PROC request to veos,"
				"return value %d", retval);
		close_syscall_args_fille(ret, sfile_name );
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	retval = pseudo_psm_recv_load_binary_req(handle->veos_sock_fd,
						&core_id, &node_id, &numa_node);
	if (0 > retval) {
		PSEUDO_ERROR("VEOS acknowledgement error");
		if (-EINVAL == retval) {
			if (core_id != -1) {
				PSEUDO_ERROR("ERROR: Core '%d' "
					"doesn't exist", core_id);
				fprintf(stderr, "ERROR: Core '%d' "
					"doesn't exist\n", core_id);
			} else {
				PSEUDO_ERROR("ERROR: Numa node '%d' "
					"doesn't exist", numa_node);
				fprintf(stderr,
					"ERROR: Numa node"
					" argument out of range\n");
			}
			veos_handle_free(handle);
			close_syscall_args_fille(ret, sfile_name );
			exit(EXIT_FAILURE);
		}
		PSEUDO_DEBUG("Failed to create VE process, return "
				"value %d", retval);
		fprintf(stderr, "VE process setup failed\n");
		close_syscall_args_fille(ret, sfile_name );
		pseudo_abort();
	}

	PSEUDO_DEBUG("CORE ID : %d\t NODE ID : %d NUMA NODE ID : %d",
			core_id, node_id, numa_node);

	if (ve_init_rvr(handle, VEMMR_START)) {
		PSEUDO_ERROR("Failed to map RVR");
		fprintf(stderr, "Failed to map RVR");
		pseudo_abort();
	}

	/* close the fd of syscall args file and remove the file */
	close_syscall_args_fille(ret, sfile_name );

	/* Set offset to zero just in case */
	vedl_set_syscall_area_offset(handle->ve_handle, 0);

	INIT_LIST_HEAD(&vemva_header.vemva_list);

	/*This task_should be done at VE Task init*/
	retval = init_vemva_header();
	if (retval) {
		PSEUDO_ERROR("failed to initialise mutex lock");
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	char *affinity_mask_string = NULL;

	affinity_mask_string = getenv("VE_CORE_LIMIT");
	if (affinity_mask_string == NULL)
		goto skip_cpu_mask_request;

	retval = pseudo_psm_send_cpu_mask(handle->veos_sock_fd, ve_affinity_mask);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("failed to send set cpu mask request, %d",	retval);
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_cpu_mask_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("Failed to receive SET_CPU_MASK "
				"acknowledgement: %d", retval);
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
skip_cpu_mask_request:
	/* load binary file */
	/* Memory Manager updates ATB & DMAATB entry */
	ret = pse_load_binary(exe_name, handle, &start_ve_req);
	if (ret) {
		PSEUDO_ERROR("Failed to load executable");
		fprintf(stderr, "Failed to load executable\n");
		process_thread_cleanup(handle, -1);
		pseudo_abort();
	}

	free(exe_name);
	exe_name = NULL;

	PSEUDO_DEBUG("LOADING SEGMENTS IS END.");
	ret = reserve_signal_trampoline(handle);
	if (ret) {
		PSEUDO_ERROR("Failed to reserve trampoline");
		fprintf(stderr, "Failed to reserve trampoline\n");
		process_thread_cleanup(handle, -1);
		pseudo_abort();
	}
	PSEUDO_DEBUG("RESERVED TRAMPOLINE");

	/* init stack */
	ret = init_stack(handle, ve_argc, ve_argv,
			envp, &start_ve_req);
	if (ret) {
		PSEUDO_ERROR("failed to make stack region");
		fprintf(stderr, "VE process setup failed\n");
		process_thread_cleanup(handle, -1);
		/* Unblock SIGSEGV signal */
		sigemptyset(&set);
		sigaddset(&set, SIGSEGV);
		sigprocmask(SIG_UNBLOCK, &set, NULL);
		kill(getpid(), SIGSEGV);
	}
	memcpy(&start_ve_req.ve_info, &ve_info,
		sizeof(struct ve_address_space_info_cmd));

	PSEUDO_DEBUG("MAKING A STACK IS END.");

	/* If the environment variable is set to VE_SIGPROCMASK,
	 * check the bits to add the corresponding signal to the signal mask.
	 */
	if (envp_sig) {
		mask = strtol(envp_sig, &endptr, 0);
		PSEUDO_DEBUG("mask value:%ld\n", mask);
		if (mask > 0 && *endptr == '\0') {
			sigemptyset(&curr_ve_mask);
			for (signum = 0; mask > 0 && signum < 32 ; signum++) {
				if ( mask % 2  == 1 && signum != 0) {
					sigaddset(&curr_ve_mask, signum);
					PSEUDO_DEBUG("sigaddset signal:%d", signum);
				}
			mask = mask / 2;
			}
		}
		unsetenv(envp_sig);
	}

	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	retval = pseudo_psm_send_signal_mask(handle->veos_sock_fd, curr_ve_mask);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("failed to send set signal mask request, %d", retval);
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}
	/* Waiting for ACK from PSM */
	retval = pseudo_psm_recv_signal_mask_ack(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("Failed to receive SIGNAL_MASK_REQ "
				"acknowledgement: %d", retval);
		fprintf(stderr, "VE process setup failed\n");
		pseudo_abort();
	}

	/* free ve_argv */
	for (i = 0; i < ve_argc; i++)
		free(ve_argv[i]);

	free(ve_argv);

	retval = pseudo_psm_send_start_ve_proc_req(&start_ve_req,
			handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("failed to send start VE process request, %d",
				retval);
		/* FATAL ERROR: Exiting pseudo process */
		fprintf(stderr, "ve process setup failed\n");
		pseudo_abort();
	} else {
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_start_ve_proc(handle->veos_sock_fd);
		if (0 > retval) {
			PSEUDO_ERROR("veos acknowledgement error");
			PSEUDO_DEBUG("Failed to receive START VE PROC "
					"acknowledgement: %d", retval);
			/* FATAL ERROR: Exiting pseudo process */
			fprintf(stderr, "VE process setup failed\n");
			pseudo_abort();
		}
	}

	/* Register signal handlers for all the signals from 1 to NSIG */
	for (i = 1; i < _NSIG; i++) {
		if (SPECIAL_SIGNAL(i)) {
			PSEUDO_DEBUG("Registering dummy signal handler"
					" skipped for signal %d", i);
			continue;
		}
		memset(&pseudo_act, '\0', sizeof(pseudo_act));
		pseudo_act.sa_sigaction = &ve_sa_sigaction_handler;
		pseudo_act.sa_flags = SA_SIGINFO;
		retval = sigaction(i, &pseudo_act, NULL);
		if (-1 == retval) {
			PSEUDO_ERROR("Sigaction for signal %d failed", i);
			fprintf(stderr, "VE process setup failed\n");
			process_thread_cleanup(handle, -1);
			pseudo_abort();
		} else {
			PSEUDO_DEBUG("Sigaction sucessfull for signal %d", i);
		}
	}

	/* If --traceme option is provided */
	if (ve_trace_me == true) {
		ret = pseudo_handle_traceme(handle);
		if (-1 == ret) {
			PSEUDO_ERROR("failed to handles the ve process ptrace"
					" traceme request.");
			fprintf(stderr, "failed to handles the ve process"
				" ptrace traceme request\n");
			process_thread_cleanup(handle, -1);
			pseudo_abort();
		}
	}
	memcpy(&ve_proc_sigmask, &curr_ve_mask, sizeof(sigset_t));

	/* start VE program and wait for exception */
	pse_exception_handler(handle, NULL);

	return 0;
}
