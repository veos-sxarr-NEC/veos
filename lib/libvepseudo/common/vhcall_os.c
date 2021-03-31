/*
 * Copyright (C) 2017-2019 NEC Corporation
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
 * @file vhcall_os.c
 * @brief sysve() handlers regarding VH call
 */

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <libved.h>
#include "mm_transfer.h"
#include <vhcall.h>
#include "vhcall_os.h"
#include "velayout.h"


#define SH_PATH      "/bin/sh"		/* Shell Path */
#define SHELL        "sh"		/* Shell Name */

/**
 * @brief Type of a function called by VH call on VH
 *
 * @param[in] handle VEOS handle
 * @param[in] inptr input buffer.
 * @param insize size of input buffer
 * @param[out] outptr output buffer
 * @param outsize size of output buffer
 *
 * @return return value. If negative, treated as -errno on VE side.
 */
typedef long vhcall_func(veos_handle *handle, const void *inptr, size_t insize,
			 void *outptr, size_t outsize);

/**
 * @brief Handler of VHCALL_INSTALL: load a dynamic library
 *
 * @param[in] handle VEOS handle
 * @param[in] filename The file name of a dynamic library, searched as dlopen().
 *
 * @return VH call handle of the library.
 *         A value between -4095 to -1 is treated as -errno on VE side.
 */
vhcall_handle sys_vhcall_install(veos_handle *handle, uintptr_t filename)
{
	intptr_t retval;
	char *pathbuf;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "called\n");
	pathbuf = malloc(PATH_MAX);
	if (NULL == pathbuf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed: %s\n", strerror(errno));
		return -errno;
	}
	memset(pathbuf, 0, PATH_MAX);
	retval = ve_recv_string(handle, filename, pathbuf, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string returned %d\n", (int)retval);
		retval = -EFAULT;
		goto err_return;
	}
	retval = (intptr_t)dlopen(pathbuf, RTLD_LAZY|RTLD_GLOBAL);
	if (0 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"dlopen() failed: %s\n", dlerror());
		retval = -ENOENT;
	}
err_return:
	free(pathbuf);
	return retval;
}

/**
 * @brief Handler of VHCALL_FIND: find a function in a VH library
 *
 * @param[in] handle VEOS handle
 * @param vh VH call handle returned by VHCALL_INSTALL
 * @param[in] sym The name of a function in a VH library
 *
 * @return Symbol ID of the function specified by sym.
 *         A value between -4095 to -1 is treated as -errno on VE side.
 */
int64_t sys_vhcall_find(veos_handle *handle, vhcall_handle vh, uintptr_t sym)
{
	intptr_t retval;
	char *symbuf;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "called\n");
	symbuf = malloc(VHCALL_SYMNAME_MAX);
	if (NULL == symbuf) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc failed: %s\n", strerror(errno));
		return -errno;
	}
	memset(symbuf, 0, VHCALL_SYMNAME_MAX);
	retval = ve_recv_string(handle, sym, symbuf, VHCALL_SYMNAME_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string returned %d\n", (int)retval);
		retval = -EFAULT;
		goto err_return;
	}
	retval = (intptr_t)dlsym((void *)vh, symbuf);
	if (0 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"dlsym(%s) failed: %s\n", symbuf, dlerror());
		retval = -EINVAL;
	}
err_return:
	free(symbuf);
	return retval;
}

/**
 * @brief Invoke function with passing arguments.
 *
 * @param[in] func function pointer
 * @param int_reg arguments passed by general registers
 * @param[in] stack_img stack image copied to local stack area
 * @param stack_cnt number of 8-byte data in stack_img
 * @param sse_reg arguments passed by floating point registers
 * @param[out] retval pointer to buffer storing return value of function
 */
void sys_vhcall_invoke_func(uint64_t *func, uint64_t int_reg[],
                                uint64_t *stack_img, uint64_t stack_cnt,
                                uint64_t sse_reg[], uint64_t *retval)
{
        /* For allocation local stack area. */
        uint64_t dummy_area[stack_cnt];
        memcpy(dummy_area, stack_img, stack_cnt*sizeof(uint64_t));
        asm volatile(
                "movsd %15, %%xmm7\n\t"
                "movsd %14, %%xmm6\n\t"
                "movsd %13, %%xmm5\n\t"
                "movsd %12, %%xmm4\n\t"
                "movsd %11, %%xmm3\n\t"
                "movsd %10, %%xmm2\n\t"
                "movsd %9,  %%xmm1\n\t"
                "movsd %8,  %%xmm0\n\t"
                "mov   %7,  %%r9\n\t"
                "mov   %6,  %%r8\n\t"
                "mov   %5,  %%rcx\n\t"
                "mov   %4,  %%rdx\n\t"
                "mov   %3,  %%rsi\n\t"
                "mov   %2,  %%rdi\n\t"
                "mov   %1,  %%rax\n\t"
                "callq *%%rax\n\t"
                "mov %%rax, %0\n\t"
                :"=m"(*retval):"m"(func), \
                "m"(int_reg[0]), "m"(int_reg[1]), "m"(int_reg[2]), \
		"m"(int_reg[3]), "m"(int_reg[4]), "m"(int_reg[5]), \
                "m"(sse_reg[0]), "m"(sse_reg[1]), "m"(sse_reg[2]), \
		"m"(sse_reg[3]), "m"(sse_reg[4]), "m"(sse_reg[5]), \
		"m"(sse_reg[6]), "m"(sse_reg[7]) \
                :"cc", "memory", "rax", \
		"rcx", "rdx", "rsi", "rdi", "r8", "r9", \
                "xmm0", "xmm1", "xmm2", "xmm3", \
		"xmm4", "xmm5", "xmm6", "xmm7"
        );
}

/**
 * @param Set value to register image or stack image
 *
 * @param[out] reg pointer to register image set value to
 * @param[inout] cnt counter of registers which has already been set value to
 * @param REG_MAX number of registers
 * @param[out] stack_img pointer to stack image set value to
 * @param[inout] s_cnt counter of 8-byte data which has already been set to stack
 * @param val value to be set to register or stack
 */
static void sys_vhcall_set_value(uint64_t reg[], int *cnt, const int REG_MAX,
		uint64_t *stack_img, uint64_t *s_cnt, uint64_t val)
{
	if (*cnt < REG_MAX) {
		memcpy(reg + *cnt, &val, sizeof(uint64_t));
		*cnt += 1;
	} else {
		memcpy(stack_img + *s_cnt, &val, sizeof(uint64_t));
		*s_cnt += 1;
	}
}

/**
 * @brief Handler of VHCALL_INVOKE_WITH_ARGS: invoke a function on VH side
 * with passing arguments
 *
 * @param[in] handle VEOS handle
 * @param symid symbol ID of the function to call
 * @param[in] inptr input buffer on VE side
 *            If inptr is not NULL, data is copied in to VH.
 * @param insize size of input buffer
 * @param retvalptr Address of VE buffer to be stored return value of
 *        VH function to
 *
 * @return 0 upon success, negative upon failure
 */
int sys_vhcall_invoke_with_args(veos_handle *handle, int64_t symid,
		uintptr_t inptr, size_t insize, uintptr_t retvalptr)
{
	int ret = -EINVAL;
        uint64_t *func;
	uint64_t retval;
        long xfer_status;
        void *inbuf = NULL;
	int num_args = 0;
	int i;
	vhcall_data *p;
        int int_cnt = 0;
        uint64_t int_reg[VHCALL_MAX_INTREG] = { 0 };
        int sse_cnt = 0;
        uint64_t sse_reg[VHCALL_MAX_SSEREG] = { 0 };
	uint64_t stack_cnt = 0;
        uint64_t *stack_img = NULL;
        void **data_img = NULL;

        VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "called\n");
        /* allocate buffer and check argument*/
        if (inptr != 0L && insize != 0) {
                inbuf = malloc(insize);
                if (NULL == inbuf) {
			ret = -errno;
                        VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
                                        "malloc failed: %s\n",
					strerror(errno));
                        goto err_alloc_inbuf;
                }

		num_args = (size_t)(insize / sizeof(vhcall_data));
                if (num_args*sizeof(vhcall_data) != insize) {
                        VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
                                        "input size:%zd is invalid for number of arguments:%d\n",
                                        insize, num_args);
                        ret = -EINVAL;
                        goto err_copyin;
                }
        }

        /* copy in */
        if (inbuf != NULL) {
                xfer_status = ve_recv_data(handle, inptr, insize, inbuf);
                if (xfer_status < 0) {
                        VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
                                        "ve_recv_data returned %ld\n",
                                        xfer_status);
                        ret = -EFAULT;
                        goto err_copyin;
                }
        }

	if (num_args > 0) {
		stack_img = calloc(1, num_args*sizeof(uint64_t));
		if (stack_img == NULL) {
			ret = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"calloc failed: %s\n", strerror(errno));
			goto err_copyin;
		}

		data_img = calloc(1, num_args*sizeof(uint64_t));
		if (data_img == NULL ) {
			ret = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"calloc failed: %s\n", strerror(errno));
			goto err_alloc_data_img;
		}
	}

	for (i=0; i<num_args; i++) {
		p = (vhcall_data *)((char *)inbuf + i*sizeof(vhcall_data));
		switch (p->cl) {
		case (VHCALL_CLASS_INT):
			sys_vhcall_set_value(
				int_reg, &int_cnt, VHCALL_MAX_INTREG,
				stack_img, &stack_cnt, p->val[0]);
			break;
		case (VHCALL_CLASS_DBL):
			sys_vhcall_set_value(
				sse_reg, &sse_cnt, VHCALL_MAX_SSEREG,
				stack_img, &stack_cnt, p->val[0]);
			break;
		case (VHCALL_CLASS_HDL):
			sys_vhcall_set_value(
				int_reg, &int_cnt, VHCALL_MAX_INTREG,
				stack_img, &stack_cnt, (uint64_t)handle);
			break;
		case (VHCALL_CLASS_PTR):
			if (p->size > 0) {
				data_img[i] = malloc(p->size);
				if (data_img[i] == NULL) {
					ret = -errno;
					VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"malloc failed: %s\n",
						strerror(errno));
					goto err_alloc_stack_img;
				}
			}

			if (p->size > 0 && p->inout != VHCALL_INTENT_OUT) {
				xfer_status = ve_recv_data(handle, p->val[0],
							p->size, data_img[i]);
				if (xfer_status < 0) {
					VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"ve_recv_data returned %ld\n",
						xfer_status);
					ret = -EFAULT;
					goto err_alloc_stack_img;
				}
			}

			sys_vhcall_set_value(
				int_reg, &int_cnt, VHCALL_MAX_INTREG,
				stack_img, &stack_cnt, (uint64_t)data_img[i]);
			break;
		default:
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"invalid argument of vhcall\n");
			ret = -EINVAL;
			goto err_alloc_stack_img;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"vhcall invoke func(symid:%lu) with args \n", symid);

        func = (uint64_t *)symid;
        sys_vhcall_invoke_func(func, int_reg, stack_img,
				stack_cnt, sse_reg, &retval);

        /* copy out */
	for (i=0; i<num_args; i++) {
		p = (vhcall_data *)((char *)inbuf + i*sizeof(vhcall_data));
		if (p->cl == VHCALL_CLASS_PTR && p->size > 0 &&
				p->inout != VHCALL_INTENT_IN) {
			xfer_status = ve_send_data(handle, p->val[0], p->size,
						data_img[i]);
			if (xfer_status < 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"ve_send_data returned %ld\n",
						xfer_status);
				ret = -EFAULT;
				goto err_alloc_stack_img;
			}
		}
	}
        if (retvalptr != 0L) {
                xfer_status = ve_send_data(handle, retvalptr, sizeof(uint64_t),
						&retval);
                if (xfer_status < 0) {
                        VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
                                        "ve_send_data returned %ld\n",
                                        xfer_status);
                        ret = -EFAULT;
			goto err_alloc_stack_img;
                }
        }

	ret = 0;
err_alloc_stack_img:
	for (i=0; i<num_args; i++)
		free(data_img[i]);
	free(data_img);
err_alloc_data_img:
	free(stack_img);
err_copyin:
        free(inbuf);
err_alloc_inbuf:
        return ret;
}

/**
 * @brief Handler of VHCALL_INVOKE: invoke a function on VH side
 *
 * @param[in] handle VEOS handle
 * @param symid symbol ID of the function to call
 * @param[in] inptr input buffer on VE side
 *                  If inptr is not NULL, data is copied in to VH.
 * @param insize size of input buffer
 * @param[out] outptr output buffer on VE side
 *                    If outptr is not NULL, data is copied out from VH.
 * @param outsize sizeof output buffer
 *
 * @return A return value of the function specified by symid
 */
long sys_vhcall_invoke(veos_handle *handle, int64_t symid, uintptr_t inptr,
		       size_t insize, uintptr_t outptr, size_t outsize)
{
	vhcall_func *func;
	long retval, xfer_status;
	void *inbuf = NULL;
	void *outbuf = NULL;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "called\n");
	/* allocate buffer */
	if (inptr != 0L && insize != 0) {
		inbuf = malloc(insize);
		if (NULL == inbuf) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc failed: %s\n", strerror(errno));
			retval = -errno;
			goto err_alloc_inbuf;
		}
	}
	if (outptr != 0L && outsize != 0) {
		outbuf = malloc(outsize);
		if (NULL == outbuf) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc failed: %s\n", strerror(errno));
			retval = -errno;
			goto err_alloc_outbuf;
		}
	}

	/* copy in */
	if (inbuf != NULL) {
		xfer_status = ve_recv_data(handle, inptr, insize, inbuf);
		if (xfer_status < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data returned %ld\n",
					xfer_status);
			retval = -EFAULT;
			goto err_copyin;
		}
	}

	func = (vhcall_func *)symid;
	retval = func(handle, inbuf, insize, outbuf, outsize);

	/* copy out */
	if (outbuf != NULL) {
		xfer_status = ve_send_data(handle, outptr, outsize, outbuf);
		if (xfer_status < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data returned %ld\n",
					xfer_status);
			retval = -EFAULT;
		}
	}
err_copyin:
	free(outbuf);
err_alloc_outbuf:
	free(inbuf);
err_alloc_inbuf:
	return retval;
}

/**
 * @brief Handler of VHCALL_UNINSTALL: unload a VH library
 *
 * @param[in] handle VEOS handle
 * @param vh VH call handle of VH library to unload
 *
 * @return 0 on success. Non-zero on error.
 */
int sys_vhcall_uninstall(veos_handle *handle, vhcall_handle vh)
{
	int retval;
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "called\n");
	retval = dlclose((void *)vh);
	if (retval != 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"dlclose(%p) failed: %s\n",
				(void *)vh, dlerror());
	}
	return retval;
}
/**
 * @brief Handler of SYSVE_SYSTEM:
 *
 *  Invoke system function on VH side whenever VE_SYSVE_SYSTEM command
 *  received from VE side
 *
 * @param[in] handle : VEOS handle
 * @param[in] line : Input buffer on VE side to receive command.
 *          [If line is not NULL, data is copied in to VH]
 * @param size : size of input buffer
 *
 * @return 0 on success. -1 on error.
 */

int sys_system(veos_handle *handle, uintptr_t line,
		size_t size)
{

	int retval = 0, recv_data_status = 0;
	void *command = NULL;
	PSEUDO_DEBUG("sys_system is called\n");


	/* allocate buffer */
	if (line != 0L && size != 0) {
		command = calloc(1, size+1);
		if (NULL == command) {
			PSEUDO_ERROR("calloc failed: %s\n",
					strerror(errno));
			retval = -1;
			goto err_alloc_command;
		}
	}
	/* copy in */
	if (command != NULL) {
		recv_data_status = ve_recv_data(handle, line, size,
				command);
		if (recv_data_status < 0) {
			PSEUDO_ERROR("ve_recv_data returned %d\n",
					recv_data_status);
			retval = -1;
			goto err_recv_data;
		}
	}
	retval = system(command);
	PSEUDO_DEBUG("(command:%s), status[%d]", (char *)command,
			retval);

err_recv_data:
	free(command);
err_alloc_command:
	return retval;
}

/**
 * @brief Handler of SYSVE_SYSTEM2:
 *
 * Whenever VE_SYSVE_SYSTEM2 command received from library side.
 * @param[in] handle : VEOS handle
 * @param[in] line : Input buffer on VE side to receive command.
 *          [If line is not NULL, data is copied in to VH]
 * @param size : size of input buffer
 * @param oldmask : old signal set
 *
 * @return 0 on success. -1 on error.
 */

int sys_system2(veos_handle *handle, uintptr_t line,
		size_t size, uint64_t oldmask)
{

	int retval = 0, recv_data_status = 0, status = 0;
	void *command = NULL;
	struct sigaction sig_intr, sig_quit;
	pid_t pid = -1;
	PSEUDO_DEBUG("sys_system2 is called\n");

	/* allocate buffer */
	if (line != 0L && size != 0) {
		command = calloc(1, size+1);
		if (NULL == command) {
			PSEUDO_ERROR("calloc failed: %s\n",
					strerror(errno));
			retval = -1;
			goto err_alloc_command;
		}
	} else if (size == 0) {
		command = calloc(1, 1);
		if (NULL == command) {
			PSEUDO_ERROR("calloc failed: %s\n",
					strerror(errno));
			retval = -1;
			goto err_alloc_command;
		}
	}
	/* copy in */
	if (command != NULL) {
		recv_data_status = ve_recv_data(handle, line, size,
							 command);
		if (recv_data_status < 0) {
			PSEUDO_ERROR("ve_recv_data returned %d\n",
					recv_data_status);
			retval = -1;
			goto err_recv_data;
		}
	}
	/* Instead of offlaoding, implemented system()
	 * For more refer #1651*/
	pid = fork();
	if (pid == -1) {
		PSEUDO_ERROR("fork in system () failed : %s\n",
				strerror(errno));
		retval = -errno;
	} else if (pid == (pid_t) 0) {
		const char *exec_argv[4];
		exec_argv[0] = SHELL;
		exec_argv[1] = "-c";
		exec_argv[2] = command;
		exec_argv[3] = NULL;

		/* close VEDL handle */
		veos_handle_free(handle);

		sigaction(SIGINT, &sig_intr, (struct sigaction *) NULL);
		sigaction(SIGQUIT, &sig_quit, (struct sigaction *) NULL);
		sigprocmask(SIG_SETMASK, (sigset_t *)&oldmask,
				(sigset_t *) NULL);

		execve(SH_PATH, (char *const *) exec_argv, environ);
		PSEUDO_DEBUG("execve failed: %s\n", strerror(errno));
		exit(127);
	} else {
		if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) != pid)
			retval = -1;
		else
			retval = status;
	}

	PSEUDO_DEBUG("(command:%s), status[%d]", (char *)command, retval);

err_recv_data:
	free(command);
err_alloc_command:
	return retval;
}
