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
 * @file vhcall_os.c
 * @brief sysve() handlers regarding VH call
 */

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>

#include <libved.h>
#include "mm_transfer.h"
#include <vhcall.h>
#include "vhcall_os.h"
#include "velayout.h"

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
	retval = (intptr_t)dlopen(pathbuf, RTLD_LAZY);
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
		command = calloc(1, size);
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
