/*
 * Copyright (C) 2021 NEC Corporation
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
 * @file  libveproductinfo.c
 * @brief implementation of libveproductinfo APIs.
 *
 * This file contains the routines implementation that are used to request to
 * VEOS for operating VE DMA from VH process.
 *
 * @internal
 * @author libsysve
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "productinfo.h"
#include "sysve_os.h"

#define VE1_CORRESPOND_TABLE "/etc/opt/nec/ve/mmm/info/ve_hw_spec.yaml"
#define VE3_CORRESPOND_TABLE "/etc/opt/nec/ve3/mmm/info/ve3_hw_spec.yaml"

/* About 3 times "ve<model>_<type>" string */
#define MODEL_TYPE_SIZE 20
/* About 2 times CORRESPOND_TABLE string */
#define CORRESPOND_TABLE_SIZE 60

/**
 * @brief This function gets VE product neme from VE model, type and a correspondence table.
 *
 * @note This function is provided as a shared library of libproductname.
 * @note This function is invoked from ve_sys_get_ve_product_name() and lscpu command.
 * @note Correspondence table is "/etc/opt/nec/ve/mmm/info/ve_hw_spec.yaml".
 *
 * @param[in] model The model of VE card in alphanumeric characters.
 *                  Be null-terminated string.
 * @param[in] type The type of VE card in alphanumeric characters.
 *                 Be null-terminated string.
 * @param[out] buffer Buffer to store VE product name.
 *                    VE product name will be a null-terminated string even if buffer size 
 *                    is small or equal to the size of information.
 * @param[in] size Buffer size.
 *
 * @return On Success, an negative error number on Failure.
 *
 * @retval -EFAULT on Pointer is invalid.
 * @retval -EINVAL on Invalid argument.
 * @retval -ENOENT on Correspondence table file does not exist.
 * @retval -ENODEV on The product name does not exist in the correspondence table.
 * @retval -ENOMEM on Insufficient memory is available.
 *
 * @internal
 *
 * @author libsysve 
*/
int get_ve_product_name(char *model, char *type, char *buffer, size_t size)
{
	int ret = 0;
	int fd = -1;
	ssize_t count = 0;
	char *filepath = NULL;
	char *tmp_buffer = NULL;
	char *ve_model_type = NULL;
	char *p, *adr, *saveptr;
	struct stat stat_buffer;

	if (model == NULL || type == NULL || buffer == NULL) {
		ret = -EFAULT;
		goto hndl_return;
	}

	if ((int)size <= 0) {
		ret = -EINVAL;
		goto hndl_return;
	}

	/* About 3 times "ve<model>_<type>" string */
	ve_model_type = (char*)malloc(sizeof(char)*MODEL_TYPE_SIZE);
	if (ve_model_type == NULL) {
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(ve_model_type, '\0', sizeof(char)*MODEL_TYPE_SIZE);

	/* type & model newline character rewriting */
	p = strchr(type, '\n');
	if (p != NULL) {
		*p = '\0';
	}

	p = strchr(model, '\n');
	if(p != NULL) {
		*p = '\0';
	}

	/* Preparation search word */
	strncat(ve_model_type, "ve", 3);
	strncat(ve_model_type, model, (MODEL_TYPE_SIZE-5)/2);
	strncat(ve_model_type, "_", 2);
	strncat(ve_model_type, type, (MODEL_TYPE_SIZE-5)/2);
	strncat(ve_model_type, ":", 2);

	/* About 2 times CORRESPOND_TABLE string */
	filepath = (char*)malloc(sizeof(char)*CORRESPOND_TABLE_SIZE);
	if (filepath == NULL) {
		ret = -ENOMEM;
		goto hndl_return;
	}
	memset(filepath, '\0', sizeof(char)*CORRESPOND_TABLE_SIZE);

	/* VE1_CORRESPOND_TABLE */ 
	fd = open(VE1_CORRESPOND_TABLE, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		ret = -ENOENT;
		goto hndl_return;
	} else {
		strncpy(filepath, VE1_CORRESPOND_TABLE, CORRESPOND_TABLE_SIZE-1);
	}

	if (stat(filepath, &stat_buffer) != 0) {
		ret = -errno;
		goto hndl_close;
	}

	tmp_buffer = (char *)malloc(stat_buffer.st_size + 1);
	if (tmp_buffer == NULL) {
		ret = -ENOMEM;
		goto hndl_close;
	}
	memset(tmp_buffer, '\0', stat_buffer.st_size + 1);
	
	count = read(fd, tmp_buffer, stat_buffer.st_size);
	if (count < 0) {
		ret = -ENOENT;
		goto hndl_close;
	}

	adr = strstr(tmp_buffer, "product_info:");
	if (adr == NULL) {
		ret = -ENODEV;
		goto hndl_close;
	}
	adr = strstr(adr, ve_model_type);
	if (adr != NULL) {
		adr = strstr(adr, "name: ");
		adr = strtok_r(adr, "\n", &saveptr);
		/* The meaning of "+6" is to skip "name: " in "name: xxxxxx". */
		strncpy(buffer, adr+6, size/sizeof(char)-1);
		goto hndl_close;
	}
	
	if (close(fd) != 0) {
		ret = -errno;
		goto hndl_return;
	}

	/* VE3_CORRESPOND_TABLE */
	fd = open(VE3_CORRESPOND_TABLE, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
		ret = -ENOENT;
		goto hndl_return;
	} else {
		strncpy(filepath, VE3_CORRESPOND_TABLE, CORRESPOND_TABLE_SIZE-1);
	}

	count = read(fd, tmp_buffer, stat_buffer.st_size);
	if (count < 0) {
		ret = -ENOENT;
		goto hndl_close;
	}
	
	adr = strstr(tmp_buffer, "product_info:");
	if (adr == NULL) {
		ret = -ENODEV;
		goto hndl_close;
	}
	adr = strstr(adr, ve_model_type);
	if (adr == NULL) {
		ret = -ENODEV;
		goto hndl_close;
	}
	adr = strstr(adr, "name: ");
	adr = strtok_r(adr, "\n", &saveptr);
	/* The meaning of "+6" is to skip "name: " in "name: xxxxxx". */
	strncpy(buffer, adr+6, size/sizeof(char)-1);

hndl_close:
	if (close(fd) != 0) {
		ret = -errno;
	}

hndl_return:
	free(ve_model_type);
	free(filepath);
	free(tmp_buffer);
	return ret;
}

