/*
 * Copyright (C) 2020-2021 NEC Corporation
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
 * @file  vhve_common.c
 * @brief This file contains functions for IPC with VEOS
 *
 * @internal
 * @author VHVE
 */
#include "vhve_common.h"
#include "vhve_socket.h"
#include "vhve_request.h"
#include <errno.h>
#include <log4c.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

log4c_category_t *cat_vhve_core;
log4c_appender_t *app_vhve_core;

char *app_file_name;
char log4c_file_path[NAME_MAX] = {0};
char log4c_home_file_path[NAME_MAX] = {0};
char log4c_curr_file_path[NAME_MAX] = {0};

const struct log4c_appender_type *type;

FILE *vhve_fp;

static void vhve_log4c_init(void);
static void vhve_handler_atfork_prepare(void);
static void vhve_handler_atfork_parent(void);
static void vhve_handler_atfork_child(void);

	__attribute__((constructor))
static void vhve_constructor(void)
{
	INIT_LIST_HEAD(&veos_hndl_list);
	pthread_mutex_init(&vhve_veos_hndl_list_lock, NULL);
	vhve_log4c_init();
	if (pthread_atfork(&vhve_handler_atfork_prepare,
				&vhve_handler_atfork_parent,
				&vhve_handler_atfork_child)) {
		VHVE_ERROR("Fail in constructor of libvhve:%s",
				strerror(errno));
		abort();
	}
}

/**
 * pthread_atfork() handler to be called just fork()
 **/
static void vhve_handler_atfork_prepare(void)
{
	pthread_mutex_lock(&vhve_veos_hndl_list_lock);
	return;
}

/**
 * pthread_atfork() handler to be called by parent
 * at the end of fork()
 **/
static void vhve_handler_atfork_parent(void)
{
	pthread_mutex_unlock(&vhve_veos_hndl_list_lock);
	return;
}

/**
 * @brief pthread_atfork() handler to be called by child
 *        at the end of fork()
 **/
static void vhve_handler_atfork_child(void)
{
	int ret;
	struct list_head *p, *tmp;
	vhve_veos_handle *h;
	pthread_mutex_unlock(&vhve_veos_hndl_list_lock);
	list_for_each_safe(p, tmp, &veos_hndl_list) {
		h = list_entry(p, vhve_veos_handle, list);
		ret = pthread_mutex_trylock(&h->hndl_lock);
		if (EBUSY == ret || 0 == ret)
			pthread_mutex_unlock(&h->hndl_lock);
		VHVE_DEBUG("RELEAES[%p]", h);
		vhve_veos_handle_free(h);
	}
	return;
}

/**
 * @biref initialize log4c routine
 **/
static void vhve_log4c_init(void)
{
	/* Log4c appender initialization for pseudo core logs */
	app_vhve_core = log4c_appender_get("vhve_appender");
	if (NULL == app_vhve_core) {
		fprintf(stderr, "libvhve setup failed, failure getting "
				"log4c appender\n");
		abort();
	}

	/* fetch the log4c layout type */
	type = log4c_appender_get_type(app_vhve_core);
	if (!type || strcmp(type->name, "stream")) {
		fprintf(stderr, "libvhve setup failed,"
				" log4c configuration file error\n");
		abort();
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
				|| !access(log4c_curr_file_path, F_OK))) {

		/* allocate memory to store log file name */
		app_file_name = (char *)malloc(NAME_MAX * sizeof(char));
		if (NULL == app_file_name) {
			fprintf(stderr, "VE process setup failed, memory allocation "
					"for log file name failed\n");
			abort();
		}
		memset(app_file_name, '\0', NAME_MAX * sizeof(char));

		/* create a name for log file */
		sprintf(app_file_name, "libvhve.log.%d", getpid());

		/* open a log file to print logs */
		vhve_fp = fopen(app_file_name, "a+");
		if (NULL == vhve_fp)
			vhve_fp = stderr;

		/* unbuffered mode */
		setbuf(vhve_fp, NULL);

		/* Replace the default appender data with the user data,
		 * This api returns the previous user data. If there is
		 * no previous user data then it returns NULL, which is
		 * not an error */
		log4c_appender_set_udata(app_vhve_core, vhve_fp);

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
		abort();
	}

	/* Log4c category initialization for pseudo core logs */
	cat_vhve_core = log4c_category_get("veos.vhve.core");
	if (NULL == cat_vhve_core) {
		fprintf(stderr, "VE process setup failed\n");
		abort();
	}

	return;
}

/**
 * @brief VEOS handle for VHVE Constructor routine
 *
 *     This routine allocates memory to vhve_veos_handle, initialises it
 *     and then returns the handler back to the caller.
 *
 * @param[in] os_socket socket file for VEOS
 *
 * @return pointer to veos handle on success and NULL on failure
 */
vhve_veos_handle *vhve_veos_handle_alloc(char *os_socket)
{
	vhve_veos_handle *hdl = NULL;
	int errv = 0;

	VHVE_TRACE("Entering");

	if (os_socket == NULL) {
		errv = EINVAL;
		VHVE_ERROR("Invalid(NULL) socket file "
				"path received");
		goto ret_hndl;
	}

	/* allocate memory for veos handle */
	hdl = (vhve_veos_handle *)malloc(sizeof(vhve_veos_handle));
	if (hdl == NULL) {
		errv = ENOMEM;
		VHVE_ERROR("Failed to allocate memory for handle structure, "
				"return value %s", strerror(errno));
		goto ret_hndl;
	}
	pthread_mutex_init(&hdl->hndl_lock, NULL);

	hdl->veos_sock_name = strdup(os_socket);
	if (hdl->veos_sock_name == NULL) {
		errv = ENOMEM;
		VHVE_ERROR("Failed to duplicate the string");
		VHVE_DEBUG("Failed to duplicate the string, return value %s",
				strerror(errno));
		goto err_hndl;
	}

	hdl->veos_sock_fd = vhve_veos_soc(os_socket);
	if (hdl->veos_sock_fd < 0) {
		errv = errno;
		VHVE_ERROR("Failed to create socket");
		goto err_hndl;
	}

	pthread_mutex_lock(&vhve_veos_hndl_list_lock);
	list_add_tail(&(hdl->list), &veos_hndl_list);
	pthread_mutex_unlock(&vhve_veos_hndl_list_lock);

	return hdl;

err_hndl:
	if (hdl->veos_sock_name != NULL)
		free(hdl->veos_sock_name);
	pthread_mutex_destroy(&hdl->hndl_lock);
	free(hdl);
ret_hndl:
	VHVE_TRACE("Exiting");
	errno = errv;
	return NULL;
}

/**
 * @brief Destructor routine for VEOS handler for VHVE.
 *
 *     This routine first closes the vedl_handle and then frees
 *     the memory allocated to veos handle memory.
 *
 * @param handle VEOS handle for VHVE
 */
void vhve_veos_handle_free(vhve_veos_handle *handle)
{
	if (!handle)
		return;

	pthread_mutex_lock(&vhve_veos_hndl_list_lock);
	list_del(&(handle->list));
	pthread_mutex_unlock(&vhve_veos_hndl_list_lock);

	/* if sockets are still open, then close here */
	close(handle->veos_sock_fd);
	free(handle->veos_sock_name);

	if (pthread_mutex_destroy(&handle->hndl_lock))
		VHVE_DEBUG("Fail pthread_mutex_destroy");

	/* freeing VEOS handle memory */
	free(handle);
}

/**
 * @brief This Function is used to communicate with VEOS
 *
 * @param[in] hdl VEOS handle for VHVE
 * @param[in] args buffer for sending data
 * @param[in] size sending buffer size
 * @param[out] msg receiving data
 *
 * @return On failure, returns -1 and on success, return 0
 */
int vhve_request_to_veos(vhve_veos_handle *hdl, void *args, size_t size,
		struct vhve_result *msg)
{
	int ret = -1;
	int errv = 0;
	ssize_t msglen;

	if (hdl == NULL || args == NULL) {
		VHVE_ERROR("INVALD argument");
		errv = EINVAL;
		goto ret_hndl;
	}

	pthread_mutex_lock(&hdl->hndl_lock);

	msglen = vhve_send_cmd(hdl->veos_sock_fd, args, size);
	if (size != msglen) {
		VHVE_ERROR("Failed to send request to VEOS");
		VHVE_DEBUG("Expected bytes: %zd Transferred bytes: %zd",
				size, msglen);
		errv = ECOMM;
		goto err_hndl;
	}

	msglen = vhve_recv_cmd(hdl->veos_sock_fd,
			msg, sizeof(struct vhve_result));
	if (sizeof(struct vhve_result) != msglen) {
		VHVE_ERROR("Failed to recv response from VEOS");
		VHVE_DEBUG("Expected bytes: %d Transferred bytes: %zd",
				MAX_VHVE_MSG_SIZE, msglen);
		errv = ENODATA;
		goto err_hndl;
	}

	ret = 0;

err_hndl:
	pthread_mutex_unlock(&hdl->hndl_lock);
ret_hndl:
	errno = errv;
	return ret;
}

/**
 * @brief This Function checks arguments of DMA request
 *
 * @param[in] vha VHVA that is source/dest of DMA xfer
 * @param[in] vea VEMVA that is source/dest of DMA xfer
 * @param[in] len length of DMA xfer
 *
 * @return On failure, returns -1 and on success, return 0
 */
int vhve_dma_check_args(uint64_t vha, uint64_t vea, uint64_t len)
{
	if (!IS_ALIGNED(len, 8)) {
		VHVE_ERROR("Unsupported transfer length (%lu bytes)", len);
		return -1;
	}
	if (len > VE_DMA_MAX_LENGTH) {
		VHVE_ERROR("Too large transfer length (0x%lx bytes)", len);
		return -1;
	}
	if (!IS_ALIGNED(vha, 8)) {
		VHVE_ERROR("DMA does not support unaligned "
				"source address (0x%016lx)", vha);
		return -1;
	}
	if (!IS_ALIGNED(vea, 8)) {
		VHVE_ERROR("DMA does not support unaligned "
				"destination address (0x%016lx)", vea);
		return -1;
	}
	return 0;
}
