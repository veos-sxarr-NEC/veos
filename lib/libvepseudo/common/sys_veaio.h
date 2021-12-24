/**
 * Copyright (C) 2018 NEC Corporation
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/**
 * @file pseudo_veaio.h
 * @brief Header for VEAIO in psedo process
 *
 * @internal
 * @author VEAIO
 */

#ifndef __PSEUDO_VEAIO_H
#define __PSEUDO_VEAIO_H

#include <sys/types.h>
#include "sys_common.h"
#include "veaio_defs.h"

struct vh_aio_ctx {
	veos_handle *handle;
	pid_t tid; /*!< tid used when transfer/receive VE data from AIO worker thread  */
	pthread_mutex_t vh_aio_status_lock; /*!< Protect vh_aio_hash and vh_aio_ctx->refcnt */
	pthread_cond_t cond; /*!< Condition variable to wait for completion of read/write */
	void *ve_ctx; /*!< AIO context on VE */
	int status; /*!< Status of read/write on worker thread */
	int refcnt; /*!< Reference sount of this context */
	int fd; /*!< File discriptor */
	size_t count; /*!< Number of bytes read/write */
	uint64_t buf; /*!< Read/write buffer */
	off_t offset; /*!< File offset */
	int32_t             op;
	uint64_t            total;
	int32_t             alive;
	int32_t             leave;
	struct seq          *seq;
	struct ve_aio2_result      *res;
};

int sys_ve_aio_read(veos_handle *handle, struct ve_aio_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset);
int sys_ve_aio_write(veos_handle *handle, struct ve_aio_ctx *ve_ctx, int fd,
                size_t count, void *buf, off_t offset);
int sys_ve_aio_wait(veos_handle *handle, struct ve_aio_ctx *ve_ctx);

int sys_ve_aio2_init(veos_handle *handle);
int sys_ve_aio2_read(veos_handle *handle, struct ve_aio2_ctx *ve_ctx, int fd,
		size_t count, void *buf, off_t offset);
int sys_ve_aio2_write(veos_handle *handle, struct ve_aio2_ctx *ve_ctx, int fd,
		size_t count, void *buf, off_t offset);
int sys_ve_aio2_wait(veos_handle *handle, struct ve_aio2_ctx *ve_ctx);

#endif
