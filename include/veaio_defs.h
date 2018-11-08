/**
 * Copyright (C) 2018 by NEC Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/**
 * @file veaio_defs.h
 * @brief Header file for VEAIO
 */

#include <sys/types.h>

#define VE_AIO_COMPLETE  1
#define VE_AIO_INPROGRESS  2

struct ve_aio_result {
	ssize_t retval; /*!< return value of pread()/pwrite() on VH */
	int errnoval; /*!< error number of pread()/pwrite() on VH */
};

struct ve_aio_ctx {
	struct ve_aio_result result;
	int status; /*!< Status of pread()/pwrite() on VH  */
	pthread_mutex_t ve_aio_status_lock; /*!< Protect ve_aio_ctx->status  */
};
