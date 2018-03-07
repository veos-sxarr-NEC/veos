/*
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file ptrace_log.c
 * @brief Handles the debugging messages of VE Ptrace library.
 *
 * @internal
 * @author PTRACE
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "ptrace_log.h"

#define VE_PTRACE_LOG_CATEGORY "veos.ptrace"

static log4c_category_t *category;
static pthread_mutex_t log_mtx;

__attribute__ ((constructor))
static void ve_ptrace_constructor(void)
{
	pthread_mutex_init(&log_mtx, NULL);
	/*
	 * There is no harm calling log4c_init() multiple times
	 * in the same process.
	 */
	if (log4c_init())
		fprintf(stderr, "log4c_init() failed.\n");

	category = log4c_category_get(VE_PTRACE_LOG_CATEGORY);
}

void ve_ptrace__vlog(int prio, const log4c_location_info_t *loc, const char *fmt,
		  va_list list)
{
	if (pthread_mutex_lock(&log_mtx)) {
		fprintf(stderr, "Failed in acquring lock while doing logging.\n");
		abort();
	}

	if (log4c_category_is_priority_enabled(category, prio))
		__log4c_category_vlog(category, loc, prio, fmt, list);

	if (pthread_mutex_unlock(&log_mtx)) {
		fprintf(stderr, "Failed in releasing lock while doing logging.\n");
		abort();
	}
}

void ve_ptrace__log(int prio, const log4c_location_info_t *loc, const char *fmt,
		 ...)
{
	va_list ap;
	va_start(ap, fmt);
	ve_ptrace__vlog(prio, loc, fmt, ap);
	va_end(ap);
}

__attribute__ ((destructor))
static void ve_ptrace_destructor(void)
{
	/*
	 * log4c_fini() always returns 0.
	 * However according to the documentation, it's recommended
	 * to check the return value.
	 */
	if (log4c_fini())
		fprintf(stderr, "log4c_fini() failed.\n");

	pthread_mutex_destroy(&log_mtx);
}
