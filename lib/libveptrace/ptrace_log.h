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
 * @file ptrace_log.h
 * @brief Header file for ptrace_log.c file
 *
 * @internal
 * @author PTRACE
 */

#ifndef __PTRACE_LOG_H
#define __PTRACE_LOG_H

#include <stdlib.h>
#include <log4c.h>
#include <log4c/category.h>
#include <log4c/priority.h>

enum ve_ptrace_priority {
	VE_PTRACE_LOG_ALERT = LOG4C_PRIORITY_ALERT,
	VE_PTRACE_LOG_CRIT = LOG4C_PRIORITY_CRIT,
	VE_PTRACE_LOG_ERR = LOG4C_PRIORITY_ERROR,
	VE_PTRACE_LOG_INFO = LOG4C_PRIORITY_INFO,
	VE_PTRACE_LOG_DEBUG = LOG4C_PRIORITY_DEBUG,
	VE_PTRACE_LOG_TRACE = LOG4C_PRIORITY_TRACE,
};

void ve_ptrace__vlog(int prio, const log4c_location_info_t *, const char *fmt,
		  va_list list);
void ve_ptrace__log(int prio, const log4c_location_info_t *, const char *fmt, ...);

#define VE_PTRACE_LOG(prio, fmt, ...) do { \
	const log4c_location_info_t locinfo__ = \
	LOG4C_LOCATION_INFO_INITIALIZER(NULL); \
	ve_ptrace__log(prio, &locinfo__, fmt, ##__VA_ARGS__); \
} while (0)

#define VE_PTRACE_ALERT(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_ALERT, fmt, ##__VA_ARGS__)
#define VE_PTRACE_CRIT(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_CRIT, fmt, ##__VA_ARGS__)
#define VE_PTRACE_ERR(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_ERR, fmt, ##__VA_ARGS__)
#define VE_PTRACE_INFO(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_INFO, fmt, ##__VA_ARGS__)
#define VE_PTRACE_DEBUG(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define VE_PTRACE_TRACE(fmt, ...) VE_PTRACE_LOG(VE_PTRACE_LOG_TRACE, fmt " %s()", ##__VA_ARGS__, __func__)
#endif
