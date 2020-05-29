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
 * @file sys_common.h
 * @brief Header file for "sys_common.c" file.
 */
#ifndef __SYS_COMMON_H
#define __SYS_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <linux/termios.h>
#include <time.h>
#include <sys/uio.h>
#include <sched.h>
#include <poll.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/sem.h>
#include <sys/vfs.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <mqueue.h>
#include <sys/ipc.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <elf.h>
#include <sys/utsname.h>
#include <linux/utsname.h>
#if __GLIBC_PREREQ(2,28)
struct ustat
{
  __daddr_t f_tfree;          /* Number of free blocks.  */
  __ino_t f_tinode;           /* Number of free inodes.  */
  char f_fname[6];
  char f_fpack[6];
};
#else
#include <ustat.h>
#endif
#include <sys/quota.h>
#include <linux/reboot.h>
#include "libved.h"
#include "handle.h"
#include "velayout.h"

#define PAGE_SHIFT     12
#define PAGE_SIZE      (1UL << PAGE_SHIFT)
#define PAGE_MASK      (~(PAGE_SIZE-1))
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)

#define NOTIFY_COOKIE_LEN       32

#define EP_MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))

/* nanoseconds in a second */
#define NSEC_PER_SEC 1000000000L

/* This is only hypothetical reference taken from kernel
 * implementation. Actual value will be fetched from
 * proc file system.
 * */
#define PROC_SEM_PATH "/proc/sys/kernel/sem"

/* Used for log4c logging in veos module */
#define SYSCALL_NAME (syscall_name+3)

#define CAT_PSEUDO_CORE cat_pseudo_core
#define PSEUDO_WARN(fmt, ...) \
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)
#define PSEUDO_ERROR(fmt, ...) \
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define PSEUDO_INFO(fmt, ...) \
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)
#define PSEUDO_DEBUG(fmt, ...) \
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define PSEUDO_TRACE(fmt, ...) \
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_TRACE, fmt " %s()", ## __VA_ARGS__, __func__)

extern log4c_category_t *cat_pseudo_core;
extern const log4c_location_info_t locinfo;
extern char **environ; /*environment variable*/
#define VE_ATOMIC_IO ve_atomic_io
extern bool ve_atomic_io;
#define MAX_IO_PER_CYCLES (64*1024*1024) /* 64 MB in Bytes*/
typedef struct non_atomic_io
{
	ssize_t io_req_size;
	ssize_t io_size;
	ssize_t io_retval;
	ssize_t io_cycles;
	ssize_t io_offset;
	ssize_t io_rem;
}non_atomic_msg_t;

typedef struct non_atomic_io_msghdr
{
	non_atomic_msg_t *non_atomic_io;
}non_atomic_msghdr_t;

typedef long int ret_t;

void ve_syscall_handler(veos_handle *, int);
ret_t ve_generic_offload(int, char *, veos_handle *);
ret_t ve_generic_dup(int, char *, veos_handle *);
ret_t ve_hndl_p_char(int, char *, veos_handle *);
ret_t ve_hndl_int_p_char(int, char *, veos_handle *);
ret_t ve_hndl_int_p_char_int_p_char(int, char *, veos_handle *);
ret_t ve_hndl_int_p_char_p_char(int, char *, veos_handle *);
ret_t ve_hndl_p_char_int_p_char(int, char *, veos_handle *);
ret_t ve_hndl_p_char_p_char(int, char *, veos_handle *);
ret_t ve_hndl_get_xattr_p_char_p_char_p_void(int, char *, veos_handle *);
ret_t ve_hndl_set_xattr_p_char_p_char_p_void(int, char *, veos_handle *);
ret_t ve_hndl_p_int_p_int_p_int(int, char *, veos_handle *);
ret_t ve_hndl_p_char_p_stat_buf(int, char *, veos_handle *);
ret_t ve_hndl_int_int_p_flock_buf(int, char *, veos_handle *);
ret_t ve_is_valid_address(veos_handle *, uint64_t);
#endif
