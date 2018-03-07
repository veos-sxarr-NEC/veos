/**
 * @file syscall_commom.h
 * @brief Header file for "syscall_common.c" file.
 */
#ifndef SYSCALL_COMMON_H
#define SYSCALL_COMMON_H

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
#include <sys/resource.h>
#include <stdbool.h>
#include <sys/msg.h>
#include <mqueue.h>
#include <sys/ipc.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include<sys/sysinfo.h>
#include "libved.h"

extern int ve_set_ve_reg(uint64_t, uint64_t);

/* Used for log4c logging in veos module */

#define CAT_PSEUDO_CORE cat_pseudo_core
extern log4c_category_t *cat_pseudo_core;
extern const log4c_location_info_t locinfo;

#define return_system_call(retval) ve_set_ve_reg(SR00, retval)

typedef long int ret_t;

void ve_syscall_handler(vedl_handle *, int);
void ve_sys_ni_syscall(int, char *, vedl_handle *);
void ve_generic_offload(int, char *, vedl_handle *);
void ve_generic_dup(int, char *, vedl_handle *);
void ve_hndl_p_char(int, char *, vedl_handle *);
void ve_hndl_int_p_char(int, char *, vedl_handle *);
void ve_hndl_int_p_char_int_p_char(int, char *, vedl_handle *);
void ve_hndl_int_p_char_p_char(int, char *, vedl_handle *);
void ve_hndl_p_char_int_p_char(int, char *, vedl_handle *);
void ve_hndl_p_char_p_char(int, char *, vedl_handle *);
void ve_hndl_get_xattr_p_char_p_char_p_void(int, char *, vedl_handle *);
void ve_hndl_set_xattr_p_char_p_char_p_void(int, char *, vedl_handle *);
void ve_hndl_p_int_p_int_p_int(int, char *, vedl_handle *);
void ve_hndl_p_char_p_stat_buf(int, char *, vedl_handle *);
void ve_hndl_int_int_p_flock_buf(int, char *, vedl_handle *);
#endif
