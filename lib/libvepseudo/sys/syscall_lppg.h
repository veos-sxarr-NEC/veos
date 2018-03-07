/**
 * @file syscall_lppg.h
 * @brief Header file for "syscall_lppg.c" file.
 */
#ifndef SYSCALL_LPPG_H
#define SYSCALL_LPPG_H

#include "libved.h"

void ve_hndl_readv_preadv(int, char *, vedl_handle *);
void ve_hndl_read_pread64(int, char *, vedl_handle *);
void ve_hndl_writev_pwritev(int, char *, vedl_handle *);
void ve_hndl_write_pwrite64(int, char *, vedl_handle *);
#endif
