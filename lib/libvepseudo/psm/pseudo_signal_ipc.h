/**
 * @file pseudo_signal_ipc.h
 * @brief Header file for "pseudo_signal_ipc.c" file.
 */
#ifndef __PSEUDO_SIGNAL_IPC_H
#define __PSEUDO_SIGNAL_IPC_H

#include <signal.h>
#include <sys/resource.h>
#include "libved.h"
#include "syscall_common.h"
#include "veos_pseudo_interface.h"

int pseudo_psm_send_signal_req(struct ve_signal_info *, int);
int pseudo_psm_send_sigreturn_req(int);
int pseudo_psm_recv_sigreturn_ack(int);
int pseudo_psm_send_sigaction_req(struct ve_sigaction_info *, int);
int pseudo_psm_recv_sigaction_ack(struct sigaction *, int);
int pseudo_psm_send_setnew_sas(int, struct ve_sigalt_info *);
int pseudo_psm_recv_setnew_sas_ack(int, struct ve_sigalt_info *);
int pseudo_psm_recv_sigprocmask_ack(sigset_t *, int);
int pseudo_psm_send_sigprocmask_req(sigset_t *, int);
int pseudo_psm_send_sigpending_req(int);
int pseudo_psm_recv_sigpending_ack(sigset_t *, int);
int pseudo_psm_send_sigsuspend_req(int, sigset_t *);
int pseudo_psm_recv_sigsuspend_ack(int);
#endif
