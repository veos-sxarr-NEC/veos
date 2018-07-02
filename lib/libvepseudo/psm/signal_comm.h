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
 * @file signal_comm.h
 * @brief Header file for "signal_comm.c" file.
 *
 *	This file contains the signature of functions used to communicate
 *	to veos for signal related requests.
 *
 * @internal
 * @author Signal Handling
 */

#ifndef __SIGNAL_COMM_H
#define __SIGNAL_COMM_H

#include <signal.h>
#include <sys/resource.h>
#include "libved.h"
#include "handle.h"
#include "comm_request.h"

/*Write macro to avoid rpm build failure */
#define WRITE(fd, data, size) \
	do {	\
		if (write(fd, data, size)) \
		; \
	} while (0)

int pseudo_psm_send_signal_req(struct ve_signal_info *, int);
int pseudo_psm_send_sigreturn_req(int);
int pseudo_psm_recv_sigreturn_ack(int, sigset_t *);
int pseudo_psm_send_sigaction_req(struct ve_sigaction_info *, int);
int pseudo_psm_recv_sigaction_ack(struct sigaction *, int);
int pseudo_psm_send_setnew_sas(int, struct ve_sigalt_info *);
int pseudo_psm_recv_setnew_sas_ack(int, struct ve_sigalt_info *);
int pseudo_psm_recv_sigprocmask_ack(struct ve_signal_mask *, int);
int pseudo_psm_send_sigprocmask_req(struct ve_signal_mask *, int);
int pseudo_psm_send_sigpending_req(int);
int pseudo_psm_recv_sigpending_ack(sigset_t *, int);
int pseudo_psm_send_sigsuspend_req(int, sigset_t *);
int pseudo_psm_recv_sigsuspend_ack(int);
int pseudo_psm_recv_hw_exp_ack(int);
int pseudo_psm_recv_signal_ack(int);
#endif
