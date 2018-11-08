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
 * @file sys_signal.c
 * @brief Handles Signal handling related system calls encountered
 * by VE process.
 *
 *	This file contains system call handlers for the various signal
 *	handling system calls encountered by VE process.
 *
 * @internal
 * @author Signal Handling
 */

#include "handle.h"
#include "mm_transfer.h"
#include "signal_comm.h"
#include "velayout.h"
#include "exception.h"
#include "sys_common.h"
#include "sys_process_mgmt.h"
#include "exception.h"

/**
 * @brief  Handle rt_sigaction() system call for VE.
 *
 * int sigaction(int signum, const struct sigaction *act,
 *					struct sigaction *oldact)
 *
 * This function receives the data and arguments from VEMVA/VEHVA and offloads
 * the functionality to VH OS sigaction() system call. It also communicates
 * with veos to set the new signal action and fetch the old signal action if
 * needed.
 *
 * This function after receiving the data from veos copies data to VEMVA
 * using VE driver interface
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 */
ret_t ve_rt_sigaction(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	struct k_sigaction act = {0}, old_act = {0};
	struct sigaction old_pseudo_act = { {0} };
	struct sigaction pseudo_act;
	struct ve_sigaction_info sigaction_info = {0};
	int signum;
	uint64_t args[4];

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);
	memset(&pseudo_act, 0, sizeof(struct sigaction));

	/* Fetch syscall argument */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigaction system call");
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[3] != _NSIG/8) {
		PSEUDO_ERROR("Invalid mask size received");
		retval= -EINVAL;
		goto hndl_return;
	}

	/* Fetch signal number */
	signum = args[0];
	PSEUDO_DEBUG("received sigaction request for signal: %d", signum);

	/* Check whether SIGNAL is valid or not */
	if (!valid_signal(signum) || signum < 1) {
		PSEUDO_ERROR("invalid signal: %d, sigaction can't be done"
				, signum);
		retval = -EINVAL;
		goto hndl_return;
	}

	if (args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(struct k_sigaction),
					(void *)&act)) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
		sigaction_info.action = 1;
	}
	pseudo_act.sa_handler = act.handler;
	pseudo_act.sa_flags = act.flags;
	memcpy(&pseudo_act.sa_mask, &act.mask, sizeof(sigset_t));
	sigdelset(&pseudo_act.sa_mask, SIGKILL);
	sigdelset(&pseudo_act.sa_mask, SIGCONT);
	sigdelset(&pseudo_act.sa_mask, SIGSTOP);
	pseudo_act.sa_restorer = act.restorer;

	PSEUDO_DEBUG("signal mask in handler context %lx"
			, pseudo_act.sa_mask.__val[0]);

	sigaction_info.signum = signum;
	sigaction_info.ve_sigaction = pseudo_act;

	PSEUDO_DEBUG("ve handler address = %lx",
			(long int)pseudo_act.sa_handler);

	retval = pseudo_psm_send_sigaction_req
				(&sigaction_info, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: send sigaction request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigaction_ack
			(&old_pseudo_act, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: send sigaction request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* a. Dummy handler should not be registered for signals SIGTSTP,
	 * SIGTTIN, SIGTTOU when registered for SIG_DFL action
	 * b. Register dummy handler which communicate with VEOS to
	 * deliver signal when signal action is set to SIG_DFL
	 * c. Do not ignore SIGCONT as the arrival of a SIGCONT signal
	 * always causes the process to resume, even if the process is
	 * currently ignoring SIGCONT.
	 */
	if ((pseudo_act.sa_handler == SIG_DFL) && (SPECIAL_SIGNAL(signum))) {
		pseudo_act.sa_handler =  SIG_DFL;
	} else if ((signum == SIGCONT && pseudo_act.sa_handler == SIG_IGN) ||
			pseudo_act.sa_handler != SIG_IGN) {
		pseudo_act.sa_sigaction =  &ve_sa_sigaction_handler;
	}

	pseudo_act.sa_flags &= (~(1 << RESTART_BIT));
	pseudo_act.sa_flags &= (~(1 << RESETHAND_BIT));

	/* Invoke sigaction() syscall */
	if (args[1] && !(((SIGRTMIN - 1) == args[0]) ||
				((SIGRTMIN - 2) == args[0]))) {
		retval = sigaction(signum, &pseudo_act, NULL);
		if (-1 == retval) {
			retval = -errno;
			PSEUDO_ERROR("sigaction() failed %d",
					(int)retval);
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("syscall %s returned %d",
					syscall_name, (int)retval);
		}
	}

	/* If third argument(i.e. old_act) for sigaction
	 * syscall is NOT-NULL then send the old action for the signal
	 * */
	if (NULL != (void *)args[2]) {
		old_act.handler = old_pseudo_act.sa_handler;
		old_act.flags = old_pseudo_act.sa_flags;
		memcpy(&old_act.mask,
				&old_pseudo_act.sa_mask,
				sizeof(old_act.mask));
		old_act.restorer = old_pseudo_act.sa_restorer;

		if (0 > ve_send_data(handle, args[2],
					sizeof(struct k_sigaction),
					(void *)(&old_act))) {
			PSEUDO_ERROR("failed to send data from VH to VE"
					" memory");
			retval = -EFAULT;
		}
	}
hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles rt_sigprocmask() system call for VE.
 *
 * int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
 *
 * This function receives the data and arguments from VEMVA/VEHVA and
 * communicate with veos to set the new signal block mask and fetch the
 * old signal block mask.
 *
 * This function after receiving the data from veos copies data to
 * VEMVA using VE driver interface
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 */
ret_t ve_rt_sigprocmask(int syscall_num, char *syscall_name
					, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	struct ve_signal_mask ve_mask;
	sigset_t signal_mask  = { {0} };

	PSEUDO_TRACE("Entering");
	PSEUDO_DEBUG("%s is called", syscall_name);

	memset(&ve_mask, 0, sizeof(struct ve_signal_mask));

	ve_mask.mask = true;
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigprocmask system call");
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[3] != _NSIG/8) {
		retval = -EINVAL;
		PSEUDO_ERROR("sigprocmask(): Invalid mask size received");
		goto hndl_return;
	}

	/* Fetch arg[1] from VE side */
	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(sigset_t),
					(uint64_t *)(&ve_mask.newset))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	} else {
		PSEUDO_DEBUG("%s is invoked with ve_mask.newset = NULL",
				syscall_name);
		ve_mask.mask = false;
	}

	if (!valid_request(args[0])) {
		retval = -EINVAL;
		PSEUDO_ERROR("sigprocmask(): The value specified "
			"in \"how\" was invalid");
		goto hndl_return;
	}
	ve_mask.how = args[0];

	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	retval = pseudo_psm_send_sigprocmask_req(&ve_mask,
			handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: sigprocmask request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigprocmask_ack(&ve_mask
			, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: sigprocmask acknowledgement"
				" returned %d",	syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	memcpy(&ve_proc_sigmask, &ve_mask.ve_curr_mask, sizeof(sigset_t));
	PSEUDO_DEBUG("Updated signal mask : %lx",
				ve_proc_sigmask.__val[0]);

	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	/* send the old signal mask */
	if (NULL != (void *)args[2]) {
		if (0 >  ve_send_data(handle, args[2],
					sizeof(sigset_t),
					(uint64_t *)(&ve_mask.oldset))) {
			PSEUDO_ERROR("failed to send data from VH to VE"
					" memory");
			retval = -EFAULT;
			goto hndl_return;
		} else {
			PSEUDO_DEBUG("Old signal mask : %lx",
					ve_mask.oldset.__val[0]);
		}
	}
	retval = 0;

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sigreturn system call for VE.
 *
 * int sigreturn(unsigned long __unused);
 *
 *	This function handles the sigreturn request done by VE process.It
 *	requests VEOS for VE signal sigreturn() and receive acknowledgment
 *	about same.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle VEOS handle
 *
 * @return positive value on success, -1 on return
 */
ret_t ve_rt_sigreturn(int syscall_num, char *syscall_name, veos_handle *handle)
{
	int retval = -1;
	sigset_t ve_curr_mask;
	sigset_t signal_mask  = { {0} };

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called handle address = %p",
			syscall_name, (void *)handle);

	sigemptyset(&ve_curr_mask);
	/* request VEOS for VE signal sigreturn() */
	retval = pseudo_psm_send_sigreturn_req(handle->veos_sock_fd);
	if (retval < 0) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: send sigreturn request returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	retval = pseudo_psm_recv_sigreturn_ack(handle->veos_sock_fd,
			&ve_curr_mask);
	if (retval < 0) {
		PSEUDO_ERROR("getting acknowledgement from veos failed");
		PSEUDO_DEBUG("%s failure: veos acknowledgement error"
				", return value %d", syscall_name
				, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* Copy VE process current mask */
	memcpy(&ve_proc_sigmask, &ve_curr_mask, sizeof(sigset_t));
	PSEUDO_DEBUG("signal mask will be: %lx",
			ve_proc_sigmask.__val[0]);
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return:
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles rt_sigpending() system call functionality for VE.
 *
 * int sigpending(sigset_t *set)
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS sigpending() system call. It also
 *	communicates with veos to fetch the list of siganls pending for
 *	delivery. This function after receiving the data from veos copies data
 *	toVEMVA using VE driver interface.
 *
 * @param[in] syscall_num Syscall number
 * @param[in] syscall_name Syscall name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative on failure.
 */
ret_t ve_rt_sigpending(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	sigset_t veos_set, pseudo_set;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	sigemptyset(&veos_set);
	sigemptyset(&pseudo_set);
	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigpending system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (!args[0]) {
		PSEUDO_DEBUG("Nothing to be done, NULL arguments");
		retval = 0;
		goto hndl_return;
	}

	/* Communicate with veos to get signal pending mask.
	 * */
	retval = pseudo_psm_send_sigpending_req(handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: veos sigpending request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigpending_ack(&veos_set
				, handle->veos_sock_fd);
	if (0 > retval) {
		PSEUDO_ERROR("veos acknowledgement error");
		PSEUDO_DEBUG("%s failure: veos sigpending acknowledgement"
				" returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call
	 * */
	retval = syscall(syscall_num,
			&pseudo_set,
			args[1]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("sigpending(): failed %d",
				(int)retval);
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}

	/* Union of VH's signal pending set and VE signal pending set
	 * */
	sigorset(&veos_set, &pseudo_set, &veos_set);

	/* Copy the signal pending information to VE area */
	if (0 > ve_send_data(handle, args[0],
				sizeof(sigset_t),
				(unsigned int *)(&veos_set))) {
		PSEUDO_ERROR("failed to send data from VH to VE"
				" memory");
		retval = -EFAULT;
		goto hndl_return;
	} else {
		PSEUDO_DEBUG("Old signal mask : %lx",
				veos_set.__val[0]);
	}
	retval = 0;

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sigwaitinfo() and sigtimedwait() syscall functionality for VE.
 *
 * int sigwaitinfo(const sigset_t *set, siginfo_t *info);
 *
 * int sigtimedwait(const sigset_t *set, siginfo_t *info,
 *                   const struct timespec *timeout);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS rt_sigtimedwait() system call.
 *	After successful execution of VH OS rt_sigtimedwait(), copies data to
 *	VEMVA using VE driver interface.
 *
 * @param[in] syscall_num Syscall number
 * @param[in] syscall_name Syscall name
 * @param[in] handle VEOS handle
 *
 * @return system call return value to VE process
 */
ret_t ve_rt_sigtimedwait(int syscall_num, char *syscall_name,
		veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	sigset_t waitset;
	struct timespec *timeout = NULL;
	siginfo_t info = {0};
	sigset_t signal_mask;
	int signo = -1;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigtimedwait system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}
	sigemptyset(&waitset);
	sigemptyset(&signal_mask);
	if (args[0]) {
		/* Fetch arg[0] from VE side */
		if (0 > ve_recv_data(handle, args[0],
					sizeof(sigset_t),
					(uint64_t *)&(waitset))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* copy timespec value from VE */
		timeout = (struct timespec *)malloc(sizeof(struct timespec));
		if (NULL == timeout) {
			retval = -errno;
			PSEUDO_ERROR("failed to create buffer for timespec");
			goto hndl_return;
		}

		if ((ve_recv_data(handle, args[2],
					sizeof(struct timespec),
					(uint64_t *)timeout)) < 0) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");

	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	signo = syscall(syscall_num, &waitset, &info, timeout, args[3]);
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	/* Post-processing of syscall started, blocking signals */
	if (!(signo > 0)) {
		retval = -errno;
		PSEUDO_ERROR("sigtimedwait(): failed %s %d",
				strerror(errno), signo);
		PSEUDO_DEBUG("Blocked signals for post-processing");
		goto hndl_return1;
	} else {
		PSEUDO_DEBUG("syscall %s returned signal number %d",
				syscall_name, signo);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");

	if (args[1]) {
		/* Copy the signal information to VE area */
		if (0 > ve_send_data(handle, args[1],
					sizeof(siginfo_t),
					(unsigned int *)(&info))) {
			PSEUDO_ERROR("failed to send data from VH to VE"
					" memory");
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
	retval = signo;
hndl_return1:
	if (NULL != timeout)
		free(timeout);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
* @brief Handles rt_sigqueueinfo() system call for VE.
*
* int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo);
*
*	This function receives the data and arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS rt_sigqueueinfo() system call.
*
* @param[in] syscall_num System Call number
* @param[in] syscall_name System Call name.
* @param[in] handle VEOS handle.
*
* @return 0 on success, -1 or -errno on failure.
*/
ret_t ve_rt_sigqueueinfo(int syscall_num, char *syscall_name
					, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	siginfo_t uinfo = {0};
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigqueuinfo system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[2]) {
		/* Fetch arg[2] from VE side */
		if (0 > ve_recv_data(handle, args[2],
					sizeof(siginfo_t),
					(uint64_t *)&(uinfo))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1]
			, args[2] ? &uinfo : NULL);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("rt_sigqueueinfo(): failed %ld",
				retval);
		goto hndl_return;
	}
	PSEUDO_ERROR("syscall %s returned %ld",
			syscall_name, retval);
	retval = 0;

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sigsuspend() system call for VE.
 *
 * int rt_sigsuspend(const sigset_t *mask);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA. It
 *	then request veos to set the signal mask of VE process for
 *	rt_sigsuspend() syscall and offloads the functionality to VH OS
 *	rt_sigsuspend() system call.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return 0 on success, negative value on failure.
 */
ret_t ve_rt_sigsuspend(int syscall_num, char *syscall_name, veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	sigset_t maskset;
	sigset_t signal_mask;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* Fetch syscall argument */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigsuspend system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Clear signal mask set */
	sigemptyset(&maskset);
	sigdelset(&maskset, SIGCONT);
	sigemptyset(&signal_mask);

	if (args[0]) {
		if (0 > ve_recv_data(handle, args[0],
					sizeof(sigset_t),
					(void *)&maskset)) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}

		/* Communicate veos about sigsuspend mask */
		retval = pseudo_psm_send_sigsuspend_req(handle->veos_sock_fd,
						&maskset);
		if (0 > retval) {
			PSEUDO_ERROR("veos request error");
			PSEUDO_DEBUG("%s failure: veos request error"
					", return value %d"
					, syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return;
		} else {
			/* Waiting for ACK from PSM */
			retval = pseudo_psm_recv_sigsuspend_ack
					(handle->veos_sock_fd);
			if (retval < 0) {
				PSEUDO_ERROR("veos acknowledgement error");
				PSEUDO_DEBUG("%s failure: send sigsuspend request returned %d",
						syscall_name, (int)retval);
				retval = -EFAULT;
				goto hndl_return;
			}
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, &maskset, args[1]);
	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (retval) {
		retval = -errno;
		PSEUDO_ERROR("sigsuspend(): failed %ld",
				retval);
		if (EINTR == -retval)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		PSEUDO_DEBUG("syscall %s returned %ld",
				syscall_name, retval);
	}
	PSEUDO_DEBUG("Blocked signals for post-processing");


hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles sigaltstack() system call functionality for VE.
 *
 * int sigaltstack(const stack_t *ss, stack_t *oss)
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS sigaltstack() system call. It
 *	also communicates with veos to set the new alternate stack and fetch
 *	the old alternate stack information if needed. This function after
 *	receiving the data from veos copies data to VEMVA using VE driver
 *	interface.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle VEOS handle
 *
 * @return 0 on success, negative value on failure
 */
ret_t ve_sigaltstack(int syscall_num, char *syscall_name, veos_handle *handle)
{
	int index = -1;
	ret_t retval = -1;
	uint64_t args[2];
	struct ve_sigalt_info sigalt_req = {0};
	struct ve_sigalt_info sigalt_ack = {0};

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for sigaltstack system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (!args[0] && !args[1]) {
		PSEUDO_DEBUG("Nothing to be done, NULL arguments");
		retval = 0;
		goto hndl_return;
	}
	if (args[0]) {
		/* Fetch arg[0] from VE side */
		if (0 > ve_recv_data(handle, args[0],
					sizeof(stack_t),
					(uint64_t *)&(sigalt_req.new_sas))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}

		PSEUDO_DEBUG("new sas received : ss_sp - %lx"
				"\t\tss_size - %d"
				"\t\tss_flags - %d",
				(long int)sigalt_req.new_sas.ss_sp,
				(int)sigalt_req.new_sas.ss_size,
				sigalt_req.new_sas.ss_flags);
		sigalt_req.new_sas_flag = 1;
	}

	if (args[1]) {
		PSEUDO_DEBUG("Need to fetch old sas");
		sigalt_req.old_sas_flag = 1;
	}

	/* Communicate veos about NEW SAS */
	retval = pseudo_psm_send_setnew_sas(handle->veos_sock_fd,
					&sigalt_req);
	if (0 > retval) {
		PSEUDO_ERROR("veos request error");
		PSEUDO_DEBUG("%s failure: veos request returned %d",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	} else {
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_setnew_sas_ack(handle->veos_sock_fd,
				&sigalt_ack);
		if (retval) {
			PSEUDO_ERROR("veos acknowledgement error");
			PSEUDO_DEBUG("%s failure: veos acknowledgement returned %d",
					syscall_name, (int)retval);
			if (retval == -ESRCH) {
				retval = -EFAULT;
				errno = -retval;
				fprintf(stderr, "syscall handling failed\n");
				pseudo_abort();
			}
			errno = -retval;
			goto hndl_return;
		}
	}

	/* Set the new alternate stack details in global thread information
	 * structure. This will be used when ve_grow() syscall is invoked.
	 * */
	if (sigalt_req.new_sas_flag == 1) {
		retval = pthread_mutex_lock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to acquire "
					"mutex lock");
			PSEUDO_DEBUG("Failed to acquire lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}

		index = find_global_array_index(syscall(SYS_gettid));

		PSEUDO_DEBUG("Saving ss_sp - %lx"
				"\t\tss_size - %d on global index %d",
				(long int)sigalt_req.new_sas.ss_sp,
				(int)sigalt_req.new_sas.ss_size, index);
		global_tid_info[index].sas_ss_sp =
			(unsigned long)sigalt_req.new_sas.ss_sp;
		global_tid_info[index].sas_ss_size = sigalt_req.new_sas.ss_size;

		/* Release mutex lock */
		retval = pthread_mutex_unlock(&tid_counter_mutex);
		if (retval != 0) {
			PSEUDO_ERROR("clone() failure: Failed to release "
					"mutex lock");
			PSEUDO_DEBUG("Failed to release lock, return value %d",
					-((int)retval));
			fprintf(stderr, "Internal resource usage "
					"error\n");
			/* FATAL ERROR: abort current process */
			pseudo_abort();
		}
	}

	if (args[1]) {
		/* Copy the OLD signal alternate stack information to VE area */
		if (0 > ve_send_data(handle, args[1],
					sizeof(stack_t),
					(void *)(&(sigalt_ack.old_sas)))) {
			PSEUDO_ERROR("failed to send data from VH to VE"
					" memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	retval = 0;

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * ve_tkill : Handles the tkill() functionality for ve.
 *
 * int tkill(int tid, int sig);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS tkill() system call. It also
 *	communicates with VEOS to send the reserved signal(32,33) after
 *	validating tid.
 *
 * @param syscall_num : System call number
 * @param syscall_name : System call name
 * @param handle : VEOS handle
 *
 * @return 0 on success, -1 on failure.
 */
ret_t ve_tkill(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[2];
	ret_t retval = -1;
	siginfo_t siginfo = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall"
				"returned %d", syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (((SIGRTMIN - 1) == args[1]) ||
			((SIGRTMIN - 2) == args[1])) {
		PSEUDO_DEBUG("Reserved signal %ld encountered",
				args[1]);
		siginfo.si_pid = getpid();
		siginfo.si_errno = 0;
		siginfo.si_code = SI_TKILL;
		siginfo.si_signo = args[1];
		siginfo.si_uid = getuid();
		if (!syscall(syscall_num, args[0], 0)) {
			PSEUDO_DEBUG("Request veos to serve library"
					" reserved signal %ld",
					args[1]);
			/*Send signal request for target thread*/
			ve_send_signal_req(args[0], args[1], &siginfo, NULL);
			retval = 0;
			goto hndl_return;
		} else {
			retval = -errno;
			PSEUDO_ERROR("failed to send request to serve library"
					" reserved signal: %ld", args[1]);
			goto hndl_return;
		}
	}
	/*
	 * unblock all signals except the one actualy blocked by VE process.
	 */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("tkill(): failed %d",
				(int)retval);
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * ve_kill : Handles the kill() functionality for ve.
 *
 * int kill(int tid, int sig);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS kill() system call.
 *
 * @param syscall_num : System call number
 * @param syscall_name : System call name
 * @param handle : VEOS handle
 *
 * @return 0 on success, -1 on failure.
 */
ret_t ve_kill(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[2];
	ret_t retval = -1;
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 2);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall"
				"returned %d", syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/*
	 * unblock all signals except the one actualy blocked by VE process.
	 */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("kill(): failed %d",
				(int)retval);
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles the tgkill() functionality for ve.
 *
 * int tgkill(int tgid, int tid, int sig);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS tgkill() system call. It also
 *	communicates with VEOS to send the reserved signal(32,33) after
 *	validating tid.
 *
 * @param syscall_num : System call number
 * @param syscall_name : Sysatem call name
 * @param handle : VEOS handle
 *
 * @return 0 on success, -1 on failure.
 */
ret_t ve_tgkill(int syscall_num, char *syscall_name, veos_handle *handle)
{
	uint64_t args[3];
	ret_t retval = -1;
	siginfo_t siginfo = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 3);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall"
				"returned %d", syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (((SIGRTMIN - 1) == args[2]) ||
			((SIGRTMIN - 2) == args[2])) {
		PSEUDO_DEBUG("Reserved signal %ld encountered",
				args[2]);
		siginfo.si_pid = getpid();
		siginfo.si_errno = 0;
		siginfo.si_code = SI_TKILL;
		siginfo.si_signo = args[2];
		siginfo.si_uid = getuid();
		if (!syscall(syscall_num, args[0], args[1], 0)) {
			PSEUDO_DEBUG("Request veos to serve library"
					" reserved signal %ld",
					args[2]);
			/*Send signal request to target thread id*/
			ve_send_signal_req(args[1], args[2], &siginfo, NULL);
			retval = 0;
			goto hndl_return;
		} else {
			retval = -errno;
			PSEUDO_ERROR("failed to send request to serve library"
					" reserved signal: %ld", args[2]);
			goto hndl_return;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			args[2]);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("tgkill(): %s failed %d",
				syscall_name, (int)retval);
	} else {
		PSEUDO_DEBUG("syscall %s returned %d",
				syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Generic Handler for system calls of VE that have first argument
 * as int  and second argument as a pointer to signal mask of type sigset_t.
 *
 *	This generic function is used by respective  ve_<sys_call_name>
 *	handlers which have similar requirements and similar post and
 *	pre processing handling.This function fetches signal mask from
 *	VEMVA using VE driver interface and offloads the functionality
 *	to VH OS system call.
 *
 *	Following system calls use this generic handler:
 *	ve_signalfd(),
 *	ve_signalfd4()
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name  System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return returns a signalfd file descriptor on succcess, negative number
 * on failure.
 */
ret_t ve_hndl_int_p_sigset(int syscall_num, char *syscall_name,
		veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	sigset_t mask;

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Clear the mask */
	sigemptyset(&mask);

	/* Fetch arg[1] from VE side */
	if (NULL != (void *)args[1]) {
		if (0 > ve_recv_data(handle, args[1],
					sizeof(sigset_t),
					(uint64_t *)(&mask))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	} else {
		PSEUDO_DEBUG("%s is invoked with signal set = NULL",
				syscall_name);
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			args[1] ? &mask : NULL, args[2], args[3]);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("signalfd4(): failed %d",
				(int)retval);
		goto hndl_return;
	}
	PSEUDO_DEBUG("syscall %s returned :%d", syscall_name, (int)retval);
hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}

/**
 * @brief Handles signalfd() system call for VE.
 *
 * int signalfd(int fd, const sigset_t *mask, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_sigset" as
 *	signalfd() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_signalfd(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_sigset(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles signalfd4() system call for VE.
 *
 * int signalfd(int fd, const sigset_t *mask, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_sigset" as
 *	signalfd4() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return system call value to VE process
 */
ret_t ve_signalfd4(int syscall_num, char *syscall_name, veos_handle *handle)
{
	return ve_hndl_int_p_sigset(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles rt_tgsigqueueinfo() system call for VE.
 *
 * int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig,
 *                              siginfo_t *uinfo);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS rt_tgsigqueueinfo() system call.
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name.
 * @param[in] handle VEOS handle.
 *
 * @return 0 on success, negative on failure.
 */
ret_t ve_rt_tgsigqueueinfo(int syscall_num, char *syscall_name,
		veos_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	siginfo_t uinfo = {0};
	sigset_t signal_mask = { {0} };

	PSEUDO_TRACE("Entering");

	PSEUDO_DEBUG("%s is called", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle->ve_handle, args, 4);
	if (retval < 0) {
		PSEUDO_ERROR("Failed to fetch arguments for tgsigqueueinfo system call");
		PSEUDO_DEBUG("%s failure: fetching arguments for syscall returned %d",
				syscall_name, (int)retval);
		PSEUDO_DEBUG("Mapping retval %d to errno %d",
				(int) retval, -EFAULT);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[3]) {
		/* Fetch arg[3] from VE side */
		if (0 > ve_recv_data(handle, args[3],
					sizeof(siginfo_t),
					(uint64_t *)&(uinfo))) {
			PSEUDO_ERROR("Failed to receive data from VE memory");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	/* unblock all signals except the one actualy blocked by VE process */
	PSEUDO_DEBUG("Pre-processing finished, unblock signals");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1], args[2]
			, args[3] ? &uinfo : NULL);

	/* Post-processing of syscall started, blocking signals */
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (-1 == retval) {
		retval = -errno;
		PSEUDO_ERROR("rt_tgsigqueueinfo(): failed %d",
				(int)retval);
		goto hndl_return;
	}
	PSEUDO_DEBUG("syscall %s returned %d",
			syscall_name, (int)retval);
	retval = 0;

hndl_return:
	/* write return value */
	PSEUDO_TRACE("Exiting");
	return retval;
}
