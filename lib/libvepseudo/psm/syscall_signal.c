/**
 * @file syscall_signal.c
 * @brief Handles Signal handling related system calls encountered
 * by VE process.
 *
 * This file contains system call handlers for the various signal
 * handling system calls encountered by VE process.
 */

#include "syscall_common.h"
#include "ve_signal.h"
#include "mem_xfer.h"
#include "pseudo_veos_soc.h"
#include "pseudo_signal_ipc.h"
#include "velayout.h"

extern __thread sigset_t ve_proc_sigmask;

/**
 * @brief  Handle rt_sigaction() system call for VE.
 *
 * int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
 *
 * This function receives the data and arguments from VEMVA/VEHVA and offloads the
 * functionality to VH OS sigaction() system call. It also communicates with veos
 * to set the new signal action and fetch the old signal action if needed.
 *
 * This function after receiving the data from veos copies data to data to VEMVA
 * using VE driver interface
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_rt_sigaction(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct k_sigaction act = {0}, old_act = {0};
	struct sigaction old_pseudo_act = { {0} };
	struct sigaction pseudo_act;
	struct ve_sigaction_info sigaction_info = {0};
	int signum;
	int veos_sock_fd;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	memset(&pseudo_act, 0, sizeof(struct sigaction));

	/* Fetch syscall argument */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed\n"
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return_1;
	}

	/* Fetch signal number */
	signum = args[0];
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "SIGNUM = %d\n", signum);

	/* Check whether SIGNAL is valid or not */
	if (!valid_signal(signum) || signum < 1) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"INVALID SIGNAL NUM = %d\n", signum);
		retval = -EINVAL;
		goto hndl_return_1;
	}

	if (args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(struct k_sigaction),
					(void *)&act)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed");
			retval = -EFAULT;
			goto hndl_return_1;
		}
	}
	pseudo_act.sa_handler = act.handler;
	pseudo_act.sa_flags = act.flags;
	memcpy(&pseudo_act.sa_mask, &act.mask, sizeof (sigset_t));
	pseudo_act.sa_restorer = act.restorer;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"SA_MASK %ld\n", pseudo_act.sa_mask.__val[0]);

	sigaction_info.signum = signum;
	sigaction_info.ve_sigaction = pseudo_act;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"VE HANDLER ADDRESS = %lx\n",
			(long int)pseudo_act.sa_handler);

	/* Communicate with veos, send sigaction request */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -errno;
		goto hndl_return_1;
	}

	retval = pseudo_psm_send_sigaction_req(&sigaction_info, veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send sigaction request to PSM\n");
		retval = -errno;
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigaction_ack(&old_pseudo_act, veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive  sigaction ack from PSM\n");
		retval = -EFAULT;
		goto hndl_return;
	}

	pseudo_act.sa_flags &= (~(1 << RESTART_BIT));
	pseudo_act.sa_flags &= (~(1 << RESETHAND_BIT));

	if (pseudo_act.sa_handler != SIG_IGN) {
		if (pseudo_act.sa_flags & SA_SIGINFO) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SA_SIGINFO is set\n");
			pseudo_act.sa_sigaction =  &ve_sa_sigaction_handler;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SA_SIGINFO is not set\n");
			pseudo_act.sa_handler = &ve_sa_signal_handler;
		}
	}

	/* Invoke sigaction() syscall */
	retval = sigaction(signum, &pseudo_act, NULL);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"VH rt_sigaction successful\n");
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

		if (-1 == ve_send_data(handle, args[2],
					sizeof(struct k_sigaction),
					(void *)(&old_act))) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed\n");
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"ve_send_data successful\n");
		}
	}
hndl_return:
	close(veos_sock_fd);
hndl_return_1:
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
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
 * data to VEMVA using VE driver interface
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_rt_sigprocmask(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	sigset_t newset, oldset;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	sigemptyset(&oldset);
	sigemptyset(&newset);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Fetch arg[1] from VE side */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(sigset_t),
					(uint64_t *)(&newset))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"%s is invoked with newset = NULL\n",
				syscall_name);
	}

	/* Updating the global "ve_proc_sigmask" variable */
	if (NULL != (void *)args[1]) {
		switch (args[0]) {
		case SIG_BLOCK:
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SIG_BLOCK set\n");
			sigorset(&ve_proc_sigmask, &ve_proc_sigmask, &newset);
			break;
		case SIG_UNBLOCK:
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SIG_UNBLOCK set\n");
			sigandset(&ve_proc_sigmask, &ve_proc_sigmask, &newset);
			break;
		case SIG_SETMASK:
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"SIG_SETMASK set\n");
			ve_proc_sigmask = newset;
			break;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Updated signal mask : %ld\n",
			ve_proc_sigmask.__val[0]);

	/* Communicate with veos to set new signal mask
	 * and get the old signal mask.
	 * */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -errno;
		goto hndl_return;
	}
	retval = pseudo_psm_send_sigprocmask_req(&ve_proc_sigmask,
			veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send sigprocmask request to PSM\n");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigprocmask_ack(&oldset, veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to get sigprocmask ack from PSM\n");
		retval = -EFAULT;
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);
	/* send the old signal mask */
	if (NULL != (void *)args[2]) {
		if (-1 == ve_send_data(handle, args[2],
					sizeof(sigset_t),
					(uint64_t *)(&oldset))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_send_data() failed\n");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Old signal mask : %ld\n",
					oldset.__val[0]);
		}
	}
	retval = 0;

hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return;
}

/**
 * @brief Handles sigreturn system call for VE.
 *
 * @param[in] syscall_num System call number
 * @param[in] syscall_name System call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_rt_sigreturn(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	int veos_sock_fd;
	int retval = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called handle address = %p\n",
			syscall_name, (void *)handle);

	/* obtain socket for communication with PSM */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed.\n");
		goto hndl_return;
	}
	/* request VEOS for VE signal sigreturn() */
	retval = pseudo_psm_send_sigreturn_req(veos_sock_fd);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_sigreturn_req failed\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	retval = pseudo_psm_recv_sigreturn_ack(veos_sock_fd);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_recv_sigreturn_ack failed\n");
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);
hndl_return:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return;
}

/**
 * ve_pause
 *
 * Handles pause() system call for ve.
 *
 * int pause(void);
 *
 * This function offloads the functionality to VH OS pause() system call.
 *
 * @param syscall_num : System Call number
 * @param syscall_name : System Call name
 * @param handle : Handle for VE driver interface
 */
void ve_pause(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	reg_t retval;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num);

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;

	}
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* write return value */
	return_system_call(retval);
	return;
}

void ve_kill(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles rt_sigpending() system call functionality for VE.
 *
 * int sigpending(sigset_t *set)
 *
 * This function receives the data and arguments from VEMVA/VEHVA and offloads the
 * functionality to VH OS sigpending() system call. It also communicates with veos
 * to fetch the list of siganls pending for delivery.
 *
 * This function after receiving the data from veos copies data to data to VEMVA
 * using VE driver interface
 *
 * @param[in] syscall_num Syscall number
 * @param[in] syscall_name Syscall name
 * @param[in] handle Handle for VE driver interface
 */
void ve_rt_sigpending(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	sigset_t veos_set, pseudo_set;
	int veos_sock_fd;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	sigemptyset(&veos_set);
	sigemptyset(&pseudo_set);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (!args[0]) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Nothing to be done, NULL arguments\n");
		retval = 0;
		goto hndl_return;
	}

	/* Communicate with veos to get signal pending mask.
	 * */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -errno;
		goto hndl_return;
	}

	retval = pseudo_psm_send_sigpending_req(veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send sigpending request to PSM\n");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	}

	retval = pseudo_psm_recv_sigpending_ack(&veos_set, veos_sock_fd);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to get sigpending ack\n");
		retval = -EFAULT;
		close(veos_sock_fd);
		goto hndl_return;
	}
	close(veos_sock_fd);

	/* call VH system call
	 * */
	retval = syscall(syscall_num,
			&pseudo_set,
			args[1]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);
	}

	/* Union of VH's signal pending set and VE signal pending set
	 * */
	sigorset(&veos_set, &pseudo_set, &veos_set);

	/* Copy the signal pending information to VE area */
	if (-1 == ve_send_data(handle, args[0],
				sizeof(sigset_t),
				(unsigned int *)(&veos_set))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data() failed\n");
		retval = -EFAULT;
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Old signal mask : %ld\n",
				veos_set.__val[0]);
	}
	retval = 0;

hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return;
}

/**
* @brief Handles sigwaitinfo() and sigtimedwait() syscall functionality for VE.
*
* int sigwaitinfo(const sigset_t *set, siginfo_t *info);
*
* int sigtimedwait(const sigset_t *set, siginfo_t *info,
*                   const struct timespec *timeout);
*
* This function receives the data and arguments from VEMVA/VEHVA and offloads
* the functionality to VH OS rt_sigtimedwait() system call. Aftre successful
* execution of VH OS rt_sigtimedwait(), copies data to VEMVA using VE driver
* interface.
*
* @param[in] syscall_num Syscall number
* @param[in] syscall_name Syscall name
* @param[in] handle Handle for VE driver interface
*/
void ve_rt_sigtimedwait(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	sigset_t waitset;
	struct timespec *timeout = NULL;
	siginfo_t info = {0};
	sigset_t signal_mask;
	int signo = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed."
				" (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	sigemptyset(&waitset);
	sigemptyset(&signal_mask);
	if (args[0]) {
		/* Fetch arg[0] from VE side */
		if (-1 == ve_recv_data(handle, args[0],
					sizeof(sigset_t),
					(uint64_t *)&(waitset))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	if (args[2]) {
		/* copy timespec value from VE */
		timeout = (struct timespec *)malloc(sizeof(struct timespec));
		if (NULL == timeout) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc for timespec failed\n");
			goto hndl_return;
		}

		if ((ve_recv_data(handle, args[2],
					sizeof(struct timespec),
					(uint64_t *)timeout)) < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed. (%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");

	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	signo = syscall(syscall_num, &waitset, &info, timeout, args[3]);
	if (!(signo > 0)) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s %d\n",
				syscall_name, strerror(errno), signo);
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return1;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned signal number %d\n",
				syscall_name, signo);
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (args[1]) {
		/* Copy the signal information to VE area */
		if (-1 == ve_send_data(handle, args[1],
					sizeof(siginfo_t),
					(unsigned int *)(&info))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data() failed\n");
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
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
* @brief Handles rt_sigqueueinfo() system call for VE.
*
* int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo);
*
* This function receives the data and arguments from VEMVA/VEHVA and offloads the
* functionality to VH OS rt_sigqueueinfo() system call.
*
* @param[in] syscall_num System Call number
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_rt_sigqueueinfo(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	siginfo_t uinfo = {0};

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[2]) {
		/* Fetch arg[2] from VE side */
		if (-1 == ve_recv_data(handle, args[2],
					sizeof(siginfo_t),
					(uint64_t *)&(uinfo))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1], &uinfo);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
* @brief Handles sigsuspend() system call for VE.
*
* int rt_sigsuspend(const sigset_t *mask);
*
* This function receives the data and arguments from VEMVA/VEHVA. It then
* request veos to set the signal mask of VE process for rt_sigsuspend() syscall
* and offloads the functionality to VH OS rt_sigsuspend() system call.
*
* @param[in] syscall_num System Call number
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_rt_sigsuspend(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	int veos_sock_fd = -1;
	uint64_t args[2];
	sigset_t maskset;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* Fetch syscall argument */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed\n"
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Clear signal mask set */
	sigemptyset(&maskset);
	sigemptyset(&signal_mask);

	if (args[0]) {
		if (-1 == ve_recv_data(handle, args[0],
					sizeof(sigset_t),
					(void *)&maskset)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed");
			retval = -EFAULT;
			goto hndl_return;
		}

		/* Communicate veos about sigsuspend mask */
		veos_sock_fd = pseudo_veos_soc(veos_sock_name);
		if (veos_sock_fd < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"socket creation failed\n");
			retval = -errno;
			goto hndl_return;
		}

		retval = pseudo_psm_send_sigsuspend_req(veos_sock_fd, &maskset);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Sending SIGSUSPEND_REQ to PSM failed\n");
			retval = -EFAULT;
			goto hndl_return1;
		} else {
			/* Waiting for ACK from PSM */
			retval = pseudo_psm_recv_sigsuspend_ack(veos_sock_fd);
			if (retval < 0) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"SIGSUSPEND_REQ ack failed\n");
				goto hndl_return1;
			}
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	sigfillset(&signal_mask);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, &maskset, args[1]);
	if (retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %ld\n",
				syscall_name, retval);
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	close(veos_sock_fd);
hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
 * @brief Handles sigaltstack() system call functionality for VE.
 *
 * int sigaltstack(const stack_t *ss, stack_t *oss)
 *
 * This function receives the data and arguments from VEMVA/VEHVA and offloads the
 * functionality to VH OS sigaltstack() system call. It also communicates with veos
 * to set the new alternate stack and fetch the old alternate stack information
 * if needed.
 *
 * This function after receiving the data from veos copies data to data to VEMVA
 * using VE driver interface
 *
 * @param[in] syscall_num System Call number
 * @param[in] syscall_name System Call name
 * @param[in] handle Handle for VE driver interface
 */
void ve_sigaltstack(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[2];
	int veos_sock_fd;
	stack_t new_sas = {0};
	struct ve_sigalt_info sigalt_req = {0};
	struct ve_sigalt_info sigalt_ack = {0};

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (!args[0] && !args[1]) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Nothing to be done, NULL arguments\n");
		retval = 0;
		goto hndl_return;
	}
	if (args[0]) {
		/* Fetch arg[0] from VE side */
		if (-1 == ve_recv_data(handle, args[0],
					sizeof(stack_t),
					(uint64_t *)&(sigalt_req.new_sas))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"NEW SAS FETCHED : ss_sp - %lx\n"
				"\t\tss_size - %d\n"
				"\t\tss_flags - %d\n",
				(long int)sigalt_req.new_sas.ss_sp,
				(int)sigalt_req.new_sas.ss_size,
				sigalt_req.new_sas.ss_flags);
		sigalt_req.new_sas_flag = 1;
	}

	if (args[1]) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Need to fetch OLD SAS\n");
		sigalt_req.old_sas_flag = 1;
	}

	/* Communicate veos about NEW SAS */
	veos_sock_fd = pseudo_veos_soc(veos_sock_name);
	if (veos_sock_fd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"socket creation failed\n");
		retval = -errno;
		goto hndl_return;
	}

	retval = pseudo_psm_send_setnew_sas(veos_sock_fd, &sigalt_req);
	if (-1 == retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send setnew_sas request to PSM\n");
		retval = -errno;
		close(veos_sock_fd);
		goto hndl_return;
	} else {
		/* Waiting for ACK from PSM */
		retval = pseudo_psm_recv_setnew_sas_ack(veos_sock_fd,
				&sigalt_ack);
		if (retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ACK not received\n");
			retval = -EFAULT;
			close(veos_sock_fd);
			goto hndl_return;
		}
	}
	/* veos handling for sigaltstack()is successful,
	 * offload sigaltstack() to kernel
	 * */
	if (args[0]) {
		new_sas.ss_sp = malloc(SIGSTKSZ);
		if (NULL == new_sas.ss_sp) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc failed for %s : %s\n",
					syscall_name, strerror(errno));
			retval = -errno;
			/* TODO: cleanup from veos?
			 * */
			goto hndl_return;
		}
		new_sas.ss_size = SIGSTKSZ;
		new_sas.ss_flags = sigalt_req.new_sas.ss_flags;

		/* call VH system call */
		retval = syscall(syscall_num, &new_sas, NULL);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			/* TODO: cleanup from veos?
			 * */
			goto hndl_return;
		}
		free(new_sas.ss_sp);
	}

	if (args[1]) {
		/* Copy the OLD signal alternate stack information to VE area */
		if (-1 == ve_send_data(handle, args[1],
					sizeof(stack_t),
					(void *)(&(sigalt_ack.old_sas)))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data() failed\n");
			retval = -EFAULT;
			/* TODO: cleanup from veos?
			 * */
			goto hndl_return;
		}
	}
	close(veos_sock_fd);
	retval = 0;

hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

void ve_tkill(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * ve_tgkill : Handles the tgkill() functionality for ve.
 *
 * int tgkill(int tgid, int tid, int sig);
 *
 * @param syscall_num : System call number
 * @param syscall_name : Sysatem call name
 * @param handle : Handle for VE driver interface
 */
void ve_tgkill(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_generic_offload(syscall_num, syscall_name, handle);
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
*	It returns the return value of the system call back to
*	the VE process using "return_system_call" interface.
*
*	Following system calls use this generic handler:
*	ve_signalfd(),
*	ve_signalfd4()
*
* @param[in] syscall_num  System Call number.
* @param[in] syscall_name  System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_hndl_int_p_sigset(int syscall_num, char *syscall_name,
		vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	sigset_t mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Clear the mask */
	sigemptyset(&mask);

	/* Fetch arg[1] from VE side */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(sigset_t),
					(uint64_t *)(&mask))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"%s is invoked with signal set = NULL\n",
				syscall_name);
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			&mask, args[2], args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"syscall successful\n");
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
* @brief Handles signalfd() system call for VE.
*
* int signalfd(int fd, const sigset_t *mask, int flags);
*
* This function uses generic handler "ve_hndl_int_p_sigset" as signalfd()
* functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_signalfd(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_sigset(syscall_num, syscall_name, handle);
}

/**
* @brief Handles signalfd4() system call for VE.
*
* int signalfd(int fd, const sigset_t *mask, int flags);
*
* This function uses generic handler "ve_hndl_int_p_sigset" as signalfd4()
* functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_signalfd4(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_sigset(syscall_num, syscall_name, handle);
}

/**
* @brief Handles rt_tgsigqueueinfo() system call for VE.
*
* int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig,
*                              siginfo_t *uinfo);
*
* This function receives the data and arguments from VEMVA/VEHVA and offloads the
* functionality to VH OS rt_tgsigqueueinfo() system call.
*
* @param[in] syscall_num System Call number
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_rt_tgsigqueueinfo(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[4];
	siginfo_t uinfo = {0};

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (args[3]) {
		/* Fetch arg[3] from VE side */
		if (-1 == ve_recv_data(handle, args[3],
					sizeof(siginfo_t),
					(uint64_t *)&(uinfo))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data() failed\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	/* call VH system call */
	retval = syscall(syscall_num, args[0], args[1], args[2], &uinfo);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	/* write return value */
	return_system_call(retval);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

void ve_kcmp(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
