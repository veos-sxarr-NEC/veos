/**
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
 * @file  psm_stat.c
 * @brief PSM interfaces regarding ptrace system call handling in VEOS.
 *
 * @author PSMG
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/capability.h>
#include "psm_stat.h"
#include "velayout.h"
#include "ve_mem.h"
#include "signal.h"
#include "locking_handler.h"
/**
 * @brief Get the scheduling priority of the VE process.
 *
 * @param[in,out] prio_req Pointer to struct ve_priorityinfo
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_getpriority_req(struct ve_priorityinfo *prio_req)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");
	if (!prio_req)
		goto hndl_return;

	pid = prio_req->who;

	/* VE default scheduling priority case */
	if (pid == 0) {
		VEOS_DEBUG("Default priority request from RPM.");
		prio_req->niceval = VE_DEF_SCHED_PRIORITY;
		retval = 0;
		goto hndl_return;
	}

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d is not found.", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Request regarding PRIO_PROCESS is only handled by VEOS */
	if (prio_req->which == PRIO_PROCESS)
		prio_req->niceval = tsk->priority;
	else {
		VEOS_ERROR("Invalid argument received.");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Check that the VE process have resource capability or not.
 *
 * @param[in] pid VE process pid
 * @param[in] capability capability to check
 *
 * @return true if pid have have capability, false if does not have capability.
 *
 * @internal
 * @note Invoked by other modules i.e. PTRACE
 */
bool check_ve_proc_capability(int pid, int capability)
{
	bool retval = false;
	uint32_t cap_data_pres = 0;
	struct __user_cap_header_struct cap_header_data = {0};
	struct __user_cap_data_struct cap_data_data = {0};

	VEOS_TRACE("Entering");
	/*
	 * checking the given pid have capability or not
	 */
	cap_user_header_t cap_header = &cap_header_data;
	cap_user_data_t cap_data = &cap_data_data;
	cap_header->pid = pid;
	cap_header->version = _LINUX_CAPABILITY_VERSION;

	/* Get the capabilities */
	if (capget(cap_header, cap_data) < 0) {
		VEOS_ERROR("failed in getting capability");
		goto hndl_return;
	}
	cap_data_pres = 1<<capability;
	if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
		VEOS_ERROR("PID %d doesn't have"
				" %d capability.",
				pid, capability);
		goto hndl_return;
	}
	retval = true;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the scheduling priority of the VE process.
 *
 * @param[in] prio_req Pointer to struct ve_priorityinfo
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_setpriority_req(struct ve_priorityinfo *prio_req)
{
	int retval = -1;
	int pid = -1;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");
	if (!prio_req)
		goto hndl_return;

	pid = prio_req->who;

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d is not found.",
				pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	if (!check_ve_proc_capability(pid, CAP_SYS_NICE)) {
		VEOS_ERROR("Checking VE process capability failed");
		retval = -EPERM;
		goto hndl_return;
	}

	/* Request regarding PRIO_PROCESS is only handled by VEOS */
	if (prio_req->which == PRIO_PROCESS) {
		pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
				"Failed to acquire task lock [PID = %d]", pid);
		if (prio_req->niceval < -20)
			tsk->priority = -20;
		else if (prio_req->niceval > 19)
			tsk->priority = 19;
		else
			tsk->priority = prio_req->niceval;
		pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
				"Failed to release task lock [PID = %d]", pid);
	} else {
		VEOS_ERROR("Invalid argument received.");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will populate the fields of struct velib_pidstat.
 *
 * @param[in] pid Pid of VE process
 * @param[out] pidstat Pointer to struct velib_pidstat.
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_pidstat_req(int pid, struct velib_pidstat *pidstat)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	bool flag;

	VEOS_TRACE("Entering");
	if (!pidstat)
		goto hndl_return;

	flag = pidstat->whole;

	memset(pidstat, 0, sizeof(struct velib_pidstat));

	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found.", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Populate the VE task state */
	switch (tsk->ve_task_state) {
	case WAIT:
		pidstat->state = 'S';
		break;
	case RUNNING:
		pidstat->state = 'R';
		break;
	case ZOMBIE:
		pidstat->state = 'Z';
		break;
	case STOP:
		pidstat->state = 'T';
		break;
	case EXIT_DEAD:
		pidstat->state = 'D';
		break;
	case P_INVAL:
		pidstat->state = 'I';
		break;
	}

	/* Fields of struct velib_pidstat like ppid, processor,
	 * priority, nice, policy are obtained directly from VE task
	 * struct.
	 */
	pidstat->ppid = tsk->parent->pid;
	pidstat->processor = tsk->p_ve_core->core_num;
	pidstat->priority = tsk->priority + PRIO_MASK;
	pidstat->nice = tsk->priority;
	pidstat->policy = tsk->policy;
	pidstat->utime = get_ve_proc_exec_time(tsk, flag);
	pidstat->cutime = tsk->sighand->cexec_time;
	pidstat->flags = tsk->flags;

	/* Calculating process start time since VE node
	 * is up for RPM request */
	pidstat->start_time = (tsk->start_time.tv_sec) +
			      (tsk->start_time.tv_usec / MICRO_SECONDS) -
		              (VE_NODE(0)->node_boot_time / MICRO_SECONDS);

	VEOS_DEBUG("START TIME %ld BOOT TIME %ld EPOCH TIME %ld",
			pidstat->start_time,
			(VE_NODE(0)->node_boot_time / MICRO_SECONDS),
			(tsk->start_time.tv_sec +
			 tsk->start_time.tv_usec / MICRO_SECONDS));

	/* VE process name */
	strncpy(pidstat->cmd, tsk->ve_comm, sizeof(tsk->ve_comm));

	/* Populate the stack pointer & instruction pointer */
	pidstat->kstesp = tsk->p_ve_thread->SR[11];
	pidstat->ksteip = tsk->p_ve_thread->IC;

	retval = 0;
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will populate the fields pf struct velib_statinfo.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 * @param[out] statinfo Pointer to struct velib_statinfo
 *
 * @return 0 on success, -1 on failure.
 */
int psm_rpm_handle_stat_req(struct ve_node_struct *p_ve_node,
		struct velib_statinfo *statinfo)
{
	int retval = -1;
	int core_loop = 0;
	unsigned long nr_switches = 0;
	struct timeval now = {0};
	uint64_t core_uptime = 0;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_TRACE("Entering");
	if (!p_ve_node || !statinfo)
		goto hndl_return;

	memset(statinfo, 0, sizeof(struct velib_statinfo));

	/* Core busy & idle values are populated in struct velib_statinfo */
	for (core_loop = 0; core_loop < p_ve_node->nr_avail_cores;
			core_loop++) {
		VEOS_DEBUG("Core loop: %d", core_loop);
		p_ve_core = VE_CORE(0, core_loop);
		gettimeofday(&now, NULL);
		core_uptime = timeval_diff(now, p_ve_core->core_uptime);
		statinfo->user[core_loop] = p_ve_core->busy_time;
		statinfo->idle[core_loop] = core_uptime - p_ve_core->busy_time;
	}

	nr_switches = psm_calc_nr_context_switches(p_ve_node);
	if ((unsigned long)-1 == nr_switches) {
		VEOS_ERROR("Failed to get number of context switches");
		goto hndl_return;
	}
	statinfo->ctxt = nr_switches;
	statinfo->running = p_ve_node->nr_active;

	/* As of now, VEOS do not maintain any state which can provide count
	 * of blocked processes which are waiting specifically for IO.
	 * So, VE blocked process count will be 0.
	 */
	statinfo->blocked = 0;
	statinfo->processes = p_ve_node->total_forks;
	statinfo->btime = p_ve_node->node_boot_time;
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Populate the VE process resource in struct velib_get_rusage_info.
 *
 * @param[in] pid PID of VE process
 * @param[out] ve_ru Pointer to struct velib_get_rusage_info
 *
 * @return 0 on success, -errno on failure
 */
int psm_rpm_handle_get_rusage_req(int pid, struct velib_get_rusage_info *ve_ru)
{
	int retval = -1;
	struct ve_rusage ve_r =  { {0} }, ve_r_child = { {0} };
	struct ve_task_struct *tsk = NULL, *group_leader = NULL;
	struct timeval now_time = {0};

	VEOS_TRACE("Entering");
	if (!ve_ru)
		goto hndl_return;

	/* Find the pointer of VE task struct from given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	retval = psm_handle_get_rusage_request(tsk, RUSAGE_CHILDREN, &ve_r_child);
	if (-1 == retval) {
		VEOS_ERROR("Getting rusage request failed "
				"for RUSAGE_CHILDREN flag");
		retval = -EFAULT;
		goto hndl_return;
	}

	retval = psm_handle_get_rusage_request(tsk, RUSAGE_SELF, &ve_r);
	if (-1 == retval) {
		VEOS_ERROR("Getting rusage request failed "
				"for RUSAGE_SELF flag");
		retval = -EFAULT;
		goto hndl_return;
	}

	ve_ru->utime.tv_sec = ve_r.ru_utime.tv_sec + ve_r_child.ru_utime.tv_sec;
	ve_ru->utime.tv_usec = ve_r.ru_utime.tv_usec + ve_r_child.ru_utime.tv_usec;
	ve_ru->ru_maxrss = ve_r.ru_maxrss + ve_r_child.ru_maxrss;
	ve_ru->page_size = tsk->p_ve_mm->pgsz;

	if ((tsk->start_time).tv_sec) {
		gettimeofday(&now_time, NULL);
		(ve_ru->elapsed).tv_sec = now_time.tv_sec - (tsk->start_time).tv_sec;

		if (now_time.tv_usec < (tsk->start_time).tv_usec) {
			/* Manually carry a one from the seconds field.  */
			now_time.tv_usec += USECOND;
			--now_time.tv_sec;
		}
		(ve_ru->elapsed).tv_usec = now_time.tv_usec - (tsk->start_time).tv_usec;
	}
	ve_ru->ru_nvcsw = ve_r.nvcsw;
	ve_ru->ru_nivcsw = ve_r.nivcsw;

	group_leader = tsk->group_leader;
	if ((group_leader->pid == tsk->pid) &&
			(group_leader->ve_task_state == ZOMBIE) &&
			(list_empty(&group_leader->thread_group))) {

		group_leader->ve_task_state = EXIT_DEAD;
		delete_entries(group_leader);
		retval = 0;
		goto hndl_return1;
	}
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
hndl_return1:
	VEOS_TRACE("Exiting");
	return retval;
}
/**
 * @brief It will set the scheduling policy and priority of VE process.
 *
 * @param[in] pid PID of VE process
 * @param[in] sched_param scheduling policy/parameters
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_sched_set_scheduler(int pid,
		struct velib_setscheduler sched_param)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	VEOS_TRACE("Entering");

	/* Check VE process have CAP_SYS_NICE capability to set the
	 * scheduling parameters.
	 */
	if (!check_ve_proc_capability(pid, CAP_SYS_NICE)) {
		VEOS_ERROR("Checking VE process capability failed");
		retval = -EPERM;
		goto hndl_return;
	}

	/* Find the pointer of VE task struct from given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock [PID = %d]", pid);
	tsk->policy = sched_param.policy;
	tsk->rt_priority = sched_param.sp.sched_priority;
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock [PID = %d]", pid);
	retval = 0;

	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Check that the VE pid exists or not
 *
 * @param[in] pid Pid of VE process
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_check_pid(int pid)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("Entering");

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("PID: %d not found.", pid);
		retval = -ESRCH;
		goto hndl_return;
	} else {
		VEOS_DEBUG("PID: %d found.", pid);
		retval = 0;
	}
	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will populate the struct velib_pidstatus
 *
 * @param[in] pid Pid of VE process
 * @param[out] pidstatus Pointer to struct velib_pidstatus
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_pidstatus(int pid, struct velib_pidstatus *pidstatus)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	struct sigaction *act;
	int i;
	sigset_t ignored, caught;

	VEOS_TRACE("Entering");
	if (!pidstatus)
		goto hndl_return;

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found.", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Populating values in struct velib_pidstatus
	 * from VE task struct.
	 */
	pidstatus->nvcsw = tsk->nvcsw;
	pidstatus->nivcsw = tsk->nivcsw;
	strncpy(pidstatus->cmd, tsk->ve_comm, sizeof(tsk->ve_comm));

	/*Collect pending and blocked signals */
	pidstatus->pending = tsk->pending.signal.__val[0];
	pidstatus->blocked = tsk->blocked.__val[0];

	/* Collect signal whose action is eighter ignore or
	 * can be caught.
	 **/
	 sigemptyset(&ignored);
	 sigemptyset(&caught);
	 act = tsk->sighand->action;
	 for (i = 1; i < _NSIG; ++i, ++act) {
		if (act->sa_handler == SIG_IGN)
			sigaddset(&ignored, i);
		else if (act->sa_handler != SIG_DFL)
			sigaddset(&caught, i);
	}
	pidstatus->caught = caught.__val[0];
	pidstatus->ignored = ignored.__val[0];

	VEOS_DEBUG("CAUGHT: %lx, IGNORED: %lx, PENDING: %lx, BLOCKED: %lx\n"
	           "CAUGHT: %llu, IGNORED: %llu, PENDING: %llu, BLOCKED: %llu",
			caught.__val[0], ignored.__val[0],
			tsk->pending.signal.__val[0], tsk->blocked.__val[0],
			pidstatus->caught, pidstatus->ignored,
			pidstatus->pending, pidstatus->blocked);

	retval = 0;
	put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will populate the struct velib_setscheduler
 * for sched_get_scheduler request.
 *
 * @param[in] pid Pid of VE process
 * @param[out] sched_param Pointer to struct velib_setscheduler
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_sched_get_scheduler(int pid,
		struct velib_setscheduler *sched_param)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	VEOS_TRACE("Entering");
	if (!sched_param)
		goto hndl_return;

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Scheduling policy is maintained in VE task struct */
	sched_param->policy = tsk->policy;
	retval = 0;
	put_ve_task_struct(tsk);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will populate the struct velib_setscheduler
 * for sched_get_param request.
 *
 * @param[in] pid Pid of VE process
 * @param[out] sched_param Pointer to struct velib_setscheduler
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_sched_get_param(int pid,
		struct sched_param *sp)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	VEOS_TRACE("Entering");
	if (!sp)
		goto hndl_return;

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found.", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Scheduling priority is maintained in VE task struct */
	sp->sched_priority = tsk->rt_priority;
	retval = 0;
	put_ve_task_struct(tsk);

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Function will fetch the VE process resource limit and populate
 * the struct velib_prlimit.
 *
 * @param[in] pid Pid of caller
 * @param[in] pid Pid of VE process
 * @param[out] prlimit Pointer to struct velib_prlimit
 * @param[in] prlimit Pointer to struct veos_thread_arg
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_prlimit(int caller_pid, int pid,
		struct velib_prlimit *prlimit, struct veos_thread_arg *pti)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;
	VEOS_TRACE("Entering");
	if (!prlimit)
		goto hndl_return;

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_ERROR("PID: %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	retval = psm_handle_get_rlimit_request(caller_pid, tsk,
			prlimit->resource, &(prlimit->old_lim), pti->cred.uid, pti->cred.gid);
	if (retval) {
		retval = -EPERM;
		goto hndl_return;
	}

	/* Set the new resource limit */
	if (true == prlimit->is_new_lim) {
		retval = psm_handle_set_rlimit_request(caller_pid, tsk,
				prlimit->resource, prlimit->new_lim, pti->cred.uid, pti->cred.gid);
		if (0 > retval) {
			VEOS_ERROR("Failed to set rlimit for PID: %d",
					pid);
			retval = -EPERM;
			goto hndl_return;
		}
	}
	retval = 0;

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Enable/disable VE process accounting of a node.
 *
 * @param[in] pid Pid of VE process
 * @param[in] acct_file Path to accounting file
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_acct(int pid, char *acct_file)
{
	int retval = -1;

	VEOS_TRACE("Entering");
	if (!check_ve_proc_capability(pid, CAP_SYS_PACCT)) {
		retval = -EPERM;
		goto hndl_return;
	}

	retval = psm_handle_do_acct_ve(acct_file);
	if (0 > retval) {
		VEOS_ERROR("PSM failed to do accounting");
		VEOS_DEBUG("Accounting failed for PID: %d, return value: %d",
				pid, retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}
