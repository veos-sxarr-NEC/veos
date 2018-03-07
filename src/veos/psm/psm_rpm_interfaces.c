#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/capability.h>
#include "psm_rpm_interfaces.h"
#include "velayout.h"

/**
 * @brief Get the scheduling priority of the VE process.
 *
 * @param[in,out] prio_req Pointer to struct ve_priority_req
 *
 * @return 0 on success, negative value on failure.
 */
int psm_rpm_handle_getpriority_req(struct ve_priority_req *prio_req)
{
	int retval = -1;
	int pid;
	struct ve_task_struct *tsk;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!prio_req)
		goto hndl_return;

	pid = prio_req->who;

	/* VE default scheduling priority case */
	if (pid == 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Default priority request from RPM.\n");
		prio_req->val = VE_DEF_SCHED_PRIORITY;
		retval = 0;
		goto hndl_return;
	}

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d is not found.\n",
				pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Request regarding PRIO_PROCESS is only handled by VEOS */
	if (prio_req->which == PRIO_PROCESS)
		prio_req->val = tsk->priority;
	else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid target received.\n");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Check that the VE process have resource capability or not.
 *
 * @param[in] pid VE process pid
 * @param[in] capability capability to check
 *
 * @return true if pid have have capability, false if doesnot have capability.
 */
bool check_ve_proc_capability(int pid, int capability)
{
	bool retval = false;
	uint32_t cap_data_pres;
	struct __user_cap_header_struct cap_header_data;
	struct __user_cap_data_struct cap_data_data;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	/*
	 * checking the given pid have capability or not
	 */
	cap_user_header_t cap_header = &cap_header_data;
	cap_user_data_t cap_data = &cap_data_data;
	cap_header->pid = pid;
	cap_header->version = _LINUX_CAPABILITY_VERSION;

	/* Get the capabilities */
	if (capget(cap_header, cap_data) < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"failed capget error\n");
		goto hndl_return;
	}
	cap_data_pres = 1<<capability;
	if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "pid %d don't have"
				" %d capability.\n",
				pid, capability);
		goto hndl_return;
	}
	retval = true;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Set the scheduling priority of the VE process.
 *
 * @param[in] prio_req Pointer to struct ve_priority_req
 *
 * @return 0 on success, negative value on failure.
 */
int psm_rpm_handle_setpriority_req(struct ve_priority_req *prio_req)
{
	int retval = -1;
	int pid;
	struct ve_task_struct *tsk;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!prio_req)
		goto hndl_return;

	pid = prio_req->who;

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d is not found.\n",
				pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	if (!check_ve_proc_capability(pid, CAP_SYS_NICE)) {
		retval = -EPERM;
		goto hndl_return;
	}

	/* Request regarding PRIO_PROCESS is only handled by VEOS */
	if (prio_req->which == PRIO_PROCESS) {
		pthread_mutex_lock(&(tsk->ve_task_lock));
		tsk->priority = prio_req->val;
		pthread_mutex_unlock(&(tsk->ve_task_lock));
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid target received.\n");
		retval = -EINVAL;
		goto hndl_return;
	}
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will populate the fields of struct ve_pidstatinfo_req.
 *
 * @param[in] pid Pid of VE process
 * @param[out] pidstat Pointer to struct ve_pidstatinfo_req
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_pidstat_req(int pid, struct ve_pidstatinfo_req *pidstat)
{
	int retval = -1;
	struct timeval now;
	uint64_t time_diff = 0;
	struct ve_task_struct *tsk = NULL;
	float cpu_usage;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pidstat)
		goto hndl_return;

	memset(pidstat, 0, sizeof(struct ve_pidstatinfo_req));

	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found.\n", pid);
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
	case P_INVAL:
		pidstat->state = 'I';
		break;
	}

	/* Fields of struct ve_pidstatinfo_req like ppid, processor,
	 * priority, nice, policy are obtained directly from VE task
	 * struct.
	 */
	pidstat->ppid = tsk->parent->pid;
	pidstat->processor = tsk->p_ve_core->core_num;
	pidstat->priority = tsk->priority;
	pidstat->nice = tsk->priority - 20;
	pidstat->policy = tsk->policy;
	pidstat->utime = tsk->exec_time;
	pidstat->cutime = tsk->cexec_time;

	/* Calculate CPU usage by VE process */
	gettimeofday(&now, NULL);
	time_diff = timeval_diff(now, tsk->start_time);
	cpu_usage = ((float)tsk->exec_time/(float)time_diff) * 100;
	pidstat->pcpu = cpu_usage;

	/* Number of threads information is maintained in
	 * VE task struct.
	 */
	pidstat->threads = tsk->sighand->ref_count;

	/* TODO: Need to fill fields wchan, flags of struct
	 * ve_pidstatinfo_req.
	 */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will populate the fields pf struct ve_statinfo_req.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 * @param[out] statinfo Pointer to struct ve_statinfo_req
 *
 * @return 0 on success, -1 on failure.
 */
int psm_rpm_handle_stat_req(struct ve_node_struct *p_ve_node,
		struct ve_statinfo_req *statinfo)
{
	int retval = -1;
	int core_loop = 0;
	int64_t nr_switches;
	struct timeval now;
	uint64_t core_uptime;
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!p_ve_node || !statinfo)
		goto hndl_return;

	memset(statinfo, 0, sizeof(struct ve_statinfo_req));

	/* Core busy & idle values are populated in struct ve_statinfo_req */
	for (core_loop = 0; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
		p_ve_core = VE_CORE(veos_start_node_id, core_loop);
		gettimeofday(&now, NULL);
		core_uptime = timeval_diff(now, p_ve_core->core_uptime);
		statinfo->user[core_loop] = p_ve_core->busy_time;
		statinfo->nice[core_loop] = 0;
		statinfo->idle[core_loop] = core_uptime - p_ve_core->busy_time;
	}

	nr_switches = psm_calc_nr_context_switches(p_ve_node);
	if (-1 == nr_switches) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to get number of context switches\n");
		goto hndl_return;
	}
	statinfo->ctxt = nr_switches;
	statinfo->running = p_ve_node->nr_active;

	/* Assuming VE processes that are performing system call execution
	 * after MONC are in blocked state.
	 */
	statinfo->blocked = p_ve_node->num_ve_proc - p_ve_node->nr_active;

	statinfo->processes = p_ve_node->total_forks;
	statinfo->btime = p_ve_node->node_boot_time;
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Populate the VE process resource in struct ve_get_rusage_info.
 *
 * @param[in] pid PID of VE process
 * @param[out] ve_ru Pointer to struct ve_get_rusage_info
 *
 * @return 0 on success, -errno on failure
 */
int psm_rpm_handle_get_rusage_req(int pid, struct ve_get_rusage_info *ve_ru)
{
	int retval = -1;
	struct ve_rusage ve_r;
	struct ve_task_struct *tsk;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!ve_ru)
		goto hndl_return;

	/* Find the pointer of VE task struct from given pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	retval = psm_handle_get_rusage_request(tsk, RUSAGE_CHILDREN, &ve_r);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_get_rusage_request() fails\n");
		retval = -EFAULT;
		goto hndl_return;
	}

	ve_ru->ru_utime = ve_r.ru_stime;
	ve_ru->ru_maxrss = ve_r.ru_maxrss;

	/* TODO:
	 * Need to add handling for updating number of voluntary and
	 * non-voluntary context switches in case of RUSAGE_CHILDERN
	 */
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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
		struct ve_scheduler_parameter sched_param)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Check VE process have CAP_SYS_NICE capability to set the
	 * scheduling parameters.
	 */
	if (!check_ve_proc_capability(pid, CAP_SYS_NICE)) {
		retval = -EPERM;
		goto hndl_return;
	}

	/* Find the pointer of VE task struct from given pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	pthread_mutex_lock(&(tsk->ve_task_lock));
	tsk->policy = sched_param.policy;
	tsk->priority = sched_param.sp.sched_priority;
	pthread_mutex_unlock(&(tsk->ve_task_lock));
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
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

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found.\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"PID: %d found.\n", pid);
		retval = 0;
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will populate the struct ve_pidstatusinfo_req
 *
 * @param[in] pid Pid of VE process
 * @param[out] pidstatus Pointer to struct ve_pidstatusinfo_req
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_pidstatus(int pid, struct ve_pidstatusinfo_req *pidstatus)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!pidstatus)
		goto hndl_return;

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found.\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Populating values in struct ve_pidstatusinfo_req
	 * from VE task struct.
	 */
	pidstatus->nvcsw = tsk->nvcsw;
	pidstatus->nivcsw = tsk->nivcsw;

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will populate the struct ve_scheduler_parameter
 * for sched_get_scheduler request.
 *
 * @param[in] pid Pid of VE process
 * @param[out] sched_param Pointer to struct ve_scheduler_parameter
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_sched_get_scheduler(int pid,
		struct ve_scheduler_parameter *sched_param)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!sched_param)
		goto hndl_return;

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found.\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Scheduling policy is maintained in VE task struct */
	sched_param->policy = tsk->policy;
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will populate the struct ve_scheduler_parameter
 * for sched_get_param request.
 *
 * @param[in] pid Pid of VE process
 * @param[out] sched_param Pointer to struct ve_scheduler_parameter
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_sched_get_param(int pid,
		struct ve_scheduler_parameter *sched_param)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!sched_param)
		goto hndl_return;

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found.\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/* Scheduling priority is maintained in VE task struct */
	sched_param->sp.sched_priority = tsk->rt_priority;
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Function will fetch the VE process resource limit and populate
 * the struct ve_prlimitinfo.
 *
 * @param[in] pid Pid of VE process
 * @param[out] prlimit Pointer to struct ve_prlimitinfo
 *
 * @return 0 on success, -errno on failure.
 */
int psm_rpm_handle_prlimit(int pid, struct ve_prlimitinfo *prlimit)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!prlimit)
		goto hndl_return;

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	retval = psm_handle_get_rlimit_request(tsk,
			prlimit->resource, &(prlimit->old_lim));

	/* Set the new resource limit */
	if (true == prlimit->is_new_lim) {
		retval = psm_handle_set_rlimit_request(tsk, prlimit->resource,
				prlimit->new_lim);
		if (0 > retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to getrlimit pid: %d, resource: %d\n",
				pid, prlimit->resource);
			retval = -EPERM;
			goto hndl_return;
		}
	}
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Enable/disable to VE process accounting of a node.
 *
 * @param[in] pid Pid of VE process
 * @param[in] acct_file Path to accounting file
 *
 * @return 0 on success, -erno on failure.
 */
int psm_rpm_handle_acct(int pid, char *acct_file)
{
	int retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Find the VE task struct from pid */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID: %d not found\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	if (!check_ve_proc_capability(pid, CAP_SYS_PACCT)) {
		retval = -EPERM;
		goto hndl_return;
	}

	retval = psm_handle_do_acct_ve(acct_file);
	if (0 > retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"PSM fails to do accounting retval: %d\n", retval);
		goto hndl_return;
	}
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
