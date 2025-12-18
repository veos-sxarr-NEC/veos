/**
* Copyright (C) 2025 NEC Corporation
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
 * @file  psm_procinfo.c
 * @brief interfaces to get process information using procps-ng.
 *
 * @author PSMG
 */
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "psm_procinfo.h"
#include "locking_handler.h"
#ifndef USE_OPENPROC
#define PROCPS_RETRY_NUM 10
#endif

/**
 * @brief mutex lock to make sure readproc() is threadsafe
 *
 */
static pthread_mutex_t readproc_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef USE_OPENPROC
/**
 * @brief Get process information for a given process ID using the procps-ng.
 *
 * This function fetches detailed information about a process identified by its
 *  PID and stored informations to the provided `proc_t` structure.
 *
 * @param[in] pid The process ID of the target process.
 * @param[out] ve_proc_info Pointer to a `proc_t` structure where the process
 *              information will be stored.
 * @return Returns 0 on success, or -1 on failure.
 */
static int psm_get_proc_info_from_procps(pid_t pid, proc_t *ve_proc_info)
{
	int retval = -1;
	int ret = 0;
	unsigned int pidlist[1] = { pid };
	struct pids_info *info = NULL;
	struct pids_fetch *pids;
	struct pids_stack *stack = NULL;
	enum pids_item items[] = {
		PIDS_ID_TID,
		PIDS_ID_EUID, PIDS_ID_EGID,          //1: euid, 2: egid
		PIDS_ID_RUID, PIDS_ID_RGID,          //3: ruid, 4: rgid
		PIDS_ID_SUID, PIDS_ID_SGID,          //5: suid, 6: sgid
		PIDS_ID_FUID, PIDS_ID_FGID,          //7: fuid, 8: fgid
		PIDS_STATE,                           //9: state
		PIDS_NS_IPC, PIDS_NS_MNT,             //10: ns_ipc, 11: ns_mnt
		PIDS_NS_NET, PIDS_NS_PID,            //12: ns_net, 13: ns_pid
		PIDS_NS_USER, PIDS_NS_UTS            //14: ns_user, 15: ns_uts
		};
	enum rel_items {
		rel_tid,
		rel_euid, rel_egid,                  //1: euid, 2: egid
		rel_ruid, rel_rgid,                  //3: ruid, 4: rgid
		rel_suid, rel_sgid,                  //5: suid, 6: sgid
		rel_fuid, rel_fgid,                  //7: fuid, 8: fgid
		rel_state, rel_ns_ipc, rel_ns_mnt,   //9: state, 10: ns_ipc, 11: ns_mnt
		rel_ns_net, rel_ns_pid,              //12: ns_net, 13: ns_pid
		rel_ns_user, rel_ns_uts              //14: ns_user, 15: ns_uts
	};

	ret = procps_pids_new(&info, items, sizeof(items)/sizeof(items[0]));
	if (ret != 0) {
		VEOS_ERROR("failed to allocate pids_info for pid:%d : error code: %d",
			pid, ret);
		return -1;
	}
	/* Retry up to 10 times because procps_pids_select() fails sometime
	 * in the normal case.
	 */
	for (int i = 0; i < PROCPS_RETRY_NUM; i++) {
		pids = procps_pids_select(info, pidlist, 1, PIDS_SELECT_PID);
		if (!((pids == NULL) && (errno == ENOMEM)))
			break;
		if (i < (PROCPS_RETRY_NUM - 1)) {
			VEOS_DEBUG("failed to procps_pids_select for pid:%d : %s "
				"(%d times)", pid, strerror(errno), i + 1);
		} else {
			VEOS_ERROR("procps_pids_select failed for pid:%d after "
				"retries : %s ", pid, strerror(errno));
			retval = -1;
			goto hndl_unref;
		}
	}
	if (!pids) {
		VEOS_ERROR("procps_pids_select failed for pid:%d : %s ",
			pid, strerror(errno));
			retval = -1;
			goto hndl_unref;
	}
	if (!pids->counts || pids->counts->total == 0 || !pids->stacks
		|| !pids->stacks[0]) {
		VEOS_ERROR("procps returned empty stack/counts for pid:%d", pid);
		retval = -1;
		goto hndl_unref;
	}
	stack = pids->stacks[0];
	ve_proc_info->tid = PIDS_VAL(rel_tid, s_int, stack, info);
	ve_proc_info->euid = PIDS_VAL(rel_euid, u_int, stack, info);
	ve_proc_info->egid = PIDS_VAL(rel_egid, u_int, stack, info);
	ve_proc_info->ruid = PIDS_VAL(rel_ruid, u_int, stack, info);
	ve_proc_info->rgid = PIDS_VAL(rel_rgid, u_int, stack, info);
	ve_proc_info->suid = PIDS_VAL(rel_suid, u_int, stack, info);
	ve_proc_info->sgid = PIDS_VAL(rel_sgid, u_int, stack, info);
	ve_proc_info->fuid = PIDS_VAL(rel_fuid, u_int, stack, info);
	ve_proc_info->fgid = PIDS_VAL(rel_fgid, u_int, stack, info);
	ve_proc_info->state = PIDS_VAL(rel_state, s_ch, stack, info);
	ve_proc_info->ns[IPCNS] = PIDS_VAL(rel_ns_ipc, ul_int, stack, info);
	ve_proc_info->ns[MNTNS] = PIDS_VAL(rel_ns_mnt, ul_int, stack, info);
	ve_proc_info->ns[NETNS] = PIDS_VAL(rel_ns_net, ul_int, stack, info);
	ve_proc_info->ns[PIDNS] = PIDS_VAL(rel_ns_pid, ul_int, stack, info);
	ve_proc_info->ns[USERNS] = PIDS_VAL(rel_ns_user, ul_int, stack, info);
	ve_proc_info->ns[UTSNS] = PIDS_VAL(rel_ns_uts, ul_int, stack, info);
	retval = 0;
hndl_unref:
	ret = procps_pids_unref(&info);
	if (ret < 0) {
		VEOS_ERROR("failed to unref pids_info for pid:%d : %s",
				pid, strerror(-ret));
	}
	return retval;
}

/**
 * @brief Check if the pseudo process corresponding to the given VE process
 * is in STOP state or ZOMBIE state with all threads in STOP state.
 *
 * This function uses the procps library to fetch process information and
 * determine the state of the pseudo process.
 *
 * @param[in] pid The process ID of the VE process.
 * @return true if the pseudo process is in STOP state or ZOMBIE state with all
 *         threads in STOP state, false otherwise.
  */
static bool psm_is_pseudo_stop_from_procps(int pid)
{
	bool retval = false;
	int ret = 0;
	unsigned int pidlist[1] = { pid };
	struct pids_info *info = NULL;
	enum pids_item items[] = { PIDS_ID_TGID, PIDS_STATE, PIDS_NLWP };
	enum rel_items { rel_tgid, rel_state, rel_nlwp };
	struct pids_fetch *pids;
	int tgid = 0, nlwp = 0;
	char proc_stat = ' ', state = ' ';

	VEOS_TRACE("Entering");

	ret = procps_pids_new(&info, items, 3);
	if (ret != 0) {
		VEOS_DEBUG("failed to allocate pids_info for pid: %d : %s",
				pid, strerror(-ret));
		goto hndl_return;
	}
	/* Retry up to 10 times because procps_pids_select() fails sometime
	 * in the normal case.
	 */
	for (int i = 0; i < PROCPS_RETRY_NUM; i++) {
		pids = procps_pids_select(info, pidlist, 1, PIDS_SELECT_PID_THREADS);
		if (!((pids == NULL) && (errno == ENOMEM)))
			break;
		if (i < (PROCPS_RETRY_NUM - 1)) {
			VEOS_DEBUG("failed to procps_pids_select for pid:%d : %s "
				"(%d times)", pid, strerror(errno), i + 1);
		} else {
			VEOS_ERROR("procps_pids_select failed for pid:%d after "
				"retries : %s ", pid, strerror(errno));
			retval = false;
			goto hndl_unref;
		}
	}
	if (!pids) {
		VEOS_ERROR("failed to get process information for pid:%d : %s ",
			pid, strerror(errno));
		goto hndl_unref;
	}
	/* Get information of thread group leader */
	if(!pids->counts || !pids->stacks) {
		VEOS_ERROR("procps returned empty stack/counts for pid:%d", pid);
		goto hndl_unref;
	}
	for (int i = 0; i < pids->counts->total; i++) {
		if (pids->stacks[i] == NULL) {
			VEOS_DEBUG("failed to get stack for pid: %d", pid);
			goto hndl_unref;
		}
		tgid = PIDS_VAL(rel_tgid, s_int, pids->stacks[i], info);
		nlwp = PIDS_VAL(rel_nlwp, s_int, pids->stacks[i], info);
		proc_stat = PIDS_VAL(rel_state, s_ch, pids->stacks[i], info);
		if (tgid == pid)
			break;
	}

	/* Check if thread group leader is Stopped */
	if (proc_stat == 'T') {
		retval = true;
	} else if (proc_stat == 'Z' && nlwp > 1) {
		/* Check if thread group leader is zombie other threads
		 * are in Stop state then corresponding VE thread group
		 * threads also needs to be in stop state, hence
		 * return true if all threads are in stop state
		 */
		retval = true;
		for (int i = 0; i < pids->counts->total; i++) {
			if (pids->stacks[i] == NULL) {
				VEOS_DEBUG("failed to get stack for pid: %d", pid);
				retval = false;
				goto hndl_unref;
			}

			tgid = PIDS_VAL(rel_tgid, s_int, pids->stacks[i], info);
			state = PIDS_VAL(rel_state, s_ch, pids->stacks[i], info);
			if ((tgid != pid) && (state != 'T')) {
				retval = false;
				break;
			}
		}
	}
hndl_unref:
	ret = procps_pids_unref(&info);
	if (ret < 0) {
		VEOS_DEBUG("failed to unref pids_info for pid: %d : %s",
				pid, strerror(-ret));
	}
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the start time of a process using procps library.
 *
 * This function retrieves the start time of a process identified by its PID
 * and stores it in the provided `stime` pointer.
 *
 * @param[in] pid The process ID of the target process.
 * @param[out] stime Pointer to store the start time in microseconds.
 *
 * @return when the process terminated returns true, otherwise false.
 */
static bool psm_get_start_time_form_procps(pid_t pid, unsigned long long *stime)
{
	int ret = 0;
	bool retval = false;
	unsigned int pidlist[1] = { pid };
	struct pids_info *info = NULL;
	struct pids_fetch *pids;
	enum pids_item items[] = { PIDS_TICS_BEGAN };
	enum rel_items { rel_start_time };

	ret = procps_pids_new(&info, items, 1);
	if (ret != 0) {
		VEOS_DEBUG("failed to allocate pids_info for pid:%d : %s",
			pid, strerror(-ret));
		retval = true;
		goto hndl_return;
	}
	/* Retry up to 10 times because procps_pids_select() fails sometime
	 * in the normal case.
	 */
	for (int i = 0; i < PROCPS_RETRY_NUM; i++) {
		pids = procps_pids_select(info, pidlist, 1, PIDS_SELECT_PID);
		if (!((pids == NULL) && (errno == ENOMEM)))
			break;
		if (i < (PROCPS_RETRY_NUM - 1)) {
			VEOS_DEBUG("failed to get process information for pid:%d"
				" : %s (%d times)", pid, strerror(errno), i + 1);
		} else {
			VEOS_ERROR("failed to get process information for pid:%d"
				" after retries : %s ", pid, strerror(errno));
			retval = true;
			goto hndl_unref;
		}
	}
	if (!pids) {
		VEOS_ERROR("failed to get process information for pid:%d : %s ",
			pid, strerror(errno));
		retval = true;
		goto hndl_unref;
	}
	if (!pids->counts || pids->counts->total == 0 || !pids->stacks
		|| !pids->stacks[0]) {
		VEOS_ERROR("procps returned empty stack/counts for pid:%d", pid);
		retval = true;
		goto hndl_unref;
	}
	*stime = PIDS_VAL(rel_start_time, ull_int, pids->stacks[0], info);
hndl_unref:
	ret = procps_pids_unref(&info);
	if (ret < 0) {
		VEOS_ERROR("failed to unref pids_info for pid:%d : %s",
			pid, strerror(-ret));
		retval = false;
	}
hndl_return:
	return retval;
}
#endif

/**
 * @brief Get the /proc/## entry information for the given pid.
 *
 * @param[in] pid Pid of VE process
 * @param[out] ve_proc_info Pointer to struct proc_t
 *
 * @return 0 on success, -1 on failure.
 */
int psm_get_ve_proc_info(pid_t pid, proc_t *ve_proc_info)
{
	int retval = -1;
#ifdef USE_OPENPROC
	PROCTAB* proc = NULL;
	proc_t *proc_info = NULL;
#endif

	VEOS_TRACE("Entering");

	pthread_mutex_lock_unlock(&readproc_mutex, LOCK,
			"Failed to acquire readproc lock");
	if (!ve_proc_info) {
		VEOS_ERROR("Invalid proc info pointer");
		retval = -1;
		goto hndl_return;
	}
#ifdef USE_OPENPROC
	/* initialize process information from /proc/ */
	proc = openproc(PROC_FILLMEM|PROC_FILLSTAT|PROC_FILLSTATUS|PROC_PID|
			PROC_FILLNS, &pid);
	if (NULL == proc) {
		VEOS_ERROR("Fails to open proc interface for pid: %d", pid);
		goto hndl_return;
	}

	/* read the proc information */
	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		VEOS_ERROR("Fail to read proc information for pid: %d", pid);
		goto hndl_return1;
	}

	memcpy(ve_proc_info, proc_info, sizeof(proc_t));
	freeproc(proc_info);
	retval = 0;
hndl_return1:
	closeproc(proc);
#else
	if ((psm_get_proc_info_from_procps(pid, ve_proc_info)) != 0) {
		VEOS_ERROR("Failed to get proc info for pid: %d", pid);
		retval = -1;
		goto hndl_return;
	}
	retval = 0;
#endif
hndl_return:
	pthread_mutex_lock_unlock(&readproc_mutex, UNLOCK,
			"Failed to release readproc lock");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Check if the task is a zombie process and if its parent 'time' command
 * has already been terminated. If so, it can be safely removed.
 *
 * @param[in] tsk Pointer to the ve_task_struct of the task to check.
 *
 * @return true if the task can be safely removed, false otherwise.
 */
bool check_for_zombie_deletion(struct ve_task_struct *tsk)
{
	bool retval = false;
	unsigned long long ve_proc_start_time = 0, time_proc_start_time = 0;
	pid_t time_pid = tsk->real_parent_pid;

	VEOS_TRACE("Entering");

	/* Check if the task's parent 'time' process has already been terminated
	 * The task can be safely removed than
	 */
	if (kill(time_pid, 0) && errno == ESRCH) {
		VEOS_DEBUG("'time' command already terminated. Proceed for zombie cleanup");
		return true;
	}
	VEOS_DEBUG("'time' command already terminated and its pid(%d) has been recycled", time_pid);
	pthread_mutex_lock_unlock(&readproc_mutex, LOCK,
			"Failed to acquire readproc lock");
#ifdef USE_OPENPROC
	PROCTAB* proc = NULL;
	proc_t *proc_info = NULL;
	/* initialize process information from /proc/ */
	proc = openproc(PROC_FILLSTAT, &time_pid);
	if (NULL == proc) {
		VEOS_DEBUG("Fails to open proc interface for 'time' pid: %d", time_pid);
		retval = true;
		goto hndl_return;
	}

	/* read the proc information */
	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		VEOS_DEBUG("Fail to read proc information for 'time' pid: %d", time_pid);
		retval = true;
		goto hndl_return1;
	}

	time_proc_start_time = proc_info->start_time;
	freeproc(proc_info);
#else
	retval = psm_get_start_time_form_procps(time_pid, &time_proc_start_time);
	if (retval == true) {
		VEOS_DEBUG("Failed to get start time for 'time' pid: %d", time_pid);
		goto hndl_return;
	}
#endif
	ve_proc_start_time = (unsigned long long)tsk->start_time.tv_sec;
	VEOS_DEBUG("'time' command start time = %llu", time_proc_start_time);
	VEOS_DEBUG("zombie process start time = %llu", ve_proc_start_time);

	if (time_proc_start_time > ve_proc_start_time)
		retval = true;
	VEOS_DEBUG("Found zombie task pid = %d", tsk->pid);
#ifdef USE_OPENPROC
hndl_return1:
	closeproc(proc);
#endif
hndl_return:
	pthread_mutex_lock_unlock(&readproc_mutex, UNLOCK,
			"Failed to release readproc lock");
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief This Function check the state of the pseudo process corresponding to
 * given VE process. If the state of the pseudo process is in ZOMBIE('Z') state
 * then check the state of its threads in the thread group.
 *
 * @param[in] pid Pid of VE process
 *
 * @return true If pseudo process state corresponding to VE process is STOP('T')
 *         or pseudo process is in ZOMBIE('Z') state and all its threads
 *         are in 'T' state.
 *         false In case of failure.
 *
 * @internal
 * @author Signal Handling
 * */
bool is_pseudo_stop(pid_t pid)
{
	bool retval = false;
#ifdef USE_OPENPROC
	PROCTAB* proc = NULL;
	proc_t *proc_info = NULL, *task_info = NULL;
#endif

	VEOS_TRACE("Entering");

	pthread_mutex_lock_unlock(&readproc_mutex, LOCK,
			"Failed to acquire readproc lock");

#ifdef USE_OPENPROC
	/* initialize process information from /proc/ */
	proc = openproc(PROC_FILLMEM|PROC_FILLSTAT|PROC_FILLSTATUS|PROC_PID|
			PROC_FILLNS, &pid);
	if (NULL == proc) {
		VEOS_DEBUG("Fails to open proc interface for pid: %d", pid);
		goto hndl_return;
	}

	/* read the proc information */
	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		VEOS_DEBUG("Fail to read proc information for pid: %d", pid);
		goto hndl_return1;
	}

	/* Check if thread group leader is Stopped */
	if ('T' == proc_info->state) {
		retval = true;
	}
	/* Check if thread group leader is zombie other threads
	 * is in Stop state then corresponding
	 * VE thread group threads also needs to be in stop state, hence
	 * return true
	 */
	else if ('Z' == proc_info->state && proc_info->nlwp > 1) {
		task_info = readtask(proc, proc_info, NULL);
		if (task_info != NULL) {
			freeproc(task_info);
			/* Read the task info for the other thread of the thread group */
			task_info = readtask(proc, proc_info, NULL);
			if (task_info != NULL) {
				if ('T' == task_info->state)
					retval = true;
				freeproc(task_info);
			} else
				VEOS_DEBUG("Fail to read task information of "
					"other threads for pid: %d", pid);
		} else {
			VEOS_DEBUG("Fail to read task information of other task for pid: %d", pid);
		}
	}

	freeproc(proc_info);
hndl_return1:
	closeproc(proc);
hndl_return:
#else
	retval = psm_is_pseudo_stop_from_procps(pid);
#endif
	pthread_mutex_lock_unlock(&readproc_mutex, UNLOCK,
			"Failed to release readproc lock");
	VEOS_TRACE("Exiting");
	return retval;
}
