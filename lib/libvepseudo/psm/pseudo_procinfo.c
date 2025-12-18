/*
 * Copyright (C) 2025 NEC Corporation
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
* @file pseudo_procinfo.c
* @brief interfaces to get process information using procps-ng.
*
* @internal
* @author PSMG
*/
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#ifdef USE_OPENPROC
#include <proc/readproc.h>
#else
#include <libproc2/pids.h>
#endif
#include "sys_common.h"
#include "pseudo_procinfo.h"

#ifndef USE_OPENPROC
#define PROCPS_RETRY_NUM 10
#endif

static pthread_mutex_t readproc_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef USE_OPENPROC
/**
 * @brief Get the process status from procps library.
 *
 * This function retrieves the status of a process identified by its PID
 * using the procps library.
 *
 * @param pid The process ID of the target process.
 * @param status Pointer to store the process status character.
 *
 * @return 0 on success, -1 on failure, 1 if the process is terminated.
 */
static int pseudo_get_proc_status_from_procps(pid_t pid, char *status)
{
	char path[PATH_MAX] = "";
	struct stat st;
	int ret = 0;
	unsigned int pidlist[1] = { pid };
	struct pids_info *info = NULL;
	struct pids_fetch *pids;
	enum pids_item items[] = { PIDS_STATE };
	enum rel_items { rel_state };

	ret = procps_pids_new(&info, items, 1);
	if (ret != 0) {
		PSEUDO_ERROR("failed to allocate pids_info for pid:%d : %s",
			pid, strerror(-ret));
		return -1;
	}
	/* Retry up to 10 times because procps_pids_select() fails sometime
	 * in the normal case.
	 */
	for (int i = 0; i < PROCPS_RETRY_NUM; i++) {
		pids = procps_pids_select(info, pidlist, 1, PIDS_SELECT_PID);
		if (!((pids == NULL) && (errno == ENOMEM)))
			break;
		PSEUDO_DEBUG("failed to procps_pids_select for pid:%d : %s "
			"(%d times)", pid, strerror(errno), i + 1);
	}
	if (!pids || !pids->counts || pids->counts->total == 0 || !pids->stacks
		|| !pids->stacks[0]) {
		PSEUDO_DEBUG("Failed to get process information for pid:%d : %s",
				pid, strerror(errno));
		ret = procps_pids_unref(&info);
		if (ret < 0) {
			PSEUDO_ERROR("failed to unref pids_info for pid:%d : %s",
				pid, strerror(-ret));
			return -1;
		}
		snprintf(path, PATH_MAX, "/proc/%d/stat", pid);
		if (stat(path, &st) != 0) {
			if (errno == ENOENT) {
				PSEUDO_DEBUG("PID:%d may be terminated", pid);
				return 1;
			}
		}
		return -1;
	}
	*status = PIDS_VAL(rel_state, s_ch, pids->stacks[0], info);
	ret = procps_pids_unref(&info);
	if (ret < 0) {
		PSEUDO_ERROR("failed to unref pids_info for pid:%d : %s",
			pid, strerror(-ret));
		return -1;
	}
	return 0;
}

/**
 * @brief Check if the pseudo process corresponding to the given VE process
 * has exited prematurely.
 *
 * This function uses the procps library to check if the pseudo process has
 * exited or is in a zombie state.
 *
 * @param pid Pid of VE process
 *
 * @return 0 if the pseudo process is alived, -1 if it has exited or zombie.
 */
static int pseudo_is_child_exit_from_procps(pid_t pid)
{
	int ret = 0;
	int retval = -1;
	unsigned int pidlist[1] = { pid };
	struct pids_fetch *pids;
	struct pids_info *info = NULL;
	enum pids_item items[] = { PIDS_STATE };
	enum rel_items { rel_state };

	ret = procps_pids_new(&info, items, 1);
	if (ret != 0) {
		PSEUDO_DEBUG("failed to allocate pids_info for pid:%d : %s",
			pid, strerror(-ret));
		return retval;
	}
	/* Retry up to 10 times because procps_pids_select() fails sometime
	 * in the normal case.
	 */
	for (int i = 0; i < PROCPS_RETRY_NUM; i++) {
		pids = procps_pids_select(info, pidlist, 1, PIDS_SELECT_PID);
		if (!((pids == NULL) && (errno == ENOMEM)))
			break;
		if (i < (PROCPS_RETRY_NUM - 1)) {
			PSEUDO_DEBUG("failed to select pids_info for pid:%d : "
			"%s (%d times)", pid, strerror(errno), i + 1);
		} else {
			PSEUDO_ERROR("failed to select pids_info for pid:%d "
				"after retries : %s", pid, strerror(errno));
			goto handle_unref;
		}
	}
	if (!pids) {
		PSEUDO_ERROR("failed to select pids_info for pid:%d : %s",
			pid, strerror(errno));
		goto handle_unref;
	}
	if (!pids->counts || pids->counts->total == 0 || !pids->stacks
		|| !pids->stacks[0]) {
		PSEUDO_DEBUG("procps returned empty stack/counts for pid:%d", pid);
		goto handle_unref;
	}
	if (PIDS_VAL(rel_state, s_ch, pids->stacks[0], info) == 'Z') {
		PSEUDO_DEBUG("VH process has become zombie");
		goto handle_unref;
	}
	retval = 0;
handle_unref:
	ret = procps_pids_unref(&info);
	if (ret < 0) {
		PSEUDO_ERROR("failed to unref pids_info for pid:%d : %s",
			pid, strerror(-ret));
		retval = -1;
	}
	return retval;
}
#endif /* USE_OPENPROC */

/**
 * @brief Get the process status of a given pid.
 *
 * @param pid Process ID to get the status for.
 * @param status Pointer to a character where the status will be stored.
 *
 * @return 0 on success, -1 on failure, return 1 when pid is not found.
 */
int get_proc_status(pid_t pid, char *status)
{
#ifdef USE_OPENPROC
	char path[PATH_MAX] = "";
	struct stat st;
	PROCTAB* proc = NULL;
	proc_t *procinfo = NULL;

	proc = openproc(PROC_FILLSTAT | PROC_PID, &pid);
	if (proc == NULL) {
		PSEUDO_DEBUG("failed to open proc interface for pid:%d", pid);
		snprintf(path, PATH_MAX, "/proc/%d/stat", pid);
		if (stat(path, &st) != 0) {
			if (errno == ENOENT) {
				PSEUDO_DEBUG("PID:%d may be terminated", pid);
				return 1;
			}
		}
		return -1;
	}
	procinfo = readproc(proc, NULL);
	if (procinfo == NULL) {
		PSEUDO_DEBUG("failed to read proc info for pid:%d", pid);
		return -1;
	}
	*status = procinfo->state;
	freeproc(procinfo);
	closeproc(proc);
	return 0;
#else
	return pseudo_get_proc_status_from_procps(pid, status);
#endif
}

/**
 *  @brief Checks that Process is alive or not by accessing proc interface
 *
 *  @param[in] pid of process whose proc entry is to be read.
 *
 *  @return -1 if task state of process has become ZOMBIE or readproc()
 *  fails for "pid", else 0 is returned if process is alive.
 */
int ve_premature_child_exit(pid_t pid)
{
	int retval = -1;
	int locked;

	locked = pthread_mutex_lock(&readproc_mutex);
	if (0 != locked) {
		PSEUDO_DEBUG("Failed to acquire read proc lock: %s",
				strerror(locked));
		goto handle_failure;
	}
#ifdef USE_OPENPROC
	PROCTAB* proc;
	proc_t *proc_info;

	proc = openproc(PROC_FILLSTAT|PROC_PID, &pid);
	if (NULL == proc) {
		PSEUDO_DEBUG("Fails to open proc interface for pid: %d", pid);
		goto handle_error;
	}

	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		PSEUDO_DEBUG("Fail to read proc information for pid: %d", pid);
		closeproc(proc);
		goto handle_error;
	}

	if (proc_info->state == 'Z') {
		PSEUDO_DEBUG("VH process has become zombie");
		freeproc(proc_info);
		closeproc(proc);
		goto handle_error;
	}
	freeproc(proc_info);
	closeproc(proc);
	retval = 0;
handle_error:
#else
	retval = pseudo_is_child_exit_from_procps(pid);
#endif
	locked = pthread_mutex_unlock(&readproc_mutex);
	if (0 != locked) {
		PSEUDO_DEBUG("Failed to release read proc lock: %s",
				strerror(locked));
		retval = -1;
	}

handle_failure:
	return retval;
}
