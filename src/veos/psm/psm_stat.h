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
 * @file psm_stat.h
 * @brief PSM interfaces for handling RPM request for VE.
 *
 * @internal
 * @author PSM
 */
#ifndef __PSM_RPM_INTERFACES_H
#define __PSM_RPM_INTERFACES_H
#include "rpm_comm.h"
#include "task_mgmt.h"

#define PRIO_MASK 20
bool check_ve_proc_capability(int, int);
int psm_rpm_handle_getpriority_req(struct ve_priorityinfo *);
int psm_rpm_handle_setpriority_req(struct ve_priorityinfo *);
int psm_rpm_handle_pidstat_req(int, struct velib_pidstat *);
int psm_rpm_handle_stat_req(struct ve_node_struct *,
		struct velib_statinfo *);
int psm_rpm_handle_sched_set_scheduler(int, struct velib_setscheduler);
int psm_rpm_handle_get_rusage_req(int, struct velib_get_rusage_info *);
int psm_rpm_handle_prlimit(int, int, struct velib_prlimit *, struct veos_thread_arg *);
int psm_rpm_handle_sched_get_param(int, struct sched_param *);
int psm_rpm_handle_sched_get_scheduler(int, struct velib_setscheduler *);
int psm_rpm_handle_pidstatus(int, struct velib_pidstatus *);
int psm_rpm_handle_check_pid(int);
int psm_rpm_handle_acct(int, char *);
int psm_rpm_handle_stat_req_v3(struct ve_node_struct *,
		struct velib_statinfo_v3 *);
int64_t psm_rpm_handle_veosctl_get_req(struct ve_veosctl_stat *sched_param);
int64_t psm_rpm_handle_veosctl_set_req(struct ve_veosctl_stat sched_param);
#endif
