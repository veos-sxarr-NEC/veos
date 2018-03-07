#ifndef __PSM_RPM_INTERFACES_H
#define __PSM_RPM_INTERFACES_H
#include "veos_rpm_ipc.h"
#include "psm_task_mgmt.h"

bool check_ve_proc_capability(int, int);
int psm_rpm_handle_getpriority_req(struct ve_priority_req *);
int psm_rpm_handle_setpriority_req(struct ve_priority_req *);
int psm_rpm_handle_pidstat_req(int, struct ve_pidstatinfo_req *);
int psm_rpm_handle_stat_req(struct ve_node_struct *,
		struct ve_statinfo_req *);
int psm_rpm_handle_sched_set_scheduler(int, struct ve_scheduler_parameter);
int psm_rpm_handle_get_rusage_req(int, struct ve_get_rusage_info *);
int psm_rpm_handle_prlimit(int, struct ve_prlimitinfo *);
int psm_rpm_handle_sched_get_param(int, struct ve_scheduler_parameter *);
int psm_rpm_handle_sched_get_scheduler(int, struct ve_scheduler_parameter *);
int psm_rpm_handle_pidstatus(int, struct ve_pidstatusinfo_req *);
int psm_rpm_handle_check_pid(int);
int psm_rpm_handle_acct(int, char *);
#endif
