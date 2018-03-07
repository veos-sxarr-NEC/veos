#ifndef __VEOS_RPM_IPC_H
#define __VEOS_RPM_IPC_H
#include <stdbool.h>
#include "veos_ipc.h"
#include "veos.h"

/**
 * @brief RPM sub commands
 */
enum veos_rpm_subcmd {
	VE_GETPRIORITY = 0,
	VE_SETPRIORITY,
	VE_CHECKPID,
	VE_MEM_INFO,
	VE_MAP_INFO,
	VE_PIDSTAT_INFO,
	VE_PIDSTATM_INFO,
	VE_PIDSTATUS_INFO,
	VE_LOAD_INFO,
	VE_STAT_INFO,
	VE_VMSTAT_INFO,
	VE_GET_RUSAGE,
	VE_SCHED_GET_SCHEDULER,
	VE_SCHED_SET_SCHEDULER,
	VE_SCHED_GET_PARAM,
	VE_GET_PRIORITY_MAX,
	VE_GET_PRIORITY_MIN,
	VE_SET_AFFINITY,
	VE_GET_AFFINITY,
	VE_PRLIMIT,
	VE_ACCTINFO,
	VE_RPM_INVALID = -1
};

/**
 * @brief Structure to set/get the nice value of VE process
 */
struct ve_priority_req {
	int which; /*!< Target VE process */
	int who; /*!< Target VE process, interpreted from the value of argument ‘which’ */
	int val; /*!< Nice value to be set */
};

/**
 * @brief Structure to get the memory data of VE node
 */
struct ve_mem_info_request {
	unsigned long kb_main_total; /*!< Total usable RAM */
	unsigned long kb_main_used; /*!< Total used RAM (kb_main_total - kb_main_free) */
	unsigned long kb_main_free; /*!< Total free memory */
	unsigned long kb_main_shared; /*!< Total shared memory size */
	unsigned long kb_main_cached; /*!< In-memory cache for files read from the disk */
	unsigned long kb_low_total; /*!< Total low memory size */
	unsigned long kb_low_free; /*!< Available free memory size */
	unsigned long kb_high_total; /*!< Total high memory size */
	unsigned long kb_high_free; /*!< Available high memory size */
};

/**
 * @brief Structure to get memory map of VE process
 */
struct ve_mapinfo_request {
	unsigned long long start; /*!< Starting  virtual  address  of  each  mapping */
	unsigned long long end; /*!< End  virtual  address  of  each  mapping */
	char perms[32]; /*!< Permissions on map */
	unsigned long long offset; /*!< Offset into the file */
	unsigned long long inode; /*!< Inode number of the device */
	unsigned int dev_major; /*!< Major number of device */
	unsigned int dev_minor; /*!< Minor number of device */
	char map_desc[128]; /*!< Name of the file backing the map */
	unsigned long long size; /*!< Size of the process virtual address space mapping */
	unsigned long long rss; /*!< Resident set size */
	unsigned long long pss; /*!< Proportional Set Size */
	unsigned long long shared_clean; /*!< Shared Pages not modified since they were mapped */
	unsigned long long anonymous; /*!< Amount of memory that does not belong to any file */
	unsigned long long anon_hugepage; /*!< Anonymous pages */
	unsigned long long mmu_pagesize; /*!< MMU page size */
	unsigned long long locked; /*!< Number of pages locked within the mapping */
	unsigned long long page_size; /*!< Page size */
	unsigned long long referenced; /*!< Amount of memory currently marked as referenced */
};

/**
 * @brief Structure to get VE process detailed information
 */
struct ve_pidstatinfo_req {
	char state; /*!< Process state (running, sleeping, stopped, zombie) */
	int ppid; /*!< Parent Process ID */
	int processor; /*!< Which CPU task is scheduled on */
	long priority; /*!< Scheduling priority */
	long nice; /*!< Nice level */
	unsigned int policy; /*!< Scheduling policy */
	float pcpu; /*!< CPU usage */
	unsigned long long utime; /*!< CPU time accumulated by process */
	unsigned long long cutime; /*!< Cumulative utime of process and reaped children */
	unsigned long long wchan; /*!< Address where VE process went to sleep */
	unsigned long flags; /*!< Task flags */
	int threads; /*!< Number of threads */
	unsigned long vsize; /*!< Process's virtual memory size */
	unsigned long rsslim; /*!< Current limit in bytes on the rss */
	unsigned long startcode; /*!< Address above which program text can run */
	unsigned long endcode; /*!< Address below which program text can run */
	unsigned long startstack; /*!< Address of the start of the stack */
	unsigned long kstesp; /*!< Current value of ESP  */
	unsigned long ksteip; /*!< Current value of EIP   */
	long rss; /*!< resident set memory size   */
	unsigned long long blkio; /*!< time spent waiting for block IO */
};

/**
 * @brief Structure to get memory statistics of VE process
 */
struct ve_pidstatminfo_req {
	long size; /*!< Total program size (as # pages) */
	long resident; /*!< Resident non-swapped memory (as # pages) */
	long share; /*!< Shared (mmap'd) memory (as # pages) */
	long trs; /*!< Text (exe) resident set (as # pages) */
	long drs; /*!< Data+stack resident set (as # pages) */
};

/**
 * @brief Structure to get VE process detailed information
 */
struct ve_pidstatusinfo_req {
	unsigned long nvcsw; /*!< Total number of voluntary context switches */
	unsigned long nivcsw; /*!< Total number of non-voluntary context switches */
};

/**
 * @brief Structure to get VE node load information
 */
struct ve_load_req {
	double av_1; /*!< Load average of last 1 minute */
	double av_5; /*!< Load average of last 5 minutes */
	double av_15; /*!< Load average of last 15 minutes */
	int runnable; /*!< Number of runnable processes and threads on VE node */
	int total_proc; /*!< Total processes and threads on VE node */
};

/**
 * @brief Structure to get overall information about VE processes
 */
struct ve_statinfo_req {
	unsigned long long user[VE_MAX_CORE_PER_NODE]; /*!<
							* Amount of time CPU spent
							* executing normal processes
							* in user mode
							*/
	unsigned long long nice[VE_MAX_CORE_PER_NODE]; /*!<
							* Amount of time CPU spent
							* executing niced processes
							* in user mode
							*/
	unsigned long long idle[VE_MAX_CORE_PER_NODE]; /*!<
							* Amount of time CPU spent
							* executing twiddling thumbs
							*/
	unsigned int ctxt; /*!< The total number of context switches across all CPUs */
	unsigned int running; /*!< The total number of runnable threads */
	unsigned int blocked; /*!< The number of processes currently blocked, waiting for I/O to complete */
	unsigned int btime; /*!< The time at which the VE nodes were booted */
	unsigned int processes; /*!< The number of processes and threads created */
};

/**
 * @brief Structure to get overall information about VE processes
 */
struct ve_vmstat_request {
	unsigned long pgfree; /*!< Number of pages placed on the free list by the system per second */
	unsigned long pgscan_direct; /*!< Number of pages scanned directly per second. */
	unsigned long pgsteal; /*!< Number of pages the system has reclaimed from cache */
};

/**
 * @brief Structure to get the nice value of VE process
 */
struct ve_get_rusage_info {
	struct timeval ru_utime; /*!< user CPU time used */
	long ru_maxrss; /*!< maximum resident set size */
	long ru_nvcsw; /*!< voluntary context switches */
	long ru_nivcsw; /*!< involuntary context switches */
};

/**
 * @brief Data structure used to set/get scheduler parameters
 */
struct ve_scheduler_parameter {
	int policy; /*!< Scheduling policy */
	struct sched_param sp; /*!< Structure to set/get priority of given process */
};

/**
 * @brief Structure to get priority limit corresponding to policy
 */
struct ve_sched_limit_request {
	int policy; /*!< policy corresponding to which, we need priority limit */
	int retval; /*!< return value(max/min limit) */
};

/**
 * @brief Data structure used to get/set CPU affinity
 */
struct ve_sched_affinity {
	size_t cpusetsize; /*!< specifies the size (in bytes) of mask */
	uint64_t mask; /*!< To get/set CPU mask */
};

/**
 * @brief Data structure used to get/set the resource limit (hard and soft) of VE process
 */
struct ve_prlimitinfo {
	int resource; /*!< Resource argument can be Address space, CPU time, FSIZE, locks etc.*/
	bool is_new_lim; /*!< Specify new limit to set or not */
	struct rlimit new_lim; /*!< New values for the soft and hard limits for resource. */
	struct rlimit old_lim;/*!<
				* Successful call to prlimit() places the previous soft and hard
				* limits for resource in the rlimit structure pointed to by old_limit
				*/
};

int veos_write_buf(int, void *, int);
void veos_rpm_send_cmd_ack(int, uint8_t *, int64_t, int64_t);
int rpm_handle_getpriority_req(struct veos_thread_arg *);
int rpm_handle_setpriority_req(struct veos_thread_arg *);
int rpm_handle_checkpid_req(struct veos_thread_arg *);
int rpm_handle_mem_info_req(struct veos_thread_arg *);
int rpm_handle_map_info_req(struct veos_thread_arg *);
int rpm_handle_pidstat_info_req(struct veos_thread_arg *);
int rpm_handle_pidstatm_info_req(struct veos_thread_arg *);
int rpm_handle_pidstatus_info_req(struct veos_thread_arg *);
int rpm_handle_load_req(struct veos_thread_arg *);
int rpm_handle_stat_req(struct veos_thread_arg *);
int rpm_handle_vmstat_info_req(struct veos_thread_arg *);
int rpm_handle_get_rusage_req(struct veos_thread_arg *);
int rpm_handle_sched_get_scheduler_req(struct veos_thread_arg *);
int rpm_handle_sched_set_scheduler_req(struct veos_thread_arg *);
int rpm_handle_sched_get_param_req(struct veos_thread_arg *);
int rpm_handle_get_priority_max_req(struct veos_thread_arg *);
int rpm_handle_get_priority_min_req(struct veos_thread_arg *);
int rpm_handle_set_affinity_req(struct veos_thread_arg *);
int rpm_handle_get_affinity_req(struct veos_thread_arg *);
int rpm_handle_prlimit_req(struct veos_thread_arg *);
int rpm_handle_acctinfo_req(struct veos_thread_arg *);
#endif
