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
 * @file  rpm_comm.c
 * @brief This file contains the functions which are responsible for
 * handling RPM request
 *
 * @author PSMG
 */
#ifndef __VEOS_RPM_IPC_H
#define __VEOS_RPM_IPC_H
#include <stdbool.h>
#include "veos_handler.h"
#include "veos.h"
#define VMFLAGS_LENGTH  81
#define VE_MAX_REGVALS  64
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
	VE_CREATE_PROCESS,
	VE_SHM_RMLS,
	VE_GET_REGVALS,
	VE_RPM_INVALID = -1
};

/**
* @brief This enumration will used to decide option for ipcrm command.
*/
enum ipc_mode {
	SHMKEY = 0,	/*!< Delete shm segment having this key*/
	SHMID,		/*!< Delete shm segment having this shmid */
	SHM_ALL,	/*!< Delete all shm segment*/
	SHMID_INFO,	/*!< Give infomation of specific shm segment*/
	SHM_LS,		/*!< List All segment*/
	SHM_SUMMARY,	/*!< Summary of share Memory*/
	SHMID_QUERY,	/*!< Query whether shmid is valid or not*/
	SHMKEY_QUERY,	/*!< Query whether shmkey is valid or not*/
};

/**
 * @brief Structure to provide summary of shared memory present on veos.
 */
struct shm_summary {
	int used_ids;
	ulong shm_tot;          /* total allocated shm */
	ulong shm_rss;          /* total resident shm */
};


/**
* @brief Structure to provide shared memory information present on veos.
*/
typedef struct ve_shm_data {
	int             id;
	key_t           key;
	uid_t           uid;	/* current uid */
	gid_t           gid;    /* current gid */
	uid_t           cuid;   /* creator uid */
	gid_t           cgid;   /* creator gid */
	unsigned int    mode;   /*Permissions + SHM_DEST*/
	uint64_t        shm_nattch; /*No. of current attaches*/
	uint64_t        shm_segsz;	/*Size of segment (bytes)*/
	int64_t         shm_atim;       /*Last attach time*/
	int64_t         shm_dtim;	/*Last detach time*/
	int64_t         shm_ctim;	/*Last change time*/
	pid_t           shm_cprid;	/*PID of creator*/
	pid_t           shm_lprid;	/*PID of last shmat(2)/shmdt(2)*/
	uint64_t        shm_rss;	/*resident shared memory*/
	uint64_t	shm_swp;	/*swaped memory*/
} sdata_t;

/**
* @brief Structure to provide information of deleted shm segment.
*/
typedef struct ipcrm_info {
	int shmid;	/*!< shmid of deleted shm segment*/
	int shm_errno;	/*!< error occured while deleting the segment*/
} sinfo_t;
/**
* @brief Structure to provide info to remove shared memory from VEOS.
*/
struct ve_shm_info {
       int mode;
	/*!< SHMKEY = 0,	-Delete shm segment having this key*/
	/*!< SHMID,		-Delete shm segment having this shmid */
	/*!< SHM_ALL,		-Delete all shm segment*/
	/*!< SHMID_INFO,	-Give infomation of specific shm segment*/
	/*!< SHM_LS,		-List All segment*/
	/*!< SHM_SUMMARY,	-Summary of share Memory*/
	/*!< SHMID_QUERY,	-Query whether shmid is valid or not*/
	/*!< SHMKEY_QUERY,	-Query whether shmkey is valid or not*/

       int key_id; /*shmkey or shmid of segment to be delete*/
};

/**
 * @brief Structure to set/get the nice value of VE process
 */
struct ve_priorityinfo {
	int which; /*!< Target VE process */
	int who; /*!< Target VE process, interpreted from the value of argument ‘which’ */
	int niceval; /*!< Nice value to be set */
};

/**
 * @brief Structure to get the memory data of VE node
 */
struct velib_meminfo {
	unsigned long kb_main_total;	/*!< Total usable RAM */
	unsigned long kb_main_used;	/*!< Total used RAM
					 * (kb_main_total - kb_main_free) */
	unsigned long kb_main_free;	/*!< Total free memory */
	unsigned long kb_main_shared;	/*!< Total shared memory size */
	unsigned long kb_hugepage_used; /*!< Total memory used by Huge page*/
};


/**
 * @brief Structure to get shared memory ID and data specific information for VEOS
 */
struct ve_mapheader {
	unsigned int length;	/*!< Shared memory segment length */
	int shmid;		/*!< Shared memory identifier */
};

/**
 * @brief Structure to get memory map of VE process
 */
struct ve_mapinfo {
	unsigned long long start;		/*!<
						 * Starting virtual address of
						 * each mapping
						 */
	unsigned long long end;			/*!<
						 * End  virtual address of each
						 * mapping
						 */
	char perms[32];				/*!< Permissions on map */
	unsigned long long offset;		/*!< Offset into the file */
	unsigned long long inode;		/*!< Inode number of the device */
	unsigned int dev_major;			/*!< Major number of device */
	unsigned int dev_minor;			/*!< Minor number of device */
	char map_desc[128];			/*!< Name of the file backing
						 * the map
						 */
	unsigned long long size;		/*!<
						 * Size of the process virtual
						 * address space mapping
						 */
	unsigned long long rss;			/*!< Resident set size */
	unsigned long long pss;			/*!< Proportional Set Size */
	unsigned long long shared_dirty;	/*!<
						 * Shared Pages modified since
						 * they were mapped
						 */
	unsigned long long private_dirty;	/*!<
						 * Private Pages modified since
						 * they were mapped
						 */
	unsigned long long shared_clean;	/*!<
						 * Shared Pages not modified
						 * since they were mapped
						 */
	unsigned long long private_clean;	/*!<
						 * Private Pages not modified
						 * since they were mapped
						 */
	unsigned long long referenced;		/*!<
						 * Amount of memory currently
						 * marked as referenced
						 */
	unsigned long long anonymous;		/*!<
						 * Amount of memory that does
						 * not belong to any file
						 */
	unsigned long long anon_hugepage;	/*!< Anonymous pages */
	unsigned long long swap;		/*!< Swap memory */
	unsigned long long mmu_pagesize;	/*!< MMU page size */
	unsigned long long locked;		/*!<
						 * Number of pages locked within
						 * the mapping
						 */
	unsigned long long pagesize;		/*!< Page size */
	char vmflags[VMFLAGS_LENGTH];		/*!<
						 * Flags associated with the
						 * mapping
						 */
};

/**
 * @brief Structure to get VE process detailed information
 */
struct velib_pidstat {
	char state;			/*!<
					 * Process state
					 * (running, sleeping, stopped, zombie)
					 */
	int ppid;			/*!< Parent Process ID  */
	int processor;			/*!< Core on which task is scheduled on */
	long priority;			/*!< Scheduling priority */
	long nice;			/*!< Nice level */
	unsigned int policy;		/*!< Scheduling policy */
	unsigned long long utime;	/*!< CPU time accumulated by process */
	unsigned long long cutime;
	unsigned long flags;		/*!< Task flags */
	unsigned long vsize;		/*!< Process's virtual memory size */
	unsigned long rsslim;		/*!< Current limit in bytes on the rss */

	unsigned long startcode;	/*!<
					 * Address above which program text can run
					 */
	unsigned long endcode;		/*!< * Address below which program text can run
					 */
	unsigned long startstack;	/*!< Address of the start of the stack */
	unsigned long kstesp;		/*!< Current value of ESP */
	unsigned long ksteip;		/*!< Current value of EIP */
	long rss;			/*!< Resident set size   */
	char cmd[255];			/*!< Only command name without path */
	unsigned long start_time;       /*!< Start time of VE process */
	bool whole;                     /*!< Flag for single thread (0) or
					  the whole thread group (1) */
};

/**
 * @brief Structure to get memory statistics of VE process
 */
struct velib_pidstatm {
	long size; /*!< Total program size (as # pages) */
	long resident; /*!< Resident non-swapped memory (as # pages) */
	long share; /*!< Shared (mmap'd) memory (as # pages) */
	long trs; /*!< Text (exe) resident set (as # pages) */
	long drs; /*!< Data+stack resident set (as # pages) */
};

/**
 * @brief Structure to get VE process detailed information
 */
struct velib_pidstatus {
	unsigned long nvcsw;	/*!<
				 * Total number of voluntary context
				 * switches task made per second
				 */
	unsigned long nivcsw;	/*!<
				 * Total number of non-voluntary context
				 * switches task made per second
				 */
        char cmd[255];                  /*!< Only command name without path */
	unsigned long long pending;		/*!< pending signals for VE task */
	unsigned long long blocked;		/*!< blocked signals for VE task */
	unsigned long long ignored;		/*!< signal with ignore disposition */
	unsigned long long caught;		/*!< signal with changed default action */
};
/**
 * @brief Structure to get VE node load information
 */
struct ve_loadavg {
	double av_1; /*!< Load average of last 1 minute */
	double av_5; /*!< Load average of last 5 minutes */
	double av_15; /*!< Load average of last 15 minutes */
	int runnable; /*!< Number of runnable processes and threads on VE node */
	int total_proc; /*!< Total processes and threads on VE node */
};

/**
 * @brief Structure to get overall information about VE processes
 */
struct velib_statinfo {
	unsigned long long user[VE_MAX_CORE_PER_NODE];	/*!<
							 * Amount of time CPU has
							 * spent executing normal
							 * processes in user mode
							 */
	unsigned long long idle[VE_MAX_CORE_PER_NODE];	/*!<
							 * Amount of time CPU has
							 * spent executing twiddling
							 * thumbs
							 */
	unsigned int ctxt;				/*!<
							 * The total number of context
							 * switches across all CPUs
							 */
	unsigned int running;				/*!<
							 * The total number of
							 * runnable threads
							 */
	unsigned int blocked;				/*!<
							 * The number of processes
							 * currently blocked,
							 * waiting for I/O to complete
							 */
	unsigned long btime;				/*!<
							 * The time at which the
							 * VE nodes were booted
							 */
	unsigned int processes;				/*!<
							 * The number of processes
							 * and threads created
							 */
};

/**
 * @brief Structure to get the nice value of VE process
 */
struct velib_get_rusage_info {
	struct timeval utime;		/*!< User CPU time used */
	struct timeval elapsed;		/*!< Elapsed real (wall clock) time */
	long ru_maxrss;			/*!< Maximum resident set size */
	long ru_nvcsw;			/*!< Voluntary context switches */
	long ru_nivcsw;			/*!< Involuntary context switches */
	long page_size;			/*!< Page Size */
};

/**
 * @brief Data structure used to set/get scheduler parameters
 */
struct velib_setscheduler {
	int policy;		/*!< Scheduling policy */
	struct sched_param sp;	/*!<
				 * Structure to set/get priority of
				 * given process
				 */
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
struct velib_affinity {
	size_t cpusetsize;	/*!< Specifies the size (in bytes) of mask */
	cpu_set_t  mask;		/*!< Affinity mask */
};
/**
 * @brief Data structure used to get/set the resource limit (hard and soft) of VE process
 */
struct velib_prlimit {
	int resource; /*!< Resource argument can be Address space, CPU time, FSIZE, locks etc.*/
	bool is_new_lim; /*!< Specify new limit to set or not */
	struct rlimit new_lim; /*!< New values for the soft and hard limits for resource. */
	struct rlimit old_lim;/*!<
				* Successful call to prlimit() places the previous soft and hard
				* limits for resource in the rlimit structure pointed to by old_limit
				*/
};

struct velib_create_process {
	int flag;      /*!< Flag to preserve the task struct for resource usage */
	int vedl_fd;    /*!< FD from VE Driver */
	struct rlimit ve_rlim[RLIM_NLIMITS];
};

int veos_write_buf(int, void *, int);
int veos_rpm_send_cmd_ack(int, uint8_t *, int64_t, int64_t);
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
int rpm_handle_ipc_ls_rm_req(struct veos_thread_arg *);
int rpm_handle_get_regvals_req(struct veos_thread_arg *pti);
#endif
