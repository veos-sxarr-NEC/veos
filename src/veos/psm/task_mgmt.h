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
 * @file task_mgmt.h
 * @brief VE process task management data structures and interfaces.
 *
 * @internal
 * @author PSMG / MP-MT
 */
#ifndef __PSM_TASK_MGMT_H
#define __PSM_TASK_MGMT_H
#include <signal.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <linux/acct.h>
#include <stdint.h>
#include <pthread.h>
#include "stdbool.h"
#include "veos.h"
#include "ve_list.h"
#include "libved.h"
//#include "cr_api.h"
#include "mm_type.h"
#include "comm_request.h"
#include "psm_defs.h"

#define VE_MVL 256
#define SCHED_OTHER 0

#define NEW_VE_PROCESS 0
#define GET_PRIORITY 1
#define DELETE_VE_PROCESS 2

#define MAX_MSGS_PSEUDO_PSM_Q 10
#define MAX_MSG_SIZE_PSEUDO_PSM_Q 1024

#define MAX_TASKS_PER_NODE 1024
#define MAX_TASKS_PER_CORE 1024

#define SECS_TO_MICROSECONDS (1000 * 1000)
#define SECS_TO_NANOSECONDS (1000 * 1000 * 1000)
#define BITS_PER_BYTE	8
#define ACCT_COMM 16

#define MAX_PSM_PSEUDO_MSG_LEN	256
#define THREAD_WAIT_FOR_USE	0
#define THREAD_IN_USE		1
#define VE_PROC_PRIORITY_MAX		0
#define VE_PROC_PRIORITY_MIN		0

#define MAX_SWAP_PROCESS 256

/**
 * This macro will be used to check the load on VE system .
 */
#define ONE_MIN 60
#define FIVE_MIN 300
#define FIFTEEN_MIN 900

/**
 * This macro will be used for difference between two timestamp .
 */
#define USECOND 1000000LL
#define SECOND 1

/**
 * This macro will be used for store or restore the s/w
 * context of user registers of processes.
 */
#define MAX_SR 64
#define PMR_CONTEXT_PSW 0
#define PMR_CONTEXT_PMRR 1
#define PMR_CONTEXT_PMCR0 2
#define PMR_CONTEXT_PMCR3 5
#define PMR_CONTEXT_PMCR4 6
#define PMR_CONTEXT_PMC16 22
#define PROGINF_VERSION 1
/**
 * This macro will check if bit of bitmap is set or not.
 */
#define GET_BIT(bitmap, bit) (((uint64_t)1 << bit) & bitmap)
/**
 * This macro will set bit of bitmap.
 */
#define SET_BIT(bitmap, bit) (bitmap |= ((uint64_t)1 << bit))
#define REG_INDEX(regid) (regid-SR00)

#define BITS_PER_LONG 64
#define IS_CPU_ALLOWED(p_ve_task, cpu_num)				\
	(((unsigned long int)(p_ve_task->cpus_allowed) & (1UL<<cpu_num))\
	>> cpu_num)


#define VE_CPU_MASK(nrcpu) ((1UL << nrcpu) - 1)

#define VE_CORE_MASK(cpu) ((1UL << cpu))

/**
 * Default scheduling priority of VE process.
 */
#define	VE_DEF_SCHED_PRIORITY	0

#define MANTSIZE        13                      /* 13 bit mantissa. */
#define EXPSIZE         3                       /* Base 8 (3 bit) exponent. */
#define MAXFRACT        ((1 << MANTSIZE) - 1)   /* Maximum fractional value. */

/*
 * to facilitate efficient searching of tasks in cores
 * it will enhance the find_ve_task_struct() latency
 */
extern __thread int prefered_core;

typedef uint64_t did_t;

/**
 * @brief VE Process execution state
 */
enum proc_state {
	WAIT = 0, /*!< VE Process wait state */
	RUNNING, /*!< VE Process running state */
	ZOMBIE, /*!< VE Process zombie state */
	STOP, /*!< VE Process stop state */
	EXIT_DEAD, /*!< to identify the task to be deleted*/
	P_INVAL = -1 /*!< VE Process invalid state */
};

/**
 * @brief Zombie VE process (whose thread group is empty) cleanup state
 */
enum zombie_cleanup_state {
	CLEANUP_NO = 0,	/*!< ZOMBIE cleanup not required */
	CLEANUP_NEEDED,	/*!< ZOMBIE cleanup needed*/
	CLEANUP_DONE	/*!< ZOMBIE cleanup completed */
};
/**
 * @brief Process sub status of STOP status
 */
enum swap_status {
        INVALID = 0,
        ACTIVE = 1, /*!< SUB-S : a */
        SWAPPING_OUT, /*!< SUB-S : o */
        SWAPPED_OUT, /*!< SUB-S : s */
        SWAPPING_IN, /*!< SUB-S : i */
        TRACED = -1 /*!< SUB-S for Traced process */
};

/**
 * @brief Data created by worker thread to handle swap-thread with Swap-out/in
 */
struct veos_swap_request_info {
	struct list_head swap_info; /*!< list head */
	pid_t pid_array[MAX_SWAP_PROCESS + 1]; /*!< process id */
	/* To set 0 to ve_ipc_sync->swapping even if ve_task_struct is
	 * released */
	struct ve_ipc_sync *ipc_sync_array[MAX_SWAP_PROCESS + 1];
	int pid_number; /*!< length of pid_array */
};

#define SET_TASK_STATE(VAR, STATE) VE_ATOMIC_SET(enum proc_state, &(VAR), STATE)

/**
 * @brief PSM Scheduling parameters
 */
struct psm_param {
	int priority; /*!< if priority based scheduling */
	int pid; /*!< required when sending reply */
	int timeslice; /*!< time slice */
};

/**
 * @brief PSM communication command struct
 */
struct psm_cmd {
	int cmd; /*!< command */
	union {
		struct psm_param param; /*!< command parameters */
	} param;
};

/**
 * @brief VE process CPU affinity mask
 */
struct ve_cpumask {
	unsigned long cpu_bits[(VE_MAX_CORE_PER_NODE/BITS_PER_LONG) + 1]; /*!< CPU Mask */
};

/**
 * @brief VE Core state
 */
enum core_state {
	STOPPED = 0, /*!< VE core stop state */
	EXECUTING, /*!< VE core executing state */
	HALT, /*!< VE core halt state */
	C_INVAL = -1 /*!< VE core invalid state */
};

#define SET_CORE_STATE(VAR, STATE) VE_ATOMIC_SET(enum core_state, &(VAR), STATE)

/**
 * @brief VE task assign state
 */
enum assign_task {
	TSK_UNASSIGN = 0, /*!< VE task unassign */
	TSK_ASSIGN, /*!< VE task assign */
};

#define SET_ASSIGN_STATE VE_ATOMIC_SET(enum assign_task, &(VAR), STATE)

/**
 * @brief VE task block state
 */
enum block_state {
	BLOCK_RECVD = 0, /*!< VE task block received */
	UNBLOCK_SERVED, /*!< VE task unblock served */
};

#define SET_BLOCK_STATE(VAR, STATE) VE_ATOMIC_SET(enum block_state, &(VAR), STATE)

/**
 * @brief VE process VFORK state
 */
enum wait_for_vfork {
	VFORK_ONGOING = 0, /*!< VE process VFORK ongoing */
	VFORK_COMPLETED, /*!< VE process VFORK completed */
	VFORK_C_INVAL = -1 /*!< VE process VFORk invalid */
};

/**
 * @brief VE process status for checking cleanup eligibility
 */
#define	EXITING 1
#define	DELETING 2

#define SET_VFORK_STATE(VAR, STATE) VE_ATOMIC_SET(enum wait_for_vfork, &(VAR),\
		STATE)

typedef  unsigned long long cputime_t;

enum acct_data {
	ACCT_TOTAL_MEM = 0,
	ACCT_TRANSDATA,
	ACCT_SYSCALL,
};

#define PMMR_MASK	0xFFFFFFFF
#define PMMR_SHIFT	0xF000000000000000
#define PMC_REG		16

/**
 * @brief Additional proginf information
 */
struct ve_proginf_v1 {
	unsigned long long ac_l1iac;       /* L1 instruction cache access count */
	unsigned long long ac_l1omc;       /* L1 operand cache miss count */
	unsigned long long ac_uxc;         /* User-specified instruction execution count */
	unsigned long long ac_l1oac;       /* L1 operand cache access count */
	unsigned long long ac_uec;         /* User-specified instruction element count */
	unsigned long long ac_l2mc;        /* L2 cache miss count */
	unsigned long long ac_l2ac;        /* L2 cache access count  */
	unsigned long long ac_brec;        /* Branch execution count */
	unsigned long long ac_sarcc;       /* Shared resource access clock count in microseconds*/
	unsigned long long ac_bpfc;        /* Branch prediction failure count */
	unsigned long long ac_iphcc;       /* Instruction pipeline hold clock count in microseconds*/
	unsigned long long ac_vlxc;        /* Vector load instruction execution count */
	unsigned long long ac_llvxc;       /* LLC vector load cache miss instruction
					      execution count */
	unsigned long long ac_llvxc2;      /* LLC vector load cache miss/miss
					      on fill instruction execution count */
	unsigned long long ac_fmaxc;       /* Fused multiply add execution count */
};

/**
 * @brief Per-process accounting information.
 */
struct pacct_struct {
	int ac_flag; /*!< status of the process when it terminated */
	__u32 ac_exitcode; /*!< task exit code passed to the exit system call */
	unsigned long ac_mem; /*!< Memory usage */
	cputime_t ac_utime; /*!< Time spend by the process while scheduled on VE core */
	unsigned long long max_thread;
	struct ve_acct *acct_info;	/* VE task accounting information */
	struct ve_proginf_v1 ve_proginf; /* To store additional PMC values which do not
					    exist for accounting */
};

/**
 * @brief VE Core struct
 */
struct ve_core_struct {
	struct ve_node_struct *p_ve_node; /*!< VE node this core belong to */
	struct ve_task_struct *ve_task_list; /*!< Tasks assigned to this VE core */
	struct ve_task_struct *curr_ve_task; /*!< Current VE task on core */
	int core_num; /*!< Logical Core Id of this VE Core*/
	int phys_core_num; /*!< Physical Core Id of this VE Core*/
	enum core_state ve_core_state; /*!< State of VE core STOPPED or RUNNING*/
	int node_num; /*!< Node Id of this VE Core*/
	volatile int num_ve_proc; /*!< Number of VE process on this core */
	volatile int nr_active; /*!< Number of active tasks on core */
	vedl_user_reg_handle *usr_regs; /*!< Core user registers */
	vedl_sys_reg_handle *sys_regs; /*!< Core system registers */
	pthread_rwlock_t ve_core_lock; /*!< Mutex Lock for per core while ADD/DEL of a VE task */
	volatile enum context_switch scheduling_status; /*!< VE core scheduling status */
	uint64_t busy_time; /*!< Core execution time */
	uint64_t busy_time_prev; /*!< Core execution time on last scheduler interval */
	struct timeval core_uptime; /*!< Core start time */
	struct timeval core_stime; /*!< Time when core started after halt */
	bool core_running; /*!< Core running/halt status */
	uint64_t nr_switches; /*!< Number of context switches on core */
	sem_t core_sem; /* Semaphore for performing scheduling on core */
	int numa_node; /* !< NUMA node to which this core belongs. */
        uint64_t pwr_throttle_cnt;/*Power throttle counter*/
        uint64_t current_PMC14;/*Current value of register PMC14*/
        uint64_t previous_PMC14;/*Previous value of register PMC14*/
};

/**
* @brief Structure storing signal action and signal count information
* for VE process.
*/
struct sighand_struct {
	int ref_count; /*!< Number of threads sharing the sighand structure */
	struct sigaction action[NSIG];	/*!< Signal action for VE process signal */
	struct pacct_struct pacct; /*!< Per process accounting information maintained */
	pthread_mutex_t siglock; /*!< Siglock for sighnd_struct */
	pthread_mutex_t del_lock; /*!< Delete lock to synchronize thread deletion */
	struct rlimit rlim[RLIM_NLIMITS]; /*!< VE process resource limit */
	uint64_t lshm_addr;	/*!< Shared page address */
	int got_sigint; /*!< used to trace sigint to turn off coredumping*/
	int ve_sigpending; /*!< No. of pending signals */
	uint64_t cexec_time; /*!< VE process execution time on VE core of its children */
	int signal_flag; /*!< Signal coredump flag */
	uint64_t utime; /*!< execution time for threads in threads group that have exited */
};

/**
* @brief Structure storing the pending signal list
*/
struct ve_sigpending {
	struct list_head list;	/*!< List data structure variable */
	sigset_t signal;	/*!< Signal pending set */
};

/**
* @brief Structure storing pending signal information
*/
struct ve_sigqueue {
	struct list_head list;	/*!< List data structure variable */
	int flag;		/*!< Flag denoted if fatal signal */
	int signo;		/*!< Signal number */
	siginfo_t info;		/*!< Stores signal information */
};

struct ve_udma;

/**
 * VE process flags.
 */
#define PF_EXITING      0x00000004 	/* getting shut down */
#define PF_FORKNOEXEC   0x00000040      /* forked but didn't exec */
#define PF_DUMPCORE     0x00000200      /* dumped core */
#define PF_SIGNALED     0x00000400      /* killed by a signal */

#define VE_SIGNAL_GROUP_EXIT		0x00000001
#define VE_SIGNAL_GROUP_COREDUMP	0x00000002

/**
 * @brief Structure containing tracing information for VE process.
 */
struct ve_ptrace_info {
	bool is_seized;		/*!< Attach using seize or not */
	bool syscall_trace;     /*!< System call trace is enabled or not */
	int tracer_pid;         /*!< Tracer's Pid */
	uint64_t ptrace_options;/*!< Ptrace options set */
	uint64_t ptrace_message;/*!< Ptrace event message */
};

struct ve_thread_struct {
	uint64_t EXS;
	void *arch_user_regs;
};

/**
 * @brief VE process task struct
 */
struct ve_task_struct {
	int *thread_sched_count; /*!< Number of threads in thread group currently scheduled on core*/
	uint64_t *thread_sched_bitmap;
	uint64_t atb_dirty;
	uint64_t *thread_core_bitmap;	/*!< Core bitmap to get ac_corebitmap for process accounting */
	bool crd_dirty;
	bool invalidate_branch_history; /*! True, do. False, no need */
	int32_t *core_dma_desc; /*!< Core ID to be assigned to the task */
	struct ve_udma *udma_context; /*!< Pointer to user dma structure */
	did_t did; /* DID (Debug id) of the task */
	bool ptraced;   /*!< Traced or not */
	int pseudo_vefd;
	char ve_comm[ACCT_COMM]; /*!< VE Command name */
	char ve_exec_path[PATH_MAX]; /*!< Path of ve_exec */
	unsigned int flags;  /* per process flags */
	unsigned int policy; /*!< Assume we have only one SCHED_OTHER policy */
	int rt_priority; /*!< realtime priority */
	pid_t pid; /*!< VE proces PID */
	pid_t namespace_pid; /*!< Namespace VE proces PID */
	jid_t jid;    /*!< Job ID */
	int priority; /*!< Assume all ve tasks have same priority */
	int sched_class; /*!< Assume all ve tasks have same scheduling class */
	enum proc_state ve_task_state; /*!< Whether this ve process is assigned some VE core or not */
	int core_id; /*!< VE core ID of this process */
	int node_id; /*!< VE node ID of this process */
	int numa_node;/*!< NUMA node number of this process */
	enum swap_status sstatus; /*!< Process sub-status of STOP status */
	struct ve_core_struct *p_ve_core; /*!< Pointer to VE core this task is assigned */
	struct ve_task_struct *next; /*!< Pointer to next ve_task on this Core */
	struct ve_thread_struct *p_ve_thread; /*!< VE core related information and state of this task */
	bool reg_dirty; /*!< register dirty or not */
	struct ve_mm_struct *p_ve_mm; /*!< VE Pages required for this process on VE */
	struct ve_task_struct *parent; /*!< Pointer to its VE parent process */
	struct ve_task_struct *real_parent; /*!< Pointer to its VE real parent process */
	struct list_head children; /*!< list of VE process's children */
	struct list_head siblings; /*!< linkage in VE process parent's children list */
	struct list_head thread_group; /*!< list of threads in its thread group */
	struct list_head tasks; /*!< list of all the VE processes maintained by INIT VE process */
	enum block_state block_status; /*!<
					* This Flag is use to help scheduler while
					* scheduling a VE process.
					* In scenario when monc is encountered and schedule
					* timer expires before its corresponding block request
					* on veos is served, VE process task_state should
					* be set to WAIT(it should not be scheduled by
					* the scheduler as MONC has occurred)
					* This flags helps in handling this scenario.
					*/
	struct ve_task_struct *group_leader; /*!< thread group leader */
	int exit_signal; /*!< VE Process exit signal */
	int *set_child_tid; /*!< VE Process set child tid address */
	int *clear_child_tid; /*!< VE Process clear child tid address */
	int offset; /*!< shared page offset for thread */
	uint64_t sr_context_bitmap; /*!<
				     * Scalar Register context bitmap to check whether the context
				     * of a VE process is updated
				     */
	uint64_t pmr_context_bitmap; /*!<
				      * Performance Register context bitmap to check whether the
				      * context of a VE process is updated
				      */
	struct timeval stime; /*!< Start time of a VE process on every scheduler interval */
	struct timeval start_time; /*!< Start time of a VE process */
	uint64_t nvcsw; /*!< Number of voluntary context switches */
	uint64_t nivcsw; /*!< Number of Involuntary context switches */
	uint64_t exec_time; /*!< VE process time on VE core */
	enum wait_for_vfork vfork_state; /*!< Wait for vforked child to complete execution */
	bool vforked_proc; /*!< Is it vforked child */
	bool execed_proc; /*!< Is it created using execve() */
	struct sighand_struct *sighand; /*!< signal handlers structure for VE process */
	int sigpending; /*!< Flag to check signal is pending for VE process */
	sigset_t blocked; /*!< Blocked signal mask for a VE process */
	struct ve_sigpending pending; /*!< List of pending signals for this task */
	pthread_mutex_t ve_task_lock; /*!< VE task Mutex lock */
	pthread_mutex_t offset_lock; /*!< VE task Mutex offset lock */
	pthread_mutex_t ref_lock; /*!< Used in get and put functionality of VE process */
	int ref_count; /*!< Reference count for get and put VE process */
	int exit_status; /*!< Flag to check cleanup eligibility of a thread */
	int exit_code; /*!< Exit code of the terminating process */
	bool exit_code_set; /*!< flag which denote whether exit code is set from exit_group*/
	pthread_mutex_t vehva_lock; /*!< VE task Mutex vehva lock */
	pthread_mutex_t ptrace_lock; /*!< VE task Mutex lock for ptrace */
	unsigned long sas_ss_sp;/*!< signal alternate stack address */
	size_t sas_ss_size; /*!< signal alternate stack size */
	int syncsignal; /*!< Flag if set denotes h/w exception has occurred */
	bool mask_saved;	/*!< Signal mask is saved or not during sigsuspend request */
	sigset_t ve_saved_sigmask; /*!< Saving signal mask during sigsuspend */
	cpu_set_t cpus_allowed; /*!< CPU mask for VE Process*/
	struct ve_ptrace_info *p_ve_ptrace; /*!< Tracing information */
	uint64_t gid; /*!< VE Process group ID */
	uint64_t uid; /*!< VE Process user ID */
	int rpm_preserve_task; /*!< Flag to indicate to preseve RPM task*/
	bool rpm_create_task; /*!< Flag to indicate to RPM created the task */
	struct ived_shared_resource_data *ived_resource; /*!< VESHM/CR */
	bool usr_reg_dirty; /*!< Registers dirty after signal delivary or through Ptrace request */
	int64_t time_slice; /*!< per process time slice */
	bool is_crt_drv; /*!< To check if the task is created on driver*/
	bool is_dlt_drv; /*!< To check if the task is deleted from driver*/
	bool cpu_lim_exceed; /*!< To check if the task exceed the RLIMIT_CPU soft limit */
	pthread_cond_t ref_lock_signal; /*!< Conditional lock for execve */
	enum assign_task assign_task_flag; /*!< VE task assign status for driver */
	bool wake_up_parent;    /*!< Flag to indicate whether vforked child should waken its parent */
	bool thread_execed;	/*!< VE thread apart from main thread invoked execve() syscall */
	bool dummy_task;	/*!< RPM dummy task identifier, to disable accounting
				* information in case RPM sends delete dummy
				* task request */
	pid_t real_parent_pid;  /*!< VE Parent proces PID */
	struct ve_ipc_sync *ipc_sync; /*!< Structure wihch has handling_request and swapping.
				       * Don't access to this structure directly,
				       * have to use ve_get_ipc_sync().
				       */
	pid_t proc_pid;		/*!< VE Parent proces PID */
	pid_t tgid;		/*!< VE process's thread group ID */
	pid_t sid;		/*!< VE process's session ID */
	unsigned short tty;		/*!< VE process's tty ID */
	uint64_t *initial_pmc_pmmr;	/* initial PMC/PMMR counter register values */
	uint64_t *pmc_pmmr;		/* updated PMC/PMMR counter register */
	int zombie_partial_cleanup;	/* Zombie VE process cleanup state */
	uint64_t core_set;		/* Set of core where ATB update is needed */
	bool ve_set_next_thread_worker;         /* Flag to indicate that create the next thread as worker */
	struct ve_task_struct *ve_task_worker_belongs;          /* Pointer to parent thread of worker */
	bool ve_task_worker_belongs_chg;          /* Flag to change parent thread of worker */
	bool ve_task_have_worker;               /* Flag whether it have worker thread */
	struct ve_task_struct *ve_worker_thread; /* Pointer to worker thread */
	bool vlfa_wait;		/*!< for VE3 hardware issue */
	cpu_set_t job_scheduler_cpus_allowed;	/* cpu affinity mask as allowed by job scheduler */
	enum VE_SCHED_STATE ve_sched_state; /* Flag whether it should be removed from scheduling */
};


/**
 * @brief VE process fork system call request information
 */
struct ve_fork_info {
	int node_id; /*!< VE process node id */
	int core_id; /*!< VE process core id */
	int parent_pid; /*!< VE process parent PID */
	int child_pid; /*!< VE process child PID */
	int child_namespace_pid; /*!< VE process namespace pid */
	int offset; /*!< VE process thread offset */
	uint64_t shm_lhm_addr;
	struct veshm_struct *veshm;
	char sfile_name[S_FILE_LEN];
};

/**
* @brief VE process halt core information
*/
struct halt_ve_cores_info {
	struct ve_task_struct *task; /*!< pointer to current task */
	int start_core_id; /*!< VE process start core id */
	int stop_core_id; /*!< VE process stop core id */
	pid_t pid; /*!< PID of VE process */
	int flag; /*!< Flag if 1 indicate single core also 0 multiple */
};

/* Data structure for PROGINF */
struct proginf_v1 {
	short              version;        /* Always set to PROGINF_VERSION */
	short              arch;           /* Architecuture VE1:0, VE3:1 */
	unsigned int       padding_1[3];
	unsigned long long ac_ex;          /* Execution count */
	unsigned long long ac_vx;          /* Vector execution count */
	unsigned long long ac_fpec;        /* Floating point data element count */
	unsigned long long ac_ve;          /* Vector elements count */
	unsigned long long ac_l1imc;       /* L1 instruction cache miss count */
	unsigned long long ac_vecc;        /* Vector execution in microseconds */
	unsigned long long ac_l1iac;       /* L1 instruction cache access count */
	unsigned long long ac_l1mcc;       /* L1 cache miss in microseconds */
	unsigned long long ac_l2mcc;       /* L2 cache miss in microseconds */
	unsigned long long ac_l1omc;       /* L1 operand cache miss count */
        unsigned long long ac_uxc;         /* User-specified instruction execution count */
	unsigned long long ac_ve2;         /* Vector elements count 2 */
	unsigned long long ac_l1oac;       /* L1 operand cache access count */
        unsigned long long ac_uec;         /* User-specified instruction element count */
	unsigned long long ac_varec;       /* Vector arithmetic execution in microseconds */
	unsigned long long ac_l1imcc;      /* L1 instruction cache miss in microseconds */
	unsigned long long ac_l2mc;        /* L2 cache miss count */
	unsigned long long ac_vldec;       /* Vector load execution in microseconds */
	unsigned long long ac_l1omcc;      /* L1 operand cache miss in microseconds */
	unsigned long long ac_l2ac;        /* L2 cache access count  */
	unsigned long long ac_pccc;        /* Port conflict in microseconds */
	unsigned long long ac_ltrc;        /* Load instruction traffic count */
	unsigned long long ac_brec;        /* Branch execution count */
        unsigned long long ac_sarcc;       /* Shared resource access clock count in microseconds*/
	unsigned long long ac_vlpc;       /* Vector load packet count */
	unsigned long long ac_strc;        /* Store instruction traffic count */
	unsigned long long ac_bpfc;        /* Branch prediction failure count */
        unsigned long long ac_iphcc;       /* Instruction pipeline hold clock count in microseconds*/
	unsigned long long ac_vlec;        /* Vector load element count */
	unsigned long long ac_vlxc;        /* Vector load instruction execution count */
	unsigned long long ac_llvml;       /* LLC vector load cache fill line count */
	unsigned long long ac_llvme;       /* LLC vector load cache miss element count */
	unsigned long long ac_llvxc;       /* LLC vector load cache miss instruction
                                              execution count */
        unsigned long long ac_llvxc2;      /* LLC vector load cache miss/miss
                                              on fill instruction execution count */
	unsigned long long ac_fmaec;       /* Fused multiply add element count */
	unsigned long long ac_fmaxc;       /* Fused multiply add execution count */
	unsigned long long ac_ptcc;        /* Power throttling in microseconds */
	unsigned long long ac_ttcc;        /* Thermal throttling in microseconds */
	unsigned long long ac_corebitmap;  /* core bitmap */
	unsigned long long ac_max_nthread; /* Maximum number of threads whose
					      state are  "RUNNING" or "WAIT"  at
					      the same time */
	unsigned long long ac_l3vsac;      /* VLD+SLD elements accessing L3 count */
	unsigned long long ac_l3vsme;      /* L3 VLD+SLD miss-hit element count */
	unsigned long long ac_l3vsml;      /* L3 VLD+SLD miss-hit cache line count */
	unsigned long long ac_llvsme;      /* LLC miss-hit element count */
	unsigned long long ac_llvsml;      /* LLC miss-hit cache line count */
	unsigned long long padding_2[2];
};

/**
* @brief Check if task is thread group leader
*
* @param p Pointer to VE task struct
*
* @return 1 if task is thread group leader else 0 is returned.
*/
static inline bool thread_group_leader(struct ve_task_struct *p)
{
	return p == p->group_leader;
}

/**
* @brief Check if thread group is empty
*
* @param p Pointer to VE task struct
*
* @return 1 if thread group is empty else 0 is returned
*/
static inline bool thread_group_empty(struct ve_task_struct *p)
{
	return list_empty(&p->group_leader->thread_group);
}

unsigned long psm_calc_nr_context_switches(struct ve_node_struct *);
int calc_last_1_5_15_load(struct ve_node_struct *, double *, double *, double *);
void populate_1_5_15_sys_load(struct ve_node_struct *, double, uint64_t);
void calc_sys_load_per_sched_interval(struct ve_node_struct *);
int psm_relocate_ve_task(int, int, int, int, struct ve_task_struct *);
int psm_least_loaded_node_n_core(void);
int get_ve_core_n_node_new_ve_proc(struct ve_task_struct *, int *, int *, int *);
int psm_get_active_proc_num(struct ve_core_struct *);
int init_psm_daemon(char *);
void list_ve_proc(void);
int handle_get_priortiy(pid_t);
int insert_ve_task(int, int, struct ve_task_struct *);
int64_t psm_handle_set_tid_addr(pid_t, uint64_t);
int64_t psm_handle_schedule_ve_process(pid_t);
int psm_handle_exec_ve_process(struct veos_thread_arg *, int *,
                int *, int, int, char *, bool, pid_t,  uint64_t, char *,
                struct rlimit *, uint64_t, uint64_t, bool, char *, int *,
		int, pid_t, pid_t);
int psm_pseudo_send_load_binary_req(struct veos_thread_arg *, int, int, int, int);
int psm_handle_delete_ve_process(struct ve_task_struct *);
void delete_entries(struct ve_task_struct *);
void clear_ve_task_struct(struct ve_task_struct *);
int psm_handle_fork_ve_request(pid_t pid, int, int);
struct ve_mm_struct *alloc_ve_mm_struct_node();
struct ve_task_struct *find_ve_task_struct(int);
int find_veo_proc(int);
int get_ve_task_struct(struct ve_task_struct *);
int get_ve_task_struct_zombie(struct ve_task_struct *);
void put_ve_task_struct(struct ve_task_struct *);
void set_state(struct ve_task_struct *);
struct ve_task_struct *alloc_ve_task_struct_node(void);
struct ve_thread_struct *alloc_ve_thread_struct_node(void);
void free_ve_thread_struct(struct ve_thread_struct *);
struct sighand_struct *alloc_ve_sighand_struct_node(void);
struct ve_task_struct current;
int update_ve_thread_node(const struct ve_context_info *, struct ve_thread_struct *);
int psm_handle_start_ve_request(struct veos_thread_arg *, int);
int psm_handle_block_request(pid_t);
int psm_handle_un_block_request(struct ve_task_struct *, bool, bool);
int psm_pseudo_sigaction_ack(struct veos_thread_arg *);
int psm_del_sighand_struct(struct ve_task_struct *);
void psm_reparent_children(struct ve_task_struct *group_leader);
void print_process_tree(struct ve_task_struct *);
void list_init_tasks(void);
long long timeval_diff(struct timeval, struct timeval);
int psm_handle_clk_cputime_request(struct ve_task_struct *, int, struct timespec *);
int psm_handle_get_rlimit_request(int, struct ve_task_struct *, int, struct rlimit *, uid_t, gid_t);
int psm_handle_set_rlimit_request(int, struct ve_task_struct *, int, struct rlimit, uid_t, gid_t);
int64_t psm_handle_getaffinity_request(pid_t pid, size_t, cpu_set_t *);
int64_t psm_handle_setaffinity_request(pid_t, pid_t, cpu_set_t);
int remove_task_from_core_list(int, int, struct ve_task_struct *);
uint64_t get_ve_proc_exec_time(struct ve_task_struct *, int);
int psm_handle_get_rusage_request(struct ve_task_struct *, int, struct ve_rusage *);
int psm_handle_sysinfo_request(struct ve_task_struct *, struct sysinfo *);
int psm_handle_do_acct_ve(char *);
void psm_acct_collect(int, struct ve_task_struct *);
void veos_acct_ve_proc(struct ve_task_struct *);
int alloc_ve_task_data(struct ve_task_struct *);
int psm_handle_set_reg_req(struct ve_task_struct *, ve_usr_reg_name_t, ve_reg_t, int64_t);
void psm_st_rst_context(struct ve_task_struct *, ve_reg_t *, ve_reg_t *, bool);
void psm_set_task_state(struct ve_task_struct *, enum proc_state);
void psm_do_process_cleanup(struct ve_task_struct *, struct ve_task_struct *, int);
int psm_get_regval(struct ve_task_struct *, int, int *, uint64_t *);
int psm_map_lhm_shm_area(struct ve_task_struct *, int, char *, uint64_t);
struct ve_task_struct *find_child_ve_task_struct(pid_t, pid_t);
void send_notice_to_swap_thread(void);
void update_accounting_data(struct ve_task_struct *tsk, enum acct_data, double);
bool veos_acct_check_free_space(void);
void veos_dump_acct_info(struct ve_task_struct *);
void veos_delete_task_from_parent_and_init(struct ve_task_struct *);
void veos_zombie_cleanup_thread(void);
void veos_modtmp_cleanup_thread(void);
bool check_for_zombie_deletion(struct ve_task_struct *);
void psm_delete_zombie_task(struct ve_task_struct *);
struct ve_task_struct*  checkpid_in_zombie_list(int pid);
int psm_change_parent_ve_task_worker(struct ve_task_struct *, struct ve_task_struct *);
int64_t psm_handle_set_next_thread_worker_request(pid_t);
int psm_handle_set_cpu_mask_request(pid_t pid, cpu_set_t ve_mask);
int64_t psm_handle_stop_user_threads_request(pid_t);
int64_t psm_handle_start_user_threads_request(pid_t);
int64_t psm_handle_get_user_threads_state_request(pid_t);
uint64_t psm_current_run_wait_thread_count(struct ve_task_struct *);
void psm_max_run_wait_thread_count(struct ve_task_struct *, uint64_t);
void get_performance_register_for_proginf(struct ve_task_struct *, struct proginf_v1 *);
void collect_proginf_data(struct ve_task_struct *, struct proginf_v1 *);
comp_t veos_encode_comp_t(unsigned long long);
unsigned long long veos_usec_to_AHZ(unsigned long long);
int alloc_pmc_pmmr(struct ve_task_struct *);
#endif
