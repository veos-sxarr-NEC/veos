/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file comm_request.h
 * @brief This file contains structures used in IPC
 *
 * @internal
 * @author PSMG / AMM /MPMT
 */
#ifndef __VEOS_PSEUDO_INTERFACE_H
#define __VEOS_PSEUDO_INTERFACE_H

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <signal.h>
#include <stdbool.h>
#include <sched.h>
#include "ve_hw.h"
#include "mm_type.h"

#define MAX_PROTO_MSG_SIZE (4*1024)

#define KB 1024
#define VEOS_THREAD_PAGE_SIZE (4*KB)
#define VEOS_BYTES_PER_VE_THREAD 64
#define VEOS_MAX_VE_THREADS (VEOS_THREAD_PAGE_SIZE \
		/ VEOS_BYTES_PER_VE_THREAD)

#define USER_REG_MASK 0xFFFFFFFFFFFFFFFF
#define SHM_BITMAX 128

#define CPUCLOCK_PERTHREAD(clock) \
        (((clock) & (clockid_t) CPUCLOCK_PERTHREAD_MASK) != 0)
#define CPUCLOCK_WHICH(clock)   ((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define CPUCLOCK_PERTHREAD_MASK 4
#define CPUCLOCK_CLOCK_MASK     3
#define CLOCKFD_MASK            (CPUCLOCK_PERTHREAD_MASK|CPUCLOCK_CLOCK_MASK)
#define S_FILE_LEN	15


/**
* @brief  enum which is used to define elf types when exit.
*/
enum exit_elf_type {
	EXIT_THREAD = 0,
	EXIT_PROCESS,
	EXIT_EXECVE_VH,
	EXIT_EXECVE_VE,
	EXIT_ZOMBIE

};

/**
* @brief  Structure to be sent to PSM for handling NEW VE process
* creation request.
*/
struct ve_new_proc_info {
	bool traced_proc;	/*!< VE process is getting traced */
	int core_id;	/*!< VE process core ID*/
};

/**
* @brief veshm related information
*/
struct veshm_struct {
	uint64_t vemva_base;
	uint64_t bitmap[4];
};

/**
 * @brief Structure used in "UNBLOCK_AND_SET_REGVAL" IPC.
 */
struct ve_sys_info {
	bool sys_trace_stop;/*!< Determine start the process after
				* syscall or not.
				*/
	bool is_blk;	/*!< Determines block/non-block system call */
	uint64_t reg_num; /*!< Register ID to update */
	bool set_reg; /*!< Determines set reg or not */
};

/**
* @brief  Structure to be sent to PSM for handling UID GID
* set request.
*/
struct giduid_info {
	uint64_t data; /*!< Data for sending to veos*/
	bool info_flag; /*!< flag for UID/GID*/
};

/**
 * @brief  Structure to be sent to PSM for handling SET_AFFINITY
 * set request.
 */
struct ve_setaffinity_req {
	pid_t pid;		/*!< Pid of VE process */
	size_t cpusetsize;	/*!< cpusetsize */
	cpu_set_t mask;		/*!< Affinity mask */
};

/**
* @brief Structure to be sent to PSM for clone system call handling.
*/
struct pseudo_ve_clone_info {
	int parent_pid;		/*!< Thread ID of parent thread. */
	int child_pid;		/*!< Thread ID of child thread. */
	uint64_t flags;		/*!< Clone flags. */
	uint64_t stack_ptr;	/*!< Stack pointer for child process/thread. */
	uint64_t ptid;		/*!<
				 * VEMVA address used for CLONE_PARENT_SETTID
				 * clone flag.
				 */
	uint64_t ctid;		/*!<
				 * VEMVA address used for
				 * CLONE_CHILD_CLEARTID clone flag.*/
	struct veshm_struct veshm_dir[32];
	uint64_t shm_lhm_addr;
	int node_id;		/*!< Node id of ve process */
	char sfile_name[S_FILE_LEN];	/*!< syscall args file name */
};

struct pseudo_ve_fork_info {
	int child_pid;
	int parent_pid;
};

/**
* @brief clone acknowledgment structure received by pseudo process from PSM.
*/
struct clone_response {
	int core_id;	/*!< Core ID assigned to new thread. */
	int node_id;	/*!< Node ID assigned to new thread. */
	int offset;	/*!< SHM area offset assigned to thread. */
};

/**
* @brief Structure to receive the argument of sigaction()
* system call invoked by VE process
*/
struct k_sigaction {
	void (*handler)(int);	/*!< Signal handler routine */
	int  flags;	/*!< Signal action flags */
	void (*restorer)(void);	/*!< Restorer element */
	unsigned mask[2];	/*!< signal mask which will be blocked */
};

/**
* @brief Structure storing the information required by "veos" to handle
* sigaltstack system call invoked by VE process.
*/
struct ve_sigalt_info {
	int retval;		/*!< return value set by veos */
	stack_t new_sas;	/*!< new sigaltstack info */
	stack_t old_sas;	/*!< current sigacltstack info */
	int new_sas_flag;	/*!< flag set when new sas is to be set*/
	int old_sas_flag;	/*!< flag set if current sas info is required*/
};

struct file_stat {
	struct stat stat;	/*!< information of file attributes */
	uint64_t pgsz; 		/*!< information of file attributes */
	int64_t offset_start;	/*!< value at Start of file*/
	int64_t offset_end;	/*!< value at End of file*/
};

/**
 * @brief Structure having information to be send for PRLIMIT system call req
 */
struct prlimit_mm {
	uint64_t option; /*!< PRLIMIT MM option */
	uint64_t value;	/*!< Value of the option */
};
/**
 * @brief Structure for exit request
 */
struct ve_exit_req {
	int clean_all_thread; /*!< exit or exit group */
	int exit_code; /*!< exit code */
	int pseudo_vefd;/*!<
			 * use to fetch/store value of ve driver
			 * fd in ve_task_struct
			 * */
};

#define ACCT_COMM 16
/**
 * @brief New VE process creation request
 */
struct new_ve_proc {
	int namespace_pid;	/*!< Namespace pid of VE process */
	int core_id;		/*!< Core id of ve process */
	int node_id;		/*!< Node id of ve process */
	char exe_name[ACCT_COMM]; /*!< Binary name */
	char sfile_name[S_FILE_LEN]; /*!< Syscall argument file */
	uint64_t exec_path;	/*!< path of ve_exec */
	bool traced_proc;       /*!< VE process is getting traced */
	pid_t tracer_pid;       /*!< Pid of VE tracer */
	uint64_t shm_lhm_addr;
	struct rlimit lim[RLIM_NLIMITS];
	uint64_t gid;		/*!< VE process group ID*/
	uint64_t uid;		/*!< VE process user ID*/
	int numa_node;		/*!< NUMA node ID */
	int mem_policy;		/*!< memory policy for VE process*/
	pid_t real_parent_pid;  /*!< Parent Process ID of VE Process*/
};


/**
* @brief ve_mmap command Information
*/
struct ve_mmap_cmd {
	vemva_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	int perm; /*!< VE physical page access permission */
	uint64_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	uint64_t flags; /*!<
			 * flag to control VE physical memory allocation
			 * and mapping
			 */
	uint64_t atb_flag; /*!< ATB flag */
	struct file_stat f_stat;
};

/**
 * @brief CMD_TPROC info;
 */
struct ve_jid_cmd {
	uid_t uid;
	uint64_t j_lim;
};

/**
 * @brief Contain information to check_rw_permission.
 */
struct ve_rw_check_iovec {
	vemva_t  vaddr;		/*!< VEMVA address to check permission */
	uint64_t len;		/*!< Length to check permission */
	pid_t pid;		/*!< Pid of process */
	int type;		/*!< Type to permission */
};

/**
 * @brief This stusture contain the process_rw_info.
 */
struct ve_process_rw_info {
	pid_t r_pid;		/*!< remote process id */
	vemva_t base_rvemva;
	uint64_t r_len;
	uint64_t len;
	uint64_t lcov_offset;	/*!< offset on local vemva address to rw*/
	uint64_t rcov_offest;	/*!< offset on remote vemva address to rw*/
	vemva_t local_vemva;	/*!< local vemva address to rw*/
	vemva_t remote_vemva;	/*!< remote vemva address to rw */
	int vm_rw;			/*!< 0 for read, 1 for write */
};

/**
 * @brief CMD_MUNMAP info.
 */
struct ve_munmap_cmd {
	vemva_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	size_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	uint64_t atb_flag; /*!< ATB flag */
};

/**
 * @brief SHM info.
 */
struct ve_shm_cmd {
	vemva_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	size_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	int flag;	/*!< SHM segment flag */

	uint64_t perm; /*!< VE physical page access permission */
	key_t key;
	int64_t shmid;
	int64_t shmperm;
	bool create;
	struct shmid_ds shm_stat;
};

/**
* @brief NEW VE PROC info
*/
struct new_proc_info {
	int core_id; /*!< Core ID */
	int node_id; /*!< Node ID */
	int numa_node; /*!< Numa Node ID */
};


/**
* @brief VEMVA_INIT_TAB info
*/
struct vemva_init_atb_cmd {
	vemva_t vaddr;
	size_t page_size;
};

/**
 * @brief VE CPU Info
 */
struct ve_cpu_info {
	int cpu; /*!< Core ID */
	int numa_node; /*!< NUMA Node ID */
};

/**
 * @brief VE Process Scheduling Information
 */
struct ve_sched_info {
	int pid; /*!< VE Process PID */
	int policy; /*!< VE Process Policy */
	int prio; /*!< VE Process Priority */
};

/**
 * @brief VE Process Priority Information
 */
struct ve_prio_info {
	pid_t pid; /*!< VE Process PID */
	int prio; /*!< VE Process Priority */
};

struct dma_args {
	int srctype;
	uint64_t srcaddr;
	int dsttype;
	uint64_t dstaddr;
	uint64_t size; /*!<
			* VE physical memory allocation/de-allocation
			* request size
			* */
};

/**
* @brief Store the signal information for the signal
* generated for VE process
*/
struct ve_signal_info {
	int signum;	/*!< Signal number generated */
	siginfo_t ve_siginfo; /*!< Stores signal information */
	pid_t tid; /* signal will be delivered to this tid */
};

/**
 * @brief This data structure stores the signal for VE task
 */

struct ve_signal_mask {
	sigset_t newset; /*!< Requested signal mask for VE task */
	sigset_t oldset; /*!< current mask of VE task */
	bool mask; /*!< do we need to update mask */
	int store_mask; /*!< store mask for later use */
	int how; /*!< action needs to perform by sigprocmask */
	sigset_t ve_curr_mask; /*!< Actual mask of VE task*/
};

/**
* @brief This data structure stores the mapping of signal
* action corresponding to the signal number for VE task.
*/
struct ve_sigaction_info {
	int signum;	/*!< Signal number generated */
	struct sigaction ve_sigaction;	/*!< Store the new signal action registered */
	struct sigaction old_ve_sigaction;	/*!< Store the current signal action */
	int action; /*!< if signal action needs to updated or not*/
};

typedef struct veos_thread_arg {
	int socket_descriptor;  /*!< descriptor to read/write */
	int flag;
	pid_t saved_pseudo_pid;
	pid_t saved_host_pid;
	void *pseudo_proc_msg;
	struct ucred cred;	/*!< credential */
} veos_thread_arg_t;

struct veos_cmd_entry {
	char *cmdname;
	int (*handler)(struct veos_thread_arg *);
};

/**
 * @brief VE context data structure required by PSM
 */
struct ve_context_info {
	reg_t IC; /*!< Instruction counter */
	reg_t SP; /*!< Stack pointer */
	reg_t SZ; /*!< Stack frame pointer */
};

struct ve_address_space_info_cmd {
	uint64_t heap_start;            /*!< Start address of heap */
	uint64_t heap_top;              /*!< Heap top of VE Process */
	uint64_t stack_limit;           /*!< Max stack limit for a VE Process.
					 * value = 0 in case of UNLIMITED,
					 * value = 'X' in case of User-Defined
					 * or default(Currently 10MB).
					 */
	uint64_t stack_bottom;          /*!< Stack bottom of a VE Process */
	uint64_t stack_pointer_aligned; /*!< Page size aligned actual stack
					 * pointer of a VE process. */
};

struct ve_start_ve_req_cmd {
	struct ve_context_info context_info;
	struct ve_address_space_info_cmd ve_info;
	uint64_t start_code, end_code,
		 start_data, end_data, pgsz;
	int argc;
	uint64_t argv_addr, argv_size;
	uint64_t auxv_addr, auxv_size;
};



/**
 * @brief Shared memory info for VE process.
 */
struct shm_seginfo {
	int shmid;      /*!< id for shared memory segment*/
	int pgmod; /*!< Page mode of shm segment */
	uint64_t size; /*!< Size of shm segment */
	int err; /*!< Errno while geting shm segment */
	uint64_t bitmap[SHM_BITMAX]; /*!< bimap correspondig to shm segment */
};

/**
* @brief Resource usage for VE process
*/
struct ve_rusage {
	struct timeval ru_utime;/*!< system CPU time used */
	long ru_maxrss;		/*!< maximum resident set size */
	uint64_t nvcsw;		/*!< Number of voluntary context switches */
	uint64_t nivcsw;	/*!< Number of Involuntary context switches */
};


/* @brief pid: PID of a process whose rusage is required
 *        who: who stores RUSAGE_SELF/RUSAGE_THREAD/RUSAGE_CHILDREN
 */
struct ve_rusage_info {
	int who;		/*!< stores RUSAGE_SELF/RUSAGE_THREAD/RUSAGE_CHILDREN */
	pid_t pid;		/*!< stores PID of process for rusage */
	bool cleanup;		/*!< whether rusage for a process involves its cleanup
				  by its parent */
};

/**
* @brief times structure for VE process
*/
struct ve_times {
	struct timeval tms_utime;/*!< user CPU time used */
	struct timeval tms_cutime;/*!< user CPU time used by the childrens */
	struct timeval uptime;/*!< Uptime for the node */
};

/* @brief pid: PID of a process whose times is required
 */
struct ve_times_info {
	pid_t pid;		/*!< stores PID of process for times */
};

/**
* @brief Clock info for VE process
*/
struct ve_clockinfo {
	pid_t pid;		/*!< PID of task whose info is required */
	pid_t current;          /*!< PID of task who invoked system call */
	clockid_t clockid;	/*!< Clock id */
	bool pid_flag;		/*!< Whether PID is present in clock_id */
};
/**
 * @brief mprotect request structure received by AMM from pseudo process.
 */
struct pseudo_mprotect_req {
	vemva_t ret_addr;	/*!< Mapped virtual address. */
	uint64_t size;		/*!< Size of the memory to map. */
	int prot;		/*!< Protection control bits. */
	int atb_flag;		/*!< Determines ATB to update or not. */
};

/**
 * @brief clone acknowledgment structure received by pseudo process from PSM.
 */
struct ve_proc_info {
	int core_id;    /*!< Core ID assigned to new thread. */
	int node_id;    /*!< Node ID assigned to new thread. */
	int offset;     /*!< SHM area offset assigned to thread. */
};

/**
* @brief Structure having information to be send in set rlimit function
*/
struct rlimit_info {
	int pid;		/*!< Pid of process to get resource */
	int resource;           /*!< Resource of rlimit */
	struct rlimit rlim;     /*!< structure of rlimit */
};

/* To support VE_LIMIT_OPT for resourec limit */
enum ve_rlim {
	HARDC = 1,
	SOFTC,
	HARDD,
	SOFTD,
	HARDI,
	SOFTI,
	HARDM,
	SOFTM,
	HARDS,
	SOFTS,
	HARDT,
	SOFTT,
	HARDV,
	SOFTV,
	VE_RLIM_CNT
};

#define MAX_RESOURCE_LIMIT 18014398509481983    /*!< Maximum limit for
                                                *resource s, v, m, c, d
                                                */

/**
 * @brief Structure having information regarding set user register
 * function
 */
struct reg_data {
	int reg;		/*!< Register ID */
	reg_t regval;		/*!< Register value */
	int64_t mask;		/*!< Mask for regval */
};


/**
* @brief : Structure having information to
*	be send in set cr_rlimit function
*/
struct cr_rlimit_info {
	pid_t pid;		/*!< process id */
	uint64_t uid;		/*!< process user id>*/
	int cr_thread_lim;	/*!< thread page lim*/
	int cr_mpi_lim;		/*!< mpi page lim*/
};


/**
* @brief : CR dump cmd info
*/
struct cr_dump_cmd {
	pid_t pid;
	uint64_t mode_flag;
};

/**
 * @brief Structure to store the setting of PCI synchronization.
 */
struct pcisval {
	uint64_t pcisyar;
	uint64_t pcisymr;
};

/**
 * @brief Structure to store the setting of DMA info.
 */
struct userdma {
	uint64_t dmades;
	uint64_t dmactl;
};

/**
* @brief command ID's used to communicate b/w VEOS and PSEUDO side
*/
enum pseudo_veos_msg_id {
	RPM_QUERY = 0,
	PTRACE_REQUEST,
	NEW_VE_PROC,
	START_VE_REQ,
	DEL_VE_PROC,
	FORK_VE_PROC,
	CLONE_VE_PROC,
	SET_TID_ADDR,
	SCHEDULE,
	BLOCK,
	UNBLOCK_AND_SET_REGVAL,
	CMD_MMAP,
	CMD_MUNMAP,
	CMD_MPROTECT,
	CMD_SHMAT,
	CMD_SHMDT,
	CMD_SHMCTL,
	DMA_REQ,
	SET_USR_REG,
	VE_SIGNAL_REQ,
	SIGRETURN_REQ,
	SIGACTION_REQ,
	SET_NEW_SAS,
	SIGPROCMASK_REQ,
	HW_EXP_REQ,
	SIGPENDING_REQ,
	CLK_CPUTIME,
	GET_CPU_REQ,
	GET_SCHED_INTRVL,
	GET_RLIMIT,
	SET_RLIMIT,
	GET_AFFINITY,
	SET_AFFINITY,
	GET_RUSAGE,
	SYSINFO_REQ,
	ACCT_REQ,
	VEFD_REQ,
	SIGSUSPEND_REQ,
	CMD_VMRW,
	VEMVA_INIT_ATB,
	CMD_TPROC,
	GET_REGVAL_REQ,
	GIDUID_REQ,
	GET_MEMPOLICY,
#if 0
	CMD_CR_RLIM,
#endif
	CR_DUMP,
	CMD_SHMGET,
	PTRACE_EVENT_MSG,
	VE_STOP_PROC,
	CMD_VESHM,
	GET_PCI_SYNC,
	CMD_CR,
	CMD_VEMM,
	VHVA_SYNC,
	CMD_VHSHM,
	MAP_DMADES,
	UNMAP_DMADES,
	RPM_QUERY_COMPT,
	NEW_VE_PROC_COMPT,
	GET_TIMES,
	GET_VEOS_PID,
	CMD_GET_MNS,
	PSEUDO_VEOS_MAX_MSG_NUM,
	CMD_INVALID = -1,
};

#endif
