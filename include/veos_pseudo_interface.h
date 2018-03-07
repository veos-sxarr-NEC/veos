#ifndef __VEOS_PSEUDO_INTERFACE_H
#define __VEOS_PSEUDO_INTERFACE_H

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdbool.h>
#include "ve_hw.h"

#define MAX_PROTO_MSG_SIZE (4*1024)

#define KB 1024
#define VEOS_THREAD_PAGE_SIZE (4*KB)
#define VEOS_BYTES_PER_VE_THREAD 64
#define VEOS_MAX_VE_THREADS (VEOS_THREAD_PAGE_SIZE \
		/ VEOS_BYTES_PER_VE_THREAD)

/**
* @brief  Structure to be sent to PSM for handling NEW VE process
* creation request.
*/
struct ve_new_proc_info {
	bool traced_proc;	/*!< VE process is getting traced */
	int core_id;	/*!< VE process core ID*/
};

/**
* @brief Structure to be sent to PSM for clone system call handling.
*/
struct pseudo_ve_clone_info {
	int child_pid;		/*!< Thread ID of child thread. */
	uint64_t flags;		/*!< Clone flags. */
	uint64_t stack_ptr;	/*!< Stack pointer for child process/thread. */
	uint64_t ptid;		/*!<
				 * VEMVA address used for CLONE_PARENT_SETTID
				 * clone flag.
				 */
	uint64_t ctid;		/*!<
				 * VEMVA address used for
				 * CLONE_CHILD_CLEARTID clone flag.
				 */
	uint64_t shm_lhm_addr;
	int shmid;
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
	unsigned long flags;	/*!< Signal action flags */
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

struct file_map_stat {
	struct stat file_stat; /*!< information of file attributes */
	int64_t offset_start; /*!< value at Start of file*/
	int64_t offset_end; /*!< value at End of file*/
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
};

#define ACCT_COMM 16
/**
 * @brief New VE process creation request
 */
struct new_ve_proc {
	int core_id;
	char exe_name[ACCT_COMM+1];
	bool traced_proc;       /*!< VE process is getting traced */
	uint64_t shm_lhm_addr;
	int shmid;
};


/**
* @brief ve_mmap command Information
*/
struct ve_mmap_cmd {
	uint64_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	uint64_t perm; /*!< VE physical page access permission */
	uint64_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	uint64_t flags; /*!<
			 * flag to control VE physical memory allocation
			 * and mapping
			 */
	uint64_t atb_flag; /*!< ATB flag */
	struct file_map_stat f_map_stat;
};

/**
* @brief CMD_MREMAP info.
*/
struct ve_munmap_cmd {
	uint64_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	uint64_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	uint64_t atb_flag; /*!< ATB flag */
};

/**
* @brief SHM info.
*/
struct ve_shm_cmd {
	uint64_t vaddr; /*!<
			 * VEMVA, used for mapping of VE physical pages to
			 * this address
			 */
	uint64_t size; /*!<
			* VE physical memory allocation/de-allocation request
			* size
			*/
	uint64_t atb_flag; /*!< ATB flag */

	uint64_t perm; /*!< VE physical page access permission */
	int64_t key;
	int64_t shmid;
};
/**
* @brief NEW VE PROC info
*/
struct new_proc_info {
	int core_id; /*!< Core ID */
	int node_id; /*!< Node ID */
};

/**
 * @brief VE CPU Info
 */
struct ve_cpu_info {
	int cpu; /*!< Core ID */
	int node; /*!< Node ID */
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
};

/**
* @brief This data structure stores the mapping of signal
* action corresponding to the signal number for VE task.
*/
struct ve_sigaction_info {
	int signum;	/*!< Signal number generated */
	struct sigaction ve_sigaction;	/*!< Store the new signal action registered */
	struct sigaction old_ve_sigaction;	/*!< Store the current signal action */
};


typedef struct veos_thread_arg {
	int socket_descriptor;  /*!< descriptor to read/write */
	int tid_used;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	int flag;
	pid_t client_pid;       /*!< pid connected to this thread */
	int pidfd;
	void *pseudo_proc_msg;
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

struct mremap_cmd {
	uint64_t vaddr_old;
	uint64_t vaddr_new;
	uint64_t size_old;
	uint64_t size_new;
};

struct shmdt_info {
	uint64_t size;
	int err;
	uint64_t bitmap[4];
};

struct ve_rusage {
	struct timeval ru_stime;/*!< system CPU time used */
	long ru_maxrss;		/*!< maximum resident set size */
};

/**
 * @brief mprotect request structure received by AMM from pseudo process.
 */
struct pseudo_mprotect_req {
	uint64_t ret_addr;	/*!< Mapped virtual address. */
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
	int resource;           /*!< Resource of rlimit */
	struct rlimit rlim;     /*!< structure of rlimit */
};

/**
* @brief command ID's used to communicate b/w VEOS and PSEUDO side
*/
enum pseudo_veos_msg_id {
	NEW_VE_PROC = 0,
	START_VE_REQ,
	DEL_VE_PROC,
	FORK_VE_PROC,
	CLONE_VE_PROC,
	SET_TID_ADDR,
	SCHEDULE,
	BLOCK,
	UNBLOCK,
	CMD_MMAP,
	CMD_MREMAP,
	CMD_MUNMAP,
	CMD_MPROTECT,
	CMD_SHMAT,
	CMD_SHMDT,
	CMD_SHMCTL,
	DMA_REQ,
	SET_REGVAL,
	HALT_CORE,
	START_CORE,
	VE_SIGNAL_REQ,
	SIGRETURN_REQ,
	SIGACTION_REQ,
	SET_NEW_SAS,
	SIGPROCMASK_REQ,
	HW_EXP_REQ,
	GET_PRIOMAX_REQ,
	GET_PRIOMIN_REQ,
	GET_PRIO_REQ,
	SET_PRIO_REQ,
	GET_SCHED_REQ,
	SET_SCHED_REQ,
	GET_PARAM_REQ,
	SET_PARAM_REQ,
	SIGPENDING_REQ,
	CLK_CPUTIME,
	GET_CPU_REQ,
	GET_SCHED_INTRVL,
	GET_RLIMIT,
	SET_RLIMIT,
	GET_AFFINITY,
	SET_AFFINITY,
	SCHED_YIELD,
	GET_RUSAGE,
	PRCTL_SET_MM,
	RPM_QUERY,
	SYSINFO_REQ,
	ACCT_REQ,
	SIGSUSPEND_REQ,
	CMD_INVALID = -1
};
#endif
