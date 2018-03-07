/**
 * @file psm_task_mgmt.h
 * @brief VE process task management data structures and interfaces.
 */
#ifndef __PSM_TASK_MGMT_H
#define __PSM_TASK_MGMT_H
#include <signal.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <linux/acct.h>
#include "stdbool.h"
#include "veos.h"
#include "veos_list.h"
#include "ve_hw.h"
#include "libved.h"
#include "sys/time.h"

#define VE_MVL 256
#define SCHED_OTHER 0

#define NEW_VE_PROCESS 0
#define GET_PRIORITY 1
#define DELETE_VE_PROCESS 2

#define MAX_MSGS_PSEUDO_PSM_Q 10
#define MAX_MSG_SIZE_PSEUDO_PSM_Q 1024

#define MAX_PROCESS_PER_NODE (MAX_PROCESS_PER_CORE * MAX_VE_CORE_PER_VE_NODE)
#define MAX_PROCESS_PER_CORE 128

#define NANO_SECONDS 1
#define MILLI_SECONDS (1000 * NANO_SECONDS)
#define MICRO_SECONDS (1000 * 1000 * NANO_SECONDS)
#define PSM_TIMER_INTERVAL_NSECS (0 * MILLI_SECONDS)

#define SECONDS 1

#define SECS_TO_NANOSECONDS (1000 * 1000 * 1000)
#define BITS_PER_BYTE	8
#define ACCT_COMM 16

/**
 * PSM_TIMER_INTERVAL_SECS is increased because the interface invoked
 * on timer expiry takes time greater than 5-10 secs to context
 * switch and schedule new VE process on VE core
 */
#define PSM_TIMER_INTERVAL_SECS (2 * SECONDS)

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

/**
 * Default scheduling priority of VE process.
 */
#define	VE_DEF_SCHED_PRIORITY	0

/**
 * @brief VE Process execution state
 */
enum proc_state {
	WAIT = 0, /*!< VE Process wait state */
	RUNNING, /*!< VE Process running state */
	ZOMBIE, /*!< VE Process zombie state */
	STOP, /*!< VE Process stop state */
	P_INVAL = -1 /*!< VE Process invalid state */
};

#define SET_TASK_STATE(VAR, STATE) VE_ATOMIC_SET(enum proc_state, &(VAR), STATE)

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

#define SET_VFORK_STATE(VAR, STATE) VE_ATOMIC_SET(enum wait_for_vfork, &(VAR),\
		STATE)

typedef  unsigned long long cputime_t;

/**
 * @brief Per-process accounting information.
 */
struct pacct_struct {
	int ac_flag; /*!< status of the process when it terminated */
	long ac_exitcode; /*!< task exit code passed to the exit system call */
	unsigned long ac_mem; /*!< Memory usage */
	cputime_t ac_stime; /*!< Time spend by the process while scheduled on VE core */
};

/**
 * @brief Accouting structure to dump on an accountiing file.
 */
struct ve_acct {
	char ac_flag; /*!< status of the process when it terminated*/
	char ac_version; /*!< Always set to ACCT_VERSION (3) */
	u_int32_t ac_exitcode; /*!< task exit code passed to the exit system call */
	u_int32_t ac_uid; /*!< Real user ID */
	u_int32_t ac_gid; /*!< Real group ID*/
	u_int32_t ac_pid; /*!< Process ID*/
	u_int32_t ac_ppid; /*!< Parent process ID*/
	u_int32_t ac_btime; /*!< process creation time*/
	float ac_etime; /*!< elapsed time from process creation to termination*/
	comp_t ac_stime; /*!< Time spend by the process while scheduled on VE core*/
	comp_t ac_mem; /*!< Average memory usage (kB)*/
	char ac_comm[ACCT_COMM]; /*!< Command name of the program*/
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
	int num_ve_proc; /*!< Number of VE process on this core */
	volatile int nr_active; /*!< Number of active tasks on core */
	core_user_reg_t *usr_regs_addr; /*!< Core user registers */
	core_system_reg_t *sys_regs_addr; /*!< Core system registers */
	pthread_rwlock_t ve_core_lock; /*!< Mutex Lock for per core while ADD/DEL of a VE task */
	pthread_cond_t ve_cond_lock; /*!< Conditional Lock for per core while ADD/DEL of a VE task */
	enum context_switch scheduling_status; /*!< VE core scheduling status */
	enum assign_task assign_task_flag; /*!< VE core task assign status */
	uint64_t busy_time; /*!< Core execution time */
	uint64_t busy_time_prev; /*!< Core execution time on last scheduler interval */
	struct timeval core_uptime; /*!< Core start time */
	struct timeval core_stime; /*!< Time when core started after halt */
	bool core_running; /*!< Core running/halt status */
	uint64_t nr_switches; /*!< Number of context switches on core */
};

/* Copied from AUSIM */
struct ve_thread_struct {
	/* Performance Counters */
	reg_t USRCC;			/*     0x0 -     0x8 */
	reg_t PMC[15];			/*     0x8 -    0x80 */
	uint8_t pad0[0x1000 - 0x80];	/*    0x80 -  0x1000 */
	/* Control Registers */
	reg_t PSW;			/*  0x1000 -  0x1008 */
	reg_t EXS;			/*  0x1008 -  0x1010 */
	reg_t IC;			/*  0x1010 -  0x1018 */
	reg_t ICE;			/*  0x1018 -  0x1020 */
	reg_t VIXR;			/*  0x1020 -  0x1028 */
	reg_t VL;			/*  0x1028 -  0x1030 */
	reg_t SAR;			/*  0x1030 -  0x1048 */
	reg_t PMMR;			/*  0x1038 -  0x1040 */
	reg_t PMCR;			/*  0x1040 -  0x1048 */
	uint8_t pad1[0x1400 - 0x1048];	/*  0x1048 -  0x1400 */
	/* Scalar Registers */
	reg_t SR[SR_NUM];		/*  0x1400 -  0x1600 */
	uint8_t pad2[0x1800 - 0x1600];	/*  0x1600 -  0x1800 */
	/* Vector Mask Registers */
	reg_t VMR[16][4];		/*  0x1800 -  0x1A00 */
	uint8_t pad3[0x40000 - 0x1A00];	/*  0x1A00 - 0x40000 */
	/* Vector Registers */
	reg_t VR[VR_NUM][VE_MVL];	/* 0x40000 - 0x60000 */
	uint8_t pad4[0x80000 - 0x60000];/* 0x60000 - 0x80000 */
};

/**
* @brief Structure storing signal action and signal count information
* for VE process.
*/
struct sighand_struct {
	int ref_count; /*!< Number of threads sharing the sighand strcuture */
	struct sigaction action[NSIG];	/*!< Signal action for VE process signal */
	struct pacct_struct pacct; /*!< Per process accounting information maintained */
	pthread_mutex_t	siglock;	/*!< Siglock for sighnd_struct */
	uint64_t lshm_addr;	/*!< Shared page address */
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

/**
 * VE process flags.
 */
#define PF_FORKNOEXEC	0x00000004 /* forked but didn't exec. */
#define PF_SIGNALED	0x00000008 /* killed by a signal. */
#define PF_DUMPCORE	0x00000200 /* dumped core. */

/**
 * @brief VE process task struct
 */
struct ve_task_struct {
	char ve_comm[ACCT_COMM+1]; /*!< VE Command name */
	unsigned int flags;  /* per process flags */
	int policy; /*!< Assume we have only one SCHED_OTHER policy */
	int rt_priority; /*!< realtime priority */
	pid_t pid; /*!< VE proces PID */
	int priority; /*!< Assume all ve tasks have same priority */
	int sched_class; /*!< Assume all ve tasks have same scheduling class */
	enum proc_state ve_task_state; /*!< Whether this ve process is assigned some VE core or not */
	int core_id; /*!< VE core ID of this process */
	int node_id; /*!< VE node ID of this process */
	unsigned long int ticks_elapsed; /*!< Assigned VE Core to the VE task */
	struct ve_core_struct *p_ve_core; /*!< Pointer to VE core this task is assigned */
	struct ve_task_struct *next; /*!< Pointer to next ve_task on this Core */
	struct ve_thread_struct *p_ve_thread; /*!< VE core related information and state of this task */
	bool reg_dirty; /*!< register dirty or not */
	struct ve_thread_struct *p_ve_sigcontext; /*!< VE signal context of this task */
	struct ve_mm_struct *p_ve_mm; /*!< VE Pages required for this process on VE */
	struct ve_task_struct *parent; /*!< Pointer to its VE parent process */
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
	pid_t tgid; /*!< thread group ID */
	int exit_signal; /*!< VE Process exit signal */
	int *clear_child_tid; /*!< VE Process clear child tid address */
	int offset; /*!< shared page offset for thread */
	uint64_t sr_context_bitmap; /*!<
				     * Scalar Register context bitmap to check whether the context
				     * of a VE process is updated
				     */
	struct timeval stime; /*!< Start time of a VE process on every scheduler interval */
	struct timeval start_time; /*!< Start time of a VE process */
	uint64_t nvcsw; /*!< Number of voluntary context switches */
	uint64_t nivcsw; /*!< Number of Involuntary context switches */
	uint64_t exec_time; /*!< VE process time on VE core */
	uint64_t cexec_time; /*!< VE process execution time on VE core of it's child's */
	enum wait_for_vfork vfork_state; /*!< Wait for vforked child to complete execution */
	bool vforked_proc; /*!< Is it vforked child */
	bool execed_proc; /*!< Is it created using execve() */
	struct sighand_struct *sighand; /*!< signal handlers structure for VE process */
	int sigpending; /*!< Flag to check signal is pending for VE process */
	sigset_t blocked; /*!< Blocked signal mask for a VE process */
	struct ve_sigpending pending; /*!< List of pending signals for this task */
	pthread_mutex_t ve_task_lock; /*!< VE task Mutex lock */
	pthread_mutex_t offset_lock; /*!< VE task Mutex offset lock */
	pthread_mutex_t siglock; /*!< VE task Mutex signal lock */
	unsigned long sas_ss_sp;/*!< signal alternate stack address */
	size_t sas_ss_size; /*!< signal alternate stack size */
	int syncsignal; /*!< Flag if set denotes h/w exception has occurred */
	struct rlimit rlim[RLIM_NLIMITS]; /*!< VE process resource limit */
	bool mask_saved;	/*!< Signal mask is saved or not during sigsuspend request */
	sigset_t ve_saved_sigmask; /*!< Saving signal mask during sigsuspend */
	uint64_t cpus_allowed; /*!< CPU mask for VE Process*/
	bool ve_traced; /*!< VE task is getting traced */
};

/**
 * @brief VE process fork system call request information
 */
struct ve_fork_info {
	int node_id; /*!< VE process node id */
	int core_id; /*!< VE process core id */
	int parent_pid; /*!< VE process parent PID */
	int child_pid; /*!< VE process child PID */
	int offset; /*!< VE process thread offset */
	uint64_t shm_lhm_addr;
	int shmid;
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

int64_t psm_calc_nr_context_switches(struct ve_node_struct *);
int calc_last_1_5_15_load(struct ve_node_struct *, double *, double *, double *);
void populate_1_5_15_sys_load(struct ve_node_struct *, double, uint64_t);
void calc_sys_load_per_sched_interval(struct ve_node_struct *);
void psm_sched_interval_handler(union sigval);
int psm_relocate_ve_task(int, int, int, int, struct ve_task_struct *);
int psm_least_loaded_node_n_core(void);
int get_ve_core_n_node_new_ve_proc(struct ve_task_struct *, int *, int *);
int init_psm_daemon(char *);
void list_ve_proc(void);
int handle_get_priortiy(pid_t);
int insert_ve_task(int, int, struct ve_task_struct *);
int64_t psm_handle_set_tid_addr(pid_t, uint64_t);
int64_t psm_handle_schedule_ve_process(pid_t);
int psm_handle_exec_ve_process(struct veos_thread_arg *, int *,
		int *, int, char *, bool, uint64_t, int);
int psm_pseudo_send_load_binary_req(struct veos_thread_arg *, int, int, int);
int psm_handle_delete_ve_process(pid_t, int, int);
int psm_handle_set_tid_addr_req(struct veos_thread_arg *);
int psm_handle_schedule_req(struct veos_thread_arg *);
int psm_handle_delete_ve_proc_req(struct veos_thread_arg *);
void delete_entries(struct ve_task_struct *);
void clear_ve_task_struct(struct ve_task_struct *);
int psm_handle_fork_ve_request(pid_t pid, int, int);
struct ve_mm_struct *alloc_ve_mm_struct_node();
struct ve_task_struct *find_ve_task_struct(int, int, int, int, int);
struct ve_task_struct *alloc_ve_task_struct_node(void);
struct ve_thread_struct *alloc_ve_thread_struct_node(void);
struct sighand_struct *alloc_ve_sighand_struct_node(void);
struct ve_task_struct current;
int update_ve_thread_node(struct ve_context_info *, struct ve_thread_struct *);
int schedule_task_on_ve_node_ve_core(struct ve_task_struct *,
		struct ve_task_struct *, bool);
int psm_handle_start_ve_request(struct veos_thread_arg *, int);
int psm_handle_block_request(pid_t);
int psm_handle_un_block_request(pid_t);
int psm_handle_set_syscall_return_req(pid_t, uint64_t);
int psm_handle_set_reg_req(pid_t, uint8_t, int64_t);
void psm_find_sched_new_task_on_core(struct ve_core_struct *, bool);
int psm_handle_halt_core_request(struct halt_ve_cores_info *);
int psm_handle_start_core_request(struct halt_ve_cores_info *);
int psm_handle_signal_req(struct veos_thread_arg *);
int psm_handle_sigreturn_req(struct veos_thread_arg *);
int psm_pseudo_send_signal_ack(struct veos_thread_arg *, char *);
int psm_handle_sigaction_req(struct veos_thread_arg *);
int psm_pseudo_sigaction_ack(struct veos_thread_arg *);
uint64_t psm_address_translation(int, uint64_t);
int psm_del_sighand_struct(struct sighand_struct *);
void psm_reparent_children(struct ve_task_struct *group_leader);
void print_process_tree(struct ve_task_struct *);
void list_init_tasks(void);
int psm_halt_ve_core(int, int);
int psm_start_ve_core(int, int);
long long timeval_diff(struct timeval, struct timeval);
int psm_handle_clk_cputime_request(struct ve_task_struct *, int, struct timespec *);
int psm_handle_get_rlimit_request(struct ve_task_struct *, int, struct rlimit *);
int psm_handle_set_rlimit_request(struct ve_task_struct *, int, struct rlimit);
int64_t psm_handle_getaffinity_request(pid_t, size_t);
int64_t psm_handle_setaffinity_request(pid_t, uint64_t);
int remove_task_from_core_list(int, int, struct ve_task_struct *);
int psm_handle_sched_yield_request(pid_t);
uint64_t get_ve_proc_exec_time(struct ve_task_struct *, int);
uint64_t get_process_tree_exec_time(struct ve_task_struct *);
int psm_handle_get_rusage_request(struct ve_task_struct *, int, struct ve_rusage *);
int psm_handle_pr_set_mm_request(struct ve_task_struct *, uint64_t, uint64_t);
int psm_handle_sysinfo_request(struct ve_task_struct *, struct sysinfo *);
int psm_handle_do_acct_ve(char *);
void psm_acct_collect(int, struct ve_task_struct *);
void veos_acct_ve_proc(struct ve_task_struct *);
int psm_init_shared_file_mmap(struct ve_task_struct *);
#endif
