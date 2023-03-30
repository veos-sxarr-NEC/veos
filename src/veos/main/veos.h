/*
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
 * @file veos.h
 * @brief VEOS Initialization Data structures
 */
#ifndef __VEOS_H
#define __VEOS_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <semaphore.h>
#include "ve_list.h"
#include "ve_atomic.h"

#include <ve_drv.h>
#include <libved.h>
#include "dma.h"
#include "mm_type.h"
#include "velayout.h"

/**
 * Set to 1 as veos Module run per VE node
 */
#define MAX_VE_NODE_PER_VH 1

/**
 * Maximum VE core supported per VE node
 */
#define VE_MAX_CORE_PER_NODE 32
#define MAX_VE_CORE_PER_VE_NODE -1

/* Defines number of pairs of PCISYARs and PCISYMRs. */
#define VE_PCI_SYNC_PAR_NUM 4

/* Define numbers of NUMA nodes. */
#define VE_MAX_NUMA_NODE 2

/*Defines number of cr page per node*/
#define MAX_CR_PAGE_PER_NODE 32

#define POLL_TIMEOUT 5000

#define KB 1024
#define VEOS_THREAD_PAGE_SIZE (4*KB)
#define VEOS_BYTES_PER_VE_THREAD 64
#define VEOS_MAX_VE_THREADS (VEOS_THREAD_PAGE_SIZE \
		/ VEOS_BYTES_PER_VE_THREAD)

#define VE_TYPE_VE1	1
#define VE_TYPE_VE3	3
#define VHVE_DMAREQ_HASH_SIZE 128

/**
 * @brief VE Nodes
 */
extern struct ve_node_struct ve_node; /* the VE node */
extern struct ve_node_struct *p_ve_node_global; /* the pointer to VE node */

#define VE_HANDLE(x) \
	(ve_node.handle)
#define VE_CORE(x, y) \
	(ve_node.p_ve_core[y])
#define VE_NODE(x) \
	(p_ve_node_global)

#define VE_CORE_USR_REG(x, y) \
	(ve_node.p_ve_core[y]->usr_regs)
#define VE_CORE_SYS_REG(x, y) \
	(ve_node.p_ve_core[y]->sys_regs)
#define VE_NODE_CNT_REG(x) \
	(ve_node.cnt_regs)

#define VE_NODE_ID(node_idx) (node_idx)

#define VE_SYSFS_PATH(node_id)	\
	(ve_node.ve_sysfs_path)

/**
 * @brief Scheduling Status
 */
enum context_switch {
	ONGOING, /*!< Scheduling ONGOING */
	COMPLETED, /*!< Scheduling COMPLETED */
	HALTED, /*!< Scheduling HALT */
};

#define SET_SCHED_STATE(VAR, STATE) VE_ATOMIC_SET(enum context_switch, &(VAR), STATE)

/**
 * @brief Data structure maintained by VEOS for enabling/disabling accounting
 */
struct ve_acct_struct {
	bool active; /*!< Accounting enable/disable info */
	char *file; /*!< Accounting filename */
	int fd; /*!< File descriptor corresponding to file */
	struct timeval check_space_time; /* !< To check disk space periodically */
	pthread_mutex_t ve_acct_lock; /*!< Mutex lock for syncronization */
} veos_acct;

/**
 * @brief These macros define the behaviour of the free space checking thread
 * which remains active when process accounting is enabled
 */

#define ACCT_RESUME 4 /* resume process accounting if free space >= this value */
#define ACCT_SUSPEND 2 /* suspend process accounting if free space <= this value */
#define ACCT_FREQ 30 /* frequency between two successive free space checks */

/* *
 * @brief VE NUMA Node Struct
 */
struct ve_numa_struct {
	int node_number; /* !< NUMA node number */
	int num_ve_proc; 	/* !< Number of VE process executing on
					VE core belonging to this NUMA node */
	struct ve_core_struct *cores[VE_MAX_CORE_PER_NODE]; /* !< Pointers of ve_core_struct belonging to NUMA node*/
	struct buddy_mempool *mp; /* !< Pointer of memory pool of NUMA node */
};

/* dummy types to hide architecture-dependent data structure */
struct veos_dmaatb_reg;
typedef struct veos_dmaatb_reg veos_dmaatb_reg_t;
union veos_pciatb_entry;
typedef union veos_pciatb_entry veos_pciatb_entry_t;

/**
 * @brief PPS file infomation Struct
 */
struct ve_swap_file_info {
	char path[PATH_MAX * 2]; /* !< Absolute path of PPS file */
	size_t size;         /* !< Size of PPS file */
	int fd;              /* !< fd of PPS file */
	bool is_opened;      /* !< Status flag of PPS file */
	bool not_del_after_swapin;  /* !< Flag indicating whether the PPS file
					can be deleted after swap in when no
					resource is swapped out */
	uid_t uid;           /* !< uid to create the PPS file */
	gid_t gid;           /* !< gid to create the PPS file */
	bool is_created_by_root;  /* !< Flag whether the PPS file is create by root */
	pid_t child_pid;     /* !< pid of the child process that creates the PPS file */
	int sockfd;          /* !< file descriptor for socket */
};

/**
 * @brief VE Node Struct
 */
struct ve_node_struct {
	struct ve_core_struct *p_ve_core[VE_MAX_CORE_PER_NODE]; /*!< Pointer to all the cores in this VE node*/
	struct file_desc *file_desc_start; /*!< Global file_desc */
	struct list_head shm_head; /*!< Global shm descriptor */
	volatile int num_ve_proc; /*!< Number of VE processes on this node*/
	pthread_mutex_t num_ve_proc_lock; /*!< Lock for num_ve_proc */
	int node_num; /*!< Node Id of this VE Node */
	struct ve_page **ve_pages; /*!< GLOBAL PAGE ARRAY structure */
	uint64_t nr_pages; /*!< Total Number of pages */
	veos_pciatb_entry_t *pciatb;

	pthread_mutex_t ve_node_lock; /*!< VE Node Mutex lock */
	pthread_mutex_t shm_node_lock; /*!< SHM node Mutex lock */
	pthread_mutex_t dmaatb_node_lock; /*!< DMAATB node Mutex lock */
	pthread_mutex_t ve_pages_node_lock; /*!< Mutex lock for ve page array*/
	pthread_mutex_t pgcache_lock; /*!< PAGE cache Mutex lock */
	pthread_mutex_t amm_node_lock; /*!< AMM node Mutex lock */
	pthread_mutex_t stop_mtx;/*!< Mutex lock specific to SIGSTOP */
	pthread_mutex_t pciatb_lock;/*!< Per VE node lock to protect pciatb entry update */
	pthread_mutex_t ve_tasklist_lock; /*!< Global tasklist_lock to serialize deletions/modifications
					* of task lists */
	pthread_mutex_t udma_bitmap_lock; /*!< Mutex lock for clearing/setting free_udma_bitmap */

	pthread_rwlock_t ve_relocate_lock; /*! Global lock for synchronizing task relocation */
	pthread_cond_t stop_cond;/*!< Conditional lock for SIGSTOP signal */
	pthread_cond_t zombie_cond;/*!< Conditional lock for zombie task cleanup */
	pthread_mutex_t zombie_mtx;/*!< Mutex lock specific to zombie task cleanup */
	volatile int num_zombie_proc; /*!< Number of zombie VE processes created
				       * using 'time' command on this node */
	pthread_cond_t pg_allc_cond;/*!< Conditional lock for allocating ve pages protected by ve_node_lock*/
	uint64_t dirty_pg_num_2M[VE_MAX_NUMA_NODE];
	uint64_t dirty_pg_num_64M[VE_MAX_NUMA_NODE];
	struct ve_mem_info mem; /*!< VE memory data , mem START and its SIZE */
	vemaa_t zeroed_page_address; /*!< VE Memory Zeroed Page address */
	vedl_handle *handle; /*!< VEDL handle */
	ve_dma_hdl *dh; /*!< VE DMA handle */
	vedl_common_reg_handle *cnt_regs; /*!< Node control registers */
	veos_dmaatb_reg_t *dmaatb; /*!< DMAATB for SHM/LHM area */
	enum context_switch scheduling_status; /*!< Scheduling ongoing flag for VE Node */
	timer_t psm_sched_timer_id; /*!< Scheduling Timer id for this node */
	const char *ve_sysfs_path; /*!< SYSFS directory Path */
	int ve_phys_core_id[VE_MAX_CORE_PER_NODE]; /*!< Mapping of logical to physical core id */
	int nr_avail_cores; /*!< Number of available cores on VE node */
	struct timeval sched_stime; /*!< Start time of PSM scheduler */
	struct list_head ve_sys_load_head; /*!< Head element of VE system load */
	uint64_t total_sys_load_time; /*!< Total load time in microseconds maintained */
	unsigned long nr_active; /*!< Number of active task on VE node */
	uint64_t total_forks; /*!< Number of forks since VE node is booted */
	uint64_t node_boot_time; /*!< Time at which node is booted */
	ve_reg_t pciattr; /*!< PCIATBA register to control PCI attributes */
	unsigned long pci_bar01_vhsaa; /*!< VHSAA of BAR01 */
	void *pci_bar01_sync_addr; /*!< Address for bar01 sync */
	struct buddy_mempool *pci_mempool; /*!<*PCI Mempool*/
	/* PCI accounting data */
	size_t pci_bar_mem_sz; /*BAR01 size */
	size_t pci_bar_mem_pgsz; /*BAR01 page size*/
	size_t pci_bar_cr;
	/*CR management*/
	bool cr_map[32];
	uint32_t cr_th_pg;
	uint32_t cr_mpi_pg;
	uint32_t cr_th_req;
	struct ve_cr_page *ve_cr_pages; /*!PAGE array of all CR pages*/
	struct ve_cr_rlim *node_cr_rlim;
	pthread_mutex_t cr_node_lock; /*! CR node Mutex Lock */
	pgno_t vdso_pfn; /*! VE Memory VDSO Page */
	pgno_t zeroed_pfn; /*! VE Memory Resv Page for clearing memory*/
	uint64_t vdso_pcientry; /*! Allocated pci enrty for vdso*/
	char cr_dump_fname[FILENAME_MAX];
	sem_t node_sem; /* Semaphore for performing scheduling on node */
	int partitioning_mode; /* !< An indicator of partitioning mode */
	int numa_count; /* !< The number of NUMA nodes */
	struct ve_numa_struct numa[VE_MAX_NUMA_NODE]; /* !< Data structures to store NUMA information */
	struct buddy_mempool *pps_mp; /* !< Memory poll of PPS buffer */
	size_t pps_mp_used[VE_MAX_NUMA_NODE]; /* !< Used size of PPS buffer for every NUMA node, in Byte */
	struct buddy_mempool *pps_file_offset; /* !< Memory poll of PPS file */
	size_t pps_file_used[VE_MAX_NUMA_NODE]; /* !< Used size of PPS file for every NUMA node, in Byte */
	struct list_head swap_request_pids_queue; /* !< Swap request queue, which contains struct veos_swap_request_info */
	pthread_mutex_t swap_request_pids_lock; /* !< Lock wihch protecs Swap request queue */
	bool swap_request_pids_enable; /* !< Status of swap request queue */
	bool resource_freed; /* !< Resource freed flag for swap */
	pthread_cond_t swap_request_pids_cond; /* !< Condition variable which is used to start Swap-out or Swap-in */
	size_t pps_buf_size; /* !< Size of PPS buffer in Byte */
	struct ve_swap_file_info pps_file; /* !< Information of PPS file */
	pthread_mutex_t pps_file_lock; /* !< Lock which protects pps_file */
	void *pps_file_transfer_buffer; /* !< Address of PPS file transfer buffer */
	void *arch_dep_data; /* !< architecture-dependent data */
	int ve_type;
	uint32_t free_udma_bitmap; /* !< bitmap to find VE core id whose DMA descriptor pair (H and E) are free */
	pthread_mutex_t pps_file_buffer_lock; /* !< Lock for transferring data from pps file buffer to pps file */
	int couredump_launcher_sockfd;
	pid_t couredump_launcher_pid;
};

/**
 * @brief Maintain the VE sytem load
 */
struct ve_sys_load {
	double sys_load; /*!< Load on system */
	uint64_t time_slice; /*!< Time interval of load */
	struct list_head list; /*!< List of next load of system */

};
/**
 * VEOS abort cause message buffer size
 */
#define VE_ABORT_CAUSE_BUF_SIZE 512

#define OPT_PCISYNC1           0
#define OPT_PCISYNC2           1
#define OPT_PCISYNC3           2
#define OPT_CLEANUP            3
#define OPT_VESWAPMAX          4
#define OPT_VESWAP_FILE_PATH   5
#define OPT_VESWAP_FILE_MAX    6
#define OPT_VESWAP_FILE_USER   7
#define OPT_VESWAP_FILE_GROUP  8
#define OPT_SKIPMEMCLEAR       9
#define OPT_DRORDERING         10


#define NOT_REQUIRED 0
#define REQUIRED     1

#define NORMAL       0
#define ABNORMAL     1

#define PROGRAM_NAME "veos"

#define TIMEOUT_SEC 20
#define TIMEOUT_USEC 0

#define CLOCK_GATING_OFF        0
#define CLOCK_GATING_ON         1
#define CHECK_STATE_RETRY_CNT   10
#define CHECK_STATE_RETRY_DELAY 1000 /* Same as ASSIGN_RETRY_DELAY */
#define CLOCK_GATING_STATE_MASK 0x0000000000000800ULL
#define CLOCK_GATING_STATE_BIT  52
#define QTYPE                   254

struct ve_mm_struct *find_ve_mm_struct(int, int, int, int, int);
int veos_init(void);
int veos_init_ve_node(void);
int veos_cleanup_pseudo(struct ve_node_struct *);
int veos_terminate_dma(void *);
int veos_init_pci_sync(void);
int veos_scheduler_timer(struct ve_node_struct *);
int veos_remove_timer(struct ve_node_struct *);
void veos_main_thread(void *arg);
int veos_amm_init(vedl_handle *);
extern char drv_sock_file[PATH_MAX];
extern struct ve_task_struct ve_init_task;
extern pthread_rwlock_t init_task_lock;
int veos_register_signal_hnldr(void);
int psm_terminate_all(int);
void veos_request_termination(int, siginfo_t *, void *);
void veos_terminate_node_core(int);
int veos_set_ve_node_state(struct ve_node_struct *, enum os_state);
int ve_make_phys_core_id_table(struct ve_node_struct *);
void veos_abort(const char *, ...)
		__attribute__ ((format(printf, 1, 2)))
		__attribute__((noreturn)) ;
int veos_set_pcisync_option(int, char *);
int veos_send_sigkil(char *);
int64_t veos_convert_sched_options(char *, int64_t, int64_t);
extern volatile sig_atomic_t terminate_flag;
extern pthread_rwlock_t handling_request_lock;
extern pthread_rwlock_t veos_scheduler_lock;  /*protects time-slice and timer-interval*/

extern int opt_ived; /* -i specified. */
extern unsigned int opt_pcisync; /* -p specified. */
extern pthread_t terminate_dma_th; /* a thread executing veos_terminate_dma() */
extern sem_t terminate_sem;
extern char ived_sock_file[PATH_MAX];
extern int no_update_os_state;
extern int skip_memclear_flag;

extern bool veos_term;
/* Used for log4c logging in veos module */

#define CAT_OS_CORE cat_os_core
#define VEOS_TRACE(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, fmt " %s()", ## __VA_ARGS__, __func__)
#define VEOS_INFO(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)
#define VEOS_ERROR(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define VEOS_DEBUG(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define VEOS_CRIT(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_CRIT, fmt, ## __VA_ARGS__)
#define VEOS_FATAL(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL, fmt, ## __VA_ARGS__)
#define VEOS_WARN(fmt, ...) \
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)
extern log4c_category_t *cat_os_core;
extern const log4c_location_info_t locinfo;

/* Initialising INIT ve_task_struct */
#define VE_INIT_TASK(ve_tsk) \
{									\
	.pid			= 1,					\
	.namespace_pid		= 1,					\
	.ptraced		= false,					\
	.priority		= 0,					\
	.sched_class		= 0,					\
	.ve_task_state		= -1,					\
	.core_id		= -1,					\
	.node_id		= -1,					\
	.p_ve_core		= NULL,					\
	.next			= NULL,					\
	.p_ve_thread		= NULL,					\
	.p_ve_mm		= NULL,					\
	.parent			= NULL,					\
	.children		= LIST_HEAD_INIT(ve_tsk.children),	\
	.siblings		= LIST_HEAD_INIT(ve_tsk.siblings),	\
	.thread_group		= LIST_HEAD_INIT(ve_tsk.thread_group),	\
	.tasks			= LIST_HEAD_INIT(ve_tsk.tasks),		\
	.block_status		= 0,					\
	.group_leader		= &ve_tsk,				\
	.exit_signal		= 0,					\
	.clear_child_tid	= NULL,					\
	.offset			= 0,					\
	.sr_context_bitmap	= 0,					\
	.stime			= {0},					\
	.exec_time		= 0,					\
	.vfork_state		= -1,					\
	.vforked_proc		= 0,					\
	.sighand		= NULL,					\
	.sigpending		= 0,					\
	.ve_task_lock		= PTHREAD_MUTEX_INITIALIZER,		\
	.offset_lock		= PTHREAD_MUTEX_INITIALIZER,		\
	.sstatus		= INVALID,				\
	.ipc_sync		= NULL,					\
	.ve_set_next_thread_worker      = false,			\
	.ve_task_worker_belongs = NULL,					\
	.ve_task_worker_belongs_chg = false,				\
	.ve_task_have_worker    = false,				\
	.ve_worker_thread       = NULL					\
}
#endif
