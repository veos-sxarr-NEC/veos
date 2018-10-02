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
#include "veos_handler.h"
#include "ve_list.h"
#include "ve_atomic.h"
#include "libved.h"
#include "dma.h"
#include "ve_drv.h"
#include "velayout.h"

/**
 * Set to 1 as veos Module run per VE node
 */
#define MAX_VE_NODE_PER_VH 1

/**
 * Maximum VE core supported per VE node
 */
#define VE_MAX_CORE_PER_NODE 16
#define MAX_VE_CORE_PER_VE_NODE -1

/* Defines number of pairs of PCISYARs and PCISYMRs. */
#define VE_PCI_SYNC_PAR_NUM 4

/*Defines number of cr page per node*/
#define MAX_CR_PAGE_PER_NODE 32

#define POLL_TIMEOUT 5000

#define KB 1024
#define VEOS_THREAD_PAGE_SIZE (4*KB)
#define VEOS_BYTES_PER_VE_THREAD 64
#define VEOS_MAX_VE_THREADS (VEOS_THREAD_PAGE_SIZE \
		/ VEOS_BYTES_PER_VE_THREAD)


/**
 * @brief VE Nodes
 */
struct ve_nodes_vh {
	struct ve_node_struct *p_ve_nodes[MAX_VE_NODE_PER_VH]; /*!< Array of VE nodes */
};

extern struct ve_nodes_vh *p_ve_nodes_vh;

#define VE_HANDLE(x) \
	(p_ve_nodes_vh->p_ve_nodes[x]->handle)
#define VE_CORE(x, y) \
	(p_ve_nodes_vh->p_ve_nodes[x]->p_ve_core[y])
#define VE_NODE(x) \
	(p_ve_nodes_vh->p_ve_nodes[x])

#define VE_CORE_USR_REG_ADDR(x, y) \
	(p_ve_nodes_vh->p_ve_nodes[x]->p_ve_core[y]->usr_regs_addr)
#define VE_CORE_SYS_REG_ADDR(x, y) \
	(p_ve_nodes_vh->p_ve_nodes[x]->p_ve_core[y]->sys_regs_addr)
#define VE_CORE_CNT_REG_ADDR(x) \
	(p_ve_nodes_vh->p_ve_nodes[x]->cnt_regs_addr)

#define VE_NODE_ID(node_idx) (node_idx)

#define VE_SYSFS_PATH(node_id)	\
	(p_ve_nodes_vh->p_ve_nodes[node_id]->ve_sysfs_path)

#define SET_ARITHMETIC_MODE(x, val) ((x)->PSW = ((x)->PSW & PSW_AM_MASK) | val);

#define VE_CR_CLUSTER_OFF(i) (offsetof(system_common_reg_t,  CR[(i)]))
#define VE_CRD_OFF(i) (offsetof(core_system_reg_t, CRD[(i)]))

/*CRD registor*/
typedef union crd_t {
	reg_t data;
	struct {
		reg_t pgnum:5, rfu:58, valid:1;
	} bf;
} crd_t;

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
	pthread_mutex_t ve_acct_lock; /*!< Mutex lock for syncronization */
} veos_acct;

/**
 * @brief VE Node Struct
 */
struct ve_node_struct {
	struct ve_core_struct *p_ve_core[VE_MAX_CORE_PER_NODE]; /*!< Pointer to all the cores in this VE node*/
	struct file_desc *file_desc_start; /*!< Global file_desc */
	struct list_head shm_head; /*!< Global shm descriptor */
	volatile int num_ve_proc; /*!< Number of VE processes on this node*/
	int node_num; /*!< Node Id of this VE Node */
	struct buddy_mempool *mp; /*!<*VE memory pool address*/
	struct ve_page **ve_pages; /*!< GLOBAL PAGE ARRAY structure */
	uint64_t nr_pages; /*!< Total Number of pages */
	pciatb_entry_t pciatb[PCIATB_VLD_SIZE]; /*!< PCIATB for access
						* from VHSAA to VEMAA/VERAA*/
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
	pthread_rwlock_t ve_relocate_lock; /*! Global lock for synchronizing task relocation */
	pthread_cond_t stop_cond;/*!< Conditional lock for SIGSTOP signal */
	pthread_cond_t pg_allc_cond;/*!< Conditional lock for allocating ve pages protected by ve_node_lock*/
	uint64_t dirty_pg_num_2M;
	uint64_t dirty_pg_num_64M;
	struct ve_mem_info mem; /*!< VE memory data , mem START and its SIZE */
	vemaa_t zeroed_page_address; /*!< VE Memory Zeroed Page address */
	vedl_handle *handle; /*!< VEDL handle */
	ve_dma_hdl *dh; /*!< VE DMA handle */
	system_common_reg_t *cnt_regs_addr; /*!< Node control registers */
	dmaatb_reg_t dmaatb; /*!< DMAATB for SHM/LHM area */
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
	reg_t pciattr; /*!< PCIATBA register to control PCI attributes */
	unsigned long pci_bar01_vhsaa; /*!< VHSAA of BAR01 */
	void *pci_bar01_sync_addr; /*!< Address for bar01 sync */
	struct buddy_mempool *pci_mempool; /*!<*PCI Mempool*/
	/* PCI accounting data */
	size_t pci_bar01_sz; /*BAR01 size */
	size_t pci_bar01_pgsz; /*BAR01 page size*/
	size_t pci_bar3;
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

#define OPT_PCISYNC1 0
#define OPT_PCISYNC2 1
#define OPT_PCISYNC3 2
#define OPT_CLEANUP  3

#define NOT_REQUIRED 0
#define REQUIRED     1

#define NORMAL       0
#define ABNORMAL     1

#define PROGRAM_NAME "veos"

#define TIMEOUT_SEC 20
#define TIMEOUT_USEC 0

struct ve_mm_struct *find_ve_mm_struct(int, int, int, int, int);
int veos_init(void);
int init_ve_node_struct(struct ve_node_struct *, int, char *);
int init_ve_core_struct(struct ve_core_struct *, struct ve_node_struct *, int);
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
void veos_request_termination(int);
void veos_terminate_node_core(int);
int veos_set_ve_node_state(struct ve_node_struct *, enum os_state);
int ve_make_phys_core_id_table(struct ve_node_struct *);
void veos_abort(const char *, ...)
		__attribute__ ((format(printf, 1, 2)))
		__attribute__((noreturn)) ;
int veos_set_pcisync_option(int, char *);
int veos_send_sigkil(char *);
int64_t veos_convert_sched_options(char *, int, int);
extern volatile sig_atomic_t terminate_flag;
extern pthread_rwlock_t handling_request_lock;
extern int opt_ived; /* -i specified. */
extern unsigned int opt_pcisync; /* -p specified. */
extern pthread_t terminate_dma_th; /* a thread executing veos_terminate_dma() */
extern sem_t terminate_sem;
extern char ived_sock_file[PATH_MAX];
extern int no_update_os_state;

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
	.tgid			= 1,					\
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
}
#endif
