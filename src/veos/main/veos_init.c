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
 * @file  veos_init.c
 * @brief Initialization of veos
 *
 * This contains the functions that are used to initialize VEOS data structures.
 * VEOS uses these data structures to handle VE process requests.
 */

#include <libudev.h>
#include <stdio.h>
#include <search.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>

#include <veos_arch_defs.h>
#include "velayout.h"
#include "veos.h"
#include <libved.h>
#include "veos_ived.h"
#include "ve_mem.h"
#include "pciatb_api.h"
#include "task_sched.h"
#if 0 /* TODO: remove */
#include "task_mgmt.h"
#endif
#include "vesync.h"

#define CLEAN_PSEUDO_SLEEP_TIME 3
#define TERMINATE_DMA_SLEEP_TIME 3
#define VE_MIN_NUMA_NODE 1
#define VE_PARTITIONING_MODE 1
#define VE_NORMAL_MODE 0

pthread_t terminate_dma_th; /* a thread executing veos_terminate_dma() */
/* Buffer to store PCISYARs value. */
static uint64_t pcisyar_argval[VE_PCI_SYNC_PAR_NUM] = {0, 0, 0, 0};
/*  Buffer to store PCISYMRs value. */
static uint64_t pcisymr_argval[VE_PCI_SYNC_PAR_NUM] = {0, 0, 0, 0};

static void init_ve_numa_struct(struct ve_node_struct *);
static int veos_make_numa_core_map(struct ve_node_struct *, int *);
static int init_veos_mode (struct ve_node_struct *);

const struct veos_arch_ops *_veos_arch_ops;

/**
 * @brief Initialize VE Node structure.
 *
 * @param[in,out] p_ve_node Pointer to VE Node to be initialized
 * @param[in] node_id Node ID
 * @param[in] drv_file VE driver file
 *
 * @return 0 on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 *
 */
static int init_ve_node_struct(struct ve_node_struct *p_ve_node, int node_id,
								char *drv_file)
{
	int retval = -1;
	int p_ret = 0;
	int a_core_num = 0;
	int mapped_core_num = 0;
	pthread_rwlockattr_t attr;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	if (!p_ve_node)
		goto hndl_return1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Initializing VE node %d", node_id);

	p_ve_node->num_ve_proc = 0;
	p_ve_node->node_num = node_id;
	p_ve_node->scheduling_status = COMPLETED;
	p_ve_node->psm_sched_timer_id = NULL;
	p_ve_node->total_sys_load_time = 0;
	p_ve_node->nr_active = 0;
	p_ve_node->total_forks = 0;
	p_ve_node->dh = NULL;
	p_ve_node->vdso_pfn = -1;
	p_ve_node->vdso_pcientry = -1;
	p_ve_node->cnt_regs = NULL;
	p_ve_node->swap_request_pids_enable = false;
	p_ve_node->pps_buf_size = 0;
	INIT_LIST_HEAD(&(p_ve_node->ve_sys_load_head));
	gettimeofday(&(p_ve_node->sched_stime), NULL);

	if (sem_init(&p_ve_node->node_sem, 0, 1) == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Initializing semaphore failed for node %d", node_id);
		goto hndl_return1;
	}

	/* Time in microseconds at time which node is booted */
	p_ve_node->node_boot_time = (p_ve_node->sched_stime.tv_sec
			* MICRO_SECONDS) + p_ve_node->sched_stime.tv_usec;

	/* Getting VE Handle for veos */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "VE driver file is %s",
								drv_file);
	p_ve_node->handle = vedl_open_ve(drv_file, -1);
	if (p_ve_node->handle == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Acquiring VE handle failed");
		goto hndl_return1;
	}

	p_ret = vedl_request_ownership(p_ve_node->handle, -1);
	if ( p_ret != 0 && errno != ENOTSUP) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Acquiring VE ownership failed");
		goto hndl_return0;
	}

	_veos_arch_ops = _veos_arch_find(p_ve_node->handle, NULL);
	if (_veos_arch_ops == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Initializing ops for VE arch class failed.");
		goto hndl_return;
	}
	p_ve_node->ve_sysfs_path = vedl_get_sysfs_path(p_ve_node->handle);
	if (p_ve_node->ve_sysfs_path == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Getting sysfs path failed");
		goto hndl_return;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "sysfs file path: %s",
						p_ve_node->ve_sysfs_path);
	/* Set os_stat in to "os_state" file in sysfs */
	if (veos_set_ve_node_state(p_ve_node, OS_ST_INITIALIZING) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Setting VE node state failed");
		goto hndl_return;
	}

	/* Get the mapping of Logical to Physical Core ID */
	mapped_core_num = ve_make_phys_core_id_table(p_ve_node);
	if (mapped_core_num < 1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to make physical core id table");
		goto hndl_return;
	}

	/* Initialize Accounting related data structure */
	veos_acct.active = false;
	veos_acct.file = NULL;
	veos_acct.fd = -1;

	p_ret = pthread_mutex_init(&(veos_acct.ve_acct_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Mutex init (ve_acct_lock) failed: %s",
			strerror(p_ret));
		goto hndl_return;
	}

	/* Fetch the MAX CORE NUMBER supported by this node */
	a_core_num = vedl_get_num_of_core(p_ve_node->handle);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"The number of cores is %d",
					a_core_num);
	if (a_core_num < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to fetch the number of cores");
		goto hndl_return;
	} else if (a_core_num > VE_MAX_CORE_PER_NODE) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"The number of cores is invalid: %d",
					a_core_num);
		goto hndl_return;
	} else if (mapped_core_num != a_core_num) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"The number of cores %d is different from detected cores %d",
						a_core_num, mapped_core_num);
		goto hndl_return;
	}
	p_ve_node->nr_avail_cores = a_core_num;

	/* allocate PCI space mapping and DMA space mapping data structures */
	if (0 != (*_veos_arch_ops->arch_alloc_veos_pci_dma_pgtables)(
				&p_ve_node->pciatb, &p_ve_node->dmaatb)) {
		goto hndl_return;
	}

	/* Mapping VE Node Control Registers */
	p_ve_node->cnt_regs = vedl_mmap_cnt_reg(p_ve_node->handle);
	if (p_ve_node->cnt_regs == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mapping common register failed");
		goto hndl_alloc_pgtbls;
	}

	vedl_barrier_regs_read(p_ve_node->handle);
	invalidate_dmaatb(p_ve_node->dmaatb);

	/* Initialize mutex lock for stopping thread */
	p_ret = pthread_mutex_init(&(p_ve_node->stop_mtx), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init for stop_mtx failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/* Initialize the conditional variable */
	p_ret = pthread_cond_init(&(p_ve_node->stop_cond), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Conditional variable init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}
	/* Initialize mutex lock for zombie cleanup thread */
	p_ret = pthread_mutex_init(&(p_ve_node->zombie_mtx), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init for zombie_mtx failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/* Initialize the conditional variable */
	p_ret = pthread_cond_init(&(p_ve_node->zombie_cond), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Conditional variable init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/* Initialize mutex lock for modification temp file cleanup thread */
	p_ret = pthread_mutex_init(&(p_ve_node->modtmp_mtx), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init for modtmp_mtx failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/* Initialize the conditional variable */
	p_ret = pthread_cond_init(&(p_ve_node->modtmp_cond), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Conditional variable init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/*init ve_node lock*/
	p_ret = pthread_mutex_init(&(p_ve_node->ve_node_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Node mutex lock init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/* init tasklist_lock*/
	p_ret = pthread_mutex_init(&(p_ve_node->ve_tasklist_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Node tasklist lock init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}
	p_ret = pthread_mutex_init(&(p_ve_node->amm_node_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init (amm_node_lock) failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	p_ret = pthread_mutex_init(&(p_ve_node->pgcache_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init (pgcache_lock) failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	p_ret = pthread_mutex_init(&(p_ve_node->pciatb_lock), NULL);
	if (0 != p_ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init (pciatb_lock) failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}
	p_ret = pthread_mutex_init(&(p_ve_node->shm_node_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init (shm_node_lock) failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}

	/*init ve_node lock*/
	p_ret = pthread_mutex_init(&(p_ve_node->cr_node_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"cr_node_lock init failed: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}
	p_ret = pthread_rwlockattr_init(&attr);
	if (p_ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to initialize attribute for "
				"init task read write lock: %s",
				strerror(p_ret));
		goto hndl_c_reg;
	}
	p_ret = pthread_rwlockattr_setkind_np(&attr,
				PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	if (p_ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Setting rwlock attribute failed: %s",
				strerror(p_ret));
		goto hndl_dstry_attr;
	}

	/* Initialize init_task_lock */
	p_ret = pthread_rwlock_init(&init_task_lock, &attr);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Read/write init task lock failed: %s",
					strerror(p_ret));
		goto hndl_dstry_attr;
	}

	/* Initialize relocate lock */
	p_ret = pthread_rwlock_init(&(VE_NODE(0)->ve_relocate_lock), &attr);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Read/write relocate lock init failed %s",
				strerror(p_ret));
		goto hndl_dstry_attr;
	}

	p_ret = pthread_mutex_init(&(p_ve_node->dmaatb_node_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init (dmaatb_node_lock) failed: %s",
				strerror(p_ret));
		goto hndl_dstry_attr;
	}

	/*Initializing Mutex lock for clearing/setting free_udma_bitmap*/
	p_ret = pthread_mutex_init(&(p_ve_node->udma_bitmap_lock), NULL);
        if (p_ret != 0) {
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                                "Mutex init udma_bitmap_lock failed: %s",
                                strerror(p_ret));
                goto hndl_dstry_attr;
        }

	p_ret = pthread_mutex_init(&(p_ve_node->num_ve_proc_lock), NULL);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init num_ve_proc_lock failed: %s",
				strerror(p_ret));
		goto hndl_dstry_attr;
	}

	p_ret = init_veos_mode(p_ve_node);
	if (p_ret != 0)
		goto hndl_dstry_attr;

	ve_init_task.sighand = alloc_ve_sighand_struct_node();
	if (!ve_init_task.sighand) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Initializing signal handling failed");
		goto hndl_dstry_attr;
	} else
		ve_init_task.sighand->action[SIGCHLD - 1].sa_handler = SIG_IGN;

	retval = 0;
	if (0 != (p_ret = pthread_rwlockattr_destroy(&attr))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to destroy attribute for "
				"init task read write lock: %s",
				strerror(p_ret));
	}
	goto hndl_return1;
hndl_dstry_attr:
	if (0 != (p_ret = pthread_rwlockattr_destroy(&attr))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to destroy attribute for "
				"init task read write lock: %s",
				strerror(p_ret));
	}
hndl_c_reg:
	if (vedl_munmap_common_reg(p_ve_node->cnt_regs) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Unmapping common register (BAR4) failed");
	}
hndl_alloc_pgtbls:
	(*_veos_arch_ops->arch_free_veos_pci_dma_pgtables)(
				p_ve_node->pciatb, p_ve_node->dmaatb);
hndl_return:
	vedl_release_ownership(p_ve_node->handle);
hndl_return0:
	vedl_close_ve(p_ve_node->handle);
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Initializes the VE Core structure for veos
 *
 * @param[in,out] p_ve_core Pointer to VE Core to be initialized
 * @param[in] p_ve_node Pointer to VE Node
 * @param[in] core_loop VE core number (logical value)
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
static int init_ve_core_struct(struct ve_core_struct *p_ve_core,
		struct ve_node_struct *p_ve_node, int core_loop, int numa_num)
{
	int retval = -1;
	int p_ret = 0;
	pthread_rwlockattr_t attr;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	if (!p_ve_core || !p_ve_node)
		goto hndl_return;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Initializing VE core %d",
								core_loop);
	p_ve_core->ve_task_list = NULL;
	p_ve_core->curr_ve_task = NULL;
	p_ve_core->core_num = core_loop;
	p_ve_core->phys_core_num = p_ve_node->ve_phys_core_id[core_loop];
	p_ve_core->ve_core_state = STOPPED;
	p_ve_core->num_ve_proc  = 0;
	p_ve_core->nr_active = 0;
	p_ve_core->node_num = 0;
	p_ve_core->scheduling_status = COMPLETED;
	p_ve_core->busy_time = 0;
	p_ve_core->busy_time_prev = 0;
	p_ve_core->core_stime = (struct timeval){0};
	p_ve_core->nr_switches = 0;
	p_ve_core->usr_regs = NULL;
	p_ve_core->sys_regs = NULL;
	p_ve_core->p_ve_node = p_ve_node;
	p_ve_core->numa_node = numa_num;
        p_ve_core->pwr_throttle_cnt = 0;
        p_ve_core->current_PMC14 = 0;
        p_ve_core->previous_PMC14 = 0;
	if (p_ve_core->numa_node == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"This core does not belong to any NUMA nodes, "
				"Logical core ID: %d physical core ID: %d",
				p_ve_core->core_num, p_ve_core->phys_core_num);
		goto hndl_return;
	}

	if (sem_init(&p_ve_core->core_sem, 0, 1) == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Initializing semaphore failed for core %d", p_ve_core->core_num);
		goto hndl_return;
	}

	gettimeofday(&(p_ve_core->core_uptime), NULL);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
		"Logical core ID: %d physical core ID: %d NUMA Node ID: %d",
		p_ve_core->core_num, p_ve_core->phys_core_num,
		p_ve_core->numa_node);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Mapping user register and system register for core %d",
				core_loop);

	p_ve_core->usr_regs = vedl_mmap_usr_reg(p_ve_node->handle,
						p_ve_core->phys_core_num);

	if (p_ve_core->usr_regs == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Mapping user register failed for core %d: physical core %d",
					core_loop,
					p_ve_core->phys_core_num);
		goto hndl_return;
	}

	vedl_barrier_regs_read(p_ve_node->handle);

	p_ve_core->sys_regs = vedl_mmap_sys_reg(p_ve_node->handle,
						p_ve_core->phys_core_num);
	if (p_ve_core->sys_regs == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Mapping system register failed for core %d: physical core %d",
					core_loop,
					p_ve_core->phys_core_num);
		goto hndl_u_reg;
	}

	vedl_barrier_regs_read(p_ve_node->handle);

	p_ret = pthread_rwlockattr_init(&attr);
	if (p_ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to initialize attribute for "
				"core's read write lock: %s",
				strerror(p_ret));
		goto hndl_s_reg;
	}
	p_ret = pthread_rwlockattr_setkind_np(&attr,
				PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	if (p_ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Setting rwlock attribute failed: %s",
				strerror(p_ret));
		goto hndl_dstry_attr;
	}
	p_ret = pthread_rwlock_init(&(p_ve_core->ve_core_lock), &attr);
	if (p_ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Read/write core lock init failed %s",
					strerror(p_ret));
		goto hndl_dstry_attr;
	}

	retval = 0;

	if (0 != (p_ret = pthread_rwlockattr_destroy(&attr))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to destroy attribute for "
				"core's read write lock: %s",
				strerror(p_ret));
	}
	goto hndl_return;
hndl_dstry_attr:
	if (0 != (p_ret = pthread_rwlockattr_destroy(&attr))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to destroy attribute for "
				"core's read write lock: %s",
				strerror(p_ret));
	}
hndl_s_reg:
	if (vedl_munmap_sys_reg(p_ve_core->sys_regs) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Unmapping non-prefetchable system register failed: core %d",
				core_loop);
	}
	p_ve_core->sys_regs = NULL;

hndl_u_reg:
	if (vedl_munmap_usr_reg(p_ve_core->usr_regs) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Unmapping non-prefetchable user register failed: core %d",
				core_loop);
	}
	p_ve_core->usr_regs = NULL;


hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Initialize all the necessary data structures relating the
 * VE node corresponding to the specified VE driver file.
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_init_ve_node(void)
{

	struct ve_node_struct *p_ve_node;
	struct ve_core_struct *p_ve_core;
	int core_loop = 0;
	int retval = -1;
	int ret = 0;
	/* Initialized at veos_make_numa_core_map() */
	int numa_core_map[VE_MAX_CORE_PER_NODE];
	ve_reg_t regdata;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/* Allocates and initialize struct ve_node_struct */
	p_ve_node = &ve_node;
	memset(p_ve_node, 0, sizeof(struct ve_node_struct));

	if (init_ve_node_struct(p_ve_node, 0, drv_sock_file) != 0)
		goto hndl_ve;

	ret = veos_make_numa_core_map(p_ve_node, numa_core_map);
	if (ret != 0)
		goto hndl_core;

	/* Allocates and initialize struct ve_core_struct */
	for (core_loop = 0; core_loop < p_ve_node->nr_avail_cores;
								core_loop++) {
		p_ve_core = (struct ve_core_struct *)
					malloc(sizeof(struct ve_core_struct));
		if (p_ve_core == NULL) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Malloc for p_ve_core[%d] failed: %s",
					core_loop, strerror(errno));
			goto hndl_core;
		}
		p_ve_node->p_ve_core[core_loop] = p_ve_core;
		if (init_ve_core_struct(p_ve_core, p_ve_node, core_loop,
						numa_core_map[core_loop]) != 0)
			goto hndl_core;

		/* Ensure VE core is halt state. */
		if (psm_halt_ve_core(0, core_loop, &regdata, false, false) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to halt ve core %d",
					core_loop);
			goto hndl_core;
		}

		/* Ensure user mode DMA is halt state. */
		if (psm_stop_udma(core_loop, DMA_DESC_E_H) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to stop udma %d",
				core_loop);
			goto hndl_core;
		}
	}

	init_ve_numa_struct(p_ve_node);

	if (_veos_arch_ops->arch_main_construct_node_arch_dep_data(p_ve_node)
		!= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Faied to construct architecture dependent data.");
		goto hndl_core;
	}

	retval = 0;
	goto hndl_return;

hndl_core:
	for (core_loop = 0; core_loop < p_ve_node->nr_avail_cores;
								core_loop++) {
		p_ve_core = p_ve_node->p_ve_core[core_loop];
		if (p_ve_core == NULL)
			continue;
		if (p_ve_core->sys_regs != NULL) {
			if (vedl_munmap_sys_reg(p_ve_core->sys_regs) != 0) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			       "Unmapping system register failed: core %d",
			       core_loop);
			}
		}
		if (p_ve_core->usr_regs != NULL) {
			if (vedl_munmap_usr_reg(p_ve_core->usr_regs) != 0) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Unmapping user register failed: core %d",
				core_loop);
			}
		}
		free(p_ve_core);
	}
	if (vedl_munmap_common_reg(p_ve_node->cnt_regs) != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Unmapping common register failed");

	vedl_release_ownership(p_ve_node->handle);
	vedl_close_ve(p_ve_node->handle);

hndl_ve:
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Send SIGKILL to pseudo processes's tid.
 *
 * @param[in] tids The pseudo processes's tids separated by a space.
 *
 * @return Numbers of pseudo processes which was sent SIGKILL on Success,
 * -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_send_sigkil(char *tids)
{
	pid_t tid = 0;
	int cnt = 0;
	char *tok;
	char *save_ptr;
	char *end_ptr;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/* Send KILL signal. */
	for (tok = strtok_r(tids, " \n", &save_ptr); tok != NULL;
				tok = strtok_r(NULL, " \n", &save_ptr)) {
		errno = 0;
		tid = (pid_t)strtol(tok, &end_ptr, 10);
		if (errno != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to convert tid. %s",
					strerror(errno));
			cnt = -1;
			goto hdnl_return;
		}
		if (*end_ptr != '\0') {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Illegal character %s in attribute file",
				end_ptr);
			cnt = -1;
			goto hdnl_return;
		}
		if (tid > 1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_WARN,
						"Send SIGKILL to %d", tid);
			kill(tid, SIGKILL);
			cnt++;
		}
	}

hdnl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return cnt;

}

/**
 * @brief Kills all pseudo processes which open the VE driver
 * file and waits their termination
 *
 * @param[in] p_ve_node Pointer to VE Node
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_cleanup_pseudo(struct ve_node_struct *p_ve_node)
{

	FILE *fp;
	char filename[PATH_MAX];
	char *buf = NULL;
	int retval = 0;
	long page_size = 0;
	int cnt;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/*
	 * get page size.
	 * The size of files in sysfs is equal to page size.
	 */
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to get pagesize");
		retval = -1;
		goto hndl_return;
	}
	buf = (char *)malloc(page_size * sizeof(char));
	if (buf == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc to read task_id_all failed: %s",
				strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	memset(buf, 0, page_size * sizeof(char));

	if ((strlen("/task_id_all") + strlen(p_ve_node->ve_sysfs_path)) >
						(sizeof(filename) - 1)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"task_id_all filepath is too long");
		retval = -1;
		goto hndl_return;
	}

	snprintf(filename, sizeof(filename), "%s/task_id_all",
						p_ve_node->ve_sysfs_path);

	/* Kills all pseudo processes. */
	for (;;) {
		cnt = 0;
		fp = fopen(filename, "r");
		if (fp == NULL) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to open %s: %s",
						filename,
						strerror(errno));
			retval = -1;
			goto hndl_return;
		}
		/*
		 * Currently, task_id_all has '\n' at the end.
		 * On the other hand, specifications for sysfs tell that
		 * '\n' at the end is dispensable if no seudo process exists.
		 */
		if (fgets(buf, page_size, fp) == NULL) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"No pseudo process exists");
			fclose(fp);
			goto hndl_return;
		}
		fclose(fp);
		/* Send KILL signal. */
		cnt = veos_send_sigkil(buf);
		if (cnt < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"Sending KILL signal failed");
			retval = -1;
			goto hndl_return;
		}
		if (cnt == 0)
			goto hndl_return;

		sleep(CLEAN_PSEUDO_SLEEP_TIME);

		if (terminate_flag != NOT_REQUIRED) {
			retval = -1;
			goto hndl_return;
		}

	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	if (buf != NULL)
		free(buf);

	return retval;

}

/**
 * @brief Wait termination request of VEOS.
 *
 * @param[in] *arg Pointer of a dma handle
 *
 * @return always 0.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_terminate_dma(void *arg)
{
	sigset_t set;
	int p_ret = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	/* Unblock all signals. */
	sigfillset(&set);
	p_ret = pthread_sigmask(SIG_UNBLOCK, &set, NULL);
	if (p_ret != 0)
		veos_abort("Failed to unblock signal mask. %s",
							strerror(p_ret));

	/* wait to update terminate_flag. */
	while (1) {
		if (sem_wait(&terminate_sem) != 0) {
			if (errno == EINTR) {
				continue;
			} else {
				veos_abort("Failed to wait semaphore. %s",
							strerror(errno));
			}
		}
		break;
	}
	if (sem_post(&terminate_sem) != 0)
		veos_abort("Failed to post semaphore. %s", strerror(errno));

	p_ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (p_ret != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to block signals. %s",
						strerror(p_ret));

	sleep(TERMINATE_DMA_SLEEP_TIME);
	ve_dma_terminate_all((ve_dma_hdl *)arg);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return 0;

}

/**
 * @brief Initialize pairs of PCISYAR and PCISYMR.
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_init_pci_sync(void)
{

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	uint8_t i;
	uint8_t mask = 1;

	for (i = 1; i < VE_PCI_SYNC_PAR_NUM; i++) {
		if ((mask & opt_pcisync) != 0) {
			if (veos_amm_set_pcisyar(i, pcisyar_argval[i]) != 0) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Setting PCISYAR register failed");
				return -1;
			}
			if (veos_amm_set_pcisymr(i, pcisymr_argval[i]) != 0) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Setting PCISYMR register failed");
				return -1;
			}
		}
		mask <<= 1;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");

	return 0;

}

/**
 * @brief Initializes all the necessary data structures relating
 * the VE node corresponding to the specified VE driver file,
 * initializes internal components.
 *
 * @return 0 on Success, -1 on Failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_init(void)
{
	int ret_p = 0;
	int retval = -1;
	int core_loop = 0;
	ve_dma_hdl *dh = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/* Initialize Data Structure */
	if (veos_init_ve_node() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Failed to initialize VE node");
		goto hndl_return;
	}

	/* open DMA handle */
	dh = ve_dma_open_p(VE_HANDLE(0));
	if (dh == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to initialize DMA manager");
		goto hndl_free;
	}
	ve_node.dh = dh;

	/* remove all tasks relating to the VE node */
	if (vedl_delete_all_ve_task(VE_HANDLE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to delete all VE tasks");
		goto hndl_dma;
	}

	/* release all VH physical pages relating to the VE node */
	if (vedl_release_pindown_page_all(VE_HANDLE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Releasing pin-downed page failed");
		goto hndl_dma;
	}

	/* reset core's interrupt counter to zero */
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
								core_loop++) {
		if (vedl_reset_interrupt_count(VE_HANDLE(0), core_loop) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Resetting interrupt count of core %d",
					core_loop);
			goto hndl_dma;
		}
	}

	if (veos_cleanup_pseudo(VE_NODE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Cleaning up pseudo process failed");
		goto hndl_dma;
	}

	(*_veos_arch_ops->arch_turn_on_clock_gating)();

	/* open a socket to connect IVED. */
	if (opt_ived != 0) {
		if (veos_ived_register_osdata() != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Registering VEOS to IVED failed");
			goto hndl_dma;
		}
	}


	/* Creates a thread which executes veos_terminate_dma() */
	ret_p = pthread_create(&terminate_dma_th, NULL,
			(void *)&veos_terminate_dma, (void *)(ve_dma_hdl *)dh);
	if (ret_p != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to create thread. %s", strerror(ret_p));
			goto hndl_ived;
	}

	/* initialize AMM */
	if (veos_amm_init(VE_HANDLE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Initializing memory manager failed");
		goto hndl_thread;
	}

	/* Allocate address for pci bar01 sync */
	if (veos_alloc_pci_bar01_sync_addr() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mapping bar01 failed");
		goto hndl_amm;
	}

	/* Start veos Scheduler timer */
	if (veos_scheduler_timer(VE_NODE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to start scheduler");
		goto hndl_bar01_sync_addr;
	}

	retval = 0;
	goto hndl_return;

hndl_bar01_sync_addr:
	veos_free_pci_bar01_sync_addr();
hndl_amm:
	/*clear AMM data*/
	veos_amm_fini();
hndl_thread:
	veos_request_termination(0, NULL, NULL);
	pthread_join(terminate_dma_th, NULL);
hndl_ived:
	if (opt_ived != 0) {
		if (veos_ived_erase_osdata() != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Unregistering VEOS from IVED failed");
		}
	}

hndl_dma:
	/* Close DMA handle. */
	if (dh != NULL) {
		if (ve_dma_close_p(VE_NODE(0)->dh) != 0)
			veos_abort("Failed to finalize DMA manager");
	}

hndl_free:
	/* Free all buffers */
	veos_terminate_node_core(ABNORMAL);

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Register signal handler for clean termination of veos.
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_register_signal_hnldr(void)
{
	static struct sigaction act;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	memset(&act, '\0', sizeof(act));
	act.sa_sigaction = veos_request_termination;
	act.sa_flags = SA_SIGINFO;

	if (sigaction(SIGTERM, &act, NULL) < 0) {
		perror("Handle SIGTERM");
		return -1;
	}
	if (sigaction(SIGINT, &act, NULL) < 0) {
		perror("Handle SIGINT");
		return -1;
	}
	if (sigaction(SIGQUIT, &act, NULL) < 0) {
		perror("Handle SIGQUIT");
		return -1;
	}

	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return 0;
}

/**
 * @brief SET the specified OS state of VEOS in SYSFS.
 *        If global variable no_update_os_state is not zero, this
 *        function does not set OS state and return 0.
 *
 * @param[in] p_ve_node Pointer to VE Node struct
 * @param[in] state OS state to set
 *
 * @return 0 on success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_set_ve_node_state(struct ve_node_struct *p_ve_node,
							enum os_state state)
{
	int retval = -1;
	FILE *fp;
	char filename[PATH_MAX];

	if (no_update_os_state) {
		return 0;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	if ((strlen("/os_state") + strlen(p_ve_node->ve_sysfs_path)) >
						(sizeof(filename) - 1)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"os_state filepath is too long");
		goto hndl_return;
	}
	snprintf(filename, sizeof(filename), "%s/os_state",
						p_ve_node->ve_sysfs_path);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Setting os_state: %d", state);
	fp = fopen(filename, "w");
	if (fp == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Fail to open %s: %s",
						filename,
						strerror(errno));
		goto hndl_return;
	}

	/* Setting Node state in sysfs */
	fprintf(fp, "%d", state);
	fclose(fp);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Create the physical core id table for the available
 * cores in SYSFS.
 *
 * @detail Make a bitmap for the available cores in SYSFS and
 * put a index number of the bitmap to p_ve_node->ve_phys_core_id
 * in order.
 *
 * @param[in] p_ve_node Pointer to struct VE Node
 *
 * @return Core numbers on success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int ve_make_phys_core_id_table(struct ve_node_struct *p_ve_node)
{
	int core_num = -1;
	int cntr, indx;
	uint64_t valid_cores = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	if (!p_ve_node)
		goto hndl_return;

	FILE *fp;
	char filename[PATH_MAX];
	char valid_cores_from_file[LINE_MAX];
	char *endptr = NULL;
	char *tmp;

	if ((strlen("/cores_enable") + strlen(p_ve_node->ve_sysfs_path)) >
						(sizeof(filename) - 1)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"cores_enable filepath is too long");
		goto hndl_return;
	}
	snprintf(filename, sizeof(filename), "%s/cores_enable",
						p_ve_node->ve_sysfs_path);

	fp = fopen(filename, "r");
	if (fp == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Fails to open %s: %s",
						filename,
						strerror(errno));
		goto hndl_return;
	}

	if (fgets(valid_cores_from_file, sizeof(valid_cores_from_file), fp)
								== NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to get valid cores: %s",
					strerror(errno));
		fclose(fp);
		goto hndl_return;
	}
	fclose(fp);

	tmp = strchr(valid_cores_from_file, '\n');
	if (tmp != NULL)
		*tmp = '\0';

	errno = 0;
	valid_cores = (uint64_t)strtoul(valid_cores_from_file, &endptr, 16);
	if (errno != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "Failed to get valid cores: %s", strerror(errno));
		goto hndl_return;
	}
	if (*endptr != '\0') {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to get valid cores: %s, %s",
					valid_cores_from_file,
					endptr);
		goto hndl_return;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Valid cores: %ld",
								valid_cores);

	for (cntr = 0, indx = 0; indx < VE_MAX_CORE_PER_NODE; indx++) {
		p_ve_node->ve_phys_core_id[indx] = -1;

		if ((valid_cores & (1 << indx)) == 0)
			continue;

		p_ve_node->ve_phys_core_id[cntr++] = indx;
	}
	core_num = cntr;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Detected cores: %d", core_num);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return core_num;
}
/**
 * @brief get values spcified "--pcisync" option.
 *
 * @param[in] index index of spcified pcisync.
 * @param[in] pcisy_val PCISYAR and PCISYMR value.
 *
 * @return 0 on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */
int veos_set_pcisync_option(int index, char *pcisy_val)
{
	char *prefix = "0x";
	char *end_ptr = NULL;
	char *save_ptr = NULL;
	char *pcisyar;
	char *pcisymr;
	int ar_index;

	pcisyar = strtok_r(pcisy_val, ",", &save_ptr);
	pcisymr = strtok_r(NULL, ",", &save_ptr);
	if ((pcisyar == NULL) || (pcisymr == NULL)) {
		fprintf(stderr, "The values of --pcisync must be separeted"
								" by \',\'\n");
		return -1;
	}

	if ((strncmp(prefix, pcisyar, 2) != 0) ||
					(strncmp(prefix, pcisymr, 2)) != 0) {
		fprintf(stderr, "Value must have \"0x\" prefix"
						"[pcisyar:%s][pcisymr:%s]\n",
						pcisyar,
						pcisymr);
		return -1;
	}

	switch (index) {
	case OPT_PCISYNC1:
		ar_index = 1;
		break;
	case OPT_PCISYNC2:
		ar_index = 2;
		break;
	case OPT_PCISYNC3:
		ar_index = 3;
		break;
	default:
		fprintf(stderr, "Wrong pcisync index[%d] specified\n", index);
		return -1;
	}

	errno = 0;
	pcisyar_argval[ar_index] = strtoull(pcisyar, &end_ptr, 0);
	if (errno != 0) {
		fprintf(stderr, "Failed to get pcisyar value due to %s\n",
							strerror(errno));
		return -1;
	}
	if (*end_ptr != '\0') {
		fprintf(stderr, "Wrong number specified[%s]\n", pcisyar);
		return -1;
	}

	errno = 0;
	pcisymr_argval[ar_index] = strtoull(pcisymr, &end_ptr, 0);
	if (errno != 0) {
		fprintf(stderr, "Failed to get pcisymr value due to %s\n",
							strerror(errno));
		return -1;
	}
	if (*end_ptr != '\0') {
		fprintf(stderr, "Wrong number specified[%s]\n", pcisymr);
		return -1;
	}

	return 0;
}

/**
 * @brief convert value which is specified as sched options.
 *
 * @param[in] value specified value.
 * @param[in] min minimum value
 * @param[in] max maximum value
 *
 * @return converted value on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */

int64_t veos_convert_sched_options(char *value, int64_t min, int64_t max)
{
	char *end_ptr = NULL;

	int64_t ret = -1;
	int64_t tmp = 0;

	errno = 0;
	tmp = (int64_t)strtoll(value, &end_ptr, 10);
	if (errno != 0) {
		fprintf(stderr, "Failed to convert value due to %s\n",
							strerror(errno));
		goto hndl_return;
	}
	if (*end_ptr != '\0') {
		fprintf(stderr, "Wrong value is specified[%s]\n", value);
		goto hndl_return;
	}

	if ((tmp < min) || (tmp > max)) {
		fprintf(stderr, "Value must be between %ld and %ld\n",
								min, max);
		goto hndl_return;
	}

	ret = tmp;

hndl_return:
	return ret;
}

/**
 * @brief Decide VEOS mode in accordance with "Partitioning Mode".
 *
 * @param[in] p_ve_node Pointer to VE Node which was initialized.
 *
 * @return 0 on on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */

static int init_veos_mode (struct ve_node_struct *p_ve_node)
{
	int ret = 0;
	int retval = -1;
	int fd = 0;
	char partition_path[PATH_MAX] = {};
	char partition_mode[LINE_MAX] = {};
	char *end_ptr = NULL;

	errno = 0;
	ret = snprintf(partition_path, PATH_MAX,
			"%s/partitioning_mode", p_ve_node->ve_sysfs_path);
	if (ret >= PATH_MAX) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"partitioning_mode filepath is too long");
		goto hndl_return;
	} else if (ret < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to set partitioning_mode filepath due to %s",
			strerror(errno));
		goto hndl_return;
	}

	fd = open(partition_path, (O_RDONLY|O_NOFOLLOW));
	if (fd == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to open partitioning_mode due to %s",
			strerror(errno));
		goto hndl_return;
	}

	ret = (int)read(fd, partition_mode, LINE_MAX - 1);
	if (ret <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to read partitioning_mode, "
				"read returned %d, %s", ret, strerror(errno));
		goto hndl_close;
	}

	end_ptr = strchr(partition_mode, '\n');
	if (end_ptr != NULL)
		*end_ptr = '\0';

	errno = 0;
	p_ve_node->partitioning_mode =
				(int)strtol(partition_mode, &end_ptr, 10);
	if (errno != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to convert partitioning_mode due to %s",
			strerror(errno));
		goto hndl_close;
	}
	if (*end_ptr != '\0') {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "partitioning_mode is not only numbers, 0x%x", *end_ptr);
		goto hndl_close;
	}

	if (p_ve_node->partitioning_mode == VE_NORMAL_MODE) {
		p_ve_node->numa_count = VE_MIN_NUMA_NODE;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"VEOS mode : normal");
	} else if (p_ve_node->partitioning_mode == VE_PARTITIONING_MODE) {
		p_ve_node->numa_count = VE_MAX_NUMA_NODE;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"VEOS mode : NUMA");
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Wrong partitioning_mode, %d",
						p_ve_node->partitioning_mode);
		goto hndl_close;
	}

	retval = 0;

hndl_close:
	ret = close(fd);
	if (ret != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to close due to %s", strerror(errno));
		retval = -1;
	}

hndl_return:
	return retval;
}

/**
 * @brief Create a mapping between NUMA nodes and logical cores.
 *
 * @param[in] p_ve_node Pointer to VE Node which was initialized.
 * @param[in, out] numa_core_map An initialized array of int,
 * and its length must be VE_MAX_CORE_PER_NODE.
 *
 * @detail Indexes of numa_core_map indicate logical cores,
 * and values of numa_core_map indicate NUMA node to which the logical core
 * belongs.
 *
 * @return 0 on on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */

static int veos_make_numa_core_map(
		struct ve_node_struct *p_ve_node, int *numa_core_map)
{
	int retval = -1;
	int ret = 0;
	int i = 0;
	int j = 0;
	int phys_core = 0;
	int fd = 0;
	uint64_t numa_cores[VE_MAX_NUMA_NODE] = {};
	char numa_cores_path[PATH_MAX] = {};
	char tmp[LINE_MAX] = {};
	char *endptr = NULL;

	/* Initialize */
	for (i = 0; i < VE_MAX_CORE_PER_NODE; i++) {
		numa_core_map[i] = -1;
	}

	if (p_ve_node->partitioning_mode == VE_NORMAL_MODE) {
		/* All cores are mapped to numa_node-0 */
		for (i = 0; i < p_ve_node->nr_avail_cores; i++) {
			numa_core_map[i] = 0;
		}
		retval = 0;
		goto hndl_return;
	}

	for (i = 0; i < p_ve_node->numa_count; i++) {
		errno = 0;
		ret = snprintf(numa_cores_path, PATH_MAX,
			       "%s/numa%d_cores", p_ve_node->ve_sysfs_path, i);
		if (ret >= PATH_MAX) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"numa%d_cores filepath is too long", i);
			goto hndl_return;
		} else if (ret < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to set numa%d_cores filepath due to %s",
				i, strerror(errno));
			goto hndl_return;
		}

		fd = open(numa_cores_path, (O_RDONLY|O_NOFOLLOW));
		if (fd == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to open numa%d_cores due to %s",
							i, strerror(errno));
			goto hndl_return;
		}

		memset(tmp, '\0', LINE_MAX);

		ret = (int)read(fd, tmp, LINE_MAX - 1);
		if (ret <= 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			       "Failed to read numa%d_cores, "
			       "read returned %d, %s", i, ret, strerror(errno));
			goto hndl_close;
		}

		endptr = strchr(tmp, '\n');
		if (endptr != NULL)
			*endptr = '\0';

		errno = 0;
		numa_cores[i] = (uint64_t)strtoull(tmp, &endptr, 16);
		if (errno != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to convert numa%d_cores due to %s",
				i, strerror(errno));
			goto hndl_close;
		}
		if (*endptr != '\0') {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"numa%d_cores is not only numbers, 0x%x",
				i, *endptr);
			goto hndl_close;
		}

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"numa%d_cores, 0x%lx", i, numa_cores[i]);

		ret = close(fd);
		if (ret != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to close due to %s", strerror(errno));
			goto hndl_return;
		}
	}

	for (i = 0; i < p_ve_node->nr_avail_cores; i++) {
		phys_core = p_ve_node->ve_phys_core_id[i];
		for (j = 0; j < p_ve_node->numa_count; j++) {
			if ((numa_cores[j] & (1 << phys_core)) != 0) {
				if (numa_core_map[i] == -1) {
					numa_core_map[i] = j;
				} else {
					VE_LOG(CAT_OS_CORE,
					       LOG4C_PRIORITY_ERROR,
					       "numa_cores overlaps with each other");
					goto hndl_return;
				}
			}
		}
	}

	retval = 0;
	goto hndl_return;

hndl_close:
	errno = 0;
	ret = close(fd);
	if (ret != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to close due to %s", strerror(errno));

hndl_return:
	return retval;
}

/**
 * @brief Initialize ve_numa_struct.
 *
 * @param[in] p_ve_node Pointer to VE Node which was initialized.
 *
 * @internal
 *
 * @author VEOS main
 */

static void init_ve_numa_struct(struct ve_node_struct *p_ve_node)
{
	int i = 0;
	int j = 0;
	int cntr = 0;

	for (i = 0; i < VE_MAX_NUMA_NODE; i++) {
		p_ve_node->numa[i].node_number = i;
		p_ve_node->numa[i].mp = NULL;
		for (j = 0; j < VE_MAX_CORE_PER_NODE; j++) {
			p_ve_node->numa[i].cores[j] = NULL;
		}
		for (j = 0, cntr = 0; j < p_ve_node->nr_avail_cores; j++) {
			if (p_ve_node->p_ve_core[j]->numa_node == i) {
				p_ve_node->numa[i].cores[cntr++] =
							p_ve_node->p_ve_core[j];
			}
		}
	}
}
