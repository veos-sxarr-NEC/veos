/**
 * @file  psm_task_mgmt.c
 * @brief Handles VE task management activities
 *
 * This contains the functions that are used to handle VE task
 * creation, deletion and scheduling.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <mqueue.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "psm_task_mgmt.h"
#include "amm_psm_if.h"
#include "amm_mem.h"
#include "veos.h"
#include "psm_signal_handler.h"
#include "pseudo_veos.pb-c.h"
#include <sys/prctl.h>
#include "velayout.h"
#ifdef __AUSIM_ENV
#include "../ausim_driver/ausim_driver_ipc.h"
#endif
#include "libved.h"

/**
 * @brief Change the core state to HALT by setting EXS register as EXS_STOP.
 *
 * @param[in] node_id VE Node Id of core to Stop
 * @param[in] core_id VE Core Id of core to Stop
 *
 * @return 0 on Success, -1 on failure.
 */
int psm_halt_ve_core(int node_id, int core_id)
{
	int retval = -1;
	reg_t regdata;
	struct timeval now;
	struct ve_core_struct *p_ve_core;
	p_ve_core = VE_CORE(node_id, core_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

#ifndef __PCIDEV_ENV
	retval = vedl_lock_core_reg(VE_HANDLE(node_id),
			p_ve_core->phys_core_num);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_lock_core_reg fail for core %d\n",
				core_id);
		goto hndl_return;
	}
	retval = vedl_get_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id, core_id),
			EXS,
			&regdata);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_usr_reg fail for core %d\n",
				core_id);
		(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
				p_ve_core->phys_core_num);
		goto hndl_return;
	}
	if ((regdata & 0x3ULL) == EXS_STOP) {
		/* the core is already stopped */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Core[%d] already stopped\n",
				core_id);
		(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
				p_ve_core->phys_core_num);
		retval = 0;
		goto hndl_return1;
	}
	regdata = (regdata & ~0x3ULL) | EXS_STOP;
	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id, core_id),
			EXS,
			regdata);
	(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
			p_ve_core->phys_core_num);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_set_usr_reg failed for core %d\n",
				core_id);
		goto hndl_return;
	}
#else
	/* In FPGA set the EXS_STOP bit in EXS register as
	 * all other bits are protected by VE HW
	 * */
	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id,
				core_id),
			EXS,
			EXS_STOP);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_set_usr_reg fail for core %d\n",
				core_id);
		goto hndl_return;
	}
	do {
		retval = vedl_get_usr_reg(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id,
					core_id),
				EXS,
				&regdata);
		if (retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_get_sys_reg failed"
					" for core %d.\n", core_id);
			goto hndl_return;
		}
	} while (regdata & 0x2);

	if (EXS_STOP == regdata) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "reset interrupt count\n");
		if (-1 == vedl_reset_interrupt_count(VE_HANDLE(node_id), core_id)) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"reset interrupt count failed\n");
			retval = -1;
			goto hndl_return;
		}
	}
#endif
#ifndef __PCIDEV_ENV
hndl_return1:
#endif
	if (!p_ve_core->core_stime.tv_sec &&
			!p_ve_core->core_stime.tv_usec) {
		retval = 0;
		goto hndl_return;
	}

	gettimeofday(&now, NULL);
	if (true == p_ve_core->core_running) {
		p_ve_core->busy_time +=
			timeval_diff(now, p_ve_core->core_stime);
		p_ve_core->core_running = false;
	}
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Change the core state from STOP to RUNNING.
 *
 * @param[in] node_id VE Node Id of core to Start
 * @param[in] core_id VE Core Id of core to Start
 *
 * @return 0 on Success, -1 on failure.
 */
int psm_start_ve_core(int node_id, int core_id)
{
	int retval = -1;
	struct ve_core_struct *p_ve_core;
	p_ve_core = VE_CORE(node_id, core_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
#ifndef __PCIDEV_ENV
	reg_t regdata;

	retval = vedl_lock_core_reg(VE_HANDLE(node_id),
			p_ve_core->phys_core_num);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_lock_core_reg fail for core %d\n",
				core_id);
		goto hndl_return;
	}
	retval = vedl_get_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id, core_id),
			EXS,
			&regdata);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_usr_reg fail for core %d\n",
				core_id);
		(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
				p_ve_core->phys_core_num);
		goto hndl_return;
	}

	/* the core is already running */
	if ((regdata & 0x3ULL) == EXS_RUN) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Core[%d] is already running\n",
				core_id);
		(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
				p_ve_core->phys_core_num);
		retval = 0;
		goto hndl_return;
	}

	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id,
				core_id),
			EXS,
			EXS_RUN);

	(void)vedl_unlock_core_reg(VE_HANDLE(node_id),
			p_ve_core->phys_core_num);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_set_usr_reg fail for core %d\n",
				core_id);
		goto hndl_return;
	}
#else
	/* In FPGA set the EXS_RUN bit in EXS register as
	 * all other bits are protected by VE HW
	 * */
	retval = vedl_set_usr_reg(VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id,
				core_id),
			EXS,
			EXS_RUN);
	if (0 != retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_set_usr_reg fail for core %d\n",
				core_id);
		goto hndl_return;
	}
#endif
	p_ve_core->core_running = true;
	gettimeofday(&(p_ve_core->core_stime), NULL);
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Calculate the total number of context switches across all
 * VE cores of given node.
 *
 * @param[in] p_ve_node Pointer to VE Node struct
 *
 * @return positive value on success, -1 on failure.
 */
int64_t psm_calc_nr_context_switches(struct ve_node_struct *p_ve_node)
{
	int64_t retval = -1;
	int64_t sum = 0;
	int core_loop = 0;
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!p_ve_node)
		goto hndl_return;

	for (; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
		p_ve_core = VE_CORE(p_ve_node->node_num, core_loop);
		if (NULL == p_ve_core) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG Core ID: %d struct is NULL\n",
					core_loop);
			continue;
		}
		sum += p_ve_core->nr_switches;
	}
	retval = sum;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Calculate the VE system last 1min, 5min, 15min load
 *
 * @param[in] p_ve_node Pointer to struct VE Node
 * @param[out] sys_load_1 Last 1min VE system load
 * @param[out] sys_load_5 Last 5min VE system load
 * @param[out] sys_load_15 Last 15min VE system load
 *
 * @return 0 on success, -1 on failure.
 */
int calc_last_1_5_15_load(struct ve_node_struct *p_ve_node,
		double *sys_load_1, double *sys_load_5, double *sys_load_15)
{
	int retval = -1;
	struct ve_sys_load *tmp;
	struct list_head *p;
	double load_1 = 0;
	double load_5 = 0;
	double load_15 = 0;
	uint64_t time = 0;
	int itr_1 = 0;
	int itr_5 = 0;
	int itr_15 = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_node || !sys_load_1 || !sys_load_5 || !sys_load_15)
		goto hndl_return;

	list_for_each_prev(p, &(p_ve_node->ve_sys_load_head)) {
		tmp = list_entry(p, struct ve_sys_load, list);
		if (time < (60 * MICRO_SECONDS)) {
			load_1 += tmp->sys_load;
			itr_1++;
		}

		if (time < (300 * MICRO_SECONDS)) {
			load_5 += tmp->sys_load;
			itr_5++;
		}
		load_15 += tmp->sys_load;
		itr_15++;
		time += tmp->time_slice;
	}

	*sys_load_1 = load_1/(double)itr_1;
	*sys_load_5 = load_5/(double)itr_5;
	*sys_load_15 = load_15/(double)itr_15;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"\nLoad in last (1min %f itr %d) (5min %f itr %d)"
			" (15min %f itr %d)\n\n",
			*sys_load_1, itr_1,
			*sys_load_5, itr_5,
			*sys_load_5, itr_15);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief It populates the list of VE system load for last 15min maximum
 * in the Node struct.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 * @param[in] load Load on system at every scheduler interval
 * @param[in] time Time slice for that scheduler interval
 */
void populate_1_5_15_sys_load(struct ve_node_struct *p_ve_node,
		double load, uint64_t time)
{
	struct ve_sys_load *ve_load;
	struct ve_sys_load *tmp;
	struct list_head *p;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!p_ve_node)
		goto hndl_return;

	ve_load = malloc(sizeof(struct ve_sys_load));
	if (NULL == ve_load) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Malloc fails: %s\n",
			strerror(errno));
		goto hndl_return;
	}
	ve_load->sys_load = load;
	ve_load->time_slice = time;
	p_ve_node->total_sys_load_time += time;
	list_add_tail(&(ve_load->list), &(p_ve_node->ve_sys_load_head));

	/* Maximum last 15min load of VE system is maintained
	 * when system load time increases from 15min entries from
	 * the list are removed.
	 */
	while (p_ve_node->total_sys_load_time > (900 * MICRO_SECONDS)) {
		/* Removing the first element of the list */
		p = p_ve_node->ve_sys_load_head.next;
		tmp = list_entry(p, struct ve_sys_load, list);
		p_ve_node->total_sys_load_time -= tmp->time_slice;
		list_del(p);
		free(tmp);
	}
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Calculate the system load on every scheduler expiry.
 *
 * @param[in] p_ve_node Pointer to VE node struct
 */
void calc_sys_load_per_sched_interval(struct ve_node_struct *p_ve_node)
{
	struct ve_core_struct *p_ve_core;
	int core_loop = 0;
	double per_core_load = 0;
	double per_node_load = 0;
	struct timeval now;
	uint64_t time_slice = 0;
	uint64_t nr_active = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!p_ve_node)
		goto hndl_return;

	gettimeofday(&now, NULL);
	time_slice = timeval_diff(now, p_ve_node->sched_stime);
	p_ve_node->sched_stime = now;
	for (; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
		p_ve_core = VE_CORE(p_ve_node->node_num, core_loop);
		if (NULL == p_ve_core) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG Core ID: %d struct is NULL\n",
					core_loop);
			continue;
		}

		per_core_load = (double)((p_ve_core->busy_time -
				p_ve_core->busy_time_prev) / (double)time_slice);
		nr_active += p_ve_core->nr_active;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Load On Core %d (In %.2f Sec) is %.2f%%\n",
				core_loop,
				(double)(time_slice/(double)MICRO_SECONDS),
				(per_core_load * 100));
		p_ve_core->busy_time_prev = p_ve_core->busy_time;
		per_node_load += per_core_load;
	}

	/* Average load on a NODE */
	per_node_load = per_node_load/MAX_VE_CORE_PER_VE_NODE;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"VE System Load (In %.2f Sec): %.4f, Active Task: %d\n",
			(double)(time_slice/(double)MICRO_SECONDS),
			per_node_load * p_ve_node->nr_active,
			p_ve_node->nr_active);

	/* Populate the load in list maintained to calculate system
	 * load in last 1min, 5min, 15min.
	 */
	populate_1_5_15_sys_load(p_ve_node,
			per_node_load * p_ve_node->nr_active,
			time_slice);

	p_ve_node->nr_active = nr_active;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Handles interrupt coming from PSM scheduling interrupt generator.
 * @detail Interrupt generator generates an interrupt after every "TIME_SLICE"
 * uS. This function handles the interrupt and updates data structure and takes
 * resecheduling decision based on current load on VE node and VE cores. This
 * function tries to distribute the load evenly amongst VE nodes and VE cores.
 * This function also schedules the very next task in the VE core task list.
 *
 * @param[in] psm_sigval sigval coming from start timer function
 */
void psm_sched_interval_handler(union sigval psm_sigval)
{
	struct timespec current_time;
	int node_loop = 0, core_loop = 0;
	struct ve_node_struct *p_ve_node;
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");


	/* node loop */
	for (; node_loop < MAX_VE_NODE_PER_VH; node_loop++) {
		p_ve_node = VE_NODE(VE_NODE_ID(node_loop));

		if (NULL == p_ve_node) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG Node ID: %d struct is NULL\n",
					VE_NODE_ID(node_loop));
			continue;
		}

		if (ONGOING == p_ve_node->scheduling_status) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Scheduling ongoing for Node %d\n",
					VE_NODE_ID(node_loop));
			continue;
		}

		/* TODO: Currently there is no need of node lock in
		 * scheduler.
		 */

		/* Start handling scheduling for this NODE
		 * Change the Node scheduling_status
		 * */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Setting ongoing for Node %d\n",
				VE_NODE_ID(node_loop));
		SET_SCHED_STATE(p_ve_node->scheduling_status, ONGOING);
#ifdef VE_OS_DEBUG
		fprintf(stdout, "Tracing Init\n");
		/* Print existing VE process PID starting from
		 * the children list of INIT VE task
		 * */
		print_process_tree(&ve_init_task);
		/* Traverse task list maintained be INIT VE task */
		list_init_tasks();
#endif
		/* core loop */
		for (; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
			p_ve_core = VE_CORE(VE_NODE_ID(node_loop), core_loop);
			if (NULL == p_ve_core) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"BUG Core ID: %d struct is NULL\n",
						core_loop);
				continue;
			}

			if ((ONGOING == p_ve_core->scheduling_status) ||
					(p_ve_core->ve_core_state == HALT)) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"core[%d] state is either HALT"
						" or scheduling is ongoing on this core"
						" core state : %d,"
						" scheduling status : %d\n",
						p_ve_core->core_num,
						p_ve_core->ve_core_state,
						p_ve_core->scheduling_status);
				continue;
			}
			psm_find_sched_new_task_on_core(p_ve_core, true);
		}
		core_loop = 0;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Scheduling Completed for Node %d\n",
				VE_NODE_ID(node_loop));
		SET_SCHED_STATE(p_ve_node->scheduling_status, COMPLETED);

		/* Caluculate the system load on every scheduler timer
		 * expiry.
		 */
		calc_sys_load_per_sched_interval(p_ve_node);
	}
	/* For DEBUG to check granularity of SCHED timer clock
	 * */
	if (0 == clock_gettime(CLOCK_MONOTONIC, &current_time)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Time Secs: %lld N_Secs: %lld\n",
				(long long int)current_time.tv_sec,
				(long long int)current_time.tv_nsec);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"time() failed ....\n");
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Calculates the time difference between two given timestamp.
 *
 * @param[in] end_time End time
 * @param[in] start_time Start time
 *
 * @return time difference between two timestamp
 */
long long timeval_diff(struct timeval end_time, struct timeval start_time)
{
	struct timeval difference;

	difference.tv_sec = end_time.tv_sec - start_time.tv_sec;
	difference.tv_usec = end_time.tv_usec - start_time.tv_usec;

	while (difference.tv_usec < 0) {
		difference.tv_usec += 1000000;
		difference.tv_sec -= 1;
	}

	return 1000000LL*difference.tv_sec + difference.tv_usec;
}

/**
 * @brief Finds and schedules the most eligible task on core
 *
 * @param[in] p_ve_core Core on which new task is to be scheduled
 * @param[in] scheduler_expiry Is scheduler expired
 */
void psm_find_sched_new_task_on_core(struct ve_core_struct *p_ve_core,
		bool scheduler_expiry)
{
	reg_t regdata;
	int retval, i;
	reg_t sr_tmp[64];
	int node_id, core_id;
	struct ve_task_struct *task_to_schedule = NULL;
	struct ve_task_struct *loop_cntr = NULL;
	struct ve_task_struct *curr_ve_task;
	struct timeval now_time;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_core)
		goto hndl_return1;

	if (ONGOING == p_ve_core->scheduling_status) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Scheduling is already Ongoing for Core: %d\n",
				p_ve_core->core_num);
		goto hndl_return1;
	}

	pthread_rwlock_rdlock(&(p_ve_core->ve_core_lock));
	curr_ve_task = p_ve_core->curr_ve_task;
	node_id = p_ve_core->node_num;
	core_id = p_ve_core->core_num;

	if (NULL == p_ve_core->ve_task_list) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"No task on Core %d\n", p_ve_core->core_num);
		goto hndl_return;
	}

	SET_SCHED_STATE(p_ve_core->scheduling_status, ONGOING);

	psm_halt_ve_core(p_ve_core->node_num, p_ve_core->core_num);

	/* STOP the VE core */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Stopped core : %d\n", core_id);

	if (NULL != curr_ve_task && curr_ve_task->reg_dirty == true) {
		/*
		 * If the corresponding bit in scalar register bitmap is
		 * set we must store the current value of register in temporary
		 * register array, then fetch hardware register and restore
		 * previous values.
		 */
		if (curr_ve_task->sr_context_bitmap) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Preserving context of software register\n");
			for (i = 0; i < 64; i++) {
				if (GET_BIT(curr_ve_task->sr_context_bitmap, i)) {
					sr_tmp[i] = curr_ve_task->
						p_ve_thread->SR[i];
					VE_LOG(CAT_OS_CORE,
						LOG4C_PRIORITY_DEBUG,
						"Storing SR[%d]: 0x%lx in tmp\n",
						i, sr_tmp[i]);
				}
			}
		}

		/* Copy context from hardware registers
		 * to software for curr_ve_task */
		vedl_get_usr_reg_all(VE_HANDLE(node_id),
				VE_CORE_USR_REG_ADDR(node_id, core_id),
				(core_user_reg_t *)curr_ve_task->
				p_ve_thread);
		/* Restore the saved context back.*/
		if (curr_ve_task->sr_context_bitmap) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Restoring context of software register\n");
			for (i = 0; i < 64; i++) {
				if (GET_BIT(curr_ve_task->
							sr_context_bitmap, i)) {
					curr_ve_task->p_ve_thread->
						SR[i] = sr_tmp[i];
					VE_LOG(CAT_OS_CORE,
						LOG4C_PRIORITY_DEBUG,
						"Restoring SR[%d] with 0x%lx\n",
						i, sr_tmp[i]);
				}
			}
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"SR Bitmap 0x%lx\n",
					curr_ve_task->sr_context_bitmap);
			curr_ve_task->sr_context_bitmap = 0;
		}

		curr_ve_task->reg_dirty = false;
		gettimeofday(&now_time, NULL);
		pthread_mutex_lock(&(curr_ve_task->ve_task_lock));
		curr_ve_task->exec_time += timeval_diff(now_time,
				(curr_ve_task->stime));

		/* Check the RLIMIT_CPU resource limit of current
		 * VE task.
		 *
		 * If limit exceeds the soft limit then SIGXCPU signal
		 * is send to VE process, if exceeds the hard limit
		 * then SIGKILL is send.
		 */
		if (((curr_ve_task->exec_time)/(double)MICRO_SECONDS) >
				curr_ve_task->rlim[RLIMIT_CPU].rlim_cur) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Sending Signal SIGXCPU to pid %d\n",
					curr_ve_task->pid);
			kill(curr_ve_task->pid, SIGXCPU);
		}

		if (((curr_ve_task->exec_time)/(double)MICRO_SECONDS) >
				curr_ve_task->rlim[RLIMIT_CPU].rlim_max) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Sending Signal SIGKILL to pid %d\n",
					curr_ve_task->pid);
			kill(curr_ve_task->pid, SIGKILL);
		}

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"\n\nCurrent PID : %d IC: %lx"
				" LR : %lx SP : %lx SR12 : %lx"
				" SR0 : %lx SR1 : %lx SR2 : %lx EXS: %lx\n\n",
				curr_ve_task->pid,
				curr_ve_task->p_ve_thread->IC,
				curr_ve_task->p_ve_thread->SR[10],
				curr_ve_task->p_ve_thread->SR[11],
				curr_ve_task->p_ve_thread->SR[12],
				curr_ve_task->p_ve_thread->SR[00],
				curr_ve_task->p_ve_thread->SR[01],
				curr_ve_task->p_ve_thread->SR[02],
				curr_ve_task->p_ve_thread->EXS);
		pthread_mutex_unlock(&(curr_ve_task->ve_task_lock));
	}

	if (NULL != curr_ve_task &&
			RUNNING ==  p_ve_core->curr_ve_task->ve_task_state) {
		/* Handling scenario:
		 * When monc or any other h/w exception like ILSA/ILPV/ILOP etc
		 * is encountered on VE and schedule timer expires before the
		 * Block request is served by veos.
		 * */
		retval = vedl_get_usr_reg(
				VE_HANDLE(p_ve_core->node_num),
				VE_CORE_USR_REG_ADDR(p_ve_core->node_num,
					p_ve_core->core_num),
				EXS,
				&regdata);
		if (0 != retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"vedl_get_usr_reg failed for core %d\n",
					p_ve_core->core_num);
			goto hndl_return;
		}
		if ((regdata & VE_EXCEPTION)
				&&
				(curr_ve_task->block_status == BLOCK_RECVD)) {
			curr_ve_task->ve_task_state = WAIT;
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Setting task state to WAIT for"
					" PID : %d CORE ID: %d\n",
					curr_ve_task->pid,
					p_ve_core->core_num);
		}
	}
	/* Finds the most eligible VE process to be
	 * scheduled on this VE core
	 * */
	if (NULL != curr_ve_task) {
		loop_cntr = curr_ve_task;
		task_to_schedule = curr_ve_task->next;
	} else {
		loop_cntr = task_to_schedule = p_ve_core->ve_task_list;
	}

	do {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"%d : Check scheduling for PID: %d State: %d\n",
				p_ve_core->core_num,
				task_to_schedule->pid,
				task_to_schedule->ve_task_state);

		if (RUNNING != task_to_schedule->ve_task_state) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"Skipping task with PID : %d\n",
					task_to_schedule->pid);
			task_to_schedule = task_to_schedule->next;
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Scheduling Task with PID : %d\n",
					task_to_schedule->pid);
			schedule_task_on_ve_node_ve_core(
					curr_ve_task,
					task_to_schedule,
					scheduler_expiry);
			break;
		}

		if (loop_cntr == task_to_schedule) {
			if (RUNNING == task_to_schedule->ve_task_state) {
				/* Finally, schedule VE process on VE core */
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Scheduling Task with PID : %d\n",
						task_to_schedule->pid);
				schedule_task_on_ve_node_ve_core(
						curr_ve_task,
						task_to_schedule,
						scheduler_expiry);
			}
			break;
		}
	} while (1);

	SET_SCHED_STATE(p_ve_core->scheduling_status, COMPLETED);

hndl_return:
	pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
hndl_return1:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Start VEOS scheduler timer and register the scheduler
 * timer handler funciton.
 *
 * @param[in] p_ve_node Pointer to node for which timer is created
 *
 * @return 0 on success, -1 on failure.
 */
int veos_scheduler_timer(struct ve_node_struct *p_ve_node)
{
	/* for timer create */
	clockid_t psm_sched_clock_id;
	struct sigevent psm_sched_clock_sig_event;

	/* for timer settime */
	struct itimerspec psm_new_timer_value = { {0} };
	struct itimerspec psm_old_timer_value = { {0} };
	int psm_interval_flags = 0;
	int psm_sched_retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_node)
		goto hndl_return;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Starting PSM scheduler timer\n");
	/* Setting clock id */
	psm_sched_clock_id = CLOCK_MONOTONIC;

	/* Setting up sig event notify functions */
	psm_sched_clock_sig_event.sigev_notify = SIGEV_THREAD;
	psm_sched_clock_sig_event.sigev_notify_function
		= psm_sched_interval_handler;
	psm_sched_clock_sig_event.sigev_notify_attributes = NULL;

	psm_sched_retval = timer_create(psm_sched_clock_id,
			&psm_sched_clock_sig_event,
			&(p_ve_node->psm_sched_timer_id));
	if (-1 == psm_sched_retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"timer_create fails: %s\n",
			strerror(errno));
		goto hndl_return;
	}

	/* setting timer interval values */
	psm_new_timer_value.it_interval.tv_sec = PSM_TIMER_INTERVAL_SECS;
	psm_new_timer_value.it_interval.tv_nsec = PSM_TIMER_INTERVAL_NSECS;

	/* setting timer initial expiration values */
	psm_new_timer_value.it_value.tv_sec = PSM_TIMER_INTERVAL_SECS;
	psm_new_timer_value.it_value.tv_nsec = PSM_TIMER_INTERVAL_NSECS;

	/* create timer */
	psm_sched_retval = timer_settime(p_ve_node->psm_sched_timer_id,
			psm_interval_flags, &psm_new_timer_value,
			&psm_old_timer_value);

	if (-1 == psm_sched_retval)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"timer_settime fails: %s\n",
				strerror(errno));
	else
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Started PSM scheduler timer"
				"with interval SECS: %d N_SECS: %d\n",
				(int)psm_new_timer_value.it_interval.tv_sec,
				(int)psm_new_timer_value.it_interval.tv_nsec);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return psm_sched_retval;
}

/**
 * @brief Stop the veos scheduler timer.
 *
 * @param[in] p_ve_node Pointer of Node for which scheduler timer is to remove
 *
 * @return 0 on success, -1 on failure.
 */
int veos_remove_timer(struct ve_node_struct *p_ve_node)
{
	int psm_sched_retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_node)
		goto hndl_return;

	if (p_ve_node->psm_sched_timer_id) {
		psm_sched_retval = timer_delete(p_ve_node->psm_sched_timer_id);
		if (-1 == psm_sched_retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"timer_delete fails: %s\n",
					strerror(errno));
			goto hndl_return;
		}
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Deleted Scheduler Timer for Node : %d\n",
				p_ve_node->node_num);
		psm_sched_retval = 0;
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return psm_sched_retval;
}

/**
 * @brief Allocates memory for ve_thread_struct
 *
 * @return pointer to VE thread struct on success, NULL on failure.
 */
struct ve_thread_struct *alloc_ve_thread_struct_node()
{
	struct ve_thread_struct *p;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	p = (struct ve_thread_struct *)malloc(sizeof(struct ve_thread_struct));
	if (!p) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}

	memset(p, 0, sizeof(struct ve_thread_struct));

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return p;
}

/**
 * @brief Allocate memory for VE task structure.
 *
 * @return pointer to VE task struct on success, NULL on failure.
 */
struct ve_task_struct *alloc_ve_task_struct_node(void)
{
	struct ve_task_struct *p;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	p = (struct ve_task_struct *)malloc(sizeof(struct ve_task_struct));
	if (!p) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}

	memset(p, 0, sizeof(struct ve_task_struct));
	if (0 != pthread_mutex_init(&(p->offset_lock), NULL)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init failed %s\n", strerror(errno));
		free(p);
		p = NULL;
	}
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return p;
}

/**
 * @brief Allocate memory for VE sighand structure.
 *
 * @return pointer to VE sighand structure on success, NULL on failure.
 */
struct sighand_struct *alloc_ve_sighand_struct_node()
{
	struct sighand_struct *p;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	p = (struct sighand_struct *)malloc(sizeof(struct sighand_struct));
	if (!p) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Malloc fails: %s\n",
				strerror(errno));
		goto hndl_return;
	}

	memset(p, '\0', sizeof(struct sighand_struct));
	if (pthread_mutex_init(&(p->siglock), NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"\n Sighand mutex init failed\n");
		free(p);
		p = NULL;
		goto hndl_return;
	}
	p->ref_count = 1;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return p;
}

/**
 * @brief Schedule the provided task on a VE core.
 *
 * @param[in,out] curr_ve_task Pointer to current VE task of the core
 * @param task_to_schedule Pointer to VE task to be scheduled on the core
 * @param scheduler_expiry Is scheduler expired
 *
 * @return 0 on success, -1 on failure.
 */
int schedule_task_on_ve_node_ve_core(struct ve_task_struct *curr_ve_task,
		struct ve_task_struct *task_to_schedule,
		bool scheduler_expiry)
{
	int node_id;
	int core_id;
	int ret = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!task_to_schedule)
		goto hndl_return;

	node_id = task_to_schedule->node_id;
	core_id = task_to_schedule->core_id;

	if (curr_ve_task) {
		/* Unassign the currently scheduled task from VE core */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Unassigning Current task with pid: %d\n",
				curr_ve_task->pid);
		vedl_unassign_task_from_core(VE_HANDLE(node_id),
				curr_ve_task->pid);
	}

	if (curr_ve_task && curr_ve_task != task_to_schedule) {
		/* Number of voluntary or involuntary context switches count
		 * of VE process/thread is updated based on the flag.
		 */
		if (true == scheduler_expiry)
			curr_ve_task->nivcsw++;
		else
			curr_ve_task->nvcsw++;

		/* Context switch count of core is incremented.
		 */
		VE_CORE(node_id, core_id)->nr_switches++;
	}

	if (1 == task_to_schedule->sigpending) {
		/* Signal is generated for this process.
		 * Set the signal handler context and save the
		 * current process context on stack
		 * */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Sigpending Flag set.\n");
		ret = psm_do_signal_ve(task_to_schedule);
		if (-1 == ret) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"psm_do_signal_ve() fails\n");
			goto hndl_return;
		}
	}

	/* Load the VE process context */
	vedl_set_usr_reg_all(
			VE_HANDLE(node_id),
			VE_CORE_USR_REG_ADDR(node_id,
				core_id),
			(core_user_reg_t *)task_to_schedule->
			p_ve_thread);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"\n\nScheduling PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0 : %lx SR1 : %lx SR2 : %lx\n\n",
			task_to_schedule->pid,
			task_to_schedule->p_ve_thread->IC,
			task_to_schedule->p_ve_thread->SR[10],
			task_to_schedule->p_ve_thread->SR[11],
			task_to_schedule->p_ve_thread->SR[12],
			task_to_schedule->p_ve_thread->SR[00],
			task_to_schedule->p_ve_thread->SR[01],
			task_to_schedule->p_ve_thread->SR[02]);

	/* Update atb and dmaatb for task_to_schedule on VE core */
	ret = amm_update_atb_all(task_to_schedule);
	if (-1 == ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"AMM Fails in updating ATB on core: %d\n",
			core_id);
		goto hndl_return;
	}

	/* Update core->curr_ve_task */
	task_to_schedule->p_ve_core->curr_ve_task = task_to_schedule;

	/* Assign the to_be_scheduled task on the VE core */
	vedl_assign_task_to_core(VE_HANDLE(node_id),
			task_to_schedule->p_ve_core->phys_core_num,
			task_to_schedule->pid);

	/* this process will run on core then it's regsiter will get
	 * updated.
	 */
	task_to_schedule->reg_dirty = true;

	/* Set the sr_context_bitmap to "0" */
	task_to_schedule->sr_context_bitmap = 0;

	/* Start VE core */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Setting the start bit\n");
	ret = psm_start_ve_core(node_id, core_id);
	if (-1 == ret) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to start core: %d\n", core_id);
		goto hndl_return;
	}

	gettimeofday(&(task_to_schedule->stime), NULL);

	/* Reset the block_status flag for VE process
	 * to handle scenario "When monc is encountered on VE and
	 * schedule timer expires before the Block request is
	 * served by veos." when this VE process will be
	 * scheduled next time.
	 * */
	task_to_schedule->block_status = BLOCK_RECVD;
	ret = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
 * @brief Handles re-scheduling from one VE Node and Core to another
 * VE node and core.
 *
 * @param[in] old_node_id VE task old Node ID
 * @param[in] old_core_id VE task Old Core ID
 * @param[in] new_node_id VE task new Node ID
 * @param[in] new_core_id VE task new Core ID
 * @param[in] p_ve_task Pointer to VE task to be relocated
 *
 * @return 0 on success, -1 on failure.
 */
int psm_relocate_ve_task(int old_node_id, int old_core_id,
		int new_node_id, int new_core_id,
		struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_task)
		goto hndl_return;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Relocating PID %d from %d:%d to %d:%d\n",
			p_ve_task->pid,
			old_node_id, old_core_id,
			new_node_id, new_core_id);

	/* Delete VE task from old core/node. Delete first so that PSM does
	 * not have two processes with similar PID at a time.
	 */
	retval = remove_task_from_core_list(old_node_id,
			old_core_id, p_ve_task);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to remove pid %d from core %d\n",
			p_ve_task->pid, old_core_id);
		goto hndl_return;
	}

	/* Insert task in to the new Node/Core */
	insert_ve_task(new_node_id, new_core_id, p_ve_task);
	retval = 0;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Finds and print least loaded Node and Core information.
 *
 * @return 0 always success.
 */
int psm_least_loaded_node_n_core(void)
{
	int ve_core_id, ve_node_id;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	get_ve_core_n_node_new_ve_proc(&ve_init_task, &ve_node_id, &ve_core_id);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "\n Least Loaded Node n Core\n"
			"VE Node Id = %d VE Core Id = %d\n",
			ve_node_id, ve_core_id);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return 0;
}

/**
 * @brief Searches for the appropriate VE Node and Core for the new VE process.
 *
 * @param[in] p_ve_task Pointer to struct ve_task_struct of VE process
 * @param[in,out] ve_node_id Obtain the appropriate VE node ID
 * @param[in,out] ve_core_id Obtain the appropriate VE core ID
 *
 * @return 0 on success, -1 on failure.
 */
int get_ve_core_n_node_new_ve_proc(struct ve_task_struct *p_ve_task,
		int *ve_node_id, int *ve_core_id)
{
	int retval = -1;
	/* Per Node */
	int min_proc_num_node = -1;
	int num_proc_node = -1;
	int num_proc_node_min = MAX_PROCESS_PER_NODE;

	/* Per Core */
	int min_proc_num_core = -1;
	int num_proc_core = -1;
	int num_proc_core_min = MAX_PROCESS_PER_CORE;

	int node_loop = 0, core_loop = 0;

	struct ve_node_struct *p_ve_node;
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_task || !ve_node_id || !ve_core_id)
		goto hndl_return;

	/* node loop
	 * Find Node with Minimum Processes */
	for (; node_loop < MAX_VE_NODE_PER_VH; node_loop++) {
		p_ve_node = VE_NODE(VE_NODE_ID(node_loop));
		if (NULL == p_ve_node) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "BUG\n");
			continue;
		}
		pthread_rwlock_rdlock(
				&(VE_NODE(VE_NODE_ID(node_loop))->ve_node_lock));
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"S:NUM PROC ON NODE %d is %d\n",
				VE_NODE_ID(node_loop), p_ve_node->num_ve_proc);
		num_proc_node = p_ve_node->num_ve_proc;
		if (num_proc_node < num_proc_node_min) {
			num_proc_node_min = num_proc_node;
			min_proc_num_node = node_loop;
		}
		pthread_rwlock_unlock(
				&(VE_NODE(VE_NODE_ID(node_loop))->ve_node_lock));
	}

	if (-1 == min_proc_num_node) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"All VE resources are busy,"
				" unable to accept new request\n");
		*ve_node_id = min_proc_num_node;
		*ve_core_id = min_proc_num_core;
		goto hndl_return;
	}
	*ve_node_id = VE_NODE_ID(min_proc_num_node);
	p_ve_node = VE_NODE(*ve_node_id);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"S:NUM PROC ON NODE %d is %d\n",
			*ve_node_id, p_ve_node->num_ve_proc);

	if ((-1 < *ve_core_id) && (*ve_core_id < MAX_VE_CORE_PER_VE_NODE))
		goto skip_get_core_num;

	/* core loop
	 * Find Core with Minimum Processes */

	for (; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
		p_ve_core = VE_CORE(*ve_node_id, core_loop);
		if ((NULL == p_ve_core) ||
				!(IS_CPU_ALLOWED(p_ve_task, (core_loop)))) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"core_loop %d, 0x%lx CPU ALLOW\n",
					core_loop,
					(IS_CPU_ALLOWED(p_ve_task, (core_loop))));
			continue;
		}
		pthread_rwlock_rdlock(&(p_ve_core->ve_core_lock));
		num_proc_core = p_ve_core->num_ve_proc;
		if (num_proc_core < num_proc_core_min) {
			num_proc_core_min = num_proc_core;
			min_proc_num_core = core_loop;
		}
		pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
	}
	*ve_core_id = min_proc_num_core;
	if (-1 == min_proc_num_core) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"BUG: This should not be failed here.\n");
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"All VE resources are busy,"
				" unable to accept new request\n");
		*ve_node_id = -1;
		goto hndl_return;
	}

skip_get_core_num:
	retval = 0;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Selected Node %d Core %d\n",
			*ve_node_id,
			*ve_core_id);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Finds VE task struct based on input PID and Node/Core values.
 *
 * @param[in] min_node Min Node to start searching from
 * @param[in] max_node Max Node to search till
 * @param[in] min_core Min Core to start searching from
 * @param[in] max_core Max Core to search till
 * @param[in] pid PID of the process to find VE task struct for
 *
 * @return pointer to VE task struct on Success, NULL if VE task is not found.
 */
struct ve_task_struct *find_ve_task_struct(int min_node,
		int max_node,
		int min_core,
		int max_core,
		int pid)
{
	int node_loop = min_node, core_loop = min_core;
	struct ve_task_struct *ve_task_list_head;
	struct ve_task_struct *ve_task_curr = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_task_struct *ve_task_ret = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
#ifdef VE_OS_DEBUG
	list_ve_proc();
#endif

	/* Node loop */
	for (; node_loop < max_node; node_loop++) {
		/* Core loop */
		for (; core_loop < max_core; core_loop++) {
			p_ve_core = VE_CORE(VE_NODE_ID(node_loop), core_loop);
			pthread_rwlock_rdlock(&(p_ve_core->ve_core_lock));
			ve_task_list_head = p_ve_core->ve_task_list;

			ve_task_curr = ve_task_list_head;

			if (NULL == ve_task_curr) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"No Task in the list "
						"for Node %d Core %d\n",
						VE_NODE_ID(node_loop), core_loop);
				pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
				continue;
			}
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Node %d: Core %d "
					"Head is %p "
					"PID(C) = %d "
					"PID(s) = %d\n",
					VE_NODE_ID(node_loop),
					core_loop,
					ve_task_list_head,
					ve_task_curr->pid,
					pid);
			do {
				if (ve_task_curr->pid == pid) {
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
							"FOUND NODE:%d"
							" CORE : %d"
							" TASK : %p"
							" TASK PID : %d\n",
							VE_NODE_ID(node_loop),
							core_loop,
							ve_task_curr,
							ve_task_curr->pid);

					pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
					ve_task_ret = ve_task_curr;
					goto hndl_return;
				}
			} while ((ve_task_list_head != ve_task_curr->next)
				&& (ve_task_curr = ve_task_curr->next));

			pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"TASK Not Found in Node %d"
					" Core %d\n",
					VE_NODE_ID(node_loop),
					core_loop);
		}
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ve_task_ret;
}

/**
 * @brief Will set the tid address of the process identified by
 * the pid passed to it.
 *
 * @param[in] pid pid of the process whose tid address is to be set
 * @param[in] tid_addr tid address to be set
 *
 * @return 0 on success, -1 on failure.
 */
int64_t psm_handle_set_tid_addr(pid_t pid, uint64_t tid_addr)
{
	int64_t retval = -1;

	/* find the ve_task_struct for process (pid) */
	struct ve_task_struct *ve_task_curr = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Task with pid %d not found\n", pid);
		goto hndl_return;
	}
	ve_task_curr->clear_child_tid = (int *)tid_addr;

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Change the state of the VE process state to RUNNING.
 *
 * @param[in] pid pid of the process whose state is to be changed
 *
 * @return 0 on success, -1 on failure.
 */
int64_t psm_handle_schedule_ve_process(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core;
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);

	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "PID %d not found. "
			"SCHEDULE REQ failed\n", pid);
		goto hndl_return;
	}

	p_ve_core = tsk->p_ve_core;

	/* Set the task state to RUNNING */
	pthread_mutex_lock(&(tsk->ve_task_lock));
	/* Start time of new VE process/thread is maintained */
	gettimeofday(&(tsk->start_time), NULL);
	tsk->ve_task_state = RUNNING;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	/* Number of active task updated on core */
	ve_atomic_inc(&(p_ve_core->nr_active));

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Update the scalar register content of the VE process.
 *
 * @param[in] pid pid of VE process whose scalar reg to update
 * @param[in] regid scalar register to update
 * @param[in] regval register value to update with
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_set_reg_req(pid_t pid, uint8_t regid, int64_t regval)
{
	struct ve_task_struct *tsk = NULL;
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);

	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "PID %d not found. "
			"SET REGVAL failed\n", pid);
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"REG VALUE : SR[%d] -> 0x%lx\n",
			REG_INDEX(regid), regval);
	pthread_mutex_lock(&(tsk->ve_task_lock));

	tsk->p_ve_thread->SR[REG_INDEX(regid)] = regval;
	SET_BIT(tsk->sr_context_bitmap, REG_INDEX(regid));
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Updates system call return value in VE process's thread struct.
 *
 * @param[in] pid Contains the pid of the VE process
 * @param[in] syscall_retval Contains the return value of the system call
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_set_syscall_return_req(pid_t pid, uint64_t syscall_retval)
{
	struct ve_task_struct *tsk = NULL;
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);

	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "PID %d not found. "
			"SET RETVAL failed\n", pid);
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SYSCALL RETURN VALUE : %ld\n", syscall_retval);
	pthread_mutex_lock(&(tsk->ve_task_lock));

	/* if the signal handling is pending for VE process, update the SR[0]
	 * of VE process signal context with the system call return value
	 * because SR[0] of VE process thread struct will be used for passing
	 * the argument to signal handling routine. When VE process resume its
	 * execution after signal handling, VE process signal handling context
	 * will be written to the VE core and system call return value will
	 * be received to VE process.
	 */

	tsk->p_ve_thread->SR[0] = syscall_retval;
	SET_BIT(tsk->sr_context_bitmap, 0);
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Releases all the resources allocated to a VE process and
 * task struct is not deleted.
 *
 * @param[in] del_task_struct VE process to be release
 */
void clear_ve_task_struct(struct ve_task_struct *del_task_struct)
{
	int node_id, core_id, pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!del_task_struct)
		goto hndl_return;

	node_id = del_task_struct->node_id;
	core_id = del_task_struct->core_id;
	pid = del_task_struct->pid;

	/* Reparent all the child processes of this exiting
	 * VE thread/ VE process.
	 */
	psm_reparent_children(del_task_struct);

	amm_del_mm_struct(&(del_task_struct->p_ve_mm), node_id);

	/* allocate the new memory structure */
	amm_alloc_mm_struct(&(del_task_struct->p_ve_mm));

	/* If Task to be deleted is current task, mark the curr_task
	 * as NULL
	 */
	if (del_task_struct == VE_CORE(node_id, core_id)->curr_ve_task) {
		vedl_unassign_task_from_core(VE_HANDLE(node_id), pid);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Unassigning PID %d from VE Core\n", pid);
		VE_CORE(node_id, core_id)->curr_ve_task = NULL;
	}

	del_task_struct->execed_proc = true;

	if (del_task_struct->ve_task_state != ZOMBIE)
		vedl_delete_ve_process(VE_HANDLE(node_id), pid);

	memset(del_task_struct->p_ve_thread, 0 , sizeof(struct ve_thread_struct));

	/* Free the LHM/SHM area */
#ifdef __PCIDEV_ENV
	shmdt((void *)del_task_struct->sighand->lshm_addr);
#else
	munmap((void *)del_task_struct->sighand->lshm_addr, LHM_SHM_SIZE);
#endif

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Dump the accounting information of struct ve_acct in a
 * accounting file.
 *
 * @param[in] tsk Pointer to VE task struct
 */
void veos_acct_ve_proc(struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct = NULL;
	struct ve_acct acct_info;
	struct timeval now;
	int retval;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!tsk)
		goto hndl_return;

	pacct = &(tsk->sighand->pacct);
	memset(&acct_info, 0, sizeof(struct ve_acct));

	acct_info.ac_flag = pacct->ac_flag;

	/* Always set to ACCT_VERSION */
	acct_info.ac_version = ACCT_VERSION;

	/* task exit code passed to the exit system call */
	acct_info.ac_exitcode = pacct->ac_exitcode;

	/*TODO: VEOS needs to maintain VE process UID. */
	/* Real user ID */
	acct_info.ac_uid = 0;

	/*TODO: VEOS needs to maintain VE process GID. */
	/*Real group ID*/
	acct_info.ac_gid = 0;

	/*Process ID*/
	acct_info.ac_pid = tsk->pid;

	/* Parent process ID*/
	acct_info.ac_ppid = tsk->parent->pid;

	/* process creation time */
	acct_info.ac_btime = (tsk->start_time.tv_sec * MICRO_SECONDS +
			tsk->start_time.tv_usec)/MICRO_SECONDS;

	/* elapsed time from process creation to termination */
	gettimeofday(&now, NULL);
	acct_info.ac_etime = timeval_diff(now, tsk->start_time);

	/* Time spend by the process while scheduled on VE core*/
	acct_info.ac_etime = pacct->ac_stime;

	/* Average memory usage (kB) */
	acct_info.ac_mem = pacct->ac_mem;

	/* Command name of the program
	 * TODO: currently not maintained*/
	strcpy(acct_info.ac_comm, tsk->ve_comm);

	/* Write struct ve_acct to file */
	retval = write(veos_acct.fd, (char *)&acct_info,
			sizeof(struct ve_acct));
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to write in accounting file: %s\n",
			strerror(errno));
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Data is successfully dumped in accounting file: %s\n",
			veos_acct.file);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
 * @brief Releases all the resources allocated to a VE process.
 *
 * @param[in] del_task_struct VE process to be deleted
 */
void delete_entries(struct ve_task_struct *del_task_struct)
{
	int pid;
	int node_id, core_id;
	struct ve_task_struct *ve_task_list_head;
	struct ve_task_struct *temp = NULL, *group_leader = NULL;
	struct list_head *p, *n;
	struct ve_core_struct *p_ve_core = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!del_task_struct)
		goto hndl_return;

	/* Check if accounting is enabled, if yes the dump
	 * struct ve_acct in accounitng file.
	 */
	if (veos_acct.active == true &&
			del_task_struct->sighand->ref_count == 1)
		veos_acct_ve_proc(del_task_struct);

	pid = del_task_struct->pid;
	node_id = del_task_struct->node_id;
	core_id = del_task_struct->core_id;
	ve_task_list_head = VE_CORE(node_id, core_id)->ve_task_list;
	group_leader = del_task_struct->group_leader;

	/* Number of active task updated on core */
	/* Delete this VE process node */
	pthread_rwlock_wrlock(&(VE_CORE(node_id, core_id)->ve_core_lock));
	if (RUNNING == del_task_struct->ve_task_state)
		ve_atomic_dec(&(VE_CORE(node_id, core_id)->nr_active));

	pthread_mutex_lock(&(del_task_struct->ve_task_lock));
	del_task_struct->ve_task_state = WAIT;
	pthread_mutex_unlock(&(del_task_struct->ve_task_lock));

	/* If Task to be deleted is current task, mark the curr_task
	 * as NULL
	 */
	if (del_task_struct == VE_CORE(node_id, core_id)->curr_ve_task) {
		psm_halt_ve_core(node_id, core_id);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Unassigning PID %d from VE Core\n", pid);
		vedl_unassign_task_from_core(VE_HANDLE(node_id), pid);
		VE_CORE(node_id, core_id)->curr_ve_task = NULL;
	}

	/* Notify vforked process's parent to wakeup
	 * */
	if (true == del_task_struct->vforked_proc) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"vforked process execution completed,"
				" waking up parent\n");
		p_ve_core = del_task_struct->parent->p_ve_core;
		ve_atomic_inc(&(p_ve_core->nr_active));

		pthread_mutex_lock(&(del_task_struct->parent->ve_task_lock));
		del_task_struct->parent->ve_task_state = RUNNING;
		del_task_struct->parent->vfork_state = VFORK_COMPLETED;
		pthread_mutex_unlock(&(del_task_struct->parent->ve_task_lock));
	}

	if ((del_task_struct == ve_task_list_head) &&
		(del_task_struct->next == del_task_struct)) {
		/* Current task to be deleted is head of the list */
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Pid %d is to be deleted\n", pid);
		ve_task_list_head = NULL;
		VE_CORE(node_id, core_id)->ve_task_list = ve_task_list_head;
		goto resume;
	}
	temp = del_task_struct->next;
	while (temp->next != del_task_struct)
		temp = temp->next;

	temp->next = del_task_struct->next;
	if (del_task_struct == ve_task_list_head) {
		ve_task_list_head = temp->next;
		VE_CORE(node_id, core_id)->ve_task_list = ve_task_list_head;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Now Head is %p\n",
					ve_task_list_head);
	}

resume:
	if (group_leader == del_task_struct) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Delete process entry from its parent's"
				" children list\n");
		list_for_each_safe(p, n, &del_task_struct->parent->children) {
			struct ve_task_struct *tmp =
				list_entry(p,
						struct ve_task_struct,
						siblings);
			if (tmp->pid == del_task_struct->pid)
				list_del(p);
		}

		pthread_spin_lock(&init_task_lock);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Delete process entry from INIT list\n");
		list_for_each_safe(p, n, &ve_init_task.tasks) {
			struct ve_task_struct *tmp =
				list_entry(p,
						struct ve_task_struct,
						tasks);

			if (tmp->pid == del_task_struct->pid) {
				list_del(p);
				break;
			}
		}
		pthread_spin_unlock(&init_task_lock);
	}

	/* Reparent all the child processes of this exiting
	 * VE thread/ VE process.
	 */
	psm_reparent_children(del_task_struct);

	amm_del_mm_struct(&(del_task_struct->p_ve_mm), del_task_struct->node_id);
	psm_del_sighand_struct(del_task_struct->sighand);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Deleting VE process structure with"
			" PID %d from Driver\n",
			pid);
	if (del_task_struct->ve_task_state != ZOMBIE)
		vedl_delete_ve_process(VE_HANDLE(node_id), pid);

	if (NULL != del_task_struct->p_ve_sigcontext)
		free(del_task_struct->p_ve_sigcontext);
	if (NULL != del_task_struct->p_ve_thread)
		free(del_task_struct->p_ve_thread);
	if (NULL != del_task_struct) {
		pthread_mutex_destroy(&(del_task_struct->ve_task_lock));
		pthread_mutex_destroy(&(del_task_struct->offset_lock));
		free(del_task_struct);
	}

	VE_NODE(node_id)->num_ve_proc--;
	VE_CORE(node_id, core_id)->num_ve_proc--;

	pthread_rwlock_unlock(&(VE_CORE(node_id, core_id)->ve_core_lock));

	if (0 == VE_CORE(node_id, core_id)->num_ve_proc)
		VE_CORE(node_id, core_id)->ve_core_state = STOPPED;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

/**
 * @brief Collect accounting information into pacct_struct.
 *
 * @param[in] exit_code task exit code
 * @param[in] tsk Pointer to VE task struct
 */
void psm_acct_collect(int exit_code, struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk)
		goto hndl_return;

	pacct = &(tsk->sighand->pacct);

	/* status of the process when it terminated
	 * TODO:
	 * ASU(set if PF_SUPERPRIV is enabled),
	 * but currently PF_SUPERPRIV is not handled.
	 */
	if (tsk->flags & PF_FORKNOEXEC)
		pacct->ac_flag |= AFORK;
	if (tsk->flags & PF_SIGNALED)
		pacct->ac_flag |= AXSIG;
	if (tsk->flags & PF_DUMPCORE)
		pacct->ac_flag |= ACORE;

	/* Time spend by the process while scheduled on VE core */
	pacct->ac_stime += tsk->exec_time;

	/* In case of thread group */
	if (tsk->group_leader == tsk) {
		pacct->ac_mem += amm_get_rss_in_kb(tsk->p_ve_mm);
		pacct->ac_exitcode = exit_code;
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return;
}

/**
 * @brief Delete's VE process of given pid.
 *
 * @param[in] pid PID of the process to be deleted
 * @param[in] clean_all_threads flag to clean single or all threads
 * @param[in] exit_code VE process exit code
 *
 * @return 0 for threads deleted other than main thread.
 *	   1 for process, for non-Zombie main thread,
 *	     for last thread in thread group whose main thread is Zombie,
 *	     for exit_group case.
 *	   2 for Zombie thread; Zombie process is not supported yet.
 *	  -1 on failure.
 */
int psm_handle_delete_ve_process(pid_t pid, int clean_all_threads,
		int exit_code)
{
	struct ve_task_struct *ve_task_curr = NULL, *group_leader = NULL;
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;
	int core_id, node_id;
	int retval = 0;

	/* Search for PID in Task List and find ve_node_id
	 * Currently only one node and one core.
	 * */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "In Func\n");

	ve_task_curr = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == ve_task_curr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID %d does not exists\n", pid);
		retval = -1;
		goto hndl_return;
	}

	/* Collect accounting information */
	psm_acct_collect(exit_code, ve_task_curr);

	node_id = ve_task_curr->node_id;
	core_id = ve_task_curr->core_id;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"DEL TASK %p NODE %d CORE %d\n",
			ve_task_curr,
			node_id,
			core_id);

	group_leader = ve_task_curr->group_leader;

	/* TODO : Zombie process not supported yet */

	if (0 == clean_all_threads) {
		/* EXIT for a single thread invoked */
		if (group_leader == ve_task_curr) {
			/* Execution time of child reaped process is
			 * updated in it's parent.
			 */
			group_leader->parent->cexec_time +=
				group_leader->exec_time;

			/* exit request has come up from thread group leader */
			if (list_empty(&group_leader->thread_group)) {
				/* thread group leader is the only thread left
				 * in the thread group
				 */
				delete_entries(group_leader);
				retval = 1;
			} else {
				/* thread group leader is not the only thread
				 * in the thread group
				 */
				pthread_mutex_lock(&(group_leader->
							ve_task_lock));
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"Task state set to Zombie\n");
				ve_task_curr->ve_task_state = ZOMBIE;
				pthread_mutex_unlock(&(group_leader->
							ve_task_lock));

				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"Invoking rescheduling on this core\n");
				psm_find_sched_new_task_on_core(group_leader->
								p_ve_core,
								false);

				if (ve_task_curr->p_ve_core->curr_ve_task == ve_task_curr) {
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Unassigning task from core\n");
					vedl_unassign_task_from_core(VE_HANDLE(node_id),
							ve_task_curr->pid);
				}
				vedl_delete_ve_process(VE_HANDLE(node_id), pid);
				retval = 2;
			}
		} else {
			/* Execution time of child reaped thread is
			 * updated in it's parent.
			 */
			ve_task_curr->parent->cexec_time +=
				ve_task_curr->exec_time;

			/* exit request has come up from thread other than
			 * thread group leader
			 */
			/* Find this thread in thread_group list and del */
			list_for_each_safe(p, n, &group_leader->thread_group) {
				tmp = list_entry(p,
						struct ve_task_struct,
						thread_group);
				if (tmp->pid == ve_task_curr->pid) {
					list_del(p);
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Deleting thread with TID %d\n",
						tmp->pid);
				}
			}
			if (list_empty(&group_leader->thread_group))
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Thread group list now empty\n");

			if ((list_empty(&group_leader->thread_group)) &&
				(ZOMBIE == group_leader->ve_task_state)) {
				/* only two threads are left in the thread
				 * group including thread group leader and
				 * thread group leader is ZOMBIE
				 */
				delete_entries(ve_task_curr);
				delete_entries(group_leader);
				retval = 1;
			} else
				delete_entries(ve_task_curr);
		}
	} else {
		/* EXIT Group invoked */

		retval = 1;

		/* Traverse thread_group list and remove all the thread entry.*/
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Deleting every thread in the thread group\n");

		if (!list_empty(&group_leader->thread_group)) {
			list_for_each_safe(p, n, &group_leader->thread_group) {
				tmp = list_entry(p,
					struct ve_task_struct,
					thread_group);
				if (tmp == group_leader)
					continue;
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Freeing thread with PID %d\n",
					tmp->pid);
				list_del(p);
				/* Execution time of child reaped thread is
				 * updated in it's parent.
				 */
				tmp->parent->cexec_time +=
					tmp->exec_time;
				delete_entries(tmp);
			}
		} else
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"No threads exists\n");

		if (1 == clean_all_threads) {
			/* Execution time of child reaped process is
			 * updated in it's parent.
			 */
			group_leader->parent->cexec_time +=
				group_leader->exec_time;
			/* Delete mm_struct and task_struct */
			delete_entries(group_leader);
		} else if (2 == clean_all_threads)
			clear_ve_task_struct(group_leader);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Reparent all the child processes of the exiting process/thread.
 *
 * @param[in] ve_tsk Task to be deleted
 */
void psm_reparent_children(struct ve_task_struct *ve_tsk)
{
	struct ve_task_struct *tmp = NULL;
	struct list_head *p, *n;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!ve_tsk)
		goto hndl_return;

	/* Notify its children (children update their parent) */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Free its children list. Notify to reparent\n");
	if (!list_empty(&ve_tsk->children)) {
		list_for_each_safe(p, n, &ve_tsk->children) {
			tmp = list_entry(p,
					struct ve_task_struct,
					siblings);
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Notifying child PID %d to reparent\n",
					tmp->pid);
			list_add_tail(&tmp->siblings,
					&ve_init_task.children);
			tmp->parent = &ve_init_task;
			list_del(p);
		}
	} else
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "No child exists\n");

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
}

#ifdef __AUSIM_ENV
/**
* @brief mmap for LHM/SHM shared area
*
* @param tsk Pointer to ve_task_struct
*
* @return -1 on failure and 0 on success.
*/
int psm_init_shared_file_mmap(struct ve_task_struct *tsk)
{
	int ret;
	uint8_t t_buff[AD_BUFFER_SIZE];
	char *buff = (char *)t_buff;
	int shmem_fd;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	sprintf(buff, "%s/" AUSIM_DRV_IPC_MMAP_FNAME "%d_%d", getenv("HOME"),
			tsk->pid, tsk->pid);

	shmem_fd = open(buff, O_RDWR | O_CREAT);
	if (shmem_fd < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "open() %s\n", strerror(errno));
		ret = shmem_fd;
		goto err;
	}

	tsk->sighand->lshm_addr = (uint64_t)mmap(0, LHM_SHM_SIZE,
					     PROT_READ | PROT_WRITE, MAP_SHARED,
					     shmem_fd, 0);
	if ((void *)tsk->sighand->lshm_addr == (void *)-1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "mmap() %s\n", strerror(errno));
		ret = -1;
		goto err_fd;
	}
	ret = 0;
err_fd:
	close(shmem_fd);
err:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}
#endif

/**
 * @brief Handle's NEW VE PROC request from pseudo process such request is
 * sent from pseudo process in case pseudo invoked ve_exec
 *
 * @param[in] pti Pointer to thread arg for Worker Thread
 * @param[in] ve_core_id VE Core Id recevied from Pseudo
 * @param[in] ve_node_id VE Node Id recevied from Pseudo
 * @param[in] pid PID of the Pseudo Process
 * @param[in] exe_name VE process exe command name
 *
 * @return 0 on success , -1 on failure.
 */
int psm_handle_exec_ve_process(struct veos_thread_arg *pti,
				int *ve_core_id,
				int *ve_node_id,
				int pid,
				char *exe_name,
				bool traced,
				uint64_t vaddr,
				int shmid)
{
	int retval = -1;
	struct ve_task_struct *tsk;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti || !ve_core_id || !ve_node_id)
		goto hndl_return;

	/* Allocate memory for VE task structure */
	tsk = alloc_ve_task_struct_node();
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task Struct alloc failed\n");
		goto hndl_return;
	}

	/* Allocate memory for VE thread structure */
	tsk->p_ve_thread = alloc_ve_thread_struct_node();
	if (!tsk->p_ve_thread) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Thread Struct alloc failed\n");
		goto free_tsk;
	}

	/* Allocate memory for VE thread structure */
	tsk->p_ve_sigcontext = alloc_ve_thread_struct_node();
	if (!tsk->p_ve_sigcontext) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Sigcontext thread struct alloc failed\n");
		goto free_tsk;
	}
	/* Allocate memory for VE MM structure */
	if (-1 == amm_alloc_mm_struct(&(tsk->p_ve_mm))) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "MM alloc failed\n");
		goto free_thread;
	}
	/* Allocate memory for VE sighand structure */
	tsk->sighand = alloc_ve_sighand_struct_node();
	if (!tsk->sighand) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"sighand struct alloc failed\n");
		goto free_mm_struct;
	}

	/* Initialize CPU MASK of the task */
	tsk->cpus_allowed = VE_CPU_MASK(ausim_max_core_num);

	retval = get_ve_core_n_node_new_ve_proc(tsk, ve_node_id, ve_core_id);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"psm_handle_exec_ve_proc_req failed\n");
		goto free_sighand;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Creating NEW VE Process on NODE : %d"
			"CORE : %d for PID : %d\n",
			*ve_node_id, *ve_core_id, pid);

	/* Populate ve_task_struct */
	strncpy(tsk->ve_comm, exe_name, ACCT_COMM);
	tsk->pid = pid;
	tsk->priority = VE_DEF_SCHED_PRIORITY;
	tsk->sched_class = 0;
	tsk->ve_task_state = WAIT;
	tsk->core_id = *ve_core_id;
	tsk->node_id = *ve_node_id;
	tsk->p_ve_core = VE_CORE(*ve_node_id, *ve_core_id);
	tsk->exit_signal = 0;
	tsk->group_leader = tsk;
	tsk->tgid = tsk->pid;
	tsk->sas_ss_sp = 0;
	tsk->sas_ss_size = 0;
	tsk->syncsignal = 0;
	tsk->policy = SCHED_OTHER;
	tsk->rt_priority = 0;
	tsk->flags = 0;
	/* Initialy setting all the VE process
	 * resource limit as unlimited i.e. -1
	 */
	memset(tsk->rlim, -1, sizeof(tsk->rlim));

	/* Parent of VE pocess created from
	 * "ve_exec" is INIT ve task */
	tsk->parent = &ve_init_task;

	tsk->offset = 0;
	tsk->sr_context_bitmap = 0;
	tsk->exec_time = 0;
	tsk->execed_proc = false;

	/* Initialize children/sibling/tasks list */
	INIT_LIST_HEAD(&tsk->children);
	INIT_LIST_HEAD(&tsk->siblings);
	INIT_LIST_HEAD(&tsk->thread_group);
	INIT_LIST_HEAD(&tsk->tasks);
	ve_init_sigpending(&tsk->pending);
	sigemptyset(&tsk->blocked);

	/* Every VE process is thread group leader */
	tsk->group_leader = tsk;

	/* Flag to handle vforked VE process */
	tsk->vfork_state = VFORK_C_INVAL;
	tsk->vforked_proc = false;

	/* Initialize block_status with BLOCK_RECVD, so that
	 * this process can be scheduled successfully after it
	 * is scheduled for the  first time by the scheduler.
	 * */
	tsk->block_status = BLOCK_RECVD;

	if (0 != pthread_mutex_init(&(tsk->ve_task_lock), NULL)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init failed %s\n",
				strerror(errno));
		retval = -1;
		goto free_sighand;
	}
	if (0 != pthread_mutex_init(&(tsk->siglock), NULL)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Mutex init failed %s\n",
				strerror(errno));
		retval = -1;
		goto free_sighand;
	}

	/* Create VE process structure at driver server */
	if (-1 == vedl_create_ve_process(VE_NODE(*ve_node_id)->handle, pid)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_create_ve_process failed.\n");
		retval = -1;
		goto free_sighand;
	}

	/* Insert the task in it's parent's children list */
	list_add_tail(&tsk->siblings, &tsk->parent->children);

	/* Insert an entry for this task in INIT tasks list */
	pthread_spin_lock(&init_task_lock);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Inserting pid: %d of core: %d to init list\n",
				pid, *ve_core_id);
	list_add_tail(&tsk->tasks, &ve_init_task.tasks);
	pthread_spin_unlock(&init_task_lock);

	/* Insert VE task list for Node and Core task list */
	insert_ve_task(tsk->node_id, tsk->core_id, tsk);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"VE Node Id = %d VE Core Id = %d\n",
			*ve_node_id,
			*ve_core_id);

	/* Get SHM/LHM area */
#ifdef __AUSIM_ENV
	retval = psm_init_shared_file_mmap(tsk);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"SHM/LHM area allocation failed\n");
		goto free_sighand;
	}
#else
	tsk->sighand->lshm_addr = (uint64_t)shmat(shmid, NULL, 0);
	if ((void *)-1 == (void *)tsk->sighand->lshm_addr) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"shmat() %s\n", strerror(errno));
		retval = -1;
		goto free_sighand;
	}
#endif
	/* Store the SHM/LHM address of pseudo process
	 * in mm_struct.
	 */
	tsk->p_ve_mm->shm_lhm_addr = vaddr;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SHM/LHM address %lx of pid %d\n",
			vaddr, tsk->pid);

	VE_NODE(*ve_node_id)->total_forks++;
	retval = 0;
	goto hndl_return;

free_sighand:
	free(tsk->sighand);
free_mm_struct:
	free(tsk->p_ve_mm);
free_thread:
	free(tsk->p_ve_thread);
free_tsk:
	free(tsk);
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Out Func\n");
	return retval;
}

/**
 * @brief Handles START VE request from Pseudo Process.
 *
 * @param[in] pti Pointer to thread arg for Worker Thread
 * @param[in] pid PID of the VE process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_start_ve_request(struct veos_thread_arg *pti, int pid)
{
	int retval = -1;
	struct ve_context_info context_info;
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!pti)
		goto hndl_return;

	memcpy(&context_info,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			sizeof(struct ve_context_info));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "IC:%lx\tSP:%lx\tSZ:%lx\n",
			context_info.IC,
			context_info.SP,
			context_info.SZ);

	/* Fetch the respective task_struct from the list */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"PID %d not found. START VE failed\n",
				pid);
		goto hndl_return;
	} else {
		/* update thread struct */
		update_ve_thread_node(&context_info, tsk->p_ve_thread);
		retval = 0;
	}

	p_ve_core = tsk->p_ve_core;
	/* Set the task state to RUNNING */
	pthread_mutex_lock(&(tsk->ve_task_lock));
	/* Start time of new VE process is maintained */
	gettimeofday(&(tsk->start_time), NULL);
	tsk->ve_task_state = RUNNING;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	/* Number of active task updated on core */
	ve_atomic_inc(&(p_ve_core->nr_active));

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Removes the task from the core list.
 *
 * @param[in] ve_node_id Node ID of the task
 * @param[in] ve_core_id Core ID of the task
 * @param[in] p_rm_task Pointer to ve_task_struct of VE process
 *
 * @return 0 on success, -1 on failure.
 */
int remove_task_from_core_list(int ve_node_id, int ve_core_id,
		struct ve_task_struct *p_rm_task)
{
	int retval = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* take lock before Updating Core task list */
	pthread_rwlock_wrlock(&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock));

	if (NULL == p_rm_task) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Error: Task to be removed is NULL\n");
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Remove task %d from Node %d Core %d"
			"Core Pointer %p\n",
			p_rm_task->pid,
			ve_node_id,
			ve_core_id,
			VE_CORE(ve_node_id, ve_core_id));

	/* Core data structure should not be NULL*/
	ve_task_list_head = VE_CORE(ve_node_id, ve_core_id)->ve_task_list;

	if (NULL == ve_task_list_head) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Error: Head task of Core should not"
				"be NULL, Task to be removed 0x%p\n",
				p_rm_task);
		goto hndl_return;
	}

	if (p_rm_task == ve_task_list_head &&
			ve_task_list_head->next == ve_task_list_head) {
		VE_CORE(ve_node_id, ve_core_id)->ve_task_list = NULL;
		goto hndl_return1;
	}

	temp = p_rm_task->next;
	while (temp->next != p_rm_task)
		temp = temp->next;

	temp->next = p_rm_task->next;
	if (p_rm_task == ve_task_list_head) {
		VE_CORE(ve_node_id, ve_core_id)->ve_task_list =
				ve_task_list_head->next;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Now Head is %p\n",
					ve_task_list_head);
	}

hndl_return1:
	VE_NODE(ve_node_id)->num_ve_proc--;
	VE_CORE(ve_node_id, ve_core_id)->num_ve_proc--;
	retval = 0;
hndl_return:
	/* release lock for Core task list */
	pthread_rwlock_unlock(&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Inserts VE task to the VE node and VE core list.
 *
 * @param[in] ve_node_id VE Node ID for the task
 * @param[in] ve_core_id VE Core ID for the task
 * @param[in] p_ve_task Pointer to VE task structure
 *
 * @return 0 on success, -1 on failure.
 */
int insert_ve_task(int ve_node_id, int ve_core_id,
		struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	struct ve_task_struct *ve_task_list_head = NULL;
	struct ve_task_struct *temp = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!p_ve_task)
		goto hndl_return;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Node %d Core %d Core Pointer %p\n",
			ve_node_id,
			ve_core_id,
			VE_CORE(ve_node_id, ve_core_id));

	/* take lock before Updating Core task list */
	pthread_rwlock_wrlock(&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock));

	/* Core data structure should not be NULL*/
	ve_task_list_head = VE_CORE(ve_node_id, ve_core_id)->ve_task_list;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"ve_task_list_head : %p\n", ve_task_list_head);

	/* Create HEAD node*/
	if (NULL == ve_task_list_head) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				":%d:%d VE task list INIT\n",
						ve_node_id, ve_core_id);
		ve_task_list_head = p_ve_task;
		ve_task_list_head->next = ve_task_list_head;
	} else if (ve_task_list_head->next == ve_task_list_head) {
		/* Create second node */
		ve_task_list_head->next = p_ve_task;
		p_ve_task->next = ve_task_list_head;
	} else {
		/* Insert the node at the last */
		temp = ve_task_list_head->next;
		while (temp->next != ve_task_list_head)
			temp = temp->next;

		p_ve_task->next = temp->next;
		temp->next = p_ve_task;
	}

	/* Update HEAD of the Core list */
	VE_CORE(ve_node_id, ve_core_id)->ve_task_list = ve_task_list_head;
	VE_NODE(ve_node_id)->num_ve_proc++;
	VE_CORE(ve_node_id, ve_core_id)->num_ve_proc++;

	/* wake up the thread which handles SIGSTOP signal */
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Signal wake up of stopping thread\n");
	pthread_cond_signal(&VE_NODE(ve_node_id)->stop_cond);
	pthread_mutex_unlock(&VE_NODE(ve_node_id)->stop_mtx);

	/* relaese lock for Core task list */
	pthread_rwlock_unlock(&(VE_CORE(ve_node_id, ve_core_id)->ve_core_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Now Head for Core %d is %p Inserted PID %d\n",
				ve_core_id,
				ve_task_list_head,
				p_ve_task->pid);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief List over all the Nodes and Core to print all task
 * currently with veos.
 */
void list_ve_proc(void)
{
	int core_loop = 0;
	int node_loop = 0;
	struct ve_node_struct *p_ve_node;
	struct ve_core_struct *p_ve_core;
	struct ve_task_struct *p_ve_task;
	struct ve_task_struct *temp;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	for (; node_loop < MAX_VE_NODE_PER_VH; node_loop++) {
		p_ve_node = VE_NODE(VE_NODE_ID(node_loop));
		if (NULL == p_ve_node) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG node_id %d\n",
					VE_NODE_ID(node_loop));
			continue;
		}
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"\nL:NUM PROC ON NODE %d is %d\n",
				VE_NODE_ID(node_loop), p_ve_node->num_ve_proc);
		if (0 == p_ve_node->num_ve_proc)
			continue;
		for (; core_loop < MAX_VE_CORE_PER_VE_NODE; core_loop++) {
			p_ve_core = p_ve_node->p_ve_core[core_loop];
			if (NULL == p_ve_core) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"BUG core_id %d\n",
						core_loop);
				continue;
			}
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"NUM PROC ON CORE %d is %d\n",
					core_loop, p_ve_core->num_ve_proc);
			pthread_rwlock_rdlock(&(VE_CORE(VE_NODE_ID(node_loop),
								core_loop)->
								ve_core_lock));
			p_ve_task = p_ve_core->ve_task_list;
			if (NULL == p_ve_task) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"LIST : No TASK for Node %d Core %d\n",
					VE_NODE_ID(node_loop), core_loop);
				pthread_rwlock_unlock(
						&(VE_CORE(VE_NODE_ID(node_loop),
							core_loop)->
							ve_core_lock));
				continue;
			} else if (p_ve_task->next == p_ve_task) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"LIST:%d:%d, HEAD = %p, PID = %d, STATE = %d\n"
					, VE_NODE_ID(node_loop), core_loop
					, p_ve_task, p_ve_task->pid
					, p_ve_task->ve_task_state);

			} else {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"LIST:%d:%d, HEAD = %p, PID = %d, STATE = %d\n"
					, VE_NODE_ID(node_loop), core_loop
					, p_ve_task, p_ve_task->pid
					, p_ve_task->ve_task_state);

				temp = p_ve_task->next;
				while (temp != p_ve_task) {
					VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"LIST:%d:%d, NODE = %p, "
						"PID = %d, STATE = %d\n"
						, VE_NODE_ID(node_loop)
						, core_loop
						, temp, temp->pid
						, temp->ve_task_state);
					temp = temp->next;
				}
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"LIST : END for "
						"Node %d Core %d\n",
						VE_NODE_ID(node_loop),
						core_loop);
			}
			pthread_rwlock_unlock(
					&(VE_CORE(VE_NODE_ID(node_loop),
						core_loop)
						->ve_core_lock));
		}
		core_loop = 0;
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "OUT Func\n");
}

/**
 * @brief Handles BLOCK request for a VE Process when it's corresponding
 * Pseudo Process is about to execute a blocking system call on VH Host.
 *
 * @param[in] pid PID of the process requesting BLOCK
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_block_request(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core;
	int retval = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Handling BLOCK REQ for PID %d\n", pid);
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Task with PID %d not found"
				"while handling block request\n",
				pid);
		retval = -1;
		goto hndl_return;
	}
	/* Set the task state to WAITING */
	p_ve_core = VE_CORE(tsk->node_id, tsk->core_id);
	pthread_mutex_lock(&(tsk->ve_task_lock));
	tsk->ve_task_state = WAIT;
	tsk->block_status = BLOCK_RECVD;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	/* Number of active task updated on core */
	ve_atomic_dec(&(p_ve_core->nr_active));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"State set to WAIT for pid %d\n", pid);

	/* Scheduling a new VE process on VE core as current
	 * VE process have generated MONC
	 */
	if (ONGOING != p_ve_core->scheduling_status) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"SCHEDULING NEW PROCESS"
				" after block on Core %d\n",
				p_ve_core->core_num);
		psm_find_sched_new_task_on_core(p_ve_core, false);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Handles UN BLOCK request for a VE Process when it has executed
 * its blocking system call on VH Host.
 *
 * @param[in] pid PID of the process requesting UNBLOCK
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_un_block_request(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core;
	int retval = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Handling UNBLOCK REQ for PID %d\n", pid);
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Task with PID %d not found"
				"while handling unblock request\n", pid);
		retval = -1;
		goto hndl_return;
	}

	p_ve_core = tsk->p_ve_core;
	/* Set the task state to RUNNING */
	pthread_mutex_lock(&(tsk->ve_task_lock));
	tsk->block_status = UNBLOCK_SERVED;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	if (VFORK_ONGOING == tsk->vfork_state) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"vforked child is executing,"
				"task state not changed\n");
	} else if (STOP == tsk->ve_task_state) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"ve process state set to STOP,"
				"task state cannot be set to RUNNING\n");
	} else {
		pthread_mutex_lock(&(tsk->ve_task_lock));
		tsk->ve_task_state = RUNNING;
		pthread_mutex_unlock(&(tsk->ve_task_lock));

		/* Number of active task updated on core */
		ve_atomic_inc(&(p_ve_core->nr_active));
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"State set to RUNNING for pid %d\n",
				pid);
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief  Change the core state to HALT.
 *
 * @details PSEUDO process requests for halting all cores only in ve_futex()
 * Here core state is changed to HALT. If request is to stop single core,
 * then change the CORE state to HALT and then unassign the VE process scheduled
 * on this core. Later it assigns the process generating the HALT CORE
 *
 * @param[in] halt_core_req pointer to structure halt_ve_cores_info. Which hold
 * information of VE node ID, start and stop core ID,PID of the process
 * requesting to halt the core and flag to represent type of core halt request
 * (Single or All).For single core halt request, start and stop core ID are same
 *
 * @return 0 on SUCCESS, negative on failure.
 */
int psm_handle_halt_core_request(struct halt_ve_cores_info *halt_core_req)
{
	int retval = 0;
#ifdef __AUSIM_ENV
	struct ve_task_struct *p_ve_task = NULL;
#endif
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_node_struct *p_ve_node = NULL;
	int i;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!halt_core_req)
		goto hndl_return;

	i = halt_core_req->start_core_id;
	/* TBD: Approach for locking on NODE need to be decided.
	 *	Currently we are providing locking on NODE and CORE but this
	 *	approach is inefficient and bulky. So a more refined approach
	 *	need to be discussed.
	 *	If locking on node is not added then race condition may happen
	 *	when simultaneous request comes for STOP and START all cores.
	 */

	p_ve_node = VE_NODE(halt_core_req->task->node_id);
	if (NULL == p_ve_node) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"BUG: Node %d not found\n",
				halt_core_req->task->node_id);
		return -1;
	}

	pthread_rwlock_rdlock(&(p_ve_node->ve_node_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Node Structure %p for Node_id %d\n",
			p_ve_node, halt_core_req->task->node_id);

	for (; i <= halt_core_req->stop_core_id; i++) {
		p_ve_core = VE_CORE(halt_core_req->task->node_id, i);
		if (NULL == p_ve_core) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG Core %d not found\n", i);
			retval = -1;
			break;
		}
		/* Assigning a Task for Register mapping is only requested
		 * in AUSIM_ENV only. In FPGA, halt_core_req->flag is always
		 * set to zero.
		 */
#ifdef __AUSIM_ENV
		if (1 == halt_core_req->flag) {
			while (p_ve_core->assign_task_flag != TSK_UNASSIGN) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"%d:Acquiring core conditional lock\n",
					halt_core_req->pid);
				pthread_cond_wait(&(p_ve_core->ve_cond_lock),
						&(p_ve_node->ve_node_lock));
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"%d:Releasing core conditional lock\n",
					halt_core_req->pid);
			}

			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"%d:p_ve_core->assign_task_flag:TSK_UNASSIGN\n",
				halt_core_req->pid);
		}
#endif
		pthread_rwlock_wrlock(&(p_ve_core->ve_core_lock));

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Core Structure %p for Core_id %d\n",
			p_ve_core, i);

#ifdef __AUSIM_ENV
		p_ve_task = p_ve_core->curr_ve_task;
#endif
		if (HALT == p_ve_core->ve_core_state)
			goto try_assign;

		p_ve_core->ve_core_state = HALT;

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Stopping core : %d\n", i);

		psm_halt_ve_core(p_ve_core->node_num,
				p_ve_core->core_num);
try_assign:
#ifdef __AUSIM_ENV
		if (1 == halt_core_req->flag) {

			if (NULL != p_ve_task) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Unassign task %d form core %d\n",
						p_ve_task->pid, i);

				retval = vedl_unassign_task_from_core(
					VE_HANDLE(p_ve_core->node_num),
						p_ve_task->pid);
				if (0 != retval) {
					VE_LOG(CAT_OS_CORE,
						LOG4C_PRIORITY_ERROR,
						"Unassign task: "
						"%d core : %d failed\n",
						p_ve_task->pid, i);
					goto unlock;
				}
			}

			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Assign task %d on core:%d\n",
					halt_core_req->pid, i);

			retval = vedl_assign_task_to_core(
					VE_HANDLE(p_ve_core->node_num),
					p_ve_core->phys_core_num,
					halt_core_req->pid);

			if (0 != retval) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Assign task : %d on core:%d failed\n",
						halt_core_req->pid, i);
			} else {
				p_ve_core->assign_task_flag = TSK_ASSIGN;
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"%d:p_ve_core->assign_task_flag:TSK_ASSIGN\n",
					halt_core_req->pid);
			/*TODO:
			 * p_ve_core->curr_ve_task = halt_core_req->task;
			 */
			}
		}
unlock:
#endif
		pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
		if (0 != retval)
			break;
	}

	pthread_rwlock_unlock(&(p_ve_node->ve_node_lock));

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Start VE cores. Change cores state as EXECUTING.
 *
 * @details For single core start, unassign the VE process scheduled on this
 * core. Pseudo process request for starting of all cores only in the case of
 * ve_futex().
 *
 * @param[in] start_core_req Pointer to structure halt_ve_cores_info. Which
 * hold information of VE node ID of task, start and stop core ID of task for
 * the loop, PID of the process requesting to start VE core and flag to
 * represent type of core start request (Single or All).For single core start
 * request, start and stop core ID are same.
 *
 * @return 0 on SUCCESS, negative on failure.
 */
int psm_handle_start_core_request(struct halt_ve_cores_info *start_core_req)
{
	int retval = 0;
	struct ve_core_struct *p_ve_core = NULL;
	struct ve_node_struct *p_ve_node = NULL;

	int i;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!start_core_req)
			goto hnd1_return;

	i = start_core_req->start_core_id;
	/* TBD: Approach for locking on NODE need to be decided.
	 *	Currently we are providing locking on NODE and CORE but this
	 *	approach is inefficient and bulky. So a more refined approach
	 *	need to be discussed.
	 *	If locking on node is not added then race condition may happen
	 *	when simultaneous request comes for STOP and START all cores.
	 */
	p_ve_node = VE_NODE(start_core_req->task->node_id);
	if (NULL == p_ve_node) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"BUG: Node %d not found\n",
			start_core_req->task->node_id);
		retval = -1;
		goto hnd1_return;
	}

	pthread_rwlock_rdlock(&(p_ve_node->ve_node_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Node Structure %p for Node_id %d\n",
			p_ve_node, start_core_req->task->node_id);

	for (; i <= start_core_req->stop_core_id; i++) {
		p_ve_core = VE_CORE(start_core_req->task->node_id, i);
		if (NULL == p_ve_core) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"BUG Core %d not found\n", i);
			retval = -1;
			break;
		}

		pthread_rwlock_wrlock(&(p_ve_core->ve_core_lock));
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Core Structure %p for Core_id %d\n",
					p_ve_core, i);

		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Setting the start bit\n");

		p_ve_core->ve_core_state = EXECUTING;

		/* Unassigning a Task After Register mapping is only requested
		 * in AUSIM_ENV only. In FPGA, halt_core_req->flag is always
		 * set to zero.
		 */
#ifdef __AUSIM_ENV
		if (1 == start_core_req->flag) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Unassign task %d form core %d\n",
				start_core_req->pid, i);

			retval = vedl_unassign_task_from_core(
					VE_HANDLE(p_ve_core->node_num),
					start_core_req->pid);
			if (0 != retval) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Unassign task:%d on core:%d failed\n",
					start_core_req->pid, i);
			} else {
				p_ve_core->assign_task_flag = TSK_UNASSIGN;
			pthread_cond_broadcast(&(p_ve_core->ve_cond_lock));
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"%d:waking up thread waiting on core conditional lock\n",
					start_core_req->pid);
			}
		}

#endif
		pthread_rwlock_unlock(&(p_ve_core->ve_core_lock));
		if (0 != retval)
			break;
	}

	pthread_rwlock_unlock(&(p_ve_node->ve_node_lock));

hnd1_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* psm_address_translation: Translates VEMVA to VEMAA.
*
* @param pid: PID of VE process for which address translation is requested.
*
* @return: -1 on FAIL, valid VEMAA address on success.
*/
uint64_t psm_address_translation(int pid, uint64_t vaddr)
{
	uint64_t ret = 0;
	struct ve_task_struct *tsk = NULL;
	atb_reg_t atb;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"task with PID %d not found",
				pid);
		return 0;
	}

	atb = tsk->p_ve_mm->atb;
	ret = amm_addr_translation((char *)vaddr, &atb);
	if (0 > ret) {
		/*failed*/
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"ATB translation failed for vddr : %lx",
				vaddr);
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
 * @brief It will delete the VE process signal handler structure.
 *
 * @param[in] sighand pointer to VE process signal handler structure
 *
 * @return 0 on success, -1 on failure.
 */
int psm_del_sighand_struct(struct sighand_struct *sighand)
{
	int retval = -1;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!sighand)
		goto hndl_return;

	pthread_mutex_lock(&(sighand->siglock));
	sighand->ref_count--;
	pthread_mutex_unlock(&(sighand->siglock));

	if (sighand->ref_count <= 0) {
		pthread_mutex_destroy(&(sighand->siglock));
#ifdef __PCIDEV_ENV
		shmdt((void *)sighand->lshm_addr);
#else
		munmap((void *)sighand->lshm_addr,
				LHM_SHM_SIZE);
#endif
		free(sighand);
	}

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Prints the PID of all the VE processes starting
 * from the veos INIT VE process.
 *
 * @param[in] ve_tsk INIT's ve_task_struct
 */
void print_process_tree(struct ve_task_struct *ve_tsk)
{
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	static int cnt;
	int cnt2;

	if (!ve_tsk)
		return;

	cnt2 = cnt;
	while (cnt2) {
		fprintf(stdout, "\t");
		cnt2--;
	}

	fprintf(stdout, "PID %d\n", ve_tsk->pid);
	if (list_empty(&ve_tsk->children))
		return;

	list_for_each_safe(p, n, &ve_tsk->children) {
		tmp = list_entry(p,
				struct ve_task_struct,
				siblings);
		cnt++;
		print_process_tree(tmp);
		cnt--;
	}
}

/**
 * @brief Traverse INIT task list.
 */
void list_init_tasks(void)
{
	struct list_head *p, *n;

	fprintf(stdout, "PID : %d\n", ve_init_task.pid);
	list_for_each_safe(p, n, &ve_init_task.tasks) {
		struct ve_task_struct *tmp =
			list_entry(p,
					struct ve_task_struct,
					tasks);
		fprintf(stdout, "PID : %d\n", tmp->pid);

	}
}

/**
 * @brief Calucates the total time that VE process exectued on VE core,
 * flag determines 0 for perticular thread and 1 for process group.
 *
 * @param[in] tsk Pointer to struct ve_task_struct
 * @param[in] flag flag detemines for thread or thread group
 *
 * @return execution time of VE process on success, 0 on failure.
 */
uint64_t get_ve_proc_exec_time(struct ve_task_struct *tsk, int flag)
{
	uint64_t total_time = 0;
	struct list_head *p, *n;
	struct ve_task_struct *tmp;
	struct ve_task_struct *group_leader;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk)
		goto hndl_return;

	group_leader = tsk->group_leader;

	if (flag) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Process with PID %d exec time(microsec) %lu\n",
			group_leader->pid, group_leader->exec_time);
		total_time = group_leader->exec_time;
		if (!list_empty(&group_leader->thread_group)) {
			list_for_each_safe(p, n, &group_leader->thread_group) {
				tmp = list_entry(p,
						struct ve_task_struct,
						thread_group);
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Thread with PID %d exec time %lu\n",
					tmp->pid, tmp->exec_time);
				total_time += tmp->exec_time;
			}
		} else
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"No threads exists\n");
	} else
		total_time = tsk->exec_time;

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return total_time;
}

/**
 * @brief Calculates the total time taken by VE process/thread on VE core.
 *
 * @param[in] tsk Pointer to struct ve_task_struct
 * @param[in] flag Flag determines process or thread
 *		0 for thread
 *		1 for process
 * @param[out] tp Pointer to struct timespec contain time to fill
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_clk_cputime_request(struct ve_task_struct *tsk,
		int flag, struct timespec *tp)
{
	int retval = -1;
	uint64_t total_time = 0;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk || !tp)
		goto hndl_return;

	memset(tp, 0, sizeof(struct timespec));

	total_time = get_ve_proc_exec_time(tsk, flag);

	/* Converting to nanoseconds */
	total_time *= 1000;

	tp->tv_sec = total_time/SECS_TO_NANOSECONDS;
	tp->tv_nsec = total_time%SECS_TO_NANOSECONDS;

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Get the specefied resource limit of the VE process.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[in] resource Resource information to get
 * @param[out] rlim Pointer to struct rlim to fill resource value
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_get_rlimit_request(struct ve_task_struct *tsk,
		int resource, struct rlimit *rlim)
{
	int retval = -1;
	struct rlimit *proc_rlim;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk || !rlim)
		goto hndl_return;

	pthread_mutex_lock(&(tsk->ve_task_lock));
	proc_rlim = tsk->rlim + resource;
	*rlim = *proc_rlim;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Get Resource :%d rlim_cur:%ld rlim_max:%ld\n",
			resource, rlim->rlim_cur, rlim->rlim_max);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Set the specefied resource limit of the VE process.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[in] resource Resource information to set
 * @param[in] rlim VE process resource value to update with
 *
 * @return 0 on success, -2 on failure.
 */
int psm_handle_set_rlimit_request(struct ve_task_struct *tsk,
		int resource, struct rlimit rlim)
{
	int retval = -2;
	struct rlimit *proc_rlim;
	uint32_t cap_data_pres;
	struct __user_cap_header_struct cap_header_data;
	struct __user_cap_data_struct cap_data_data;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk)
		goto hndl_return;

	proc_rlim = tsk->rlim + resource;

	if (rlim.rlim_max < proc_rlim->rlim_max)
		/* No need to check privileged */
		goto update_rlim;

	/*
	 * checking does pseudo having a  CAP_SYS_RESOURCE
	 * capability.
	 */
	cap_user_header_t cap_header = &cap_header_data;
	cap_user_data_t cap_data = &cap_data_data;
	cap_header->pid = tsk->pid;
	cap_header->version = _LINUX_CAPABILITY_VERSION;

	/* Get the capabilities */
	if (capget(cap_header, cap_data) < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"failed capget error\n");
		goto hndl_return;
	}
	cap_data_pres = 1<<CAP_SYS_RESOURCE;
	if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "pid %d don't have"
			" CAP_SYS_RESOURCE capability.\n",
			tsk->pid);
		goto hndl_return;
	}

update_rlim:
	pthread_mutex_lock(&(tsk->ve_task_lock));
	*proc_rlim = rlim;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Set Resource :%d rlim_cur:%ld rlim_max:%ld\n",
			resource, proc_rlim->rlim_cur, proc_rlim->rlim_max);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Provide the CPU affinity value for the VE process.
 *
 * @param[in] pid PID of the VE process
 * @param[in] cpusetsize Size of cpu mask
 *
 * @return affinity mask of VE process on success, -errno on failure.
 */
int64_t psm_handle_getaffinity_request(pid_t pid, size_t cpusetsize)
{
	int64_t retval = -1;
	struct ve_task_struct *tsk = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Handling GET AFFINITY REQ for PID %d\n", pid);

	if ((cpusetsize * BITS_PER_BYTE) < ausim_max_core_num) {
		retval = -EINVAL;
		goto hndl_return;
	}

	if (cpusetsize & (sizeof(unsigned long)-1)) {
		retval = -EINVAL;
		goto hndl_return;
	}
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Task with PID %d not found"
			"while handling GET AFFINITY REQ request\n", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	pthread_mutex_lock(&(tsk->ve_task_lock));
	retval = tsk->cpus_allowed;
	pthread_mutex_unlock(&(tsk->ve_task_lock));
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Sets the CPU affinity value for the VE process.
 *
 * @param[in] pid PID of the VE process
 * @param[in] mask cpu mask to set
 *
 * @return 0 on success, -errno on failure.
 */
int64_t psm_handle_setaffinity_request(pid_t pid, uint64_t mask)
{
	struct ve_task_struct *tsk = NULL;
	int core_id = -1;
	int node_id = -1;
	int64_t retval = -1;
	uint32_t cap_data_pres;
	struct __user_cap_header_struct cap_header_data;
	struct __user_cap_data_struct cap_data_data;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Handling SET AFFINITY REQ for PID %d\n", pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Task with PID %d not found"
				"while handling SET AFFINITY REQ request\n",
				pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	/*
	 * checking does pseudo having a  CAP_SYS_NICE
	 * capability.
	 */
	cap_user_header_t cap_header = &cap_header_data;
	cap_user_data_t cap_data = &cap_data_data;
	cap_header->pid = tsk->pid;
	cap_header->version = _LINUX_CAPABILITY_VERSION;

	/* Get the capabilities */
	if (capget(cap_header, cap_data) < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"failed capget error\n");
		retval = -EPERM;
		goto hndl_return;
	}
	cap_data_pres = 1<<CAP_SYS_NICE;
	if (cap_data_pres != (cap_data->effective&cap_data_pres)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "pid %d don't have"
			" CAP_SYS_NICE capability.\n",
			tsk->pid);
		retval = -EPERM;
		goto hndl_return;
	}

	pthread_mutex_lock(&(tsk->ve_task_lock));
	tsk->cpus_allowed = mask;
	pthread_mutex_unlock(&(tsk->ve_task_lock));

	/* check that after updating the affinity VE process
	 * need to relocate or not.
	 */
	if (!(IS_CPU_ALLOWED(tsk, tsk->core_id))) {
		retval = get_ve_core_n_node_new_ve_proc(tsk, &node_id,
				&core_id);
		if (-1 == retval) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Fail to get core node id\n");
			retval = -EFAULT;
			goto hndl_return;
		}
		psm_relocate_ve_task(tsk->node_id, tsk->core_id, node_id,
			core_id, tsk);
	}

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Yield the core on which VE process is running.
 *
 * @param[in] pid PID of the VE process
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_sched_yield_request(pid_t pid)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core;
	int retval = -1;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Handling SCHED YIELD for PID %d\n", pid);

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (!tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Task with PID %d not found"
			"while handling SET AFFINITY REQ request\n", pid);
		goto hndl_return;
	}

	p_ve_core = VE_CORE(tsk->node_id, tsk->core_id);
	/* Scheduling a new VE process on VE core as current
	 * VE process requested to yield the core.
	 * */
	if (ONGOING != p_ve_core->scheduling_status) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"SCHEDULING NEW PROCESS"
				" after SCHED YIELD %d from PID %d\n",
				p_ve_core->core_num, pid);
		psm_find_sched_new_task_on_core(p_ve_core, false);
	}

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
 * @brief Calculates the total execution time to its child process
 * and grandchild process if available.
 *
 * @param[in] tsk Pointer to ve_task_struct
 *
 * @return execution time on success, 0 on failure.
 */
uint64_t get_process_tree_exec_time(struct ve_task_struct *tsk)
{
	struct list_head *p, *n;
	struct ve_task_struct *tmp = NULL;
	static uint64_t time;

	if (!tsk) {
		time = 0;
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "PID %d\n", tsk->pid);
	time = get_ve_proc_exec_time(tsk, 1);

	if (list_empty(&tsk->children))
		return time;

	list_for_each_safe(p, n, &tsk->children) {
		tmp = list_entry(p,
				struct ve_task_struct,
				siblings);
		time += get_process_tree_exec_time(tmp);
	}

hndl_return:
	return time;
}

/**
 * @brief Obtains and fills the VE process resource usage in struct ve_rusage.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[in] who resource usage measures for who
 * @param[out] ve_r Pointer to struct ve_rusage to fill
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_get_rusage_request(struct ve_task_struct *tsk,
		int who, struct ve_rusage *ve_r)
{
	int retval = -1;
	uint64_t total_time = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!tsk || !ve_r)
		goto hndl_return;

	if (who == RUSAGE_SELF) {
		total_time = get_ve_proc_exec_time(tsk, 1);
		ve_r->ru_stime.tv_sec = total_time/1000000;
		ve_r->ru_stime.tv_usec = total_time%1000000;
	} else if (who == RUSAGE_THREAD) {
		total_time = get_ve_proc_exec_time(tsk, 0);
		ve_r->ru_stime.tv_sec = total_time/1000000;
		ve_r->ru_stime.tv_usec = total_time%1000000;
	} else if (who == RUSAGE_CHILDREN) {
		/* TODO: resource usage statistics for all children of the
		 * calling process that have terminated and been waited for.
		 *
		 * Handling for Zombie child process needs to add.
		 */
		total_time = get_process_tree_exec_time(tsk);
		ve_r->ru_stime.tv_sec = total_time/1000000;
		ve_r->ru_stime.tv_usec = total_time%1000000;
	} else
		goto hndl_return;

	/* TODO: For RUSAGE_CHILDREN, RSS of the largest child,
	 * not the maximum resident set size of the process tree.
	 */
	ve_r->ru_maxrss = amm_get_rss_in_kb(tsk->p_ve_mm);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Max RSS: %ld CPU time (%ld sec %ld microsec)\n",
			ve_r->ru_maxrss,
			ve_r->ru_stime.tv_sec,
			ve_r->ru_stime.tv_usec);
	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief Function updates the memory map descriptor fields of the
 * calling VE process.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[in] option memory map field to update
 * @param[in] value data to update with
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_pr_set_mm_request(struct ve_task_struct *tsk,
		uint64_t option, uint64_t value)
{
	int retval = -1;
	uint64_t rlim;
	struct ve_mm_struct *mm;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!tsk)
		goto hndl_return;

	mm = tsk->p_ve_mm;
	rlim = tsk->rlim[RLIMIT_DATA].rlim_cur;

	switch (option) {
	case PR_SET_MM_START_CODE:
		mm->start_code = value;
		break;
	case PR_SET_MM_END_CODE:
		mm->end_code = value;
		break;
	case PR_SET_MM_START_DATA:
		mm->start_data = value;
		break;
	case PR_SET_MM_END_DATA:
		mm->end_data = value;
		break;
	case PR_SET_MM_START_BRK:
		if (value < mm->end_data)
			goto hndl_return;

		if (rlim < RLIM_INFINITY &&
				(value - mm->start_brk) +
				(mm->end_data - mm->start_data) > rlim)
			goto hndl_return;

		mm->start_brk = value;
		break;
	case PR_SET_MM_BRK:
		if (value <= mm->end_data)
			goto hndl_return;

		if (rlim < RLIM_INFINITY &&
			(value - mm->start_brk) +
			(mm->end_data - mm->start_data) > rlim)
			goto hndl_return;

		mm->brk = value;
		break;
	case PR_SET_MM_START_STACK:
		 mm->start_stack = value;
		 break;
	case PR_SET_MM_ARG_START:
		mm->arg_start = value;
		break;
	case PR_SET_MM_ARG_END:
		mm->arg_end = value;
		break;
	case PR_SET_MM_ENV_START:
		mm->env_start = value;
		break;
	case PR_SET_MM_ENV_END:
		mm->env_end = value;
		break;
	case PR_SET_MM_AUXV:
		/* TODO: need to discuss */
		break;
	default:
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid PR_SET_MM option.\n");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief Populate the values in struct sysinfo maintained in VEOS.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[out] ve_sysinfo Pointer to struct sysinfo to populate
 *
 * @return 0 on success, -1 on failure.
 */
int psm_handle_sysinfo_request(struct ve_task_struct *tsk,
		struct sysinfo *ve_sysinfo)
{
	int retval = -1;
	struct timeval now;
	double av_1, av_5, av_15;
	struct ve_node_struct *p_ve_node = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	if (!tsk || !ve_sysinfo)
		goto hndl_return;

	p_ve_node = VE_NODE(tsk->node_id);

	retval = calc_last_1_5_15_load(p_ve_node, &av_1, &av_5, &av_15);
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to get loadavg\n");
		goto hndl_return;
	}

	gettimeofday(&now, NULL);
	/* VE node boot time */
	ve_sysinfo->uptime = ((now.tv_sec * MICRO_SECONDS) + now.tv_usec) -
		p_ve_node->node_boot_time;

	/* Convert micro seconds to seconds */
	ve_sysinfo->uptime /= MICRO_SECONDS;

	/* Number of current processes*/
	ve_sysinfo->procs = p_ve_node->num_ve_proc;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "uptime: %lu procs: %d\n",
			ve_sysinfo->uptime,
			ve_sysinfo->procs);

	ve_sysinfo->loads[0] =
		(unsigned long)(av_1 * (float)(1 << SI_LOAD_SHIFT));
	ve_sysinfo->loads[1] =
		(unsigned long)(av_5 * (float)(1 << SI_LOAD_SHIFT));
	ve_sysinfo->loads[2] =
		(unsigned long)(av_15 * (float)(1 << SI_LOAD_SHIFT));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Load 1min: %lu, 5min: %lu, 15min: %lu\n",
			ve_sysinfo->loads[0],
			ve_sysinfo->loads[1],
			ve_sysinfo->loads[2]);
	/* TODO:
	 * currently an dummy function will be added in amm_mem.c
	 * that will be filled later on when these fields are handled
	 * by AMM.
	 */
	amm_sys_meminfo(ve_sysinfo);

	retval = 0;
hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
/**
 * @brief Enable/disable process accounting.
 *
 * @param[in] file_name Filename to append accouting detail
 *
 * @return 0 on success, -errno on failure.
 */
int psm_handle_do_acct_ve(char *file_name)
{
	int retval = -1;
	int fd;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Disable previous accounting */
	pthread_mutex_lock(&(veos_acct.ve_acct_lock));
	veos_acct.active = false;
	if (NULL != veos_acct.file) {
		free(veos_acct.file);
		veos_acct.file = NULL;
	}
	if (0 < veos_acct.fd) {
		close(veos_acct.fd);
		veos_acct.fd = -1;
	}

	/* Case to disable accounting */
	if (NULL == file_name) {
		retval = 0;
		goto hndl_return;
	}

	/* Enable accounting */
	fd = open(file_name, O_WRONLY|O_APPEND|O_LARGEFILE, 0);
	if (-1 == fd) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"VEOS fails to open accounting file: %s\n",
				file_name);
		retval = -errno;
		goto hndl_return;
	}

	veos_acct.active = true;
	veos_acct.fd = fd;
	veos_acct.file = file_name;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"VE Accounting File: %s\n", veos_acct.file);

	retval = 0;
hndl_return:
	pthread_mutex_unlock(&(veos_acct.ve_acct_lock));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}
