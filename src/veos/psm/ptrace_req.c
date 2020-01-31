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
 * @file ptrace_req.c
 * @brief PSM interfaces regarding ptrace system call handling in VEOS.
 *
 * @internal
 * @author PTRACE
 */

#include <unistd.h>
#include <search.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/capability.h>
#include "ve_mem.h"
#include "ptrace_req.h"
#include "task_mgmt.h"
#include "task_signal.h"
#include "velayout.h"
#include "psm_stat.h"
#include "locking_handler.h"


/**
 * @brief mutex lock to make sure readproc() is threadsafe
 *
 */
pthread_mutex_t readproc_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Change the state to RUNNING of the provided VE process.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ve_start_process(struct ve_task_struct *p_ve_task)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	/* Acquire core lock as we can update number of active task on core */
	pthread_rwlock_lock_unlock(&(p_ve_task->p_ve_core->ve_core_lock),
			WRLOCK,	"Failed to acquire core lock");
	/* Acquire task lock */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");

	/* Changing the State of process */
	if (VFORK_ONGOING == p_ve_task->vfork_state) {
		VEOS_DEBUG("vforked child is executing task state not changed");
	} else if (p_ve_task->block_status == BLOCK_RECVD &&
			(p_ve_task->p_ve_thread->EXS & VE_EXCEPTION)) {
		VEOS_DEBUG("Setting state WAIT for pid %d "
				"due to any exception bit is set in EXS",
				p_ve_task->pid);

		/* Update the task state to WAIT */
		psm_set_task_state(p_ve_task, WAIT);
	} else if (p_ve_task->ve_task_state != ZOMBIE) {
		VEOS_DEBUG("Setting state RUNNING for pid %d", p_ve_task->pid);

		/* Update the task state to RUNNING */
		psm_set_task_state(p_ve_task, RUNNING);
	} else {
		VEOS_DEBUG("PID: %d state is ZOMBIE", p_ve_task->pid);
	}

	/* Release task lock */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(p_ve_task->p_ve_core->ve_core_lock),
				UNLOCK,	"Failed to release core lock");
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Change the State of the VE process to STOP.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ve_stop_process(struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	struct ve_core_struct *p_ve_core = NULL;
	reg_t regdata = 0;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	p_ve_core = VE_CORE(p_ve_task->node_id, p_ve_task->core_id);

	VEOS_DEBUG("Setting state STOP for pid %d", p_ve_task->pid);

	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			WRLOCK, "Failed to acquire core's write lock");
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	psm_set_task_state(p_ve_task, STOP);

	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's write lock");

	/* check it is the current process or not */
	if (p_ve_core->curr_ve_task == p_ve_task &&
			COMPLETED == p_ve_core->scheduling_status) {
		VEOS_DEBUG("SCHEDULING NEW PROCESS after stoping current"
				" process of PID %d on Core %d",
				p_ve_task->pid, p_ve_core->core_num);
		psm_find_sched_new_task_on_core(p_ve_core, false, false);
	}

	/* If still this task is current on the core and latest register
	 * is not fetched from then core, then get the latest context
	 * from the VE core.
	 */
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			WRLOCK, "Failed to acquire core's write lock");
	pthread_mutex_lock_unlock(&p_ve_task->p_ve_mm->thread_group_mm_lock,
			LOCK, "failed to acquire thread group lock");
	if (p_ve_core->curr_ve_task == p_ve_task && p_ve_task->reg_dirty) {
		VEOS_DEBUG("Get process %d context from core %d",
				p_ve_task->pid, p_ve_core->core_num);
		psm_halt_ve_core(p_ve_core->node_num
				,p_ve_core->core_num, &regdata, false);
		psm_save_current_user_context(p_ve_task);
	}
	pthread_mutex_lock_unlock(&p_ve_task->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "failed to release thread group lock");
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's read lock");

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Attach the VE process as a tracee.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] tracer_pid Pid of Tracer
 * @param[in] tracer_uid UID of Tracer
 * @param[in] tracer_gid GID of Tracer
 * @param[in] use_seize Determines attach using seize or not
 *
 * @retval 0 on success
 * @retval PROCES_UNDER_SWAPPING on failure because process is under swapping.
 * @retval -1 on failure due to other reasons.
 */
int psm_attach_ve_process(struct ve_task_struct *p_ve_task,
		pid_t tracer_pid, uid_t tracer_uid,
		gid_t tracer_gid, bool use_seize)
{
	int retval = -1;
	int sstatus;
	bool attach = true;
	bool copy_ops = false;
	uint64_t p_ops = 0;
	proc_t ve_proc_info;
	struct iovec local_iov = {0}, remote_iov = {0};
	struct ve_ptrace_info *ptrace_info = NULL;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	memset(&ve_proc_info, 0, sizeof(proc_t));

	/* Get the information of /proc/## for the given pid */
	retval = psm_get_ve_proc_info(p_ve_task->pid, &ve_proc_info);
	if (-1 == retval) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				p_ve_task->pid);
		goto hndl_return;
	}

	/* Check if the tracer and tracee process belongs to same user,
	 * if same then directly attach/seize the VE process.
	 */
	if (tracer_uid == ve_proc_info.euid &&
		tracer_uid == ve_proc_info.suid &&
		tracer_uid == ve_proc_info.ruid &&
		tracer_gid == ve_proc_info.egid &&
		tracer_gid == ve_proc_info.sgid &&
		tracer_gid == ve_proc_info.rgid) {
		VEOS_DEBUG("Tracer: %d and Tracee: %d belongs to same user",
			tracer_pid, p_ve_task->pid);
		goto ok;
	}

	/* Check if the tracer have CAP_SYS_PTRACE capability or not */
	if (!check_ve_proc_capability(tracer_pid, CAP_SYS_PTRACE)) {
		retval = -1;
		goto hndl_return;
	}

ok:
	ptrace_info = malloc(sizeof(struct ve_ptrace_info));
	if (NULL == ptrace_info) {
		VEOS_CRIT("Internal memory allocation failed: %s",
				strerror(errno));
		retval = -1;
		goto hndl_return;
	}
	/*MEMSET*/
	memset(ptrace_info, '\0', sizeof(struct ve_ptrace_info));

	/* To prevent PTRACE request from overlapping with Swap-out Procedure,
	 * Check sstatus */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
					"Failed to acquire ve_task_lock");
	sstatus = p_ve_task->sstatus;
	if ((sstatus != ACTIVE) && (sstatus != INVALID)) {
		VEOS_ERROR("Swap-out/in procedure against VE task: %d "
						"is on going", p_ve_task->pid);
		pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
					"Failed to release ve_task_lock");
		free(ptrace_info);
		retval = -PROCES_UNDER_SWAPPING;
		goto hndl_return;
	}
	p_ve_task->ptraced = true;
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
					"Failed to release ve_task_lock");

	ptrace_info->tracer_pid = tracer_pid;
	ptrace_info->syscall_trace = false;
	ptrace_info->is_seized = use_seize;
	ptrace_info->ptrace_options = 0;
	ptrace_info->ptrace_message = 0;

	local_iov.iov_base = &attach;
	local_iov.iov_len = sizeof(attach);

	remote_iov.iov_base = (void *)(PTRACE_PRIVATE_DATA + p_ve_task->offset);
	remote_iov.iov_len = sizeof(attach);

	/* Write the tracing information in pseudo process address space */
	retval = process_vm_writev(p_ve_task->pid, &local_iov,
			1, &remote_iov, 1, 0);
	if (-1 == retval) {
		VEOS_DEBUG("process_vm_writev() fails: %s", strerror(errno));
		free(ptrace_info);
		goto hndl_return;
	}

	VEOS_DEBUG("process_vm_writev() written %d bytes", retval);

	/* Ptrace information will be maintained in VE task Struct */
	p_ve_task->p_ve_ptrace = ptrace_info;

	/* Check if this attach of process/thread after following ptrace
	 * events occured:-
	 * PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, PTRACE_O_TRACECLONE
	 */
	if (p_ve_task->group_leader == p_ve_task &&
			p_ve_task->parent->ptraced == true &&
			p_ve_task->parent->p_ve_ptrace->ptrace_message ==
			(uint64_t)p_ve_task->pid) {
		copy_ops = true;
		p_ops = p_ve_task->parent->p_ve_ptrace->ptrace_options;
		VEOS_DEBUG("Ptrace ops copied from parent PID: %d",
				p_ve_task->parent->pid);
	} else if (p_ve_task->group_leader != p_ve_task &&
			p_ve_task->group_leader->ptraced == true &&
			p_ve_task->group_leader->p_ve_ptrace->ptrace_message ==
			(uint64_t)p_ve_task->pid) {
		copy_ops = true;
		p_ops = p_ve_task->group_leader->p_ve_ptrace->ptrace_options;
		VEOS_DEBUG("Ptrace ops copied from group_leader PID: %d",
				p_ve_task->group_leader->pid);
	}

	if (false == copy_ops) {
		retval = 0;
		goto hndl_return;
	}

	/* Copy the Ptrace options from parent process/group leader
	 * if they are traced.
	 */
	retval = psm_ptrace_setoptions(p_ve_task, p_ops);
	if (-1 == retval) {
		VEOS_DEBUG("Fails to set options in pseudo: %d",
				p_ve_task->pid);
		free(ptrace_info);
	}

hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Read the content from the VE memory at the given address (VEMVA).
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] addr VEMVA of tracee process
 * @param[out] data Pointer to fill with memory content
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_peekdata(struct ve_task_struct *p_ve_task, uint64_t addr,
		void *data)
{
	int retval = -1;
	int node_id = 0;
	pid_t pid = -1;

	VEOS_TRACE("Entering");

	if (!p_ve_task || !data)
		goto hndl_return;

	pid = p_ve_task->pid;
	node_id = p_ve_task->node_id;

	/* Get the content content of VE memory at the given VEMVA using
	 * DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VEMVA_WO_PROT_CHECK, addr, pid, VE_DMA_VHVA,
			(uint64_t)data, getpid(), sizeof(uint64_t), node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace PEEKDATA");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Write the content to the VE memory at the given address (VEMVA).
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] addr VEMVA of tracee process
 * @param[in] data Data to write on given address
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_pokedata(struct ve_task_struct *p_ve_task, uint64_t addr,
		uint64_t data)
{
	int retval = -1;
	int node_id = 0;
	pid_t pid = -1;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	pid = p_ve_task->pid;
	node_id = p_ve_task->node_id;

	/* Allocate the new page if underlying page corresponding to
	 * VEMA received have Read-Only permission.
	 */
	retval = veos_handle_ptrace_poke_req(p_ve_task, addr);
	if (0 > retval) {
		VEOS_DEBUG("veos_handle_ptrace_poke_req fails: %d", retval);
		retval = -1;
		goto hndl_return;
	}

	/* Write the content to VE memory at the given VEMVA using
	 * DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&data, getpid(),
			VE_DMA_VEMVA_WO_PROT_CHECK, addr, pid, sizeof(uint64_t), node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace POKEDATA");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the offset of VE register.
 *
 * @param[in] reg VE user register
 *
 * @return offset on success, -1 on failure.
 */
off_t psm_get_reg_offset(usr_reg_name_t reg)
{
	switch ((usr_reg_name_t)reg) {
	case USRCC:
		VEOS_DEBUG("offset of USRCC");
		return (offsetof(core_user_reg_t, USRCC));
	case PSW:
		VEOS_DEBUG("offset of PSW");
		return (offsetof(core_user_reg_t, PSW));
	case EXS:
		VEOS_DEBUG("offset of EXS");
		return (offsetof(core_user_reg_t, EXS));
	case IC:
		VEOS_DEBUG("offset of IC");
		return (offsetof(core_user_reg_t, IC));
	case ICE:
		VEOS_DEBUG("offset of ICE");
		return (offsetof(core_user_reg_t, ICE));
	case VIXR:
		VEOS_DEBUG("offset of VIXR");
		return (offsetof(core_user_reg_t, VIXR));
	case VL:
		VEOS_DEBUG("offset of VL");
		return (offsetof(core_user_reg_t, VL));
	case SAR:
		VEOS_DEBUG("offset of SAR");
		return (offsetof(core_user_reg_t, SAR));
	case PMMR:
		VEOS_DEBUG("offset of PMMR");
		return (offsetof(core_user_reg_t, PMMR));
	default:
		if ((reg >= PMCR00) && (reg <= PMCR04)) {
			VEOS_DEBUG("offset of PMCR[%02d]", reg - PMCR00);
			return (offsetof(core_user_reg_t, PMCR[reg - PMCR00]));
		}
		if ((reg >= PMC00) && (reg <= PMC15)) {
			VEOS_DEBUG("offset of PMC[%02d]", reg - PMC00);
			return (offsetof(core_user_reg_t, PMC[reg - PMC00]));
		}
		if ((reg >= SR00) && (reg <= SR63)) {
			VEOS_DEBUG("offset of SR[%02d]", reg - SR00);
			return (offsetof(core_user_reg_t, SR[reg - SR00]));
		}

		VEOS_DEBUG("usr_reg: no such a register(%d).", reg);
	}
	return -1;
}

/**
 * @brief Read the content from the given VE register of the tracee
 * process.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] addr VE register to get
 * @param[out] data Data of VE register
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_peekuser(struct ve_task_struct *p_ve_task, uint64_t addr,
		void *data)
{
	int retval = -1;
	off_t reg_offset = -1;

	VEOS_TRACE("Entering");

	if (!p_ve_task || !data)
		goto hndl_return;

	/* Find the offset of the given VE register */
	reg_offset = psm_get_reg_offset((usr_reg_name_t)addr);
	if (-1 == reg_offset) {
		VEOS_DEBUG("Reg: %ld offset not found", addr);
		goto hndl_return;
	}

	/* Get the content of VE register maintained in VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy(data, (void *)((void *)(p_ve_task->p_ve_thread) + reg_offset),
			sizeof(reg_t));
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Stores the content to the given VE register of the tracee
 * process.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] addr VE register to get
 * @param[in] data Data of VE register
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_pokeuser(struct ve_task_struct *p_ve_task, uint64_t addr,
		uint64_t data)
{
	int retval = -1;
	off_t reg_offset = -1;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	/* Find the offset of the given VE register */
	reg_offset = psm_get_reg_offset((usr_reg_name_t)addr);
	if (-1 == reg_offset) {
		VEOS_DEBUG("Reg: %ld offset not found", addr);
		goto hndl_return;
	}

	/* Set the content of VE register maintained in VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy((void *)((void *)(p_ve_task->p_ve_thread) + reg_offset),
			&data, sizeof(reg_t));
	p_ve_task->usr_reg_dirty = true;
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the content of VE user register set of the tracee process
 * and stores in the given VHVA of tracer.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] data VEHVA of tracer to fill VE register set
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_getregs(struct ve_task_struct *p_ve_task, uint64_t data)
{
	int retval = -1;
	struct ve_user_regs ve_u_reg;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	memset(&ve_u_reg, 0, sizeof(struct ve_user_regs));

	/* Get the VE user register set maintained the VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy(&ve_u_reg, p_ve_task->p_ve_thread, sizeof(struct ve_user_regs));
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	/* Write the content to tracer's memory at a given address
	 * 'data' using DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&ve_u_reg, getpid(),
			VE_DMA_VHVA, data, p_ve_task->p_ve_ptrace->tracer_pid,
			sizeof(struct ve_user_regs), p_ve_task->node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace GETREGS");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the content of VE user register set of the tracee process
 * provide by the tracer.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] data VEHVA of tracer to get VE register set
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_setregs(struct ve_task_struct *p_ve_task, uint64_t data)
{
	int retval = -1;
	struct ve_user_regs ve_u_reg;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	memset(&ve_u_reg, 0, sizeof(struct ve_user_regs));

	/* Get the content from tracer's memory at a given address
	 * 'data' using DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VHVA, data,
			p_ve_task->p_ve_ptrace->tracer_pid,
			VE_DMA_VHVA, (uint64_t)&ve_u_reg, getpid(),
			sizeof(struct ve_user_regs), p_ve_task->node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace SETREGS");
		goto hndl_return;
	}

	/* Update the VE user register set maintained the VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy(p_ve_task->p_ve_thread, &ve_u_reg, sizeof(struct ve_user_regs));
	p_ve_task->usr_reg_dirty = true;
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the content of VE vector register set of the tracee process
 * and stores in the given VHVA of tracer.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] data VEHVA of tracer to fill VE register set
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_getvregs(struct ve_task_struct *p_ve_task, uint64_t data)
{
	int retval = -1;
	struct ve_user_vregs ve_u_vreg;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	memset(&ve_u_vreg, 0, sizeof(struct ve_user_vregs));

	/* Get the VE vector register set maintained in the VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy(&ve_u_vreg, (void *)(p_ve_task->p_ve_thread) +
			sizeof(struct ve_user_regs),
			sizeof(struct ve_user_vregs));
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	/* Write the content to tracer's memory at a given address
	 * 'data' using DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&ve_u_vreg, getpid(),
			VE_DMA_VHVA, data, p_ve_task->p_ve_ptrace->tracer_pid,
			sizeof(struct ve_user_vregs), p_ve_task->node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace GETVREGS");
		goto hndl_return;
	}

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the content of VE vector register set of the tracee process
 * provide by the tracer.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] data VEHVA of tracer to get VE register set
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_setvregs(struct ve_task_struct *p_ve_task, uint64_t data)
{
	int retval = -1;
	struct ve_user_vregs ve_u_vreg;

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	memset(&ve_u_vreg, 0, sizeof(struct ve_user_vregs));

	/* Get the content from tracer's memory at a given address
	 * 'data' using DMA API's.
	 */
	retval = amm_dma_xfer(VE_DMA_VHVA, data,
			p_ve_task->p_ve_ptrace->tracer_pid,
			VE_DMA_VHVA, (uint64_t)&ve_u_vreg, getpid(),
			sizeof(struct ve_user_vregs), p_ve_task->node_id);
	if (-1 == retval) {
		VEOS_DEBUG("DMA failed during ptrace SETVREGS");
		goto hndl_return;
	}

	/* Update the VE vector register set maintained the VE task struct */
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	memcpy((void *)(p_ve_task->p_ve_thread) + sizeof(struct ve_user_regs),
			&ve_u_vreg, sizeof(struct ve_user_vregs));
	p_ve_task->usr_reg_dirty = true;
	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
			"Failed to release task lock");

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Detach the VE process from tracing and remove all its tracing
 * information.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_detach(struct ve_task_struct *p_ve_task)
{
	int retval = -1;
	bool attach = false;
	struct iovec local_iov = {0}, remote_iov = {0};

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	local_iov.iov_base = &attach;
	local_iov.iov_len = sizeof(attach);

	remote_iov.iov_base = (void *)(PTRACE_PRIVATE_DATA + p_ve_task->offset);
	remote_iov.iov_len = sizeof(attach);

	/* Write the tracing information in pseudo process address space */
	retval = process_vm_writev(p_ve_task->pid, &local_iov,
			1, &remote_iov, 1, 0);
	/* As per the discussion under trac #841 for FCS we will ignore the
	 * failure of process_vm_writev() when errno is EFAULT.
	 */
	if (-1 == retval && errno != EFAULT) {
		VEOS_DEBUG("process_vm_writev() fails: %s", strerror(errno));
		goto hndl_return;
	}

	VEOS_DEBUG("process_vm_writev() written %d bytes", retval);

	/* Remove the tracing information from VE task Struct */
	p_ve_task->ptraced = false;
	free(p_ve_task->p_ve_ptrace);
	p_ve_task->p_ve_ptrace = NULL;

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Enable/disable the VE process system call tracing.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] on Enable/disable system call tracing
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_syscall(struct ve_task_struct *p_ve_task, bool on)
{
	int retval = -1;
	struct iovec local_iov = {0}, remote_iov = {0};

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	local_iov.iov_base = &on;
	local_iov.iov_len = sizeof(on);

	remote_iov.iov_base = (void *)(PTRACE_PRIVATE_DATA +
			p_ve_task->offset + SYSCALL_TRACE_OFFSET);
	remote_iov.iov_len = sizeof(on);

	/* Write the tracing information in pseudo process address space */
	retval = process_vm_writev(p_ve_task->pid, &local_iov,
			1, &remote_iov, 1, 0);
	if (-1 == retval) {
		VEOS_DEBUG("process_vm_writev() fails: %s", strerror(errno));
		goto hndl_return;
	}

	VEOS_DEBUG("process_vm_writev() written %d bytes", retval);

	/* Update the system call tracing information in VE task Struct */
	p_ve_task->p_ve_ptrace->syscall_trace = on;

	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the ICE register value of the VE process.
 *
 * @param[in] pid Pid of VE process
 * @param[out] ice Pointer to fill ICE register value
 *
 * @return 0 on success, -errno on failure.
 */
int psm_get_ice_regval(int pid, uint64_t *ice)
{
	int retval = -1;
	int core_id = -1;
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core = NULL;

	VEOS_DEBUG("Entering");

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("Task with pid %d not found", pid);
		retval = -ESRCH;
		goto hndl_return;
	}

	core_id = tsk->core_id;
	p_ve_core = tsk->p_ve_core;

	if (tsk == p_ve_core->curr_ve_task) {
		VEOS_DEBUG("Getting ICE from core: %d", core_id);
		retval = vedl_get_usr_reg(VE_HANDLE(0),
				VE_CORE_USR_REG_ADDR(0, core_id),
				ICE,
				ice);
		if (0 != retval) {
			VEOS_DEBUG("vedl_get_usr_reg fail for core %d",
					core_id);
			retval = -EFAULT;
			goto hndl_return;
		}
	} else
		*ice = tsk->p_ve_thread->ICE;

	VEOS_DEBUG("ICE: %lx of Pid: %d", *ice, pid);
	retval = 0;
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Set the given ptrace options in VE process task struct.
 *
 * @param[in] p_ve_task Pointer to VE task Struct
 * @param[in] data Bit mask of ptrace options
 *
 * @return 0 on success, -1 on failure.
 */
int psm_ptrace_setoptions(struct ve_task_struct *p_ve_task, uint64_t data)
{
	int retval = -1;
	uint64_t flags = 0;
	struct iovec local_iov = {0}, remote_iov = {0};

	VEOS_TRACE("Entering");

	if (!p_ve_task)
		goto hndl_return;

	/* Check the ptrace bitmap received is valid or not */
	if (data & ~(uint64_t)(PTRACE_O_MASK | PTRACE_O_EXITKILL)) {
		VEOS_DEBUG("Invalid ptrace option bitmask received: %lx", data);
		goto hndl_return;
	}

	/* Update the ptrace options in VE task struct */
	flags = p_ve_task->p_ve_ptrace->ptrace_options;
	flags |= data;
	p_ve_task->p_ve_ptrace->ptrace_options = flags;

	VEOS_DEBUG("Ptrace options now: %lx for PID: %d", flags, p_ve_task->pid);

	local_iov.iov_base = &flags;
	local_iov.iov_len = sizeof(flags);

	remote_iov.iov_base = (void *)(PTRACE_PRIVATE_DATA +
			p_ve_task->offset + PTRACE_OPTION_OFFSET);
	remote_iov.iov_len = sizeof(flags);

	/* Write the tracing information in pseudo process address space */
	retval = process_vm_writev(p_ve_task->pid, &local_iov,
			1, &remote_iov, 1, 0);
	if (-1 == retval) {
		VEOS_DEBUG("process_vm_writev() fails: %s", strerror(errno));
		goto hndl_return;
	}

	VEOS_DEBUG("process_vm_writev() written %d bytes", retval);
	retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Get the /proc/## entry information for the given pid.
 *
 * @param[in] pid Pid of VE process
 * @param[out] ve_proc_info Pointer to struct proc_t
 *
 * @return 0 on success, -1 on failure.
 */
int psm_get_ve_proc_info(pid_t pid, proc_t *ve_proc_info)
{
	int retval = -1;
	PROCTAB* proc = NULL;
	proc_t *proc_info = NULL;

	VEOS_TRACE("Entering");

	pthread_mutex_lock_unlock(&readproc_mutex, LOCK,
                        "Failed to acquire readproc lock");
	if (!ve_proc_info)
		goto hndl_return;
	/* initialize process information from /proc/ */
	proc = openproc(PROC_FILLMEM|PROC_FILLSTAT|PROC_FILLSTATUS|PROC_PID|
			PROC_FILLNS, &pid);
	if (NULL == proc) {
		VEOS_DEBUG("Fails to open proc interface for pid: %d", pid);
		goto hndl_return;
	}

	/* read the proc information */
	proc_info = readproc(proc, NULL);
	if (NULL == proc_info) {
		VEOS_DEBUG("Fail to read proc information for pid: %d", pid);
		goto hndl_return1;
	}

	memcpy(ve_proc_info, proc_info, sizeof(proc_t));
	freeproc(proc_info);
	retval = 0;
hndl_return1:
	closeproc(proc);
hndl_return:
	pthread_mutex_lock_unlock(&readproc_mutex, UNLOCK,
                        "Failed to release readproc lock");
	VEOS_TRACE("Exiting");
	return retval;
}
