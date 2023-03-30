/**
* Copyright (C) 2017-2020 NEC Corporation
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
* @file	task_signal.c
*
* @brief Handles and manages the signal request for VE process
* from Pseudo process.
*
*	This file contains the functions which provides support for signal
*	related functionalities to VE process, it provides support for signal
*	generation and delivery.
*
* @internal
* @author Signal Handling
*/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>

#include <ve_memory_ve1.h>
#include <veos_arch_defs.h>

#include <align.h>

#include "task_mgmt.h"
#include "task_signal.h"
#include "veos_handler.h"
#include "mm_common.h"
#include "ve_mem.h"
#include "psm_comm.h"
#include "signal.h"
#include "velayout.h"
#include "task_sched.h"
#include "locking_handler.h"

#include "task_signal_ve1.h"

int ve1_psm_get_SP_from_core(int core_id, ve_reg_t *sp)
{
	return vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id),
			VE_USR_SR11, sp);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_stack_pointer_from_core, ve1_psm_get_SP_from_core)

ve_reg_t ve1_psm_get_SP_on_thread_struct(const void *u)
{
	const ve1_core_user_reg_t *user_regs = u;
	return user_regs->SR[11];
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_stack_pointer_on_thread_struct, ve1_psm_get_SP_on_thread_struct)

/**
* @brief Restore the VE process context after the execution of signal handler.
*
*	Function calculate the address of VE task's stack where the context was
*	stored before executing signal handler routine.
*	Function read the context from VE process task stack and copy it in
*	"ve_thread_struct" so that VE task can resume its execution in next
*	scheduling cycle.
*
* @param[in] ve_task_curr Pointer to "ve_task_struct"
*
* @return 0 on success, negative value on failure.
*/
int ve1_psm_restore_ve_context(struct ve_task_struct *ve_task_curr)
{
	int64_t frame_v_addrs;
	ve_reg_t curr_sp;
	struct ve1_sigframe p_ve_sigframe;
	ve_dma_hdl *dh;
	ve_dma_status_t st;
	struct ve_node_struct *vnode_info;
	int retval = 0;

	VEOS_TRACE("Entering");

	memset(&p_ve_sigframe, 0, sizeof(p_ve_sigframe));
	pthread_rwlock_lock_unlock(&(ve_task_curr->p_ve_core->ve_core_lock),
			RDLOCK, "Failed to acquire core's read lock");
	if (ve_task_curr->p_ve_core->curr_ve_task == ve_task_curr) {
		if (ve1_psm_get_SP_from_core(ve_task_curr->core_id, &curr_sp)) {
			veos_abort("failed to get user registers");
		}
	} else {
		curr_sp = ve1_psm_get_SP_on_thread_struct(ve_task_curr->p_ve_thread->arch_user_regs);
	}
	pthread_rwlock_lock_unlock(&(ve_task_curr->p_ve_core->ve_core_lock),
			UNLOCK, "Failed to release core's read lock");

	VEOS_DEBUG("signal handler stack address : %lx",
			curr_sp);

	/* Find the virtual address of stack where the process
	 * context is stored
	 * */
	frame_v_addrs = curr_sp + HANDLER_STACK_FRAME;

	VEOS_DEBUG("Frame Virtual address : %lx", frame_v_addrs);

	vnode_info = VE_NODE(ve_task_curr->node_id);
	dh = vnode_info->dh;
	/* read the signal frame from VE process physical memory
	 * */
	st = ve_dma_xfer_p_va(dh, VE_DMA_VEMVA, ve_task_curr->pid,
			(uint64_t)frame_v_addrs, VE_DMA_VHVA, getpid(),
			(uint64_t)&p_ve_sigframe,
			(uint64_t)sizeof(p_ve_sigframe));
	if (st != 0) {
		VEOS_ERROR("%d failed to read the signal frame from VE process"
				" virtual memory", ve_task_curr->pid);
		retval = -EFAULT;
		goto ret;
	} else {
		size_t dma_size = sizeof(p_ve_sigframe);
		double size_kb = dma_size / (double)1024.0;
		update_accounting_data(ve_task_curr, ACCT_TRANSDATA, size_kb);
	}

	/* Copy the current hardware context from the sigframe
	 * */
	pthread_mutex_lock_unlock(&(ve_task_curr->ve_task_lock), LOCK,
				"failed to acquire task lock");
	memset(ve_task_curr->p_ve_thread->arch_user_regs,
			'\0', sizeof(ve1_core_user_reg_t));
	memcpy(ve_task_curr->p_ve_thread->arch_user_regs,
		&p_ve_sigframe.uc.uc_mcontext, sizeof(ve1_core_user_reg_t));
	ve_task_curr->p_ve_thread->EXS = p_ve_sigframe.uc.uc_mcontext.EXS;

	ve_task_curr->usr_reg_dirty = true;

	/* Copy current lshm context */
	memcpy((void *)
		(ve_task_curr->sighand->lshm_addr + ve_task_curr->offset),
			p_ve_sigframe.lshm_area, LSHM_SZ);

	/* Restore the signal mask
	 * */
	ve_task_curr->blocked = p_ve_sigframe.uc.uc_sigmask;

	const ve1_core_user_reg_t *user_regs =
			ve_task_curr->p_ve_thread->arch_user_regs;

	VEOS_DEBUG("Sigreturn Context PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0 : %lx",
			ve_task_curr->pid,
			user_regs->IC, user_regs->SR[10], user_regs->SR[11],
			user_regs->SR[12], user_regs->SR[0]);

	pthread_mutex_lock_unlock(&(ve_task_curr->ve_task_lock), UNLOCK,
				"failed to release task lock");
	if (p_ve_sigframe.flag == SYNCHRONOUS_SIGNAL) {
		VEOS_DEBUG("Signal: %d sent to pid[%d] namespace pid[%d]",
			p_ve_sigframe.signum, ve_task_curr->pid,
				ve_task_curr->namespace_pid);
		if (1 == ve_task_curr->namespace_pid)
			kill(ve_task_curr->pid, SIGKILL);
		else
			kill(ve_task_curr->pid, p_ve_sigframe.signum);
		retval = -1;
		return retval;
	}

	psm_recalc_sigpending(ve_task_curr);


	VEOS_TRACE("Exiting");
	return retval;
ret:
	ve_force_sigsegv(SIGSEGV, ve_task_curr);
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_restore_ve_context_from_sighand, ve1_psm_restore_ve_context)

void *ve1_psm_get_ICE_on_thread_struct(const void *u)
{
	const ve1_core_user_reg_t *user_regs = u;
	return (void *)user_regs->ICE;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_exception_addr_on_thread_struct, ve1_psm_get_ICE_on_thread_struct)

/**
* @brief Function calculate the VE task stack physical address for writing
*	the signal handler frame.
*
*	VE process signal handler frame (contain VE process current context)
*	can be saved while handling signal.
*	In case stack overflow occur, SIGSEGV is delivered to VE process.
*	If VE process had registered the SIGSEGV handler on alternate stack,
*	SIGSEGV handler will be execute	else VE task will terminate with core
*	dump and SIGKILL signal will be delivered to the corresponding pseudo
*	process.
*
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] signum Signal Number getting served
* @param[out] vir_frame_addr Signal Frame virtual address
* @param[out] phy_frame_addr Signal Frame physical address
* @param[out] offset offset at which DMA to be done
* @param[out] on_altstack Determines altstack is used or not
*
* @return 0 on success -1 on failure
*/
static int ve1_psm_getframe(struct ve_task_struct *p_ve_task,
				int signum, vemaa_t *vir_frame_addr,
				vemaa_t *phy_frame_addr, uint64_t *offset,
				int *on_altstack, int *pg_mode)
{
	int onsigstack = on_sig_stack(p_ve_task);
	int flag = p_ve_task->sighand->action[signum - 1].sa_flags;
	vemaa_t frame_phy_addrs[3] = {0};
	vemva_t frame_vir_addrs, aligned_addr;
	int ret = -1, pgmod = -1;

	VEOS_TRACE("Entering");

	ve1_core_user_reg_t *user_regs = p_ve_task->p_ve_thread
						->arch_user_regs;
	if (!onsigstack) {
		/* Signal alternate stack not active
		 * */
		VEOS_DEBUG("Signal alternate stack inactive");

		if ((flag & SA_ONSTACK) && (p_ve_task->sas_ss_size)) {
			/* SA_ONSTACK is set, handle signal
			 * on alternate stack
			 * */
			VEOS_DEBUG("SA_ONSTACK flag set");
			frame_vir_addrs = p_ve_task->sas_ss_sp
				+ p_ve_task->sas_ss_size
				- sizeof(struct ve1_sigframe);
			*on_altstack = 1;

		} else {
			/* SA_ONSTACK not set
			 * */
			VEOS_DEBUG("Either SA_ONSTACK flag disable or"
					" size is invalid");
			frame_vir_addrs = user_regs->SR[11]
				- (sizeof(struct ve1_sigframe));
		}
	} else {
		/* Signal alternate stack active
		 * */
		VEOS_DEBUG("Signal alternate stack active");

		frame_vir_addrs = user_regs->SR[11]
			- sizeof(struct ve1_sigframe);
	}
	frame_vir_addrs = ROUND_DN(frame_vir_addrs, 8);
	frame_phy_addrs[0] = __veos_virt_to_phy(frame_vir_addrs,
			&(p_ve_task->p_ve_mm->atb[0]), NULL, &pgmod);
	if (0 > frame_phy_addrs[0]) {
		ret = -1;
		goto error_return;
	}

	aligned_addr = ALIGN(frame_vir_addrs, pgmod_to_pgsz(pgmod));

	if (aligned_addr - frame_vir_addrs < sizeof(struct ve1_sigframe)) {
		frame_phy_addrs[1] = __veos_virt_to_phy(aligned_addr,
				&(p_ve_task->p_ve_mm->atb[0]), NULL, &pgmod);
		if (0 > frame_phy_addrs[1]) {
			ret = -1;
			goto error_return;
		}
		*offset = aligned_addr - frame_vir_addrs;
	}

	*pg_mode = pgmod;
	memcpy(vir_frame_addr, &frame_vir_addrs, sizeof(uint64_t));
	memcpy(phy_frame_addr, &frame_phy_addrs, sizeof(frame_phy_addrs));
	ret = 0;
error_return:
	VEOS_TRACE("Exiting");
	return ret;
}

/**
* @brief Sets the signal handler context and saves the process
*	context onto stack
*
*	This function prepares the signal handler frame on VE process stack
*	Save the current context of VE process on VE stack
*	Set the value of VE process registers for the execution	of signal
*	handler routine.
*
* @param[in] signum Signal Number being delivered.
* @param[in] p_ve_task Pointer to "ve_task_struct"
* @param[in] ve_siginfo Stores the signal information.
* @param[in] flag "flag" is set when signal is generated from h/w exception.
*
* @return 0 in Success, -1 in Error.
*/
int ve1_psm_setup_ve_frame(int signum,
		struct ve_task_struct *p_ve_task,
		siginfo_t *ve_siginfo,
		int flag)
{
	/*
	 *	      STACK IMAGE
	 *
	 *	high |		|
	 *	 ^   +----------+ <--- Current SP
	 *	 |   |  Current	|
	 *	 |   |	context |
	 *	 |   |	   +	|
	 *  512KB|   |	signal  |
	 *	 |   |  handler |
	 *	 |   |arguments	|
	 *	 |   |	   +	|
	 *	 |   |Trampoline|
	 *	 v   +----------+ <--- Address of frame
	 *	 ^   |  signal	|      saving current context
	 *   512B|   |  handler |
	 *	 |   |  stack   |
	 *	 |   |	frame   |
	 *	 v   +----------+ <--- New SP(signal handler)
	 *	     |		|
	 *	low
	 */
	int ret = 0, i = 0;
	uint64_t offset = 0, local_offset = 0, dma_size = 0;
	vemaa_t frame_addrs[3] = {0};
	vemaa_t frame_vir_addr = 0;
	vemva_t trampoline_vaddr = 0;
	struct ve1_sigframe ve_sigframe;
	ve_dma_hdl *dma_handle;
	ve_dma_status_t status;
	int on_altstack = 0;
	int pg_mode = -1;

	struct ve_node_struct *vnode_info;

	VEOS_TRACE("Entering");

	memset(&ve_sigframe, '\0', sizeof(struct ve1_sigframe));

	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK
		, "failed to acquire task lock");

	ret = ve1_psm_getframe(p_ve_task, signum, &frame_vir_addr,
			frame_addrs, &offset, &on_altstack, &pg_mode);
	if (-1 == ret) {
		VEOS_DEBUG("[%d] Failed to fetch physical translation",
				p_ve_task->pid);
		pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK
				, "failed to release task lock");
		return -EFAULT;
	}

	VEOS_DEBUG("Frame Virtual address : %p",
			(void *)(frame_vir_addr));

	VEOS_DEBUG("Frame Physical address[0] : %lx", frame_addrs[0]);
	VEOS_DEBUG("Frame Physical address[1] : %lx", frame_addrs[1]);

	memcpy(&ve_sigframe.ve_siginfo, ve_siginfo, sizeof(siginfo_t));

	ve_sigframe.flag = flag;
	ve_sigframe.signum = signum;
	/* Copy the current hardware context on the sigframe
	 * */
	memcpy(&(ve_sigframe.uc.uc_mcontext),
			p_ve_task->p_ve_thread->arch_user_regs,
			sizeof(ve1_core_user_reg_t));

	if (p_ve_task->mask_saved == true) {
		VEOS_DEBUG("Saving the \"saved_sigmask\"");
		ve_sigframe.uc.uc_sigmask = p_ve_task->ve_saved_sigmask;
	} else {
		VEOS_DEBUG("Saving the current signal mask");
		ve_sigframe.uc.uc_sigmask = p_ve_task->blocked;
	}
	ve_sigframe.uc.uc_flags = 0;
	ve_sigframe.uc.uc_link = 0;
	ve_sigframe.uc.uc_stack.ss_sp = (void *)(p_ve_task->sas_ss_sp);
	ve_sigframe.uc.uc_stack.ss_size = p_ve_task->sas_ss_size;
	ve_sigframe.uc.uc_stack.ss_flags =
			on_sig_stack(p_ve_task)
			? SS_ONSTACK : 0;

	/* Copy current lshm context */
	memcpy(ve_sigframe.lshm_area,
			(void *)(p_ve_task->sighand->lshm_addr
				+ p_ve_task->offset), LSHM_SZ);

	vnode_info = VE_NODE(p_ve_task->node_id);
	dma_handle = vnode_info->dh;

	for (i = 0; frame_addrs[i]; i++) {
		if (i == 0) {
			local_offset = 0;
			dma_size = offset ? offset : (uint64_t)sizeof(struct ve1_sigframe);
		} else {
			local_offset = offset;
			dma_size = (uint64_t)sizeof(struct ve1_sigframe) - offset;
		}

		VEOS_DEBUG("DMA[%d] SRC: %lx DEST: %lx length: %lx", i,
			((uint64_t)&ve_sigframe) + local_offset,
			(uint64_t)frame_addrs[i],
			dma_size);
		/* Write the signal frame to VE process physical memory */
		status = ve_dma_xfer_p_va(dma_handle, VE_DMA_VHVA, getpid()
				, ((uint64_t)&ve_sigframe) + local_offset, VE_DMA_VEMAA
				, p_ve_task->pid, (uint64_t)frame_addrs[i]
				, dma_size);
		if (status != 0) {
			VEOS_ERROR("%d unable to write signal frame1 %d",
							p_ve_task->pid, status);
			pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock),
					UNLOCK,
					"failed to release task lock");
			return -EFAULT;
		} else {
			double size_kb = dma_size / (double)1024.0;
			update_accounting_data(p_ve_task, ACCT_TRANSDATA,
				size_kb);
			
		}
	}
	ve1_core_user_reg_t *user_regs
		= p_ve_task->p_ve_thread->arch_user_regs;
	VEOS_DEBUG("Sigreturn Context PID : %d IC: %lx"
			" LR : %lx SP : %lx SR12 : %lx"
			" SR0: %lx",
		p_ve_task->pid, user_regs->IC, user_regs->SR[10],
		user_regs->SR[11], user_regs->SR[12], user_regs->SR[0]);

	/* SET THE SIGNAL HANDLER CONTEXT */

	/* set the instruction counter of VE process with
	 * signal handler routine address
	 */
	user_regs->IC = (ve_reg_t)p_ve_task->sighand->
					action[signum - 1].sa_handler;

	/* update the value of outer register used to point the start
	 * address of calling function with the address of signal
	 * handler routine.
	 * */
	user_regs->SR[12] = user_regs->IC;

	/* set the value signal handler routine argument in SR[0],
	 * SR[1] and SR[2]
	 * */
	user_regs->SR[0] = (ve_reg_t)signum;

	user_regs->SR[1] = frame_vir_addr +
		offsetof(struct ve1_sigframe, ve_siginfo);
	user_regs->SR[2] = frame_vir_addr + offsetof(struct ve1_sigframe, uc);

	/* Signal trampoline code is stored at fixed address(#1410),
	 * which is mapped during VE process loading.*/
	trampoline_vaddr = (vemva_t)((pg_mode == PG_2M) ?
					TRAMP_2MB : TRAMP_64MB);

	VEOS_DEBUG("Signal Trampoline save at VIRT 0x%lx", trampoline_vaddr);

	/* set the link register with the return address of signal handler
	 * routine, we have set link register with the address of trampoline
	 * instruction so that when signal handler routine return it will
	 * excute sigreturn instruction written as trampoline.
	 */
	user_regs->SR[10] = (uint64_t)trampoline_vaddr;

	/* update the value of stack pointer SR[11] for executing the signal
	 * handler routine
	 * */
	user_regs->SR[11] = frame_vir_addr - HANDLER_STACK_FRAME;

	/* update the value of SR[8], if handled needs to execute on alternats
	 * stack
	 */
	if (on_altstack) {
		user_regs->SR[8] = p_ve_task->sas_ss_sp;
		VEOS_DEBUG("SR[8]: %lx", user_regs->SR[8]);
	}

	VEOS_DEBUG("signal handler stack address : %lx",
			user_regs->SR[11]);

	pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK
			, "failed to release task lock");

	VEOS_TRACE("Exiting");
	return ret;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_setup_ve_frame, ve1_psm_setup_ve_frame)

ve_reg_t ve1_psm_get_SR0_on_thread_struct(const void *u)
{
	const ve1_core_user_reg_t *user_regs = u;
	return user_regs->SR[0];
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_retval_on_thread_struct, ve1_psm_get_SR0_on_thread_struct)

void ve1_psm_set_SR0_on_thread_struct(void *u, ve_reg_t val)
{
	ve1_core_user_reg_t *user_regs = u;
	user_regs->SR[0] = val;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_retval_on_thread_struct, ve1_psm_set_SR0_on_thread_struct)

void ve1_psm_rewind_IC_on_thread_struct(void *u)
{
	ve1_core_user_reg_t *user_regs = u;
	user_regs->IC -= 8;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_program_counter_to_restart, ve1_psm_rewind_IC_on_thread_struct)
