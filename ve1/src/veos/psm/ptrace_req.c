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

#include <sys/types.h>
#include "ptrace_req.h"
#include "ptrace_req_ve1.h"
#define _VE_ARCH_VE1_ 1
#include <ve_hw.h>
#include <libved.h>
#include <veos_arch_defs.h>
#include <locking_handler.h>
#include <ve_mem.h>

/**
 * @brief Get the offset of VE register.
 *
 * @param[in] reg VE user register
 *
 * @return offset on success, -1 on failure.
 */
off_t ve1_psm_get_reg_offset(ve_usr_reg_name_t reg)
{
	switch ((ve_usr_reg_name_t)reg) {
	case VE_USR_USRCC:
		VEOS_DEBUG("offset of USRCC");
		return (offsetof(ve1_core_user_reg_t, USRCC));
	case VE_USR_PSW:
		VEOS_DEBUG("offset of PSW");
		return (offsetof(ve1_core_user_reg_t, PSW));
	case VE_USR_EXS:
		VEOS_DEBUG("offset of EXS");
		return (offsetof(ve1_core_user_reg_t, EXS));
	case VE_USR_IC:
		VEOS_DEBUG("offset of IC");
		return (offsetof(ve1_core_user_reg_t, IC));
	case VE_USR_ICE:
		VEOS_DEBUG("offset of ICE");
		return (offsetof(ve1_core_user_reg_t, ICE));
	case VE_USR_VIXR:
		VEOS_DEBUG("offset of VIXR");
		return (offsetof(ve1_core_user_reg_t, VIXR));
	case VE_USR_VL:
		VEOS_DEBUG("offset of VL");
		return (offsetof(ve1_core_user_reg_t, VL));
	case VE_USR_SAR:
		VEOS_DEBUG("offset of SAR");
		return (offsetof(ve1_core_user_reg_t, SAR));
	case VE_USR_PMMR:
		VEOS_DEBUG("offset of PMMR");
		return (offsetof(ve1_core_user_reg_t, PMMR));
	default:
		if ((reg >= VE_USR_PMC00) && (reg <= VE_USR_PMC15)) {
			VEOS_DEBUG("offset of PMC[%02d]", reg - VE_USR_PMC00);
			return (offsetof(ve1_core_user_reg_t, PMC[reg - VE_USR_PMC00]));
		}
		if ((reg >= VE_USR_PMCR00) && (reg <= VE_USR_PMCR03)) {
			VEOS_DEBUG("offset of PMCR[%02d]", reg - VE_USR_PMCR00);
			return (offsetof(ve1_core_user_reg_t, PMCR[reg - VE_USR_PMCR00]));
		}
		if ((reg >= VE_USR_SR00) && (reg <= VE_USR_SR63)) {
			VEOS_DEBUG("offset of SR[%02d]", reg - VE_USR_SR00);
			return (offsetof(ve1_core_user_reg_t, SR[reg - VE_USR_SR00]));
		}

		VEOS_DEBUG("usr_reg: no such a register(%d).", reg);
	}
	return -1;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_reg_offset, ve1_psm_get_reg_offset)

int ve1_getreg_from_core(int regid, int core_id, void *data)
{
	int retval = 0;
	retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id),
			regid, (ve_reg_t *)data);
	return retval;

}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_getreg_from_core, ve1_getreg_from_core)

int ve1_check_reg_consistency(struct ve_task_struct *p_ve_task)
{
       /*PVL32 does not supported in ve1*/
       return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_check_reg_consistency, ve1_check_reg_consistency)

int ve1_psm_ptrace_getvregs(struct ve_task_struct *p_ve_task, pid_t pid, uint64_t data)
{
       int retval = -1;
        struct ve1_user_vregs ve_u_vreg;

        VEOS_TRACE("Entering");

        if (!p_ve_task)
                goto hndl_return;

        memset(&ve_u_vreg, 0, sizeof(struct ve1_user_vregs));

        /* Get the VE vector register set maintained in the VE task struct */
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
                        "Failed to acquire task lock");
        memcpy(&ve_u_vreg, (void *)(p_ve_task->p_ve_thread->arch_user_regs) +
                        sizeof(struct ve1_user_regs),
                        sizeof(struct ve1_user_vregs));
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
                        "Failed to release task lock");

        /* Write the content to tracer's memory at a given address
         * 'data' using DMA API's.
         */
        retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&ve_u_vreg, pid,
                        VE_DMA_VHVA, data, p_ve_task->p_ve_ptrace->tracer_pid,
                        sizeof(struct ve1_user_vregs), p_ve_task->node_id);
        if (-1 == retval) {
                VEOS_DEBUG("DMA failed during ptrace GETVREGS");
                goto hndl_return;
        } else {
                update_accounting_data(p_ve_task, ACCT_TRANSDATA,
                                sizeof(struct ve1_user_vregs) / (double)1024);
        }

        retval = 0;
hndl_return:
        VEOS_TRACE("Exiting");
        return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_ptrace_getvregs, ve1_psm_ptrace_getvregs)

int ve1_psm_ptrace_setvregs(struct ve_task_struct *p_ve_task, pid_t pid, uint64_t data)
{
       struct ve1_user_vregs ve_u_vreg;
       int retval = -1;

        VEOS_TRACE("Entering");

        if (!p_ve_task)
                goto hndl_return;

        memset(&ve_u_vreg, 0, sizeof(struct ve1_user_vregs));

        /* Get the content from tracer's memory at a given address
         * 'data' using DMA API's.
         */
        retval = amm_dma_xfer(VE_DMA_VHVA, data,
                        p_ve_task->p_ve_ptrace->tracer_pid,
                        VE_DMA_VHVA, (uint64_t)&ve_u_vreg, pid,
                        sizeof(struct ve1_user_vregs), p_ve_task->node_id);
        if (-1 == retval) {
                VEOS_DEBUG("DMA failed during ptrace SETVREGS");
                goto hndl_return;
        } else {
                update_accounting_data(p_ve_task, ACCT_TRANSDATA,
                                sizeof(struct ve1_user_vregs) / (double)1024);
        }

        /* Update the VE vector register set maintained the VE task struct */
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
                        "Failed to acquire task lock");
        memcpy((p_ve_task->p_ve_thread->arch_user_regs) + sizeof(struct ve1_user_regs),
                        &ve_u_vreg, sizeof(struct ve1_user_vregs));
        p_ve_task->usr_reg_dirty = true;
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
                        "Failed to release task lock");

        retval = 0;
hndl_return:
       VEOS_TRACE("Exiting");
        return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_ptrace_setvregs, ve1_psm_ptrace_setvregs)

int ve1_psm_ptrace_getregs(struct ve_task_struct *p_ve_task, pid_t pid, uint64_t data)
{
	int retval = -1;
	struct ve1_user_regs ve_u_reg;

        VEOS_TRACE("Entering");

        if (!p_ve_task)
                goto hndl_return;

        memset(&ve_u_reg, 0, sizeof(struct ve1_user_regs));

        /* Get the VE user register set maintained the VE task struct */
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
                        "Failed to acquire task lock");
        memcpy(&ve_u_reg, (p_ve_task->p_ve_thread->arch_user_regs), sizeof(struct ve1_user_regs));
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
                        "Failed to release task lock");

        /* Write the content to tracer's memory at a given address
        * 'data' using DMA API's.
        */
        retval = amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&ve_u_reg, pid,
                        VE_DMA_VHVA, data, p_ve_task->p_ve_ptrace->tracer_pid,
                        sizeof(struct ve1_user_regs), p_ve_task->node_id);
        if (-1 == retval) {
                VEOS_DEBUG("DMA failed during ptrace GETREGS");
                goto hndl_return;
        } else {
                update_accounting_data(p_ve_task, ACCT_TRANSDATA,
                                sizeof(struct ve1_user_regs) / (double)1024);
        }


        retval = 0;
hndl_return:

	VEOS_TRACE("Exiting");
        return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_ptrace_getregs, ve1_psm_ptrace_getregs)

int ve1_psm_ptrace_setregs(struct ve_task_struct *p_ve_task, pid_t pid, uint64_t data)
{
       int retval = -1;

        struct ve1_user_regs ve_u_reg;

        VEOS_TRACE("Entering");

        if (!p_ve_task)
                goto hndl_return;

        memset(&ve_u_reg, 0, sizeof(struct ve1_user_regs));

        /* Get the content from tracer's memory at a given address
       * 'data' using DMA API's.
        */
        retval = amm_dma_xfer(VE_DMA_VHVA, data,
                        p_ve_task->p_ve_ptrace->tracer_pid,
                        VE_DMA_VHVA, (uint64_t)&ve_u_reg, pid,
                        sizeof(struct ve1_user_regs), p_ve_task->node_id);
        if (-1 == retval) {
                VEOS_DEBUG("DMA failed during ptrace SETREGS");
                goto hndl_return;
        } else {
                update_accounting_data(p_ve_task, ACCT_TRANSDATA,
                                sizeof(struct ve1_user_regs) / (double)1024);
        }


        /* Update the VE user register set maintained the VE task struct */
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), LOCK,
                        "Failed to acquire task lock");
        memcpy((p_ve_task->p_ve_thread->arch_user_regs), &ve_u_reg, sizeof(struct ve1_user_regs));
        p_ve_task->usr_reg_dirty = true;
        pthread_mutex_lock_unlock(&(p_ve_task->ve_task_lock), UNLOCK,
                        "Failed to release task lock");

        retval = 0;
hndl_return:
	VEOS_TRACE("Exiting");
        return retval;

}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_ptrace_setregs, ve1_psm_ptrace_setregs)
