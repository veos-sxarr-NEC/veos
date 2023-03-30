/**
* Copyright (C) 2020 NEC Corporation
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
 * @file  task_mgmt.c
 * @brief VE3-dependent part of VE task management activities
 *
 */
#include <ve_hw.h>
#include <libved.h>

#include <veos_arch_defs.h>
#include <veos.h>
#include <task_mgmt.h>
#include <locking_handler.h>
#include <mm_common.h>
#include <task_sched.h>
#include "task_mgmt_ve3.h"
#include "veos_ve3.h"

void ve3_turn_on_clock_gating(void);

void ve3_psm_save_scalar_registers(ve_reg_t *buffer, const void *u,
					uint64_t bitmap)
{
	const ve3_core_user_reg_pre_t *user_regs = u;
	for (int i = 0; i < VE3_SR_NUM; ++i) {
		if (GET_BIT(bitmap, i))
			buffer[i] = user_regs->SR[i];
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_save_scalar_registers, ve3_psm_save_scalar_registers)

void ve3_psm_restore_scalar_registers(void *u, const ve_reg_t *buffer,
					uint64_t bitmap)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	for (int i = 0; i < VE3_SR_NUM; ++i) {
		if (GET_BIT(bitmap, i)) {
			user_regs->SR[i] = buffer[i];
			VEOS_DEBUG("Storing SR[%d]: 0x%lx in tmp",
				i, buffer[i]);
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_restore_scalar_registers, ve3_psm_restore_scalar_registers)

void ve3_psm_save_pmc_registers(ve_reg_t *buffer, const void *u,
				uint64_t bitmap)
{
	const ve3_core_user_reg_pre_t *user_regs = u;
	for (int i = PMR_CONTEXT_PSW; i < PMR_CONTEXT_LOOP_VE3; ++i) {
		if (GET_BIT(bitmap, i)) {
			if (i == PMR_CONTEXT_PSW) {
				buffer[i] = user_regs->PSW;
				VEOS_DEBUG("Storing PSW: 0x%lx in tmp",
                                                        buffer[i]);
			}
			if (i == PMR_CONTEXT_PMRR) {
				buffer[i] = user_regs->PMMR;
				VEOS_DEBUG("Storing PMMR: 0x%lx in tmp",
							buffer[i]);
			}
			if ((i >= PMR_CONTEXT_PMCR0) &&
				(i <= PMR_CONTEXT_PMCR3)) {
				buffer[i] = user_regs->PMCR[i - PMR_CONTEXT_PMCR0];
				VEOS_DEBUG("Storing PMCR[%d]: 0x%lx in tmp",
					i - PMR_CONTEXT_PMCR0, buffer[i]);
			}
			if (i >= PMR_CONTEXT_PMCR4) {
				buffer[i] = user_regs->PMC[i - PMR_CONTEXT_PMCR4];
				VEOS_DEBUG("Storing PMC[%d]: 0x%lx in tmp",
					i - PMR_CONTEXT_PMCR4, buffer[i]);
			}
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_save_mode_registers, ve3_psm_save_pmc_registers)

void ve3_psm_restore_pmc_registers(void *u, const ve_reg_t *buffer,
					uint64_t bitmap)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	for (int i = PMR_CONTEXT_PSW; i < PMR_CONTEXT_LOOP_VE3; ++i) {
		if (GET_BIT(bitmap, i)) {
			if (i == PMR_CONTEXT_PSW) {
				user_regs->PSW = buffer[i];
				VEOS_DEBUG("Storing PSW: 0x%lx in tmp",
                                                        buffer[i]);
			}
			if (i == PMR_CONTEXT_PMRR) {
				user_regs->PMMR = buffer[i];
				VEOS_DEBUG("Storing PMMR: 0x%lx in tmp",
							buffer[i]);
			}
			if ((i >= PMR_CONTEXT_PMCR0) &&
				(i <= PMR_CONTEXT_PMCR3)) {
				user_regs->PMCR[i - PMR_CONTEXT_PMCR0] = buffer[i];
				VEOS_DEBUG("Storing PMCR[%d]: 0x%lx in tmp",
					i - PMR_CONTEXT_PMCR0, buffer[i]);
			}
			if (i >= PMR_CONTEXT_PMCR4) {
				user_regs->PMC[i - PMR_CONTEXT_PMCR4] = buffer[i];
				VEOS_DEBUG("Storing PMC[%d]: 0x%lx in tmp",
					i - PMR_CONTEXT_PMCR4, buffer[i]);
			}
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_restore_mode_registers, ve3_psm_restore_pmc_registers)

ve_reg_t ve3_get_PSW_from_thread(const void *u)
{
	const ve3_core_user_reg_pre_t *user_regs = u;
	return user_regs->PSW;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_PSW_from_thread_struct, ve3_get_PSW_from_thread)

void ve3_set_PSW_on_thread(void *u, ve_reg_t val)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	user_regs->PSW = val;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_PSW_on_thread_struct, ve3_set_PSW_on_thread)

static int ve3_get_usr_reg(int core_id, ve_usr_reg_name_t reg, ve_reg_t *valp)
{
	int retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id), reg, valp);
	if (retval != 0) {
		VEOS_ERROR("Failed to get user register");
		VEOS_DEBUG("Failed to get register %d, returned %d",
			reg, retval);
	}
	return retval;
}
#define VE3_UPDATE_VAL_ON_USER_REGS(u_, member_, val_, mask_) \
do { \
	ve3_core_user_reg_pre_t *user_regs_ = (u_); \
	uint64_t m_ = (mask_); \
	ve_reg_t oldval_ = user_regs->member_; \
	ve_reg_t newval_ = (oldval_ & (~m_)) | ((val_) & m_); \
	user_regs_->member_ = newval_; \
} while (0)

int ve3_psm_set_reg_on_thread_struct(void *u, int core_id, int sync,
		ve_usr_reg_name_t regid, ve_reg_t regval, uint64_t mask,
		uint64_t *pmr_bitmap, uint64_t *sr_bitmap)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	int retval;
	if (regid == VE_USR_PSW) {
		if (sync && !GET_BIT(*pmr_bitmap, 0)) {
			VEOS_DEBUG("Getting PSW from Core %d", core_id);
			retval = ve3_get_usr_reg(core_id, VE_USR_PSW,
					&(user_regs->PSW));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE3_UPDATE_VAL_ON_USER_REGS(user_regs, PSW, regval, mask);
		SET_BIT(*pmr_bitmap, 0);
		return 0;
	}
	if (regid == VE_USR_PMMR) {
		VEOS_DEBUG("Getting VL from Core %d", core_id);
		retval = ve3_get_usr_reg(core_id, VE_USR_VL,
					&(user_regs->VL));
		if (retval) {
			VEOS_DEBUG("returned %d, mapped to -EFAULT",
				retval);
			return -EFAULT;
		}
		VEOS_DEBUG("Getting PVL32 from Core %d", core_id);
		retval = ve3_get_usr_reg(core_id, VE_USR_PVL32,
					&(user_regs->PVL32));
		if (retval) {
			VEOS_DEBUG("returned %d, mapped to -EFAULT",
				retval);
			return -EFAULT;
		}

		if (sync && !GET_BIT(*pmr_bitmap, 1)) {
			VEOS_DEBUG("Getting PMMR from Core %d", core_id);
			retval = ve3_get_usr_reg(core_id, VE_USR_PMMR,
					&(user_regs->PMMR));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		regval = (regval & ~0xf000) | 0x1000;
		VE3_UPDATE_VAL_ON_USER_REGS(user_regs, PMMR, regval, mask);
		SET_BIT(*pmr_bitmap, 1);
		return 0;
	}
	if ((regid >= VE_USR_SR00) && (regid <= VE_USR_SR63)) {
		/* In scaler register mask will be always USER_REG_MASK,
		 * so we dont need the latest register value from core.
		 */
		int sr_id = regid - VE_USR_SR00;
		VE3_UPDATE_VAL_ON_USER_REGS(user_regs, SR[sr_id], regval, mask);
		SET_BIT(*sr_bitmap, sr_id);
		return 0;
	}
	if ((regid >= VE_USR_PMCR00) && (regid <= VE_USR_PMCR03)) {
		int pmcr_id = regid - VE_USR_PMCR00;
		if (sync && !GET_BIT(*pmr_bitmap, (pmcr_id + 2))) {
			VEOS_DEBUG("Getting PMCR%d from Core %d", pmcr_id,
					core_id);
			retval = ve3_get_usr_reg(core_id, regid,
					&(user_regs->PMCR[pmcr_id]));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE3_UPDATE_VAL_ON_USER_REGS(user_regs, PMCR[pmcr_id],
						regval, mask);
		SET_BIT(*pmr_bitmap, (pmcr_id + 2));
		return 0;
	}
	if (((regid >= VE_USR_PMC00) && (regid <= VE_USR_PMC15)) ||
	    ((regid >= VE_USR_PMC16) && (regid <= VE_USR_PMC20))) {
		int pmc_id;
		if (regid >= VE_USR_PMC16) {
			pmc_id = regid - VE_USR_PMC16 + 16;
		} else {
			pmc_id = regid - VE_USR_PMC00;
		}
		if (sync && !GET_BIT(*pmr_bitmap, (pmc_id + 6))) {
			VEOS_DEBUG("Getting PMC%d from Core %d", pmc_id,
					core_id);
			retval = ve3_get_usr_reg(core_id, regid,
					&(user_regs->PMC[pmc_id]));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE3_UPDATE_VAL_ON_USER_REGS(user_regs, PMC[pmc_id],
						regval, mask);
		SET_BIT(*pmr_bitmap, (pmc_id + 6));
		return 0;
	}

	VEOS_ERROR("Failed to handle pseudo process request: "
			"unmatched register");
	return -1;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_reg_on_thread_struct, ve3_psm_set_reg_on_thread_struct)

void ve3_psm_clear_EXS_to_NOML(struct ve_thread_struct *p_ve_thread)
{
	p_ve_thread->EXS = EXS_NOML;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_clear_execution_status_on_thread_struct, ve3_psm_clear_EXS_to_NOML)

ve_reg_t ve3_get_IC_from_thread(const void *u)
{
	return ((const ve3_core_user_reg_pre_t *)u)->IC;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_program_counter_from_thread_struct, ve3_get_IC_from_thread)

int ve3_psm_check_valid_userreg(int regid, bool *should_stop_core)
{
	if (regid < VE_USR_USRCC || regid > VE_USR_PMC20) {
		return -1;
	}
	/* Check if Register ID array contains any register for
	 * which core is needed to be stopped if task
	 * is current task on core */
	if (!((VE_USR_USRCC <= regid && regid <= VE_USR_PMC15)
		|| (VE_USR_PMC16 <= regid && regid <= VE_USR_PMC20)
		|| (regid == VE_USR_EXS)
		|| (VE_USR_SAR <= regid && regid <= VE_USR_PMCR03)))
			*should_stop_core = true;
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_check_valid_userreg, ve3_psm_check_valid_userreg )

void ve3_psm_init_perf_accounting(struct ve_task_struct *tsk, ve_reg_t pmmr, uint64_t *pmc, ve_usr_reg_name_t reg_id)
{
	ve_reg_t pmmr_mode = 0x00, pmmr_mode_val = 0x00;

	if (VE_USR_PMC00 <= reg_id && reg_id <= VE_USR_PMC15) {
		tsk->pmc_pmmr[reg_id - VE_USR_PMC00] = -1;
		return;
	} else if (VE_USR_PMC16 <= reg_id && reg_id <= VE_USR_PMC20) {
		tsk->pmc_pmmr[reg_id - VE_USR_PMC16 + 16] = -1;
		return;
	} else if (reg_id != VE_USR_PMMR)
		return;

	if (((struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info))->ac_version == 0 || tsk->execed_proc) {
		((struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info))->ac_version = VE3_ACCT_VERSION | ACCT_BYTEORDER;
		/* Reset pmc_pmmr[i] to zero because the mode is updated at
		 * the first time */
		for(int i = 0; i < PMC_REG_VE3; i++)
			tsk->pmc_pmmr[i] = 0;
	} else {
		/* Invalidate pmc_pmmr[i] because the mode is updated twice or
		 * more */
		for(int i = 0; i < PMC_REG_VE3; i++)
			tsk->pmc_pmmr[i] = -1;
		return;
	}
	for(int i = 0; i < PMC_REG_VE3; i++) {
		int regid = 0;
		if (i <= 15) {
			regid = VE_USR_PMC00 + i;
			pmmr = (pmmr & ~0xf000) | 0x1000;
			pmmr_mode_val =  (pmmr & (PMMR_SHIFT >> 4*i));
			pmmr_mode = (pmmr_mode_val >> 4 * ((PMC_REG_VE3 - 5) - i - 1));
		} else {
			regid = VE_USR_PMC16 + i - 16;
			pmmr_mode_val = 0;
			pmmr_mode = 0;
		}

		switch (regid) {
		case VE_USR_PMC00:
		case VE_USR_PMC01:
		case VE_USR_PMC02:
		case VE_USR_PMC14:
		case VE_USR_PMC15:
			if (pmmr_mode == 0){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC04:
		case VE_USR_PMC11:
		case VE_USR_PMC13:
		case VE_USR_PMC03:
			if (pmmr_mode == 0 || pmmr_mode == 2){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC05:
			if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2 || pmmr_mode == 8){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC06:
			if (pmmr_mode == 0 || pmmr_mode == 2 || pmmr_mode == 8){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC07:
		case VE_USR_PMC08:
			if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC09:
		case VE_USR_PMC10:
			if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2 || pmmr_mode == 3){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC12:
			if (pmmr_mode == 1) {
				ve3_core_user_reg_pre_t *user_regs = tsk->p_ve_thread->arch_user_regs;
				user_regs->PMC[12] = 0;
				SET_BIT((tsk->pmr_context_bitmap), ((VE_USR_PMC12 - VE_USR_PMC00) + 6));
				tsk->initial_pmc_pmmr[i] = 0;
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC16:
		case VE_USR_PMC17:
		case VE_USR_PMC18:
		case VE_USR_PMC19:
		case VE_USR_PMC20:
			tsk->initial_pmc_pmmr[i] = pmc[i];
			break;
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_init_perf_accounting, ve3_psm_init_perf_accounting)

int ve3_psm_fetch_performance_registers(struct ve_task_struct *tsk, int **regids, uint64_t **pmc)
{
	int retval = -1;
	int tmp_regids[PMC_REG_VE3] = {0};
	uint64_t tmp_pmc[PMC_REG_VE3] = {0};

	retval = get_ve_task_struct(tsk);
	if (0 > retval) {
		VEOS_ERROR("failed to get task reference");
		retval = -ESRCH;
		goto handle_return;
	}

	for (int i = 0; i < 16; i++)
		tmp_regids[i] = VE_USR_PMC00 + i;
	for (int i = 16; i < PMC_REG_VE3; i++)
		tmp_regids[i] = VE_USR_PMC16 + i - 16;
	retval = psm_get_regval(tsk, PMC_REG_VE3, tmp_regids, tmp_pmc);
	if (retval < 0) {
		VEOS_ERROR("failed to get task's register");
		goto handle_return;
	}

	*regids = (int *)calloc(PMC_REG_VE3, sizeof(int));
	if (*regids == NULL) {
		retval = -ENOMEM;
		goto handle_return;
	}

	*pmc = (uint64_t *)calloc(PMC_REG_VE3, sizeof(uint64_t));
	if (*pmc == NULL) {
		retval = -ENOMEM;
		goto free_regids;
	}

	memcpy(*regids, &tmp_regids, PMC_REG_VE3*sizeof(int));
	memcpy(*pmc, &tmp_pmc, PMC_REG_VE3*sizeof(uint64_t));
	retval = 0;
	goto handle_return;
free_regids:
	free (*regids);
	*regids = NULL;
handle_return:
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_fetch_performance_registers, ve3_psm_fetch_performance_registers)

ve_reg_t ve3_psm_get_PMMR_on_thread_struct(struct ve_task_struct *task)
{
        ve3_core_user_reg_pre_t *user_regs = task->p_ve_thread->arch_user_regs;
        return user_regs->PMMR;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_PMMR_on_thread_struct, ve3_psm_get_PMMR_on_thread_struct);

void ve3_psm_get_performance_register_info(struct ve_task_struct *tsk,
		uint64_t clock_val_mhz, struct proginf_v1 *proginf)
{
	ve_reg_t pmmr = 0x00, pmmr_mode = 0x00, pmmr_mode_val = 0x00;
	ve_reg_t group_leader_pmmr = 0x00, group_leader_pmmr_mode = 0x00, group_leader_pmmr_mode_val = 0x00;
	struct ve_acct_v16 *acct_info = NULL;
	struct ve_proginf_v1 *proginf_ex_fld= NULL;

	acct_info = (struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info);
	proginf_ex_fld = &(tsk->sighand->pacct.ve_proginf);

	pmmr = ve3_psm_get_PMMR_on_thread_struct(tsk);
	group_leader_pmmr = ve3_psm_get_PMMR_on_thread_struct(tsk->group_leader);

	for(int i = 0; i < PMC_REG_VE3; i++) {
		int regid;
		if (i <= 15) {
			regid = VE_USR_PMC00 + i;
			pmmr_mode_val = pmmr & (PMMR_SHIFT >> 4 * i);
			pmmr_mode = (pmmr_mode_val >> 4 * ((PMC_REG_VE3 - 5) - i - 1));
			group_leader_pmmr_mode_val = group_leader_pmmr & (PMMR_SHIFT >> 4 * i);
			group_leader_pmmr_mode = (group_leader_pmmr_mode_val >> 4 * ((PMC_REG_VE3 - 5) - i - 1));
		} else {
			regid = VE_USR_PMC16 + i - 16;
			pmmr_mode = 0;
		}
		/*each case corresponding to PMCXX */
		switch (regid) {
			case VE_USR_PMC00:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode)
						proginf->ac_ex = -1;
					else if (pmmr_mode == 0)
						proginf->ac_ex += tsk->pmc_pmmr[i];
					else
						proginf->ac_ex = -1;
					break;
				}
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_ex += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ex = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC01:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode)
						proginf->ac_vx = -1;
					else if (pmmr_mode == 0)
						proginf->ac_vx += tsk->pmc_pmmr[i];
					else
						proginf->ac_vx = -1;
					break;
				}
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_vx += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vx = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC02:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode)
                                                proginf->ac_fpec = -1;
                                        else if (pmmr_mode == 0)
						proginf->ac_fpec += tsk->pmc_pmmr[i];
					else
						proginf->ac_fpec = -1;
					break;
				}
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_fpec += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_fpec = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC03:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_ve = -1;
						proginf->ac_l1imc = -1;
					} else if (pmmr_mode == 0){
						proginf->ac_ve += tsk->pmc_pmmr[i];
						proginf->ac_l1imc = -1;
					} else if(pmmr_mode == 2){
						proginf->ac_l1imc += tsk->pmc_pmmr[i];
						proginf->ac_ve = -1;
					} else {
						proginf->ac_ve = -1;
						proginf->ac_l1imc = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ve = tsk->pmc_pmmr[i];
					acct_info->ac_l1imc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					acct_info->ac_ve += tsk->pmc_pmmr[i];
					acct_info->ac_l1imc = -1;
				} else if (pmmr_mode == 2) {
					acct_info->ac_l1imc += tsk->pmc_pmmr[i];
					acct_info->ac_ve = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ve = tsk->pmc_pmmr[i];
					acct_info->ac_l1imc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC04:
				if (proginf){
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_vecc = -1;
						proginf->ac_l1iac = -1;
					} else if (pmmr_mode == 0) {
						proginf->ac_vecc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l1iac = -1;
					} else if(pmmr_mode == 2){
						proginf->ac_l1iac += tsk->pmc_pmmr[i];
						proginf->ac_vecc = -1;
					} else {
						proginf->ac_vecc = -1;
						proginf->ac_l1iac = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_vecc = -1;
						proginf_ex_fld->ac_l1iac = -1;
				} else if (pmmr_mode == 0) {
						/*conversion of clock count to microsecond*/
						acct_info->ac_vecc += (tsk->pmc_pmmr[i]/clock_val_mhz);
				} else {
					acct_info->ac_vecc = -1;
					if (pmmr_mode == 2)
						proginf_ex_fld->ac_l1iac += tsk->pmc_pmmr[i];
					else
						proginf_ex_fld->ac_l1iac = -1;
				}
				break;
			case VE_USR_PMC05:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_l1mcc = -1;
						proginf->ac_l2mcc = -1;
						proginf->ac_l1omc = -1;
						proginf->ac_uxc = -1;
                                        } else if (pmmr_mode == 0) {
						proginf->ac_l1mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l2mcc = -1;
						proginf->ac_l1omc = -1;
						proginf->ac_uxc = -1;
					} else if (pmmr_mode == 1) {
						proginf->ac_l1mcc = -1;
						proginf->ac_l2mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l1omc = -1;
						proginf->ac_uxc = -1;
					} else if (pmmr_mode == 2) {
						proginf->ac_l1mcc = -1;
						proginf->ac_l2mcc = -1;
						proginf->ac_l1omc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_uxc = -1;
					} else if (pmmr_mode == 8) {
						proginf->ac_l1mcc = -1;
						proginf->ac_l2mcc = -1;
						proginf->ac_l1omc = -1;
						proginf->ac_uxc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					} else{
						proginf->ac_l1mcc = -1;
						proginf->ac_l2mcc = -1;
						proginf->ac_l1omc = -1;
						proginf->ac_uxc = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_l1mcc = tsk->pmc_pmmr[i];
					acct_info->ac_l2mcc = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_l1omc = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_uxc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l2mcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l2mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1mcc = -1;
				} else {
					acct_info->ac_l1mcc = -1;
					acct_info->ac_l2mcc = -1;
					if (pmmr_mode == 2) {
						proginf_ex_fld->ac_l1omc += tsk->pmc_pmmr[i]/clock_val_mhz;
						proginf_ex_fld->ac_uxc = -1;
					} else if (pmmr_mode == 8) {
						proginf_ex_fld->ac_uxc += tsk->pmc_pmmr[i]/clock_val_mhz;
						proginf_ex_fld->ac_l1omc = -1;
					} else {
						proginf_ex_fld->ac_l1omc = -1;
						proginf_ex_fld->ac_uxc = -1;
					}
				}
				break;
			case VE_USR_PMC06:
				if (proginf){
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_ve2 = -1;
						proginf->ac_l1oac = -1;
						proginf->ac_uec = -1;
					} else if (pmmr_mode == 0) {
						proginf->ac_ve2 += tsk->pmc_pmmr[i];
						proginf->ac_l1oac = -1;
						proginf->ac_uec = -1;
					} else if (pmmr_mode == 2) {
						proginf->ac_ve2 = -1;
						proginf->ac_l1oac += tsk->pmc_pmmr[i];
						proginf->ac_uec = -1;
					} else if (pmmr_mode == 8) {
						proginf->ac_ve2 = -1;
						proginf->ac_l1oac = -1;
						proginf->ac_uec += tsk->pmc_pmmr[i];
					} else {
						proginf->ac_ve2 = -1;
						proginf->ac_l1oac = -1;
						proginf->ac_uec = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ve2 = -1;
					proginf_ex_fld->ac_uec = -1;
					proginf_ex_fld->ac_l1oac = -1;
				} else if (pmmr_mode == 0) {
					acct_info->ac_ve2 += tsk->pmc_pmmr[i];
				} else {
					acct_info->ac_ve2 = -1;
					if (pmmr_mode == 2) {
						proginf_ex_fld->ac_l1oac += tsk->pmc_pmmr[i];
						proginf_ex_fld->ac_uec = -1;
					} else if (pmmr_mode == 8) {
						proginf_ex_fld->ac_uec += tsk->pmc_pmmr[i];
						proginf_ex_fld->ac_l1oac = -1;
					} else {
						proginf_ex_fld->ac_uec = -1;
						proginf_ex_fld->ac_l1oac = -1;
					}
				}
				break;
			case VE_USR_PMC07:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_varec = -1;
						proginf->ac_l1imcc = -1;
						proginf->ac_l2mc = -1;
					} else if (pmmr_mode == 0) {
						proginf->ac_varec += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l1imcc = -1;
						proginf->ac_l2mc = -1;
					} else if (pmmr_mode == 1) {
						proginf->ac_varec = -1;
						proginf->ac_l1imcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l2mc = -1;
					} else if (pmmr_mode == 2) {
						proginf->ac_varec = -1;
						proginf->ac_l1imcc = -1;
						proginf->ac_l2mc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					} else{
						proginf->ac_varec = -1;
						proginf->ac_l1imcc = -1;
						proginf->ac_l2mc = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_varec = tsk->pmc_pmmr[i];
					acct_info->ac_l1imcc = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_l2mc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_varec += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1imcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1imcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_varec = -1;
				} else {
					acct_info->ac_varec = -1;
					acct_info->ac_l1imcc = -1;
					if (pmmr_mode == 2)
						proginf_ex_fld->ac_l2mc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					else
						proginf_ex_fld->ac_l2mc = -1;
				}
				break;
			case VE_USR_PMC08:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_vldec = -1;
						proginf->ac_l1omcc = -1;
						proginf->ac_l2ac = -1;
					} else if (pmmr_mode == 0) {
						proginf->ac_vldec += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l1omcc = -1;
						proginf->ac_l2ac = -1;
					} else if (pmmr_mode == 1) {
						proginf->ac_vldec = -1;
						proginf->ac_l1omcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_l2ac = -1;
					} else if (pmmr_mode == 2) {
						proginf->ac_vldec = -1;
						proginf->ac_l1omcc = -1;
						proginf->ac_l2ac += (tsk->pmc_pmmr[i]/clock_val_mhz);
					} else {
						proginf->ac_vldec = -1;
						proginf->ac_l1omcc = -1;
						proginf->ac_l2ac = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vldec = tsk->pmc_pmmr[i];
					acct_info->ac_l1omcc = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_l2ac = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_vldec += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1omcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1omcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_vldec = -1;
				} else {
					acct_info->ac_vldec = -1;
					acct_info->ac_l1omcc = -1;
					if (pmmr_mode == 2)
						proginf_ex_fld->ac_l2ac += (tsk->pmc_pmmr[i]/clock_val_mhz);
					else
						proginf_ex_fld->ac_l2ac = -1;
				}
				break;
			case VE_USR_PMC09:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_pccc = -1;
						proginf->ac_ltrc = -1;
						proginf->ac_brec = -1;
						proginf->ac_sarcc = -1;
					} else if (pmmr_mode == 0) {
						proginf->ac_pccc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf->ac_ltrc = -1;
						proginf->ac_brec = -1;
						proginf->ac_sarcc = -1;
					} else if (pmmr_mode == 1){
						proginf->ac_pccc = -1;
						proginf->ac_ltrc += tsk->pmc_pmmr[i];
						proginf->ac_brec = -1;
						proginf->ac_sarcc = -1;
					} else if (pmmr_mode == 2){
						proginf->ac_pccc = -1;
						proginf->ac_ltrc = -1;
						proginf->ac_brec += tsk->pmc_pmmr[i];
						proginf->ac_sarcc = -1;
					} else if (pmmr_mode == 3) {
						proginf->ac_pccc = -1;
						proginf->ac_ltrc = -1;
						proginf->ac_brec = -1;
						proginf->ac_sarcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					} else {
						proginf->ac_pccc = -1;
						proginf->ac_ltrc = -1;
						proginf->ac_brec = -1;
						proginf->ac_sarcc = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_pccc = tsk->pmc_pmmr[i];
					acct_info->ac_ltrc = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_brec = tsk->pmc_pmmr[i];
					proginf_ex_fld->ac_sarcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_pccc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_ltrc = -1;
				} else if (pmmr_mode == 1) {
					acct_info->ac_ltrc += tsk->pmc_pmmr[i];
					acct_info->ac_pccc = -1;
				} else {
					acct_info->ac_pccc = tsk->pmc_pmmr[i];
					acct_info->ac_ltrc = tsk->pmc_pmmr[i];
					if (pmmr_mode == 2) {
						proginf_ex_fld->ac_brec += tsk->pmc_pmmr[i];
						proginf_ex_fld->ac_sarcc = -1;
					} else if (pmmr_mode == 3) {
						proginf_ex_fld->ac_sarcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
						proginf_ex_fld->ac_brec = -1;
					} else {
						proginf_ex_fld->ac_brec = tsk->pmc_pmmr[i];
						proginf_ex_fld->ac_sarcc = tsk->pmc_pmmr[i];
					}
				}
				break;
			case VE_USR_PMC10:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_vlpc = -1;
						proginf->ac_strc = -1;
						proginf->ac_bpfc = -1;
						proginf->ac_iphcc = -1;
					} else if (pmmr_mode == 0){
						proginf->ac_vlpc += tsk->pmc_pmmr[i];
						proginf->ac_strc = -1;
						proginf->ac_bpfc = -1;
						proginf->ac_iphcc = -1;
					} else if (pmmr_mode == 1){
						proginf->ac_vlpc = -1;
						proginf->ac_strc += tsk->pmc_pmmr[i];
						proginf->ac_bpfc = -1;
						proginf->ac_iphcc = -1;
					} else if (pmmr_mode == 2){
						proginf->ac_vlpc = -1;
						proginf->ac_strc = -1;
						proginf->ac_bpfc += tsk->pmc_pmmr[i];
						proginf->ac_iphcc = -1;
					} else if (pmmr_mode == 3) {
						proginf->ac_vlpc = -1;
						proginf->ac_strc = -1;
						proginf->ac_bpfc = -1;
						proginf->ac_iphcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					} else {
						proginf->ac_vlpc = -1;
						proginf->ac_strc = -1;
						proginf->ac_bpfc = -1;
						proginf->ac_iphcc = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vlpc = tsk->pmc_pmmr[i];
					acct_info->ac_strc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					acct_info->ac_vlpc += tsk->pmc_pmmr[i];
					acct_info->ac_strc = -1;
				} else if (pmmr_mode == 1) {
					acct_info->ac_strc += tsk->pmc_pmmr[i];
					acct_info->ac_vlpc = -1;
				} else {
					acct_info->ac_vlpc = -1;
					acct_info->ac_strc = -1;
				}
				break;
			case VE_USR_PMC11:
				if (proginf){
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_vlec = -1;
						proginf->ac_vlxc = -1;
					} else if (pmmr_mode == 0){
						proginf->ac_vlec += tsk->pmc_pmmr[i];
						proginf->ac_vlxc = -1;
					} else if (pmmr_mode == 2){
						proginf->ac_vlxc += tsk->pmc_pmmr[i];
						proginf->ac_vlec = -1;
					} else {
						proginf->ac_vlxc = -1;
						proginf->ac_vlec = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vlec = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					acct_info->ac_vlec += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vlec = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC12:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_llvml = -1;
						proginf->ac_llvme = -1;
						proginf->ac_llvxc = -1;
						proginf->ac_llvxc2 = -1;
					} else if (pmmr_mode == 1){
						proginf->ac_llvml = -1;
						proginf->ac_llvme += tsk->pmc_pmmr[i];
						proginf->ac_llvxc = -1;
						proginf->ac_llvxc2 = -1;
					} else {
						proginf->ac_llvml = -1;
						proginf->ac_llvme = -1;
						proginf->ac_llvxc = -1;
						proginf->ac_llvxc2 = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_llvml = tsk->pmc_pmmr[i];
					acct_info->ac_llvme = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 1) {
					acct_info->ac_llvme += tsk->pmc_pmmr[i];
					acct_info->ac_llvml = -1;
				} else {
					acct_info->ac_llvml = -1;
					acct_info->ac_llvme = -1;
				}
				break;
			case VE_USR_PMC13:
				if (proginf){
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
						proginf->ac_fmaec = -1;
						proginf->ac_fmaxc = -1;
					} else if (pmmr_mode == 0){
						proginf->ac_fmaec += tsk->pmc_pmmr[i];
						proginf->ac_fmaxc = -1;
					} else if (pmmr_mode == 2){
						proginf->ac_fmaxc += tsk->pmc_pmmr[i];
						proginf->ac_fmaec = -1;
					} else {
						proginf->ac_fmaxc = -1;
						proginf->ac_fmaec = -1;
					}
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_fmaec = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1){
					acct_info->ac_fmaec += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_fmaec = -1;
				}
				break;
			case VE_USR_PMC14:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode)
						proginf->ac_ptcc = -1;
					else if (pmmr_mode == 0)
						proginf->ac_ptcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					else
						proginf->ac_ptcc = -1;
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ptcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_ptcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ptcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC15:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode)
						proginf->ac_ttcc = -1;
					else if (pmmr_mode == 0)
						proginf->ac_ttcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					else
						proginf->ac_ttcc = -1;
					break;
				}
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ttcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_ttcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ttcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC16:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1)
						proginf->ac_l3vsac = -1;
					else
						proginf->ac_l3vsac += tsk->pmc_pmmr[i];
				} else {
					if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1) {
						acct_info->ac_l3vsac += tsk->pmc_pmmr[i];
					} else {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_l3vsac = tsk->pmc_pmmr[i];
					}
				}
				break;
			case VE_USR_PMC17:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1)
						proginf->ac_l3vsme = -1;
					else
						proginf->ac_l3vsme += tsk->pmc_pmmr[i];
				} else {
					if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1) {
						acct_info->ac_l3vsme += tsk->pmc_pmmr[i];
					} else {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_l3vsme = tsk->pmc_pmmr[i];
					}
				}
				break;
			case VE_USR_PMC18:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1)
						proginf->ac_l3vsml = -1;
					else
						proginf->ac_l3vsml += tsk->pmc_pmmr[i];
				} else {
					if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1) {
						acct_info->ac_l3vsml += tsk->pmc_pmmr[i];
					} else {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_l3vsml = tsk->pmc_pmmr[i];
					}
				}
				break;
			case VE_USR_PMC19:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1)
						proginf->ac_llvsme = -1;
					else
						proginf->ac_llvsme += tsk->pmc_pmmr[i];
				} else {
					if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1) {
						acct_info->ac_llvsme += tsk->pmc_pmmr[i];
					} else {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_llvsme = tsk->pmc_pmmr[i];
					}
				}
				break;
			case VE_USR_PMC20:
				if (proginf) {
					if (tsk->pmc_pmmr[i] == -1)
						proginf->ac_llvsml = -1;
					else
						proginf->ac_llvsml += tsk->pmc_pmmr[i];
				} else {
					if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1) {
						acct_info->ac_llvsml += tsk->pmc_pmmr[i];
					} else {
						tsk->pmc_pmmr[i] = -1;
						acct_info->ac_llvsml = tsk->pmc_pmmr[i];
					}
				}
				break;
		}
	}

}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_performance_register_info, ve3_psm_get_performance_register_info)

void ve3_print_accounting(struct pacct_struct *pacct)
{
	struct ve_acct_v16 *acct_info = (struct ve_acct_v16 *)(pacct->acct_info);
	VEOS_DEBUG("Accounting information of PID : %d", acct_info->ac_pid);
	VEOS_DEBUG("ac_comm: %s, ac_vesrion: %d, ac_exitcode: %d",
			acct_info->ac_comm, acct_info->ac_version,
			acct_info->ac_exitcode);
	VEOS_DEBUG("ac_uid: %d, ac_gid: %d, ac_pid: %d, ac_ppid: %d",
			acct_info->ac_uid, acct_info->ac_gid,
			acct_info->ac_pid, acct_info->ac_ppid);
	VEOS_DEBUG("ac_mem : %d, ac_sid: %d, ac_total_mem: %f, ac_maxmem: %lld",
			acct_info->ac_mem, acct_info->ac_sid,
			acct_info->ac_total_mem, acct_info->ac_maxmem);
	VEOS_DEBUG("ac_timeslice: %d, ac_max_nthread: %d, ac_syscall: %lld, "
			"ac_transdata: %f, ac_numanode: %d",
			acct_info->ac_timeslice, acct_info->ac_max_nthread,
			acct_info->ac_syscall, acct_info->ac_transdata,
			acct_info->ac_numanode);
	VEOS_DEBUG("ac_ex: %llx, ac_vx: %llx, ac_fpec: %llx, ac_ve: %llx",
			acct_info->ac_ex, acct_info->ac_vx,
			acct_info->ac_fpec, acct_info->ac_ve);
	VEOS_DEBUG("ac_l1imc: %llx, ac_vecc: %llx, ac_l1mcc: %llx, ac_l2mcc: %llx",
			acct_info->ac_l1imc, acct_info->ac_vecc,
			acct_info->ac_l1mcc, acct_info->ac_l2mcc);
	VEOS_DEBUG("ac_ve2: %llx, ac_varec: %llx, ac_l1imcc: %llx, ac_vldec: %llx",
			acct_info->ac_ve2, acct_info->ac_varec,
			acct_info->ac_l1imcc, acct_info->ac_vldec);
	VEOS_DEBUG("ac_l1omcc: %llx, ac_pccc: %llx, ac_ltrc: %llx, ac_vlpc: %llx",
			acct_info->ac_l1omcc, acct_info->ac_pccc,
			acct_info->ac_ltrc, acct_info->ac_vlpc);
	VEOS_DEBUG("ac_strc: %llx, ac_vlec: %llx, ac_llvml: %llx, ac_llvme: %llx",
			acct_info->ac_strc, acct_info->ac_vlec,
			acct_info->ac_llvml, acct_info->ac_llvme);
	VEOS_DEBUG("ac_fmaec: %llx, ac_ptcc: %llx, ac_ttcc: %llx",
			acct_info->ac_fmaec, acct_info->ac_ptcc,
			acct_info->ac_ttcc);
	VEOS_DEBUG("ac_l3vsac: %llx, ac_l3vsme: %llx, ac_l3vsml: %llx",
			acct_info->ac_l3vsac, acct_info->ac_l3vsme,
			acct_info->ac_l3vsml);
	VEOS_DEBUG("ac_llvsme: %llx, ac_llvsml: %llx",
			acct_info->ac_llvsme, acct_info->ac_llvsml);
}

void ve3_veos_prepare_acct_info(struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct = NULL;
	struct ve_acct_v16 *acct_info = NULL;
	struct timeval now = {0};
	pacct = &(tsk->sighand->pacct);
	acct_info = (struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info);
	acct_info->ac_flag = (char)(pacct->ac_flag);

	/* Always set to VE_ACCT_VERSION | ACCT_BYTEORDER */
	acct_info->ac_version = VE3_ACCT_VERSION | ACCT_BYTEORDER;

	/* task exit code passed to the exit system call */
	acct_info->ac_exitcode = pacct->ac_exitcode;

	/* Real user ID */
	acct_info->ac_uid = tsk->uid;

	/*Real group ID*/
	acct_info->ac_gid = tsk->gid;

	/*Process ID*/
	acct_info->ac_pid = tsk->pid;

	/* Parent process ID*/
	if (1 == tsk->parent->pid)
		acct_info->ac_ppid = tsk->real_parent_pid;
	else
		acct_info->ac_ppid = tsk->parent->pid;

	/* process creation time */
	acct_info->ac_btime = tsk->start_time.tv_sec +
		tsk->start_time.tv_usec/MICRO_SECONDS;

	/* elapsed time from process creation to termination */
	gettimeofday(&now, NULL);
	acct_info->ac_etime = veos_usec_to_AHZ(timeval_diff(now,
				tsk->start_time));
	/* In VE stime of process would be zero */
	acct_info->ac_stime = 0;

	/* Time spend by the process while scheduled on VE core */
	acct_info->ac_utime = veos_encode_comp_t(veos_usec_to_AHZ
			(pacct->ac_utime));

	/* Average memory usage (kB) */
	acct_info->ac_mem = veos_encode_comp_t(pacct->ac_mem);


	/* In case of thread group VE's max memory usage [kb] */
	acct_info->ac_maxmem = ((tsk->p_ve_mm->rss_max) / 1024);

	/*The number of NUMA node */
	acct_info->ac_numanode = tsk->numa_node;

	/*Timeslice of the process (us)*/
	acct_info->ac_timeslice = VE_ATOMIC_GET(uint64_t, &veos_time_slice);

	/*session_id*/
	acct_info->ac_sid = tsk->sid;

	/*controlling terminal (tty)*/
	acct_info->ac_tty = tsk->tty;

	/* Command name of the program */
	memcpy(acct_info->ac_comm, tsk->ve_comm, ACCT_COMM-1);

	acct_info->ac_corebitmap = *(tsk->thread_core_bitmap);

	acct_info->ac_max_nthread = pacct->max_thread;

	ve3_print_accounting(pacct);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_prepare_acct_info, ve3_veos_prepare_acct_info)

void ve3_veos_update_accounting_data(struct ve_task_struct *tsk,
                                        enum acct_data ac_type, double size)
{
	struct ve_acct_v16 *acct_info = (struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info);
	switch (ac_type) {
		case ACCT_TOTAL_MEM:
			acct_info->ac_total_mem += size;
			break;
		case ACCT_TRANSDATA:
			acct_info->ac_transdata += size;
			break;
		case ACCT_SYSCALL:
			acct_info->ac_syscall += 1;
			break;
	}
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_update_accounting_data, ve3_veos_update_accounting_data)

int ve3_psm_alloc_pmc_pmmr(struct ve_task_struct *tsk)
{
	int retval  = -1;
	tsk->pmc_pmmr = (uint64_t *)malloc(sizeof(uint64_t) * PMC_REG_VE3);
	if (!tsk->pmc_pmmr) {
		VEOS_ERROR("Failed to allocate memory for pmc_pmmr: %s",
				strerror(errno));
		return retval;
	}
	memset(tsk->pmc_pmmr, 0, (sizeof(uint64_t) * PMC_REG_VE3));

	tsk->initial_pmc_pmmr = (uint64_t *)malloc(sizeof(uint64_t) * PMC_REG_VE3);
	if (!tsk->initial_pmc_pmmr) {
		VEOS_ERROR("Failed to allocate memory for initial_pmc_pmmr: %s",
				strerror(errno));
		free(tsk->pmc_pmmr);
		return retval;
	}
	memset(tsk->initial_pmc_pmmr, 0, (sizeof(uint64_t) * PMC_REG_VE3));
	retval = 0;
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_alloc_pmc_pmmr, ve3_psm_alloc_pmc_pmmr)

void ve3_psm_free_pmc_pmmr(struct ve_task_struct *task)
{
	free(task->pmc_pmmr);
	free(task->initial_pmc_pmmr);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_free_pmc_pmmr, ve3_psm_free_pmc_pmmr)

struct ve_acct *ve3_psm_alloc_acct(void)
{
	struct ve_acct_v16 *ve_acct = malloc(sizeof(struct ve_acct_v16));
	if (!ve_acct) {
                VEOS_ERROR("Failed to allocate memory for ve_acct: %s",
                                strerror(errno));
                return NULL;
        }
	memset(ve_acct, 0, sizeof(struct ve_acct_v16));
	return (struct ve_acct *)ve_acct;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_alloc_acct, ve3_psm_alloc_acct)

void ve3_psm_free_acct(struct ve_acct *acct)
{
	free(acct);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_free_acct, ve3_psm_free_acct)

uint64_t ve3_veos_acct_size()
{
	return (sizeof(struct ve_acct_v16));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_acct_size, ve3_veos_acct_size)

void ve3_increment_num_ve_proc(void)
{
	int old, ret;
	int retry = CHECK_STATE_RETRY_CNT;
	uint64_t state = 0;
	struct timespec retry_delay = {};
	struct ve3_node_arch_dep_data *data =
		(struct ve3_node_arch_dep_data *)(VE_NODE(0)->arch_dep_data);

	retry_delay.tv_sec = 0;
	retry_delay.tv_nsec = CHECK_STATE_RETRY_DELAY;

	pthread_mutex_lock_unlock(&(VE_NODE(0)->num_ve_proc_lock), LOCK,
					"Failed to acquire num_ve_proc_lock");

	old = VE_NODE(0)->num_ve_proc;
	ve_atomic_inc(&(VE_NODE(0)->num_ve_proc));
	if ((old == 0) && (data->type != QTYPE)) {
		VEOS_DEBUG("Turning off core clock gating");
		ret = vedl_handle_clock_gating(
					VE_NODE(0)->handle, CLOCK_GATING_OFF);
		if (__builtin_expect((ret != 0), 0))
			veos_abort("Faild to turn OFF core clock gating %s",
							strerror(errno));
		do {

			ret = vedl_get_clock_gating_state(
						VE_NODE(0)->handle, &state);
			if (__builtin_expect((ret != 0), 0))
				veos_abort("Faild to get clock gating state %s",
							strerror(errno));

			if (((state & CLOCK_GATING_STATE_MASK)
					>> (63 - CLOCK_GATING_STATE_BIT))
					== CLOCK_GATING_OFF)
				break;

			retry--;
			if (__builtin_expect((retry < 1), 0))
				veos_abort("Cannot turn OFF core clock gating");

			VEOS_DEBUG("Re-try to get clock gating state");
			nanosleep(&retry_delay, NULL);
		} while (1);
	}

	pthread_mutex_lock_unlock(&(VE_NODE(0)->num_ve_proc_lock), UNLOCK,
					"Failed to release num_ve_proc_lock");

	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_increment_num_ve_proc, ve3_increment_num_ve_proc)

void ve3_decrement_num_ve_proc(void)
{
	int old;

	pthread_mutex_lock_unlock(&(VE_NODE(0)->num_ve_proc_lock), LOCK,
					"Failed to acquire num_ve_proc_lock");

	old = VE_NODE(0)->num_ve_proc;
	ve_atomic_dec(&(VE_NODE(0)->num_ve_proc));
	if (old == 1)
		ve3_turn_on_clock_gating();

	pthread_mutex_lock_unlock(&(VE_NODE(0)->num_ve_proc_lock), UNLOCK,
					"Failed to release num_ve_proc_lock");

	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_decrement_num_ve_proc, ve3_decrement_num_ve_proc)

void ve3_get_proginf_architecture(struct proginf_v1 *proginf)
{
	proginf->arch = VE3_ARCH_NUM;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_get_proginf_architecture, ve3_get_proginf_architecture)

void ve3_psm_initialize_pmc(struct ve_task_struct *new_task, struct ve_task_struct *current)
{
        ve_reg_t pmc[PMR_CONTEXT_LOOP_VE3];
        int i = 0;

        for(i = 0; i < PMC_REG_VE3; i++) {
                ve3_psm_save_pmc_registers(pmc, current->p_ve_thread->arch_user_regs, ((uint64_t)1 << (i+PMR_CONTEXT_PMCR4)));
                new_task->initial_pmc_pmmr[i] = (pmc[i+PMR_CONTEXT_PMCR4] & OVERFLOW_BIT_VE3);
        }
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_initialize_pmc, ve3_psm_initialize_pmc)

void ve3_psm_update_pmc_check_overflow(struct ve_task_struct *tsk)
{
	uint64_t tmp_pmc_pmmr = 0, diff = 0;
	ve_reg_t gb[PMR_CONTEXT_LOOP_VE3];

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock [PID = %d]", tsk->pid);
	for(int i = 0; i < PMC_REG_VE3; i++) {
		if (tsk->pmc_pmmr[i] != -1) {
			/* Condition for pmc_mmr[i] reached to the max */
			if (tsk->pmc_pmmr[i] == (uint64_t)(UINT64_MAX - 1))
				continue;
			ve3_psm_save_pmc_registers(gb,
					tsk->p_ve_thread->arch_user_regs,
					((uint64_t)1 << (i+PMR_CONTEXT_PMCR4)));
			tmp_pmc_pmmr = gb[i+PMR_CONTEXT_PMCR4];
			VEOS_DEBUG("Received PMC[%d] value from register: %lu",
							i, tmp_pmc_pmmr);
			/* Check for overflow */
			if((tmp_pmc_pmmr & OVERFLOW_BIT_VE3) < tsk->initial_pmc_pmmr[i]) {
				VEOS_INFO("PMC[%d] Overflowed", i);
				diff = (MAX_PMC_VALUE_VE3 - (tsk->initial_pmc_pmmr[i]))
					+ (tmp_pmc_pmmr & OVERFLOW_BIT_VE3) +1;
				VEOS_DEBUG("PMC[%d]'s current and initial value difference: %lu",
						i, diff);
				if(tsk->pmc_pmmr[i] > (diff + (tsk->pmc_pmmr[i])))  {
					VEOS_DEBUG("PMC%d's limit reached at max", i);
					tsk->pmc_pmmr[i] = UINT64_MAX - 1;
				} else {
					tsk->pmc_pmmr[i] += diff;
					tsk->initial_pmc_pmmr[i] =
						(tmp_pmc_pmmr & OVERFLOW_BIT_VE3);
				}
			} else /* Not overflowed */ {
				tsk->pmc_pmmr[i] += (tmp_pmc_pmmr & OVERFLOW_BIT_VE3) -
					tsk->initial_pmc_pmmr[i];
				tsk->initial_pmc_pmmr[i] = (tmp_pmc_pmmr & OVERFLOW_BIT_VE3);
			}
		}
		VEOS_DEBUG("PMC[%d]:%lu Initial PMC[%d]:%lu", i, tsk->pmc_pmmr[i],
							i, tsk->initial_pmc_pmmr[i]);
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock [PID = %d]", tsk->pid);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_update_pmc_check_overflow, ve3_psm_update_pmc_check_overflow)

void ve3_psm_get_performance_of_terminated_thread(struct ve_task_struct *tsk, struct proginf_v1 *proginf)
{
	ve_reg_t pmmr_mode = 0x00, pmmr_mode_val = 0x00;
	struct ve_acct_v16 *acct_info = NULL;
	struct ve_proginf_v1 *proginf_ex_fld= NULL;
	ve_reg_t gb[PMR_CONTEXT_LOOP_VE3];

	acct_info = (struct ve_acct_v16 *)(tsk->sighand->pacct.acct_info);
	proginf_ex_fld = &(tsk->sighand->pacct.ve_proginf);
	ve3_psm_save_pmc_registers(gb,
			tsk->p_ve_thread->arch_user_regs,
			((uint64_t)1 << (PMR_CONTEXT_PMRR)));
	for(int i = 0; i < PMC_REG_VE3; i++) {
		int regid;
		if (i <= 15) {
			regid = VE_USR_PMC00 + i;
			pmmr_mode_val = gb[PMR_CONTEXT_PMRR] & (PMMR_SHIFT >> 4 * i);
			pmmr_mode = (pmmr_mode_val >> 4 * ((PMC_REG_VE3 - 5) - i - 1));
		} else {
			regid = VE_USR_PMC16 + i - 16;
			pmmr_mode = 0;
		}
		/*each case corresponding to PMCXX */
		switch (regid) {
			case VE_USR_PMC00:
				if (pmmr_mode == 0 && acct_info->ac_ex != -1)
					proginf->ac_ex += acct_info->ac_ex;
				break;
			case VE_USR_PMC01:
				if (pmmr_mode == 0 && acct_info->ac_vx != -1)
					proginf->ac_vx += acct_info->ac_vx;
				break;
			case VE_USR_PMC02:
				if (pmmr_mode == 0 && acct_info->ac_fpec != -1)
					proginf->ac_fpec += acct_info->ac_fpec;
				break;
			case VE_USR_PMC03:
				if (pmmr_mode == 0 && acct_info->ac_ve != -1) {
					proginf->ac_ve += acct_info->ac_ve;
				} else if (pmmr_mode == 2 &&
						acct_info->ac_l1imc != -1) {
					proginf->ac_l1imc += acct_info->ac_l1imc;
				}
				break;
			case VE_USR_PMC04:
				if (pmmr_mode == 0 && acct_info->ac_vecc != -1) {
					proginf->ac_vecc += acct_info->ac_vecc;
				} else if(pmmr_mode == 2 &&
						proginf_ex_fld->ac_l1iac != -1) {
					proginf->ac_l1iac += proginf_ex_fld->ac_l1iac;
				}
				break;
			case VE_USR_PMC05:
				if (pmmr_mode == 0 && acct_info->ac_l1mcc != -1) {
					proginf->ac_l1mcc += acct_info->ac_l1mcc;
				} else if (pmmr_mode == 1 && acct_info->ac_l2mcc != -1) {
					proginf->ac_l2mcc += acct_info->ac_l2mcc;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_l1omc != -1) {
					proginf->ac_l1omc += proginf_ex_fld->ac_l1omc;
				} else if (pmmr_mode == 8 && proginf_ex_fld->ac_uxc != -1) {
					proginf->ac_uxc += proginf_ex_fld->ac_uxc;
				}
				break;
			case VE_USR_PMC06:
				if (pmmr_mode == 0 && acct_info->ac_ve2 != -1) {
					proginf->ac_ve2 += acct_info->ac_ve2;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_l1oac != -1) {
					proginf->ac_l1oac += proginf_ex_fld->ac_l1oac;
				} else if (pmmr_mode == 8 && proginf_ex_fld->ac_uec != -1) {
					proginf->ac_uec += proginf_ex_fld->ac_uec;
				}
				break;
			case VE_USR_PMC07:
				if (pmmr_mode == 0 && acct_info->ac_varec != -1) {
					proginf->ac_varec += acct_info->ac_varec;
				} else if (pmmr_mode == 1 && acct_info->ac_l1imcc != -1) {
					proginf->ac_l1imcc += acct_info->ac_l1imcc;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_l2mc != -1) {
					proginf->ac_l2mc += proginf_ex_fld->ac_l2mc;
				}
				break;
			case VE_USR_PMC08:
				if (pmmr_mode == 0 && acct_info->ac_vldec != -1) {
					proginf->ac_vldec += acct_info->ac_vldec;
				} else if (pmmr_mode == 1 && acct_info->ac_l1omcc != -1) {
					proginf->ac_l1omcc += acct_info->ac_l1omcc;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_l2ac != -1) {
					proginf->ac_l2ac += proginf_ex_fld->ac_l2ac;
				}
				break;
			case VE_USR_PMC09:
				if (pmmr_mode == 0 && acct_info->ac_pccc != -1) {
					proginf->ac_pccc += acct_info->ac_pccc;
				} else if (pmmr_mode == 1 && acct_info->ac_ltrc != -1) {
					proginf->ac_ltrc += acct_info->ac_ltrc;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_brec != -1) {
					proginf->ac_brec += proginf_ex_fld->ac_brec;
				} else if (pmmr_mode == 3 && proginf_ex_fld->ac_sarcc != -1) {
					proginf->ac_sarcc += proginf_ex_fld->ac_sarcc;
				}
				break;
			case VE_USR_PMC10:
				if (pmmr_mode == 0 && acct_info->ac_vlpc != -1) {
					proginf->ac_vlpc += acct_info->ac_vlpc;
				} else if (pmmr_mode == 1 && acct_info->ac_strc != -1) {
					proginf->ac_strc += acct_info->ac_strc;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_bpfc != -1) {
					proginf->ac_bpfc += proginf_ex_fld->ac_bpfc;
				} else if (pmmr_mode == 3 && proginf_ex_fld->ac_iphcc != -1) {
					proginf->ac_iphcc += proginf_ex_fld->ac_iphcc;
				}
				break;
			case VE_USR_PMC11:
				if (pmmr_mode == 0 && acct_info->ac_vlec != -1) {
					proginf->ac_vlec += acct_info->ac_vlec;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_vlxc != -1) {
					proginf->ac_vlxc += proginf_ex_fld->ac_vlxc;
				}
				break;
			case VE_USR_PMC12:
				if (pmmr_mode == 1 && acct_info->ac_llvme != -1) {
					proginf->ac_llvme += acct_info->ac_llvme;
				}
				break;
			case VE_USR_PMC13:
				if (pmmr_mode == 0 && acct_info->ac_fmaec != -1) {
					proginf->ac_fmaec += acct_info->ac_fmaec;
				} else if (pmmr_mode == 2 && proginf_ex_fld->ac_fmaxc != -1) {
					proginf->ac_fmaxc += proginf_ex_fld->ac_fmaxc;
				}
				break;
			case VE_USR_PMC14:
				if (pmmr_mode == 0 && acct_info->ac_ptcc != -1)
					proginf->ac_ptcc += acct_info->ac_ptcc;
				break;
			case VE_USR_PMC15:
				if (pmmr_mode == 0 && acct_info->ac_ttcc != -1)
					proginf->ac_ttcc += acct_info->ac_ttcc;
				break;
			case VE_USR_PMC16:
				proginf->ac_l3vsac += acct_info->ac_l3vsac;
				break;
			case VE_USR_PMC17:
				proginf->ac_l3vsme += acct_info->ac_l3vsme;
				break;
			case VE_USR_PMC18:
				proginf->ac_l3vsml += acct_info->ac_l3vsml;
				break;
			case VE_USR_PMC19:
				proginf->ac_llvsme += acct_info->ac_llvsme;
				break;
			case VE_USR_PMC20:
				proginf->ac_llvsml += acct_info->ac_llvsml;
				break;
		}
	}

}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_performance_of_terminated_thread, ve3_psm_get_performance_of_terminated_thread)

int ve3_psm_save_performance_registers(struct ve_task_struct *tsk)
{
	int retval = -1, i = 0;
	int tmp_regids[PMC_REG_VE3+1] = {0};
	ve_reg_t tmp_pmc[PMC_REG_VE3+1] = {0};
	ve_reg_t pmmr_mode = 0x00, pmmr_mode_val = 0x00;
	ve3_core_user_reg_pre_t *user_regs = tsk->p_ve_thread->arch_user_regs;

	retval = get_ve_task_struct(tsk);
	if (0 > retval) {
		VEOS_ERROR("failed to get task reference");
		retval = -ESRCH;
		goto handle_return;
	}

	for (i = 0; i < 16; i++)
		tmp_regids[i] = VE_USR_PMC00 + i;
	for (i = 16; i < PMC_REG_VE3; i++)
		tmp_regids[i] = VE_USR_PMC16 + i - 16;
	tmp_regids[i] = VE_USR_PMMR;

	retval = psm_get_regval(tsk, PMC_REG_VE3+1, tmp_regids, tmp_pmc);
	if (retval < 0) {
		VEOS_ERROR("failed to get task's register");
		goto handle_return;
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	user_regs->PMMR = tmp_pmc[PMC_REG_VE3];
	for(int i = 0; i < PMC_REG_VE3; i++) {
		int regid = 0;
		if (i <= 15) {
			regid = VE_USR_PMC00 + i;
			pmmr_mode_val =  (tmp_pmc[PMC_REG_VE3] & (PMMR_SHIFT >> 4*i));
			pmmr_mode = (pmmr_mode_val >> 4 * ((PMC_REG_VE3 - 5) - i - 1));
		} else {
			regid = VE_USR_PMC16 + i - 16;
			pmmr_mode_val = 0;
			pmmr_mode = 0;
		}

		switch (regid) {
			case VE_USR_PMC00:
			case VE_USR_PMC01:
			case VE_USR_PMC02:
			case VE_USR_PMC14:
			case VE_USR_PMC15:
				if (pmmr_mode == 0)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC04:
			case VE_USR_PMC11:
			case VE_USR_PMC13:
			case VE_USR_PMC03:
				if (pmmr_mode == 0 || pmmr_mode == 2)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC05:
				if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2 || pmmr_mode == 8)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC06:
				if (pmmr_mode == 0 || pmmr_mode == 2 || pmmr_mode == 8)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC07:
			case VE_USR_PMC08:
				if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC09:
			case VE_USR_PMC10:
				if (pmmr_mode == 0 || pmmr_mode == 1 || pmmr_mode == 2 || pmmr_mode == 3)
					user_regs->PMC[i] = tmp_pmc[i];
				break;
			case VE_USR_PMC12:
				if (pmmr_mode == 1) {
					user_regs->PMC[12] = tmp_pmc[i];
				}
				break;
			case VE_USR_PMC16:
			case VE_USR_PMC17:
			case VE_USR_PMC18:
			case VE_USR_PMC19:
			case VE_USR_PMC20:
				user_regs->PMC[i] = tmp_pmc[i];
				break;
		}
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	retval = 0;
handle_return:
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_save_performance_registers, ve3_psm_save_performance_registers)

void ve3_psm_reset_perf_accounting(struct ve_task_struct *tsk)
{
	for(int i = 0; i < PMC_REG_VE3; i++)
		tsk->pmc_pmmr[i] = 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_reset_perf_accounting, ve3_psm_reset_perf_accounting)
