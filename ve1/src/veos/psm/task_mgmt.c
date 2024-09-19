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
 * @brief VE1-dependent part of VE task management activities
 *
 */
#include <ve_hw.h>
#include <stdint.h>
#include <linux/types.h>
#include <libved.h>

#include <veos_arch_defs.h>
#include <veos.h>
#include <task_mgmt.h>
#include <mm_common.h>
#include "task_mgmt_ve1.h"
#include <task_sched.h>

#include <sys/syslog.h>

void ve1_psm_save_scalar_registers(ve_reg_t *buffer, const void *u,
					uint64_t bitmap)
{
	const ve1_core_user_reg_t *user_regs = u;
	for (int i = 0; i < VE1_SR_NUM; ++i) {
		if (GET_BIT(bitmap, i))
			buffer[i] = user_regs->SR[i];
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_save_scalar_registers, ve1_psm_save_scalar_registers)

void ve1_psm_restore_scalar_registers(void *u, const ve_reg_t *buffer,
					uint64_t bitmap)
{
	ve1_core_user_reg_t *user_regs = u;
	for (int i = 0; i < VE1_SR_NUM; ++i) {
		if (GET_BIT(bitmap, i)) {
			user_regs->SR[i] = buffer[i];
			VEOS_DEBUG("Storing SR[%d]: 0x%lx in tmp",
				i, buffer[i]);
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_restore_scalar_registers, ve1_psm_restore_scalar_registers)

void ve1_psm_save_pmc_registers(ve_reg_t *buffer, const void *u,
				uint64_t bitmap)
{
	const ve1_core_user_reg_t *user_regs = u;
	for (int i = PMR_CONTEXT_PSW; i < PMR_CONTEXT_LOOP_VE1; ++i) {
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
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_save_mode_registers, ve1_psm_save_pmc_registers)

void ve1_psm_restore_pmc_registers(void *u, const ve_reg_t *buffer,
					uint64_t bitmap)
{
	ve1_core_user_reg_t *user_regs = u;
	for (int i = PMR_CONTEXT_PSW; i < PMR_CONTEXT_LOOP_VE1; ++i) {
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
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_restore_mode_registers, ve1_psm_restore_pmc_registers)

ve_reg_t ve1_get_PSW_from_thread(const void *u)
{
	const ve1_core_user_reg_t *user_regs = u;
	return user_regs->PSW;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_PSW_from_thread_struct, ve1_get_PSW_from_thread)

void ve1_set_PSW_on_thread(void *u, ve_reg_t val)
{
	ve1_core_user_reg_t *user_regs = u;
	user_regs->PSW = val;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_PSW_on_thread_struct, ve1_set_PSW_on_thread)

static int ve1_get_usr_reg(int core_id, ve_usr_reg_name_t reg, ve_reg_t *valp)
{
	int retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id), reg, valp);
	if (retval != 0) {
		VEOS_ERROR("Failed to get user register");
		VEOS_DEBUG("Failed to get register %d, returned %d",
			reg, retval);
	}
	return retval;
}
#define VE1_UPDATE_VAL_ON_USER_REGS(u_, member_, val_, mask_) \
do { \
	ve1_core_user_reg_t *user_regs_ = (u_); \
	uint64_t m_ = (mask_); \
	ve_reg_t oldval_ = user_regs->member_; \
	ve_reg_t newval_ = (oldval_ & (~m_)) | ((val_) & m_); \
	user_regs_->member_ = newval_; \
} while (0)

int ve1_psm_set_reg_on_thread_struct(void *u, int core_id, int sync,
		ve_usr_reg_name_t regid, ve_reg_t regval, uint64_t mask,
		uint64_t *pmr_bitmap, uint64_t *sr_bitmap)
{
	ve1_core_user_reg_t *user_regs = u;
	int retval;
	if (regid == VE_USR_PSW) {
		if (sync && !GET_BIT(*pmr_bitmap, 0)) {
			VEOS_DEBUG("Getting PSW from Core %d", core_id);
			retval = ve1_get_usr_reg(core_id, VE_USR_PSW,
					&(user_regs->PSW));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE1_UPDATE_VAL_ON_USER_REGS(user_regs, PSW, regval, mask);
		SET_BIT(*pmr_bitmap, 0);
		return 0;
	}
	if (regid == VE_USR_PMMR) {
		if (sync && !GET_BIT(*pmr_bitmap, 1)) {
			VEOS_DEBUG("Getting PMMR from Core %d", core_id);
			retval = ve1_get_usr_reg(core_id, VE_USR_PMMR,
					&(user_regs->PMMR));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE1_UPDATE_VAL_ON_USER_REGS(user_regs, PMMR, regval, mask);
		SET_BIT(*pmr_bitmap, 1);
		return 0;
	}
	if ((regid >= VE_USR_SR00) && (regid <= VE_USR_SR63)) {
		/* In scaler register mask will be always USER_REG_MASK,
		 * so we dont need the latest register value from core.
		 */
		int sr_id = regid - VE_USR_SR00;
		VE1_UPDATE_VAL_ON_USER_REGS(user_regs, SR[sr_id], regval, mask);
		SET_BIT(*sr_bitmap, sr_id);
		return 0;
	}
	if ((regid >= VE_USR_PMCR00) && (regid <= VE_USR_PMCR03)) {
		int pmcr_id = regid - VE_USR_PMCR00;
		if (sync && !GET_BIT(*pmr_bitmap, (pmcr_id + 2))) {
			VEOS_DEBUG("Getting PMCR%d from Core %d", pmcr_id,
					core_id);
			retval = ve1_get_usr_reg(core_id, regid,
					&(user_regs->PMCR[pmcr_id]));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE1_UPDATE_VAL_ON_USER_REGS(user_regs, PMCR[pmcr_id],
						regval, mask);
		SET_BIT(*pmr_bitmap, (pmcr_id + 2));
		return 0;
	}
	if ((regid >= VE_USR_PMC00) &&  (regid <= VE_USR_PMC15)) {
		int pmc_id = regid - VE_USR_PMC00;
		if (sync && !GET_BIT(*pmr_bitmap, (pmc_id + 6))) {
			VEOS_DEBUG("Getting PMC%d from Core %d", pmc_id,
					core_id);
			retval = ve1_get_usr_reg(core_id, regid,
					&(user_regs->PMC[pmc_id]));
			if (retval) {
				VEOS_DEBUG("returned %d, mapped to -EFAULT",
					retval);
				return -EFAULT;
			}
		}
		VE1_UPDATE_VAL_ON_USER_REGS(user_regs, PMC[pmc_id],
						regval, mask);
		SET_BIT(*pmr_bitmap, (pmc_id + 6));
		return 0;
	}
	VEOS_ERROR("Failed to handle pseudo process request: "
			"unmatched register");
	return -1;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_reg_on_thread_struct, ve1_psm_set_reg_on_thread_struct)

void ve1_psm_clear_EXS_to_NOML(struct ve_thread_struct *p_ve_thread)
{
	p_ve_thread->EXS = EXS_NOML;
	ve1_core_user_reg_t *u = p_ve_thread->arch_user_regs;
	u->EXS = EXS_NOML;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_clear_execution_status_on_thread_struct, ve1_psm_clear_EXS_to_NOML)

ve_reg_t ve1_get_IC_from_thread(const void *u)
{
	return ((const ve1_core_user_reg_t *)u)->IC;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_program_counter_from_thread_struct, ve1_get_IC_from_thread)

int ve1_psm_check_valid_userreg(int regid, bool *should_stop_core)
{
	if (regid < VE_USR_USRCC || regid > VE_USR_SR63) {
		return -1;
	}
	/* Check if Register ID array contains any register for
	 * which core is needed to be stopped if task
	 * is current task on core */
	if (!((VE_USR_USRCC <= regid && regid <= VE_USR_PMC15)
		|| (regid == VE_USR_EXS)
		|| (VE_USR_SAR <= regid && regid <= VE_USR_PMCR03)))
			*should_stop_core = true;
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_check_valid_userreg, ve1_psm_check_valid_userreg )

void ve1_psm_init_perf_accounting(struct ve_task_struct *tsk, ve_reg_t pmmr, uint64_t *pmc, ve_usr_reg_name_t reg_id)
{
	ve_reg_t pmmr_mode = 0x00, pmmr_mode_val = 0x00;

	if (VE_USR_PMC00 <= reg_id && reg_id <= VE_USR_PMC15) {
		tsk->pmc_pmmr[reg_id - VE_USR_PMC00] = -1;
		return;
	} else if (reg_id != VE_USR_PMMR)
		return;

	if (((struct ve_acct_v15 *)(tsk->sighand->pacct.acct_info))->ac_version == 0 || tsk->execed_proc) {
		((struct ve_acct_v15 *)(tsk->sighand->pacct.acct_info))->ac_version = VE1_ACCT_VERSION;
		/* Reset pmc_pmmr[i] to zero because the mode is updated at
		 * the first time */
		for(int i = 0; i < PMC_REG_VE1; i++)
			tsk->pmc_pmmr[i] = 0;
	} else {
		/* Invalidate pmc_pmmr[i] because the mode is updated twice or
                 * more */
		for(int i = 0; i < PMC_REG_VE1; i++)
			tsk->pmc_pmmr[i] = -1;
		return;
	}
	for(int i = 0; i < PMC_REG_VE1; i++) {
		int regid = VE_USR_PMC00 + i;
		pmmr_mode_val =  (pmmr & (PMMR_SHIFT >> 4*i));
		pmmr_mode = (pmmr_mode_val >> 4*(PMC_REG_VE1 - i - 1));
		switch (regid){
		case VE_USR_PMC00:
		case VE_USR_PMC01:
		case VE_USR_PMC02:
		case VE_USR_PMC04:
		case VE_USR_PMC06:
		case VE_USR_PMC11:
		case VE_USR_PMC13:
		case VE_USR_PMC14:
		case VE_USR_PMC15:
			if (pmmr_mode == 0){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC03:
			if (pmmr_mode == 0 || pmmr_mode == 2){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		case VE_USR_PMC05:
		case VE_USR_PMC07:
		case VE_USR_PMC08:
		case VE_USR_PMC09:
		case VE_USR_PMC10:
		case VE_USR_PMC12:
			if (pmmr_mode == 0 || pmmr_mode == 1){
				tsk->initial_pmc_pmmr[i] = pmc[i];
			} else {
				tsk->initial_pmc_pmmr[i] = 0;
			}
			break;
		}
	}
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_init_perf_accounting, ve1_psm_init_perf_accounting )

int ve1_psm_fetch_performance_registers(struct ve_task_struct *tsk, int **regids, uint64_t **pmc)
{
	int retval = -1;
	int tmp_regids[PMC_REG_VE1] = {0};
	uint64_t tmp_pmc[PMC_REG_VE1] = {0};
	ve1_core_user_reg_t *user_regs = tsk->p_ve_thread->arch_user_regs;

	for (int i = 0; i < PMC_REG_VE1; i++){
		tmp_regids[i] = VE_USR_PMC00 + i;
		tmp_pmc[i] = user_regs->PMC[i];
	}

	*regids = (int *)calloc(PMC_REG_VE1, sizeof(int));
	if (*regids == NULL) {
		retval = -ENOMEM;
		goto handle_return;
	}

	*pmc = (uint64_t *)calloc(PMC_REG_VE1, sizeof(uint64_t));
	if (*pmc == NULL) {
		retval = -ENOMEM;
		goto free_regids;
	}

	memcpy(*regids, &tmp_regids, PMC_REG_VE1*sizeof(int));
	memcpy(*pmc, &tmp_pmc, PMC_REG_VE1*sizeof(uint64_t));
	retval = 0;
	goto handle_return;
free_regids:
	free (*regids);
	*regids = NULL;
handle_return:
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_fetch_performance_registers, ve1_psm_fetch_performance_registers )

ve_reg_t ve1_psm_get_PMMR_on_thread_struct(struct ve_task_struct *task)
{
        ve1_core_user_reg_t *user_regs = task->p_ve_thread->arch_user_regs;
        return user_regs->PMMR;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_PMMR_on_thread_struct, ve1_psm_get_PMMR_on_thread_struct);

void ve1_psm_get_performance_register_info(struct ve_task_struct *tsk,
		uint64_t clock_val_mhz, struct proginf_v1 *proginf)
{
	ve_reg_t pmmr = 0x00, pmmr_mode = 0x00, pmmr_mode_val = 0x00;
	ve_reg_t group_leader_pmmr = 0x00, group_leader_pmmr_mode = 0x00, group_leader_pmmr_mode_val = 0x00;
	struct ve_acct_v15  *acct_info = NULL;

	acct_info = (struct ve_acct_v15 *)(tsk->sighand->pacct.acct_info);

	pmmr = ve1_psm_get_PMMR_on_thread_struct(tsk);
	group_leader_pmmr = ve1_psm_get_PMMR_on_thread_struct(tsk->group_leader);

	for(int i = 0; i < PMC_REG_VE1; i++) {
		int regid = VE_USR_PMC00 + i;

		pmmr_mode_val = pmmr & (PMMR_SHIFT >> 4 * i);
		pmmr_mode = (pmmr_mode_val >> 4*(PMC_REG_VE1 - i - 1));
		group_leader_pmmr_mode_val = group_leader_pmmr & (PMMR_SHIFT >> 4 * i);
		group_leader_pmmr_mode = (group_leader_pmmr_mode_val >> 4*(PMC_REG_VE1 - i - 1));
		/*each case corresponding to PMCXX */
		switch (regid) {
			case VE_USR_PMC00:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_ex += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ex = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC01:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_vx += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vx = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC02:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_fpec += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_fpec = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC03:
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
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vecc = -1;
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_vecc += (tsk->pmc_pmmr[i]/clock_val_mhz);
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vecc = -1;
				}
				break;
			case VE_USR_PMC05:
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_l1mcc = tsk->pmc_pmmr[i];
					acct_info->ac_l2mcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l2mcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l2mcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1mcc = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_l1mcc = tsk->pmc_pmmr[i];
					acct_info->ac_l2mcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC06:
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ve2 = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					acct_info->ac_ve2 += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ve2 = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC07:
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_varec = tsk->pmc_pmmr[i];
					acct_info->ac_l1imcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_varec += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1imcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1imcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_varec = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_varec = tsk->pmc_pmmr[i];
					acct_info->ac_l1imcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC08:
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vldec = tsk->pmc_pmmr[i];
					acct_info->ac_l1omcc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_vldec += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_l1omcc = -1;
				} else if (pmmr_mode == 1) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_l1omcc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_vldec = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vldec = tsk->pmc_pmmr[i];
					acct_info->ac_l1omcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC09:
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_pccc = tsk->pmc_pmmr[i];
					acct_info->ac_ltrc = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_pccc += (tsk->pmc_pmmr[i]/clock_val_mhz);
					acct_info->ac_ltrc = -1;
				} else if (pmmr_mode == 1) {
					acct_info->ac_ltrc += tsk->pmc_pmmr[i];
					acct_info->ac_pccc = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_pccc = tsk->pmc_pmmr[i];
					acct_info->ac_ltrc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC10:
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
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_vlpc = tsk->pmc_pmmr[i];
					acct_info->ac_strc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC11:
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
				if (tsk->pmc_pmmr[i] == -1 || group_leader_pmmr_mode != pmmr_mode) {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_llvml = tsk->pmc_pmmr[i];
					acct_info->ac_llvme = tsk->pmc_pmmr[i];
				} else if (pmmr_mode == 0) {
					acct_info->ac_llvml += tsk->pmc_pmmr[i];
					acct_info->ac_llvme = -1;
				} else if (pmmr_mode == 1) {
					acct_info->ac_llvme += tsk->pmc_pmmr[i];
					acct_info->ac_llvml = -1;
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_llvml = tsk->pmc_pmmr[i];
					acct_info->ac_llvme = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC13:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					acct_info->ac_fmaec += tsk->pmc_pmmr[i];
				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_fmaec = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC14:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_ptcc += (tsk->pmc_pmmr[i]/clock_val_mhz);

				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ptcc = tsk->pmc_pmmr[i];
				}
				break;
			case VE_USR_PMC15:
				if (pmmr_mode == 0 && tsk->pmc_pmmr[i] != -1
						&& group_leader_pmmr_mode == pmmr_mode) {
					/*conversion of clock count to microsecond*/
					acct_info->ac_ttcc += (tsk->pmc_pmmr[i]/clock_val_mhz);

				} else {
					tsk->pmc_pmmr[i] = -1;
					acct_info->ac_ttcc = tsk->pmc_pmmr[i];
				}
				break;
		}
	}

}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_performance_register_info, ve1_psm_get_performance_register_info )

void ve1_print_accounting(struct pacct_struct *pacct)
{
	struct ve_acct_v15 *acct_info = (struct ve_acct_v15 *)(pacct->acct_info);
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
}

void ve1_veos_prepare_acct_info(struct ve_task_struct *tsk)
{
	struct pacct_struct *pacct = NULL;
	struct ve_acct_v15 *acct_info = NULL;
	struct timeval now = {0};
	pacct = &(tsk->sighand->pacct);
	acct_info = (struct ve_acct_v15 *)(tsk->sighand->pacct.acct_info);

	acct_info->ac_flag = (char)(pacct->ac_flag);

	/* Always set to VE_ACCT_VERSION | ACCT_BYTEORDER */
	acct_info->ac_version = VE1_ACCT_VERSION | ACCT_BYTEORDER;

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

	ve1_print_accounting(pacct);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_veos_prepare_acct_info, ve1_veos_prepare_acct_info)

void ve1_veos_update_accounting_data(struct ve_task_struct *tsk,
                                        enum acct_data ac_type, double size)
{
	struct ve_acct_v15 *acct_info = (struct ve_acct_v15 *)((tsk->sighand->pacct.acct_info));
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
VEOS_ARCH_DEP_FUNC(ve1, arch_veos_update_accounting_data, ve1_veos_update_accounting_data)

int ve1_psm_alloc_pmc_pmmr(struct ve_task_struct *tsk)
{
	int retval  = -1;
	tsk->pmc_pmmr = (uint64_t *)malloc(sizeof(uint64_t) * PMC_REG_VE1);
	if (!tsk->pmc_pmmr) {
		VEOS_ERROR("Failed to allocate memory for pmc_pmmr: %s",
				strerror(errno));
		goto hndl_return;
	}
	memset(tsk->pmc_pmmr, 0, (sizeof(uint64_t) * PMC_REG_VE1));

	tsk->initial_pmc_pmmr = (uint64_t *)malloc(sizeof(uint64_t) * PMC_REG_VE1);
	if (!tsk->initial_pmc_pmmr) {
		VEOS_ERROR("Failed to allocate memory for initial_pmc_pmmr: %s",
				strerror(errno));
		free(tsk->pmc_pmmr);
		goto hndl_return;
	}
	memset(tsk->initial_pmc_pmmr, 0, (sizeof(uint64_t) * PMC_REG_VE1));
	retval = 0;
hndl_return:
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_alloc_pmc_pmmr, ve1_psm_alloc_pmc_pmmr)

void ve1_psm_free_pmc_pmmr(struct ve_task_struct *task)
{
	free(task->pmc_pmmr);
	free(task->initial_pmc_pmmr);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_free_pmc_pmmr, ve1_psm_free_pmc_pmmr)

struct ve_acct *ve1_psm_alloc_acct(void)
{
	struct ve_acct_v15 *ve_acct = malloc(sizeof(struct ve_acct_v15));
	if (!ve_acct) {
		VEOS_ERROR("Failed to allocate memory for ve_acct: %s",
				strerror(errno));
		return NULL;
	}
	memset(ve_acct, 0, sizeof(struct ve_acct_v15));
	return (struct ve_acct *)ve_acct;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_alloc_acct, ve1_psm_alloc_acct)

void ve1_psm_free_acct(struct ve_acct *acct)
{
	free(acct);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_free_acct, ve1_psm_free_acct)

uint64_t ve1_veos_acct_size()
{
	return (sizeof(struct ve_acct_v15));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_veos_acct_size, ve1_veos_acct_size)

void ve1_increment_num_ve_proc(void)
{
	ve_atomic_inc(&(VE_NODE(ve_node_id)->num_ve_proc));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_increment_num_ve_proc, ve1_increment_num_ve_proc )

void ve1_decrement_num_ve_proc(void)
{
	ve_atomic_dec(&(VE_NODE(0)->num_ve_proc));
}
VEOS_ARCH_DEP_FUNC(ve1, arch_decrement_num_ve_proc, ve1_decrement_num_ve_proc)

void ve1_get_proginf_architecture(struct proginf_v1 *proginf)
{
	proginf->arch = VE1_ARCH_NUM;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_get_proginf_architecture, ve1_get_proginf_architecture)

void ve1_psm_initialize_pmc(struct ve_task_struct *new_task, struct ve_task_struct *current)
{
        ve_reg_t pmc[PMR_CONTEXT_LOOP_VE1];
        int i = 0;

        for(i = 0; i < PMC_REG_VE1; i++) {
                ve1_psm_save_pmc_registers(pmc, current->p_ve_thread->arch_user_regs,
				((uint64_t)1 << (i+PMR_CONTEXT_PMCR4)));
                new_task->initial_pmc_pmmr[i] = (pmc[i+PMR_CONTEXT_PMCR4] & OVERFLOW_BIT);
        }
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_initialize_pmc, ve1_psm_initialize_pmc)

int ve1_psm_update_pmc_check_overflow(struct ve_task_struct *tsk)
{
	uint64_t tmp_pmc_pmmr = 0, diff = 0;
	ve_reg_t gb[PMR_CONTEXT_LOOP_VE1];
	int ret_val = 0;
	int ovfl_chk = 0;

	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock [PID = %d]", tsk->pid);
	for(int i = 0; i < PMC_REG_VE1; i++) {
		ovfl_chk = 0;
		int regid = VE_USR_PMC00 + i;
		if (tsk->pmc_pmmr[i] != -1) {
			/* Condition for pmc_mmr[i] reached to the max */
			if (tsk->pmc_pmmr[i] == (uint64_t)(UINT64_MAX - 1))
				continue;
			ve1_psm_save_pmc_registers(gb,
					tsk->p_ve_thread->arch_user_regs,
					((uint64_t)1 << (i+PMR_CONTEXT_PMCR4)));
			tmp_pmc_pmmr = gb[i+PMR_CONTEXT_PMCR4];
			/* Check for overflow */
			VEOS_DEBUG("Received PMC[%d] value from register: %lu & initial_pmc_pmmr: %lu",
							i, tmp_pmc_pmmr, tsk->initial_pmc_pmmr[i]);
			if((tmp_pmc_pmmr & OVERFLOW_BIT) < tsk->initial_pmc_pmmr[i]) {
				VEOS_ERROR("PMC[%d] Overflowed", i);
				if(regid == VE_USR_PMC00 || regid == VE_USR_PMC01){
					if((tsk->initial_pmc_pmmr[i] - (tmp_pmc_pmmr & OVERFLOW_BIT))
							< (MAX_PMC_VALUE_52BIT / 2)){
						/* There's no overflow, but the value is inverted */
						ovfl_chk = 1;
					}
					diff = (MAX_PMC_VALUE_52BIT - (tsk->initial_pmc_pmmr[i]))
						+ (tmp_pmc_pmmr & OVERFLOW_BIT) + 1;
				}else{
					if((tsk->initial_pmc_pmmr[i] - (tmp_pmc_pmmr & OVERFLOW_BIT))
							< (MAX_PMC_VALUE_56BIT / 2)){
						/* There's no overflow, but the value is inverted */
						ovfl_chk = 1;
					}
					diff = (MAX_PMC_VALUE_56BIT - (tsk->initial_pmc_pmmr[i]))
						+ (tmp_pmc_pmmr & OVERFLOW_BIT) + 1;
				}
				if(ovfl_chk){
					VEOS_ERROR("PMC[%d] the value is invalid. sid[%d], "
						"pid[%d], curr[%ld], init[%ld]", i, tsk->sid,
						tsk->pid, tmp_pmc_pmmr, tsk->initial_pmc_pmmr[i]);
					syslog(LOG_INFO, "PMC[%d] the value is invalid. ve[%d],"
						"sid[%d], pid[%d], curr[%ld], init[%ld]", i,
						VE_NODE(0)->ve_num, tsk->sid, tsk->pid, tmp_pmc_pmmr,
						tsk->initial_pmc_pmmr[i]);
					ret_val = 1;
				}


				VEOS_DEBUG("PMC[%d]'s current and initial value difference: %lu",
						i, diff);
				if(tsk->pmc_pmmr[i] > (diff + (tsk->pmc_pmmr[i])))  {
					VEOS_DEBUG("PMC%d's limit reached at max", i);
					tsk->pmc_pmmr[i] = UINT64_MAX - 1;
				} else {
					tsk->pmc_pmmr[i] += diff;
					tsk->initial_pmc_pmmr[i] =
						(tmp_pmc_pmmr & OVERFLOW_BIT);
				}
			} else /* Not overflowed */ {
				tsk->pmc_pmmr[i] += (tmp_pmc_pmmr & OVERFLOW_BIT) -
					tsk->initial_pmc_pmmr[i];
				tsk->initial_pmc_pmmr[i] = (tmp_pmc_pmmr & OVERFLOW_BIT);
			}
		}
		VEOS_DEBUG("PMC[%d]:%lu Initial PMC[%d]:%lu", i, tsk->pmc_pmmr[i],
				i, tsk->initial_pmc_pmmr[i]);
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock [PID = %d]", tsk->pid);
	return ret_val;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_update_pmc_check_overflow, ve1_psm_update_pmc_check_overflow)

int ve1_psm_save_performance_registers(struct ve_task_struct *tsk)
{
	int retval = -1, i = 0;
	int tmp_regids[PMC_REG_VE1+1] = {0};
	ve_reg_t tmp_pmc[PMC_REG_VE1+1] = {0};
	ve_reg_t pmmr_mode = 0x00, pmmr_mode_val = 0x00;
	ve1_core_user_reg_t *user_regs = tsk->p_ve_thread->arch_user_regs;

	for (i = 0; i < 16; i++)
		tmp_regids[i] = VE_USR_PMC00 + i;
	tmp_regids[i] = VE_USR_PMMR;

	retval = psm_get_regval(tsk, PMC_REG_VE1+1, tmp_regids, tmp_pmc);
	if (retval < 0) {
		VEOS_ERROR("failed to get task's register. sid[%d], "
			"pid[%d]", tsk->sid, tsk->pid);
		syslog(LOG_INFO, "Failed to get task's register. ve[%d], sid[%d], "
			"pid[%d]", VE_NODE(0)->ve_num, tsk->sid, tsk->pid);
		goto handle_return;
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), LOCK,
			"Failed to acquire task lock");
	user_regs->PMMR = tmp_pmc[PMC_REG_VE1];
	for(int i = 0; i < PMC_REG_VE1; i++) {
		int regid = 0;
		if (i <= 15) {
			regid = VE_USR_PMC00 + i;
			pmmr_mode_val =  (tmp_pmc[PMC_REG_VE1] & (PMMR_SHIFT >> 4*i));
			pmmr_mode = (pmmr_mode_val >> 4 * ((PMC_REG_VE1 - 5) - i - 1));
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
				if (pmmr_mode == 0 || pmmr_mode == 1) {
					user_regs->PMC[i] = tmp_pmc[i];
				}
				break;
		}
	}
	pthread_mutex_lock_unlock(&(tsk->ve_task_lock), UNLOCK,
			"Failed to release task lock");
	retval = 0;
handle_return:
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_save_performance_registers, ve1_psm_save_performance_registers)

void ve1_psm_reset_perf_accounting(struct ve_task_struct *tsk)
{
	for(int i = 0; i < PMC_REG_VE1; i++)
		tsk->pmc_pmmr[i] = 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_reset_perf_accounting, ve1_psm_reset_perf_accounting)

int ve1_veos_del_temporary_files()
{
	return(0);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_veos_del_temporary_files, ve1_veos_del_temporary_files)

void ve1_veos_del_temporary_files_wake_up()
{
	return;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_veos_del_temporary_files_wake_up, ve1_veos_del_temporary_files_wake_up)
