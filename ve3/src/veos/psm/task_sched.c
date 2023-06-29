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
 * @file  task_sched.c
 * @brief VE3-depenent part of Scheduler functionality.
 *
 * @author PSMG / Scheduling and context switch
 */

#include <ve_drv.h>
#include <ve_hw.h>
#include <libved.h>
#include <libved_ve3.h>
#include <sys/syslog.h>
#include <veos_arch_defs.h>

#include <veos.h>
#include <dma.h>
#include <dma_ve3.h>

#include <udma_ve3.h>

#include <ve_mem_ve3.h>

#include <task_sched.h>
#include <dmaatb_api.h>
#include <mm_common.h>

#include "task_sched_ve3.h"
#include "task_mgmt_ve3.h"

#define VE3_PSM_CTXSW_CREG_VERAA(phys_core_id_) \
		(VEDRV_VE3_PCI_BAR2_CREG_SIZE * (phys_core_id_))
#define VE3_PSM_CTXSW_CREG_SIZE (offsetof(ve3_core_user_reg_pre_t, VR) + \
		sizeof(((ve3_core_user_reg_pre_t *)NULL)->VR))
#define PMC_OVFLW_BIT ((uint64_t)1 << 63)
#define PMC_MAX_VAL 0xFFFFFFFFFFFFFFFULL /*Maximum value in PMC14 0xFFFFFFFFFFFFFFF*/

/**
 * @brief Save context from VE core
 *
 * @param dh DMA handle
 * @param phys_core_id physical core ID to save
 * @param veos_pid Process ID of destination
 * @param buffer destination to store context
 */
int ve3_save_context_from_core_reg(ve_dma_hdl *dh, int phys_core_id,
			pid_t veos_pid, void *buffer)
{
	return ve_dma_xfer_p_va(dh, VE3_DMA_VERAA_PREFETCHABLE, 0,
			VE3_PSM_CTXSW_CREG_VERAA(phys_core_id), VE_DMA_VHVA,
			veos_pid, (uintptr_t)buffer, VE3_PSM_CTXSW_CREG_SIZE);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_save_context_from_core_reg, ve3_save_context_from_core_reg);

/*
* @brief Function sets the updated register value on core
*
* @param task Pointer to VE task struct
*/
void ve3_psm_set_context(struct ve_task_struct *task)
{
	int i = 0;
	int ret = -1;
	vedl_user_reg_handle *core_regs = VE_CORE_USR_REG(0, task->core_id);
	ve3_core_user_reg_pre_t *user_regs = task->p_ve_thread->arch_user_regs;

	VEOS_TRACE("Entering");
	if (task->sr_context_bitmap) {
		for (i = 0; i < VE3_SR_NUM; i++) {
			if (GET_BIT(task->sr_context_bitmap, i)) {
				/* Invoke VEDL API */
				ret = vedl_set_usr_reg(core_regs,
					(VE_USR_SR00 + i), user_regs->SR[i]);
				if (ret) {
					VEOS_DEBUG("Setting context returned %d for PID %d",
						ret, task->pid);
					goto abort;
				}
				VEOS_DEBUG("Set SR[%d]: 0x%lx in tmp",
					i, user_regs->SR[i]);
			}
		}
	}

	if (task->pmr_context_bitmap) {
		for (i = 0; i < PMR_CONTEXT_LOOP_VE3; i++) {
			if (GET_BIT(task->pmr_context_bitmap, i)) {
				if (i == PMR_CONTEXT_PSW) { /* PSW */
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(core_regs,
						VE_USR_PSW, user_regs->PSW);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}

				if (i == PMR_CONTEXT_PMRR) { /* PMMR */
					/* Invoke VEDL API */
                                        ret = vedl_set_usr_reg(core_regs,
						VE_USR_PMMR, user_regs->PMMR);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}

				if ((i >= PMR_CONTEXT_PMCR0) && (i <= PMR_CONTEXT_PMCR3)) { /* PMCR00-03 */
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(core_regs,
							VE_USR_PMCR00 + (i-2),
							user_regs->PMCR[i-2]);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}
				if (i >= PMR_CONTEXT_PMCR4) { /* PMC00-15 && PMC16-20*/
					/* Invoke VEDL API */
					int pmc_id = 0;
					if (i < PMR_CONTEXT_PMC16)
						pmc_id = VE_USR_PMC00 + i-PMR_CONTEXT_PMCR4;
					else if (i < PMR_CONTEXT_LOOP_VE3)
						pmc_id = VE_USR_PMC16 + i- PMR_CONTEXT_PMC16;

					ret = vedl_set_usr_reg(core_regs,
						//	VE_USR_PMC00 + (i-6),
							pmc_id,
							user_regs->PMC[i-PMR_CONTEXT_PMCR4]);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}
			}
		}
	}
	VEOS_TRACE("Exiting");
	return;
abort:
	pthread_mutex_lock_unlock(&task->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release thread group lock");
	veos_abort("Setting context failed");
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_context_from_task_to_core, ve3_psm_set_context)

/**
* @brief Set the JID and DID of VE process on VE core JIDR and
* DIDR registers of VE core
*
* @param tsk Pointer to VE task struct
*
* @return 0 on success and -1 on failure.
*/
int ve3_psm_set_jdid(struct ve_task_struct *tsk)
{
	int retval = -1;

	VEOS_TRACE("Entering");
	/* Set JIDR register */
	VEOS_DEBUG("Set JID %u to core %d",
			tsk->jid, tsk->core_id);
	retval = vedl_set_sys_reg(VE_CORE_SYS_REG(0, tsk->core_id),
			VE_SYS_JIDR, tsk->jid);
	if (0 > retval) {
		VEOS_ERROR("Setting JID %d failed for task %d",
				tsk->jid, tsk->pid);
		retval = -1;
		goto set_jdid_fail;
	}

	/* Set DIDR register */
	VEOS_DEBUG("Set DID %ld to core %d",
			tsk->did, tsk->core_id);
	retval = vedl_set_sys_reg(VE_CORE_SYS_REG(0, tsk->core_id),
			VE_SYS_DIDR, tsk->did);
	if (0 > retval) {
		VEOS_ERROR("Setting DID failed");
		retval = -1;
		goto set_jdid_fail;
	}

	retval = 0;
set_jdid_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_jdid_from_task_to_core, ve3_psm_set_jdid)

int ve3_psm_get_EXS(int core_id, ve_reg_t *exsp)
{
	return vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS, exsp);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_core_execution_status, ve3_psm_get_EXS)

int ve3_psm_set_EXS_STOP(int core_id)
{
	return vedl_set_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS,
				EXS_STOP);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_request_core_to_stop, ve3_psm_set_EXS_STOP)

int ve3_psm_check_EXS_stopped(ve_reg_t exs)
{
	return (exs & EXS_STOPPING) == EXS_STOP;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_check_core_status_is_stopped, ve3_psm_check_EXS_stopped)

int ve3_psm_set_EXS_RUN(int core_id)
{
	return vedl_set_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS,
				EXS_RUN);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_request_core_to_start, ve3_psm_set_EXS_RUN)

int ve3_psm_check_EXS_running(ve_reg_t exs)
{
	return (exs & EXS_RUN);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_check_core_status_is_running, ve3_psm_check_EXS_running)

int ve3_psm_set_dmajid(struct ve_task_struct *tts)
{
	int retval = -1;
	uint64_t offset_pack, offset_jidr;

	offset_pack = offsetof(ve3_system_common_reg_nonpre_t,
					DMACTL_PACK[*(tts->core_dma_desc)]);

	offset_jidr = offsetof(struct ve3_dma_control_pack, DMAJIDR[0]);
	retval = vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
			offset_pack + offset_jidr, tts->jid);
	if (0 > retval) {
		VEOS_ERROR("Setting DMAJID %d [#0] failed for task %d",
				tts->jid, tts->pid);
		goto set_jdid_fail;
	}

	offset_jidr = offsetof(struct ve3_dma_control_pack, DMAJIDR[1]);
	retval = vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
			offset_pack + offset_jidr, tts->jid);
	if (0 > retval) {
		VEOS_ERROR("Setting DMAJID %d [#1] failed for task %d",
				tts->jid, tts->pid);
	}
set_jdid_fail:
	return retval;
}

inline int find_dma_desc()
{
	uint8_t count = 0;
	uint32_t bitmap = VE_NODE(0)->free_udma_bitmap;
	uint32_t num = (~bitmap & (bitmap+1));
	if ((uint32_t)bitmap == UINT_MAX)
		return -1;
	while(num>>=1) count++;
	return count;
}

int ve3_psm_restore_context_for_new_thread(struct ve_task_struct *tts)
{
	int retval = -1;
	int udma_desc_id = -1;

	VEOS_TRACE("Entering");
	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), LOCK,
			"Failed to acquire udma bitmap lock");
	udma_desc_id = find_dma_desc();
	if (udma_desc_id == -1) {
		pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock),
				UNLOCK,
				"Failed to release udma bitmap mutex lock");
		VEOS_ERROR("Error getting valid free udma descriptor index");
		veos_abort("Failed to get free udma descriptor index");
	}
	*(tts->core_dma_desc) = udma_desc_id;
	SET_BIT(VE_NODE(0)->free_udma_bitmap, udma_desc_id);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), UNLOCK,
			"Failed to release udma bitmap mutex lock");
	VEOS_DEBUG("Found free udma descriptor id:%d for pid:%d",
						udma_desc_id, tts->pid);

	VEOS_DEBUG("Restore CR");
	if (veos_restore_cr(tts)) {
		VEOS_ERROR("Restoring CR failed");
		goto restore_context_failed;
	}
	/* Schedule in DMAATB */
	VEOS_DEBUG("Schedule in DMAATB");
	if (veos_schedulein_dmaatb(tts)) {
		VEOS_ERROR("Schedule in DMAATB failed");
		retval = -1;
		goto restore_context_failed;
	}
	VEOS_DEBUG("Set DMAATB context, udma descriptor id:%d for pid:%d",
						udma_desc_id, tts->pid);
	if (veos_update_dmaatb_context(tts, udma_desc_id)) {
		VEOS_ERROR("Update DMAATB context failed in VEOS");
		goto restore_context_failed;
	}

	/* Restore UDMA */
	VEOS_DEBUG("Restore udma context, udma descriptor id:%d for pid:%d",
						udma_desc_id, tts->pid);
	if (psm_restore_udma_context(tts, udma_desc_id)) {
		VEOS_ERROR("Restoring UDMA context failed");
		goto restore_context_failed;
	}
	/* Set the DMAJIDR[] register pair (for both H and E) */
	VEOS_DEBUG("Set the DMAJIDR[] register pair for H and E");
	if (ve3_psm_set_dmajid(tts)) {
		VEOS_ERROR("Setting  DMAJID register pair failed");
		goto restore_context_failed;
	}
	/* Start UDMA */
	VEOS_DEBUG("Start UDMA");
	if (psm_start_udma(udma_desc_id, tts->p_ve_mm->udma_desc_bmap)) {
		VEOS_DEBUG("Start UDMA failed");
		goto restore_context_failed;
	}

	retval = 0;
restore_context_failed:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_restore_context_for_new_thread, ve3_psm_restore_context_for_new_thread)

/**
* @brief This function stops udma, saves the udma context and then frees
* the mapped DMAATB dir entry.
*
* @param curr_ve_task Pointer to current VE task struct
*
* @return 0 on success and -1 on failure
*/
static int psm_process_udma_context(struct ve_task_struct *curr_ve_task)
{
	int retval = -1;

	VEOS_TRACE("Entering");

	/* don't proceed if udma desc is not mapped. */
	if (*(curr_ve_task->core_dma_desc) == -1)
		return 0;

	/* Stop udma */
	if (psm_stop_udma(*(curr_ve_task->core_dma_desc),
			curr_ve_task->p_ve_mm->udma_desc_bmap)) {
		VEOS_ERROR("Stopping user DMA failed");
		goto save_context_fail;
	}
	VEOS_DEBUG("User DMA Halted");

	/* Save UDMA context */
	if (psm_save_udma_context(curr_ve_task,
				*(curr_ve_task->core_dma_desc))) {
		VEOS_ERROR("Saving user DMA context failed");
		goto save_context_fail;
	}
	VEOS_DEBUG("UDMA saved successfully");

	/* AMM free DMAATB dir entry */
	if (veos_scheduleout_dmaatb(curr_ve_task)) {
		VEOS_ERROR("Scheduling out DMAATB failed");
		goto save_context_fail;
	}

	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), LOCK,
			"Failed to acquire udma bitmap lock");
	CLEAR_BIT(VE_NODE(0)->free_udma_bitmap, *(curr_ve_task->core_dma_desc));
	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), UNLOCK,
			"Failed to release udma bitmap lock");
	VEOS_DEBUG("Freed DMAATB dir entry udma descriptor id %d successfully",
				*(curr_ve_task->core_dma_desc));
	/* core_dma_desc reset */
	VEOS_DEBUG("Reset Core DMA descriptor flag");
	*(curr_ve_task->core_dma_desc) = -1;


	/* AMM save CR page and free it */
	if (veos_save_cr(curr_ve_task)) {
		VEOS_ERROR("Saving CR page failed");
		goto save_context_fail;
	}
	VEOS_DEBUG("Saved CR page");
	retval = 0;

save_context_fail:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
* @brief Check and performs DMA migration if required.
*
* Function checks if the current task cores DMA descriptor table is mapped
* to VEHVA
* If core DMA descriptor is mapped then function checks if any thread of
* current VE task is executingon any other VE core.
* If some other thread of same thread group is running then DMA
* migration is performed, else DMA is halted and context is saved.
*
* @param curr_ve_task Pointer to current VE task struct
*
* @return 0 on success, abort veos on failure.
*/
int ve3_psm_process_dma_management(struct ve_task_struct* curr_ve_task)
{
	int tsd = -1;
	int retval = -1;

	VEOS_TRACE("Entering");

	/* Check the whether other thread of same thread group is executing */
	tsd = *(curr_ve_task->thread_sched_count);

	VEOS_DEBUG("THREAD_SCHED_COUNT %d PID %d", tsd, curr_ve_task->pid);

	if (tsd == 0) {
		/* No other thread of thread group is executing, process the
		 * udma context information in order to save it */
		VEOS_DEBUG("No other thread of PID %d is running",
				curr_ve_task->pid);
		if (psm_process_udma_context(curr_ve_task)) {
			VEOS_ERROR("No DMA migration failed");
			goto dma_migration_fail;
		}
	} else if (tsd > 0) {
		/* Other thread of thread group are executing */
		VEOS_DEBUG("Some other threads of PID %d are executing "
				"DMA management not required",
				curr_ve_task->pid);
	} else {
		/* Normally this should never happen. If this happens then
		 * there is inconsistency while updating "thread_sched_count".
		 */
		VEOS_DEBUG("THREAD_SCHED_COUNT is %d for PID %d",
				tsd, curr_ve_task->pid);
		goto dma_migration_fail;
	}

	VEOS_TRACE("Exiting");
	retval = 0;
	return retval;
dma_migration_fail:
	veos_abort("VEOS aborting due to failure of DMA migration");
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_process_dma_resource, ve3_psm_process_dma_management)

/**
 * @brief Stop User level DMA
 *
 * Function stops the operation status of DMA descriptor table H and E
 * depending on the argument "udma_desc_bmap" received
 *
 * @param[in] core_id VE core ID
 * @param[in] udma_desc_bmap Specifies DMA corresponding to which DMA
 * descriptor table needs to be stopped
 *
 * @return 0 on success and -1 on failure
 */
int ve3_psm_stop_udma(int udma_desc_id, uint8_t udma_desc_bmap)
{
	int retval = -1;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");

	regdata = VE_UDMA_CTL_PERM_STOP;

	if (udma_desc_bmap & DMA_DESC_H) {
		/* Stop DMA operation on DMA decriptor H */
		VEOS_DEBUG("Unset H DMACTL permission bit of "
					"udma desc id :%d", udma_desc_id);
		retval = vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0),
				LIBVED_VE3_AREA_BAR4,
				VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
					VE_UDMA_HENTRY), regdata);
		if (0 > retval) {
			VEOS_ERROR("Unsetting H DMACTL permission bit failed");
			goto stop_udma_fail;
		}
	}

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Stop DMA operation on DMA decriptor E */
		VEOS_DEBUG("Unset E DMACTL permission bit of "
					"udma desc id :%d", udma_desc_id);
		retval = vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0),
				LIBVED_VE3_AREA_BAR4,
				VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
					VE_UDMA_EENTRY), regdata);
		if (0 > retval) {
			VEOS_ERROR("Unsetting permission bit failed");
			goto stop_udma_fail;
		}
	}

	regdata = 0;

	if (udma_desc_bmap & DMA_DESC_H) {
		/* Wait for raising halt bit of DMA control reg
		 * corresponding to DMA descriptor table H
		 * */
		do {
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_H "
					"udma desc id :%d", udma_desc_id);
			retval = vedl_get_cnt_reg_word(VE_NODE_CNT_REG(0),
					LIBVED_VE3_AREA_BAR4,
					VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
						VE_UDMA_HENTRY), &regdata);
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for udma descriptor id %d", udma_desc_id);
				goto stop_udma_fail;
			}
		} while (!(regdata & 0x2));
	}

	regdata = 0;

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Wait for raising halt bit of DMA control reg
		 * corresponding to DMA descriptor table E
		 * */
		do {
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_E "
					"udma desc id :%d", udma_desc_id);
			retval = vedl_get_cnt_reg_word(VE_NODE_CNT_REG(0),
					LIBVED_VE3_AREA_BAR4,
					VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
						VE_UDMA_EENTRY), &regdata);
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for udma descriptor id %d", udma_desc_id);
				goto stop_udma_fail;
			}
		} while (!(regdata & 0x2));
	}

	retval = 0;
	VEOS_DEBUG("UDMA descriptor id %d stopped", udma_desc_id);
stop_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_stop_udma, ve3_psm_stop_udma)

/**
* @brief Start user level DMA
*
* Function sets the permission bit of DMA control register
*
* @param[in] core_id VE core ID
* @param[in] udma_desc_bmap Specifies DMA corresponding to which DMA
* descriptor table needs to be started
*
* @return 0 on success and -1 on failure.
*/
int ve3_psm_start_udma(int udma_desc_id, uint8_t udma_desc_bmap)
{
	int retval = -1;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");
	regdata = VE_UDMA_CTL_PERM_START;

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Set permission bit to start operation on
		 * DMA descriptor table E */
		if (vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0),
			LIBVED_VE3_AREA_BAR4,
			VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
					VE_UDMA_EENTRY), regdata)) {
			VEOS_ERROR("Setting permission bit failed for E entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for E entry of udma "
						"descriptor id %d", udma_desc_id);
		}
	}
	if (udma_desc_bmap & DMA_DESC_H) {
		/* Set permission bit to start operation on
		 * DMA descriptor table H */
		if (vedl_set_cnt_reg_word(VE_NODE_CNT_REG(0),
			LIBVED_VE3_AREA_BAR4,
			VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id,
						VE_UDMA_HENTRY), regdata)) {
			VEOS_ERROR("Setting permission bit failed for H entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for H entry of udma "
						"descriptor id %d", udma_desc_id);
		}
	}
	retval = 0;
start_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_start_udma, ve3_psm_start_udma)

/**
* @brief Saves core's user DMA descriptor tables and DMA control register
* corresponding to H or E depending upon the argument received.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
* @param[in] dma_entry_type Identifier for type of DMA descriptor table
*
* @return 0 on sucess and -1 on failure
*/
int ve3__psm_save_udma_context(struct ve_task_struct *ve_task,
		int udma_desc_id, int dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");

	/* Save DMA descriptor table */
	if (vedl_get_cnt_reg_words(VE_NODE_CNT_REG(ve_task->node_id),
		LIBVED_VE3_AREA_BAR4,
		VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, dma_entry_type),
		&(TO_VE3_UDMA(ve_task->udma_context)->dmades[dma_entry_type]),
		sizeof(ve3_dma_desc_t) * VE3_DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Saving DMA descriptor table failed");
		goto __save_udma_fail;
	}

	/* Save DMA control register */
	if (vedl_get_cnt_reg_words(VE_NODE_CNT_REG(0),
		LIBVED_VE3_AREA_BAR4,
		VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id, dma_entry_type),
		&(TO_VE3_UDMA(ve_task->udma_context)->dmactl[dma_entry_type]),
		sizeof(ve3_dma_control_t))) {
		VEOS_ERROR("Saving DMA control register failed");
		goto __save_udma_fail;
	}
	retval = 0;
__save_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch__psm_save_udma_context, ve3__psm_save_udma_context)

/**
* @brief Restores user DMA descriptor tables and control register
* saved in ve_task_struct to specified core's register.
*
* @param[in] ve_task Pointer to VE task struct
* @param[in] core_id VE core ID
* @param[in] dma_entry_type Identifier for type of DMA descriptor table
*
* @return 0 on success and -1 on failure
*/
int ve3__psm_restore_udma_context(struct ve_task_struct *ve_task,
		int udma_desc_id, int dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");
	/* Set the UDMA descriptors table to core */
	if (vedl_set_cnt_reg_words(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
		VE3_UDMA_OFFSET_OF_DMADESC(udma_desc_id, dma_entry_type),
		&(TO_VE3_UDMA(ve_task->udma_context)->dmades[dma_entry_type]),
		sizeof(ve3_dma_desc_t) * VE3_DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Restoring DMA descriptor table failed");
		goto __restore_dma_fail;
	}

	/* Set the UDMA control register to core */
	if (vedl_set_cnt_reg_words(VE_NODE_CNT_REG(0), LIBVED_VE3_AREA_BAR4,
		VE3_UDMA_OFFSET_OF_DMACTL(udma_desc_id, dma_entry_type),
		&(TO_VE3_UDMA(ve_task->udma_context)->dmactl[dma_entry_type]),
		sizeof(ve3_dma_control_t))) {
		VEOS_ERROR("Restoring DMA control registers failed");
		goto __restore_dma_fail;
	}
	VEOS_DEBUG("Successfully restored DMA descriptors/control registers");
	retval = 0;
__restore_dma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve3, arch__psm_restore_udma_context, ve3__psm_restore_udma_context)

int ve3_psm_restore_context_to_core_regs(struct ve_core_struct *p_ve_core, pid_t veos_pid,
				struct ve_thread_struct *p_ve_thread)
{
	ve_dma_status_t dmast;
	int phys_core_id = p_ve_core->phys_core_num;
	dmast = ve_dma_xfer_p_va(VE_NODE(0)->dh, VE_DMA_VHVA, veos_pid,
			(uint64_t)p_ve_thread->arch_user_regs,
			VE3_DMA_VERAA_PREFETCHABLE, 0,
			VE3_PSM_CTXSW_CREG_VERAA(phys_core_id),
			VE3_PSM_CTXSW_CREG_SIZE);
	if (dmast != VE_DMA_STATUS_OK) {
		VEOS_DEBUG("Setting user registers on BAR23 failed");
		return -1;
	}
	if (vedl_set_usr_reg(VE_CORE_USR_REG(0, p_ve_core->core_num), VE_USR_EXS,
				p_ve_thread->EXS) != 0) {
		VEOS_DEBUG("Setting EXS failed");
		return -1;
	}
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_restore_all_context_to_core_regs, ve3_psm_restore_context_to_core_regs)


/* wrap vedl_ve3_update_dmaatb_dir() */
int ve3_psm_update_dmaatb_dir(vedl_common_reg_handle *creg,
			const veos_dmaatb_reg_t *regs, int count)
{
	return vedl_ve3_update_dmaatb_dir(creg, (ve3_dmaatb_reg_t *)regs,
						count);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_update_dmaatb_dir, ve3_psm_update_dmaatb_dir)

size_t ve3_psm_context_size(void)
{
	return VE3_PSM_CTXSW_CREG_SIZE;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_context_size, ve3_psm_context_size)

void ve3_veos_clear_udma(int core_num)
{
	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), LOCK,
			"Failed to acquire udma bitmap lock");
	CLEAR_BIT(VE_NODE(0)->free_udma_bitmap, core_num);
	pthread_mutex_lock_unlock(&(VE_NODE(0)->udma_bitmap_lock), UNLOCK,
			"Failed to release udma bitmap lock");
	VEOS_DEBUG("Freed DMAATB dir entry udma descriptor id %d successfully",
			core_num);
	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_veos_clear_udma, ve3_veos_clear_udma)

void ve3_psm_wait_for_delayed_VLFA_exception(bool should_vlfa_wait,
				struct ve_task_struct *curr_ve_task)
{
	struct timespec ts = {0}, rem = {0};
	ts.tv_nsec = 400;
	if (curr_ve_task == NULL)
		return;
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock), LOCK,
					"Failed to acquire task lock");
	if (curr_ve_task->vlfa_wait == true
			|| should_vlfa_wait == false)
		goto handle_return;
wait_again:
	nanosleep(&ts, &rem);
	if (rem.tv_nsec != 0) {
		ts.tv_nsec = rem.tv_nsec;
		rem.tv_nsec = 0;
		goto wait_again;
	}
	if (psm_unassign_assign_task(curr_ve_task, true))
		curr_ve_task->vlfa_wait = true;
handle_return:
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock), UNLOCK,
					"Failed to release task lock");
	return;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_wait_for_delayed_VLFA_exception, ve3_psm_wait_for_delayed_VLFA_exception)

void ve3_psm_set_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
					LOCK, "Failed to acquire task lock");
	if (curr_ve_task->vlfa_wait == false)
		curr_ve_task->vlfa_wait = true;
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
					UNLOCK, "Failed to release task lock");
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_vlfa_wait, ve3_psm_set_vlfa_wait)

void ve3_psm_clear_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
					LOCK, "Failed to acquire task lock");
	if (curr_ve_task->vlfa_wait == true)
		curr_ve_task->vlfa_wait = false;
	pthread_mutex_lock_unlock(&(curr_ve_task->ve_task_lock),
					UNLOCK, "Failed to release task lock");
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_clear_vlfa_wait, ve3_psm_clear_vlfa_wait)

bool ve3_psm_get_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	return curr_ve_task->vlfa_wait;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_get_vlfa_wait, ve3_psm_get_vlfa_wait)

void ve3_psm_update_pwr_throttle(int core_id, bool ctx_switch)
{
	int retval = 0;
	ve_reg_t PMC_val = 0;
	struct ve_core_struct *p_ve_core = NULL;
	ve_reg_t pmmr_mode = 0;
	uint64_t diff = 0;
	p_ve_core = VE_CORE(0,core_id);

	retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id),
						VE_USR_PMMR, &pmmr_mode);
	if (retval != 0) {
		VEOS_DEBUG("Failed to get register PMMR, returned %d", retval);
		return;
	}
	pmmr_mode =  (pmmr_mode & (PMMR_SHIFT >> 56));

	/* Check Power Throttling occured only if PMMR mode is Zero*/
	if(pmmr_mode != 0)
		return;

	retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_PMC14, &PMC_val);
	if (retval != 0) {
		VEOS_DEBUG("Failed to get register PMC14, returned %d", retval);
		return;
	}
	p_ve_core->current_PMC14 = PMC_val & PMC_MAX_VAL;
	if(ctx_switch)
		p_ve_core->previous_PMC14 = PMC_val & PMC_MAX_VAL;

	diff = (p_ve_core->current_PMC14 - p_ve_core->previous_PMC14)
								& PMC_MAX_VAL;
	if (first_power_throttling_occured == false
			&& p_ve_core->pwr_throttle_cnt == 0
			&& diff != 0) {
#ifdef SHOW_POWER_THROTTLING
		syslog(LOG_INFO,
			"Power throttling occurred Core %02d %ld",
			core_id, diff);
#endif
		first_power_throttling_occured = true;
		p_ve_core->pwr_throttle_cnt = 0;
		p_ve_core->previous_PMC14 = p_ve_core->current_PMC14;
		return;
	}
	p_ve_core->pwr_throttle_cnt += diff;
	p_ve_core->previous_PMC14 = p_ve_core->current_PMC14;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_update_pwr_throttle, ve3_psm_update_pwr_throttle)
void ve3_psm_log_pwr_throttle(int core_id, bool log_power_throttling)
{
	struct ve_core_struct *p_ve_core = NULL;
	ve_reg_t pmmr_mode = 0;
	int retval = 0;

	p_ve_core = VE_CORE(0,core_id);

	retval = vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id),
						VE_USR_PMMR, &pmmr_mode);
	if (retval != 0) {
		VEOS_DEBUG("Failed to get register PMMR, returned %d", retval);
		return;
	}
	pmmr_mode =  (pmmr_mode & (PMMR_SHIFT >> 56));

	/* Check Power Throttling occured only if PMMR mode is Zero*/
	if(pmmr_mode != 0)
		return;
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), WRLOCK,
					"Failed to acquire Core %d read lock",
					p_ve_core->core_num);
	ve3_psm_update_pwr_throttle(core_id, false);

	if(log_power_throttling == true && p_ve_core->pwr_throttle_cnt > 0) {
#ifdef SHOW_POWER_THROTTLING
		syslog(LOG_INFO,"Power throttling occurred Core %02d %ld",
					core_id, p_ve_core->pwr_throttle_cnt);
#endif
		p_ve_core->pwr_throttle_cnt = 0;
	}
	pthread_rwlock_lock_unlock(&(p_ve_core->ve_core_lock), UNLOCK,
					"Failed to release Core %d read lock",
					p_ve_core->core_num);

}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_log_pwr_throttle, ve3_psm_log_pwr_throttle)
