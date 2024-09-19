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
 * @brief VE1-depenent part of Scheduler functionality.
 *
 * @author PSMG / Scheduling and context switch
 */

#include <ve_drv.h>
#include <ve_hw.h>
#include <libved.h>
#include <libved_ve1.h>

#include <veos_arch_defs.h>

#include <veos.h>
#include <dma.h>
#include <dma_ve1.h>

#include <udma_ve1.h>

#include <ve_mem_ve1.h>

#include <task_sched.h>
#include <dmaatb_api.h>
#include <mm_common.h>

#include "task_sched_ve1.h"

#define VE1_PSM_CTXSW_CREG_VERAA(phys_core_id_) \
		(VEDRV_VE1_PCI_BAR2_CREG_SIZE * (phys_core_id_))
#define VE1_PSM_CTXSW_CREG_SIZE (offsetof(ve1_core_user_reg_t, VR) + \
		sizeof(((ve1_core_user_reg_t *)NULL)->VR))
/**
 * @brief Save context from VE core
 *
 * @param dh DMA handle
 * @param phys_core_id physical core ID to save
 * @param veos_pid Process ID of destination
 * @param buffer destination to store context
 */
int ve1_save_context_from_core_reg(ve_dma_hdl *dh, int phys_core_id,
			pid_t veos_pid, void *buffer)
{
	return ve_dma_xfer_p_va(dh, VE1_DMA_VERAA, 0,
			VE1_PSM_CTXSW_CREG_VERAA(phys_core_id), VE_DMA_VHVA,
			veos_pid, (uintptr_t)buffer, VE1_PSM_CTXSW_CREG_SIZE);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_save_context_from_core_reg, ve1_save_context_from_core_reg);

/*
* @brief Function sets the updated register value on core
*
* @param task Pointer to VE task struct
*/
void ve1_psm_set_context(struct ve_task_struct *task)
{
	int i = 0;
	int ret = -1;
	vedl_user_reg_handle *core_regs = VE_CORE_USR_REG(0, task->core_id);
	ve1_core_user_reg_t *user_regs = task->p_ve_thread->arch_user_regs;

	VEOS_TRACE("Entering");
	if (task->sr_context_bitmap) {
		for (i = 0; i < VE1_SR_NUM; i++) {
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
		for (i = 0; i < 22; i++) {
			if (GET_BIT(task->pmr_context_bitmap, i)) {
				if (i == 0) { /* PSW */
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(core_regs,
						VE_USR_PSW, user_regs->PSW);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}

				if (i == 1) { /* PMMR */
					/* Invoke VEDL API */
                                        ret = vedl_set_usr_reg(core_regs,
						VE_USR_PMMR, user_regs->PMMR);
					if (ret) {
						VEOS_DEBUG("Setting context returned %d for PID %d",
							ret, task->pid);
						goto abort;
					}
				}

				if ((i >= 2) && (i <= 5)) { /* PMCR00-03 */
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
				if (i >= 6) { /* PMC00-15 */
					/* Invoke VEDL API */
					ret = vedl_set_usr_reg(core_regs,
							VE_USR_PMC00 + (i-6),
							user_regs->PMC[i-6]);
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
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_context_from_task_to_core, ve1_psm_set_context)

/**
* @brief Set the JID and DID of VE process on VE core JIDR and
* DIDR registers of VE core
*
* @param tsk Pointer to VE task struct
*
* @return 0 on success and -1 on failure.
*/
int ve1_psm_set_jdid(struct ve_task_struct *tsk)
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
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_jdid_from_task_to_core, ve1_psm_set_jdid)

int ve1_psm_get_EXS(int core_id, ve_reg_t *exsp)
{
	return vedl_get_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS, exsp);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_core_execution_status, ve1_psm_get_EXS)

int ve1_psm_set_EXS_STOP(int core_id)
{
	return vedl_set_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS,
				EXS_STOP);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_request_core_to_stop, ve1_psm_set_EXS_STOP)

int ve1_psm_check_EXS_stopped(ve_reg_t exs)
{
	return (exs & EXS_STOPPING) == EXS_STOP;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_check_core_status_is_stopped, ve1_psm_check_EXS_stopped)

int ve1_psm_set_EXS_RUN(int core_id)
{
	return vedl_set_usr_reg(VE_CORE_USR_REG(0, core_id), VE_USR_EXS,
				EXS_RUN);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_request_core_to_start, ve1_psm_set_EXS_RUN)

int ve1_psm_check_EXS_running(ve_reg_t exs)
{
	return (exs & EXS_RUN);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_check_core_status_is_running, ve1_psm_check_EXS_running)

int ve1_psm_restore_context_for_new_thread(struct ve_task_struct *tts)
{
       int retval = -1;

       VEOS_TRACE("Entering");
       VEOS_DEBUG("Restore CR");

       retval = veos_restore_cr(tts);
       if (0 > retval) {
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

       VEOS_DEBUG("Set DMAATB context");
       if (veos_update_dmaatb_context(tts, tts->core_id)) {
               VEOS_ERROR("Update DMAATB context failed in VEOS");
               retval = -1;
               goto restore_context_failed;
       }

       *(tts->core_dma_desc) = tts->core_id;
       VEOS_DEBUG("Core DMA descriptor set to %d",
                       *(tts->core_dma_desc));

       /* Restore UDMA */
       VEOS_DEBUG("Restore udma context");
       retval = psm_restore_udma_context(tts, tts->core_id);
       if (retval) {
               VEOS_ERROR("Restoring UDMA context failed");
               goto restore_context_failed;
       }

       /* Start UDMA */
       VEOS_DEBUG("Start UDMA");
       retval = psm_start_udma(tts->core_id,
                       tts->p_ve_mm->udma_desc_bmap);
       if (retval) {
               VEOS_DEBUG("Start UDMA failed");
               goto restore_context_failed;
       }
       retval = 0;
restore_context_failed:
       VEOS_TRACE("Exiting");
       return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_restore_context_for_new_thread, ve1_psm_restore_context_for_new_thread)

/**
* @brief Check core's DMA is mapped to VEHVA and save DMA context
*
* Function check if core's DMA is mapped to VEHVA. If DMA is mapped then
* DMA is halted and DMA descriptor table is saved.
*
* @param curr_ve_task Pointer to current VE task struct
*
* @return 0 on success and -1 on failure
*/
static int psm_udma_no_migration(struct ve_task_struct *curr_ve_task)
{
	int retval = -1;

	VEOS_TRACE("Entering");
	/* Check if core's DMA is mapped to VEHVA */
	if (psm_check_udma_desc(curr_ve_task)) {
		/* core_dma_desc reset */
		VEOS_DEBUG("Reset Core DMA descriptor flag");
		*(curr_ve_task->core_dma_desc) = -1;

		/* Stop udma */
		if (psm_stop_udma(curr_ve_task->core_id,
					curr_ve_task->p_ve_mm->udma_desc_bmap)) {
			VEOS_ERROR("Stopping user DMA failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("User DMA Halted");

		/* Save UDMA context */
		if (psm_save_udma_context(curr_ve_task,
					curr_ve_task->core_id)) {
			VEOS_ERROR("Saving user DMA context failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("UDMA saved successfully");

		/* AMM free DMAATB dir entry */
		if (veos_scheduleout_dmaatb(curr_ve_task)) {
			VEOS_ERROR("Scheduling out DMAATB failed");
			goto save_context_fail;
		}
		VEOS_DEBUG("Freed DMAATB dir entry successfully");
	}

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
* @brief Find core for DMA migration and perform DMA migration.
*
* Function finds the eligible core from core bitmap where DMA
* can be migrated.
* Function stops the DMA on current core, saves DMA descriptor table.
* Functions set the DMA and restore the DMA descriptor table entry
* on new core
*
* @param curr_ve_task Pointer to current VE task struct
* @param core_bitmap_set Bitmap representing core executing threads
* of same thread group
*
* @return 0 on success and -1 on failure
*/
static int psm_udma_do_migration(struct ve_task_struct *curr_ve_task,
		uint64_t core_bitmap_set)
{
	int migrate_core_id = -1;
	int core_loop = 0;
	int retval = -1;
	struct ve_task_struct *chk_ve_tsk = NULL;

	VEOS_TRACE("Entering");
	/* Find migrate core id*/
	migrate_core_id = ffsl(core_bitmap_set) - 1;

	VEOS_DEBUG("Migrate core ID %d",
			migrate_core_id);
	/* Stop udma on current core*/
	if (psm_stop_udma(curr_ve_task->core_id,
				curr_ve_task->p_ve_mm->udma_desc_bmap)) {
		VEOS_ERROR("Stopping UDMA failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA halted");

	/* Save UDMA context */
	if (psm_save_udma_context(curr_ve_task,
				curr_ve_task->core_id)) {
		VEOS_ERROR("Saving UDMA context failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA saved successfully");

	/* Update core_dma_desc to migrated core id */
	*(curr_ve_task->core_dma_desc) = migrate_core_id;
	VEOS_DEBUG("Core DMA descriptor set to %d",
			*(curr_ve_task->core_dma_desc));

	VEOS_DEBUG("Invoking veos_update_dmaatb_context()");
	if (veos_update_dmaatb_context(curr_ve_task, migrate_core_id)) {
		VEOS_ERROR("Updating DMA context failed");
		goto udma_migration_fail;
	}

	/* Migrate DMA on new core ID */
	if (psm_restore_udma_context(curr_ve_task, migrate_core_id)) {
		VEOS_ERROR("Restoring DMA context failed");
		goto udma_migration_fail;
	}
	VEOS_DEBUG("UDMA restored successfully on new core");

	if (psm_start_udma(migrate_core_id,
				curr_ve_task->p_ve_mm->udma_desc_bmap)) {
		VEOS_ERROR("Start UDMA failed");
		goto udma_migration_fail;
	}

	/* Start all core of core_set */
	for (; core_loop < VE_NODE(0)->nr_avail_cores; core_loop++) {
		if (CHECK_BIT(core_bitmap_set, core_loop)) {
			chk_ve_tsk = VE_CORE(0, core_loop)->curr_ve_task;
			if (chk_ve_tsk && chk_ve_tsk->atb_dirty){
				VEOS_DEBUG("ATB is dirty, so the core "
					"won't start:%d,%d,0x%lx,%s", core_loop,
					chk_ve_tsk->pid, chk_ve_tsk->atb_dirty,
					__func__);
				SET_CORE_STATE(VE_CORE(0, core_loop)
						->ve_core_state, STOPPED);
			}else{
				psm_start_ve_core(0, core_loop);
			}
			SET_SCHED_STATE(VE_CORE(0, core_loop)->scheduling_status,
					COMPLETED);
		}
	}
	retval = 0;
udma_migration_fail:
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
int ve1_psm_process_dma_migration(struct ve_task_struct* curr_ve_task)
{
	int tsd = -1;
	int retval = -1;
	uint64_t core_set = 0;
	ve_reg_t *exception_arr = NULL;

	VEOS_TRACE("Entering");

	/* Check the whether other thread of same thread group is executing */
	tsd = *(curr_ve_task->thread_sched_count);

	exception_arr = (ve_reg_t *)malloc(
			VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));
	if (!exception_arr) {
		VEOS_CRIT("Internal Memory allocation failed");
		goto dma_migration_fail;
	}

	memset(exception_arr, 0, VE_NODE(0)->nr_avail_cores * sizeof(ve_reg_t));

	VEOS_DEBUG("THREAD_SCHED_COUNT %d PID %d",
			tsd, curr_ve_task->pid);

	if (tsd == 0) {
		/* No other thread of thread group is executing */
		VEOS_DEBUG("No other thread of PID %d is running",
				curr_ve_task->pid);
		if (psm_udma_no_migration(curr_ve_task)) {
			VEOS_ERROR("No DMA migration failed");
			goto dma_migration_fail;
		}
	} else if (tsd > 0) {
		/* Other thread of thread group are executing */
		VEOS_DEBUG("Some other threads of PID %d are executing",
				curr_ve_task->pid);
		if (psm_check_udma_desc(curr_ve_task)) {
			/* Core DMA desc is mapped to VEHVA */
			if (psm_check_sched_jid_core(&core_set,
						curr_ve_task, REG_INVAL, exception_arr)) {
				VEOS_DEBUG("Initiate DMA migration");
				if (psm_udma_do_migration(curr_ve_task, core_set)) {
					VEOS_DEBUG("UDMA migration failed");
					goto dma_migration_fail;
				}
			} else {
				VEOS_DEBUG("No DMA migration, Save context");
				if (psm_udma_no_migration(curr_ve_task)) {
					VEOS_DEBUG("No DMA migration failed");
					goto dma_migration_fail;
				}
			}
		}
	} else {
		/* Normally this should never happen. If this happens then
		 * there is inconsistency while updating "thread_sched_count".
		 */
		VEOS_DEBUG("THREAD_SCHED_COUNT is %d for PID %d",
				tsd, curr_ve_task->pid);
		goto dma_migration_fail;
	}

	retval = 0;
	free(exception_arr);
	VEOS_TRACE("Exiting");
	return retval;
dma_migration_fail:
	veos_abort("VEOS aborting due to failure of DMA migration");
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_process_dma_resource, ve1_psm_process_dma_migration)

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
int ve1_psm_stop_udma(int core_id, uint8_t udma_desc_bmap)
{
	int retval = -1;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");

	regdata = VE_UDMA_CTL_PERM_STOP;

	if (udma_desc_bmap & DMA_DESC_H) {
		/* Stop DMA operation on DMA decriptor H */
		VEOS_DEBUG("Unset H DMACTL permission bit");
		retval = vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id),
				0, VE1_UDMA_OFFSET_OF_DMACTL(VE_UDMA_HENTRY),
				&regdata, sizeof(regdata));
		if (0 > retval) {
			VEOS_ERROR("Unsetting H DMACTL permission bit failed");
			goto stop_udma_fail;
		}
	}

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Stop DMA operation on DMA decriptor E */
		VEOS_DEBUG("Unset E DMACTL permission bit");
		retval = vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id),
				0, VE1_UDMA_OFFSET_OF_DMACTL(VE_UDMA_EENTRY),
				&regdata, sizeof(regdata));
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
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_H");
			retval = vedl_get_sys_reg_words(VE_CORE_SYS_REG(0,
								core_id), 0,
					VE1_UDMA_OFFSET_OF_DMACTL(
						VE_UDMA_HENTRY), &regdata,
					sizeof(regdata));
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for Core %d", core_id);
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
			VEOS_DEBUG("Waiting for DMA to stop: DMA_DESC_E");
			retval = vedl_get_sys_reg_words(VE_CORE_SYS_REG(0,
								core_id), 0,
					VE1_UDMA_OFFSET_OF_DMACTL(
						VE_UDMA_EENTRY), &regdata,
					sizeof(regdata));
			if (0 > retval) {
				VEOS_ERROR("Getting system register failed"
						" for Core %d", core_id);
				goto stop_udma_fail;
			}
		} while (!(regdata & 0x2));
	}

	retval = 0;
	VEOS_DEBUG("UDMA stopped for core %d", core_id);
stop_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_stop_udma, ve1_psm_stop_udma)

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
int ve1_psm_start_udma(int core_id, uint8_t udma_desc_bmap)
{
	int retval = -1;
	ve_reg_t regdata = 0;

	VEOS_TRACE("Entering");
	regdata = VE_UDMA_CTL_PERM_START;

	if (udma_desc_bmap & DMA_DESC_E) {
		/* Set permission bit to start operation on
		 * DMA descriptor table E */
		if (vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id),
			0, VE1_UDMA_OFFSET_OF_DMACTL(VE_UDMA_EENTRY),
			&regdata, sizeof(regdata))) {
			VEOS_ERROR("Setting permission bit failed for E entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for E entry");
		}
	}
	if (udma_desc_bmap & DMA_DESC_H) {
		/* Set permission bit to start operation on
		 * DMA descriptor table H */
		if (vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id),
			0, VE1_UDMA_OFFSET_OF_DMACTL(VE_UDMA_HENTRY),
			&regdata, sizeof(regdata))) {
			VEOS_ERROR("Setting permission bit failed for H entry");
			goto start_udma_fail;
		} else {
			VEOS_DEBUG("Started UDMA for H entry");
		}
	}
	retval = 0;
start_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_start_udma, ve1_psm_start_udma)

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
int ve1__psm_save_udma_context(struct ve_task_struct *ve_task,
		int core_id, int dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");

	/* Save DMA descriptor table */
	if (vedl_get_sys_reg_words(VE_CORE_SYS_REG(ve_task->node_id, core_id),
		0, VE1_UDMA_OFFSET_OF_DMADESC(dma_entry_type),
		&(TO_VE1_UDMA(ve_task->udma_context)->dmades[dma_entry_type]),
		sizeof(ve1_dma_desc_t) * VE1_DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Saving DMA descriptor table failed");
		goto __save_udma_fail;
	}

	/* Save DMA control register */
	if (vedl_get_sys_reg_words(VE_CORE_SYS_REG(0, core_id),
		0, VE1_UDMA_OFFSET_OF_DMACTL(dma_entry_type),
		&(TO_VE1_UDMA(ve_task->udma_context)->dmactl[dma_entry_type]),
		sizeof(ve1_dma_control_t))) {
		VEOS_ERROR("Saving DMA control register failed");
		goto __save_udma_fail;
	}
	retval = 0;
__save_udma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch__psm_save_udma_context, ve1__psm_save_udma_context)

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
int ve1__psm_restore_udma_context(struct ve_task_struct *ve_task,
		int core_id, int dma_entry_type)
{
	int retval = -1;
	VEOS_TRACE("Entering");
	/* Set the UDMA descriptors table to core */
	if (vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id), 0,
		VE1_UDMA_OFFSET_OF_DMADESC(dma_entry_type),
		&(TO_VE1_UDMA(ve_task->udma_context)->dmades[dma_entry_type]),
		sizeof(ve1_dma_desc_t) * VE1_DMA_DSCR_ENTRY_SIZE)) {
		VEOS_ERROR("Restoring DMA descriptor table failed");
		goto __restore_dma_fail;
	}

	/* Set the UDMA control register to core */
	if (vedl_set_sys_reg_words(VE_CORE_SYS_REG(0, core_id), 0,
		VE1_UDMA_OFFSET_OF_DMACTL(dma_entry_type),
		&(TO_VE1_UDMA(ve_task->udma_context)->dmactl[dma_entry_type]),
		sizeof(ve1_dma_control_t))) {
		VEOS_ERROR("Restoring DMA control registers failed");
		goto __restore_dma_fail;
	}
	VEOS_DEBUG("Successfully restored DMA descriptors/control registers");
	retval = 0;
__restore_dma_fail:
	VEOS_TRACE("Exiting");
	return retval;
}
VEOS_ARCH_DEP_FUNC(ve1, arch__psm_restore_udma_context, ve1__psm_restore_udma_context)

int ve1_psm_restore_context_to_core_regs(struct ve_core_struct *p_ve_core, pid_t veos_pid,
				struct ve_thread_struct *p_ve_thread)
{
	ve_dma_status_t dmast;
	int phys_core_id = p_ve_core->phys_core_num;
	dmast = ve_dma_xfer_p_va(VE_NODE(0)->dh, VE_DMA_VHVA, veos_pid,
			(uint64_t)p_ve_thread->arch_user_regs,
			VE1_DMA_VERAA, 0,
			VE1_PSM_CTXSW_CREG_VERAA(phys_core_id),
			VE1_PSM_CTXSW_CREG_SIZE);
	if (dmast != VE_DMA_STATUS_OK) {
		VEOS_DEBUG("Setting user registers on BAR2 failed");
		return -1;
	}
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_restore_all_context_to_core_regs, ve1_psm_restore_context_to_core_regs)

/* wrap vedl_ve1_update_dmaatb_dir() */
int ve1_psm_update_dmaatb_dir(vedl_common_reg_handle *creg,
			const veos_dmaatb_reg_t *regs, int count)
{
	return vedl_ve1_update_dmaatb_dir(creg, (ve1_dmaatb_reg_t *)regs,
						count);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_update_dmaatb_dir, ve1_psm_update_dmaatb_dir)

size_t ve1_psm_context_size(void)
{
	return VE1_PSM_CTXSW_CREG_SIZE;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_context_size, ve1_psm_context_size)

void ve1_veos_clear_udma(int core_num)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_veos_clear_udma, ve1_veos_clear_udma)

void ve1_psm_wait_for_delayed_VLFA_exception(bool should_vlfa_wait,
					struct ve_task_struct *curr_ve_task)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_wait_for_delayed_VLFA_exception, ve1_psm_wait_for_delayed_VLFA_exception)

void ve1_psm_set_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	return;
}

VEOS_ARCH_DEP_FUNC(ve1, arch_psm_set_vlfa_wait, ve1_psm_set_vlfa_wait)

void ve1_psm_clear_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_clear_vlfa_wait, ve1_psm_clear_vlfa_wait)

bool ve1_psm_get_vlfa_wait(struct ve_task_struct *curr_ve_task)
{
	return false;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_get_vlfa_wait, ve1_psm_get_vlfa_wait)
void ve1_psm_log_pwr_throttle(int core_id, bool log_power_throttling)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_log_pwr_throttle, ve1_psm_log_pwr_throttle)
void ve1_psm_update_pwr_throttle(int core_id, bool ctx_switch)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_psm_update_pwr_throttle, ve1_psm_update_pwr_throttle)
