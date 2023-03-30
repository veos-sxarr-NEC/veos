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
 * @file  clone_handler.c
 * @brief VE3-dependent part of VE Process fork/clone handling
 */

#include <ve_hw.h>

#include <veos.h>
#include <comm_request.h>

#include <ve_mem.h>

#include <veos_arch_defs.h>
#include <task_mgmt_ve3.h>

/* Setting last 6 bits of PEF to 0 by bitwise &*/
#define PSW_PEF_RST             (~0x3f)


void *ve3_psm_alloc_user_regs(void)
{
	return calloc(1, sizeof(ve3_core_user_reg_pre_t));
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_alloc_user_regs, ve3_psm_alloc_user_regs)

void ve3_psm_copy_user_regs_in_thread_struct(void *dst, const void *src)
{
	const ve3_core_user_reg_pre_t *s = src;
	ve3_core_user_reg_pre_t *d = dst;
	*d = *s;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_copy_user_regs_in_thread_struct, ve3_psm_copy_user_regs_in_thread_struct)

#define VE3_SET_ARITHMETIC_MODE(x, val) ((x)->PSW = ((x)->PSW & PSW_AM_MASK) | val);

void ve3_psm_update_ve_thread_struct(void *u, const struct ve_context_info *ctx)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	VEOS_DEBUG("\tIC: %lx SP: %lx SZ: %lx", ctx->IC, ctx->SP, ctx->SZ);
	user_regs->IC = ctx->IC;
	user_regs->SR[8] = ctx->SZ;
	user_regs->SR[11] = ctx->SP;
	user_regs->SR[01] = 0;
	user_regs->PMMR = 0x1000;
	/* Set arithmetic mode to nearest even */
	VE3_SET_ARITHMETIC_MODE(user_regs, PSW_AM_RN);
	VEOS_TRACE("Exiting");
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_update_thread_struct, ve3_psm_update_ve_thread_struct)

void ve3_psm_set_child_tls_desc(void *child_user_regs,
				const void *parent_user_regs)
{
	const ve3_core_user_reg_pre_t *parent = parent_user_regs;
	ve3_core_user_reg_pre_t *child = child_user_regs;
	child->SR[14] = parent->SR[5];
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_child_tls_desc, ve3_psm_set_child_tls_desc)

void ve3_psm_set_stack_pointer_on_thread(void *u, ve_reg_t sp)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	user_regs->SR[11] = sp;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_stack_pointer_on_thread_struct, ve3_psm_set_stack_pointer_on_thread)

void ve3_psm_set_retval_on_thread(void *u, ve_reg_t rv)
{
	ve3_core_user_reg_pre_t *user_regs = u;
	user_regs->SR[0] = rv;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_retval_on_thread_struct, ve3_psm_set_retval_on_thread)

int ve3_psm_set_thread_descriptor_area_on_stack(pid_t veos_pid, uint64_t value,
					pid_t child_pid, const void *u)
{
	const ve3_core_user_reg_pre_t *user_regs = u;
	uint64_t addr = user_regs->SR[14] + 0x18;
	return amm_dma_xfer(VE_DMA_VHVA, (uint64_t)&value, veos_pid,
			VE_DMA_VEMVA, addr, child_pid, sizeof(uint64_t), 0);
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_set_thread_descriptor_area_on_stack, ve3_psm_set_thread_descriptor_area_on_stack)

int64_t ve3_psm_clear_PEF_in_PSW_mask()
{
	return PSW_PEF_RST;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_clear_PEF_in_PSW_mask, ve3_psm_clear_PEF_in_PSW_mask)

void ve3_psm_reinitialize_acct(struct ve_task_struct *task)
{
	task->sighand->pacct.max_thread = 0;
	((struct ve_acct_v16 *)(task->sighand->pacct.acct_info))->ac_syscall = 0;
}
VEOS_ARCH_DEP_FUNC(ve3, arch_psm_reinitialize_acct, ve3_psm_reinitialize_acct)
