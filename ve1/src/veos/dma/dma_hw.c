/*
 * Copyright (C) 2020 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file dma_hw.c
 * @brief VE1-spacific functions to access registers regarding DMA engine
 */

#include <libved.h>
#include <ve_hw.h>

#include <align.h>

#include <veos_arch_defs.h>
#include "dma_ve1.h"
#include "dma_log.h"
#include "dma_private.h"
#include "ve1dma_hw.h"

/**
 * @brief Get a read pointer value
 *
 * @param[in] h VEDL handle
 * @param[in] creg pointer to node control register area
 *
 * @return the value of the read pointer
 */
int ve1_dma_hw_get_readptr(vedl_handle *h, vedl_common_reg_handle *creg)
{
	ve_reg_t reg;
	VE_DMA_TRACE("called");
	vedl_barrier_regs_read(h);
	vedl_get_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_WORD_READPTR, &reg);
	return reg & VE_DMA_CTL_READ_PTR_MASK;
}

/**
 * @brief Get a exc flag and read pointer value
 *
 * @param[in] h VEDL handle
 * @param[in] creg pointer to node control register area
 *
 * @return the value of the exc flag and read pointer
 */
uint64_t ve1_dma_hw_get_ctlword1(vedl_handle *h, vedl_common_reg_handle *creg)
{
	ve_reg_t reg;
	VE_DMA_TRACE("called");
	vedl_barrier_regs_read(h);
	vedl_get_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_WORD_READPTR, &reg);
	return reg & (VE_DMA_CTL_EXCEPTION_MASK | VE_DMA_CTL_READ_PTR_MASK);
}

/**
 * @brief Read status of DMA control register
 *
 *        Read halt bit and permission bit.
 *
 * @param[in] h VEDL handle
 * @param[in] creg pointer to node control register area
 *
 * @return the value of halt bit and permission bit
 */
uint32_t ve1_dma_hw_get_ctlstatus(vedl_handle *h, vedl_common_reg_handle *creg)
{
	ve_reg_t reg;
	VE_DMA_TRACE("called");
	vedl_barrier_regs_read(h);
	vedl_get_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMACTL, &reg);
	return reg & VE_DMA_CTL_STATUS_MASK;
}

/**
 * @brief Print the type of an address space for debug
 *
 * @param[in] msg prefixed message
 * @param t address space type on address space field of a DMA descriptor
 *
 * @return 0 on success. Non-zero on failure.
 */
static int ve1_dma_hw_check_addr_type(const char *msg, uint64_t t)
{
	VE_DMA_TRACE("called");
	switch (t) {
	case VE_DMA_DESC_ADDR_VEMAA:
		VE_DMA_TRACE("%s addr type is VEMAA", msg);
		return 0;
	case VE_DMA_DESC_ADDR_VERAA:
		VE_DMA_TRACE("%s addr type is VERAA", msg);
		return 0;
	case VE_DMA_DESC_ADDR_VHSAA:
		VE_DMA_TRACE("%s addr type is VHSAA", msg);
		return 0;
	default:
		VE_DMA_ERROR("%s unsupported addr type (%ld)",
			   msg, t);
		return -EINVAL;
	}
}

/**
 * @brief Post a DMA request on a DMA descriptor
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 * @param entry index of DMA descriptor
 * @param srctype source address space field in DMA descriptor
 * @param srcaddr source address
 * @param dsttype destination address space field in DMA descriptor
 * @param dstaddr destination address
 * @param len transfer length in byte
 * @param sync sync bit of this request is enabled when sync is non-zero.
 * @param ro   ro bit of this request is enabled when ro is non-zero.
 * @param ido  ido bit of this request is enabled when ido is non-zero.
 *
 * @return 0 on success. Non-zero on failure.
 */
int ve1_dma_hw_post_dma(vedl_handle *h, vedl_common_reg_handle *creg, int entry,
		       uint64_t srctype, uint64_t srcaddr, uint64_t dsttype,
		       uint64_t dstaddr, uint32_t len, int sync, int ro, int ido)
{
	VE_DMA_TRACE("called (entry #%d: srctype=%ld, srcaddr=0x%016lx, "
		 "dsttype=%ld, dstaddr=0x%016lx, length=0x%x)",
		 entry, srctype, srcaddr, dsttype, dstaddr, len);
	/*
	 * Check the start addresses and the length.
	 * Although DMA engine allows 4 byte aligned transfer unless
	 * neigher source nor destination is in register address space,
	 * VERAA or VECRAA, DMA manager only allows 8 byte aligned.
	 */
	if (len > VE_DMA_DESC_LEN_MAX ||
	    !IS_ALIGNED(len, VE_DMA_DESC_REQUEST_ALIGN)) {
		VE_DMA_ERROR("Unsupported length (%u bytes)",
			     (unsigned int)len);
		return -EINVAL;
	}
	if (!IS_ALIGNED(srcaddr, VE_DMA_DESC_REQUEST_ALIGN)) {
		VE_DMA_ERROR("DMA does not support unaligned "
			     "source address (0x%016lx)", srcaddr);
		return -EINVAL;
	}
	if (!IS_ALIGNED(dstaddr, VE_DMA_DESC_REQUEST_ALIGN)) {
		VE_DMA_ERROR("DMA does not support unaligned "
			     "destination address (0x%016lx)", dstaddr);
		return -EINVAL;
	}
	if (ve1_dma_hw_check_addr_type("source", srctype) != 0) {
		/* error message is output in ve_dma_hw_check_addr_type(). */
		return -EINVAL;
	}
	if (ve1_dma_hw_check_addr_type("destination", dsttype) != 0) {
		/* error message is output in ve_dma_hw_check_addr_type(). */
		return -EINVAL;
	}
	if (entry < 0 || entry >= VE1_DMA_NUM_DESC) {
		VE_DMA_ERROR("Descriptor number %d is invalid", entry);
		return -EINVAL;
	}

	/* write DMA descriptor */
	vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMADESC(entry), 0);
	vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMADESC(entry) + 8,
	/* TODO: use interrupt on exception and read-completion */
		VE_DMA_DESC_CTL_INTR_COMPLETION |
		(sync ? VE_DMA_DESC_CTL_SYNC : 0) |
		(ro ? VE_DMA_DESC_CTL_PCI_RO : 0) |
                (ido ? VE_DMA_DESC_CTL_PCI_IDO : 0) |
		VE_DMA_DESC_ADDR_SRC(srctype) |
		VE_DMA_DESC_ADDR_DST(dsttype) | len);
	vedl_set_cnt_reg_word(creg, 0,
		VE_DMA_OFFSET_OF_DMADESC(entry) + 0x10, srcaddr);
	vedl_set_cnt_reg_word(creg, 0,
		VE_DMA_OFFSET_OF_DMADESC(entry) + 0x18, dstaddr);
	vedl_set_cnt_reg_word(creg, 0,
		VE_DMA_OFFSET_OF_DMADESC(entry), VE_DMA_DESC_STATUS_PREPARED);

	return 0;
}

/**
 * @brief Start DMA transfer, with permission bit enabled.
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 */
void ve1_dma_hw_start(vedl_common_reg_handle *creg)
{
	VE_DMA_TRACE("called");
	vedl_set_cnt_reg_word(creg, 0,
		VE_DMA_OFFSET_OF_DMACTL, VE_DMA_CTL_PERM_START);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_hw_start, ve1_dma_hw_start)

/**
 * @brief Post DMA stop request, with halt bit enabled.
 *
 *        only write the halt bit, returning without waiting for stop.
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 */
void ve1_dma_hw_post_stop(vedl_common_reg_handle *creg)
{
	VE_DMA_TRACE("called");
	vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMACTL, 0);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_hw_post_stop, ve1_dma_hw_post_stop)

/**
 * @brief Get word 0 of DMA descriptor, word which includes its status.
 *
 * @param[in] h VEDL handle
 * @param[in] creg pointer to node control register area
 * @param entry index of DMA descriptor
 *
 * @return Word 0 of DMA descriptor.
 */
uint64_t ve1_dma_hw_desc_status(vedl_handle *h, vedl_common_reg_handle *creg,
				int entry)
{
	ve_reg_t word;
	VE_DMA_TRACE("called (entry=%d)", entry);

	VE_DMA_ASSERT(0 <= entry && entry < VE1_DMA_NUM_DESC);

	vedl_barrier_regs_read(h);
	vedl_get_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMADESC(entry), &word);
	VE_DMA_TRACE("DMA desc %d word 0: %016lx", entry, word);
	return word & (VE_DMA_DESC_STATUS_MASK | VE_DMA_DESC_EXCEPTION_MASK);
}

/**
 * @brief Nullify a DMA descriptor
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 * @param entry index of DMA descriptor
 */
void ve1_dma_hw_nullify_dma(vedl_handle *h, vedl_common_reg_handle *creg,
				int entry)
{
	VE_DMA_TRACE("called (entry=%d)", entry);

	VE_DMA_ASSERT(0 <= entry && entry < VE1_DMA_NUM_DESC);
	/*
	 * overwrite transfer length with zero.
	 * src/dst address space bits are also cleared.
	 */
	vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMADESC(entry) + 8,
		VE_DMA_DESC_CTL_INTR_COMPLETION);
}

/**
 * @brief Clear all DMA descriptor
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 *
 * @return 0 on success. Current implementation always returns 0..
 */
int ve1_dma_hw_clear_dma(vedl_handle *h, vedl_common_reg_handle *creg)
{
	VE_DMA_TRACE("called");

	for (int i = 0; i < VE1_DMA_NUM_DESC; ++i)
		vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_DMADESC(i), 0);
	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_hw_clear_all_dma, ve1_dma_hw_clear_dma)

/**
 * @brief Set read pointer
 *
 * @param[in,out] h VEDL handle
 * @param[in,out] creg pointer to node control register area
 * @param entry value to be set on read pointer
 *
 * @return 0 on success. Current implementation always returns 0.
 */
int ve1_dma_hw_set_readptr(vedl_handle *h, vedl_common_reg_handle *creg,
				int entry)
{
	ve_reg_t word;
	VE_DMA_TRACE("called (entry=%d)", entry);
	VE_DMA_ASSERT(0 <= entry && entry < VE1_DMA_NUM_DESC);

	word = entry;
	vedl_set_cnt_reg_word(creg, 0, VE_DMA_OFFSET_OF_WORD_READPTR, word);
	VE_DMA_TRACE("DMA read ptr is set to %ld", word);
	return 0;
}

int ve1_dma_hw_engine_is_halt(vedl_handle *h, vedl_common_reg_handle *creg)
{
	uint32_t ctl_status = ve1_dma_hw_get_ctlstatus(h, creg);
	return ctl_status == VE_DMA_CTL_STATUS_HALT;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_dma_hw_engine_is_halt, ve1_dma_hw_engine_is_halt)
