/**
 * @file amm_dma_api.c
 * @brief handle the dma request from pseudo process
 */
#include <unistd.h>
#include <sys/mman.h>
#include "amm_mem.h"
#include "amm_psm_if.h"
#include "memory.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "psm_task_mgmt.h"
#include "velayout.h"

/**
* @brief Translation from VEMVA to VEMAA.
*
* @param[in] pid Identifier for the process
* @param[in] vaddr Virtual address to translate
* @param[in] paddr COrresponding physical address
*
* @return On success returns 0 and -1 on error
*/
int vemva_to_vemaa(pid_t pid, uint64_t vaddr, uint64_t *paddr)
{
	int retval = -1;
	struct ve_task_struct *ve_task = NULL;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"VEMVA to VEMAA traslation request for PID : %d\n",
			pid);
	/* Get ve task struct */
	ve_task = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == ve_task) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch the"
				"task structure of PID : %d\n", pid);
		return retval;
	}
	/* Get the VE process physical address corresponding to
	 *  VE process virtual address*/
	retval = amm_addr_translation((char *)vaddr, &(ve_task->p_ve_mm->atb));
	if (-1 == retval) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch VEMVA -> VEMAA for PID : %d\n",
				pid);
		return retval;
	}

	*paddr = (uint64_t)retval;
	return 0;
}

/**
* @brief DMA transfer request to DMA library.
*
* @param[in] srctype source address type
* @param[in] src_addr source address
* @param[in] src_pid process identifier
* @param[in] dsttype destination type
* @param[out] dst_addr destination address
* @param[in] dst_pid destination process identifier
* @param[in] length Length of the data to DMA
* @param[in] node_id Node ID
*
* @return On success returns 0 and -1 on error
*/
int amm_dma_xfer(int srctype, uint64_t src_addr, int src_pid,
		int dsttype, uint64_t dst_addr, int dst_pid,
		uint64_t length, int node_id)
{
	int retval = 0;
	ve_dma_hdl *dh;
	ve_dma_status_t st;
	struct ve_node_struct *vnode_info = VE_NODE(node_id);

	dh = vnode_info->dh;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"DMA Transfer From(PID:%d): 0x%lx "
			"To(PID:%d): 0x%lx of Size: %ld\n",
			src_pid, src_addr, dst_pid, dst_addr, length);
	/* DMA transfer using DMA lib */
	st = ve_dma_xfer_p_va(dh, srctype, src_pid,
			src_addr, dsttype, dst_pid, dst_addr, length);
	if (st != VE_DMA_STATUS_OK) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"DMA error (%d)\n", st);
		retval = -1;
	}
	return retval;
}
