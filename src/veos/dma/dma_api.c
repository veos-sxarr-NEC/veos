/*
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @file dma_api.c
 * @brief DMA manager API
 */
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>

#include "dma.h"
#include "dma_private.h"
#include "dma_hw.h"
#include "dma_reqlist.h"
#include "dma_intr.h"
#include "dma_log.h"
#include "vedma_hw.h"
#include "ve_mem.h"
#include "vesync.h"

/**
 * @brief Initialize DMA engine on VE node
 *
 * @param[in] vh VE handle
 *
 * @return DMA engine handle on success. NULL upon failure.
 */
ve_dma_hdl *ve_dma_open_p(vedl_handle *vh)
{
	ve_dma_hdl *ret;
	uint32_t ctl_status;
	int i;
	int err;
	void *ret_from_helper;

	ve_dma_log_init();
	VE_DMA_TRACE("called");
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		VE_DMA_CRIT("malloc for dma handle failed.");
		return NULL;
	}
	/* initialize a DMA handle */
	INIT_LIST_HEAD(&ret->waiting_list);
	INIT_LIST_HEAD(&ret->pin_waiting_request);
	ret->vedl_handle = vh;
	ret->should_stop = 0;
	VE_ATOMIC_SET(int, &ret->blk_count, 0);
	pthread_mutex_init(&ret->mutex, NULL);
	pthread_mutex_init(&ret->pin_wait_list_mutex, NULL);
	pthread_cond_init(&ret->pin_wait_list_cond, NULL);
	memset(&ret->req_entry, 0, sizeof(ret->req_entry));
	ret->control_regs = vedl_mmap_cnt_reg(vh);
	if (ret->control_regs == MAP_FAILED) {
		VE_DMA_CRIT("mmap of node control registers failed");
		goto err_map_cnt_reg;
	}

	ctl_status = ve_dma_hw_get_ctlstatus(vh, ret->control_regs);
	if ((ctl_status & VE_DMA_CTL_STATUS_HALT) == 0) {
		VE_DMA_WARN("DMA is not halted unexpectedly"
			   " (%08x). Stop and clear the DMA descriptors.",
			   ctl_status);
		ve_dma__stop_engine(ret);
	}
	for (i = 0; i < VE_DMA_NUM_DESC; ++i)
		ve_dma_hw_clear_dma(vh, ret->control_regs, i);
	/* read pointer */
	ret->desc_used_begin = ve_dma_hw_get_readptr(vh, ret->control_regs);
	/* DMA descriptors are unused yet */
	ret->desc_num_used = 0;

	/* start a helper thread */
	err = pthread_create(&ret->helper, NULL, ve_dma_intr_helper, ret);
	if (err != 0) {
		VE_DMA_CRIT("Failed to create ve_dma_intr_helper thread. %s",
			    strerror(err));
		goto err_create_helper;
	}
	/* start a pindown helper thread */
	err = pthread_create(&ret->pin_helper, NULL, ve_dma_pindown_helper, ret);
	if (err != 0) {
                VE_DMA_CRIT("Failed to create ve_dma_pindown_helper thread. %s",
                            strerror(err));
                goto err_create_pin_helper;
        }
	veos_commit_rdawr_order();
	VE_DMA_DEBUG("DMA engine is opend.");
	return ret;
err_create_pin_helper:
	ret->should_stop = 1;
	err = pthread_join(ret->helper, &ret_from_helper);
	if (err != 0)
		VE_DMA_CRIT("Failed to join ve_dma_intr_helper thread. %s",
		             strerror(err));
err_create_helper:
	munmap(ret->control_regs, sizeof(system_common_reg_t));
err_map_cnt_reg:
	pthread_mutex_destroy(&ret->mutex);
	pthread_mutex_destroy(&ret->pin_wait_list_mutex);
	free(ret);
	return NULL;
}

/**
 * @brief Close DMA engine handle.
 *
 * @param[in] hdl DMA engine handle to be closed
 *
 * @return 0 on success. -EBUSY on busy.
 */
int ve_dma_close_p(ve_dma_hdl *hdl)
{
	void *ret_from_helper;
	void *ret_from_pin_helper;
	int err;

	VE_DMA_TRACE("called");
	pthread_mutex_lock(&hdl->mutex);
	if (hdl->desc_num_used != 0) {
		VE_DMA_CRIT("%d descriptors are still used.",
			    hdl->desc_num_used);
		pthread_mutex_unlock(&hdl->mutex);
		return -EBUSY;
	}
	if (hdl->should_stop) {
		VE_DMA_CRIT("DMA engine is already going to be closed.");
		pthread_mutex_unlock(&hdl->mutex);
		return -EBUSY;
	}
	hdl->should_stop = 1;
	ve_dma__stop_engine(hdl);
	/*
	 * Interrupt helper thread sleeping in vedl_wait_interrupt() shoud be
	 * woken up. But there is no need to do anything because it will wake
	 * automatically by timedout of vedl_wait_interrupt().
	 */
	veos_commit_rdawr_order();
	pthread_mutex_unlock(&hdl->mutex);
	pthread_mutex_lock(&hdl->pin_wait_list_mutex);
	pthread_cond_signal(&hdl->pin_wait_list_cond);
	pthread_mutex_unlock(&hdl->pin_wait_list_mutex);
	err = pthread_join(hdl->pin_helper, &ret_from_pin_helper);
	if (err != 0)
                VE_DMA_CRIT("Failed to join ve_dma_pindown_helper thread. %s",
                             strerror(err));
	err = pthread_join(hdl->helper, &ret_from_helper);
	if (err != 0)
		VE_DMA_CRIT("Failed to join ve_dma_intr_helper thread. %s",
			     strerror(err));
	pthread_mutex_destroy(&hdl->mutex);
	pthread_mutex_destroy(&hdl->pin_wait_list_mutex);
	pthread_cond_destroy(&hdl->pin_wait_list_cond);
	munmap(hdl->control_regs, sizeof(system_common_reg_t));
	free(hdl);
	VE_DMA_DEBUG("DMA engine is closed.");
	return 0;
}

/**
 * @brief Print the type of an address space for debug
 *
 * @param[in] msg prefixed message
 * @param t address space type on address space field of a DMA descriptor
 *
 * @return 0 on success. Non-zero on failure.
 */
static int ve_dma_post__check_addr_type(const char *msg, ve_dma_addrtype_t t)
{
	VE_DMA_TRACE("called");
	switch (t) {
	case VE_DMA_VEMVA:
		VE_DMA_TRACE("%s addr type is VE_DMA_VEMVA", msg);
		return 0;
	case VE_DMA_VEMVA_WO_PROT_CHECK:
		VE_DMA_TRACE("%s addr type is VE_DMA_VEMVA_WO_PROT_CHECK",
			 msg);
		return 0;
	case VE_DMA_VHVA:
		VE_DMA_TRACE("%s addr type is VE_DMA_VHVA", msg);
		return 0;
	case VE_DMA_VEMAA:
		VE_DMA_TRACE("%s addr type is VE_DMA_VEMAA", msg);
		return 0;
	case VE_DMA_VERAA:
		VE_DMA_TRACE("%s addr type is VE_DMA_VERAA", msg);
		return 0;
	case VE_DMA_VHSAA:
		VE_DMA_TRACE("%s addr type is VE_DMA_VHSAA", msg);
		return 0;
	default:
		VE_DMA_ERROR("%s unsupported addr type (%d)",
			   msg, t);
		return -EINVAL;
	}
}

/**
 * @brief Post a DMA request
 *
 * @param[in] hdl DMA engine handle to post DMA request
 * @param[in] srctype Address type of source
 * @param[in] srcpid Process ID of source. Ignored when srctype is physical
 *           (VE_DMA_VEMAA, VE_DMA_VERAA or VE_DMA_VHSAA).
 * @param[in] srcaddr source address
 *            srcaddr shall be 8 byte aligned.
 * @param[in] dsttype Address type of destination
 * @param[in] dstpid Process ID of destination. Ignored when dsttype is
 *           physical (VE_DMA_VEMAA, VE_DMA_VERAA or VE_DMA_VHSAA).
 * @param[in] dstaddr destination address
 *            destaddr shall be 8 byte aligned.
 * @param[in] length transfer length in byte
 *            length shall be 8 byte aligned.
 *
 * @return DMA request handle on success. NULL on failure.
 */
ve_dma_req_hdl *ve_dma_post_p_va(ve_dma_hdl *hdl, ve_dma_addrtype_t srctype,
				 pid_t srcpid, uint64_t srcaddr,
				 ve_dma_addrtype_t dsttype, pid_t dstpid,
				 uint64_t dstaddr, uint64_t length)
{
	return ve_dma_post_p_va_with_opt(hdl,srctype,srcpid,srcaddr,
					dsttype,dstpid,dstaddr,length,
					VE_DMA_OPT_SYNC | VE_DMA_OPT_SYNC_API,
					-1,NULL);
}

ve_dma_req_hdl *ve_dma_post_p_va_with_opt(ve_dma_hdl *hdl,
				ve_dma_addrtype_t srctype,
				pid_t srcpid, uint64_t srcaddr,
                		ve_dma_addrtype_t dsttype,
				pid_t dstpid, uint64_t dstaddr, uint64_t length,
				uint64_t opt, int vh_sock_fd, 
				struct ve_ipc_sync *ipc_sync)
{
	ve_dma_req_hdl *ret;
	int64_t n_dma_req;
	int err = 0;

	VE_DMA_TRACE("called");
	VE_DMA_DEBUG("DMA request is posted. "
		     "(srctype = %d, srcpid = %d, srcaddr = 0x%016lx, "
		     "dsttype = %d, dstpid = %d, dstaddr = 0x%016lx, "
		     "length = 0x%lx)",
		     srctype, (int)srcpid, srcaddr,
		     dsttype, (int)dstpid, dstaddr, length);
	/* parameter check */
	if (!IS_ALIGNED(length, 8)) {
		VE_DMA_ERROR("Unsupported transfer length (%lu bytes)", length);
		err = EINVAL;
	}
	if (length > VE_DMA_MAX_LENGTH) {
		VE_DMA_ERROR("Too large transfer length (0x%lx bytes)", length);
		err = EINVAL;
	}
	if (!IS_ALIGNED(srcaddr, 8)) {
		VE_DMA_ERROR("DMA does not support unaligned "
			     "source address (0x%016lx)", srcaddr);
		err = EINVAL;
	}
	if (!IS_ALIGNED(dstaddr, 8)) {
		VE_DMA_ERROR("DMA does not support unaligned "
			     "destination address (0x%016lx)", dstaddr);
		err = EINVAL;
	}
	if (ve_dma_post__check_addr_type("Source", srctype) != 0) {
		/* error message is output in ve_dma_post__check_addr_type(). */
		err = EINVAL;
	}
	if (ve_dma_post__check_addr_type("Destination", dsttype) != 0) {
		/* error message is output in ve_dma_post__check_addr_type(). */
		err = EINVAL;
	}

	/*
	 * create DMA request handle
	 */
	if (!err) {
		ret = malloc(sizeof(*ret));
		if (ret == NULL) {
			err = errno;
			VE_DMA_ERROR("malloc for DMA request handle failed.");
		}
	}
	/* Error check to create DMA request handle */
	if (err) {
		if (ipc_sync)
			ve_put_ipc_sync(ipc_sync);
		errno = err;
		return NULL;
	}

	ret->engine = hdl;
	pthread_cond_init(&ret->cond, NULL);
	ret->cancel = 0;
	ret->waiting_src.type = 0;
	ret->waiting_dst.type = 0;
	ret->waiting_src.pid = 0;
	ret->waiting_dst.pid = 0;
	ret->waiting_src.addr = 0;
	ret->waiting_dst.addr = 0;
	ret->src_blk = NULL;
	ret->dst_blk = NULL;
	ret->length = 0;
	ret->opt = 0;
	ret->vh_sock_fd = 0;
	ret->comp = 0;
	ret->posting = 1;
	ret->ipc_sync = ipc_sync;
	INIT_LIST_HEAD(&ret->reqlist);
	INIT_LIST_HEAD(&ret->ptrans_src);
	INIT_LIST_HEAD(&ret->ptrans_dst);
	INIT_LIST_HEAD(&ret->pin_waiting_list);

	if (ipc_sync) {
		pthread_mutex_lock(
			&(ipc_sync->swap_exclusion_lock));
		while (ipc_sync->swapping != 0) {
			pthread_cond_wait(&(ipc_sync->swapping_cond),
				&(ipc_sync->swap_exclusion_lock));
		}
		ipc_sync->handling_request++;
		VE_DMA_DEBUG("ipc_sync(%p) : handling_request %d",
				ipc_sync, ipc_sync->handling_request);
		pthread_mutex_unlock(
			&(ipc_sync->swap_exclusion_lock));
	}

	n_dma_req = ve_dma_reqlist_make(ret, srctype, srcpid, srcaddr, NULL, dsttype,
					dstpid, dstaddr, NULL, length, opt, vh_sock_fd);
	if (n_dma_req < 0) {
		err = errno;
		VE_DMA_ERROR("Error occured on making DMA reqlist entries. "
			     "(srctype = %d, srcpid = %d, srcaddr = 0x%016lx, "
			     "dsttype = %d, dstpid = %d, dstaddr = 0x%016lx, "
			     "length = 0x%lx, opt = 0x%lx, vh_sock_fd = %d)",
			     srctype, (int)srcpid, srcaddr,
			     dsttype, (int)dstpid, dstaddr, length, opt, vh_sock_fd);
		/* No need to acquire dma handle lock.
		 * Request has already been canceled and other DMA threads can't operate. */
		ve_dma__dec_ipc_sync_nolock(ret);
		ve_dma_reqlist_free(ret);
		pthread_cond_destroy(&ret->cond);
		free(ret);
		errno = err;
		return NULL;
	}
	return ret;
}

/**
 * @brief Synchronouse data transfer by DMA
 *
 * @param[in] hdl DMA engine handle to post DMA request
 * @param[in] srctype Address type of source
 * @param[in] srcpid Process ID of source. Ignored when srctype is physical
 *           (VE_DMA_VEMAA, VE_DMA_VERAA or VE_DMA_VHSAA).
 * @param[in] srcaddr source address
 *            srcaddr shall be 8 byte aligned.
 * @param[in] dsttype Address type of destination
 * @param[in] dstpid Process ID of destination. Ignored when dsttype is
 *           physical (VE_DMA_VEMAA, VE_DMA_VERAA or VE_DMA_VHSAA).
 * @param[in] dstaddr destination address
 *            destaddr shall be 8 byte aligned.
 * @param[in] length transfer length in byte
 *            length shall be 8 byte aligned.
 *
 * @return status of the request:
 *         VE_DMA_STATUS_OK on success,
 *         VE_DMA_STATUS_CANCELED at cancellation, and
 *         VE_DMA_STATUS_ERROR on failure.
 */
ve_dma_status_t ve_dma_xfer_p_va(ve_dma_hdl *hdl, ve_dma_addrtype_t srctype,
				 pid_t srcpid, uint64_t srcaddr,
				 ve_dma_addrtype_t dsttype, pid_t dstpid,
				 uint64_t dstaddr, uint64_t length)
{
	ve_dma_status_t ret;

	VE_DMA_TRACE("called");
	ve_dma_req_hdl *req = ve_dma_post_p_va(hdl, srctype, srcpid, srcaddr,
						dsttype, dstpid, dstaddr,
						length);
	if (req == NULL)
		return VE_DMA_STATUS_ERROR;

	ret = ve_dma_wait(req);
	ve_dma_req_free(req);

	return ret;
}

static ve_dma_status_t ve_dma__test_nolock(ve_dma_req_hdl *req)
{
	ve_dma_status_t ret;
	ret = ve_dma_reqlist_test(req);
	return ret;
}

/**
 * @brief Test whether DMA request has been finished
 *
 * @param req DMA request handle to be tested
 *
 * @return state of the DMA request:
 *         VE_DMA_STATUS_OK on success,
 *         VE_DMA_STATUS_NOT_FINISHED when the request is not finished yet,
 *         VE_DMA_STATUS_CANCELED at cancellation, and
 *         VE_DMA_STATUS_ERROR on failure.
 */
ve_dma_status_t ve_dma_test(ve_dma_req_hdl *req)
{
	ve_dma_status_t ret;

	VE_DMA_TRACE("called");
	pthread_mutex_lock(&req->engine->mutex);
	ret = ve_dma__test_nolock(req);
	pthread_mutex_unlock(&req->engine->mutex);
	return ret;
}

/**
 * @brief Wait for DMA request completion
 *
 * @param req DMA request handle for which the call waits
 *
 * @return state of the DMA request:
 *         VE_DMA_STATUS_OK on success,
 *         VE_DMA_STATUS_CANCELED at cancellation, and
 *         VE_DMA_STATUS_ERROR on failure.
 */
ve_dma_status_t ve_dma_wait(ve_dma_req_hdl *req)
{
	ve_dma_status_t ret;
	VE_DMA_TRACE("called");
	pthread_mutex_lock(&req->engine->mutex);
	while (req->engine->should_stop == 0 &&
		(req->comp == 0 || req->posting != 0)) {
		VE_DMA_TRACE("wait for interrupts");
		pthread_cond_wait(&req->cond, &req->engine->mutex);
		VE_DMA_TRACE("woken");
	}
	ret = ve_dma__test_nolock(req);
	pthread_mutex_unlock(&req->engine->mutex);
	if (ret == VE_DMA_STATUS_NOT_FINISHED)
		ret = VE_DMA_STATUS_CANCELED;
	return ret;
}

/**
 * @brief Wait for DMA request completion or timedout
 *
 * @param req DMA request handle for which the call waits
 *
 * @return state of the DMA request:
 *         VE_DMA_STATUS_OK on success,
 *         VE_DMA_STATUS_TIMEDOUT when the request is timed out,
 *         VE_DMA_STATUS_CANCELED at cancellation, and
 *         VE_DMA_STATUS_ERROR on failure.
 */
ve_dma_status_t ve_dma_timedwait(ve_dma_req_hdl *req, const struct timespec *t)
{
	ve_dma_status_t ret;
	VE_DMA_TRACE("called");
	pthread_mutex_lock(&req->engine->mutex);
	ret = ve_dma__test_nolock(req);
	while (ret == VE_DMA_STATUS_NOT_FINISHED &&
	       req->engine->should_stop == 0) {
		VE_DMA_TRACE("not finished. wait for interrupts");
		int err = pthread_cond_timedwait(&req->cond,
						 &req->engine->mutex, t);
		if (err == ETIMEDOUT) {
			VE_DMA_TRACE(
				"pthread_cond_timedwait returned ETIMEDOUT");
			ret = VE_DMA_STATUS_TIMEDOUT;
			break;
		}
		ret = ve_dma__test_nolock(req);
	}
	pthread_mutex_unlock(&req->engine->mutex);
	if (ret == VE_DMA_STATUS_NOT_FINISHED)
		ret = VE_DMA_STATUS_CANCELED;
	return ret;
}

/**
 * @brief Free a DMA request handle
 *
 * @param req DMA request handle to be freed
 *
 * @return 0 on success. Current implementation does not return non-zero.
 */
int ve_dma_req_free(ve_dma_req_hdl *req)
{
	VE_DMA_TRACE("called");
	ve_dma_reqlist_free(req);
	pthread_cond_destroy(&req->cond);
	free(req);
	return 0;
}

/**
 * @brief Stop DMA
 *
 * @param hdl DMA handle
 *
 * Request to stop DMA transfer and wait for the stop.
 */
void ve_dma__stop_engine(ve_dma_hdl *hdl)
{
	uint32_t ctl_status;
	/* note: the caller shall hold hdl->mutex */
	ve_dma_hw_post_stop(hdl->vedl_handle, hdl->control_regs);
	while ((ctl_status = ve_dma_hw_get_ctlstatus(hdl->vedl_handle,
		hdl->control_regs) & VE_DMA_CTL_STATUS_MASK)
		!= VE_DMA_CTL_STATUS_HALT) {
		VE_DMA_TRACE("Waiting for DMA halt state (DMA status = %08x)",
			     ctl_status);
	}
}

/**
 * @brief Remove DMA requests from request queue and post on free descriptors
 *
 * @param hdl DMA handle
 */
void ve_dma__drain_waiting_list(ve_dma_hdl *hdl)
{
	/*
	 * note: a caller shall hold hdl->mutex.
	 */
	int posted;

	VE_DMA_TRACE("drain the wait queue");
	posted = ve_dma_reqlist_drain_waiting_list(hdl);
	if (hdl->should_stop == 0 && posted > 0) {
		ve_dma_hw_start(hdl->vedl_handle, hdl->control_regs);
		veos_commit_rdawr_order();
	}
}

/**
 * @brief Terminate all DMA requests on the specified DMA engine
 *
 * @param hdl DMA handle
 */
void ve_dma_terminate_all(ve_dma_hdl *hdl)
{
	int i;

	VE_DMA_TRACE("called");

	pthread_mutex_lock(&hdl->mutex);

	/* stop DMA engine */
	ve_dma__stop_engine(hdl);

	/* remove all the DMA requests on DMA descriptor table */
	for (i = 0; i < VE_DMA_NUM_DESC; ++i) {
		if (hdl->req_entry[i] != NULL) {
			ve_dma_req_hdl *dh;

			VE_DMA_TRACE("Cancel DMA descriptor %d (request %p)",
				     i, hdl->req_entry[i]);
			dh = ve_dma_reqlist_entry_to_req_hdl(hdl->req_entry[i]);
			ve_dma_reqlist__cancel(dh);
			pthread_cond_broadcast(&dh->cond);
		} else {
			VE_DMA_TRACE("DMA descriptor %d is unused", i);
		}
	}
	/* remove all the DMA reqlist entries in the wait queue */
	while (!list_empty(&hdl->waiting_list)) {
		ve_dma_req_hdl *dh;
		dh = ve_dma_waiting_list_head_to_req_hdl(
						hdl->waiting_list.next);
		VE_DMA_TRACE("remove request (request handle %p)", dh);
		ve_dma_reqlist__cancel(dh);
		pthread_cond_broadcast(&dh->cond);
	}
	VE_DMA_ASSERT(list_empty(&hdl->waiting_list));

	for (i = 0; i < VE_DMA_NUM_DESC; ++i)
		ve_dma_hw_clear_dma(hdl->vedl_handle, hdl->control_regs, i);
	/* reset used desc count */
	hdl->desc_used_begin = ve_dma_hw_get_readptr(hdl->vedl_handle,
						     hdl->control_regs);
	hdl->desc_num_used = 0;

	veos_commit_rdawr_order();
	pthread_mutex_unlock(&hdl->mutex);

}
