/*
 * Copyright (C) 2020-2021 NEC Corporation
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
 * @file  vhve.c
 * @brief Handling DMA requests from VH processes.
 */
#include <dhash.h>
#include "veos.h"
#include "dma.h"
#include "task_mgmt.h"
#include "psm_comm.h"
#include "veos_handler.h"
#include "velayout.h"
#include "ptrace_req.h"

/* hash entry of dma_req_hdl_list to store ve_dma_req_hdl */
struct vhve_dma_hashent_t {
	ve_dma_req_hdl *hdl;
};
typedef struct vhve_dma_hashent_t vhve_dma_hashent;

/**
 * @brief wait and free dma_req_hdl for all hash entry
 *
 * @param dma_req_hdl_list hash list that value ofeach entry is
 *                         vhve_dma_hashent. vhve_dma_hashent has a
 *                         pointer to ve_dma_req_hdl.
 **/
void veos_vhve_dma_hash_free_all(hash_table_t *dma_req_hdl_list)
{
	unsigned long n_entries = 0;
	struct hash_iter_context_t *iter;
	hash_entry_t *entry;
	ve_dma_req_hdl *hdl;
	iter = new_hash_iter_context(dma_req_hdl_list);
	while ((entry = iter->next(iter)) != NULL) {
		hdl = ((vhve_dma_hashent *)entry->value.ptr)->hdl;
		ve_dma_wait(hdl);
		ve_dma_req_free(hdl);
		free(entry->value.ptr);
		n_entries++;
	}
	free(iter);
	/* Assure number of visits equal the table size */
	if (n_entries != hash_count(dma_req_hdl_list))
		VEOS_ERROR("Free %lu dma_req_hdl but list has %lu",
				n_entries, hash_count(dma_req_hdl_list));
}

/**
 * @brier allocate hash entry for hash list of ve_dma_req_hdl
 *
 * @param dma_req_hdl_list hash list that value of each entry is
 *                         vhve_dma_hashent.
 *
 * @return pointer to vhve_dma_hashent on success, null on failure
 **/
static vhve_dma_hashent *veos_vhve_dma_hash_alloc_ent(
		hash_table_t *dma_req_hdl_list)
{
	vhve_dma_hashent *e;
	hash_key_t key;
	hash_value_t value;

	e = malloc(sizeof(vhve_dma_hashent));
	if (!e)
		return NULL;
	e->hdl = NULL;

	key.type   = HASH_KEY_ULONG;
	key.ul     = (uint64_t)e;
	value.type = HASH_VALUE_PTR;
	value.ptr  = (void *)e;
	if (HASH_SUCCESS != hash_enter(dma_req_hdl_list, &key, &value)) {
		free(e);
		return NULL;
	}
	return e;
}

/**
 * @brier delete hash entry in hash list of ve_dma_req_hdl
 *
 * @param dma_req_hdl_list hash list that value of each entry is
 *                         vhve_dma_hashent.
 * @param e an entry of dma_req_hdl_list to be deleted.
 **/
static void veos_vhve_dma_hash_delete_ent(hash_table_t *dma_req_hdl_list,
		vhve_dma_hashent *e)
{
	hash_key_t key;

	key.type = HASH_KEY_ULONG;
	key.ul   = (uint64_t)e;
	if (HASH_SUCCESS != hash_delete(dma_req_hdl_list, &key)) {
		VEOS_ERROR("Fail to delete hash entry for key %lu", key.ul);
		return;
	}
	free(e);
	return;
}

/**
 * @brier look up entry in hash list and get ve_dma_req_hdl
 *
 * @param dma_req_hdl_list hash list that value of each entry is
 *                         vhve_dma_hashent.
 * @param req hash key of entry
 *
 * @return pointer to ve_dma_req_hdl on success, null on failure
 **/
static ve_dma_req_hdl *veos_vhve_dma_hash_lookup(hash_table_t *dma_req_hdl_list,
		uint64_t req)
{
	ve_dma_req_hdl *hdl;
	int error;
	hash_key_t key;
	hash_value_t value;

	key.type = HASH_KEY_ULONG;
	key.ul   = req;
	error = hash_lookup(dma_req_hdl_list, &key, &value);
	if (HASH_SUCCESS != error) {
		VEOS_ERROR("Fail to lookup hash entry for key %lu: %s",
				req, hash_error_string(error));
		return NULL;
	}
	hdl = ((vhve_dma_hashent *)value.ptr)->hdl;
	return hdl;
}

/**
 * @ This is request interface for dma
 *
 * @param[in] pti containing REQ info.
 *
 * @return On Success return 0 and -1 on failure.
 **/
int veos_handle_vhve_dma_req(veos_vhve_thread_arg_t *pti)
{
	int ret = -1;
	ve_dma_status_t st;
	ve_dma_req_hdl *hdl = NULL;
	ve_dma_hdl *dh = NULL;
	struct ve_node_struct *vnode_info;
	int sd;
	struct vhve_dma_args *args;
	struct ve_task_struct *tsk = NULL;
	struct vhve_result ack = { VHVE_RESULT, 0, 0 };
	vhve_dma_hashent *hash_ent = NULL;

	VEOS_TRACE("Entering");

	if (!pti) {
		VEOS_ERROR("NULL argument received");
		goto hndl_return;
	}

	if (pti->vh_proc_size != sizeof(struct vhve_dma_args)) {
		VEOS_ERROR("Receive cmd size is unexpected: %zd(should be %zd)",
				pti->vh_proc_size, sizeof(struct vhve_dma_args));
		goto hndl_return;
	}

	sd = pti->socket_descriptor;
	args = (struct vhve_dma_args *)(pti->vh_proc_msg);

	if (args->reqid) {
		hdl = veos_vhve_dma_hash_lookup(pti->dma_req_hdl_list,
				args->reqid);
		if (!hdl) {
			ack.ret = -EINVAL;
			goto send_ack;
		}
		if (args->is_wait)
			st = ve_dma_wait(hdl);
		else
			st = ve_dma_test(hdl);
		switch (st) {
		case VE_DMA_STATUS_ERROR:
		case VE_DMA_STATUS_CANCELED:
			ack.ret = -EFAULT;
			break;
		case VE_DMA_STATUS_NOT_FINISHED:
			ack.ret = 1;
			break;
		case  VE_DMA_STATUS_OK:
		default:
			ack.ret = 0;
			break;
		}
		if (ack.ret != 1) {
			veos_vhve_dma_hash_delete_ent(pti->dma_req_hdl_list,
					(vhve_dma_hashent *)args->reqid);
			ve_dma_req_free(hdl);
		}
		ret = 0;
		goto send_ack;
	}

	tsk = find_ve_task_struct(args->vepid);
	if (NULL == tsk) {
		ack.ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %ld",
				strerror(errno), args->vepid);
		goto send_ack;
	}
	vnode_info = VE_NODE(tsk->node_id);
	dh = vnode_info->dh;

	/* ve_task_struct is not updated by setuid(). For checking credential
         * more precisely, psm_get_ve_proc_info() should be used.
         * Following way puts priority on performance */
	if (!(pti->cred.uid == tsk->uid && pti->cred.gid == tsk->gid)) {
		VEOS_DEBUG("VH proc:%d has no permission of memory access for VE proc:%d",
				pti->cred.pid, tsk->pid);
		ack.ret = -EPERM;
		goto send_ack;
	}

	if (!args->is_wait) {
		hash_ent = veos_vhve_dma_hash_alloc_ent(pti->dma_req_hdl_list);
		if (NULL == hash_ent) {
			ack.ret = -ENOMEM;
			goto send_ack;
		}
	}

	if (args->is_write) {
		hdl = ve_dma_post_p_va_with_opt(dh, VE_DMA_VHVA,
				pti->cred.pid, args->srcaddr,
				VE_DMA_VEMVA, args->vepid, args->dstaddr,
				args->size, args->opt, pti->socket_descriptor);
	} else {
		hdl = ve_dma_post_p_va_with_opt(dh, VE_DMA_VEMVA,
				args->vepid, args->srcaddr,
				VE_DMA_VHVA, pti->cred.pid, args->dstaddr,
				args->size, args->opt, pti->socket_descriptor);
	}
	if (!hdl) {
		ack.ret = -EFAULT;
		VEOS_DEBUG("Error (%s) posting DMA request failed",
				strerror(errno));
		goto err_dma;
	}

	if (!args->is_wait) {
		hash_ent->hdl = hdl;
		ack.val = (uint64_t)hash_ent;
	} else {
		st = ve_dma_wait(hdl);
		switch (st) {
		case VE_DMA_STATUS_ERROR:
		case VE_DMA_STATUS_CANCELED:
			ack.ret = -EFAULT;
			break;
		case  VE_DMA_STATUS_OK:
		default:
			ack.ret = 0;
			break;
		}
		ve_dma_req_free(hdl);
	}
	ack.ret = 0;
	ret = 0;

err_dma:
	if (hash_ent && ret)
		veos_vhve_dma_hash_delete_ent(pti->dma_req_hdl_list,
				hash_ent);
send_ack:
	ret = psm_pseudo_send_cmd(sd, &ack, sizeof(struct vhve_result));
	if (tsk)
		put_ve_task_struct(tsk);
hndl_return:
	VEOS_TRACE("returned");
	return ret;
}
