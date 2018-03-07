/*
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
 * @file veos_cr.c
 * @brief CR functions in VEOS.
 *
 * @internal
 * @author CR
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "proto_buff_schema.pb-c.h"
#include "comm_request.h"
#include "ived_request.h"
#include "vehva_mgmt.h"

#include "ived.pb-c.h"
#include "ived_ipc.h"
#include "vecr_defs.h"
#include "veos_ived.h"
#include "veos_ived_common.h"
#include "vesync.h"
#include "ived_common.h"
#include "cr_api.h"

#define VALID_CR_MODE			(VE_CR_THREAD | VE_CR_MPI)
#define INVALID_CR_PAGE_NUM		0xffffffffffffffffll
#define DUMMY_CR_PAGE_NUM_FOR_THREAD	0xfffffffffffffffell
#define INVALID_VEHVA			0xffffffffffffffffll
#define CR_VEHVA_START			0x0000000c0000ll
#define CR_VEHVA_END			0x0000000fffffll

/**
 * @brief Initialize CR-related data
 *
 * @param [in] resource		Resource data to initialize
 *
 * @return 0 on success, -1 on failure
 */
int veos_cr_init_resource(struct ived_shared_resource_data *resource)
{
	struct proc_cr_page *cr_page = NULL;
	int i;
	int ret;

	ret = pthread_mutex_init(&resource->proc_cr_lock, NULL);
	if (ret) {
		IVED_ERROR(log4cat_veos_ived,
			"Initializing a mutex faile: %s",
			strerror(ret));
		return -1;
	}
	for (i = 0; i < MAX_CRD_PER_CORE; i++) {
		cr_page = resource->cr_page + i;
		cr_page->mode_flag = 0;
		cr_page->cr_page_num = INVALID_CR_PAGE_NUM;
	}
	return 0;
}

/**
 * @brief Get resource data
 *
 * @param [in] tsk	Task structure
 *
 * @return The pointer of resource data on success, NULL on failure
 */
static struct ived_shared_resource_data *veos_get_resource_data(
						struct ve_task_struct *tsk)
{
	if (tsk->ived_resource == NULL) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to get the resource data of pid:%d", tsk->pid);
		return NULL;
	}
	return tsk->ived_resource;
}

/**
 * @brief Invokes CR RPC on IVED.
 *
 * @param [in]	cr_arg		Arguments
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_common(RpcCrArg *cr_arg, int64_t *ived_retval)
{
	IvedReturn *reply;
	int ived_req_sock;
	int ret;

	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Fail to create socket with IVED");
		return IVED_RPC_ERR;
	}

	ret = ived_exchange_cr_msg(ived_req_sock, cr_arg, &reply);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived, "Failed to communicate with IVED");
		ived_finish_soc(ived_req_sock);
		return ret;
	}
	if (ived_retval) {
		if (reply->retval < 0)
			*ived_retval = reply->error;
		else
			*ived_retval = reply->retval;
	}
	ived_return__free_unpacked(reply, NULL);
	ived_finish_soc(ived_req_sock);
	return 0;
}

/**
 * @brief Invokes CR ALLOC RPC on IVED.
 *
 * @param [in]	mode_flag	Mode flag
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	my_uid		Uid of the requester
 * @param [in]	my_crd_number	CR directory number
 * @param [in]	cr_page		CR page number
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_alloc(uint64_t mode_flag, pid_t my_pid,
				uid_t my_uid, uint64_t my_crd_number,
				uint64_t cr_page, int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubAlloc cr_arg_alloc = RPC_CR_SUB_ALLOC__INIT;

	cr_arg.subcmd = CR_ALLOC;
	cr_arg.alloc = &cr_arg_alloc;
	cr_arg.alloc->mode_flag = mode_flag;
	cr_arg.alloc->my_pid = my_pid;
	cr_arg.alloc->my_uid = my_uid;
	cr_arg.alloc->my_crd_number = my_crd_number;
	cr_arg.alloc->cr_page = cr_page;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Invokes CR ATTACH RPC on IVED.
 *
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	my_uid		Uid of the requester
 * @param [in]	pid		Pid of the existing user
 * @param [in]	crd_number	CR directory number
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_attach(pid_t my_pid, uid_t my_uid, pid_t pid,
				uint64_t crd_number, int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubAttach cr_arg_attach = RPC_CR_SUB_ATTACH__INIT;

	cr_arg.subcmd = CR_ATTACH;
	cr_arg.attach = &cr_arg_attach;
	cr_arg.attach->my_pid = my_pid;
	cr_arg.attach->my_uid = my_uid;
	cr_arg.attach->pid = pid;
	cr_arg.attach->crd_number = crd_number;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Invokes CR ATTACHED RPC on IVED.
 *
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	my_crd_number	CR directory number
 * @param [in]	my_vehva	VEHVA
 * @param [in]	pid		Pid of the existing user
 * @param [in]	crd_number	CR directory number of the existing user
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_attached(pid_t my_pid, uint64_t my_crd_number,
		uint64_t my_vehva, pid_t pid, uint64_t crd_number,
						int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubAttached cr_arg_attached = RPC_CR_SUB_ATTACHED__INIT;

	cr_arg.subcmd = CR_ATTACHED;
	cr_arg.attached = &cr_arg_attached;
	cr_arg.attached->my_pid = my_pid;
	if (my_crd_number != INVALID_CR_PAGE_NUM) {
		cr_arg.attached->has_my_crd_number = 1;
		cr_arg.attached->my_crd_number = my_crd_number;
	}
	if (my_vehva != INVALID_VEHVA) {
		cr_arg.attached->has_my_vehva = 1;
		cr_arg.attached->my_vehva = my_vehva;
	}
	cr_arg.attached->pid = pid;
	cr_arg.attached->crd_number = crd_number;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Invokes CR CANCEL ATTACH RPC on IVED.
 *
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	pid		Pid of the existing user
 * @param [in]	crd_number	CR directory number of the existing user
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_cancel_attach(pid_t my_pid, pid_t pid,
				uint64_t crd_number, int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubCancelAttach cr_arg_cancel_attach =
		RPC_CR_SUB_CANCEL_ATTACH__INIT;

	cr_arg.subcmd = CR_CANCEL_ATTACH;
	cr_arg.cancel = &cr_arg_cancel_attach;
	cr_arg.cancel->my_pid = my_pid;
	cr_arg.cancel->pid = pid;
	cr_arg.cancel->crd_number = crd_number;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Invokes CR RELEASE LOCAL RPC on IVED.
 *
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	my_crd_number	CR directory number
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 */
static int veos_cr_rpc_release_local(pid_t my_pid, uint64_t my_crd_number,
						int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubReleaseLocal cr_arg_release_local =
		RPC_CR_SUB_RELEASE_LOCAL__INIT;

	cr_arg.subcmd = CR_RELEASE_LOCAL;
	cr_arg.release_local = &cr_arg_release_local;
	cr_arg.release_local->my_pid = my_pid;
	cr_arg.release_local->my_crd_number = my_crd_number;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Invokes CR RELEASE REMOTE RPC on IVED.
 *
 * @param [in]	my_pid		Pid of the requester
 * @param [in]	my_vehva	VEHVA
 * @param [out]	ived_retval	Return value from IVED
 *
 * @return Result of RPC
 * @retval 0 on success
 * @retval IVED_RPC_ERR on failure before sending a message
 * @retval IVED_RPC_ERR_SEND on failure during sending
 * @retval IVED_RPC_ERR_RECV on failure during receiving
 *
 */
static int veos_cr_rpc_release_remote(pid_t my_pid, uint64_t my_vehva,
						int64_t *ived_retval)
{
	RpcCrArg cr_arg = RPC_CR_ARG__INIT;
	RpcCrSubReleaseRemote cr_arg_release_remote =
		RPC_CR_SUB_RELEASE_REMOTE__INIT;

	cr_arg.subcmd = CR_RELEASE_REMOTE;
	cr_arg.release_remote = &cr_arg_release_remote;
	cr_arg.release_remote->my_pid = my_pid;
	cr_arg.release_remote->my_vehva = my_vehva;
	return veos_cr_rpc_common(&cr_arg, ived_retval);
}

/**
 * @brief Handles CR_ALLOC sub-command of CR_CMD command.
 *
 * @param [in] mode_flag	This flag specifies attributes of an CR
 * @param [in] cred		A credential of pseudo process
 * @param [in] tsk		Task structure
 *
 * @return CR directory number on success, -errno on failure
 */
static int64_t veos_cr_alloc(uint64_t mode_flag, struct ucred *cred,
						struct ve_task_struct *tsk)
{
	int crd_number;
	struct ived_shared_resource_data *resource = NULL;
	uint64_t cr_page_num = INVALID_CR_PAGE_NUM;
	int64_t ived_retval;
	int64_t veos_retval;
	int ret;

	if ((mode_flag & VALID_CR_MODE) != mode_flag) {
		IVED_DEBUG(log4cat_veos_ived,
			"mode:%#"PRIx64" pid:%d",
			mode_flag, cred->pid);
		return -EINVAL;
	}

	if (((mode_flag & VE_CR_THREAD) && (mode_flag & VE_CR_MPI)) ||
			((mode_flag & (VE_CR_THREAD | VE_CR_MPI)) == 0)) {
		IVED_DEBUG(log4cat_veos_ived,
			"mode:%#"PRIx64" pid:%d",
			mode_flag, cred->pid);
		return -EINVAL;
	}

	if ((mode_flag & VE_CR_MPI) && IVED_LINKAGE_OFF) {
		IVED_DEBUG(log4cat_veos_ived, "IVED is unavailable");
		return -ENOTSUP;
	}

	if (IVED_LINKAGE_ON) {
		resource = veos_get_resource_data(tsk);
		if (resource == NULL)
			return -EINVAL;
	}

	veos_sync_r_bar01_bar3();
	IVED_DEBUG(log4cat_veos_ived,
		"Allocating a CR page with mode %#"PRIx64" to pid:%d",
		mode_flag, cred->pid);
	crd_number = veos_allocate_cr_page(mode_flag, cred->pid);
	if (crd_number < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to allocate a CR page with mode %#"PRIx64" to pid:%d: %s",
			mode_flag, cred->pid, strerror(-crd_number));
		/*
		 * The possible reason is that a CR directory entry or
		 * a CR page is not available.
		 */
		return -ENOMEM;
	}
	if (crd_number >= MAX_CRD_PER_CORE) {
		IVED_ERROR(log4cat_veos_ived,
			"The allocated CR directory number is invalid: %d",
			crd_number);
		/*
		 * Return -ENOMEM: A CR directory entry or a CR page
		 * is not available.
		 */
		veos_retval = -ENOMEM;
		goto err_release_cr;
	}

	if (IVED_LINKAGE_ON) {
		struct proc_cr_page *cr_page;

		if (mode_flag & VE_CR_MPI) {
			ret = veos_get_cr_page(crd_number, cred->pid);
			if (ret < 0) {
				IVED_ERROR(log4cat_veos_ived,
					"Failed to get the CR page referenced by pid:%d crd:%#x: %s",
					cred->pid, crd_number,
					strerror(-ret));
				/*
				 * Return -ENOMEM: A CR directory
				 * entry or a CR page is not
				 * available.
				 */
				veos_retval = -ENOMEM;
				goto err_release_cr;
			}
			cr_page_num = ret;
			IVED_DEBUG(log4cat_veos_ived,
				"Got cr_page_num:%"PRIu64, cr_page_num);

			ret = veos_cr_rpc_alloc(mode_flag, cred->pid,
				cred->uid, crd_number, cr_page_num,
				&ived_retval);
			if (ret != 0) {
				veos_retval = -ECANCELED;
				if (ret == IVED_RPC_ERR_RECV) {
					/*
					 * We do not know whether the
					 * CR page is registered to
					 * IVED or not.
					 */
					goto err_release_cr;
				}
				goto err_put_cr_page;
			}
			if (ived_retval != 0) {
				veos_retval = ived_retval;
				IVED_ERROR(log4cat_veos_ived,
					"IVED returned failure on allocating the CR page referenced by pid:%d crd:%#x: %s",
					cred->pid, crd_number,
					strerror(-ived_retval));
				goto err_put_cr_page;
			}
		} else {
			cr_page_num = DUMMY_CR_PAGE_NUM_FOR_THREAD;
		}

		assert(resource);
		pthread_mutex_lock(&resource->proc_cr_lock);
		cr_page = resource->cr_page + crd_number;
		cr_page->mode_flag = mode_flag;
		cr_page->cr_page_num = cr_page_num;
		pthread_mutex_unlock(&resource->proc_cr_lock);
	}

	veos_sync_r_bar2();
	IVED_DEBUG(log4cat_veos_ived,
		"Allocated the CR page referenced by crd:%#x to pid:%d",
		crd_number, cred->pid);

	return crd_number;
err_put_cr_page:
	veos_put_cr_page(cr_page_num);
err_release_cr:
	veos_detach_cr_page(crd_number, cred->pid);
	veos_sync_r_bar2();
	return veos_retval;
}

/**
 * @brief Handles CR_RELEASE_LOCAL sub-command of CR_CMD command.
 *
 * @param [in] crd_number	CR directory number
 * @param [in] cred		A credential of pseudo process
 * @param [in] tsk		Task structure
 *
 * @return 0 on success, -errno on failure
 */
static int64_t veos_cr_release_local(uint64_t crd_number, struct ucred *cred,
						struct ve_task_struct *tsk)
{
	uint64_t mode_flag = 0;
	uint64_t cr_page_num = INVALID_CR_PAGE_NUM;
	int64_t ived_retval;
	int ret;

	if (crd_number >= MAX_CRD_PER_CORE)
		return -EINVAL;

	if (IVED_LINKAGE_ON) {
		struct proc_cr_page *cr_page;
		struct ived_shared_resource_data *resource;

		resource = veos_get_resource_data(tsk);
		if (resource == NULL)
			return -EINVAL;

		pthread_mutex_lock(&resource->proc_cr_lock);
		cr_page = resource->cr_page + crd_number;
		mode_flag = cr_page->mode_flag;

		if (mode_flag == 0) {
			pthread_mutex_unlock(&resource->proc_cr_lock);
			IVED_ERROR(log4cat_veos_ived,
				"Releasing the non-allocated local CR page referenced by pid:%d crd:%#"PRIx64" is requested",
				cred->pid, crd_number);
			return -EINVAL;
		}
		cr_page_num = cr_page->cr_page_num;
		cr_page->mode_flag = 0;
		cr_page->cr_page_num = INVALID_CR_PAGE_NUM;
		pthread_mutex_unlock(&resource->proc_cr_lock);
	}

	IVED_DEBUG(log4cat_veos_ived,
		"Releasing the local CR page referenced by pid:%d crd:%#"
		PRIx64,	cred->pid, crd_number);

	veos_sync_r_bar01_bar3();
	ret = veos_detach_cr_page(crd_number, cred->pid);
	if (ret) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to release the local CR page referenced by pid:%d crd:%#"PRIx64": %s",
			cred->pid, crd_number, strerror(-ret));
		/*
		 * We should not return error to VE process because we
		 * have cleared cr_page.
		 */
	} else {
		IVED_DEBUG(log4cat_veos_ived,
			"Released the local CR page referenced by pid:%d crd:%#"PRIx64,
			cred->pid, crd_number);
	}

	if (IVED_LINKAGE_ON) {
		if (mode_flag & VE_CR_MPI) {
			ret = veos_cr_rpc_release_local(cred->pid,
					crd_number, &ived_retval);
			if (ret == 0 && ived_retval < 0) {
				IVED_ERROR(log4cat_veos_ived,
					"IVED returned failure on releasing the CR page referenced by pid:%d crd:%#" PRIx64": %s",
					cred->pid, crd_number,
					strerror(-ived_retval));
			} else if (ret == 0 && ived_retval == 0) {
				if (cr_page_num != INVALID_CR_PAGE_NUM)
					veos_put_cr_page(cr_page_num);
			}
		}
	}
	veos_sync_r_bar2();
	return 0;
}

/**
 * @brief Handles CR_ATTACH_LOCAL sub-command of CR_CMD command.
 *
 * @param [in] pid		A process ID.
 * @param [in] crd_number	CR directory number
 * @param [in] cred		A credential of pseudo process
 * @param [in] tsk		Task structure
 *
 * @return CR directory number on success, -errno on failure
 */
static int64_t veos_cr_attach_local(pid_t pid, uint64_t crd_number,
			struct ucred *cred, struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct proc_cr_page *cr_page;
	int cr_page_num;
	int64_t new_crd_number;
	int64_t veos_retval;
	int64_t ived_retval;
	int ret;

	if (IVED_LINKAGE_OFF) {
		IVED_DEBUG(log4cat_veos_ived, "IVED is unavailable");
		return -ENOTSUP;
	}

	if (crd_number >= MAX_CRD_PER_CORE)
		return -EINVAL;

	if (pid == cred->pid)
		return -EINVAL;

	resource = veos_get_resource_data(tsk);
	if (resource == NULL)
		return -EINVAL;

	IVED_DEBUG(log4cat_veos_ived,
		"Attaching the local CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d",
		 pid, crd_number, cred->pid);
	ret = veos_cr_rpc_attach(cred->pid, cred->uid, pid, crd_number,
							&ived_retval);
	if (ret != 0)
		return -ECANCELED;
	if (ived_retval < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"IVED returned failure on attaching the CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d: %s",
			pid, crd_number, cred->pid, strerror(-ived_retval));
		return ived_retval;
	}
	if (ived_retval > 0) {
		/* Remote CR page */
		IVED_ERROR(log4cat_veos_ived,
			"The CR page referenced by pid:%d crd:%#"PRIx64" is in remote VE node",
			pid, crd_number);
		veos_retval = -EINVAL;
		goto err_cancel;
	}
	new_crd_number = veos_attach_cr_page(crd_number, pid, cred->pid);
	if (new_crd_number < -1) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to attach the local CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d: %s",
			pid, crd_number, cred->pid, strerror(-new_crd_number));
		switch (-new_crd_number) {
		case EINVAL:
			/* fall through */
		case ESRCH:
			/* fall through */
		case ENOMEM:
			veos_retval = new_crd_number;
			break;
		case EFAULT:
			veos_retval = -EINVAL;
			break;
		default:
			veos_retval = -EINVAL;
		}
		goto err_cancel;
	}
	if (new_crd_number >= MAX_CRD_PER_CORE) {
		IVED_ERROR(log4cat_veos_ived,
			"The allocated CR directory number is invalid: %#"PRIx64,
			new_crd_number);
		/*
		 * Return -ENOMEM: A CR directory entry or a CR page
		 * is not available.
		 */
		veos_retval = -ENOMEM;
		goto err_detach_cr;
	}

	cr_page_num = veos_get_cr_page(new_crd_number, cred->pid);
	if (cr_page_num < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to get the CR page referenced by pid:%d crd:%#"PRIx64": %s",
			cred->pid, new_crd_number, strerror(-cr_page_num));
		/*
		 * Return -ENOMEM: A CR directory entry or a CR page
		 * is not available.
		 */
		veos_retval = -ENOMEM;
		goto err_detach_cr;
	}
	IVED_DEBUG(log4cat_veos_ived, "Got cr_page_num:%d", cr_page_num);
	veos_put_cr_page(cr_page_num);
	IVED_DEBUG(log4cat_veos_ived, "Put cr_page_num:%d", cr_page_num);

	ret = veos_cr_rpc_attached(cred->pid, new_crd_number,
		INVALID_VEHVA, pid, crd_number, &ived_retval);
	if (ret != 0) {
		veos_retval = -ECANCELED;
		goto err_detach_cr;
	}
	if (ived_retval != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"IVED returned failure on notify the CR page referenced by pid:%d crd:%#"PRIx64": %s",
			cred->pid, new_crd_number, strerror(-ived_retval));
		veos_retval = ived_retval;
		goto err_detach_cr;
	}

	pthread_mutex_lock(&resource->proc_cr_lock);
	cr_page = resource->cr_page + new_crd_number;
	cr_page->mode_flag = VE_CR_MPI;
	cr_page->cr_page_num = cr_page_num;
	pthread_mutex_unlock(&resource->proc_cr_lock);

	IVED_DEBUG(log4cat_veos_ived,
		"Attached the local CR page to pid:%d crd:%#"PRIx64,
		cred->pid, new_crd_number);
	return new_crd_number;

err_detach_cr:
	veos_detach_cr_page(new_crd_number, cred->pid);
err_cancel:
	veos_cr_rpc_cancel_attach(cred->pid, pid, crd_number, NULL);
	return veos_retval;
}

/**
 * @brief Handles CR_ATTACH_REMOTE sub-command of CR_CMD command.
 *
 * @param [in] pid		A process ID.
 * @param [in] crd_number	An index of CRD entry
 * @param [in] cred		A credential of pseudo process
 *
 * @return VEHVA on success, -errno on failure
 */
static int64_t veos_cr_attach_remote(pid_t pid, uint64_t crd_number,
						struct ucred *cred)
{
	uint64_t remote_cr_page_vhsaa;
	uint64_t vhsaa[3];
	int64_t vehva;
	int64_t ived_retval;
	int64_t veos_retval;
	int ret;

	if (IVED_LINKAGE_OFF) {
		IVED_DEBUG(log4cat_veos_ived, "IVED is unavailable");
		return -ENOTSUP;
	}

	if (crd_number >= MAX_CRD_PER_CORE)
		return -EINVAL;

	IVED_DEBUG(log4cat_veos_ived,
		"Attaching the remote CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d",
		 pid, crd_number, cred->pid);

	ret = veos_cr_rpc_attach(cred->pid, cred->uid, pid, crd_number,
							&ived_retval);
	if (ret != 0)
		return -ECANCELED;
	if (ived_retval < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"IVED returned failure on attaching the CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d: %s",
			pid, crd_number, cred->pid, strerror(-ived_retval));
		return ived_retval;
	}
	if (ived_retval == 0) {
		/* Local CR page */
		IVED_ERROR(log4cat_veos_ived,
			"The CR page referenced by pid:%d crd:%#"PRIx64" is in local VE node",
			pid, crd_number);
		veos_retval = -EINVAL;
		goto err_cancel;
	}

	remote_cr_page_vhsaa = ived_retval;
	vhsaa[0] = remote_cr_page_vhsaa;
	vhsaa[1] = remote_cr_page_vhsaa + PAGE_SIZE_4KB;
	vhsaa[2] = 0;
	vehva = veos_alloc_dmaatb_entry_for_aa(cred->pid, vhsaa,
				PROT_READ | PROT_WRITE, VE_ADDR_VHSAA,
						VEHVA_CR | VEHVA_4K);
	if (vehva < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to attach the remote CR page referenced by pid:%d crd:%#"PRIx64" to pid:%d: %s",
			pid, crd_number, cred->pid, strerror(-vehva));
		veos_retval = -ENOMEM;
		goto err_cancel;
	}

	ret = veos_cr_rpc_attached(cred->pid, INVALID_CR_PAGE_NUM, vehva,
					pid, crd_number, &ived_retval);
	if (ret != 0) {
		veos_retval = -ECANCELED;
		goto err_free_dmaatb;
	}
	if (ived_retval != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"IVED returned failure on notify the CR page referenced by pid:%d vehva:%#"PRIx64": %s",
			cred->pid, vehva, strerror(-ived_retval));
		veos_retval = ived_retval;
		goto err_free_dmaatb;
	}

	IVED_DEBUG(log4cat_veos_ived,
		"Attached the remote CR page to pid:%d vehva:%#"PRIx64,
		cred->pid, vehva);
	return vehva;

err_free_dmaatb:
	veos_free_dmaatb_entry(cred->pid, vehva, PAGE_SIZE_4KB * 2);
err_cancel:
	veos_cr_rpc_cancel_attach(cred->pid, pid, crd_number, NULL);
	return veos_retval;
}

/**
 * @brief Handles CR_RELEASE_REMOTE sub-command of CR_CMD command.
 *
 * @param [in] vehva	VEHVA
 * @param [in] cred	A credential of pseudo process
 *
 * @return 0 on success, -errno on failure
 */
static int64_t veos_cr_release_remote(uint64_t vehva, struct ucred *cred)
{
	int64_t ived_retval;
	int ret;

	if (IVED_LINKAGE_OFF) {
		IVED_DEBUG(log4cat_veos_ived, "IVED is unavailable");
		return -ENOTSUP;
	}

	if (vehva < CR_VEHVA_START || vehva > CR_VEHVA_END ||
					!IS_ALIGNED(vehva, PAGE_SIZE_4KB))
		return -EINVAL;

	IVED_DEBUG(log4cat_veos_ived,
		"Releasing the remote CR page referenced by pid:%d vehva:%#"PRIx64,
		cred->pid, vehva);
	ret = veos_free_dmaatb_entry(cred->pid, vehva, PAGE_SIZE_4KB * 2);
	if (ret) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to release the remote CR page referenced by pid:%d vehva:%#"PRIx64": %s",
			cred->pid, vehva, strerror(-ret));
		return -EINVAL;
	}

	ret = veos_cr_rpc_release_remote(cred->pid, vehva, &ived_retval);
	if (ret == 0 && ived_retval < 0) {
		IVED_ERROR(log4cat_veos_ived,
			"IVED returned failure on releasing the CR page referenced by pid:%d vehva:%#" PRIx64": %s",
			 cred->pid, vehva, strerror(-ived_retval));
	}
	IVED_DEBUG(log4cat_veos_ived,
		"Released the remote CR page referenced by pid:%d vehva:%#"PRIx64,
		cred->pid, vehva);
	return 0;
}

/**
 * @brief Handles CR_CMD command from pseudo process.
 *
 * @param [in]	pti	 Containing REQ info
 *
 * @return: 0 on success, -1 on failure
 */
int veos_shared_cr_crctl(veos_thread_arg_t *pti)
{
	struct ucred cred;
	struct ve_task_struct *tsk;
	int ucred_size = sizeof(struct ucred);
	ProtobufCBinaryData *bin_data;
	struct cr_args *cr_args;
	int64_t veos_retval;
	int ret;

	assert(pti);

	ret = getsockopt(pti->socket_descriptor,
			 SOL_SOCKET, SO_PEERCRED, &cred,
			 (socklen_t *)&ucred_size);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Getting credential failed: %s",
			strerror(errno));
		/*
		 * Returns without sending reply, because the socket
		 * is in a unexpected state.
		 */
		return -1;
	}

	bin_data = (ProtobufCBinaryData *)
		(&(((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg));
	if (bin_data->len != sizeof(struct cr_args)) {
		IVED_DEBUG(log4cat_veos_ived, "Invalid message length: %d",
			(int)bin_data->len);
		veos_retval = -EINVAL;
		goto err_ret;
	}
	if (bin_data->data == NULL) {
		IVED_DEBUG(log4cat_veos_ived, "Message data is null");
		veos_retval = -EINVAL;
		goto err_ret;
	}
	cr_args = (struct cr_args *)bin_data->data;
	IVED_DEBUG(log4cat_veos_ived, "Request from pid:%d, Sub command:%#x",
		cred.pid, cr_args->subcmd);

	tsk = find_ve_task_struct(cred.pid);
	if (tsk == NULL) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to get the task struct of pid:%d", cred.pid);
		/*
		 * Set -ESRCH as return value though this value will
		 * never be returned to VE program.
		 */
		veos_retval = -ESRCH;
		goto err_ret;
	}

	switch (cr_args->subcmd) {
	case CR_ALLOC:
		veos_retval = veos_cr_alloc(cr_args->args[0], &cred, tsk);
		break;
	case CR_RELEASE_LOCAL:
		veos_retval = veos_cr_release_local(cr_args->args[0], &cred,
									tsk);
		break;
	case CR_ATTACH_LOCAL:
		veos_retval = veos_cr_attach_local(cr_args->args[0],
						cr_args->args[1], &cred, tsk);
		break;
	case CR_ATTACH_REMOTE:
		veos_retval = veos_cr_attach_remote(cr_args->args[0],
						cr_args->args[1], &cred);
		break;
	case CR_RELEASE_REMOTE:
		veos_retval = veos_cr_release_remote(cr_args->args[0], &cred);
		break;
	default:
		IVED_ERROR(log4cat_veos_ived, "Invalid request type. (%d)",
							cr_args->subcmd);
		veos_retval = -EINVAL;
		break;
	}
	put_ve_task_struct(tsk);
err_ret:
	ret = veos_ived_reply(veos_retval, NULL, pti);
	IVED_DEBUG(log4cat_veos_ived, "Request finished: %"PRId64,
							veos_retval);
	return ret;
}

/**
 * @brief Release the specified CR page
 *
 * @param [in] request		The request from IVED
 *
 * @return: 0 on success, -1 on failure
 */
static int veos_cr_not_referenced(RpcCrSubNotReferenced *request)
{
	int ret;

	if (request->cr_page >= MAX_CR_PAGE_PER_NODE)
		return -EINVAL;

	IVED_DEBUG(log4cat_veos_ived,
		"Releasing the CR page referenced by page number:%"PRIu64,
		request->cr_page);
	veos_sync_r_bar01_bar3();
	ret = veos_put_cr_page(request->cr_page);
	if (ret) {
		IVED_ERROR(log4cat_veos_ived,
			"Releasing the CR page referenced by page number:%"PRIu64" failed: %s",
			request->cr_page, strerror(-ret));
	} else {
		IVED_DEBUG(log4cat_veos_ived,
			"Released the CR page referenced by page number:%"PRIu64,
			request->cr_page);
	}
	veos_sync_r_bar2();
	return 0;
}

/**
 * @brief Handles IPC request from IVED
 *
 * @param [in] cr_args		The argument of the request from IVED
 *
 * @return: 0 on success, -1 on failure
 */
int veos_cr_rpc_from_ived(int sock_fd, RpcCrArg *cr_args)
{
	int64_t veos_retval;

	switch (cr_args->subcmd) {
	case CR_NOT_REFERENCED:
		if (cr_args->not_referenced == NULL) {
			veos_retval = -ECANCELED;
			goto err;
		}
		veos_retval = veos_cr_not_referenced(cr_args->not_referenced);
		break;
	default:
		veos_retval = -EINVAL;
	}
err:
	return ived_send_int64(sock_fd,
				veos_retval < 0 ? IVED_REQ_NG : veos_retval,
				veos_retval < 0 ? veos_retval : 0);
}

/**
 * @brief Releases all local CR page
 *
 * @param [in] tsk		Task of group leader of the process
 *
 * @return: 0 on success, -1 on failure
 */
int veos_cr_discard_all(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct proc_cr_page *cr_page;
	uint64_t mode_flag;
	uint64_t cr_page_num;
	int64_t ived_retval;
	int ret;
	int i;

	if (IVED_LINKAGE_OFF)
		return 0;

	resource = veos_get_resource_data(tsk);
	if (resource == NULL)
		return -1;

	veos_sync_r_bar01_bar3();
	for (i = 0; i < MAX_CRD_PER_CORE; i++) {
		pthread_mutex_lock(&resource->proc_cr_lock);

		cr_page = resource->cr_page + i;
		mode_flag = cr_page->mode_flag;
		cr_page_num = cr_page->cr_page_num;

		cr_page->mode_flag = 0;
		cr_page->cr_page_num = INVALID_CR_PAGE_NUM;
		pthread_mutex_unlock(&resource->proc_cr_lock);

		if ((mode_flag & VE_CR_MPI) == 0)
			continue;

		ret = veos_cr_rpc_release_local(tsk->pid, i, &ived_retval);
		if (ret == 0 && ived_retval < 0) {
			IVED_ERROR(log4cat_veos_ived,
				"IVED returned failure on releasing the CR page referenced by pid:%d crd:%#x: %s",
				tsk->pid, i, strerror(-ived_retval));
		} else if (ret == 0 && ived_retval == 0) {
			veos_put_cr_page(cr_page_num);
		}
	}
	veos_sync_r_bar2();
	return 0;
}
