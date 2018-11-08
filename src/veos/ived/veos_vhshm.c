/**
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
 * @file veos_vhshm.c
 * @brief VH-VE shared memory functions (VEOS side)
 *
 * @internal
 * @author VHSHM
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libved.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "veos_ived.h"
#include "veos_vhshm.h"
#include "ived_common.h"
#include "vhshm_defs.h"
#include "proto_buff_schema.pb-c.h"
#include "ived_request.h"
#include "veos.h"
#include "psm_comm.h"
#include "dmaatb_api.h"
#include "vehva_mgmt.h"

/**
 * @brief Check whether VHSHM lock is locked.
 *
 * @param [in] vhshm_lock Pointer to VHSHM lock in veos_vhshm structure
 */
static void veos_vhshm_check_lock_owned(pthread_mutex_t *vhshm_lock)
{
	int ret = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	ret = pthread_mutex_trylock(vhshm_lock);
	if (ret != EBUSY)
		veos_abort("Internal error : The VHSHM lock is missing, %s",
								strerror(ret));

	IVED_TRACE(log4cat_veos_ived, "Out func");
}

/**
 * @brief Initialize resource information of shared memory on VH in VEOS
 *
 * @param [in] ived_resource pointer to IVED resource data per process
 *
 * @retval 0 on success, -1 on failure.
 *
 * @note Ensure that ived_resource is not NULL before calling this function
 */
int veos_initialize_vhshm_resource(struct ived_shared_resource_data
								*ived_resource)
{
	int ret = 0;
	struct veos_vhshm *vhshm_resource =
					&(ived_resource->veos_vhshm_res_head);

	IVED_TRACE(log4cat_veos_ived, "In func");

	INIT_LIST_HEAD(&(vhshm_resource->res));

	ret = pthread_mutex_init(&(vhshm_resource->veos_vhshm_lock), NULL);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to initialize VHSHM lock due to %s",
				strerror(ret));
		ret = -1;
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");

	return ret;
}

/**
 * @brief Return responce to Pseudo Process
 *
 * @param[in] pseudo_sock_fd Descriptor used to communicate with VEOS.
 * @param[in] ret Return value to Pseudo Process
 *
 * @return 0 on Success, -1 on Failure.
 */
static int veos_vhshm_return_responce(int pseudo_sock_fd, int64_t ret)
{
	int retval = -1;
	PseudoVeosMessage vhshm_responce = PSEUDO_VEOS_MESSAGE__INIT;
	void *msg_buff = NULL;
	size_t msg_len = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	vhshm_responce.has_syscall_retval = true;
	vhshm_responce.syscall_retval = ret;

	msg_len = pseudo_veos_message__get_packed_size(&vhshm_responce);
	msg_buff = malloc(msg_len);
	if (msg_buff == NULL) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to allocate buffer for VHSHM responce");
		goto hndl_return;
	}
	memset(msg_buff, '\0', msg_len);
	if (msg_len != pseudo_veos_message__pack(&vhshm_responce, msg_buff)) {
		IVED_ERROR(log4cat_veos_ived, "Failed to pack VHSHM responce");
		goto hndl_return;
	}

	retval = psm_pseudo_send_cmd(pseudo_sock_fd, msg_buff, msg_len);
	if (retval < msg_len) {
		retval = -1;
		IVED_ERROR(log4cat_veos_ived, "Failed to send VHSHM responce");
		goto hndl_return;
	}

	retval = 0;

hndl_return:
	free(msg_buff);
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function check that specified VHSAA is Huge Page with kpageflags
 *
 * @param [in] vhsaa VHSAA address
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_vhshm_check_huge(uint64_t vhsaa)
{
	uint64_t PFN = 0;
	uint64_t pageflag = 0;
	uint64_t offset = 0;
	int fd = 0;
	int ret = 0;
	int retval = -1;
	long page_size = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		IVED_ERROR(log4cat_veos_ived, "Failed to get page size");
		goto hndl_return;
	}
	PFN = vhsaa / page_size;
	offset = PFN * sizeof(uint64_t);

hndl_retry:
	errno = 0;
	fd = open(KPAGEFLAG, O_RDONLY);
	if ((fd == -1) && (errno == ENOENT)) {
		IVED_DEBUG(log4cat_veos_ived, "Failed to open %s due to %s, "
						"retry to open it",
						KPAGEFLAG, strerror(errno));
		goto hndl_retry;
	} else if (fd == -1) {
		IVED_ERROR(log4cat_veos_ived, "Failed to open %s due to %s",
						KPAGEFLAG, strerror(errno));
		goto hndl_return;
	}

	errno = 0;
	ret = (int)pread(fd, (void *)&pageflag, sizeof(uint64_t), offset);
	if (ret == -1) {
		IVED_ERROR(log4cat_veos_ived,
			   "Failed to get page mode flag due to %s",
			   strerror(errno));
		goto hndl_close;
	} else if (ret == 0) {
		IVED_ERROR(log4cat_veos_ived, "Failed to read %s", KPAGEFLAG);
		goto hndl_close;
	}
	IVED_DEBUG(log4cat_veos_ived, "pageflag is 0x%lx", pageflag);

	if ((pageflag & HUGE_BIT) == 0) {
		IVED_ERROR(log4cat_veos_ived, "0x%lx is not Huge Page", vhsaa);
	} else {
		IVED_DEBUG(log4cat_veos_ived, "0x%lx is Huge Page", vhsaa);
		retval = 0;
	}

hndl_close:
	errno = 0;
	ret = close(fd);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
					"Failed to close fd due to %s",
					strerror(errno));
		retval = -1;
	}

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function release all which specified veos_vhshm_resouces
 * structure has.
 *
 * @param [in] info Pointer to veos_vhshm_resouces structure
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_vhshm_release_all_pindowned_pages
					(struct veos_vhshm_resouces *info)
{
	vedl_handle *handle = NULL;
	struct veos_vhshm_resouces *del_info = info;
	int retval = 0;
	int ret = 0;
	int i = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	handle = VE_HANDLE(0);

	for (i = 0; i < del_info->page_num; i++) {
		errno = 0;
		ret = vedl_release_pindown_page(handle, del_info->vhsaas[i]);
		if (ret != 0) {
			IVED_ERROR(log4cat_veos_ived,
				   "Failed to release pin-downed page 0x%lx due to %s",
				   del_info->vhsaas[i], strerror(errno));
			retval = -1;
		}
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}


/**
 * @brief This function release all pages which specified veos_vhshm structure
 * has.
 *
 * @param [in] vhshm_resource_struct pointer to veos_vhshm structure which has
 * deleting pagesd.
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_vhshm_release_all_pages
				(struct veos_vhshm *vhshm_resource_struct)
{
	int retval = 0;
	int ret = 0;
	struct veos_vhshm_resouces *del_info = NULL;
	struct list_head *p = NULL;
	struct list_head *q = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	veos_vhshm_check_lock_owned(&(vhshm_resource_struct->veos_vhshm_lock));

	list_for_each_safe(p, q, &(vhshm_resource_struct->res)) {
		del_info = list_entry(p, struct veos_vhshm_resouces, list);
		ret = veos_vhshm_release_all_pindowned_pages(del_info);
		if (ret != 0) {
			IVED_ERROR(log4cat_veos_ived,
						"Failed to release Huge page");
			retval = -1;
		}

		list_del(&(del_info->list));
		free(del_info->vhsaas);
		free(del_info);
		del_info = NULL;
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function stores resource informations of VHSHM
 *
 * @param [in] requester PID of Pseudo Process
 * @param [in] page_num A page number
 * @param [in] vhsaa An array of VHSAA, it must be null terminated.
 * @param [in] vehva VEHVA
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_vhshm_store_info(struct ve_task_struct *tsk_struct,
				int page_num, uint64_t *vhsaa, int64_t vehva)
{
	int retval = -1;
	struct veos_vhshm *vhshm_resource_struct = NULL;
	struct veos_vhshm_resouces *new_info = NULL;
	struct ived_shared_resource_data *ived_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	ived_struct = tsk_struct->ived_resource;
	vhshm_resource_struct = &(ived_struct->veos_vhshm_res_head);

	new_info = (struct veos_vhshm_resouces *)
				malloc(sizeof(struct veos_vhshm_resouces));
	if (new_info == NULL) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to allocate memory for resource info");
		goto hndl_return;
	}

	new_info->vehva = vehva;
	new_info->vhsaas = vhsaa;
	new_info->page_num = page_num;

	pthread_mutex_lock(&(vhshm_resource_struct->veos_vhshm_lock));

	list_add(&(new_info->list), &(vhshm_resource_struct->res));

	pthread_mutex_unlock(&(vhshm_resource_struct->veos_vhshm_lock));

	retval = 0;

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function gets veos_vhshm_resouces structure corresponding to
 * specified VEHVA
 *
 * @param [in] vhshm_struct Pointer to veos_vhshm structure of requester of
 * vh_shmdt()
 * @param [in] VEHVA VEHVA which being to be released.
 * @param [out] vhshm_resouces veos_vhshm_resouces structure corresponding to
 * specified VEHVA
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_vhshm_search_resource_info(
				struct veos_vhshm *vhshm_struct, uint64_t vehva,
				struct veos_vhshm_resouces **ret_struct)
{

	struct veos_vhshm_resouces *res_info = NULL;
	struct veos_vhshm_resouces *tmp = NULL;
	struct list_head *p = NULL;
	struct list_head *q = NULL;
	int retval = -1;

	IVED_TRACE(log4cat_veos_ived, "In func");

	veos_vhshm_check_lock_owned(&(vhshm_struct->veos_vhshm_lock));

	list_for_each_safe(p, q, &(vhshm_struct->res)) {
		tmp = list_entry(p, struct veos_vhshm_resouces, list);
		if (tmp->vehva == vehva) {
			res_info = tmp;
			retval = 0;
			break;
		}
	}

	*ret_struct = res_info;
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief Delete resource information of shared memory on VH
 *
 * @param[in] ived_resource pointer to IVED resource data per process
 *
 * @retval 0 on success, -1 on failure.
 */
int veos_delete_vhshm_resource(struct ived_shared_resource_data
								*ived_resource)
{
	int retval = 0;
	int ret = 0;
	struct veos_vhshm *vhshm_resource_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (ived_resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		retval = -1;
		goto hndl_return;
	}
	vhshm_resource_struct = &(ived_resource->veos_vhshm_res_head);

	pthread_mutex_lock(&(vhshm_resource_struct->veos_vhshm_lock));

	ret = veos_vhshm_release_all_pages(vhshm_resource_struct);
	if (ret != 0) {
		retval = -1;
		IVED_ERROR(log4cat_veos_ived,
				"Some VHSHM resources are not released");
	}

	pthread_mutex_unlock(&(vhshm_resource_struct->veos_vhshm_lock));

	ret = pthread_mutex_destroy(&(vhshm_resource_struct->veos_vhshm_lock));
	if (ret != 0) {
		retval = -1;
		IVED_ERROR(log4cat_veos_ived,
					"Failed to destroy lock due to %s",
					strerror(ret));
	}

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function maps received VHVA to DMAATB entry and returns VEHVA as
 * a result of mapping.
 *
 * @param [in] requester PID of Pseudo Process
 * @param [in] vhva VHVA which is being registered with DMAATB
 * @param [in] size A size of VHVA
 * @param [in] A permission of DMAATB entry.
 *
 * @retval VEHVA on success, -errno on failure.
 *
 * @note Ensure that tsk_struct is not NULL before calling this function.
 */
int64_t veos_map_vhva_to_vehva(pid_t requester, uint64_t vhva,
					size_t size, int shmflag,
					struct ve_task_struct *tsk_struct)
{
	int64_t retval = 0;
	int64_t vehva = 0;
	/* Array of VHSAA, It MUST BE NULL terminated ! */
	uint64_t *vhsaa = NULL;
	int ret = 0;
	int page_num = 0;
	int i = 0;
	int pfnmap = 0;
	int write_check = 0;
	int count = 0; /* Counter of transrated page */
	int permission = 0;
	vedl_handle *handle = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if ((void *)vhva == NULL) {
		IVED_ERROR(log4cat_veos_ived, "Receive invalid VHVA");
		retval = -EFAULT;
		goto hndl_return;

	}
	IVED_DEBUG(log4cat_veos_ived,
				"VHVA = 0x%lx, size = %ld, shmflag = %d",
				vhva, size, shmflag);
	if ((shmflag & SHM_RDONLY) != 0) {
		permission = PROT_READ;
	} else {
		permission = (PROT_READ | PROT_WRITE);
		write_check = 1;
	}
	IVED_DEBUG(log4cat_veos_ived, "Permission : %d, Write : %d",
						permission, write_check);

	handle = VE_HANDLE(0);

	page_num = (size / HUGE_PAGE_SIZE_2MB);
	if ((size % HUGE_PAGE_SIZE_2MB) != 0)
		page_num++;

	vhsaa = (uint64_t *)malloc((page_num + 1) * sizeof(uint64_t));
	if (vhsaa == NULL) {
		IVED_ERROR(log4cat_veos_ived,
					"Failed to allocate memory for VHSAA");
		retval = -ENOMEM;
		goto hndl_return;
	}
	memset(vhsaa, '\0', (page_num + 1) * sizeof(uint64_t));
	for (i = 0; i < page_num; i++) {
		IVED_DEBUG(log4cat_veos_ived,
					"Transrate VHVA : 0x%lx",
					vhva + i * HUGE_PAGE_SIZE_2MB);
		errno = 0;
		vhsaa[i] = vedl_get_dma_address(handle,
					(void *)(vhva + i * HUGE_PAGE_SIZE_2MB),
					requester, 1, write_check, &pfnmap);
		retval = -errno;
		if (vhsaa[i] == (uint64_t)-1) {
			IVED_ERROR(log4cat_veos_ived,
						"Failed to v2p due to %s",
						strerror(-retval));
			goto hndl_pindown;
		}
		count++;
		if (pfnmap == 1) {
			IVED_ERROR(log4cat_veos_ived,
						"0x%lx is invalid address",
						vhva + i * HUGE_PAGE_SIZE_2MB);
			retval = -EFAULT;
			goto hndl_pindown;
		}
		ret = veos_vhshm_check_huge(vhsaa[i]);
		if (ret != 0) {
			retval = -EFAULT;
			goto hndl_pindown;
		}
		IVED_DEBUG(log4cat_veos_ived, "VHSAA : 0x%lx", vhsaa[i]);
	}

	vehva = veos_alloc_dmaatb_entry_for_aa(requester, vhsaa, permission,
				VE_ADDR_VHSAA, VEHVA_VESHM|VEHVA_2MB);
	if (vehva < 0) {
		IVED_ERROR(log4cat_veos_ived,
			   "Failed to register 0x%lx with DMAATB due to %s",
			   vhva, strerror(-(int)vehva));
		retval = vehva;
		goto hndl_pindown;
	}
	IVED_DEBUG(log4cat_veos_ived, "VEHVA : 0x%lx", vehva);

	ret = veos_vhshm_store_info(tsk_struct, page_num, vhsaa, vehva);
	if (ret != 0) {
		retval = -ECANCELED;
		goto hndl_VHEVA_release;
	}

	retval = vehva;
	goto hndl_return;

hndl_VHEVA_release:
	ret = veos_free_dmaatb_entry(requester, vehva,
					(page_num *  HUGE_PAGE_SIZE_2MB));
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
					"Failed to release 0x%lx due to %s",
					vehva, strerror(-ret));
	}

hndl_pindown:
	for (i = 0; i < count; i++) {
		errno = 0;
		ret = vedl_release_pindown_page(handle, vhsaa[i]);
		if (ret != 0) {
			IVED_ERROR(log4cat_veos_ived,
				"Failed to release page 0x%lx due to %s",
				vhsaa[i], strerror(errno));
		}
	}
	free(vhsaa);
	vhsaa = NULL;

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function unmaps VEHVA from DMAATB and release
 * all pin-downed pages corresponding to VEHVA.
 *
 * @param [in] requester PID of Pseudo Process
 * @param [in] vehva which is being released
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Ensure that tsk_struct is not NULL before calling this function.
 */
int64_t veos_unmap_vhva_from_vehva(pid_t requester, uint64_t vehva,
					struct ve_task_struct *tsk_struct)
{
	int64_t retval = 0;
	int ret = 0;
	struct veos_vhshm *vhshm_resource_struct = NULL;
	struct veos_vhshm_resouces *del_info = NULL;
	struct ived_shared_resource_data *ived_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	ived_struct = tsk_struct->ived_resource;
	vhshm_resource_struct = &(ived_struct->veos_vhshm_res_head);

	pthread_mutex_lock(&(vhshm_resource_struct->veos_vhshm_lock));

	ret = veos_vhshm_search_resource_info(vhshm_resource_struct,
							vehva, &del_info);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
					"0x%lx is not registered", vehva);
		retval = -EINVAL;
		goto hndl_release_lock;
	}

	IVED_DEBUG(log4cat_veos_ived, "Releasing DMAATB 0x%lx",
							del_info->vehva);
	ret = (int)veos_free_dmaatb_entry(requester, del_info->vehva,
				(del_info->page_num * HUGE_PAGE_SIZE_2MB));
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to release DMAATB entry 0x%lx due to %s",
			vehva, strerror(-ret));
		retval = -ECANCELED;
		goto hndl_release_lock;
	}

	ret = veos_vhshm_release_all_pindowned_pages(del_info);
	if (ret != 0) {
		/* Return success to Pseudo because releasing DMAATB has
		 * finished */
		goto hndl_release_lock;
	}

	list_del(&(del_info->list));
	free(del_info->vhsaas);
	free(del_info);
	del_info = NULL;

hndl_release_lock:
	pthread_mutex_unlock(&(vhshm_resource_struct->veos_vhshm_lock));

	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function is an entry point of sysve system call with CMD_VHSHM
 * command. This function passes the request to a function specified by sub
 * command.
 *
 * @param [in] vedl_handle Pointer to the thread argument structure containing
 * IPC data. This argument is not NULL and it is ensured.
 *
 * @retval 0 on success, -1 on failure.
 *
 * @note This function is invoked from only worker thread and any other
 * functions must not invoke this function.
 */
int veos_vhshm(veos_thread_arg_t *pti)
{
	int w_retval = 0;
	int ucred_size = sizeof(struct ucred);
	int subcmd = 0;
	int attached = 0;
	int64_t ret = 0;
	int64_t p_retval = -ECANCELED;
	PseudoVeosMessage *request = NULL;
	struct vhshm_args arguments;
	struct ucred cred;
	struct ve_task_struct *tsk_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (IVED_LINKAGE_OFF) {
		p_retval = -ENOTSUP;
		goto hndl_return;
	}

	memset(&cred, '\0', sizeof(struct ucred));
	errno = 0;
	ret = (int64_t)getsockopt(pti->socket_descriptor,
						SOL_SOCKET, SO_PEERCRED, &cred,
						(socklen_t *)&ucred_size);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to get PID of requester due to %s",
				strerror(errno));
		goto hndl_return;
	}
	IVED_DEBUG(log4cat_veos_ived, "Requester : %d", cred.pid);

	request = pti->pseudo_proc_msg;
	if (!(request->has_pseudo_msg)) {
		IVED_ERROR(log4cat_veos_ived,
					"VHSHM request does not have message");
		goto hndl_return;
	} else if (request->pseudo_msg.data == NULL) {
		IVED_ERROR(log4cat_veos_ived,
					"VHSHM request has invalid message");
		goto hndl_return;
	} else if (request->pseudo_msg.len != sizeof(struct vhshm_args)) {
		IVED_ERROR(log4cat_veos_ived,
					"VHSHM request has wrong size message");
		goto hndl_return;
	}
	memcpy(&arguments, request->pseudo_msg.data, request->pseudo_msg.len);
	subcmd = arguments.subcmd;
	IVED_DEBUG(log4cat_veos_ived, "subcmd = %d", subcmd);

	tsk_struct = find_ve_task_struct(cred.pid);
	if (tsk_struct == NULL) {
		IVED_ERROR(log4cat_veos_ived, "Failed to get process info");
		goto hndl_return;
	}

	switch (subcmd) {
	case VHSHM_AT:
		ret = veos_map_vhva_to_vehva(cred.pid, arguments.at_arg.vhva,
						arguments.at_arg.size,
						arguments.at_arg.shmflag,
						tsk_struct);
		if (ret > 0)
			attached = 1;
		p_retval = ret;
		break;
	case VHSHM_DT:
		ret = veos_unmap_vhva_from_vehva(cred.pid,
					arguments.dt_arg.vehva, tsk_struct);
		p_retval = ret;
		break;
	default:
		IVED_ERROR(log4cat_veos_ived,
			   "Internal error: Invalid command %d", subcmd);
	}

hndl_return:
	/* Return to Pseudo Process! */
	ret = (int64_t)veos_vhshm_return_responce(
					pti->socket_descriptor, p_retval);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived, "Failed to return responce");
		w_retval = -1;
		if (attached != 0) {
			ret = veos_unmap_vhva_from_vehva(cred.pid,
							p_retval, tsk_struct);
			if (ret != 0)
				IVED_ERROR(log4cat_veos_ived,
						"Failed to clear VHSHM");
		}
	}

	if (tsk_struct != NULL)
		put_ve_task_struct(tsk_struct);

	/* Return to worker thread! */
	return w_retval;
}
