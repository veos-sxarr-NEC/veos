/**
 * Copyright (C) 2017-2022 NEC Corporation
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
 * @file veos_devmem.c
 * @brief VE-GPU data transfer functions (VEOS side)
 *
 * @internal
 * @author VE-GPU
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
#include <sys/mman.h>
#include <fcntl.h>

#include "veos_ived.h"
#include "veos_devmem.h"
#include "veos_ived_private.h"
#include "ived_common.h"
#include "devmem_defs.h"
#include "proto_buff_schema.pb-c.h"
#include "ived_request.h"
#include "veos.h"
#include "psm_comm.h"
#include "dmaatb_api.h"
#include "vehva_mgmt.h"
#include "ve_memory.h"

static pthread_t devmem_th;

struct mapped_devmem {
	struct list_head list;
	pid_t pid;
	int devmem_id;
};

struct node_devmem_id_list {
	struct mapped_devmem devmem;
	pthread_mutex_t devmem_id_list_lock;
};

static struct node_devmem_id_list ve_devmem_id_list;

/**
 * @brief Check whether DEVMEM lock is locked.
 *
 * @param [in] devmem_lock Pointer to DEVMEM lock in veos_dev_mem structure
 */
static void veos_devmem_check_lock_owned(pthread_mutex_t *devmem_lock)
{
	int ret = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	ret = pthread_mutex_trylock(devmem_lock);
	if (ret != EBUSY)
		veos_abort("Internal error : "
			   "The DEVMEM lock is missing, %s",
			   strerror(ret));

	IVED_TRACE(log4cat_veos_ived, "Out func");
}

/**
 * @brief Initialize resource information of gpu memory on VH in VEOS
 *
 * @param [in] ived_resource pointer to IVED resource data per process
 *
 * @retval 0 on success, -1 on failure.
 *
 * @note Ensure that ived_resource is not NULL before calling this function
 */
int veos_initialize_devmem_resource(struct ived_shared_resource_data
							*ived_resource)
{
	int ret = 0;
	struct veos_dev_mem *devmem_resource =
					&(ived_resource->veos_dev_mem_res_head);

	IVED_TRACE(log4cat_veos_ived, "In func");

	INIT_LIST_HEAD(&(devmem_resource->res));

	ret = pthread_mutex_init(&(devmem_resource->veos_dev_mem_lock), NULL);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to initialize DEVMEM lock due to %s",
				strerror(ret));
		ret = -1;
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");

	return ret;
}

/**
 * @brief Add device id and pid to list or increment reference counter
 *
 * @param [in] req_devmem_id	ID of device memory
 * @param [in] req_pid		Target process
 *
 * @retval 0 on success to adding or already added, -1 on failure.
 *
 * @note Aquire node_devmem_id_list.devmem_id_list_lock before invoke this.
 */
static int add_to_devmem_id_list(int req_devmem_id, pid_t req_pid)
{
	int retval = 0;
	struct mapped_devmem *new = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	new = malloc(sizeof(struct mapped_devmem));
	if (new == NULL) {
		IVED_ERROR(log4cat_veos_ived,
			"failed to allocate memory for devmem_id list");
		retval = -1;
		goto hndl_return;
	}
	
	new->devmem_id = req_devmem_id;
	new->pid = req_pid;
	list_add_tail(&new->list, &ve_devmem_id_list.devmem.list);
	IVED_TRACE(log4cat_veos_ived,
		   "add new list for devmem_id:%d pid:%d",
		   req_devmem_id, req_pid);

 hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");

	return retval;
}

/**
 * @brief Delete device id and pid from list or decrement reference counter
 *
 * @param [in] req_devmem_id	ID of device memory
 * @param [in] req_pid		Target process
 *
 * @retval 0 on success, -1 on failure.
 *
 * @note Aquire node_devmem_id_list.devmem_id_list_lock before invoke this.
 */
static int delete_from_devmem_id_list(int req_devmem_id, pid_t req_pid)
{
	int retval = 0;
	struct mapped_devmem *pos = NULL, *tmp = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	/* search devmem_id list */
	list_for_each_entry_safe(pos, tmp,
				&ve_devmem_id_list.devmem.list, list) {
		if ((pos->devmem_id == req_devmem_id) &&
		    (pos->pid == req_pid)) {
			list_del(&pos->list);
			free(pos);
			pos = NULL;
			goto hndl_return;
		}
	}
	IVED_ERROR(log4cat_veos_ived,
			"devmem_id:%d pid:%d does not found in list",
			req_devmem_id, req_pid);
	retval = -1;

 hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");

	return retval;

}

/**
 * @brief Return responce to Pseudo Process
 *
 * @param[in] pseudo_sock_fd Descriptor used to communicate with VEOS.
 * @param[in] ret Return value to Pseudo Process
 *
 * @return 0 on Success, -1 on Failure.
 */
static int veos_devmem_return_responce(int pseudo_sock_fd, int64_t ret)
{
	int retval = -1;
	PseudoVeosMessage devmem_responce = PSEUDO_VEOS_MESSAGE__INIT;
	void *msg_buff = NULL;
	size_t msg_len = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");

	devmem_responce.has_syscall_retval = true;
	devmem_responce.syscall_retval = ret;

	msg_len = pseudo_veos_message__get_packed_size(&devmem_responce);
	msg_buff = malloc(msg_len);
	if (msg_buff == NULL) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to allocate buffer for DEVMEM responce");
		goto hndl_return;
	}
	memset(msg_buff, '\0', msg_len);
	if (msg_len != pseudo_veos_message__pack(&devmem_responce, msg_buff)) {
		IVED_ERROR(log4cat_veos_ived, "Failed to pack DEVMEM responce");
		goto hndl_return;
	}

	retval = psm_pseudo_send_cmd(pseudo_sock_fd, msg_buff, msg_len);
	if (retval < msg_len) {
		retval = -1;
		IVED_ERROR(log4cat_veos_ived, "Failed to send DEVMEM responce");
		goto hndl_return;
	}

	retval = 0;

hndl_return:
	free(msg_buff);
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function release pin-downed pages which specified
 *  veos_dev_mem_resources structure has.
 *
 * @param [in] info Pointer to veos_dev_mem_resources structure
 *
 * @retval 0 on success, negative errno on failure.
 */
static int veos_devmem_release_pindowned_pages
					(struct veos_dev_mem_resources *info)
{
	vedl_handle *handle = NULL;
	struct veos_dev_mem_resources *del_info = info;
	int ret = 0;

	IVED_TRACE(log4cat_veos_ived, "In func");
	IVED_TRACE(log4cat_veos_ived,
		"release pin-downed pages, paddr = %lx, page_num = %ld",
		(uint64_t)(del_info->paddr), del_info->page_num);

	handle = VE_HANDLE(0);

	errno = 0;
	ret = vedl_put_devmem(handle, del_info->id);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to release pin-downed page=0x%lx id=%hd : %s",
			(uint64_t)(del_info->paddr), del_info->id,
			strerror(errno));
		ret = -errno;
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");
	return ret;
}

/**
 * @brief This function release all pages which specified veos_dev_mem 
 * structure has.
 *
 * @param [in] pid Target process
 * @param [in] devmem_resource_struct pointer to veos_dev_mem structure 
 * which has deleting pages.
 *
 * @retval 0 on success, -1 on failure.
 *
 * @note Aquire devmem_id_list_lock and veos_dev_mem_lock before invoke
 * this function. This function does not release DMAATB entry because it
 * will be released by other function when task exit.
 */
static int veos_devmem_release_all_pages(
				pid_t pid,
				struct veos_dev_mem *devmem_resource_struct)
{
	int retval = 0;
	int ret = 0;
	struct veos_dev_mem_resources *del_info = NULL;
	struct list_head *p = NULL;
	struct list_head *q = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	veos_devmem_check_lock_owned(
			     &(devmem_resource_struct->veos_dev_mem_lock));
	list_for_each_safe(p, q, &(devmem_resource_struct->res)) {
		del_info = list_entry(p, struct veos_dev_mem_resources, list);
		ret = veos_devmem_release_pindowned_pages(del_info);
		if (ret != 0) {
			/* Even if veos_devmem_release_pindowned_pages() fails,
			   the information for devmem needs to be deleted. */
			IVED_ERROR(log4cat_veos_ived,
					"Failed to release pin-downed pages");
			retval = -1;
		}
		ret = delete_from_devmem_id_list(del_info->id, pid);
		if (ret != 0) {
			IVED_DEBUG(log4cat_veos_ived,
				"failed to delete devmem_id_list. ret=%d", ret);
			retval = -1;
		}
		list_del(&(del_info->list));
		free(del_info->paddr);
		free(del_info);
		del_info = NULL;
	}

	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function stores resource informations of DEVMEM
 *
 * @param [in] tsk_struct VE Process
 * @param [in] page_num A number of pages
 * @param [in] paddr An array of physical address, it must be null terminated.
 * @param [in] vehva VEHVA
 * @param [in] id id of device memory
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_devmem_store_info(struct ve_task_struct *tsk_struct,
			int page_num, uint64_t *paddr, int64_t vehva, int id)
{
	int retval = -1;
	struct veos_dev_mem *devmem_resource_struct = NULL;
	struct veos_dev_mem_resources *new_info = NULL;
	struct ived_shared_resource_data *ived_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	ived_struct = tsk_struct->ived_resource;
	if (ived_struct == NULL) {
		IVED_ERROR(log4cat_veos_ived, "invalid ived_resource");
		goto hndl_return;
	}
	devmem_resource_struct = &(ived_struct->veos_dev_mem_res_head);

	new_info = (struct veos_dev_mem_resources *)
				malloc(sizeof(struct veos_dev_mem_resources));
	if (new_info == NULL) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to allocate memory for resource info");
		goto hndl_return;
	}

	new_info->vehva = vehva;
	new_info->paddr = paddr;
	new_info->page_num = page_num;
	new_info->id = (uint32_t)id;
	IVED_DEBUG(log4cat_veos_ived,
		"store new_info: paddr = %lx, paddr = %lx, "
		"page_num = %ld, id=%d",
		new_info->vehva, (uint64_t)(new_info->paddr),
		new_info->page_num, id);

	pthread_mutex_lock(&(devmem_resource_struct->veos_dev_mem_lock));

	list_add(&(new_info->list), &(devmem_resource_struct->res));

	pthread_mutex_unlock(&(devmem_resource_struct->veos_dev_mem_lock));

	retval = 0;

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function gets veos_dev_mem_resources structure corresponding to
 * specified VEHVA
 *
 * @param [in] devmem_struct Pointer to veos_dev_mem structure of requester
 * @param [in] VEHVA VEHVA which being to be released.
 * @param [out] devmem_resouces veos_dev_mem_resources structure corresponding to
 * specified VEHVA
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_devmem_search_resource_info(
				struct veos_dev_mem *devmem_struct,
				uint64_t vehva,
				struct veos_dev_mem_resources **ret_struct)
{
	struct veos_dev_mem_resources *res_info = NULL;
	struct veos_dev_mem_resources *tmp = NULL;
	struct list_head *p = NULL;
	struct list_head *q = NULL;
	int retval = -1;

	IVED_TRACE(log4cat_veos_ived, "In func");

	veos_devmem_check_lock_owned(&(devmem_struct->veos_dev_mem_lock));

	list_for_each_safe(p, q, &(devmem_struct->res)) {
		tmp = list_entry(p, struct veos_dev_mem_resources, list);
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
 * @brief Delete resource information of device memory
 *
 * @param[in] tsk pointer to struct of target process
 *
 * @retval 0 on success, -1 on failure.
 */
int veos_delete_devmem_resource(struct ve_task_struct *tsk)
{
	int retval = 0;
	int ret = 0;
	struct ived_shared_resource_data *ived_resource = NULL;
	struct veos_dev_mem *devmem_resource_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (tsk == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		retval = -1;
		goto hndl_return;
	}
	ived_resource = tsk->ived_resource;
	if (ived_resource == NULL) {
		IVED_ERROR(log4cat_veos_ived, "ived resource struct is NULL");
		retval = -1;
		goto hndl_return;
	}
	devmem_resource_struct = &(ived_resource->veos_dev_mem_res_head);

	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				LOCK,
				"Failed to aquire devmem_id_list lock");
	pthread_mutex_lock(&(devmem_resource_struct->veos_dev_mem_lock));

	ret = veos_devmem_release_all_pages(tsk->pid, devmem_resource_struct);
	if (ret != 0) {
		retval = -1;
		IVED_ERROR(log4cat_veos_ived,
				"Some DEVMEM resources are not released");
	}

	pthread_mutex_unlock(&(devmem_resource_struct->veos_dev_mem_lock));
	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  UNLOCK,
				  "Failed to release devmem_id_list lock");

	ret = pthread_mutex_destroy(
			&(devmem_resource_struct->veos_dev_mem_lock));
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
 * @param [in] id ID of GPU memory
 * @param [in] task Target process
 *
 * @retval VEHVA on success, -errno on failure.
 *
 * @note Ensure that *task is not NULL before calling this function.
 */
int64_t veos_map_dev_mem_paddr_to_vehva(int id,
			struct ve_task_struct *task)
{
	int64_t retval = 0;
	int64_t vehva = 0;
	/* Array of PADDR, It MUST BE NULL terminated ! */
	uint64_t *pa = NULL;
	uint64_t size_total = 0;
	pid_t requester = task->pid;
	uint64_t paddr = 0, size = 0;
	vedl_handle *handle = VE_HANDLE(0);
	int ret = 0;
	int page_num = 0;
	int i = 0;
	int permission = 0;
	struct veos_dev_mem *devmem_resource = NULL;
	struct veos_dev_mem_resources *del_info = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (id <= 0) {
		IVED_ERROR(log4cat_veos_ived, "invalid id");
		retval = -EINVAL;
		goto hndl_return;
	}
	if (task->ived_resource == NULL) {
		IVED_ERROR(log4cat_veos_ived, "invalid ived_resource");
		retval = -EINVAL;
		goto hndl_return;
	}
	devmem_resource = &task->ived_resource->veos_dev_mem_res_head;

	errno = 0;
	ret = vedl_get_devmem(handle, (uint32_t)id, &paddr, &size);
	if(ret == 0) {
		IVED_DEBUG(log4cat_veos_ived,
			   "get devmem info with id(%d) succeed: "
			   "paddr = %lx, size = %lx",
			   id, paddr, size);
		if(paddr == 0) {
			retval = -ECANCELED;
			goto hndl_return;
		}
	} else {
		IVED_ERROR(log4cat_veos_ived,
			"failed to get devmem info with id (%d): %s",
			id, strerror(errno));
		retval = -errno;
		goto hndl_return;
	}

	permission = (PROT_READ | PROT_WRITE);
	size_total = (paddr & ATTACHMASK64M) + size;
	page_num = size_total / DMAATB_PAGE_SIZE_FOR_DEVMEM;
	if ((size_total % DMAATB_PAGE_SIZE_FOR_DEVMEM) != 0)
		page_num++;
	IVED_DEBUG(log4cat_veos_ived, "devmem size_total = %lx, page_num = %d",
			size_total, page_num);

	pa = (uint64_t *)malloc((page_num + 1) * sizeof(uint64_t));
	if (pa == NULL) {
		IVED_ERROR(log4cat_veos_ived,
					"Failed to allocate memory for PADDR");
		retval = -ENOMEM;
		goto hndl_put;
	}
	memset(pa, '\0', (page_num + 1) * sizeof(uint64_t));
	for (i = 0; i < page_num; i++) {
		pa[i] = (uint64_t)(paddr + i * DMAATB_PAGE_SIZE_FOR_DEVMEM);
	}

	vehva = veos_alloc_dmaatb_entry_for_aa(requester, pa, permission,
				VE_ADDR_VHSAA, VEHVA_VESHM|VEHVA_64MB);
	if (vehva < 0) {
		IVED_ERROR(log4cat_veos_ived,
			   "Failed to register 0x%lx with DMAATB due to %s",
			   paddr, strerror(-(int)vehva));
		retval = vehva;
		goto hndl_pindown;
	}

	ret = veos_devmem_store_info(task, page_num, pa, vehva, id);
	if (ret != 0) {
		retval = -ECANCELED;
		goto hndl_VEHVA_release;
	}

	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  LOCK,
				  "Failed to aquire devmem_id_list lock");
	ret = add_to_devmem_id_list(id, task->pid);
	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  UNLOCK,
				  "Failed to release devmem_id_list lock");
	if (ret != 0) {
		retval = -ECANCELED;
		goto hndl_del_info;
	}

	retval = (paddr & ATTACHMASK64M) | vehva;
	IVED_DEBUG(log4cat_veos_ived,
		"registered DEVMEM paddr = %lx, vehva=%lx, vehva(offset) = %lx",
		(uint64_t)pa, (uint64_t)vehva, (uint64_t)retval);
	goto hndl_return;

hndl_del_info:
	pthread_mutex_lock_unlock(&devmem_resource->veos_dev_mem_lock,
				LOCK, "Failed to aquire veos_dev_mem_lock");
	ret = veos_devmem_search_resource_info(devmem_resource, vehva, &del_info);
	if (ret == 0) {
		list_del(&del_info->list);
		free(del_info);
		del_info = NULL;
	}
	pthread_mutex_lock_unlock(&devmem_resource->veos_dev_mem_lock,
				UNLOCK, "Failed to release veos_dev_mem_lock");
hndl_VEHVA_release:
	ret = veos_free_dmaatb_entry(requester, vehva,
				(page_num *  DMAATB_PAGE_SIZE_FOR_DEVMEM));
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
					"Failed to release 0x%lx due to %s",
					vehva, strerror(-ret));
	}

hndl_pindown:
	free(pa);
	pa = NULL;

hndl_put:
	errno = 0;
	ret = vedl_put_devmem(handle, (uint32_t)id);
	if (ret < 0) { 
		IVED_DEBUG(log4cat_veos_ived,
			"Failed to put dev_mem ID:%d: %s",
			id, strerror(errno));
	}

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function unmaps VEHVA from DMAATB and release
 * pin-downed pages corresponding to VEHVA.
 *
 * @param [in] vehva which is being released
 * @param [in] task Target process
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Ensure that *task is not NULL before calling this function.
 */
int64_t veos_unmap_dev_mem_paddr_from_vehva(uint64_t vehva,
				struct ve_task_struct *task)
{
	int64_t retval = 0;
	int ret = 0;
	pid_t requester = 0;
	uint64_t off_vehva = vehva & ~(ATTACHMASK64M);
	int devmem_id = 0;
	struct veos_dev_mem *devmem_resource_struct = NULL;
	struct veos_dev_mem_resources *del_info = NULL;
	struct ived_shared_resource_data *ived_struct = NULL;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (task == NULL) {
		IVED_ERROR(log4cat_veos_ived, "invalid task struct");
		retval = -EINVAL;
		goto hndl_return;
	}

	ived_struct = task->ived_resource;
	if (ived_struct == NULL) {
		IVED_ERROR(log4cat_veos_ived, "invalid ived resource  struct");
		retval = -EINVAL;
		goto hndl_return;
	}
	devmem_resource_struct = &(ived_struct->veos_dev_mem_res_head);
	requester = task->pid;

	pthread_mutex_lock(&(devmem_resource_struct->veos_dev_mem_lock));

	ret = veos_devmem_search_resource_info(devmem_resource_struct,
						off_vehva, &del_info);
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
					"0x%lx is not registered", off_vehva);
		retval = -EINVAL;
		goto hndl_unlock;
	}
	
	devmem_id = del_info->id;
	IVED_DEBUG(log4cat_veos_ived, "Releasing DMAATB 0x%lx",
							del_info->vehva);
	ret = (int)veos_free_dmaatb_entry(requester, del_info->vehva,
			(del_info->page_num * DMAATB_PAGE_SIZE_FOR_DEVMEM));
	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
			"Failed to release DMAATB entry 0x%lx due to %s",
			del_info->vehva, strerror(-ret));
		retval = -ECANCELED;
		goto hndl_unlock;
	}

	ret = veos_devmem_release_pindowned_pages(del_info);
	if (ret != 0) {
		/* Return success to Pseudo because releasing DMAATB has
		 * finished */
		IVED_DEBUG(log4cat_veos_ived,
			"releasing some pindowned pages is failed. ret=%d",
			ret);
		goto hndl_unlock;
	}
	list_del(&(del_info->list));
	free(del_info->paddr);
	free(del_info);
	del_info = NULL;
	
       	pthread_mutex_unlock(&(devmem_resource_struct->veos_dev_mem_lock));

	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  LOCK,
				  "Failed to aquire devmem_id_list lock");

	ret = delete_from_devmem_id_list(devmem_id, task->pid);
	if (ret != 0) {
		IVED_DEBUG(log4cat_veos_ived,
			"failed to delete devmem_id_list. ret=%d", ret);
	}
	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  UNLOCK,
				  "Failed to release devmem_id_list lock");
	goto hndl_return;

hndl_unlock:
	pthread_mutex_unlock(&(devmem_resource_struct->veos_dev_mem_lock));

hndl_return:
	IVED_TRACE(log4cat_veos_ived, "Out func");
	return retval;
}

/**
 * @brief This function is an entry point of sysve system call with CMD_DEVMEM
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
int veos_dev_mem(veos_thread_arg_t *pti)
{
	int ucred_size = sizeof(struct ucred);
	int subcmd = 0;
	int attached = 0;
	int64_t ret = 0;
	int64_t pseudo_retval = -ECANCELED;
	int64_t worker_retval = 0; 
	PseudoVeosMessage *request = NULL;
	struct dev_mem_args arguments;
	struct ucred cred;
	struct ve_task_struct *tsk_struct = NULL;

	int id = 0;
	uint64_t vehva;

	IVED_TRACE(log4cat_veos_ived, "In func");

	if (IVED_LINKAGE_OFF) {
		pseudo_retval = -ENOTSUP;
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
					"DEVMEM request does not have message");
		goto hndl_return;
	} else if (request->pseudo_msg.data == NULL) {
		IVED_ERROR(log4cat_veos_ived,
					"DEVMEM request has invalid message");
		goto hndl_return;
	} else if (request->pseudo_msg.len != sizeof(struct dev_mem_args)) {
		IVED_ERROR(log4cat_veos_ived,
				"DEVMEM request has wrong size message");
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
	case DEVMEM_AT:
		id = arguments.atg_arg.devmem_id;
		pseudo_retval = veos_map_dev_mem_paddr_to_vehva(id, tsk_struct);
		if (pseudo_retval > 0) {
			vehva = (uint64_t)pseudo_retval;
			attached = 1;
		}
		break;
	case DEVMEM_DT:
		pseudo_retval = veos_unmap_dev_mem_paddr_from_vehva(
						arguments.dtg_arg.vehva,
						tsk_struct);
		break;
	default:
		IVED_ERROR(log4cat_veos_ived,
			   "Internal error: Invalid command %d", subcmd);
	}

 hndl_return:
	/* Return to Pseudo Process! */
	ret = (int64_t)veos_devmem_return_responce(
					pti->socket_descriptor, pseudo_retval);

	if (ret != 0) {
		IVED_ERROR(log4cat_veos_ived,
				"Failed to return responce. ret=%ld", ret);
		worker_retval = -1;
		if (attached != 0) {
			ret = veos_unmap_dev_mem_paddr_from_vehva(
							vehva, tsk_struct);
			if (ret != 0)
				IVED_ERROR(log4cat_veos_ived,
					"Failed to clear DEVMEM. ret=%ld",
					ret);
		}
	}
	if (tsk_struct != NULL)
		put_ve_task_struct(tsk_struct);
	/* Return to worker thread! */
	return worker_retval;
}

/**
 * @brief This function gets veos_dev_mem_resources structure corresponding to
 * specified ID
 *
 * @param [in] devmem_struct Pointer to veos_dev_mem structure of requester
 * @param [in] id ID of device memory
 * @param [out] devmem_resouces veos_dev_mem_resources structure corresponding to
 * specified ID
 *
 * @retval 0 on success, -1 on failure.
 */
static int veos_devmem_search_resource_info_from_id(
			 struct veos_dev_mem *devmem_struct,
			 int32_t id,
			 struct veos_dev_mem_resources **ret_struct)
{
  	struct veos_dev_mem_resources *res_info = NULL;
	struct veos_dev_mem_resources *tmp = NULL;
	struct list_head *p = NULL;
	struct list_head *q = NULL;
	int retval = -1;

	IVED_TRACE(log4cat_veos_ived, "In func");

	veos_devmem_check_lock_owned(&(devmem_struct->veos_dev_mem_lock));

	list_for_each_safe(p, q, &(devmem_struct->res)) {
		tmp = list_entry(p, struct veos_dev_mem_resources, list);
		if (tmp->id == id) {
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
 * @brief This function unmap VEHVA from DMAATB and release all pin-downed pages
 *  corresponding to specified ID
 *
 * @param [in] id ID of device memory
 */
static void veos_unmap_devmem_from_id(int id)
{
	int ret = 0;
	struct mapped_devmem *pos = NULL, *tmp = NULL;
	struct ve_task_struct *tsk = NULL;
	struct ived_shared_resource_data *ived_resource = NULL;
	struct veos_dev_mem *devmem = NULL;
	struct veos_dev_mem_resources *res_info = NULL;
	vedl_handle *handle = VE_HANDLE(0);

	IVED_TRACE(log4cat_veos_ived, "In func");

	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
				  LOCK,
                                "Failed to aquire devmem_id_list lock");

	/*search id_list*/
	list_for_each_entry_safe(pos, tmp,
				 &ve_devmem_id_list.devmem.list, list) {
		if (pos->devmem_id == id) {
			tsk = find_ve_task_struct(pos->pid);
			if (tsk == NULL) {
				IVED_DEBUG(log4cat_veos_ived,
					"Failed to get process info "
					"(pid:%d)", pos->pid);
				continue;
			}
			if (tsk->ived_resource == NULL) {
				IVED_DEBUG(log4cat_veos_ived,
					"no ived_resource (pid:%d)",
					pos->pid);
				put_ve_task_struct(tsk);
				continue;
			}
			ived_resource = tsk->ived_resource;
			devmem = &(ived_resource->veos_dev_mem_res_head);
			
			pthread_mutex_lock(&(devmem->veos_dev_mem_lock));
			
			ret = veos_devmem_search_resource_info_from_id(devmem,
								id, &res_info);
			if ((ret != 0) || (res_info == NULL)) {
				/* If failed get devmem info,
				   it maybe be released by
				   another function. So, skip
				   releasing. */
				IVED_DEBUG(log4cat_veos_ived,
						"Failed to get devmem "
						"info(ID:%d)", id);
				pthread_mutex_unlock(
						&(devmem->veos_dev_mem_lock));
				break;
			}
			IVED_TRACE(log4cat_veos_ived, "Release "
					"vehva:%lx pid:%d devmem_id:%d",
					res_info->vehva, pos->pid, id);
			/* release DMAATB entry.
			   Decrementing ref_counter and unregistering
			   is done in VE driver.*/
			ret = (int)veos_free_dmaatb_entry(
						tsk->pid,
						res_info->vehva,
						(res_info->page_num *
						 DMAATB_PAGE_SIZE_FOR_DEVMEM));
			if (ret != 0) {
				/* If failed to release DMAATB entry,
				   continue releasing all attached
				   device memory.*/
				IVED_DEBUG(log4cat_veos_ived,
					"Failed to release DMAATB entry"
					   " (ID:%hd, VEHVA:0x%lx) due to %s",
					   res_info->id, res_info->vehva,
						   strerror(-ret));
			}
			errno = 0;
			ret = vedl_put_devmem(handle, id);
			if (ret != 0) {
				IVED_DEBUG(log4cat_veos_ived,
						"Failed to notify finishing "
						"to release DMAATB(ID:%hd) "
						"due to %s",
						res_info->id, strerror(errno));
			}
			list_del(&(res_info->list));
			free(res_info->paddr);
			free(res_info);
			res_info = NULL;
			
			pthread_mutex_unlock(&(devmem->veos_dev_mem_lock));

			put_ve_task_struct(tsk);

			list_del(&(pos->list));
			free(pos);
			pos = NULL;
		}
	}
	pthread_mutex_lock_unlock(&ve_devmem_id_list.devmem_id_list_lock,
					  UNLOCK,
                                "Failed to release devmem_id_list lock");

	IVED_TRACE(log4cat_veos_ived, "Out func");

	return;
}

/**
 * @brief This function checks aborted ID and release them.
 */
static void veos_devmem_check_aborted_id_thread(void)
{
	vedl_handle *handle = VE_HANDLE(0);
	uint32_t id = 0;
	int ret = 0;

	/* If no GPU device, this thread exit. */
	errno = 0;
	ret = vedl_get_devmem_abortid(handle, 1);
	if (ret < 0) {
		if (errno == ENOTSUP) {
			IVED_DEBUG(log4cat_veos_ived,
				   "Exit thread because no GPU device");
			goto hndl_return;
		}
	}
	while (terminate_flag == 0) {
		/* check per 1 sec */
		errno = 0;
		ret = vedl_get_devmem_abortid(handle, 1000);
		if (ret < 0) {
		  	IVED_ERROR(log4cat_veos_ived,
				"Failed to get devmem id of "
				"aborted process: %s",
				strerror(errno));
			continue;
		} else if (ret > 0) {
			id = (uint32_t)ret;
			IVED_TRACE(log4cat_veos_ived,
				"start to search and detach devmem(id:%hd)",
				id);
			veos_unmap_devmem_from_id(id);
		}
	}
hndl_return:
	pthread_exit(NULL);
}


/**
 * @brief This function create thread for abort id
 *
 * @param [in] vnode pointer to VE node
 *
 * @retval 0 on success, negative errno on failure.
 */
int veos_devmem_init(struct ve_node_struct *vnode) {
	pthread_attr_t attr;
	int ret = 0;

	if (vnode == NULL) {
		VEOS_CRIT("Failed to init devmem due to invalid argument.");
		return -EINVAL;
	}

	pthread_mutex_init(&ve_devmem_id_list.devmem_id_list_lock, NULL);
	INIT_LIST_HEAD(&ve_devmem_id_list.devmem.list);

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		VEOS_CRIT("Faild to initialize pthread attribute: %s",
			strerror(ret));
		goto error;
	}
	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret != 0) {
		VEOS_CRIT("Faild to set detach state of pthread attribute: %s",
			strerror(ret));
		goto error;
	}
	ret = pthread_create(&devmem_th, &attr,
			(void *)&veos_devmem_check_aborted_id_thread, NULL);
	if (ret != 0) {
		VEOS_CRIT("Failed to create thread. %s", strerror(ret));
		goto error;
	}
	return 0;

error:
	return -ret;
}
