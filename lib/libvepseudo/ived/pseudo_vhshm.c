/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file pseudo_vhshm.c
 * @brief VH-VE shared memory functions (Pseudo process side)
 *
 * @internal
 * @author VHSHM
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/shm.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <unistd.h>

#include "proto_buff_schema.pb-c.h"
#include "pseudo_vhshm.h"
#include "veos_defs.h"
#include "vhshm_defs.h"
#include "pseudo_ived_common.h"
#include "ived_common.h"
#include "ived_request.h"
#include "comm_request.h"
#include "mm_transfer.h"

/* For resource information. */
struct pseudo_vhshm_resources {
	struct list_head list; /* List of next resource */
	void *vhva;
	int64_t vehva;
};

/* A lock for vhshm resource information */
pthread_mutex_t pseudo_vhshm_lock = PTHREAD_MUTEX_INITIALIZER;
/* A list head for vhshm resources */
struct list_head pseudo_vhshm_list = LIST_HEAD_INIT(pseudo_vhshm_list);

/**
 * @brief Check whether VHSHM lock is locked.
 */
static void sys_vhshm_check_lock_owned(void)
{
	int ret = 0;

	ret = pthread_mutex_trylock(&pseudo_vhshm_lock);
	if (ret != EBUSY) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Internal error : the VHSHM lock is missing, %s",
			strerror(ret));
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}
}

/**
 * @brief For preparation of clearing all inherited resource informations of
 * shared memory on VH, get a lock.
 *
 * @retval Return always 0.
 */
void sys_prepar_clear_all_vhshm_resource(void)
{
	IVED_TRACE(log4cat_pseudo_ived, "In func");

	pthread_mutex_lock(&pseudo_vhshm_lock);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
}

/**
 * @brief Clear all inherited resource informations of shared memory on VH.
 *
 * @param [in] child PID which is returned from fork()
 */
void sys_clear_all_vhshm_resource(pid_t child)
{
	int ret = 0;
	struct list_head *p = NULL;
	struct list_head *q = NULL;
	struct pseudo_vhshm_resources *del_info = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");
	if (child != 0)
		goto hndl_release;

	sys_vhshm_check_lock_owned();

	list_for_each_safe(p, q, &pseudo_vhshm_list) {
		del_info = list_entry(p, struct pseudo_vhshm_resources, list);
		errno = 0;
		ret = shmdt(del_info->vhva);
		if (ret != 0) {
			IVED_ERROR(log4cat_pseudo_ived,
				"Failed to release inherited shared memory due to %s",
				strerror(errno));
			fprintf(stderr, "Internal resource usage error\n");
			pseudo_abort();
		}

		list_del(&(del_info->list));
		free(del_info);
		del_info = NULL;
	}

hndl_release:
	pthread_mutex_unlock(&pseudo_vhshm_lock);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
}

/**
 * @brief Store resource information.
 *
 * @param [in] VHVA An address of shared memory on VH
 * @param [in] VEHVA an entry of DMAATB corresponding to above VHVA
 */
static void sys_vhshm_store_info(struct pseudo_vhshm_resources *info)
{
	struct pseudo_vhshm_resources *new_info = info;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	IVED_DEBUG(log4cat_pseudo_ived,
				"Storing VHVA : %p  and VEHVA : 0x%lx",
				new_info->vhva, new_info->vehva);

	pthread_mutex_lock(&pseudo_vhshm_lock);

	list_add(&(new_info->list), &pseudo_vhshm_list);

	pthread_mutex_unlock(&pseudo_vhshm_lock);
}

/**
 * @brief Search VEHVA corresponding to specified VHVA.
 *
 * @param [in] VHVA VHVA to be detached.
 *
 * @retval Pointer to pseudo_vhshm_resources strcture on success,
 * NULL on failure.
 *
 * @note Acquire pseudo_vhshm_lock before calling this function.
 */
static struct pseudo_vhshm_resources *search_info(const void *vhva)
{
	struct list_head *p = NULL;
	struct list_head *q = NULL;
	struct pseudo_vhshm_resources *delete_res = NULL;
	struct pseudo_vhshm_resources *tmp = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	sys_vhshm_check_lock_owned();

	list_for_each_safe(p, q, &pseudo_vhshm_list) {
		tmp = list_entry(p, struct pseudo_vhshm_resources, list);
		if (tmp->vhva == vhva) {
			delete_res = tmp;
			break;
		}
	}

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return delete_res;
}

/*
 * @brief This function sends VHSHM request and receives responce.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] args Pointer to vhshm_args structure which is going to be sent.
 *
 * @retval A return value which is corresponding to sub command of args.
 */
static int64_t sys_vhshm_exchange_request(veos_handle *handle,
						const struct vhshm_args *args)
{
	int ret = 0;
	int64_t retval = 0;
	PseudoVeosMessage vhshm_req = PSEUDO_VEOS_MESSAGE__INIT;
	ProtobufCBinaryData vhshm_req_msg;
	struct vhshm_args arguments;
	PseudoVeosMessage *ret_msg = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&vhshm_req_msg, '\0', sizeof(ProtobufCBinaryData));
	memcpy(&arguments, args, sizeof(struct vhshm_args));
	vhshm_req_msg.len = sizeof(struct vhshm_args);
	vhshm_req_msg.data = (uint8_t *)&arguments;

	vhshm_req.pseudo_veos_cmd_id = CMD_VHSHM;
	vhshm_req.has_pseudo_pid = true;
	vhshm_req.pseudo_pid = syscall(SYS_gettid);
	vhshm_req.has_pseudo_msg = true;
	vhshm_req.pseudo_msg = vhshm_req_msg;

	ret = exchange_request(handle, &vhshm_req, &ret_msg);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Failed to excahnge VHSHM request(%d) with VEOS",
			arguments.subcmd);
		fprintf(stderr, "Failed to communicate with VEOS\n");
		pseudo_abort();
	} else {
		retval = ret_msg->syscall_retval;
	}
	IVED_DEBUG(log4cat_pseudo_ived, "Response is %ld", retval);
	pseudo_veos_message__free_unpacked(ret_msg, NULL);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/*
 * @brief This function excanges vh_shmat() request with VEOS.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] VHVA An address which is registered with DMAATB
 * @param [in] size A size of VHVA
 * @param [in] shmflag A flag of VHVA
 *
 * @retval VEHVA on success, -errno on failure.
 *
 * @note Before calling this function, check all arguments.
 */
int64_t sys_vhshm_exchange_attach_request(veos_handle *handle,
					void *vhva, size_t size, int shmflag)
{
	int64_t retval = 0;
	struct vhshm_args arguments;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&arguments, '\0', sizeof(struct vhshm_args));
	arguments.subcmd = VHSHM_AT;
	arguments.at_arg.vhva = (uint64_t)vhva;
	arguments.at_arg.size = size;
	arguments.at_arg.shmflag = shmflag;

	retval = sys_vhshm_exchange_request(handle, &arguments);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;

}

/*
 * @brief This function exchanges vh_shmdt() request with VEOS.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] VEHVA An address which is registered with DMAATB
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Before calling this function, check all arguments.
 */
int sys_vhshm_exchange_detach_request(veos_handle *handle, int64_t vehva)
{
	int retval = 0;
	struct vhshm_args arguments;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	memset(&arguments, '\0', sizeof(struct vhshm_args));
	arguments.subcmd = VHSHM_DT;
	arguments.dt_arg.vehva = (uint64_t)vehva;

	retval = (int)sys_vhshm_exchange_request(handle, &arguments);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;

}

/**
 * @brief This function gets segment id of system V shared memory on VH
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] key A key value associated with System V shared memory segment on
 * VH
 * @param [in] size Size of System V shared memory segment on VH
 * @param [in] shmflag Flag value.
 *
 * @retval Segment ID on success, -errno on failure.
 *
 * @note Before calling this function, ensure that argument "handle" is not
 * NULL.
 */
int sys_vh_shmget(veos_handle *handle, key_t key, size_t size, int shmflag)
{
	int segid = 0;
	int retval = -EINVAL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	if (key == IPC_PRIVATE) {
		goto hndl_return;
	}
	if ((shmflag & SHM_HUGETLB) == 0) {
		goto hndl_return;
	} else if ((shmflag & (SHM_NORESERVE | IPC_EXCL | IPC_CREAT)) != 0) {
		goto hndl_return;
	}

	IVED_DEBUG(log4cat_pseudo_ived,
			"Invoke shmget with key:%d size:%ld shmflag:%d",
			key, size, shmflag);

	errno = 0;
	segid = shmget(key, size, shmflag);
	retval = -errno;
	if (segid == -1) {
		IVED_ERROR(log4cat_pseudo_ived,
				"Failed to get shared memory on VH due to %s",
				strerror(-retval));
		goto hndl_return;
	}
	retval = segid;

hndl_return:
	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function attaches system V shared memory on VH and requests VEOS
 * to register it with DMAATB.
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] shmid A segment ID specifying System V shared memory segment on
 * VH
 * @param [in] shmaddr This argument must be NULL
 * @param [in] shmflag Flag value.
 * @param [out] vehva An address of pointer to store VEHVA
 *
 * @retval VHVA(The address of the attached shared memory segment on VH)
 * on success, -errno on failure.
 *
 * @note Before calling this function, ensure that argument "handle" is not
 * NULL.
 */
int64_t sys_vh_shmat(veos_handle *handle, int shmid, const void *shmaddr,
						int shmflag, void **vehva)
{
	int ret = 0;
	int64_t retval = -EINVAL;
	int64_t l_vehva = 0;
	size_t segment_size = 0;
	void *vhva = NULL;
	struct shmid_ds ds;
	struct pseudo_vhshm_resources *new_info = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	if (shmaddr != NULL) {
		goto hndl_return;
	}
	if ((shmflag & (SHM_EXEC | SHM_REMAP | SHM_RND)) != 0) {
		goto hndl_return;
	}
	if (vehva == NULL) {
		retval = -EFAULT;
		goto hndl_return;
	}

	errno = 0;
	vhva = shmat(shmid, NULL, shmflag);
	retval = -errno;
	if (vhva == (void *)-1) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Failed to attach shared memory on VH due to %s",
			strerror(-retval));
		goto hndl_return;
	}
	IVED_DEBUG(log4cat_pseudo_ived, "VHVA = %p", vhva);

	memset(&ds, '\0', sizeof(struct shmid_ds));
	errno = 0;
	ret = shmctl(shmid, IPC_STAT, &ds);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
				"Failed to get a size of segment due to %s",
				strerror(errno));
		retval = -ECANCELED;
		goto hndl_detach;
	}
	segment_size = ds.shm_segsz;
	IVED_DEBUG(log4cat_pseudo_ived, "Segment ID %d, size : %ld",
							shmid, segment_size);

	l_vehva = sys_vhshm_exchange_attach_request(handle, vhva,
							segment_size, shmflag);
	if (l_vehva < 0) {
		IVED_ERROR(log4cat_pseudo_ived,
				"VEOS returned error(%s) to vh_shmat() request",
				strerror(-(int)l_vehva));
		retval = l_vehva;
		goto hndl_detach;
	}
	IVED_DEBUG(log4cat_pseudo_ived, "VEHVA = 0x%lx", l_vehva);

	ret = ve_send_data(handle, (uint64_t)vehva, sizeof(void *), &l_vehva);
	if (ret != 0) {
		retval = -EFAULT;
		IVED_ERROR(log4cat_pseudo_ived,
					"Failed to transfer VEHVA due to %s",
					strerror(ret));
		goto hndl_request_release;
	}

	new_info = (struct pseudo_vhshm_resources *)
				malloc(sizeof(struct pseudo_vhshm_resources));
	if (new_info == NULL) {
		IVED_ERROR(log4cat_pseudo_ived,
			   "Failed to allocate memory for resource info");
		retval = -ENOMEM;
		goto hndl_request_release;
	}
	new_info->vhva = vhva;
	new_info->vehva = l_vehva;
	sys_vhshm_store_info(new_info);

	retval = (int64_t)vhva;
	goto hndl_return;

hndl_request_release:
	ret = sys_vhshm_exchange_detach_request(handle, l_vehva);
	if (ret != 0)
		IVED_ERROR(log4cat_pseudo_ived,
				"VEOS returned error(%s) to vh_shmdt() request",
				strerror(-ret));

hndl_detach:
	errno = 0;
	ret = shmdt(vhva);
	if (ret != 0)
		IVED_ERROR(log4cat_pseudo_ived,
			   "Failed to detach shared memory on VH due to %s",
			   strerror(errno));

hndl_return:
	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function sends a request to VEOS to release attached address with
 * DAMATB and detaches system V shared memory on VH
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] shmaddr An address which is attached to System V shared memory on
 * VH
 *
 * @retval 0 on success, -errno on failure.
 *
 * @note Before calling this function, ensure that argument "handle" is not
 * NULL.
 */
int sys_vh_shmdt(veos_handle *handle, const void *vhva)
{
	int retval = -EINVAL;
	int ret = 0;
	int64_t vehva = 0;
	struct pseudo_vhshm_resources *delete_res = NULL;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	if (vhva == NULL)
		goto hndl_return;

	pthread_mutex_lock(&pseudo_vhshm_lock);

	delete_res = search_info(vhva);
	if (delete_res == NULL) {
		IVED_ERROR(log4cat_pseudo_ived, "%p is not attached", vhva);
		pthread_mutex_unlock(&pseudo_vhshm_lock);
		goto hndl_return;
	}

	IVED_DEBUG(log4cat_pseudo_ived, "Detaching VHVA : %p, VEHVA 0x%lx",
					delete_res->vhva, delete_res->vehva);
	vehva = delete_res->vehva;

	pthread_mutex_unlock(&pseudo_vhshm_lock);

	ret = sys_vhshm_exchange_detach_request(handle, vehva);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived,
				"VEOS returned error(%s) to vh_shmdt() request",
				strerror(-ret));
		retval = ret;
		goto hndl_return;
	}
	pthread_mutex_lock(&pseudo_vhshm_lock);

	delete_res = search_info(vhva);
	if (delete_res == NULL) {
		IVED_ERROR(log4cat_pseudo_ived,
			"Failed to search the VHVA which is going to detach");
		fprintf(stderr, "Internal resource usage error\n");
		pseudo_abort();
	}

	errno = 0;
	ret = shmdt(delete_res->vhva);
	if (ret != 0) {
		IVED_ERROR(log4cat_pseudo_ived, "Failed to detach %p due to %s",
					delete_res->vhva, strerror(errno));
		/*
		 * Return Success because this error will be recovered when a VE
		 * program exits.
		 * */
	}
	IVED_DEBUG(log4cat_pseudo_ived, "Erase VHVA %p, VEHVA 0x%lx",
					delete_res->vhva, delete_res->vehva);
	list_del(&(delete_res->list));
	free(delete_res);
	delete_res = NULL;
	retval = 0;

	pthread_mutex_unlock(&pseudo_vhshm_lock);

hndl_return:
	IVED_TRACE(log4cat_pseudo_ived, "Out func");
	return retval;
}

/**
 * @brief This function is an entry point of sysve system call for "VH-VE shared
 * memory"
 *
 * @param [in] handle VEOS handle of Pseudo Process
 * @param [in] args Pointer to system call arguments
 *
 * @retval Any positive value on success, -errno on failure.
 */
ret_t sys_vhshm(veos_handle *handle, uint64_t *args)
{
	int subcmd = 0;
	ret_t retval = -ECANCELED;

	IVED_TRACE(log4cat_pseudo_ived, "In func");

	if ((handle == NULL) || (args == NULL)) {
		IVED_CRIT(log4cat_pseudo_ived,
					"Internal error: Argument is NULL");
		goto hndl_return;
	}

	subcmd = (int)args[0];
	IVED_DEBUG(log4cat_pseudo_ived, "subcmd of VHSHM : %d", subcmd);

	switch (subcmd) {
	case VHSHM_GET:
		retval = sys_vh_shmget(handle, args[1], args[2], args[3]);
		break;
	case VHSHM_AT:
		retval = sys_vh_shmat(handle, args[1], (const void *)args[2],
						args[3], (void **)args[4]);
		break;
	case VHSHM_DT:
		retval = sys_vh_shmdt(handle, (const void *)args[1]);
		break;
	default:
		IVED_ERROR(log4cat_pseudo_ived,
			   "Internal error: Invalid command %d", subcmd);
	}

hndl_return:
	IVED_DEBUG(log4cat_pseudo_ived, "Return with %ld", retval);

	IVED_TRACE(log4cat_pseudo_ived, "Out func");

	return retval;
}
