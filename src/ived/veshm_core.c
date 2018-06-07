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
 * @file veshm_core.c  
 * @brief Core functions for VESHM requests
 *
 * @internal
 * @author VESHM
 */
#define __USE_GNU
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <inttypes.h>
#include "veshm_core.h"
#include "ve_list.h"
#include "ived_common.h"
#include "ived.pb-c.h"
#include "ived_ipc.h"
#include "veshm_ipc.h"
#include "ived.h"
#include "ived_core.h"
#include "ived_veshm_core.h"

#define RETRY		3	/* Retry of a request */

#define LOCK_TIMEOUT 10      /* seconds */

/**
 * @brief Chack an existence of VESHM info in erase_list
 *
 * @param [in] veshm_info	Target VESHM information
 * @param [in] list_head	list_head of erase_list
 *
 * @return result
 * @retval 0   veshm_info doesn't exist in list_head
 * @retval 1   veshm_info exists in list_head
 * @retval -1  error occured
 */
int
check_veshm_entry_list(struct veshm_memory_info *veshm_info, 
		       struct list_head *list_head)
{
	struct list_head *list_chk;
	struct veshm_memory_info *veshm_info_chk = NULL;
	int added;

	if (veshm_info == NULL || list_head == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		assert (0);
		return(-1);
	}
	added = 0;
	list_for_each(list_chk, list_head){
		veshm_info_chk = list_entry(list_chk, 
					    struct veshm_memory_info, erase_list);
		if (veshm_info == veshm_info_chk){
			added = 1;
			break;
		}
	}
	return (added);
}

/**
 * @brief Search the specified attaching process information
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * veshm_info->veshm_lock
 *
 * @param [in]	veshm_info	Target VESHM
 * @param [in]	pid       	PID of a target user process
 *
 * @return Pointer of ived_resource_user on success, NULL on failure
 */
struct ived_resource_user *
search_veshm_attach_proc(struct veshm_memory_info *veshm_info,
			 int pid)
{ 
	if (veshm_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(NULL);
	}

	return ( search_ived_resource_user(&veshm_info->attach_proc_list,
					   &veshm_info->veshm_lock, 
					   pid));
}



/**
 * @brief Create a ived_resource_user.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * veshm_info->veshm_lock
 *
 * A caller makes sure that a caller has locked veshm_lock.
 * Add ived_resource_user (user proc info of the VESHM) to the target 
 * VESHM (veshm_info).
 * ived_resource_user is created in tandem with attaching_veshm_info.
 *
 * @param [in]	veshm_info	veshm_memory_info  (target)
 * @param [in]	pid		User pid
 * @param [in]	uuid_proc	UUID of a user process
 *
 * @return Pointer of ived_resource_user on success, NULL on failure
 */

struct ived_resource_user *
create_veshm_attach_proc(struct veshm_memory_info *veshm_info, 
			 pid_t user_pid, uuid_t uuid_proc)
{
	if (veshm_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(NULL);
	}

	return (create_ived_resource_user(&veshm_info->attach_proc_list,
					  &veshm_info->veshm_lock,
					  user_pid, uuid_proc));
}


/**
 * @brief Unlink & delete a ived_resource_user.
 *
 * A caller makes sure that a caller has locked veshm_lock.
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * veshm_lock
 *
 * @param [in]	veshm_info	veshm_memory_info  (target)
 * @param [in]	erase_ent	Erase entry
 *
 * @return 0 on success.
 */
int 
erase_veshm_attach_proc(struct veshm_memory_info *veshm_info,
			struct ived_resource_user *erase_ent)
{
	IVED_DEBUG(log4cat_veshm, "Delete attach proc info:%p from veshm:%p", 
		   erase_ent, veshm_info);

	if (veshm_info == NULL || erase_ent == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(-1);
	}

	return erase_ived_resource_user(erase_ent,
					&veshm_info->attach_proc_list,
					&veshm_info->veshm_lock);
}


/**
 * @brief Pickup a having / attaching VESHM information by UUID of VESHM
 * This function searchs the specified VESHM and returns a having / attaching
 * VESHM info.
 * NOTE: Before entering this function, a caller must acquire a lock.
 *
 * @param [in]	head		List head of a target list
 * @param [in]	proc_info	Target process of serching
 * @param [in]	uuid_veshm	UUID of VESHM
 *
 * @return Pointer to Having/Attaching VEHM information on success, 
 *         NULL on failure
 */
struct veshm_info_tracker *
search_veshm_tracker_uuid(struct list_head *head, 
			  struct process_info *proc_info, uuid_t uuid_veshm)
{ 
	int ret;
	struct list_head *list_p;
	struct veshm_info_tracker *entry = NULL;
	struct veshm_memory_info *veshm = NULL;
	int existing = 0;

	IVED_TRACE(log4cat_veshm, "[%u] PASS", (uint)pthread_self());

	assert(head      != NULL);
	assert(proc_info != NULL);
	if (head == NULL || proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		goto err_ret;
	}

	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	if (ret != 0){
		goto err_ret;
	}

	list_for_each(list_p, head){
		entry = list_entry(list_p, struct veshm_info_tracker, list);
		veshm = entry->veshm_info;
		if ( uuid_compare(veshm->uuid_veshm, uuid_veshm) == 0){
			existing = 1;
			break;
		}
	}
	if (existing == 0){
		entry = NULL;
	}

err_ret:
	IVED_DEBUG(log4cat_veshm, "[%u] entry:%p", (uint)pthread_self(), entry);
	return (entry);
}


/**
 * @brief Pickup a having / attaching VESHM information
 *
 * This function searchs the specified VESHM and returns a having / attaching
 * VESHM info. Returned VESHM is ***VALID***.
 * NOTE: Before entering this function, a caller must acquire a lock.
 *
 * @param [in]	head		List head of a target list
 * @param [in]	proc_info	Target process of serching
 * @param [in]	pid		Pid of an owner process
 * @param [in]	vemva		VEMVA of VESHM
 * @param [in]	size		Size of VESHM
 * @param [in]	checking_mask   Flags which must be check for the request
 *
 * @return Pointer to Having/Attaching VEHM information on success, 
 *         NULL on failure
 */
struct veshm_info_tracker *
search_veshm_tracker(struct list_head *head, struct process_info *proc_info,
		     int owner_pid, uint64_t vemva, uint64_t  size,
		     int syncnum, uint64_t mode_flag, uint64_t checking_mask)
{ 
	int ret;
	struct list_head *list_p;
	struct veshm_info_tracker *entry = NULL;
	struct veshm_memory_info *veshm = NULL;
	int existing = 0;

	if (head == NULL || proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(NULL);
	}
	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	if (ret != 0){
		goto err_ret;
	}

	list_for_each(list_p, head){
		entry = list_entry(list_p, struct veshm_info_tracker, list);
		veshm = entry->veshm_info;
		if ( veshm->pid_of_owner == owner_pid
		     && veshm->start_vemva == vemva 
		     && veshm->size == size
		     && ( ! isset_flag(veshm->mode_flag, VESHM_MODE_INVALID) )
		     && issame_flag(veshm->mode_flag, mode_flag,
				    checking_mask)){
			if (isset_flag(mode_flag, VESHM_MODE_SYNC)
			    && (veshm->pcisync_num != syncnum)){
				continue;
			}
			existing = 1;
			break;
		}
	}
	if (existing == 0){
		entry = NULL;
	}

err_ret:
	IVED_DEBUG(log4cat_veshm, "[%u] entry:%p", (uint)pthread_self(), entry);
	return (entry);
}

/**
 * @brief Create a having VESHM information 
 * NOTE: Before entering this function, a caller must acquire a lock.
 *
 * Count up process_info->own_veshm_num and 
 *
 * @param [in]		proc_info	Pointer of process_info
 * @param [in]		pid		Pid of an owner process
 * @param [in]		vemva		VEMVA of VESHM
 * @param [in]		size		Size of VESHM
 *
 * @return Pointer to Having/Attaching VEHM information on success, 
 *         NULL on failure
 */
struct veshm_info_tracker *
create_having_veshm_tracker(struct process_info *proc_info)
{ 
	int ret;
	struct veshm_info_tracker *entry = NULL;
	struct veshm_memory_info *new_veshm = NULL;

	if (proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(NULL);
	}
	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	if (ret != 0)
		goto err_ret;

	entry = (struct veshm_info_tracker *)malloc
		(sizeof (struct veshm_info_tracker));
	if (entry== NULL){
		IVED_CRIT(log4cat_veshm, "Tracker data allocation failed");
		goto err_ret;
	}
	new_veshm = create_veshm_info(proc_info->os_info);
	if (new_veshm == NULL)
		goto err_ret;

	entry->veshm_info = new_veshm;
	INIT_LIST_HEAD(&entry->list);
	proc_info->own_veshm_num++;
	list_add(&entry->list, &proc_info->having_veshm_info);

	IVED_DEBUG(log4cat_veshm, "[%u] entry:%p", (uint)pthread_self(), entry);
	return (entry);	

err_ret:
	IVED_DEBUG(log4cat_veshm, "[%u] err:%p", (uint)pthread_self(), entry);
	if (entry != NULL)
		free(entry);

	return(NULL);
}


/**
 * @brief Create an attaching VESHM information 
 *
 * NOTE: Before entering this function, a caller must acquire a lock.
 * proc_lock
 * NOTE: Don't change veshm_info because it may not be protected.
 *
 * @param [in]		proc_info	process_info of a user process
 * @param [in]		veshm_info	Address of a target VESHM info
 *
 * @return Pointer to Having/Attaching VEHM information on success, 
 *         NULL on failure
 */
struct veshm_info_tracker *
create_attaching_veshm_tracker(struct process_info *proc_info)
{ 
	int ret;
	struct veshm_info_tracker *entry = NULL;

	if (proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(NULL);
	}
	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	if (ret != 0){
		goto err_ret;
	}

	entry = (struct veshm_info_tracker *)malloc
		(sizeof (struct veshm_info_tracker));
	if (entry == NULL){
		IVED_CRIT(log4cat_veshm, "Tracker data allocation failed");
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veshm, "Add a tracker for attaching");

	/* Increase attach_veshm_num */
	proc_info->attach_veshm_num++;

	INIT_LIST_HEAD(&entry->list);
	list_add(&entry->list, &proc_info->attaching_veshm_info);

	IVED_DEBUG(log4cat_veshm, "[%u] entry:%p", (uint)pthread_self(), entry);
	return(entry);

err_ret:
	IVED_DEBUG(log4cat_veshm, "[%u] Failed", (uint)pthread_self());

	return(NULL);
}


/**
 * @brief Erase a VESHM tracker information 
 *
 * It is a common function.
 *
 * @param [in]	erase_ent	Erase entry
 * @param [in]	counter		Pointer of erase_ent's counter in proc_info
 *
 * @return 0 on success, -1 on failure
 */
int
erase_veshm_tracker(struct veshm_info_tracker *erase_ent, int *counter)
{ 
	assert(erase_ent != NULL);
	assert(counter != NULL);
	if (erase_ent == NULL || counter == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return (-1);
	}

	IVED_DEBUG(log4cat_veshm, "Delete tracker :%p, counter:%d",
		   erase_ent, *counter);

	(*counter)--;
	list_del(&erase_ent->list);
	free(erase_ent);

	return(0);
}

/**
 * @brief Erase a having VESHM information 
 *
 * Decrement process_info->own_veshm_num
 * Before enter this function, caller ensures locking process_info.
 *
 * @param [in]		proc_info	Pointer of process_info
 * @param [in]		erase_ent	Erase entry
 *
 * @return 0 on success, -1 on failure
 */
int
erase_having_veshm_tracker(struct process_info *proc_info,
			   struct veshm_info_tracker *erase_ent)
{
	assert(proc_info != NULL);
	assert(erase_ent != NULL);
	if ((proc_info == NULL) || (erase_ent == NULL)){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(-1);
	}
	IVED_DEBUG(log4cat_veshm, "Delete having_veshm_tracker:%p", erase_ent);
	erase_veshm_tracker(erase_ent, &proc_info->own_veshm_num);
	return(0);
}


/**
 * @brief Create a new VESHM memory information
 *
 * This function initializes values and link a new entry to VESHM list in
 * a corresponding OS information.
 *
 * NOTE: This function doesn't allocate pci_address area, because 
 * the size of pci_address is specified by a open request value.
 * The top function of VESHM open request should allocate the area.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * os_lock
 *
 * @return Pointer to the new VESHM memory information on success,
 *         NULL on failure
 */
struct veshm_memory_info *
create_veshm_info(struct veos_info *os_info)
{
	int ret;
	struct veshm_memory_info *new_ent = NULL;

	if (os_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		goto err_ret;
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	assert(ret == 0);
	if (ret != 0)
		goto err_ret;

	new_ent = (struct veshm_memory_info *)malloc
		(sizeof(struct veshm_memory_info));
	if (new_ent == NULL){
		IVED_CRIT(log4cat_veshm, "VESHM data allocation failed");
		goto err_ret;
	}

	INIT_LIST_HEAD(&new_ent->list);
	INIT_LIST_HEAD(&new_ent->erase_list);
	INIT_LIST_HEAD(&new_ent->attach_proc_list);
	new_ent->start_vemva       = UNUSED;
	new_ent->register_cnt_dev  = 0;
	new_ent->register_cnt_proc = 0;
	new_ent->reference_cnt     = 0;
	new_ent->n_pci_address     = 0;
	new_ent->pci_address       = NULL;
	pthread_mutex_init(&new_ent->veshm_lock, &chkmutex);

	os_info->veshm_mem_num++;
	list_add(&new_ent->list, &os_info->veshm_mem_info_list);

	IVED_DEBUG(log4cat_veshm, "New ent .next[%p] = %p",
		   &os_info->veshm_mem_info_list.next,
		   &new_ent->list);

err_ret:
	IVED_DEBUG(log4cat_veshm, "New veshm information = %p", new_ent);
	return(new_ent);
}

/**
 * @brief Search VESHM memory information by (proc_info(pid), vemva, size)
 * NOTE: This function aquires veshm_lock.
 *
 * @param [in] proc_info	Owner process of a target VESHM
 * @param [in] vemva		VEMVA of VESHM 
 * @param [in] size		Size of VESHM
 * @param [in] syncnum		PCISYNC pair number
 * @param [in] mode_flag	Mode flag
 *
 * @return Pointer of struct veshm_info on success, 
 * NULL and set errno on failure
 *         
 */
struct veshm_memory_info *
search_veshm_info(struct process_info *proc_info, uint64_t vemva, 
		  uint64_t size, int syncnum, uint64_t mode_flag,
		  uint64_t checking_mask)
{
	int ret;
	struct veshm_info_tracker *veshm_track = NULL;
	struct veshm_memory_info *veshm_info = NULL;

	if (proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		errno = EINVAL;
		goto err_ret;
	}

	veshm_track = search_veshm_tracker(&proc_info->having_veshm_info,
					   proc_info, proc_info->pid, vemva, 
					   size, syncnum, mode_flag,
					   checking_mask);
	if (veshm_track == NULL){
		IVED_DEBUG(log4cat_veshm, "%s (tracker)", strerror(ENOENT));
		errno = ENOENT;
		goto err_ret;
	}

	ret = pthread_mutex_lock(&veshm_track->veshm_info->veshm_lock);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
			   strerror(ret));
	}

	veshm_info = veshm_track->veshm_info;

err_ret:
	return(veshm_info);
}


/**
 * @brief Erase VESHM memory information
 * This function unlocks veshm_info if releasing fails.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * os_info, veshm_lock
 *
 * NOTE: This function unlock veshm_lock and free veshm_info
 *
 * @param [in] os_info		OS info of erasing VESHM
 * @param [in] veshm_info	Erasing VESHM info
 *
 * @return Result of erasing VESHM memory information
 * @retval 0 if delete
 * @retval 1 if not delete
 * @retval -1 on failure (not delete)
 *         
 */
int 
erase_veshm_info(struct veos_info *os_info, 
		 struct veshm_memory_info *veshm_info)
{
	int ret;

	IVED_DEBUG(log4cat_veshm, "Try to delete veshm_info:%p", veshm_info);

	assert(os_info    != NULL);
	assert(veshm_info != NULL);

	if (os_info == NULL || veshm_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(-1);
	}
	dump_uuid("Try to delete uuid_veshm", veshm_info->uuid_veshm);

	ret = ived_check_mutex_locked(&os_info->os_lock);
	assert(ret == 0);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Not locked (veshm_info)");
		return (-1);
	}
	ret = ived_check_mutex_locked(&veshm_info->veshm_lock);
	assert(ret == 0);
	if (ret != 0){
		IVED_DEBUG(log4cat_veshm, "Not locked (veshm_info)");
		return (-1);
	}
	if (veshm_info->reference_cnt != 0
	    || veshm_info->register_cnt_dev != 0
	    || veshm_info->register_cnt_proc != 0){
		IVED_DEBUG(log4cat_veshm, /* DEBUG level is OK. */
			   "VESHM is still used: proc:%d, dev:%d, ref:%d", 
			   veshm_info->register_cnt_proc,
			   veshm_info->register_cnt_dev,
			   veshm_info->reference_cnt);

		pthread_mutex_unlock(&veshm_info->veshm_lock);
		return (1);
	}
	IVED_DEBUG(log4cat_veshm, "Delete veshm_info:%p", veshm_info);

	os_info->veshm_mem_num--;
	list_del(&veshm_info->list);

	pthread_mutex_unlock(&veshm_info->veshm_lock);
	pthread_mutex_destroy(&veshm_info->veshm_lock);
	if (veshm_info->pci_address != NULL){
		free(veshm_info->pci_address);
	}
	free(veshm_info);
	return(0);
}

/**
 * @brief Delete all own VESHM areas of a process
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * os_lock and proc_lock.
 *
 * @param [in] os_info   OS on which a target process exists
 * @param [in] proc_info Target process_info
 * @param [in] mode_flag Mode flag (IVED_PROC_EXIT,IVED_VEOS_EXIT)
 *
 * @return 0 on sucess, negative value on failure
 */
static int
ived_veshm_close_all(struct veos_info *os_info,
		     struct process_info *proc_info, uint64_t mode_flag)
{
	int ret;
	int64_t retval = -1;
	int reterr = 0;
	int ret_refcnt = 0;
	struct list_head *own_list_p, *list_n;
	struct veshm_info_tracker *having_info = NULL;

	assert (os_info   != NULL);
	assert (proc_info != NULL);

	if (os_info == NULL || proc_info == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		goto err_ret;
	}

	ret = ived_check_mutex_locked(&os_info->os_lock);
	if (ret != 0)
		goto err_ret;
	ret = ived_check_mutex_locked(&proc_info->proc_lock);
	if (ret != 0)
		goto err_ret;

	IVED_DEBUG(log4cat_veshm, "own_veshm_num: %d",
		   proc_info->own_veshm_num);

	proc_info->proc_stat = VE_STAT_STOP;

	list_for_each_safe(own_list_p, list_n,
			   &(proc_info->having_veshm_info)){

		/* Retrieve a own VESHM infomation and etc.. 
		 * Close a VESHM of the information. */ 
		having_info = list_entry(own_list_p, 
					 struct veshm_info_tracker, list);

		/* Close function may delete having_info, veshm_info,
		 * and proc_info. */
		ived_veshm_close_common(os_info, proc_info, having_info,
					mode_flag, 
					&retval, &reterr, &ret_refcnt);
	}
	retval = 0;
err_ret:
	return(retval);
}


/**
 * @brief Delete all (attaching) VESHM areas of a process
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * user process's os_lock and proc_lock.
 *
 * @param [in] user_os_info   OS on which a target process exists
 * @param [in] user_proc_info Target process
 *
 * @return 0 on success
 */
static int
ived_veshm_detach_all(struct veos_info *user_os_info,
		      struct process_info *user_proc_info,
		      struct list_head *erase_veshm_list)
{
	int ret;
	uint64_t retval = -1;
	struct list_head *attach_list_p, *list_n;
	struct veshm_info_tracker *attaching_info = NULL;
	struct ived_resource_user *attaching_proc = NULL;
	struct veshm_memory_info *veshm_info = NULL;

	assert (user_os_info   != NULL);
	assert (user_proc_info != NULL);

	if (user_os_info == NULL || user_proc_info == NULL 
	    || erase_veshm_list == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veshm, "attach_veshm_num: %d",
		   user_proc_info->attach_veshm_num);

	ret = ived_check_mutex_locked(&user_os_info->os_lock);
	if (ret != 0)
		goto err_ret;

	ret = ived_check_mutex_locked(&user_proc_info->proc_lock);
	if (ret != 0){
		goto err_ret;
	}

	list_for_each_safe(attach_list_p, list_n,
			   &(user_proc_info->attaching_veshm_info)){

		/* Retrieve an attaching VESHM infomation and etc.. 
		 * Detach a VESHM of the information. */ 
		attaching_info = list_entry(attach_list_p, 
					    struct veshm_info_tracker, list);

		veshm_info      = attaching_info->veshm_info;

		/* Delete attaching processes infomation and tracker */
		erase_veshm_tracker(attaching_info, 
				    &user_proc_info->attach_veshm_num);

		if (veshm_info == NULL){
			assert(0);
			continue;
		}

		ret = pthread_mutex_lock(&veshm_info->veshm_lock);
		if (ret != 0){
			IVED_DEBUG(log4cat_veshm, "Acquire VESHM lock: %s",
				   strerror(ret));
		}

		veshm_info->reference_cnt--;

		attaching_proc = search_veshm_attach_proc(veshm_info, 
							  user_proc_info->pid);
		if (attaching_proc == NULL){
			IVED_WARN(log4cat_veshm, 
				  "Not found attaching process data. veshm:%p",
				  veshm_info);
		} else {
			erase_veshm_attach_proc(veshm_info, attaching_proc);
		}

		if (veshm_info->register_cnt_proc == 0
		    && veshm_info->register_cnt_dev == 0
		    && veshm_info->reference_cnt == 0){

			ret = check_veshm_entry_list(veshm_info, 
						     erase_veshm_list);
			if (ret == 0){
				/* VESHM info is erased later */
				list_add(&veshm_info->erase_list, 
					 erase_veshm_list);
			}
		} 
		ret = pthread_mutex_unlock(&veshm_info->veshm_lock);
	}
	retval = 0;

	IVED_DEBUG(log4cat_veshm, "attach_veshm_num: %d",
		   user_proc_info->attach_veshm_num);
err_ret:
	IVED_DEBUG(log4cat_veshm, "retval:%d", (int)retval);
	return(retval);
}


/**
 * @brief Clear all resources of a process
 * Delete all (attaching) VESHM areas and close VESHM.
 * Own VESHM are already closed when this function called from 
 * process exitting. 
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * os_lock and proc_lock.
 *
 * @param [in] os_info   OS on which a target process exists
 * @param [in] proc_info Target process_info
 * @param [in] mode_flag Mode flag (IVED_PROC_EXIT,IVED_VEOS_EXIT)
 * @param [in] erase_veshm_list List for erased VESHMs
 *
 * @return 0 
 */
int
ived_veshm_discard_all(struct veos_info *os_info,
		       struct process_info *proc_info, uint64_t mode_flag,
		       struct list_head *erase_veshm_list)
{
	IVED_TRACE(log4cat_veshm,"PASS");

	assert (os_info   != NULL);
	assert (proc_info != NULL);

	if (os_info == NULL || proc_info == NULL || erase_veshm_list == NULL){
		IVED_CRIT(log4cat_veshm, "Argument is NULL.");
		return(-1);
	}
	ived_veshm_detach_all(os_info, proc_info, erase_veshm_list);

	if (isset_flag (mode_flag, IVED_VEOS_EXIT)){
		ived_veshm_close_all(os_info, proc_info, mode_flag);
	}

	IVED_TRACE(log4cat_veshm,"PASS");
	return (0);
}


/**
 * For test
 */

int
dump_veshm_info(struct veshm_memory_info *veshm_info)
{
	IVED_DEBUG(log4cat_veshm,"Dump veshm_memory_info: %p", veshm_info);
	if (veshm_info == NULL)
		return(0);

	IVED_DEBUG(log4cat_veshm,
		   "    uid: %d, pid:%d, vemva:0x%"PRIx64", size:0x%"PRIx64"",
		   veshm_info->uid_of_owner,
		   veshm_info->pid_of_owner,
		   veshm_info->start_vemva,
		   veshm_info->size);
	IVED_DEBUG(log4cat_veshm,
		   "    n_pci_address:%zu, mode:0x%"PRIx64", syncnum:%d",
		   veshm_info->n_pci_address,
		   veshm_info->mode_flag,
		   veshm_info->pcisync_num);
	IVED_DEBUG(log4cat_veshm,
		   "    register_cnt_dev: %d, _proc:%d, reference_cnt:%d",
		   veshm_info->register_cnt_dev,
		   veshm_info->register_cnt_proc,
		   veshm_info->reference_cnt);
	dump_uuid("uuid_owner_proc", veshm_info->uuid_owner_proc);
	dump_uuid("uuid_veshm", veshm_info->uuid_veshm);
	return(0);
}

int
dump_tracker(struct veshm_info_tracker *tracker)
{
	IVED_DEBUG(log4cat_veshm,"Dump veshm_info_tracker: %p", tracker);
	if (tracker == NULL)
		return(0);

	IVED_DEBUG(log4cat_veshm,
		   "    veshm_info(p):%p",
		   tracker->veshm_info);
	return(0);
}

int
dump_attach_proc_info(struct ived_resource_user *info)
{
	IVED_DEBUG(log4cat_veshm,"Dump ived_resource_user");
	if (info == NULL)
		return(0);

	IVED_DEBUG(log4cat_veshm,
		   "    pid:%d",
		   info->pid);
	dump_uuid("dump_attach_proc_info proc", info->uuid_proc);
	return(0);
}

