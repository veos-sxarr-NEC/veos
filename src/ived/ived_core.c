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
 * @file ived_common.c  
 * @brief Common functions for IVED (daemon)
 *
 * @internal
 * @author VESHM
 */

#define __USE_GNU
#include <stdio.h>
#include <string.h>
#include <log4c.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>
#include <uuid/uuid.h>
#include "ived_core.h"
#include "ived.h"
#include "ived_common.h"
#include "ve_list.h"


/**
 * @brief Search ived_resource_user by pid
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * lock
 *
 * @param [in]	list_head	List head of a target list
 * @param [in]	lock       	Lock which protects a target list
 * @param [in]	pid       	PID of a target user process
 *
 * @return Pointer of ived_resource_user on success, NULL on failure
 */
struct ived_resource_user *
search_ived_resource_user(struct list_head *list_head,
			  pthread_mutex_t *lock, int pid)
{ 
	int ret;
	struct list_head *list_p;
	struct ived_resource_user *entry = NULL;
	int found = 0;

	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());

	assert(list_head != NULL);
	assert(lock      != NULL);

	if (list_head == NULL || lock == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(NULL);
	}

	ret = ived_check_mutex_locked(lock);
	if (ret != 0){
		goto err_ret;
	}

	list_for_each(list_p, list_head){
		entry = list_entry(list_p, struct ived_resource_user, list);
		if (entry->pid == pid){
			found = 1;
			break;
		}
	}
	if (found == 0){
		entry = NULL;
	}

err_ret:
	IVED_DEBUG(log4cat_main, "[%u] entry:%p", (uint)pthread_self(), entry);
	return (entry);
}


/**
 * @brief Create a ived_resource_user.
 * A caller makes sure that a caller has locked "lock".
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * lock
 *
 * @param [in]	list_head	List head of a target list
 * @param [in]	lock       	Lock which protects a target list
 * @param [in]	pid       	PID of a target user process
 * @param [in]	uuid_proc	UUID of a target user process
 *
 * @return Pointer of ived_resource_user on success, NULL on failure
 */

struct ived_resource_user *
create_ived_resource_user(struct list_head *list_head,
			  pthread_mutex_t *lock, 
			  pid_t pid, uuid_t uuid_proc)
{
	int ret;
	struct ived_resource_user *entry = NULL;

	IVED_TRACE(log4cat_main, "[%u] PASS", (uint)pthread_self());

	assert(list_head != NULL);
	assert(lock      != NULL);

	if (list_head == NULL || lock == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(NULL);
	}

	ret = ived_check_mutex_locked(lock);
	if (ret != 0){
		goto err_ret;
	}

	entry = search_ived_resource_user(list_head, lock, pid);
	if ( entry != NULL ){
		goto ret_found;
	}

	entry = (struct ived_resource_user *)malloc
		(sizeof (struct ived_resource_user));
	if (entry == NULL){
		IVED_CRIT(log4cat_main, "Resource user data allocation failed");
		goto err_ret;
	}

	entry->pid = pid;
	entry->reference_cnt_cr = 0;
	uuid_copy(entry->uuid_proc, uuid_proc);
	INIT_LIST_HEAD(&entry->list);

	list_add(&entry->list, list_head);

ret_found:
err_ret:
	IVED_DEBUG(log4cat_main, "[%u] entry:%p", (uint)pthread_self(), entry);
	return(entry); 
}


/**
 * @brief Unlink & delete a ived_resource_user.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * lock
 *
 * @param [in]	erase_ent	Erase entry
 * @param [in]	list_head	List head of a target list
 * @param [in]	lock       	Lock which protects a target list
 *
 * @return 0 on success, -1 on failure
 */
int 
erase_ived_resource_user(struct ived_resource_user *erase_ent,
			 struct list_head *list_head, 
			 pthread_mutex_t *lock)
{
	int ret;
	IVED_DEBUG(log4cat_main, "Delete entry:%p, list_head:%p",
		   erase_ent, list_head);

	assert(erase_ent != NULL);
	assert(list_head != NULL);
	assert(lock      != NULL);

	if (erase_ent == NULL || list_head == NULL || lock == NULL){
		IVED_CRIT(log4cat_main, "Argument is NULL.");
		return(-1);
	}

	ret = ived_check_mutex_locked(lock);
	assert(ret == 0);

	list_del(&erase_ent->list);
	free(erase_ent);

	return(0);
}


/** For test **/
int
dump_os_info(struct veos_info *os_info)
{
	IVED_DEBUG(log4cat_main,"Dump os_info: %p", os_info);
	if (os_info == NULL)
		return(0);

	IVED_DEBUG(log4cat_main,"\tpid:%d,  socket_name:%s, node_stat:%d",
		   os_info->os_pid, 
		   os_info->drv_socket_name,
		   os_info->node_stat);
	IVED_DEBUG(log4cat_main,"\tproc_info_num:%d, veshm_mem_num:%d",
		   os_info->proc_info_num,
		   os_info->veshm_mem_num);
	IVED_DEBUG(log4cat_main,
		   "\tPCIATB size: %"PRIx64", BAR01:0x%"PRIx64
		   ", BAR3:0x%"PRIx64"",
		   os_info->pciatb_pgsize,
		   os_info->bar01_paddr,
		   os_info->bar_cr_paddr);
	return(0);
}

int
dump_proc_info(struct process_info *proc_info)
{
	IVED_DEBUG(log4cat_main,"Dump process_info: %p", proc_info);
	if (proc_info == NULL)
		return(0);

	IVED_DEBUG(log4cat_main,
		   "pid:%d, os_info:%p (os_pid=%d)",
		   proc_info->pid,
		   proc_info->os_info,
		   (proc_info->os_info)->os_pid);

	IVED_DEBUG(log4cat_main,
		   "own veshm:%d, attaching veshm:%d",
		   proc_info->own_veshm_num,
		   proc_info->attach_veshm_num);

	IVED_DEBUG(log4cat_main,
		   "local crd:(%p, %p", 
		   proc_info->local_crd[0], proc_info->local_crd[1]);

	IVED_DEBUG(log4cat_main,
		   "local crd: %p, %p)", 
		   proc_info->local_crd[2], proc_info->local_crd[3]);
	dump_uuid("\tuuid_proc: ", proc_info->uuid_proc);

	return(0);
}

int
dump_resource_user_info(struct ived_resource_user *info)
{
	IVED_DEBUG(log4cat_main,"Dump ived_resource_user: %p", info);
	if (info == NULL)
		return(0);

	IVED_DEBUG(log4cat_main,
		   "    pid:%d",
		   info->pid);
	dump_uuid("uuid_proc", info->uuid_proc);
	return(0);
}

