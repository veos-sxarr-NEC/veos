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
 * @file veos_veshm.c  
 * @brief VESHM functions in VEOS
 *
 * @internal
 * @author VESHM
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>
#include <uuid/uuid.h>

#include "libved.h"
#include "ve_hw.h"
#include "veos.h"
#include "veos_handler.h"
#include "task_mgmt.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "veos_ived.h"
#include "veos_ived_misc.h"
#include "veos_veshm.h"
#include "veos_veshm_core.h"
#include "ived_ipc.h"
#include "ived_common.h"
#include "ived.pb-c.h"
#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"
#include "veos_veshm_ipc.h"

/* Terminated process's VESHM list */
/* About order of lock, please see definition of ived_task_list_lock. */
struct list_head veshm_remains_list;
pthread_mutex_t veshm_remains_lock;

#define REPLY_OK	0
#define REPLY_NG	-ECANCELED
#define LOCK_TIMEOUT	10	/* seconds */
#define INVALID_VESHM	0xFFFFFFFFFFFFFFFF


/**
 * @brief Check page mode per 2MB.
 * If an area includes 2 page modes, this function returns failure.
 *
 * @param [in]		pid     PID
 * @param [in]		vemva	Start VEMVA
 * @param [in]		size	Size of an area
 *
 * @return 0 on success, -1 on failure
 */
int 
check_mem_pgmode(int pid, int64_t vemva, int64_t size)
{
	int i;
	int check_num = -1;
	int last_pgmode = 0, pgmode = 0;

	if (pid < 0 || vemva < 0 || size < 0){
		IVED_ERROR(log4cat_veos_ived, "Getting page size failed.");
		return (-1);
	}

	/* Test page size per 2MB size. */
	check_num = (size + (PGSIZE_2M - 1)) >> SHFT_2M;

	last_pgmode = veos_get_pgmode(VE_ADDR_VEMVA, pid, vemva);
	if (last_pgmode < 0){
		IVED_DEBUG(log4cat_veos_ived, 
			   "Getting page size failed.(err:%d)", last_pgmode);
		return (-1);
	}

	for (i = 0; i < check_num; i++){
		pgmode = veos_get_pgmode(VE_ADDR_VEMVA, pid, 
					 vemva + PGSIZE_2M * i);
		if (pgmode < 0){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Getting page size failed.(err:%d)", pgmode);
			return (-1);
		}
		if (pgmode != last_pgmode){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Detected multiple page sizes in a requested memory.");
			return (-1);
		}
		last_pgmode = pgmode;
	}

	return(0);
}

/**
 * @brief Check permission of all pages which are included in an area
 * If an area includes Read Only page, this function returns failure.
 *
 * @param [in]		pid     PID
 * @param [in]		vemva	Start VEMVA
 * @param [in]		size	Size of an area
 *
 * @return 0 on success, -1 on failure
 */

int
check_mem_perm(int pid, int64_t vemva, int64_t size, int prot)
{
	int i;
	int check_num = -1;
	int64_t paddr = -1;
	int atb_prot;

	if (pid < 0 || vemva < 0 || size < 0 || prot < 0){
		IVED_ERROR(log4cat_veos_ived, 
			   "Getting page permission failed");
		return (-1);
	}

	/* Test page size per 2MB size. */
	check_num = (size + (PGSIZE_2M - 1)) >> SHFT_2M;

	for (i = 0; i < check_num; i++){
		paddr = veos_virt_to_phy(vemva + PGSIZE_2M * i, pid, false, 
					 &atb_prot);
		if (paddr == -1){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Permission check failed");
			return (-1);
		}
		if (atb_prot != prot){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Permissions are not matched");
			return (-1);
		}
	}

	return(0);
}

/**
 * @brief Create physical address array for own VESHM
 *
 * NOTE: A caller must have been checked all page sizes 
 * which are included in a VESHM. (by check_mem_pgmode)
 *
 * @param [in] pid           Pid of VESHM owner
 * @param [in] start_veshm   Pointer of struct owned_veshm_info
 * @param [in] size          Size of VESHM
 * @param [in] pgsize        Page size of page
 * @param [out] array	     Address of memory stored physsical address array
 *
 * @return page number of array on success, -1 on failure
 */
int
create_veshm_paddr_array(pid_t pid, uint64_t start_vemva, int64_t size,
			 uint64_t pgsize, uint64_t *array)
{
	int offset;
	uint64_t cur_vemva;
	uint64_t paddr;
	int64_t rest_size;
	int atb_prot;
	int pgnum = 0;

	if (array == NULL){
		assert(0);
		return (-1);
	}

	if (size < 0){
		IVED_ERROR(log4cat_veos_ived, 
			   "Specified size is invalid: %"PRId64"", size);
		return (-1);
	}

	cur_vemva = start_vemva;
	rest_size = size;
	offset = 0;

	while (rest_size > 0){
		paddr = veos_virt_to_phy(cur_vemva, pid, false, &atb_prot);
		if (paddr == -1){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Address translation failed.");
			return (-1);
		}
		*(array + offset) = paddr;

		rest_size -= pgsize;
		cur_vemva += pgsize;
		offset++;
		pgnum++;
	}

	IVED_DEBUG(log4cat_veos_ived, "Length of paddr_array: %d", pgnum);
	return(pgnum);
}

/**
 * @brief Check physical address and specified memory's
 *
 * @param [in] paddr	Registered physical address
 * @param [in] entries  Length of registered physical address array
 * @param [in] pgsize   Page size of registered physical pages
 * @param [in] pid	PID of examined process 
 * @param [in] vemva	Virtual address of examined address
 * @param [in] memsize	Memory size 
 *
 * @return Result of a comparison of physical address
 * @retval 0  Physical addresses are not changed
 * @retval 1  Physical addresses are changed
 * @retval -1 Failed
 */
int
check_veshm_paddr(uint64_t *paddr, uint64_t entries, uint64_t pgsize,
		  pid_t pid, uint64_t vemva, uint64_t memsize)
{
	int i;
	uint64_t test_paddr;
	int atb_prot;

	if (paddr == NULL){
		assert(0);
		return (-1);
	}

	for (i = 0; i < entries; i++){
		test_paddr = veos_virt_to_phy(vemva + pgsize * i, pid, false, 
					      &atb_prot);
		if (test_paddr != *(paddr + i)){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Physical address is changed: vemva:%#"PRIx64"",
				   vemva+pgsize*i);
			return(1);
		}
	}

	IVED_DEBUG(log4cat_veos_ived, 
		   "Physical addresses are not changed. pid:%d, vemva:%#"PRIx64", size:%"PRIx64"",
		   pid, vemva, memsize);
	return(0);
}

/**
 * @brief Create PCI addresses from PCIATB slots
 *
 * Convert PCIATB slot number to PCI address.
 * If PCIATB slot is -1, conversion is not done and this
 * function returns. 
 *
 * @param [in]  pciatb_entries    # of PCIATB slots
 * @param [in]  pciatb_slot       Array of PCIATB slots
 * @param [out] pci_address       Array of PCI addresses
 *
 * @return 0 on success, -1 on failure
 */
int
conv_pcislot_to_pciaddr(int pciatb_entries, int *pciatb_slot, 
			uint64_t *pci_address)
{
	int i;
	uint64_t pciatb_pagesize;

	if (current_node == NULL){
		IVED_CRIT(log4cat_veos_ived, 
			   "Current node data is invalid.");
		assert(0);
		return(-1);
	}

	if (pciatb_entries <= 0
	    || pciatb_slot == NULL || pci_address == NULL){
		IVED_CRIT(log4cat_veos_ived, 
			  "Conversion failed: entries: %d, slot:%p, out: %p",
			  pciatb_entries, pciatb_slot, pci_address);
		return(-1);
	}

	pciatb_pagesize = (uint64_t)ived_pci_pgsize_flag2byte
		(current_node->pciattr);

	for (i=0; i <= pciatb_entries; i++){
		if (pciatb_slot[i] == -1)
			break;
		pci_address[i] = current_node->pci_bar01_vhsaa + 
			(uint64_t)pciatb_slot[i] * pciatb_pagesize;
	}

	return(0);
}



/**
 * @brief Search a specified entry which is valid
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * ived_resource_lock
 *
 * @param [in]		resource IVED resource (VESHM owner)
 * @param [in]		vemva	VEMVA of VESHM
 * @param [in]		size	Size  of VESHM
 * @param [in]		syncnum PCISYNC pair num
 * @param [in]		status_flag Request mode flag
 *
 * @return Pointer of owned_veshm_info structure on success, NULL on failure
 */

struct owned_veshm_info *
pickup_owned_veshm_addr(struct ived_shared_resource_data *resource, 
			uint64_t vemva, uint64_t size, int syncnum, 
			uint64_t status_flag)
{
	struct list_head *list_p;
	struct owned_veshm_info *entry = NULL;
	int found = 0;
	uint64_t checking_mask = (VESHM_MODE_SYNC | VESHM_MODE_PCIATB
				  | VESHM_MODE_RO);

	list_for_each(list_p, &(resource->owned_veshm_list)){
		entry = list_entry(list_p, struct owned_veshm_info, list);
		if ( entry->vemva == vemva 
		     && entry->size == size 
		     && ( ! isset_flag(entry->status_flag, VESHM_MODE_INVALID) )
		     && issame_flag(entry->status_flag, status_flag,
				    checking_mask)){
			if (isset_flag(status_flag, VESHM_MODE_SYNC)
			    && entry->pcisync_num != syncnum){
				continue;
			}
			found = 1;
			break;
		}
	}
	if ( found == 0 )
		entry = NULL;

	return (entry);
}


/**
 * @brief Search a specified entry
 *
 * @param [in]		head        List head  of owned_veshm_info
 * @param [in]		uuid_veshm  UUID of VESHM area
 *
 * @return Pointer of owned_veshm_info structure on success, NULL on failure
 */

struct owned_veshm_info *
pickup_owned_veshm_uuid(struct list_head *head, uuid_t uuid_veshm)
{
	struct list_head *list_p;
	struct owned_veshm_info *entry;
	int found = 0;

	if (head == NULL)
		return (NULL);

	list_for_each(list_p, head){
		entry = list_entry(list_p, struct owned_veshm_info, list);
		if ( uuid_compare(entry->uuid_veshm, uuid_veshm) == 0){
			found = 1;
			break;
		}
	}
	if ( found == 0 )
		entry = NULL;

	return (entry);
}

/*
 * @brief get owened VESHM information from all VESHM areas
 * NOTE: Before entering this function, a caller must acquire locks.
 * veshm_remains_lock (if resource is null)
 * ived_resource_lock(if resource is NOT null)
 *
 * Search all VESHM area by uuid_veshm and pick up a owned_veshm_info.
 *
 * @param [in]    uuid_veshm	UUID of VESHM
 * @param [in]    resource      IVED shared resource struct
 *
 * @return 0 on succes, Not 0 and set errno on failure
 */
struct owned_veshm_info *
search_all_owned_veshm_uuid(uuid_t uuid_veshm, 
			    struct ived_shared_resource_data *resource)
{
	struct owned_veshm_info *entry = NULL;
	struct list_head *owner_list_head = NULL;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	/* Check whether the process is alive. */
	if (resource != NULL){

		owner_list_head = &(resource->owned_veshm_list);
		entry = pickup_owned_veshm_uuid(owner_list_head, uuid_veshm);

	} else {  /* The process had terminated. */
		entry = pickup_owned_veshm_uuid(&veshm_remains_list,
						uuid_veshm);
	}

	IVED_DEBUG(log4cat_veos_ived, "ived_resource:%p, entry:%p", 
		   resource, entry);
	return(entry);
}


/**
 * @brief Delete a specified entry
 *
 * NOTE: Array for PCIATB slots is deleted separately so that
 * other function can release PCIATB entries.
 *
 * @param [in]		owner_list_head  List head of owner veshm list
 * @param [in]		list_cnt Counter of a list (Can be NULL)
 * @param [in]		entry	 Remove the entry from owned_veshm_info
 *
 * @return Pointer of owned_veshm_info structure on success, -1 on failure
 */
int
delete_owned_veshm_info(struct list_head *owner_list_head,
			int  *list_cnt, struct owned_veshm_info *entry)
{
	IVED_TRACE(log4cat_veos_ived, "PASS");

	if (owner_list_head == NULL || entry == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		return (-1);
	}
	if (list_cnt != NULL)
		(*list_cnt)--;
	list_del(&entry->list);
	free(entry->paddr_array);
	free(entry);

	return (0);
}


/**
 * @brief Release all owned VESHM information
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * ived_resource_lock
 *
 * @param [in] tsk	Target process
 *
 * @retval 0 on success, -1 on failure
 */
static int
release_owned_veshm_all(struct ve_task_struct *tsk)
{
	int ret;
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry;
	struct list_head *list_p, *list_n;
	struct list_head *cur_remains_1st, *cur_veshm_1st;
	struct list_head *cur_veshm_last;

	RpcVeshmSubClose request_close;
	IvedReturn reply;
	RpcVeshmReturn veshm_ret;
	ProtobufCBinaryData uuid1, uuid2;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	assert(tsk != NULL);
	if (tsk == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		return(-1);
	}
	resource = tsk->ived_resource;

	list_p = resource->owned_veshm_list.next;

	list_for_each_safe(list_p, list_n, &resource->owned_veshm_list){

		entry = list_entry(list_p, struct owned_veshm_info, list);

		rpc_veshm_sub_close__init(&request_close);
		ived_return__init(&reply);
		rpc_veshm_return__init(&veshm_ret);
		reply.veshm_ret = &veshm_ret;

		request_close.owner_pid = resource->pid; 
		set_flag(entry->status_flag, IVED_PROC_EXIT);
		set_flag(entry->status_flag, VESHM_MODE_CLOSE);

		uuid1.len                     = sizeof(uuid_t);
		uuid1.data                   = (uint8_t *)entry->uuid_veshm;
		request_close.has_uuid_veshm = 1;
		request_close.uuid_veshm     = uuid1;

		uuid2.len                     = sizeof(uuid_t);
		uuid2.data                   = (uint8_t *)entry->uuid_proc;
		request_close.has_uuid_proc  = 1;
		request_close.uuid_proc      = uuid2;

		dump_uuid("close all proc", entry->uuid_proc);
		dump_uuid("close all veshm", entry->uuid_veshm);
		ret = veos_veshm_close_common(&request_close, &reply, 
					      tsk, entry);
		IVED_TRACE(log4cat_veos_ived, "ret:%d, reply.ret_val:%"PRIx64"",
			   ret, reply.retval);

	}

	/* Move all entries to veshm_remains_list */
	if (!list_empty(&resource->owned_veshm_list)){

		pthread_mutex_lock(&veshm_remains_lock);

		cur_veshm_1st   = resource->owned_veshm_list.next;
		cur_veshm_last  = resource->owned_veshm_list.prev;
		cur_remains_1st = veshm_remains_list.next;

		/* Insert resource->owned_veshm_list into the
		 * top of veshm_remains_list. */
		veshm_remains_list.next = cur_veshm_1st;
		cur_veshm_1st->prev     = &veshm_remains_list;

		cur_veshm_last->next  = cur_remains_1st;
		cur_remains_1st->prev = cur_veshm_last;

		INIT_LIST_HEAD(&resource->owned_veshm_list);

		resource->owned_veshm_num = 0;

		pthread_mutex_unlock(&veshm_remains_lock);
	}

	return(0);
}

/**
 * @brief Search a specified entry which is valid
 *
 * @param [in]		resource IVED shared resource struct (VESHM user)
 * @param [in]		pid	PID of VESHM owner process
 * @param [in]		vemva	VEMVA of VESHM
 * @param [in]		size	Size  of VESHM
 * @param [in]          mode_flag Mode of VESHM
 *
 * @return Pointer of attaching_veshm_info structure on success, NULL on failure
 */
struct attaching_veshm_info *
pickup_attaching_veshm(struct ived_shared_resource_data *resource,
		       int pid, uint64_t vemva, 
		       uint64_t size, int syncnum, uint64_t mode_flag)
{
	struct list_head *list_p;
	struct attaching_veshm_info *entry = NULL;
	int found = 0;
	uint64_t checking_mask = VESHM_MODE_SYNC | VESHM_MODE_PCIATB
		| VESHM_MODE_RO;

	assert(resource != NULL);
	if (resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		goto err_ret;
	}

	list_for_each(list_p, &(resource->attach_veshm_list)){
		entry = list_entry(list_p, struct attaching_veshm_info, list);
		if ( ( ! isset_flag(entry->mode_flag, VESHM_MODE_INVALID) )
		     && entry->target_pid == pid 
		     && entry->target_vemva == vemva 
		     && entry->size == size
		     && issame_flag(entry->mode_flag, mode_flag, 
				    checking_mask)){
			if (isset_flag(mode_flag, VESHM_MODE_SYNC)
			    && entry->pcisync_num != syncnum){
				continue;
			}
			found = 1;
			break;
		}
	}
	if ( found == 0 )
		entry = NULL;
err_ret:
	return (entry);
}

/**
 * @brief Search a specified entry by vemva or vehva which is attached address
 *
 * @param [in]	resource IVED shared resource struct
 * @param [in]	address VEMVA or VEHVA attached VESHM 
 * @param [in]	atb_kind  Which address is valid, vemva or vehva?
 *
 * @return Pointer of attaching_veshm_info structure on success, NULL on failure
 */
struct attaching_veshm_info *
pickup_attaching_veshm_kind(struct ived_shared_resource_data *resource, 
			    uint64_t address, uint64_t atb_kind)
{
	struct list_head *list_p;
	struct attaching_veshm_info *entry = NULL;
	int found = 0;

	assert(resource != NULL);
	if (resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		goto err_ret;
	}

	list_for_each(list_p, &(resource->attach_veshm_list)){
		entry = list_entry(list_p, struct attaching_veshm_info, list);

		if ( isset_flag(atb_kind, (VE_REGISTER_VEHVA | VE_MEM_LOCAL))){
			if ( entry->vehva == address ){
				found = 1;
				break;
			}
		} else {
			if ( entry->vemva == address ){
				found = 1;
				break;
			}
		}
	}
	if ( found == 0 )
		entry = NULL;

err_ret:
	return (entry);
}


/**
 * @brief Delete a specified entry
 *
 * @param [in]		resource IVED shared resource struct
 * @param [in]		entry    Erased data
 *
 * @return 0 on success, -errno on failure
 */
int
delete_attaching_veshm_info(struct ived_shared_resource_data *resource, 
			    struct attaching_veshm_info *entry)
{
	IVED_TRACE(log4cat_veos_ived, "PASS");

	assert(resource != NULL);

	if (entry == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		return (-EINVAL);
	}

	if (resource == NULL ){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		return(-EINVAL);
	}

	resource->attach_veshm_num--;
	list_del(&entry->list);
	free(entry);

	return (0);
}


/**
 * @brief Release all attaching VESHM information
 *
 * It is for cleaning IVED resources for process exiting.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * ived_task_list_lock
 *
 * @param [in] resource IVED shared resource struct (Exiting process)
 *
 * @return 0
 */
static int
release_attaching_veshm_all(struct ived_shared_resource_data *resource)
{
	struct attaching_veshm_info *entry;
	struct list_head *list_p, *list_n;

	IVED_TRACE(log4cat_veos_ived, "PASS");
	assert(resource != NULL);

	list_for_each_safe(list_p, list_n, &resource->attach_veshm_list){

		entry = list_entry(list_p, struct attaching_veshm_info, list);
		resource->attach_veshm_num--;
		list_del(&entry->list);
		free(entry);
	}

	IVED_TRACE(log4cat_veos_ived, "PASS");
	return(0);
}

/**
 * @brief Delete all VESHM management data
 *
 * NOTE: If a process sends a detach request after
 * it acquired ived_task_list_lock, releasing VESHM
 * request will stall in veos_veshm_erase_area.
 * So, don't acquire ived_task_list_lock.
 *
 * @param [in] tsk	Target process
 *
 * @retval 0 on sucess, -1 on failure
 *
 */
int
veos_veshm_discard_all(struct ve_task_struct *tsk)
{
	IVED_TRACE(log4cat_veos_ived, "PASS");

	if (tsk == NULL){
		return(-1);
	}

	if (tsk->group_leader != tsk){
		tsk->ived_resource = NULL;
		IVED_ERROR(log4cat_veos_ived, "Not group leader");
		goto ret_sucess;
	}

	if (tsk->ived_resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Resource data is NULL.");
		return(-1);
	}

	pthread_rwlock_wrlock(&tsk->ived_resource->ived_resource_lock);
	/* NOTE: veshm_remains_lock will be locked in 
	 * release_owned_veshm_all. */

	/* Ask IVED to clear one by one */
	release_owned_veshm_all(tsk);

	/* Only free all data structures */
	release_attaching_veshm_all(tsk->ived_resource); 

	pthread_rwlock_unlock(&tsk->ived_resource->ived_resource_lock);


ret_sucess:
	IVED_TRACE(log4cat_veos_ived, "PASS");
	return(0);
}

/**
 * @brief update VESHM is_swap_out
 * 
 * This function updates is_swap_out@ived_shared_resource_data,
 * before Swap-out and after Swap-in.
 * So, This function must be invoked in the beginning of Swap-out,
 * and must be invoked at the end of Swap-in, from "swap thread",
 * only with handling_request_lock_task@ve_task_struct,
 * with write lock of ived_resource_lock@ived_shared_resource_data
 *
 * @param [in] tsk	Target process
 *
 * @param [in] is_swap_out process swap out or not
 *
 * @retval 0 on sucess
 * @retval -1 on failure
 */
int
veos_veshm_update_is_swap_out(struct ve_task_struct *tsk, bool is_swap_out)
{
	int retval = -1;
	struct ived_shared_resource_data *resource;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	if (tsk == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Task is NULL.");
		goto hndl_return;
	}

	if (tsk->ived_resource == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Resource data is NULL.");
		goto hndl_return;
	}

	resource = tsk->ived_resource;

	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	resource->is_swap_out = is_swap_out;
	pthread_rwlock_unlock(&resource->ived_resource_lock);

	retval = 0;
	IVED_TRACE(log4cat_veos_ived, "PASS");
hndl_return:
	return retval;
}

/**
 * @brief checkes phycal address of own VESHM information
 *
 * This function checks physical address of owned
 * VESHM information was changed or not, before Swap-out.
 * This function is invoked from ve_so_swapout().
 * The current check is only VESHM that is not
 * registered in PCIATB
 *
 * @param [in] tsk	Target process
 * 
 * @retval 0 on sucess
 * @retval -1 on failure
 */
int 
veos_veshm_test_paddr_array_all(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry = NULL;
	struct list_head *list_p, *list_n;
	int ret = 0;
	int retval = -1;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	if (tsk == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Task is NULL.");
		goto hndl_return;
	}

	if (tsk->ived_resource == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Resource data is NULL.");
		goto hndl_return;
	}

	resource = tsk->ived_resource;

	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	/* loop VESHM information*/
	list_for_each_safe(list_p, list_n, &resource->owned_veshm_list) {
		/* get owned VESHM information */
		entry = list_entry(list_p, struct owned_veshm_info, list);
		/* get physical address of owned VESHM */
		/* check physical address */
		if (entry->pciatb_entries == 0) {
			ret = check_veshm_paddr(entry->paddr_array,
					entry->physical_pages,
					entry->physical_pgsize, tsk->pid,
					entry->vemva, entry->size);
			if (ret == -1) {
				IVED_ERROR(log4cat_veos_ived,
				   "check_veshm_paddr failed.");
			} else if (ret == 1) {
				entry->paddr_array[0] = INVALID_VESHM;
			}
		}
	}
	pthread_rwlock_unlock(&resource->ived_resource_lock);
	retval = 0;
	IVED_TRACE(log4cat_veos_ived, "PASS");
hndl_return:
	return retval;
}
/**
 * @brief update physical address and specified memory's
 *
 * @param [in] entries  Length of registered physical address array
 * @param [in] pgsize   Page size of registered physical pages
 * @param [in] pid	PID of examined process 
 * @param [in] vemva	Virtual address of examined address
 * @param [in] memsize	Memory size 
 * @param [out] paddr	Registered physical address
 *
 * @retval 0  Physical addresses update success.
 * @retval -1 Failed
 */
int
update_veshm_paddr(uint64_t entries, uint64_t pgsize, pid_t pid,
			uint64_t vemva, uint64_t memsize, uint64_t *paddr)
{
	int i;
	int64_t new_paddr;
	int atb_prot;

	if (paddr == NULL){
		assert(0);
		return (-1);
	}

	for (i = 0; i < entries; i++){
		new_paddr = veos_virt_to_phy(vemva + pgsize * i,
						pid, false, &atb_prot);
		if (new_paddr < 0) {
			new_paddr = INVALID_VESHM;
		}
		*(paddr + i) = (uint64_t)new_paddr;
		IVED_DEBUG(log4cat_veos_ived, 
			"Physical address is changed: vemva:%#"PRIx64"",
				vemva+pgsize*i);
	}

	return(0);
}

/**
 * @brief checkes phycal address of own VESHM information
 *
 * This function update physical address of owned
 * VESHM information was if they were changed by Swap-in.
 * This function is invoked from ve_do_swapin().
 * The current check is only VESHM that is not
 * registered in PCIATB
 *
 * @param [in] tsk	Target process
 * @return None
 */
void
veos_veshm_update_paddr_array_all(struct ve_task_struct *tsk)
{
	struct ived_shared_resource_data *resource;
	struct owned_veshm_info *entry = NULL;
	struct list_head *list_p, *list_n;
	int ret = 0;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	if (tsk == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Task is NULL.");
		goto hndl_return;
	}

	if (tsk->ived_resource == NULL) {
		IVED_CRIT(log4cat_veos_ived, "Resource data is NULL.");
		goto hndl_return;
	}

	resource = tsk->ived_resource;

	pthread_rwlock_wrlock(&resource->ived_resource_lock);
	/* loop VESHM information*/
	list_for_each_safe(list_p, list_n, &resource->owned_veshm_list) {
		/* get owned VESHM information */
		entry = list_entry(list_p, struct owned_veshm_info, list);
		/* get physical address of owned VESHM */
		/* check physical address */
		if (entry->pciatb_entries == 0) {
			if (entry->paddr_array == (uint64_t *)INVALID_VESHM) {
				IVED_DEBUG(log4cat_veos_ived,
				   "veshm_paddr all 'F'");
				continue;
			}
			ret = check_veshm_paddr(entry->paddr_array,
					entry->physical_pages,
					entry->physical_pgsize, tsk->pid,
					entry->vemva, entry->size);
			if (ret == -1) {
				IVED_ERROR(log4cat_veos_ived,
					   "check_veshm_paddr failed.");
			} else if (ret == 0) { 
				IVED_DEBUG(log4cat_veos_ived,
		   			"Physical addresses are not changed");
			} else {
				ret = update_veshm_paddr(entry->physical_pages,
						entry->physical_pgsize,
						tsk->pid,
						entry->vemva, entry->size,
						entry->paddr_array);
				if (ret == -1){
					IVED_ERROR(log4cat_veos_ived,
						"Updating physical addresses "
						"failed");
				} else {
					IVED_DEBUG(log4cat_veos_ived,
			   			"Physical addresses are "
						"update.");
				}
			}
		}
	}
	pthread_rwlock_unlock(&resource->ived_resource_lock);
	IVED_TRACE(log4cat_veos_ived, "PASS");
hndl_return:
	return;
}
