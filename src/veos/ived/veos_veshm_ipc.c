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
 * @file veos_veshm_ipc.c  
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
#include <sys/mman.h>
#include <limits.h>

#include "ve_memory.h"
#include "libved.h"
#include "ve_hw.h"
#include "veos.h"
#include "veos_handler.h"
#include "task_mgmt.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "vehva_mgmt.h"
#include "pciatb_api.h"
#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"

#include "veos_ived.h"
#include "veos_ived_misc.h"
#include "veos_ived_common.h"
#include "veos_veshm.h"
#include "veos_veshm_core.h"
#include "vesync.h"
#include "ived_ipc.h"
#include "ived_common.h"
#include "ived.pb-c.h"

#define REPLY_OK	0
#define REPLY_NG	-ECANCELED
#define LOCK_TIMEOUT	10	/* seconds */

/**
 * @brief Common VESHM open function
 *
 * @param [in]     request_open	Structure for arguments of VESHM open
 * @param [out]    reply   	Reply message of VESHM (Need initialized)
 *
 * @return 0 on succes, -1 and set errno on failure
 * @retval IVED_REQ_OK    Succeeded the request
 * @retval IVED_REQ_NG    Failed the request in the IVED
 * @retval IVED_FUNC_ERR  Failed in this function
 *
 */
int 
veos_veshm_open_common(RpcVeshmSubOpen *request_open, IvedReturn *reply)
{ 
	int i;
	int ret = 0;
	int existing = 0;	/* 1 =  A memory exists in owned_veshm list */
	int get_pciatb_ent = 0; /* 1 =  Get new PCIATB entries */
	int renew_veshm = 0;	/* 1 =  Renew VESHM registration */
	size_t pciatb_slot_num = 0;

	struct owned_veshm_info *entry=NULL, *newent=NULL;
	struct ve_task_struct *tsk = NULL;
	struct ived_shared_resource_data *ived_resource = NULL;
	uint64_t stat_check_val = 0;

	int64_t pciatb_pagesize;
	int vemva_pg_mode;
	int pciatb_pgsize_flag = -1;
	int64_t align_size;
	int pg_shft;
	int64_t physical_pgsize = 0;
	uint64_t page_mask, start_vemva;
	size_t   vemva_size;
	int slot;
	uint64_t *allocated_pci = NULL;

	int ived_req_sock = -1;
	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	IvedReturn *ret_ived=NULL;
	ProtobufCBinaryData uuid_data;

	assert(request_open != NULL);
	assert(reply != NULL);
	if ((request_open == NULL) || (reply == NULL)){
		if (reply != NULL){
			reply->retval = IVED_REQ_NG;
			reply->error  = -ECANCELED;
		}
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret_nolock;
	}

	reply->retval = IVED_REQ_NG;
	reply->error  = -ECANCELED;

	if (current_node == NULL){
		IVED_CRIT(log4cat_veos_ived, "Current node data is invalid.");
		goto err_ret_nolock;
	}
	pciatb_pagesize = (int64_t)ived_pci_pgsize_flag2byte
		(current_node->pciattr);

	/* Mode flag conversion request_open->mode_flag to
	 * stat_check_val for check */
	stat_check_val = (request_open->mode_flag & ~VE_SYS_FLAG_MASK);

	/* Check combination of mode_flag */
	/* invalid flag */
	if ( isset_flag(stat_check_val,
			~(VE_SHM_RO | VE_PCISYNC 
			  | VE_REGISTER_PCI | VE_REGISTER_NONE))){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM registration: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* Exclusive OR flags */
	ret = 0;
	if ( isset_flag(stat_check_val, VE_REGISTER_PCI) )
		ret++;
	if ( isset_flag(stat_check_val, VE_REGISTER_NONE) )
		ret++;
	if (ret != 1){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM registration: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* Not register to PCI, but VE_PCISYNC is specified. */
	if ( isset_flag(stat_check_val, VE_REGISTER_NONE) 
	     &&  (stat_check_val & VE_PCISYNC) ){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM registration: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* syncnum check */
	if ( isset_flag(stat_check_val, VE_PCISYNC)){
		if (request_open->syncnum < 0 || request_open->syncnum > 3){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM registration: Invalid sync register");
			goto err_ret_invalid_arg;
		}
	} else { 
		/* If VE_PCISYNC is not set, syncnum is set to -1 forcibly. */
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM:  SYNC off: Set sync register number to -1.");
		request_open->syncnum = -1;
	}

	/* Check start vemva and size */
	if (request_open->vemva == (uint64_t)NULL || request_open->size == 0){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM registration: Invalid address or size");
		goto err_ret_invalid_arg;
	}

	vemva_pg_mode = veos_get_pgmode(VE_ADDR_VEMVA, 
					request_open->pid_of_owner,
					request_open->vemva);
	if (vemva_pg_mode < 0){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM: Check of page size failed (err:%d)",
			   vemva_pg_mode);
		goto err_ret_invalid_arg;
	}
	if ( isset_flag(stat_check_val, VE_REGISTER_PCI)){
		align_size = pciatb_pagesize;

	} else { /* Case VE_REGISTER_NONE */
		align_size = (vemva_pg_mode == PG_2M) ? PGSIZE_2M : PGSIZE_64M;
	}
	if (align_size == PGSIZE_2M){
		page_mask = POFFMASK;
	} else {
		page_mask = POFFMASK_H;
	}
	if ( ((request_open->vemva & page_mask) != 0)
	     || (request_open->size & page_mask) != 0 ){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM registration: Invalid address or size");
		goto err_ret_invalid_arg;
	}

	if ( isset_flag(stat_check_val, VE_REGISTER_PCI)){
		/* Combination of 2MB physical page and 64MB PCIATB page 
		 * is NOT allowed. 
		 * Combination of 64MB physical page and 2MB PCIATB page 
		 * is allowed. (Partial mapping) 
		 */
		pciatb_pgsize_flag = (pciatb_pagesize == PGSIZE_2M)?
			PG_2M : PG_HP;

		if (vemva_pg_mode == PG_2M
		    && pciatb_pgsize_flag == PG_HP){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM registration: Not allowed page mode");
			goto err_ret_invalid_arg;
		}
	}

	tsk = find_ve_task_struct(request_open->pid_of_owner);
	if (tsk == NULL){
		reply->error  = -ESRCH;
		IVED_ERROR(log4cat_veos_ived, 
			   "VESHM registration: %s",strerror(ESRCH)); 
		goto err_ret_nolock;
	}
	IVED_DEBUG(log4cat_veos_ived, "task struct of %d: %p", 
		   request_open->pid_of_owner, tsk);

	ived_resource = tsk->ived_resource;

	ret = pthread_rwlock_wrlock(&ived_resource->ived_resource_lock);
	assert(ret == 0);

	entry = pickup_owned_veshm_addr(ived_resource, 
					request_open->vemva,
					request_open->size,
					request_open->syncnum,
					stat_check_val);

	if ( entry != NULL ){
		ret = check_veshm_paddr(entry->paddr_array, 
					entry->physical_pages,
					entry->physical_pgsize,
					request_open->pid_of_owner,
					request_open->vemva,
					request_open->size);
		if (ret == 1){
			dump_uuid("VESHM Renewal: renewed veshm", 
				  entry->uuid_veshm);
			set_flag(entry->status_flag, VESHM_MODE_INVALID);
			entry = NULL;
			renew_veshm = 1;

		} else if (ret < 0){
			reply->error  = -ENOMEM;
			goto err_ret;
		}
	}

	if ( entry != NULL ){
		/* Existing VESHM area */
		existing = 1;
		IVED_DEBUG(log4cat_veos_ived, "Entry exists");

		if (entry->pciatb_entries != 0){

			allocated_pci = (uint64_t *)malloc
				(sizeof(uint64_t) * entry->pciatb_entries);
			if (allocated_pci == NULL){
				IVED_CRIT(log4cat_veos_ived, 
					  "VESHM registration: Buffer allocation failed (PCI)");
				reply->error  = -ENOMEM;
				goto err_ret;
			}

			/* Convert PCI slot to PCI address */
			ret = conv_pcislot_to_pciaddr(entry->pciatb_entries-1, 
						      entry->pciatb_slot,
						      allocated_pci);
			if (ret != 0){
				reply->error  = -ECANCELED;
				goto err_ret;
			}
			allocated_pci[entry->pciatb_entries-1] = -1;
		}

	} else {

		IVED_DEBUG(log4cat_veos_ived, "New entry");

		/* Check memory page size and permission */
		ret = check_mem_pgmode(request_open->pid_of_owner,
				       request_open->vemva,
				       request_open->size);
		if (ret != 0){
			reply->error  = -ENOMEM;
			goto err_ret;
		}

		/* prot is PROT_READ or PROT_WRITE */
		ret = check_mem_perm(request_open->pid_of_owner,
				     request_open->vemva,
				     request_open->size, PROT_WRITE);
		if (ret != 0){
			reply->error  = -EACCES;
			goto err_ret;
		}

		/* New VESHM area */
		newent = (struct owned_veshm_info *)malloc
			(sizeof (struct owned_veshm_info));
		if (newent == NULL){
			IVED_CRIT(log4cat_veos_ived, 
				  "VESHM registration: Buffer allocation failed (entry)");
			reply->error  = -ENOMEM;
			goto err_ret;
		}

		pg_shft = (vemva_pg_mode == PG_2M) ? SHFT_2M : SHFT_64M;
		physical_pgsize = (vemva_pg_mode == PG_2M) ? 
			(uint64_t)PGSIZE_2M : (uint64_t)PGSIZE_64M;

		INIT_LIST_HEAD(&newent->list);
		newent->vemva		= request_open->vemva;
		newent->size		= request_open->size;
		newent->pcisync_num	= request_open->syncnum;
		newent->pciatb_slot	= NULL;
		newent->pciatb_entries	= 0;
		newent->status_flag       = stat_check_val;
		newent->paddr_array	= NULL;
		newent->physical_pgsize = physical_pgsize;
		newent->physical_pages  = (request_open->size + 
					   (physical_pgsize - 1)) >> pg_shft;

		newent->paddr_array = (uint64_t *)malloc
			(sizeof(uint64_t) * newent->physical_pages);
		if (newent->paddr_array == NULL){
			IVED_CRIT(log4cat_veos_ived, 
				  "VESHM registration: Buffer allocation failed (array)");
			reply->error  = -ENOMEM;
			goto err_ret_free_newent;
		}

		ret = create_veshm_paddr_array(request_open->pid_of_owner,
					       newent->vemva,
					       newent->size,
					       newent->physical_pgsize,
					       newent->paddr_array);

		if (ret < 0 || ret != newent->physical_pages){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM registration: Physical address check failed");
			reply->error  = -ENOMEM;
			goto err_ret_free_newent;
		}

		uuid_generate(newent->uuid_veshm);
		uuid_copy(newent->uuid_proc, ived_resource->uuid_proc);
		entry = newent;

		dump_uuid("open veshm", entry->uuid_veshm);
	}

	if (existing == 0 
	    && isset_flag(newent->status_flag, VE_REGISTER_PCI)){

		/* Get new PCIATB entries. */
		start_vemva = request_open->vemva;
		vemva_size  = request_open->size;

		/* vemva_size is PCIATB size aligned */
		if ( pciatb_pagesize == PGSIZE_2M){ 
			pciatb_slot_num = vemva_size >> SHFT_2M;
		} else {
			pciatb_slot_num = vemva_size >> SHFT_64M;
		}

		IVED_DEBUG(log4cat_veos_ived, "PCIATB slots: %zu",
			   pciatb_slot_num);

		if (pciatb_slot_num > PCIATB_VLD_SIZE || pciatb_slot_num == 0){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Invalid number of PCIATB slots: %zu",
				   pciatb_slot_num);
			reply->error  = -ENOMEM;
			goto err_ret_free_newent;
		}

		/* Allocate a memory for pciatb_slot list */
		entry->pciatb_entries = pciatb_slot_num + 1;
		entry->pciatb_slot = (int *)malloc
			(sizeof(int) * entry->pciatb_entries);
		if (entry->pciatb_slot == NULL){
			IVED_CRIT(log4cat_veos_ived, 
				  "VESHM registration: Buffer allocation failed (slot)");
			reply->error  = -ENOMEM;
			goto err_ret_free_newent;
		}

		/* Allocate a memory for attached PCI address list for IPC */
		allocated_pci = (uint64_t *)malloc
			(sizeof(uint64_t) * entry->pciatb_entries);
		if (allocated_pci == NULL){
			IVED_CRIT(log4cat_veos_ived, 
				  "VESHM registration: Buffer allocation failed (PCI)");
			reply->error  = -ENOMEM;
			goto err_ret_free_newent;
		}

		veos_sync_r_bar01_bar3();

		get_pciatb_ent = 1;
		for (i = 0; i < entry->pciatb_entries-1 ; i++){
			/* Request PCIATB entry one by one */
			/* NOTE: This approach can be improved. */
			slot = veos_alloc_pciatb
				(request_open->pid_of_owner,
				 start_vemva + pciatb_pagesize * i, 
				 pciatb_pagesize, PROT_READ|PROT_WRITE, true);
			if (slot < 0){
				entry->pciatb_slot[i] = -1;
				IVED_ERROR(log4cat_veos_ived, 
					   "VHSAA allocation failed.");
				reply->error  = -ENOMEM;
				veos_sync_r_bar2();
				goto err_ret_free_pciatb;
			}

			entry->pciatb_slot[i] = slot;

			if ( isset_flag(stat_check_val, VE_PCISYNC)){
				ret = veos_set_pciatb_pgdesc
					(request_open->pid_of_owner,
					 request_open->syncnum, slot, 1);
				if (ret != 0){
					/* PCI allocation succeeded, so
					 * index is i+1 */
					entry->pciatb_slot[i+1] = -1;
					IVED_ERROR(log4cat_veos_ived, 
						   "VHSAA allocation failed.");
					reply->error  = -ENOMEM;
					veos_sync_r_bar2();
					goto err_ret_free_pciatb;
				}
			}
		}
		entry->pciatb_slot[entry->pciatb_entries-1] = -1;

		veos_sync_r_bar2();

		/* Create PCI address for IVED */
		ret = conv_pcislot_to_pciaddr(entry->pciatb_entries-1, 
					      entry->pciatb_slot,
					      allocated_pci);
		if (ret != 0){
			reply->error  = -ECANCELED;
			goto err_ret_free_pciatb;
		}
		allocated_pci[entry->pciatb_entries-1] = -1;
	}

	/* Inform the registration to IVED. */
	/* Fill a IVED request message */

	uuid_data.len = sizeof(uuid_t);
	uuid_data.data = (uint8_t *)&(entry->uuid_veshm);
	request_open->has_uuid_veshm	= 1;
	request_open->uuid_veshm	= uuid_data;

	if (entry->pciatb_entries != 0){
		request_open->n_pci_address     = entry->pciatb_entries;
		request_open->pci_address       = allocated_pci;
	} else {
		request_open->n_pci_address     = 0;
		request_open->pci_address       = NULL;
	}

	if (renew_veshm == 1){
		set_flag(request_open->mode_flag, VE_MEM_RENEW);
	}
	IVED_DEBUG(log4cat_veos_ived, "renew_veshm: %d", renew_veshm);

	request.open_arg		= request_open;
	request.subcmd			= VESHM_OPEN;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		reply->error  = -ECANCELED;
		goto err_ret_free_pciatb;
	}

	ret = ived_exchange_veshm_msg(ived_req_sock, &request, &ret_ived);
	if (ret != 0 || ret_ived == NULL){

		reply->error = -ECANCELED;

		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM open) failed");
		if (ret == IVED_RPC_ERR || ret == IVED_RPC_ERR_SEND){
			goto err_ret_ipc_failed;
		} else {
			/* If VEOS didn't receive reply from IVED, VEOS
			 * doesn't release PCIATB. If a request is from IB,
			 * VESHM data in IVED is not cleared when a process
			 * terminates. */
			IVED_ERROR(log4cat_veos_ived, 
				   "Receiving a result in IVED daemon failed.");
			goto err_ret_ipc_failed;
		}
	}
	if (ret_ived->retval == IVED_REQ_NG){
		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM open) failed");
		reply->error = ret_ived->error;
		goto err_ret_ipc_failed;
	}

	if ( existing == 0 ){
		/* related counters */
		ived_resource->owned_veshm_num++;
		list_add(&newent->list, &ived_resource->owned_veshm_list);
	}

	pthread_rwlock_unlock(&ived_resource->ived_resource_lock);

	/* make reply */
	reply->retval = IVED_REQ_OK;
	reply->error  = 0;

	if (isset_flag(request_open->mode_flag, VE_REQ_DEV)){
		reply->veshm_ret->n_pci_address  = entry->pciatb_entries;
		reply->veshm_ret->pci_address    = allocated_pci;
	} else {
		reply->veshm_ret->n_pci_address  = 0;
		reply->veshm_ret->pci_address    = NULL;
	}

	reply->veshm_ret->has_uuid_veshm = 1;
	reply->veshm_ret->uuid_veshm     = uuid_data;

	dump_uuid("open veshm", entry->uuid_veshm);

	ived_return__free_unpacked(ret_ived, NULL);

	ived_finish_soc(ived_req_sock);
	if (errno == EIO){
		IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
	}

	if ((allocated_pci != NULL)
	    && (isset_flag(request_open->mode_flag, VE_REQ_PROC))){
		free(allocated_pci);
	}

	put_ve_task_struct(tsk);
	return(IVED_REQ_OK);


err_ret_ipc_failed:
	if (ret_ived != NULL){
		ived_return__free_unpacked(ret_ived, NULL);
	}

	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
err_ret_free_pciatb:
	if (get_pciatb_ent == 1){
		IVED_DEBUG(log4cat_veos_ived, "Free VHSAA");

		veos_sync_r_bar01_bar3();
		for (i=0; entry->pciatb_slot[i] != -1; i++){
			IVED_TRACE(log4cat_veos_ived,"Release PCIATB [%d] %d", 
				   i, entry->pciatb_slot[i]);
			if (veos_delete_pciatb((uint64_t)entry->pciatb_slot[i], 
					       (size_t)pciatb_pagesize) < 0){
				IVED_ERROR(log4cat_veos_ived,
					   "Release PCIATB failed: slot %d", 
					   entry->pciatb_slot[i]);
			}
		}
		veos_sync_r_bar2();
	}

err_ret_free_newent:
	/* If get a new owned veshm info, clear. */
	if (newent != NULL){
		if ((get_pciatb_ent == 1) && (newent->pciatb_slot != NULL)){
			free(newent->pciatb_slot);
		}
		if (newent->paddr_array != NULL){
			free(newent->paddr_array);
		}
		free(newent);
	}

err_ret:
	if (allocated_pci != NULL){
		free(allocated_pci);
	}

	pthread_rwlock_unlock(&ived_resource->ived_resource_lock);
	put_ve_task_struct(tsk);
err_ret_nolock:
	IVED_DEBUG(log4cat_veos_ived, "VESHM open request failed");
	return(IVED_REQ_NG);

err_ret_invalid_arg:
	reply->error  = -EINVAL;
	IVED_DEBUG(log4cat_veos_ived, "VESHM open request failed");
	return(IVED_REQ_NG);
}

/**
 * @brief Make physical address array of VEMAA
 *
 * @param [out] arr	Pointer of physical address array
 *
 * @return 0 or -1
 */
static int
conv_modeflag_prot(uint64_t mode_flag)
{
	int prot = 0;
	if (isset_flag(mode_flag, VE_SHM_RO)){
		prot = PROT_READ;
	} else {
		prot = PROT_READ|PROT_WRITE;
	}
	return (prot);
}

/*
 * @brief Sub function for VESHM attach (Get DMAATB entries)
 *
 * @param [in]    user_pid	PID of DMAATB's owner. (Host PID)
 * @param [in]    target_addr	Array of VE_ADDR_VERAA, VE_ADDR_VECRAA and
 * VE_ADDR_VHSAA.
 * @param [in]    entries	DMAATB entries
 * @param [in]    pci_pgsize	PCIATB page size
 * @param [in]    permission	Access permission set to DMAATB
 *
 * @return VEHVA on success, -errno on failure
 */
static uint64_t 
get_dmaatb_for_attaching(int user_pid, uint64_t *target_addr, size_t entries,
			 uint64_t pci_pgsize, int permission)
{
	uint64_t attached_addr = -1;
	uint8_t vehva_type = 0;

	/* Check address type */
	if ( pci_pgsize == PGSIZE_64M ){
		vehva_type = VEHVA_VESHM | VEHVA_64MB;
	} else if ( pci_pgsize == PGSIZE_2M ){
		vehva_type = VEHVA_VESHM | VEHVA_2MB;
	} else {
		IVED_DEBUG(log4cat_veos_ived, "Invalid PCI pagesize");
		return (-EINVAL);
	}

	target_addr[entries-1] = (uint64_t) NULL;

	attached_addr = veos_alloc_dmaatb_entry_for_aa
		(user_pid, target_addr, permission, VE_ADDR_VHSAA, vehva_type);

	return (attached_addr);
}

/**
 * @brief Send a cancel request of attaching.
 * A caller needs to know uuid_veshm and uuid_proc to use 
 * this function.
 *
 * @param [in]    pid		  PID of a requester (Host PID)
 * @param [in]    uuid_proc	  UUID of an owner process
 * @param [in]    uuid_veshm	  UUID of a target veshm
 *
 * @return Result of ived_exchange_veshm_msg()
 */
static int
veos_ived_cancel_attach_req(pid_t pid,
			    uuid_t uuid_proc, uuid_t uuid_veshm)
{
	int retval = -1;
	int ived_req_sock = -1;
	RpcVeshmSubDetach request_detach = RPC_VESHM_SUB_DETACH__INIT;
	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	ProtobufCBinaryData uuid_data1, uuid_data2;
	IvedReturn *ret_ived=NULL;

	IVED_TRACE(log4cat_veos_ived, "PASS");


	/* To detach a VESHM, send pid of a user process,
	 * uuid_veshm of owner's and uuid_proc of owner's. */

	request_detach.user_pid   = pid;

	uuid_data1.len	= sizeof(uuid_t);
	uuid_data1.data = (uint8_t *)uuid_proc;
	request_detach.has_uuid_proc	= 1;
	request_detach.uuid_proc	= uuid_data1;
	dump_uuid("proc", uuid_data1.data);

	uuid_data2.len  = sizeof(uuid_t);
	uuid_data2.data = (uint8_t *)uuid_veshm;
	request_detach.has_uuid_veshm	= 1;
	request_detach.uuid_veshm	= uuid_data2;
	dump_uuid("veshm", uuid_data2.data);

	request.detach_arg              = &request_detach;
	request.subcmd                  = VESHM_DETACH;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		retval = IVED_RPC_ERR;
		goto err_ret;
	}

	retval = ived_exchange_veshm_msg(ived_req_sock, &request, &ret_ived);

	if (ret_ived != NULL){
		IVED_ERROR(log4cat_veos_ived, 
			   "Cancel request of VESHM attaching finished(returned err:%d)",
			   -ret_ived->error);
		ived_return__free_unpacked(ret_ived, NULL);
	}

	errno = 0;
	ived_finish_soc(ived_req_sock);
	if (errno == EIO){
		IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
	}

err_ret:
	return(retval);
}


/*
 * @brief Add data for attaching own memory to VEHVA
 *
 * @param [in] entry	attaching_veshm_info for own memory (It can be NULL)
 * @param [in] reply	address which will be stored result
 * @param [in] req_user_pid	pid of requester
 * @param [in] req_owner_pid	pid of requester (target memory is own memory)
 * @param [in] req_owner_vemva	VEMVA of a terget memory
 * @param [in] req_size		page size
 * @param [in] req_mode_flag	mode_flag 
 *
 * @return attaching_veshm_info address for a requested memory on succes, 
 * NULL on failure. 
 */
static struct attaching_veshm_info *
veos_veshm_attach_mem_local(struct attaching_veshm_info *entry,
			    IvedReturn *reply,
			    int req_user_pid, int req_owner_pid,
			    uint64_t req_owner_vemva, uint64_t req_size,
			    uint64_t req_mode_flag)
{
	int ret;
	int perm;
	int64_t attached_addr;
	struct attaching_veshm_info *ret_entry = NULL, *newent = NULL;

	if (reply == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL");
		goto err_ret;
	}

	if (entry != NULL){
		/* Multiple request */
		if ((unsigned int)entry->ref_cnt_vehva + 1 > INT_MAX){
			IVED_ERROR(log4cat_veos_ived, 
				   "Too many VESHM attachment");
			reply->error  = -ENOMEM;
			goto err_ret;

		}
		IVED_DEBUG(log4cat_veos_ived, "Use existing entry");
		entry->ref_cnt_vehva++;
		ret_entry = entry;
		goto ret_success;
	}

	/* Create an attaching VESHM info */

	/* Check memory page size and permission. */
	ret = check_mem_pgmode(req_owner_pid, req_owner_vemva,
			       req_size);
	if (ret != 0){
		reply->error  = -ENOMEM;
		goto err_ret;
	}

	/* prot is PROT_READ or PROT_WRITE */
	ret = check_mem_perm(req_owner_pid, req_owner_vemva, req_size,
			     PROT_WRITE);
	if (ret != 0){
		reply->error  = -EACCES;
		goto err_ret;
	}


	IVED_DEBUG(log4cat_veos_ived, "New entry");
	newent = (struct attaching_veshm_info *)malloc 
		(sizeof (struct attaching_veshm_info));
	if (newent == NULL){
		reply->error = -errno;
		IVED_CRIT(log4cat_veos_ived, 
			  "VESHM attaching: Buffer allocation failed");
		goto err_ret;
	}

	INIT_LIST_HEAD(&newent->list);
	newent->target_pid	= req_owner_pid;
	newent->target_vemva	= req_owner_vemva;
	newent->size		= req_size;
	newent->pcisync_num     = -1;
	newent->mode_flag       = req_mode_flag & 
		(VESHM_MODE_SYNC | VESHM_MODE_PCIATB | VESHM_MODE_RO) ;
	newent->vemva		= -1;
	newent->ref_cnt_vemva   = 0;
	newent->vehva		= -1;
	newent->ref_cnt_vehva   = 0;

	uuid_generate(newent->uuid_veshm);
	/* uuid_proc are set later. */
	uuid_clear(newent->uuid_proc);

	/* Create DMAATB image and update */
	perm = conv_modeflag_prot(req_mode_flag);
	attached_addr = veos_alloc_dmaatb_entry_for_vemva
		(req_user_pid, req_owner_pid, req_owner_vemva, 
		 req_size, perm, false);

	if (attached_addr < 0){
		IVED_DEBUG(log4cat_veos_ived, "VEHVA allocation failed");
		reply->error = -ENOMEM;
		free(newent);
		goto err_ret;
	}

	newent->vehva = attached_addr;
	newent->ref_cnt_vehva++;	/* = 1 */
	ret_entry = newent;

ret_success:
err_ret:
	IVED_DEBUG(log4cat_veos_ived, "Result: %s", 
		   (ret_entry == NULL) ? "OK" : "NG");
	return (ret_entry);
}

/*
 * @brief Common VESHM attach function
 *
 * @param [in]    request_attach Request data
 * @param [in]    reply		 Reply message (Initialized)
 *
 * @return 0 on succes, Not 0 and set errno on failure
 * @retval IVED_REQ_OK    Succeeded the request
 * @retval IVED_REQ_NG    Failed the request in the IVED
 * @retval IVED_FUNC_ERR  Failed in this function
 */
int 
veos_veshm_attach_common(RpcVeshmSubAttach *request_attach, IvedReturn *reply)
{
	int ret = 0;
	struct attaching_veshm_info *ret_entry;

	int ived_req_sock = -1;
	int req_user_pid, req_owner_pid;
	uint64_t req_owner_vemva, req_size, req_user_vemva, req_mode_flag = 0;
	int req_syncnum;
	uint64_t stat_check_val = 0;
	uint64_t page_mask;
	int vemva_pg_mode;
	int64_t pciatb_pagesize;
	int n_pci_address = 0;

	struct ve_task_struct *owner_tsk = NULL;
	struct ived_shared_resource_data *owner_ived_resource = NULL;
	struct owned_veshm_info *veshm_entry=NULL;

	struct ve_task_struct *user_tsk = NULL;
	struct ived_shared_resource_data *user_ived_resource = NULL;
	int64_t attached_addr = -1;
	uint64_t *target_addr = NULL;
	int perm;
	struct attaching_veshm_info *entry, *newent = NULL;
	uint64_t pgsize = 0;
	uint64_t add_another_mapping = -1;
	int renewed_veshm = 0;		/* 1: VESHM had been renewed */
	int create_new_attach = 0;	/* 1: Create a new attaching_veshm_info */
	int veshm_paddr_chk_err  = 0;   /* 1: Paddr check is failed 
					   or paddr is changed */
	int user_ived_locked = 0;	/* 1: Acquired user ived_resource_lock */

	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	IvedReturn *ret_ived=NULL;
	ProtobufCBinaryData uuid_data1;
	uuid_t received_uuid_veshm, received_uuid_proc;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	assert(request_attach != NULL);
	assert(reply != NULL);
	if ((request_attach == NULL) || (reply == NULL)){
		if (reply != NULL){
			reply->retval = IVED_REQ_NG;
			reply->error  = -ECANCELED;
		}
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret_nolock;
	}

	reply->retval = IVED_REQ_NG;
	reply->error  = -ECANCELED;

	req_user_pid      = request_attach->user_pid;
	req_owner_pid     = request_attach->owner_pid;
	req_owner_vemva   = request_attach->vemva;
	req_size          = request_attach->size;
	req_syncnum       = request_attach->syncnum;
	req_mode_flag     = request_attach->mode_flag;
	req_user_vemva    = request_attach->user_vemva;


	/* The upper 32bits are checked by a caller of this function. 
	 * This function checks the lower 32bits.
	 */
	stat_check_val = (req_mode_flag & ~VE_SYS_FLAG_MASK);

	/* Check combination of mode_flag */
	/* Invalid flag */
	if ( isset_flag(stat_check_val,
			~(VE_MEM_LOCAL | VE_PCISYNC | VE_SHM_RO 
			  | VE_REGISTER_NONE  | VE_REGISTER_PCI 
			  | VE_REGISTER_VEMVA | VE_REGISTER_VEHVA))){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM attaching: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* Exclusive OR flags (1) */
	ret = 0;
	if ( isset_flag(stat_check_val, VE_REGISTER_VEHVA) )
		ret++;
	if ( isset_flag(stat_check_val, VE_REGISTER_VEMVA) )
		ret++;
	if ( isset_flag(stat_check_val, VE_MEM_LOCAL) )
		ret++;
	if (ret != 1){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM attaching: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* Get page mode of the first target page.
	 * Error check of veos_get_pgmode() will be done later. */
	vemva_pg_mode = veos_get_pgmode(VE_ADDR_VEMVA, 
					req_owner_pid, req_owner_vemva);

	if ( isset_flag(stat_check_val, VE_MEM_LOCAL) ){

		ret = 0;
		if ( isset_flag(stat_check_val, VE_REGISTER_NONE) )
			ret++;
		if ( isset_flag(stat_check_val, VE_REGISTER_PCI) )
			ret++;
		if ( isset_flag(stat_check_val, VE_PCISYNC) )
			ret++;
		if (ret > 0){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM attaching: Invalid flags");
			goto err_ret_invalid_arg;
		}

		if (req_owner_pid != req_user_pid ){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM attaching: Invalid VESHM");
			goto err_ret_invalid_arg;
		}

		/* Page align check */
		if (vemva_pg_mode < 0){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM: Check of page size failed (err:%d)",
				   vemva_pg_mode);
			goto err_ret_invalid_arg;
		}
		page_mask = (vemva_pg_mode == PG_2M) ? POFFMASK : POFFMASK_H;

		if ( ((req_owner_vemva & page_mask) != 0)
		     || (req_size & page_mask) != 0 ){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM attaching: Invalid address or size");
			goto err_ret_invalid_arg;
		}


	} else {
		/* Exclusive OR flags (2) */
		ret = 0;
		if ( isset_flag(stat_check_val, VE_REGISTER_NONE) )
			ret++;
		if ( isset_flag(stat_check_val, VE_REGISTER_PCI) )
			ret++;
		if (ret != 1){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM attaching: Invalid flags");
			goto err_ret_invalid_arg;
		}

		/* When VE_REGISTER_VEHVA or VE_REGISTER_VEMVA is 
		 * specified, attaching own VESHM fails. */
		if (req_owner_pid == req_user_pid ){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VESHM attaching: Invalid flags");
			goto err_ret_invalid_arg;
		}

		/* Check impossible access */
		if ( isset_flag(stat_check_val, VE_REGISTER_NONE) ){
			if (vemva_pg_mode < 0){
				IVED_DEBUG(log4cat_veos_ived, 
					   "VESHM: Impossible access request");
				goto err_ret_invalid_arg;
			}
		}

		/* Local attach request, but page size is a mismatch. */
		if ( isset_flag(stat_check_val, VE_REGISTER_PCI) ){
			pciatb_pagesize = (int64_t)ived_pci_pgsize_flag2byte
				(current_node->pciattr);

			if (pciatb_pagesize == PGSIZE_2M
			    && vemva_pg_mode == PG_HP){ 
				/* target process exiss in the same node */
				IVED_DEBUG(log4cat_veos_ived, 
					   "VESHM: Page size mismatch");
				goto err_ret_invalid_arg;
			}
		}
	}

	/* syncnum check */
	if ( ! isset_flag(stat_check_val, VE_PCISYNC)){
		/* If VE_PCISYNC is not set, syncnum is set to -1 forcibly. */
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM:  SYNC off: Set sync register number to -1.");
		request_attach->syncnum = -1;
		req_syncnum = request_attach->syncnum;
	}

	/* Use owner_tsk later. find_ve_task_struct() increases reference
	 * count of the task, so owner_tsk is not erased by owner process
	 * until invoking put_ve_task_struct(). */
	owner_tsk = find_ve_task_struct(req_owner_pid);
	if (owner_tsk == NULL){
		/* If an owner process exists on the other nodes,
		 * owner_tsk will be NULL */
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM owner process (%d) is not found",
			   req_owner_pid);
	}

	user_tsk = find_ve_task_struct(req_user_pid);
	if (user_tsk == NULL){
		IVED_ERROR(log4cat_veos_ived, 
			   "Getting requester process (%d) data failed",
			   req_user_pid);
		reply->error = -ESRCH;
		goto err_ret_nolock;
	}

	user_ived_resource = user_tsk->ived_resource;
	ret = pthread_rwlock_wrlock(&user_ived_resource->ived_resource_lock);
	user_ived_locked = 1;
	assert(ret == 0);

	/* Attaching own memory:
	 * To use DMA transfer, a process needs to attach its memory
	 * on DMAATB. VEOS doesn't need to ask an address. 
	 * mode_flag = VE_MEM_LOCAL */
	if ( isset_flag(req_mode_flag, VE_MEM_LOCAL)){

		IVED_DEBUG(log4cat_veos_ived, "Attaching own memory");

		/* Check attaching VESHM list */
		/* pickup_attaching_veshm() checks req_mode_flag about SYNC bit.
		 * It returns an valid (latest) entry for a specified VESHM 
		 * in this process. */
		entry = pickup_attaching_veshm(user_ived_resource, 
					       req_owner_pid, 
					       req_owner_vemva, req_size,
					       req_syncnum, req_mode_flag);

		ret_entry = veos_veshm_attach_mem_local
			(entry, reply, req_user_pid, req_owner_pid,
			 req_owner_vemva, req_size, req_mode_flag);
		if (ret_entry == NULL){
			goto err_ret;
		} else {
			if (entry == NULL){
				/* Added a new entry */
				entry = ret_entry;
				uuid_copy(entry->uuid_proc, 
					  user_ived_resource->uuid_proc);
				user_ived_resource->attach_veshm_num++;
				list_add(&entry->list, 
					 &user_ived_resource->attach_veshm_list
					);
			}
			attached_addr = entry->vehva;
			goto ret_success_mem_local;
		}

		/* Not reach here */
	}

	/* Send an attach request to IVED (For VE_REGISTER_*) */

	/* Ask an address, a node of the target VESHM, 
	 * PCIATB page size, uuid and etc. to IVED.
	 * Register this attach request to IVED
	 * if the requested area has not been attached. */

	/* Fill a IVED request message */
	uuid_data1.len             = sizeof(uuid_t);
	uuid_data1.data            = (uint8_t *)
		user_ived_resource->uuid_proc;
	request_attach->has_uuid_proc	= 1;
	request_attach->uuid_proc	= uuid_data1;
	request.attach_arg		= request_attach;
	request.subcmd			= VESHM_ATTACH;

	user_ived_locked = 0;
	pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		reply->error = -ECANCELED;
		goto err_ret;
	}
	ret = ived_exchange_veshm_msg(ived_req_sock, 
				      &request, &ret_ived);
	/* Even if ived_exchange_veshm_msg failed, this function doesn't 
	 * send a cancel request. If an attching request in IVED succeeded,
	 * the data will be delete when a process terminates. */
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM attach) failed in VEOS (%d)",
			   ret);
		reply->error = -ECANCELED;
		goto err_ret;
	}
	if (ret_ived->retval == IVED_REQ_NG){
		reply->error = ret_ived->error;
		if (ret_ived->error == -ECANCELED)
			IVED_ERROR(log4cat_veos_ived, "IPC (VESHM attach) failed. err:%d", 
				   -(reply->error));
		else
			IVED_DEBUG(log4cat_veos_ived, "IPC (VESHM attach) failed. err:%d", 
				   -(reply->error));
		goto err_ret;
	}
	if (ret_ived->veshm_ret == NULL){
		IVED_CRIT(log4cat_veos_ived, 
			  "IPC (VESHM attach) is corrupted.");
		assert(ret_ived->veshm_ret != NULL);
		reply->error = -ECANCELED;
		goto err_ret_cancel_req;
	}


	/* Store uuid_veshm, uuid_proc of owner */
	uuid_copy(received_uuid_veshm, 
		  ret_ived->veshm_ret->uuid_veshm.data);
	uuid_copy(received_uuid_proc, 
		  ret_ived->veshm_ret->uuid_proc.data);
	dump_uuid("attach proc", received_uuid_proc);
	dump_uuid("attach veshm", received_uuid_veshm);

	/* If a target VESHM exists on a remote node, 
	 * members (address and pagesize) hold VHSAA 
	 * and its page size. 
	 * If a target VESHM exists on a local node,
	 * pci_address is NULL, n_pci_address is 0, pagesize is -1. */
	target_addr = ret_ived->veshm_ret->pci_address;
	n_pci_address = ret_ived->veshm_ret->n_pci_address; 
	pgsize = ret_ived->veshm_ret->pagesize;

	/* ------------ requested to IVED ---------------- */

	if (pgsize == -1){
		if (owner_tsk == NULL || owner_tsk->ived_resource == NULL){
			IVED_ERROR(log4cat_veos_ived, 
				   "Getting VESHM owner process (%d) data failed",
				   req_owner_pid);
			reply->error  = -ESRCH;
			veshm_paddr_chk_err = 1;
		}

	} 
	if (pgsize == -1 && veshm_paddr_chk_err == 0){

		/* Target VESHM exists on a local node */
		owner_ived_resource = owner_tsk->ived_resource;
		ret = pthread_rwlock_wrlock
			(&owner_ived_resource->ived_resource_lock);
		assert(ret == 0);

		/* Check physical address change */
		veshm_entry = pickup_owned_veshm_addr
			(owner_ived_resource, 
			 req_owner_vemva, req_size, req_syncnum,
			 req_mode_flag);

		if (veshm_entry == NULL){
			IVED_DEBUG(log4cat_veos_ived, 
				   "Target VESHM is not found");
			veshm_paddr_chk_err = 1;
		} else {
			dump_uuid("VESHM paddr check: veshm", 
				  veshm_entry->uuid_veshm);
			ret = check_veshm_paddr(veshm_entry->paddr_array, 
						veshm_entry->physical_pages,
						veshm_entry->physical_pgsize,
						req_owner_pid, req_owner_vemva,
						req_size);
			if (ret < 0 || ret == 1){
				veshm_paddr_chk_err = 1;
			}
		}

		pthread_rwlock_unlock(&owner_ived_resource->ived_resource_lock);
	}


	ret = pthread_rwlock_wrlock(&user_ived_resource->ived_resource_lock);
	user_ived_locked = 1;
	assert(ret == 0);

	/* Check attaching VESHM list */
	/* pickup_attaching_veshm() checks req_mode_flag about SYNC bit.
	 * It returns an valid (latest) entry for a specified VESHM 
	 * in this process. */
	entry = pickup_attaching_veshm(user_ived_resource, req_owner_pid, 
				       req_owner_vemva, req_size,
				       req_syncnum, req_mode_flag);

	/* Check VESHM renewal by uuid */
	if (entry != NULL){
		if (uuid_compare(entry->uuid_veshm, received_uuid_veshm)
		    == 0){
			/* VESHM is not renewal */
			renewed_veshm = 0;
		} else {
			dump_uuid("VESHM Renewal: renewed veshm", 
				  entry->uuid_veshm);
			renewed_veshm = 1;
		}
	}

	if ( veshm_paddr_chk_err == 1){
		/* For err_ret_cancel_req, need entry and renewed_veshm */
		goto err_ret_cancel_req;
	}

	/* If a process attaches a VESHM twice or more, 
	 * this function doesn't create a new data
	 * structure. */
	if ( entry != NULL && renewed_veshm == 0){
		/* Existing VESHM area:
		 * attaching_veshm_info manages ref_cnt_vemva and ref_cnt_vehva.
		 * Even though an entry exists but requested attaching is not
		 * registered.  */

		/* NOTE: A new data in IVED is not added, so it doesn't 
		 * need to send a cancel request in an error case. */

		IVED_DEBUG(log4cat_veos_ived, "Entry exists");
		if ( isset_flag(req_mode_flag, VE_REGISTER_VEHVA) ){

			if ((unsigned int)entry->ref_cnt_vehva + 1 > INT_MAX){
				IVED_ERROR(log4cat_veos_ived, 
					   "Too many VESHM attachment");
				reply->error  = -ENOMEM;
				goto err_ret_clear_reply;

			}
			if (entry->ref_cnt_vehva != 0){
				attached_addr = entry->vehva;
				entry->ref_cnt_vehva++;
				goto ret_existing;
			} else {
				/* The VESHM was mapped to VEMVA and
				 * this request wants to map it to VEHVA. 
				 * The VESHM must be on local node. */
				if (pgsize != -1){
					reply->error  = -EINVAL;
					IVED_DEBUG(log4cat_veos_ived, 
						   "VESHM exists on a remote node");
					goto err_ret_clear_reply;
				}
				add_another_mapping = VE_REGISTER_VEHVA;
			}
		} else {
			/* Case of req_mode_flag == VE_REGISTER_VEMVA */
			if ((unsigned int)entry->ref_cnt_vemva + 1 > INT_MAX){
				IVED_ERROR(log4cat_veos_ived, 
					   "Too many VESHM attachment");
				reply->error  = -ENOMEM;
				goto err_ret_clear_reply;
			}
			if (entry->ref_cnt_vemva != 0){
				attached_addr = entry->vemva;
				entry->ref_cnt_vemva++;
				goto ret_existing;
			} else {
				/* The VESHM was mapped to VEHVA and
				 * this request wants to map it to VEMVA. 
				 * The VESHM must be on local node. */
				if (pgsize != -1){
					reply->error  = -EINVAL;
					IVED_DEBUG(log4cat_veos_ived, 
						   "VESHM exists on a remote node");
					goto err_ret_clear_reply;
				}
				add_another_mapping = VE_REGISTER_VEMVA;
			}
		} 
	} else if ( entry != NULL && renewed_veshm == 1){
		set_flag(entry->mode_flag, VESHM_MODE_INVALID);
		IVED_DEBUG(log4cat_veos_ived, "Mark attach info with invalid");
		dump_attach_veshm(entry);

		/* Reset entry */
		entry = NULL;
	}


	if ( entry == NULL ){ 
		/* NOTE: A new data in IVED is added, so it 
		 * needs to send a cancel request in an error case. */

		create_new_attach = 1;

		/* Create an attaching VESHM info */
		IVED_DEBUG(log4cat_veos_ived, "New entry");
		newent = (struct attaching_veshm_info *)malloc 
			(sizeof (struct attaching_veshm_info));
		if (newent == NULL){
			reply->error = -errno;
			IVED_CRIT(log4cat_veos_ived, 
				  "VESHM attaching: Buffer allocation failed");
			goto err_ret_cancel_req;
		}

		INIT_LIST_HEAD(&newent->list);
		newent->target_pid	= req_owner_pid;
		newent->target_vemva	= req_owner_vemva;
		newent->size		= req_size;
		newent->pcisync_num     = req_syncnum;
		newent->mode_flag       = req_mode_flag & 
			(VESHM_MODE_SYNC | VESHM_MODE_PCIATB | VESHM_MODE_RO) ;
		newent->vemva		= -1;
		newent->ref_cnt_vemva   = 0;
		newent->vehva		= -1;
		newent->ref_cnt_vehva   = 0;
		uuid_copy(newent->uuid_veshm, received_uuid_veshm); 
		uuid_copy(newent->uuid_proc, received_uuid_proc); 

		entry = newent;
	}

	/* ----- err_ret_free_info -------------------------------- */


	/* Set up ATB/DMAATB for an new entry and another mapping */
	perm = conv_modeflag_prot(req_mode_flag);

	if ( isset_flag(req_mode_flag, VE_REGISTER_VEHVA) ){
		if (pgsize == -1){
			/* It may be better to use 
			 * veos_alloc_dmaatb_entry_for_aa for an internal 
			 * attating too. */

			/* Same node */
			attached_addr = veos_alloc_dmaatb_entry_for_vemva
				(req_user_pid, req_owner_pid,
				 req_owner_vemva, req_size, perm, false);
			if (attached_addr < 0){
				IVED_ERROR(log4cat_veos_ived, 
					   "VEHVA allocation failed");
				reply->error = -ENOMEM;
				goto err_ret_free_info;
			}
		} else {
			/* External node */
			/* Create DMAATB image and update */
			attached_addr = get_dmaatb_for_attaching
				(req_user_pid, target_addr, n_pci_address,
				 pgsize, perm);
			if (attached_addr < 0){
				IVED_ERROR(log4cat_veos_ived, 
					   "VEHVA allocation failed");
				reply->error = -ENOMEM;
				goto err_ret_free_info;
			}
		}
		entry->ref_cnt_vehva++; /* = 1 */
		entry->vehva = attached_addr;

	} else { /*  isset_flag(req_mode_flag, VE_REGISTER_VEMVA) */
		/* Same node */
		ret = veos_share_vemva_region
			(req_owner_pid, req_owner_vemva, req_user_pid, 
			 req_user_vemva, req_size, perm, false);

		if (ret < 0){
			IVED_ERROR(log4cat_veos_ived, 
				   "VEMVA allocation failed");
			reply->error = -ENOMEM;
			goto err_ret_free_info;
		}
		entry->ref_cnt_vemva++; /* = 1 */
		entry->vemva  = req_user_vemva;
		attached_addr = req_user_vemva;
	}

	if (add_another_mapping == -1){
		/* Add an entry to a list */
		/* attach_veshm_num is equal to the number of linked 
		 * attaching_veshm_info data. */
		user_ived_resource->attach_veshm_num++;
		list_add(&entry->list, &user_ived_resource->attach_veshm_list);
	}

ret_success_mem_local:
	dump_attach_veshm(entry);
	IVED_TRACE(log4cat_veos_ived, "Add a data to the attaching list.");

ret_existing:
	reply->retval = IVED_REQ_OK;
	reply->error  = 0;
	reply->veshm_ret->has_address = 1;
	reply->veshm_ret->address = attached_addr;  /* VEMVA or VEHVA */
	if (user_ived_locked == 1){
		user_ived_locked = 0;
		pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);
	}

	if (ret_ived != NULL)
		ived_return__free_unpacked(ret_ived, NULL);

	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}

	if (owner_tsk != NULL)
		put_ve_task_struct(owner_tsk);
	put_ve_task_struct(user_tsk);
	IVED_DEBUG(log4cat_veos_ived, "rpc_ret:%"PRId64", rpc_err:%d", 
		   reply->retval, reply->error);
	return(IVED_REQ_OK); 


err_ret_free_info:
	/* Free a new entry for attaching_veshm_info */
	/* Don't use entry for check instead of newent */
	if (newent != NULL)
		free(newent);

err_ret_cancel_req:
	/* NOTE: For err_ret_cancel_req, need entry and renewed_veshm */
err_ret_clear_reply:
	if (ret_ived != NULL)
		ived_return__free_unpacked(ret_ived, NULL);

	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}

	/* Send a detach request to IVED for cancellation */
	if ( renewed_veshm == 1 || create_new_attach == 1 
	     || veshm_paddr_chk_err == 1 ){
		/* Don't care about a result */
		veos_ived_cancel_attach_req(req_user_pid, received_uuid_proc,
					    received_uuid_veshm);
	}

err_ret:
	/* unlock & put task */
	if (user_ived_locked == 1){
		user_ived_locked = 0;
		pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);
	}

	if (owner_tsk != NULL)
		put_ve_task_struct(owner_tsk);
	put_ve_task_struct(user_tsk);

err_ret_nolock:
	IVED_DEBUG(log4cat_veos_ived, "VESHM attaching request failed");
	return(IVED_REQ_NG);

err_ret_invalid_arg:
	reply->error  = -EINVAL;
	IVED_DEBUG(log4cat_veos_ived, "VESHM attaching request failed");
	return(IVED_REQ_NG);
}

/*
 * @brief IPC part of VESHM detach function
 *
 * @param [in]    detach_uuid_proc  UUID of owner process
 * @param [in]    detach_uuid_veshm UUID of target veshm
 * @param [in]    request_detach Arguments of VESHM detach
 * @param [out]   reply		Reply message of VEOS (Initialized)
 *
 * @return  Result of RPC (return value and error are stored in the argument reply.
 * @retval  Return value from IVED on success. It is a positive value
 * @retval  IVED_REQ_NG which is a reply of IVED
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 */
static int 
veos_veshm_detach_ipc(uuid_t detach_uuid_proc, uuid_t detach_uuid_veshm,
		      RpcVeshmSubDetach *request_detach, IvedReturn *reply)
{
	int retval = IVED_RPC_ERR;

	int ived_req_sock = -1;
	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	ProtobufCBinaryData uuid_data1, uuid_data2;
	IvedReturn *ret_ived = NULL;

	/* Fill a IVED request message */
	uuid_data1.len  = sizeof(uuid_t);
	uuid_data1.data = (uint8_t *)detach_uuid_proc;
	request_detach->has_uuid_proc  = 1;
	request_detach->uuid_proc      = uuid_data1;
	dump_uuid("proc", uuid_data1.data);

	uuid_data2.len  = sizeof(uuid_t);
	uuid_data2.data = (uint8_t *)detach_uuid_veshm;
	request_detach->has_uuid_veshm = 1;
	request_detach->uuid_veshm = uuid_data2;
	dump_uuid("veshm", uuid_data2.data);

	request.detach_arg		= request_detach;
	request.subcmd			= VESHM_DETACH;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		reply->error  = -ECANCELED;
		retval = IVED_RPC_ERR;
		goto err_ret;
	}
	retval = ived_exchange_veshm_msg(ived_req_sock, &request, 
					 &ret_ived);

	if (ived_finish_soc(ived_req_sock) < 0){
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", 
				  strerror(errno));
		}
	}
	if ( ret_ived != NULL ){
		ived_return__free_unpacked(ret_ived, NULL);
	} else {
		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM detach) failed");
	}

err_ret:
	return (retval);
}

/*
 * @brief Common VESHM detach function
 *
 * @param [in]    request_detach Arguments of VESHM detach
 * @param [out]   reply		 Reply message (VEOS will send)
 *
 * @return 0 on succes, Not 0 and set errno on failure
 * @retval IVED_REQ_OK    Succeeded the request
 * @retval IVED_REQ_NG    Failed the request in the IVED
 * @retval IVED_FUNC_ERR  Failed in this function
 *
 */
int 
veos_veshm_detach_common(RpcVeshmSubDetach *request_detach, IvedReturn *reply)
{
	int ret = 0;
	uint64_t req_mode_flag = 0;
	struct ve_task_struct *user_tsk = NULL;
	struct ived_shared_resource_data *user_ived_resource = NULL;
	struct attaching_veshm_info *attaching_info = NULL;
	uint64_t stat_check_val = 0;

	int memory_error = 0;
	uint64_t veshm_size = 0;
	int ref_cnt_vemva = 0;

	uuid_t detach_uuid_proc, detach_uuid_veshm;

	assert(request_detach != NULL);
	assert(reply != NULL);
	if ((request_detach == NULL) || (reply == NULL)){
		if (reply != NULL){
			reply->retval = IVED_REQ_NG;
			reply->error  = -ECANCELED;
		}
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret_nolock;
	}

	req_mode_flag = request_detach->mode_flag;

	reply->retval = IVED_REQ_NG;
	reply->error  = -ECANCELED;

	/* The upper 32bits are checked by a caller of this function. 
	 * This function checks the lower 32bits.
	 */
	stat_check_val = (req_mode_flag & ~VE_SYS_FLAG_MASK);

	/* Check combination of mode_flag */
	/* Invalid flag */
	if ( isset_flag(stat_check_val,
			~(VE_MEM_LOCAL
			  | VE_REGISTER_VEMVA | VE_REGISTER_VEHVA))){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM detaching: Invalid flags");
		goto err_ret_invalid_arg;
	}

	/* Exclusive OR */
	ret = 0;
	if ( isset_flag(stat_check_val, VE_MEM_LOCAL) )
		ret++;
	if ( isset_flag(stat_check_val, VE_REGISTER_VEHVA) )
		ret++;
	if ( isset_flag(stat_check_val, VE_REGISTER_VEMVA) )
		ret++;
	if (ret != 1){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM detaching: Invalid flags");
		goto err_ret_invalid_arg;
	}

	user_tsk = find_ve_task_struct(request_detach->user_pid);
	if (user_tsk == NULL){
		IVED_ERROR(log4cat_veos_ived, 
			   "VESHM detaching: %s", strerror(ESRCH));
		reply->error = -ESRCH;
		goto err_ret_nolock;
	}

	user_ived_resource = user_tsk->ived_resource;
	ret = pthread_rwlock_wrlock(&user_ived_resource->ived_resource_lock);
	assert(ret == 0);

	/* Search attaching_veshm_info */
	attaching_info = pickup_attaching_veshm_kind
		(user_ived_resource, request_detach->address, req_mode_flag);
	if (attaching_info == NULL){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM detaching: %s", strerror(EINVAL));
		reply->error  = -EINVAL;
		pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);
		goto err_ret_put_task;
	}

	veshm_size = attaching_info->size;

	dump_uuid("Detach veshm", attaching_info->uuid_veshm);

	/*  Free DMAATB or ATB entries */
	if ( isset_flag(req_mode_flag, (VE_REGISTER_VEHVA | VE_MEM_LOCAL))){
		if (attaching_info->ref_cnt_vehva < 1){
			/* VEMVA reference cnt is larger then 1, but VEHVA
			 * reference cnt is 0. */
			attaching_info->ref_cnt_vehva = 1;
			IVED_WARN(log4cat_veos_ived, 
				  "Fix reference count (VEHVA) to 1");
		}

		if (attaching_info->ref_cnt_vehva > 1){
			IVED_DEBUG(log4cat_veos_ived, "VEHVA reference cnt: %d",
				   attaching_info->ref_cnt_vehva);
			attaching_info->ref_cnt_vehva--;
			pthread_rwlock_unlock
				(&user_ived_resource->ived_resource_lock);
			goto ret_success;
		} else {
			IVED_DEBUG(log4cat_veos_ived, "Free VEHVA");

			ret = veos_free_dmaatb_entry(request_detach->user_pid,
						     attaching_info->vehva,
						     attaching_info->size);
			if (ret != 0){
				reply->error  = -ECANCELED;
				IVED_ERROR(log4cat_veos_ived, 
					   "Releasing VEHVA failed");
			}
			attaching_info->vehva = UNUSED;
		}

	} else {	/* (req_mode_flag has VE_REGISTER_VEMVA) */
		if (attaching_info->ref_cnt_vemva < 1){
			/* VMHVA reference cnt is larger then 1, but VEMVA
			 * reference cnt is 0. */
			IVED_WARN(log4cat_veos_ived, 
				  "Fix reference count (VEMVA) to 1");
			attaching_info->ref_cnt_vemva = 1;
		}

		if (attaching_info->ref_cnt_vemva > 1){
			IVED_DEBUG(log4cat_veos_ived, 
				   "VEMVA reference count: %d",
				   attaching_info->ref_cnt_vemva);
			attaching_info->ref_cnt_vemva--;
			ref_cnt_vemva = attaching_info->ref_cnt_vemva;
			pthread_rwlock_unlock
				(&user_ived_resource->ived_resource_lock);
			goto ret_success;
		} else {
			IVED_DEBUG(log4cat_veos_ived, "Free VEMVA");

			ret = veos_unshare_vemva_region
				(request_detach->user_pid,
				 attaching_info->vemva, attaching_info->size);
			if (ret != 0){
				memory_error = 1;
				IVED_ERROR(log4cat_veos_ived, 
					   "Releasing VEMVA failed");
			}
			attaching_info->vemva = UNUSED;
		}
	} 

	if (attaching_info->vemva == UNUSED && attaching_info->vehva == UNUSED){
		/* NOTE: Before sending a request to IVED, delete 
		 * attaching_info and UNLOCK ived_resource_lock. 
		 * delete_attaching_veshm_info() will free attaching_info, 
		 * so some membees should be copied to local variables. */

		uuid_copy(detach_uuid_proc, attaching_info->uuid_proc);
		uuid_copy(detach_uuid_veshm, attaching_info->uuid_veshm);
		delete_attaching_veshm_info(user_ived_resource, attaching_info);
		pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);

		ref_cnt_vemva = 0;
		attaching_info = NULL;

		if ( ! isset_flag(req_mode_flag, VE_MEM_LOCAL) ){
			/* If this request is the last one for the VESHM area,
			 * a data in IVED should be released. */

			ret = veos_veshm_detach_ipc(detach_uuid_proc, 
						    detach_uuid_veshm,
						    request_detach, reply);

			if (ret == IVED_RPC_ERR ){
				reply->error = -ECANCELED;
				goto err_ret_ipc_failed;

			} else if ((ret == IVED_RPC_ERR_SEND)
				   || (ret == IVED_RPC_ERR_RECV)){
				IVED_WARN(log4cat_veos_ived, 
					  "Sending a request to IVED failed.");
			}

			/* Even if a request failed, this function 
			 * returns suceess to a VE program.
			 * Data in IVED will be deleted when a process 
			 * terminates. */
		}

	} else {
		ref_cnt_vemva = attaching_info->ref_cnt_vemva;
		pthread_rwlock_unlock(&user_ived_resource->ived_resource_lock);
	}


ret_success:
	if ( isset_flag(req_mode_flag, (VE_REGISTER_VEMVA))
	     && (memory_error == 0)){
		reply->veshm_ret->has_size   = 1;
		reply->veshm_ret->size       = veshm_size;
		reply->veshm_ret->has_counts = 1;
		reply->veshm_ret->counts     = ref_cnt_vemva;
	}

	reply->retval = IVED_REQ_OK;
	reply->error  = 0;
	IVED_DEBUG(log4cat_veos_ived, "rpc_ret:%"PRId64", rpc_err:%d", 
		   reply->retval, reply->error);
	put_ve_task_struct(user_tsk);
	return(IVED_REQ_OK); 

err_ret_ipc_failed:
	reply->retval = IVED_REQ_NG;
	/* reply->error has set. ; */
	if ( isset_flag(req_mode_flag, (VE_REGISTER_VEMVA))
	     && (memory_error == 0)){
		reply->veshm_ret->has_size   = 1;
		reply->veshm_ret->size       = veshm_size;
		reply->veshm_ret->has_counts = 1;
		reply->veshm_ret->counts     = 0;
	}

	put_ve_task_struct(user_tsk);

	IVED_DEBUG(log4cat_veos_ived, "VESHM detach IPC exchange failed");
	return(IVED_REQ_NG); 

err_ret_put_task:
	put_ve_task_struct(user_tsk);

err_ret_nolock:
	IVED_DEBUG(log4cat_veos_ived, "VESHM detach request failed");
	return (ERR_RET);

err_ret_invalid_arg:
	reply->error  = -EINVAL;
	IVED_DEBUG(log4cat_veos_ived, "VESHM detach request failed");
	return (ERR_RET);

}


/*
 * @brief IPC part of VESHM close function
 *
 * @param [in]    request_close Arguments of VESHM close
 * @param [out]   reply		Reply message of VEOS (Initialized)
 *
 * @return  Result of RPC (return value and error are stored in the argument reply.
 * @retval  Return value from IVED on success. It is a positive value
 * @retval  IVED_REQ_NG which is a reply of IVED
 * @retval  IVED_RPC_ERR on failure before sending a message and reply is NULL
 * @retval  IVED_RPC_ERR_SEND on failure during sending and reply is NULL
 * @retval  IVED_RPC_ERR_RECV on failure during receiving and reply is NULL
 */
static int 
veos_veshm_close_ipc(struct owned_veshm_info *entry, 
		     RpcVeshmSubClose *request_close, IvedReturn *reply)
{
	int ret = 0;
	int ived_req_sock = -1;
	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	ProtobufCBinaryData uuid_data1, uuid_data2;
	IvedReturn *ret_ived = NULL;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	assert(request_close!= NULL);
	assert(reply != NULL);

	if ((entry == NULL) || (request_close == NULL) || (reply == NULL)){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		return (IVED_RPC_ERR);
	}

	reply->retval = IVED_REQ_NG;
	reply->error  = -ECANCELED;

	/* Set VESHM_MODE_CLOSE to veshm_info->status_flag,
	 * but VESHM agent doesn't use the flag to check attachable.
	 * It is just used for recording a status. */
	set_flag(entry->status_flag, VESHM_MODE_CLOSE);

	/* Request IVED to close of the requested VESHM */

	/* Fill a IVED request message */
	set_flag(request_close->mode_flag, VESHM_MODE_CLOSE);

	if (isset_flag(entry->status_flag, IVED_PROC_EXIT)){
		set_flag(request_close->mode_flag, IVED_PROC_EXIT);
	}

	uuid_data1.len   = sizeof(uuid_t);
	uuid_data1.data  = (uint8_t *)entry->uuid_proc;
	request_close->has_uuid_proc  = 1;
	request_close->uuid_proc      = uuid_data1;
	dump_uuid("proc", uuid_data1.data);

	uuid_data2.len  = sizeof(uuid_t);
	uuid_data2.data = (uint8_t *)entry->uuid_veshm;
	request_close->has_uuid_veshm = 1;
	request_close->uuid_veshm     = uuid_data2;
	dump_uuid("veshm", uuid_data2.data);

	request.close_arg		= request_close;
	request.subcmd			= VESHM_CLOSE;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		reply->error  = -ENOLINK;
		goto err_ret;
	}

	ret = ived_exchange_veshm_msg(ived_req_sock, &request, &ret_ived);

	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM close) failed in VEOS (%d)",
			   ret);
		reply->retval = ret;
		reply->error  = -ECANCELED;
	} 
	else if (ret_ived->retval == IVED_REQ_NG){
		IVED_ERROR(log4cat_veos_ived, "IPC (VESHM close) failed");
		reply->retval = IVED_REQ_NG;
		reply->error  = ret_ived->error;
	} else {
		if (ret_ived->veshm_ret == NULL){
			IVED_ERROR(log4cat_veos_ived, 
				   "Reply message (VESHM close) is corrupted");
			reply->retval = IVED_REQ_NG;
			reply->error  = -ECANCELED;
			goto err_ret;
		}
		reply->retval = ret_ived->retval;
		reply->error  = 0;
		reply->veshm_ret->has_counts = 1;
		reply->veshm_ret->counts     = ret_ived->veshm_ret->counts;
	}

err_ret:
	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
	if ( ret_ived != NULL ){
		ived_return__free_unpacked(ret_ived, NULL);
	}
	IVED_DEBUG(log4cat_veos_ived, "reply->retval:%d", (int)reply->retval);
	return (reply->retval);
}


/*
 * @brief Common VESHM close function
 * 
 * NOTE:
 * The argument terminating_tsk is used by release_owned_veshm_all().
 * release_owned_veshm_all() has aquired ived_resource_lock.
 *
 * @param [in]    request_close Arguments of VESHM close
 * @param [out]   reply		Reply message of VEOS (Initialized)
 * @param [in]    terminating_tsk VE task struct 
 *
 * @return 0 on succes, Not 0 and set errno on failure
 * @retval IVED_REQ_OK    Succeeded the request
 * @retval IVED_REQ_NG    Failed the request in the IVED
 */
int 
veos_veshm_close_common(RpcVeshmSubClose *request_close, IvedReturn *reply,
			struct ve_task_struct *terminating_tsk,
			struct owned_veshm_info *terminating_entry)
{
	int i;
	int ret = 0;
	struct ve_task_struct *tsk = NULL;
	struct ived_shared_resource_data *ived_resource = NULL;
	struct owned_veshm_info *entry = NULL;

	int64_t pciatb_pagesize;
	uuid_t req_uuid_veshm;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	/* Use uuid_proc and uuid_veshm for a request because the process may 
	 * have been terminated. */

	assert(request_close != NULL);
	assert(reply != NULL);

	if ((request_close == NULL) || (reply == NULL)
	    || (reply->veshm_ret == NULL)){
		if (reply != NULL){
			reply->retval = IVED_REQ_NG;
			reply->error  = -ECANCELED;
		}
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret_nolock;
	}

	reply->retval = IVED_REQ_NG;
	reply->error  = -ECANCELED;

	if (current_node == NULL){
		IVED_CRIT(log4cat_veos_ived, "Current node data is invalid.");
		goto err_ret_nolock;
	}
	pciatb_pagesize = (int64_t)ived_pci_pgsize_flag2byte
		(current_node->pciattr);

	/* NOTE: mode_flag specified by a user is checked in 
	 * veos_veshm_close(). */

	/* syncnum check */
	if ( ! isset_flag(request_close->mode_flag, VE_PCISYNC)){
		/* If VE_PCISYNC is not set, syncnum is set to -1 forcibly. */
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM:  SYNC off: Set sync register number to -1.");
		request_close->syncnum = -1;
	}

	uuid_copy(req_uuid_veshm, request_close->uuid_veshm.data);
	dump_uuid("Close veshm", req_uuid_veshm);

	if ((request_close->vemva == 0) 
	    && (uuid_is_null(req_uuid_veshm) == 1 /* == NULL */)){
		IVED_DEBUG(log4cat_veos_ived, 
			   "VESHM erasing: Invalid VESHM");
		reply->error  = -EINVAL;
		goto err_ret_nolock;
	}

	/* 
	 * To get ived_shared_resource_data, use find_ve_task_struct(), but
	 * a target owner process may not exist. 
	 * If a return value of find_ve_task_struct() is NULL, search
	 * ived_shared_resource_data by ived_task_list, then 
	 * VESHM from terminated process's VESHM list (veshm_remains_list).
	 */

	/* Find ve_task_struct by pid if the target process is alive. */
	if (terminating_tsk != NULL){
		assert (terminating_entry != NULL);
		/* The pid process is terminating. */
		tsk = terminating_tsk;
		/* ived_resource_lock has been acquired by a caller function. 
		 * NOTE:
		 * ived_task_list_lock is not lockd because this function
		 * with valid terminating_tsk doesn't use ived_task_list.
		 */
		ived_resource = tsk->ived_resource;

	} else {
		/* The pid process is alive or exiting. (MPI or IB) 
		 * NOTE: If a thread perform process's termination,
		 * find_ve_task_struct() probably returns NULL.
		 */

		tsk = find_ve_task_struct(request_close->owner_pid);
		if (tsk != NULL){
			ived_resource = tsk->ived_resource;
			if (ived_resource == NULL){
				IVED_CRIT(log4cat_veos_ived, 
					  "IVED resource data is NULL.");
				goto err_ret_nolock;
			}
			ret = pthread_rwlock_wrlock
				(&ived_resource->ived_resource_lock);
			assert(ret == 0);
		}

		if (ived_resource == NULL){
			/* Search again by ived_task_list.
			 * search_ived_resource_data() acquires ived_resource_lock. 
			 */
			pthread_mutex_lock(&ived_task_list_lock);
			ived_resource = search_ived_resource_data
				(request_close->owner_pid);
			pthread_mutex_unlock(&ived_task_list_lock);
		}
	}

	if (ived_resource == NULL){
		/* If ived_resource == NULL, the task had terminated.
		 * A requester is from IB if req_uuid_veshm is not NULL. */
		if (uuid_is_null(req_uuid_veshm) == 1 /* == NULL */){
			IVED_ERROR(log4cat_veos_ived, 
				   "VESHM erasing: %s", strerror(ESRCH));
			reply->error = -ESRCH;
			goto err_ret_nolock;
		}
	}

	if (terminating_entry != NULL){
		/* Exiting task */
		IVED_DEBUG(log4cat_veos_ived, "Close for a terminating proc.");
		entry = terminating_entry;

	} else if ( ived_resource != NULL && request_close->vemva != 0){
		IVED_DEBUG(log4cat_veos_ived, "Search by vaddr.");
		/* From MPI, a target process is alive. */
		entry = pickup_owned_veshm_addr(ived_resource, 
						request_close->vemva, 
						request_close->size,
						request_close->syncnum, 
						request_close->mode_flag);
	} else if ( ived_resource != NULL && request_close->vemva == 0){
		IVED_DEBUG(log4cat_veos_ived, "Search by uuid, task data exists");
		/* From IB, a target process is alive (after exec()) 
		 * or it is terminating. If a process is terminating,
		 * remaining VESHMs may be moved to veshm_remains_list.
		 * search_all_owned_veshm_uuid() will return NULL, so
		 * search again later. */
		entry = search_all_owned_veshm_uuid(req_uuid_veshm,
						    ived_resource);
	}

	/* Search again */
	if (entry == NULL){
		if ( ived_resource != NULL && request_close->vemva == 0){
			/* Request from IB and a target process is terminating.
			 * ived_resource is existing in ived_task_list, but
			 * VESHM data are moved to veshm_remains_list.
			 * Set NULL to ived_resource for 
			 * delete_owned_veshm_info */
			pthread_rwlock_unlock
				(&ived_resource->ived_resource_lock);
			ived_resource = NULL;
		}

		/* Lock for terminated processes list */
		pthread_mutex_lock(&veshm_remains_lock);

		IVED_DEBUG(log4cat_veos_ived, "Search by uuid.");
		/* From IB, a target process dead. */
		entry = search_all_owned_veshm_uuid(req_uuid_veshm, NULL);
		if (entry == NULL){
			IVED_DEBUG(log4cat_veos_ived, "VESHM is not found");
			reply->error  = -EINVAL;
			goto err_ret_unlock_remains;
		}

		pthread_mutex_unlock(&veshm_remains_lock);
	}

	dump_own_veshm(entry);

	ret = veos_veshm_close_ipc(entry, request_close, reply);
	if (ret < 0){
		if (ret == IVED_RPC_ERR_RECV){
			IVED_WARN(log4cat_veos_ived, 
				  "Receiving a result in IVED daemon failed.");
			IVED_WARN(log4cat_veos_ived, 
				  "It may cause memory leaking of VEOS.");

		} else if (reply->error == -ENOLINK){
			IVED_WARN(log4cat_veos_ived, 
				  "VEOS didn't communicate with IVED. ");
			IVED_WARN(log4cat_veos_ived, 
				  "A memory used for specified VESHM is not released.");
		}
		goto err_ret;
	} 

	if (reply->retval == 0){
		/* = sum of registration counters */

		reply->error  = 0;

		if (reply->veshm_ret->counts == 0
		    && isset_flag(entry->status_flag, VE_REGISTER_PCI)){
			/* No one references this VESHM */

			IVED_DEBUG(log4cat_veos_ived, "Release PCI address");
			veos_sync_r_bar01_bar3();

			for (i=0; i < entry->pciatb_entries-1 ; i++){
				ret = veos_delete_pciatb
					(entry->pciatb_slot[i], 
					 pciatb_pagesize);
				if (ret != 0){
					IVED_ERROR(log4cat_veos_ived, 
						   "Releasing PCI adress failed. (slot:%d)",
						   entry->pciatb_slot[i]);
				}
			}
			veos_sync_r_bar2();

			free(entry->pciatb_slot);
		}

		/* Even if reference count is larger than  0,
		 * delete owned_veshm_info. */
		if (ived_resource != NULL){
			/* Process is still alive (terminating or running) 
			 * (MPI or IB request) */
			delete_owned_veshm_info
				(&ived_resource->owned_veshm_list,
				 &ived_resource->owned_veshm_num,
				 entry);
		} else {
			/* Process is not running or terminating (IB) */
			pthread_mutex_lock(&veshm_remains_lock);
			delete_owned_veshm_info(&veshm_remains_list, 
						NULL, entry);
			pthread_mutex_unlock(&veshm_remains_lock);
		}
	}

	if (ived_resource != NULL && terminating_tsk == NULL){
		/* if terminating_tsk is valid, this function
		 * needs not to unlock ived_resource_lock */
		ret = pthread_rwlock_unlock(&ived_resource->ived_resource_lock);
		assert(ret == 0);
	}

	if (tsk != NULL && terminating_tsk == NULL)
		put_ve_task_struct(tsk);


	IVED_DEBUG(log4cat_veos_ived, "VESHM close: Sum of references = %d", 
		   (int)reply->retval);
	return(IVED_REQ_OK); 

err_ret_unlock_remains:
	pthread_mutex_unlock(&veshm_remains_lock);

err_ret:
	if (ived_resource != NULL && terminating_tsk == NULL){
		pthread_rwlock_unlock
			(&ived_resource->ived_resource_lock);
	}


err_ret_nolock:
	if (tsk != NULL && terminating_tsk == NULL)
		put_ve_task_struct(tsk);

	IVED_DEBUG(log4cat_veos_ived, "VESHM close request failed");
	return (IVED_REQ_NG);

}

/**
 * @brief Erase VESHM area by IVED IPC request
 *
 * request_detach is the same as VESHM detach request.
 * An owner process of the target VESHM had terminated.
 *
 * @param [in]    request_detach Arguments of VESHM erasing 
 *
 * @return 0 on succes, Not 0 and set errno on failure
 */
int
veos_veshm_erase_area(size_t n_pci_address, uint64_t *pci_address)
{
	int i;
	int ret = 0;
	int64_t bar01_addr = -1;
	int pciatb_pg_shift = -1;
	int64_t pciatb_pagesize = -1;
	int64_t pciatb_slot = -1;

	if (pci_address == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret;
	}

	if (current_node == NULL){
		IVED_CRIT(log4cat_veos_ived, "Current node data is invalid.");
		goto err_ret;
	}
	pciatb_pagesize = (int64_t)ived_pci_pgsize_flag2byte
		(current_node->pciattr);
	pciatb_pg_shift = (current_node->pciattr == PGMODE_FLAG_64M) ?
		SHFT_64M : SHFT_2M;
	bar01_addr = current_node->pci_bar01_vhsaa;
	assert(bar01_addr != -1);

	veos_sync_r_bar01_bar3();
	for (i=0; i < n_pci_address-1 ; i++){
		/* The last value of pci_address[] is -1. */

		pciatb_slot = ((int64_t)pci_address[i] - bar01_addr)
			>> pciatb_pg_shift;

		ret = veos_delete_pciatb(pciatb_slot, pciatb_pagesize);
		if (ret != 0){
			IVED_ERROR(log4cat_veos_ived, 
				   "Releasing PCI adress failed. (slot:%lld)",
				   (long long)pciatb_slot);
		}

		IVED_DEBUG(log4cat_veos_ived, "shift:%x slot:%lld",
			   pciatb_pg_shift, (long long)pciatb_slot);
	}
	veos_sync_r_bar2();

	IVED_DEBUG(log4cat_veos_ived, "Erasing VESHM succeeded.");
	return(IVED_REQ_OK); 

err_ret:
	IVED_DEBUG(log4cat_veos_ived, "Erasing VESHM failed.");
	return (ERR_RET);

}
