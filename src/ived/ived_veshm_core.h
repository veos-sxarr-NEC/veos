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
 * @file ived_veshm_core.h  
 * @brief  Header file for VESHM manager
 *
 * @internal
 * @author VESHM
 */

#ifndef _IVED_VESHM_CORE_H
#define _IVED_VESHM_CORE_H

/*
 * Macro
 */


/*
 * Data structures
 */


/** 
 * @brief This structure holds data of VESHM memory 
 * It is protected by veshm_lock in this structure.
 *
 * This data must be deleted in accordance with the following rule.
 * 1-1. Get veshm_lock 
 * 1-2. Check condition
 *      If VESHM isn't used by any VESHM user processes, IVED can
 *      erase the VESHM.
 * 1-3  Get proc_lock of owner process.
 * 1-4. Unlink veshm_info_tracker (having_veshm_info) from owner process.
 * 1-5. Free the veshm_info_tracker
 *      (Store an address of veshm_memory_info before erasing)
 * 1-6. Free veshm_memory_info.
 *
 * If some VESHM user processes are attating, VESHM is erased when 
 * all processes detach it. 
 * 2-1. Get proc_lock of user process
 * 2-2. Unlink veshm_info_tracker (attaching_veshm_info)
 * 2-3. Unlink ived_resource_user and free the tracker via veshm_info
 * 2-4. Free attaching_veshm_info
 * 2-5. Get veshm_lock 
 * 2-6. Check condition
 *      If VESHM isn't used by any VESHM user processes, IVED can
 *      erase the VESHM.
 *      See 1-*
 */
/*
 * veshm_lock is a new approach. 
 */
struct veshm_memory_info{
	struct list_head list;
	struct list_head erase_list;	/*!< Used for VESHM batch erase */
	pthread_mutex_t veshm_lock;	/*!< lock for veshm_memory_info */
	uuid_t	uuid_veshm;		/*!< UUID of VESHM */
	uid_t	uid_of_owner;		/*!< Uid of an owner */
	pid_t   pid_of_owner;		/*!< Pid of an owner process */
	uuid_t	uuid_owner_proc;	/*!< UUID of an owner process */
	uint64_t  start_vemva;		/*!< VEMVA of an owner process */
	uint64_t size;			/*!< Size of VESHM area */
	int	pcisync_num;		/*!< PCISYAR/MR pair num */
	uint64_t mode_flag;		/*!< Mode flag of VESHM */
	uint64_t *pci_address;		/*!< Array of attached pci address*/
	size_t  n_pci_address;		/*!< # of pci_address entries */
	int	register_cnt_proc;	/*!< Registration counter for process
					  (number of open requests from proc)*/
	int	register_cnt_dev;	/*!< Registration counter for IB 
					  (number of open requests from IB) */
	int	reference_cnt;		/*!< Reference counter (# of process)*/
	struct list_head attach_proc_list;
	struct	veos_info *os_info;	/*!< OS corresponding to VESHM */
};

/** 
 * @brief This structure holds a pointer for VESHM memory info.
 * It is protected by owner process's proc_lock.
 * When a process attaches a VESHM on ATB or DMAATB, the data is created.
 * When a process detaches a VESHM completely, the data is erased.
 */
struct veshm_info_tracker{
	struct list_head list;
	struct veshm_memory_info *veshm_info;
};



#endif
