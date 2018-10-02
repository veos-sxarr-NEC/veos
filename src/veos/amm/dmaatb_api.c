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
 * @file dmaatb_api.c
 * @brief DMAATB realated function which manages the DMAATB
 */
#include <sys/mman.h>
#include "ve_shm.h"
#include "ve_mem.h"
#include "mm_common.h"
#include "ve_memory.h"
#include "veos.h"
#include "libved.h"
#include "dma.h"
#include "dmaatb_api.h"
#include "ve_hw.h"
#include "vehva_mgmt.h"

/**
 * @brief This function will allocate DMAAATB entry for system call area.
 *
 * @param[in] requester PID of the requesting process.
 * @param[in] vehva System call argument region virtual address of process.
 *            represented by ‘pid’.
 * @param[in] vhsaa VHSAA corresponding to VEHVA. It is not required to
 *            convert VEHVA to VHSAA.
 *
 * @return on success returns start address of VEHVA and negative of errno is
 *         returned on failure.
 */
int64_t veos_alloc_dmaatb_entry_for_syscall(struct ve_task_struct *tsk,
		vehva_t vehva, vhsaa_t vhsaa)
{
	vhsaa_t syscall_vhsaa[2] =  {0, 0};
	int64_t ret = -1;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with syscall VHSAA :%lx for tsk(%p):pid: %d",
			syscall_vhsaa[0], tsk, tsk->pid);

	syscall_vhsaa[0] = vhsaa;

	/*For syscall Area*/
	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk,
			syscall_vhsaa,
			PROT_READ|PROT_WRITE,
			VE_ADDR_VHSAA, VEHVA_SYSCALL|VEHVA_4K,
			false);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while allocating syscall DMAATB for"
				" tsk:pid:%d",
			strerror(-ret), tsk->pid);
		return ret;
	}
	VEOS_DEBUG("tsk(%p):pid(%d): system call dmaatb dir:%ld",
		tsk, tsk->pid, ret);
	/*
	 * Allocating DMAATB for System common register.
	 */
	veraa_t veraa_paddr[3] =  {0};
	veraa_paddr[0] = SYSCOM_ADD + SYSSTM_OFFSET;
	veraa_paddr[1] = SYSCOM_ADD + SYSCRPM_OFFSET;

	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk,
			veraa_paddr,
			PROT_READ,
			VE_ADDR_VERAA, VEHVA_SYSCOM_REG|VEHVA_4K,
			false);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while allocating SCOM DMAATB for tsk:pid:%d",
			strerror(-ret), tsk->pid);
		return ret;
	}

	VEOS_DEBUG("returned with %ld", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief The function will allocate DMAATB entry using VEMVA of process.
 *
 * @param[in] requester PID of the requesting process.
 * @param[in] owner PID of the process which owns the VEMVA specified.
 * @param[in] vemva VEMVA address of the owner process.
 * @param[in] size Size of VEMVA region for which DMAATB entries needs
 *            to be allocated.
 * @param[in] permission Access permission (PROT_READ, PROT_WRITE)
 *            to requesting process DMAATB.
 * @param[in] access Whether it is required to verify requestor permission
 *            flags match with owner or not.
 *
 * @return on success returns start address of VEHVA and negative of errno is
 *            returned on failure.
 */
int64_t veos_alloc_dmaatb_entry_for_vemva(pid_t requester, pid_t owner,
		vemva_t vemva_addr, size_t size, int permission,
		bool access_ok)
{
	struct ve_task_struct *req_tsk = NULL;
	struct ve_task_struct *own_tsk = NULL;
	uint64_t pgsz = 0;
	int64_t ret = -1;
	vemva_t vaddr = 0, *map = NULL;
	vehva_t vehva = 0;
	vemaa_t vemaa = 0;
	uint16_t flags = 0;
	int prot = 0;
	atb_reg_t tmp_atb = { { { {0} } } };
	int pgmod = -1, tpgmod = 0, count = 0, i = 0;
	ssize_t tsize  = 0;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with requestor:%d, owner =%d, vemva_addr=%ld"
			"size = %ld, permission = %d, access = %d",
			requester, owner, vemva_addr, size, permission,
			access_ok);

	/* check if valid size is received or not */
	if (size <= 0) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s)", strerror(-ret));
		goto err_handle;
	}

	req_tsk = find_ve_task_struct(requester);
	if (NULL == req_tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-ret), requester);
		goto err_handle;
	}

	own_tsk = find_ve_task_struct(owner);
	if (NULL == own_tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-ret), owner);
		goto err_handle;
	}

	/* Check if permission is PROT_NONE or not */
	if (!((permission & PROT_READ) || (permission & PROT_WRITE))) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) for permission", strerror(-ret));
		goto err_handle;
	}

	pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	memcpy(&tmp_atb, &own_tsk->p_ve_mm->atb, sizeof(atb_reg_t));

	tsize = size;
	vaddr = vemva_addr;

	/* Get page number from VEMVA and increase reference count of the
	 * page */
	while (tsize > 0) {
		vemaa = __veos_virt_to_phy(vaddr,
				&tmp_atb, &prot, &tpgmod);
		if (0 > vemaa) {
			ret = -EFAULT;
			VEOS_DEBUG("Error (%s) for vemva 0x%lxi of pid %d"
					, strerror(-ret), vaddr, owner);
			ret = -EFAULT;
			pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
			goto malloc_err;
		}

		if (((pgmod == -1) || (pgmod == tpgmod)))
			pgmod = tpgmod;
		else{
			ret = -EINVAL;
			pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
			goto malloc_err;
		}

		VEOS_DEBUG("vemaa = 0x%lx", vemaa);
		if (!(prot & permission) && (access_ok)) {
			ret = -EACCES;
			VEOS_DEBUG("Error (%s) for process %d",
					strerror(-ret), owner);
			pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->
					thread_group_mm_lock, UNLOCK,
					"Failed to release thread-group-mm-lock");
			goto malloc_err;
		}
		pgsz = (uint64_t)pgmod_to_pgsz(pgmod);

		if (NULL == map) {
			count = size/pgsz;
			map = calloc(count + 1, sizeof(uint64_t));
			if (NULL == map) {
				ret = -errno;
				VEOS_CRIT("Error (%s) in allocating hold vemva map info",
						strerror(-ret));
				pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->
						thread_group_mm_lock, UNLOCK,
						"Failed to release thread-group-mm-lock");
				goto malloc_err;
			}
		}
		map[i++] = vemaa;
		tsize -= pgsz;
		vaddr += pgsz;
	}

	amm_get_page(map);
	pthread_mutex_lock_unlock(&own_tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	flags |= VEHVA_VESHM | ((pgmod == PG_2M) ? VEHVA_2MB : VEHVA_64MB);

	pthread_mutex_lock_unlock(&req_tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	vehva = veos_alloc_dmaatb_entry_for_aa_tsk(req_tsk, map, permission,
			VE_ADDR_VEMAA, flags, true);
	if (0 > vehva) {
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-vehva), requester);
		pthread_mutex_lock_unlock(&req_tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		for (i = 0; map[i]; i++)
			amm_put_page(map[i]);
		goto malloc_err;
	}

	pthread_mutex_lock_unlock(&req_tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	amm_dump_dmaatb(req_tsk, 1);

#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from *_for_vemva");
	amm_dump_dmaatb(tsk, 1);
#endif
	ret = vehva;

malloc_err:
	if (map)
		free(map);
err_handle:
	if (req_tsk)
		put_ve_task_struct(req_tsk);
	if (own_tsk)
		put_ve_task_struct(own_tsk);
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief  This function will allocate DMATB entry for requests that include
 *         VHSAA of VESHM and CR.
 *
 * @param[in] requester PID of VE process
 * @param[in] arr Array of VE_ADDR_VERAA, VE_ADDR_VECRAA and VE_ADDR_VHSAA.
 * @param[in] permission Access permission (PROT_READ, PROT_WRITE) to
 *            requesting process DMAATB.
 * @param[in] addr_type Type of address to allocate DMA entry.
 * @param[in] vehva_type Type of vehva address.
 *
 * @return on success returns start address of VEHVA and negative of errno is
 *         returned on failure.
 */
int64_t veos_alloc_dmaatb_entry_for_aa(pid_t requester, uint64_t *addr,
		int permission, int addr_flag, uint64_t vehva_flag)
{
	struct ve_task_struct *tsk = NULL;
	int64_t ret = 0;

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid %d permission = %d add_type %d vehva_flag"
			"0x%lx", requester, permission, addr_flag, vehva_flag);

	tsk = find_ve_task_struct(requester);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-ret), requester);
		goto err_handle;
	}

	amm_dump_dmaatb(tsk, 1);

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, (vehva_t *)addr, permission,
			addr_flag, vehva_flag, true);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-ret), requester);
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK,
				"Failed to release thread-group-mm-lock");
		goto err_handle;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	amm_dump_dmaatb(tsk, 1);
err_handle:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief  This function will allocate DAATB entry for requests that include
 *         VHSAA of VESHM and CR.
 *
 * @param[in] tsk Pointer to VE process task structure
 * @param[in] arr Array of VE_ADDR_VERAA, VE_ADDR_VECRAA and VE_ADDR_VHSAA.
 * @param[in] permission Access permission (PROT_READ, PROT_WRITE) to
 *            requesting process DMAATB.
 * @param[in] addr_type Type of address to allocate DMA entry.
 * @param[in] vehva_type Type of vehva address.
 * @param[in] halt_all Halt other task or not
 *
 * @return on success returns start address of VEHVA and negative of errno is
 *         returned on failure.
 */
int64_t veos_alloc_dmaatb_entry_for_aa_tsk(struct ve_task_struct *tsk,
		vhsaa_t *addr, int permission, int addr_flag,
		uint64_t vehva_flag, bool halt_all)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	ssize_t i = 0, ret = -1;
	vehva_t vehva = 0;
	size_t pgsize = 0;
	int pgmod = 0;
	size_t size = 0;
	dir_t prv_dir = -1;
	dir_t dir_num = -1;
	dir_t dirs[DMAATB_DIR_NUM] = {0};
	int prot = 0, cnt = 0;
	dmaatb_reg_t tsk_cp = { { { {0} } } } ,node_cp = { { { {0} } } };

	memset(dirs, -1, sizeof(dirs));

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid = %d, permission = %d, addr_flag = %d"
			"vehva_flag = %ld halt_all = %d",
			tsk->pid, permission, addr_flag, vehva_flag, halt_all);


	VEOS_DEBUG("Start Dump Array of ABS addresses");

	for (i = 0; addr[i]; i++)
		VEOS_DEBUG("addr[%ld]:%lx", i, addr[i]);

	VEOS_DEBUG("End Dump Array of ABS addresses");

	pgsize = (size_t)((vehva_flag & VEHVA_4K) ? PAGE_SIZE_4KB :
		(vehva_flag & VEHVA_2MB) ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB);
	pgmod = (vehva_flag & VEHVA_4K) ? PG_4K :
		(vehva_flag & VEHVA_2MB) ? PG_2M :
		PG_HP;

	VEOS_DEBUG("pgsize %ld  pgmod %d", pgsize, pgmod);
	for (i = 0; addr[i]; i++)
		size += pgsize;

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	ret = veos_vehva_alloc(vehva_flag, size, tsk);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while allocating VEHVA for pid %ld",
				strerror(-ret), ret);
		goto err_handle;
	}

	vehva = (vehva_t)ret;
	memset(&tsk_cp, 0 , sizeof(dmaatb_reg_t));
	memset(&node_cp, 0 , sizeof(dmaatb_reg_t));
	/* Here we save the content of node_dmaatb and task_dmaatb.
	 * so in case of failure we can do proper cleanup.
	 */
	memcpy(&tsk_cp, &tsk->p_ve_mm->dmaatb, sizeof(dmaatb_reg_t));
	memcpy(&node_cp, &vnode->dmaatb, sizeof(dmaatb_reg_t));

	prot = (permission & PROT_WRITE) ? 1 : 0;

	/* Allocate DMAATB entry for the absolute address */
	for (i = 0; addr[i]; i++) {
		dir_num = validate_vehva(vehva+(i*pgsize), prot,
				pfnum(addr[i], pgmod),
				&tsk->p_ve_mm->dmaatb,
				pgmod, addr_flag, tsk->jid, vehva_flag);
		if (0 > dir_num) {
				ret = -ENOMEM;
			VEOS_DEBUG("Error (%s) while setting vehva 0x%lx",
					strerror(-ret), vehva);
			goto clean_up;
		}

		if (prv_dir == -1 || (prv_dir != dir_num)) {
			if (DMAATB_DIR_NUM == dir_num)
				continue;
			dirs[cnt++] = dir_num;
			prv_dir = dir_num;
		}
	}

	i = 0;
	while (0 <= dirs[i]) {
		/* Syncing DMAATB with h/w */
		dir_num = dirs[i++];
		if (DMAATB_DIR_NUM == dir_num)
			continue;
		psm_sync_hw_regs(tsk, _DMAATB, &(vnode->dmaatb),
				halt_all,
				dir_num, 1);
	}

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");

	ret = vehva;
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");
#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from *_for_aa");
	amm_dump_dmaatb(tsk, 0);
#endif
	return ret;
clean_up:
	memcpy(&tsk->p_ve_mm->dmaatb, &tsk_cp, sizeof(dmaatb_reg_t));
	memcpy(&vnode->dmaatb, &node_cp, sizeof(dmaatb_reg_t));
	if(0 > veos_vehva_free(vehva, size, tsk)) {
		VEOS_DEBUG("Error (%s) while freeing vehva",
				strerror(-ret));
	}

err_handle:
	VEOS_DEBUG("returned with 0x%lx", ret);
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return ret;
}

/**
 * @brief This function free the DMAATB entry reserved for system call
 *         region of VE process  or thread.
 *
 * @param[in] p_mm_struct Pointer to mm_struct of process.
 *
 * @return Will return 0 on success and negative of errno on failure.
 */
int veos_scheduleout_dmaatb(struct ve_task_struct *tsk)
{
	int64_t ret = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid = %d", tsk->pid);
	amm_dump_dmaatb(tsk, true);

	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	ret = veos_release_dmaatb_entry(tsk);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while realeasing the dmaatb directiory",
				strerror(-ret));
		goto err_handle;
	}

	psm_sync_hw_regs(tsk, _DMAATB, &(vnode->dmaatb), false, ret, 1);
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	amm_dump_dmaatb(tsk, true);
	VEOS_DEBUG("returned with %ld", ret);
	VEOS_TRACE("returned");
	return 0;
err_handle:
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	VEOS_DEBUG("returned with %ld", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief This function free the DMAATB entry reserved for system call
 *        region of VE process  or thread.
 *
 * @param[in] p_mm_struct Pointer to mm_struct of process.
 *
 * @return Will return 0 on success and negative of errno on failure.
 */
int veos_schedulein_dmaatb(struct ve_task_struct *tsk)
{
	int64_t ret = 0, dir_num  = 0;
	vehva_t vehva = 0;
	vhsaa_t vhsaa_addr = 0;
	struct ve_mm_struct *ve_mm = NULL;
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid = %d", tsk->pid);

	ve_mm = tsk->p_ve_mm;
	vehva = ve_mm->shm_lhm_addr;
	vhsaa_addr = ve_mm->shm_lhm_addr_vhsaa;
	amm_dump_dmaatb(tsk, true);
	if (!vhsaa_addr) {
		VEOS_DEBUG("No VHSAA for SYSCALL region need to"
				" initialize");
		ret = vedl_get_dma_address(handle, (void *)vehva,
				tsk->pid, 1, 0, 0);
		if (0 > ret) {
			VEOS_DEBUG("VHVA->VHSAA conversion failed for "
					"vaddr = %p for task :%d",
					(void *)vehva, tsk->pid);
			return ret;
		}
		vhsaa_addr = ret;
		VEOS_DEBUG("Physical address: %lx", vhsaa_addr);
		tsk->p_ve_mm->shm_lhm_addr_vhsaa = vhsaa_addr;
	}
	if (!ps_isvalid(&tsk->p_ve_mm->dmaatb.dir[0])) {
		VEOS_DEBUG("first time schedule in");
		ret = veos_alloc_dmaatb_entry_for_syscall(tsk,
				vehva, vhsaa_addr);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while set dmaatb for sys",
					strerror(-ret));
			return ret;
		}
	} else {
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
				"Failed to acquire node dmaatb lock");
		dir_num = sync_node_dmaatb_dir(tsk->p_ve_mm->shm_lhm_vehva,
				tsk->p_ve_mm, 0, tsk->jid);
		if (0 > dir_num) {
			VEOS_DEBUG("Error (%s) while acquiring dma directory",
					strerror(-ret));
			ret = dir_num;
			goto hndl_err;
		}

		VEOS_DEBUG("current_dir = %lx", dir_num);
		psm_sync_hw_regs(tsk, _DMAATB, &(vnode->dmaatb),
				false, dir_num, 1);
		pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
				"Failed to release node dmaatb lock");
	}
	ret = 0;
	amm_dump_dmaatb(tsk, true);
	VEOS_DEBUG("returned with %lx", ret);
	VEOS_TRACE("returned");
	return ret;
hndl_err:
	VEOS_DEBUG("returned with %lx", ret);
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return ret;
}
/**
 * @brief Free VEHVA region update the DMAATB entries register.
 *
 * @param[in] requester PID of the requesting process
 * @param[in] vehva VEHVA start address.
 * @param[in] size Size of VEHVA needs to de-allocate
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t veos_free_dmaatb_entry(pid_t pid, vehva_t vehva, size_t size)
{
	struct ve_task_struct *tsk = NULL;
	int64_t ret = 0;

	VEOS_TRACE("Invoked");
	VEOS_TRACE("Invoked with pid:%d vehva = %ld size = %ld",
			pid, vehva, size);

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-ret), pid);
		goto err;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	ret = veos_free_dmaatb_entry_tsk(tsk, vehva, size);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while freeing the dmaatb",
				strerror(-ret));
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK,	"Failed to release thread-group-mm-lock");
		goto err;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
err:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_DEBUG("returned with %ld", ret);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief Free VEHVA region update the DMAATB entries register.
 *
 * @param[in] req_tsk Pointer to VE task structure.
 * @param[in] vehva VEHVA start address.
 * @param[in] size Size of VEHVA needs to de-allocate.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int64_t veos_free_dmaatb_entry_tsk(struct ve_task_struct *req_tsk,
		vehva_t vehva, size_t size)
{
	int64_t ret = -1;
	int8_t dir_num = -1;
	int8_t prv_dir = -1;
	int8_t dirs[DMAATB_DIR_NUM] = {-1};
	vehva_t tmp_vehva = 0;
	uint64_t pgsz = 0;
	uint64_t count = 0;
	int pgmod = 0, i = 0, noc = 0, start = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");
	VEOS_DEBUG("Invoked with pid:%d vehva:%ld size:%ld",
			req_tsk->pid, vehva, size);

	memset(dirs, -1, sizeof(dirs));
	noc = vnode->nr_avail_cores;
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	amm_dump_dmaatb(req_tsk, true);
	/*
	 * Use veos_get_pgmod instead of returning pgmod from veos_vehva_free*/
	pgmod = veos_vehva_free(vehva, size, req_tsk);
	if (0 > pgmod) {
		ret = pgmod;
		VEOS_DEBUG("Error (%s) while freeing vehva",
				strerror(-ret));
		goto err_handle;
	}

	pgsz = (uint64_t)((pgmod == PG_4K) ? PAGE_SIZE_4KB :
		(pgmod == PG_2M) ? PAGE_SIZE_2MB :
		PAGE_SIZE_64MB);

	count = size/pgsz;
	tmp_vehva = vehva;

	for (i = 0; i < count; i++) {
		dir_num = invalidate_vehva(tmp_vehva + (i*pgsz),
				&req_tsk->p_ve_mm->dmaatb,
				req_tsk->jid);
		if (0 > dir_num) {
			ret = -EFAULT;
			VEOS_DEBUG("Error (%s) while unsetting dmaatb",
					strerror(-ret));
			goto err_handle;
		}
		/* Check for node DMAATB for jid & VEHVA  with false
		 * if dir is -1 then do nothing and if any directory
		 * then invalidate correspodning entry
		 * */
		if (prv_dir == -1 || (prv_dir != dir_num))
			dirs[start++] = dir_num;

		prv_dir = dir_num;
	}
	i = 0;

	while (0 <= dirs[i]) {
		if ((dirs[i] >= noc) || (req_tsk->p_ve_mm->is_sched == true)) {
			psm_sync_hw_regs(req_tsk, _DMAATB, &(vnode->dmaatb),
					true, dirs[i++], 1);
		} else
			i++;
	}
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	amm_dump_dmaatb(req_tsk, true);
#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from free_dmaatb_entry");
	amm_dump_dmaatb(NULL, 0);
#endif

	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	return 0;
err_handle:
	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return ret;
}

/**
 * @brief free the dmaatb of specified process.
 *
 * @param[in] dmaatb pointer to DMAATB structure.
 */
void veos_free_dmaatb(dmaatb_reg_t *dmaatb)
{
	int i = 0, ret = 0, entry = 0, core_num = 0;
	pgno_t pb = 0;
	int pg_type = 0, pgmod = 0;;
	vemaa_t vemaa = 0;
	system_common_reg_t *cnt_regs_addr = VE_CORE_CNT_REG_ADDR(0);
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");

	core_num = vnode->nr_avail_cores;
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");

	for (i = core_num; i < DMAATB_DIR_NUM; i++) {
		if (ps_isvalid(&dmaatb->dir[i])) {
			VEOS_DEBUG("%d : Partial Space Offset %p",
					i, (void *)dmaatb->dir[i].data);
			pgmod = ps_getpgsz(&dmaatb->dir[i]);
			ps_invalid(&dmaatb->dir[i]);
			ps_clrdir(&vnode->dmaatb.dir[i]);
			ps_invalid(&vnode->dmaatb.dir[i]);
			for (entry = 0; entry <
					DMAATB_ENTRY_MAX_SIZE; entry++) {

				if (pg_isvalid(&(dmaatb->entry[i][entry]))) {
					pg_type = pg_gettype(&(dmaatb->entry[i][entry]));
					if (pg_type == VE_ADDR_VEMAA) {
						VEOS_TRACE("Dec pages ref count");
						pb = pg_getpb(&(dmaatb->entry[i][entry]), pgmod);
						vemaa = pbaddr(pb, pgmod);
						VEOS_DEBUG("vemaa = 0x%lx", vemaa);
						amm_put_page(vemaa);
					}
				}

				pg_invalid(&(dmaatb->entry[i][entry]));
				pg_invalid(&(vnode->dmaatb.entry[i][entry]));
				pg_unsetprot(&(dmaatb->entry[i][entry]));
				pg_unsetprot(&(vnode->dmaatb.entry[i][entry]));
				pg_unsettype(&(dmaatb->entry[i][entry]));
				pg_unsettype(&(vnode->dmaatb.entry[i][entry]));
				pg_clearpfn(&(dmaatb->entry[i][entry]));
				pg_clearpfn(&(vnode->dmaatb.entry[i][entry]));
			}
			hw_dma_map[i].count = 0;
		} else  {
			VEOS_TRACE("DIR: %d is invalid.", i);
			continue;
		}
		ret = vedl_update_dmaatb_dir(handle, cnt_regs_addr,
				&(vnode->dmaatb), i);
		if (0 > ret) {
			VEOS_DEBUG("vedl_update_dmaatb_dir Failed");
			veos_abort("failed to sync dmaatb");
			goto error;
		}
	}

#if DEBUG
	VEOS_DEBUG("Dumping DMAATB from veos_free_dmaatb");
	amm_dump_dmaatb(NULL, 0);
#endif
	VEOS_TRACE("returned");
error:
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	return;
}

/**
 * @brief This function translates Physical address to VEHVA.
 *
 * @param[in] pid process descriptor of VE process.
 * @param[in] addr Address to translate.
 * @param[in] type Type of Physical address.
 *
 * @return returnes VEHVA on success and negative of errno on error.
 */
int64_t veos_aa_to_vehva(pid_t pid, vemaa_t addr, int type)
{
	struct ve_task_struct *tsk = NULL;
	struct ve_mm_struct *ve_mm = NULL;
	dmaatb_reg_t dmaatb = { { { {0} } } };
	atb_dir_t *atbp = NULL;
	uint64_t pgsz = 0;
	uint64_t pgmask = 0;
	uint64_t data = 0;
	vehva_t vehva = 0;
	uint64_t psnum_dir = 0;
	int ps_entry = 0;
	int pg_entry = 0;
	int64_t ret = -1;
	uint8_t pgmode_dir = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");

	VEOS_DEBUG("Invoked with pid:%d, addr:%ld type:%d",
			pid, addr, type);

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("Failed to fetch the task struct of PID :%d",
				pid);
		ret = -ESRCH;
		goto err;
	}

	ve_mm = tsk->p_ve_mm;
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, LOCK,
			"Failed to acquire node dmaatb lock");
	memcpy(&dmaatb, &ve_mm->dmaatb, sizeof(dmaatb_reg_t));

	atbp = dmaatb.dir;

	for (ps_entry = 0; ps_entry < DMAATB_DIR_NUM; ps_entry++) {
		/* Is atbp valid? */
		if (ps_isvalid(atbp)) {

			/* pgmode check */
			pgmode_dir = ps_getpgsz(atbp);

			pgsz = (uint64_t)((pgmode_dir == PG_2M) ? PAGE_SIZE_2MB :
				(pgmode_dir == PG_4K) ? PAGE_SIZE_4KB :
				PAGE_SIZE_64MB);

			pgmask = ~(uint64_t)(pgsz - 1);

			for (pg_entry = 0; pg_entry <
					DMAATB_ENTRY_MAX_SIZE; pg_entry++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(dmaatb.entry[ps_entry][pg_entry]))) {
					data = dmaatb.entry[ps_entry]
						[pg_entry].data;
					VEOS_DEBUG("%d : %d :PB"
							" Address %p",
							ps_entry, pg_entry,
							(void *)data);
					if ((data & pgmask) == addr) {
						if (type != ((data >> type_shft)
									& PG_TYP_MSK))
							continue;
						psnum_dir = ps_getps(atbp,
								pgmode_dir);
						goto done;
					}
				}
			}
		}
		atbp++;
	}

	VEOS_DEBUG("veos_aa_to_vehva fails");

	if (tsk)
		put_ve_task_struct(tsk);
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	ret = -EFAULT;
	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	return ret;
done:
	vehva = psnum_dir + (pg_entry*pgsz);
	pthread_mutex_lock_unlock(&vnode->dmaatb_node_lock, UNLOCK,
			"Failed to release node dmaatb lock");
	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");

	if (tsk)
		put_ve_task_struct(tsk);
	return vehva;
err:
	VEOS_DEBUG("returned with:%ld", ret);
	VEOS_TRACE("returned");
	return ret;
}
/**
 * @brief This function updates DMAATB registers of the VE core in which VE
 *	task is going to execute, DMA ATB registers are updated using VE
 *	driver API.
 *
 * @param[in] p_ve_task Pointer to task struct.
 * @param[in] core_num logical core number on which process is going to schedule.
 *
 * @return On success returns 0 and negative of errno is returned on failure.
 */
int64_t veos_update_dmaatb_context(struct ve_task_struct *tsk, int core_num)
{
	int64_t ret = 0, err_ret = 0;
	int phys_core = 0;
	struct ve_core_struct *p_ve_core = NULL;
	veraa_t paddr[2] =  {0, 0};

	VEOS_TRACE("Invoked");

	if (!tsk || (-1 == core_num))
		return -1;

	amm_dump_dmaatb(tsk, true);
	p_ve_core = VE_CORE(0, core_num);
	phys_core = p_ve_core->phys_core_num;
	VEOS_DEBUG("update_dmaatb_context for pid %d on"
			" logical core %d physical core: %d",
			tsk->pid, core_num, phys_core);

	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMACTL_OFF;

	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk,
			paddr,
			PROT_READ,
			VE_ADDR_VERAA,
			VEHVA_DMA_CNT_REG|VEHVA_4K|VEHVA_MAP_FIXED,
			false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		return ret;
	}
	amm_dump_dmaatb(tsk, true);
	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMADESC_E_OFF;

	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE,
			VE_ADDR_VERAA,
			VEHVA_DMA_DESC_E_REG|VEHVA_4K|VEHVA_MAP_FIXED,
			false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		err_ret = ret;
		goto hndl_err;
	}
	amm_dump_dmaatb(tsk, true);

	/* If DMA Descriptor table H is enabled then allocate dmaatb
	 * entry.
	 */
	if (!(tsk->p_ve_mm->udma_desc_bmap & DMA_DESC_H))
		goto done;

	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMADESC_H_OFF;

	ret = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE,
			VE_ADDR_VERAA,
			VEHVA_DMA_DESC_H_REG|VEHVA_4K|VEHVA_MAP_FIXED,
			false);
	if (0 > ret) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		err_ret = ret;
		goto hndl_err1;
	}
	amm_dump_dmaatb(tsk, true);

done:
	VEOS_DEBUG("updated dmaatb_context for pid %d on"
			" logical core %d physical core %d",
			tsk->pid, core_num, phys_core);
	ret = 0;
	VEOS_TRACE("returned");
	return ret;

hndl_err1:
	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMADESC_E_OFF;
	ret = veos_free_dmaatb_entry_tsk(tsk, paddr[0],
			VEHVA_4K);
	if (0 > ret)
		VEOS_DEBUG("veos_free_dmaatb_fail");
hndl_err:
	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMACTL_OFF;
	ret = veos_free_dmaatb_entry_tsk(tsk, paddr[0],
			VEHVA_4K);
	if (0 > ret)
		VEOS_DEBUG("veos_free_dmaatb_fail");

	VEOS_DEBUG("returned with 0x%lx", err_ret);
	VEOS_TRACE("returned");
	return err_ret;
}
/**
 * @brief Release DMAATB directorty.
 *
 * @param[in] tsk Pointer to task struct.
 *
 * @return On success returns directory number, negative of errno on error.
 */
int veos_release_dmaatb_entry(struct ve_task_struct *tsk)
{
	dir_t dir_num = 0;
	int ps_entry  = 0;
	dmaatb_reg_t *dmaatb = &tsk->p_ve_mm->dmaatb;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("Invoked");
	VEOS_TRACE("Invoked veos_release_dmaatb_entry for pid:%d",
			tsk->pid);

	dir_num = __get_pgd(tsk->p_ve_mm->shm_lhm_vehva, NULL,
			tsk->jid, false);
	if (0 > dir_num) {
		VEOS_DEBUG("DMAATB Directory not available"
				"for vehva");
		return -EFAULT;
	}

	ps_clrdir(&(vnode->dmaatb.dir[dir_num]));
	ps_invalid(&(vnode->dmaatb.dir[dir_num]));

	for (ps_entry = 0; ps_entry <
			ATB_ENTRY_MAX_SIZE; ps_entry++) {
		pg_unsetprot(&(vnode->dmaatb.entry[dir_num][ps_entry]));
		pg_unsettype(&(vnode->dmaatb.entry[dir_num][ps_entry]));
		pg_clearpfn(&(vnode->dmaatb.entry[dir_num][ps_entry]));
		pg_invalid(&(vnode->dmaatb.entry[dir_num][ps_entry]));
	}

	for (ps_entry = 3; ps_entry < 6; ps_entry++) {
		pg_unsetprot(&(dmaatb->entry[0][ps_entry]));
		pg_unsettype(&(dmaatb->entry[0][ps_entry]));
		pg_clearpfn(&(dmaatb->entry[0][ps_entry]));
		pg_invalid(&(dmaatb->entry[0][ps_entry]));
	}

	VEOS_TRACE("returned with 0x%x", dir_num);
	VEOS_TRACE("returned");
	return dir_num;
}


/**
* @brief This function will sync DMAATB directory from process
*	software copy to node software copy.
*
* @param[in] vehva virtual address for which DMAATB directory to be sync.
* @param[in] dmaatb page table(DMAATB).
* @param[in] dir_idx DMAATB directory number.
* @param[in] jid jid of VE process.
*
* @return on success returns page table(DMAATB) directory and negative of errno on failure.
*/
int sync_node_dmaatb_dir(vehva_t vehva, struct ve_mm_struct *mm, dir_t dir_idx, jid_t jid)
{
	atb_dir_t *pgd = NULL;
	atb_entry_t *pte = NULL;
	dir_t dir_num = 0;
	dmaatb_reg_t *dmaatb = &mm->dmaatb;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("Invoked");
	VEOS_DEBUG("vehva %lx dmaatb %p dir_idx %d jid %d",
			vehva, dmaatb, dir_idx, jid);

	if (PG_4K == ps_getpgsz(&dmaatb->dir[dir_idx])) {
		dir_num = __get_pgd(vehva, &vnode->dmaatb, jid, true);
		if (0 > dir_num && mm->is_sched) {
			dir_num = -EINVAL;
			VEOS_DEBUG("Error (%s) while getting directory for VEHVA %p",
					strerror(-dir_num), (void *)vehva);
			return dir_num;
		} else if (!mm->is_sched) {
			VEOS_DEBUG("process is scheduleout and \
					requested for syscall directiory entry");
			return DMAATB_DIR_NUM;
		}
	} else {
		dir_num = dir_idx;
	}

	ps_clrjid(&dmaatb->dir[dir_idx], jid);
	ps_setjid(&dmaatb->dir[dir_idx], jid);
	pgd = &vnode->dmaatb.dir[dir_num];
	pte = vnode->dmaatb.entry[dir_num];

	memcpy(&pgd->data, &dmaatb->dir[dir_idx].data, sizeof(uint64_t));
	memcpy(pte, dmaatb->entry[dir_idx],
			sizeof(uint64_t)*ATB_ENTRY_MAX_SIZE);

	return dir_num;
}

/**
 * @brief  This function will allocate the DMAATB entry for DMA Descriptor
 * table H for the given PID.
 *
 * @param[in] pid PID of VE process
 * @param[out] vehva_dmades VEHVA of DMA descriptor table H
 * @param[out] vehva_dmactl VEHVA of DMA control registor for H
 *
 * @return 0 on success, -errno on failure
 */
int veos_map_dmades(pid_t pid, uint64_t *vehva_dmades, uint64_t *vehva_dmactl)
{
	int retval = -1, phys_core = -1;
	struct ve_task_struct *tsk = NULL;
	struct ve_core_struct *p_ve_core = NULL;
	veraa_t paddr[2] = {0, 0};
	bool set_permission_bit = true;

	VEOS_TRACE("Entering");

	/* Checking for valid arguments received or not */
	if (vehva_dmades == NULL || vehva_dmactl == NULL) {
		VEOS_DEBUG("NULL args, vehva_dmades: %p vehva_dmactl: %p",
				vehva_dmades, vehva_dmactl);
		retval = -EINVAL;
		goto err_return1;
	}

	/* Find the task struct corresponding to the given PID */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		retval = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-retval), pid);
		goto err_return1;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	/* Check if DMA descriptor table H is already enabled or not */
	if (tsk->p_ve_mm->udma_desc_bmap & DMA_DESC_H) {
		VEOS_DEBUG("DMAATB for DMA descriptor table H"
				" is already allocated of PID: %d", pid);
		retval = -EBUSY;
		goto err_return2;
	}

	/* Currently VE task is not scheduled on any of the core.
	 * So we will just update the field "DMA_DESC_H" and
	 * during scheduling DMAATB entry will get allocated.
	 */
	if (-1 == *tsk->core_dma_desc || false == tsk->p_ve_mm->is_sched) {
		VEOS_DEBUG("PID: %d is not scheduled.", tsk->pid);

		/* Currently task is scheduled out so there is no need
		 * to set the permission bit of DMA control register H.
		 */
		set_permission_bit = false;
		goto update_field;
	}

	p_ve_core = VE_CORE(0, *tsk->core_dma_desc);
	phys_core = p_ve_core->phys_core_num;
	VEOS_DEBUG("PID %d DMA DESC logical core %d physical core: %d",
			tsk->pid, *tsk->core_dma_desc, phys_core);

	paddr[0] = VERAA(phys_core) + SYSPROT_OFF + EDMADESC_H_OFF;
	amm_dump_dmaatb(tsk, true);
	retval = veos_alloc_dmaatb_entry_for_aa_tsk(tsk, paddr,
			PROT_READ|PROT_WRITE,
			VE_ADDR_VERAA,
			VEHVA_DMA_DESC_H_REG|VEHVA_4K|VEHVA_MAP_FIXED,
			true);
	if (0 > retval) {
		VEOS_DEBUG("veos_alloc_dmaatb_entry_for_aa failed");
		goto err_return2;
	}

	amm_dump_dmaatb(tsk, true);

update_field:
	/* Zero-clear DMA descriptor table H and DMA control register corresponding
	 * to DMA descriptor table H.
	 */
	memset(&(tsk->udma_context->dmades[VE_UDMA_HENTRY]), 0,
				sizeof(dma_desc_t)*DMA_DSCR_ENTRY_SIZE);
	memset(&(tsk->udma_context->dmactl[VE_UDMA_HENTRY]), 0,
				sizeof(dma_control_t));

	/* If any threads of the process are running on VE cores, then sync the
	 * soft copy of DMA descriptor table H and DMA control register
	 * corresponding to DMA descriptor table H to actual registers, and set
	 * permission bit in the DMA control register of H.
	 */
	if (true == set_permission_bit) {
		VEOS_DEBUG("Restore UDMA context corresponding to H");
		if (__psm_restore_udma_context(tsk,
					*(tsk->core_dma_desc), VE_UDMA_HENTRY))
			veos_abort("Fail to Restore DMA H context of core: %d",
					*tsk->core_dma_desc);

		if (psm_start_udma(*(tsk->core_dma_desc), DMA_DESC_H))
			veos_abort("Fail to START DMA H of core: %d",
					*tsk->core_dma_desc);
	}

	*vehva_dmades = DMA_DESC_H_START;
	*vehva_dmactl = DMA_CNT_START;
	tsk->p_ve_mm->udma_desc_bmap = DMA_DESC_E_H;
	VEOS_DEBUG("DMA descriptor table H is now enabled of PID: %d", pid);
	retval = 0;
err_return2:
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	put_ve_task_struct(tsk);
err_return1:
	VEOS_TRACE("Exiting");
	return retval;
}

/**
 * @brief Free VEHVA region update the DMAATB entries register.
 *
 * @param[in] requester PID of the requesting process
 * @param[in] vehva_dmades VEHVA which DMA descriptor is mapped
 *
 * @return 0 on success, -errno on failure
 */
int veos_unmap_dmades(pid_t pid, uint64_t vehva_dmades)
{
	struct ve_task_struct *tsk = NULL;
	int retval = 0;

	VEOS_TRACE("Entering");

	/* Check if vehva_dmades received is not a valid VEHVA of
	 * DMA descriptor table H.
	 */
	if (vehva_dmades != DMA_DESC_H_START) {
		VEOS_DEBUG("Invalid VEHVA received : %lx", vehva_dmades);
		retval = -EINVAL;
		goto err_return1;
	}

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		retval = -ESRCH;
		VEOS_DEBUG("Error (%s) while searching for pid %d",
				strerror(-retval), pid);
		goto err_return1;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	if (!(tsk->p_ve_mm->udma_desc_bmap & DMA_DESC_H)) {
		retval = -EINVAL;
		VEOS_DEBUG("Error (%s) dmadesc is not enable for %d",
				strerror(-retval), pid);
		goto err_return2;
	}

	tsk->p_ve_mm->udma_desc_bmap = DMA_DESC_E;

	/* If we VE task is scheduled on core then we will invoke
	 * veos_free_dmaatb_entry_tsk() else DMAATB was already released
	 * from function veos_release_dmaatb_entry() during schedule out.
	 */
	if (true == tsk->p_ve_mm->is_sched && *tsk->core_dma_desc != -1) {
		/* Stop the user mode DMA corresponding to DMA
		 * descriptor table H.
		 */
		if (psm_stop_udma(*tsk->core_dma_desc, DMA_DESC_H))
			veos_abort("Fail to STOP DMA H of core: %d",
					*tsk->core_dma_desc);

		retval = veos_free_dmaatb_entry_tsk(tsk, vehva_dmades,
				PAGE_SIZE_4KB);
		if (0 > retval) {
			VEOS_DEBUG("Error (%s) while freeing the dmaatb",
					strerror(-retval));

			/* Revert the bitmap in case of failure */
			tsk->p_ve_mm->udma_desc_bmap = DMA_DESC_E_H;
			goto err_return2;
		}
	} else {
		VEOS_DEBUG("PID: %d is not scheduled on core", tsk->pid);
	}

	VEOS_DEBUG("DMA descriptor table H is now disabled of PID: %d", pid);
	retval = 0;
err_return2:
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	put_ve_task_struct(tsk);
err_return1:
	VEOS_TRACE("Exiting");
	return retval;
}
