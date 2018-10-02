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
/*
 * @brief Handle command send by RMP.
 *
 * @internal
 * @author AMM
 */
#include "mm_stat.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/shm.h>
#include "velayout.h"
#include "veos.h"
#include "buddy.h"
#include "pmap.h"

/*
   Supported Vmflags
   rd  - readable
   wr  - writeable
   ex  - executable
   sh  - shared
   mr  - may read
   mw  - may write
   me  - may execute
   ms  - may share
   gd  - stack segment growns down
   ht  - area uses huge tlb pages

   Unsupported Vmflags
   dc  - do not copy area on fork
   pf  - pure PFN range
   dw  - disabled write to the mapped file
   lo  - pages are locked in memory
   io  - memory mapped I/O area
   sr  - sequential read advise provided
   rr  - random read advise provided
   de  - do not expand area on remapping
   ac  - area is accountable
   nr  - swap space is not reserved for the area
   ar  - architecture specific flag
   dd  - do not include area into core dump
   sd  - soft-dirty flag
   mm  - mixed map area
   hg  - huge page advise flag
   nh  - no-huge page advise flag
   mg  - mergable advise flag.
   */

char *unsupported_vmflgas[] = {"pf", "dw", "lo", "io",
				"sr", "rr", "de", "ac",
				"nr", "ar", "dd", "sd", "dc"
				"mm", "hg", "nh", "mg", "null"};


/**
 * @brief Fill memory related information in struct sysinfo.
 *
 * @param[out] sys Pointer to struct sysinfo.
 */
void veos_sysinfo(int node_id, struct sysinfo *sys)
{
	struct ve_node_struct *vnode = VE_NODE(node_id);
	uint64_t i = 0, count = 0;

	VEOS_TRACE("invoked for node %d and syinfo %p", node_id, sys);

	if (NULL == sys) {
		VEOS_DEBUG("sysinfo is NULL");
		return;
	}
	sys->totalram = vnode->mem.ve_mem_size;

	sys->freeram = count*PAGE_SIZE_2MB;
	count = 0;
	for (i = 0; i < vnode->nr_pages; i++) {
		if (NULL != VE_PAGE(vnode, i)) {
			if ((PG_SHM & VE_PAGE(vnode, i)->flag) ||
					(MAP_SHARED & VE_PAGE(vnode, i)->flag)) {
				count = count + VE_PAGE(vnode, i)->pgsz;
				VEOS_TRACE("VE page %lx is shared", i);
			}
		VEOS_TRACE("VE page no %lx not shared", i);
		}

	}

	sys->sharedram = count;
	sys->bufferram = 0;	/*this is data is not supported for VE*/
	sys->totalhigh = 0;	/*this is data is not supported for VE*/
	sys->freehigh = 0;	/*this is data is not supported for VE*/
	sys->mem_unit = 0;	/*this is data is not supported for VE*/
	sys->totalswap = 0;	/*this is data is not supported for VE*/
	sys->freeswap = 0;	/*this is data is not supported for VE*/
	VEOS_DEBUG("Total RAM %lx\nFree RAM "
			"%lx\n Shared RAM %lx", sys->totalram,
			sys->freeram, sys->freeram);
	VEOS_TRACE("returned");
}

/**
 * @brief Function will populate the fields of struct ve_pidstatinfo_req.
 *
 * @param[in] pid Pid of VE process.
 * @param[out] pidstat Pointer to struct ve_pidstatinfo_req.
 *
 * @return 0 on success, negative of errno on failure.
 */

int veos_pidstat_info(pid_t pid, struct velib_pidstat *pidstat)
{
	int ret = 0;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("invoked for task:pid(%d)", pid);

	if (NULL == pidstat) {
		ret = -EINVAL;
		goto hndl_return;
	}
	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task for pid %d",
			strerror(-ret), pid);
		goto hndl_return;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	pidstat->vsize = get_vm_size(tsk->p_ve_mm); /*In Bytes*/
	pidstat->rss = (tsk->p_ve_mm->rss_cur)/1024; /*In KBytes*/
	pidstat->startcode = tsk->p_ve_mm->start_code;
	pidstat->endcode = tsk->p_ve_mm->end_code;
	pidstat->rsslim = tsk->sighand->rlim[RLIMIT_RSS].rlim_cur; /*In Bytes*/
	pidstat->startstack = tsk->p_ve_mm->start_stack;
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	put_ve_task_struct(tsk);

hndl_return:
	VEOS_TRACE("returned with value %d", ret);
	return ret;
}
/**
 * @brief  This function calculates the total virtual memory in bytes
 *         taken by the VE process.
 *
 * @param[in] mm Pointer to struct ve_mm_struct of VE process.
 *
 * @return: Always Success it return process virtual memory size.
 */
uint64_t get_vm_size(struct ve_mm_struct *mm)
{
	uint64_t max_vm = 0;
	int type = 0;
	atb_reg_t *atb = &(mm->atb);
	int entry_cntr = -1, dir_cntr = -1;

	VEOS_TRACE("invoked for task with mm desc %p", mm);
	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			type = ps_getpgsz(&(atb->dir[dir_cntr]));
			for (entry_cntr = 0; entry_cntr < ATB_ENTRY_MAX_SIZE;
					entry_cntr++) {
				/* Check if page entries is valid */
				if (pg_isvalid(&(atb->
						entry[dir_cntr][entry_cntr]))) {
					if (type == PG_2M)
						max_vm += PAGE_SIZE_2MB;
					else if (type == PG_HP)
						max_vm += PAGE_SIZE_64MB;
				} else {
					if (pg_getpb(&(atb->
							entry[dir_cntr][entry_cntr]),
							PG_2M)) {
						if (type == PG_2M)
							max_vm += PAGE_SIZE_2MB;
						else if (type == PG_HP)
							max_vm += PAGE_SIZE_64MB;
					}
				}
			} /* end entry loop */
		} /* end*/
		else
			VEOS_TRACE("Task page directory %d is invalidated", dir_cntr);
	} /* end dir loop */

	VEOS_TRACE("returned");
	return max_vm;
}

/**
* @brief Function will populate the fields of struct ve_pidstatminfo_req.
*
* @param[in] pid Pid of the process.
* @param[out] pidstatm Pointer to struct velib_pidstatm.
*
* @return 0 on success, -ve of errno on failure.
*/
int veos_pidstatm_info(int pid, struct velib_pidstatm *pidstatm)
{
	int ret = 0;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("invoked for tsk:pid(%d) and pidstat %p", pid, pidstatm);

	if (NULL == pidstatm) {
		ret = EINVAL;
		VEOS_DEBUG("Invalid input argument");
		goto error;
	}

	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task for pid %d",
			strerror(-ret), pid);
		goto error;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	pidstatm->size = tsk->p_ve_mm->rss_cur; /*In Bytes*/
	pidstatm->resident = tsk->p_ve_mm->rss_cur; /*In Butes*/
	pidstatm->share = tsk->p_ve_mm->shared_rss; /* In Bytes */
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	pidstatm->trs = ALIGN(tsk->p_ve_mm->end_code, tsk->p_ve_mm->pgsz) -
		tsk->p_ve_mm->start_code; /*In Bytes*/

	pidstatm->drs = pidstatm->size - pidstatm->trs; /*In Bytes*/

	put_ve_task_struct(tsk);

error:
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief Function will populate the field of struct ve_mem_info_request.
*
* @param[out] mem_info Pointer to struct ve_mem_info_request.
*
* @return 0 on success, negative of errno on failure.
*/
int veos_meminfo(struct velib_meminfo *mem_info)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t i, count = 0;
	int ret = 0;

	VEOS_TRACE("invoked with meminfo %p", mem_info);

	if (NULL == mem_info) {
		VEOS_DEBUG("Invalid input argument");
		ret = -EINVAL;
		goto error;
	}

	/* Total VE memory in Bytes */
	mem_info->kb_main_total = (vnode->mem).ve_mem_size;

	/* Total VE memory used in Bytes */
	mem_info->kb_main_used = (vnode->mp->small_page_used +
		(HUGE_PAGE_IDX * vnode->mp->huge_page_used)) * PAGE_SIZE_2MB;

	/* Total VE memory free in Bytes*/
	mem_info->kb_main_free = (vnode->mp->total_pages -
			(vnode->mp->small_page_used +
		(HUGE_PAGE_IDX * vnode->mp->huge_page_used))) * PAGE_SIZE_2MB;

	/*Total VE memory used by HUGEPAGE in Bytes*/
	mem_info->kb_hugepage_used = (vnode->mp->huge_page_used * PAGE_SIZE_64MB);


	for (i = 0; i < vnode->nr_pages; i++) {
		if (NULL == VE_PAGE(vnode, i))
			continue;
		if (PG_SHM & VE_PAGE(vnode, i)->flag || MAP_SHARED
				& VE_PAGE(vnode, i)->flag)
			count = (count + PAGE_SIZE_2MB);
	}
	/*Total VE shared memory in Bytes*/
	mem_info->kb_main_shared = count;

error:
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief Function will populate the max rss field of struct ve_rusage.
*
* @param[in] who Whose max rss has to be returned.
* @param[out] ve_r Pointer to struct ve_rusage.
* @param[in] tsk Pointer to the task struct of process.
*
* @return 0 on success, negative of errno on failure.
*/
int veos_getrusage(int who, struct ve_rusage *ve_r,
		struct ve_task_struct *tsk)
{
	int ret = 0;
	VEOS_TRACE("invoked to get rusage for tsk(%p):pid(%d) - who %d rusage %p",
			tsk, tsk->pid, who, ve_r);

	if (who == RUSAGE_SELF) {
		ve_r->ru_maxrss = tsk->p_ve_mm->rss_max/1024; /*In KBytes*/
	} else if (who == RUSAGE_THREAD) {
		ve_r->ru_maxrss = tsk->p_ve_mm->rss_max/1024; /*In KBytes*/
	} else if (who == RUSAGE_CHILDREN) {
			VEOS_DEBUG ("pid = %d crss_max = %ld", tsk->pid, tsk->p_ve_mm->crss_max);
			ve_r->ru_maxrss = tsk->p_ve_mm->crss_max/1024;
	} else {
		ret = -EINVAL;
		VEOS_DEBUG("Invalid input argument");
		return ret;
	}

	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will give the memory mapping of
*		respective process for given pid.
*
* @param[in] pid pid of process.
* @param[in] header map hearder.
*
* @return return 0 on success and negative of errno on failure.
*/
int veos_pmap(pid_t pid, struct ve_mapheader *header)
{
	int pmapcount = 0;
	int i = 0, shmid = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct _psuedo_pmap *ve_map = NULL;
	struct _psuedo_pmap *vemap_l = NULL;
	struct _psuedo_pmap *vemap_tmp = NULL;
	struct ve_mapinfo pmap_entry = {0};
	struct ve_task_struct *tsk = NULL;
	int ret = 0;
	int str_len = 0;
	void *shmaddr = NULL;

	VEOS_TRACE("invoked for task:pid(%d) and header %p", pid, header);
	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task for pid %d",
			strerror(-ret), pid);
		goto err;
	}

	pmapcount = get_vepmap(&ve_map, tsk);
	if (0 == pmapcount) {
		VEOS_DEBUG("no segment to dump");
		ret = 0;
		header->shmid = 0;
		goto err;
	}
	vemap_l = ve_map;
	shmid = shmget(IPC_PRIVATE, sizeof(struct ve_mapinfo)*pmapcount,
			IPC_CREAT | 0666);
	if (0 > shmid) {
		VEOS_DEBUG("VHOS shmget failed for pmap");
		ret = -errno;
		goto err;
	}

	shmaddr = shmat(shmid, NULL, 0);
	if ((void *)-1 == shmaddr) {
		VEOS_DEBUG("VHOS shmat failed for pmap");

		if (0 > shmctl(shmid, IPC_RMID, NULL))
			VEOS_DEBUG("Failed to set shared memory for deletion");
		ret = -errno;
		goto err;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, LOCK,
			"Failed to acquire ve_pages_node_lock");

	for (i = 0; i < pmapcount; i++) {
		memset(&pmap_entry, '\0', sizeof(pmap_entry));
		pmap_entry.start = ve_map->begin;
		pmap_entry.end = ve_map->end;
		pmap_entry.size = (ve_map->end - ve_map->begin)/KB; /*In KBytes*/
		pmap_entry.rss	= get_map_attr(ve_map->begin, (size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "rss")/KB;/*In KBytes*/
		pmap_entry.inode = ve_map->inode;
		pmap_entry.offset = ve_map->foo;
		pmap_entry.mmu_pagesize = get_map_attr(ve_map->begin, (size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "page_size")/KB; /*In KBytes*/
		pmap_entry.pagesize = pmap_entry.mmu_pagesize; /*In KBytes*/

		pmap_entry.anon_hugepage = get_map_attr(ve_map->begin, (size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "anon_hugepg")/KB; /*In KBytes*/

		pmap_entry.anonymous = get_map_attr(ve_map->begin, (size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "anonymous")/KB; /*In KBytes*/

		pmap_entry.dev_major = strtol(ve_map->dev, NULL, 16);
		pmap_entry.dev_minor = strtol(ve_map->dev+3, NULL, 16);
		pmap_entry.pss = get_map_attr(ve_map->begin, (size_t)(pmap_entry.size * KB),
				tsk->p_ve_mm, "pss")/KB; /*In KBytes*/
		if (ve_map->vmflags[0]) {
			/*Removed Vmflags which are not supported*/
			parse_vmflags(pmap_entry.vmflags, ve_map->vmflags);
			/*check whether mapping is for stack*/
			if (check_flag(ve_map->begin, MAP_STACK, tsk->p_ve_mm)) {
				str_len = strlen(pmap_entry.vmflags);
				strncpy((pmap_entry.vmflags + (str_len-1)), " gd", strlen(" gd"));
			}
			/*check whether maping is with huge page*/
			if (check_flag(ve_map->begin, MAP_64MB, tsk->p_ve_mm)) {
				str_len = strlen(pmap_entry.vmflags);
				strncpy((pmap_entry.vmflags + (str_len-1)), " ht", strlen(" ht"));
			}
		} else {
			memcpy(pmap_entry.vmflags, " ", 1);
		}
		memcpy(pmap_entry.perms, ve_map->perm, 5);
		if (ve_map->mapname[0])
			memcpy(pmap_entry.map_desc, ve_map->mapname, 128);
		else
			memcpy(pmap_entry.map_desc, "[anon]", strlen("[anon]")+1);

		memcpy(shmaddr+(i*sizeof(pmap_entry)),
				&pmap_entry, sizeof(pmap_entry));
		ve_map = ve_map->next;
	}
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Failed to release ve_pages_node_lock");

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	VEOS_DEBUG("VE maping List:");
	/*Dumping As well as freeing the VE pmap list*/
	while (vemap_l != NULL) {
		VEOS_TRACE("%p - %p, %s, %s",
				(void *)vemap_l->begin, (void *)vemap_l->end,
				vemap_l->perm, vemap_l->mapname);
		vemap_tmp = vemap_l;
		vemap_l = vemap_l->next;
		free(vemap_tmp);
	}

	header->shmid = shmid;
	header->length = (unsigned int)pmapcount;

	ret = shmdt(shmaddr);
	if (0 > ret) {
		VEOS_DEBUG("VHOS shmdt failed for pmap");
		if (0 > shmctl(shmid, IPC_RMID, NULL))
			VEOS_DEBUG("Failed to set shared memory for deletion");
		ret = -errno;
	}

err:
	if (tsk)
		put_ve_task_struct(tsk);
	return ret;
}

/**
* @brief This function will return mapping various size attributes
*        (such as pss, page size etc).
*
* @param[in] vemap ve_map_begin starting address of mapping.
* @param[in] map_sz map_size Total size of mapping.
* @param[in] mm reference to the mm struct.
* @param[in] attr required mapping attribute.
*
* @return return size attributes (bytes) always.
*/
size_t get_map_attr(vemva_t vemap, size_t map_sz, struct ve_mm_struct *mm, char *attr)
{
	pgno_t pgno = 0;
	int pgmod = 0;
	vemaa_t phy  = 0;
	size_t size = 0;
	size_t pg_sz = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("invoked");

	VEOS_DEBUG("vemap(0x%lx) map size(0x%lx) required attribute(%s)",
		vemap, map_sz, attr);

	while (map_sz > 0) {
		phy = __veos_virt_to_phy(vemap, &mm->atb, NULL, &pgmod);
		if (phy < 0) {
			VEOS_DEBUG("No physical mapping for(0x%lx)", vemap);
			break;
		}

		pgno = pfnum(phy, PG_2M);
		pg_sz = (size_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB);

		if (!strcasecmp(attr, "pss")) {
			if (map_sz < pg_sz) {
				if (VE_PAGE(vnode, pgno)->flag & MAP_VDSO) {
					size += pg_sz;
				} else {
					if (VE_PAGE(vnode, pgno)->ref_count)
						size = map_sz/VE_PAGE(vnode, pgno)->ref_count;
				}
				break;
			} else {
				if (VE_PAGE(vnode, pgno)->flag & MAP_VDSO) {
					size += pg_sz;
				} else {
					if (VE_PAGE(vnode, pgno)->ref_count)
						size += (pg_sz/VE_PAGE(vnode, pgno)->ref_count);
				}
			}
		} else if (!strcasecmp(attr, "rss")) {
			size += pg_sz;
		} else if (!strcasecmp(attr, "page_size")) {
			size = pg_sz;
			break;
		} else if (!strcasecmp(attr, "anon_hugepg")) {
			if (pgmod == PG_HP)
				size += pg_sz;
		} else if (!strcasecmp(attr, "anonymous")) {
			if (VE_PAGE(vnode, pgno)->flag & MAP_ANON)
				size += pg_sz;
		}
		vemap += pg_sz;
		map_sz -= pg_sz;
		VEOS_DEBUG("vemap(0x%lx) map_sz(0x%lx)", vemap, map_sz);
	}
	VEOS_TRACE("returned(0x%lx)", size);
	return size;
}

/**
* @brief This function will parseout Vmflags which are not supported.
*
* @param[out] parsed These are parsed Vmflags.
* @param[in] toparse These are all Vmflags for which parsing to be carried out.
*/
void parse_vmflags(char *parsed, char *toparse)
{
	int idx = 0;
	char *strloc =  NULL;
	char tmp_parse[VMFLAGS_LENGTH];
	memset(tmp_parse, '\0', VMFLAGS_LENGTH);
	strncpy(tmp_parse, toparse, VMFLAGS_LENGTH);

	/*Explicitly adding null character at the end to prevent buffer overrun*/
	tmp_parse[VMFLAGS_LENGTH - 1] = '\0';

	VEOS_TRACE("invoked");
	VEOS_DEBUG("Vmflags before parsing (%s)", toparse);

	while (strcasecmp(unsupported_vmflgas[idx], "null")) {
		strcpy(parsed, tmp_parse);
		strloc = strstr(parsed, unsupported_vmflgas[idx]);
		if (strloc != NULL) {
			strcpy(strloc, (strloc + strlen(unsupported_vmflgas[idx]) + 1));
			VEOS_DEBUG("Vmflags(%s) removed", unsupported_vmflgas[idx]);
		}
		strcpy(tmp_parse, parsed);
		idx++;
	}
	VEOS_DEBUG("Vmflags after parsing (%s)", parsed);

	VEOS_TRACE("returned");
}

/**
* @brief This function will check flags associated with mapping
*
* @param[in] vemap mapping start address.
* @param[in] flag flags flags to be check.
* @param[in] mm reference to the process mm struct.
*
* @return return true if flags is associated with mapping else false.
*/
bool check_flag(vemva_t vemap, uint64_t flag, struct ve_mm_struct *mm)
{
	pgno_t pgno = 0;
	int pgmod = 0;
	vemaa_t phy  = 0;
	bool is_flag = false;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("invoked");

	phy = __veos_virt_to_phy(vemap, &mm->atb, NULL, &pgmod);
	if (phy < 0) {
		VEOS_DEBUG("No physical mapping for(0x%lx)", vemap);
		return is_flag;
	}

	pgno = pfnum(phy, PG_2M);

	if (flag & MAP_STACK) {
		if (flag & VE_PAGE(vnode, pgno)->flag)
			is_flag = true;
	} else if (flag & MAP_64MB) {
		if (VE_PAGE(vnode, pgno)->pgsz == PAGE_SIZE_64MB)
			is_flag = true;
	}

	VEOS_TRACE("returned");
	return is_flag;
}

/*
* @brief This function will change the owner of shm segmnet.
*
* @param[in] uid uid of requestor process.
* @param[in] shmid shmid of segment whose owner to be changed.
*
* @return if success return 0 else negative of errno.
*/
int change_owner_shm(int uid, int shmid)
{
	int ret = 0;
	struct shmid_ds buf;

	VEOS_TRACE("Entering");
	VEOS_DEBUG("Changing owner of shm segment shmid(%d)", shmid);
	/*Changing the owner of Sys V shared memory*/
	ret = shmctl(shmid, IPC_STAT, &buf);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Failed to get shared memory segment stat");
		shmctl(shmid, IPC_RMID, NULL);
		goto err;
	}

	buf.shm_perm.uid = (__uid_t)uid;

	ret = shmctl(shmid, IPC_SET, &buf);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Failed to Set shared memory segment stat");
		shmctl(shmid, IPC_RMID, NULL);
	}
	VEOS_TRACE("returning");
err:
	return ret;
}
