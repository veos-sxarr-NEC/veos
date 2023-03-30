/*
 * Copyright (C) 2017-2019 NEC Corporation
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
#include "mman_ve.h"
#include "veos.h"
#include "ve_memory.h"
#include "buddy.h"
#include "pmap.h"
#include "mempolicy.h"
#include "veos_sock.h"
#include "ve_memory_def.h"

#include <veos_arch_defs.h>

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
	struct velib_meminfo mem_info = {0};

	VEOS_TRACE("Invoked");

	/*Get the VE memory information*/
	veos_meminfo(&mem_info);

	sys->totalram = mem_info.kb_main_total; /*Total used VE memory*/
	sys->freeram =	mem_info.kb_main_free; /*Total free VE memory*/
	sys->sharedram = mem_info.kb_main_shared; /*Total shared VE memory*/
	sys->mem_unit = 1;	/*VE memory unit size in bytes*/
	sys->bufferram = 0;	/*this is data is not supported for VE*/
	sys->totalhigh = 0;	/*this is data is not supported for VE*/
	sys->freehigh = 0;	/*this is data is not supported for VE*/
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
	if (NULL == tsk && !(tsk = checkpid_in_zombie_list(pid))) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task for pid %d",
			strerror(-ret), pid);
		goto hndl_return;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	pidstat->vsize = get_vm_size(tsk->p_ve_mm); /*In Bytes*/
	pidstat->rss = (get_uss(tsk->p_ve_mm, NULL) + get_pss(tsk->p_ve_mm, NULL))/1024;
								/*In KBytes*/
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
	atb_reg_t *atb = &(mm->atb[0]);
	int entry_cntr = -1, dir_cntr = -1;

	VEOS_TRACE("invoked for task with mm desc %p", mm);
	/* Loop for very directory for ATB */
	for (dir_cntr = 0; dir_cntr < VEOS_ATB_DIR_NUM; dir_cntr++) {
		/* Check entries only when directory entry is valid */
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			type = ps_getpgsz(&(atb->dir[dir_cntr]));
			for (entry_cntr = 0; entry_cntr < VEOS_ATB_ENTRY_MAX_SIZE;
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
		ret = -EINVAL;
		VEOS_DEBUG("Invalid input argument");
		goto error;
	}

	/* Find the VE task for given pid */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk && !(tsk = checkpid_in_zombie_list(pid))) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task for pid %d",
			strerror(-ret), pid);
		goto error;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	pidstatm->size = tsk->p_ve_mm->vm_size; /*In Bytes*/
	pidstatm->resident = get_uss(tsk->p_ve_mm, NULL) + get_pss(tsk->p_ve_mm, NULL);
								/*In Bytes*/
	pidstatm->share = tsk->p_ve_mm->shared_rss; /* In Bytes */
	pidstatm->trs = ALIGN(tsk->p_ve_mm->end_code, tsk->p_ve_mm->pgsz) -
				tsk->p_ve_mm->start_code;/*In Bytes*/
	pidstatm->drs = pidstatm->size - pidstatm->trs; /*In Bytes*/
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

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
	struct buddy_mempool *numa_mp = NULL;
	uint64_t i = 0, count = 0;
	int ret = 0;

	VEOS_TRACE("invoked with meminfo %p", mem_info);

	if (mem_info == NULL) {
		VEOS_DEBUG("Invalid input argument");
		ret = -EINVAL;
		goto error;
	}

	/* Total VE memory in Bytes */
	mem_info->kb_main_total = (vnode->mem).ve_mem_size;

	mem_info->kb_main_used = 0;
	mem_info->kb_main_free = 0;
	mem_info->kb_hugepage_used = 0;
	for (i = 0; i < vnode->numa_count; i++) {
		numa_mp = vnode->numa[i].mp;
		/* Total VE memory used in Bytes */
		mem_info->kb_main_used += (numa_mp->small_page_used +
			 (HUGE_PAGE_IDX * numa_mp->huge_page_used)) *
			 PAGE_SIZE_2MB;

		/* Total VE memory free in Bytes*/
		mem_info->kb_main_free += (numa_mp->total_pages -
			(numa_mp->small_page_used + (HUGE_PAGE_IDX *
			 numa_mp->huge_page_used))) * PAGE_SIZE_2MB;

		/*Total VE memory used by HUGEPAGE in Bytes*/
		mem_info->kb_hugepage_used += (numa_mp->huge_page_used *
			 PAGE_SIZE_64MB);
	}

	for (i = 0; i < vnode->nr_pages; i++) {
		if (VE_PAGE(vnode, i) == NULL)
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
			VEOS_DEBUG("pid = %d crss_max = %ld", tsk->pid,
					tsk->p_ve_mm->crss_max);
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
* @param[in] gid GID of caller process.
* @param[in] uid UID of caller process.
* @param[in] header map hearder.
*
* @return return 0 on success and negative of errno on failure.
*/
int veos_pmap(pid_t pid, uid_t gid, uid_t uid, struct ve_mapheader *header)
{
	int pmapcount = 0;
	int i = 0, fd = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct _psuedo_pmap *ve_map = NULL;
	struct _psuedo_pmap *vemap_l = NULL;
	struct _psuedo_pmap *vemap_tmp = NULL;
	struct ve_mapinfo pmap_entry = {0};
	struct ve_task_struct *tsk = NULL;
	int ret = 0;
	int str_len = 0;
	void *shmaddr = NULL;
	char *file_base_name = NULL;
	char *filename = NULL;

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
	if (0 >= pmapcount) {
		VEOS_DEBUG("no segment to dump");
		ret = pmapcount;
		goto err;
	}
	vemap_l = ve_map;

	filename = (char *)malloc(PATH_MAX);
	if (NULL == filename) {
		ret = -ENOMEM;
		VEOS_CRIT("Internal memory allocation fails.");
		VEOS_DEBUG("malloc fails: %s", strerror(errno));
		goto err;
	}

	sprintf(filename, "%s/veos%d-tmp/rpm_cmd_XXXXXX",
			VEOS_SOC_PATH, header->node_id);

	VEOS_DEBUG("File path: %s", filename);

	/* create a unique temporary file and opens it */
	fd =  mkstemp(filename);
	if (fd < 0) {
		ret = -errno;
		VEOS_DEBUG("mkstemp fails: %s", strerror(errno));
		goto err;
	}

	/* Change file onwership so that RPM command can access file */
	if (fchown(fd, uid, gid)) {
		ret = -errno;
		VEOS_DEBUG("fail to change file onwer: %s", strerror(errno));
		close(fd);
		unlink(filename);
		goto err;
	}

	/* truncate file to size PAGE_SIZE_4KB */
	ret = ftruncate(fd, sizeof(struct ve_mapinfo)*pmapcount);
	if (-1 == ret) {
		ret = -errno;
		VEOS_DEBUG("ftruncate fails: %s", strerror(errno));
		close(fd);
		unlink(filename);
		goto err;
	}

	shmaddr = mmap(NULL,
			sizeof(struct ve_mapinfo)*pmapcount,
			PROT_READ|PROT_WRITE,
			MAP_SHARED,
			fd,
			0);
	if ((void *)-1 == shmaddr) {
		ret = -errno;
		VEOS_DEBUG("VHOS mmap failed for pmap: %s", strerror(errno));
		close(fd);
		unlink(filename);
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
		pmap_entry.rss	= get_map_attr(ve_map->begin,
				(size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "rss")/KB;/*In KBytes*/
		pmap_entry.inode = ve_map->inode;
		pmap_entry.offset = ve_map->foo;
		pmap_entry.mmu_pagesize = get_map_attr(ve_map->begin,
				(size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "page_size")/KB; /*In KBytes*/
		pmap_entry.pagesize = pmap_entry.mmu_pagesize; /*In KBytes*/

		pmap_entry.anon_hugepage = get_map_attr(ve_map->begin,
				(size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "anon_hugepg")/KB; /*In KBytes*/

		pmap_entry.anonymous = get_map_attr(ve_map->begin,
				(size_t)(pmap_entry.size*KB),
				tsk->p_ve_mm, "anonymous")/KB; /*In KBytes*/

		pmap_entry.dev_major = strtol(ve_map->dev, NULL, 16);
		pmap_entry.dev_minor = strtol(ve_map->dev+3, NULL, 16);
		pmap_entry.pss = get_map_attr(ve_map->begin,
				(size_t)(pmap_entry.size * KB),
				tsk->p_ve_mm, "pss")/KB; /*In KBytes*/
		if (ve_map->vmflags[0]) {
			/*Removed Vmflags which are not supported*/
			parse_vmflags(pmap_entry.vmflags, ve_map->vmflags);
			/*check whether mapping is for stack*/
			if (check_flag(ve_map->begin, MAP_STACK,
						tsk->p_ve_mm)) {
				str_len = strlen(pmap_entry.vmflags);

				memcpy((pmap_entry.vmflags + (str_len-1)), " gd", strlen(" gd"));
			}
			/*check whether maping is with huge page*/
			if (check_flag(ve_map->begin, MAP_64MB,
						tsk->p_ve_mm)) {
				str_len = strlen(pmap_entry.vmflags);

				memcpy((pmap_entry.vmflags + (str_len-1)), " ht", strlen(" ht"));
			}
		} else {
			memcpy(pmap_entry.vmflags, " ", 1);
		}
		memcpy(pmap_entry.perms, ve_map->perm, 5);
		if (ve_map->mapname[0])
			memcpy(pmap_entry.map_desc, ve_map->mapname, 128);
		else
			memcpy(pmap_entry.map_desc, "[anon]",
							strlen("[anon]")+1);

		memcpy(shmaddr+(i*sizeof(pmap_entry)),
				&pmap_entry, sizeof(pmap_entry));
		ve_map = ve_map->next;
	}
	pthread_mutex_lock_unlock(&vnode->ve_pages_node_lock, UNLOCK,
			"Failed to release ve_pages_node_lock");

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");

	file_base_name = basename(filename);
	header->length = (unsigned int)pmapcount;
	strncpy(header->filename, file_base_name, S_FILE_LEN);
	VEOS_DEBUG("File name: %s", file_base_name);

	if (msync(shmaddr, pmapcount*sizeof(struct ve_mapinfo), MS_SYNC)) {
		ret = -errno;
		unlink(filename);
		VEOS_DEBUG("VHOS msync failed : %s", strerror(errno));
	}

	if (munmap(shmaddr, pmapcount*sizeof(struct ve_mapinfo))) {
		ret = -errno;
		unlink(filename);
		VEOS_DEBUG("VHOS munmap() failed for pmap");
	}
	close(fd);
err:
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

	if (tsk)
		put_ve_task_struct(tsk);
	if (filename)
		free(filename);

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
		phy = __veos_virt_to_phy(vemap, &mm->atb[0], NULL, &pgmod);
		if (phy < 0) {
			VEOS_DEBUG("No physical mapping for(0x%lx)", vemap);
			break;
		}

		pgno = pfnum(phy, PG_2M);
		pg_sz = (size_t)((pgmod == PG_2M) ?
					PAGE_SIZE_2MB : PAGE_SIZE_64MB);

		if (!strcasecmp(attr, "pss")) {
			if (map_sz < pg_sz) {
				if (VE_PAGE(vnode, pgno)->flag & MAP_VDSO) {
					size += pg_sz;
				} else {
					if (VE_PAGE(vnode, pgno)->ref_count)
						size = map_sz /	VE_PAGE(vnode, pgno)->ref_count;
				}
				break;
			} else {
				if (VE_PAGE(vnode, pgno)->flag & MAP_VDSO) {
					size += pg_sz;
				} else {
					if (VE_PAGE(vnode, pgno)->ref_count)
						size += (pg_sz  / VE_PAGE(vnode, pgno)->ref_count);
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

	/* Explicitly adding null character
	 * at the end to prevent buffer overrun*/
	tmp_parse[VMFLAGS_LENGTH - 1] = '\0';

	VEOS_TRACE("invoked");
	VEOS_DEBUG("Vmflags before parsing (%s)", toparse);

	while (strcasecmp(unsupported_vmflgas[idx], "null")) {
		strcpy(parsed, tmp_parse);
		strloc = strstr(parsed, unsupported_vmflgas[idx]);
		if (strloc != NULL) {
			if(strlen(strloc) <= strlen(unsupported_vmflgas[idx]) + 1){
				memset(strloc, '\0', strlen(strloc));
			}
			else{
				memmove(strloc, strloc +
					strlen(unsupported_vmflgas[idx]) + 1, strlen(strloc +
					strlen(unsupported_vmflgas[idx]) + 1));
				VEOS_DEBUG("Vmflags(%s) removed",
						unsupported_vmflgas[idx]);
			}
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

	phy = __veos_virt_to_phy(vemap, &mm->atb[0], NULL, &pgmod);
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


/**
 * @brief  This function will set memory policy to ve_task_struct.
 *
 * @param[out] ve_task Pointer of struct ve_task_struct
 * @param[in] mempolicy Memory policy (MPOL_DEFAULT or MPOL_BIND)
 *
 * @return if success return 0 else negative of errno.
 */
int veos_set_mempolicy(struct ve_task_struct *ve_task, int mempolicy)
{
	int ret = 0;

	VEOS_TRACE("invoked with ve_task %p", ve_task);

	if (ve_task == NULL) {
		VEOS_DEBUG("Invalid input argument");
		ret = -EINVAL;
		goto error;
	}

	if (mempolicy != MPOL_DEFAULT && mempolicy != MPOL_BIND) {
		VEOS_DEBUG("Invalid input argument mempolicy %d", mempolicy);
		ret = -EINVAL;
		goto error;
	}

	pthread_mutex_lock_unlock(&ve_task->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire thread-group-mm-lock");
	ve_task->p_ve_mm->mem_policy = mempolicy;
	pthread_mutex_lock_unlock(&ve_task->p_ve_mm->thread_group_mm_lock,
			UNLOCK,	"Failed to release thread-group-mm-lock");
	VEOS_DEBUG("Setting mempolicy %d", mempolicy);
error:
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief  This function will get memory policy from ve_task_struct.
 *
 * @param[in] ve_task Pointer of struct ve_task_struct
 *
 * @return if success returns memory policy of
 *		ve_task (MPOL_DEFAULT or MPOL_BIND) else  negative of errno.
 */
int veos_get_mempolicy(struct ve_task_struct *ve_task)
{
	int ret = 0;

	VEOS_TRACE("invoked with ve_task %p", ve_task);
	if (ve_task == NULL) {
		VEOS_DEBUG("Invalid input argument");
		ret = -EINVAL;
		goto error;
	}

	pthread_mutex_lock_unlock(&ve_task->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	ret = ve_task->p_ve_mm->mem_policy;
	pthread_mutex_lock_unlock(&ve_task->p_ve_mm->thread_group_mm_lock,
			UNLOCK,
			"Failed to release thread-group-mm-lock");
	VEOS_DEBUG("Get mempolicy %d", ret);
error:
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief  This function is used to get the VE memory information and
 *	   update the data structure array struct velib_meminfo per NUMA node.
 *
 * @param[out] mem_info Pointer of struct ve_lib_meminfo array.
 * @param[in] size Size of struct velib_meminfo array.
 *
 * @return If success returns the number of NUMA nodes count,
 *	   else negative value.
 */
int veos_numa_meminfo(struct velib_meminfo *mem_info, size_t size)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	uint64_t index = 0, i = 0;
	uint64_t count[VE_MAX_NUMA_NODE] = {};
	struct buddy_mempool *numa_mp = NULL;
	int ret = 0;
	int mp_num = 0;

	VEOS_TRACE("invoked with numa_meminfo %p", mem_info);

	if (mem_info == NULL) {
		VEOS_DEBUG("Invalid input argument");
		ret = -EINVAL;
		goto error;
	}

	if (vnode->numa_count != size/sizeof(struct velib_meminfo)) {
		VEOS_DEBUG("Invalid velib size count :%ld, numa_count :%d",
			size/sizeof(struct velib_meminfo), vnode->numa_count);
		ret = -EINVAL;
		goto error;
	}
	for (index = 0; index < vnode->numa_count; index++) {
		numa_mp = vnode->numa[index].mp;
		/* Total VE memory in Bytes */
		mem_info[index].kb_main_total =
			(vnode->mem).ve_mem_size / vnode->numa_count;

		/* Total VE memory used in Bytes */
		mem_info[index].kb_main_used = (numa_mp->small_page_used +
			(HUGE_PAGE_IDX * numa_mp->huge_page_used)) *
						PAGE_SIZE_2MB;

		/* Total VE memory free in Bytes*/
		mem_info[index].kb_main_free = (numa_mp->total_pages *
			PAGE_SIZE_2MB) - mem_info[index].kb_main_used;

		/*Total VE memory used by HUGEPAGE in Bytes*/
		mem_info[index].kb_hugepage_used =
			(numa_mp->huge_page_used * PAGE_SIZE_64MB);
	}

	for (i = 0; i < vnode->nr_pages; i++) {
		if (VE_PAGE(vnode, i) == NULL)
			continue;
		if (PG_SHM & VE_PAGE(vnode, i)->flag || MAP_SHARED
				& VE_PAGE(vnode, i)->flag) {
			if (vnode->partitioning_mode) {
				mp_num = (int)paddr2mpnum(pbaddr(i, PG_2M),
						  numa_sys_info.numa_mem_blk_sz,
						  numa_sys_info.first_mem_node);
			}
			count[mp_num] = (count[mp_num] + PAGE_SIZE_2MB);
		}
	}
	/*Total VE shared memory in Bytes*/
	for (index = 0; index < vnode->numa_count; index++)
		mem_info[index].kb_main_shared = count[index];

	ret = vnode->numa_count;
error:
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief Get swapped memory size on DMA space
 * @note ve_task_lock of struct ve_task_struct is acquired in advance.
 *
 * @param[in] tsk Pointer to VE task struct
 * @param[out] swapped_sz_p Pointer to contain the swapped memory size of
 *            VE process
 *
 * @return zero on success; -errno on failure.
 */
int veos_get_dma_space_swappable_size(struct ve_task_struct *tsk,
				unsigned long *swappable_sz_p)
{
	return (*_veos_arch_ops->arch_amm_get_dma_space_swappable_size)(
				tsk->p_ve_mm->dmaatb, swappable_sz_p);
}
