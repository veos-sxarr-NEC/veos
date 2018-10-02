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
 * @file  pmap.c
 * @brief To generate pmap of process.
 *
 *       This file contains the functions that help in fetching the
 *	 memory mapped information of VE process.
 *
 * @internal
 * @author AMM
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include "pmap.h"

/**
 * @brief To get the file permission.
 *
 * @param[in] prm pointer to a string
 *
 * @return permission of a file.
 */
int get_perm(char *prm)
{
	int perm = 0;

	if (prm[0] == 'r')
		perm += 4;
	if (prm[1] == 'w')
		perm += 2;
	if (prm[2] == 'x')
		perm += 1;
	return perm;
}

/**
 * @brief Detect the virtual address is heap or not
 *
 * @param[in] vaddr is virtual addr for VE process
 * @param[in] pgsize is page size of VE process
 * @param[in] tsk is the pointer to ve_task_struct.
 *
 * @return On success it return 0 and negative of errno on failure.
 */

int8_t isheap(uint64_t vaddr, struct ve_task_struct *tsk, int pgmod)
{
	int ret = -1;
	dir_t dir_num = -1;
	int64_t pgoff = 0;
	pgno_t pgno = 0;
	struct ve_page *ve_page = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	dir_num =  __get_pgd(vaddr, (void *)&tsk->p_ve_mm->atb, -1, false);
	if (0 > dir_num) {
		VEOS_DEBUG("ATB Directory not available"
				"for vaddr %p", (void *)vaddr);
		ret = -EINVAL;
		goto end;
	}
	pgoff = pgentry(vaddr, pgmod);
	if (0 > pgoff) {
		VEOS_DEBUG("Invalid ATB entry pgoff: %ld"
				"for vaddr %p", pgoff, (void *)vaddr);
		ret = -EINVAL;
		goto end;
	}
	if (pg_isvalid(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]))) {
		pgno = pg_getpb(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]),
				PG_2M);
		if ((!pgno) || (pgno == PG_BUS)) {
			VEOS_DEBUG("Invalid page");
			ret = -EINVAL;
			goto end;;
		}
		ve_page = VE_PAGE(vnode, pgno);
		if (ve_page->flag & MAP_ADDR_SPACE)
			ret = 0;
		else
			ret = 1;
	} else {
		pgno = pg_getpb(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]),
				PG_2M);
		if (pgno) {
			ret = 1;
		} else {
			VEOS_DEBUG("ATB ENTRY not yet allocated %ld", pgno);
			goto end;
		}
	}
	VEOS_DEBUG("Addr: %p is heap,"
			" val: %d", (void *)vaddr, ret);
end:
	return ret;
}

/**
 * @brief Detect the virtual address is stack or not
 *
 * @param[in] vaddr is virtual addr for VE process
 * @param[in] pgsize is page size of VE process
 * @param[in] tsk is the pointer to ve_task_struct.
 *
 * @return On success it return 0 and negative of errno on failure.
 */

int8_t isstack(uint64_t vaddr,	struct ve_task_struct *tsk, int pgmod)
{
	int ret = -1;
	dir_t dir_num = -1;
	int64_t pgoff = 0;
	pgno_t pgno = 0;
	struct ve_page *ve_page = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	dir_num =  __get_pgd(vaddr, (void *)&tsk->p_ve_mm->atb, -1, false);
	if (0 > dir_num) {
		VEOS_DEBUG("ATB Directory not available"
				"for vaddr %p", (void *)vaddr);
		ret = -EINVAL;
		goto end;
	}
	pgoff = pgentry(vaddr, pgmod);
	if (0 > pgoff) {
		VEOS_DEBUG("Invalid ATB entry pgoff: %ld"
				"for vaddr %p", pgoff, (void *)vaddr);
		ret = -EINVAL;
		goto end;
	}
	if (pg_isvalid(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]))) {
		pgno = pg_getpb(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]),
				PG_2M);
		if ((!pgno) || (pgno == PG_BUS)) {
			VEOS_DEBUG("Invalid page");
			ret = -EINVAL;
			goto end;;
		}
		ve_page = VE_PAGE(vnode, pgno);
		if (ve_page->flag & MAP_STACK)
			ret = 0;
		else
			ret = 1;
	} else {
		pgno = pg_getpb(&(tsk->p_ve_mm->atb.entry[dir_num][pgoff]),
				PG_2M);
		if (pgno) {
			ret = 1;
		} else {
			VEOS_DEBUG("ATB ENTRY not yet allocated %ld", pgno);
			goto end;
		}
	}
	VEOS_DEBUG("Addr: %p is stack,"
			" val: %d", (void *)vaddr, ret);
end:
	return ret;
}

/**
 * @brief Initialize memory map of VE process.
 *
 * @param[out] pvemap pointer to _psuedo_pmap(VE).
 * @param[in] pmap pointer to _psuedo_pmap(VH).
 * @param[in] idx index for VE Process memory map.
 *
 * @return On success it return 0 else -1.
 */
int valid_map_range( struct _psuedo_pmap *pmap,
		struct _psuedo_pmap **pvemap, int idx,
		struct ve_task_struct *tsk)
{
	int pgmod = -1;
	uint64_t diff = 0;
	uint64_t pgsz = 0;
	uint64_t aligndiff = 0;
	int loop = 0;
	int flag = 0;
	int8_t retval = -1;
	uint64_t aligned_addr = 0;
	uint64_t begin_addr = 0;
	uint64_t end_addr = 0;
	int ret = 0;

	if (0 == strcmp(pmap[idx].mapname, "")) {
		pgmod = __veos_get_pgmode(VE_ADDR_VEMVA, tsk, pmap[idx].begin);
		if (0 > pgmod) {
			ret = -1;
			goto error;
		}
		pgsz = (pgmod == PG_2M) ? (1 << PSSHFT) :
					((uint64_t)1 << PSSHFT_H);

                /*Aligned starting address*/
		begin_addr = pmap[idx].begin;
                if (!IS_ALIGNED(begin_addr, pgsz))
                        begin_addr =  ALIGN_RD(begin_addr, pgsz);
		end_addr = pmap[idx].end;
                if (!IS_ALIGNED(end_addr, pgsz))
                        end_addr = ALIGN(end_addr, pgsz);

		aligndiff = end_addr - begin_addr;
		diff = aligndiff/pgsz;
		aligned_addr = begin_addr;
		VEOS_DEBUG("Isvalid Begin_addr: %p, End_addr: %p, Aligned_begin: %p"
				" loop %d, diff %ld, pgsz: %p",
				(void *)(pmap[idx].begin), (void *)(pmap[idx].end),
				(void *)aligned_addr,
				loop, diff, (void *)pgsz);
		while ( loop < diff ) {
			retval = isstack(aligned_addr, tsk, pgmod);
			/* Initially flag is 0, it enters the condition.
			* To find the begin address as "stack" */
			if ((0 == retval) && (2 != flag)) {
				if (flag == 3) {
					/* Dump the "anon" memory */
					struct _psuedo_pmap tpmap[2];
					tpmap[0].flag = pmap[idx].flag;
                                        tpmap[0].begin = pmap[idx].begin;
                                        tpmap[0].end = aligned_addr;
                                        tpmap[0].size= pmap[idx].size;
                                        tpmap[0].inode = pmap[idx].inode;
                                        tpmap[0].foo = pmap[idx].foo;
                                        (void)strncpy(tpmap[0].perm,
                                                        pmap[idx].perm,
                                                        sizeof(pmap[idx].perm));
                                        (void)strncpy(tpmap[0].dev,
                                                        pmap[idx].dev,
                                                        sizeof(pmap[idx].dev));
                                        (void)strncpy(tpmap[0].mapname, "[anon]",
                                                        sizeof("[anon]"));
                                        if (fill_ve_pmap(tpmap, pvemap, 0)) {
                                                VEOS_WARN(
                                                                "Record not inserted: %p - %p",
                                                                (void *)tpmap[0].begin,
                                                                (void *)tpmap[0].end);
                                        }
				}
				(void)strncpy(pmap[idx].mapname, "[stack]",
						sizeof("[stack]"));
				pmap[idx].begin = aligned_addr;
				flag = 2;
			} else if (1 == retval) {
				/* if program enters then some memory (anon)
				*  other than stack arrives*/
				if (2 == flag) {
					/* Dump the "anon" memory */
					struct _psuedo_pmap tpmap[2];
					tpmap[0].flag = pmap[idx].flag;
					tpmap[0].begin = aligned_addr;
					tpmap[0].end = pmap[idx].end;
					tpmap[0].size= pmap[idx].size;
					tpmap[0].inode = pmap[idx].inode;
					tpmap[0].foo = pmap[idx].foo;
					(void)strncpy(tpmap[0].perm,
							pmap[idx].perm,
							sizeof(pmap[idx].perm));
					(void)strncpy(tpmap[0].dev,
							pmap[idx].dev,
							sizeof(pmap[idx].dev));
					(void)strncpy(tpmap[0].mapname, "[anon]",
							sizeof("[anon]"));
					if (fill_ve_pmap(tpmap, pvemap, 0)) {
						VEOS_WARN(
								"Record not inserted: %p - %p",
								(void *)tpmap[0].begin,
								(void *)tpmap[0].end);
					}
					pmap[idx].end = aligned_addr;
					break;
				} else {
					flag = 3;
					(void)strncpy(pmap[idx].mapname, "[anon]",
							sizeof("[anon]"));
				}
			} else if (0 > retval) {
				/* Enters if "end" address is invalid */
				if (2 == flag) {
					/* Take this addr as "stack" */
					pmap[idx].end = aligned_addr;
					break;
				}
				if (3 == flag) {
                                        /* Take this addr as "anon" */
                                        pmap[idx].end = aligned_addr;
                                        break;
                                }
			} else {
			}
			aligned_addr += pgsz;
			loop++;
		}
		if ((0 > retval) && (!flag)) ret = -1;
	}
error:
	return ret;
}

/**
 * @brief Initialize memory map of VE process.
 *
 * @param[out] pvemap pointer to _psuedo_pmap(VE).
 * @param[in] pmap pointer to _psuedo_pmap(VH).
 * @param[in] idx index for VE Process memory map.
 *
 * @return On success it return 0 else -1.
 */
int fill_ve_pmap(struct _psuedo_pmap *pmap,
		struct _psuedo_pmap **pvemap, int idx)
{
	psuedo_map *veobj = NULL;
	int ret = 0;

	/* Fill the data in original list */
	veobj =  (*pvemap);
	if (NULL == veobj) {
		veobj =
			(struct _psuedo_pmap *)
			malloc(sizeof(struct _psuedo_pmap));
		if (NULL == veobj) {
			VEOS_DEBUG("Malloc fail,ve_pmap: %s",
					strerror(errno));
			ret = -1;
			goto end;
		}
		/*MEMSET*/
		memset(veobj, '\0', sizeof(struct _psuedo_pmap));
		veobj->flag = 0;
		veobj->begin = pmap[idx].begin;
		veobj->end = pmap[idx].end;
		veobj->inode = pmap[idx].inode;
		veobj->foo = pmap[idx].foo;
		(void)strncpy(veobj->perm, pmap[idx].perm,
				sizeof(veobj->perm));
		(void)strncpy(veobj->dev, pmap[idx].dev,
				sizeof(veobj->dev));
		(void)strncpy(veobj->vmflags, pmap[idx].vmflags,
				sizeof(veobj->vmflags));
		(void)strncpy(veobj->mapname, pmap[idx].mapname,
				sizeof(veobj->mapname));
		veobj->prmsn = get_perm(veobj->perm);
		veobj->next = NULL;
		(*pvemap) = veobj;
	} else {
		while (NULL != veobj->next)
			veobj = veobj->next;
		veobj->next =
			(struct _psuedo_pmap *)
			malloc(sizeof(struct _psuedo_pmap));
		if (NULL == veobj->next) {
			VEOS_DEBUG("Malloc fail,ve_pmap: %s",
					strerror(errno));
			ret = -1;
			goto end;
		}
		/*MEMSET*/
		memset(veobj->next, '\0', sizeof(struct _psuedo_pmap));
		(veobj->next)->flag = 0;
		(veobj->next)->begin = pmap[idx].begin;
		(veobj->next)->end = pmap[idx].end;
		(veobj->next)->inode = pmap[idx].inode;
		(veobj->next)->foo = pmap[idx].foo;
		(void)strncpy((veobj->next)->perm, pmap[idx].perm,
				sizeof((veobj->next)->perm));
		(void)strncpy((veobj->next)->dev, pmap[idx].dev,
				sizeof((veobj->next)->dev));
		(void)strncpy((veobj->next)->vmflags, pmap[idx].vmflags,
				sizeof((veobj->next)->vmflags));
		(void)strncpy((veobj->next)->mapname, pmap[idx].mapname,
				sizeof((veobj->next)->mapname));
		(veobj->next)->prmsn = get_perm((veobj->next)->perm);
		(veobj->next)->next = NULL;
	}
end:
	return ret;
}

/**
 * @brief Validate the heap start and fill VE _psuedo_pmap struct.
 *
 * @param[out] pvemap pointer to _psuedo_pmap(VE).
 * @param[in] task pointer to VE task_struct
 *
 * @return 0 in case of any success else -1.
 */
int insert_heap(struct _psuedo_pmap *pvemap,
		struct ve_task_struct *tsk)
{
	int pgmod = -1;
	int ret = 0;
	struct _psuedo_pmap *ptempobj = NULL;

	if (NULL == pvemap) {
		ret = -1;
		goto end;
	}
	ptempobj = pvemap;

	while (ptempobj != NULL) {
		if (tsk->p_ve_mm->start_brk == ptempobj->begin) {
			pgmod = __veos_get_pgmode(VE_ADDR_VEMVA,
					tsk, ptempobj->begin);
			if (0 > pgmod) {
				ret = -1;
				goto end;
			}

			ret = isheap(ptempobj->begin, tsk, pgmod);
			if (!ret) {
				(void)strncpy(ptempobj->mapname, "[heap]",
						sizeof("[heap]"));
				VEOS_DEBUG("Heap %p - %p, %s, %s",
						(void *)ptempobj->begin,
						(void *)ptempobj->end,
						ptempobj->perm,
						ptempobj->mapname);

			}
		}
		ptempobj = ptempobj->next;
	}
end:
	return ret;
}

/**
* @brief This function will aligned mapping address(start, end) and it will remove
*        entry which are not VE page aligned.
*
* @param[out] pointer to _psuedo_pmap(VE).
* @param[in] tsk pointer to VE task_struct.
* @param[put] veentry ve mapping entry count.
*/
void final_pmap(struct _psuedo_pmap *pvemap,
		struct ve_task_struct *tsk, int *veentry)
{
	struct _psuedo_pmap *curr = NULL;
	struct _psuedo_pmap *prev = NULL;
	size_t pg_sz = 0;
	size_t prev_diff = 0;
	size_t curr_diff = 0;
	int pgmod = 0;
	int counter = 0;

	VEOS_TRACE("invoking");

	if (NULL == pvemap)
		return;

	curr = pvemap;
	prev = NULL;

	while (curr != NULL) {
		VEOS_DEBUG("checking for mapping start(0x%lx) end(0x%lx)",
					curr->begin, curr->end);
		pgmod = __veos_get_pgmode(VE_ADDR_VEMVA,
				tsk, curr->begin);
		if (0 > pgmod) return;
		pg_sz = (size_t)((pgmod == PG_2M) ? PAGE_SIZE_2MB : PAGE_SIZE_64MB);

		/*Aligned starting address*/
		if (!IS_ALIGNED(curr->begin, pg_sz))
			curr->begin =  ALIGN_RD(curr->begin, pg_sz);

		if (!IS_ALIGNED(curr->end, pg_sz))
			curr->end = ALIGN(curr->end, pg_sz);

		VEOS_DEBUG("Aligned start(0x%lx) end(0x%lx)", curr->begin, curr->end);
		if (prev) {
			prev_diff = (size_t)(prev->end - prev->begin);
			curr_diff = (size_t)(curr->end - curr->begin);
			VEOS_DEBUG("prev_diff(0x%lx) curr_diff(0x%lx)", prev_diff, curr_diff);
			if (prev->begin == curr->begin) {
				if (prev_diff < curr_diff) {
					curr->begin = prev->end;
				} else {
					VEOS_DEBUG("removing mapping (0x%lx) map size(0x%lx)",
						curr->begin, curr_diff);
					prev->next = curr->next;
					free(curr);
					counter++;
				}
				curr = prev;
			} else if ((curr->begin > prev->begin) && (curr->begin < prev->end)) {
				curr->begin = prev->end;
				if (prev->end == curr->end) {
					VEOS_DEBUG("removing mapping BEGIN: (0x%lx) END: (0x%lx)",
                                                curr->begin, curr->end);
					prev->next = curr->next;
					free(curr);
					counter++;
				}
				curr = prev;
			} else {
			}
		}
		prev = curr;
		curr = curr->next;

	}
	*veentry -= counter;
	VEOS_TRACE("returning");
}

/**
 * @brief Parse the memory map of pseudo process.
 *
 * @param[out] pvemap pointer to _psuedo_pmap(VE).
 * @param[in] pmap pointer to _psuedo_pmap(VH).
 * @param[in] count number of memory map for VH.
 * @param[in] ve_count number of valid VE memory map
 * @param[in] task pointer to VE task_struct
 *
 * @return number of VE memory map counts.
 */
int parse_psuedopmap(struct _psuedo_pmap *pmap,
		struct _valid_atbdir *pve_dir,
		struct _psuedo_pmap **pvemap,
		int count, int ve_count,
		struct ve_task_struct *tsk)
{
	int indx = 0; /* index to traverse psuedo_map list */
	int nve = 0;
	int isvalid = 0;
	int pgmod = -1;
	struct _psuedo_pmap *ptempobj = NULL;
	struct _valid_atbdir *ptempdir = NULL;

	VEOS_TRACE("In Func");

	ptempdir = pve_dir;
	while (indx < count) {
		pgmod = __veos_get_pgmode(VE_ADDR_VEMVA, tsk,
				pmap[indx].begin);
		if (0 > pgmod) {
			indx++;
			ptempdir = pve_dir;
			continue;
		}
		while(ptempdir != NULL) {
			if ((pmap[indx].begin >=  ptempdir->begin) &&
					(pmap[indx].begin <  ptempdir->end)) {
				if (1 != pmap[indx].flag) {
					pmap[indx].flag = 1;
					if (0 == strcmp(pmap[indx].mapname, "")) {
						isvalid = valid_map_range(pmap,
								pvemap, indx, tsk);
						if (0 > isvalid) {
							VEOS_WARN(
							"Skip Record: %p - %p",
							(void *)pmap[indx].begin,
							(void *)pmap[indx].end);
							indx++;
							ptempdir = pve_dir;
							continue;
						}
					}
					if (fill_ve_pmap(pmap, pvemap, indx)) {
						VEOS_WARN(
						"Record not inserted: %p - %p",
						(void *)pmap[indx].begin,
						(void *)pmap[indx].end);
						indx++;
						ptempdir = pve_dir;
						continue;
					}
					nve++;
				}
				break;
			}
			ptempdir = ptempdir->next;
		}
		indx++;
		ptempdir = pve_dir;
	}

	VEOS_DEBUG("Going to fill the heap");
	ptempobj = *pvemap;
	if (insert_heap(ptempobj, tsk))
		VEOS_DEBUG("No heap");

	ptempobj = *pvemap;
	final_pmap(ptempobj, tsk, &nve);


	ptempobj = *pvemap;
	VEOS_DEBUG("Filter Data:");
	while (ptempobj != NULL) {
		VEOS_DEBUG("%p - %p, %s, %s",
				(void *)ptempobj->begin, (void *)ptempobj->end,
				ptempobj->perm, ptempobj->mapname);
		ptempobj = ptempobj->next;
	}
	VEOS_DEBUG("Out Func %d (ve pmap count)", nve);
	VEOS_TRACE("Out Func");
	return nve;
}



/**
 * @brief Initialize the valid atb directories.
 *
 * @param[out] ve_atb pointer to _valid_atbdir.
 * @param[out] abt pointer to atb_reg_t
 * @param[in] sub subscript of a structure.
 * @param[in] psnum  partial space number
 * @param[in] jid  JID in partial space directory
 * @param[in] page_sz page size of partial space
 *
 * @return number of valid VE memory map.
 */
int parse_valid_atbdir(struct _valid_atbdir **ve_atb,
		atb_reg_t *atb)
{
	int dir_cntr = 0;
	int ve_entry = 0;
	struct _valid_atbdir *atbobj = NULL;

	VEOS_TRACE("In Func");
	atbobj = (*ve_atb);
	for (; dir_cntr < ATB_DIR_NUM; dir_cntr++) {
		if (ps_isvalid(&(atb->dir[dir_cntr]))) {
			if (NULL == atbobj) {
				atbobj = (struct _valid_atbdir *)
					malloc(sizeof(struct _valid_atbdir));
				if (NULL == atbobj) {
					ve_entry = -errno;
					VEOS_DEBUG(
						"Malloc fail: Creating atbdir %s",
							strerror(-ve_entry));
					goto end;
				}
				/*MEMSET*/
				memset(atbobj, '\0', sizeof(struct _valid_atbdir));
				atbobj->pagesize =
					(atb->dir[dir_cntr].data) &
					PAGE_MASK_BIT;
				/* Comparing PAGESIZE 2MB */
				if (2 == atbobj->pagesize) {
					atbobj->begin =
					(uint64_t)((atb->dir[dir_cntr].data)
						& PSN_MASK_2MB);
					atbobj->end = (uint64_t)((atbobj->begin)
						+ ((1 << PSSHFT) * DIR_ENTRIES));
				} /* Comparing PAGESIZE 64MB */
				else if (4 == atbobj->pagesize) {
					atbobj->begin =
					(uint64_t)((atb->dir[dir_cntr].data)
						& PSN_MASK_64MB);
					atbobj->end = (uint64_t)((atbobj->begin)
						+ (((uint64_t)1 << PSSHFT_H) * DIR_ENTRIES));
				}
				atbobj->next = NULL;
				(*ve_atb) = atbobj;
			} else {
				while (NULL != atbobj->next)
					atbobj = atbobj->next;
				atbobj->next = (struct _valid_atbdir *)
					malloc(sizeof(struct _valid_atbdir));
				if (NULL == atbobj->next) {
					ve_entry = -errno;
					VEOS_DEBUG(
					"Malloc fail: Creating atbdir: %s",
							strerror(-ve_entry));
					goto end;
				}
				/*MEMSET*/
				memset(atbobj->next, '\0', sizeof(struct _valid_atbdir));
				(atbobj->next)->pagesize =
					(atb->dir[dir_cntr].data)
					& PAGE_MASK_BIT;
				/* Comparing PAGESIZE 2MB */
				if (2 == (atbobj->next)->pagesize) {
					(atbobj->next)->begin =
						(atb->dir[dir_cntr].data)
						& PSN_MASK_2MB;
					(atbobj->next)->end =
						((atbobj->next)->begin)
						+ ((1 << PSSHFT) * DIR_ENTRIES);
				}  /* Comparing PAGESIZE 64MB */
				else if (4 == (atbobj->next)->pagesize) {
					(atbobj->next)->begin =
						(atb->dir[dir_cntr].data)
						& PSN_MASK_64MB;
					(atbobj->next)->end =
						((atbobj->next)->begin)
						+ (((uint64_t)1 << PSSHFT_H) * DIR_ENTRIES);
				}
				(atbobj->next)->next = NULL;
			}
			ve_entry++;
		}
	}
	atbobj = (*ve_atb);
	while (atbobj != NULL) {
		VEOS_DEBUG("VE_ATBDIR Begin: %lx, End: %lx",
				atbobj->begin, atbobj->end);
		atbobj = atbobj->next;
	}
end:
	VEOS_DEBUG("Out Func: %d (Number of ve_entries)", ve_entry);
	VEOS_TRACE("Out Func");
	return ve_entry;
}

/**
 * @brief Read the pmap of pseduo process from file
 * and Initialize the memory map for it.
 *
 * @param[out] pmap to _psuedo_pmap.
 * @param[in] pid process ID to pseduo.
 *
 * @return the number of entries in psuedo pmap.
 */
int fill_maps(struct _psuedo_pmap **pmap,
		pid_t pid)
{
	char fname[PATH_MAX] = {0};
	FILE *fptr = NULL;
	int ret = 0;
	int nentry = 1, nfields = 0;
	psuedo_map *head = NULL;
	psuedo_map *free_pmap = NULL;
	char buf[PATH_MAX] = {0};

	VEOS_DEBUG("Func: fill_maps() From /proc/pid/maps");

	(void)sprintf(fname, "/proc/%ld/smaps", (long)pid);
	fptr = fopen(fname, "r");
	if (!fptr) {
		ret = -errno;
		VEOS_DEBUG("Fopen fails:%s: %s", fname, strerror(-ret));
		nentry = ret;
		goto end1;
	}

	while (!feof(fptr)) {
		if (0 == fgets(buf, sizeof(buf), fptr))
			break;
		/* Here 'i' denotes the number lines read from file in a loop.
		 * memory is allocated as per count of 'i'.
		 * 'i-1' is used to write the data in the start of a block.
		 * Data read from file is written in allocated block.
		 * */
		free_pmap = *pmap;
		head = (*pmap) = (psuedo_map *)(void *)realloc(*pmap,
				sizeof(psuedo_map) * nentry);
		if (NULL == head) {
			ret = -errno;
            if (free_pmap) {
                free(free_pmap);
                free_pmap = NULL;
            }
			VEOS_DEBUG("%s: %s",
					"Realloc fail: Parsing pmap file",
					strerror(-ret));
			nentry = ret;
			goto end;
		}
		(*pmap) = (psuedo_map *)((char *)(*pmap) +
				(sizeof(psuedo_map) * (nentry-1)));
		(*pmap)->mapname[0] = '\0';
		nfields = sscanf(buf, "%lx-%lx %4s %lx %5s %ld %s",
				&(*pmap)->begin,
				&(*pmap)->end,
				(*pmap)->perm,
				&(*pmap)->foo,
				(*pmap)->dev,
				&(*pmap)->inode,
				(*pmap)->mapname);
		if (nfields == 0) {
			(*pmap) = head;
			continue;
		}
		do {
			memset(buf, 0, sizeof buf);
			if (0 == fgets(buf, sizeof(buf), fptr))
				break;
			nfields = sscanf(buf, "VmFlags: %[a-z ]", (*pmap)->vmflags);
		} while (nfields == 0);

		(*pmap)->flag = 0;
		(*pmap)->prmsn = 0;
		(*pmap) = head;
		nentry++;
		memset(buf, 0, sizeof buf);
	}
	/* To get the end of list, Last block is marked as zero */
	free_pmap = *pmap;
	(*pmap) = (psuedo_map *)realloc((*pmap), sizeof(psuedo_map)*nentry);
	if (!*pmap) {
        ret = -errno;
        if (free_pmap) {
            free(free_pmap);
            free_pmap = NULL;
        }
		VEOS_DEBUG("%s: %s", "Realloc fail: Parsing pmap file",
				strerror(-ret));
		nentry = ret;
		goto end;
	}
	((psuedo_map *)((char *)(*pmap) +
		(sizeof(psuedo_map) * (nentry-1))))->begin = 0;


	struct _psuedo_pmap *pseudo_info = NULL;
	pseudo_info = *pmap;
	while ((*pmap)->begin != 0) {
		VEOS_DEBUG("%lx-%lx %s %lx %s %ld %s %s",
				(*pmap)->begin, (*pmap)->end, (*pmap)->perm,
				(*pmap)->foo, (*pmap)->dev, (*pmap)->inode,
				(*pmap)->mapname, (*pmap)->vmflags);
		(*pmap) = (psuedo_map *)((char *)(*pmap) +
				(sizeof(psuedo_map)));
	}
	*pmap = pseudo_info;
end:
	fclose(fptr);
end1:
	return nentry;
}

/**
 * @brief Get the VE pmap form psuedo process pmap.
 *
 * @param[out] pvemap pointer to _psuedo_pmap.
 * @param[in] task is the pointer to ve_task_struct.
 *
 * @return number of ve pmap count from pseudo pmap.
 */
int get_vepmap(struct _psuedo_pmap **pvemap,
		struct ve_task_struct *tsk)
{
	psuedo_map *pmap = NULL;
	valid_atbdir *pve_atb = NULL;
	valid_atbdir *temp_atb = NULL;
	int nentry = 0;
	int ve_entry = 0;
	int nve = 0;

	VEOS_TRACE("In Func");
	nentry = fill_maps(&pmap, tsk->pid);
	if (0 >= nentry) {
		VEOS_DEBUG("No entries in psuedo pmap");
		nve = nentry;
		goto end;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	ve_entry = parse_valid_atbdir(&pve_atb, &tsk->p_ve_mm->atb);
	if (0 >= ve_entry) {
		VEOS_DEBUG("No valid atb directories");
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK,	"Failed to release thread-group-mm-lock");
		nve = ve_entry;
		goto end;
	}

	nve = parse_psuedopmap(pmap, pve_atb, pvemap, nentry, ve_entry, tsk);
	if (0 >= nve) {
		VEOS_DEBUG("No ve pmap from pseudo pmap");
		pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
				UNLOCK,	"Failed to release thread-group-mm-lock");
		goto end;
	}
	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			UNLOCK,	"Failed to release thread-group-mm-lock");
	VEOS_DEBUG("VE PMAP DONE");
end:
	if (pmap)
		free(pmap);
	while (pve_atb != NULL) {
		temp_atb = pve_atb;
		pve_atb = pve_atb->next;
		free(temp_atb);
	}
	VEOS_TRACE("Out Func");
	return nve;
}
