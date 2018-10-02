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
 * @file cr_api.c
 * @brief This file contains all required defination of cr management related function.
 *
 * @internal
 * @author AMM
 */
#include <string.h>
#include <stdlib.h>
#include "ve_mem.h"
#include "libved.h"
#include "mm_type.h"
#include "cr_api.h"


/**
* @brief This simple func to compaire to elements.

* @param[in] a first element.
* @param[in] b second element.
*
* @return 0 if both element are equal, -1 if a is small,
*			1 if a is greater,
*
*/
int cmp_func(const void *a, const void *b)
{
	return (*(int *)a - *(int *)b);
}


/**
 * @brief This function will give free cr page count.
 *
 * @param[in] vnode ref to node struct.
 *
 * @return This function will return free cr page count.
 */
int get_free_cr_count(struct ve_node_struct *vnode)
{
	int idx = 0;
	int count = 0;

	for (idx = 0; idx < MAX_CR_PAGE_PER_NODE; idx++) {
		if (vnode->cr_map[idx] == false)
			++count;
	}

	return count;
}


/**
* @brief This function will dump content of perticular CR cluster.
*
* @param[in] file name of dump file.
* @param[in] cr_cluster_no CR cluster Number.
*
* @return return 0 on success and negative of errno on failure.
*
*/
#ifdef __CR_DBG
int amm_dump_cr_reg_process(char *file, int cr_cluster_no)
{
	cr_cluster_t *cr_arr = NULL;
	vedl_handle *handle = VE_HANDLE(0);
	int cr_reg_no = 0;
	int ret = 0;
	off_t offset = VE_CR_CLUSTER_OFF(cr_cluster_no);
	FILE *fp = NULL;
	system_common_reg_t *to = VE_CORE_CNT_REG_ADDR(0);

	VEOS_TRACE("invoked to dump CR cluster %d in file %s",
		cr_cluster_no, file);


	fp = fopen(file, "a+");
	if (NULL == fp) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) in open file %s",
			strerror(-ret), file);
		return ret;
	}

	cr_arr = (cr_cluster_t *)calloc(1, sizeof(cr_cluster_t));
	if (NULL == cr_arr) {
		ret = -errno;
		VEOS_CRIT("Error (%s) while allocating CR cluster object",
				 strerror(-ret));
		return ret;
	}

	ret = vedl_get_cnt_reg_words(handle, to, offset,
			cr_arr, sizeof(cr_cluster_t));
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in getting CR cluster from H/W",
				strerror(-ret));
		free(cr_arr);
		veos_abort("Error while getting cr attribute");
	}
	fprintf(fp, "CR_CLUSTER : %d Dumping Start ....\n",
			cr_cluster_no);
	for (cr_reg_no = 0; cr_reg_no < CR_REG_PER_PAGE; cr_reg_no++) {
		fprintf(fp, "CR_CLUSTER[%d][%d] : %lx\n",
			cr_cluster_no, cr_reg_no,
			cr_arr[0].data[cr_reg_no]);
	}
	fprintf(fp, "CR_CLUSTER : %d Dumping End ....\n",
		cr_cluster_no);

	free(cr_arr);
	fclose(fp);
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function will dump content of all CR cluster.
*
* @param[in] filename Dump file name.
*
* @return return 0 on success and negative of errno on failure.
*/
int amm_dump_cr_reg_node(char *filename)
{
	cr_cluster_t cr_arr[32] = {0};
	vedl_handle *handle = VE_HANDLE(0);
	int cr_cluster_no = 0;
	int cr_reg_no = 0;
	int ret = 0;
	off_t offset = VE_CR_CLUSTER_OFF(0);
	FILE *fp = NULL;
	system_common_reg_t *to = VE_CORE_CNT_REG_ADDR(0);

	VEOS_TRACE("invoked with %s", filename);


	fp = fopen(filename, "a+");
	if (NULL == fp) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) in open file %s",
			strerror(errno), filename);
		return ret;
	}

	ret = vedl_get_cnt_reg_words(handle, to, offset,
			cr_arr, sizeof(cr_arr));
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) in getting CR cluster from H/W",
				strerror(-ret));
		veos_abort("Error while getting CR cluster");
	}

	for (cr_cluster_no = 0; cr_cluster_no <
			MAX_CR_PAGE_PER_NODE; cr_cluster_no++) {
		for (cr_reg_no = 0; cr_reg_no <
				CR_REG_PER_PAGE; cr_reg_no++) {
			if (cr_arr[cr_cluster_no].data[cr_reg_no]) {
				fprintf(fp, "CR_CLUSTER[%d][%d] : %lx\n",
				cr_cluster_no, cr_reg_no,
				cr_arr[cr_cluster_no].data[cr_reg_no]);
			}
		}
	}

	fclose(fp);
	VEOS_TRACE("returned with %d", ret);
	return ret;
}
#endif

/**
* @brief This function will  initializes all cr reg.
*
* @return return 0 on success and negative of errno on failure.
*/
int amm_init_cr_reg(void)
{
	int ret = 0;
	cr_cluster_t cr_arr[32] = { { {CR_INIT_VAL}, {CR_INIT_VAL} } };
	vedl_handle *handle = VE_HANDLE(0);
	off_t offset = VE_CR_CLUSTER_OFF(0);
	system_common_reg_t *to = VE_CORE_CNT_REG_ADDR(0);

	VEOS_TRACE("invoked");

	memset(cr_arr, 0, sizeof(cr_arr));
	ret = vedl_set_cnt_reg_words(handle, to, offset,
			cr_arr, sizeof(cr_arr));
	if (ret < 0) {
		VEOS_DEBUG("Failed in initializing CR cluster to zero.");
		veos_abort("Fail to initialize cr data");
	}

	VEOS_TRACE("retured(%d)", ret);
	return ret;
}

/**
* @brief This function will set rlimit either for node or process.
* @param[in] pid_t pid of process/ -1 for node.
* @param[in] thread_lim cr_thread_page limit.
* @param[in] mpi_lim cr_mpi_page limit.
*
* @return return 0 on success and negative of errno on failure.
*/
int set_cr_rlimit(pid_t pid, uint64_t uid, int thread_lim, int mpi_lim)
{
	int ret = 0;
	struct ve_task_struct *tsk = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *mm = NULL;

	VEOS_TRACE("invoked to change CR limits with thread(%d):for"
			"uid(%ld) thread_lim (%d) mpi_lim (%d)",
			pid, uid, thread_lim, mpi_lim);
	if (uid != getuid()) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) to set cr rlimit", strerror(-ret));
		return ret;
	}

	if ((thread_lim + mpi_lim) > MAX_CRD_PER_CORE) {
		VEOS_DEBUG("CR limits exceeds current limit");
		ret = -EINVAL;
		return ret;
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");

	if (pid == -1) {
		VEOS_DEBUG("Setting CR limit for node");
		vnode->node_cr_rlim->cr_th_pg_mx = thread_lim;
		vnode->node_cr_rlim->cr_mpi_pg_mx = mpi_lim;
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Failed to release node cr lock");
		return ret;
	}
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while serching pid (%d)",
				strerror(-ret), pid);
		return ret;
	}
	mm = tsk->p_ve_mm;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	if (mm->p_cr_rlim->cr_th_pg_mx > thread_lim) {
		VEOS_DEBUG("Can't modify CR_THREAD PAGE LIM for pid %d",
				pid);
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		ret = -EINVAL;
		goto err_return;
	}
	/*Setting cr rlim for process*/
	mm->p_cr_rlim->cr_th_pg_mx = thread_lim;
	mm->p_cr_rlim->cr_th_pg_mx = mpi_lim;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
err_return:
	put_ve_task_struct(tsk);

	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function will dump all CR related node specific or process specific information.
*	   if tsk is NULL it will dump node specific data.
*	   else it will dump process specific data.
* @param[in] tsk reference to the process task struct.
* @param[in] mode_flag flag specifying cr page type VE_CR_THREAD/VE_CR_MPI.
* @return zero on success and negative of errno on failure.
*/
int veos_dump_cr(struct ve_task_struct *tsk, uint64_t mode_flag)
{
	int cr_pgnum = 0;
	int crd_num, ret = 0;
	/*FILE *fp  = stdout;*/
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *mm = NULL;
	/*char *filename;*/

	VEOS_TRACE("invoked");
	if (!vnode->node_cr_rlim) {
		VEOS_DEBUG("no dump information available");
		return 0;
	}

	if (tsk) {
		mm = tsk->p_ve_mm;
		/*filename = tsk->p_ve_mm->cr_dump_fname;*/
	} else {
		/*filename = vnode->cr_dump_fname;*/
	}
#if 0
	fp = fopen(filename, "a+");
	if (NULL == fp) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) in open file %s", strerror(-ret),
				filename);
		return ret;
	}
#endif
	if (!tsk) {
		VEOS_DEBUG("==================== CR NODE DUMP =======================");
		VEOS_DEBUG("NODE CR THREAD PAGE MAX : %d",
			vnode->node_cr_rlim->cr_th_pg_mx);
		VEOS_DEBUG("NODE CR MPI PAGE MAX    : %d",
			vnode->node_cr_rlim->cr_mpi_pg_mx);
		VEOS_DEBUG("NODE CR PAGE MAX        : %d",
			vnode->node_cr_rlim->cr_pg_mx);
		VEOS_DEBUG("---------------------------------------------------------");
		VEOS_DEBUG("CLUSTER NO    CR REG OFF    PAGE TYPE    REF COUNT   USER");
		VEOS_DEBUG("---------------------------------------------------------");

		switch ((mode_flag & VE_CR_THREAD) ? THREAD :
				((mode_flag & VE_CR_MPI) ? MPI : ALL)) {
		case THREAD:
		for (cr_pgnum = 0; cr_pgnum <
				MAX_CR_PAGE_PER_NODE; cr_pgnum++) {
			if ((mode_flag & VE_CR_THREAD)
				&& (vnode->ve_cr_pages[cr_pgnum].
				page_attr & VE_CR_THREAD)){
				VEOS_DEBUG("CR_CLUSTER[%2d]%10d%15s%10ld%10d",
				cr_pgnum, cr_pgnum, "VE_CR_THREAD",
				vnode->
				ve_cr_pages[cr_pgnum].ref_count,
				(vnode->
				ve_cr_pages[cr_pgnum].tsk != NULL) ?
				vnode->
				ve_cr_pages[cr_pgnum].tsk->pid : -1);
			}

		}
		VEOS_DEBUG("---------------------------------------------------------");
		break;
		case MPI:
		for (cr_pgnum = 0; cr_pgnum <
				MAX_CR_PAGE_PER_NODE; cr_pgnum++) {
			if ((mode_flag & VE_CR_MPI)
				&& (vnode->ve_cr_pages[cr_pgnum].
				page_attr & VE_CR_MPI)){
				VEOS_DEBUG("CR_CLUSTER[%2d]%10d%15s%10ld%10d",
				cr_pgnum, cr_pgnum, "VE_CR_MPI",
				vnode->ve_cr_pages[cr_pgnum].ref_count,
				(vnode->ve_cr_pages[cr_pgnum].tsk != NULL) ?
				vnode->ve_cr_pages[cr_pgnum].tsk->pid : -1);
			}
		}
		break;
		VEOS_DEBUG("---------------------------------------------------------");
		case ALL:
		for (cr_pgnum = 0; cr_pgnum <
				MAX_CR_PAGE_PER_NODE; cr_pgnum++) {
			if (vnode->cr_map[cr_pgnum] == true) {
				VEOS_DEBUG("CR_CLUSTER[%2d]%10d%15s%10ld%10d",
				cr_pgnum, cr_pgnum,
				(vnode->ve_cr_pages[cr_pgnum].page_attr &
				VE_CR_THREAD) ? "VE_CR_THREAD" : "VE_CR_MPI",
				vnode->ve_cr_pages[cr_pgnum].ref_count,
				(vnode->ve_cr_pages[cr_pgnum].tsk != NULL) ?
				vnode->ve_cr_pages[cr_pgnum].tsk->pid : -1);
			} else {
				VEOS_DEBUG("......... CR PAGE IS FREE .........");
			}
		}
		VEOS_DEBUG("---------------------------------------------------------");
		break;
		default:
		break;
	}
#if 0
		VEOS_DEBUG("---------------------------------------------------------");
		fclose(fp);
		ret = amm_dump_cr_reg_node(vnode->cr_dump_fname);
		if (0 > ret) {
			VEOS_DEBUG("Error (%s) while dumping node cr data",
					strerror(-ret));
			return ret;
		}
#endif
		VEOS_DEBUG("Total thread cr page allocated (%u)", vnode->cr_th_pg);
		VEOS_DEBUG("Total mpi cr  page allocated   (%u)", vnode->cr_mpi_pg);
		VEOS_DEBUG("---------------------------------------------------------");
	} else {
		VEOS_DEBUG("==================== CR PROC DUMP =======================");
		VEOS_DEBUG("PROCESS IDENTIFIER      : %d",
			tsk->group_leader->pid);
		VEOS_DEBUG("PROCESS CR THREAD PAGE MAX : %d",
			mm->p_cr_rlim->cr_th_pg_mx);
		VEOS_DEBUG("PROCESS CR MPI PAGE MAX    : %d",
			mm->p_cr_rlim->cr_mpi_pg_mx);
		VEOS_DEBUG("PROCESS PAGE MAX        : %d",
			mm->p_cr_rlim->cr_pg_mx);
		VEOS_DEBUG("---------------------------------------------------------");
		VEOS_DEBUG("     CR PAGE NO    PAGE TYPE     REF COUNT      CRD");
		VEOS_DEBUG("---------------------------------------------------------");
		for (crd_num = 0; crd_num < MAX_CRD_PER_CORE; crd_num++) {
			if (crdisvalid(&mm->crd[crd_num])) {
				cr_pgnum = cr_getpg(&mm->crd[crd_num]);
				VEOS_DEBUG("%10d%18s%10ld%12d", cr_pgnum,
					((vnode->ve_cr_pages[cr_pgnum].
					page_attr & VE_CR_THREAD) ?
						"VE_CR_THREAD" : "VE_CR_MPI"),
					vnode->ve_cr_pages[cr_pgnum].
							ref_count, crd_num);
				} else {
					VEOS_DEBUG("%10c%18c%10c%12d",
					'-', '-', '-', crd_num);
				}

		}
		VEOS_DEBUG("---------------------------------------------------------");
#if 0
		VEOS_DEBUG("---------------------------------------------------------");
		fclose(fp);
		for (crd_num = 0; crd_num < MAX_CRD_PER_CORE; crd_num++) {
			if (crdisvalid(&mm->crd[crd_num])) {
				cr_pgnum = cr_getpg(&mm->crd[crd_num]);
				ret = amm_dump_cr_reg_process
					(tsk->p_ve_mm->cr_dump_fname,
						cr_pgnum);
				if (0 > ret) {
					VEOS_DEBUG("Error (%s) while dump_cr",
							strerror(-ret));
					return ret;
				}
			}
		}
#endif
	}
	VEOS_DEBUG("%u CR thread page requested from node",
			vnode->cr_th_req);
	VEOS_TRACE("returned with %d", ret);
	return 0;
}

/**
* @brief This function will set CRD entry in core CRD h/w
*
* @param[in] crd s/w image of CRD.
* @param[in] crd_entry CRD entry number to set To set all
*		entries 'crd_entry' will be zero.
* @param[in] core_id core identifier of process.
* @param[in] size size of crd entries.
*
* @return return 0 on success and negative of errno on failure.
*/
int amm_set_crd(crd_t *crd, int crd_entry, int core_id, size_t size)
{
	int ret = 0;
	vedl_handle *handle = VE_HANDLE(0);

	VEOS_TRACE("invoked with crd (%p) crd_entry (%d) core (%d) size(%ld)",
			crd, crd_entry, core_id, size);

	off_t offset = VE_CRD_OFF(crd_entry); /*Offset of CRD*/;
	core_system_reg_t *to = VE_CORE_SYS_REG_ADDR(0, core_id);

	ret = vedl_set_sys_reg_words(handle, to, offset,
				&crd[crd_entry], size);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) to set crd crd entry",
				strerror(-ret));
	}
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function will allocated memory for cr related data.
*
* @param[in] vnode ref to the node structure.
*
* @return return 0 on success and negative of errno on failure.
*/
int amm_init_node_cr_data(struct ve_node_struct *vnode)
{
	int ret = 0, idx = 0;

	VEOS_TRACE("invoked");

	vnode->ve_cr_pages  = (struct ve_cr_page *)malloc
				((sizeof(struct ve_cr_page)
					* MAX_CR_PAGE_PER_NODE));
	if (vnode->ve_cr_pages == NULL) {
		VEOS_DEBUG("memory allocation for struct ve_cr_page failed");
		return -1;
	}
	/*CR node dump file name*/
	sprintf(vnode->cr_dump_fname, "/tmp/cr_dump_node_%d", 0);

	memset(vnode->ve_cr_pages, '\0',
		sizeof(struct ve_cr_page) * MAX_CR_PAGE_PER_NODE);

	vnode->node_cr_rlim = (struct ve_cr_rlim *)malloc(sizeof(struct ve_cr_rlim));
	if (vnode->node_cr_rlim == NULL) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) for allcating memory for node cr limit",
				strerror(-ret));
		free(vnode->ve_cr_pages);
		return ret;
	}

	memset(vnode->node_cr_rlim, 0, sizeof(struct ve_cr_rlim));

	for (idx = 0; idx < MAX_CRD_PER_CORE; idx++)
		vnode->cr_map[idx] = false;

	/*Set CR Node limit*/
	vnode->node_cr_rlim->cr_th_pg_mx = 1;
	vnode->node_cr_rlim->cr_pg_mx = 4;
	vnode->node_cr_rlim->cr_mpi_pg_mx = (vnode->node_cr_rlim->cr_pg_mx -
			vnode->node_cr_rlim->cr_th_pg_mx);

	VEOS_TRACE("returning");
	return 0;
}

/**
 * @brief This function check whether cdr is available or not
 *			according to cr_rlimit set is node/task struct.
 * @param[in] node_cr_rlim max limit of cr pages(THREAD/MPI) for node
 * @param[in] p_cr_rlim max limit of cr pages(THREAD/MPI) for process.
 * @param[in] t_cr_pg total cr pages allocated by process.
 *
 * @return return 0 on success and -1 on failure.
 */
int val_cra(int node_cr_rlim,
		int p_cr_rlim, int t_cr_pg)
{
	int ret = -1;

	VEOS_TRACE("invoked with node_cr_rlim (%d)proc_cr_rlim(%d) to_page(%d)",
			node_cr_rlim, p_cr_rlim, t_cr_pg);

	if (IS_EQUAL(int, node_cr_rlim, p_cr_rlim)) {
		if (!IS_EQUAL(int, t_cr_pg, p_cr_rlim)) {
			VEOS_TRACE("returned with %d", ret);
			return ret;
		}
	} else {
		if (!IS_EQUAL(int, t_cr_pg, node_cr_rlim)) {
			VEOS_TRACE("returned with %d", ret);
			return ret;
		}
	}

	ret = 0;
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
 * @brief This function will update ve_cr_page attributes.
 *
 * @param[in] vnode reference to ve_node_struct
 *
 * @param[in] mode_flag mode flag (VE_CR_THERAD/ VE_CR_MPI).
 * @param[in] cr_pg cr page number.
 * @param[in] crd crd number.
 * @param[in] tsk reference to task struct.
 */
void update_ve_cr_page(struct ve_node_struct *vnode, uint64_t mode_flag,
	int cr_pg, struct ve_task_struct *tsk)
{
	VEOS_TRACE("invoked with mode (%ld) cr_pg (%d) pid  (%d)",
			mode_flag, cr_pg, tsk->pid);

	vnode->ve_cr_pages[cr_pg].page_attr = mode_flag;
	vnode->ve_cr_pages[cr_pg].tsk = tsk;
	vnode->ve_cr_pages[cr_pg].cr_page_no = (uint64_t)cr_pg;

	VEOS_TRACE("returned");
}

/**
 * @brief This function will increase/decrease reference count according to 'atomic_op' flag.
 * @param[in] cr_pg cr page number.
 * @param[in] atomic_op flag indicating whether to inc/dec ref count.
 *	      If set to GET_PAGE it will increament ref count else it will decreament the ref count.
 *
 * @return return 0 on success and negative of errno on failure.
 */
int common_get_put_cr_page(int cr_pg, int atomic_op)
{
	int ret = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	VEOS_TRACE("invoked");

	VEOS_DEBUG("CR page(%d) and get/put operation(%d)",
			cr_pg, atomic_op);

	VEOS_DEBUG("CR page(%d) refcnt before atomic %s %d", cr_pg,
			(atomic_op & GET_PAGE) ? "inc" : "dec",
			(int)vnode->ve_cr_pages[cr_pg].ref_count);

	if (atomic_op & GET_PAGE) {
		__sync_fetch_and_add(&vnode->
			ve_cr_pages[cr_pg].ref_count, 1);
	} else {
		if (vnode->ve_cr_pages[cr_pg].ref_count) {
			__sync_fetch_and_sub(&vnode->
					ve_cr_pages[cr_pg].ref_count, 1);
			if (!vnode->ve_cr_pages[cr_pg].ref_count) {
				ret =  veos_free_cr_page(cr_pg);
				if (0 > ret) {
					VEOS_DEBUG("Error (%s) while veos_free_cr_page",
							strerror(-ret));
					return ret;
				}
			}

		}
	}

	VEOS_DEBUG("CR page(%d) refcnt after atomic %s %d", cr_pg,
			(atomic_op & GET_PAGE) ? "inc" : "dec",
			(int)vnode->ve_cr_pages[cr_pg].ref_count);

	VEOS_TRACE("returned with %d", ret);
	return ret;
}
/**
 * @brief This function will initialize ve process specific CR data.
 *
 * @param[in] tsk task struct of ve_process.
 *
 * @return return 0 on success and negative of errno of failure.
 */
int amm_alloc_cr_data(struct ve_mm_struct *mm)
{
	struct ve_node_struct *vnode = VE_NODE(0);
	int crd_num, ret = 0;
	int idx = 0;

	VEOS_TRACE("invoked");

	/*Allocating memory for cr directory size to updated*/
	if (NULL !=  mm->crd) {
		VEOS_DEBUG("Error crd's are already allocated to task");
		ret = -EINVAL;
		return ret;
	}

	mm->crd = (crd_t *)calloc(MAX_CRD_PER_CORE, sizeof(crd_t));
	if (NULL ==  mm->crd) {
		ret = -errno;
		VEOS_CRIT("Error (%s) while allocating crd entries",
				strerror(-ret));
		return ret;
	}

	/*Invalidate All CRD*/
	for (crd_num = 0; crd_num <
			MAX_CRD_PER_CORE; crd_num++) {
		VEOS_DEBUG("Invalidating task crd entry %d", crd_num);
		setcrdinvalid(&mm->crd[crd_num]);
		VEOS_DEBUG("crd %d contents 0x%lx",
			crd_num, mm->crd[crd_num].data);
	}

	/*Allocate memory for cr page accounting data*/
	mm->tsk_cr_pg_acc = (struct tsk_cr_pg *)
		calloc(1, sizeof(struct tsk_cr_pg));
	if (NULL == mm->tsk_cr_pg_acc) {
		ret = -errno;
		VEOS_CRIT("Error (%s) while allocating memory for tsk cr page object",
				strerror(-ret));
		free(mm->crd);
		return ret;
	}

	mm->p_cr_rlim = (struct ve_cr_rlim *)calloc(1, sizeof(struct ve_cr_rlim));
	if (NULL == mm->p_cr_rlim) {
		ret = -errno;
		VEOS_CRIT("Error (%s) while allocating memory for cr rlimit obj",
				strerror(-ret));
		free(mm->crd);
		free(mm->tsk_cr_pg_acc);
		return ret;
	}
	/*Set Process cr rlimits*/
	memcpy(mm->p_cr_rlim, vnode->node_cr_rlim, sizeof(struct ve_cr_rlim));

	/*Clear cr data*/
	memset(mm->cr_data, 0, (sizeof(cr_cluster_t) * MAX_CRD_PER_CORE));

	/* This flags are used to take decision
	 * whether allocated crd is thred type or mpi type*/
	for (; idx < MAX_CRD_PER_CORE; idx++)
		mm->crd_type[idx] = NONE;

	mm->is_sched = true;

	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
 * @brief This function will free all cr related data.
 *
 * @param[in] tsk current process Task struct.
 */
void amm_free_cr_data(struct ve_mm_struct *mm)
{
	int crd_num = -1;
	int cr_pgnum = -1;
	struct ve_node_struct *vnode = VE_NODE(0);

	if (mm == NULL)
		return;

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");
	VEOS_TRACE("invoked");

	 /*Here we will decreament
	  *the ref count of cr Page*/
	 VEOS_DEBUG("freeing tsk CR allocations");
	 for (crd_num = 0; crd_num < MAX_CRD_PER_CORE; crd_num++) {
		 if (crdisvalid(&mm->crd[crd_num])) {
			 cr_pgnum = cr_getpg(&mm->crd[crd_num]);
			 veos_put_cr_page(cr_pgnum);
		 }
		 if ((mm->crd_type[crd_num] == THREAD) ||
				 (mm->crd_type[crd_num] == DELAYED)) {
			 if (vnode->cr_th_req)
				 vnode->cr_th_req--;
		 }
		 mm->crd_type[crd_num] = NONE;
		 VEOS_DEBUG("crd(%d) is not allocated", crd_num);
	 }

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
	VEOS_DEBUG("currently %u thread CR page requested",
			vnode->cr_th_req);
	VEOS_DEBUG("tsk CR allocations are freed");

	free(mm->crd);
	mm->crd = NULL;

	 /*free task cr page accountability data*/
	free(mm->tsk_cr_pg_acc);
	mm->tsk_cr_pg_acc = NULL;
	free(mm->p_cr_rlim);

	VEOS_TRACE("returned");
}

/**
* @brief This function is used to allocate CR pages for the requesting VE process.
*
* @modeflag[in] type of cr page(VE_CR_THREAD/VE_CR_MPI).
*
* @return On success returns CR page number and negative of errno on failure.
*/
int veos_get_free_cr_page(uint64_t modeflag)
{
	int idx = 0;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked");

	for (idx = 0; idx < MAX_CR_PAGE_PER_NODE; idx++) {
		if (vnode->cr_map[idx] == false) {
			vnode->cr_map[idx] = true;
			/*Set bit for free CR page*/
			VEOS_DEBUG("cr page no %d is free to use", idx);
			break;
		}
	}
	if (idx == MAX_CR_PAGE_PER_NODE) {
		VEOS_ERROR("no cr page is free");
		return -ENOMEM;
	}
	if (modeflag == VE_CR_THREAD)
		vnode->cr_th_pg++;
	else
		vnode->cr_mpi_pg++;

	VEOS_DEBUG("thread cr cnt(%u) and mpi cr cnt(%u)",
		vnode->cr_th_pg, vnode->cr_mpi_pg);
	VEOS_TRACE("returned");
	return idx;
}

/**
* @brief This function is used to allocate CR pages for the requesting VE process.
*
* @param[in] mode_flag This flag specifies attribute (VE_CR_THREAD or VE_CR_MPI) of CR page.
*
* @param[in] pid This is “pid” of the VE process for which the CR page to allocate.
*
* @return On success returns CR directory number and negative of errno is returned on failure.
*/
int veos_allocate_cr_page(uint64_t mode_flag, pid_t pid)
{
	int crd_num = -1;
	int ret = 0;
	int cr_pg = -1;
	crd_t crd_tmp[MAX_CRD_PER_CORE] = { {0} };
	struct ve_task_struct *tsk = NULL;
	struct ve_mm_struct *mm = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);

	VEOS_TRACE("invoked to alloc (%s) CR page for tsk:pid(%d)",
			mode_flag_to_str(mode_flag), pid);

	if ((!(mode_flag & VE_CR_THREAD) && !(mode_flag & VE_CR_MPI))
		|| (mode_flag == (VE_CR_MPI | VE_CR_THREAD))) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) modeflag(0x%lx)",
			strerror(-ret), mode_flag);
		return ret;
	}

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) for pid (%d)", strerror(-ret), pid);
		return ret;
	}

	mm = tsk->p_ve_mm;

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	/*check limit of allocated cr pages*/
	if (mm->tsk_cr_pg_acc->t_cr_pg == MAX_CRD_PER_CORE) {
		VEOS_ERROR("No free crd available for tsk(%d)", pid);
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		ret = -ENOMEM;
		goto hndl_return;
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");
	if (mode_flag & VE_CR_THREAD) {
		ret = val_cra(vnode->node_cr_rlim->cr_th_pg_mx,
				mm->p_cr_rlim->cr_th_pg_mx,
				mm->tsk_cr_pg_acc->t_th_pg);
		if (0 > ret) {
			VEOS_ERROR("Error (%s) can't allcocate crd for thread",
					strerror(-ret));
			pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
					"Failed to release node cr lock");
			goto err_return;
		}
	} else {
		ret = val_cra(vnode->node_cr_rlim->cr_mpi_pg_mx,
				mm->p_cr_rlim->cr_mpi_pg_mx,
				mm->tsk_cr_pg_acc->t_mpi_pg);
		if (0 > ret) {
			ret = -ENOMEM;
			VEOS_ERROR("Error (%s) can't allocate crd for mpi",
					strerror(-ret));
			pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
					"Failed to release node cr lock");
			goto err_return;
		}
	}

	memcpy(crd_tmp, mm->crd, (sizeof(crd_t) * MAX_CRD_PER_CORE));
	/*find free crd to be allocated.*/
	for (crd_num = 0; crd_num < MAX_CRD_PER_CORE; crd_num++) {
		if (!crdisvalid(&crd_tmp[crd_num]) && (mm->crd_type[crd_num] == NONE))
			break;
	}

	VEOS_DEBUG("tsk(%d) crd %d is free", pid, crd_num);

	/* Decide whether to allocate cr page or not.
	 * If process is sched out on MONC then we will allocated
	 * cr page when process will sched in.*/
	if ((false == mm->is_sched) && (mode_flag & VE_CR_THREAD)) {
		VEOS_DEBUG("Delayed allocation of CR thread page for tsk:pid(%d)",
				tsk->pid);
		cr_pg = -1;
		mm->crd_type[crd_num] = DELAYED;
		mm->tsk_cr_pg_acc->t_th_pg++;
		vnode->cr_th_req++;
	} else {
		VEOS_DEBUG("Instant allocation %s CR"
				"page for tsk:pid(%d)",
				mode_flag_to_str(mode_flag), tsk->pid);
		VEOS_DEBUG("%u cr pages are reserved and %u pages used for mpi",
				tot_cr_res(vnode), vnode->cr_mpi_pg);
		if ((mode_flag & VE_CR_MPI) &&
				((tot_cr_res(vnode) + vnode->cr_mpi_pg) >=
				 MAX_CR_PAGE_PER_NODE)) {
			ret = -ENOMEM;
			VEOS_DEBUG("Instant allocation failed for mpi"
				 "to maintain reserved CR pages");
			pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
					"Failed to release node cr lock");
			goto err_return;
		}

		cr_pg = veos_get_free_cr_page(mode_flag);
		if (0 > cr_pg) {
			VEOS_DEBUG("Error (%s) while getting free_cr_page",
					strerror(-ret));
			ret = cr_pg;
			pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
					"Failed to release node cr lock");
			goto err_return;
		}

		update_ve_cr_page(vnode, mode_flag, cr_pg, tsk);
		common_get_put_cr_page(cr_pg, GET_PAGE);

		if ((mode_flag & VE_CR_THREAD)) {
			if (true == mm->is_sched)
				mm->crd_type[crd_num] = THREAD;
			mm->tsk_cr_pg_acc->t_th_pg++;
			vnode->cr_th_req++;
		} else {
			mm->tsk_cr_pg_acc->t_mpi_pg++;
			mm->crd_type[crd_num] = MPI;
		}
	}

	VEOS_DEBUG("total %d thread page requested from node",
				vnode->cr_th_req);

	VEOS_DEBUG("node CR stat: thread(%d), mpi(%d)",
		vnode->cr_th_pg, vnode->cr_mpi_pg);

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");

	/*first clear cr page number*/
	cr_clearpg(&crd_tmp[crd_num]);

	/*set cr page number in crd*/
	cr_setpg(&crd_tmp[crd_num], cr_pg);

	setcrdvalid(&crd_tmp[crd_num]);
	VEOS_DEBUG("tsk:pid(%d) crd[%u] with val 0x%lx",
			tsk->pid, crd_num, crd_tmp[crd_num].data);

	VEOS_DEBUG("CR page(%d) set to tsk:pid(%d) crd(%u) ",
			cr_pg, tsk->pid, crd_num);
	/*Mark crd as valid*/
	if ((false == mm->is_sched) && (mode_flag & VE_CR_THREAD))
		setcrdinvalid(&crd_tmp[crd_num]);

	memcpy(mm->crd, crd_tmp, (sizeof(crd_t) * MAX_CRD_PER_CORE));

	/*Update Total CR page allocated to process
	and cr Page number for accounting*/
	mm->tsk_cr_pg_acc->t_cr_pg = (mm->tsk_cr_pg_acc->
				t_th_pg + mm->tsk_cr_pg_acc->t_mpi_pg);
	/*sync crd reg(h/w) with updated copy*/
	if (true == mm->is_sched) {
		VEOS_DEBUG("sync tsk:pid(%d) crd(%u) for instant req",
				tsk->pid, crd_num);
		veos_set_crd(tsk, crd_num, 1, false, true);
	}

	ret = crd_num;

	VEOS_DEBUG("tsk:pid(%d) CR stat: thread(%d), mpi(%d)",
		tsk->pid, mm->tsk_cr_pg_acc->t_th_pg,
		mm->tsk_cr_pg_acc->t_mpi_pg);


	veos_dump_cr(tsk, ALL);
err_return:
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
hndl_return:
	put_ve_task_struct(tsk);
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function is used to attach CR pages to the requesting VE process.
*
* @param[in] crd This flag specifies CR directory number of owner process.
* @param[in] owner PID of process which owns the CR page.
* @param[in] req This is “pid” of the VE process to which the CR page to allocate.
*
* @return On success returns valid CR directory number and negative of errno on failure.
*/
int64_t veos_attach_cr_page(uint64_t crd,
			pid_t owner, pid_t req)
{

	int crd_num = -1;
	crd_t crd_tmp[MAX_CRD_PER_CORE] = { {0} };
	int64_t cr_pg = -1, ret = 0;
	struct ve_task_struct *own_tsk = NULL;
	struct ve_task_struct *req_tsk = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *own_mm = NULL;
	struct ve_mm_struct *req_mm = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("req to attach owner(%d) crd(%ld) to requstr(%d)",
			owner, crd, req);

	own_tsk = find_ve_task_struct(owner);
	if (NULL == own_tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) for pid :%d", strerror(-ret), owner);
		return ret;
	}

	req_tsk = find_ve_task_struct(req);
	if (NULL == req_tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) for pid : %d", strerror(-ret),
				req);
		goto err_return;
	}

	own_mm = own_tsk->p_ve_mm;
	req_mm = req_tsk->p_ve_mm;

	pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");
	/*check whether requested CRD is valid or not*/
	if (!crdisvalid(&own_mm->crd[crd]) || (crd > MAX_CRD_PER_CORE)) {
		ret = -EINVAL;
		VEOS_ERROR("Error (%s) crd(%ld) is not valid for tsk:pid(%d)",
				strerror(-ret), crd, owner);
		goto err_own;
	}

	/*Clear all entries from crd_tmp*/
	memset(crd_tmp, 0, sizeof(crd_tmp));
	memcpy(crd_tmp, own_mm->crd, sizeof(crd_tmp));

	/* Get cr_page number from CRD
	 * and check page attributes
	 * if page attribute is VE_CR_THREAD
	 * then this function will failer
	 */
	cr_pg =  cr_getpg(&crd_tmp[crd]);
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Fail to acquire node cr lock");
	if (vnode->ve_cr_pages[cr_pg].page_attr & VE_CR_THREAD) {
		ret = -EINVAL;
		VEOS_DEBUG("Error (%s) attaching crd(%ld) has thread attr set",
			strerror(-ret), crd);
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Fail to release node cr lock");
		goto err_own;
	}

	/*Increament the ref count*/
	common_get_put_cr_page(cr_pg, GET_PAGE);

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Fail to release node cr lock");
	if (own_mm != req_mm) {
		VEOS_DEBUG("Owner and reqestor are different");
		pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		pthread_mutex_lock_unlock(&req_mm->thread_group_mm_lock, LOCK,
				"Failed to acquire thread-group-mm-lock");
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Fail to acquire node cr lock");
	/*check whether all directories used or not*/
	if (req_mm->tsk_cr_pg_acc->t_cr_pg == MAX_CRD_PER_CORE) {
		VEOS_DEBUG("No crd is free for reqtsk:pid(%d)",
				req_tsk->pid);
		common_get_put_cr_page(cr_pg, PUT_PAGE);
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Fail to release node cr lock");
		ret = -ENOMEM;
		goto err_req;
	}


	/*validate this allocation*/
	ret = val_cra(vnode->node_cr_rlim->cr_mpi_pg_mx,
			req_mm->p_cr_rlim->cr_mpi_pg_mx,
		req_mm->tsk_cr_pg_acc->t_mpi_pg);
	if (0 > ret) {
		ret = -ENOMEM;
		VEOS_DEBUG("Error (%s) req:pid(%d) can't attach mpi cr page",
				strerror(-ret), req_tsk->pid);
		common_get_put_cr_page(cr_pg, PUT_PAGE);
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Fail to release node cr lock");
		goto err_req;
	}

	VEOS_DEBUG("total %d thread page requested from node",
			vnode->cr_th_req);

	VEOS_DEBUG("node CR stat: thread(%d), mpi(%d)",
			vnode->cr_th_pg, vnode->cr_mpi_pg);
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Fail to release node cr lock");
	/*Clear all entries from crd_tmp*/
	memset(crd_tmp, 0, sizeof(crd_tmp));

	/*Get s/w image of req*/
	memcpy(crd_tmp, req_mm->crd, sizeof(crd_tmp));

	/*find free CRD*/
	for (crd_num = 0; crd_num < MAX_CRD_PER_CORE; crd_num++) {
		if (!crdisvalid(&crd_tmp[crd_num]) && (req_mm->crd_type[crd_num] == NONE))
			break;
	}

	VEOS_DEBUG("crd(%d) free to attach CR page(%ld) to tsk:pid(%d)",
			crd_num, cr_pg, req_tsk->pid);
	/*Clear previous page number*/
	cr_clearpg(&crd_tmp[crd_num]);

	/*Set CRD entry with page number*/
	cr_setpg(&crd_tmp[crd_num], cr_pg);

	/*Mark crd as valid*/
	setcrdvalid(&crd_tmp[crd_num]);
	req_mm->crd_type[crd_num] = MPI;

	memcpy(req_mm->crd, crd_tmp, sizeof(crd_tmp));


	req_mm->tsk_cr_pg_acc->t_mpi_pg++;

	/*Update Total CR page allocated to process
	and cr Page number for accounting*/
	req_mm->tsk_cr_pg_acc->t_cr_pg = (req_mm->tsk_cr_pg_acc->t_th_pg +
			req_mm->tsk_cr_pg_acc->t_mpi_pg);

	veos_set_crd(req_tsk, crd_num, 1, false, true);
	VEOS_DEBUG("%d crd allocated to tsk(%d)",
			crd_num, req);
	ret = crd_num;

	VEOS_DEBUG("req tsk:pid(%d) CR stat: thread(%d), mpi(%d)",
			req_tsk->pid, req_mm->tsk_cr_pg_acc->t_th_pg,
			req_mm->tsk_cr_pg_acc->t_mpi_pg);

	VEOS_DEBUG("own tsk:pid(%d) CR stat: thread(%d), mpi(%d)",
			own_tsk->pid, own_mm->tsk_cr_pg_acc->t_th_pg,
			own_mm->tsk_cr_pg_acc->t_mpi_pg);

	veos_dump_cr(req_tsk, ALL);
err_req:
	pthread_mutex_lock_unlock(&req_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
	goto err_return;
err_own:
	pthread_mutex_lock_unlock(&own_mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
err_return:
	if (own_tsk)
		put_ve_task_struct(own_tsk);
	if (req_tsk)
		put_ve_task_struct(req_tsk);
	VEOS_TRACE("returned with %ld", ret);
	return ret;
}
/**
 * @brief This function is used to increase reference count of CR page allocated.
 *		This interface will always be invoked by CR manager.
 *		AMM will invoke low level interface
 *		to increase ref count of page.
 * @param[in] crd This specifies CR directory number.
 * @param[in] owner PID of process which owns the CR page.
 *
 * @return On success returns CR page number associated with CRD entry
 *	and negative of errno on failure.
 */
int veos_get_cr_page(uint64_t crd, pid_t owner)
{
	int cr_pg = -1, ret = 0;
	struct ve_task_struct *tsk = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *mm = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("get cr page of crd(%ld) for pid(%d)", crd, owner);


	tsk = find_ve_task_struct(owner);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) for pid : %d", strerror(-ret), owner);
		return ret;
	}

	mm = tsk->p_ve_mm;
	if (!crdisvalid(&mm->crd[crd])) {
		ret = -EINVAL;
		put_ve_task_struct(tsk);
		VEOS_DEBUG("Error (%s) CRD not allocated : %ld",
				strerror(-ret), crd);
		return ret;
	}


	 /* Get the cr page number from CRD*/
	cr_pg = cr_getpg(&mm->crd[crd]);

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");

	if (vnode->ve_cr_pages[cr_pg].page_attr & VE_CR_THREAD) {
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Failed to release node cr lock");
		put_ve_task_struct(tsk);
		VEOS_DEBUG("Invalid get operation on thread CR page");
		ret  = -EINVAL;
		return ret;
	}

	ret = common_get_put_cr_page(cr_pg, GET_PAGE);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) for getting page_no (%d)",
				strerror(-ret), cr_pg);
		pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
				"Failed to release node cr lock");
		put_ve_task_struct(tsk);
		return ret;
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
	put_ve_task_struct(tsk);
	VEOS_TRACE("returned with %d", cr_pg);
	return cr_pg;
}

/**
* @brief This function is used to detach CR pages to the requesting VE process.
*
* @param[in] crd This flag specifies CR directory entry number.
* @param[in] req PID of process which owns the CR page.
*
* @return On success returns 0 and negative of errno on failure.
*/
int veos_detach_cr_page(uint64_t crd, pid_t req)
{
	return veos_do_detach_cr_page(crd, req, true);
}


/**
 * @brief This function is used to detach CR pages to the requesting VE process.
 *
 * @param[in] crd CRD number to be detached.
 *
 * @param[in] req PID of process which owns the CR page.
 * @param[in] clear TRUE clear the local cr_data contents else does not clear
 *               local cr_data contents.
 * @return On success returns 0 and negative of errno failure.
 */
int veos_do_detach_cr_page(uint64_t crd, pid_t req, bool clear)
{
	int ret = 0;
	struct ve_task_struct *tsk = NULL;
	struct ve_mm_struct *mm = NULL;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("detach crd(%ld) of  pid(%d) and clear flag(%d)", crd,
			req, clear);

	tsk = find_ve_task_struct(req);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting tsk:pid(%d)",
				strerror(-ret), req);
		return ret;
	}

	mm = tsk->p_ve_mm;
	/*check whether requested CRD is valid or not*/

	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, LOCK,
			"Failed to acquire thread-group-mm-lock");

	/* When process is process sched out and CRD type is thread,
	 * As cr thread pages is already released, We are just updating
	 * the data structure and setting CRD type to none.*/
	if ((mm->is_sched == false) && (mm->crd_type[crd] == THREAD)) {
		if (mm->tsk_cr_pg_acc->t_th_pg)
			mm->tsk_cr_pg_acc->t_th_pg--;

		VEOS_DEBUG("%u thread pages allocated to tsk(%d)",
			mm->tsk_cr_pg_acc->t_th_pg, tsk->pid);
		mm->crd_type[crd] = NONE;

		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		VEOS_DEBUG("Nothing To Do!");
		VEOS_TRACE("returned(%d)", ret);
		goto hndl_return;
	}

	if (!crdisvalid(&mm->crd[crd]) || (crd > MAX_CRD_PER_CORE)) {
		ret = -EINVAL;
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		VEOS_DEBUG("Error (%s) CRD %ld is not valid for tsk:pid(%d) ",
				strerror(-ret), crd, tsk->pid);
		goto hndl_return;
	}

	ret =  __veos_do_detach_cr_page(crd, tsk, clear);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while detaching crd (%ld) of"
			"tsk:pid(%d)",	strerror(-ret), crd, tsk->pid);
		pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
				"Failed to release thread-group-mm-lock");
		put_ve_task_struct(tsk);
		return ret;
	}
	pthread_mutex_lock_unlock(&mm->thread_group_mm_lock, UNLOCK,
			"Failed to release thread-group-mm-lock");
hndl_return:
	put_ve_task_struct(tsk);
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
 * @brief This function is used to detach CR pages to the requesting VE process.
 *
 * @param[in] crd CRD number to be detached.
 *
 * @param[in] tsk process task struct.
 * @param[in] clear TRUE clear the local cr_data contents else does not clear
 *            local cr_data contents.
 * @return On success returns 0 and negative of errno on failure.
 */
int __veos_do_detach_cr_page(uint64_t crd,
		struct ve_task_struct *tsk, bool clear)
{
	int cr_pg = -1;
	int ret = 0;
	uint64_t crd_type = 0;
	crd_t crd_tmp[MAX_CRD_PER_CORE] = { {0} };
	struct ve_node_struct *vnode = VE_NODE(0);
	struct ve_mm_struct *mm = tsk->p_ve_mm;

	VEOS_TRACE("invoked");

	VEOS_DEBUG("detach crd(%ld) of tsk:pid(%d) with clr flg(%d)",
			crd, tsk->pid, clear);

	/*Get crd image of req
	* and obtain the cr page number*/
	memset(crd_tmp, 0, sizeof(crd_tmp));

	memcpy(crd_tmp, mm->crd, sizeof(crd_tmp));

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");
	cr_pg = cr_getpg(&crd_tmp[crd]);

	crd_type = vnode->ve_cr_pages[cr_pg].page_attr;

	if ((crd_type & VE_CR_THREAD) && clear) {
		VEOS_DEBUG("clearing cr page contents");
		/*clear the containt of cr page*/
		memset(&mm->cr_data[crd], 0, sizeof(cr_cluster_t));
	}

	/*Invalidate crd*/
	setcrdinvalid(&crd_tmp[crd]);
	mm->crd_type[crd] = NONE;

	memcpy(mm->crd, crd_tmp, sizeof(crd_tmp));


	ret = veos_put_cr_page(cr_pg);
	if (0 > ret) {
		VEOS_DEBUG("Error (%s) while putting page no (%d)",
				strerror(-ret), cr_pg);
		goto err_return;
	}

	if (crd_type & VE_CR_MPI) {
		if (mm->tsk_cr_pg_acc->t_mpi_pg)
			mm->tsk_cr_pg_acc->t_mpi_pg--;
		VEOS_DEBUG("total %u mpi pages allocated to tsk(%d)",
			mm->tsk_cr_pg_acc->t_mpi_pg, tsk->pid);

	} else if (crd_type & VE_CR_THREAD) {
		if (mm->tsk_cr_pg_acc->t_th_pg)
			mm->tsk_cr_pg_acc->t_th_pg--;
		VEOS_DEBUG("%u thread pages allocated to tsk(%d)",
			mm->tsk_cr_pg_acc->t_th_pg, tsk->pid);
	}

	/*Update Total CR page allocated to process
	and cr Page number for accounting*/
	mm->tsk_cr_pg_acc->t_cr_pg = (mm->tsk_cr_pg_acc->
				t_th_pg + mm->tsk_cr_pg_acc->t_mpi_pg);

	VEOS_DEBUG("total %u pages allocated to tsk(%d)",
		mm->tsk_cr_pg_acc->t_cr_pg, tsk->pid);

	VEOS_DEBUG("total (%u) mpi page allocated on NODE(%d)",
			vnode->cr_mpi_pg, vnode->node_num);
	VEOS_DEBUG("total (%u) thread page allocated on NODE(%d)",
			vnode->cr_th_pg, vnode->node_num);

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
	veos_set_crd(tsk, crd, MAX_CRD_PER_CORE, false, true);

	veos_dump_cr(tsk, ALL);
	goto err_return1;
err_return:
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
err_return1:
	VEOS_TRACE("returned with %d", ret);
	return ret;
}


/**
 * @brief This function is used to free the CR page.
 *
 * @param[in] cr_page CR page number.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_free_cr_page(uint64_t cr_page)
{
	int ret = 0;
	cr_cluster_t cr_data = { {0} };
	vedl_handle *handle = VE_HANDLE(0);
	struct ve_node_struct *vnode = VE_NODE(0);
	system_common_reg_t *to = VE_CORE_CNT_REG_ADDR(0);
	off_t offset = VE_CR_CLUSTER_OFF(cr_page);

	VEOS_TRACE("invoked");
	VEOS_DEBUG("freeing  cr page %ld", cr_page);


	memset(&cr_data, 0, sizeof(cr_cluster_t));

	if (cr_page > MAX_CR_PAGE_PER_NODE) {
		ret  = -EINVAL;
		VEOS_DEBUG("Error (%s) cr page %ld is not valid",
				strerror(-ret), cr_page);
		return ret;
	}

	if (vnode->cr_map[cr_page] == false) {
		ret = -EFAULT;
		VEOS_DEBUG("Error (%s) cr page %ld not allocated",
				strerror(-ret), cr_page);
		return ret;
	}

	if (vnode->ve_cr_pages[cr_page].page_attr == VE_CR_THREAD) {
		if (vnode->cr_th_pg)
			--vnode->cr_th_pg;
	} else {
		if (vnode->cr_mpi_pg)
			--vnode->cr_mpi_pg;
	}

	/*clear the bit corrosponds to cr page*/
	vnode->cr_map[cr_page] = false;
	vnode->ve_cr_pages[cr_page].page_attr = 0;
	vnode->ve_cr_pages[cr_page].ref_count = 0;
	vnode->ve_cr_pages[cr_page].cr_page_no = 0;
	vnode->ve_cr_pages[cr_page].tsk = NULL;

	VEOS_DEBUG("total %u CR pages are in use", (vnode->cr_th_pg + vnode->cr_mpi_pg));

	/*free the content of cr page*/
	ret = vedl_set_cnt_reg_words(handle, to, offset,
			&cr_data, sizeof(cr_cluster_t));
	if (ret < 0) {
		VEOS_DEBUG("failed to initialize content of CR page(%ld)", cr_page);
		veos_abort("CR cluster regs sync failed");
	}

	VEOS_DEBUG("CR page(%ld) content has been cleared", cr_page);
	VEOS_TRACE("returned with %d", ret);
	return ret;

}


/**
 * @brief This function is used to decrease reference count of CR page allocated.
 *
 * @param[in] cr_page This flag specifies CR Page number.
 *
 * @return On success returns 0 and negative of errno on failure.
 */
int veos_put_cr_page(uint64_t cr_page)
{
	return common_get_put_cr_page(cr_page, PUT_PAGE);
}

/**
* @brief This function updates the core specific CR directory entry for the VE programs or threads.
*
* @param[in] tsk process task struct.
* @param[in] crd_entry An index of process’s CRD entry.
* @param[in] count Count of CRD entries to be update.
* @param[in] all TRUE then update all the CRD entries.
* @param[in] halt_all In case of system call then flag is TRUE as PSM need to halt all associated threads
*            but for re-scheduling it is not required to halt other threads so flag is false.
*/
void veos_set_crd(struct ve_task_struct *tsk, uint8_t crd_entry,
		int count, bool all, bool halt_all)
{

	struct ve_mm_struct *mm = NULL;

	mm = tsk->p_ve_mm;
	VEOS_TRACE("invoked");
	VEOS_DEBUG("sync crd(%d) with count(%d)"
			"all (%d) halt(%d) for tsk:pid(%d)", crd_entry,
			count, all, halt_all, tsk->pid);

	if (all) {
		/*SET all entries in core CRD registor*/
		psm_sync_hw_regs(tsk, _CRD, mm->crd, halt_all, 0, 4);
	} else {
		/* SET perticular  crd_entry
		 * */
		psm_sync_hw_regs(tsk, _CRD, mm->crd, halt_all, crd_entry, 1);
	}

	VEOS_TRACE("returned");
}


/**
* @brief This function will save the CR page marked as VE_CR_THREAD during schedule-out.
*
* @param[in] tsk ref to task struct of current process.
*
* @return On success returns 0 and negative of errno on failure.
*/
int veos_save_cr(struct ve_task_struct *tsk)
{
	int ret = 0;
	int crd_no = 0;
	int cr_pg = -1;
	off_t offset = 0;
	struct ve_mm_struct *mm = NULL;
	struct ve_node_struct *vnode = VE_NODE(0);
	vedl_handle *handle = VE_HANDLE(0);
	system_common_reg_t *from = VE_CORE_CNT_REG_ADDR(0);

	VEOS_TRACE("invoked");
	VEOS_DEBUG("invoked with pid (%d)", tsk->pid);

	mm = tsk->p_ve_mm;
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");

	mm->is_sched = false;

	if (mm->tsk_cr_pg_acc->t_th_pg == 0) {
		VEOS_DEBUG("no cr thread page allocated to tsk:pid(%d)", tsk->pid);
		goto err_return;
	}

	/*Extract cr page number from CRD entries*/
	for (crd_no = 0; crd_no < MAX_CRD_PER_CORE; crd_no++) {
		if (mm->crd_type[crd_no] == DELAYED) {
			VEOS_DEBUG("flag delayed set for %d crd[0x%lx]",
					crd_no, mm->crd[crd_no].data);
			setcrdinvalid(&mm->crd[crd_no]);
			continue;
		} else if (mm->crd_type[crd_no] == THREAD) {
			/*obtain the cr page number from crd*/
			if (crdisvalid(&mm->crd[crd_no])) {
				cr_pg = cr_getpg(&mm->crd[crd_no]);
				VEOS_DEBUG("freeing cr page (%d) for tsk:pid(%d)", cr_pg, tsk->pid);
				/*save the content of cr pages into mm struct*/
				offset = VE_CR_CLUSTER_OFF(cr_pg);
				VEOS_DEBUG("save CR contents from %p to %lx of size %lx",
					from, offset, sizeof(cr_cluster_t));
				ret = vedl_get_cnt_reg_words(handle, from, offset,
						&mm->cr_data[crd_no], sizeof(cr_cluster_t));
				if (0 > ret) {
					VEOS_DEBUG("Error(%s) while saving CR cluster %d",
							strerror(-ret), cr_pg);
					pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
							"Failed to release node cr lock");
					veos_abort("fail to save cr pages");
				}
				/*free the current cr page*/
				ret = veos_free_cr_page(cr_pg);
				if (0 > ret) {
					VEOS_DEBUG("Error (%s) while freeing cr page(%d)",
							strerror(-ret), cr_pg);
					goto err_return;
				}
				/*first clear page numner*/
				cr_clearpg(&mm->crd[crd_no]);

				/*Mark as invalid*/
				setcrdinvalid(&mm->crd[crd_no]);
			}
		}
	}

	VEOS_DEBUG("total %d thread page requested from node",
				vnode->cr_th_req);

	VEOS_DEBUG("node CR stat: thread(%d), mpi(%d)",
		vnode->cr_th_pg, vnode->cr_mpi_pg);

	VEOS_DEBUG("tsk:pid(%d) CR stat: thread(%d), mpi(%d)",
		tsk->pid, mm->tsk_cr_pg_acc->t_th_pg,
		mm->tsk_cr_pg_acc->t_mpi_pg);

err_return:
	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
	VEOS_TRACE("returned with %d", ret);
	return ret;
}

/**
* @brief This function restore the content of CR from software copy
*		to newly allocated CR page.
*
* @param[in] tsk This is pointer to VE task struct
*		to get ref data structure representing
*		CR page information.
* @return On success returns 0 and negative of errno on failure.
*/
int veos_restore_cr(struct ve_task_struct *tsk)
{
	int ret = 0;
	int t_cr_th_pg = 0;
	int crd_no = 0;
	crd_t crd_tmp[MAX_CRD_PER_CORE] = { {0} };
	off_t offset = 0;
	struct ve_node_struct *vnode = VE_NODE(0);
	vedl_handle *handle = VE_HANDLE(0);
	system_common_reg_t *to = VE_CORE_CNT_REG_ADDR(0);
	struct ve_mm_struct *mm = tsk->p_ve_mm;
	cr_cluster_t *cr_data = NULL;

	VEOS_TRACE("invoked");
	VEOS_DEBUG("restoring CR contents for tsk:pid(%d)", tsk->pid);

	/* Marked task is scheduled
	*/
	mm->is_sched = true;

	t_cr_th_pg = mm->tsk_cr_pg_acc->t_th_pg;

	if (!t_cr_th_pg) {
		VEOS_DEBUG("no cr page allocated to tsk:pid(%d)", tsk->pid);
		goto err_return;
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, LOCK,
			"Failed to acquire node cr lock");

	cr_data =  mm->cr_data;

	VEOS_DEBUG("total %d cr thread pages type pages was allocated", t_cr_th_pg);

	/*Get the s/w image of crd */
	memcpy(crd_tmp, mm->crd, (sizeof(crd_t) * MAX_CRD_PER_CORE));

	/*update crd with new pages number*/
	for (crd_no = 0; crd_no < MAX_CRD_PER_CORE; crd_no++) {
		if ((mm->crd_type[crd_no] == THREAD) ||
				(mm->crd_type[crd_no] == DELAYED)) {
			VEOS_DEBUG("%u crd is assigned for thread for tsk:pid(%d)",
						crd_no, tsk->pid);
			if (!crdisvalid(&crd_tmp[crd_no])) {
				ret = veos_get_free_cr_page(VE_CR_THREAD);
				if (0 > ret) {
					VEOS_DEBUG("Error (%s) while getting free cr page",
							strerror(-ret));
					pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
							"Failed to release node cr lock");
					goto err_return;
				} else {
					VEOS_DEBUG("cr page(%d) is free to allocate", ret);
					/*set page attributes in global cr page array.*/
					common_get_put_cr_page(ret, GET_PAGE);

					update_ve_cr_page(vnode, VE_CR_THREAD, ret, tsk);

					/*clear old cr page number*/
					cr_clearpg(&crd_tmp[crd_no]);

					/*set cr page number in crd*/
					cr_setpg(&(crd_tmp[crd_no]), ret);

					/*Mark crd as valid*/
					setcrdvalid(&crd_tmp[crd_no]);

					if (mm->crd_type[crd_no] == DELAYED)
						mm->crd_type[crd_no] = THREAD;

					/*restore cr date in cr pages*/
					offset = VE_CR_CLUSTER_OFF(ret);
					VEOS_DEBUG("save CR contents from %p to %lx of size %lx",
						&cr_data[crd_no], offset, sizeof(cr_cluster_t));
					ret = vedl_set_cnt_reg_words(handle, to, offset,
							&cr_data[crd_no], sizeof(cr_cluster_t));
					if (0 > ret) {
						VEOS_DEBUG("Error (%s) while set crd words",
								strerror(-ret));
						veos_abort("syncing CR failed");
					}
				}
			}

		}
	}

	pthread_mutex_lock_unlock(&vnode->cr_node_lock, UNLOCK,
			"Failed to release node cr lock");
	memcpy(mm->crd, crd_tmp, (sizeof(crd_t) * MAX_CRD_PER_CORE));

	/*Set CRD h/w registor*/
	veos_set_crd(tsk, 0, MAX_CRD_PER_CORE, true, false);

	VEOS_DEBUG("total %d thread page requested from node",
			vnode->cr_th_req);

	VEOS_DEBUG("node CR stat: thread(%d), mpi(%d)",
			vnode->cr_th_pg, vnode->cr_mpi_pg);

	VEOS_DEBUG("tsk:pid(%d) CR stat: thread(%d), mpi(%d)",
			tsk->pid, mm->tsk_cr_pg_acc->t_th_pg,
			mm->tsk_cr_pg_acc->t_mpi_pg);

	VEOS_DEBUG("CR pages data has been restored into registor");
err_return:
	VEOS_TRACE("returned with %d", ret);
	return ret;
}


/**
* @brief This function updates CRD of new process or thread.
*
* @param[in] tsk This is pointer to VE task`s thread group leader task structure which contains
*		data structure representing CR information.
*/
void veos_set_crd_context(struct ve_task_struct *tsk)
{

	VEOS_TRACE("invoked with pid %d", tsk->pid);

	veos_set_crd(tsk, 0, MAX_CRD_PER_CORE, true, false);

	VEOS_TRACE("returned");
}
