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
 * @file mm_comm.c
 * @brief Handles commands sent from PSEUDO PROCESS.
 * This file defines command handlers and invokes there respective handlers.
 *
 * @internal
 * @author AMM
 */
#include <unistd.h>
#include <fcntl.h>
#include <search.h>
#include <sys/stat.h>
#include "psm_stat.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/capability.h>
#include "ve_hw.h"
#include "ptrace_req.h"
#include "ve_mem.h"
#include "veos_handler.h"
#include "veos.h"
#include "task_mgmt.h"
#include "ve_shm.h"
#include "psm_comm.h"
#include "proto_buff_schema.pb-c.h"
#include "velayout.h"
#include "cr_api.h"
#include "task_sched.h"
#include <sys/ipc.h>
#include <sys/shm.h>

/**
* @brief This is request interface which will extract the argument
*	 pass it to the amm_do_vemav_init_atb function.
*
* @param[in] pti It contains request information
*
* @return on success return 0 and -1 on failure.
*/
int amm_handle_vhva_sync_req(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage vhva_sync_req_ack = PSEUDO_VEOS_MESSAGE__INIT;
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	sync_at_exit(tsk);

send_ack:
	vhva_sync_req_ack.has_syscall_retval = true;
	vhva_sync_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&vhva_sync_req_ack);

	msg_len = pseudo_veos_message__pack(&vhva_sync_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which will extract the argument
*	pass it to the amm_do_vemav_init_atb function.
*
* @param[in] pti It contains request information
*
* @return On success return 0 and -1 on failure.
*/
int amm_handle_vemva_init_atb_req(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct vemva_init_atb_cmd req = {0};
	int pgmod = -1;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage vemva_init_atb_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	pgmod = (req.page_size == PAGE_SIZE_2MB) ? PG_2M : PG_HP;

	ret = amm_do_vemva_init_atb(req.vaddr, pgmod, tsk);
	if (0 > ret)
		VEOS_ERROR("error while intializing ATB  for pid %d", pid);
	else
		VEOS_DEBUG("ATB initialization succeed for pid :%d", pid);

send_ack:
	vemva_init_atb_req_ack.has_syscall_retval = true;
	vemva_init_atb_req_ack.syscall_retval =  ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			vemva_init_atb_req_ack);

	msg_len = pseudo_veos_message__pack(&vemva_init_atb_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will handle request to dump CR.
*
* @param[in] pti It contains request information.
*
* @return return 0 on success and -1 on failure.
*/
int amm_dump_cr_req(veos_thread_arg_t *pti)
{
	int ret = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct cr_dump_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage cr_dump_ack = PSEUDO_VEOS_MESSAGE__INIT;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}

	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	tsk = find_ve_task_struct(req.pid);
	if (tsk == NULL) {
		ret = -ESRCH;
		VEOS_DEBUG("Error(%s) while getting task structure for pid %d",
			strerror(-ret), req.pid);
		goto send_ack;
	}

	ret = veos_dump_cr(tsk, req.mode_flag);
	if (0 > ret)
		VEOS_ERROR("error occured while dummping CR");
	else
		VEOS_DEBUG("CR dumping succeed");

send_ack:
	cr_dump_ack.has_syscall_retval = true;
	cr_dump_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&cr_dump_ack);

	msg_len = pseudo_veos_message__pack(&cr_dump_ack, (uint8_t *)ack);
	if (pseudo_msg_len != msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This function will handle pseudo req to set cr rlimits.
*
* @param[in] pti This pointer will contains req information.
*
* @return return 0 on success and -1 on failure.
*/
int set_cr_rlimit_req(veos_thread_arg_t *pti)
{

	int ret = 0;
	int sd = pti->socket_descriptor;
	struct cr_rlimit_info req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);

	PseudoVeosMessage cr_rlimit_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}

	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	ret = set_cr_rlimit(req.pid, req.uid,
			req.cr_thread_lim, req.cr_mpi_lim);
	if (0 > ret)
		VEOS_ERROR("error while setting cr rlimit (pid : %d)", req.pid);
	else
		VEOS_DEBUG("cr rlimit changed by (pid : %d)", req.pid);

send_ack:
	cr_rlimit_req_ack.has_syscall_retval = true;
	cr_rlimit_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			cr_rlimit_req_ack);

	msg_len = pseudo_veos_message__pack(&cr_rlimit_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_return:
	VEOS_TRACE("returned");
	return ret;
}

/* @brief This is request interface which extracts shmget
*            arguments and pass to generic shmget handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_shmget(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd req =  {0};
	struct shm *shm = NULL;
	struct shmid_ds buf = { {0} };
	struct shm_seginfo *shm_info = NULL;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	proc_t ve_proc_info = {0};
	int length = -1;
	pid_t pid = -1;
	ProtobufCBinaryData ve_shm_ack_msg = {0};
	PseudoVeosMessage ve_shmget_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		ve_shmget_ack.has_syscall_retval = true;
		ve_shmget_ack.syscall_retval = -ESRCH;
		goto send_ack;
	}

	shm_info = calloc(1, sizeof(struct shm_seginfo));
	if (NULL == shm_info) {
		ret = -ENOMEM;
		VEOS_CRIT("calloc error (%s) while allocating mem for shm object",
				strerror(-ret));
		goto send_ack;
	}

	/* Get the information of /proc/## for the given remote pid */
	ret = psm_get_ve_proc_info(tsk->pid, &ve_proc_info);
	if (-1 == ret) {
		ret = -EACCES;
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		goto send_ack;
	}

	ret = shmctl(req.shmid, IPC_STAT, &buf);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) by host shmctl()"
				"for shmid(0x%lx)", strerror(-ret), req.shmid);
		goto send_ack;
	}

	if ((buf.shm_perm.uid == ve_proc_info.euid &&
				buf.shm_perm.uid == ve_proc_info.suid &&
				buf.shm_perm.uid == ve_proc_info.ruid &&
				buf.shm_perm.gid == ve_proc_info.egid &&
				buf.shm_perm.gid == ve_proc_info.sgid &&
				buf.shm_perm.gid == ve_proc_info.rgid) ||
			(buf.shm_perm.cuid == ve_proc_info.euid &&
			 buf.shm_perm.cuid == ve_proc_info.suid &&
			 buf.shm_perm.cuid == ve_proc_info.ruid &&
			 buf.shm_perm.cgid == ve_proc_info.egid &&
			 buf.shm_perm.cgid == ve_proc_info.sgid &&
			 buf.shm_perm.cgid == ve_proc_info.rgid)) {
		VEOS_DEBUG("%d belongs to same user", tsk->pid);
		goto ok;
	}

	/* Check if the  have CAP_IPC_LOCK capability or not */
	if (!check_ve_proc_capability(tsk->pid, CAP_IPC_OWNER)) {
		ret = -EACCES;
		goto send_ack;
	}
ok:
	shm = amm_get_shm_segment(req.key, req.shmid, req.size,
			req.flag, req.create);
	if (NULL == shm) {
		ret = -errno;
		VEOS_ERROR("Error while getting shm segment for (pid :%d)", pid);
	} else {
		ret = 0;
		shm_info->pgmod = shm->pgmod;
		shm_info->size = shm->size;
		VEOS_DEBUG("shm segment allocated to (pid :%d) successfull", pid);
	}

send_ack:
	ve_shmget_ack.has_syscall_retval = true;
	ve_shm_ack_msg.len = sizeof(struct shm_seginfo);
	ve_shm_ack_msg.data = (uint8_t *)shm_info;
	ve_shmget_ack.has_pseudo_msg = true;
	ve_shmget_ack.pseudo_msg = ve_shm_ack_msg;
	ve_shmget_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_shmget_ack);

	msg_len = pseudo_veos_message__pack(&ve_shmget_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		ret = -1;
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
	}

hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	if (shm_info)
		free(shm_info);
	return ret;
}


/* @brief This is request interface which extracts shmat arguments
*          and pass to generic shmat handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_shmat(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	struct shmid_ds buf = { {0} };
	proc_t ve_proc_info = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_shmat_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	/* Get the information of /proc/## for the given remote pid */
	ret = psm_get_ve_proc_info(tsk->pid, &ve_proc_info);
	if (-1 == ret) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		ret = -EACCES;
		goto send_ack;
	}

	ret = shmctl(req.shmid, IPC_STAT, &buf);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) by host shmctl()"
				"for shmid(0x%lx)", strerror(-ret), req.shmid);
		goto send_ack;
	}

	if ((buf.shm_perm.uid == ve_proc_info.euid &&
				buf.shm_perm.uid == ve_proc_info.suid &&
				buf.shm_perm.uid == ve_proc_info.ruid &&
				buf.shm_perm.gid == ve_proc_info.egid &&
				buf.shm_perm.gid == ve_proc_info.sgid &&
				buf.shm_perm.gid == ve_proc_info.rgid) ||
			(buf.shm_perm.cuid == ve_proc_info.euid &&
			 buf.shm_perm.cuid == ve_proc_info.suid &&
			 buf.shm_perm.cuid == ve_proc_info.ruid &&
			 buf.shm_perm.cgid == ve_proc_info.egid &&
			 buf.shm_perm.cgid == ve_proc_info.sgid &&
			 buf.shm_perm.cgid == ve_proc_info.rgid)) {
		VEOS_DEBUG("%d belongs to same user",
				tsk->pid);
		goto ok;
	}

	/* Check if the  have CAP_IPC_LOCK capability or not */
	if (!check_ve_proc_capability(tsk->pid, CAP_IPC_OWNER)) {
		ret = -EACCES;
		goto send_ack;
	}

ok:

	ret = amm_do_shmat(req.key, req.shmid, req.vaddr, req.size,
			req.shmperm, tsk);
	if (0 > ret)
		VEOS_ERROR("error while attaching shm segment for (pid %d)", pid);
	else
		VEOS_DEBUG("shm segment attached successfully (pid %d)", pid);

send_ack:

	ve_shmat_req_ack.has_syscall_retval = true;
	ve_shmat_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_shmat_req_ack);

	msg_len = pseudo_veos_message__pack(&ve_shmat_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}
hndl_return:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts shmctl arguments
*        and pass to generic shmctl handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_shmctl(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	proc_t ve_proc_info = {0};
	struct shmid_ds buf = { {0} };
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_shmctl_req_ack = PSEUDO_VEOS_MESSAGE__INIT;
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
			strerror(-ret), pid);
		goto send_ack;
	}

	/* Get the information of /proc/## for the given remote pid */
	ret = psm_get_ve_proc_info(tsk->pid, &ve_proc_info);
	if (-1 == ret) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		ret = -EACCES;
		goto send_ack;
	}

	ret = shmctl(req.shmid, IPC_STAT, &buf);
	if (0 > ret) {
		ret = -errno;
		VEOS_DEBUG("Error (%s) by host shmctl()"
				"for shmid(0x%lx)", strerror(-ret), req.shmid);
		goto send_ack;
	}

	if ((buf.shm_perm.uid == ve_proc_info.euid) ||
			(buf.shm_perm.cuid == ve_proc_info.euid)) {
		VEOS_DEBUG("%d belongs to same user",
				tsk->pid);
		goto ok;
	}

	/* Check if the  have CAP_IPC_LOCK capability or not */
	if (!check_ve_proc_capability(tsk->pid, CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto send_ack;
	}
ok:
	VEOS_DEBUG("pid(%d) calling shmclt for shmid(%ld)", tsk->pid, req.shmid);
	ret = amm_do_shmctl(req.shmid);
	if (0 > ret)
		VEOS_DEBUG("error while control operation on shm segment (pid:%d)", pid);
	else
		VEOS_DEBUG("control operation on shm segment is successfull (pid:%d)", pid);


send_ack:
	ve_shmctl_req_ack.has_syscall_retval = true;
	ve_shmctl_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_shmctl_req_ack);

	msg_len = pseudo_veos_message__pack(&ve_shmctl_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
			pseudo_msg_len, ret);
		ret = -1;
	}

hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts shmdt arguments
*        and pass to shmdt handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_shmdt(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	pid_t pid = -1;
	struct shm_seginfo shm_info = {0};

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	ProtobufCBinaryData ve_shm_ack_msg;
	PseudoVeosMessage ve_shmdt_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	ret = amm_do_shmdt(req.vaddr, tsk, &shm_info);
	if (0 > ret)
		VEOS_ERROR("error while deleting shm segment(pid:%d)", pid);
	else
		VEOS_DEBUG("shm segment deleted successfully (pid:%d)", pid);

	ve_shmdt_ack.has_syscall_retval = true;
	ve_shm_ack_msg.len = sizeof(struct shm_seginfo);
	ve_shm_ack_msg.data = (uint8_t *)&shm_info;
	ve_shmdt_ack.has_pseudo_msg = true;
	ve_shmdt_ack.pseudo_msg = ve_shm_ack_msg;

send_ack:
	ve_shmdt_ack.syscall_retval = ret;
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_shmdt_ack);

	msg_len = pseudo_veos_message__pack(&ve_shmdt_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}
hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts mmap arguments
*        and pass to generic mmap handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_mmap(veos_thread_arg_t *pti)
{
	int ret = -1;
	struct ve_mmap_cmd req = {0};
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	pid_t pid = -1;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	PseudoVeosMessage ve_mmap = PSEUDO_VEOS_MESSAGE__INIT;

	VEOS_TRACE("Invoked with pti (%p)", pti);

	/* PID recieved from PSEUDO process */
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto hndl_return;
	}
	VEOS_DEBUG("mmap request length received from protobuf:%d", length);

	if (length > sizeof(struct ve_mmap_cmd)) {
		VEOS_DEBUG("Invalid message length");
		return -1;
	}

	memcpy(&req, (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
				pseudo_msg).data, length);

	/*If file backed*/
	if (!(req.flags & MAP_ANON)) {
		VEOS_DEBUG("Request need to fetch more data to get file stat");
		VEOS_DEBUG("MMAP request for file_inode %ld and range offset_start %ld "
				" ------ offset_end %ld",
				(req.f_stat).stat.st_ino,
				(req.f_stat).offset_start,
				(req.f_stat).offset_end);
	}

	/*
	 * finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */
	ve_mmap.has_syscall_retval = true;

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		ret = -ESRCH;
		goto hndl_return;
	}

	ret = amm_do_mmap(req.vaddr, req.size, req.perm, req.flags, tsk, &(req.f_stat));
	if (0 > ret)
		VEOS_ERROR("error while mapping memory for (pid:%d)", pid);
	else
		VEOS_DEBUG("memory mapped successfully (pid:%d)", pid);


hndl_return:
	ve_mmap.syscall_retval = ret;
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mmap);

	msg_len = pseudo_veos_message__pack(&ve_mmap, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}
hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts munmap arguments
*        and pass to generic unmap handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_munmap(veos_thread_arg_t *pti)
{
	int ret = 0;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_munmap_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	int length = -1;
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_munmap_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	ret = amm_do_munmap(req.vaddr, req.size, tsk, false);
	if (0 > ret)
		VEOS_DEBUG("error while unmapping the memory (pid:%d)", pid);
	else
		VEOS_DEBUG("memory successfully unmapped (pid %d)", pid);

send_ack:
	ve_munmap_req_ack.has_syscall_retval = true;
	ve_munmap_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_munmap_req_ack);

	msg_len = pseudo_veos_message__pack(&ve_munmap_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts mprotect arguments
*         and pass to generic mprotect handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_mprotect(veos_thread_arg_t *pti)
{
	int ret = 0;
	pid_t pid = -1;
	int length = -1;
	struct ve_task_struct *tsk = NULL;
	ProtobufCBinaryData pseudo_mprotect_msg = {0};
	struct pseudo_mprotect_req mprotect_request = {0};

	VEOS_TRACE("invoked thread arg pti(%p)", pti);

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;


	/* finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		ret = amm_send_mprotect_ack(pti, ret);
		if (0 > ret)
			VEOS_DEBUG("Sending mprotect ack failed with ret %d", ret);
		ret = -1;
		goto req_mprotect_error;
	}


	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		ret = -EINVAL;
		VEOS_DEBUG("Invalid message length %d", length);
		goto req_mprotect_error;
	}

	/* Retrive pseudo_mprotect_req data from proto-message */
	pseudo_mprotect_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&mprotect_request, pseudo_mprotect_msg.data,
			pseudo_mprotect_msg.len);

	ret = amm_do_mprotect(mprotect_request.ret_addr, mprotect_request.size,
			mprotect_request.prot, tsk);
	if (0 > ret) {
		VEOS_ERROR("error while changing memory protection (pid:%d)", pid);
		ret = amm_send_mprotect_ack(pti, ret);
		if (0 > ret) {
			VEOS_DEBUG("error while sending ack (pid:%d)", pid);
			goto req_mprotect_error;
		}
	} else {
		ret = amm_send_mprotect_ack(pti, ret);
		if (0 > ret)
			VEOS_DEBUG("ack send successfully (pid:%d)", pid);
		else
			ret = 0;
	}

req_mprotect_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
 * @brief Sends acknowlegdment for mprotect request received from pseudo process.
 *
 * @param[in] pti contains the request received from the pseudo process.
 * @param[in] syscall_ret contains return value of halt_core_request.
 *
 * @return On failure, returns -1 and on success, returns a positive value.
 */
int amm_send_mprotect_ack(struct veos_thread_arg *pti, int64_t syscall_ret)
{
	int ret = 0;
	PseudoVeosMessage mprotect_ack = PSEUDO_VEOS_MESSAGE__INIT;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);

	/* Populate acknowledgment message */
	mprotect_ack.has_syscall_retval = true;
	mprotect_ack.syscall_retval = syscall_ret;

	/* Pack mprotect_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&mprotect_ack);

	msg_len = pseudo_veos_message__pack(&mprotect_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_return;
	}

	/* Send ACK to the pseudo side */
	ret = psm_pseudo_send_cmd(pti->socket_descriptor, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_return:
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface for dma memory.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_dma_req(veos_thread_arg_t *pti)
{
	int ret = 0;
	int srctype = 0, dsttype = 0;
	uint64_t src_addr = 0, dst_addr = 0;
	int64_t length = -1;
	size_t size;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	struct dma_args dma_param = {0};
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_dma_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %ld", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy(&dma_param,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* Get the arguments */
	srctype  = dma_param.srctype;
	src_addr = dma_param.srcaddr;
	dsttype =  dma_param.dsttype;
	dst_addr = dma_param.dstaddr;
	length =   dma_param.size;

	VEOS_DEBUG("DMA.SRCTYPE : %d,"
			"DMA.DSTTYPE : %d"
			"DMA.SRCADDR : %lx"
			"DMA.DSTADDR : %lx"
			"DMA.LEN : %ld",
			dma_param.srctype,
			dma_param.dsttype,
			dma_param.srcaddr,
			dma_param.dstaddr,
			dma_param.size);


	/* finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */
	if ((dma_param.srctype == VE_DMA_VEMAA) ||
			(dma_param.srctype == VE_DMA_VERAA) ||
			(dma_param.srctype == VE_DMA_VHSAA) ||
			(dma_param.dsttype == VE_DMA_VEMAA) ||
			(dma_param.dsttype == VE_DMA_VERAA) ||
			(dma_param.dsttype == VE_DMA_VHSAA) ||
			(dma_param.dsttype == VE_DMA_VEMVA_WO_PROT_CHECK)) {
		ve_dma_req_ack.has_syscall_retval = true;
		ve_dma_req_ack.syscall_retval = -EINVAL;
		goto send_ack;
	}

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			LOCK, "Failed to acquire mm-thread-group-lock");
	if (srctype == VE_DMA_VHVA) {
		/*Check if dst_addr is mapped with a file*/
		size = is_addr_file_backed(src_addr, tsk);
		if (!size)
			VEOS_DEBUG("src address is not file backed");
		else if (length > size)
			length = size;
	}

	if (dsttype == VE_DMA_VHVA) {
		/*Check if dst_addr is mapped with a file*/
		size = is_addr_file_backed(dst_addr, tsk);
		if (!size)
			VEOS_DEBUG("src address is not file backed");
		else if (length > size)
			length = size;
	}

	pthread_mutex_lock_unlock(&tsk->p_ve_mm->thread_group_mm_lock,
			UNLOCK, "Failed to release mm-thread-group-lock");

	ret =  amm_dma_xfer(srctype, src_addr, pid, dsttype,
			dst_addr, pid, length, tsk->node_id);
	if (0 > ret)
		VEOS_ERROR("error while DMA transfer (pid:%d)", pid);
	else
		VEOS_DEBUG("DMA transfer done (pid %d)", pid);

send_ack:
	ve_dma_req_ack.has_syscall_retval = true;
	ve_dma_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_dma_req_ack);

	msg_len = pseudo_veos_message__pack(&ve_dma_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}

/**
* @brief This is request interface which extracts vm_rw request arguments and
*	pass to generic vm_rw handler.
*
* @param[in] pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_process_vm_rw_req(veos_thread_arg_t *pti)
{
	int ret = 0;
	int length = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	proc_t ve_proc_info;
	struct ve_process_rw_info ve_process_rw_info = {0};
	pid_t pid = -1;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_vm_rw_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -EINVAL;
		goto send_ack;
	}
	memcpy(&ve_process_rw_info,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);


	/* finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */

	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -ESRCH;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}
	VEOS_DEBUG("base_rvemva = 0x%lx, r_len = 0x%lx, len = %ld"
			" lcov_offeset = 0x%lx, rcov_offest = 0x%lx"
			" remote_vemva = 0x%lx local_vemva = 0x%lx"
			"vm_rw = %d",
			ve_process_rw_info.base_rvemva, ve_process_rw_info.r_len,
			ve_process_rw_info.len, ve_process_rw_info.lcov_offset,
			ve_process_rw_info.rcov_offest, ve_process_rw_info.remote_vemva,
			ve_process_rw_info.local_vemva,
			ve_process_rw_info.vm_rw);

	/* Get the information of /proc/## for the given remote pid */
	ret = psm_get_ve_proc_info(ve_process_rw_info.r_pid, &ve_proc_info);
	if (-1 == ret) {
		VEOS_ERROR("Failed to get proc information for pid: %d",
				tsk->pid);
		ret = -EPERM;
		goto send_ack;
	}

	if (pti->cred.uid == ve_proc_info.euid &&
			pti->cred.uid == ve_proc_info.suid &&
			pti->cred.uid == ve_proc_info.ruid &&
			pti->cred.gid == ve_proc_info.egid &&
			pti->cred.gid == ve_proc_info.sgid &&
			pti->cred.gid == ve_proc_info.rgid) {
		VEOS_DEBUG("Tracer: %d and Tracee: %d belongs to same user",
				ve_proc_info.euid, tsk->pid);
		goto ok;
	}

	/* Check if the  have CAP_SYS_PTRACE capability or not */
	if (!check_ve_proc_capability(tsk->pid, CAP_SYS_PTRACE)) {
		ret = -EPERM;
		goto send_ack;
	}

ok:

	ret = amm_do_processs_vm_rw(tsk, ve_process_rw_info);
	if (0 > ret)
		VEOS_ERROR("error while transferring date between process address space (pid %d)", pid);
	else
		VEOS_DEBUG("transfer of date between process address space is done(pid:%d)", pid);


send_ack:
	ve_vm_rw_ack.has_syscall_retval = true;
	ve_vm_rw_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_vm_rw_ack);

	msg_len = pseudo_veos_message__pack(&ve_vm_rw_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}


/**
* @brief This function serve the request to set the new limit for JID.
*
* @param[in] pti pti containing REQ info.
*
* @return On Success return 0 and -1 on failure.
*/
int amm_handle_set_totol_process(veos_thread_arg_t *pti)
{
	int ret = 0;
	pid_t pid = -1;
	int length = -1;
	int sd = pti->socket_descriptor;
	struct ve_jid_cmd req = {0};
	char ack[MAX_PROTO_MSG_SIZE] = {0};
	ssize_t pseudo_msg_len = -1, msg_len = -1;
	struct ve_task_struct *tsk = NULL;

	VEOS_TRACE("invoked thread arg pti(%p)", pti);
	PseudoVeosMessage ve_set_tproc_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	/* finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */
	tsk = find_ve_task_struct(pid);
	if (NULL == tsk) {
		ret = -1;
		VEOS_DEBUG("Error (%s) while getting task structure for pid %d",
				strerror(-ret), pid);
		goto send_ack;
	}

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (0 >= length) {
		VEOS_DEBUG("Invalid message length %d", length);
		ret = -1;
		goto send_ack;
	}

	memcpy((char *)&req,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);
	ret = amm_do_set_tproc(req, tsk);
	if (0 > ret)
		VEOS_ERROR("error while setting new limit for JID (pid :%d)", pid);
	else
		VEOS_DEBUG("updated new limit for JID (pid %d)", pid);
send_ack:
	ve_set_tproc_req_ack.has_syscall_retval = true;
	ve_set_tproc_req_ack.syscall_retval = ret;

	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_set_tproc_req_ack);

	msg_len = pseudo_veos_message__pack(&ve_set_tproc_req_ack, (uint8_t *)ack);
	if (msg_len != pseudo_msg_len) {
		VEOS_DEBUG("packing protobuf msg error (expected length: %ld returned length: %ld)",
				pseudo_msg_len, msg_len);
		ret = -1;
		goto hndl_error;
	}

	ret = psm_pseudo_send_cmd(sd, ack, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VEOS_DEBUG("error while sending ack (expected bytes: %ld Transferred bytes: %d)",
				pseudo_msg_len, ret);
		ret = -1;
	}

hndl_error:
	if (tsk)
		put_ve_task_struct(tsk);
	VEOS_TRACE("returned");
	return ret;
}
