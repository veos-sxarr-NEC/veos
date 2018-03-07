/*
 * @file amm_ve_req.c
 * @brief Handles commands sent from PSEUDO PROCESS.
 * This file defines command handlers and invokes there respective handlers.
 *
 */
#include <unistd.h>
#include <fcntl.h>
#include <search.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "ve_hw.h"
#include "amm_mem.h"
#include "veos_ipc.h"
#include "veos.h"
#include "psm_task_mgmt.h"
#include "amm_shm.h"
#include "psm_pseudo_ipc.h"
#include "pseudo_veos.pb-c.h"
#include "velayout.h"

/* @brief This is request interface which extracts shmat arguments
* and pass to generic shmat handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_shmat(veos_thread_arg_t *pti)
{
	int ret = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd cmd;
	void *cmd_buf;
	ssize_t pseudo_msg_len;
	int length = -1;
	pid_t pid = -1;
	PseudoVeosMessage ve_shmat_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SHMAT Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
							pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fails in recieving msg %d\n", length);
		goto req_shmat_error;
	}
	memcpy((char *)&cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch ve_task_struct\n");
		ve_shmat_req_ack.has_syscall_retval = true;
		ve_shmat_req_ack.syscall_retval = -EFAULT;
		goto req_shmat_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	ret = amm_do_shmat(cmd.key, cmd.shmid, cmd.vaddr, cmd.size,
			cmd.perm, tsk);
	if (ret == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to do SHMAT\n");
		ve_shmat_req_ack.has_syscall_retval = true;
		ve_shmat_req_ack.syscall_retval = -EFAULT;
		goto req_shmat_error;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"amm_do_shmat Success\n");
		ve_shmat_req_ack.has_syscall_retval = true;
		ve_shmat_req_ack.syscall_retval = 0;
		ret = 0;
	}

req_shmat_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_shmat_req_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		ret = -1;
		goto malloc_error;
	}
	memset(cmd_buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_shmat_req_ack, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"shmat_req_ack pack failed\n");
		ret = -1;
		goto hndl_return;
	}

	ret = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sending SHMAT ACK failed with retval %d\n",
				ret);
		ret = -1;
	}

hndl_return:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief This is request interface which extracts shmctl arguments
* and pass to generic shmctl handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_shmctl(veos_thread_arg_t *pti)
{
	int ret = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd cmd;
	void *cmd_buf;
	ssize_t pseudo_msg_len;
	int length = -1;
	pid_t pid = -1;
	PseudoVeosMessage ve_shmctl_req_ack = PSEUDO_VEOS_MESSAGE__INIT;


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SHMCTL Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive msg SHMCTL %d\n",
				length);
		goto req_shmctl_error;
	}
	memcpy((char *)&cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch ve_task_struct");
		ve_shmctl_req_ack.has_syscall_retval = true;
		ve_shmctl_req_ack.syscall_retval = -EFAULT;
		goto req_shmctl_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	ret = amm_do_shmctl(cmd.shmid, tsk);
	if (ret == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to do SHMCTL\n");
		ve_shmctl_req_ack.has_syscall_retval = true;
		ve_shmctl_req_ack.syscall_retval = -EFAULT;
		goto req_shmctl_error;
	} else {
		ve_shmctl_req_ack.has_syscall_retval = true;
		ve_shmctl_req_ack.syscall_retval = 0;
	}
	ret = 0;

req_shmctl_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_shmctl_req_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		ret = -1;
		goto malloc_error;
	}
	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_shmctl_req_ack, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"shmctl_req_ack pack failed\n");
		ret = -1;
		goto hndl_error;
	}

	ret = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (ret < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sending SHMCTL ACK failed with retval %d\n",
				ret);
		ret = -1;
	}

hndl_error:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief This is request interface which extracts shmdt arguments
* and pass to shmdt handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_shmdt(veos_thread_arg_t *pti)
{
	int ret = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_shm_cmd cmd;
	void *cmd_buf;
	ssize_t pseudo_msg_len;
	int length = -1;
	pid_t pid = -1;
	struct shmdt_info dt_info;
	ProtobufCBinaryData ve_shm_ack_msg;
	PseudoVeosMessage ve_shmdt_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");
	memset(&dt_info, '\0', sizeof(dt_info));
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"SHMDT Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
							pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed recieving msg SHMTDT_REQ %d\n",
				length);
		goto req_shmdt_error;
	}
	memcpy((char *)&cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		ve_shmdt_ack.has_syscall_retval = true;
		ve_shmdt_ack.syscall_retval = -EFAULT;
		goto req_shmdt_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	ret = amm_do_shmdt(cmd.vaddr, tsk, &dt_info);
	if (ret == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to do SHMDT\n");
		ve_shmdt_ack.has_syscall_retval = true;
		ve_shmdt_ack.syscall_retval = -EFAULT;
		goto req_shmdt_error;
	} else {
		ve_shmdt_ack.has_syscall_retval = true;
		ve_shm_ack_msg.len = sizeof(struct shmdt_info);
		ve_shm_ack_msg.data = (uint8_t *)&dt_info;
		ve_shmdt_ack.has_pseudo_msg = true;
		ve_shmdt_ack.pseudo_msg = ve_shm_ack_msg;
	}
req_shmdt_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_shmdt_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		ret = -1;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto malloc_error;
	}
	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_shmdt_ack, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"shmdt_ack pack failed\n");
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sending SHMDT ACK failed with retval %d\n",
				ret);
		ret = -1;
	}

hndl_error:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief This is request interface which extracts mmap arguments
* and pass to generic mmap handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_mmap(veos_thread_arg_t *pti)
{
	int retval = -1;
	struct ve_mmap_cmd *cmd = NULL;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct file_map_stat *f_map_stat = NULL;

	pid_t pid = -1;
	void *cmd_buf = NULL;
	ssize_t pseudo_msg_len;
	int length = -1;
	PseudoVeosMessage ve_mmap = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* PID recieved from PSEUDO process */
	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Mmap Request From PID : %d\n", pid);

	cmd = (struct ve_mmap_cmd *)malloc(sizeof(struct ve_mmap_cmd));
	if (!cmd) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s\n", strerror(errno));
		retval = -1;
		goto malloc_error;
	}
	memset(cmd, '\0', sizeof(struct ve_mmap_cmd));

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Fail to receive msg for MMAP_REQ %d\n",
				length);
		goto malloc_error;
	}

	memcpy(cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/*If file backed*/
	if (!(cmd->flags & MAP_ANON)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Fetching file_stat for file_backed_mmap\n");

		f_map_stat = (struct file_map_stat *)
			malloc(sizeof(struct file_map_stat));
		if (f_map_stat == NULL) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s\n", strerror(errno));
			retval = -1;
			goto malloc_error;
		}
		memset(f_map_stat, '\0', sizeof(struct file_map_stat));

		/* Fetching File Information Received from pseudo */
		memcpy(f_map_stat,
			&(cmd->f_map_stat), sizeof(struct file_map_stat));
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"file_inode %ld offset_start %ld "
				"offset_end %ld\n",
				f_map_stat->file_stat.st_ino,
				f_map_stat->offset_start,
				f_map_stat->offset_end);
	}

	/*
	 * finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */

	ve_mmap.has_syscall_retval = true;

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch the ve_mm_struct of PID :%d\n",
				pid);
		ve_mmap.syscall_retval = -EFAULT;
		goto hndl_return;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	retval = amm_do_mmap(cmd->vaddr, cmd->size, cmd->perm, cmd->flags,
				tsk, f_map_stat);
	if (retval < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Failed to mmap\n");
		ve_mmap.syscall_retval = -EFAULT;
		goto hndl_return;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Sending ACK to requesting process\n");

		ve_mmap.syscall_retval = 0;
		retval = 0;
		goto hndl_return;
	}

hndl_return:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_mmap);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		retval = -1;
		goto malloc_error;
	}
	memset(cmd_buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_mmap, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"MMAP ACK pack failed\n");
		retval = -1;
		goto malloc_error;
	}

	retval = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				retval);
		retval = -1;
	}
malloc_error:
	if (cmd_buf)
		free(cmd_buf);
	if (f_map_stat)
		free(f_map_stat);
	if (cmd)
		free(cmd);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief This is request interface which extracts munmap arguments
* and pass to generic unmap handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_munmap(veos_thread_arg_t *pti)
{
	int ret = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct ve_munmap_cmd cmd;
	void *cmd_buf = NULL;
	ssize_t pseudo_msg_len;
	int length = -1;
	pid_t pid = -1;
	PseudoVeosMessage ve_munmap_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Munmap Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
							pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to recieve msg for DMA_REQ %d\n", length);
		goto req_munmap_error;
	}
	memcpy((char *)&cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch ve_task_struct of PID : %d\n",
				pid);
		ve_munmap_req_ack.has_syscall_retval = true;
		ve_munmap_req_ack.syscall_retval = -EFAULT;
		goto req_munmap_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	ret = amm_do_munmap(cmd.vaddr, cmd.size, tsk);
	if (ret == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to do munmap\n");
		ve_munmap_req_ack.has_syscall_retval = true;
		ve_munmap_req_ack.syscall_retval = -EFAULT;
		goto req_munmap_error;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"amm_do_munmap Success\n");
		ve_munmap_req_ack.has_syscall_retval = true;
		ve_munmap_req_ack.syscall_retval = 0;
		ret = 0;
	}

req_munmap_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_munmap_req_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		ret = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto malloc_error;
	}
	memset(cmd_buf, '\0', pseudo_msg_len);
	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_munmap_req_ack, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"munmap_req_ack Pack failed\n");
		ret = -1;
		goto hndl_error;
	}

	ret = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sending MUNMAP ACK failed with retval %d\n",
				ret);
		ret = -1;
	}
hndl_error:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief This is request interface which extracts mprotect arguments
* and pass to generic mprotect handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_mprotect(veos_thread_arg_t *pti)
{
	int ret = -1;
	int32_t pid;
	int length = -1;
	struct ve_task_struct *tsk = NULL;
	ProtobufCBinaryData pseudo_mprotect_msg;
	struct pseudo_mprotect_req mprotect_request;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In func\n");

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"Mprotect Request From PID : %d\n", pid);

	/* finds the ve_task_struct based on the pid received from
	 * pseudo process.
	 */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to fetch the ve_task_struct of PID : %d\n",
			pid);
		ret = amm_send_mprotect_ack(pti, -1);
		if (-1 == ret)
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"send_mprotect_ack failed\n");
		else
			ret = -1;

		goto req_mprotect_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to recieve msg for DMA_REQ %d\n", length);
		goto req_mprotect_error;
	}

	/* Retrive pseudo_mprotect_req data from proto-message */
	pseudo_mprotect_msg = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->
		pseudo_msg;
	memcpy(&mprotect_request, pseudo_mprotect_msg.data,
			pseudo_mprotect_msg.len);

	ret = amm_do_mprotect(mprotect_request.ret_addr, mprotect_request.size,
			mprotect_request.prot, tsk);
	if (ret == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to mprotect\n");
		ret = amm_send_mprotect_ack(pti, -1);
		if (-1 == ret)
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"send_mprotect_ack failed\n");
		else
			ret = -1;
		goto req_mprotect_error;
	} else {
		ret = amm_send_mprotect_ack(pti, 0);
		if (-1 == ret)
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"send_mprotect_ack failed\n");
		else
			ret = 0;
	}

req_mprotect_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out func\n");
	return ret;
}

/**
 * @brief Sends acknowlegdment for MPROTECT
 *               request received from pseudo process.
 *
 * @param[in] pti contains the request received from the pseudo process
 * @param[in] syscall_ret contains return value of halt_core_request
 *
 * @return On failure, returns -1 and on success, returns a positive value
 */
int amm_send_mprotect_ack(struct veos_thread_arg *pti, int64_t syscall_ret)
{
	int ret = -1;
	PseudoVeosMessage mprotect_ack = PSEUDO_VEOS_MESSAGE__INIT;
	void *buf = NULL;
	ssize_t pseudo_msg_len;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	/* Populate acknowledgment message */
	mprotect_ack.has_syscall_retval = true;
	mprotect_ack.syscall_retval = syscall_ret;

	/* Pack mprotect_ack before sending */
	pseudo_msg_len = pseudo_veos_message__get_packed_size
		(&mprotect_ack);
	buf = malloc(pseudo_msg_len);
	if (NULL == buf) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Malloc for structure packing failed.\n");
		ret = -1;
		goto malloc_error;
	}
	memset(buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&mprotect_ack, buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"mprotect_ack pack failed\n");
		ret = -1;
		goto hndl_return;
	}


	/* Send ACK to the pseudo side */
	ret = psm_pseudo_send_cmd(pti->socket_descriptor,
			buf,
			pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				ret);
		ret = -1;
	}

hndl_return:
	if (buf)
		free(buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}

/**
* @brief This is request interface for dma memory.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_dma_req(veos_thread_arg_t *pti)
{
	int retval = -1;
	int srctype, dsttype;
	uint64_t src_addr, dst_addr;
	int length = -1;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk;
	void *cmd_buf = NULL;
	ssize_t pseudo_msg_len;
	struct dma_args dma_param;
	pid_t pid = -1;
	PseudoVeosMessage ve_dma_req_ack = PSEUDO_VEOS_MESSAGE__INIT;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"DMA Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to received message for "
				"command DMA_REQ %d\n",
				length);
		goto req_dma_error;
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

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "DMA.SRCTYPE : %d,"
			"DMA.DSTTYPE : %d"
			"DMA.SRCADDR : %lx"
			"DMA.DSTADDR : %lx"
			"DMA.LEN : %ld\n",
			dma_param.srctype,
			dma_param.dsttype,
			dma_param.srcaddr,
			dma_param.dstaddr,
			dma_param.size);

	 /* finds the ve_task_struct based on the pid received from
	  * pseudo process.
	  */

	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
					MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch the ve_task_struct "
				"of PID : %d\n",
				pid);
		ve_dma_req_ack.has_syscall_retval = true;
		ve_dma_req_ack.syscall_retval = -EFAULT;
		goto req_dma_error;
	}

	retval =  amm_dma_xfer(srctype, src_addr, pid, dsttype,
				dst_addr, pid, length, tsk->node_id);

	if (retval < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"DMA transfer Failed\n");
		ve_dma_req_ack.has_syscall_retval = true;
		ve_dma_req_ack.syscall_retval = -EFAULT;
		goto req_dma_error;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Sending ACK to requesting process\n");
		ve_dma_req_ack.has_syscall_retval = true;
		ve_dma_req_ack.syscall_retval = 0;
	}
		retval = 0;
req_dma_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&ve_dma_req_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		retval = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto malloc_error;
	}
	if (pseudo_msg_len != pseudo_veos_message__pack(&ve_dma_req_ack,
				cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"dma_req pack failed\n");
		retval = -1;
		goto hndl_error;
	}
	retval = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (retval < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Sending DMA ACK failed with retval %d\n",
				retval);
		retval = -1;
	}

hndl_error:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return retval;
}

/**
* @brief This is request interface which extracts mremap arguments
* and pass to generic mremap handler.
*
* @param[in] pti containing REQ info
*
* @return On Success return 0 and -1 on failure
*/
int amm_handle_mremap(veos_thread_arg_t *pti)
{
	int ret = 0;
	uint64_t vaddr_old;
	uint64_t vaddr_new;
	size_t size_old;
	size_t size_new;
	int sd = pti->socket_descriptor;
	struct ve_task_struct *tsk = NULL;
	struct mremap_cmd mremap_cmd;
	void *cmd_buf = NULL;
	ssize_t pseudo_msg_len;
	int length = -1;
	pid_t pid = -1;
	PseudoVeosMessage ve_mremap_req_ack = PSEUDO_VEOS_MESSAGE__INIT;


	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	pid = ((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_pid;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"mremap Request From PID : %d\n", pid);

	length = (((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			pseudo_msg).len;
	if (length <= 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive msg for DMA_REQ %d\n",
				length);
		goto mremap_error;
	}
	memcpy((char *)&mremap_cmd,
			(((PseudoVeosMessage *)(pti->pseudo_proc_msg))->
			 pseudo_msg).data,
			length);

	vaddr_old = mremap_cmd.vaddr_old;
	vaddr_new = mremap_cmd.vaddr_new;
	size_old  = mremap_cmd.size_old;
	size_new  = mremap_cmd.size_new;

	/* finds the ve_task_struct based on the pid received from pseudo
	 * process */
	tsk = find_ve_task_struct(0, MAX_VE_NODE_PER_VH, 0,
			MAX_VE_CORE_PER_VE_NODE, pid);
	if (NULL == tsk) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to fetch the ve_task_struct "
				"of PID : %d\n",
				pid);
		ve_mremap_req_ack.has_syscall_retval = true;
		ve_mremap_req_ack.syscall_retval = -EFAULT;
		goto mremap_error;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
			"TASK CORE-ID : %d PID : %d TASK mm_struct %p\n",
			tsk->core_id, pid, tsk->p_ve_mm);

	ret = amm_do_mremap(vaddr_old, size_old, size_new, vaddr_new, tsk);
	if (ret < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "Failed to mremap\n");
		ve_mremap_req_ack.has_syscall_retval = true;
		ve_mremap_req_ack.syscall_retval = -EFAULT;
		goto mremap_error;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Sending ACK to requesting process\n");
		ve_mremap_req_ack.has_syscall_retval = true;
		ve_mremap_req_ack.syscall_retval = 0;
	}
		ret = 0;

mremap_error:
	pseudo_msg_len = pseudo_veos_message__get_packed_size(&
			ve_mremap_req_ack);
	cmd_buf = malloc(pseudo_msg_len);
	if (NULL == cmd_buf) {
		ret = -errno;
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR, "malloc failed %s\n",
				strerror(errno));
		goto malloc_error;
	}
	memset(cmd_buf, '\0', pseudo_msg_len);

	if (pseudo_msg_len != pseudo_veos_message__pack(&
				ve_mremap_req_ack, cmd_buf)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"mremap_req_ack PACK failed\n");
		ret = -1;
		goto hndl_error;
	}
	ret = psm_pseudo_send_cmd(sd, cmd_buf, pseudo_msg_len);
	if (ret < pseudo_msg_len) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"pseudo_psm_send_cmd wrote %d bytes\n",
				ret);
		ret = -1;

	}

hndl_error:
	free(cmd_buf);
malloc_error:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}
