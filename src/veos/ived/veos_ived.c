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
 * @file  veos_ived.c
 * @brief IVED functions in VEOS
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
#include <uuid/uuid.h>
#include <sys/un.h>
#include "veos.h"
#include "libved.h"
#include "veos.h"
#include "veos_ived.h"
#include "veos_veshm_core.h"
#include "ived_ipc.h"
#include "ived_common.h"
#include "ived.pb-c.h"
#include "veos_cr.h"
#include "veos_veshm_ipc.h"
#include "veos_veshm.h"
#include "veos_vhshm.h"
#include "ve_swap.h"

#define LOCK_TIMEOUT 10      /* seconds */

int  ived_socket_fd;		/* Socket to IVED */
int  ived_linkage;
struct ve_node_struct *current_node = NULL;
pthread_t ived_req_thread;
uuid_t null_id;			/* It represents NULL ID */

pthread_rwlockattr_t rw_lock_attr;
pthread_rwlock_t ived_requesting_lock;

/* When VEOS acquires ived_task_list_lock, veshm_remains_lock
 * and ived_resource_lock, VEOS must acquires the locks
 * in this order.
 * 1. ived_task_list_lock
 * 2. ived_resource_lock
 * 3. veshm_remains_lock
 *
 */

/* List of ived_shared_resource_data */
struct list_head ived_task_list;
/* Protect list in ived_shared_resource_data */
pthread_mutex_t ived_task_list_lock;

log4c_category_t *log4cat_veos_ived = NULL;

static int veos_ived_register_procdata(struct ived_shared_resource_data *);
static int veos_ived_erase_procdata(struct ived_shared_resource_data *);

/**
 * @brief Initializing for IVED functions
 *
 * @return 0 on success, -1 on failure
 */
int
veos_ived_init()
{
	struct sockaddr_un sa;

	/* IVED socket check */
	if (ived_sock_file[0] == '\0'){
		IVED_ERROR(log4cat_veos_ived, 
			   "IVED socket file is not found.");
		goto err_ret_nolock;
	}
	if (access(ived_sock_file, F_OK)){
		IVED_ERROR(log4cat_veos_ived, 
			   "IVED socket file is not found.");
		goto err_ret_nolock;
	}

	if (strlen(ived_sock_file) > sizeof(sa.sun_path)-1){
		IVED_ERROR(log4cat_veos_ived, 
			   "IVED socket file is too long.");
		goto err_ret_nolock;
	}
	ived_sock_file[sizeof(sa.sun_path)-1] = '\0';

	current_node = VE_NODE(0);


	/* List of ived_shared_resource_data */
	INIT_LIST_HEAD(&ived_task_list);

	/* Terminated processes' VESHM list */
	INIT_LIST_HEAD(&veshm_remains_list);

	/* Initialize locks */
	pthread_mutex_init(&ived_task_list_lock, NULL);
	pthread_mutex_init(&veshm_remains_lock, NULL);

	if (pthread_rwlockattr_init(&rw_lock_attr) < 0) {
		IVED_ERROR(log4cat_veos_ived, "%s", strerror(errno));
		goto err_ret_lock1;
	}
	pthread_rwlockattr_setkind_np
		(&rw_lock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	if (pthread_rwlock_init(&ived_requesting_lock, &rw_lock_attr) != 0){
		IVED_ERROR(log4cat_veos_ived, "Initializing a lock failed.");
		goto err_ret_lock2;
	}

	/* misc */
	uuid_clear(null_id);

	IVED_DEBUG(log4cat_veos_ived, "Initialized IVED agent.");

	return(0);

err_ret_lock2:
	pthread_rwlock_destroy(&ived_requesting_lock);
	pthread_rwlockattr_destroy(&rw_lock_attr);
err_ret_lock1:
	pthread_mutex_destroy(&veshm_remains_lock);
err_ret_nolock:
	return(-1);
}

/**
 * @brief Finalize IVED agent
 *
 * @return 0
 */
int
veos_ived_finalize()
{
	IVED_DEBUG(log4cat_veos_ived, "Clean up IVED resources.");

	/* Clear locks */
	pthread_mutex_destroy(&veshm_remains_lock);
	pthread_rwlockattr_destroy(&rw_lock_attr);

	return(0);
}



/**
 * @brief get a telegram and extract a command from IVED.
 * 
 * @param [in]     socket       Socket to IVED 
 * @param [in,out] message_buf  Buffer to store a telegram
 * @param [in,out] rpc_command  Buffer to store an unpacked command struct
 *
 * @return received size of a message, and update message_buf and rpc_command on success
 *  return a negative value and *rpc_command is set NULL on failure
 */
static int
get_command_from_ived(int socket, uint8_t *message_buf, 
		      RpcCommand **rpc_command)
{
	int received_size;

	if ((message_buf == NULL) || (rpc_command == NULL)){
		IVED_ERROR(log4cat_veos_ived,"%s", strerror(EINVAL));
		return(-1);
	}
	/* Wait a request and receive it */
	received_size = ived_rpc_receive(socket, &message_buf);
	if (received_size < 0){
		return -1;
	}
	IVED_DEBUG(log4cat_veos_ived, "Receive a message from IVED");
	*rpc_command = rpc_command__unpack (NULL, received_size, message_buf);

	if (*rpc_command == NULL){
		IVED_ERROR(log4cat_veos_ived, "Cannot read a request.");
		return (-1);
	}
	return(received_size);
}



/**
 * @brief Wait and execute  a request from IVED
 *
 * This thread works until veos termination.
 * Receive a message, execute the request, then send a reply.
 *
 * @retval NULL on failure
 */
static void
execute_req_from_ived()
{
	int ret;
	int received_size;
	uint8_t *message_buf = NULL;
	RpcCommand *rpc_command = NULL;
	RpcVeshmArg *request_veshm = NULL;
	RpcCrArg *request_cr = NULL;
	IvedReturn reply;
	int invalid_cmd;

	IVED_TRACE(log4cat_veos_ived, "PASS");

	ret = get_rpc_buf(&message_buf, IVED_BUF_MAX_SIZE);
	if (ret != 0){
		IVED_CRIT(log4cat_veos_ived, 
			  "Can't handle IVED requests. (ENOMEM)");
		goto err_ret_nolock;
	}
	memset(message_buf, 0, IVED_BUF_MAX_SIZE);

	while(1){
		/* Performing a request is done sequentially. */
		ived_return__init(&reply);

		received_size = get_command_from_ived
			(ived_socket_fd, message_buf, &rpc_command);

		ret = pthread_rwlock_rdlock(&ived_requesting_lock);
		if (ret != 0 ){
			veos_abort("Abort a request from IVED.");
			/* Not return to here */
		}

		if (received_size <= 0){
			/* A socket of IVED side closed or error occured */
			goto ret;
		}

		IVED_DEBUG(log4cat_veos_ived, 
			   "New request from IVED:  subcmd:%#x",
			   rpc_command->cmd);

		invalid_cmd = 0;	/* For cmd and subcmd check */

		switch (rpc_command->cmd){
		case IVED_VESHM:
			/* Release a VESHM area. Reauested by VESHM detach */
			request_veshm = rpc_command->veshm;
			if (request_veshm == NULL){
				IVED_ERROR(log4cat_veos_ived, 
					   "Obtaining an argument failed.");
				ived_send_int64(ived_socket_fd, IVED_REQ_NG, 
						-ECANCELED);
				break;
			}
			switch(request_veshm->subcmd){
			case VESHM_DETACH_AREA:
				dump_uuid("Erased VESHM owner", 
					  request_veshm->detach_arg->
					  uuid_proc.data);
				dump_uuid("Erased VESHM", 
					  request_veshm->detach_arg->
					  uuid_veshm.data);

				veos_veshm_erase_area
					(request_veshm->detach_arg->n_pci_address,
					 request_veshm->detach_arg->pci_address,
					 request_veshm->detach_arg->mode_flag);
				/* NOTE: Send ack to IVED after
				 * veos_veshm_erase_area. IVED doesn't care 
				 * a result of the function.
				 * VEOS and IVED can ignore a result of 
				 * ived_send_int64(). The result doesn't affect
				 * them.
				 */
				ived_send_int64(ived_socket_fd, IVED_REQ_OK, 0);
				break;
			default:
				invalid_cmd = 1;
				break;
			}
			break;
		case IVED_CR:
			request_cr = rpc_command->cr;
			if (request_cr == NULL){
				IVED_ERROR(log4cat_veos_ived, 
					   "Obtaining CR argument failed.");
				ived_send_int64(ived_socket_fd, IVED_REQ_NG, 
						-ECANCELED);
				break;
			}
			veos_cr_rpc_from_ived(ived_socket_fd, request_cr);
			break;
		default:
			invalid_cmd = 1;
			break;
		}

		if (invalid_cmd == 1){
			IVED_ERROR(log4cat_veos_ived,"%s", strerror(EINVAL));
			ived_send_int64(ived_socket_fd, IVED_REQ_NG, -EINVAL);
		}

		/* Clear used buffers */
		memset(message_buf, 0, IVED_BUF_MAX_SIZE);
		rpc_command__free_unpacked(rpc_command, NULL);
		rpc_command = NULL;
		request_veshm = NULL;
		request_cr = NULL;
		pthread_rwlock_unlock(&ived_requesting_lock);
	}

ret:
	pthread_rwlock_unlock(&ived_requesting_lock);

err_ret_nolock:
	ived_finish_soc(ived_socket_fd);
	if (message_buf != NULL)
		free(message_buf);
	pthread_exit(NULL);
}


/**
 * @brief Connect to IVED and register VE node.
 * It is the first IVED function called by a veos.
 *
 * @return  O on success, -1 on failure.
 * */
int
veos_ived_register_osdata()
{
	int ret, retval = -1;
	pthread_attr_t pthread_attr;

	vedl_handle *handle;
	uint64_t pciatb_pgsize, pci_bar01, pci_bar3, pci_bar01_size; 

	RpcOsRegister osdata = RPC_OS_REGISTER__INIT;
	RpcIvedArg ived_arg  = RPC_IVED_ARG__INIT;
	IvedReturn *result = NULL;	/* IVED returns the type */

	/* Initialize */
	ret = veos_ived_init();
	if (ret != 0){
		retval = ret;
		goto err_ret;
	}

	handle = current_node->handle;
	if (handle == NULL){
		IVED_CRIT(log4cat_veos_ived, "vedl handle is NULL");
		goto err_ret;
	}

	ret = vedl_get_pci_bar0_address(handle, &pci_bar01);
	if (ret != 0)
		goto err_ret;

	ret = vedl_get_pci_bar3_address(handle, &pci_bar3);
	if (ret != 0)
		goto err_ret;

	/* Set PCI BAR01 start address */
	current_node->pci_bar01_vhsaa = pci_bar01;

	/* Get PCIATB page size. IVED needs to know the size before
	 * AMM function sets vnode_info->pciattr. */
	ret = vedl_get_pci_bar0_size(handle, &pci_bar01_size);
	if (ret != 0)
		goto err_ret;
	if (pci_bar01_size < 128 * SIZE_MB) {
		IVED_ERROR(log4cat_veos_ived, "BAR01 size %lx is too small",
			   pci_bar01_size);
		goto err_ret;
	} else if (pci_bar01_size == 128 * SIZE_MB) {
		pciatb_pgsize = PGSIZE_2M;
	} else {
		pciatb_pgsize = PGSIZE_64M;
	}

	/* Set arguments */
	osdata.pid         = getpid();
	osdata.socket_name = drv_sock_file;
	osdata.pciatb_pgsize = pciatb_pgsize;
	osdata.bar01_addr    = pci_bar01;
	osdata.bar3_addr     = pci_bar3;
	IVED_DEBUG(log4cat_veos_ived, "Device :%s", osdata.socket_name);
	IVED_DEBUG(log4cat_veos_ived, "bar01:0x%"PRIx64"", osdata.bar01_addr);
	IVED_DEBUG(log4cat_veos_ived, "bar3 :0x%"PRIx64"", osdata.bar3_addr);

	ived_arg.subcmd = IVED_OS_REG;
	ived_arg.register_os_arg = &osdata; 

	/* Create socket to IVED */
	ived_socket_fd = ived_create_soc(ived_sock_file);
	if (ived_socket_fd < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		goto err_ret;
	}

	ret = ived_exchange_ived_msg(ived_socket_fd, &ived_arg, &result);
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "Sending OS registration failed");
		goto err_ret;
	}
	if (result->error){
		IVED_ERROR(log4cat_veos_ived,
			   "OS registration failed.:#%d %s",
			   result->error, strerror(-result->error));
		goto err_ret;
	}
	IVED_DEBUG(log4cat_veos_ived, 
		   "OS Registration succeeded.");

	/* Create a thread for executing a request from IVED.
	 * The thread uses the socket created by this function.
	 */
	ret = pthread_attr_init(&pthread_attr);
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived,"%s", strerror(errno));
		goto err_ret;
	}
	pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&ived_req_thread, &pthread_attr, 
		       (void *)execute_req_from_ived, NULL);
	pthread_attr_destroy(&pthread_attr);

	ived_return__free_unpacked(result, NULL);

	/* Note: Don't close ived_socket_fd if this request succeeded.
	 * The socket connects to IVED persistently to receive requests
	 * from IVED. */

	ived_linkage = 1;
	retval = 0;

	IVED_DEBUG(log4cat_veos_ived, "retval = %d", retval);
	return(retval);

err_ret:
	if (ived_socket_fd != -1){
		ret = ived_finish_soc(ived_socket_fd);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
	if (result != NULL)
		ived_return__free_unpacked(result, NULL);

	IVED_DEBUG(log4cat_veos_ived, "error retval = %d", retval);
	return(retval);
}

/**
 * @brief Erase registration of VEOS.
 * Even if an error occured, this function return 0 (Success).
 * IVED daemon will fix veos data when VEOS for the same VE
 * node will boot.
 *
 * @return  Always 0 if IVED lincage is valid. -1 if IVED lincage is invalid.
 */
int
veos_ived_erase_osdata()
{
	int ret;
	int ived_req_sock;

	RpcOsRegister osdata = RPC_OS_REGISTER__INIT;
	RpcIvedArg ived_arg  = RPC_IVED_ARG__INIT;
	IvedReturn *result = NULL;	/* IVED returns the type */

	if (IVED_LINKAGE_OFF){
		IVED_WARN(log4cat_veos_ived, "Unnecessary call.");
		return(-1);
	}

	IVED_TRACE(log4cat_veos_ived, "PASS");

	/* Wait finishing of all IVED requests */
	ived_linkage = 0;

	/* Note: All VE processes are terminated by VEOS(PSM). */

	/* Set arguments */
	osdata.pid         = getpid();
	set_flag(osdata.mode_flag, IVED_VEOS_EXIT);
	ived_arg.subcmd = IVED_OS_STOP;
	ived_arg.register_os_arg = &osdata; 

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		goto err_ret;
	}

	ret = ived_exchange_ived_msg(ived_req_sock, &ived_arg, &result);
	if (ret != 0 || result == NULL){
		/* Even if this communication failed, it isn't a fatal error.
		 * IVED can detect VEOS termination. */
		IVED_WARN(log4cat_veos_ived,
			  "Sending OS termination failed.");
		goto err_ret;
	} 
	if (result->retval < 0){
		IVED_WARN(log4cat_veos_ived,
			  "Sending OS termination failed.:#%d %s",
			  result->error, strerror(-result->error));
		goto err_ret;
	}

	ived_return__free_unpacked(result, NULL);

	ived_finish_soc(ived_req_sock);
	if (errno == EIO){
		IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
	}

	pthread_rwlock_wrlock(&ived_requesting_lock);
	veos_ived_finalize();

	IVED_DEBUG(log4cat_veos_ived, "Erasing VEOS succeeded");
	return(0);

err_ret:
	pthread_rwlock_wrlock(&ived_requesting_lock);
	veos_ived_finalize();

	if (ived_socket_fd != -1){
		ret = ived_finish_soc(ived_socket_fd);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
	if (result != NULL)
		ived_return__free_unpacked(result, NULL);

	IVED_ERROR(log4cat_veos_ived, "Erasing VEOS failed");
	return(0);
}



/**
 * @brief Initialize IVED resource management data per process
 * If an argument tsk is a thread and it has had a ived_shared_resource_data,
 * this function returns 0.
 *
 * @param [in] tsk	ve_task_struct of a new task
 *
 * @return 0 on success, -1 on failure
 */
int
veos_init_ived_proc_property(struct ve_task_struct *tsk)
{
	int ret;
	struct ived_shared_resource_data *newdata = NULL;

	if (IVED_LINKAGE_OFF){
		return(0);
	}

	if (tsk == NULL) {
		IVED_CRIT(log4cat_veos_ived, "%s", strerror(EINVAL));
		goto err_ret;
	}

	/* Copying may be not needed. */
	if (tsk->group_leader != tsk){
		tsk->ived_resource = tsk->parent->ived_resource;
		IVED_DEBUG(log4cat_veos_ived, "Not group leader");
		goto ret_sucess;
	}
	if (tsk->ived_resource != NULL){
		IVED_ERROR(log4cat_veos_ived, "IVED data exists: %p",
			   tsk->ived_resource);
		goto ret_sucess;
	}

	newdata = (struct ived_shared_resource_data *)malloc
		(sizeof(struct ived_shared_resource_data));
	if (newdata == NULL){
		IVED_CRIT(log4cat_veos_ived, 
			  "Inter VE resource data allocation failed");
		goto err_ret;
	}

	if (pthread_rwlock_init(&newdata->ived_resource_lock,
				&rw_lock_attr) != 0){
		IVED_CRIT(log4cat_veos_ived, 
			  "Initialize ived resource lock failed.");
		goto err_ret;
	}

	if (veos_cr_init_resource(newdata)) {
		IVED_ERROR(log4cat_veos_ived,
			   "Initializing CR management data failed.");
		goto err_ret;
	}

	if (pthread_mutex_init(&newdata->re_attach_veshm_lock,
				NULL) != 0){
		IVED_CRIT(log4cat_veos_ived,
			  "Initialize re-attach veshm lock failed.");
		goto err_ret;
	}

	INIT_LIST_HEAD(&newdata->owned_veshm_list);
	INIT_LIST_HEAD(&newdata->attach_veshm_list);
	INIT_LIST_HEAD(&newdata->swapped_owned_veshm_list);
	INIT_LIST_HEAD(&newdata->swapped_attach_veshm_list);
	newdata->owned_veshm_num    = 0;
	newdata->attach_veshm_num   = 0;
	newdata->pid		    = tsk->pid;
	newdata->is_swap_out	    = false;
	uuid_generate(newdata->uuid_proc);

	/* Initialize a resource information about VHSHM */
	ret = veos_initialize_vhshm_resource(newdata);
	if (ret != 0) {
		pthread_rwlock_destroy(&newdata->ived_resource_lock);
		pthread_mutex_destroy(&newdata->proc_cr_lock);
		pthread_mutex_destroy(&newdata->re_attach_veshm_lock);
		goto err_ret;
	}

	/* Register a new process with IVED */
	ret = veos_ived_register_procdata(newdata); 
	if (ret < 0){
		pthread_rwlock_destroy(&newdata->ived_resource_lock);
		pthread_mutex_destroy(&newdata->proc_cr_lock);
		pthread_mutex_destroy(&newdata->re_attach_veshm_lock);
		pthread_mutex_destroy(
				&newdata->veos_vhshm_res_head.veos_vhshm_lock);
		goto err_ret;
	}

	pthread_mutex_lock(&ived_task_list_lock);
	list_add(&(newdata->list), &ived_task_list);
	pthread_mutex_unlock(&ived_task_list_lock);

	tsk->ived_resource = newdata;

	IVED_DEBUG(log4cat_veos_ived, "Initialization succeeded. (data:%p)",
		   newdata);

ret_sucess:
	return(0);

err_ret:
	if (newdata != NULL)
		free(newdata);
	return(-1);
}

/**
 * @brief IVED resource management data per process
 *
 * @param [in] tsk	ve_task_struct of a terminating process
 *
 * @return 0 on success, -1  on failure
 */
int
veos_clean_ived_proc_property(struct ve_task_struct *tsk)
{
	int ret;
	struct ived_shared_resource_data *ived_resource = NULL;

	if (IVED_LINKAGE_OFF){
		return(0);
	}

	IVED_TRACE(log4cat_veos_ived, "PASS");
	if (tsk == NULL){
		IVED_CRIT(log4cat_veos_ived, "%s",strerror(EINVAL)); 
		return(-1);

	}

	if (tsk->group_leader != tsk)
		return(0);

	ived_resource = tsk->ived_resource;

	/* Free and delete
	* swapped_owned_veshm_list and swapped_attach_veshm_list
	 */
	del_swapped_owned_veshm_list(tsk);
	del_swapped_attach_veshm_list(tsk);

	/* Try to clear all VESHM area. Some VESHM which is used by other
	 * VESHM user processes are not cleared. 
	 * Attaching VESHM info are freed forcibly. Information of attaching
	 * in IVED side will be cleared in a erasing process data request. */
	ret = veos_veshm_discard_all(tsk);
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "Releasing VESHM failed.");
	}

	ret = veos_cr_discard_all(tsk);
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "Releasing local CR pages failed.");
	}

	/* Release VHSHM resources */
	ret = veos_delete_vhshm_resource(ived_resource);
	if (ret != 0)
		IVED_ERROR(log4cat_veos_ived,
					"Releasing VHSHM resources failed");

	/* Erase a registration of this process */
	veos_ived_erase_procdata(ived_resource);

	pthread_mutex_lock(&ived_task_list_lock);
	pthread_rwlock_wrlock(&ived_resource->ived_resource_lock);
	list_del(&ived_resource->list);
	pthread_mutex_unlock(&ived_task_list_lock);
	pthread_rwlock_unlock(&ived_resource->ived_resource_lock);

	pthread_rwlock_destroy(&ived_resource->ived_resource_lock);
	pthread_mutex_destroy(&ived_resource->proc_cr_lock);
	pthread_mutex_destroy(&ived_resource->re_attach_veshm_lock);
	free(ived_resource);
	tsk->ived_resource = NULL;

	return(0);
}


/**
 * @brief Connect to IVED and register process.
 *
 * It can register processe which are executed by a user.
 *
 * @param [in] resource  IVED resource management data
 *
 * @return  O on success, negative value on failure.
 */
static int
veos_ived_register_procdata(struct ived_shared_resource_data *resource)
{
	int ret, retval = -1;
	int ived_req_sock = -1;

	RpcIvedArg ived_arg = RPC_IVED_ARG__INIT;
	RpcProcList proc_list_arg = RPC_PROC_LIST__INIT;
	IvedReturn *result = NULL;
	ProtobufCBinaryData uuid_data;

	if (IVED_LINKAGE_OFF){
		return(0);
	}

	assert(resource != NULL);
	if (resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veos_ived, "New request from pid: %d subcmd:%#x",
		   resource->pid, IVED_PROC_REG);

	proc_list_arg.uid = UNUSED;
	proc_list_arg.pid = resource->pid;

	uuid_data.len		= sizeof(uuid_t);
	uuid_data.data		= (uint8_t *)resource->uuid_proc;
	proc_list_arg.uuid_proc	= uuid_data;
	dump_uuid("proc", uuid_data.data);

	ived_arg.subcmd = IVED_PROC_REG;
	ived_arg.proc_arg = &proc_list_arg;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		goto err_ret;
	}

	ret = ived_exchange_ived_msg(ived_req_sock, &ived_arg, &result);
	if (ret != 0){
		IVED_ERROR(log4cat_veos_ived, "Sending process registration failed");
		retval = ret;
		goto err_ret;
	}
	if (result->error){
		IVED_ERROR(log4cat_veos_ived,
			   "Process registration failed.:#%d %s",
			   result->error, strerror(-result->error));
		goto err_ret;
	}

	retval = 0;

	IVED_DEBUG(log4cat_veos_ived, 
		   "Process Registration succeeded.");

err_ret:
	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
	if (result != NULL)
		ived_return__free_unpacked(result, NULL);

	if (retval == IVED_RPC_ERR_RECV){
		/* Send a cancel request */
		IVED_DEBUG(log4cat_veos_ived, "Cancel the failed request.");
		/* IVED closes a socket per a request (ived_exchange_ived_msg),
		 * so this if statement should be after ived_finish_soc(). */

		veos_ived_erase_procdata(resource);
		/* Don't care about the result. */
	}

	IVED_DEBUG(log4cat_veos_ived, "Request finished");
	return(retval);
}


/**
 * @brief Connect to IVED and erase a registration of process.
 * If a request failed, it will be erased at VEOS termination
 * or VEOS rebooting.
 *
 * NOTE: Before entering this function, a caller must acquire locks.
 * ived_resource_lock
 *
 * @param [in] resource       Shared resource data of a target process
 *
 * @return  0 on success, -1 on failure
 */
static int
veos_ived_erase_procdata(struct ived_shared_resource_data *resource)
{
	int ret;
	int ived_req_sock = -1;

	RpcIvedArg ived_arg = RPC_IVED_ARG__INIT;
	RpcProcList proc_list_arg = RPC_PROC_LIST__INIT;
	IvedReturn *result = NULL;
	ProtobufCBinaryData uuid_data;

	if (IVED_LINKAGE_OFF){
		return(0);
	}

	IVED_TRACE(log4cat_veos_ived, "PASS");

	assert(resource != NULL); /* If false, stop */
	if (resource == NULL){
		IVED_CRIT(log4cat_veos_ived, "Argument is NULL.");
		return(-1);
	}

	IVED_DEBUG(log4cat_veos_ived, "New request from pid: %d subcmd:%#x",
		   resource->pid, IVED_PROC_ERASE);

	proc_list_arg.pid = resource->pid;
	set_flag(proc_list_arg.mode_flag, IVED_PROC_EXIT);

	uuid_data.len		= sizeof(uuid_t);
	uuid_data.data		= (uint8_t *)resource->uuid_proc;
	proc_list_arg.uuid_proc	= uuid_data;
	dump_uuid("proc", uuid_data.data);

	ived_arg.subcmd = IVED_PROC_ERASE;
	ived_arg.proc_arg = &proc_list_arg;

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		IVED_ERROR(log4cat_veos_ived, 
			   "Fail to create socket with IVED.");
		goto err_ret;
	}

	ret = ived_exchange_ived_msg(ived_req_sock, &ived_arg, &result);
	if (ret != 0){
		IVED_WARN(log4cat_veos_ived, "Sending process termination failed");
		goto err_ret;
	}
	if (result->retval){
		IVED_WARN(log4cat_veos_ived,
			  "Erasing a process failed.:#%d %s",
			  result->error, strerror(-result->error));
		goto err_ret;
	}
	IVED_DEBUG(log4cat_veos_ived, 
		   "Process erasing succeeded.");

err_ret:
	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}
	if (result != NULL)
		ived_return__free_unpacked(result, NULL);

	IVED_DEBUG(log4cat_veos_ived, "Request finished");
	return(0);
}



/**
 * @brief Get PCIATB size on which a process exists
 *
 * @param [in] pid    Target process
 *
 * @return PCIATB page size on success, -1 and set errno on failure
 */
int
veos_ived_get_pciatb_pgmode(int pid)
{
	int retval = -1;
	int ived_req_sock = -1;
	int ret;
	int sv_errno = 0;

	RpcVeshmArg request = RPC_VESHM_ARG__INIT;
	RpcVeshmPgsize request_pgsize = RPC_VESHM_PGSIZE__INIT;
	IvedReturn *ret_ived = NULL;

	if (IVED_LINKAGE_OFF){
		errno = ENOTSUP;
		return(-1);
	}

	request_pgsize.pid	  = pid;
	request.pgsize_arg	  = &request_pgsize;
	request.subcmd		  = VESHM_PGSIZE;

	IVED_DEBUG(log4cat_veos_ived,
		   "Ask pgmode  pid: %d", request_pgsize.pid);

	/* Create socket to IVED */
	ived_req_sock = ived_create_soc(ived_sock_file);
	if (ived_req_sock < 0) {
		sv_errno = ECANCELED;
		IVED_ERROR(log4cat_veos_ived,
			   "Fail to create socket with IVED.");
		goto err_ret;
	}

	/* Must free(ret_ived) later */
	ret = ived_exchange_veshm_msg(ived_req_sock, &request, &ret_ived);
	if (ret != 0 || ret_ived == NULL){
		sv_errno = ECANCELED;
		goto err_ret;
	}

	if (ret_ived->retval == IVED_REQ_NG){
		if (ret_ived->error == -ECANCELED)
			IVED_ERROR(log4cat_veos_ived,
				   "The query is failed (ECANCELED)");
		else 
			IVED_DEBUG(log4cat_veos_ived,
				   "The query is failed.  err:%d",
				   ret_ived->error);
		sv_errno = -ret_ived->error;
		goto err_ret;
	}

	if (ret_ived->veshm_ret == NULL
	    || ret_ived->veshm_ret->pagesize > INT_MAX){
		IVED_ERROR(log4cat_veos_ived, "Reply message is corrupted");
		sv_errno = ECANCELED;
		goto err_ret;
	}

	IVED_DEBUG(log4cat_veos_ived, "return from ived (pgsize): %"PRIx64"",
		   ret_ived->veshm_ret->pagesize);

	retval = (int) ret_ived->veshm_ret->pagesize;

err_ret:
	if (ived_req_sock != -1){
		ret = ived_finish_soc(ived_req_sock);
		if (errno == EIO){
			IVED_WARN(log4cat_veos_ived,"%s", strerror(errno));
		}
	}

	if (ret_ived != NULL)
		ived_return__free_unpacked(ret_ived, NULL);


	IVED_DEBUG(log4cat_veos_ived, "PCI pagesize (pid:%d): pgsize(retval):0x%lx",
		   pid, (long)retval);
	errno = sv_errno;
	return(retval);
}


