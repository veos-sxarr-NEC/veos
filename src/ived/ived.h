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
 * @file ived.h  
 * @brief Header for IVED
 *
 * @internal
 * @author VESHM
 */

#ifndef __IVED_H
#define __IVED_H

#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/socket.h>
#include <log4c.h>
#include <uuid/uuid.h>
#include "ve_list.h"
#include "ived.pb-c.h"

extern uuid_t null_id;
extern log4c_category_t *log4cat_main;
extern log4c_category_t *log4cat_veshm;
extern log4c_category_t *log4cat_cr;
extern pthread_mutexattr_t chkmutex;	/* PTHREAD_MUTEX_ERRORCHECK_NP */

#define MAX_VE_NODE		8	/* connected to same VH */
#define MAX_THREADS		20	/* worker threads */
#define BUFFER_LENGTH		256
#define PID_FILE		"pid_file.txt"

#define IVED_MAX_CMD_NUM	4	/* # of IPC handlers */


#define CREATE_INFO	0x1	/* Frag: If a specified entry doesn't exist,
				   create a new one */

#define VE_STAT_UNUSED	-1	/* It means veos_info[n] is not used */
#define VE_STAT_0	0	/* Don't use 0 (reserved) */
#define VE_STAT_RUNNING	1	/* It means an OS is running. */
#define VE_STAT_STOP	2	/* It is set when VESHM resources are used by
				   others but VEOS stops. */

#define BOOT_TIMEOUT	 120	/* seconds. Wait time while IVED boots. */
#define OS_LOCK_TIMEOUT	  30	/* seconds. Wait time for OS locking. */


/*
 * flags 
 */

#define THREAD_STOP		-1
#define THREAD_WAIT_FOR_USE     0
#define THREAD_IN_USE		1

/*
 * Data structures 
 */

struct cr_page_info;

/** 
 * @brief Process informtaion per os. 
 */
struct process_info{
	struct list_head list;
	pthread_mutex_t proc_lock;	/*!< lock for process_info */
	int	proc_stat;		/*!< Process status */
	pid_t	pid;
	uuid_t  uuid_proc;		/*!< UUID of process */
	struct	veos_info *os_info;

	/* VESHM */
	int	own_veshm_num;		/*!< # of having_veshm_info items */
	int	attach_veshm_num;	/*!< # of attaching_veshm_info items */
	struct list_head having_veshm_info;	/*!< Head of having list */
	struct list_head attaching_veshm_info;	/*!< Head of attaching list */

	/* CR */
	struct cr_page_info *local_crd[4]; /*!< Using local CRs for MPI mode */
	struct	list_head using_cr_info;/*!< Head of using CR list */
};

/** 
 * @brief VEOS information. 
 */
struct veos_info{
	pthread_mutex_t os_lock;	/*!< Protect this item */
	pthread_cond_t  os_cv;
	pid_t	os_pid;
	int	node_stat;		/*!< VEOS status (running|stop) */
	uint64_t bar01_paddr;		/*!< start address of bar01 */
	uint64_t bar3_paddr;		/*!< start address of bar3 */
	uint64_t pciatb_pgsize;		/*!< PCIATB page size in byte */
	char	*drv_socket_name;	/*!< Device name corresponding to a VEOS */
	int	veos_sock;		/*!< Socket of VEOS for IVED request */
	pthread_mutex_t veos_sock_lock;	/*!< Lock of the socket */
	/* Process */
	struct list_head proc_info_list;	/*!< Head of process info */
	int	proc_info_num;		/*!< Number of processes */
	/* VESHM */
	struct list_head veshm_mem_info_list;	/*!< Head of VESHM mem info */
	int	veshm_mem_num;		/*!< # of existing VESHM in a node */
	/* CR */
	struct cr_page_info	*cr_page_info;	/* Pointer to an array of CR */
};


/**
 * @brief information of threads
 */
typedef struct ived_thread_arg{		/* often named pti */
	int socket_descriptor;		/* descriptor to read/write */
	int tid_used;			/* if thread is used or not */
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	struct ucred	cred;		/*!< credential */
	uint flag;			/*!< status flag of thread */

	uint8_t *telegram_buf;		/*!< Buffer for telegram */
	RpcCommand	*request;	/*!< unpacked request */
	int		socket_not_close; 
				/*!< If a request is IVED_OS_REG, don't close
				 * the socket. It is reused. */
} ived_thread_arg_t;


/**
 * @brief RPC command and function list
 */
struct ived_handler_list {
	int command;
	int (*handler)(struct ived_thread_arg *);
};


/** 
 * @brief This structure holds PID of VESHM/CR user process.
 * VESHM: It is protected by veshm_lock.
 * CR   : It is protected by cr_lock.
 */
struct ived_resource_user{
	struct list_head list;
	pid_t  pid;			/*!< PID of user process */
	uuid_t uuid_proc;		/*!< UUID of user process (=pseudo pid).
					 *   It is used by VESHM only. */
	int	reference_cnt_cr;	/*!< Reference count for CR page */
};


extern struct veos_info veos_info[MAX_VE_NODE];


#endif
