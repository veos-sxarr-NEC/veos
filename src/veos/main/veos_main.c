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
 * @file  veos_main.c
 * @brief Functions for startup and termination including main() function.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/mman.h>
#include <log4c.h>
#include <libudev.h>

#include <veos_arch_defs.h>
#include <pwd.h>
#include <grp.h>
#include "veos.h"
#include "veos_handler.h"
#include "velayout.h"
#include "mm_common.h"
#include "task_signal.h"
#include "veos_ived.h"
#include "veos_vemm.h"
#include "task_sched.h"
#include "veos_ived_common.h"
#include "config.h"
#include "vesync.h"
#include "ve_swap.h"
#include "ve_mem.h"
#include "veos_sock.h"
#include "veos_devmem.h"

#define IPC_QUEUE_LEN 20
#define UG_NAME_MAX 32

static char veos_sock_file[PATH_MAX] = {'\0'};
static char veos_vhve_sock_file[PATH_MAX] = {'\0'};
char drv_sock_file[PATH_MAX] = {'\0'};
/* Buffer to store IVED's socket file path. */
char ived_sock_file[PATH_MAX] = {'\0'};
sem_t terminate_sem;
log4c_category_t *cat_os_core;
volatile sig_atomic_t terminate_flag = NOT_REQUIRED;
pthread_rwlock_t handling_request_lock;
/* Condition variable to wait update of terminate_flag */
int opt_ived = 0; /* -i specified. */
unsigned int opt_pcisync = 0; /* --pcisync? specified. */
int opt_rordering = 1;   /* enable relaxed ordering */
/* VE Initial task struct */
struct ve_task_struct ve_init_task = VE_INIT_TASK(ve_init_task);
pthread_rwlock_t init_task_lock;
int64_t veos_timer_interval = PSM_TIMER_INTERVAL_SECS * 1000000000 +
						PSM_TIMER_INTERVAL_NSECS;
int64_t veos_time_slice = PSM_TIME_SLICE_SECS * 1000000 +
						(PSM_TIME_SLICE_NSECS / 1000);
/*Power Throttle Logging Interval set to One hour in secs*/
int64_t power_throttle_log_interval = PSM_POWER_THROTTLING_LOG_INTERVAL;
pthread_rwlock_t veos_scheduler_lock; /*protects time-slice and timer-interval*/
int no_update_os_state = 0;
struct ve_node_struct ve_node; /* the VE node */
struct ve_node_struct *p_ve_node_global = &ve_node; /* the pointer to VE node */
static char veos_abort_message[VE_ABORT_CAUSE_BUF_SIZE];
int skip_memclear_flag = 0;
static siginfo_t r_sig_info;
static int signal_received_flag = false;

/**
 * @brief This function releases all the resources
 *
 * @param[in] abnormal 0 on normal termination, 1 on abnormal termination.
 *
 * @internal
 *
 * @author VEOS main
 */
void veos_terminate_node_core(int abnormal)
{
	int core_loop = 0;
	struct ve_node_struct *p_ve_node;
	struct ve_core_struct *p_ve_core;
	struct list_head *p, *q;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Deallocating VE node/core structures");
	if (abnormal == NORMAL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"Normal termination");
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
						"Abnormal termination");

	}

	p_ve_node = &ve_node;
	/* acquiring semaphore for node */
	if (-1 == sem_wait(&p_ve_node->node_sem)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Node semaphore lock failed");
	}
	/* Removing VE system load */
	list_for_each_safe(p, q, &(p_ve_node->ve_sys_load_head)) {
		struct ve_sys_load *tmp =
			list_entry(p, struct ve_sys_load, list);
		free(tmp);
	}
	sem_post(&p_ve_node->node_sem);
	if (vedl_munmap_common_reg(VE_NODE(0)->cnt_regs) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Unmapping common register failed");
	}

	if (sem_destroy(&(p_ve_node->node_sem)) == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Destroying semaphore node_sem failed");
	}

	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
	     core_loop++) {
		p_ve_core = p_ve_node->p_ve_core[core_loop];
		if (p_ve_core == NULL)
			continue;
		if (vedl_munmap_usr_reg(p_ve_core->usr_regs) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Unmapping user register failed: core %d",
				core_loop);
		}
		if (vedl_munmap_sys_reg(p_ve_core->sys_regs) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Unmapping system register failed: core %d",
				core_loop);
		}

		if (sem_destroy(&(p_ve_core->core_sem)) == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Destroying semaphore failed for core %d",
				p_ve_core->core_num);
		}
		if (pthread_rwlock_destroy(&(p_ve_core->ve_core_lock))) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Destroying read_write lock failed for core %d",
				core_loop);
		}
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"Free Core[%d]",
			core_loop);
		free(p_ve_core);
	}
	if (abnormal == NORMAL) {
		if (veos_set_ve_node_state(p_ve_node,
						OS_ST_OFFLINE) != 0)
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Setting VE node state failed");
	}
	/*destroy ve_node lock*/
	if (pthread_mutex_destroy(&p_ve_node->ve_node_lock) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Node mutex lock destroy failed");
	}

	/* destroy tasklist_lock*/
	if (pthread_mutex_destroy(&p_ve_node->ve_tasklist_lock) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Node tasklist lock destroy failed");
	}

	if (pthread_rwlock_destroy(&(VE_NODE(0)->ve_relocate_lock)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Failed to destroy ipc read-write lock");
	}

	vedl_close_ve(VE_HANDLE(0));

	psm_del_sighand_struct(&ve_init_task);
	if (pthread_rwlock_destroy(&init_task_lock)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to destroy init task read-write lock");
	}
	(*_veos_arch_ops->arch_free_veos_pci_dma_pgtables)(p_ve_node->pciatb,
						p_ve_node->dmaatb);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG, "Out Func");
}

/**
 * @brief Request internal threads to stop handling new IPC requests and
 * VEMM agent to stop handling new VEMM requests.
 *
 * @details This function is registered as signal handler for
 * SIGTERM/SIGABRT/SIGHUP/SIGQUIT.
 *
 * @param[in] signal The signal number being handled.
 *
 * @internal
 *
 * @author VEOS main
 */
void veos_request_termination(int signal, siginfo_t *info, void *ucontext)
{
	terminate_flag = REQUIRED;
	sem_post(&terminate_sem);
	if (info != NULL) {
		memcpy(&r_sig_info, info, sizeof(siginfo_t));
		signal_received_flag = true;
	}
}

/**
 * @brief Halts all VE cores, deletes all VE processes,
 * kills all pseudo processes, and releases all the resources allocated.
 *
 * @param[in] abnormal 0 on normal termination, 1 on abnormal termination.
 *
 * @internal
 *
 * @author VEOS main
 */
static void veos_termination(int abnormal)
{
	struct ve_node_struct *p_ve_node;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	/* Waits termination of the thread which
	 * executes veos_termincate_dma()
	 */
	pthread_join(terminate_dma_th, NULL);

	p_ve_node = VE_NODE(0);

	/* PSM halts all VE cores and user mode DMA,
	 * deletes all VE processes and
	 * kills all pseudo processes
	 */
	psm_terminate_all(p_ve_node->node_num);

	/* VESHM/CR agent notifies VEOS's termination to IVED */
	if (opt_ived != 0) {
		if (veos_ived_erase_osdata() != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Unregistering VEOS from IVED failed");
		}
	}

	veos_free_ppsbuf();
	pthread_mutex_lock_unlock(&(p_ve_node->pps_file_lock), LOCK,
				"Failed to aqcuire pps_file_lock");
	veos_del_pps_file(p_ve_node);
	struct ve_swap_file_hdr_comm msg;
	if (!p_ve_node->pps_file.is_created_by_root){
		memset(&msg, '\0', sizeof(struct ve_swap_file_hdr_comm));
		msg.kind = PPS_F_HDR_TERMINATE_REQ;
		send_pps_file_handler_comm(p_ve_node->pps_file.sockfd, msg);
	}
	pthread_mutex_lock_unlock(&(p_ve_node->pps_file_lock), UNLOCK,
				"Failed to release pps_file_lock");

	if (ve_dma_close_p(p_ve_node->dh) != 0)
		veos_abort("Failed to finalize DMA manager");
	/*Deallocating node AMM resourcces*/
	veos_free_pci_bar01_sync_addr();
	veos_amm_fini();

	/* Deallocating VE node/code structure*/
	veos_terminate_node_core(abnormal);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"VEOS termination complete");

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
}

/* @brief Usage function to display veos usage
 *
 * @param[in] veos_path Command name of VEOS displayed in usage message.
 *
 * @internal
 *
 * @author VEOS main
 */
static void usage(char *veos_path)
{
	const char *Usage = "[OPTIONS]\n"
	"  Start VEOS.\n"
	"  The following options must be given:\n"
	"    -s path, --sock=path  VEOS socket file which VEOS creates.\n"
	"    -d path, --dev=path   VE driver file.\n"
	"\n"
	"  The following options are optional:\n"
	"    -i path, --ived=path          IVED socket file which VEOS uses to\n"
	"                                  communicate with IVED.\n"
	"    -m path, --vemm=path          VEMM socket file which VEOS uses to\n"
	"                                  communicate with VEMM.\n"
	"    -t value,                     The interval between invocations of\n"
	"    --timer-interval=value        the timer handler of the scheduler,\n"
	"                                  in milliseconds.\n"
	"    -T value,                     The period of time for which a thread\n"
	"    --time-slice=value            of a process is allowed to run,\n"
	"                                  in milliseconds.\n"
	"    --pcisync1=pcisyar1,pcisymr1  The values of PCISYAR1 and PCISYMR1\n"
	"                                  which VEOS sets.\n"
	"    --pcisync2=pcisyar2,pcisymr2  The values of PCISYAR2 and PCISYMR2\n"
	"                                  which VEOS sets.\n"
	"    --pcisync3=pcisyar3,pcisymr3  The values of PCISYAR3 and PCISYMR3\n"
	"                                  which VEOS sets.\n"
	"    --ve-swap-mem-max=value       Maximum value of memory that can be\n"
	"                                  swapped out per VE node.\n"
	"    --ve-swap-file-path=value     Path of file that can be swapped out\n"
	"                                  per VE node.\n"
	"    --ve-swap-file-max=value      Maximum value of file that can be\n"
	"                                  swapped out per VE node.\n"
	"    --ve-swap-file-user=value     User name of the user who creates\n"
	"                                  the file to swap out\n"
	"    --ve-swap-file-group=value    Group name of the group who creates\n"
	"                                  the file to swap out\n"
	"    --cleanup                     Starts a VEOS and terminates it\n"
	"                                  immediately, in order to ensure all VE\n"
	"                                  core, user mode DMA and privileged DMA\n"
	"                                  are halted, and clean up resources.\n"
	"    -h, --help                    Display this help and exit.\n"
	"    -V, --version                 Display version information and exit.\n"
	"\n"
	"Each pcisyar and pcisymr value is hexadecimal with \"0x\" prefix.\n";

	fprintf(stderr, "Usage: %s %s\n", veos_path, Usage);
}

/**
 * @brief Function to abort VEOS.
 *
 * @details This function aborts VEOS without any notification to
 * other external components.
 *
 * @param[in] cause Cause of aborting. printf() style format can be specified.
 * @param[in] ... Arguments.
 *
 * @internal
 *
 * @author VEOS main
 */
void veos_abort(const char *cause, ...)
{
	va_list ap;
	char cause_str[VE_ABORT_CAUSE_BUF_SIZE];

	va_start(ap, cause);
	vsnprintf(cause_str, VE_ABORT_CAUSE_BUF_SIZE, cause, ap);
	va_end(ap);
	VEOS_FATAL("VEOS aborted due to unrecoverable error: %s",
			cause_str);
	memcpy(veos_abort_message, cause_str, VE_ABORT_CAUSE_BUF_SIZE);;
	abort();
}

/**
 * @brief Ensures all VE cores, user mode DMA and privileged DMA are halted,
 * cleans up resources, and terminates itself.
 *
 * @return 0 on Success, -1 on failure.
 *
 * @internal
 *
 * @author VEOS main
 */
static int veos_cleanup(void)
{
	int retval = -1;
	ve_dma_hdl *dh;
	int core_loop = 0;

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");

	/* Delete remaining socket file. */
	remove(veos_sock_file);
        remove(veos_vhve_sock_file);

	no_update_os_state = 1;

	if (veos_init_ve_node() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Initializing VE node failed");
		return retval;
	}

	dh = ve_dma_open_p(VE_NODE(0)->handle);
	if (dh == NULL) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Initializing DMA manager failed");
		goto hndl_error_struct;
	}
	VE_NODE(0)->dh = dh;

	if (vedl_delete_all_ve_task(VE_HANDLE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Deleting VE tasks failed");
		goto hndl_error_dma;
	}

	if (vedl_release_pindown_page_all(VE_HANDLE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to releasing pin-downed pages");
		goto hndl_error_dma;
	}

	errno = 0;
	if (vedl_put_devmem_all(VE_HANDLE(0)) != 0) {
		if (errno != ENOTSUP) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to releasing all registered device memory");
			goto hndl_error_dma;
		}
	}
	
	for (core_loop = 0; core_loop < VE_NODE(0)->nr_avail_cores;
								core_loop++) {
		if (vedl_reset_interrupt_count(VE_HANDLE(0), core_loop) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
			"Resetting interrupt counter failed: core %d",
			core_loop);
		goto hndl_error_dma;
		}
	}

	if (veos_cleanup_pseudo(VE_NODE(0)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Cleaning up pseudo processes failed");
		goto hndl_error_dma;
	}

	(*_veos_arch_ops->arch_turn_on_clock_gating)();
	retval = 0;

	if (opt_ived != 0) {
		if (veos_ived_register_osdata() != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Registering VEOS to IVED failed");
			retval = -1;
		} else {
			if (veos_ived_erase_osdata() != 0) {
				VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Unregistering VEOS to IVED failed");
				retval = -1;
			}
		}
	}

	/* remove PPS file if it already exist. */
	remove(VE_NODE(0)->pps_file.path);

hndl_error_dma:
	if (ve_dma_close_p(VE_NODE(0)->dh) != 0)
		veos_abort("Failed to finalize DMA manager");

hndl_error_struct:
	veos_terminate_node_core(retval * (-1));
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return retval;
}

/**
 * @brief Creates a socket to listen connections.
 *
 * @return File descriptor number on success, -1 on failure
 *
 * @internal
 *
 * @author VEOS main
 */

static int veos_create_socket(void)
{
	int l_sock;

	struct sockaddr_un sa = {0};

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	/* create socket */
	l_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (l_sock == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Creating socket failed");
		goto hndl_error;
	}

	/* create sockaddr_un */
	sa.sun_family = AF_UNIX;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
					"veos sock is %s", veos_sock_file);

	if ((sizeof(sa.sun_path)) < (strlen(veos_sock_file) + 1)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Socket file path is too long");
		goto hndl_close;
	}
	strncpy(sa.sun_path, veos_sock_file, sizeof(sa.sun_path) - 1);

	/* VEOS socket file has already removed.
	 * bind()
	 */
	if (bind(l_sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Binding socket failed");
		goto hndl_close;
	}

	/* change permission */
	chmod(sa.sun_path, 0777);

	/* listen */
	if ((listen(l_sock, IPC_QUEUE_LEN)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Listing socket failed");
		goto hndl_close;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return l_sock;

hndl_close:
	errno = 0;
	if (close(l_sock) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Closing socket failed");
	}

hndl_error:
	remove(sa.sun_path);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return -1;
}

/**
 * @brief Creates a socket to listen connections for VH process.
 *
 * @return File descriptor number on success, -1 on failure
 *
 * @internal
 *
 * @author VHVE
 */
static int veos_create_vhve_socket(void)
{
	int l_sock_vhve;

	struct sockaddr_un sa = {0};

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "In Func");
	/* create socket */
	l_sock_vhve = socket(AF_UNIX, SOCK_STREAM, 0);
	if (l_sock_vhve == -1) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Creating socket failed");
		goto hndl_error;
	}

	/* create sockaddr_un */
	sa.sun_family = AF_UNIX;
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
			"veos sock is %s", veos_vhve_sock_file);

	if ((sizeof(sa.sun_path)) < (strlen(veos_vhve_sock_file) + 1)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Socket file path is too long");
		goto hndl_close;
	}
	strncpy(sa.sun_path, veos_vhve_sock_file, sizeof(sa.sun_path) - 1);

	/* VEOS socket file has already removed.
	 * bind()
	 */
	if (bind(l_sock_vhve, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Binding socket failed");
		goto hndl_close;
	}

	/* change permission */
	chmod(sa.sun_path, 0777);

	/* listen */
	if ((listen(l_sock_vhve, IPC_QUEUE_LEN)) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Listing socket failed");
		goto hndl_close;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return l_sock_vhve;

hndl_close:
	errno = 0;
	if (close(l_sock_vhve) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Closing socket failed");
	}

hndl_error:
	remove(sa.sun_path);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	return -1;
}

static void veos_logging_recived_signal(void)
{
	int fd;
	char cmd[PATH_MAX + 1] = {'\0'};
	char path_to_proc[PATH_MAX + 1] = {'\0'};
	ssize_t rd;

	if (signal_received_flag == false)
		return;

	snprintf(path_to_proc, PATH_MAX + 1,
					"/proc/%d/cmdline", r_sig_info.si_pid);
	fd = open(path_to_proc, O_RDONLY|O_NOFOLLOW);
	if (fd != -1) {
		rd = read(fd, cmd, PATH_MAX);
		if (rd == -1) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_NOTICE,
				"Signal %d from PID %d recived",
				r_sig_info.si_signo, r_sig_info.si_pid);
		} else {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_NOTICE,
				"Signal %d from %s(PID : %d) recived",
				r_sig_info.si_signo, cmd, r_sig_info.si_pid);
		}
		close(fd);
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_NOTICE,
				"Signal %d from PID %d recived",
				r_sig_info.si_signo, r_sig_info.si_pid);
	}
}

/**
 * @brier main() for veos
 *
 * @param[in] argc Received argument count
 * @param[in] argv Argument buffers received
 *
 * @return exit() with negative value on failure
 *
 * @internal
 *
 * @author VEOS main
 */
#ifdef __UNIT_TEST
int veos_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	int l_sock[2];
	int index = 0;
	int s, retval = 0;
	/* Buffer to store VEMM's socket file path. */
	static char vemm_sock_file[PATH_MAX] = {'\0'};
	int opt_dev = 0; /* -d specified. */
	int opt_sock = 0; /* -s specified. */
	int opt_vemm = 0; /* -m specified. */
	int opt_clean = 0; /* --clean specified. */
	sigset_t set;
	pthread_t veos_thread;
	pthread_t veos_poller_thread;
	pthread_t veos_sigstop_thread;
	pthread_t veos_zombie_cleaner_thread;
	pthread_attr_t attr;
	pthread_rwlockattr_t rw_attr;
	size_t pps_buf_size = 0;
	size_t pps_file_size = 0;
	char pps_file_path[PATH_MAX-2] = {'\0'};
	size_t pps_file_buf_size = 0;
	uid_t pps_file_uid = 0;
	gid_t pps_file_gid = 0;
	char pps_file_username[UG_NAME_MAX + 1] = {'\0'};
	char pps_file_groupname[UG_NAME_MAX + 1] = {'\0'};
	struct passwd *pwd;
	struct group *grp;
	bool mem_mode_flg = false;
	bool file_mode_flg = false;

	struct option long_options[] = {
			{"pcisync1",          required_argument, NULL,  0 },
			{"pcisync2",          required_argument, NULL,  0 },
			{"pcisync3",          required_argument, NULL,  0 },
			{"cleanup",           no_argument,       NULL,  0 },
			{"ve-swap-mem-max",   required_argument, NULL,  0 },
			{"ve-swap-file-path", required_argument, NULL,  0 },
			{"ve-swap-file-max",  required_argument, NULL,  0 },
			{"ve-swap-file-user", required_argument, NULL,  0 },
			{"ve-swap-file-group",required_argument, NULL,  0 },
			{"skip-memclear",     no_argument,       NULL,  0 },
			{"disable-rordering", no_argument,       NULL,  0 },
			{"help",              no_argument,       NULL, 'h'},
			{"sock",              required_argument, NULL, 's'},
			{"dev",               required_argument, NULL, 'd'},
			{"ived",              required_argument, NULL, 'i'},
			{"vemm",              required_argument, NULL, 'm'},
			{"timer-interval",    required_argument, NULL, 't'},
			{"time-slice",        required_argument, NULL, 'T'},
			{"version",           no_argument,       NULL, 'V'},
                        {"power-throttle-log-interval",  required_argument, NULL, 'p'},
			{0, 0, 0, 0}
			};

	/* Parse the options */
	while ((s = getopt_long(argc, argv, "hs:d:i:m:t:T:V:p", long_options,
							&index)) != -1) {
		switch (s) {
		case 's':
			snprintf(veos_sock_file, sizeof(veos_sock_file),
								"%s", optarg);
			opt_sock = 1;
			break;
		case 'd':
			snprintf(drv_sock_file, sizeof(drv_sock_file),
								"%s", optarg);
			snprintf(veos_vhve_sock_file, sizeof(veos_vhve_sock_file),
				"%s/veos%d_vhve.sock",VEOS_SOC_PATH,
				get_ve_node_num_from_sock_file(drv_sock_file));
			opt_dev = 1;
			break;
		case 'i':
			opt_ived = 1;
			snprintf(ived_sock_file, sizeof(ived_sock_file),
								"%s", optarg);
			break;
		case 'm':
			opt_vemm = 1;
			snprintf(vemm_sock_file, sizeof(vemm_sock_file),
								"%s", optarg);
			break;
		case 't':
			veos_timer_interval =
					veos_convert_sched_options(optarg,
						PSM_TIMER_INTERVAL_MIN_MLSECS,
						PSM_TIMER_INTERVAL_MAX_MLSECS);
			if (veos_timer_interval == -1) {
				fprintf(stderr,
					"-t/--timer-interval option error\n");
				exit(EXIT_FAILURE);
			}
			veos_timer_interval *= (1000 * 1000);
			break;
		case 'T':
			veos_time_slice = veos_convert_sched_options(optarg,
						PSM_TIME_SLICE_MIN_MLSECS,
						PSM_TIME_SLICE_MAX_MLSECS);
			if (veos_time_slice == -1) {
				fprintf(stderr,
					"-T/--time-slice option error\n");
				exit(EXIT_FAILURE);
			}
			veos_time_slice *= 1000;
			break;
                case 'p':/*Power Throttle Logging Interval*/
                        power_throttle_log_interval = veos_convert_sched_options(optarg,
					PSM_POWER_THROTTLING_LOG_INTERVAL_MIN,
					PSM_POWER_THROTTLING_LOG_INTERVAL_MAX);
                        if (power_throttle_log_interval == -1) {
                                fprintf(stderr,
                                        "-p/--power-throttle-log-interval "
							"option error\n");
                                exit(EXIT_FAILURE);
                        }
                        break;

		case 0:
			if ((index == OPT_PCISYNC1) ||
						(index == OPT_PCISYNC2) ||
						(index == OPT_PCISYNC3)) {
				if (veos_set_pcisync_option(index, optarg)
									!= 0) {
					fprintf(stderr, "%s option error\n",
						long_options[index].name);
					exit(EXIT_FAILURE);
				}
				opt_pcisync = opt_pcisync | (0x01 << index);
				break;
			} else if (index == OPT_CLEANUP) {
				opt_clean = 1;
				break;
			} else if (index == OPT_VESWAPMAX) {
				pps_buf_size =
					veos_convert_sched_options(optarg,
						0, INT64_MAX / (1024 * 1024));
				if (pps_buf_size == -1) {
					fprintf(stderr, "%s option error\n",
						long_options[index].name);
					exit(EXIT_FAILURE);
				}
				mem_mode_flg = true;
				break;
			} else if (index == OPT_VESWAP_FILE_PATH) {
				snprintf(pps_file_path, sizeof(pps_file_path),
								"%s", optarg);
				if (pps_file_path[0] == '\0') {
					pps_file_buf_size = 0;
					fprintf(stderr, "%s option error\n",
						long_options[index].name);
					exit(EXIT_FAILURE);
				}
				pps_file_buf_size = PPS_TRANSFER_BUFFER_SIZE;
				file_mode_flg = true;
				break;
			} else if (index == OPT_VESWAP_FILE_MAX) {
				pps_file_size =
					veos_convert_sched_options(optarg,
						0, INT64_MAX / (1024 * 1024));
				if (pps_file_size == -1) {
					pps_file_buf_size = 0;
					fprintf(stderr, "%s option error\n",
						long_options[index].name);
					exit(EXIT_FAILURE);
				}
				pps_file_buf_size = PPS_TRANSFER_BUFFER_SIZE;
				file_mode_flg = true;
				break;
			} else if (index == OPT_VESWAP_FILE_USER) {
				snprintf(pps_file_username, 
					sizeof(pps_file_username), "%s", 
								optarg);
				if ((pwd = getpwnam(pps_file_username)) == 
								NULL){
					fprintf(stderr, "%s option error %s. "
						"Unable to get user information"
						" due to %s\n",
						long_options[index].name,
							pps_file_username,
							strerror(errno));
					exit(EXIT_FAILURE);
				}else{
					pps_file_uid = pwd->pw_uid;
				}
				break;
			} else if (index == OPT_VESWAP_FILE_GROUP) {
				snprintf(pps_file_groupname, 
					sizeof(pps_file_groupname), "%s", 
								optarg);
				if ((grp = getgrnam(pps_file_groupname)) == 
								NULL){
					fprintf(stderr, "%s option error %s. "
						"Unable to get group infomation"
						" due to %s\n",
						long_options[index].name, 
							pps_file_groupname,
							strerror(errno));
					exit(EXIT_FAILURE);
				}else{
					pps_file_gid = grp->gr_gid;
				}
				break;
			} else if (index == OPT_SKIPMEMCLEAR) {
				skip_memclear_flag = 1;
				break;
			} else if (index == OPT_DRORDERING) {
				opt_rordering = 0;
				break;
			} else {
				fprintf(stderr, "Wrong option specified\n");
				exit(EXIT_FAILURE);
			}
		case 'h':
			usage(basename(argv[0]));
			exit(EXIT_SUCCESS);
		case 'V':
			fprintf(stderr, "%s (%s) %s\n",
				PROGRAM_NAME, PACKAGE, PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
		default:
			usage(basename(argv[0]));
			exit(EXIT_FAILURE);
		}
	}

	if ((opt_sock != 1) || (opt_dev != 1)) {
		fprintf(stderr, "-d and -s options must be specified\n");
		exit(EXIT_FAILURE);
	}

	/* Log4c initialization */
	if (log4c_init()) {
		fprintf(stderr, "Initializing log4c failed\n");
		exit(EXIT_FAILURE);
	}

	/* Log4c category initialization for veos core logs */
	cat_os_core = log4c_category_get("veos.os_module.core");
	if (cat_os_core == NULL) {
		fprintf(stderr, "Initializing log4c category failed\n");
		exit(EXIT_FAILURE);
	}
	if (veos_ived_log4c_init()) {
		fprintf(stderr, "Initializing log4c for IVED failed\n");
		retval = 1;
		goto hndl_return;
	}
	if (veos_pps_log4c_init()) {
		fprintf(stderr, "Initializing log4c for PPS failed\n");
		retval = 1;
		goto hndl_return;
	}

	if (sem_init(&terminate_sem, 0, 0) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
			"Failed to initialize semaphore terminate_sem: %s"
							, strerror(errno));
		retval = 1;
		goto hndl_return;
	}

	/* Out put PPS mode */
	if (print_pps_mode_info(pps_file_path[0], pps_file_size, mem_mode_flg,
		file_mode_flg) != 0) {
		retval = 1;
		goto hndl_return;
	}
	/* Out put PPS info */
	if ((mem_mode_flg) || (file_mode_flg)) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PPS buffer size is %ld", pps_buf_size);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PPS file size is %ld", pps_file_size);
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"PPS file path is %s", pps_file_path);
	}
	/* Out put PPS uid/gid info */
	if (file_mode_flg) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
		"PPS file is created by uid:%d gid:%d", pps_file_uid, 
								pps_file_gid);
	}

	retval = pthread_rwlockattr_init(&rw_attr);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
		       "Failed to initialize rwlock attribute: %s",
		       strerror(retval));
		retval = 1;
		goto hndl_sem;
	}

	retval = pthread_rwlockattr_setkind_np(&rw_attr,
				PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
			"Failed to set kind of rwlock attribute: %s",
			strerror(retval));
		retval = 1;
		goto hndl_sem;
	}
	retval = pthread_rwlock_init(&handling_request_lock, &rw_attr);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Failed to initialize rwlock handling_request_lock: %s",
				strerror(retval));
		retval = 1;
		goto hndl_sem;
	}
	retval = pthread_rwlock_init(&veos_scheduler_lock, &rw_attr);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Failed to initialize rwlock veos_scheduler_lock: %s",
				strerror(retval));
		retval = 1;
		goto hndl_sem;
	}

	/* Blocking SIGINT/SIGTERM/SIGQUIT signal*/
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGQUIT);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
						"Failed to set signal mask");
		retval = 1;
		goto hndl_sem;
	}

	/* Handle SIGINT/SIGTERM/SIGQUIT signal*/
	if (veos_register_signal_hnldr() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
				"Signal handler registration failed");
		retval = 1;
		goto hndl_sem;
	} else {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_DEBUG,
				"Signal handler registered successful");
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "VEOS socket file %s",
						veos_sock_file);
        VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "VEOS VHVE socket file %s",
                                                veos_vhve_sock_file);
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "VE driver file %s",
						drv_sock_file);

	if (opt_ived != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"IVED socket file %s",
						ived_sock_file);
	if (opt_vemm != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"VEMM socket file %s",
						vemm_sock_file);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Timer interval is %ld ms",
					veos_timer_interval / (1000 * 1000));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
					"Time slice is %ld ms",
					veos_time_slice / 1000);

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
				"Power Throttle log interval is %ld sec",
				power_throttle_log_interval );
	if (opt_clean != 0) {
		fprintf(stderr, "Cleaning up resources ...\n");
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Cleaning up resources ...");
		if (veos_cleanup() != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to cleanup VEOS");
			retval = 1;
			goto hndl_sem;
		}
		retval = 0;
		goto hndl_sem;
	}

	fprintf(stderr, "Initializing VEOS ...\n");
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO, "Initializing VEOS ...");
	if (skip_memclear_flag)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_INFO,
						"Skip clearing VE memory");

	/* remove veos socket file if it already exist. */
	remove(veos_sock_file);
        remove(veos_vhve_sock_file);

	/* Initialize veos */
	if (veos_init() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Initializing VEOS failed");
		retval = 1;
		goto hndl_sem;
	}
	
	if (veos_init_pps_file_info(pps_file_path, pps_file_size,
		drv_sock_file, pps_file_uid, pps_file_gid) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Initializing PPS file info failed");
		retval = 1;
		goto hndl_termination;	
	}

	if (veos_alloc_ppsbuf(pps_buf_size, pps_file_buf_size) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Initializing Partial Process Swapping failed");
		retval = 1;
		goto hndl_termination;
	}

        if (veos_coredump_helper_launcher() != 0) {
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                                "Start coredump_helper launcher failed");
                retval = 1;
                goto hndl_termination;
	}

	if (veos_init_pci_sync() != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
					"Initializing PCI synchronization failed");
		retval = 1;
		goto hndl_termination;
	}

	if (opt_vemm != 0) {
		if (vemm_agent_run(vemm_sock_file) != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
						"Running VEMM agent failed");
			retval = 1;
			goto hndl_termination;
		}
	}

	l_sock[0] = veos_create_socket();
	if (l_sock[0] < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
						"Failed to create socket");
		retval = 1;
		goto hndl_vemm;
	}

	l_sock[1] = veos_create_vhve_socket();
	if (l_sock[1] < 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Failed to create socket");
		retval = 1;
		goto hndl_close2;
	}

	if (veos_set_ve_node_state(VE_NODE(0), OS_ST_ONLINE) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
						"Failed to update OS state");
		retval = 1;
		goto hndl_close;
	}

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_NOTICE,
					"VEOS initialization complete");
	fprintf(stderr, "VEOS initialization complete\n");

	/* create threads */
	retval = pthread_attr_init(&attr);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Faild to initialize pthread attribute: %s",
				strerror(retval));
		retval = 1;
		goto hndl_close;
	}
	retval = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
			"Faild to get pthread attribute detachable: %s",
			strerror(retval));
		retval = 1;
		goto hndl_close;
	}

	retval = pthread_create(&veos_thread, &attr, (void *)&veos_main_thread,
			(void *)(int *)&l_sock);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Faild to create veos_thread: %s",
				strerror(retval));
		retval = 1;
		goto hndl_close;

	}
	retval = pthread_create(&veos_sigstop_thread, &attr,
			(void *)&veos_stopping_thread, NULL);
	if (retval != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Faild to create veos_sigstop_thread: %s",
				strerror(retval));
		retval = 1;
		veos_request_termination(0, NULL, NULL);
	}
	if (retval == 0) {
		retval = pthread_create(&veos_poller_thread, &attr,
					(void *)&veos_polling_thread, NULL);
		if (retval != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Faild to create veos_poller_thread: %s",
				strerror(retval));
			retval = 1;
			veos_request_termination(0, NULL, NULL);
		}
	}
	if (retval == 0) {
		retval = pthread_create(&veos_zombie_cleaner_thread, &attr,
			(void *)&veos_zombie_cleanup_thread, NULL);
		if (retval != 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_FATAL,
				"Faild to create veos_zombie_cleanup_thread: %s",
				strerror(retval));
			retval = 1;
			veos_request_termination(0, NULL, NULL);
		}
	}
	/* Wait to change terminate_flag value from 0 to 1. */
	sem_wait(&terminate_sem);
	if (sem_post(&terminate_sem) != 0)
		veos_abort("Failed to post semaphore. %s", strerror(errno));

	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_NOTICE, "Terminating VEOS ...");

	veos_logging_recived_signal();

	if (veos_set_ve_node_state(VE_NODE(0), OS_ST_TERMINATING) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to update OS state");
		retval = 1;
	}

	/* Delete socket file. */
	remove(veos_sock_file);
        remove(veos_vhve_sock_file);

	/* Requests internal VEMM agent to stop handling new VEMM request */
	if (opt_vemm != 0) {
		if (vemm_agent_request_finish() < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to finish vemm_agent");
			retval = 1;
		}
	}

	if (veos_remove_timer(&ve_node) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Can't stop VEOS scheduler timer");
		retval = 1;
	}

	/* Wake up all threads of waiting to allocate memory */
	amm_wake_alloc_page();

	/* Wake up swap threads and T(s) processes */
	send_notice_to_swap_thread();

	/* wait termination of in-progress IPC request and
	 * in-progress state change of process
	 */
	pthread_rwlock_wrlock(&handling_request_lock);

	if (opt_vemm != 0) {
		if (vemm_agent_wait() < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to wait vemm_agent");
			retval = 1;
		}
	}

	veos_termination(retval);

	if (sem_destroy(&terminate_sem) != 0) {
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "Failed to destroy semaphore terminate_sem %s",
		       strerror(errno));
		retval = 1;
	}

hndl_return:
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	log4c_fini();
	exit(retval);

hndl_close:
        remove(veos_vhve_sock_file);
        if (close(l_sock[1]) != 0)
                VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
                                        "Failed to close socket.%s",
                                        strerror(errno));

hndl_close2:
	/* Delete socket file. */
	remove(veos_sock_file);
	if (close(l_sock[0]) != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to close socket.%s",
					strerror(errno));

hndl_vemm:
	if (opt_vemm != 0) {
		if (vemm_agent_request_finish() < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to request VEMM agent to finish");
		}
		if (vemm_agent_wait() < 0) {
			VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to wait VEMM agent");
		}
	}

hndl_termination:
	if (veos_remove_timer(&ve_node) != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "Can't stop VEOS scheduler timer");
	veos_request_termination(0, NULL, NULL);
	send_notice_to_swap_thread();
	veos_termination(retval);

hndl_sem:
	if (sem_destroy(&terminate_sem) != 0)
		VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_ERROR,
		       "Failed to destroy semaphore terminate_sem: %s",
		       strerror(errno));
	if (_veos_arch_ops){
		(*_veos_arch_ops->arch_main_free_node_arch_dep_data)(&ve_node);
	}
	VE_LOG(CAT_OS_CORE, LOG4C_PRIORITY_TRACE, "Out Func");
	log4c_fini();
	exit(retval);
}
