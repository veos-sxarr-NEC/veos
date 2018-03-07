/**
* @file syscall_lppg.c
* @brief Handles LPPG related system calls encountered by VE process.
*
* This file contains LPPG related system call handlers for the various
* system calls encountered by VE process.
*/

#include "syscall_common.h"
#include "syscall_lppg.h"
#include "mem_xfer.h"
#include "velayout.h"
#include "ve_signal.h"

/**
 * @brief Generic Handler for write() and pwrite64() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and then offloads the functionality to VH OS
 *	write()/pwrite64() system call.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_write_pwrite64(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *write_buff;
	int recv_size;
	uint64_t args[4];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get argument failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive write buffer size from VE memory */
	recv_size = args[2];

	/* allocate memory to store write data */
	write_buff = (char *)malloc(recv_size * sizeof(char));
	if (NULL == write_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(write_buff, '\0', recv_size);

	/* receive the write buffer */
	if (-1 == ve_recv_data(handle, args[1],
				recv_size, (uint64_t *)write_buff)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_data failed to receive args[1]\n");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			write_buff, recv_size, args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return1:
	free(write_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
 * @brief Handles write() system call for VE.
 *
 *	ssize_t write(int fd, const void *buf, size_t count);
 *
 *	This function uses generic handler "ve_hndl_write_pwrite64" as write()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_write(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_write_pwrite64(syscall_num, syscall_name, handle);
}

/**
 * @brief Generic Handler for writev() and pwritev() system calls for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS writev()/pwritev() system call.
 *	It copies the data to VEMVA using VE driver interface.
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_writev(),
 *	ve_pwritev().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_writev_pwritev(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	struct iovec *vh_iov;
	int iovcnt = 0;
	int i = 0;
	uint64_t args[4];
	uint64_t **vh_buff_addr;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* writev() iovcnt from VE memory */
	iovcnt = args[2];
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"VE buffer count : %d\n", iovcnt);
	/* local memory buffer to store writev data */
	vh_iov = (struct iovec *)malloc(iovcnt * sizeof(struct iovec));
	if (NULL == vh_iov) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(vh_iov, '\0', (iovcnt * sizeof(struct iovec)));

	/* receive writev() const struct iovec*  from VE memory */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					(iovcnt * sizeof(struct iovec)),
					(uint64_t *)(vh_iov))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
	}

	/*create VH buffers */
	vh_buff_addr = malloc(iovcnt * (sizeof(uint64_t)));
	if (NULL == vh_buff_addr) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return1;
	}

	memset(vh_buff_addr, '\0', iovcnt * sizeof(uint64_t));

	/* Create VH environment for writev() */
	for (i = 0; i < iovcnt; i++) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"VE data: buff: %d length :%lu data:%lu\n",
				i, (unsigned long)(vh_iov[i].iov_len),
				(unsigned long)vh_iov[i].iov_base);

		if ((NULL != (void *)vh_iov[i].iov_base) &&
				(0 != vh_iov[i].iov_len)) {

			vh_buff_addr[i] = (uint64_t *)malloc
					((vh_iov[i].iov_len) * sizeof(char));
			if (NULL != (void *)vh_buff_addr[i]) {
				if (-1 == ve_recv_data(handle,
					(uint64_t)(vh_iov[i].iov_base),
					(vh_iov[i].iov_len*sizeof(char)),
					(uint64_t *)(vh_buff_addr[i]))) {
						VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"Failed to receive args[%d]\n",
							i);
						retval = -EFAULT;
						goto hndl_return2;
				}
			} else {
				retval = -errno;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"malloc fail for buffer %d\n",
						i+1);
				goto hndl_return2;
			}
		}
		vh_iov[i].iov_base = (void *)vh_buff_addr[i];
	}
	/* VH data for writev() */
	for (i = 0; i < iovcnt; i++) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"VH OS write buff: %d length :%u data: %s\n",
				i, (unsigned int)(vh_iov[i].iov_len),
				(char *)vh_iov[i].iov_base);
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/*call VH system call */
	retval = syscall(syscall_num, args[0], vh_iov, iovcnt, args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name,
				strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;

	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s writev %lu bytes\n",
				syscall_name, retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* cleaning local storage */
hndl_return2:
	for (i = 0; i < iovcnt; i++) {
		if (NULL != (void *)vh_buff_addr[i])
			free(vh_buff_addr[i]);
	}
	free(vh_buff_addr);
hndl_return1:
	free(vh_iov);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Generic handler for readv() and preadv() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS readv()/preadv() system call. This
 *	function after receiving the data from VH OS call copies the data to
 *	VEMVA using VE driver interface.
 *	It returns the return value of the system call back to
 *	the VE process using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_readv(),
 *	ve_preadv().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_readv_preadv(int syscall_num, char *syscall_name,
					vedl_handle *handle)
{
	ret_t retval = -1;
	struct iovec *vh_iov;
	int iovcnt = 0, i = 0;
	int err_flag = -1;
	int cnt = 0;
	uint64_t args[4], *ve_buff_addr;
	sigset_t signal_mask;
	ret_t send_bytes = -1;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed.(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* receive readv()iovcnt from VE memory */
	iovcnt = args[2];
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"VE buffer count : %d\n", iovcnt);

	/* Create local memory to store readv data */
	vh_iov = (struct iovec *)malloc(iovcnt * sizeof(struct iovec));
	if (NULL == vh_iov) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}

	/* Receive environment for readv from VE */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					(iovcnt*sizeof(struct iovec)),
					(uint64_t *)(vh_iov))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"struct iovec buffer received NULL\n");
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* create buffer to store VE buffer addresses */
	ve_buff_addr = malloc(iovcnt * sizeof(uint64_t));
	if (NULL == ve_buff_addr) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}

	/* Allocate memory for VH buffers */
	for (i = 0; i < iovcnt; i++) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"VE buffer %d : length %lu : buff_add %lu\n",
				i, (unsigned long) (vh_iov[i].iov_len),
				(unsigned long) (vh_iov[i].iov_base));

		ve_buff_addr[i] = (uint64_t)vh_iov[i].iov_base;
		vh_iov[i].iov_base = NULL;
		if (0 < vh_iov[i].iov_len) {
			vh_iov[i].iov_base = (void *)malloc
				((vh_iov[i].iov_len) * sizeof(char));
			if (NULL == (void *) vh_iov[i].iov_base) {
				retval = -errno;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Error for malloc in "
						"buffer %d\n", i);
				err_flag = 1;
				goto hndl_return2;
			}
			cnt++;
		}
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* All things is ready now its time to call linux VH system call */
	retval = syscall(syscall_num, args[0], vh_iov, iovcnt, args[3]);
	if (-1 == retval) {
		retval = -errno;
		err_flag = 1;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;

		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s readv %lu bytes\n",
				syscall_name, retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* Just for reference to see what data it currently holds.
	 * This loop need to be removed in main implementation otherwise extra
	 * overhead of for-loop occurs.
	 */
	for (i = 0; i < iovcnt; i++) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
				"Ready buffer buff: %d length :%u data : %s\n",
				i, (unsigned int)(vh_iov[i].iov_len),
				(char *)vh_iov[i].iov_base);
	}
	/* Clean memory on VH buffers and send data available to VE memory.*/

hndl_return2:
	send_bytes = retval;
	for (i = 0; i < cnt; i++) {
		if(!send_bytes)
			break;
		if (NULL != (void *)vh_iov[i].iov_base) {
			if (err_flag != 1) {
				if(send_bytes >= vh_iov[i].iov_len)
					send_bytes = send_bytes - vh_iov[i].iov_len;
				else {
					vh_iov[i].iov_len = send_bytes;
					send_bytes = 0;
				}
				if (-1 == ve_send_data(handle,
							(uint64_t)(ve_buff_addr[i]),
							(vh_iov[i].iov_len),
							(uint64_t *)vh_iov[i].iov_base)) {
					VE_LOG(CAT_PSEUDO_CORE,
							LOG4C_PRIORITY_ERROR,
							"ve_send_data failed to send args[%d]\n",
							i);
					retval = -EFAULT;
					err_flag = 1;
				} else
					VE_LOG(CAT_PSEUDO_CORE,
							LOG4C_PRIORITY_DEBUG,
							"buffer %d send to VE\n", i);
			}
			free(vh_iov[i].iov_base);
		}
	}
	free(ve_buff_addr);
hndl_return1:
	free(vh_iov);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
 * @brief Handles readv() system call for VE.
 *
 *	ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
 *
 *	This function uses generic handler(ve_hndl_readv_preadv) as readv()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 *
 */
void ve_readv(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_readv_preadv(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles writev() system call for VE.
 *
 *	ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
 *
 *	This function uses generic handler(ve_hndl_writev_pwritev) as writev()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_writev(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_writev_pwritev(syscall_num, syscall_name, handle);
}


/**
 * @brief Generic handler for read() and pread64() system call for VE.
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS read()/pread64() system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 *	Following system calls use this generic handler:
 *	ve_read(),
 *	ve_pread64().
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_hndl_read_pread64(int syscall_num, char *syscall_name,
					vedl_handle *handle)
{
	ret_t retval = -1;
	char *read_buff;
	size_t send_size;
	uint64_t args[4];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Get arguments failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* receive read() buffer size from VE memory */
	send_size = args[2];
	/* allocate memory to store read data */
	read_buff = (char *)malloc(send_size * sizeof(char));
	if (NULL == read_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(read_buff, '\0', send_size);

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			read_buff, send_size, args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;

		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall = %s read_buf= %s\n read %lu bytes\n",
				syscall_name, read_buff, retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* send the read buffer */
	if (-1 == ve_send_data(handle, args[1],
				retval, (uint64_t *)read_buff)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[1]\n");
		retval = -EFAULT;
		goto hndl_return1;
	}

hndl_return1:
	free(read_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles read() system call for VE.
 *
 *	ssize_t read(int fd, void *buf, size_t count);
 *
 *	This function uses generic handler "ve_hndl_read_pread64" as read()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_read(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_read_pread64(syscall_num, syscall_name, handle);
}

/**
* @brief Handles open() system call functionality for VE.
*
*      int open(const char *pathname, int flags);
*      int open(const char *pathname, int flags, mode_t mode);
*
*      This function fetches Path from VEMVA using VE driver interface
*      and offloads the functionality to VH OS system call.It returns
*      the return value of the system call back to the VE process using
*      "return_system_call" interface. As length of path is unknown
*      this function uses ve_recv_string().
*
* @param[in] syscall_num  System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_open(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	uint64_t args[3];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/*receive contents of 1st argument */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
	/* call VH system call */
	retval = syscall(syscall_num,
			path_buff,
			args[1],
			args[2]);

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles close() system call for VE.
*
*	int close(int fd);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS close() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_close(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args[1];
	ret_t retval = -1;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0]);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
			syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles stat() system call functionality for VE.
*
*	int stat(const char *path, struct stat *buf);
*
*	This function uses generic handler "ve_hndl_p_char_p_stat_buf" as stat()
*	functionality for ve has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_stat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_stat_buf(syscall_num, syscall_name, handle);
}

/**
* @brief Handles fstat() system call for VE.
*
*	int fstat(int fd, struct stat *buf);
*
*	This function fetches the arguments from VEHVA/VEMVA and then invokes
*	VH OS fstat() system call. "stat" buffer returned from VH OS system call
*	is then copied back to VEMVA using VE driver interface.
*	It returns the return value of the system call back to
*	the VE process using "return_system_call" interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_fstat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct stat stat_buf;
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], &stat_buf);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* send the filled stat buf */
	if (-1 == ve_send_data(handle, args[1],
			sizeof(struct stat), (uint64_t *)(&stat_buf))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[1]\n");
		retval = -EFAULT;
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles lstat() system call functionality for VE.
*
*	int lstat(const char *path, struct stat *buf);
*
*	This function uses generic handler "ve_hndl_p_char_p_stat_buf" as
*	lstat() functionality for ve has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_lstat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_stat_buf(syscall_num, syscall_name, handle);
}

/**
* @brief Handles poll() system call for VE.
*
*	int poll(struct pollfd *fds, nfds_t nfds, int timeout);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS poll() system call. The data to
*	be send to VEMVA is done using VE driver interface.
*	It returns the return value of the
*	system call back to the VE process using "return_system_call" interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_poll(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct pollfd *fds;
	nfds_t nfds;
	uint64_t args[3];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	nfds = args[1];
	fds = (struct pollfd *)malloc(nfds * sizeof(struct pollfd));
	if (NULL == fds) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	if (NULL != (void *)args[0]) {
		if (-1 == ve_recv_data(handle, args[0],
					(nfds*sizeof(struct pollfd)),
					(uint64_t *)(fds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[0]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"fds[0].fd = %d\n", fds[0].fd);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"fds[0].events=%d\n", fds[0].events);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"fds[1].fd=%d\n", fds[1].fd);
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"fds[1].events=%d\n", fds[1].events);

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	retval = syscall(syscall_num, fds, nfds, args[2]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* Copy back FD's to VE area */
	if (NULL != (void *)args[0]) {
		if (-1 == ve_send_data(handle, args[0],
					sizeof(struct pollfd),
					(uint64_t *)(fds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[0]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
	}
hndl_return1:
	free(fds);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_lseek(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles ioctl() system call functionality for VE.
 *
 *	int ioctl(int d, int request, ...);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *	Only Tty ioctl commands are currently supported.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 * */
void ve_ioctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];
	unsigned int bytes;
	char *buff;
	struct termios termios_buff;
	struct termio termio_buff;
	struct winsize winsize_buff;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"tty ioctl command is: %lu\n", args[1]);

	/* handling added for tty_ioctl commands */
	switch (args[1]) {
	/* following commands take pointer to struct termios
	 * as third argument and the structure is to be copied
	 * back to VE area
	 * */
	case TCGETS:
	case TIOCGLCKTRMIOS:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&termios_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		/* send the filled termios_buf */
		if (NULL != (void *)args[2]) {
			if (-1 == ve_send_data(handle, args[2],
						sizeof(struct termios),
						(uint64_t *)(&termios_buff))) {
				VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"ve_send_data failed to send args[2]\n");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following command takes pointer to struct termio
		 * as third argument and the structure is to be copied
		 * back to VE area
		 * */
	case TCGETA:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&termio_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		/* send the filled termio_buf */
		if (NULL != (void *)args[2]) {
			if (-1 == ve_send_data(handle, args[2],
						sizeof(struct termio),
						(uint64_t *)(&termio_buff))) {
				VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"ve_send_data failed to send args[2]\n");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following command takes pointer to struct winsize
		 * as third argument and the structure is to be copied
		 * back to VE area
		 * */
	case TIOCGWINSZ:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&winsize_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		/* send the filled winsize_buf */
		if (NULL != (void *)args[2]) {
			if (-1 == ve_send_data(handle, args[2],
						sizeof(struct winsize),
						(uint64_t *)(&winsize_buff))) {
				VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"ve_send_data failed to send args[2]\n");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following commands take pointer to struct termios
		 * as third argument and structure pointer is not
		 * copied to VE area
		 * */
	case TCSETS:
	case TCSETSW:
	case TCSETSF:
	case TIOCSLCKTRMIOS:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&termios_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		break;

		/* following commands take pointer to struct termio
		 * as third argument and structure pointer is
		 * not copied to VE area
		 * */
	case TCSETAW:
	case TCSETAF:
	case TCSETA:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&termio_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		break;

		/* following commands take pointer to struct winsize as
		 * third argument and structure pointer is not copied
		 * to VE area
		 * */
	case TIOCSWINSZ:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&winsize_buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

		break;

		/* following commands take integer pointer as
		 * third argument and it is to be copied back
		 * to VE area
		 * */
	case FIONREAD:		/* or TIOCINQ */
	case TIOCOUTQ:
	case TIOCGETD:
	case TIOCMGET:
	case TIOCGSID:
	case TIOCGSOFTCAR:
	case TIOCGPGRP:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&bytes);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		}
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);


		/* Copy back integer value to VE area */
		if (NULL != (void *)args[2]) {
			if (-1 == ve_send_data(handle, args[2],
						sizeof(unsigned int),
						(unsigned int *)(&bytes))) {
				VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"ve_send_data failed to send args[2]\n");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
		break;

		/* following commands take integer pointer as
		 * third argument and integer pointer is not copied
		 * to VE area
		 * */
	case TIOCSETD:
	case TIOCPKT:
	case TIOCMSET:
	case TIOCMBIC:
	case TIOCMBIS:
	case TIOCSSOFTCAR:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				&bytes);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		}

		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		break;

		/* following commands take integer as third argument */
	case TCSBRK:
	case TCSBRKP:
	case TCXONC:
	case TCFLSH:
	case TIOCSCTTY:

		/* following commands take void as third argument */
	case TIOCSBRK:
	case TIOCCBRK:
	case TIOCCONS:
	case TIOCNOTTY:
	case TIOCEXCL:
	case TIOCNXCL:
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				args[2]);
		/* write return value */
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		}
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		break;

		/* following command take character pointer as third argument */
	case TIOCSTI:
		/* allocate memory to receive contents of
		 * third argument */
		buff = (char *)malloc(PATH_MAX * sizeof(char));
		if (NULL == buff) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		}
		memset(buff, '\0', PATH_MAX);

		/*receive contents of third argument */
		retval = ve_recv_string(handle, args[2],
				(char *)buff, PATH_MAX);
		if (retval < 0) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_string failed "
					"(%s) returned %d\n",
					syscall_name, (int)retval);
			retval = -EFAULT;
			goto hndl_buff_free;
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished"
				", unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				buff);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ERESTARTSYS. VE process
				 * will restart the syscall if SA_RESTART
				 * flag is provided for signal
				 * */
				retval = -VE_ERESTARTSYS;
			/* Post-processing of syscall started,
			 * blocking signals
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Blocking signals\n");
			pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
			goto hndl_buff_free;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* Post-processing of syscall started,
		 * blocking signals
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_buff_free:
		free(buff);
		break;

	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Only tty_ioctl are supported\n");
		retval = -EINVAL;
		goto hndl_return;
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles pread64() system call for VE.
*
*	ssize_t pread64(int fd, void *buf, size_t count, off64_t offset);
*
*	This function uses generic handler "ve_hndl_read_pread64" as pread64()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_pread64(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_read_pread64(syscall_num, syscall_name, handle);
}

/**
* @brief Handles pwrite64() system call for VE.
*
*	ssize_t pwrite64(int fd, void *buf, size_t count, off64_t offset);
*
*	This function uses generic handler "ve_hndl_write_pwrite64" as
*	pwrite64()functionality for ve has common pre and
*	post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_pwrite64(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_write_pwrite64(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles access() system call functionality for VE.
 *
 *	int access(const char *pathname, int mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as access()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_access(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pipe() and pipe2() system calls for VE.
 *
 *	int pipe(int pipefd[2]);
 *	int pipe2(int pipefd[2], int flags);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and offloads the functionality to VH OS
 *	pipe/pipe2()system call.
 *	This function sends the data to be written to VEMVA using VE driver
 *	interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_pipe(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	int fd[2];
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	retval = vedl_get_syscall_args(handle, args, 2);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* call VH system call */
	retval = syscall(syscall_num, fd, args[1]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	if (-1 == ve_send_data(handle, args[0],
				(sizeof(int) * 2), (uint64_t *)fd)) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[0]\n");
		goto hndl_return;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"syscall %s returned %d\n",
			syscall_name, (int)retval);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles select() system call functionality for VE.
*
*	int select(int nfds, fd_set *readfds, fd_set *writefds,
*		fd_set *exceptfds, struct timeval *timeout);
*
*	This function fetches the arguments from VEHVA/VEMVA and then invokes
*	the VH OS select() system call. Updated buffers received from VH OS are
*	are then copied back to VEMVA using VE driver interface.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_select(int syscall_num, char *syscall_name, vedl_handle *handle)
{

	/* TODO : To inform PSM as select is a blocking call.*/
	ret_t retval = -1;
	fd_set rfds, wfds , excptfds;
	struct timeval tv = {0};
	uint64_t args[5];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&excptfds);

	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(fd_set), (uint64_t *)(&rfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[2]) {
		if (-1 == ve_recv_data(handle, args[2],
					sizeof(fd_set), (uint64_t *)(&wfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[2]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[3]) {
		if (-1 == ve_recv_data(handle, args[3],
					sizeof(fd_set),
					(uint64_t *)(&excptfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[3]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[4]) {
		if (-1 == ve_recv_data(handle, args[4],
					sizeof(struct timeval),
					(uint64_t *)(&tv))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[4]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
			"syscall arguments (nfds: 0x%lx, rfds: 0x%lx,"
			" wfds: 0x%lx, excptfds: 0x%lx, tv: 0x%lx)\n",
			args[0], args[1], args[2],
			args[3], args[4]);

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			&rfds, &wfds, &excptfds, &tv);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return;
	} else if (retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"No ACTIVITY on fd set\n");

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* Copy back FD's to VE area */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_send_data(handle, args[1],
					sizeof(fd_set), (uint64_t *)(&rfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[2]) {
		if (-1 == ve_send_data(handle, args[2],
					sizeof(fd_set), (uint64_t *)(&wfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[2]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}
	if (NULL != (void *)args[3]) {
		if (-1 == ve_send_data(handle, args[3],
					sizeof(fd_set),
					(uint64_t *)(&excptfds))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[3]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

	/**
	 * Linux updates tv. Hence updating it. This is not a POSIX
	 * requirement
	 */
	if (NULL != (void *)args[4]) {
		if (-1 == ve_send_data(handle, args[4],
					sizeof(struct timeval),
					(uint64_t *)(&tv))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[4]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_mincore(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_madvise(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_shmget(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles system call functionality for dup(), dup2(), dup3() syscall in VE.
*
*	int dup(int oldfd);
*	int dup2(int oldfd, int newfd);
*	int dup3(int oldfd, int newfd, int flags);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS dup(), dup2(), dup3() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_generic_dup(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args[3];
	ret_t retval = -1;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
		"Generic Handler for SYSCALL %s invoked\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1],
			args[2]);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
			syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_dup(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_dup2(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles nanosleep() system call functionality for VE.
 *
 *	int nanosleep(const struct timespec *req, struct timespec *rem);
 *
 *	This function fetches arguments from VEHVA/VEMVA and then invokes the
 *	VH OS nanosleep() system call. Updated buffers received from VH OS are
 *	then copied back to VEMVA using VE driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_nanosleep(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct timespec req;
	struct timespec rem;
	uint64_t args[3];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	if (-1 == ve_recv_data(handle, args[0],
				sizeof(struct timespec), (uint64_t *)(&req))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_data failed to receive args[0]\n");
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	if (NULL == (void *)args[1]) {
		retval = syscall(syscall_num, &req, NULL);
		if (-1 == retval) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			retval = -errno;
			if (EINTR == errno)
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ENORESTART. VE process
				 * will not restart the syscall even if
				 * SA_RESTART flag is provided for signal
				 * */
				retval = -VE_ENORESTART;
		}
	} else {
		retval = syscall(syscall_num, &req, &rem);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			/* If nanosleep is interrupted,
			 * remaining time is written into rem. */
			if (EINTR == errno) {
				/* If VHOS syscall is interrupted by signal
				 * set retval to -VE_ENORESTART. VE process
				 * will not restart the syscall even if
				 * SA_RESTART flag is provided for signal
				 * */
				retval = -VE_ENORESTART;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO,
						"rem.tv_sec=%lld "
						"rem.tv_nsec=%ld\n",
						(long long)rem.tv_sec,
						rem.tv_nsec);
				/* Post-processing of syscall started,
				 * blocking signals
				 * */
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
						"Blocking signals\n");
				pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

				if (-1 == ve_send_data(handle, args[1],
							sizeof(struct timespec),
							(uint64_t *)(&rem))) {
					VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to send args[1]\n");
					retval = -EFAULT;
					goto hndl_return;
				}
				goto hndl_return;
			}
		}
	}
	if (-1 != retval)
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_getitimer(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_alarm(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setitimer(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sendfile(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles the socket() system call functionality for VE.
*
*	int socket(int domain, int type, int protocol);
*
*	This function uses generic handler "ve_generic_offload" as socket()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num  System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_socket(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
* @brief Handles connect() system call functionality for VE.
*
*	int connect(int sockfd, const struct sockaddr *addr,
*	 socklen_t addrlen)
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS connect() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_connect(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};
	socklen_t addr_len;
	uint64_t args[3];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	addr_len = (socklen_t)args[2];

	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					addr_len,
					(uint64_t *)(&addr))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		} else {
			/* unblock all signals except the one
			 * actualy blocked by VE process
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Pre-processing finished,"
					" unblock signals\n");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
			/* calling kernel System call on VH side */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr, addr_len);
		}
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"%s is invoked with sockaddr= NULL\n",
				syscall_name);
		/* calling kernel System call on VH side  with sock addr as NULL
		 * Kernel will return an error which is propagated back to VE
		 */
		retval = syscall(syscall_num, args[0], args[1], addr_len);
	}

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;


}

/**
* @brief Handles the accept() system call functionality for VE.
*
*	int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS accept() system call.
*	The updated buffers returned from VH OS are copied back to VEMVA using
*	VE driver interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_accept(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;

	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};

	socklen_t addr_len;
	uint64_t args[3];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/*
	 * if sock addr is received as NULL from VE pass NULL as sock addr to
	 * kernel system call. sock addr len is deliberatley passed as NULL
	 * since man page says that if sock addr is NULL ,
	 * sock len should also be NULL
	 * hence no sock len is fetched from VE side and NULL is only passed
	 * even if sock len is NON NULL on VE
	 */

	if (NULL == (void *)args[1]) {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		retval = syscall(syscall_num, args[0], args[1], NULL);
	} else {
		/*sock addr is not NULL */
		if (NULL != (void *)args[2]) {
			/*sock len addr is not NULL fetch data from VE*/
			if (-1 == ve_recv_data(handle, args[2],
						sizeof(socklen_t),
						(uint64_t *)(&addr_len))) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_data failed to receive args[2]\n");
				retval = -EINVAL;
				goto hndl_return;
			}

			/* unblock all signals except the one actualy
			 * blocked by VE process
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Pre-processing finished, unblock signals\n");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
			/*calling kernel System call on VH side ->
			 * addr is populated by kernel
			 */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr,
					&addr_len);
		} else {
			/* unblock all signals except the one actualy
			 * blocked by VE process
			 * */
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"Pre-processing finished, unblock signals\n");
			sigfillset(&signal_mask);
			pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

			/* sock addr is non  NULL but sock len addr is
			 * NULL, kernel throws error , propagate to VE
			 */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr, args[2]);
		}
	}

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	/* send addr received from kernel to VE side
	 * in case sock addr was non NULL on VE
	 */
	if (NULL != (void *)args[1]) {

		if (-1 == ve_send_data(handle, args[1],
				addr_len,
				(uint64_t *)(&addr))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		}
		 /* send addr_len recvd from kernel to VE side */
		if (NULL != (void *)args[2]) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"addr_len received from kernel = %d\n",
					addr_len);
			if (-1 == ve_send_data(handle, args[2],
					sizeof(socklen_t),
					(uint64_t *)(&addr_len))) {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[2]\n");
				retval = -EFAULT;
				goto hndl_return;
			}
		}
	}



hndl_return:
	/* write return value */
	return_system_call(retval);
	return;


}

void ve_sendto(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_recvfrom(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sendmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_recvmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_shutdown(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles bind() system call for VE.
*
*	int bind(int sockfd, const struct sockaddr *addr,
*		socklen_t addrlen);
*
*	This function fetches the arguments from VEHVA/VEMVA using VE driver
*	interface and then invokes the VH OS bind() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_bind(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;

	/* Structure large enough to hold any socket address
	 * as used by Linux kernel
	 * */
	struct sockaddr_storage addr = {0};

	socklen_t addr_len;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	addr_len = (socklen_t)args[2];

	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					addr_len,
					(uint64_t *)(&addr))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return;
		} else {
		       /*calling kernel System call on VH side */
			retval = syscall(syscall_num, args[0], (struct sockaddr *)&addr, addr_len);
		}


	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"%s is invoked with sockaddr= NULL\n",
				syscall_name);
		/*calling kernel System call on VH side  with sock addr as NULL
		 * Kernel will return an error which is propagated back to VE
		 */
		retval = syscall(syscall_num, args[0], args[1], addr_len);
	}

	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}

hndl_return:
	/* write return value */
	return_system_call(retval);
	return;

}

/**
* @brief  Handles listen() system call functionality for VE.
*
*	int listen(int sockfd, int backlog);
*
*	This function uses generic handler "ve_generic_offload" as listen()
*	functionality for ve has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_listen(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_generic_offload(syscall_num, syscall_name, handle);
}

void ve_getsockname(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getpeername(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_socketpair(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setsockopt(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getsockopt(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_uname(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_semget(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_semop(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_semctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles ve_msgget() system call for VE.
*
*	int msgget(key_t key, int msgflg);
*
*	This function uses generic handler "ve_generic_offload" as msgget()
*	functionality for VE has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_msgget(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles ve_msgsnd() system call for VE.
 *
 *	int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA using
 *	VE driver interface and offloads the functionality to VH OS msgsnd()
 *	system call.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_msgsnd(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	size_t msgsz;
	uint64_t args[4];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive arguments. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		return_system_call(retval);
		return;
	}
	msgsz = args[2];
	struct msg {
		long mtype;
		char mtext[msgsz];
	} *msgp;

	/* allocate memory to store read data */
	msgp = (struct msg *)malloc(sizeof(struct msg));
	if (NULL == msgp) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}

	memset(msgp, '\0', (sizeof(struct msg)));

	if (-1 == ve_recv_data(handle, args[1],
				(sizeof(struct msg)), (uint64_t *)msgp)) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive args[1]\n");
		goto hndl_return1;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			msgp, msgsz, args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall = %s send buf = %s\n retval %lu\n",
				syscall_name, msgp->mtext, retval);
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	free(msgp);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles ve_msgrcv() system call for VE.
 *
 *	ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
 *		int msgflg);
 *
 *	This function receives the data and arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS msgrcv() system call.
 *	Updated buffers returned from VH OS are copied back to VEMVA using VE
 *	driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_msgrcv(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	size_t msgsz;
	long msgtype;
	uint64_t args[5];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);
	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive arguments. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		return_system_call(retval);
		return;
	}
	msgsz = args[2];
	msgtype = args[3];

	struct msg {
		long mtype;
		char mtext[msgsz];
	} *msgp;
	/* allocate memory to store read data */
	msgp = (struct msg *)malloc(sizeof(struct msg));
	if (NULL == msgp) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(msgp, '\0', (sizeof(struct msg)));

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num, args[0],
			msgp, msgsz, msgtype, args[4]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ENORESTART. VE process
			 * will not restart the syscall even if
			 * SA_RESTART flag is provided for signal
			 * */
			retval = -VE_ENORESTART;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return1;
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	if (-1 == ve_send_data(handle, args[1],
				(sizeof(struct msg)), (uint64_t *)msgp)) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send args[1]\n");
		goto hndl_return1;
	}
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"syscall = %s read_buf= %s\n read %lu bytes\n",
			syscall_name, msgp->mtext, retval);
hndl_return1:
	free(msgp);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
* @brief Handles ve_msgctl() system call for VE.
*
*	int msgctl(int msqid, int cmd, struct msqid_ds *buf);
*
*	This function receives the data and arguments from VEMVA/VEHVA using
*	VE driver interface.
*	It offloads the functionality to VH OS msgctl() system call.
*	Updated buffers returned from VH OS are copied back to VEMVA using
*	using VE driver interface.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_msgctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct msqid_ds msqds;
	struct msginfo msg_info;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive arguments. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	switch (args[1]) {
	case IPC_SET:
	case IPC_STAT:
	case MSG_STAT:
	case IPC_RMID:
		/* To receive struct ve_file_lock values from VE */
		if (IPC_SET == args[1]) {
			if (-1 == ve_recv_data(handle, args[2],
						sizeof(struct msqid_ds),
						(uint64_t *)(&msqds))) {
				retval = -EFAULT;
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Failed to receive args[2]\n");
				goto hndl_return;
			}
		}
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1],	&msqds);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			} else if (MSG_STAT == args[1] || IPC_STAT == args[1]) {
				if (-1 == ve_send_data(handle, args[2],
					sizeof(struct msqid_ds),
						(uint64_t *)&msqds)) {
					retval = -EFAULT;
					VE_LOG(CAT_PSEUDO_CORE,
						LOG4C_PRIORITY_ERROR,
						"Failed to send args[2]\n");
					goto hndl_return;
				}
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
						"syscall %s returned %d\n",
						syscall_name, (int)retval);
				goto hndl_return;
			} else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
						"syscall %s returned %d\n",
						syscall_name, (int)retval);
				goto hndl_return;
			}
	case IPC_INFO:
	case MSG_INFO:
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1], &msg_info);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		}
		/* Send the filled ve_file_lock to VE */
		if (-1 == ve_send_data(handle, args[2],
				sizeof(struct msginfo), (uint64_t *)(&msg_info))) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to send args[2]");
			goto hndl_return;
		}
		goto hndl_return;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Invalid flag passed");
		retval = -EINVAL;
}
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
 * @brief Handles fcntl() system call functionality for VE.
 *
 *	int fcntl(int fd, int cmd, ...);
 *
 *	This function receives the arguments from VEMVA/VEHVA and
 *	offloads the functionality to VH OS  system call.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_fcntl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;

		/* write return value */
		return_system_call(retval);
		return;
	}
	/* check for number of argument */
	switch (args[1]) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_GETFD:
	case F_SETFD:
	case F_GETFL:
	case F_SETFL:
	case F_SETOWN:
		ve_generic_offload(syscall_num, syscall_name, handle);
		break;
	case F_GETOWN:
		/* call VH system call */
		retval = syscall(syscall_num,
				args[0],
				args[1],
				args[2]);
		/* In case f_owner of the args[0] is a process group,
		 * the return value is a negative value between the
		 * range of -1 to -4095. Same negative value is
		 * returned to the VE using retval.
		 * For more information regarding this please check
		 * man page for fcntl.
		 * */
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		}
		/* write return value */
		return_system_call(retval);
		break;
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		ve_hndl_int_int_p_flock_buf(syscall_num,
				syscall_name, handle);
		break;
		/* These flags required further investigation in case of
		 * signal handling. For now offloading it to generic handler.
		 * */
	case F_NOTIFY:
	case F_GETLEASE:
	case F_SETLEASE:
	case F_GETSIG:
	case F_SETSIG:
		ve_generic_offload(syscall_num, syscall_name, handle);
		break;
	default:
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"INVALID FLAG PASSED IN "
				"FCNTL SYSTEM CALL\n");
		retval = -EINVAL;
		return_system_call(retval);
	}
	return;
}

/**
* @brief Handles flock() system call functionality for VE.
*
*	int flock(int fd, int operation);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS flock() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_flock(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args[2];
	ret_t retval = -1;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
		"Generic Handler for SYSCALL %s invoked\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
			syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_fsync(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fdatasync(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles truncate() system call functionality for VE.
*
*	int truncate(const char *path, off_t length);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS truncate() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_truncate(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	uint64_t args[6];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 6);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/*receive contents of 1st argument */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			path_buff,
			args[1],
			args[2],
			args[3],
			args[4],
			args[5]);

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
		"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
* @brief Handles ftruncate() system call functionality for VE
*
*	int ftruncate(int fd, off_t length);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS ftruncate() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_ftruncate(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	uint64_t args[2];
	ret_t retval = -1;
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
		"Generic Handler for SYSCALL %s invoked\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			args[1]);
	/* write return value */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
			syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	}
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

void ve_getdents(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles getcwd() system call functionality for VE.
 *
 *	long getcwd(char *buf, unsigned long size);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA and then invokes
 *	the VH OS system call.
 *	Buffer containing current working directory received
 *	as output from VH OS system call is then copied back to VEMVA using VE
 *	driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_getcwd(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	int recv_size;
	char *path_buf;
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	recv_size = args[1];

	/* allocate memory for current path to be fetched */
	path_buf = (char *)malloc(recv_size * sizeof(char));
	if (NULL == path_buf) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buf, '\0', recv_size);

	/* call VH system call */
	retval = syscall(syscall_num, path_buf, recv_size);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* send the filled path_buf */
	if (-1 == ve_send_data(handle, args[0],
				recv_size, (uint64_t *)(path_buf))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[0]\n");
		retval = -EFAULT;
		goto hndl_return1;
	}

hndl_return1:
	free(path_buf);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles chdir() system call functionality for VE.
 *
 *	int chdir(const char *path);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chdir()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_chdir(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_fchdir(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles rename() system call functionality for VE.
 *
 *	int rename(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as rename()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_rename(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mkdir() system call functionality for VE.
 *
 *	int mkdir(const char *pathname, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mkdir()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface..
 */

void ve_mkdir(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles rmdir() system call functionality for VE.
 *
 *	int rmdir(const char *pathname);
 *
 *	This function uses generic handler "ve_hndl_p_char" as rmdir()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_rmdir(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles creat() system call functionality for VE.
*
*	int creat(const char *pathname, mode_t mode);
*
*	This function receives the arguments from VEMVA/VEHVA and
*	offloads the functionality to VH OS creat() system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_creat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	uint64_t args[2];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"vedl_get_syscall_args failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "malloc %s failed %s\n",
			syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/*receive contents of 1st argument */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
			"ve_recv_string failed. (%s) returned %d\n",
					syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* unblock all signals except the one actualy blocked by VE process */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Pre-processing finished, unblock signals\n");
	sigfillset(&signal_mask);
	pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
	/* call VH system call */
	retval = syscall(syscall_num,
			path_buff,
			args[1]);

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR, "syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles link() system call functionality for VE.
 *
 *	int link(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as link()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_link(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles unlink() system call functionality for VE.
 *
 *	int unlink(const char *pathname);
 *
 *	This function uses generic handler "ve_hndl_p_char" as unlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_unlink(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles symlink() system call functionality for VE.
 *
 *	int symlink(const char *oldpath, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as symlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_symlink(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles readlink() system call functionality for VE.
 *
 *	ssize_t readlink(const char *path, char *buf, size_t bufsiz);
 *
 *	This function fetches arguments from VEHVA/ VEMVA and then invokes the
 *	VH OS readlink() system call.
 *	ve_recv_string is used to fetch symlink name from VE side.
 *	Buffer(containig symbolic link data)
 *	received as output from VH OS system call is then copied back to VEMVA
 *	using VE driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_readlink(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *symlink, *buffer;
	int recv_size;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* prepare buffer */
	recv_size = args[2];

	/* allocate memory to send contents of 2nd argument */
	buffer = (char *)malloc(recv_size * sizeof(char));
	if (NULL == buffer) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer, '\0', recv_size);

	/* allocate memory for storing symbolic link name */
	symlink = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == symlink) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(symlink, '\0', PATH_MAX);

	/* receive symlink name from VE side */
	retval = ve_recv_string(handle, args[0], (char *)symlink, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	/* call VH system call */
	retval = syscall(syscall_num, symlink, buffer, recv_size);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	/* copy back obtained buffer to VE area */
	if (-1 == ve_send_data(handle, args[1],
				recv_size, (uint64_t *)buffer)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[1]\n");
		retval = -EFAULT;
		goto hndl_return2;
	}
hndl_return2:
	free(symlink);
hndl_return1:
	free(buffer);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles chmod() system call functionality for VE.
 *
 *	int chmod(const char *path, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chmod()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_chmod(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_fchmod(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles chown() system call functionality for VE.
 *
 *	int chown(const char *path, uid_t owner, gid_t group);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chown()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */


void ve_chown(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_fchown(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles lchown() system call functionality for ve.
 *
 *	int lchown(const char *path, uid_t owner, gid_t group);
 *
 *	This function uses generic handler "ve_hndl_p_char" as lchown()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_lchown(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_umask(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_times(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_syslog(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getgid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setgid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_geteuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getegid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setreuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setregid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getgroups(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setgroups(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setresuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
/**
 * @brief Handles getresuid() system call functionality for VE.
 *
 *	int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
 *
 *	This function uses generic handler "ve_hndl_p_int_p_int_p_int" as
 *	getresuid()i functionality for ve has common
 *	pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_getresuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	 ve_hndl_p_int_p_int_p_int(syscall_num, syscall_name, handle);
}

void ve_setresgid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
/**
 * @brief Handles getresgid() system call functionality for VE.
 *
 *	int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
 *
 *	This function uses generic handler "ve_hndl_p_int_p_int_p_int" as
 *	getresgid() functionality for VE has common pre and
 *	post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name  System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_getresgid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_int_p_int_p_int(syscall_num, syscall_name, handle);
}

void ve_setfsuid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setfsgid(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles utime() system call functionality for VE.
 *
 *	int utime(const char *filename, const struct utimbuf *times);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA using VE driver
 *	interface and then invokes the VH OS utime() system call.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_utime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	struct utimbuf time;
	int recv_size;
	uint64_t args[2];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 2);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	recv_size = PATH_MAX;

	/* allocate memory to receive contents of 1st argument */
	path_buff = (char *)malloc(recv_size * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', recv_size);

	/* receive contents of 1st argument(filename) */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, recv_size);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* receive contents of 2nd argument(utimbuf) */
	if (NULL != (void *)args[1]) {
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(struct utimbuf),
					(uint64_t *)&time)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[1]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* call VH system call */
		retval = syscall(syscall_num, path_buff, &time);
	} /* call VH system call */
	else
		retval = syscall(syscall_num, path_buff, NULL);

	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles mknod() system call functionality for VE.
 *
 *	int mknod(const char *pathname, mode_t mode, dev_t dev);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mknod()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_mknod(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_uselib(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_personality(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_ustat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_statfs(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fstatfs(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sysfs(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_mlock(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_munlock(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_mlockall(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_munlockall(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_vhangup(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_modify_ldt(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_pivot_root(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sysctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_adjtimex(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles chroot() system call functionality for VE.
 *
 *	int chroot(const char *path);
 *
 *	This function uses generic handler "ve_hndl_p_char" as chroot()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_chroot(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

void ve_sync(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_mount(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_umount2(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_swapon(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_swapoff(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_reboot(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sethostname(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setdomainname(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_iopl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_ioperm(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_create_module(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_init_module(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_delete_module(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_get_kernel_syms(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_query_module(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_quotactl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_nfsservctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getpmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_putpmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_afs_syscall(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_tuxcall(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_security(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles ve_readahead() system call for VE.
*
*	ssize_t readahead(int fd, off64_t offset, size_t count);
*
*	This function uses generic handler "ve_generic_offload" as readahead()
*	functionality for VE has common pre and post processing needs.
*
* @param[in] syscall_num System Call number.
* @param[in] syscall_name System Call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_readahead(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	/* TODO: In ve, we are not supporting page cache as of now.
	 * So we can test and update this handler after the support provided.
	 */
	ve_generic_offload(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles setxattr() system call for VE.
 *
 *	int setxattr(const char *path, const char *name,
 *		const void *value, size_t size, int flags);
 *
 *	This function uses generic handler
 *	"ve_hndl_set_xattr_p_char_p_char_p_void"
 *	as setxattr() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num  System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_setxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_set_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
* @brief Handles lsetxattr() system call for VE.
*
*	int lsetxattr(const char *path, const char *name,
*		const void *value, size_t size, int flags);
*
*	This function uses generic handler
*	"ve_hndl_set_xattr_p_char_p_char_p_void" as lsetxattr() functionality
*	for VE has common pre and post processing needs.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_lsetxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_set_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
* @brief Handles fsetxattr() system call for VE.
*
*	int fsetxattr(const char *path, const char *name,
*		const void *value, size_t size, int flags);
*
*	This function does the following:
*	Reads the system call arguments from VEMVA using VE driver interfaces.
*	Invokes ve_recv_string for fetching the value of system call argument
*	pathname and extended attribute name from VEMVA.
*	Offload the system call to VH OS and sends the return value of system
*	call to VE program using "return_system_call" interface.
*
* @param syscall_num System Call number.
* @param syscall_name System Call name.
* @param handle Handle for VE driver interface.
*/
void ve_fsetxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1;
	void *buffer2 = NULL;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(XATTR_NAME_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		goto hndl_return1;
	}
	memset(buffer1, '\0', XATTR_NAME_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[1],
				(char *)buffer1, XATTR_NAME_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	if (args[3]) {
		buffer2 = (void *)malloc(sizeof(char) * args[3]);
		if (NULL == buffer2) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return1;
		}
		memset(buffer2, '\0', args[3]);

		/* Receive buffer2 from VE side */
		if (-1 == ve_recv_data(handle, args[2],
				args[3], (void *)buffer2)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[2]\n");
			retval = -EFAULT;
			goto hndl_return2;
		}
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			buffer2,
			args[3],
			args[4]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles getxattr() system call functionality for VE.
 *
 *	ssize_t getxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *	This function uses generic handler
 *	"ve_hndl_get_xattr_p_char_p_char_p_void" as getxattr() functionality
 *	for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_getxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_get_xattr_p_char_p_char_p_void(syscall_num,
						syscall_name, handle);
}

/**
 * @brief Handles lgetxattr() system call functionality for VE.
 *
 *	ssize_t lgetxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *	This function uses generic handler
 *	"ve_hndl_get_xattr_p_char_p_char_p_void"as lgetxattr()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_lgetxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_get_xattr_p_char_p_char_p_void(syscall_num,
							syscall_name, handle);
}

/**
 * @brief Handles fgetxattr() system call functionality for VE.
 *
 *	ssize_t fgetxattr(const char *path, const char *name,
 *		void *value, size_t size);
 *
 *
 *	This function fetches arguments from VEMVA using VE driver interface.
 *	As length of Pathname/Extended attribute name is unknown this
 *	function uses ve_recv_string().
 *	It then offloads the functionality to VH OS system call.
 *	Updated buffers received from VH OS are copied back to VEMVA using VE
 *	driver interface.
 *	It returns the return value of the system call to VE process using the
 *	"return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 * */
void ve_fgetxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *buffer1 = NULL;
	void *buffer2 = NULL;
	uint64_t args[6];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* Allocate memory for buffer1 */
	buffer1 = (char *)malloc(XATTR_NAME_MAX * sizeof(char));
	if (NULL == buffer1) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer1, '\0', XATTR_NAME_MAX);

	/* Receive buffer1 from VE side */
	retval = ve_recv_string(handle, args[1], (char *)buffer1, XATTR_NAME_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* Allocate memory for buffer2 */
	if (args[3]) {
		buffer2 = (void *)malloc(args[3] * sizeof(char));
		if (NULL == buffer2) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"malloc %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return1;
		}
		memset(buffer2, '\0', args[3]);
	}

	/* call VH system call */
	retval = syscall(syscall_num,
			args[0],
			buffer1,
			buffer2,
			args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	if (args[3]) {
		/* using args[3] to send data as buffer2
		 * length is args[3]
		 * */
		if (-1 == ve_send_data(handle, args[2],
					args[3], (void *)(&buffer2))) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_send_data failed to "
					"send args[2]\n");
			retval = -EFAULT;
			goto hndl_return2;
		}
	}

hndl_return2:
	free(buffer2);
hndl_return1:
	free(buffer1);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

void ve_listxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_llistxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_flistxattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles removexattr() system call functionality for VE.
 *
 *	int removexattr(const char *path, const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char" as
 *	removexattr()functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_removexattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles lremovexattr() system call functionality for VE.
 *
 *	int lremovexattr(const char *path, const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char_p_char"
 *	as lremovexattr()functionality for VE has common pre and
 *	post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_lremovexattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles fremovexattr() system call functionality for VE.
 *
 *	int fremovexattr(int fd, const char *name);
 *
 *	This function uses generic handler(ve_hndl_int_p_char) as fremovexattr()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_fremovexattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

void ve_io_setup(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_io_destroy(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_io_getevents(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_io_submit(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_io_cancel(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_lookup_dcookie(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_create(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_ctl_old(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_wait_old(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_getdents64(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_restart_syscall(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_semtimedop(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fadvise64(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timer_create(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timer_settime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timer_gettime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timer_getoverrun(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timer_delete(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_clock_nanosleep(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_wait(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_ctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_utimes(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_vserver(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles mq_open() system call functionality for VE.
*
*	mqd_t mq_open(const char *name, int oflag);
*	mqd_t mq_open(const char *name, int oflag, mode_t mode,
*		struct mq_attr *attr);
*
*	This function receives the data and arguments from VEMVA/VEHVA using
*	VE driver interface.As length of path is unknown this function uses
*	ve_recv_string().
*	It then offloads the functionality to VH OS system call.
*	It returns the return value of the system call back to the VE process
*	using "return_system_call" interface.
*
* @param syscall_num System call number.
* @param syscall_name System call name.
* @param handle Handle for VE driver interface.
*/
void ve_mq_open(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *path_buff;
	struct mq_attr attr;
	uint64_t args[4];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive contents of 1st argument i.e PATH */
	path_buff = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == path_buff) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(path_buff, '\0', PATH_MAX);

	/* receive contents of 1st argument */
	retval = ve_recv_string(handle, args[0], (char *)path_buff, PATH_MAX);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Receive string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* receive content of 4th argument i.e struct mq_attr */
	if (NULL != (void *)args[3]) {
		if (-1 == ve_recv_data(handle, args[3],
					sizeof(struct mq_attr), &attr)) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"ve_recv_data failed to "
					"receive args[3]\n");
			retval = -EFAULT;
			goto hndl_return1;
		}
		/* call VH system call if 4th argument is not NULL */
		retval = syscall(syscall_num, path_buff, args[1], args[2], &attr);
	} else {
		/* call VH system call if 4th argument is NULL */
		retval = syscall(syscall_num, path_buff, args[1],
				args[2], args[3]);
	}

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

hndl_return1:
	free(path_buff);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles mq_unlink() system call functionality for VE.
 *
 *	int mq_unlink(const char *name);
 *
 *	This function uses generic handler "ve_hndl_p_char" as mq_unlink()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_mq_unlink(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char(syscall_num, syscall_name, handle);
}

/**
* @brief Handles mq_timedsend() system call functionality for VE.
*
*	int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
*		unsigned msg_prio, const struct timespec *abs_timeout);
*
*	This function fetches the arguments and data from VEMVA/VEHVA
*	using VE driver interface. It offloads the functionality to VH OS
*	mq_timedsend() system call. It returns the return value of the system
*	call back to the VE process using "return_system_call" interface.
*
* @param[in] syscall_num System call number.
* @param[in] syscall_name System call name.
* @param[in] handle Handle for VE driver interface.
*/
void ve_mq_timedsend(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *msgptr;
	int msg_len;
	struct timespec abs_timeout;
	uint64_t args[5];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive arguments. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive send buffer size from VE memory */
	msg_len = args[2];

	/* allocate memory to store send data */
	msgptr = (char *)malloc(msg_len * sizeof(char));
	if (NULL == msgptr) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(msgptr, '\0', msg_len);

	/* receive contents to be send from 1st argument */
	if (-1 == ve_recv_data(handle, args[1],
				msg_len, (uint64_t *)msgptr)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive args[1]\n");
		retval = -EFAULT;
		goto hndl_return1;
	}
	/* receive the struct timespec values from 5th argument */
	if (NULL != (void *)args[4]) {
		if (-1 == ve_recv_data(handle, args[4],
					sizeof(struct timespec),
					(uint64_t *)&abs_timeout)) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to receive args[4]\n");
			goto hndl_return1;
		}
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);

		/* call VH system call if time is specified in 5th argument */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, args[3], &abs_timeout);
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if 5th argument is NULL */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, args[3], args[4]);
	}
	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

hndl_return1:
	free(msgptr);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

/**
 * @brief Handles mq_timedreceive() system call functionality for VE.
 *
 *	ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
 *		unsigned *msg_prio, const struct timespec *abs_timeout);
 *
 *	This function fetches the arguments and data from VEMVA/VEHVA and
 *	offloads the functionality to VH OS mq_timedreceive() system call.
 *	This function after receiving the data from VH OS call copies the
 *	data to VEMVA using VE driver interface.
 *	It returns the return value of the system call back to the VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System call number.
 * @param[in] syscall_name System call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_mq_timedreceive(int syscall_num, char *syscall_name,
						vedl_handle *handle)
{
	ret_t retval = -1;
	char *msgptr;
	int msg_len;
	struct timespec abs_timeout;
	unsigned prio;
	uint64_t args[5];
	sigset_t signal_mask;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 5);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to receive arguments. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* receive buffer size from VE memory */
	msg_len = args[2];

	/* allocate memory to store data */
	msgptr = (char *)malloc(msg_len * sizeof(char));
	if (NULL == msgptr) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(msgptr, '\0', msg_len);

	/* receive the struct timespec values from 5th argument */
	if (NULL != (void *)args[4]) {
		if (-1 == ve_recv_data(handle, args[4],
					sizeof(struct timespec),
					(uint64_t *)&abs_timeout)) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to receive args[4]\n");
			goto hndl_return1;
		}

		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if time is specified in 5th argument */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, &prio, &abs_timeout);
	} else {
		/* unblock all signals except the one actualy
		 * blocked by VE process
		 * */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Pre-processing finished, unblock signals\n");
		sigfillset(&signal_mask);
		pthread_sigmask(SIG_SETMASK, &ve_proc_sigmask, NULL);
		/* call VH system call if 5th argument is NULL */
		retval = syscall(syscall_num, args[0],
				msgptr, msg_len, &prio, args[4]);
	}

	/* check for success and failure after syscall return */
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		if (EINTR == errno)
			/* If VHOS syscall is interrupted by signal
			 * set retval to -VE_ERESTARTSYS. VE process
			 * will restart the syscall if SA_RESTART
			 * flag is provided for signal
			 * */
			retval = -VE_ERESTARTSYS;
		/* Post-processing of syscall started, blocking signals */
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"Blocking signals for post-processing\n");
		pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);
	/* Post-processing of syscall started, blocking signals */
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"Blocking signals for post-processing\n");
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);


	/* send the received buffer */
	if (-1 == ve_send_data(handle, args[1],
				msg_len, (uint64_t *)msgptr)) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send args[1]\n");
		goto hndl_return1;
	}

	/* send the received priority */
	if (-1 == ve_send_data(handle, args[3],
				sizeof(unsigned), (uint64_t *)&prio)) {
		retval = -EFAULT;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to send args[3]\n");
	}
hndl_return1:
	free(msgptr);
hndl_return:
	/* write return value */
	return_system_call(retval);
}

void ve_mq_notify(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
* @brief Handles mq_getsetattr() system call functionality for VE.
*
*	int mq_getsetattr(mqd_t mqdes, struct mq_attr *newattr,
*		struct mq_attr *oldattr);
*
*      This function fetches the arguments and data from VEMVA/VEHVA
*      using VE driver interface. It then offloads the functionality to
*      VH OS mq_getsetattr() system call.Updated buffers received from VH OS
*      are sent back to VEMVA using VE driver interface.It returns the return
*      value of the system call back to the VE process	using
*      "return_system_call" interface.
*
* @param syscall_num System call number.
* @param syscall_name System call name.
* @param handle Handle for VE driver interface.
*/
void ve_mq_getsetattr(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct mq_attr oldattr;
	struct mq_attr newattr;
	uint64_t args[3];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 3);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to get argument. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* To handle mq_getattr library function */
	if (0 == args[1]) {
		/* call VH system call */
		retval = syscall(syscall_num, args[0], args[1], &oldattr);
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
		/* send the attributes to VE */
		if (-1 == ve_send_data(handle, args[2],
					sizeof(struct mq_attr), (uint64_t *)&oldattr)) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to send args[2]\n");
			goto hndl_return;
		}
		/* To handle mq_setattr library function */
	} else {
		/* receive the new attributes from VE */
		if (-1 == ve_recv_data(handle, args[1],
					sizeof(struct mq_attr), (uint64_t *)&newattr)) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to receive args[1]\n");
			goto hndl_return;
		}

		/* receive the old attributes from VE */
		if (-1 == ve_recv_data(handle, args[2],
				sizeof(struct mq_attr), (uint64_t *)&oldattr)) {
			retval = -EFAULT;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Failed to receive args[2]\n");
			goto hndl_return;
		}
		/* call VH system call */
		retval = syscall(syscall_num, args[0], &newattr, &oldattr);

		/* check for success and failure return from syscall. */
		if (-1 == retval) {
			retval = -errno;
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"syscall %s failed %s\n",
					syscall_name, strerror(errno));
			goto hndl_return;
		} else
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
					"syscall %s returned %d\n",
					syscall_name, (int)retval);
	}
hndl_return:
	/* write return value */
	return_system_call(retval);
}

void ve_kexec_load(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_add_key(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_request_key(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_keyctl(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_ioprio_set(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_ioprio_get(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_inotify_init(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_inotify_add_watch(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_inotify_rm_watch(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles openat() system call functionality for VE.
 *
 *	int openat(int dirfd, const char *pathname, int flags);
 *	int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as openat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_openat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mkdirat() system call functionality for VE.
 *
 *	int mkdirat(int dirfd, const char *pathname, mode_t mode);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as mkdirat()
 *	functionality for ve has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_mkdirat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles mknodat() system call functionality for VE.
 *
 *	int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as mknodat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_mknodat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles fchownat() system call functionality for VE.
 *
 *	int fchownat(int dirfd, const char *pathname,
 *		uid_t owner, gid_t group, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as fchownat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_fchownat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

void ve_futimesat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles newfstatat() system call functionality for VE.
 *
 *	int newfstatat(int dirfd, const char *pathname,
 *		struct stat *buf, int flags);
 *
 *	This function fetches the arguments from VEHVA/ VEMVA using VE driver
 *	interface and then invokes the VH OS newfstatat() system call.
 *	Updated buffers received from VH OS are copied back to VEMVA using
 *	VE driver interface.
 *	It returns the return value of the system call back to VE process
 *	using "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_newfstatat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	struct stat buffer;
	char *pathname;
	uint64_t args[4];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}

	/* allocate memory to receive path name */
	pathname = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == pathname) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(pathname, '\0', PATH_MAX);

	/* receive the path name */
	retval = ve_recv_string(handle, args[1], (char *)pathname, PATH_MAX);
	if (retval < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return1;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], pathname, &buffer, args[3]);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %d\n",
				syscall_name, (int)retval);

	/* send the filled stat_buf */
	if (-1 == ve_send_data(handle, args[2],
				sizeof(struct stat), (uint64_t *)(&buffer))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[2]\n");
		retval = -EFAULT;
	}

hndl_return1:
	free(pathname);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles unlinkat() system call functionality for VE.
 *
 *	int unlinkat(int dirfd, const char *pathname, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as unlinkat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_unlinkat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles renameat() system call functionality for VE.
 *
 *	int renameat(int olddirfd, const char *oldpath,
 *		int newdirfd, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_int_p_char_int_p_char" as
 *	renameat() functionality for ve has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_renameat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles linkat() system call functionality for VE.
 *
 *	int linkat(int olddirfd, const char *oldpath,
 *		int newdirfd, const char *newpath, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char_int_p_char" as
 *	linkat() functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_linkat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles symlinkat() system call functionality for VE.
 *
 *	int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
 *
 *	This function uses generic handler "ve_hndl_p_char_int_p_char" as
 *	symlinkat() functionality for VE has common pre and post processing
 *	needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_symlinkat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_p_char_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles readlinkat() system call functionality for VE.
 *
 *	int readlinkat(int dirfd, const char *pathname, char *buf,
 *		size_t bufsiz);
 *
 *	This function fetches arguments from VEHVA/ VEMVA using VE driver
 *	interface. It then invokes the VH OS readlinkat() system call.
 *	As the symlink name length is unknown , it uses "ve_recv_string" to
 *	fetch the same. Buffer(containig symbolic link data)
 *	received as output from VH OS system call is then copied back to VEMVA
 *	area using VE driver interface.
 *	It returns the return value of the system call back to VE process using
 *	the "return_system_call" interface.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_readlinkat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ret_t retval = -1;
	char *symlink, *buffer;
	int recv_size;
	uint64_t args[4];

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
			"%s is called\n", syscall_name);

	/* get arguments */
	retval = vedl_get_syscall_args(handle, args, 4);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"vedl_get_syscall_args failed. "
				"(%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return;
	}
	/* prepare buffer */
	recv_size = args[3];

	/* allocate memory to send contents of 2nd argument */
	buffer = (char *)malloc(recv_size * sizeof(char));
	if (NULL == buffer) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return;
	}
	memset(buffer, '\0', recv_size);

	/* allocate memory for storing symbolic link name */
	symlink = (char *)malloc(PATH_MAX * sizeof(char));
	if (NULL == symlink) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"malloc %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return1;
	}
	memset(symlink, '\0', PATH_MAX);

	/* receive symlink name from VE side */
	retval = ve_recv_string(handle, args[1], (char *)symlink, PATH_MAX);
	if (0 > retval) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_recv_string failed. (%s) returned %d\n",
				syscall_name, (int)retval);
		retval = -EFAULT;
		goto hndl_return2;
	}

	/* call VH system call */
	retval = syscall(syscall_num, args[0], symlink, buffer, recv_size);
	if (-1 == retval) {
		retval = -errno;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"syscall %s failed %s\n",
				syscall_name, strerror(errno));
		goto hndl_return2;
	} else
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"syscall %s returned %lu\n",
				syscall_name, retval);

	/* copy back obtained buffer to VE area */
	if (-1 == ve_send_data(handle, args[2],
				recv_size, (uint64_t *)buffer)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"ve_send_data failed to send args[2]\n");
		retval = -EFAULT;
		goto hndl_return2;
	}
hndl_return2:
	free(symlink);
hndl_return1:
	free(buffer);
hndl_return:
	/* write return value */
	return_system_call(retval);
	return;
}

/**
 * @brief Handles fchmodat() system call functionality for VE.
 *
 *	int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as fchmodat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_fchmodat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles faccessat() system call functionality for VE.
 *
 *	int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 *	This function uses generic handler "ve_hndl_int_p_char" as faccessat()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */

void ve_faccessat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_int_p_char(syscall_num, syscall_name, handle);
}

void ve_pselect6(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_ppoll(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_unshare(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_splice(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_tee(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sync_file_range(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_vmsplice(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_utimensat(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_pwait(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timerfd_create(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_eventfd(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fallocate(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timerfd_settime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_timerfd_gettime(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_accept4(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_eventfd2(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_epoll_create1(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_dup3(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles pipe2() system call functionality for VE.
 *
 *	int pipe2(int pipefd[2], int flags);
 *
 *	This function uses same handler "ve_pipe" as pipe2()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 */
void ve_pipe2(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_pipe(syscall_num, syscall_name, handle);
}

void ve_inotify_init1(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

/**
 * @brief Handles preadv() system call for VE.
 *
 *	ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
 *		off_t offset);
 *
 *	This function uses generic handler "ve_hndl_readv_preadv" as preadv()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 *
 */
void ve_preadv(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_readv_preadv(syscall_num, syscall_name, handle);
}

/**
 * @brief Handles pwritev() system call for VE.
 *
 *	ssize_t pwritev(int fd, const struct iovec *iov,
 *		int iovcnt, off_t offset);
 *
 *	This function uses generic handler "ve_hndl_writev_pwritev" as pwritev()
 *	functionality for VE has common pre and post processing needs.
 *
 * @param[in] syscall_num System Call number.
 * @param[in] syscall_name System Call name.
 * @param[in] handle Handle for VE driver interface.
 *
 */
void ve_pwritev(int syscall_num, char *syscall_name, vedl_handle *handle)
{
	ve_hndl_writev_pwritev(syscall_num, syscall_name, handle);
}

void ve_perf_event_open(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_recvmmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fanotify_init(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_fanotify_mark(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_name_to_handle_at(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_open_by_handle_at(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_syncfs(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_sendmmsg(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_setns(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}

void ve_finit_module(int syscall_num, char *syscall_name, vedl_handle *handle)
{
}
