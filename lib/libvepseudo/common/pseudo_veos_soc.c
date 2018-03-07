/**
* @file  veos_soc.c
* @brief Socket Creation.
*
* This file contains the routines that are used for creation of socket
* to be used for communication with VEOS modules i.e AMM/PSM.
*/

#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include "syscall_common.h"
#include "pseudo_veos_soc.h"
#include "libved.h"
#include "velayout.h"

/**
 * @brief Socket creation routine.
 *
 *	This routine creates socket for communication with VEOS modules
 *	AMM/PSM.
 *
 * @param[in] sockpath Socket file path name.
 *
 * @return: -1 on FAILURE, socket file descriptor on SUCCESS.
 */
int pseudo_veos_soc(char *sockpath)
{
	struct sockaddr_un sa = {0};
	int sockfd = -1;
	char *sock_path = sockpath;
	struct sigaction ve_act;

	ve_act.sa_handler = SIG_IGN;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_INFO, "SOCKPATH:%s\n", sockpath);

	/* ignore SIGPIPE */
	if (-1 == sigaction(SIGPIPE, &ve_act, NULL)) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to register signal handler\n");
		return -1;
	}

	/* Create a socket */
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Failed to create socket: %s\n",
				sockpath);
		perror("Error:");
		return -1;
	}

	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, sock_path);

	/* connect */
	if (-1 == connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
				"Connection to veos socket failed %s\n",
				sock_path);
		perror("Error:");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

/**
 * @brief This Function is used to communicate with PSM
 *
 * @param socket_fd Descriptor used to communicate with PSM
 * @param buff contain req info to be sent to PSM
 * @param max_len size of packed structure
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
ssize_t pseudo_veos_send_cmd(int socket_fd, void *buff, int max_len)
{
	ssize_t transferred = 0;
	ssize_t write_byte;

	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "In Func\n");

	if (!buff)
		goto send_error;

	while ((write_byte =
		write(socket_fd, buff + transferred,
		      max_len - transferred)) != 0) {
		if (write_byte == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else {
				VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
						"Sending Command from Pseudo"
						"to PSM failed %s\n",
						strerror(errno));
				break;
			}
		}
		transferred += write_byte;
		if (transferred == max_len)
			break;
		VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG,
				"transferred = %ld, write_byte = %ld\n",
				transferred, write_byte);
	}

send_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return transferred;
}

/**
 * @brief This function is used to communicate with PSM
 *
 * @param sock_fd veos_sock_fd Descriptor used to communicate with PSM
 * @param buff Response returned from PSM
 * @param bufsize Size of Packed strcuture
 *
 * @return On failure, returns -1 and on success, returns any positive value
 */
int64_t pseudo_veos_recv_cmd(int sock_fd,
		void *buff, int bufsize)
{
	ret_t ret = -1;

	if (!buff)
		goto recv_error;

	while ((ret = read(sock_fd, buff, bufsize)) == -1) {
		if (errno == EINTR || errno == EAGAIN) {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Received Command from VEOS"
					"to Pseudo failed :%s\n",
					strerror(errno));
			continue;
		} else {
			VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_ERROR,
					"Received Command from VEOS"
					"to Pseudo failed :%s\n",
					strerror(errno));
			ret = -1;
			goto recv_error;
		}
	}

recv_error:
	VE_LOG(CAT_PSEUDO_CORE, LOG4C_PRIORITY_DEBUG, "Out Func\n");
	return ret;
}
