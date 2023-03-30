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
 * @file veos_vemm.c
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <libved.h>

#include "vehva_mgmt.h"
#include "dmaatb_api.h"
#include "ve_memory.h"

#include "proto_buff_schema.pb-c.h"
#include "psm_comm.h"

#if HAVE_VEMMAGENT_H
#include <vemmagent.h>
#else
#include <vemmagent_fallback.h>
#endif /* HAVE_VEMMAGENT_H */

#ifndef LIBVEMMAGENT_NAME
#define LIBVEMMAGENT_NAME "libvemmagent.so.1"
#endif

#include "veos_vemm_log.h"
#include "veos_vemm_handler.h"

log4c_category_t *cat_vemm_agent;

static vemm_agent *agentp;
static pthread_t agent_thread;

/* to call functions in libvemmagent */
static struct vemm_agent_functions {
	void *handle;
	vemm_agent *(*create)(const char *,
			const struct vemm_agent_operations *);
	int (*exec)(vemm_agent *);
	void (*stop)(vemm_agent *);
	void (*destroy)(vemm_agent *);
} agent_func;

/**
 * @brief initialize pointers to functions in libvemmagent.so
 *
 * @return zero upon success; negative upon failure.
 */
static int vemm_agent_functions_init(void)
{
	VEMM_AGENT_TRACE("%s()", __func__);
	void *handle = dlopen(LIBVEMMAGENT_NAME, RTLD_LAZY);
	if (handle == NULL) {
		VEMM_AGENT_DEBUG("dlopen(\"" LIBVEMMAGENT_NAME "\") failed. "
			"Retry using an absolute path.");
		handle = dlopen(VEMM_AGENT_LIBDIR "/" LIBVEMMAGENT_NAME,
				RTLD_LAZY);
	}
	if (handle == NULL) {
		VEMM_AGENT_ERROR("cannot load VEMM agent: %s", dlerror());
		return -1;
	}
	agent_func.handle = handle;

	agent_func.create = dlsym(handle, "vemm_agent__create");
	if (agent_func.create == NULL) {
		VEMM_AGENT_ERROR("vemm_agent__create is not found.");
		goto sym_not_found;
	}
	agent_func.exec = dlsym(handle, "vemm_agent__exec");
	if (agent_func.exec == NULL) {
		VEMM_AGENT_ERROR("vemm_agent__exec is not found.");
		goto sym_not_found;
	}
	agent_func.stop = dlsym(handle, "vemm_agent__request_stop");
	if (agent_func.stop == NULL) {
		VEMM_AGENT_ERROR("vemm_agent__request_stop is not found.");
		goto sym_not_found;
	}
	agent_func.destroy = dlsym(handle, "vemm_agent__destroy");
	if (agent_func.destroy == NULL) {
		VEMM_AGENT_ERROR("vemm_agent__destroy is not found.");
		goto sym_not_found;
	}
	return 0;

sym_not_found:
	dlclose(handle);
	return -1;
}

/**
 * @brief Run VEMM agent
 *
 * @param sockname the name of a socket of VEMM daemon
 *
 * @return zero upon sucess; negative upon failure.
 */
int vemm_agent_run(const char *sockname)
{
	struct vemm_agent_operations ops = {
		.check_pid = veos_vemm_check_pid,
		.acquire = veos_vemm_acquire,
		.get_pages = veos_vemm_get_pages,
		.put_pages = veos_vemm_put_pages,
		.dmaattach = veos_vemm_dmaattach,
		.dmadetach = veos_vemm_dmadetach,
	};
	/* initialize log4c */
	cat_vemm_agent = log4c_category_get(VEMM_AGENT_LOG_CAT);
	if (cat_vemm_agent == NULL) {
		/* output to stderr bacause log4c is unavailable here. */
		fputs("failed to get log4c category.\n", stderr);
		return -1;
	}
	/* output trace log after confirming that log4c is available. */
	VEMM_AGENT_TRACE("%s(%s)", __func__, sockname);
	if (vemm_agent_functions_init() != 0) {
		VEMM_AGENT_ERROR("failed to load VEMM agent.");
		return -1;
	}
	/* create agent */
	agentp = agent_func.create(sockname, &ops);
	if (agentp == NULL) {
		VEMM_AGENT_ERROR("failed to create VEMM agent.");
		goto error_agent;
	}
	/* create agent thread */
	int e = pthread_create(&agent_thread, NULL,
			       (void *(*)(void *))agent_func.exec, agentp);
	if (e != 0) {
		VEMM_AGENT_ERROR("failed to create agent thread: %s",
			strerror(e));
		goto error_thread;
	}
	return 0;
error_thread:
	agent_func.destroy(agentp);
error_agent:
	dlclose(agent_func.handle);
	return -1;
}

/**
 * @brief Request VEMM agent to stop event loop and to finish.
 *
 * @return zero upon success; netative upon failure.
 *         The current implementation always returns zero.
 */
int vemm_agent_request_finish(void)
{
	VEMM_AGENT_TRACE("%s()", __func__);
	agent_func.stop(agentp);
	return 0;
}

/**
 * @brief Wait for completion of VEMM agent thread.
 *
 * @return zero upon success; negative upon failure.
 */
int vemm_agent_wait(void)
{
	int e;
	long rv;
	VEMM_AGENT_TRACE("%s()", __func__);
	e = pthread_join(agent_thread, (void **)&rv);
	if (e != 0)
		VEMM_AGENT_ERROR("unexpected error at pthread_join(): %s",
			strerror(e));
	if (rv != 0)
		VEMM_AGENT_ERROR("error from agent (returned = %ld)", rv);
	agent_func.destroy(agentp);
	agentp = NULL;
	dlclose(agent_func.handle);
	return (e == 0 && rv == 0) ? 0 : -1;
}

/**
 * @brief Get VEHVA from VHVA
 *
 * @param addr VHVA
 * @param pid process ID
 *
 * @return VEHVA mapped to the area specified by VHVA
 */
int64_t veos_vemm_vhva_to_vehva(void *addr, pid_t pid)
{
	VEMM_AGENT_TRACE("%s(%p, %d)", __func__, addr, pid);
	int pfnmap;
	uint64_t vhsaa;

	/* safe because TID authentication has done here. */
	/* not pinned because the area is likely to be on PCI MMIO area. */
	/* unnecessary to check write protection */
	vhsaa = vedl_get_dma_address(VE_HANDLE(0), addr, pid, 0, 0, &pfnmap);
	VEMM_AGENT_DEBUG("PID %d, VHVA=%p -> VHSAA=%p (pfnmap=%d)", pid, addr,
		(void *)vhsaa, pfnmap);
	if (vhsaa == (uint64_t)-1) {
		VEMM_AGENT_ERROR("translation failed (pid=%d, addr=%p)",
			(int)pid, addr);
		return -EFAULT;
	}
	int64_t vehva = veos_aa_to_vehva(pid, vhsaa, VE_ADDR_VHSAA);
	if (vehva < 0) {
		VEMM_AGENT_ERROR("cannot translate VHSAA %p into VEHVA (%ld)",
			(void *)vhsaa, vehva);
	}
	VEMM_AGENT_TRACE("%s(): vehva=%p", __func__, (void *)vehva);
	return vehva;
}

/**
 * @brief Send a reply to a client
 *
 * @param[in] pti containing request info
 * @param syscall_retval return value to be sent to client
 *
 * @return 0 upon success; negative upon failure.
 */
int veos_vemm_send_reply(veos_thread_arg_t *pti, int64_t syscall_retval)
{
	VEMM_AGENT_TRACE("%s(%p, %#lx)", __func__, pti,
			(unsigned long)syscall_retval);

	PseudoVeosMessage reply_msg = PSEUDO_VEOS_MESSAGE__INIT;
	reply_msg.has_syscall_retval = 1;
	reply_msg.syscall_retval = syscall_retval;

	ssize_t msglen = pseudo_veos_message__get_packed_size(&reply_msg);
	VEMM_AGENT_DEBUG("size calculated = %ld", (long)msglen);
	uint8_t *msgbuf = malloc(msglen);
	if (msgbuf == NULL) {
		VEMM_AGENT_ERROR("malloc() failed: %s", strerror(errno));
		return -1;
	}
	
	int ret, retval = -1;
	ret = pseudo_veos_message__pack(&reply_msg, msgbuf);
	VEMM_AGENT_DEBUG("message size = %d", ret);
	if (ret != msglen) {
		VEMM_AGENT_ERROR("unexpected size: determined=%d, packed=%d",
				(int)msglen, ret);
		retval = -1;
		goto err_ret;
	}
	ret = psm_pseudo_send_cmd(pti->socket_descriptor, msgbuf, msglen);
	if (ret < 0) {
		VEMM_AGENT_ERROR("failed to send reply");
		retval = -1;
		goto err_ret;
	}
	retval = 0;
err_ret:
	free(msgbuf);
	return retval;
}

/**
 * @brief handles a request from pseudo process.
 *
 * @param[in] pti containing request info
 *
 * @return 0 upon success; negative upon failure.
 */
int veos_handle_vemmctl(veos_thread_arg_t *pti)
{
	VEMM_AGENT_TRACE("%s(%p)", __func__, pti);

	ProtobufCBinaryData *pseudo_msg;
	int rv;
	struct ucred cred;
	socklen_t ucred_size = sizeof(cred);

	assert(pti);

	/*
	 * Although the caller already checks PID of requester,
	 * the PID is not passed. Hence, get it again here.
	 */
	rv = getsockopt(pti->socket_descriptor, SOL_SOCKET, SO_PEERCRED, &cred,
			(socklen_t *)&ucred_size);
	if (rv != 0) {
		VEMM_AGENT_ERROR("failed to get credential (%s)",
				strerror(errno));
		return -1;
	}
	VEMM_AGENT_DEBUG("requester PID = %d", cred.pid);
	pseudo_msg = &(((PseudoVeosMessage *)pti->pseudo_proc_msg)->pseudo_msg);
	void *vhva;
	int64_t retval;
	if (sizeof(vhva) != pseudo_msg->len) {
		VEMM_AGENT_ERROR("invalid message size: %lu",
				(unsigned long)pseudo_msg->len);
		retval = -EINVAL;
		goto send_reply;
	}
	vhva = *(void **)pseudo_msg->data;
	VEMM_AGENT_DEBUG("argument = %p", vhva);
	retval = veos_vemm_vhva_to_vehva(vhva, cred.pid);
send_reply:
	VEMM_AGENT_DEBUG("send reply (retval = %ld)", retval);
	rv = veos_vemm_send_reply(pti, retval);
	return rv;
}
