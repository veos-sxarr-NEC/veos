/**
 * Copyright (C) 2018 by NEC Corporation
 * This file is part of the VEOS.]
 *
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see * <http://www.gnu.org/licenses/>.
 */
/**
 * @file sys_vepci.c
 * @brief Handle PCI operation system call on VE
 *
 * @internal
 * @author VEPCI
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "handle.h"
#include "libvepseudo.h"
#include "sysve_os.h"

/**
 * @brief This function is handler of ve_register/unregister_mem_to/from_pci
 *        and ve_register/unregister_pci_to/from_vehva
 * @param[in] handle Handle for VE driver interface
 * @param[in] addr Address to register or unregister
 * @param[in] size Size of address
 * @param[in] msg_id Identifier of request operation
 *
 * @return Return Address or 0 on success. Negative value on failure.
 */
int64_t ve_sys_pcireq(veos_handle *handle, uint64_t addr, size_t size,
			enum pseudo_veos_msg_id msg_id)
{
        int64_t ret = 0;
	PseudoVeosMessage *reply_msg = NULL;
        struct pcicmd *cmd = NULL;
        ProtobufCBinaryData request_msg = {0};

        PSEUDO_TRACE("invoked");

        cmd = (struct pcicmd *)calloc(1, sizeof(struct pcicmd));
        if (NULL == cmd) {
                PSEUDO_DEBUG("Fail to allocate memory for "
                                "amm request block\n");
                return -ENOMEM;
        }

        /* Populating struct ve_mmap_cmd buffer to Generate IPC Command */
        cmd->addr = addr;
        cmd->size = size;

        PSEUDO_DEBUG("Sending request for PCI operation to VEOS for addr(0x%lx) "
                        "size(0x%lx)",
                        cmd->addr, cmd->size);

        /* Populate parameters for ve_mmap req */
        request_msg.len = sizeof(struct pcicmd);
        request_msg.data = (uint8_t *)cmd;
	ret = ve_request_veos(handle, msg_id, &request_msg, &reply_msg);
	if (ret < 0) {
		PSEUDO_ERROR("Failed to request PCI operation to VEOS: %s",
				strerror(-ret));
		goto hndl_return;
	}

	ret = (int64_t)reply_msg->syscall_retval;
        if (reply_msg->syscall_retval < 0) {
                PSEUDO_DEBUG("Error(%s) occurred on VE OS while PCI operation for addr(0x%lx)",
                                strerror(-ret), addr);
        } else {
                PSEUDO_DEBUG("retval:0x%lx PCI operation successfully done on VE",
				reply_msg->syscall_retval);
        }
        pseudo_veos_message__free_unpacked(reply_msg, NULL);
hndl_return:
        if (cmd)
                free(cmd);
        PSEUDO_TRACE("returned(%ld)", ret);
        return ret;
}
