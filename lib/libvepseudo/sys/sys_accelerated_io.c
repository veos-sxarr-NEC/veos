/*
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/*
 * @file sys_accelerated_io.c
 * @brief Handles Accelerated IO system calls encountered by VE process.
 *
 * This file contains Accelerated IO related system call handlers for the
 * various
 * system calls encountered by VE process.
 *
 * @internal
 * @author Pseudo/System Call Handling
 */

#include "sys_common.h"
#include "mm_transfer.h"
#include "sys_accelerated_io.h"
#include "pseudo_vhshm.h"
#include "veshm_defs.h"
#include "pseudo_veshm.h"
#include "veos_defs.h"
#include "vemva_mgmt.h"

typedef struct {
	uint64_t vh_buf_vhva;   /*!< vhva of VH buffer */
	ssize_t vh_buf_size;    /*!< size of VH buffer */
} vh_buf_info;

static __thread uint64_t pseudo_ve_buf_vehva = 0;
static vh_buf_info pseudo_vh_buf_info = {0, 0};

/**
 * @brief This function allocates VH buffer and registers VH IO buffer and VE
 * IO buffer to DMAATB.
 *
 * @param[in] VEOS handle of Pseudo Process
 * @param[out] An address of pointer to store an address of VH buffer
 * @param[out] An address of variable to store VEHVA of VH buffer
 * @param[in]  An address of VE buff.
 * @param[out] An address of variable to store VEHVA of VE buffer
 * @param[in]  The number of cores
 *
 * @return 0 on success, -errno on Failure.
 */
int sys_accelerated_io_init(veos_handle *handle, void **vhva,
				uint64_t *vehva, void *local_vemva,
				uint64_t *local_vehva, int core_num)
{
	int retval = -EIO;
	int ret;
	void *l_vhva;
	ssize_t vh_buff_size;

	if (NULL == local_vemva) {
		PSEUDO_ERROR("Input local_vemva(%p) is an invalid value",
			local_vemva);
		retval = -EINVAL;
		return retval;
	}
	vh_buff_size = SIZE_8MB * core_num;
	PSEUDO_DEBUG("Core number is %d", core_num);
	PSEUDO_DEBUG("VH buffer size is %ld", vh_buff_size);

	/* allocates VH buffer */
	pseudo_vh_buf_info.vh_buf_vhva = 0;
	pseudo_vh_buf_info.vh_buf_size = 0;
	l_vhva = mmap(0, vh_buff_size, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_SHARED|MAP_HUGETLB,
			-1, 0);
	if (MAP_FAILED == l_vhva) {
		retval = -errno;
		PSEUDO_ERROR("Failed to create VH buffer:%s", strerror(errno));
		return retval;
	}

	PSEUDO_DEBUG("l_vhva = %p\n", l_vhva);
	PSEUDO_DEBUG("vehva = %p\n", vehva);
	PSEUDO_DEBUG("local_vemva = %p\n", local_vemva);
	PSEUDO_DEBUG("local_vehva = %p\n", local_vehva);

	pseudo_vh_buf_info.vh_buf_vhva = (uint64_t)l_vhva;
	pseudo_vh_buf_info.vh_buf_size = vh_buff_size;

	/* registers VH IO buffer and VE IO buffer to DMAATB */
	ret = sys_accelerated_io_register_dmaatb(handle, l_vhva,
					vehva, local_vemva,
					local_vehva, core_num);
	if (0 != ret) {
		retval = ret;
		munmap(l_vhva, vh_buff_size);
		return retval;
	}

	/* set results */
	if (ve_send_data(handle, (uint64_t)vhva,
		sizeof(uint64_t), &l_vhva) != 0) {
		PSEUDO_ERROR("Failed to send vhva");
		return retval;
	}
	retval = 0;
	return retval;
}

/**
 * @brief This function registers VH IO buffer and VE IO buffer to DMAATB.
 *
 * @param[in] VEOS handle of Pseudo Process
 * @param[in] An address of VH buffer or NULL
 * @param[out] An address of variable to store VEHVA of VH buffer
 * @param[in]  An address of VE buff or NULL
 * @param[out] An address of variable to store VEHVA of VE buffer
 * @param[in]  The number of cores
 *
 * @return 0 on success, -errno on Failure.
 */
int sys_accelerated_io_register_dmaatb(veos_handle *handle, void *vhva,
					 uint64_t *vehva, void *local_vemva,
					 uint64_t *local_vehva, int core_num)
{
	int retval = -EIO;
	uint64_t ve_args[VESHM_MAX_ARGS+1];
	uint64_t ve_detach_args[3];
	int64_t l_vehva;
	int64_t l_local_vehva;
	uint64_t l_local_vemva = 0;
	uint64_t change_mask;
	ssize_t vh_buff_size;
	int64_t vemva_pg_size;
	int64_t register_size = 0;
	pid_t pid;

	vh_buff_size = SIZE_8MB * core_num;
	PSEUDO_DEBUG("Core number is %d", core_num);
	PSEUDO_DEBUG("VH buffer size is %ld", vh_buff_size);

	/* register VH IO buffer to DMAATB */
	if (NULL != vhva) {
		l_vehva = sys_vhshm_exchange_attach_request(handle, vhva,
							vh_buff_size, 0);
		if (0 > l_vehva) {
			PSEUDO_ERROR("Failed to register VH buff to DMAATB:%s",
					strerror(-l_vehva));
			retval = l_vehva;
			return retval;
		}
		/* set results */
		if (ve_send_data(handle, (uint64_t)vehva,
			sizeof(uint64_t), &l_vehva) != 0) {
			sys_vhshm_exchange_detach_request(handle, l_vehva);
			PSEUDO_ERROR("Failed to send vehva");
			return retval;
		}
	}
	if (NULL != local_vemva) {
		/* adjust the register size and address of VE IO buffer */
		pid = getpid();
		vemva_pg_size = pseudo_veshm_get_pgmode(handle, VE_ADDR_VEMVA,
						pid, (uint64_t)local_vemva);
		PSEUDO_DEBUG("Page size is %ld", vemva_pg_size);
		if (vemva_pg_size == SIZE_2MB) {
			register_size = SIZE_8MB;
			change_mask = CHANGE_MASK_2MB;
		} else if (vemva_pg_size == SIZE_64MB) {
			register_size = SIZE_64MB;
			change_mask = CHANGE_MASK_64MB;
		} else if (vemva_pg_size < 0) {
			PSEUDO_ERROR("Failed to get page size: %d",
					(int)vemva_pg_size);
			retval = vemva_pg_size;
			sys_vhshm_exchange_detach_request(handle, l_vehva);
			return retval;
		} else {
			PSEUDO_ERROR("Unsupported page size: %d",
					(int)vemva_pg_size);
			retval = -EIO;
			sys_vhshm_exchange_detach_request(handle, l_vehva);
			return retval;
		}

		l_local_vemva = ((uint64_t)local_vemva) & change_mask;
		if ((l_local_vemva + register_size)
			< ((uint64_t)local_vemva + SIZE_8MB)) {
			register_size = register_size + vemva_pg_size;
		}

		PSEUDO_DEBUG("Orignal vemva is %p", (void *)local_vemva);
		PSEUDO_DEBUG("Changed vemva is %p", (void *)l_local_vemva);

		/* register VE IO buffer to DMAATB */
		ve_args[1] = pid;
		ve_args[2] = l_local_vemva;
		ve_args[3] = register_size;
		ve_args[4] = 0;
		ve_args[5] = VE_MEM_LOCAL;

		PSEUDO_DEBUG("pid = %ld\n", ve_args[1]);
		PSEUDO_DEBUG("l_local_vemva = %p\n", (void *)ve_args[2]);
		PSEUDO_DEBUG("register_size = %ld\n", ve_args[3]);

		l_local_vehva = pseudo_veshm_attach(ve_args, handle);
		if (0 > l_local_vehva) {
			PSEUDO_ERROR("Failed to register VE buff to DMAATB:%s",
					 strerror(-l_local_vehva));
			retval = l_local_vehva;
			sys_vhshm_exchange_detach_request(handle, l_vehva);
			return retval;
		}
		pseudo_ve_buf_vehva = l_local_vehva;
		PSEUDO_DEBUG("pseudo_ve_buf_vehva = %p\n",
				 (void *)pseudo_ve_buf_vehva);
		l_local_vehva = l_local_vehva
				+ ((uint64_t)local_vemva - l_local_vemva);
		/* set results */
		if (ve_send_data(handle, (uint64_t)local_vehva,
			sizeof(uint64_t), &l_local_vehva) != 0) {
			PSEUDO_ERROR("Failed to send local_vehva");
			ve_detach_args[1] = pseudo_ve_buf_vehva;
			ve_detach_args[2] = VE_MEM_LOCAL;
			pseudo_veshm_detach(ve_detach_args, handle);
			sys_vhshm_exchange_detach_request(handle, l_vehva);
			return retval;
		}
		retval = 0;
		return retval;
	}
	retval = 0;
	return retval;
}

/**
 * @brief This function call pseudo_veshm_detach() to unregister ve buffer
 * memory from DMAATB
 *
 */
void sys_accelerated_unregister_ve_buf_vehva(veos_handle *handle)
{
	uint64_t ve_detach_args[3];

	ve_detach_args[1] = pseudo_ve_buf_vehva;
	ve_detach_args[2] = VE_MEM_LOCAL;
	PSEUDO_DEBUG("ve_buf_vehva = %p", (void *)ve_detach_args[1]);
	if (ve_detach_args[1]) {
		pseudo_veshm_detach(ve_detach_args, handle);
	}
}

/**
 * @brief This function free the vh buffer
 *
 */
void sys_accelerated_free_vh_buf(void)
{
	munmap((void *)pseudo_vh_buf_info.vh_buf_vhva,
		pseudo_vh_buf_info.vh_buf_size);
}

