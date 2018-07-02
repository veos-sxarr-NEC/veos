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

/**
 * @file ived_request.h  
 * @brief IVED related interface between VEOS and pseudo process.
 *
 * @internal
 * @author VESHM
 */

#ifndef __VEOS_PSEUDO_INTERFACE_IVED_H
#define __VEOS_PSEUDO_INTERFACE_IVED_H

#define NR_CR_ARGS	4

/* It is used by VESHM and CR. */
struct ived_sub_reply {
	uint64_t address;
	uint64_t size;
	uint32_t attr;
	uint32_t num;
};

/* Data structure for Pseudo process and VEOS */
struct veshm_args {
	int subcmd;

	union {
		struct open_arg{
			uint64_t vemva;
			uint64_t size;
			uint32_t syncnum;
			uint64_t mode_flag;
		} args_veshm_sub_open;

		struct attach_arg {
			uint64_t user_vemva;
			uint32_t owner_pid;
			uint64_t vemva;
			uint64_t size;
			uint32_t syncnum;
			uint64_t mode_flag;
		} args_veshm_sub_attach;

		struct detach_arg {
			uint64_t address;
			uint64_t mode_flag;
		} args_veshm_sub_detach;

		struct close_arg {
			uint64_t vemva;
			uint64_t size;
			uint32_t syncnum;
			uint64_t mode_flag;
		} args_veshm_sub_close;

		struct pgsize_arg {
			uint32_t pid;
			uint64_t address;
			uint64_t mode_flag;
		} args_veshm_pgsize;
	}arg;
};

struct cr_args {
	int subcmd;
	uint64_t args[NR_CR_ARGS];
};

struct vhshm_args {
	int subcmd;
	union {
		struct at_args {  /* Used to vh_shmat() request. */
			uint64_t vhva;
			size_t size;
			int shmflag;
		} at_arg;
		struct dt_args {/* Used to vh_shmdt() request. */
			uint64_t vehva;
		} dt_arg;
	};
};

#endif
