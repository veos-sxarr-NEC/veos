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
#ifndef VEOS_VEMMAGENT_FALLBACK_H_
#define VEOS_VEMMAGENT_FALLBACK_H_

#warning "A fallback header in VEOS tree is used."

#ifdef __cplusplus
/* C API */
extern "C" {
#endif

struct vemm_agent_operations {
	int (*check_pid)(pid_t);
	int (*acquire)(pid_t, uint64_t, size_t);
	int (*get_pages)(uid_t, pid_t, uint64_t, size_t, int,
			 uint64_t **, size_t *, unsigned char *);
	int (*put_pages)(uid_t, pid_t, unsigned char *);
	int (*dmaattach)(uid_t, pid_t, uint64_t, int, uint64_t *);
	int (*dmadetach)(uid_t, pid_t, uint64_t);
};

struct vemm_agent_struct;
typedef struct vemm_agent_struct vemm_agent;

#ifdef __cplusplus
}
#endif

#endif
