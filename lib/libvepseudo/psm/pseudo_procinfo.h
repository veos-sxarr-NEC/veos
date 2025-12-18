/*
 * Copyright (C) 2025 NEC Corporation
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
* @file pseudo_procinfo.h
* @brief Header file for "pseudo_procinfo.c" file.
*
* @internal
* @author PSMG
*/
#ifndef __PSEUDO_PROCINFO_H
#define __PSEUDO_PROCINFO_H
#include <pthread.h>

int get_proc_status(pid_t, char *);
int ve_premature_child_exit(pid_t);

#endif /* __PSEUDO_PROCINFO_H */
