/**
* Copyright (C) 2017-2020 NEC Corporation
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
 * @file ve_clone.h
 * @brief Interfaces for handling fork and clone system call request.
 *
 * @internal
 * @author PSMG / MP-MT
 */
#ifndef __PSEUDO_CLONE_H
#define __PSEUDO_CLONE_H

#include "task_mgmt.h"
#define REQUEST_FOR_PROCESS_SHARED	1
#define REQUEST_FOR_PROCESS_PRIVATE	2


#define task_thread_info(task)  ((struct thread_info *)(task)->stack)
#define task_stack_page(task)   ((task)->stack)

int arch_dup_ve_task_struct(struct ve_task_struct *, struct ve_task_struct *);
int arch_dup_ve_thread_struct(struct ve_thread_struct *, const struct ve_thread_struct *);
struct ve_thread_struct *alloc_ve_thread_info_node();
struct ve_task_struct *dup_ve_task_struct(struct ve_task_struct *);
int copy_ve_mm(struct ve_task_struct *, unsigned long,
				struct ve_task_struct *);
int copy_ve_thread(struct ve_task_struct *, unsigned long, unsigned long,
		unsigned long, struct ve_task_struct*);
struct ve_task_struct *copy_ve_process(unsigned long, unsigned long,
		unsigned long, int *, struct ve_fork_info *, struct ve_task_struct *);
int copy_ve_sighand(struct ve_task_struct *, unsigned long,
		 struct ve_task_struct *);
int find_shared_page_offset(struct ve_task_struct *);
void wake_up_new_ve_task(struct ve_task_struct *);
int do_ve_fork(unsigned long, unsigned long, unsigned long, int *, int *,
		struct ve_fork_info *);
#endif
