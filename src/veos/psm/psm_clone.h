/**
 * @file psm_clone.h
 * @brief Interfaces for handling fork and clone system call request.
 */
#ifndef __PSEUDO_CLONE_H
#define __PSEUDO_CLONE_H

#include "psm_task_mgmt.h"
#define REQUEST_FOR_PROCESS_SHARED	1
#define REQUEST_FOR_PROCESS_PRIVATE	2


#define task_thread_info(task)  ((struct thread_info *)(task)->stack)
#define task_stack_page(task)   ((task)->stack)

void setup_ve_thread_stack(struct ve_task_struct *, struct ve_task_struct *);
int arch_dup_ve_task_struct(struct ve_task_struct *, struct ve_task_struct *);
int arch_dup_ve_thread_struct(struct ve_thread_struct *, struct ve_thread_struct *);
struct ve_thread_struct *alloc_ve_thread_info_node();
struct ve_task_struct *dup_ve_task_struct(struct ve_task_struct *);
int copy_ve_mm(struct ve_task_struct *, unsigned long,
				struct ve_task_struct *);
int copy_ve_thread(struct ve_task_struct *, unsigned long, unsigned long,
		unsigned long, struct ve_task_struct*);
struct ve_task_struct *copy_ve_process(unsigned long, unsigned long,
		unsigned long, int *, struct ve_fork_info *);
int copy_ve_sighand(struct ve_task_struct *, unsigned long,
		 struct ve_task_struct *);
int find_shared_page_offset(struct ve_task_struct *);
void wake_up_new_ve_task(struct ve_task_struct *);
int do_ve_fork(unsigned long, unsigned long, unsigned long, int *, int *,
		struct ve_fork_info *);
#endif
