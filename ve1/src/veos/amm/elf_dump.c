#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libved.h>
#include <ve_hw.h>
#include <libved_ve1.h>
#include "ptrace_req_ve1.h"
#include <veos_arch_defs.h>



unsigned long ve1_copy_user_regs_to_elf_thread_info(void *u, struct ve_thread_struct *p_ve_thread)
{
        struct ve1_user_regs *user_regs = u;
        memcpy(user_regs, p_ve_thread->arch_user_regs, sizeof(struct ve1_user_regs));
        user_regs->EXS = p_ve_thread->EXS;
	u = (void *)user_regs;
	unsigned long n = sizeof(struct ve1_user_regs);
        return n;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_copy_user_regs_to_elf_thread_info, ve1_copy_user_regs_to_elf_thread_info)


void ve1_copy_vector_regs_from_thread_struct(void *user_vregs, struct ve_thread_struct *p_ve_thread)
{
        memcpy(user_vregs, (p_ve_thread->arch_user_regs)+
                sizeof(struct ve1_user_regs), sizeof(struct ve1_user_vregs));
        return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_copy_vector_regs_from_thread_struct, ve1_copy_vector_regs_from_thread_struct)
