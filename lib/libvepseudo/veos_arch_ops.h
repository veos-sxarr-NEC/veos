#ifndef LIBVEPSEUDO_VEOS_ARCH_OPS_H
#define LIBVEPSEUDO_VEOS_ARCH_OPS_H
#include <signal.h>
#include <stdint.h>
#include <libvepseudo.h>
#include <elf.h>

typedef Elf64_Ehdr Elf_Ehdr;

struct veos_arch_ops {
	int (*arch_exception_to_signal)(uint64_t, siginfo_t *);
	void (*arch_exception_handler)(veos_handle *, uint64_t);
	int (*arch_get_fixed_vehva)(uint64_t, uint64_t *);
	void (*arch_fill_ve_elf_data)(char *);
	uint64_t (*arch_get_hardware_capability)(uint32_t);
	void (*arch_ve_validate_gap)(Elf_Ehdr *);
	int64_t (*arch_set_PSW_bitmask)();
};
extern const struct veos_arch_ops *_veos_arch_ops;
#endif
