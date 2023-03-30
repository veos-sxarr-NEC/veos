#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libved.h>
#include <veos.h>
#include <veos_ve1.h>
#include <veos_arch_defs.h>

int veos_ve1_probe(vedl_handle *handle, void *unused)
{
	const char *arch_class = vedl_get_arch_class_name(handle);
	return strcmp(arch_class, "ve1") == 0;
}

VEOS_ARCH_DEF(ve1, _veos_ve1_arch_ops, veos_ve1_probe)

int ve1_construct_node_arch_dep_data(struct ve_node_struct *venode)
{
	venode->arch_dep_data = calloc(1,
					sizeof(struct ve1_node_arch_dep_data));
	if (venode->arch_dep_data == NULL) {
		return -errno;
	}

	venode->ve_type = VE_TYPE_VE1;

	return 0;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_main_construct_node_arch_dep_data, ve1_construct_node_arch_dep_data)

void ve1_free_node_arch_dep_data(struct ve_node_struct *venode)
{
        free(venode->arch_dep_data);
}
VEOS_ARCH_DEP_FUNC(ve1, arch_main_free_node_arch_dep_data, ve1_free_node_arch_dep_data)

void ve1_turn_on_clock_gating(void)
{
	return;
}
VEOS_ARCH_DEP_FUNC(ve1, arch_turn_on_clock_gating, ve1_turn_on_clock_gating)
