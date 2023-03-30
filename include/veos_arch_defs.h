/* Copyright (C) 2017-2018 by NEC Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
/**
 * @file   veos_arch_defs.h
 * @brief  Macros to make architecture-dependent code.
 */

#ifndef VEOS_ARCH_DEFS_H_INCLUDE_
#define VEOS_ARCH_DEFS_H_INCLUDE_

#include <veos_arch_ops.h>
#include <libved.h>
#include <stdio.h>

struct veos_architecture_definition {
	const char *name;
	const struct veos_arch_ops *ops;
	int (*probe)(vedl_handle *, void *);
};

/*
 * Compling each source, a compiler verifies the type of function
 * by generating its function prototype declaration.
 */
#define VEOS_ARCH_DEP_FUNC(archname_, funcptr_, impl_) \
extern struct veos_architecture_definition _veos_ ## archname_ ## _arch_def; \
__typeof(*_veos_ ## archname_ ## _arch_def.ops->funcptr_) impl_;

#define VEOS_ARCH_DEF(archname_, ops_, probefunc_) \
extern struct veos_arch_ops _veos_ ## archname_ ## _arch_ops; \
struct veos_architecture_definition _veos_ ## archname_ ## _arch_def = { \
	.name = #archname_, \
	.ops = &ops_, \
	.probe = probefunc_, \
}; \
const struct veos_architecture_definition *_veos_ ## archname_ ## _arch_def_ptr \
__attribute__((__section__("veos_arch_defs"), __used__)) = \
&_veos_ ## archname_ ## _arch_def;

extern const struct veos_architecture_definition *__start_veos_arch_defs;
extern const struct veos_architecture_definition *__stop_veos_arch_defs;
static inline const struct veos_arch_ops *_veos_arch_find(vedl_handle *handle,
							void *arg)
{
	const struct veos_architecture_definition **p;
	int ret = 0;
	for (p = &__start_veos_arch_defs; p < &__stop_veos_arch_defs; ++p) {
		ret = (*p)->probe(handle, arg);
		if (ret != 0)
		{
			if( ret == -1)
				return NULL;
			return (*p)->ops;
		}
	}
	const char *ve_arch_class = vedl_get_arch_class_name(handle);
	fprintf(stderr, "This unified VEOS source code is not supported for %s VE device",ve_arch_class);

	return NULL;
}

#endif
