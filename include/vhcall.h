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
 * @file vhcall.h
 */
#ifndef __VE_VHCALL_H
#define __VE_VHCALL_H
#include <stdint.h>
#include <stddef.h>

#define VHCALL_SYMNAME_MAX (1023)
#define VHCALL_MAX_INTREG 6
#define VHCALL_MAX_SSEREG 8

typedef uint64_t vhcall_handle;

enum vhcall_args_class {
        VHCALL_CLASS_INT = 1,
	VHCALL_CLASS_DBL,
	VHCALL_CLASS_CDB,
	VHCALL_CLASS_PTR,
	VHCALL_CLASS_HDL
};

enum vhcall_args_intent {
	VHCALL_INTENT_IN = 1,
	VHCALL_INTENT_INOUT,
	VHCALL_INTENT_OUT
};

typedef struct vhcall_data {
	enum vhcall_args_class cl;
	enum vhcall_args_intent inout;
	uint64_t val[2];
	size_t size;
} vhcall_data;

#endif
