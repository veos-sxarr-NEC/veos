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
 * @file   veshm_defs.h
 * @brief  Header file for VESHM 
 */

#ifndef _IVED_VESHM_H
#define _IVED_VESHM_H

enum VESHM_mode_flag {
	VE_SHM_RO		= 0x0000000000000001LL, 
	VE_PCISYNC		= 0x0000000000000002LL,
	VE_REGISTER_PCI		= 0x0000000000000004LL,
};

enum VESHM_additional_mode_flag {
	VE_REGISTER_NONE	= 0x0000000000001000LL,	/* IPC */
	VE_REGISTER_VEMVA	= 0x0000000000002000LL, /* IPC */
	VE_REGISTER_VEHVA	= 0x0000000000004000LL, /* IPC */
	VE_MEM_LOCAL		= 0x0000000000008000LL, /* IPC */
};

/* RPC sub commands for VESHM */
enum VESHM_command {
	VESHM_OPEN	= 0x30,
	VESHM_ATTACH,
	VESHM_DETACH,
	VESHM_CLOSE,

	VESHM_PGSIZE	= 0x36,
	VESHM_CHECK_PARTIAL,
};

#endif
