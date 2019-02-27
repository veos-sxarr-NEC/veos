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
#ifndef __VE_SYSVE_H
#define __VE_SYSVE_H

enum sysve_command {
	VE_SYSVE_DUMMY = 0,
	VE_SYSVE_VHCALL_INSTALL = 0x10,
	VE_SYSVE_VHCALL_FIND,
	VE_SYSVE_VHCALL_INVOKE,
	VE_SYSVE_VHCALL_UNINSTALL,
	VE_SYSVE_VESHM_CTL = 0x20,
	VE_SYSVE_CR_CTL,
	VE_SYSVE_GET_PCISYNC = 0x30,
	VE_SYSVE_GET_FIXED_VEHVA,
	VE_SYSVE_SET_USER_REG,
	VE_SYSVE_GET_VE_INFO,
	VE_SYSVE_VHSHM_CTL = 0x40,
	VE_SYSVE_MAP_DMADES = 0x50,
	VE_SYSVE_UNMAP_DMADES,
	VE_SYSVE_AIO_READ = 0x60,
	VE_SYSVE_AIO_WRITE,
	VE_SYSVE_AIO_WAIT,
	VE_SYSVE_ACCELERATED_IO_INIT,
	VE_SYSVE_ACCELERATED_IO_REGISTER_DMAATB,
	VE_SYSVE_SYSTEM
};

#endif
