/*
 * Copyright (C) 2021 NEC Corporation
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
* @file  productinfo.h
* @brief header file of libproductname.
*
* @internal
* @author PRODUCTNAME
*/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PRODUCTNAME_H
#define __PRODUCTNAME_H

#include <stdint.h>
#include <stddef.h>

/**
 * \defgroup libveproductinfo productname library
 *
 * VH VE library provides data transfer APIs for user's VH program.
 *
 * Please include "productinfo.h". Please specify "-lveproductinfo" option to gcc
 * to link libveproductinfo.
 */
/*@{*/

int get_ve_product_name(char *, char *, char *, size_t);

#endif

#ifdef __cplusplus
}
#endif
