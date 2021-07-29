/*
 * Copyright (C) 2020-2021 NEC Corporation
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
* @file  vhve.h
* @brief header file of libvhve.
*
* @internal
* @author VHVE
*/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __VHVE_H
#define __VHVE_H

#include <stdint.h>
#include <stddef.h>

/**
 * \defgroup libvhve VH VE library
 *
 * VH VE library provides data transfer APIs for user's VH program.
 *
 * Please include "vhve.h". Please specify "-lvhve" option to gcc
 * to link libvhve.
 */
/*@{*/

#define VHVE_DMA_OPT_SYNC 0x0000000000000001 /*!<  post DMA request with SYNC bit*/
#define VHVE_DMA_OPT_RO   0x0000000000000002 /*!< post DMA request with RO bit */
#define VHVE_DMA_OPT_IDO  0x0000000000000004 /*!< post DMA request with IDO bit */

uint64_t vhve_create_veos_handle(int);
void vhve_release_veos_handle(uint64_t);
int vhve_dma_read_vemem(uint64_t, int, uint64_t, void *, size_t, uint64_t);
int vhve_dma_write_vemem(uint64_t, int, uint64_t, void *, size_t, uint64_t);
uint64_t vhve_dma_aread_vemem(uint64_t, int, uint64_t, void *, size_t, uint64_t);
uint64_t vhve_dma_awrite_vemem(uint64_t, int, uint64_t, void *, size_t, uint64_t);
int vhve_dma_wait(uint64_t, uint64_t);
int vhve_dma_query(uint64_t, uint64_t);

#endif

#ifdef __cplusplus
}
#endif
