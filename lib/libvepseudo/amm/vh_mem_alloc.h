/*
 * Copyright (C) 2017-2018 NEC Corporation
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
 * @file vh_mem_alloc.h
 * @brief Header file for "vh_mem_alloc.c"
 *
 * @internal
 * @author AMM
 */
#ifndef __VH_MEM_ALLOC_H
#define __VH_MEM_ALLOC_H

#include <sys/mman.h>
#include <sys/types.h>
#include <stdbool.h>

void *vh_alloc_buf(size_t, bool);
void vh_free_buf(void *);
#endif
