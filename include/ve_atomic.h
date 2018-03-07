/*
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of the VEOS.
 *
 * The VEOS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The VEOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VEOS; if not, see
 * <http://www.gnu.org/licenses/>.
 */
/**
 * @file ve_atomic.h
 * @brief This file contains functions used in atomic operation
 *
 * @internal
 * @author PSMG
 */
#ifndef _VE_ATOMIC_H
#define _VE_ATOMIC_H

#define VE_ATOMIC_SET(TYPE, var, val) __atomic_store_n((TYPE *)var,\
                (TYPE)val, __ATOMIC_SEQ_CST)
#define VE_ATOMIC_GET(TYPE, var) __atomic_load_n((TYPE *)var, __ATOMIC_SEQ_CST)

static inline void ve_atomic_inc(volatile int *x)
{
        int old = *x;
        while (!__atomic_compare_exchange_n(x, &old, old+1, 0,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
}

static inline void ve_atomic_dec(volatile int *x)
{
        int old = *x;
        while (!__atomic_compare_exchange_n(x, &old, old-1, 0,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
}
#endif
