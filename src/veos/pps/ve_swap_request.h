/*
 * Copyright (C) 2019-2020 NEC Corporation
 * This file is part of the VEOS.
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
 * @file ve_swap_request.h
 * @brief Data structures which is used by libsysve and veswap command
 */

#ifndef __VE_SWAP_REQUEST_H
#define __VE_SWAP_REQUEST_H

#include <sys/types.h>

/**
 * @brief This contains 'cns(Current Non-swappable memory Size)' or
 *        'mns(Maximum Non-swappable memory Size) of process specified by pid'
 */
struct ve_ns_info_proc {
        pid_t pid;
        int64_t ns;
};

#endif
