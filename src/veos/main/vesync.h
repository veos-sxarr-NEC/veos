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
/*
 * @file vesync.h
 * @brief Header for VE sync operation functions
 */
#ifndef __VESYNC_H
#define __VESYNC_H

int veos_alloc_pci_bar01_sync_addr(void);
int veos_free_pci_bar01_sync_addr(void);
int veos_commit_rdawr_order(void);
int veos_invalidate_branch_history(int);
int veos_sync_w_bar2(void);
int veos_sync_r_bar01_bar_cr(void);
int veos_sync_r_bar2(void);

#endif
