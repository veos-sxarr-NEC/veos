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
 * @file veos_vemm_log.h
 * @brief private header for logging in VEMM agent in VE OS
 * DO NOT include from sources out of vemm.
 */
#ifndef VE_VEOS_VEMM_LOG_H
#define VE_VEOS_VEMM_LOG_H
#include <velayout.h>

#define VEMM_AGENT_LOG_CAT "veos.os_module.vemm.ops"
#define VEMM_AGENT_LOG(prio, ...) VE_LOG(cat_vemm_agent, prio, __VA_ARGS__)
#define VEMM_AGENT_ERROR(...) VEMM_AGENT_LOG(LOG4C_PRIORITY_ERROR, __VA_ARGS__)
#define VEMM_AGENT_DEBUG(...) VEMM_AGENT_LOG(LOG4C_PRIORITY_DEBUG, __VA_ARGS__)
#define VEMM_AGENT_TRACE(...) VEMM_AGENT_LOG(LOG4C_PRIORITY_TRACE, __VA_ARGS__)
extern log4c_category_t *cat_vemm_agent;

#endif
