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
 * @file dma_log.h
 * @brief Header for functions in dma_log.c
 *
 * @author DMA manager
 */
#ifndef VE_VEOS_DMA_LOG_H
#define VE_VEOS_DMA_LOG_H
#include <log4c/category.h>
#include <log4c/priority.h>
#include "veos.h"

void ve_dma_log_init(void);
extern log4c_category_t *cat_os_dma;

#define CAT_OS_DMA cat_os_dma
#define VE_DMA_TRACE(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_TRACE, "%s " fmt, __func__, ## __VA_ARGS__)
#define VE_DMA_INFO(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_INFO, fmt, ## __VA_ARGS__)
#define VE_DMA_ERROR(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_ERROR, fmt, ## __VA_ARGS__)
#define VE_DMA_DEBUG(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_DEBUG, fmt, ## __VA_ARGS__)
#define VE_DMA_CRIT(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_CRIT, fmt, ## __VA_ARGS__)
#define VE_DMA_FATAL(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_FATAL, fmt, ## __VA_ARGS__)
#define VE_DMA_WARN(fmt, ...) \
	VE_LOG(CAT_OS_DMA, LOG4C_PRIORITY_WARN, fmt, ## __VA_ARGS__)

#define VE_DMA_ASSERT(expr) do { if (!(expr)) { \
	VE_DMA_FATAL("assertion [%s] failed.", #expr); \
	veos_abort("DMA manager failed."); \
} } while (0)

#endif
