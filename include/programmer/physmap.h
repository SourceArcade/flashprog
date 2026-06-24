/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2026 Nico Huber <nico.h@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __PROGRAMMER_PHYSMAP_H__
#define __PROGRAMMER_PHYSMAP_H__

#include <stdint.h>

#include "flash.h"		/* for chipaddr, *sigh* */
#include "hwaccess_physmap.h"

struct par_master;
static inline void mmio_chip_writeb(const struct par_master *par, uint8_t val, chipaddr addr)
{
	mmio_writeb(val, (void *)addr);
}
static inline void mmio_chip_writew(const struct par_master *par, uint16_t val, chipaddr addr)
{
	mmio_writew(val, (void *)addr);
}
static inline void mmio_chip_writel(const struct par_master *par, uint32_t val, chipaddr addr)
{
	mmio_writel(val, (void *)addr);
}
static inline uint8_t mmio_chip_readb(const struct par_master *par, const chipaddr addr)
{
	return mmio_readb((void *)addr);
}
static inline uint16_t mmio_chip_readw(const struct par_master *par, const chipaddr addr)
{
	return mmio_readw((void *)addr);
}
static inline uint32_t mmio_chip_readl(const struct par_master *par, const chipaddr addr)
{
	return mmio_readl((void *)addr);
}
static inline void mmio_chip_readn(const struct par_master *par, uint8_t *buf, const chipaddr addr, size_t len)
{
	mmio_readn((void *)addr, buf, len);
}

#endif /* __PROGRAMMER_PHYSMAP_H__ */
