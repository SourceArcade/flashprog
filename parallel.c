/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2000 Silicon Integrated System Corporation
 * Copyright (C) 2004 Tyan Corp <yhlu@tyan.com>
 * Copyright (C) 2005-2008 coresystems GmbH
 * Copyright (C) 2008,2009 Carl-Daniel Hailfinger
 * Copyright (C) 2016 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
 * Copyright (C) 2009,2010,2011 Carl-Daniel Hailfinger
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

#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "programmer.h"
#include "chipdrivers/probing.h"
#include "chipdrivers/memory_bus.h"

void chip_writeb(const struct flashctx *flash, uint8_t val, chipaddr addr)
{
	flash->mst.par->chip_writeb(flash->mst.par, val, addr);
}

void chip_writew(const struct flashctx *flash, uint16_t val, chipaddr addr)
{
	flash->mst.par->chip_writew(flash->mst.par, val, addr);
}

void chip_writel(const struct flashctx *flash, uint32_t val, chipaddr addr)
{
	flash->mst.par->chip_writel(flash->mst.par, val, addr);
}

void chip_writen(const struct flashctx *flash, const uint8_t *buf, chipaddr addr, size_t len)
{
	flash->mst.par->chip_writen(flash->mst.par, buf, addr, len);
}

uint8_t chip_readb(const struct flashctx *flash, const chipaddr addr)
{
	return flash->mst.par->chip_readb(flash->mst.par, addr);
}

uint16_t chip_readw(const struct flashctx *flash, const chipaddr addr)
{
	return flash->mst.par->chip_readw(flash->mst.par, addr);
}

uint32_t chip_readl(const struct flashctx *flash, const chipaddr addr)
{
	return flash->mst.par->chip_readl(flash->mst.par, addr);
}

void chip_readn(const struct flashctx *flash, uint8_t *buf, chipaddr addr,
		size_t len)
{
	flash->mst.par->chip_readn(flash->mst.par, buf, addr, len);
}

struct memory_found_id *alloc_memory_found_id(void)
{
	struct memory_found_id *const found = calloc(1, sizeof(*found));
	if (found)
		found->generic.info.ext = &found->memory_info;
	return found;
}

static const struct bus_probe memory_probes[] = {
    /* prio. type		function		function argument */
};

static bool memory_probe_match(const struct flashchip *chip, const struct id_info_ext *found)
{
	const struct memory_chip_info *const probe_info = found->ext;

	return	(memcmp(&found->id, &chip->id, sizeof(chip->id)) == 0) &&
		(probe_info->chip_size == chip->total_size * KiB) &&
		(probe_info->chip_features == (probe_info->chip_features & chip->feature_bits));
}

int register_par_master(const struct par_master *mst, const enum chipbustype buses,
			const uintptr_t rom_base, const size_t max_rom_decode, void *data)
{
	struct registered_master rmst = { 0 };

	if (mst->shutdown) {
		if (register_shutdown(mst->shutdown, data)) {
			mst->shutdown(data); /* cleanup */
			return 1;
		}
	}

	if (!mst->chip_writeb || !mst->chip_writew || !mst->chip_writel ||
	    !mst->chip_writen || !mst->chip_readb || !mst->chip_readw ||
	    !mst->chip_readl || !mst->chip_readn) {
		msg_perr("%s called with incomplete master definition.\n"
			 "Please report a bug at flashprog@flashprog.org\n",
			 __func__);
		return ERROR_FLASHPROG_BUG;
	}

	rmst.buses_supported = buses;
	rmst.probing.probe_count = ARRAY_SIZE(memory_probes);
	rmst.probing.probes = memory_probes;
	rmst.probing.match = memory_probe_match;
	rmst.par = *mst;

	rmst.par.rom_base = rom_base;
	if (data)
		rmst.par.data = data;

	if (max_rom_decode)
		rmst.common.max_rom_decode = max_rom_decode;
	else
		rmst.common.max_rom_decode = DEFAULT_MAX_DECODE_PARALLEL;

	return register_master(&rmst);
}
