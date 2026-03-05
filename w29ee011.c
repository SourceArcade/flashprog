/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2007 Markus Boas <ryven@ryven.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdint.h>

#include "programmer.h"
#include "chipdrivers/memory_bus.h"

/* According to the Winbond W29EE011, W29EE012, W29C010M, W29C011A
 * datasheets this is the only valid probe function for those chips.
 */
struct found_id *probe_w29ee011(const struct bus_probe *probe,
				const struct master_common *mst,
				const struct flashchip *chip)
{
	const struct par_master *const par = (const struct par_master *)mst;
	const chipsize_t chip_size = chip ? chip->total_size * KiB : 128*KiB;
	uint8_t raw[2];

	const chipaddr bios = (chipaddr)programmer_map_flash_data(par, chip_size, "");
	if (bios == (chipaddr)ERROR_PTR)
		return NULL;

	/* Issue JEDEC Product ID Entry command */
	par->chip_writeb(par, 0xAA, bios + 0x5555);
	programmer_delay(10);
	par->chip_writeb(par, 0x55, bios + 0x2AAA);
	programmer_delay(10);
	par->chip_writeb(par, 0x80, bios + 0x5555);
	programmer_delay(10);
	par->chip_writeb(par, 0xAA, bios + 0x5555);
	programmer_delay(10);
	par->chip_writeb(par, 0x55, bios + 0x2AAA);
	programmer_delay(10);
	par->chip_writeb(par, 0x60, bios + 0x5555);
	programmer_delay(10);

	/* Read product ID */
	raw[0] = par->chip_readb(par, bios);
	raw[1] = par->chip_readb(par, bios + 0x01);

	/* Issue JEDEC Product ID Exit command */
	par->chip_writeb(par, 0xAA, bios + 0x5555);
	programmer_delay(10);
	par->chip_writeb(par, 0x55, bios + 0x2AAA);
	programmer_delay(10);
	par->chip_writeb(par, 0xF0, bios + 0x5555);
	programmer_delay(10);

	programmer_unmap_flash_region(par, (void *)bios, chip_size);

	if (flashprog_no_data(raw, sizeof(raw)))
		return NULL;

	msg_cdbg("%s (%uKiB): id1 0x%02x, id2 0x%02x\n",
		 __func__, chip_size / KiB, raw[0], raw[1]);

	struct memory_found_id *const found = alloc_memory_found_id();
	if (!found) {
		msg_cerr("Out of memory!\n");
		return NULL;
	}

	found->generic.info.id.manufacture	= raw[0];
	found->generic.info.id.model		= raw[1];
	found->generic.info.id.type		= ID_W29EE011;
	found->memory_info.chip_size		= chip_size;
	found->memory_info.chip_features	= 0;

	return &found->generic;
}
