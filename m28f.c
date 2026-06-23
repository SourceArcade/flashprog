/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2026 Nico Huber <nico.h@gmx.de>
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

#include "flash.h"
#include "chipdrivers/memory_bus.h"

static int write_m28f_1(struct flashctx *flash, unsigned int pos, uint8_t val)
{
	const chipaddr base = flash->virtual_memory;
	unsigned int tries;

	for (tries = 25; tries > 0; --tries) {
		chip_writeb(flash, 0x40, base);
		chip_writeb(flash, val, base + pos);
		programmer_delay(10);

		chip_writeb(flash, 0xc0, base);
		programmer_delay(6);

		if (chip_readb(flash, base) == val)
			return 0;
	}

	msg_cerr("Write failed at 0x%06x.\n", pos);
	return 1;
}

int write_m28f(struct flashctx *flash, const uint8_t *src, unsigned int pos, unsigned int len)
{
	const chipaddr base = flash->virtual_memory;
	const unsigned int limit = pos + len;
	int ret;

	for (; pos < limit; ++pos, ++src) {
		if (*src == 0xff) /* skip no-op writes */
			continue;

		ret = write_m28f_1(flash, pos, *src);
		if (ret)
			goto return_to_read_mode;
	}

return_to_read_mode:
	chip_writeb(flash, 0x00, base);
	return ret;
}

int erase_m28f(struct flashctx *flash, unsigned int addr, unsigned int blocksize)
{
	const chipaddr base = flash->virtual_memory;
	unsigned int tries, pos;
	int ret;

	/* Programming everything to 0 is required. */
	for (pos = 0; pos < blocksize; ++pos) {
		ret = write_m28f_1(flash, pos, 0x00);
		if (ret)
			goto return_to_read_mode;
	}

	for (pos = 0, tries = 1000; tries > 0; --tries) {
		chip_writeb(flash, 0x20, base);
		chip_writeb(flash, 0x20, base);
		programmer_delay(10*1000);

		for (; pos < blocksize; ++pos) {
			chip_writeb(flash, 0xa0, base + pos);
			programmer_delay(6);

			if (chip_readb(flash, base) != 0xff)
				break;
		}
		if (pos == blocksize)
			goto return_to_read_mode;
	}

	msg_cerr("Erase failed at 0x%06x.\n", pos);
	ret = 1;

return_to_read_mode:
	chip_writeb(flash, 0x00, base);
	return ret;
}
