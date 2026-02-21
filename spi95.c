/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2019 Konstantin Grudnev
 * Copyright (C) 2019 Nikolay Nikolaev
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Contains SPI chip driver functions related to ST95XXX series (SPI EEPROM)
 */
#include <string.h>
#include <stdlib.h>

#include "chipdrivers/spi.h"
#include "programmer.h"
#include "spi.h"

/* For ST95XXX chips which have RDID */
struct found_id *probe_spi_st95(const struct bus_probe *probe, const struct master_common *mst)
{
	/*
	 * ST_M95_RDID_OUTSIZE depends on size of the flash and
	 * not all ST_M95XXX have RDID.
	 */
	static const unsigned char cmd[ST_M95_RDID_OUTSIZE_MAX] = { ST_M95_RDID };
	const struct spi_master *const spi = (const struct spi_master *)mst;
	const size_t address_len = (uintptr_t)probe->arg;
	unsigned char readarr[ST_M95_RDID_INSIZE];

	if (spi->command(spi, 1 + address_len, sizeof(readarr), cmd, readarr))
		return NULL;
	if (flashprog_no_data(readarr, sizeof(readarr)))
		return NULL;

	struct found_id *const found = calloc(1, sizeof(*found));
	if (!found) {
		msg_cerr("Out of memory!\n");
		return NULL;
	}

	struct id_info *const id = &found->info.id;

	id->manufacture	= readarr[0];
	id->model	= (readarr[1] << 8) | readarr[2];
	id->type	= ID_SPI_ST95;

	msg_cdbg("%s: id1 0x%02x, id2 0x%04x\n", __func__, id->id1, id->id2);

	return found;
}

/* ST95XXX chips don't have erase operation and erase is made as part of write command */
int spi_block_erase_emulation(struct flashctx *flash, unsigned int addr, unsigned int blocklen)
{
	uint8_t *erased_contents = NULL;
	int result = 0;

	erased_contents = (uint8_t *)malloc(blocklen * sizeof(uint8_t));
	if (!erased_contents) {
		msg_cerr("Out of memory!\n");
		return 1;
	}
	memset(erased_contents, ERASED_VALUE(flash), blocklen * sizeof(uint8_t));
	result = spi_write_chunked(flash, erased_contents, 0, blocklen, flash->chip->page_size);
	free(erased_contents);
	return result;
}
