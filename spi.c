/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2007, 2008, 2009, 2010, 2011 Carl-Daniel Hailfinger
 * Copyright (C) 2008 coresystems GmbH
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

/*
 * Contains the generic SPI framework
 */

#include <strings.h>
#include <string.h>
#include "flash.h"
#include "flashchips.h"
#include "chipdrivers.h"
#include "programmer.h"
#include "spi.h"

int spi_send_command(const struct flashctx *flash, unsigned int writecnt,
		     unsigned int readcnt, const unsigned char *writearr,
		     unsigned char *readarr)
{
	return flash->mst->spi.command(flash, writecnt, readcnt, writearr,
				       readarr);
}

int spi_send_multicommand(const struct flashctx *flash, struct spi_command *cmds)
{
	return flash->mst->spi.multicommand(flash, cmds);
}

int default_spi_send_command(const struct flashctx *flash, unsigned int writecnt,
			     unsigned int readcnt,
			     const unsigned char *writearr,
			     unsigned char *readarr)
{
	struct spi_command cmd[] = {
	{
		.writecnt = writecnt,
		.readcnt = readcnt,
		.writearr = writearr,
		.readarr = readarr,
	}, {
		.writecnt = 0,
		.writearr = NULL,
		.readcnt = 0,
		.readarr = NULL,
	}};

	return spi_send_multicommand(flash, cmd);
}

int default_spi_send_multicommand(const struct flashctx *flash,
				  struct spi_command *cmds)
{
	int result = 0;
	for (; (cmds->writecnt || cmds->readcnt) && !result; cmds++) {
		result = spi_send_command(flash, cmds->writecnt, cmds->readcnt,
					  cmds->writearr, cmds->readarr);
	}
	return result;
}

int default_spi_read(struct flashctx *flash, uint8_t *buf, unsigned int start,
		     unsigned int len)
{
	unsigned int max_data = flash->mst->spi.max_data_read;
	if (max_data == MAX_DATA_UNSPECIFIED) {
		msg_perr("%s called, but SPI read chunk size not defined on this hardware.\n"
			 "Please report a bug at flashprog@flashprog.org\n", __func__);
		return 1;
	}
	return spi_read_chunked(flash, buf, start, len, max_data);
}

int default_spi_write_256(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	unsigned int max_data = flash->mst->spi.max_data_write;
	if (max_data == MAX_DATA_UNSPECIFIED) {
		msg_perr("%s called, but SPI write chunk size not defined on this hardware.\n"
			 "Please report a bug at flashprog@flashprog.org\n", __func__);
		return 1;
	}
	return spi_write_chunked(flash, buf, start, len, max_data);
}

int spi_chip_read(struct flashctx *flash, uint8_t *buf, unsigned int start,
		  unsigned int len)
{
	int ret;
	size_t to_read;
	for (; len; len -= to_read, buf += to_read, start += to_read) {
		/* Do not cross 16MiB boundaries in a single transfer.
		   This helps with
		   o multi-die 4-byte-addressing chips,
		   o dediprog that has a protocol limit of 32MiB-512B. */
		to_read = min(ALIGN_DOWN(start + 16*MiB, 16*MiB) - start, len);
		ret = flash->mst->spi.read(flash, buf, start, to_read);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Program chip using page (256 bytes) programming.
 * Some SPI masters can't do this, they use single byte programming instead.
 * The redirect to single byte programming is achieved by setting
 * .write_256 = spi_chip_write_1
 */
/* real chunksize is up to 256, logical chunksize is 256 */
int spi_chip_write_256(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	return flash->mst->spi.write_256(flash, buf, start, len);
}

int spi_aai_write(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	if (flash->mst->spi.write_aai)
		return flash->mst->spi.write_aai(flash, buf, start, len);
	return default_spi_write_aai(flash, buf, start, len);
}

bool default_spi_probe_opcode(const struct flashctx *flash, uint8_t opcode)
{
	return true;
}

int register_spi_master(const struct spi_master *mst, void *data)
{
	struct registered_master rmst;

	if (mst->shutdown) {
		if (register_shutdown(mst->shutdown, data)) {
			mst->shutdown(data); /* cleanup */
			return 1;
		}
	}

	if (!mst->write_256 || !mst->read || !mst->command ||
	    !mst->multicommand || !mst->probe_opcode ||
	    ((mst->command == default_spi_send_command) &&
	     (mst->multicommand == default_spi_send_multicommand))) {
		msg_perr("%s called with incomplete master definition.\n"
			 "Please report a bug at flashprog@flashprog.org\n",
			 __func__);
		return ERROR_FLASHPROG_BUG;
	}


	rmst.buses_supported = BUS_SPI;
	rmst.spi = *mst;
	if (data)
		rmst.spi.data = data;
	return register_master(&rmst);
}

/*
 * The following array has erasefn and opcode list pair. The opcode list pair is
 * 0 termintated and must have size one more than the maximum number of opcodes
 * used by any erasefn. Also the opcodes must be in increasing order.
 */
static const struct {
	erasefunc_t *func;
	uint8_t opcode[3];
	bool native_4ba;
} function_opcode_list[] = {
	{spi_block_erase_20, {0x20}, false},
	{spi_block_erase_21, {0x21}, true},
	{spi_block_erase_50, {0x50}, false},
	{spi_block_erase_52, {0x52}, false},
	{spi_block_erase_53, {0x53}, true},
	{spi_block_erase_5c, {0x5c}, true},
	{spi_block_erase_60, {0x60}, false},
	{spi_block_erase_62, {0x62}, false},
	{spi_block_erase_81, {0x81}, false},
	{spi_block_erase_c4, {0xc4}, false},
	{spi_block_erase_c7, {0xc7}, false},
	{spi_block_erase_d7, {0xd7}, false},
	{spi_block_erase_d8, {0xd8}, false},
	{spi_block_erase_db, {0xdb}, false},
	{spi_block_erase_dc, {0xdc}, true},
	//AT45CS1282
	{spi_erase_at45cs_sector, {0x50, 0x7c, 0}, false},
	//AT45DB**
	{spi_erase_at45db_page, {0x81}, false},
	{spi_erase_at45db_block, {0x50}, false},
	{spi_erase_at45db_sector, {0x7c}, false},
	{spi_erase_at45db_chip, {0xc7}, false},
};

const uint8_t *spi_get_opcode_from_erasefn(erasefunc_t *func, bool *native_4ba)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(function_opcode_list); i++) {
		if (function_opcode_list[i].func == func) {
			if (native_4ba)
				*native_4ba = function_opcode_list[i].native_4ba;
			return function_opcode_list[i].opcode;
		}
	}
	msg_cinfo("%s: unknown erase function (0x%p). Please report "
			"this at flashprog@flashprog.org\n", __func__, func);
	return NULL;
}
