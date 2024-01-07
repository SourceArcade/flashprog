/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009, 2010 Carl-Daniel Hailfinger
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "flash.h"
#include "programmer.h"
#include "spi.h"
#include "spi_command.h"
#include "bitbang_spi.h"

struct bitbang_spi_master_data {
	const struct bitbang_spi_master *mst;
	void *spi_data;
};

/* Note that CS# is active low, so val=0 means the chip is active. */
static void bitbang_spi_set_cs(const struct bitbang_spi_master * const master, int val, void *spi_data)
{
	master->set_cs(val, spi_data);
}

static void bitbang_spi_set_sck(const struct bitbang_spi_master * const master, int val, void *spi_data)
{
	master->set_sck(val, spi_data);
}

static void bitbang_spi_request_bus(const struct bitbang_spi_master * const master, void *spi_data)
{
	if (master->request_bus)
		master->request_bus(spi_data);
}

static void bitbang_spi_release_bus(const struct bitbang_spi_master * const master, void *spi_data)
{
	if (master->release_bus)
		master->release_bus(spi_data);
}

static void bitbang_spi_set_sck_set_mosi(const struct bitbang_spi_master * const master, int sck, int mosi,
					void *spi_data)
{
	if (master->set_sck_set_mosi) {
		master->set_sck_set_mosi(sck, mosi, spi_data);
		return;
	}

	master->set_sck(sck, spi_data);
	master->set_mosi(mosi, spi_data);
}

static int bitbang_spi_set_sck_get_miso(const struct bitbang_spi_master * const master, int sck,
					void *spi_data)
{
	if (master->set_sck_get_miso)
		return master->set_sck_get_miso(sck, spi_data);

	master->set_sck(sck, spi_data);
	return master->get_miso(spi_data);
}

static void bitbang_spi_idle_io(const struct bitbang_spi_master_data *bbs)
{
	if (bbs->mst->set_idle_io)
		bbs->mst->set_idle_io(bbs->spi_data);
}

static void bitbang_spi_run_clock(const struct bitbang_spi_master_data *bbs, unsigned int cycles)
{
	for (; cycles > 0; --cycles) {
		bbs->mst->set_sck(0, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		bbs->mst->set_sck(1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}
}

static int bitbang_spi_send_command(const struct flashctx *flash,
				    unsigned int writecnt, unsigned int readcnt,
				    const unsigned char *writearr,
				    unsigned char *readarr);
static int bitbang_spi_send_multicommand(const struct flashctx *, struct spi_command *);
static int bitbang_spi_shutdown(void *data);

static const struct spi_master spi_master_bitbang = {
	.features	= SPI_MASTER_4BA,
	.max_data_read	= MAX_DATA_READ_UNLIMITED,
	.max_data_write	= MAX_DATA_WRITE_UNLIMITED,
	.command	= bitbang_spi_send_command,
	.multicommand	= bitbang_spi_send_multicommand,
	.read		= default_spi_read,
	.write_256	= default_spi_write_256,
	.shutdown	= bitbang_spi_shutdown,
	.probe_opcode	= default_spi_probe_opcode,
};

static int bitbang_spi_shutdown(void *data)
{
	/* FIXME: Run bitbang_spi_release_bus here or per command? */
	free(data);
	return 0;
}

int register_spi_bitbang_master(const struct bitbang_spi_master *master, void *spi_data)
{
	struct spi_master mst = spi_master_bitbang;
	/* If someone forgot to initialize a bitbang function, we catch it here. */
	if (!master || !master->set_cs ||
	    !master->set_sck || !master->set_mosi || !master->get_miso ||
	    (master->request_bus && !master->release_bus) ||
	    (!master->request_bus && master->release_bus) ||
	    (master->set_sck_set_dual_io && !master->set_sck_get_dual_io) ||
	    (!master->set_sck_set_dual_io && master->set_sck_get_dual_io) ||
	    (master->set_sck_set_quad_io && !master->set_sck_get_quad_io) ||
	    (!master->set_sck_set_quad_io && master->set_sck_get_quad_io) ||
	    ((master->set_sck_set_dual_io || master->set_sck_set_quad_io) &&
	     !master->set_idle_io)) {
		msg_perr("Incomplete SPI bitbang master setting!\n"
			 "Please report a bug at flashprog@flashprog.org\n");
		return ERROR_FLASHPROG_BUG;
	}

	if (master->set_sck_set_dual_io)
		mst.features |= SPI_MASTER_DUAL;
	if (master->set_sck_set_quad_io)
		mst.features |= SPI_MASTER_QUAD | SPI_MASTER_QPI;

	struct bitbang_spi_master_data *data = calloc(1, sizeof(struct bitbang_spi_master_data));
	if (!data) {
		msg_perr("Out of memory!\n");
		return ERROR_OOM;
	}

	data->mst = master;
	data->spi_data = spi_data;
	register_spi_master(&mst, 0, data);

	/* Only mess with the bus if we're sure nobody else uses it. */
	bitbang_spi_request_bus(master, spi_data);
	bitbang_spi_idle_io(data);
	bitbang_spi_set_cs(master, 1, spi_data);
	bitbang_spi_set_sck_set_mosi(master, 0, 0, spi_data);
	/* FIXME: Release SPI bus here and request it again for each command or
	 * don't release it now and only release it on programmer shutdown?
	 */
	bitbang_spi_release_bus(master, spi_data);
	return 0;
}

static uint8_t bitbang_spi_read_byte(const struct bitbang_spi_master *master, void *spi_data)
{
	uint8_t ret = 0;
	int i;

	for (i = 7; i >= 0; i--) {
		if (i == 0)
			bitbang_spi_set_sck_set_mosi(master, 0, 0, spi_data);
		else
			bitbang_spi_set_sck(master, 0, spi_data);
		programmer_delay(master->half_period);
		ret <<= 1;
		ret |= bitbang_spi_set_sck_get_miso(master, 1, spi_data);
		programmer_delay(master->half_period);
	}
	return ret;
}

static uint8_t bitbang_spi_read_dual(const struct bitbang_spi_master_data *const bbs)
{
	uint8_t ret = 0;
	int i;

	for (i = 6; i >= 0; i -= 2) {
		bbs->mst->set_sck(0, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		ret <<= 2;
		ret |= bbs->mst->set_sck_get_dual_io(1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}
	return ret;
}

static uint8_t bitbang_spi_read_quad(const struct bitbang_spi_master_data *const bbs)
{
	uint8_t ret = 0;
	int i;

	for (i = 4; i >= 0; i -= 4) {
		bbs->mst->set_sck(0, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		ret <<= 4;
		ret |= bbs->mst->set_sck_get_quad_io(1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}
	return ret;
}

static void bitbang_spi_write_byte(const struct bitbang_spi_master *master, uint8_t val, void *spi_data)
{
	int i;

	for (i = 7; i >= 0; i--) {
		bitbang_spi_set_sck_set_mosi(master, 0, (val >> i) & 1, spi_data);
		programmer_delay(master->half_period);
		bitbang_spi_set_sck(master, 1, spi_data);
		programmer_delay(master->half_period);
	}
}

static void bitbang_spi_write_dual(const struct bitbang_spi_master_data *bbs, uint8_t val)
{
	int i;

	for (i = 6; i >= 0; i -= 2) {
		bbs->mst->set_sck_set_dual_io(0, (val >> i) & 3, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		bbs->mst->set_sck(1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}
}

static void bitbang_spi_write_quad(const struct bitbang_spi_master_data *bbs, uint8_t val)
{
	int i;

	for (i = 4; i >= 0; i -= 4) {
		bbs->mst->set_sck_set_quad_io(0, (val >> i) & 0xf, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		bbs->mst->set_sck(1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}
}

static int bitbang_spi_send_command(const struct flashctx *flash,
				    unsigned int writecnt, unsigned int readcnt,
				    const unsigned char *writearr,
				    unsigned char *readarr)
{
	unsigned int i;
	const struct bitbang_spi_master_data *data = flash->mst.spi->data;
	const struct bitbang_spi_master *master = data->mst;

	/* FIXME: Run bitbang_spi_request_bus here or in programmer init?
	 * Requesting and releasing the SPI bus is handled in here to allow the
	 * programmer to use its own SPI engine for native accesses.
	 */
	bitbang_spi_request_bus(master, data->spi_data);
	bitbang_spi_set_cs(master, 0, data->spi_data);
	for (i = 0; i < writecnt; i++)
		bitbang_spi_write_byte(master, writearr[i], data->spi_data);
	for (i = 0; i < readcnt; i++)
		readarr[i] = bitbang_spi_read_byte(master, data->spi_data);

	bitbang_spi_set_sck(master, 0, data->spi_data);
	programmer_delay(master->half_period);
	bitbang_spi_set_cs(master, 1, data->spi_data);
	programmer_delay(master->half_period);
	/* FIXME: Run bitbang_spi_release_bus here or in programmer init? */
	bitbang_spi_release_bus(master, data->spi_data);

	return 0;
}

static int bitbang_spi_send_multicommand(const struct flashctx *flash, struct spi_command *cmds)
{
	const struct bitbang_spi_master_data *const bbs = flash->mst.spi->data;
	int ret = 0;

	bitbang_spi_request_bus(bbs->mst, bbs->spi_data);

	for (; !spi_is_empty(cmds); ++cmds) {
		size_t write_single = 0, write_dual = 0, write_quad = 0;
		size_t read_single = 0, read_dual = 0, read_quad = 0;
		unsigned int high_z_cycles;

		switch (cmds->io_mode) {
		case SINGLE_IO_1_1_1:
			write_single = cmds->opcode_len + cmds->address_len + cmds->write_len;
			high_z_cycles = 8 * cmds->high_z_len;
			read_single = cmds->read_len;
			break;
		case DUAL_OUT_1_1_2:
			write_single = cmds->opcode_len + cmds->address_len + cmds->write_len;
			high_z_cycles = 4 * cmds->high_z_len;
			read_dual = cmds->read_len;
			break;
		case DUAL_IO_1_2_2:
			write_single = cmds->opcode_len;
			write_dual = cmds->address_len + cmds->write_len;
			high_z_cycles = 4 * cmds->high_z_len;
			read_dual = cmds->read_len;
			break;
		case QUAD_OUT_1_1_4:
			write_single = cmds->opcode_len + cmds->address_len + cmds->write_len;
			high_z_cycles = 2 * cmds->high_z_len;
			read_quad = cmds->read_len;
			break;
		case QUAD_IO_1_4_4:
			write_single = cmds->opcode_len;
			write_quad = cmds->address_len + cmds->write_len;
			high_z_cycles = 2 * cmds->high_z_len;
			read_quad = cmds->read_len;
			break;
		case QPI_4_4_4:
			write_quad = cmds->opcode_len + cmds->address_len + cmds->write_len;
			high_z_cycles = 2 * cmds->high_z_len;
			read_quad = cmds->read_len;
			break;
		default:
			return SPI_FLASHPROG_BUG;
		}

		bitbang_spi_set_cs(bbs->mst, 0, bbs->spi_data);

		const unsigned char *out = cmds->writearr;
		for (; write_single > 0; --write_single, ++out)
			bitbang_spi_write_byte(bbs->mst, *out, bbs->spi_data);
		for (; write_dual > 0; --write_dual, ++out)
			bitbang_spi_write_dual(bbs, *out);
		for (; write_quad > 0; --write_quad, ++out)
			bitbang_spi_write_quad(bbs, *out);

		if (high_z_cycles || read_dual || read_quad) {
			bitbang_spi_idle_io(bbs);
			bitbang_spi_run_clock(bbs, high_z_cycles);
		}

		unsigned char *in = cmds->readarr;
		for (; read_quad > 0; --read_quad, ++in)
			*in = bitbang_spi_read_quad(bbs);
		for (; read_dual > 0; --read_dual, ++in)
			*in = bitbang_spi_read_dual(bbs);
		for (; read_single > 0; --read_single, ++in)
			*in = bitbang_spi_read_byte(bbs->mst, bbs->spi_data);

		bitbang_spi_set_sck(bbs->mst, 0, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
		bitbang_spi_set_cs(bbs->mst, 1, bbs->spi_data);
		programmer_delay(bbs->mst->half_period);
	}

	bitbang_spi_release_bus(bbs->mst, bbs->spi_data);

	return ret;
}
