/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2015 Paul Kocialkowski <contact@paulk.fr>
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

#include <string.h>
#include "flash.h"
#include "programmer.h"
#include "chipdrivers/edi.h"
#include "spi_command.h"
#include "ene.h"
#include "edi.h"

static unsigned int edi_read_buffer_length = EDI_READ_BUFFER_LENGTH_DEFAULT;

static void edi_write_cmd(unsigned char *cmd, unsigned short address, unsigned char data)
{
	cmd[0] = EDI_WRITE; /* EDI write command. */
	cmd[1] = 0x00; /* Address is only 2 bytes. */
	cmd[2] = (address >> 8) & 0xff; /* Address higher byte. */
	cmd[3] = (address >> 0) & 0xff; /* Address lower byte. */
	cmd[4] = data; /* Write data. */
}

static void edi_read_cmd(unsigned char *cmd, unsigned short address)
{
	cmd[0] = EDI_READ; /* EDI read command. */
	cmd[1] = 0x00; /* Address is only 2 bytes. */
	cmd[2] = (address >> 8) & 0xff; /* Address higher byte. */
	cmd[3] = (address >> 0) & 0xff; /* Address lower byte. */
}

static int edi_write(const struct spi_master *spi, unsigned short address, unsigned char data)
{
	unsigned char cmd[5];
	int rc;

	edi_write_cmd(cmd, address, data);

	rc = spi->command(spi, sizeof(cmd), 0, cmd, NULL);
	if (rc)
		return -1;

	return 0;
}

static int edi_read_byte(const struct spi_master *spi, unsigned short address, unsigned char *data)
{
	unsigned char cmd[4];
	unsigned char buffer[edi_read_buffer_length];
	unsigned int index;
	unsigned int i;
	int rc;

	edi_read_cmd(cmd, address);

	rc = spi->command(spi, sizeof(cmd), sizeof(buffer), cmd, buffer);
	if (rc)
		return -1;

	index = 0;

	for (i = 0; i < sizeof(buffer); i++) {
		index = i;

		if (buffer[i] == EDI_NOT_READY)
			continue;

		if (buffer[i] == EDI_READY) {
			if (i == (sizeof(buffer) - 1)) {
				/*
				 * Buffer size was too small for receiving the value.
				 * This is as good as getting only EDI_NOT_READY.
				 */

				buffer[i] = EDI_NOT_READY;
				break;
			}

			*data = buffer[i + 1];
			return 0;
		}
	}

	if (buffer[index] == EDI_NOT_READY)
		return -EDI_NOT_READY;

	return -1;
}

static int edi_read(const struct spi_master *spi, unsigned short address, unsigned char *data)
{
	int rc;

	do {
		rc = edi_read_byte(spi, address, data);
		if (rc == -EDI_NOT_READY) {
			/*
			 * Buffer size is increased, one step at a time,
			 * to hold more data if we only catch EDI_NOT_READY.
			 * Once CS is deasserted, no more data will be sent by the EC,
			 * so we cannot keep reading afterwards and have to start a new
			 * transaction with a longer buffer, to be safe.
			 */

			if (edi_read_buffer_length < EDI_READ_BUFFER_LENGTH_MAX) {
				msg_pwarn("%s: Retrying read with greater buffer length!\n", __func__);
				edi_read_buffer_length++;
			} else {
				msg_perr("%s: Maximum buffer length reached and data still not ready!\n", __func__);
				return -1;
			}
		} else if (rc < 0) {
			return -1;
		}
	} while (rc == -EDI_NOT_READY);

	return 0;
}

static int edi_disable(const struct spi_master *spi)
{
	unsigned char cmd = EDI_DISABLE;
	int rc;

	rc = spi->command(spi, sizeof(cmd), 0, &cmd, NULL);
	if (rc)
		return -1;

	return 0;
}

static struct found_id *edi_chip_probe(const struct spi_master *spi)
{
	unsigned char hwversion;
	unsigned char ediid;
	int rc;

	rc = edi_read(spi, ENE_EC_HWVERSION, &hwversion);
	if (rc < 0) {
		msg_cdbg("%s: reading hwversion failed\n", __func__);
		return NULL;
	}

	rc = edi_read(spi, ENE_EC_EDIID, &ediid);
	if (rc < 0) {
		msg_cdbg("%s: reading ediid failed\n", __func__);
		return NULL;
	}

	struct found_id *const found = calloc(1, sizeof(*found));
	if (!found) {
		msg_cerr("Out of memory!\n");
		return NULL;
	}

	struct id_info *const id = &found->info.id;

	id->hwversion	= hwversion;
	id->model	= ediid;
	id->type	= ID_EDI;

	msg_cdbg("%s: hwversion 0x%02x, ediid 0x%02x\n", __func__, hwversion, ediid);

	return found;
}

static int edi_spi_enable(const struct spi_master *spi)
{
	unsigned char buffer;
	int rc;

	rc = edi_read(spi, ENE_XBI_EFCFG, &buffer);
	if (rc < 0)
		return -1;

	buffer |= ENE_XBI_EFCFG_CMD_WE;

	rc = edi_write(spi, ENE_XBI_EFCFG, buffer);
	if (rc < 0)
		return -1;

	return 0;
}

static int edi_spi_disable(const struct spi_master *spi)
{
	unsigned char buffer;
	int rc;

	rc = edi_read(spi, ENE_XBI_EFCFG, &buffer);
	if (rc < 0)
		return -1;

	buffer &= ~ENE_XBI_EFCFG_CMD_WE;

	rc = edi_write(spi, ENE_XBI_EFCFG, buffer);
	if (rc < 0)
		return -1;

	return 0;
}

static int edi_spi_busy(const struct spi_master *spi)
{
	unsigned char buffer;
	int rc;

	rc = edi_read(spi, ENE_XBI_EFCFG, &buffer);
	if (rc < 0)
		return -1;

	return !!(buffer & ENE_XBI_EFCFG_BUSY);
}

static int edi_spi_address(const struct spi_master *spi, unsigned int start, unsigned int address)
{
	int rc;

	if ((address == start) || (((address - 1) & 0xff) != (address & 0xff))) {
		rc = edi_write(spi, ENE_XBI_EFA0, ((address & 0xff) >> 0));
		if (rc < 0)
			return -1;
	}

	if ((address == start) || (((address - 1) & 0xff00) != (address & 0xff00))) {
		rc = edi_write(spi, ENE_XBI_EFA1, ((address & 0xff00) >> 8));
		if (rc < 0)
			return -1;
	}

	if ((address == start) || (((address - 1) & 0xff0000) != (address & 0xff0000))) {
		rc = edi_write(spi, ENE_XBI_EFA2, ((address & 0xff0000) >> 16));
		if (rc < 0)
			return -1;
	}

	return 0;
}

static int edi_8051_reset(const struct spi_master *spi)
{
	unsigned char buffer;
	int rc;

	rc = edi_read(spi, ENE_EC_PXCFG, &buffer);
	if (rc < 0)
		return -1;

	buffer |= ENE_EC_PXCFG_8051_RESET;

	rc = edi_write(spi, ENE_EC_PXCFG, buffer);
	if (rc < 0)
		return -1;

	return 0;
}

static int edi_8051_execute(const struct spi_master *spi)
{
	unsigned char buffer;
	int rc;

	rc = edi_read(spi, ENE_EC_PXCFG, &buffer);
	if (rc < 0)
		return -1;

	buffer &= ~ENE_EC_PXCFG_8051_RESET;

	rc = edi_write(spi, ENE_EC_PXCFG, buffer);
	if (rc < 0)
		return -1;

	return 0;
}

int edi_chip_block_erase(struct flashctx *flash, unsigned int page, unsigned int size)
{
	const struct spi_master *const spi = flash->mst.spi;
	unsigned int timeout = 64;
	int rc;

	if (size != flash->chip->page_size) {
		msg_perr("%s: Block erase size is not page size!\n", __func__);
		return -1;
	}

	rc = edi_spi_enable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to enable SPI!\n", __func__);
		return -1;
	}

	rc = edi_spi_address(spi, page, page);
	if (rc < 0)
		return -1;

	rc = edi_write(spi, ENE_XBI_EFCMD, ENE_XBI_EFCMD_ERASE);
	if (rc < 0)
		return -1;

	while (edi_spi_busy(spi) == 1 && timeout) {
		programmer_delay(10);
		timeout--;
	}

	if (!timeout) {
		msg_perr("%s: Timed out waiting for SPI not busy!\n", __func__);
		return -1;
	}

	rc = edi_spi_disable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to disable SPI!\n", __func__);
		return -1;
	}

	return 0;
}

int edi_chip_write(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	const struct spi_master *const spi = flash->mst.spi;
	unsigned int address = start;
	unsigned int pages;
	unsigned int timeout;
	unsigned int i, j;
	int rc;

	if ((start % flash->chip->page_size) != 0) {
		msg_perr("%s: Start address is not page-aligned!\n", __func__);
		return -1;
	}

	if ((len % flash->chip->page_size) != 0) {
		msg_perr("%s: Length is not page-aligned!\n", __func__);
		return -1;
	}

	pages = len / flash->chip->page_size;

	rc = edi_spi_enable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to enable SPI!\n", __func__);
		return -1;
	}

	for (i = 0; i < pages; i++) {
		timeout = 64;

		/* Clear page buffer. */
		rc = edi_write(spi, ENE_XBI_EFCMD, ENE_XBI_EFCMD_HVPL_CLEAR);
		if (rc < 0)
			return -1;

		for (j = 0; j < flash->chip->page_size; j++) {
			rc = edi_spi_address(spi, start, address);
			if (rc < 0)
				return -1;

			rc = edi_write(spi, ENE_XBI_EFDAT, *buf);
			if (rc < 0)
				return -1;

			rc = edi_write(spi, ENE_XBI_EFCMD, ENE_XBI_EFCMD_HVPL_LATCH);
			if (rc < 0)
				return -1;

			buf++;
			address++;
		}

		/* Program page buffer to flash. */
		rc = edi_write(spi, ENE_XBI_EFCMD, ENE_XBI_EFCMD_PROGRAM);
		if (rc < 0)
			return -1;

		while (edi_spi_busy(spi) == 1 && timeout) {
			programmer_delay(10);
			timeout--;
		}

		if (!timeout) {
			msg_perr("%s: Timed out waiting for SPI not busy!\n", __func__);
			return -1;
		}

		flashprog_progress_add(flash, flash->chip->page_size);
	}

	rc = edi_spi_disable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to disable SPI!\n", __func__);
		return -1;
	}

	return 0;
}

int edi_chip_read(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	const struct spi_master *const spi = flash->mst.spi;
	unsigned int address = start;
	unsigned int i;
	unsigned int timeout;
	int rc;

	rc = edi_spi_enable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to enable SPI!\n", __func__);
		return -1;
	}

	/*
	 * EDI brings such a drastic overhead that there is about no need to
	 * have any delay in between calls. The EDI protocol will handle wait
	 * I/O times on its own anyway.
	 */

	for (i = 0; i < len; i++) {
		timeout = 64;

		rc = edi_spi_address(spi, start, address);
		if (rc < 0)
			return -1;

		rc = edi_write(spi, ENE_XBI_EFCMD, ENE_XBI_EFCMD_READ);
		if (rc < 0)
			return -1;

		do {
			rc = edi_read(spi, ENE_XBI_EFDAT, buf);
			if (rc == 0)
				break;

			/* Just in case. */
			while (edi_spi_busy(spi) == 1 && timeout) {
				programmer_delay(10);
				timeout--;
			}

			if (!timeout) {
				msg_perr("%s: Timed out waiting for SPI not busy!\n", __func__);
				return -1;
			}
		} while (1);

		buf++;
		address++;
		flashprog_progress_add(flash, 1);
	}

	rc = edi_spi_disable(spi);
	if (rc < 0) {
		msg_perr("%s: Unable to disable SPI!\n", __func__);
		return -1;
	}

	return 0;
}

void edi_finish(struct flashctx *flash)
{
	const struct spi_master *const spi = flash->mst.spi;

	if (edi_8051_execute(spi) < 0)
		msg_perr("%s: Unable to execute 8051!\n", __func__);

	if (edi_disable(spi) < 0)
		msg_perr("%s: Unable to disable EDI!\n", __func__);
}

struct found_id *probe_edi(const struct bus_probe *probe,
			   const struct master_common *mst,
			   const struct flashchip *chip)
{
	const struct spi_master *const spi = (const struct spi_master *)mst;
	unsigned char hwversion;

	/*
	 * ENE chips enable EDI by detecting a clock frequency between 1 MHz and
	 * 8 MHz. In many cases, the chip won't be able to both detect the clock
	 * signal and serve the associated request at the same time.
	 *
	 * Thus, a dummy read has to be added to ensure that EDI is enabled and
	 * operational starting from the next request. This dummy read below
	 * draws the chip's attention and as result the chip enables its EDI.
	 */
	edi_read(spi, ENE_EC_HWVERSION, &hwversion);

	return edi_chip_probe(spi);
}

int edi_prepare(struct flashctx *flash)
{
	int rc;

	rc = edi_8051_reset(flash->mst.spi);
	if (rc < 0) {
		msg_perr("%s: Unable to reset 8051!\n", __func__);
		return rc;
	}

	return 0;
}
