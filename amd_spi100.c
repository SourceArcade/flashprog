/*
 * This file is part of the flashrom project.
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
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "hwaccess_physmap.h"
#include "programmer.h"
#include "spi.h"

#define SPI100_FIFO_SIZE	71

struct spi100 {
	uint8_t *spibar;
	unsigned int altspeed;
};

static void spi100_write8(const struct spi100 *spi100, unsigned int reg, uint8_t val)
{
	mmio_writeb(val, spi100->spibar + reg);
}

static void spi100_write16(const struct spi100 *spi100, unsigned int reg, uint16_t val)
{
	mmio_writew(val, spi100->spibar + reg);
}

static void spi100_writen(const struct spi100 *spi100, unsigned int reg, const uint8_t *data, size_t len)
{
	for (; len > 0; --len, ++reg, ++data)
		mmio_writeb(*data, spi100->spibar + reg);
}

static uint8_t spi100_read8(const struct spi100 *spi100, unsigned int reg)
{
	return mmio_readb(spi100->spibar + reg);
}

static uint16_t spi100_read16(const struct spi100 *spi100, unsigned int reg)
{
	return mmio_readw(spi100->spibar + reg);
}

static uint32_t spi100_read32(const struct spi100 *spi100, unsigned int reg)
{
	return mmio_readl(spi100->spibar + reg);
}

static void spi100_readn(const struct spi100 *spi100, unsigned int reg, uint8_t *data, size_t len)
{
	mmio_readn(spi100->spibar + reg, data, len);
}

static int spi100_check_readwritecnt(const unsigned int writecnt, const unsigned int readcnt)
{
	if (writecnt < 1) {
		msg_perr("ERROR: SPI controller needs to send at least 1 byte.\n");
		return SPI_INVALID_LENGTH;
	}

	if (writecnt - 1 > SPI100_FIFO_SIZE) {
		msg_perr("ERROR: SPI controller can not send %u bytes, it is limited to %u bytes.\n",
			 writecnt, SPI100_FIFO_SIZE + 1);
		return SPI_INVALID_LENGTH;
	}

	const unsigned int maxreadcnt = SPI100_FIFO_SIZE - (writecnt - 1);
	if (readcnt > maxreadcnt) {
		msg_perr("ERROR: SPI controller can not receive %u bytes for this command,\n"
			 "it is limited to %u bytes write+read count.\n",
			 readcnt, SPI100_FIFO_SIZE + 1);
		return SPI_INVALID_LENGTH;
	}
	return 0;
}

static int spi100_send_command(const struct flashctx *const flash,
			       const unsigned int writecnt, const unsigned int readcnt,
			       const unsigned char *const writearr, unsigned char *const readarr)
{
	const struct spi100 *const spi100 = flash->mst->spi.data;

	int ret = spi100_check_readwritecnt(writecnt, readcnt);
	if (ret)
		return ret;

	spi100_write8(spi100, 0x45, writearr[0]);	/* First "command" byte is sent separately. */
	spi100_write8(spi100, 0x48, writecnt - 1);
	spi100_write8(spi100, 0x4b, readcnt);
	if (writecnt > 1)
		spi100_writen(spi100, 0x80, &writearr[1], writecnt - 1);

	/* Trigger command */
	spi100_write8(spi100, 0x47, BIT(7));

	/* Wait for completion */
	int timeout_us = 10*1000*1000;
	uint32_t spistatus;
	while (((spistatus = spi100_read32(spi100, 0x4c)) & BIT(31)) && timeout_us--)
		programmer_delay(1);
	if (spistatus & BIT(31)) {
		msg_perr("ERROR: SPI transfer timed out (0x%08x)!\n", spistatus);
		return SPI_PROGRAMMER_ERROR;
	}
	msg_pspew("%s: spistatus: 0x%08x\n", __func__, spistatus);

	if (readcnt)
		spi100_readn(spi100, 0x80 + writecnt - 1, readarr, readcnt);

	return 0;
}

static int spi100_shutdown(void *data)
{
	struct spi100 *const spi100 = data;

	const uint16_t speed_cfg = spi100_read16(spi100, 0x22);
	spi100_write16(spi100, 0x22, (speed_cfg & ~0xf0) | spi100->altspeed << 4);

	free(spi100);
	return 0;
}

static struct spi_master spi100_master = {
	.max_data_read	= SPI100_FIFO_SIZE - 4, /* Account for up to 4 address bytes. */
	.max_data_write	= SPI100_FIFO_SIZE - 4,
	.command	= spi100_send_command,
	.multicommand	= default_spi_send_multicommand,
	.read		= default_spi_read,
	.write_256	= default_spi_write_256,
	.probe_opcode	= default_spi_probe_opcode,
	.shutdown	= spi100_shutdown,
};

const char *const spimodes[] = {
	"Normal read (up to 33MHz)",
	"Reserved",
	"Dual IO (1-1-2)",
	"Quad IO (1-1-4)",
	"Dual IO (1-2-2)",
	"Quad IO (1-1-4)",
	"Normal read (up to 66MHz)",
	"Fast Read",
};

const struct {
	unsigned int khz;
	const char *speed;
} spispeeds[] = {
	{  66666, "66.66 MHz" },
	{  33333, "33.33 MHz" },
	{  22222, "22.22 MHz" },
	{  16666, "16.66 MHz" },
	{ 100000, "100 MHz"   },
	{    800, "800 kHz"   },
	{      0, "Reserved"  },
	{      0, "Reserved"  },
};

static void spi100_print(const struct spi100 *const spi100)
{
	const uint32_t spi_cntrl0 = spi100_read32(spi100, 0x00);
	msg_pdbg("(0x%08" PRIx32 ") ",		spi_cntrl0);
	msg_pdbg("SpiArbEnable=%u, ",		spi_cntrl0 >> 19 & 1);
	msg_pdbg("IllegalAccess=%u, ",		spi_cntrl0 >> 21 & 1);
	msg_pdbg("SpiAccessMacRomEn=%u, ",	spi_cntrl0 >> 22 & 1);
	msg_pdbg("SpiHostAccessRomEn=%u,\n",	spi_cntrl0 >> 23 & 1);
	msg_pdbg("              ");
	msg_pdbg("ArbWaitCount=%u, ",		spi_cntrl0 >> 24 & 7);
	msg_pdbg("SpiBridgeDisable=%u, ",	spi_cntrl0 >> 27 & 1);
	msg_pdbg("SpiClkGate=%u,\n",		spi_cntrl0 >> 28 & 1);
	msg_pdbg("              ");
	msg_pdbg("SpiReadMode=%s, ",		spimodes[(spi_cntrl0 >> 28 & 6) | (spi_cntrl0 >> 18 & 1)]);
	msg_pdbg("SpiBusy=%u\n",		spi_cntrl0 >> 31 & 1);

	const uint8_t alt_spi_cs = spi100_read8(spi100, 0x1d);
	msg_pdbg("Using SPI_CS%u\n", alt_spi_cs & 0x3);

	const uint16_t speed_cfg = spi100_read16(spi100, 0x22);
	msg_pdbg("NormSpeed: %s\n", spispeeds[speed_cfg >> 12 & 0xf].speed);
	msg_pdbg("FastSpeed: %s\n", spispeeds[speed_cfg >>  8 & 0xf].speed);
	msg_pdbg("AltSpeed:  %s\n", spispeeds[speed_cfg >>  4 & 0xf].speed);
	msg_pdbg("TpmSpeed:  %s\n", spispeeds[speed_cfg >>  0 & 0xf].speed);
}

static void spi100_set_altspeed(struct spi100 *const spi100)
{
	const uint16_t speed_cfg = spi100_read16(spi100, 0x22);
	const unsigned int normspeed = speed_cfg >> 12 & 0xf;
	spi100->altspeed = speed_cfg >> 4 & 0xf;

	/* Set SPI speed to 33MHz but not higher than `normal read` speed */
	unsigned int altspeed;
	if (spispeeds[normspeed].khz != 0 && spispeeds[normspeed].khz < 33333)
		altspeed = normspeed;
	else
		altspeed = 1;

	if (altspeed != spi100->altspeed) {
		msg_pinfo("Setting SPI speed to %s.\n", spispeeds[altspeed].speed);
		spi100_write16(spi100, 0x22, (speed_cfg & ~0xf0) | altspeed << 4);
	}
}

int amd_spi100_probe(void *const spibar)
{
	struct spi100 *const spi100 = malloc(sizeof(*spi100));
	if (!spi100) {
		msg_perr("Out of memory!\n");
		return ERROR_FATAL;
	}
	spi100->spibar = spibar;

	spi100_print(spi100);

	spi100_set_altspeed(spi100);

	return register_spi_master(&spi100_master, spi100);
}
