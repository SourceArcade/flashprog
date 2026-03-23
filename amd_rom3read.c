/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2025 Nico Huber <nico.h@gmx.de>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "flash.h"
#include "hwaccess_physmap.h"
#include "programmer.h"

struct spi100 {
	const uint8_t *memory;
	size_t size_override;
};

static uint16_t spi100_read16(const char *spibar, unsigned int reg)
{
	return mmio_readw(spibar + reg);
}

static uint32_t spi100_read32(const char *spibar, unsigned int reg)
{
	return mmio_readl(spibar + reg);
}

static uint64_t spi100_read64(const char *spibar, unsigned int reg)
{
	return (uint64_t)mmio_readl(spibar + reg + 4) << 32 | mmio_readl(spibar + reg);
}

static int spi100_mmap_read(struct flashctx *flash, uint8_t *dst, unsigned int start, unsigned int len)
{
	const struct spi100 *const spi100 = flash->mst.opaque->data;
	mmio_readn_aligned(spi100->memory + start, dst, len, 8);
	return 0;
}

static int rom3read_prepare(struct flashctx *const flash)
{
	const struct spi100 *const spi100 = flash->mst.opaque->data;
	const void *const rom3 = spi100->memory;

	size_t flash_size = spi100->size_override;
	if (!flash_size) {
		/*
		 * Only thing to probe is the size. That's going to be peculiar,
		 * though: As the whole 64MiB rom3 range is decoded, we can only
		 * look for repeating memory contents.
		 */
		msg_pinfo("Trying to probe flash size based on its contents and read patterns. If this\n"
			  "doesn't work, you can override probing with `-p internal:rom_size_mb=<size>`.\n");

		flash_size = estimate_addressable_size(rom3, 64*MiB);
	}

	flash->chip->total_size = flash_size / KiB;
	flash->chip->feature_bits |= FEATURE_NO_ERASE;
	flash->chip->tested = (struct flashprog_test_status)
		{ .probe = OK, .read = OK, .erase = NA, .write = NA, .block_protection = NA };

	return !!flash->chip->total_size;
}

static int rom3read_read(struct flashctx *const flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	/* Use top-aligned decoding, for some reason it's
	   faster after using the bottom end for probing. */
	start += 64*MiB - flashprog_flash_getsize(flash);
	return flashprog_read_chunked(flash, buf, start, len, MAX_DATA_READ_UNLIMITED, spi100_mmap_read);
}

static int rom3read_write(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	msg_perr("Write is not supported with ROM Armor enabled.\n");
	return 1;
}

static int rom3read_erase(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen)
{
	msg_perr("Erase is not supported with ROM Armor enabled.\n");
	return 1;
}

static int rom3read_shutdown(void *spi100)
{
	free(spi100);
	return 0;
}

static const struct opaque_master rom3read_master = {
	.max_data_read	= MAX_DATA_UNSPECIFIED,
	.max_data_write	= MAX_DATA_UNSPECIFIED,
	.prepare	= rom3read_prepare,
	.read		= rom3read_read,
	.write		= rom3read_write,
	.erase		= rom3read_erase,
	.shutdown	= rom3read_shutdown,
};

static bool spi100_check_4ba(const void *const spibar)
{
	const uint16_t rom2_addr_override = spi100_read16(spibar, 0x30);
	const uint32_t addr32_ctrl3 = spi100_read32(spibar, 0x5c);

	/* Most bits are undocumented ("reserved"), so we play safe. */
	if (rom2_addr_override != 0x14c0) {
		msg_perr("ROM2 address override *not* in default configuration.\n");
		return false;
	}

	/* Another override (xor'ed) for the most-significant address bits. */
	if (addr32_ctrl3 & 0xff) {
		msg_perr("SPI ROM page bits set: 0x%02x\n", addr32_ctrl3 & 0xff);
		return false;
	}

	return true;
}

int amd_rom3read_probe(const void *const spibar, const void *const rom2,
		       const void *const rom3, const size_t rom3_len)
{
	if (rom3_len != 64*MiB) {
		msg_perr("Error: Only 64MiB rom range 3 supported.\n");
		return ERROR_FATAL;
	}

	if (!spi100_check_4ba(spibar))
		return ERROR_FATAL;

	size_t size = 0;
	char *const size_override = extract_programmer_param("rom_size_mb");
	if (size_override) {
		char *endptr;
		size = strtoul(size_override, &endptr, 10);
		if (*endptr || size < 1 || size > 64 || (size & (size - 1)))  {
			msg_perr("Error: Invalid ROM size override: \"%s\".\n"
				 "Valid values are powers of 2 from 1 through 64 (MiB).\n",
				 size_override);
			free(size_override);
			return -1;
		}
		size *= MiB;
	}
	free(size_override);

	const uint64_t rom3_base = spi100_read64(spibar, 0x60);
	if (rom3_base != 0xfd00000000) {
		msg_perr("Unexpected value for Rom3 base: 0x%"PRIx64"\n", rom3_base);
		return ERROR_FATAL;
	}

	if (compare_sparse(rom2, rom3 + 48*MiB, 16*MiB)) {
		msg_perr("Rom2 and Rom3 don't seem to map the same memory.\n");
		return ERROR_FATAL;
	}

	struct spi100 *const spi100 = malloc(sizeof(*spi100));
	if (!spi100) {
		msg_perr("Out of memory!\n");
		return ERROR_FATAL;
	}
	spi100->memory = rom3;
	spi100->size_override = size;

	return register_opaque_master(&rom3read_master, spi100);
}
