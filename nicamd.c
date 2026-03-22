/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2024 Nico Huber <nico.h@gmx.de>
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
#include <flash.h>
#include <hwaccess_x86_io.h>
#include <hwaccess_physmap.h>
#include <platform/pci.h>
#include <programmer.h>

#define PCI_VENDOR_ID_AMD	0x1022

static const struct dev_entry nics_amd[] = {
	{PCI_VENDOR_ID_AMD, 0x2000, OK, "AMD", "79C97x [PCnet32 LANCE]"},

	{0},
};

static uint8_t readb(const struct par_master *, chipaddr);
static void writeb(const struct par_master *, uint8_t val, chipaddr);
static int shutdown(void *);

static const struct par_master par_master = {
	.chip_readb	= readb,
	.chip_readw	= fallback_chip_readw,
	.chip_readl	= fallback_chip_readl,
	.chip_readn	= fallback_chip_readn,
	.chip_writeb	= writeb,
	.chip_writew	= fallback_chip_writew,
	.chip_writel	= fallback_chip_writel,
	.chip_writen	= fallback_chip_writen,
	.shutdown	= shutdown,
};

#define ROM_BAR_SIZE	(1*MiB)

/* ----- i/o  space ----- */

#define ANY_IO_RDP	0x10	/* Register Data Port */
#define WORD_IO_RAP	0x12
#define WORD_IO_RESET	0x14
#define WORD_IO_BDP	0x16

#define DWORD_IO_RAP	0x14	/* Register Address Port */
#define DWORD_IO_RESET	0x18
#define DWORD_IO_BDP	0x1c	/* BCR (Bus Configuration Register) Data Port */

/* ----- BCR  space ----- */

#define EXP_BUS_ADDR_LOWER	28
#define EXP_BUS_ADDR_UPPER	29
#define  EBADDRU_FLASH		(1 << 15)
#define EXP_BUS_DATA_PORT	30

/* all BCR registers are 16-bit wide */

static uint16_t bcr_read16(unsigned int io_base, unsigned int reg)
{
	OUTL(reg, io_base + DWORD_IO_RAP);
	return INL(io_base + DWORD_IO_BDP);
}

static void bcr_write16(unsigned int io_base, unsigned int reg, uint16_t val)
{
	OUTL(reg, io_base + DWORD_IO_RAP);
	OUTL(val, io_base + DWORD_IO_BDP);
}

static int init(struct flashprog_programmer *const prog)
{
	size_t max_decode = 0;
	char *const decode_override = extract_programmer_param("max_decode_kb");
	if (decode_override) {
		char *endptr;
		max_decode = strtoul(decode_override, &endptr, 10);
		if (*endptr || max_decode < 16 || max_decode > 1024 || (max_decode & (max_decode - 1)))  {
			msg_perr("Error: Invalid ROM decode override: \"%s\".\n"
				 "Valid values are powers of 2 from 16 through 1024 (KiB).\n",
				 decode_override);
			free(decode_override);
			return 1;
		}
		max_decode *= KiB;
	}
	free(decode_override);

	if (rget_io_perms())
		return 1;

	struct pci_dev *const dev = pcidev_init(nics_amd, PCI_BASE_ADDRESS_0);
	if (!dev)
		return 1;

	uintptr_t io_base = pcidev_readbar(dev, PCI_BASE_ADDRESS_0);
	if (!io_base)
		return 1;

	if (!max_decode) {
		msg_pinfo("Trying to guess addressable size based on read contents and patterns. If this\n"
			  "doesn't work, you can override probing with `-p nicamd:max_decode_kb=<size>`.\n");

		const uint16_t command = pci_read_word(dev, PCI_COMMAND);
		if (!(command & PCI_COMMAND_MEMORY)) {
			msg_perr("Error: PCI memory access is disabled.\n");
			return 1;
		}

		const uint32_t rom_base = pci_read_long(dev, PCI_ROM_ADDRESS);
		if (!rom_base) {
			msg_perr("Error: PCI ROM base is not configured.\n");
			return 1;
		}

		void *physmap(const char *descr, uintptr_t phys_addr, size_t len);
		void *const rom = physmap("ROM BAR", rom_base & ~1u, ROM_BAR_SIZE);
		if (rom == ERROR_PTR)
			return 1;

		if (!(rom_base & 1u))
			pci_write_long(dev, PCI_ROM_ADDRESS, rom_base | 1);

		max_decode = estimate_addressable_size(rom, ROM_BAR_SIZE);

		if (!(rom_base & 1u))
			pci_write_long(dev, PCI_ROM_ADDRESS, rom_base);

		physunmap(rom, ROM_BAR_SIZE);

		if (!max_decode) {
			max_decode = 256*KiB;
			msg_pwarn("Estimating addressable size failed. Using default of %zuKiB.\n",
				  max_decode / KiB);
		}
	}

	/*
	 * Now comes the fun part: This controller knows two i/o modes,
	 * word and dword. Writing with the wrong width is illegal, and
	 * it's impossible to tell the current mode without writing.
	 *
	 * The datasheet was reasoned with and we concluded:
	 *   * A soft reset can be performed with read requests only.
	 *   * Trying a dword-i/o reset in word i/o mode is only a read
	 *     from a reserved register and shouldn't hurt.
	 *   * Trying a word-i/o reset in dword i/o mode is only a read
	 *     with the wrong length.
	 *   * After reset we still don't know the mode  (it is decided
	 *     by EEPROM bits), though we can switch to dword i/o mode,
	 *     blindly.
	 */
	INW(io_base + WORD_IO_RESET);
	INL(io_base + DWORD_IO_RESET);
	OUTL(0, io_base + ANY_IO_RDP); /* supposed to enable dword i/o mode */

	OUTL(18, io_base + DWORD_IO_RAP);
	msg_pdbg2("BBCR: 0x%04x\n", INL(io_base + DWORD_IO_BDP) & 0xffff);
	OUTL(0x98e1, io_base + DWORD_IO_BDP);

	msg_pdbg2("BCR25: 0x%04x\n", bcr_read16(io_base, 25));
	bcr_write16(io_base, 25, 0);

	return register_par_master(&par_master, BUS_PARALLEL, 0, max_decode, (void *)io_base);
}

static uint8_t readb(const struct par_master *par, chipaddr addr)
{
	uintptr_t io_base = (uintptr_t)par->data;

	bcr_write16(io_base, EXP_BUS_ADDR_UPPER, EBADDRU_FLASH | addr >> 16);
	bcr_write16(io_base, EXP_BUS_ADDR_LOWER, addr);
	return bcr_read16(io_base, EXP_BUS_DATA_PORT);
}

static void writeb(const struct par_master *par, uint8_t val, chipaddr addr)
{
	uintptr_t io_base = (uintptr_t)par->data;

	bcr_write16(io_base, EXP_BUS_ADDR_UPPER, EBADDRU_FLASH | addr >> 16);
	bcr_write16(io_base, EXP_BUS_ADDR_LOWER, addr);
	bcr_write16(io_base, EXP_BUS_DATA_PORT, val);
}

static int shutdown(void *data)
{
	uintptr_t io_base = (uintptr_t)data;

	/* Reset just in case. */
	INL(io_base + DWORD_IO_RESET);

	return 0;
}

const struct programmer_entry programmer_nicamd = {
	.name			= "nicamd",
	.type			= PCI,
	.devs.dev		= nics_amd,
	.init			= init,
};
