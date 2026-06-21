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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "programmer.h"
#include "platform/pci.h"
#include "hwaccess_physmap.h"
#include "programmer/physmap.h"

#define PCI_VENDOR_ID_MATROX	0x102b

static const struct dev_entry gfx_matrox[] = {
	{PCI_VENDOR_ID_MATROX, 0x051b, OK, "Matrox Electronics Systems Ltd.", "MGA 2164W [Millennium II]" },

	{0},
};

static const struct par_master par_master_gfxmatrox = {
	.chip_readb	= mmio_chip_readb,
	.chip_readw	= mmio_chip_readw,
	.chip_readl	= mmio_chip_readl,
	.chip_readn	= mmio_chip_readn,
	.chip_writeb	= mmio_chip_writeb,
	.chip_writew	= mmio_chip_writew,
	.chip_writel	= mmio_chip_writel,
	.chip_writen	= fallback_chip_writen,
	.map_flash	= physmap,
	.unmap_flash	= physunmap,
};

static int gfxmatrox_init(struct flashprog_programmer *const prog)
{
	bool borrow_mmio_bar = false;
	char *const bar_param = extract_programmer_param("bar");
	if (bar_param) {
		if (strcmp(bar_param, "no_gfx_driver_running") != 0) {
			msg_perr("Error: Unknown argument for `bar' parameter: \"%s\".\n", bar_param);
			free(bar_param);
			return 1;
		}
		borrow_mmio_bar = true;
	}
	free(bar_param);

	struct pci_dev *const matrox = pcidev_init(gfx_matrox, PCI_BASE_ADDRESS_1);
	if (!matrox)
		return 1;

	const uint16_t command = pci_read_word(matrox, PCI_COMMAND);
	if (!(command & PCI_COMMAND_MEMORY)) {
		msg_perr("Error: PCI memory access is disabled.\n");
		return 1;
	}

	/* Enable flash + writes. */
	const uint32_t option = pci_read_long(matrox, 0x40);
	rpci_write_long(matrox, 0x40, option | (1 << 30) | (1 << 20));

	uint32_t rom_base = pci_read_long(matrox, PCI_ROM_ADDRESS);
	if (!rom_base) {
		if (!borrow_mmio_bar) {
			msg_perr("Error: PCI ROM base is not configured.\n");
			msg_perr("We can try to work around this if no graphics driver is running. When no driver\n");
			msg_perr("is running, confirm this by supplying `-p gfxmatrox:bar=no_gfx_driver_running'.\n");
			return 1;
		}
		/* If the ROM BAR isn't enabled, borrow the MMIO BAR. */
		rom_base = pcidev_readbar(matrox, PCI_BASE_ADDRESS_1);
	}
	rpci_write_long(matrox, PCI_ROM_ADDRESS, rom_base | 1);

	return register_par_master(&par_master_gfxmatrox, BUS_PARALLEL, rom_base & ~1u, 64*KiB, NULL);
}

const struct programmer_entry programmer_gfxmatrox = {
	.name			= "gfxmatrox",
	.type			= PCI,
	.devs.dev		= gfx_matrox,
	.init			= gfxmatrox_init,
};
