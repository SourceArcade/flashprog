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

#include "programmer.h"
#include "platform/pci.h"
#include "hwaccess_physmap.h"
#include "programmer/physmap.h"

#define PCI_VENDOR_ID_LSI	0x1000

static const struct dev_entry scsi_lsi[] = {
	{PCI_VENDOR_ID_LSI, 0x000f, OK, "LSI", "53c875" },

	{0},
};

static const struct par_master par_master_scsilsi = {
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

static int scsilsi_init(struct flashprog_programmer *const prog)
{
	struct pci_dev *const lsi = pcidev_init(scsi_lsi, PCI_BASE_ADDRESS_1);
	if (!lsi)
		return 1;

	const uint16_t command = pci_read_word(lsi, PCI_COMMAND);
	if (!(command & PCI_COMMAND_MEMORY)) {
		msg_perr("Error: PCI memory access is disabled.\n");
		return 1;
	}

	const uint32_t rom_base = pci_read_long(lsi, PCI_ROM_ADDRESS);
	if (!rom_base) {
		msg_perr("Error: PCI ROM base is not configured.\n");
		return 1;
	}
	rpci_write_long(lsi, PCI_ROM_ADDRESS, rom_base | 1);

	/* TODO: Use ROM BAR size detection. */

	return register_par_master(&par_master_scsilsi, BUS_PARALLEL, rom_base & ~1u, 1*MiB, NULL);
}

const struct programmer_entry programmer_scsilsi = {
	.name			= "scsilsi",
	.type			= PCI,
	.devs.dev		= scsi_lsi,
	.init			= scsilsi_init,
};
