/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2000 Silicon Integrated System Corporation
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

/*
 * Datasheet:
 *  - Name: Intel 82802AB/82802AC Firmware Hub (FWH)
 *  - URL: http://www.intel.com/design/chipsets/datashts/290658.htm
 *  - PDF: http://download.intel.com/design/chipsets/datashts/29065804.pdf
 *  - Order number: 290658-004
 */

#include <stdbool.h>
#include <stdlib.h>

#include "flash.h"
#include "programmer.h"
#include "chipdrivers/memory_bus.h"

void print_status_82802ab(uint8_t status)
{
	msg_cdbg("%s", status & 0x80 ? "Ready:" : "Busy:");
	msg_cdbg("%s", status & 0x40 ? "BE SUSPEND:" : "BE RUN/FINISH:");
	msg_cdbg("%s", status & 0x20 ? "BE ERROR:" : "BE OK:");
	msg_cdbg("%s", status & 0x10 ? "PROG ERR:" : "PROG OK:");
	msg_cdbg("%s", status & 0x8 ? "VP ERR:" : "VPP OK:");
	msg_cdbg("%s", status & 0x4 ? "PROG SUSPEND:" : "PROG RUN/FINISH:");
	msg_cdbg("%s", status & 0x2 ? "WP|TBL#|WP#,ABORT:" : "UNLOCK:");
}

static struct found_id *probe_82802ab_generic(
		const struct par_master *par,
		chipsize_t chip_size, feature_bits_t chip_features)
{
	const unsigned int addr_shift = chip_features & FEATURE_ADDR_SHIFTED ? 1 : 0;
	uint8_t raw[2], flashcontent1, flashcontent2;

	const chipaddr bios = (chipaddr)programmer_map_flash_data(par, chip_size, "");
	if (bios == (chipaddr)ERROR_PTR)
		return NULL;

	/* Reset to get a clean state */
	par->chip_writeb(par, 0xFF, bios);
	programmer_delay(10);

	/* Enter ID mode */
	par->chip_writeb(par, 0x90, bios);
	programmer_delay(10);

	raw[0] = par->chip_readb(par, bios + (0x00 << addr_shift));
	raw[1] = par->chip_readb(par, bios + (0x01 << addr_shift));

	/* Leave ID mode */
	par->chip_writeb(par, 0xFF, bios);

	programmer_delay(10);

	/*
	 * Read the product ID location again. We should now see normal
	 * flash contents.
	 */
	flashcontent1 = par->chip_readb(par, bios + (0x00 << addr_shift));
	flashcontent2 = par->chip_readb(par, bios + (0x01 << addr_shift));

	programmer_unmap_flash_region(par, (void *)bios, chip_size);

	if (flashprog_no_data(raw, sizeof(raw)))
		return NULL;

	msg_cdbg("%s (%uKiB, features: 0x%02x): id1 0x%02x, id2 0x%02x",
		 __func__, chip_size / KiB, chip_features, raw[0], raw[1]);

	if (!oddparity(raw[0]))
		msg_cdbg(", id1 parity violation");

	if (raw[0] == flashcontent1)
		msg_cdbg(", id1 is normal flash content");
	if (raw[1] == flashcontent2)
		msg_cdbg(", id2 is normal flash content");
	msg_cdbg("\n");

	struct memory_found_id *const found = alloc_memory_found_id();
	if (!found) {
		msg_cerr("Out of memory!\n");
		return NULL;
	}

	found->generic.info.id.manufacture	= raw[0];
	found->generic.info.id.model		= raw[1];
	found->generic.info.id.type		= ID_82802AB;
	found->memory_info.chip_size		= chip_size;
	found->memory_info.chip_features	= chip_features;

	return &found->generic;
}

struct found_id *probe_82802ab(const struct bus_probe *probe,
			       const struct master_common *mst,
			       const struct flashchip *chip)
{
	const struct par_master *const par = (const struct par_master *)mst;
	struct found_id *ids = NULL, **next_ptr = &ids;
	chipsize_t chip_size;

	if (chip)
		return probe_82802ab_generic(par, chip->total_size * KiB, chip->feature_bits);

	for (chip_size = 32*KiB; chip_size <= 2*MiB; chip_size *= 2) {
		*next_ptr = probe_82802ab_generic(par, chip_size, 0);
		if (*next_ptr)
			next_ptr = &(*next_ptr)->next;

		*next_ptr = probe_82802ab_generic(par, chip_size, FEATURE_ADDR_SHIFTED);
		if (*next_ptr)
			next_ptr = &(*next_ptr)->next;
	}

	return ids;
}

/* FIXME: needs timeout */
uint8_t wait_82802ab(struct flashctx *flash)
{
	uint8_t status;
	chipaddr bios = flash->virtual_memory;

	chip_writeb(flash, 0x70, bios);

	while ((chip_readb(flash, bios) & 0x80) == 0)	// it's busy
		;

	status = chip_readb(flash, bios);

	/* Reset to get a clean state */
	chip_writeb(flash, 0xFF, bios);

	return status;
}

int erase_block_82802ab(struct flashctx *flash, unsigned int page,
			unsigned int pagesize)
{
	chipaddr bios = flash->virtual_memory;
	uint8_t status;

	// clear status register
	chip_writeb(flash, 0x50, bios + page);

	// now start it
	chip_writeb(flash, 0x20, bios + page);
	chip_writeb(flash, 0xd0, bios + page);
	programmer_delay(10);

	// now let's see what the register is
	status = wait_82802ab(flash);
	print_status_82802ab(status);

	/* FIXME: Check the status register for errors. */
	return 0;
}

/* chunksize is 1 */
int write_82802ab(struct flashctx *flash, const uint8_t *src, unsigned int start, unsigned int len)
{
	unsigned int i;
	chipaddr dst = flash->virtual_memory + start;

	for (i = 0; i < len; i++) {
		/* transfer data from source to destination */
		chip_writeb(flash, 0x40, dst);
		chip_writeb(flash, *src++, dst++);
		wait_82802ab(flash);
		flashprog_progress_add(flash, 1);
	}

	/* FIXME: Ignore errors for now. */
	return 0;
}

int unlock_28f004s5(struct flashctx *flash)
{
	chipaddr bios = flash->virtual_memory;
	uint8_t mcfg, bcfg;
	bool need_unlock = false, can_unlock = false;
	unsigned int i;

	/* Clear status register */
	chip_writeb(flash, 0x50, bios);

	/* Read identifier codes */
	chip_writeb(flash, 0x90, bios);

	/* Read master lock-bit */
	mcfg = chip_readb(flash, bios + 0x3);
	msg_cdbg("master lock is ");
	if (mcfg) {
		msg_cdbg("locked!\n");
	} else {
		msg_cdbg("unlocked!\n");
		can_unlock = true;
	}

	/* Read block lock-bits */
	for (i = 0; i < flashprog_flash_getsize(flash); i+= (64 * 1024)) {
		bcfg = chip_readb(flash, bios + i + 2); // read block lock config
		msg_cdbg("block lock at %06x is %slocked!\n", i, bcfg ? "" : "un");
		if (bcfg) {
			need_unlock = true;
		}
	}

	/* Reset chip */
	chip_writeb(flash, 0xFF, bios);

	/* Unlock: clear block lock-bits, if needed */
	if (can_unlock && need_unlock) {
		msg_cdbg("Unlock: ");
		chip_writeb(flash, 0x60, bios);
		chip_writeb(flash, 0xD0, bios);
		chip_writeb(flash, 0xFF, bios);
		msg_cdbg("Done!\n");
	}

	/* Error: master locked or a block is locked */
	if (!can_unlock && need_unlock) {
		msg_cerr("At least one block is locked and lockdown is active!\n");
		return -1;
	}

	return 0;
}

int unlock_lh28f008bjt(struct flashctx *flash)
{
	chipaddr bios = flash->virtual_memory;
	uint8_t mcfg, bcfg;
	bool need_unlock = false, can_unlock = false;
	unsigned int i;

	/* Wait if chip is busy */
	wait_82802ab(flash);

	/* Read identifier codes */
	chip_writeb(flash, 0x90, bios);

	/* Read master lock-bit */
	mcfg = chip_readb(flash, bios + 0x3);
	msg_cdbg("master lock is ");
	if (mcfg) {
		msg_cdbg("locked!\n");
	} else {
		msg_cdbg("unlocked!\n");
		can_unlock = true;
	}

	/* Read block lock-bits, 8 * 8 KB + 15 * 64 KB */
	for (i = 0; i < flashprog_flash_getsize(flash);
	     i += (i >= (64 * 1024) ? 64 * 1024 : 8 * 1024)) {
		bcfg = chip_readb(flash, bios + i + 2); /* read block lock config */
		msg_cdbg("block lock at %06x is %slocked!\n", i,
			 bcfg ? "" : "un");
		if (bcfg)
			need_unlock = true;
	}

	/* Reset chip */
	chip_writeb(flash, 0xFF, bios);

	/* Unlock: clear block lock-bits, if needed */
	if (can_unlock && need_unlock) {
		msg_cdbg("Unlock: ");
		chip_writeb(flash, 0x60, bios);
		chip_writeb(flash, 0xD0, bios);
		chip_writeb(flash, 0xFF, bios);
		wait_82802ab(flash);
		msg_cdbg("Done!\n");
	}

	/* Error: master locked or a block is locked */
	if (!can_unlock && need_unlock) {
		msg_cerr("At least one block is locked and lockdown is active!\n");
		return -1;
	}

	return 0;
}
