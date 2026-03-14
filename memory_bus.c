/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2014 Stefan Tauner
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

#include "flash.h"
#include "programmer.h"

#include "chipdrivers/memory_bus.h"

static void *programmer_map_flash_region(const struct par_master *par, const char *descr,
					 uintptr_t phys_addr, chipsize_t len)
{
	void *ret;
	if (par->map_flash)
		ret = par->map_flash(descr, phys_addr, len);
	else
		ret = fallback_map(descr, phys_addr, len);
	msg_gspew("%s: mapping%s%s from 0x%0*" PRIxPTR " to 0x%0*" PRIxPTR "\n",
		  __func__, *descr ? " " : "", descr,
		  PRIxPTR_WIDTH, phys_addr, PRIxPTR_WIDTH, (uintptr_t)ret);
	return ret;
}

void programmer_unmap_flash_region(const struct par_master *par, void *virt_addr, chipsize_t len)
{
	if (par->unmap_flash)
		par->unmap_flash(virt_addr, len);
	else
		fallback_unmap(virt_addr, len);
	msg_gspew("%s: unmapped 0x%0*" PRIxPTR "\n", __func__, PRIxPTR_WIDTH, (uintptr_t)virt_addr);
}

static uintptr_t calculate_flash_data_base(const struct par_master *par, chipsize_t size)
{
	return par->rom_base ? par->rom_base : (0xffffffff - size + 1);
}

void *programmer_map_flash_data(const struct par_master *par, chipsize_t size, const char *descr)
{
	uintptr_t base = calculate_flash_data_base(par, size);
	void *const addr = programmer_map_flash_region(par, descr, base, size);
	if (addr == ERROR_PTR) {
		msg_perr("Could not map flash chip%s%s at 0x%0*" PRIxPTR ".\n",
			 *descr ? " " : "", descr, PRIxPTR_WIDTH, base);
	}
	return addr;
}

int prepare_memory_access(struct flashctx *flash)
{
	const struct par_master *const par = flash->mst.par;

	/* Init pointers to the fail-safe state to distinguish them later from legit values. */
	flash->virtual_memory = (chipaddr)ERROR_PTR;
	flash->virtual_registers = (chipaddr)ERROR_PTR;

	const chipsize_t size = flashprog_flash_getsize(flash);
	void *const addr = programmer_map_flash_data(par, size, flash->chip->name);
	if (addr == ERROR_PTR)
		return 1;

	flash->physical_memory = calculate_flash_data_base(par, size);
	flash->virtual_memory = (chipaddr)addr;

	return 0;
}

int prepare_memory_register_access(struct flashctx *flash)
{
	const struct par_master *const par = flash->mst.par;

	if (prepare_memory_access(flash))
		return 1;

	/*
	 * FIXME: Special function registers normally live 4 MByte below flash space,
	 * but it might be somewhere completely different on some chips and programmers,
	 * or not mappable at all. Ignore these problems for now and always report success.
	 */
	const chipsize_t size = flashprog_flash_getsize(flash);
	const uintptr_t base = 0xffffffff - size - 0x400000 + 1;
	void *const addr = programmer_map_flash_region(par, "flash chip registers", base, size);
	if (addr == ERROR_PTR) {
		msg_pdbg2("Could not map flash chip registers %s at 0x%0*" PRIxPTR ".\n",
			 flash->chip->name, PRIxPTR_WIDTH, base);
		return 0;
	}
	flash->physical_registers = base;
	flash->virtual_registers = (chipaddr)addr;

	return 0;
}

void finish_memory_access(struct flashctx *flash)
{
	const size_t size = flashprog_flash_getsize(flash);

	if (flash->virtual_registers != (chipaddr)ERROR_PTR) {
		programmer_unmap_flash_region(flash->mst.par, (void *)flash->virtual_registers, size);
		flash->physical_registers = 0;
		flash->virtual_registers = (chipaddr)ERROR_PTR;
	}

	if (flash->virtual_memory != (chipaddr)ERROR_PTR) {
		programmer_unmap_flash_region(flash->mst.par, (void *)flash->virtual_memory, size);
		flash->physical_memory = 0;
		flash->virtual_memory = (chipaddr)ERROR_PTR;
	}
}
