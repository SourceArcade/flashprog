/*
 * This file is part of the flashprog project.
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

#include "chipdrivers.h"

static void *programmer_map_flash_region(const struct flashctx *flash, const char *descr,
					 uintptr_t phys_addr, size_t len)
{
	void *ret;
	if (flash->mst.par->map_flash)
		ret = flash->mst.par->map_flash(descr, phys_addr, len);
	else
		ret = fallback_map(descr, phys_addr, len);
	msg_gspew("%s: mapping %s from 0x%0*" PRIxPTR " to 0x%0*" PRIxPTR "\n",
		  __func__, descr, PRIxPTR_WIDTH, phys_addr, PRIxPTR_WIDTH, (uintptr_t) ret);
	return ret;
}

static void programmer_unmap_flash_region(const struct flashctx *flash, void *virt_addr, size_t len)
{
	if (flash->mst.par->unmap_flash)
		flash->mst.par->unmap_flash(virt_addr, len);
	else
		fallback_unmap(virt_addr, len);
	msg_gspew("%s: unmapped 0x%0*" PRIxPTR "\n", __func__, PRIxPTR_WIDTH, (uintptr_t)virt_addr);
}

int prepare_memory_access(struct flashctx *flash, enum preparation_steps prep)
{
	/* Init pointers to the fail-safe state to distinguish them later from legit values. */
	flash->virtual_memory = (chipaddr)ERROR_PTR;
	flash->virtual_registers = (chipaddr)ERROR_PTR;

	const chipsize_t size = flash->chip->total_size * 1024;
	const uintptr_t base = flashbase ? flashbase : (0xffffffff - size + 1);
	void *const addr = programmer_map_flash_region(flash, flash->chip->name, base, size);
	if (addr == ERROR_PTR) {
		msg_perr("Could not map flash chip %s at 0x%0*" PRIxPTR ".\n",
			 flash->chip->name, PRIxPTR_WIDTH, base);
		return 1;
	}
	flash->physical_memory = base;
	flash->virtual_memory = (chipaddr)addr;

	return 0;
}

int prepare_memory_register_access(struct flashctx *flash, enum preparation_steps prep)
{
	if (prepare_memory_access(flash, prep))
		return 1;

	/*
	 * FIXME: Special function registers normally live 4 MByte below flash space,
	 * but it might be somewhere completely different on some chips and programmers,
	 * or not mappable at all. Ignore these problems for now and always report success.
	 */
	const chipsize_t size = flash->chip->total_size * 1024;
	const uintptr_t base = 0xffffffff - size - 0x400000 + 1;
	void *const addr = programmer_map_flash_region(flash, "flash chip registers", base, size);
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
		programmer_unmap_flash_region(flash, (void *)flash->virtual_registers, size);
		flash->physical_registers = 0;
		flash->virtual_registers = (chipaddr)ERROR_PTR;
	}

	if (flash->virtual_memory != (chipaddr)ERROR_PTR) {
		programmer_unmap_flash_region(flash, (void *)flash->virtual_memory, size);
		flash->physical_memory = 0;
		flash->virtual_memory = (chipaddr)ERROR_PTR;
	}
}
