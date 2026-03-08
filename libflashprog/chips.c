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

#include <stdlib.h>

#define flashprog_chip flashchip	/* For now, we use direct pointers   */
#include "libflashprog.h"		/* to the internal struct flashchip. */

#include "flash.h"
#include "flashchips.h"

/**
 * @defgroup flashprog-chips Chip Enumeration
 * @{
 */

/* Magic pointer that represents our built in database. */
#define FLASHCHIPS_DB (struct flashprog_chips *)(uintptr_t)-1

static bool chip_from_db(const struct flashprog_chip *chip) {
	return flashchips <= chip && chip < flashchips + flashchips_size;
}

/**
 * @brief Enumerate the internal chips database.
 *
 * @param[out] chips Points to a struct flashprog_chips pointer that gets
 *                   set if the enumeration is successful. *chips has to be
 *                   freed by the caller with @ref flashprog_chips_release.
 * @return 0 on success
 */
int flashprog_chips_all(struct flashprog_chips **chips) {
	*chips = FLASHCHIPS_DB;
	return 0;
}

/**
 * @brief Count the chips in an enumeration.
 *
 * @return The number of chips.
 */
unsigned int flashprog_chips_count(const struct flashprog_chips *chips)
{
	unsigned int count = 0;
	const struct flashprog_chip *chip;
	for (chip = flashprog_chip_first(chips); chip; chip = flashprog_chip_next(chip))
		++count;
	return count;
}

/**
 * @brief Free a set of enumerated chips.
 *
 * This also invalidates all references that were acquired via
 * @ref flashprog_chip_first or @ref flashprog_chip_next from
 * the given set.
 *
 * @param chips Chip enumeration to free.
 */
void flashprog_chips_release(struct flashprog_chips *chips)
{
	if (chips == FLASHCHIPS_DB)
		return;

	free(chips);
}

/**
 * @brief Starts an iteration over a given set of enumerated chips.
 *
 * The referenced chip structure will stay valid until either the iteration
 * is advanced (@ref flashprog_chip_next) or the provided chips enumeration
 * is released. Note, each call may allocated additional resources that are
 * only freed by walking the iteration to its end,  or releasing the entire
 * chips set.
 *
 * @param chips A set of enumerated chips.
 * @return A pointer to the structure of the first chip or NULL if the set is empty.
 */
const struct flashprog_chip *flashprog_chip_first(const struct flashprog_chips *chips)
{
	if (chips == FLASHCHIPS_DB)
		return flashchips;

	return NULL;
}

/**
 * @brief Iterates to the next chip structure in a set of enumerated chips.
 *
 * The referenced chip structure will stay valid until either the iteration
 * is advanced further or the original chips enumeration is released (cf.
 * @ref flashprog_chip_first).
 *
 * @param chip The previous chip in the enumeration. The referenced
 *             structure will be invalidated by the call.
 * @return A pointer to the structure of the next chip or NULL if there is none.
 */
const struct flashprog_chip *flashprog_chip_next(const struct flashprog_chip *chip)
{
	if (chip_from_db(chip)) {
		for (++chip; chip->name; ++chip) {
			if (chip->id.manufacture == PROGMANUF_ID)
				continue;
			if (chip->id.manufacture == GENERIC_MANUF_ID)
				continue;
			if (chip->id.model == GENERIC_DEVICE_ID)
				continue;
			return chip;
		}
		return NULL;
	}

	return NULL;
}

/** @} */ /* end flashprog-chips */


/**
 * @defgroup flashprog-chip Chip Information
 * @{
 */

/**
 * @brief Get the vendor string of a given chip structure.
 *
 * @param chip reference to query.
 * @return Vendor string.
 */
const char *flashprog_chip_vendor(const struct flashprog_chip *chip) {
	return chip->vendor;
}

/**
 * @brief Get the name string of a given chip structure.
 *
 * @param chip reference to query.
 * @return Name string.
 */
const char *flashprog_chip_name(const struct flashprog_chip *chip) {
	return chip->name;
}

/**
 * @brief Get the size of a given chip in bytes.
 *
 * @param chip reference to query.
 * @return Size in bytes.
 */
size_t flashprog_chip_size(const struct flashprog_chip *chip) {
	return chip->total_size * KiB;
}

/** @} */ /* end flashprog-chip */
