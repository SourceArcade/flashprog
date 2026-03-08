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
#include "programmer.h"

/**
 * @defgroup flashprog-chips Chip Enumeration
 * @{
 */

/* Magic pointer that represents our built in database. */
#define FLASHCHIPS_DB (struct flashprog_chips *)(uintptr_t)-1

/** @private */
struct flashprog_chips {
	/** @private */
	struct chip_entry {
		struct flashprog_chip chip;
		const struct master_common *bus;
		struct chip_entry *next;
	} *entries;
};

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

static int flashprog_chips_probe_bus(struct flashprog_chips *chips,
				     struct registered_master *bus)
{
	flashprog_bus_probe(bus, NULL);

	int chip;
	for (chip = 0; flashchips[chip].name; ++chip) {
		/* Ignore generic entries if we already have a match. */
		if (chips->entries &&
		    ((flashchips[chip].id.model == SFDP_DEVICE_ID) ||
		     (flashchips[chip].id.model == GENERIC_DEVICE_ID)))
			continue;

		if (!flashprog_chip_match(bus, &flashchips[chip]))
			continue;

		struct chip_entry *const entry = malloc(sizeof(*entry));
		if (!entry) {
			msg_cerr("Out of memory!\n");
			return 1;
		}

		entry->chip = flashchips[chip];
		entry->bus  = &bus->common;
		entry->next = chips->entries;

		chips->entries = entry;
	}

	return 0;
}

/** @private */
const struct master_common *flashprog_chip_probe(
		const struct flashprog_programmer *flashprog,
		const struct flashchip *chip)
{
	if (!chip_from_db(chip))
		/* If not in the DB, it must be a probed `chip_entry`. */
		return ((const struct chip_entry *)chip)->bus;

	int i;
	for (i = 0; i < registered_master_count; ++i) {
		struct registered_master *const bus = &registered_masters[i];

		if (!(bus->buses_supported & chip->bustype))
			continue;

		/* If it can't be probed, assume it's there. */
		if (chip->id.type == ID_NONE)
			return &bus->common;

		/* We probe for a specific chip, so we can adapt the voltage early. */
		if (bus->common.adapt_voltage &&
		    bus->common.adapt_voltage(&bus->common, chip->voltage.min, chip->voltage.max))
			return NULL;

		flashprog_bus_probe(bus, chip);
		if (flashprog_chip_match(bus, chip))
			return &bus->common;
	}

	return NULL;
}

/**
 * @brief Probe for flash chips.
 *
 * Probes for flash chips on a given programmer. Can return multiple
 * matches in case of ambiguous IDs or when the programmer features
 * multiple buses.
 *
 * @param[out] chips Points to a struct flashprog_chips pointer that gets
 *		     set if probing is successful. *chips has to be freed
 *		     by the caller with @ref flashprog_chips_release after
 *		     successful calls.
 * @param[in] flashprog The flash programmer used to access the chip.
 * @return 0 on success
 */
int flashprog_chips_probe(struct flashprog_chips **chips, const struct flashprog_programmer *flashprog)
{
	struct flashprog_chips *const matched_chips = calloc(1, sizeof(*matched_chips));
	if (!matched_chips) {
		msg_gerr("Out of memory!\n");
		return 1;
	}

	int bus_index;
	for (bus_index = 0; bus_index < registered_master_count; bus_index++) {
		if (flashprog_chips_probe_bus(matched_chips, &registered_masters[bus_index])) {
			flashprog_chips_release(matched_chips);
			return 1;
		}
	}

	*chips = matched_chips;
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
	if (!chips || chips == FLASHCHIPS_DB)
		return;

	struct chip_entry *next;
	for (; chips->entries; chips->entries = next) {
		next = chips->entries->next;
		free(chips->entries);
	}
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

	return &chips->entries->chip;
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

	/* If not in the DB, it must be a probed `chip_entry`. */
	return &((const struct chip_entry *)chip)->next->chip;
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

/**
 * @brief Get a bit mask of the supported bus types.
 *
 * @param chip reference to query.
 * @return bit mask of supported bus types.
 */
enum flashprog_bus_type flashprog_chip_buses(const struct flashprog_chip *chip) {
	return chip->bustype;
}

/**
 * @brief Get a string that lists the supported bus types.
 *
 * The resulting string needs to be freed with free().
 *
 * @param chip reference to query.
 * @return comma-separated string of supported bus types.
 */
char *flashprog_chip_bus_names(const struct flashprog_chip *chip) {
	return flashbuses_to_text(chip->bustype);
}

/**
 * @brief Get the supported operating voltage range.
 *
 * @param chip reference to query.
 * @return supported operating voltage range.
 */
struct flashprog_voltage_range flashprog_chip_voltage_range(const struct flashprog_chip *chip)
{
	return (struct flashprog_voltage_range) {
		.min = chip->voltage.min / 1000.f,
		.max = chip->voltage.max / 1000.f,
	};
}

/**
 * @brief Get the test status of a chip's standard features.
 *
 * @param chip reference to query.
 * @return struct with the test status of the chip's standard features.
 */
struct flashprog_test_status flashprog_chip_test_status(const struct flashprog_chip *chip) {
	return chip->tested;
}

/** @} */ /* end flashprog-chip */
