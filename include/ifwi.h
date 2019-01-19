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

/*
 * The Integrated Firmware Image (IFWI) is used as a partitioning
 * format on some Intel SoCs (e.g. Apollo Lake). It is not tied to
 * NOR flashes, rather to have a common format between different
 * types of boot media.
 */

#ifndef __IFWI_H__
#define __IFWI_H__ 1

#include <stdint.h>

#include "layout.h"

int layout_from_ifwi_rom(struct flashprog_layout **, struct flashprog_flashctx *, size_t offset, size_t size);

/*********** Boot Partition Descriptor Table (BPDT) ***********/

#define BPDT_SIGNATURE		0x000055aa
#define BPDT_HEADER_LENGTH	24

struct bpdt_header {
	uint32_t signature;
	uint16_t desc_count;
	uint16_t version;
	uint32_t xorsum;		/* covers BPDT to S-BPDT (inclusive), iff there is
					   a redundant Logical Boot Partition, otherwise 0 */
	uint32_t ifwi_version;		/* revision of this IFWI build */
};

#define BPDT_ENTRY_LENGTH	12

struct bpdt_entry {			/* points to a Sub-Partition */
	uint16_t type;
	uint16_t flags;
	uint32_t offset;		/* from start of Logical Boot Partition */
	uint32_t size;
};

/**************** Sub-Partition Directory (SPD) ***************/

#define SPD_MARKER		0x44504324	/* $CPD */
#define SPD_MIN_HEADER_LENGTH	16

struct spd_header {
	uint32_t marker;
	uint32_t num_entries;
	uint8_t header_version;
	uint8_t entry_version;
	uint8_t header_length;
	uint8_t checksum;		/* xor-sum covering header + entries */
	char name[4 + 1];		/* serialized as 4 chars w/o terminator */
};

#define SPD_ENTRY_OFFSET_MASK	0x01ffffff
#define SPD_ENTRY_LENGTH	24

struct spd_entry {
	char name[12 + 1];		/* serialized as 12 chars w/o terminator */
	uint32_t offset;		/* from start of the SPD header */
	uint32_t length;
};

#endif	/* __IFWI_H__ */
