/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2019 secunet Security Networks AG
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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libflashprog.h"
#include "platform.h"
#include "layout.h"
#include "flash.h"
#include "ifwi.h"

static size_t bpdt_size(const struct bpdt_header *const header)
{
	return BPDT_HEADER_LENGTH + header->desc_count * BPDT_ENTRY_LENGTH;
}

static int deserialize_bpdt_header(struct bpdt_header *const header, const uint8_t *const from)
{
	header->signature	= read_le32(from,  0);
	header->desc_count	= read_le16(from,  4);
	header->version		= read_le16(from,  6);
	header->xorsum		= read_le32(from,  8);
	header->ifwi_version	= read_le32(from, 12);

	if (header->signature != BPDT_SIGNATURE) {
		msg_gerr("IFWI: BPDT signature mismatch. Found 0x%08"PRIx32", expected 0x%08x.\n",
			 header->signature, BPDT_SIGNATURE);
		return -4;
	}
	if (header->version != 1) {
		msg_gerr("IFWI: Unknown BPDT version: %"PRIu32".\n", header->version);
		return -3;
	}
	return 0;
}

static int deserialize_bpdt_entries(struct bpdt_entry entries[], const unsigned int count,
				    const uint8_t *const from, const size_t limit)
{
	unsigned int i;
	size_t offset;

	for (i = 0, offset = 0; i < count; ++i, offset += BPDT_ENTRY_LENGTH) {
		entries[i].type		= read_le16(from, offset + 0);
		entries[i].flags	= read_le16(from, offset + 2);
		entries[i].offset	= read_le32(from, offset + 4);
		entries[i].size		= read_le32(from, offset + 8);
		msg_gdbg("IFWI: BPDT entry #%u (0x%04"PRIx16", 0x%04"PRIx16", 0x%08"PRIx32", 0x%08"PRIx32")\n",
			 i, entries[i].type, entries[i].flags, entries[i].offset, entries[i].size);

		const uint32_t end = entries[i].offset + entries[i].size;
		if (end < entries[i].offset) {
			msg_gerr("IFWI: BPDT entry overflows 32-bit space; "
				 "offset 0x%08"PRIx32" size 0x%08"PRIx32"\n",
				 entries[i].offset, entries[i].size);
			return -4;
		}
		if (end > limit) {
			msg_gerr("IFWI: BPDT entry points outside of the partition: %08"PRIx32":%08"PRIx32"\n",
				 entries[i].offset, end - 1);
			return -4;
		}
	}
	return (int)i;
}

static int read_bpdt(struct bpdt_header *const header, struct bpdt_entry **const entries,
		     const size_t flash_offset, const size_t partition_limit,
		     int (*const read)(void *args, uint8_t *buf, unsigned int start, unsigned int len),
		     void *const read_args)
{
	uint8_t *buf;
	int ret;

	buf = malloc(BPDT_HEADER_LENGTH);
	if (!buf) {
		msg_gerr("Out of memory!\n");
		return -1;
	}

	if (read(read_args, buf, flash_offset, BPDT_HEADER_LENGTH)) {
		ret = -2;
		goto _free_buf_ret;
	}
	ret = deserialize_bpdt_header(header, buf);
	if (ret < 0)
		goto _free_buf_ret;
	free(buf);

	buf = malloc(header->desc_count * BPDT_ENTRY_LENGTH);
	*entries = malloc(header->desc_count * sizeof(**entries));
	if (!buf || !*entries) {
		ret = -1;
		goto _free_entries_ret;
	}

	if (read(read_args, buf, flash_offset + BPDT_HEADER_LENGTH, header->desc_count * BPDT_ENTRY_LENGTH)) {
		ret = -2;
		goto _free_entries_ret;
	}
	ret = deserialize_bpdt_entries(*entries, header->desc_count, buf, partition_limit);
	if (ret < 0)
		goto _free_entries_ret;
	free(buf);

	return 0;

_free_entries_ret:
	free(*entries);
_free_buf_ret:
	free(buf);
	return ret;
}

static int deserialize_spd_header(struct spd_header *const header, const uint8_t *const from)
{
	header->marker		= read_le32(from,  0);
	header->num_entries	= read_le32(from,  4);
	header->header_version	= read_le8 (from,  8);
	header->entry_version	= read_le8 (from,  9);
	header->header_length	= read_le8 (from, 10);
	header->checksum	= read_le8 (from, 11);
	memcpy(header->name, from + 12, sizeof(header->name) - 1);
	header->name[sizeof(header->name) - 1] = '\0';

	if (header->marker != SPD_MARKER) {
		msg_gerr("IFWI: SPD marker mismatch. Found 0x%08"PRIx32", expected 0x%08x.\n",
			 header->marker, SPD_MARKER);
		return -4;
	}
	if (header->header_version != 1) {
		msg_gerr("IFWI: Unknown SPD header version: %"PRIu8".\n", header->header_version);
		return -3;
	}
	if (header->entry_version != 1) {
		msg_gerr("IFWI: Unknown SPD entry version: %"PRIu8".\n", header->entry_version);
		return -3;
	}
	return 0;
}

static int deserialize_spd_entries(struct spd_entry entries[], const unsigned int count,
				   const uint8_t *const from, const size_t limit)
{
	unsigned int i;
	size_t offset;

	for (i = 0, offset = 0; i < count; ++i, offset += SPD_ENTRY_LENGTH) {
		memcpy(entries[i].name, from + offset, sizeof(entries[i].name) - 1);
		entries[i].name[sizeof(entries[i].name) - 1] = '\0';
		entries[i].offset	= read_le32(from, offset + 12);
		entries[i].length	= read_le32(from, offset + 16);
		msg_gdbg("IFWI: SPD entry #%u (%s, 0x%08"PRIx32", 0x%08"PRIx32")\n",
			 i, entries[i].name, entries[i].offset, entries[i].length);

		const uint32_t end = entries[i].offset + entries[i].length;
		if (end < entries[i].offset) {
			msg_gerr("IFWI: SPD entry overflows 32-bit space; "
				 "offset 0x%08"PRIx32" size 0x%08"PRIx32"\n",
				 entries[i].offset, entries[i].length);
			return -4;
		}
		if (end > limit) {
			msg_gerr("IFWI: SPD entry points outside of the partition: %08"PRIx32":%08"PRIx32"\n",
				 entries[i].offset, end - 1);
			return -4;
		}
	}
	return (int)i;
}

static int read_spd(struct spd_header *const header, struct spd_entry **const entries,
		    const size_t flash_offset, const size_t partition_limit,
		    int (*const read)(void *args, uint8_t *buf, unsigned int start, unsigned int len),
		    void *const read_args)
{
	uint8_t *buf;
	int ret;

	buf = malloc(SPD_MIN_HEADER_LENGTH);
	if (!buf) {
		msg_gerr("Out of memory!\n");
		return -1;
	}

	if (read(read_args, buf, flash_offset, SPD_MIN_HEADER_LENGTH)) {
		ret = -2;
		goto _free_buf_ret;
	}
	ret = deserialize_spd_header(header, (uint8_t *)buf);
	if (ret < 0)
		goto _free_buf_ret;
	free(buf);

	buf = malloc(header->num_entries * SPD_ENTRY_LENGTH);
	*entries = malloc(header->num_entries * sizeof(**entries));
	if (!buf || !*entries) {
		ret = -1;
		goto _free_entries_ret;
	}

	if (read(read_args, buf, flash_offset + header->header_length, header->num_entries * SPD_ENTRY_LENGTH)) {
		ret = -2;
		goto _free_entries_ret;
	}
	ret = deserialize_spd_entries(*entries, header->num_entries, buf, partition_limit);
	if (ret < 0)
		goto _free_entries_ret;
	free(buf);

	return 0;

_free_entries_ret:
	free(*entries);
_free_buf_ret:
	free(buf);
	return ret;
}

static int _add_layout_entry(struct flashprog_layout **const layout,
			     const char *const prefix, const char *const name,
			     const size_t start, const size_t end)
{
	size_t name_buf_len = strlen(prefix) + strlen(name) + 2;
	char *name_buf = malloc(name_buf_len);

	snprintf(name_buf, name_buf_len, "%s/%s", prefix, name);
	int ret = flashprog_layout_add_region(*layout, start, end, name_buf);
	free(name_buf);
	return ret;
}

static int _layout_from_ifwi(struct flashprog_layout **const layout,
			     const char *const partition_name,
			     const size_t primary_offset, const size_t secondary_offset,
			     const size_t partition_limit,
			     int (*const read)(void *args, uint8_t *buf, unsigned int start, unsigned int len),
			     void *const read_args)
{
	struct bpdt_header header;
	struct bpdt_entry *entries;
	struct spd_header spd_header;
	struct spd_entry *spd_entries;
	size_t bpdt_offset, offset;
	unsigned int i, j;
	int ret = -1;

	if (!secondary_offset)
		bpdt_offset = primary_offset;
	else
		bpdt_offset = secondary_offset;

	ret = read_bpdt(&header, &entries, bpdt_offset, partition_limit - primary_offset, read, read_args);
	if (ret < 0)
		return ret;

	ret = _add_layout_entry(layout, partition_name, secondary_offset ? "S-BPDT" : "BPDT",
				bpdt_offset, bpdt_offset + bpdt_size(&header) - 1);
	if (ret < 0)
		goto _free_entries_ret;

	for (i = 0; i < header.desc_count; ++i) {
		offset = primary_offset + entries[i].offset;

		if (!entries[i].offset || !entries[i].size) {
			msg_gdbg("IFWI: Skipping empty BPDT entry #%u of type %"PRIu16".\n",
				 i, entries[i].type);
			continue;
		}

		switch (entries[i].type) {
		case 5:
			/* recurse into secondary BPDT */
			ret = _layout_from_ifwi(layout, partition_name, primary_offset, offset,
						partition_limit, read, read_args);
			if (ret)
				goto _free_entries_ret;
			continue;
		case  0: /* Fall through.*/
		case  1: /* Fall through.*/
		case  2: /* Fall through.*/
		case  3: /* Fall through.*/
		case  4: /* Fall through.*/
		case  6: /* Fall through.*/
		case  7: /* Fall through.*/
		case  8: /* Fall through.*/
		case  9: /* Fall through.*/
		case 14: /* Fall through.*/
		case 15:
			break;
		default: /* TODO: Other entries could be added to the layout,
				  too. They'd need hardcoded names, though. */
			continue;
		}

		ret = read_spd(&spd_header, &spd_entries, offset, partition_limit - offset, read, read_args);
		switch (ret) {
		case 0:
			break;
		case -1: /* Fall through. */
		case -2:
			goto _free_entries_ret;
		default:
			continue;
		}

		ret = _add_layout_entry(layout, partition_name, spd_header.name,
					offset, offset + entries[i].size - 1);
		if (ret < 0) {
			free(spd_entries);
			goto _free_entries_ret;
		}
		for (j = 0; j < spd_header.num_entries; ++j) {
			offset = primary_offset + entries[i].offset +
				 (spd_entries[j].offset & SPD_ENTRY_OFFSET_MASK);
			ret = _add_layout_entry(layout, partition_name, spd_entries[j].name,
						offset, offset + spd_entries[j].length - 1);
			if (ret < 0) {
				free(spd_entries);
				goto _free_entries_ret;
			}
		}
		free(spd_entries);
	}

	ret = 0;

_free_entries_ret:
	free(entries);
	return ret;
}

static int layout_from_ifwi(struct flashprog_layout **const layout,
			    const size_t offset, const size_t size,
			    int (*const read)(void *args, uint8_t *buf, unsigned int start, unsigned int len),
			    void *const read_args)
{
	int ret;

	if (flashprog_layout_new(layout))
		return -1;

	ret = _layout_from_ifwi(layout, "LBP1", offset, 0, offset + size / 2, read, read_args);
	if (ret)
		goto _free_layout_ret;

	ret = _layout_from_ifwi(layout, "LBP2", offset + size / 2, 0, offset + size, read, read_args);
	if (ret)
		goto _free_layout_ret;

_free_layout_ret:
	if (ret)
		flashprog_layout_release(*layout);
	return ret;
}

int layout_from_ifwi_rom(struct flashprog_layout **const layout,
			 struct flashprog_flashctx *const flashctx,
			 const size_t offset, const size_t size)
{
	return layout_from_ifwi(layout, offset, size,
				(int (*)(void *, uint8_t *, unsigned int, unsigned int))flashctx->chip.read,
				flashctx);
}
