/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009-2010 Carl-Daniel Hailfinger
 * Copyright (C) 2013 Stefan Tauner
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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "layout.h"
#include "programmer.h"

/* Check if raw data is all 0 or all 1. */
bool flashprog_no_data(const void *const raw_data, const size_t len)
{
	const uint8_t *const raw_end = (const uint8_t *)raw_data + len;
	const uint8_t patterns[] = { 0x00, 0xff };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(patterns); ++i) {
		const uint8_t *raw_ptr;
		for (raw_ptr = raw_data; raw_ptr < raw_end; ++raw_ptr) {
			if (*raw_ptr != patterns[i])
				break;
		}
		if (raw_ptr == raw_end)
			return true;
	}

	return false;
}

int flashprog_read_chunked(struct flashctx *const flash, uint8_t *dst, unsigned int start, unsigned int len,
			   unsigned int chunksize, readfunc_t *const read)
{
	int ret;
	size_t to_read;

	if (chunksize > 256 && chunksize & 3)
		chunksize &= ~3;

	for (; len; len -= to_read, dst += to_read, start += to_read) {
		to_read = min(chunksize, len);
		ret = read(flash, dst, start, to_read);
		if (ret)
			return ret;
		flashprog_progress_add(flash, to_read);
	}
	return 0;
}

int flashprog_limit_chip(struct flashctx *flash)
{
	const chipsize_t limit = flash->mst.common->max_rom_decode;
	struct flashchip *const chip = &flash->chip;
	const chipsize_t chip_size = chip->total_size * 1024;
	unsigned int usable_erasers = 0;
	unsigned int i;


	/* Chip is small enough or already limited. */
	if (chip_size <= limit)
		return 0;

	const struct flashprog_layout *const layout = get_default_layout(flash);
	if (layout) {
		struct romentry *const entry = (struct romentry *)layout_next(layout, NULL);
		if (entry)
			entry->end = limit - 1;
	}

	/* Undefine all block_erasers that don't operate on the whole chip,
	   and adjust the eraseblock size of those which do. */
	for (i = 0; i < NUM_ERASEFUNCTIONS; ++i) {
		if (chip->block_erasers[i].eraseblocks[0].size != chip_size) {
			chip->block_erasers[i].eraseblocks[0].count = 0;
			chip->block_erasers[i].block_erase = NULL;
		} else {
			chip->block_erasers[i].eraseblocks[0].size = limit;
			usable_erasers++;
		}
	}

	if (usable_erasers) {
		chip->total_size = limit / 1024;
		if (chip->page_size > limit)
			chip->page_size = limit;
		return 0;
	} else {
		msg_pdbg("Failed to adjust size of chip \"%s\" (%d kB).\n",
			 chip->name, chip->total_size);
		return -1;
	}
}

/* Compare 64 naturally aligned bytes (often matches a cache line). */
static int compare64(const char *const s1, const char *const s2, unsigned int offset)
{
	offset &= ~63;
	return memcmp(s1 + offset, s2 + offset, 64);
}

/* Compare two memory ranges at pseudo-random offsets. */
int compare_sparse(const void *const s1, const void *const s2, const size_t n)
{
	const unsigned int offsets[] = {
		12, 123, 1234, 12345, 123456, 123456, 1234567, 12345678, 123456789,
		0x12, 0x123, 0x1234, 0x12345, 0x123456, 0x1234567, 0x12345678,
		0, 01, 012, 0123, 01234, 012345, 0123456, 01234567,
	};
	const unsigned int step = 1234;

	if (n < step + 64)
		return 0;

	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(offsets); ++i) {
		const unsigned int offset = offsets[i] % ((n - 64) / step) * step;

		const int diff1 = compare64(s1, s2, offset);
		if (diff1)
			return diff1;

		const int diff2 = compare64(s1, s2, n - 64 - offset);
		if (diff2)
			return diff2;
	}

	return 0;
}

/* Guesstimate the addressable size inside a memory mapping. `len' should be a power of 2. */
size_t estimate_addressable_size(const void *const base, size_t len)
{
	if (len & (len - 1))
		msg_perr("Error in %s: Given `len=%zu' is not a power of 2.\n", __func__, len);

	/*
	 * We start comparing the two halves of the given space. And if
	 * they match, split the lower half, and so on until we find a
	 * mismatch (or not, in the unlikely case of empty memory?).
	 */
	for (; len > 0; len /= 2) {
		if (compare_sparse(base, base + len / 2, len / 2))
			break;
	}

	return len;
}

/* Returns the minimum number of bits needed to represent the given address.
 * FIXME: use mind-blowing implementation. */
uint32_t address_to_bits(uint32_t addr)
{
	unsigned int lzb = 0;
	while (((1u << (31 - lzb)) & ~addr) != 0)
		lzb++;
	return 32 - lzb;
}

unsigned int bitcount(unsigned long a)
{
	unsigned int i = 0;
	for (; a != 0; a >>= 1)
		if (a & 1)
			i++;
	return i;
}

int max(int a, int b)
{
	return (a > b) ? a : b;
}

int min(int a, int b)
{
	return (a < b) ? a : b;
}

char *strcat_realloc(char *dest, const char *src)
{
	dest = realloc(dest, strlen(dest) + strlen(src) + 1);
	if (!dest) {
		msg_gerr("Out of memory!\n");
		return NULL;
	}
	strcat(dest, src);
	return dest;
}

void tolower_string(char *str)
{
	for (; *str != '\0'; str++)
		*str = (char)tolower((unsigned char)*str);
}

uint8_t reverse_byte(uint8_t x)
{
	x = ((x >> 1) & 0x55) | ((x << 1) & 0xaa);
	x = ((x >> 2) & 0x33) | ((x << 2) & 0xcc);
	x = ((x >> 4) & 0x0f) | ((x << 4) & 0xf0);

	return x;
}

void reverse_bytes(uint8_t *dst, const uint8_t *src, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
		dst[i] = reverse_byte(src[i]);
}

/* FIXME: Find a better solution for MinGW. Maybe wrap strtok_s (C11) if it becomes available */
#ifdef __MINGW32__
char* strtok_r(char *str, const char *delim, char **nextp)
{
	if (str == NULL)
		str = *nextp;

	str += strspn(str, delim); /* Skip leading delimiters */
	if (*str == '\0')
		return NULL;

	char *ret = str;
	str += strcspn(str, delim); /* Find end of token */
	if (*str != '\0')
		*str++ = '\0';

	*nextp = str;
	return ret;
}

/* strndup is a POSIX function not present in MinGW */
char *strndup(const char *src, size_t maxlen)
{
	char *retbuf;
	size_t len;
	for (len = 0; len < maxlen; len++)
		if (src[len] == '\0')
			break;
	if ((retbuf = malloc(1 + len)) != NULL) {
		memcpy(retbuf, src, len);
		retbuf[len] = '\0';
	}
	return retbuf;
}
#endif

/* There is no strnlen in DJGPP */
#if defined(__DJGPP__) || (!defined(__LIBPAYLOAD__) && !defined(HAVE_STRNLEN))
size_t strnlen(const char *str, size_t n)
{
	size_t i;
	for (i = 0; i < n && str[i] != '\0'; i++)
		;
	return i;
}
#endif
