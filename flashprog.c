/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2000 Silicon Integrated System Corporation
 * Copyright (C) 2004 Tyan Corp <yhlu@tyan.com>
 * Copyright (C) 2005-2008 coresystems GmbH
 * Copyright (C) 2008,2009 Carl-Daniel Hailfinger
 * Copyright (C) 2016 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
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

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "flash.h"
#include "flashchips.h"
#include "programmer.h"
#include "hwaccess_physmap.h"
#include "chipdrivers.h"

const char flashprog_version[] = FLASHPROG_VERSION;
const char *chip_to_probe = NULL;

static const struct programmer_entry *programmer = NULL;
static char *programmer_param = NULL;

/* If nonzero, used as the start address of bottom-aligned flash. */
unsigned long flashbase;

/* Is writing allowed with this programmer? */
bool programmer_may_write;

#define SHUTDOWN_MAXFN 32
static int shutdown_fn_count = 0;
/** @private */
static struct shutdown_func_data {
	int (*func) (void *data);
	void *data;
} shutdown_fn[SHUTDOWN_MAXFN];
/* Initialize to 0 to make sure nobody registers a shutdown function before
 * programmer init.
 */
static bool may_register_shutdown = false;

/* Did we change something or was every erase/write skipped (if any)? */
static bool all_skipped = true;

static int check_block_eraser(const struct flashctx *flash, int k, int log);

int shutdown_free(void *data)
{
	free(data);
	return 0;
}

/* Register a function to be executed on programmer shutdown.
 * The advantage over atexit() is that you can supply a void pointer which will
 * be used as parameter to the registered function upon programmer shutdown.
 * This pointer can point to arbitrary data used by said function, e.g. undo
 * information for GPIO settings etc. If unneeded, set data=NULL.
 * Please note that the first (void *data) belongs to the function signature of
 * the function passed as first parameter.
 */
int register_shutdown(int (*function) (void *data), void *data)
{
	if (shutdown_fn_count >= SHUTDOWN_MAXFN) {
		msg_perr("Tried to register more than %i shutdown functions.\n",
			 SHUTDOWN_MAXFN);
		return 1;
	}
	if (!may_register_shutdown) {
		msg_perr("Tried to register a shutdown function before "
			 "programmer init.\n");
		return 1;
	}
	shutdown_fn[shutdown_fn_count].func = function;
	shutdown_fn[shutdown_fn_count].data = data;
	shutdown_fn_count++;

	return 0;
}

int register_chip_restore(chip_restore_fn_cb_t func,
			  struct flashctx *flash, uint8_t status)
{
	if (flash->chip_restore_fn_count >= MAX_CHIP_RESTORE_FUNCTIONS) {
		msg_perr("Tried to register more than %i chip restore"
		         " functions.\n", MAX_CHIP_RESTORE_FUNCTIONS);
		return 1;
	}
	flash->chip_restore_fn[flash->chip_restore_fn_count].func = func;
	flash->chip_restore_fn[flash->chip_restore_fn_count].status = status;
	flash->chip_restore_fn_count++;

	return 0;
}

static int deregister_chip_restore(struct flashctx *flash)
{
	int rc = 0;

	while (flash->chip_restore_fn_count > 0) {
		int i = --flash->chip_restore_fn_count;
		rc |= flash->chip_restore_fn[i].func(
			flash, flash->chip_restore_fn[i].status);
	}

	return rc;
}

int programmer_init(struct flashprog_programmer *const prog)
{
	int ret;

	if (prog == NULL || prog->driver == NULL) {
		msg_perr("Invalid programmer specified!\n");
		return -1;
	}
	programmer = prog->driver;
	programmer_param = prog->param;
	/* Initialize all programmer specific data. */
	/* Default to top aligned flash at 4 GB. */
	flashbase = 0;
	/* Registering shutdown functions is now allowed. */
	may_register_shutdown = true;
	/* Default to allowing writes. Broken programmers set this to 0. */
	programmer_may_write = true;

	msg_pdbg("Initializing %s programmer\n", programmer->name);
	ret = programmer->init(prog);
	if (programmer_param && strlen(programmer_param)) {
		if (ret != 0) {
			/* It is quite possible that any unhandled programmer parameter would have been valid,
			 * but an error in actual programmer init happened before the parameter was evaluated.
			 */
			msg_pwarn("Unhandled programmer parameters (possibly due to another failure): %s\n",
				  programmer_param);
		} else {
			/* Actual programmer init was successful, but the user specified an invalid or unusable
			 * (for the current programmer configuration) parameter.
			 */
			msg_perr("Unhandled programmer parameters: %s\n", programmer_param);
			msg_perr("Aborting.\n");
			ret = ERROR_FATAL;
		}
	}
	programmer_param = NULL;
	return ret;
}

/** Calls registered shutdown functions and resets internal programmer-related variables.
 * Calling it is safe even without previous initialization, but further interactions with programmer support
 * require a call to programmer_init() (afterwards).
 *
 * @return The OR-ed result values of all shutdown functions (i.e. 0 on success). */
int programmer_shutdown(struct flashprog_programmer *const prog)
{
	int ret = 0;

	/* Registering shutdown functions is no longer allowed. */
	may_register_shutdown = false;
	while (shutdown_fn_count > 0) {
		int i = --shutdown_fn_count;
		ret |= shutdown_fn[i].func(shutdown_fn[i].data);
	}
	registered_master_count = 0;

	return ret;
}

void programmer_delay(unsigned int usecs)
{
	if (usecs > 0) {
		if (programmer->delay)
			programmer->delay(usecs);
		else
			internal_delay(usecs);
	}
}

static int read_memmapped_chunk(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	chip_readn(flash, buf, flash->virtual_memory + start, len);
	return 0;
}
int read_memmapped(struct flashctx *flash, uint8_t *buf, unsigned int start, int unsigned len)
{
	return flashprog_read_chunked(flash, buf, start, len, MAX_DATA_READ_UNLIMITED, read_memmapped_chunk);
}

/* This is a somewhat hacked function similar in some ways to strtok().
 * It will look for needle with a subsequent '=' in haystack, return a copy of
 * needle and remove everything from the first occurrence of needle to the next
 * delimiter from haystack.
 */
static char *extract_param(char *const *haystack, const char *needle, const char *delim)
{
	char *param_pos, *opt_pos, *rest;
	char *opt = NULL;
	int optlen;
	int needlelen;

	needlelen = strlen(needle);
	if (!needlelen) {
		msg_gerr("%s: empty needle! Please report a bug at "
			 "flashprog@flashprog.org\n", __func__);
		return NULL;
	}
	/* No programmer parameters given. */
	if (*haystack == NULL)
		return NULL;
	param_pos = strstr(*haystack, needle);
	do {
		if (!param_pos)
			return NULL;
		/* Needle followed by '='? */
		if (param_pos[needlelen] == '=') {
			/* Beginning of the string? */
			if (param_pos == *haystack)
				break;
			/* After a delimiter? */
			if (strchr(delim, *(param_pos - 1)))
				break;
		}
		/* Continue searching. */
		param_pos++;
		param_pos = strstr(param_pos, needle);
	} while (1);

	if (param_pos) {
		/* Get the string after needle and '='. */
		opt_pos = param_pos + needlelen + 1;
		optlen = strcspn(opt_pos, delim);
		/* Return an empty string if the parameter was empty. */
		opt = malloc(optlen + 1);
		if (!opt) {
			msg_gerr("Out of memory!\n");
			exit(1);
		}
		strncpy(opt, opt_pos, optlen);
		opt[optlen] = '\0';
		rest = opt_pos + optlen;
		/* Skip all delimiters after the current parameter. */
		rest += strspn(rest, delim);
		memmove(param_pos, rest, strlen(rest) + 1);
		/* We could shrink haystack, but the effort is not worth it. */
	}

	return opt;
}

char *extract_programmer_param(const char *param_name)
{
	return extract_param(&programmer_param, param_name, ",");
}

static void flashprog_progress_report(struct flashprog_progress *const p)
{
	if (p->current > p->total) {
		msg_gdbg2("Sanitizing progress report: %zu bytes off.", p->current - p->total);
		p->current = p->total;
	}

	if (!p->callback)
		return;

	p->callback(p->stage, p->current, p->total, p->user_data);
}

static void flashprog_progress_start(struct flashprog_flashctx *const flashctx,
				    const enum flashprog_progress_stage stage, const size_t total)
{
	flashctx->progress.stage	= stage;
	flashctx->progress.current	= 0;
	flashctx->progress.total	= total;
	flashprog_progress_report(&flashctx->progress);
}

static void flashprog_progress_start_by_layout(struct flashprog_flashctx *const flashctx,
					      const enum flashprog_progress_stage stage,
					      const struct flashprog_layout *const layout)
{
	const struct romentry *entry = NULL;
	size_t total = 0;

	while ((entry = layout_next_included(layout, entry)))
		total += entry->end - entry->start + 1;

	flashprog_progress_start(flashctx, stage, total);
}

static void flashprog_progress_set(struct flashprog_flashctx *const flashctx, const size_t current)
{
	flashctx->progress.current = current;
	flashprog_progress_report(&flashctx->progress);
}

/** @private */
void flashprog_progress_add(struct flashprog_flashctx *const flashctx, const size_t progress)
{
	flashctx->progress.current += progress;
	flashprog_progress_report(&flashctx->progress);
}

static void flashprog_progress_finish(struct flashprog_flashctx *const flashctx)
{
	if (flashctx->progress.current == flashctx->progress.total)
		return;

	flashctx->progress.current = flashctx->progress.total;
	flashprog_progress_report(&flashctx->progress);
}

/* Returns the number of well-defined erasers for a chip. */
static unsigned int count_usable_erasers(const struct flashctx *flash)
{
	unsigned int usable_erasefunctions = 0;
	int k;
	for (k = 0; k < NUM_ERASEFUNCTIONS; k++) {
		if (!check_block_eraser(flash, k, 0))
			usable_erasefunctions++;
	}
	return usable_erasefunctions;
}

static int compare_range(const uint8_t *wantbuf, const uint8_t *havebuf, unsigned int start, unsigned int len)
{
	int ret = 0, failcount = 0;
	unsigned int i;
	for (i = 0; i < len; i++) {
		if (wantbuf[i] != havebuf[i]) {
			/* Only print the first failure. */
			if (!failcount++)
				msg_cerr("FAILED at 0x%08x! Expected=0x%02x, Found=0x%02x,",
					 start + i, wantbuf[i], havebuf[i]);
		}
	}
	if (failcount) {
		msg_cerr(" failed byte count from 0x%08x-0x%08x: 0x%x\n",
			 start, start + len - 1, failcount);
		ret = -1;
	}
	return ret;
}

/* start is an offset to the base address of the flash chip */
static int check_erased_range(struct flashctx *flash, unsigned int start, unsigned int len)
{
	int ret;
	const uint8_t erased_value = ERASED_VALUE(flash);

	uint8_t *cmpbuf = malloc(len);
	if (!cmpbuf) {
		msg_gerr("Out of memory!\n");
		return -1;
	}
	memset(cmpbuf, erased_value, len);
	ret = verify_range(flash, cmpbuf, start, len);

	free(cmpbuf);
	return ret;
}

int flashprog_read_range(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	flashprog_progress_start(flash, FLASHPROG_PROGRESS_READ, len);
	const int ret = flash->chip->read(flash, buf, start, len);
	flashprog_progress_finish(flash);
	return ret;
}

/*
 * @cmpbuf	buffer to compare against, cmpbuf[0] is expected to match the
 *		flash content at location start
 * @start	offset to the base address of the flash chip
 * @len		length of the verified area
 * @return	0 for success, -1 for failure
 */
int verify_range(struct flashctx *flash, const uint8_t *cmpbuf, unsigned int start, unsigned int len)
{
	if (!len)
		return -1;

	if (start + len > flash->chip->total_size * 1024) {
		msg_gerr("Error: %s called with start 0x%x + len 0x%x >"
			" total_size 0x%x\n", __func__, start, len,
			flash->chip->total_size * 1024);
		return -1;
	}

	uint8_t *readbuf = malloc(len);
	if (!readbuf) {
		msg_gerr("Out of memory!\n");
		return -1;
	}

	int ret = flash->chip->read(flash, readbuf, start, len);
	if (ret) {
		msg_gerr("Verification impossible because read failed "
			 "at 0x%x (len 0x%x)\n", start, len);
		ret = -1;
		goto out_free;
	}

	ret = compare_range(cmpbuf, readbuf, start, len);
out_free:
	free(readbuf);
	return ret;
}

size_t gran_to_bytes(const enum write_granularity gran)
{
	switch (gran) {
		case write_gran_1bit:			return 1;
		case write_gran_1byte:			return 1;
		case write_gran_1byte_implicit_erase:	return 1;
		case write_gran_128bytes:		return 128;
		case write_gran_256bytes:		return 256;
		case write_gran_264bytes:		return 264;
		case write_gran_512bytes:		return 512;
		case write_gran_528bytes:		return 528;
		case write_gran_1024bytes:		return 1024;
		case write_gran_1056bytes:		return 1056;
		default:				return 0;
	}
}

/* Helper function for need_erase() that focuses on granularities of gran bytes. */
static int need_erase_gran_bytes(const uint8_t *have, const uint8_t *want, unsigned int len,
                                 unsigned int gran, const uint8_t erased_value)
{
	unsigned int i, j, limit;
	for (j = 0; j < len / gran; j++) {
		limit = min (gran, len - j * gran);
		/* Are 'have' and 'want' identical? */
		if (!memcmp(have + j * gran, want + j * gran, limit))
			continue;
		/* have needs to be in erased state. */
		for (i = 0; i < limit; i++)
			if (have[j * gran + i] != erased_value)
				return 1;
	}
	return 0;
}

/*
 * Check if the buffer @have can be programmed to the content of @want without
 * erasing. This is only possible if all chunks of size @gran are either kept
 * as-is or changed from an all-ones state to any other state.
 *
 * Warning: This function assumes that @have and @want point to naturally
 * aligned regions.
 *
 * @have        buffer with current content
 * @want        buffer with desired content
 * @len		length of the checked area
 * @gran	write granularity (enum, not count)
 * @return      0 if no erase is needed, 1 otherwise
 */
static int need_erase(const uint8_t *have, const uint8_t *want, unsigned int len,
		      enum write_granularity gran, const uint8_t erased_value)
{
	unsigned int i;
	size_t stride;

	switch (gran) {
	case write_gran_1bit:
		for (i = 0; i < len; i++) {
			if ((have[i] & want[i]) != want[i])
				return 1;
		}
		return 0;
	case write_gran_1byte:
		for (i = 0; i < len; i++) {
			if ((have[i] != want[i]) && (have[i] != erased_value))
				return 1;
		}
		return 0;
	case write_gran_1byte_implicit_erase:
		/* Do not erase, handle content changes from anything->0xff by writing 0xff. */
		return 0;
	default:
		stride = gran_to_bytes(gran);
		if (stride) {
			return need_erase_gran_bytes(have, want, len, stride, erased_value);
		}
		msg_cerr("%s: Unsupported granularity! Please report a bug at "
			 "flashprog@flashprog.org\n", __func__);
		return 0;
	}
}

/**
 * Check if the buffer @have needs to be programmed to get the content of @want.
 * If yes, return 1 and fill in first_start with the start address of the
 * write operation and first_len with the length of the first to-be-written
 * chunk. If not, return 0 and leave first_start and first_len undefined.
 *
 * Warning: This function assumes that @have and @want point to naturally
 * aligned regions.
 *
 * @have	buffer with current content
 * @want	buffer with desired content
 * @len		length of the checked area
 * @gran	write granularity (enum, not count)
 * @first_start	offset of the first byte which needs to be written (passed in
 *		value is increased by the offset of the first needed write
 *		relative to have/want or unchanged if no write is needed)
 * @return	length of the first contiguous area which needs to be written
 *		0 if no write is needed
 *
 * FIXME: This function needs a parameter which tells it about coalescing
 * in relation to the max write length of the programmer and the max write
 * length of the chip.
 */
static unsigned int get_next_write(const uint8_t *have, const uint8_t *want, chipsize_t len,
				   chipoff_t *first_start, enum write_granularity gran)
{
	bool need_write = false;
	unsigned int rel_start = 0, first_len = 0;
	unsigned int i, limit;

	const size_t stride = gran_to_bytes(gran);
	if (!stride) {
		msg_cerr("%s: Unsupported granularity! Please report a bug at "
			 "flashprog@flashprog.org\n", __func__);
		/* Claim that no write was needed. A write with unknown
		 * granularity is too dangerous to try.
		 */
		return 0;
	}
	for (i = 0; i < len / stride; i++) {
		limit = min(stride, len - i * stride);
		/* Are 'have' and 'want' identical? */
		if (memcmp(have + i * stride, want + i * stride, limit)) {
			if (!need_write) {
				/* First location where have and want differ. */
				need_write = true;
				rel_start = i * stride;
			}
		} else {
			if (need_write) {
				/* First location where have and want
				 * do not differ anymore.
				 */
				break;
			}
		}
	}
	if (need_write)
		first_len = min(i * stride - rel_start, len);
	*first_start += rel_start;
	return first_len;
}

/*
 * Return a string corresponding to the bustype parameter.
 * Memory is obtained with malloc() and must be freed with free() by the caller.
 */
char *flashbuses_to_text(enum chipbustype bustype)
{
	char *ret = calloc(1, 1);
	/*
	 * FIXME: Once all chipsets and flash chips have been updated, NONSPI
	 * will cease to exist and should be eliminated here as well.
	 */
	if (bustype == BUS_NONSPI) {
		ret = strcat_realloc(ret, "Non-SPI, ");
	} else {
		if (bustype & BUS_PARALLEL)
			ret = strcat_realloc(ret, "Parallel, ");
		if (bustype & BUS_LPC)
			ret = strcat_realloc(ret, "LPC, ");
		if (bustype & BUS_FWH)
			ret = strcat_realloc(ret, "FWH, ");
		if (bustype & BUS_SPI)
			ret = strcat_realloc(ret, "SPI, ");
		if (bustype & BUS_PROG)
			ret = strcat_realloc(ret, "Programmer-specific, ");
		if (bustype == BUS_NONE)
			ret = strcat_realloc(ret, "None, ");
	}
	/* Kill last comma. */
	ret[strlen(ret) - 2] = '\0';
	ret = realloc(ret, strlen(ret) + 1);
	return ret;
}

static int init_default_layout(struct flashctx *flash)
{
	/* Fill default layout covering the whole chip. */
	if (flashprog_layout_new(&flash->default_layout) ||
	    flashprog_layout_add_region(flash->default_layout,
			0, flash->chip->total_size * 1024 - 1, "complete flash") ||
	    flashprog_layout_include_region(flash->default_layout, "complete flash"))
	        return -1;
	return 0;
}

int probe_flash(struct registered_master *mst, int startchip, struct flashctx *flash, int force)
{
	const struct flashchip *chip;
	enum chipbustype buses_common;
	char *tmp;

	for (chip = flashchips + startchip; chip && chip->name; chip++) {
		if (chip_to_probe && strcmp(chip->name, chip_to_probe) != 0)
			continue;
		buses_common = mst->buses_supported & chip->bustype;
		if (!buses_common)
			continue;
		/* Only probe for SPI25 chips by default. */
		if (chip->bustype == BUS_SPI && !chip_to_probe && chip->spi_cmd_set != SPI25)
			continue;
		msg_gdbg("Probing for %s %s, %d kB: ", chip->vendor, chip->name, chip->total_size);
		if (!chip->probe && !force) {
			msg_gdbg("failed! flashprog has no probe function for this flash chip.\n");
			continue;
		}

		/* Start filling in the dynamic data. */
		flash->chip = calloc(1, sizeof(*flash->chip));
		if (!flash->chip) {
			msg_gerr("Out of memory!\n");
			return -1;
		}
		*flash->chip = *chip;
		flash->mst.par = &mst->par; /* both `mst` are unions, so we need only one pointer */

		if (flash->chip->prepare_access && flash->chip->prepare_access(flash, PREPARE_PROBE))
			goto free_chip;

		/* We handle a forced match like a real match, we just avoid probing. Note that probe_flash()
		 * is only called with force=1 after normal probing failed.
		 */
		if (force)
			break;

		if (flash->chip->probe(flash) != 1)
			goto notfound;

		/* If this is the first chip found, accept it.
		 * If this is not the first chip found, accept it only if it is
		 * a non-generic match. SFDP and CFI are generic matches.
		 * startchip==0 means this call to probe_flash() is the first
		 * one for this programmer interface (master) and thus no other chip has
		 * been found on this interface.
		 */
		if (startchip == 0 && flash->chip->model_id == SFDP_DEVICE_ID) {
			msg_cinfo("===\n"
				  "SFDP has autodetected a flash chip which is "
				  "not natively supported by flashprog yet.\n");
			if (count_usable_erasers(flash) == 0)
				msg_cinfo("The standard operations read and "
					  "verify should work, but to support "
					  "erase, write and all other "
					  "possible features");
			else
				msg_cinfo("All standard operations (read, "
					  "verify, erase and write) should "
					  "work, but to support all possible "
					  "features");

			msg_cinfo(" we need to add them manually.\n"
				  "You can help us by mailing us the output of the following command to "
				  "flashprog@flashprog.org:\n"
				  "'flashprog -VV [plus the -p/--programmer parameter]'\n"
				  "Thanks for your help!\n"
				  "===\n");
		}

		/* First flash chip detected on this bus. */
		if (startchip == 0)
			break;
		/* Not the first flash chip detected on this bus, but not a generic match either. */
		if ((flash->chip->model_id != GENERIC_DEVICE_ID) && (flash->chip->model_id != SFDP_DEVICE_ID))
			break;
		/* Not the first flash chip detected on this bus, and it's just a generic match. Ignore it. */
notfound:
		if (flash->chip->finish_access)
			flash->chip->finish_access(flash);
free_chip:
		free(flash->chip);
		flash->chip = NULL;
	}

	if (!flash->chip)
		return -1;

	if (init_default_layout(flash) < 0)
		return -1;

	tmp = flashbuses_to_text(flash->chip->bustype);
	msg_cinfo("%s %s flash chip \"%s\" (%d kB, %s) ", force ? "Assuming" : "Found",
		  flash->chip->vendor, flash->chip->name, flash->chip->total_size, tmp);
	free(tmp);
#if CONFIG_INTERNAL == 1
	if (flash->physical_memory != 0 && mst->par.map_flash == physmap)
		msg_cinfo("mapped at physical address 0x%0*" PRIxPTR ".\n",
			  PRIxPTR_WIDTH, flash->physical_memory);
	else
#endif
		msg_cinfo("on %s.\n", programmer->name);

	/* Flash registers may more likely not be mapped if the chip was forced.
	 * Lock info may be stored in registers, so avoid lock info printing. */
	if (!force)
		if (flash->chip->printlock)
			flash->chip->printlock(flash);

	/* Get out of the way for later runs. */
	if (flash->chip->finish_access)
		flash->chip->finish_access(flash);

	/* Return position of matching chip. */
	return chip - flashchips;
}

/* Even if an error is found, the function will keep going and check the rest. */
static int selfcheck_eraseblocks(const struct flashchip *chip)
{
	int i, j, k;
	int ret = 0;
	unsigned int prev_eraseblock_count = chip->total_size * 1024;

	for (k = 0; k < NUM_ERASEFUNCTIONS; k++) {
		unsigned int done = 0;
		struct block_eraser eraser = chip->block_erasers[k];
		unsigned int curr_eraseblock_count = 0;

		for (i = 0; i < NUM_ERASEREGIONS; i++) {
			/* Blocks with zero size are bugs in flashchips.c. */
			if (eraser.eraseblocks[i].count &&
			    !eraser.eraseblocks[i].size) {
				msg_gerr("ERROR: Flash chip %s erase function %i region %i has size 0.\n"
					 "Please report a bug at flashprog@flashprog.org\n",
					 chip->name, k, i);
				ret = 1;
			}
			/* Blocks with zero count are bugs in flashchips.c. */
			if (!eraser.eraseblocks[i].count &&
			    eraser.eraseblocks[i].size) {
				msg_gerr("ERROR: Flash chip %s erase function %i region %i has count 0.\n"
					 "Please report a bug at flashprog@flashprog.org\n",
					 chip->name, k, i);
				ret = 1;
			}
			done += eraser.eraseblocks[i].count *
				eraser.eraseblocks[i].size;
			curr_eraseblock_count += eraser.eraseblocks[i].count;
		}
		/* Empty eraseblock definition with erase function.  */
		if (!done && eraser.block_erase)
			msg_gspew("Strange: Empty eraseblock definition with "
				  "non-empty erase function. Not an error.\n");
		if (!done)
			continue;
		if (done != chip->total_size * 1024) {
			msg_gerr("ERROR: Flash chip %s erase function %i "
				"region walking resulted in 0x%06x bytes total,"
				" expected 0x%06x bytes.\n"
				"Please report a bug at flashprog@flashprog.org\n",
				chip->name, k, done, chip->total_size * 1024);
			ret = 1;
		}
		if (!eraser.block_erase)
			continue;
		/* Check if there are identical erase functions for different
		 * layouts. That would imply "magic" erase functions. The
		 * easiest way to check this is with function pointers.
		 */
		for (j = k + 1; j < NUM_ERASEFUNCTIONS; j++) {
			if (eraser.block_erase ==
			    chip->block_erasers[j].block_erase) {
				msg_gerr("ERROR: Flash chip %s erase function %i and %i are identical.\n"
					 "Please report a bug at flashprog@flashprog.org\n",
					 chip->name, k, j);
				ret = 1;
			}
		}
		if(curr_eraseblock_count > prev_eraseblock_count)
		{
			msg_gerr("ERROR: Flash chip %s erase function %i is not in order.\n"
				 "Please report a bug at flashprog@flashprog.org\n",
				 chip->name, k);
			ret = 1;
		}
		prev_eraseblock_count = curr_eraseblock_count;
	}
	return ret;
}

static int check_block_eraser(const struct flashctx *flash, int k, int log)
{
	struct block_eraser eraser = flash->chip->block_erasers[k];

	if (!eraser.block_erase && !eraser.eraseblocks[0].count) {
		if (log)
			msg_cdbg("not defined. ");
		return 1;
	}
	if (!eraser.block_erase && eraser.eraseblocks[0].count) {
		if (log)
			msg_cdbg("eraseblock layout is known, but matching "
				 "block erase function is not implemented. ");
		return 1;
	}
	if (eraser.block_erase && !eraser.eraseblocks[0].count) {
		if (log)
			msg_cdbg("block erase function found, but "
				 "eraseblock layout is not defined. ");
		return 1;
	}

	if (flash->chip->bustype == BUS_SPI && flash->chip->spi_cmd_set == SPI25) {
		bool native_4ba;
		int i;

		const uint8_t *opcode = spi_get_opcode_from_erasefn(eraser.block_erase, &native_4ba);
		if (!opcode)
			return 1;

		for (i = 0; opcode[i]; i++) {
			if ((native_4ba && !spi_master_4ba(flash)) ||
			    !flash->mst.spi->probe_opcode(flash, opcode[i])) {
				if (log)
					msg_cdbg("block erase function and layout found "
						 "but SPI master doesn't support the function. ");
				return 1;
			}
		}
	}
	// TODO: Once erase functions are annotated with allowed buses, check that as well.
	return 0;
}

/**
 * @brief Reads the included layout regions into a buffer.
 *
 * If there is no layout set in the given flash context, the whole chip will
 * be read.
 *
 * @param flashctx Flash context to be used.
 * @param buffer   Buffer of full chip size to read into.
 * @return 0 on success,
 *	   1 if any read fails.
 */
static int read_by_layout(struct flashctx *const flashctx, uint8_t *const buffer)
{
	const struct flashprog_layout *const layout = get_layout(flashctx);
	const struct romentry *entry = NULL;

	flashprog_progress_start_by_layout(flashctx, FLASHPROG_PROGRESS_READ, layout);

	while ((entry = layout_next_included(layout, entry))) {
		const chipoff_t region_start	= entry->start;
		const chipsize_t region_len	= entry->end - entry->start + 1;

		if (flashctx->chip->read(flashctx, buffer + region_start, region_start, region_len))
			return 1;
	}

	flashprog_progress_finish(flashctx);

	return 0;
}

/**
 * @private
 *
 * For read-erase-write, `curcontents` and `newcontents` shall point
 * to buffers of the chip's size. Both are supposed to be prefilled
 * with at least the included layout regions of the current flash
 * contents (`curcontents`) and the data to be written to the flash
 * (`newcontents`).
 *
 * For erase, `curcontents` and `newcontents` shall be NULL-pointers.
 *
 * The `chipoff_t` values are used internally by `walk_by_layout()`.
 */
struct walk_info {
	uint8_t *curcontents;
	const uint8_t *newcontents;
	chipoff_t region_start;
	chipoff_t region_end;
	chipoff_t erase_start;
	chipoff_t erase_end;
};

struct eraseblock_data {
	chipoff_t start_addr;
	chipoff_t end_addr;
	bool selected;
	size_t block_num;
	size_t first_sub_block_index;
	size_t last_sub_block_index;
};

struct erase_layout {
	struct eraseblock_data* layout_list;
	size_t block_count;
	const struct block_eraser *eraser;
};

static bool explicit_erase(const struct walk_info *const info)
{
	/* For explicit erase, we are called without new contents. */
	return !info->newcontents;
}

static size_t calculate_block_count(const struct block_eraser *const eraser)
{
	size_t block_count = 0, i;

	for (i = 0; i < ARRAY_SIZE(eraser->eraseblocks); ++i)
		block_count += eraser->eraseblocks[i].count;

	return block_count;
}

static void init_eraseblock(struct erase_layout *layout, size_t idx, size_t block_num,
		chipoff_t start_addr, chipoff_t end_addr, size_t *sub_block_index)
{
	struct eraseblock_data *edata = &layout[idx].layout_list[block_num];
	edata->start_addr = start_addr;
	edata->end_addr = end_addr;
	edata->selected = false;
	edata->block_num = block_num;

	if (!idx)
		return;
	const struct erase_layout *const sub_layout = &layout[idx - 1];

	edata->first_sub_block_index = *sub_block_index;
	for (; *sub_block_index < sub_layout->block_count; ++*sub_block_index) {
		if (sub_layout->layout_list[*sub_block_index].end_addr > end_addr)
			break;
	}
	edata->last_sub_block_index = *sub_block_index - 1;
}

/*
 * @brief Function to free the created erase_layout
 *
 * @param layout pointer to allocated layout
 * @param erasefn_count number of erase functions for which the layout was created
 *
 */
static void free_erase_layout(struct erase_layout *layout, unsigned int erasefn_count)
{
	size_t i;

	if (!layout)
		return;
	for (i = 0; i < erasefn_count; i++) {
		free(layout[i].layout_list);
	}
	free(layout);
}

/*
 * @brief Function to create an erase layout
 *
 * @param	flashctx	flash context
 * @param	e_layout	address to the pointer to store the layout
 * @return	0 on success,
 *		-1 if layout creation fails
 *
 * This function creates a layout of which erase functions erase which regions
 * of the flash chip. This helps to optimally select the erase functions for
 * erase/write operations.
 */
static int create_erase_layout(struct flashctx *const flashctx, struct erase_layout **e_layout)
{
	const struct flashchip *chip = flashctx->chip;
	const size_t erasefn_count = count_usable_erasers(flashctx);

	if (!erasefn_count) {
		msg_gerr("No erase functions supported\n");
		return 0;
	}

	struct erase_layout *layout = calloc(erasefn_count, sizeof(struct erase_layout));
	if (!layout) {
		msg_gerr("Out of memory!\n");
		return -1;
	}

	size_t layout_idx = 0, eraser_idx;
	for (eraser_idx = 0; eraser_idx < NUM_ERASEFUNCTIONS; eraser_idx++) {
		if (check_block_eraser(flashctx, eraser_idx, 0))
			continue;

		layout[layout_idx].eraser = &chip->block_erasers[eraser_idx];
		const size_t block_count = calculate_block_count(&chip->block_erasers[eraser_idx]);
		size_t sub_block_index = 0;

		layout[layout_idx].block_count = block_count;
		layout[layout_idx].layout_list = (struct eraseblock_data *)calloc(block_count,
									sizeof(struct eraseblock_data));

		if (!layout[layout_idx].layout_list) {
			free_erase_layout(layout, layout_idx);
			return -1;
		}

		size_t block_num = 0;
		chipoff_t start_addr = 0;

		int i;
		for (i = 0; block_num < block_count;  i++) {
			const struct eraseblock *block = &chip->block_erasers[eraser_idx].eraseblocks[i];

			size_t num;
			for (num = 0; num < block->count; num++) {
				chipoff_t end_addr = start_addr + block->size - 1;
				init_eraseblock(layout, layout_idx, block_num,
						start_addr, end_addr, &sub_block_index);
				block_num += 1;
				start_addr = end_addr + 1;
			}
		}
		layout_idx++;
	}

	*e_layout = layout;
	return layout_idx;
}

static void deselect_erase_block_rec(const struct erase_layout *layout, size_t findex, size_t block_num)
{
	struct eraseblock_data *const ed = &layout[findex].layout_list[block_num];
	size_t i;

	if (ed->selected) {
		ed->selected = false;
	} else if (findex > 0) {
		for (i = ed->first_sub_block_index; i <= ed->last_sub_block_index; ++i)
			deselect_erase_block_rec(layout, findex - 1, i);
	}
}

/*
 * @brief	Function to select the list of sectors that need erasing
 *
 * @param	flashctx	flash context
 * @param	layout		erase layout
 * @param	findex		index of the erase function
 * @param	block_num	index of the block to erase according to the erase function index
 * @param	info		current info from walking the regions
 * @return number of bytes selected for erase
 */
static size_t select_erase_functions_rec(const struct flashctx *flashctx, const struct erase_layout *layout,
					 size_t findex, size_t block_num, const struct walk_info *info)
{
	struct eraseblock_data *ll = &layout[findex].layout_list[block_num];
	const size_t eraseblock_size = ll->end_addr - ll->start_addr + 1;
	if (!findex) {
		if (ll->start_addr <= info->region_end && ll->end_addr >= info->region_start) {
			if (explicit_erase(info)) {
				ll->selected = true;
				return eraseblock_size;
			}
			const chipoff_t write_start = MAX(info->region_start, ll->start_addr);
			const chipoff_t write_end   = MIN(info->region_end, ll->end_addr);
			const chipsize_t write_len  = write_end - write_start + 1;
			const uint8_t erased_value  = ERASED_VALUE(flashctx);
			ll->selected = need_erase(
				info->curcontents + write_start, info->newcontents + write_start,
				write_len, flashctx->chip->gran, erased_value);
			if (ll->selected)
				return eraseblock_size;
		}
		return 0;
	} else {
		const int sub_block_start = ll->first_sub_block_index;
		const int sub_block_end = ll->last_sub_block_index;
		size_t bytes = 0;

		int j;
		for (j = sub_block_start; j <= sub_block_end; j++)
			bytes += select_erase_functions_rec(flashctx, layout, findex - 1, j, info);

		if (bytes > eraseblock_size / 2) {
			if (ll->start_addr >= info->region_start && ll->end_addr <= info->region_end) {
				deselect_erase_block_rec(layout, findex, block_num);
				ll->selected = true;
				bytes = eraseblock_size;
			}
		}
		return bytes;
	}
}

static size_t select_erase_functions(const struct flashctx *flashctx, const struct erase_layout *layout,
				     size_t erasefn_count, const struct walk_info *info)
{
	size_t bytes = 0;
	size_t block_num;
	for (block_num = 0; block_num < layout[erasefn_count - 1].block_count; ++block_num)
		bytes += select_erase_functions_rec(flashctx, layout, erasefn_count - 1, block_num, info);
	return bytes;
}

static int write_range(struct flashctx *const flashctx, const chipoff_t flash_offset,
		       const uint8_t *const curcontents, const uint8_t *const newcontents,
		       const chipsize_t len, bool *const skipped)
{
	unsigned int writecount = 0;
	chipoff_t starthere = 0;
	chipsize_t lenhere = 0;

	while ((lenhere = get_next_write(curcontents + starthere, newcontents + starthere,
					 len - starthere, &starthere, flashctx->chip->gran))) {
		if (!writecount++)
			msg_cdbg("W");
		if (flashctx->chip->write(flashctx, newcontents + starthere,
					  flash_offset + starthere, lenhere))
			return 1;
		starthere += lenhere;
		if (skipped) {
			flashprog_progress_set(flashctx, starthere);
			*skipped = false;
		}
	}
	return 0;
}

typedef int (*erasefn_t)(struct flashctx *, unsigned int addr, unsigned int len);
/* returns 0 on success, 1 to retry with another erase function, 2 for immediate abort */
typedef int (*per_blockfn_t)(struct flashctx *, const struct walk_info *, erasefn_t);

static int walk_eraseblocks(struct flashctx *const flashctx,
			    struct erase_layout *const layouts,
			    const size_t layout_count,
			    struct walk_info *const info,
			    const per_blockfn_t per_blockfn)
{
	int ret;
	size_t i, j;
	bool first = true;

	for (i = 0; i < layout_count; ++i) {
		const struct erase_layout *const layout = &layouts[i];

		for (j = 0; j < layout->block_count; ++j) {
			struct eraseblock_data *const eb = &layout->layout_list[j];

			if (eb->start_addr > info->region_end)
				break;
			if (eb->end_addr < info->region_start)
				continue;
			if (!eb->selected)
				continue;

			/* Print this for every block except the first one. */
			if (first)
				first = false;
			else
				msg_cdbg(", ");
			msg_cdbg("0x%06x-0x%06x:", eb->start_addr, eb->end_addr);

			info->erase_start = eb->start_addr;
			info->erase_end = eb->end_addr;
			ret = per_blockfn(flashctx, info, layout->eraser->block_erase);
			if (ret)
				return ret;

			/* Clean the erase layout up for future use on other
			   regions. `.selected` is the only field we alter. */
			eb->selected = false;
		}
	}
	msg_cdbg("\n");
	return 0;
}

static int walk_by_layout(struct flashctx *const flashctx, struct walk_info *const info,
			  const per_blockfn_t per_blockfn)
{
	const bool do_erase = explicit_erase(info) || !(flashctx->chip->feature_bits & FEATURE_NO_ERASE);
	const struct flashprog_layout *const layout = get_layout(flashctx);
	struct erase_layout *erase_layouts = NULL;
	const struct romentry *entry = NULL;
	int ret = 0, layout_count = 0;

	all_skipped = true;
	msg_cinfo("Erasing %sflash chip... ", info->newcontents ? "and writing " : "");

	if (do_erase) {
		layout_count = create_erase_layout(flashctx, &erase_layouts);
		if (layout_count <= 0)
			return 1;
	}

	while ((entry = layout_next_included(layout, entry))) {
		info->region_start = entry->start;
		info->region_end   = entry->end;

		if (do_erase) {
			const size_t total = select_erase_functions(flashctx, erase_layouts, layout_count, info);

			/* We verify every erased block manually. Technically that's
			   reading, but accounting for it as part of the erase helps
			   to provide a smooth, overall progress. Hence `total * 2`. */
			flashprog_progress_start(flashctx, FLASHPROG_PROGRESS_ERASE, total * 2);

			ret = walk_eraseblocks(flashctx, erase_layouts, layout_count, info, per_blockfn);
			if (ret) {
				msg_cerr("FAILED!\n");
				goto free_ret;
			}

			flashprog_progress_finish(flashctx);
		}

		if (info->newcontents) {
			bool skipped = true;
			msg_cdbg("0x%06x-0x%06x:", info->region_start, info->region_end);
			flashprog_progress_start(flashctx, FLASHPROG_PROGRESS_WRITE,
						info->region_end - info->region_start + 1);
			ret = write_range(flashctx, info->region_start,
					  info->curcontents + info->region_start,
					  info->newcontents + info->region_start,
					  info->region_end + 1 - info->region_start, &skipped);
			if (ret) {
				msg_cerr("FAILED!\n");
				goto free_ret;
			}
			flashprog_progress_finish(flashctx);
			if (skipped) {
				msg_cdbg("S\n");
			} else {
				msg_cdbg("\n");
				all_skipped = false;
			}
		}
	}
	if (all_skipped)
		msg_cinfo("\nWarning: Chip content is identical to the requested image.\n");
	msg_cinfo("Erase%s done.\n", info->newcontents ? "/write" : "");

free_ret:
	free_erase_layout(erase_layouts, layout_count);
	return ret;
}

static int erase_block(struct flashctx *const flashctx,
		       const struct walk_info *const info, const erasefn_t erasefn)
{
	const unsigned int erase_len = info->erase_end + 1 - info->erase_start;
	const bool region_unaligned = info->region_start > info->erase_start ||
				      info->erase_end > info->region_end;
	uint8_t *backup_contents = NULL, *erased_contents = NULL;
	int ret = 1;

	/*
	 * If the region is not erase-block aligned, merge current flash con-
	 * tents into a new buffer `backup_contents`.
	 */
	if (region_unaligned) {
		backup_contents = malloc(erase_len);
		erased_contents = malloc(erase_len);
		if (!backup_contents || !erased_contents) {
			msg_cerr("Out of memory!\n");
			goto _free_ret;
		}
		memset(backup_contents, ERASED_VALUE(flashctx), erase_len);
		memset(erased_contents, ERASED_VALUE(flashctx), erase_len);

		msg_cdbg("R");
		/* Merge data preceding the current region. */
		if (info->region_start > info->erase_start) {
			const chipoff_t start	= info->erase_start;
			const chipsize_t len	= info->region_start - info->erase_start;
			if (flashctx->chip->read(flashctx, backup_contents, start, len)) {
				msg_cerr("Can't read! Aborting.\n");
				goto _free_ret;
			}
		}
		/* Merge data following the current region. */
		if (info->erase_end > info->region_end) {
			const chipoff_t start     = info->region_end + 1;
			const chipoff_t rel_start = start - info->erase_start; /* within this erase block */
			const chipsize_t len      = info->erase_end - info->region_end;
			if (flashctx->chip->read(flashctx, backup_contents + rel_start, start, len)) {
				msg_cerr("Can't read! Aborting.\n");
				goto _free_ret;
			}
		}
	}

	all_skipped = false;

	msg_cdbg("E");
	if (erasefn(flashctx, info->erase_start, erase_len))
		goto _free_ret;
	flashprog_progress_add(flashctx, erase_len);
	if (check_erased_range(flashctx, info->erase_start, erase_len)) {
		msg_cerr("ERASE FAILED!\n");
		goto _free_ret;
	}
	if (info->curcontents)
		memset(info->curcontents + info->erase_start, ERASED_VALUE(flashctx), erase_len);

	if (region_unaligned) {
		if (write_range(flashctx, info->erase_start, erased_contents, backup_contents, erase_len, NULL))
			goto _free_ret;
		if (info->curcontents)
			memcpy(info->curcontents + info->erase_start, backup_contents, erase_len);
	}

	ret = 0;

_free_ret:
	free(erased_contents);
	free(backup_contents);
	return ret;
}

/**
 * @brief Erases the included layout regions.
 *
 * If there is no layout set in the given flash context, the whole chip will
 * be erased.
 *
 * @param flashctx Flash context to be used.
 * @return 0 on success,
 *	   1 if all available erase functions failed.
 */
static int erase_by_layout(struct flashctx *const flashctx)
{
	struct walk_info info = { 0 };
	return walk_by_layout(flashctx, &info, &erase_block);
}

/**
 * @brief Writes the included layout regions from a given image.
 *
 * If there is no layout set in the given flash context, the whole image
 * will be written.
 *
 * @param flashctx    Flash context to be used.
 * @param curcontents A buffer of full chip size with current chip contents of included regions.
 * @param newcontents The new image to be written.
 * @return 0 on success,
 *	   1 if anything has gone wrong.
 */
static int write_by_layout(struct flashctx *const flashctx,
			   void *const curcontents, const void *const newcontents)
{
	struct walk_info info;
	info.curcontents = curcontents;
	info.newcontents = newcontents;
	return walk_by_layout(flashctx, &info, erase_block);
}

/**
 * @brief Compares the included layout regions with content from a buffer.
 *
 * If there is no layout set in the given flash context, the whole chip's
 * contents will be compared.
 *
 * @param flashctx    Flash context to be used.
 * @param layout      Flash layout information.
 * @param curcontents A buffer of full chip size to read current chip contents into.
 * @param newcontents The new image to compare to.
 * @return 0 on success,
 *	   1 if reading failed,
 *	   3 if the contents don't match.
 */
static int verify_by_layout(
		struct flashctx *const flashctx,
		const struct flashprog_layout *const layout,
		void *const curcontents, const uint8_t *const newcontents)
{
	const struct romentry *entry = NULL;

	flashprog_progress_start_by_layout(flashctx, FLASHPROG_PROGRESS_READ, layout);

	while ((entry = layout_next_included(layout, entry))) {
		const chipoff_t region_start	= entry->start;
		const chipsize_t region_len	= entry->end - entry->start + 1;

		if (flashctx->chip->read(flashctx, curcontents + region_start, region_start, region_len))
			return 1;
		if (compare_range(newcontents + region_start, curcontents + region_start,
				  region_start, region_len))
			return 3;
	}

	flashprog_progress_finish(flashctx);

	return 0;
}

static void nonfatal_help_message(void)
{
	msg_gerr("Good, writing to the flash chip apparently didn't do anything.\n");
#if CONFIG_INTERNAL == 1
	if (programmer == &programmer_internal)
		msg_gerr("This means we have to add special support for your board, programmer or flash\n"
			 "chip. Please report this to the mailing list at flashprog@flashprog.org or\n"
			 "on IRC (see https://www.flashprog.org/Contact for details), thanks!\n"
			 "-------------------------------------------------------------------------------\n"
			 "You may now reboot or simply leave the machine running.\n");
	else
#endif
		msg_gerr("Please check the connections (especially those to write protection pins) between\n"
			 "the programmer and the flash chip. If you think the error is caused by flashprog\n"
			 "please report this to the mailing list at flashprog@flashprog.org or on IRC\n"
			 "(see https://www.flashprog.org/Contact for details), thanks!\n");
}

void emergency_help_message(void)
{
	msg_gerr("Your flash chip is in an unknown state.\n");
#if CONFIG_INTERNAL == 1
	if (programmer == &programmer_internal)
		msg_gerr("Get help on IRC (see https://www.flashprog.org/Contact) or mail\n"
			"flashprog@flashprog.org with the subject \"FAILED: <your board name>\"!\n"
			"-------------------------------------------------------------------------------\n"
			"DO NOT REBOOT OR POWEROFF!\n");
	else
#endif
		msg_gerr("Please report this to the mailing list at flashprog@flashprog.org\n"
			 "or on IRC (see https://www.flashprog.org/Contact for details), thanks!\n");
}

void list_programmers_linebreak(int startcol, int cols, int paren)
{
	const char *pname;
	int pnamelen;
	int remaining = 0, firstline = 1;
	size_t p;
	int i;

	for (p = 0; p < programmer_table_size; p++) {
		pname = programmer_table[p]->name;
		pnamelen = strlen(pname);
		if (remaining - pnamelen - 2 < 0) {
			if (firstline)
				firstline = 0;
			else
				msg_ginfo("\n");
			for (i = 0; i < startcol; i++)
				msg_ginfo(" ");
			remaining = cols - startcol;
		} else {
			msg_ginfo(" ");
			remaining--;
		}
		if (paren && (p == 0)) {
			msg_ginfo("(");
			remaining--;
		}
		msg_ginfo("%s", pname);
		remaining -= pnamelen;
		if (p < programmer_table_size - 1) {
			msg_ginfo(",");
			remaining--;
		} else {
			if (paren)
				msg_ginfo(")");
		}
	}
}

int selfcheck(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < programmer_table_size; i++) {
		const struct programmer_entry *const p = programmer_table[i];
		if (p == NULL) {
			msg_gerr("Programmer with index %d is NULL instead of a valid pointer!\n", i);
			ret = 1;
			continue;
		}
		if (p->name == NULL) {
			msg_gerr("All programmers need a valid name, but the one with index %d does not!\n", i);
			ret = 1;
			/* This might hide other problems with this programmer, but allows for better error
			 * messages below without jumping through hoops. */
			continue;
		}
		switch (p->type) {
		case USB:
		case PCI:
		case OTHER:
			if (p->devs.note == NULL) {
				if (strcmp("internal", p->name) == 0)
					break; /* This one has its device list stored separately. */
				msg_gerr("Programmer %s has neither a device list nor a textual description!\n",
					 p->name);
				ret = 1;
			}
			break;
		default:
			msg_gerr("Programmer %s does not have a valid type set!\n", p->name);
			ret = 1;
			break;
		}
		if (p->init == NULL) {
			msg_gerr("Programmer %s does not have a valid init function!\n", p->name);
			ret = 1;
		}
	}

	/* It would be favorable if we could check for the correct layout (especially termination) of various
	 * constant arrays: flashchips, chipset_enables, board_matches, boards_known, laptops_known.
	 * They are all defined as externs in this compilation unit so we don't know their sizes which vary
	 * depending on compiler flags, e.g. the target architecture, and can sometimes be 0.
	 * For 'flashchips' we export the size explicitly to work around this and to be able to implement the
	 * checks below. */
	if (flashchips_size <= 1 || flashchips[flashchips_size - 1].name != NULL) {
		msg_gerr("Flashchips table miscompilation!\n");
		ret = 1;
	} else {
		for (i = 0; i < flashchips_size - 1; i++) {
			const struct flashchip *chip = &flashchips[i];
			const char *const name = chip->name != NULL ? chip->name : "unnamed";
			if (chip->vendor == NULL || chip->name == NULL || chip->bustype == BUS_NONE) {
				ret = 1;
				msg_gerr("ERROR: Some field of flash chip #%d (%s) is misconfigured.\n"
					 "Please report a bug at flashprog@flashprog.org\n", i, name);
			}
			if (chip->feature_bits &
			    (FEATURE_4BA_ENTER | FEATURE_4BA_ENTER_WREN | FEATURE_4BA_ENTER_EAR7 |
			     FEATURE_ANY_DUAL | FEATURE_ANY_QUAD)
			    && !chip->prepare_access) {
				msg_gerr("ERROR: Flash chip #%d (%s) misses chip\n"
					 "preparation function for 4BA and multi-i/o modes.\n"
					 "Please report a bug at flashprog@flashprog.org\n", i, name);
				ret = 1;
			}
			uint8_t zero_cycles[sizeof(chip->dummy_cycles)] = { 0 };
			if ((chip->feature_bits & (FEATURE_QPI_35_F5 | FEATURE_QPI_38_FF)) &&
			    !memcmp(&chip->dummy_cycles, zero_cycles, sizeof(zero_cycles))) {
				msg_gerr("ERROR: Flash chip #%d (%s) misses QPI dummy-cycle\n"
					 "settings. Please report a bug at flashprog@flashprog.org\n",
					 i, name);
				ret = 1;
			}
			if (chip->reg_bits.bp[0].reg != INVALID_REG &&
			    (!chip->wp_write_cfg || !chip->wp_read_cfg ||
			     !chip->wp_get_ranges || !chip->decode_range)) {
				msg_gerr("ERROR: Flash chip #%d (%s) advertises block-protection\n"
					 "bits, but misses one or more write-protection functions.\n"
					 "Please report a bug at flashprog@flashprog.org\n", i, name);
				ret = 1;
			}
			if (selfcheck_eraseblocks(chip)) {
				ret = 1;
			}
		}
	}

#if CONFIG_INTERNAL == 1
	ret |= selfcheck_board_enables();
#endif

	/* TODO: implement similar sanity checks for other arrays where deemed necessary. */
	return ret;
}

/* FIXME: This function signature needs to be improved once prepare_flash_access()
 * has a better function signature.
 */
static int chip_safety_check(const struct flashctx *flash, int force,
			     int read_it, int write_it, int erase_it, int verify_it)
{
	const struct flashchip *chip = flash->chip;

	if (!programmer_may_write && (write_it || erase_it)) {
		msg_perr("Write/erase is not working yet on your programmer in "
			 "its current configuration.\n");
		/* --force is the wrong approach, but it's the best we can do
		 * until the generic programmer parameter parser is merged.
		 */
		if (!force)
			return 1;
		msg_cerr("Continuing anyway.\n");
	}

	if (read_it || erase_it || write_it || verify_it) {
		/* Everything needs read. */
		if (chip->tested.read == BAD) {
			msg_cerr("Read is not working on this chip. ");
			if (!force)
				return 1;
			msg_cerr("Continuing anyway.\n");
		}
		if (!chip->read) {
			msg_cerr("flashprog has no read function for this "
				 "flash chip.\n");
			return 1;
		}
	}
	if (erase_it || write_it) {
		/* Write needs erase. */
		if (chip->tested.erase == NA) {
			msg_cerr("Erase is not possible on this chip.\n");
			return 1;
		}
		if (chip->tested.erase == BAD) {
			msg_cerr("Erase is not working on this chip. ");
			if (!force)
				return 1;
			msg_cerr("Continuing anyway.\n");
		}
		if(count_usable_erasers(flash) == 0) {
			msg_cerr("flashprog has no erase function for this "
				 "flash chip.\n");
			return 1;
		}
	}
	if (write_it) {
		if (chip->tested.write == NA) {
			msg_cerr("Write is not possible on this chip.\n");
			return 1;
		}
		if (chip->tested.write == BAD) {
			msg_cerr("Write is not working on this chip. ");
			if (!force)
				return 1;
			msg_cerr("Continuing anyway.\n");
		}
		if (!chip->write) {
			msg_cerr("flashprog has no write function for this "
				 "flash chip.\n");
			return 1;
		}
	}
	return 0;
}

int prepare_flash_access(struct flashctx *const flash,
			 const bool read_it, const bool write_it,
			 const bool erase_it, const bool verify_it)
{
	if (chip_safety_check(flash, flash->flags.force, read_it, write_it, erase_it, verify_it)) {
		msg_cerr("Aborting.\n");
		return 1;
	}

	if (layout_sanity_checks(flash, write_it)) {
		msg_cerr("Requested regions can not be handled. Aborting.\n");
		return 1;
	}

	if (flash->chip->prepare_access && flash->chip->prepare_access(flash, PREPARE_FULL))
		return 1;

	/* Initialize chip_restore_fn_count before chip unlock calls. */
	flash->chip_restore_fn_count = 0;

	/* Given the existence of read locks, we want to unlock for read,
	   erase and write. */
	if (flash->chip->unlock)
		flash->chip->unlock(flash);

	return 0;
}

void finalize_flash_access(struct flashctx *const flash)
{
	deregister_chip_restore(flash);
	if (flash->chip->finish_access)
		flash->chip->finish_access(flash);
}

/**
 * @addtogroup flashprog-flash
 * @{
 */

/**
 * @brief Erase the specified ROM chip.
 *
 * If a layout is set in the given flash context, only included regions
 * will be erased.
 *
 * @param flashctx The context of the flash chip to erase.
 * @return 0 on success.
 */
int flashprog_flash_erase(struct flashctx *const flashctx)
{
	if (prepare_flash_access(flashctx, false, false, true, false))
		return 1;

	const int ret = erase_by_layout(flashctx);

	finalize_flash_access(flashctx);

	return ret;
}

/** @} */ /* end flashprog-flash */

/**
 * @defgroup flashprog-ops Operations
 * @{
 */

/**
 * @brief Read the current image from the specified ROM chip.
 *
 * If a layout is set in the specified flash context, only included regions
 * will be read.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Target buffer to write image to.
 * @param buffer_len Size of target buffer in bytes.
 * @return 0 on success,
 *         2 if buffer_len is too short for the flash chip's contents,
 *         or 1 on any other failure.
 */
int flashprog_image_read(struct flashctx *const flashctx, void *const buffer, const size_t buffer_len)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;

	if (flash_size > buffer_len)
		return 2;

	if (prepare_flash_access(flashctx, true, false, false, false))
		return 1;

	msg_cinfo("Reading flash... ");

	int ret = 1;
	if (read_by_layout(flashctx, buffer)) {
		msg_cerr("Read operation failed!\n");
		msg_cinfo("FAILED.\n");
		goto _finalize_ret;
	}
	msg_cinfo("done.\n");
	ret = 0;

_finalize_ret:
	finalize_flash_access(flashctx);
	return ret;
}

static void combine_image_by_layout(const struct flashctx *const flashctx,
				    uint8_t *const newcontents, const uint8_t *const oldcontents)
{
	const struct flashprog_layout *const layout = get_layout(flashctx);
	const struct romentry *included;
	chipoff_t start = 0;

	while ((included = layout_next_included_region(layout, start))) {
		if (included->start > start) {
			/* copy everything up to the start of this included region */
			memcpy(newcontents + start, oldcontents + start, included->start - start);
		}
		/* skip this included region */
		start = included->end + 1;
		if (start == 0)
			return;
	}

	/* copy the rest of the chip */
	const chipsize_t copy_len = flashctx->chip->total_size * 1024 - start;
	memcpy(newcontents + start, oldcontents + start, copy_len);
}

/**
 * @brief Write the specified image to the ROM chip.
 *
 * If a layout is set in the specified flash context, only erase blocks
 * containing included regions will be touched.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Source buffer to read image from (may be altered for full verification).
 * @param buffer_len Size of source buffer in bytes.
 * @param refbuffer If given, assume flash chip contains same data as `refbuffer`.
 * @return 0 on success,
 *         4 if buffer_len doesn't match the size of the flash chip,
 *         3 if write was tried but nothing has changed,
 *         2 if write failed and flash contents changed,
 *         or 1 on any other failure.
 */
int flashprog_image_write(struct flashctx *const flashctx, void *const buffer, const size_t buffer_len,
                         const void *const refbuffer)
{
	const size_t flash_size = flashctx->chip->total_size * 1024;
	const bool verify_all = flashctx->flags.verify_whole_chip;
	const bool verify = flashctx->flags.verify_after_write;
	const struct flashprog_layout *const verify_layout =
		verify_all ? get_default_layout(flashctx) : get_layout(flashctx);

	if (buffer_len != flash_size)
		return 4;

	int ret = 1;

	uint8_t *const newcontents = buffer;
	const uint8_t *const refcontents = refbuffer;
	uint8_t *const curcontents = malloc(flash_size);
	uint8_t *oldcontents = NULL;
	if (verify_all)
		oldcontents = malloc(flash_size);
	if (!curcontents || (verify_all && !oldcontents)) {
		msg_gerr("Out of memory!\n");
		goto _free_ret;
	}

#if CONFIG_INTERNAL == 1
	if (programmer == &programmer_internal && cb_check_image(newcontents, flash_size) < 0) {
		if (flashctx->flags.force_boardmismatch) {
			msg_pinfo("Proceeding anyway because user forced us to.\n");
		} else {
			msg_perr("Aborting. You can override this with "
				 "-p internal:boardmismatch=force.\n");
			goto _free_ret;
		}
	}
#endif

	if (prepare_flash_access(flashctx, false, true, false, verify))
		goto _free_ret;

	/* If given, assume flash chip contains same data as `refcontents`. */
	if (refcontents) {
		msg_cinfo("Assuming old flash chip contents as ref-file...\n");
		memcpy(curcontents, refcontents, flash_size);
		if (oldcontents)
			memcpy(oldcontents, refcontents, flash_size);
	} else {
		/*
		 * Read the whole chip to be able to check whether regions need to be
		 * erased and to give better diagnostics in case write fails.
		 * The alternative is to read only the regions which are to be
		 * preserved, but in that case we might perform unneeded erase which
		 * takes time as well.
		 */
		msg_cinfo("Reading old flash chip contents... ");
		if (verify_all) {
			if (flashprog_read_range(flashctx, oldcontents, 0, flash_size)) {
				msg_cinfo("FAILED.\n");
				goto _finalize_ret;
			}
			memcpy(curcontents, oldcontents, flash_size);
		} else {
			if (read_by_layout(flashctx, curcontents)) {
				msg_cinfo("FAILED.\n");
				goto _finalize_ret;
			}
		}
		msg_cinfo("done.\n");
	}

	if (write_by_layout(flashctx, curcontents, newcontents)) {
		msg_cerr("Uh oh. Erase/write failed. ");
		ret = 2;
		if (verify_all) {
			msg_cerr("Checking if anything has changed.\n");
			msg_cinfo("Reading current flash chip contents... ");
			if (!flashprog_read_range(flashctx, curcontents, 0, flash_size)) {
				msg_cinfo("done.\n");
				if (!memcmp(oldcontents, curcontents, flash_size)) {
					nonfatal_help_message();
					goto _finalize_ret;
				}
				msg_cerr("Apparently at least some data has changed.\n");
			} else
				msg_cerr("Can't even read anymore!\n");
			emergency_help_message();
			goto _finalize_ret;
		} else {
			msg_cerr("\n");
		}
		emergency_help_message();
		goto _finalize_ret;
	}

	/* Verify only if we actually changed something. */
	if (verify && !all_skipped) {
		msg_cinfo("Verifying flash... ");

		if (verify_all)
			combine_image_by_layout(flashctx, newcontents, oldcontents);
		ret = verify_by_layout(flashctx, verify_layout, curcontents, newcontents);
		/* If we tried to write, and verification now fails, we
		   might have an emergency situation. */
		if (ret)
			emergency_help_message();
		else
			msg_cinfo("VERIFIED.\n");
	} else {
		/* We didn't change anything. */
		ret = 0;
	}

_finalize_ret:
	finalize_flash_access(flashctx);
_free_ret:
	free(oldcontents);
	free(curcontents);
	return ret;
}

/**
 * @brief Verify the ROM chip's contents with the specified image.
 *
 * If a layout is set in the specified flash context, only included regions
 * will be verified.
 *
 * @param flashctx The context of the flash chip.
 * @param buffer Source buffer to verify with.
 * @param buffer_len Size of source buffer in bytes.
 * @return 0 on success,
 *         3 if the chip's contents don't match,
 *         2 if buffer_len doesn't match the size of the flash chip,
 *         or 1 on any other failure.
 */
int flashprog_image_verify(struct flashctx *const flashctx, const void *const buffer, const size_t buffer_len)
{
	const struct flashprog_layout *const layout = get_layout(flashctx);
	const size_t flash_size = flashctx->chip->total_size * 1024;

	if (buffer_len != flash_size)
		return 2;

	const uint8_t *const newcontents = buffer;
	uint8_t *const curcontents = malloc(flash_size);
	if (!curcontents) {
		msg_gerr("Out of memory!\n");
		return 1;
	}

	int ret = 1;

	if (prepare_flash_access(flashctx, false, false, false, true))
		goto _free_ret;

	msg_cinfo("Verifying flash... ");
	ret = verify_by_layout(flashctx, layout, curcontents, newcontents);
	if (!ret)
		msg_cinfo("VERIFIED.\n");

	finalize_flash_access(flashctx);
_free_ret:
	free(curcontents);
	return ret;
}

/** @} */ /* end flashprog-ops */
