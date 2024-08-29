/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2012, 2016 secunet Security Networks AG
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
/**
 * @mainpage
 *
 * Have a look at the Modules section for a function reference.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "flash.h"
#include "fmap.h"
#include "programmer.h"
#include "layout.h"
#include "ich_descriptors.h"
#include "libflashprog.h"
#include "writeprotect.h"

/**
 * @defgroup flashprog-general General
 * @{
 */

/** Pointer to log callback function. */
static flashprog_log_callback *global_log_callback = NULL;

/**
 * @brief Initialize libflashprog.
 *
 * @param perform_selfcheck If not zero, perform a self check.
 * @return 0 on success
 */
int flashprog_init(const int perform_selfcheck)
{
	if (perform_selfcheck && selfcheck())
		return 1;
	myusec_calibrate_delay();
	return 0;
}

/**
 * @brief Shut down libflashprog.
 * @return 0 on success
 */
int flashprog_shutdown(void)
{
	return 0; /* TODO: nothing to do? */
}

/* TODO: flashprog_set_loglevel()? do we need it?
         For now, let the user decide in their callback. */

/**
 * @brief Set the log callback function.
 *
 * Set a callback function which will be invoked whenever libflashprog wants
 * to output messages. This allows frontends to do whatever they see fit with
 * such messages, e.g. write them to syslog, or to file, or print them in a
 * GUI window, etc.
 *
 * @param log_callback Pointer to the new log callback function.
 */
void flashprog_set_log_callback(flashprog_log_callback *const log_callback)
{
	global_log_callback = log_callback;
}
/** @private */
int print(const enum flashprog_log_level level, const char *const fmt, ...)
{
	if (global_log_callback) {
		int ret;
		va_list args;
		va_start(args, fmt);
		ret = global_log_callback(level, fmt, args);
		va_end(args);
		return ret;
	}
	return 0;
}

/** @} */ /* end flashprog-general */



/**
 * @defgroup flashprog-query Querying
 * @{
 */

/* TBD */

/** @} */ /* end flashprog-query */



/**
 * @defgroup flashprog-prog Programmers
 * @{
 */

/**
 * @brief Initialize the specified programmer.
 *
 * Currently, only one programmer may be initialized at a time.
 *
 * @param[out] flashprog Points to a pointer of type struct flashprog_programmer
 *                       that will be set if programmer initialization succeeds.
 *                       *flashprog has to be shutdown by the caller with @ref
 *                       flashprog_programmer_shutdown.
 * @param[in] prog_name Name of the programmer to initialize.
 * @param[in] prog_param Pointer to programmer specific parameters.
 * @return 0 on success
 */
int flashprog_programmer_init(struct flashprog_programmer **const flashprog,
			     const char *const prog_name, const char *const prog_param)
{
	unsigned prog;

	for (prog = 0; prog < programmer_table_size; prog++) {
		if (strcmp(prog_name, programmer_table[prog]->name) == 0)
			break;
	}
	if (prog >= programmer_table_size) {
		msg_ginfo("Error: Unknown programmer \"%s\". Valid choices are:\n", prog_name);
		list_programmers_linebreak(0, 80, 0);
		msg_ginfo(".\n");
		return 1;
	}

	*flashprog = malloc(sizeof(**flashprog));
	if (!*flashprog) {
		msg_gerr("Out of memory!\n");
		return 1;
	}

	(*flashprog)->driver = programmer_table[prog];
	if (prog_param) {
		(*flashprog)->param = strdup(prog_param);
		if (!(*flashprog)->param) {
			msg_gerr("Out of memory!\n");
			goto _free_err;
		}
	} else {
		(*flashprog)->param = NULL;
	}

	if (programmer_init(*flashprog))
		goto _free_err;

	return 0;

_free_err:
	free((*flashprog)->param);
	free(*flashprog);
	return 1;
}

/**
 * @brief Shut down the initialized programmer.
 *
 * @param flashprog The programmer to shut down.
 * @return 0 on success
 */
int flashprog_programmer_shutdown(struct flashprog_programmer *const flashprog)
{
	if (programmer_shutdown(flashprog))
		return 1;
	free(flashprog);
	return 0;
}

/* TODO: flashprog_programmer_capabilities()? */

/** @} */ /* end flashprog-prog */



/**
 * @defgroup flashprog-flash Flash chips
 * @{
 */

/**
 * @brief Probe for a flash chip.
 *
 * Probes for a flash chip and returns a flash context, that can be used
 * later with flash chip and @ref flashprog-ops "image operations", if
 * exactly one matching chip is found.
 *
 * @param[out] flashctx Points to a pointer of type struct flashprog_flashctx
 *                      that will be set if exactly one chip is found. *flashctx
 *                      has to be freed by the caller with @ref flashprog_flash_release.
 * @param[in] flashprog The flash programmer used to access the chip.
 * @param[in] chip_name Name of a chip to probe for, or NULL to probe for
 *                      all known chips.
 * @return 0 on success,
 *         3 if multiple chips were found,
 *         2 if no chip was found,
 *         or 1 on any other error.
 */
int flashprog_flash_probe(struct flashprog_flashctx **const flashctx,
			 const struct flashprog_programmer *const flashprog,
			 const char *const chip_name)
{
	int i, ret = 2;
	struct flashprog_flashctx second_flashctx = { 0, };

	chip_to_probe = chip_name; /* chip_to_probe is global in flashprog.c */

	*flashctx = malloc(sizeof(**flashctx));
	if (!*flashctx)
		return 1;
	memset(*flashctx, 0, sizeof(**flashctx));

	for (i = 0; i < registered_master_count; ++i) {
		int flash_idx = -1;
		if (!ret || (flash_idx = probe_flash(&registered_masters[i], 0, *flashctx, 0)) != -1) {
			ret = 0;
			/* We found one chip, now check that there is no second match. */
			if (probe_flash(&registered_masters[i], flash_idx + 1, &second_flashctx, 0) != -1) {
				flashprog_layout_release(second_flashctx.default_layout);
				free(second_flashctx.chip);
				ret = 3;
				break;
			}
		}
	}
	if (ret) {
		flashprog_flash_release(*flashctx);
		*flashctx = NULL;
	}
	return ret;
}

/**
 * @brief Returns the size of the specified flash chip in bytes.
 *
 * @param flashctx The queried flash context.
 * @return Size of flash chip in bytes.
 */
size_t flashprog_flash_getsize(const struct flashprog_flashctx *const flashctx)
{
	return flashctx->chip->total_size * 1024;
}

/**
 * @brief Free a flash context.
 *
 * @param flashctx Flash context to free.
 */
void flashprog_flash_release(struct flashprog_flashctx *const flashctx)
{
	if (!flashctx)
		return;

	flashprog_layout_release(flashctx->default_layout);
	free(flashctx->chip);
	free(flashctx);
}

/**
 * @brief Set the progress callback function.
 *
 * Set a callback function which will be invoked whenever libflashprog wants
 * to indicate the progress has changed. This allows frontends to do whatever
 * they see fit with such values, e.g. update a progress bar in a GUI tool.
 *
 * @param flashctx Current flash context.
 * @param progress_callback Pointer to the new progress callback function.
 * @param user_data Pointer to any data the API user wants to have passed to the callback.
 */
void flashprog_set_progress_callback(struct flashprog_flashctx *const flashctx,
				    flashprog_progress_callback *const progress_callback,
				    void *const user_data)
{
	flashctx->progress.callback = progress_callback;
	flashctx->progress.user_data = user_data;
}

/**
 * @brief Set a flag in the given flash context.
 *
 * @param flashctx Flash context to alter.
 * @param flag	   Flag that is to be set / cleared.
 * @param value	   Value to set.
 */
void flashprog_flag_set(struct flashprog_flashctx *const flashctx,
		       const enum flashprog_flag flag, const bool value)
{
	switch (flag) {
		case FLASHPROG_FLAG_FORCE:		 flashctx->flags.force = value; break;
		case FLASHPROG_FLAG_FORCE_BOARDMISMATCH: flashctx->flags.force_boardmismatch = value; break;
		case FLASHPROG_FLAG_VERIFY_AFTER_WRITE:	 flashctx->flags.verify_after_write = value; break;
		case FLASHPROG_FLAG_VERIFY_WHOLE_CHIP:	 flashctx->flags.verify_whole_chip = value; break;
		case FLASHPROG_FLAG_NON_VOLATILE_WRSR:	 flashctx->flags.non_volatile_wrsr = value; break;
	}
}

/**
 * @brief Return the current value of a flag in the given flash context.
 *
 * @param flashctx Flash context to read from.
 * @param flag	   Flag to be read.
 * @return Current value of the flag.
 */
bool flashprog_flag_get(const struct flashprog_flashctx *const flashctx, const enum flashprog_flag flag)
{
	switch (flag) {
		case FLASHPROG_FLAG_FORCE:		 return flashctx->flags.force;
		case FLASHPROG_FLAG_FORCE_BOARDMISMATCH: return flashctx->flags.force_boardmismatch;
		case FLASHPROG_FLAG_VERIFY_AFTER_WRITE:	 return flashctx->flags.verify_after_write;
		case FLASHPROG_FLAG_VERIFY_WHOLE_CHIP:	 return flashctx->flags.verify_whole_chip;
		case FLASHPROG_FLAG_NON_VOLATILE_WRSR:	 return flashctx->flags.non_volatile_wrsr;
		default:				 return false;
	}
}

/** @} */ /* end flashprog-flash */



/**
 * @defgroup flashprog-layout Layout handling
 * @{
 */

/**
 * @brief Read a layout from the Intel ICH descriptor in the flash.
 *
 * Optionally verify that the layout matches the one in the given
 * descriptor dump.
 *
 * @param[out] layout Points to a struct flashprog_layout pointer that
 *                    gets set if the descriptor is read and parsed
 *                    successfully.
 * @param[in] flashctx Flash context to read the descriptor from flash.
 * @param[in] dump     The descriptor dump to compare to or NULL.
 * @param[in] len      The length of the descriptor dump.
 *
 * @return 0 on success,
 *         6 if descriptor parsing isn't implemented for the host,
 *         5 if the descriptors don't match,
 *         4 if the descriptor dump couldn't be parsed,
 *         3 if the descriptor on flash couldn't be parsed,
 *         2 if the descriptor on flash couldn't be read,
 *         1 on any other error.
 */
int flashprog_layout_read_from_ifd(struct flashprog_layout **const layout, struct flashctx *const flashctx,
				  const void *const dump, const size_t len)
{
#ifndef __FLASHPROG_LITTLE_ENDIAN__
	return 6;
#else
	struct flashprog_layout *dump_layout = NULL, *chip_layout = NULL;
	int ret = 1;

	void *const desc = malloc(0x1000);
	if (prepare_flash_access(flashctx, true, false, false, false))
		goto _free_ret;

	msg_cinfo("Reading ich descriptor... ");
	if (flashprog_read_range(flashctx, desc, 0, 0x1000)) {
		msg_cerr("Read operation failed!\n");
		msg_cinfo("FAILED.\n");
		ret = 2;
		goto _finalize_ret;
	}
	msg_cinfo("done.\n");

	if (layout_from_ich_descriptors(&chip_layout, desc, 0x1000)) {
		msg_cerr("Couldn't parse the descriptor!\n");
		ret = 3;
		goto _finalize_ret;
	}

	if (dump) {
		if (layout_from_ich_descriptors(&dump_layout, dump, len)) {
			msg_cerr("Couldn't parse the descriptor!\n");
			ret = 4;
			goto _finalize_ret;
		}

		const struct romentry *chip_entry = layout_next(chip_layout, NULL);
		const struct romentry *dump_entry = layout_next(dump_layout, NULL);
		while (chip_entry && dump_entry && !memcmp(chip_entry, dump_entry, sizeof(*chip_entry))) {
			chip_entry = layout_next(chip_layout, chip_entry);
			dump_entry = layout_next(dump_layout, dump_entry);
		}
		flashprog_layout_release(dump_layout);
		if (chip_entry || dump_entry) {
			msg_cerr("Descriptors don't match!\n");
			ret = 5;
			goto _finalize_ret;
		}
	}

	*layout = (struct flashprog_layout *)chip_layout;
	ret = 0;

_finalize_ret:
	finalize_flash_access(flashctx);
_free_ret:
	if (ret)
		flashprog_layout_release(chip_layout);
	free(desc);
	return ret;
#endif
}

#ifdef __FLASHPROG_LITTLE_ENDIAN__
static int flashprog_layout_parse_fmap(struct flashprog_layout **layout,
		struct flashctx *const flashctx, const struct fmap *const fmap)
{
	int i;
	char name[FMAP_STRLEN + 1];
	const struct fmap_area *area;
	struct flashprog_layout *l;

	if (!fmap || flashprog_layout_new(&l))
		return 1;

	for (i = 0, area = fmap->areas; i < fmap->nareas; i++, area++) {
		snprintf(name, sizeof(name), "%s", area->name);
		if (flashprog_layout_add_region(l, area->offset, area->offset + area->size - 1, name)) {
			flashprog_layout_release(l);
			return 1;
		}
	}

	*layout = l;
	return 0;
}
#endif /* __FLASHPROG_LITTLE_ENDIAN__ */

/**
 * @brief Read a layout by searching the flash chip for fmap.
 *
 * @param[out] layout Points to a struct flashprog_layout pointer that
 *                    gets set if the fmap is read and parsed successfully.
 * @param[in] flashctx Flash context
 * @param[in] offset Offset to begin searching for fmap.
 * @param[in] offset Length of address space to search.
 *
 * @return 0 on success,
 *         3 if fmap parsing isn't implemented for the host,
 *         2 if the fmap couldn't be read,
 *         1 on any other error.
 */
int flashprog_layout_read_fmap_from_rom(struct flashprog_layout **const layout,
		struct flashctx *const flashctx, size_t offset, size_t len)
{
#ifndef __FLASHPROG_LITTLE_ENDIAN__
	return 3;
#else
	struct fmap *fmap = NULL;
	int ret = 0;

	msg_gdbg("Attempting to read fmap from ROM content.\n");
	if (fmap_read_from_rom(&fmap, flashctx, offset, len)) {
		msg_gerr("Failed to read fmap from ROM.\n");
		return 1;
	}

	msg_gdbg("Adding fmap layout to global layout.\n");
	if (flashprog_layout_parse_fmap(layout, flashctx, fmap)) {
		msg_gerr("Failed to add fmap regions to layout.\n");
		ret = 1;
	}

	free(fmap);
	return ret;
#endif
}

/**
 * @brief Read a layout by searching buffer for fmap.
 *
 * @param[out] layout Points to a struct flashprog_layout pointer that
 *                    gets set if the fmap is read and parsed successfully.
 * @param[in] flashctx Flash context
 * @param[in] buffer Buffer to search in
 * @param[in] size Size of buffer to search
 *
 * @return 0 on success,
 *         3 if fmap parsing isn't implemented for the host,
 *         2 if the fmap couldn't be read,
 *         1 on any other error.
 */
int flashprog_layout_read_fmap_from_buffer(struct flashprog_layout **const layout,
		struct flashctx *const flashctx, const uint8_t *const buf, size_t size)
{
#ifndef __FLASHPROG_LITTLE_ENDIAN__
	return 3;
#else
	struct fmap *fmap = NULL;
	int ret = 1;

	if (!buf || !size)
		goto _ret;

	msg_gdbg("Attempting to read fmap from buffer.\n");
	if (fmap_read_from_buffer(&fmap, buf, size)) {
		msg_gerr("Failed to read fmap from buffer.\n");
		goto _ret;
	}

	msg_gdbg("Adding fmap layout to global layout.\n");
	if (flashprog_layout_parse_fmap(layout, flashctx, fmap)) {
		msg_gerr("Failed to add fmap regions to layout.\n");
		goto _free_ret;
	}

	ret = 0;
_free_ret:
	free(fmap);
_ret:
	return ret;
#endif
}

/**
 * @brief Set the active layout for a flash context.
 *
 * Note: This just sets a pointer. The caller must not release the layout
 *       as long as he uses it through the given flash context.
 *
 * @param flashctx Flash context whose layout will be set.
 * @param layout   Layout to bet set.
 */
void flashprog_layout_set(struct flashprog_flashctx *const flashctx, const struct flashprog_layout *const layout)
{
	flashctx->layout = layout;
}

/** @} */ /* end flashprog-layout */


/**
 * @defgroup flashprog-wp
 * @{
 */

/**
 * @brief Create a new empty WP configuration.
 *
 * @param[out] cfg Points to a pointer of type struct flashprog_wp_cfg that will
 *                 be set if creation succeeds. *cfg has to be freed by the
 *                 caller with @ref flashprog_wp_cfg_release.
 * @return  0 on success
 *         >0 on failure
 */
enum flashprog_wp_result flashprog_wp_cfg_new(struct flashprog_wp_cfg **cfg)
{
	*cfg = calloc(1, sizeof(**cfg));
	return *cfg ? 0 : FLASHPROG_WP_ERR_OTHER;
}

/**
 * @brief Free a WP configuration.
 *
 * @param[out] cfg Pointer to the flashprog_wp_cfg to free.
 */
void flashprog_wp_cfg_release(struct flashprog_wp_cfg *cfg)
{
	free(cfg);
}

/**
 * @brief Set the protection mode for a WP configuration.
 *
 * @param[in]  mode The protection mode to set.
 * @param[out] cfg  Pointer to the flashprog_wp_cfg structure to modify.
 */
void flashprog_wp_set_mode(struct flashprog_wp_cfg *cfg, enum flashprog_wp_mode mode)
{
	cfg->mode = mode;
}

/**
 * @brief Get the protection mode from a WP configuration.
 *
 * @param[in] cfg The WP configuration to get the protection mode from.
 * @return        The configuration's protection mode.
 */
enum flashprog_wp_mode flashprog_wp_get_mode(const struct flashprog_wp_cfg *cfg)
{
	return cfg->mode;
}

/**
 * @brief Set the protection range for a WP configuration.
 *
 * @param[out] cfg   Pointer to the flashprog_wp_cfg structure to modify.
 * @param[in]  start The range's start address.
 * @param[in]  len   The range's length.
 */
void flashprog_wp_set_range(struct flashprog_wp_cfg *cfg, size_t start, size_t len)
{
	cfg->range.start = start;
	cfg->range.len = len;
}

/**
 * @brief Get the protection range from a WP configuration.
 *
 * @param[out] start Points to a size_t to write the range start to.
 * @param[out] len   Points to a size_t to write the range length to.
 * @param[in]  cfg   The WP configuration to get the range from.
 */
void flashprog_wp_get_range(size_t *start, size_t *len, const struct flashprog_wp_cfg *cfg)
{
	*start = cfg->range.start;
	*len = cfg->range.len;
}

/**
 * @brief Write a WP configuration to a flash chip.
 *
 * @param[in] flash The flash context used to access the chip.
 * @param[in] cfg   The WP configuration to write to the chip.
 * @return  0 on success
 *         >0 on failure
 */
enum flashprog_wp_result flashprog_wp_write_cfg(struct flashctx *flash, const struct flashprog_wp_cfg *cfg)
{
	if (!flash->chip->wp_write_cfg)
		return FLASHPROG_WP_ERR_CHIP_UNSUPPORTED;

	return flash->chip->wp_write_cfg(flash, cfg);
}

/**
 * @brief Read the current WP configuration from a flash chip.
 *
 * @param[out] cfg   Pointer to a struct flashprog_wp_cfg to store the chip's
 *                   configuration in.
 * @param[in]  flash The flash context used to access the chip.
 * @return  0 on success
 *         >0 on failure
 */
enum flashprog_wp_result flashprog_wp_read_cfg(struct flashprog_wp_cfg *cfg, struct flashctx *flash)
{
	if (!flash->chip->wp_read_cfg)
		return FLASHPROG_WP_ERR_CHIP_UNSUPPORTED;

	return flash->chip->wp_read_cfg(cfg, flash);
}

/**
 * @brief Get a list of protection ranges supported by the flash chip.
 *
 * @param[out] ranges Points to a pointer of type struct flashprog_wp_ranges
 *                    that will be set if available ranges are found. Finding
 *                    available ranges may not always be possible, even if the
 *                    chip's protection range can be read or modified. *ranges
 *                    must be freed using @ref flashprog_wp_ranges_free.
 * @param[in] flash   The flash context used to access the chip.
 * @return  0 on success
 *         >0 on failure
 */
enum flashprog_wp_result flashprog_wp_get_available_ranges(struct flashprog_wp_ranges **list, struct flashprog_flashctx *flash)
{
	if (!flash->chip->wp_get_ranges)
		return FLASHPROG_WP_ERR_CHIP_UNSUPPORTED;

	return flash->chip->wp_get_ranges(list, flash);
}

/**
 * @brief Get a number of protection ranges in a range list.
 *
 * @param[in]  ranges The range list to get the count from.
 * @return Number of ranges in the list.
 */
size_t flashprog_wp_ranges_get_count(const struct flashprog_wp_ranges *list)
{
	return list->count;
}

/**
 * @brief Get a protection range from a range list.
 *
 * @param[out] start  Points to a size_t to write the range's start to.
 * @param[out] len    Points to a size_t to write the range's length to.
 * @param[in]  ranges The range list to get the range from.
 * @param[in]  index  Index of the range to get.
 * @return  0 on success
 *         >0 on failure
 */
enum flashprog_wp_result flashprog_wp_ranges_get_range(size_t *start, size_t *len, const struct flashprog_wp_ranges *list, unsigned int index)
{
	if (index >= list->count)
		return FLASHPROG_WP_ERR_OTHER;

	*start = list->ranges[index].start;
	*len = list->ranges[index].len;

	return 0;
}

/**
 * @brief Free a WP range list.
 *
 * @param[out] cfg Pointer to the flashprog_wp_ranges to free.
 */
void flashprog_wp_ranges_release(struct flashprog_wp_ranges *list)
{
	if (!list)
		return;

	free(list->ranges);
	free(list);
}


/** @} */ /* end flashprog-wp */
