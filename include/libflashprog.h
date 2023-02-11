/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2010 Google Inc.
 * Copyright (C) 2012 secunet Security Networks AG
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

#ifndef __LIBFLASHPROG_H__
#define __LIBFLASHPROG_H__ 1

#include <sys/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

int flashprog_init(int perform_selfcheck);
int flashprog_shutdown(void);
/** @ingroup flashprog-general */
enum flashprog_log_level {
	FLASHPROG_MSG_ERROR	= 0,
	FLASHPROG_MSG_WARN	= 1,
	FLASHPROG_MSG_INFO	= 2,
	FLASHPROG_MSG_DEBUG	= 3,
	FLASHPROG_MSG_DEBUG2	= 4,
	FLASHPROG_MSG_SPEW	= 5,
};
/** @ingroup flashprog-general */
typedef int(flashprog_log_callback)(enum flashprog_log_level, const char *format, va_list);
void flashprog_set_log_callback(flashprog_log_callback *);

/** @ingroup flashprog-prog */
struct flashprog_programmer;
int flashprog_programmer_init(struct flashprog_programmer **, const char *prog_name, const char *prog_params);
int flashprog_programmer_shutdown(struct flashprog_programmer *);

struct flashprog_flashctx;
int flashprog_flash_probe(struct flashprog_flashctx **, const struct flashprog_programmer *, const char *chip_name);
size_t flashprog_flash_getsize(const struct flashprog_flashctx *);
int flashprog_flash_erase(struct flashprog_flashctx *);
void flashprog_flash_release(struct flashprog_flashctx *);

enum flashprog_progress_stage {
	FLASHPROG_PROGRESS_READ,
	FLASHPROG_PROGRESS_WRITE,
	FLASHPROG_PROGRESS_ERASE,
};
typedef void(flashprog_progress_callback)(enum flashprog_progress_stage, size_t current, size_t total, void *user_data);
void flashprog_set_progress_callback(struct flashprog_flashctx *, flashprog_progress_callback *, void *user_data);

/** @ingroup flashprog-flash */
enum flashprog_flag {
	FLASHPROG_FLAG_FORCE,
	FLASHPROG_FLAG_FORCE_BOARDMISMATCH,
	FLASHPROG_FLAG_VERIFY_AFTER_WRITE,
	FLASHPROG_FLAG_VERIFY_WHOLE_CHIP,
	FLASHPROG_FLAG_NON_VOLATILE_WRSR,
};
void flashprog_flag_set(struct flashprog_flashctx *, enum flashprog_flag, bool value);
bool flashprog_flag_get(const struct flashprog_flashctx *, enum flashprog_flag);

int flashprog_image_read(struct flashprog_flashctx *, void *buffer, size_t buffer_len);
int flashprog_image_write(struct flashprog_flashctx *, void *buffer, size_t buffer_len, const void *refbuffer);
int flashprog_image_verify(struct flashprog_flashctx *, const void *buffer, size_t buffer_len);

struct flashprog_layout;
int flashprog_layout_new(struct flashprog_layout **);
int flashprog_layout_read_from_ifd(struct flashprog_layout **, struct flashprog_flashctx *, const void *dump, size_t len);
int flashprog_layout_read_fmap_from_rom(struct flashprog_layout **,
		struct flashprog_flashctx *, size_t offset, size_t length);
int flashprog_layout_read_fmap_from_buffer(struct flashprog_layout **layout,
		struct flashprog_flashctx *, const uint8_t *buf, size_t len);
int flashprog_layout_add_region(struct flashprog_layout *, size_t start, size_t end, const char *name);
int flashprog_layout_include_region(struct flashprog_layout *, const char *name);
int flashprog_layout_get_region_range(const struct flashprog_layout *, const char *name, size_t *start, size_t *len);
void flashprog_layout_release(struct flashprog_layout *);
void flashprog_layout_set(struct flashprog_flashctx *, const struct flashprog_layout *);

/** @ingroup flashprog-wp */
enum flashprog_wp_result {
	FLASHPROG_WP_OK = 0,
	FLASHPROG_WP_ERR_CHIP_UNSUPPORTED = 1,
	FLASHPROG_WP_ERR_OTHER = 2,
	FLASHPROG_WP_ERR_READ_FAILED = 3,
	FLASHPROG_WP_ERR_WRITE_FAILED = 4,
	FLASHPROG_WP_ERR_VERIFY_FAILED = 5,
	FLASHPROG_WP_ERR_RANGE_UNSUPPORTED = 6,
	FLASHPROG_WP_ERR_MODE_UNSUPPORTED = 7,
	FLASHPROG_WP_ERR_RANGE_LIST_UNAVAILABLE = 8,
	FLASHPROG_WP_ERR_UNSUPPORTED_STATE = 9,
};

enum flashprog_wp_mode {
	FLASHPROG_WP_MODE_DISABLED,
	FLASHPROG_WP_MODE_HARDWARE,
	FLASHPROG_WP_MODE_POWER_CYCLE,
	FLASHPROG_WP_MODE_PERMANENT
};
struct flashprog_wp_cfg;
struct flashprog_wp_ranges;

enum flashprog_wp_result flashprog_wp_cfg_new(struct flashprog_wp_cfg **);
void flashprog_wp_cfg_release(struct flashprog_wp_cfg *);
void flashprog_wp_set_mode(struct flashprog_wp_cfg *, enum flashprog_wp_mode);
enum flashprog_wp_mode flashprog_wp_get_mode(const struct flashprog_wp_cfg *);
void flashprog_wp_set_range(struct flashprog_wp_cfg *, size_t start, size_t len);
void flashprog_wp_get_range(size_t *start, size_t *len, const struct flashprog_wp_cfg *);

enum flashprog_wp_result flashprog_wp_read_cfg(struct flashprog_wp_cfg *, struct flashprog_flashctx *);
enum flashprog_wp_result flashprog_wp_write_cfg(struct flashprog_flashctx *, const struct flashprog_wp_cfg *);

enum flashprog_wp_result flashprog_wp_get_available_ranges(struct flashprog_wp_ranges **, struct flashprog_flashctx *);
size_t flashprog_wp_ranges_get_count(const struct flashprog_wp_ranges *);
enum flashprog_wp_result flashprog_wp_ranges_get_range(size_t *start, size_t *len, const struct flashprog_wp_ranges *, unsigned int index);
void flashprog_wp_ranges_release(struct flashprog_wp_ranges *);

#endif				/* !__LIBFLASHPROG_H__ */
