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

#ifndef FLASHPROG_CLI_H
#define FLASHPROG_CLI_H

#include "libflashprog.h"

enum {
	OPTION_VERBOSE = 'V',
	OPTION_LOGFILE = 'o',
	OPTION_CHIP = 'c',
	OPTION_PROGRAMMER = 'p',
	OPTION_LAYOUT = 'l',

	/* Options below have only long option names, i.e. no single char: */
	OPTION_IFD = 0x0100,
	OPTION_FMAP,
	OPTION_FMAP_FILE,
	OPTION_FLASH_CONTENTS,
	OPTION_FLASH_NAME,
	OPTION_FLASH_SIZE,
	OPTION_PROGRESS,
};

struct log_args {
	enum flashprog_log_level screen_level;
	enum flashprog_log_level logfile_level;
	char *logfile;
};

struct flash_args {
	char *chip;
	char *prog_name;
	char *prog_args;
};

struct layout_args {
	bool ifd;
	bool fmap;
	char *fmapfile;
	char *layoutfile;
};

int cli_check_filename(const char *filename, const char *type);

int cli_parse_log_args(struct log_args *, int opt, const char *optarg);
int cli_parse_flash_args(struct flash_args *, int opt, const char *optarg);
int cli_parse_layout_args(struct layout_args *, int opt, const char *optarg);
int cli_process_layout_args(struct flashprog_layout **, struct flashprog_flashctx *, const struct layout_args *);

#endif
