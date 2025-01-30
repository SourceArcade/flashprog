/*
 * This file is part of the flashprog project.
 *
 * Copyright (C) 2023 Nico Huber <nico.h@gmx.de>
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

#include <stdbool.h>

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
	OPTION_CONFIG_GET,
	OPTION_CONFIG_SET,
	OPTION_CONFIG_VOLATILE,
	OPTION_WP_STATUS,
	OPTION_WP_SET_RANGE,
	OPTION_WP_SET_REGION,
	OPTION_WP_ENABLE,
	OPTION_WP_DISABLE,
	OPTION_WP_LIST,
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

int cli_init(void);

int flashprog_classic_main(int argc, char *argv[]);
int flashprog_config_main(int argc, char *argv[]);
int flashprog_wp_main(int argc, char *argv[]);

extern enum flashprog_log_level verbose_screen;
extern enum flashprog_log_level verbose_logfile;
int open_logfile(const char * const filename);
int close_logfile(void);
void start_logging(void);

/* generic helper, like getopt_long() but without `--' prefix, re-uses `optind` */
struct opt_command {
	const char *name;
	int val;
};
int getopt_command(int argc, char *const argv[], const struct opt_command *);

void print_generic_options(bool layout_options);

#endif
