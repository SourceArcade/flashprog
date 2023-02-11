/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2009 Carl-Daniel Hailfinger
 * Copyright (C) 2011-2014 Stefan Tauner
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
#include <string.h>
#include <sys/stat.h>

#include "flash.h"
#include "cli.h"

int cli_check_filename(const char *const filename, const char *const type)
{
	if (!filename || (filename[0] == '\0')) {
		fprintf(stderr, "Error: No %s file specified.\n", type);
		return 1;
	}
	/* Not an error, but maybe the user intended to specify a CLI option instead of a file name. */
	if (filename[0] == '-' && filename[1] != '\0')
		fprintf(stderr, "Warning: Supplied %s file name starts with -\n", type);
	return 0;
}

int cli_parse_log_args(struct log_args *const args, const int opt, const char *const optarg)
{
	switch (opt) {
	case OPTION_VERBOSE:
		args->screen_level++;
		if (args->screen_level > FLASHPROG_MSG_DEBUG2)
			args->logfile_level = args->screen_level;
		break;
	case OPTION_LOGFILE:
		if (cli_check_filename(optarg, "log"))
			return 1;

		if (args->logfile) {
			fprintf(stderr, "Warning: -o/--output specified multiple times.\n");
			free(args->logfile);
		}

		args->logfile = strdup(optarg);
		if (!args->logfile) {
			fprintf(stderr, "Out of memory!\n");
			return 2;
		}
		break;
	}

	return 0;
}

int cli_parse_flash_args(struct flash_args *const args, const int opt, const char *const optarg)
{
	switch (opt) {
	case OPTION_PROGRAMMER:
		if (args->prog_name) {
			fprintf(stderr,
				"Error: --programmer specified more than once. You can separate multiple\n"
				"arguments for a programmer with ','. Please see the man page for details.\n");
			return 1;
		}
		const char *const colon = strchr(optarg, ':');
		if (colon) {
			args->prog_name = strndup(optarg, colon - optarg);
			args->prog_args = strdup(colon + 1);
		} else {
			args->prog_name = strdup(optarg);
		}
		if (!args->prog_name || (colon && !args->prog_args)) {
			fprintf(stderr, "Out of memory!\n");
			return 2;
		}
		break;
	case OPTION_CHIP:
		if (args->chip) {
			fprintf(stderr, "Error: --chip specified more than once.\n");
			return 1;
		}
		args->chip = strdup(optarg);
		if (!args->chip) {
			fprintf(stderr, "Out of memory!\n");
			return 2;
		}
		break;
	}

	return 0;
}

int cli_parse_layout_args(struct layout_args *const args, const int opt, const char *const optarg)
{
	if (args->layoutfile || args->ifd || args->fmap || args->fmapfile) {
		fprintf(stderr, "Error: Only one layout source may be specified.\n");
		return 1;
	}

	switch (opt) {
	case OPTION_LAYOUT:
		if (cli_check_filename(optarg, "layout"))
			return 1;

		args->layoutfile = strdup(optarg);
		if (!args->layoutfile) {
			fprintf(stderr, "Out of memory!\n");
			return 2;
		}
		break;
	case OPTION_IFD:
		args->ifd = true;
		break;
	case OPTION_FMAP:
		args->fmap = true;
		break;
	case OPTION_FMAP_FILE:
		if (cli_check_filename(optarg, "fmap"))
			return 1;

		args->fmapfile = strdup(optarg);
		if (!args->fmapfile) {
			fprintf(stderr, "Out of memory!\n");
			return 2;
		}
		break;
	}

	return 0;
}

int cli_process_layout_args(struct flashprog_layout **const layout,
			    struct flashprog_flashctx *const flash,
			    const struct layout_args *const args)
{
	*layout = NULL;

	if (args->layoutfile) {
		if (layout_from_file(layout, args->layoutfile))
			return 1;
	} else if (args->ifd) {
		if (flashprog_layout_read_from_ifd(layout, flash, NULL, 0))
			return 1;
	} else if (args->fmap) {
		if (flashprog_layout_read_fmap_from_rom(layout, flash, 0, flashprog_flash_getsize(flash)))
			return 1;
	} else if (args->fmapfile) {
		struct stat s;
		if (stat(args->fmapfile, &s) != 0) {
			msg_gerr("Failed to stat fmapfile \"%s\"\n", args->fmapfile);
			return 1;
		}

		size_t fmapfile_size = s.st_size;
		uint8_t *fmapfile_buffer = malloc(fmapfile_size);
		if (!fmapfile_buffer) {
			fprintf(stderr, "Out of memory!\n");
			return 1;
		}

		if (read_buf_from_file(fmapfile_buffer, fmapfile_size, args->fmapfile)) {
			free(fmapfile_buffer);
			return 1;
		}

		if (flashprog_layout_read_fmap_from_buffer(layout, flash, fmapfile_buffer, fmapfile_size)) {
			free(fmapfile_buffer);
			return 1;
		}
		free(fmapfile_buffer);
	}

	return 0;
}

void print_chip_support_status(const struct flashchip *chip)
{
	if (chip->feature_bits & FEATURE_OTP) {
		msg_cdbg("This chip may contain one-time programmable memory. flashprog cannot read\n"
			 "and may never be able to write it, hence it may not be able to completely\n"
			 "clone the contents of this chip (see man page for details).\n");
	}

	if ((chip->tested.erase == NA) && (chip->tested.write == NA)) {
		msg_cdbg("This chip's main memory can not be erased/written by design.\n");
	}

	if ((chip->tested.probe == BAD) || (chip->tested.probe == NT) ||
	    (chip->tested.read == BAD)  || (chip->tested.read == NT) ||
	    (chip->tested.erase == BAD) || (chip->tested.erase == NT) ||
	    (chip->tested.write == BAD) || (chip->tested.write == NT)) {
		msg_cinfo("===\n");
		if ((chip->tested.probe == BAD) ||
		    (chip->tested.read == BAD) ||
		    (chip->tested.erase == BAD) ||
		    (chip->tested.write == BAD)) {
			msg_cinfo("This flash part has status NOT WORKING for operations:");
			if (chip->tested.probe == BAD)
				msg_cinfo(" PROBE");
			if (chip->tested.read == BAD)
				msg_cinfo(" READ");
			if (chip->tested.erase == BAD)
				msg_cinfo(" ERASE");
			if (chip->tested.write == BAD)
				msg_cinfo(" WRITE");
			msg_cinfo("\n");
		}
		if ((chip->tested.probe == NT) ||
		    (chip->tested.read == NT) ||
		    (chip->tested.erase == NT) ||
		    (chip->tested.write == NT)) {
			msg_cinfo("This flash part has status UNTESTED for operations:");
			if (chip->tested.probe == NT)
				msg_cinfo(" PROBE");
			if (chip->tested.read == NT)
				msg_cinfo(" READ");
			if (chip->tested.erase == NT)
				msg_cinfo(" ERASE");
			if (chip->tested.write == NT)
				msg_cinfo(" WRITE");
			msg_cinfo("\n");
		}
		msg_cinfo("The test status of this chip may have been updated in the latest development\n"
			  "version of flashprog. If you are running the latest development version,\n"
			  "please email a report to flashprog@flashprog.org if any of the above\n"
			  "operations work correctly for you with this flash chip. Please include the\n"
			  "flashprog log file for all operations you tested (see the man page for details),\n"
			  "and mention which mainboard or programmer you tested in the subject line.\n"
			  "Thanks for your help!\n");
	}
}
