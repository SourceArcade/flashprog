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

#include "flash.h"
#include "cli.h"

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
