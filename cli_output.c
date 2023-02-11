/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Sean Nelson <audiohacked@gmail.com>
 * Copyright (C) 2011 Carl-Daniel Hailfinger
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
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "flash.h"
#include "cli.h"

enum flashprog_log_level verbose_screen = FLASHPROG_MSG_INFO;
enum flashprog_log_level verbose_logfile = FLASHPROG_MSG_DEBUG2;

static FILE *logfile = NULL;

int close_logfile(void)
{
	if (!logfile)
		return 0;
	/* No need to call fflush() explicitly, fclose() already does that. */
	if (fclose(logfile)) {
		/* fclose returned an error. Stop writing to be safe. */
		logfile = NULL;
		msg_gerr("Closing the log file returned error %s\n", strerror(errno));
		return 1;
	}
	logfile = NULL;
	return 0;
}

int open_logfile(const char * const filename)
{
	if (!filename) {
		msg_gerr("No logfile name specified.\n");
		return 1;
	}
	if ((logfile = fopen(filename, "w")) == NULL) {
		msg_gerr("Error: opening log file \"%s\" failed: %s\n", filename, strerror(errno));
		return 1;
	}
	return 0;
}

void start_logging(void)
{
	enum flashprog_log_level oldverbose_screen = verbose_screen;

	/* Shut up the console. */
	verbose_screen = FLASHPROG_MSG_ERROR;
	print_version();
	verbose_screen = oldverbose_screen;
}

static const char *flashprog_progress_stage_to_string(enum flashprog_progress_stage stage)
{
	if (stage == FLASHPROG_PROGRESS_READ)
		return "Reading";
	if (stage == FLASHPROG_PROGRESS_WRITE)
		return "Writing";
	if (stage == FLASHPROG_PROGRESS_ERASE)
		return "Erasing";
	return "Progress";
}

static void print_progress_bar(enum flashprog_progress_stage stage, unsigned int pc)
{
	char progress_line[73], *bar;
	unsigned int i;

	const int bar_start = snprintf(progress_line, sizeof(progress_line), "%s... [",
				       flashprog_progress_stage_to_string(stage));

	for (bar = progress_line + bar_start, i = 0; i < pc; i += 2)
		*bar++ = '=';
	if (i < 100)
		*bar++ = '>', i += 2;
	for (; i < 100; i += 2)
		*bar++ = ' ';

	snprintf(bar, sizeof(progress_line) - (bar - progress_line), "] %3u%% ", pc);

	printf("\r%s", progress_line);
}

void flashprog_progress_cb(enum flashprog_progress_stage stage, size_t current, size_t total, void *user_data)
{
	static enum flashprog_progress_stage last_stage = (enum flashprog_progress_stage)-1;
	static unsigned int last_pc = (unsigned int)-1;

	const unsigned int pc = total ? (current * 100ull) / total : 100;

	if (last_stage == stage && last_pc == pc)
		return;

	if (last_stage != stage || pc == 0)
		printf("\n");

	print_progress_bar(stage, pc);
	last_stage = stage;
	last_pc = pc;
}

/* Please note that level is the verbosity, not the importance of the message. */
int flashprog_print_cb(enum flashprog_log_level level, const char *fmt, va_list ap)
{
	int ret = 0;
	FILE *output_type = stdout;

	va_list logfile_args;
	va_copy(logfile_args, ap);

	if (level < FLASHPROG_MSG_INFO)
		output_type = stderr;

	if (level <= verbose_screen) {
		ret = vfprintf(output_type, fmt, ap);
		/* msg_*spew often happens inside chip accessors in possibly
		 * time-critical operations. Don't slow them down by flushing. */
		if (level != FLASHPROG_MSG_SPEW)
			fflush(output_type);
	}

	if ((level <= verbose_logfile) && logfile) {
		ret = vfprintf(logfile, fmt, logfile_args);
		if (level != FLASHPROG_MSG_SPEW)
			fflush(logfile);
	}

	va_end(logfile_args);
	return ret;
}
