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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "cli.h"

static const char *const command_prefixes[] = { "flashprog-", "flash", "f" };

static const struct {
	const char *name;
	int (*main)(int argc, char *argv[]);
} commands[] = {
	{ "prog",		flashprog_classic_main },
	{ "cfg",		flashprog_config_main },
	{ "config",		flashprog_config_main },
	{ "wp",			flashprog_wp_main },
	{ "write-protect",	flashprog_wp_main },
};

static void usage(const char *const name)
{
	fprintf(stderr, "\nUsage: %s [<command>] [<argument>...]\n", name);
	fprintf(stderr, "\nWhere <command> can be\n\n"
			" prog                     Standard memory operations\n"
			"                          (read/erase/write/verify)\n"
			" cfg | config             Status/config register operations\n"
			" wp | write-protect       Write-protection operations\n"
			"\n"
			"The default is 'prog'. See `%s <command> --help`\n"
			"for further instructions.\n\n", name);
	exit(1);
}

static int combine_argv01(char *argv[])
{
	const size_t len = strlen(argv[0]) + 1 + strlen(argv[1]) + 1;
	char *const argv0 = malloc(len);
	if (!argv0) {
		fprintf(stderr, "Out of memory!\n");
		return 1;
	}
	snprintf(argv0, len, "%s %s", argv[0], argv[1]);
	argv[1] = argv0;
	return 0;
}

int main(int argc, char *argv[])
{
	const char *cmd;
	size_t i;

	print_version();
	print_banner();

	if (argc < 1)
		usage("flashprog");

	/* Turn something like `./flashprog-cmd` into `flashprog-cmd`: */
	const char *const slash = strrchr(argv[0], '/');
	if (slash)
		cmd = slash + 1;
	else
		cmd = argv[0];

	if (strcmp(cmd, "flashprog")) {
		/* Strip command prefix, i.e. `flashprog-cmd` becomes `cmd`: */
		for (i = 0; i < ARRAY_SIZE(command_prefixes); ++i) {
			if (!strncmp(cmd, command_prefixes[i],
				     strlen(command_prefixes[i]))) {
				cmd += strlen(command_prefixes[i]);
				break;
			}
		}
	}

	/* Run `cmd` if found: */
	for (i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (!strcmp(cmd, commands[i].name))
			return commands[i].main(argc, argv);
	}

	/* Try to find command as first argument in argv[1]: */
	for (i = 0; argc >= 2 && i < ARRAY_SIZE(commands); ++i) {
		if (!strcmp(argv[1], commands[i].name)) {
			/* Squash argv[0] into argv[1]: */
			if (combine_argv01(argv))
				return 1;
			return commands[i].main(argc - 1, argv + 1);
		}
	}

	/* Bail if first argument looks like an
	   unknown command (i.e. not starting with `-'): */
	if (argc >= 2 && argv[1][0] != '-')
		usage(argv[0]);

	/* We're still here? Fall back to classic cli: */
	return flashprog_classic_main(argc, argv);
}
