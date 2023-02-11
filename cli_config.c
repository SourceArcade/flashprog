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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>

#include "libflashprog.h"
#include "chipdrivers.h"
#include "flash.h"
#include "cli.h"

enum settings {
	QUAD_ENABLE,
};

static const struct reg_bit_info *get_bit_info(
		const struct flashctx *flash, enum settings setting)
{
	switch (setting) {
	case QUAD_ENABLE:
		return &flash->chip->reg_bits.qe;
	default:
		return NULL;
	}
}

static int config_get(const struct flashctx *flash, enum settings setting)
{
	const struct reg_bit_info *const bit = get_bit_info(flash, setting);
	uint8_t reg_val;

	if (!bit)
		return 1;

	const int ret = spi_read_register(flash, bit->reg, &reg_val);
	if (ret)
		return 1;

	printf("%u\n", reg_val >> bit->bit_index & 1);
	return 0;
}

static int config_set(const struct flashctx *flash, enum settings setting, unsigned int value)
{
	const struct reg_bit_info *const bit = get_bit_info(flash, setting);
	uint8_t reg_val;
	int ret;

	if (!bit)
		return 1;

	ret = spi_read_register(flash, bit->reg, &reg_val);
	if (ret)
		return 1;

	reg_val &= ~(1 << bit->bit_index);
	reg_val |= (value & 1) << bit->bit_index;

	ret = spi_write_register(flash, bit->reg, reg_val, default_wrsr_target(flash));
	if (ret)
		return 1;

	return 0;
}

static void usage(const char *const name, const char *const msg)
{
	if (msg)
		fprintf(stderr, "\nError: %s\n", msg);

	fprintf(stderr, "\nUsage:"
			"\t%s [get] <options> <setting>\n"
			"\t%s  set  <options> [--temporary] <setting> <value>\n",
			name, name);
	print_generic_options(/* layout_options =>*/false);
	fprintf(stderr, "\n<setting> can be\n"
			"    qe | quad-enable        Quad-Enable (QE) bit\n"
			"\nand <value> can be `true', `false', or a number.\n"
			"\nBy default, the setting is queried (`get').\n"
			"\n");
	exit(1);
}

static int parse_setting(const char *const setting)
{
	if (!strcmp(setting, "qe") ||
	    !strcmp(setting, "quad-enable"))
		return QUAD_ENABLE;
	return -1;
}

static int parse_value(const char *const value)
{
	if (!strcmp(value, "true"))
		return 1;
	if (!strcmp(value, "false"))
		return 0;

	char *endptr;
	const unsigned long i = strtoul(value, &endptr, 0);
	if (value[0] && !endptr[0] && i <= INT_MAX)
		return i;

	return -1;
}

int flashprog_config_main(int argc, char *argv[])
{
	static const char optstring[] = "+p:c:Vo:h";
	static const struct option long_options[] = {
		{"programmer",		1, NULL, 'p'},
		{"chip",		1, NULL, 'c'},
		{"verbose",		0, NULL, 'V'},
		{"output",		1, NULL, 'o'},
		{"help",		0, NULL, 'h'},
		{"get",			0, NULL, OPTION_CONFIG_GET},
		{"set",			0, NULL, OPTION_CONFIG_SET},
		{"temporary",		0, NULL, OPTION_CONFIG_VOLATILE},
		{NULL,			0, NULL, 0},
	};
	static const struct opt_command cmd_options[] = {
		{"get",		OPTION_CONFIG_GET},
		{"set",		OPTION_CONFIG_SET},
		{NULL,		0},
	};

	unsigned int ops = 0;
	int ret = 1, opt;
	struct log_args log_args = { FLASHPROG_MSG_INFO, FLASHPROG_MSG_DEBUG2, NULL };
	struct flash_args flash_args = { 0 };
	bool get = false, set = false, volat1le = false;

	if (cli_init()) /* TODO: Can be moved below argument parsing once usage() uses `stderr` directly. */
		goto free_ret;

	if (argc < 2)
		usage(argv[0], NULL);

	while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1 ||
	       (opt = getopt_command(argc, argv, cmd_options)) != -1) {
		switch (opt) {
		case 'V':
		case 'o':
			ret = cli_parse_log_args(&log_args, opt, optarg);
			if (ret == 1)
				usage(argv[0], NULL);
			else if (ret)
				goto free_ret;
			break;
		case 'p':
		case 'c':
			ret = cli_parse_flash_args(&flash_args, opt, optarg);
			if (ret == 1)
				usage(argv[0], NULL);
			else if (ret)
				goto free_ret;
			break;
		case OPTION_CONFIG_GET:
			get = true;
			++ops;
			break;
		case OPTION_CONFIG_SET:
			set = true;
			++ops;
			break;
		case OPTION_CONFIG_VOLATILE:
			volat1le = true;
			break;
		case '?':
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}

	if (!ops) {
		get = true;
		++ops;
	}

	if (ops > 1)
		usage(argv[0], "Only one operation may be specified.");

	if (!set && volat1le)
		usage(argv[0], "`--temporary' may only be specified for `set'.");
	if (get && optind != argc - 1)
		usage(argv[0], "`get' requires exactly one argument.");
	if (set && optind != argc - 2)
		usage(argv[0], "`set' requires exactly two arguments.");

	if (!flash_args.prog_name)
		usage(argv[0], "No programmer specified.");

	const int setting = parse_setting(argv[optind]);
	if (setting < 0) {
		fprintf(stderr, "\nError: Unknown <setting> argument `%s'.\n", argv[optind]);
		usage(argv[0], NULL);
	}
	int value = 0;
	if (set) {
		value = parse_value(argv[optind + 1]);
		if (value < 0) {
			fprintf(stderr, "\nError: Cannot parse value `%s'.\n", argv[optind + 1]);
			usage(argv[0], NULL);
		}
	}

	struct flashprog_programmer *prog;
	struct flashprog_flashctx *flash;
	ret = 1;

	if (log_args.logfile && open_logfile(log_args.logfile))
		goto free_ret;
	verbose_screen = log_args.screen_level;
	verbose_logfile = log_args.logfile_level;
	start_logging();

	if (flashprog_programmer_init(&prog, flash_args.prog_name, flash_args.prog_args))
		goto free_ret;
	if (flashprog_flash_probe(&flash, prog, flash_args.chip)) {
		fprintf(stderr, "No EEPROM/flash device found.\n");
		goto shutdown_ret;
	}

	if (flash->chip->bustype != BUS_SPI || flash->chip->spi_cmd_set != SPI25) {
		fprintf(stderr, "Only SPI25 flash chips are supported.\n");
		goto shutdown_ret;
	}

	flashprog_flag_set(flash, FLASHPROG_FLAG_NON_VOLATILE_WRSR, set && !volat1le);

	if (get)
		ret = config_get(flash, setting);

	if (set)
		ret = config_set(flash, setting, value);

	flashprog_flash_release(flash);
shutdown_ret:
	flashprog_programmer_shutdown(prog);
free_ret:
	free(flash_args.chip);
	free(flash_args.prog_args);
	free(flash_args.prog_name);
	free(log_args.logfile);
	close_logfile();
	return ret;
}
