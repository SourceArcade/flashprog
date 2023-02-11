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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "libflashprog.h"
#include "cli.h"

static void usage(const char *const name, const char *const msg)
{
	if (msg)
		fprintf(stderr, "\nError: %s\n", msg);

	fprintf(stderr, "\nUsage: %s [--volatile] [<operation>]\n"
			"\t\t\t\t-p <programmername>[:<parameters] [-c <chipname>]\n"
			"\t\t\t\t[--layout <layoutfile>|--fmap-file <fmapfile>|--fmap|--ifd]\n"
			"\t\t\t\t[-V[V[V]]] [-o <logfile>]\n", name);
	fprintf(stderr, "\nWhere <operation> can be\n\n"
			" --disable                Disable write protection\n"
			" --enable                 Enable write protection\n"
			" --list                   List supported write protection ranges\n"
			" --status                 Show write protection state\n"
			" --range <start>,<len>    Set write protection range (use --range=0,0\n"
			"                          to unprotect the entire flash)\n"
			" --region <region-name>   Set write protection region\n"
			"\n"
			"The default is '--status'.\n\n");
	exit(1);
}

static int parse_wp_range(size_t *const start, size_t *const len)
{
	char *endptr = NULL, *token = NULL;

	if (!optarg) {
		fprintf(stderr, "Error: No wp-range values provided\n");
		return -1;
	}

	token = strtok(optarg, ",");
	if (!token) {
		fprintf(stderr, "Error: Invalid wp-range argument format\n");
		return -1;
	}
	*start = strtoul(token, &endptr, 0);

	token = strtok(NULL, ",");
	if (!token) {
		fprintf(stderr, "Error: Invalid wp-range argument format\n");
		return -1;
	}
	*len = strtoul(token, &endptr, 0);

	return 0;
}

static int print_wp_range(struct flashprog_flashctx *const flash, size_t start, size_t len)
{
	/* Start address and length */
	printf("start=0x%08zx length=0x%08zx ", start, len);

	/* Easily readable description like 'none' or 'lower 1/8' */
	size_t chip_len = flashprog_flash_getsize(flash);

	if (len == 0) {
		printf("(none)");
	} else if (len == chip_len) {
		printf("(all)");
	} else {
		const char *location = "";
		if (start == 0)
			location = "lower ";
		if (start == chip_len - len)
			location = "upper ";

		/* Remove common factors of 2 to simplify */
		/* the (range_len/chip_len) fraction. */
		while ((chip_len % 2) == 0 && (len % 2) == 0) {
			chip_len /= 2;
			len /= 2;
		}

		printf("(%s%zu/%zu)", location, len, chip_len);
	}

	return 0;
}

static const char *get_wp_error_str(int err)
{
	switch (err) {
	case FLASHPROG_WP_ERR_CHIP_UNSUPPORTED:
		return "WP operations are not implemented for this chip";
	case FLASHPROG_WP_ERR_READ_FAILED:
		return "failed to read the current WP configuration";
	case FLASHPROG_WP_ERR_WRITE_FAILED:
		return "failed to write the new WP configuration";
	case FLASHPROG_WP_ERR_VERIFY_FAILED:
		return "unexpected WP configuration read back from chip";
	case FLASHPROG_WP_ERR_MODE_UNSUPPORTED:
		return "the requested protection mode is not supported";
	case FLASHPROG_WP_ERR_RANGE_UNSUPPORTED:
		return "the requested protection range is not supported";
	case FLASHPROG_WP_ERR_RANGE_LIST_UNAVAILABLE:
		return "could not determine what protection ranges are available";
	case FLASHPROG_WP_ERR_UNSUPPORTED_STATE:
		return "can't operate on current WP configuration of the chip";
	}
	return "unknown WP error";
}

static int wp_print_status(struct flashprog_flashctx *const flash)
{
	size_t start, len;
	enum flashprog_wp_mode mode;
	struct flashprog_wp_cfg *cfg = NULL;
	enum flashprog_wp_result ret;

	ret = flashprog_wp_cfg_new(&cfg);
	if (ret == FLASHPROG_WP_OK)
		ret = flashprog_wp_read_cfg(cfg, flash);

	if (ret != FLASHPROG_WP_OK) {
		fprintf(stderr, "Failed to get WP status: %s\n", get_wp_error_str(ret));
		flashprog_wp_cfg_release(cfg);
		return 1;
	}

	flashprog_wp_get_range(&start, &len, cfg);
	mode = flashprog_wp_get_mode(cfg);
	flashprog_wp_cfg_release(cfg);

	printf("Protection range: ");
	print_wp_range(flash, start, len);
	printf("\n");

	printf("Protection mode: ");
	switch (mode) {
	case FLASHPROG_WP_MODE_DISABLED:
		printf("disabled");
		break;
	case FLASHPROG_WP_MODE_HARDWARE:
		printf("hardware");
		break;
	case FLASHPROG_WP_MODE_POWER_CYCLE:
		printf("power_cycle");
		break;
	case FLASHPROG_WP_MODE_PERMANENT:
		printf("permanent");
		break;
	default:
		printf("unknown");
		break;
	}
	printf("\n");

	return 0;
}

static int wp_print_ranges(struct flashprog_flashctx *const flash)
{
	struct flashprog_wp_ranges *list;
	size_t i;

	const enum flashprog_wp_result ret = flashprog_wp_get_available_ranges(&list, flash);
	if (ret != FLASHPROG_WP_OK) {
		fprintf(stderr, "Failed to get list of protection ranges: %s\n", get_wp_error_str(ret));
		return 1;
	}

	printf("Available protection ranges:\n");
	const size_t count = flashprog_wp_ranges_get_count(list);
	for (i = 0; i < count; i++) {
		size_t start, len;

		flashprog_wp_ranges_get_range(&start, &len, list, i);
		printf("\t");
		print_wp_range(flash, start, len);
		printf("\n");
	}
	flashprog_wp_ranges_release(list);

	return 0;
}

static int wp_apply(struct flashprog_flashctx *const flash,
		    const bool enable_wp, const bool disable_wp,
		    const bool set_wp_range, const size_t wp_start, size_t wp_len)
{
	struct flashprog_wp_cfg *cfg;
	enum flashprog_wp_result ret;

	ret = flashprog_wp_cfg_new(&cfg);
	if (ret == FLASHPROG_WP_OK)
		ret = flashprog_wp_read_cfg(cfg, flash);

	if (ret != FLASHPROG_WP_OK) {
		fprintf(stderr, "Failed to get WP status: %s\n", get_wp_error_str(ret));
		flashprog_wp_cfg_release(cfg);
		return 1;
	}

	/* Store current WP mode for printing help text if changing the cfg fails. */
	const enum flashprog_wp_mode old_mode = flashprog_wp_get_mode(cfg);

	if (set_wp_range)
		flashprog_wp_set_range(cfg, wp_start, wp_len);

	if (disable_wp)
		flashprog_wp_set_mode(cfg, FLASHPROG_WP_MODE_DISABLED);

	if (enable_wp)
		flashprog_wp_set_mode(cfg, FLASHPROG_WP_MODE_HARDWARE);

	ret = flashprog_wp_write_cfg(flash, cfg);

	flashprog_wp_cfg_release(cfg);

	if (ret != FLASHPROG_WP_OK) {
		fprintf(stderr, "Failed to apply new WP settings: %s\n", get_wp_error_str(ret));

		/* Warn user if active WP is likely to have caused failure */
		if (ret == FLASHPROG_WP_ERR_VERIFY_FAILED) {
			switch (old_mode) {
			case FLASHPROG_WP_MODE_HARDWARE:
				fprintf(stderr, "Note: hardware status register protection is enabled. "
					"The chip's WP# pin must be set to an inactive voltage "
					"level to be able to change the WP settings.\n");
				break;
			case FLASHPROG_WP_MODE_POWER_CYCLE:
				fprintf(stderr, "Note: power-cycle status register protection is enabled. "
					"A power-off, power-on cycle is usually required to change "
					"the chip's WP settings.\n");
				break;
			case FLASHPROG_WP_MODE_PERMANENT:
				fprintf(stderr, "Note: permanent status register protection is enabled. "
					"The chip's WP settings cannot be modified.\n");
				break;
			default:
				break;
			}
		}

		return 1;
	}

	if (disable_wp)
		printf("Disabled hardware protection\n");

	if (enable_wp)
		printf("Enabled hardware protection\n");

	if (set_wp_range) {
		printf("Configured protection range: ");
		print_wp_range(flash, wp_start, wp_len);
		printf("\n");
	}

	return 0;
}

int flashprog_wp_main(int argc, char *argv[])
{
	static const char optstring[] = "p:c:l:Vo:h";
	static const struct option long_options[] = {
		{"programmer",		1, NULL, 'p'},
		{"chip",		1, NULL, 'c'},
		{"layout",		1, NULL, 'l'},
		{"ifd",			0, NULL, OPTION_IFD},
		{"fmap",		0, NULL, OPTION_FMAP},
		{"fmap-file",		1, NULL, OPTION_FMAP_FILE},
		{"volatile",		0, NULL, OPTION_CONFIG_VOLATILE},
		{"status",		0, NULL, OPTION_WP_STATUS},
		{"list",		0, NULL, OPTION_WP_LIST},
		{"range",		1, NULL, OPTION_WP_SET_RANGE},
		{"region",		1, NULL, OPTION_WP_SET_REGION},
		{"enable",		0, NULL, OPTION_WP_ENABLE},
		{"disable",		0, NULL, OPTION_WP_DISABLE},
		{"verbose",		0, NULL, 'V'},
		{"output",		1, NULL, 'o'},
		{"help",		0, NULL, 'h'},
		{NULL,			0, NULL, 0},
	};

	unsigned int ops = 0;
	int ret, opt, option_index;
	struct log_args log_args = { FLASHPROG_MSG_INFO, FLASHPROG_MSG_DEBUG2, NULL };
	struct flash_args flash_args = { 0 };
	struct layout_args layout_args = { 0 };
	bool volat1le = false;
	bool enable_wp = false, disable_wp = false, print_wp_status = false;
	bool set_wp_range = false, set_wp_region = false, print_wp_ranges = false;
	size_t wp_start = 0, wp_len = 0;
	char *wp_region = NULL;

	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &option_index)) != EOF) {
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
		case OPTION_LAYOUT:
		case OPTION_IFD:
		case OPTION_FMAP:
		case OPTION_FMAP_FILE:
			ret = cli_parse_layout_args(&layout_args, opt, optarg);
			if (ret == 1)
				usage(argv[0], NULL);
			else if (ret)
				goto free_ret;
			break;
		case OPTION_CONFIG_VOLATILE:
			volat1le = true;
			break;
		case OPTION_WP_STATUS:
			print_wp_status = true;
			++ops;
			break;
		case OPTION_WP_LIST:
			print_wp_ranges = true;
			++ops;
			break;
		case OPTION_WP_SET_RANGE:
			if (parse_wp_range(&wp_start, &wp_len) < 0)
				usage(argv[0], "Incorrect wp-range arguments provided.");
			set_wp_range = true;
			++ops;
			break;
		case OPTION_WP_SET_REGION:
			wp_region = strdup(optarg);
			if (!wp_region) {
				fprintf(stderr, "Out of memory!\n");
				goto free_ret;
			}
			set_wp_region = true;
			++ops;
			break;
		case OPTION_WP_ENABLE:
			enable_wp = true;
			++ops;
			break;
		case OPTION_WP_DISABLE:
			disable_wp = true;
			++ops;
			break;
		case '?':
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}

	if (optind < argc)
		usage(argv[0], "Extra parameter found.");

	if (!ops) {
		print_wp_status = true;
		++ops;
	}
	if (ops > 1)
		usage(argv[0], "Only one operation may be specified.");

	if (!flash_args.prog_name)
		usage(argv[0], "No programmer specified.");

	struct flashprog_programmer *prog;
	struct flashprog_flashctx *flash;
	struct flashprog_layout *layout = NULL;
	ret = 1;

	if (cli_init())
		goto free_ret;

	if (log_args.logfile && open_logfile(log_args.logfile))
		goto free_ret;
	verbose_screen = log_args.screen_level;
	verbose_logfile = log_args.logfile_level;
	start_logging();

	if (flashprog_programmer_init(&prog, flash_args.prog_name, flash_args.prog_args))
		goto free_ret;
	ret = flashprog_flash_probe(&flash, prog, flash_args.chip);
	if (ret == 3) {
		fprintf(stderr, "Multiple flash chip definitions match the detected chip.\n"
				"Please specify which chip definition to use with the -c <chipname> option.\n");
	} else if (ret) {
		fprintf(stderr, "No EEPROM/flash device found.\n");
		goto shutdown_ret;
	}

	flashprog_flag_set(flash, FLASHPROG_FLAG_NON_VOLATILE_WRSR, !volat1le);

	if (print_wp_status)
		ret = wp_print_status(flash);

	if (print_wp_ranges)
		ret = wp_print_ranges(flash);

	if (set_wp_region) {
		if (cli_process_layout_args(&layout, flash, &layout_args)) {
			fprintf(stderr, "Failed to read layout.\n");
			goto release_ret;
		}
		if (!layout) {
			fprintf(stderr, "Error: `--region` operation requires a layout.\n");
			goto release_ret;
		}

		if (flashprog_layout_get_region_range(layout, wp_region, &wp_start, &wp_len)) {
			fprintf(stderr, "Cannot find region '%s'.\n", wp_region);
			goto release_ret;
		}
		set_wp_range = true;
	}

	if (set_wp_range || enable_wp || disable_wp)
		ret = wp_apply(flash, enable_wp, disable_wp, set_wp_range, wp_start, wp_len);

release_ret:
	flashprog_layout_release(layout);
	flashprog_flash_release(flash);
shutdown_ret:
	flashprog_programmer_shutdown(prog);
free_ret:
	free(wp_region);
	free(layout_args.fmapfile);
	free(layout_args.layoutfile);
	free(flash_args.chip);
	free(flash_args.prog_args);
	free(flash_args.prog_name);
	free(log_args.logfile);
	close_logfile();
	return ret;
}
