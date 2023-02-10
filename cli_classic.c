/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2000 Silicon Integrated System Corporation
 * Copyright (C) 2004 Tyan Corp <yhlu@tyan.com>
 * Copyright (C) 2005-2008 coresystems GmbH
 * Copyright (C) 2008,2009,2010 Carl-Daniel Hailfinger
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
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include "flash.h"
#include "flashchips.h"
#include "fmap.h"
#include "programmer.h"
#include "libflashprog.h"
#include "cli.h"

static void cli_classic_usage(const char *name)
{
	printf("Usage: %s [-h|-R|-L|"
#if CONFIG_PRINT_WIKI == 1
	       "-z|"
#endif
	       "\n\t-p <programmername>[:<parameters>] [-c <chipname>]\n"
	       "\t\t(--flash-name|--flash-size|\n"
	       "\t\t [-E|(-r|-w|-v) <file>]\n"
	       "\t\t [(-l <layoutfile>|--ifd| --fmap|--fmap-file <file>) [-i <imagename>]...]\n"
	       "\t\t [-n] [-N] [-f])]\n"
	       "\t[-V[V[V]]] [-o <logfile>]\n\n", name);

	printf(" -h | --help                        print this help text\n"
	       " -R | --version                     print version (release)\n"
	       " -r | --read <file>                 read flash and save to <file>\n"
	       " -w | --write (<file>|-)            write <file> or the content provided\n"
	       "                                    on the standard input to flash\n"
	       " -v | --verify (<file>|-)           verify flash against <file>\n"
	       "                                    or the content provided on the standard input\n"
	       " -E | --erase                       erase flash memory\n"
	       " -V | --verbose                     more verbose output\n"
	       " -c | --chip <chipname>             probe only for specified flash chip\n"
	       " -f | --force                       force specific operations (see man page)\n"
	       " -n | --noverify                    don't auto-verify\n"
	       " -N | --noverify-all                verify included regions only (cf. -i)\n"
	       " -l | --layout <layoutfile>         read ROM layout from <layoutfile>\n"
	       "      --flash-name                  read out the detected flash name\n"
	       "      --flash-size                  read out the detected flash size\n"
	       "      --fmap                        read ROM layout from fmap embedded in ROM\n"
	       "      --fmap-file <fmapfile>        read ROM layout from fmap in <fmapfile>\n"
	       "      --ifd                         read layout from an Intel Firmware Descriptor\n"
	       " -i | --include <region>            only read/write image <region> from layout\n"
	       "      --image <region>              deprecated, please use --include\n"
	       " -o | --output <logfile>            log output to <logfile>\n"
	       "      --flash-contents <ref-file>   assume flash contents to be <ref-file>\n"
	       " -L | --list-supported              print supported devices\n"
#if CONFIG_PRINT_WIKI == 1
	       " -z | --list-supported-wiki         print supported devices in wiki syntax\n"
#endif
	       "      --progress                    show progress percentage on the standard output\n"
	       " -p | --programmer <name>[:<param>] specify the programmer device. One of\n");
	list_programmers_linebreak(4, 80, 0);
	printf(".\n\nYou can specify one of -h, -R, -L, "
#if CONFIG_PRINT_WIKI == 1
	         "-z, "
#endif
	         "-E, -r, -w, -v or no operation.\n"
	       "If no operation is specified, flashprog will only probe for flash chips.\n");
}

static void cli_classic_abort_usage(const char *msg)
{
	if (msg)
		fprintf(stderr, "%s", msg);
	printf("Please run \"flashprog --help\" for usage info.\n");
	exit(1);
}

static void cli_classic_validate_singleop(int *operation_specified)
{
	if (++(*operation_specified) > 1) {
		cli_classic_abort_usage("More than one operation specified. Aborting.\n");
	}
}

/* Ensure a file is open by means of fstat */
static bool check_file(FILE *file)
{
	struct stat statbuf;

	if (fstat(fileno(file), &statbuf) < 0)
		return false;
	return true;
}

static int do_read(struct flashctx *const flash, const char *const filename)
{
	int ret;

	unsigned long size = flashprog_flash_getsize(flash);
	unsigned char *buf = calloc(size, sizeof(unsigned char));
	if (!buf) {
		msg_gerr("Memory allocation failed!\n");
		return 1;
	}

	ret = flashprog_image_read(flash, buf, size);
	if (ret > 0)
		goto free_out;

	ret = write_buf_to_file(buf, size, filename);

free_out:
	free(buf);
	return ret;
}

static int do_write(struct flashctx *const flash, const char *const filename, const char *const referencefile)
{
	const size_t flash_size = flashprog_flash_getsize(flash);
	int ret = 1;

	uint8_t *const newcontents = malloc(flash_size);
	uint8_t *const refcontents = referencefile ? malloc(flash_size) : NULL;

	if (!newcontents || (referencefile && !refcontents)) {
		msg_gerr("Out of memory!\n");
		goto _free_ret;
	}

	if (read_buf_from_file(newcontents, flash_size, filename))
		goto _free_ret;

	if (referencefile) {
		if (read_buf_from_file(refcontents, flash_size, referencefile))
			goto _free_ret;
	}

	ret = flashprog_image_write(flash, newcontents, flash_size, refcontents);

_free_ret:
	free(refcontents);
	free(newcontents);
	return ret;
}

static int do_verify(struct flashctx *const flash, const char *const filename)
{
	const size_t flash_size = flashprog_flash_getsize(flash);
	int ret = 1;

	uint8_t *const newcontents = malloc(flash_size);
	if (!newcontents) {
		msg_gerr("Out of memory!\n");
		goto _free_ret;
	}

	if (read_buf_from_file(newcontents, flash_size, filename))
		goto _free_ret;

	ret = flashprog_image_verify(flash, newcontents, flash_size);

_free_ret:
	free(newcontents);
	return ret;
}

/* Returns true if the flash chip cannot be completely accessed due to size/address limits of the programmer. */
static bool max_decode_exceeded(const struct registered_master *const mst, const struct flashctx *const flash)
{
	if (flashprog_flash_getsize(flash) <= mst->max_rom_decode)
		return false;

	msg_pdbg("Chip size %u kB is bigger than supported size %zu kB of\n"
		 "chipset/board/programmer for memory-mapped interface, probe/read/erase/write\n"
		 "may fail.\n", flash->chip->total_size, mst->max_rom_decode / KiB);
	return true;
}

int main(int argc, char *argv[])
{
	const struct flashchip *chip = NULL;
	/* Probe for up to eight flash chips. */
	struct flashctx flashes[8] = {{0}};
	struct flashctx *fill_flash;
	int opt, i, j;
	int startchip = -1, chipcount = 0, option_index = 0;
	int operation_specified = 0;
	bool force = false;
#if CONFIG_PRINT_WIKI == 1
	bool list_supported_wiki = false;
#endif
	bool flash_name = false, flash_size = false;
	bool read_it = false, write_it = false, erase_it = false, verify_it = false;
	bool dont_verify_it = false, dont_verify_all = false;
	bool list_supported = false;
	bool show_progress = false;
	struct flashprog_layout *layout = NULL;
	struct flashprog_programmer *prog = NULL;
	int ret = 0;

	static const char optstring[] = "r:Rw:v:nNVEfc:l:i:p:Lzho:";
	static const struct option long_options[] = {
		{"read",		1, NULL, 'r'},
		{"write",		1, NULL, 'w'},
		{"erase",		0, NULL, 'E'},
		{"verify",		1, NULL, 'v'},
		{"noverify",		0, NULL, 'n'},
		{"noverify-all",	0, NULL, 'N'},
		{"chip",		1, NULL, 'c'},
		{"verbose",		0, NULL, 'V'},
		{"force",		0, NULL, 'f'},
		{"layout",		1, NULL, 'l'},
		{"ifd",			0, NULL, OPTION_IFD},
		{"fmap",		0, NULL, OPTION_FMAP},
		{"fmap-file",		1, NULL, OPTION_FMAP_FILE},
		{"image",		1, NULL, 'i'}, // (deprecated): back compatibility.
		{"include",		1, NULL, 'i'},
		{"flash-contents",	1, NULL, OPTION_FLASH_CONTENTS},
		{"flash-name",		0, NULL, OPTION_FLASH_NAME},
		{"flash-size",		0, NULL, OPTION_FLASH_SIZE},
		{"get-size",		0, NULL, OPTION_FLASH_SIZE}, // (deprecated): back compatibility.
		{"list-supported",	0, NULL, 'L'},
		{"list-supported-wiki",	0, NULL, 'z'},
		{"programmer",		1, NULL, 'p'},
		{"help",		0, NULL, 'h'},
		{"version",		0, NULL, 'R'},
		{"output",		1, NULL, 'o'},
		{"progress",		0, NULL, OPTION_PROGRESS},
		{NULL,			0, NULL, 0},
	};

	char *filename = NULL;
	char *referencefile = NULL;
	char *logfile = NULL;
	char *tempstr = NULL;
	struct flash_args flash_args = { 0 };
	struct layout_args layout_args = { 0 };
	struct layout_include_args *include_args = NULL;

	/*
	 * Safety-guard against a user who has (mistakenly) closed
	 * stdout or stderr before exec'ing flashprog.  We disable
	 * logging in this case to prevent writing log data to a flash
	 * chip when a flash device gets opened with fd 1 or 2.
	 */
	if (check_file(stdout) && check_file(stderr)) {
		flashprog_set_log_callback(
			(flashprog_log_callback *)&flashprog_print_cb);
	}

	print_version();
	print_banner();

	/* FIXME: Delay calibration should happen in programmer code. */
	if (flashprog_init(1))
		exit(1);

	setbuf(stdout, NULL);
	/* FIXME: Delay all operation_specified checks until after command
	 * line parsing to allow --help overriding everything else.
	 */
	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, &option_index)) != EOF) {
		switch (opt) {
		case 'r':
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			read_it = true;
			break;
		case 'w':
			cli_classic_validate_singleop(&operation_specified);
			filename = strdup(optarg);
			write_it = true;
			break;
		case 'v':
			//FIXME: gracefully handle superfluous -v
			cli_classic_validate_singleop(&operation_specified);
			if (dont_verify_it) {
				cli_classic_abort_usage("--verify and --noverify are mutually exclusive. Aborting.\n");
			}
			filename = strdup(optarg);
			verify_it = true;
			break;
		case 'n':
			if (verify_it) {
				cli_classic_abort_usage("--verify and --noverify are mutually exclusive. Aborting.\n");
			}
			dont_verify_it = true;
			break;
		case 'N':
			dont_verify_all = true;
			break;
		case 'c':
		case 'p':
			ret = cli_parse_flash_args(&flash_args, opt, optarg);
			if (ret == 1)
				cli_classic_abort_usage(NULL);
			else if (ret)
				exit(1);
			break;
		case 'V':
			verbose_screen++;
			if (verbose_screen > FLASHPROG_MSG_DEBUG2)
				verbose_logfile = verbose_screen;
			break;
		case 'E':
			cli_classic_validate_singleop(&operation_specified);
			erase_it = true;
			break;
		case 'f':
			force = true;
			break;
		case OPTION_LAYOUT:
		case OPTION_IFD:
		case OPTION_FMAP:
		case OPTION_FMAP_FILE:
			ret = cli_parse_layout_args(&layout_args, opt, optarg);
			if (ret == 1)
				cli_classic_abort_usage(NULL);
			else if (ret)
				exit(1);
			break;
		case 'i':
			tempstr = strdup(optarg);
			if (register_include_arg(&include_args, tempstr)) {
				free(tempstr);
				cli_classic_abort_usage(NULL);
			}
			break;
		case OPTION_FLASH_CONTENTS:
			if (referencefile)
				cli_classic_abort_usage("Error: --flash-contents specified more than once."
							"Aborting.\n");
			referencefile = strdup(optarg);
			break;
		case OPTION_FLASH_NAME:
			cli_classic_validate_singleop(&operation_specified);
			flash_name = true;
			break;
		case OPTION_FLASH_SIZE:
			cli_classic_validate_singleop(&operation_specified);
			flash_size = true;
			break;
		case 'L':
			cli_classic_validate_singleop(&operation_specified);
			list_supported = true;
			break;
		case 'z':
#if CONFIG_PRINT_WIKI == 1
			cli_classic_validate_singleop(&operation_specified);
			list_supported_wiki = true;
#else
			cli_classic_abort_usage("Error: Wiki output was not "
					"compiled in. Aborting.\n");
#endif
			break;
		case 'R':
			/* print_version() is always called during startup. */
			cli_classic_validate_singleop(&operation_specified);
			exit(0);
			break;
		case 'h':
			cli_classic_validate_singleop(&operation_specified);
			cli_classic_usage(argv[0]);
			exit(0);
			break;
		case 'o':
			if (logfile) {
				fprintf(stderr, "Warning: -o/--output specified multiple times.\n");
				free(logfile);
			}

			logfile = strdup(optarg);
			if (logfile[0] == '\0') {
				cli_classic_abort_usage("No log filename specified.\n");
			}
			break;
		case OPTION_PROGRESS:
			show_progress = true;
			break;
		default:
			cli_classic_abort_usage(NULL);
			break;
		}
	}

	if (optind < argc)
		cli_classic_abort_usage("Error: Extra parameter found.\n");
	if ((read_it | write_it | verify_it) && cli_check_filename(filename, "image"))
		cli_classic_abort_usage(NULL);
	if (referencefile && cli_check_filename(referencefile, "reference"))
		cli_classic_abort_usage(NULL);
	if (logfile && cli_check_filename(logfile, "log"))
		cli_classic_abort_usage(NULL);
	if (logfile && open_logfile(logfile))
		cli_classic_abort_usage(NULL);

#if CONFIG_PRINT_WIKI == 1
	if (list_supported_wiki) {
		print_supported_wiki();
		goto out;
	}
#endif

	if (list_supported) {
		if (print_supported())
			ret = 1;
		goto out;
	}

	start_logging();

	print_buildinfo();
	msg_gdbg("Command line (%i args):", argc - 1);
	for (i = 0; i < argc; i++) {
		msg_gdbg(" %s", argv[i]);
	}
	msg_gdbg("\n");

	if (layout_args.layoutfile && layout_from_file(&layout, layout_args.layoutfile)) {
		ret = 1;
		goto out;
	}

	if (!layout_args.ifd && !layout_args.fmap && !layout_args.fmapfile &&
	    process_include_args(layout, include_args)) {
		ret = 1;
		goto out;
	}
	/* Does a chip with the requested name exist in the flashchips array? */
	if (flash_args.chip) {
		for (chip = flashchips; chip && chip->name; chip++)
			if (!strcmp(chip->name, flash_args.chip))
				break;
		if (!chip || !chip->name) {
			msg_cerr("Error: Unknown chip '%s' specified.\n", flash_args.chip);
			msg_gerr("Run flashprog -L to view the hardware supported in this flashprog version.\n");
			ret = 1;
			goto out;
		}
		/* Keep chip around for later usage in case a forced read is requested. */
	}

	if (flash_args.prog_name == NULL) {
		const char *const default_programmer = CONFIG_DEFAULT_PROGRAMMER_NAME;

		if (default_programmer[0]) {
			/* We need to strdup here because we free() unconditionally later. */
			flash_args.prog_name = strdup(default_programmer);
			flash_args.prog_args = strdup(CONFIG_DEFAULT_PROGRAMMER_ARGS);
			if (!flash_args.prog_name || !flash_args.prog_args) {
				fprintf(stderr, "Out of memory!\n");
				ret = 1;
				goto out;
			}
			msg_pinfo("Using default programmer \"%s\" with arguments \"%s\".\n",
				  flash_args.prog_name, flash_args.prog_args);
		} else {
			msg_perr("Please select a programmer with the --programmer parameter.\n"
#if CONFIG_INTERNAL == 1
				 "To choose the mainboard of this computer use 'internal'. "
#endif
				 "Valid choices are:\n");
			list_programmers_linebreak(0, 80, 0);
			msg_ginfo(".\n");
			ret = 1;
			goto out;
		}
	}

	if (flashprog_programmer_init(&prog, flash_args.prog_name, flash_args.prog_args)) {
		msg_perr("Error: Programmer initialization failed.\n");
		ret = 1;
		goto out;
	}
	tempstr = flashbuses_to_text(get_buses_supported());
	msg_pdbg("The following protocols are supported: %s.\n", tempstr);
	free(tempstr);

	chip_to_probe = flash_args.chip;
	struct registered_master *matched_master = NULL;
	for (j = 0; j < registered_master_count; j++) {
		startchip = 0;
		while (chipcount < (int)ARRAY_SIZE(flashes)) {
			startchip = probe_flash(&registered_masters[j], startchip, &flashes[chipcount], 0);
			if (startchip == -1)
				break;
			if (chipcount == 0)
				matched_master = &registered_masters[j];
			chipcount++;
			startchip++;
		}
	}

	if (chipcount > 1) {
		msg_cinfo("Multiple flash chip definitions match the detected chip(s): \"%s\"",
			  flashes[0].chip->name);
		for (i = 1; i < chipcount; i++)
			msg_cinfo(", \"%s\"", flashes[i].chip->name);
		msg_cinfo("\nPlease specify which chip definition to use with the -c <chipname> option.\n");
		ret = 1;
		goto out_shutdown;
	} else if (!chipcount) {
		msg_cinfo("No EEPROM/flash device found.\n");
		if (!force || !flash_args.chip) {
			msg_cinfo("Note: flashprog can never write if the flash chip isn't found "
				  "automatically.\n");
		}
		if (force && read_it && flash_args.chip) {
			struct registered_master *mst;
			int compatible_masters = 0;
			msg_cinfo("Force read (-f -r -c) requested, pretending the chip is there:\n");
			/* This loop just counts compatible controllers. */
			for (j = 0; j < registered_master_count; j++) {
				mst = &registered_masters[j];
				/* chip is still set from the search earlier in this function. */
				if (mst->buses_supported & chip->bustype)
					compatible_masters++;
			}
			if (!compatible_masters) {
				msg_cinfo("No compatible controller found for the requested flash chip.\n");
				ret = 1;
				goto out_shutdown;
			}
			if (compatible_masters > 1)
				msg_cinfo("More than one compatible controller found for the requested flash "
					  "chip, using the first one.\n");
			for (j = 0; j < registered_master_count; j++) {
				mst = &registered_masters[j];
				startchip = probe_flash(mst, 0, &flashes[0], 1);
				if (startchip != -1)
					break;
			}
			if (startchip == -1) {
				// FIXME: This should never happen! Ask for a bug report?
				msg_cinfo("Probing for flash chip '%s' failed.\n", flash_args.chip);
				ret = 1;
				goto out_shutdown;
			}
			msg_cinfo("Please note that forced reads most likely contain garbage.\n");
			flashprog_flag_set(&flashes[0], FLASHPROG_FLAG_FORCE, force);
			ret = do_read(&flashes[0], filename);
			free(flashes[0].chip);
			goto out_shutdown;
		}
		ret = 1;
		goto out_shutdown;
	} else if (!flash_args.chip) {
		/* repeat for convenience when looking at foreign logs */
		tempstr = flashbuses_to_text(flashes[0].chip->bustype);
		msg_gdbg("Found %s flash chip \"%s\" (%d kB, %s).\n",
			 flashes[0].chip->vendor, flashes[0].chip->name, flashes[0].chip->total_size, tempstr);
		free(tempstr);
	}

	fill_flash = &flashes[0];

	if (show_progress)
		flashprog_set_progress_callback(fill_flash, &flashprog_progress_cb, NULL);

	print_chip_support_status(fill_flash->chip);

	if (max_decode_exceeded(matched_master, fill_flash) && !force) {
		msg_cerr("This flash chip is too big for this programmer (--verbose/-V gives details).\n"
			 "Use --force/-f to override at your own risk.\n");
		ret = 1;
		goto out_shutdown;
	}

	if (!(read_it | write_it | verify_it | erase_it | flash_name | flash_size)) {
		msg_ginfo("No operations were specified.\n");
		goto out_shutdown;
	}

	if (flash_name) {
		if (fill_flash->chip->vendor && fill_flash->chip->name) {
			printf("vendor=\"%s\" name=\"%s\"\n",
				fill_flash->chip->vendor,
				fill_flash->chip->name);
		} else {
			ret = -1;
		}
		goto out_shutdown;
	}

	if (flash_size) {
		printf("%zu\n", flashprog_flash_getsize(fill_flash));
		goto out_shutdown;
	}

	if (layout_args.ifd && (flashprog_layout_read_from_ifd(&layout, fill_flash, NULL, 0) ||
							process_include_args(layout, include_args))) {
		ret = 1;
		goto out_shutdown;
	} else if (layout_args.fmapfile) {
		struct stat s;
		if (stat(layout_args.fmapfile, &s) != 0) {
			msg_gerr("Failed to stat fmapfile \"%s\"\n", layout_args.fmapfile);
			ret = 1;
			goto out_shutdown;
		}

		size_t fmapfile_size = s.st_size;
		uint8_t *fmapfile_buffer = malloc(fmapfile_size);
		if (!fmapfile_buffer) {
			ret = 1;
			goto out_shutdown;
		}

		if (read_buf_from_file(fmapfile_buffer, fmapfile_size, layout_args.fmapfile)) {
			ret = 1;
			free(fmapfile_buffer);
			goto out_shutdown;
		}

		if (flashprog_layout_read_fmap_from_buffer(&layout, fill_flash, fmapfile_buffer, fmapfile_size) ||
		    process_include_args(layout, include_args)) {
			ret = 1;
			free(fmapfile_buffer);
			goto out_shutdown;
		}
		free(fmapfile_buffer);
	} else if (layout_args.fmap && (flashprog_layout_read_fmap_from_rom(&layout, fill_flash, 0,
			flashprog_flash_getsize(fill_flash)) || process_include_args(layout, include_args))) {
		ret = 1;
		goto out_shutdown;
	}

	flashprog_layout_set(fill_flash, layout);
	flashprog_flag_set(fill_flash, FLASHPROG_FLAG_FORCE, force);
#if CONFIG_INTERNAL == 1
	flashprog_flag_set(fill_flash, FLASHPROG_FLAG_FORCE_BOARDMISMATCH, force_boardmismatch);
#endif
	flashprog_flag_set(fill_flash, FLASHPROG_FLAG_VERIFY_AFTER_WRITE, !dont_verify_it);
	flashprog_flag_set(fill_flash, FLASHPROG_FLAG_VERIFY_WHOLE_CHIP, !dont_verify_all);

	/* FIXME: We should issue an unconditional chip reset here. This can be
	 * done once we have a .reset function in struct flashchip.
	 * Give the chip time to settle.
	 */
	programmer_delay(100000);
	if (read_it)
		ret = do_read(fill_flash, filename);
	else if (erase_it) {
		ret = flashprog_flash_erase(fill_flash);
		/*
		 * FIXME: Do we really want the scary warning if erase failed?
		 * After all, after erase the chip is either blank or partially
		 * blank or it has the old contents. A blank chip won't boot,
		 * so if the user wanted erase and reboots afterwards, the user
		 * knows very well that booting won't work.
		 */
		if (ret)
			emergency_help_message();
	}
	else if (write_it)
		ret = do_write(fill_flash, filename, referencefile);
	else if (verify_it)
		ret = do_verify(fill_flash, filename);

	flashprog_layout_release(layout);

out_shutdown:
	flashprog_programmer_shutdown(prog);
out:
	for (i = 0; i < chipcount; i++) {
		flashprog_layout_release(flashes[i].default_layout);
		free(flashes[i].chip);
	}

	cleanup_include_args(&include_args);
	free(filename);
	free(referencefile);
	free(layout_args.fmapfile);
	free(layout_args.layoutfile);
	free(flash_args.prog_args);
	free(flash_args.prog_name);
	free(flash_args.chip);
	/* clean up global variables */
	chip_to_probe = NULL;
	free(logfile);
	ret |= close_logfile();
	return ret;
}
