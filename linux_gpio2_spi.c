/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2024 Nico Huber <nico.h@gmx.de>
 *
 * based on linux_gpio_spi.c
 * Copyright (C) 2023 Steve Markgraf <steve@steve-m.de>
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
#include <limits.h>
#include <errno.h>
#include <gpiod.h>
#include "programmer.h"
#include "bitbang_spi.h"
#include "spi.h"
#include "flash.h"

#define CONSUMER "flashprog"

enum {
	CS	= 0,
	SCK	= 1,
	MOSI	= 2,
	MISO	= 3,
	IO0	= 2,
	IO1	= 3,
	IO2	= 4,
	IO3	= 5,
	MAX_LINES
};

struct linux_gpio_spi {
	struct gpiod_chip *chip;
	struct gpiod_line_request *lines;
	struct gpiod_line_config *single;
	struct gpiod_line_config *multi_in;
	struct gpiod_line_config *multi_out;
	struct gpiod_line_config *current_config;
	unsigned int offsets[MAX_LINES];
	unsigned int io_lines;
};

static int ensure_spi_mode(struct linux_gpio_spi *gpio_spi, struct gpiod_line_config *config)
{
	if (gpio_spi->current_config == config)
		return 0;

	const int ret = gpiod_line_request_reconfigure_lines(gpio_spi->lines, config);
	if (ret < 0)
		msg_perr("Switching line config failed: %s\n", strerror(errno));
	else
		gpio_spi->current_config = config;

	return ret;
}

static void linux_gpio_spi_bitbang_set_cs(int val, void *data)
{
	const struct linux_gpio_spi *const gpio_spi = data;

	if (gpiod_line_request_set_value(gpio_spi->lines, gpio_spi->offsets[CS], val) < 0)
		msg_perr("Setting cs line failed: %s\n", strerror(errno));
}

static void linux_gpio_spi_bitbang_set_sck(int val, void *data)
{
	const struct linux_gpio_spi *const gpio_spi = data;

	if (gpiod_line_request_set_value(gpio_spi->lines, gpio_spi->offsets[SCK], val) < 0)
		msg_perr("Setting sck line failed: %s\n", strerror(errno));
}

static void linux_gpio_spi_bitbang_set_mosi(int val, void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	if (ensure_spi_mode(gpio_spi, gpio_spi->single) < 0)
		return;

	if (gpiod_line_request_set_value(gpio_spi->lines, gpio_spi->offsets[MOSI], val) < 0)
		msg_perr("Setting mosi line failed: %s\n", strerror(errno));
}

static int linux_gpio_spi_bitbang_get_miso(void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	if (ensure_spi_mode(gpio_spi, gpio_spi->single) < 0)
		return -1;

	const enum gpiod_line_value ret =
		gpiod_line_request_get_value(gpio_spi->lines, gpio_spi->offsets[MISO]);
	if (ret < 0)
		msg_perr("Getting miso line failed: %s\n", strerror(errno));
	return ret;
}

static void linux_gpio_spi_bitbang_set_sck_set_mosi(int sck, int mosi, void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	if (ensure_spi_mode(gpio_spi, gpio_spi->single) < 0)
		return;

	enum gpiod_line_value vals[] = { sck, mosi };
	if (gpiod_line_request_set_values_subset(gpio_spi->lines, 2, &gpio_spi->offsets[SCK], vals) < 0)
		msg_perr("Setting sck/mosi lines failed: %s\n", strerror(errno));
}

static void linux_gpio_spi_bitbang_set_sck_set_multi_io(int sck, int io, void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	if (ensure_spi_mode(gpio_spi, gpio_spi->multi_out) < 0)
		return;

	enum gpiod_line_value vals[] = { sck, io & 1, io >> 1 & 1, io >> 2 & 1, io >> 3 & 1 };
	if (gpiod_line_request_set_values_subset(gpio_spi->lines,
				gpio_spi->io_lines + 1, &gpio_spi->offsets[SCK], vals) < 0)
		msg_perr("Setting sck/io lines failed: %s\n", strerror(errno));
}

static int linux_gpio_spi_bitbang_set_sck_get_multi_io(int sck, void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	if (ensure_spi_mode(gpio_spi, gpio_spi->multi_in) < 0)
		return -1;

	linux_gpio_spi_bitbang_set_sck(sck, data);

	enum gpiod_line_value vals[4] = { 0, };
	const int ret = gpiod_line_request_get_values_subset(gpio_spi->lines,
				gpio_spi->io_lines, &gpio_spi->offsets[IO0], vals);
	if (ret < 0) {
		msg_perr("Getting io lines failed: %s\n", strerror(errno));
		return -1;
	}

	return vals[0] | vals[1] << 1 | vals[2] << 2 | vals[3] << 3;
}

static void linux_gpio_spi_bitbang_set_idle_io(void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	(void)ensure_spi_mode(gpio_spi, gpio_spi->multi_in);
}

static struct bitbang_spi_master bitbang_spi_master_gpiod = {
	.set_cs			= linux_gpio_spi_bitbang_set_cs,
	.set_sck		= linux_gpio_spi_bitbang_set_sck,
	.set_mosi		= linux_gpio_spi_bitbang_set_mosi,
	.get_miso		= linux_gpio_spi_bitbang_get_miso,
	.set_sck_set_mosi	= linux_gpio_spi_bitbang_set_sck_set_mosi,
	.set_sck_set_dual_io	= linux_gpio_spi_bitbang_set_sck_set_multi_io,
	.set_sck_get_dual_io	= linux_gpio_spi_bitbang_set_sck_get_multi_io,
	.set_idle_io		= linux_gpio_spi_bitbang_set_idle_io,
};

static int linux_gpio_spi_shutdown(void *data)
{
	struct linux_gpio_spi *gpio_spi = data;

	if (gpio_spi->multi_out)
		gpiod_line_config_free(gpio_spi->multi_out);
	if (gpio_spi->multi_in)
		gpiod_line_config_free(gpio_spi->multi_in);
	if (gpio_spi->single)
		gpiod_line_config_free(gpio_spi->single);
	if (gpio_spi->lines)
		gpiod_line_request_release(gpio_spi->lines);
	if (gpio_spi->chip)
		gpiod_chip_close(gpio_spi->chip);

	free(data);

	return 0;
}

static int linux_gpio_spi_init(struct flashprog_programmer *const prog)
{
	struct param {
		const char *names[2];
		bool required;
	};
	static const struct param int_params[] = {
		{ .names = { "cs", },		.required = true, },
		{ .names = { "sck", },		.required = true, },
		{ .names = { "mosi", "io0", }, 	.required = true, },
		{ .names = { "miso", "io1", }, 	.required = true, },
		{ .names = { "io2", }, 		.required = false, },
		{ .names = { "io3", }, 		.required = false, },
		{ .names = { "gpiochip", },	.required = false, },
	};

	struct linux_gpio_spi *gpio_spi = NULL;
	unsigned int param_int[ARRAY_SIZE(int_params)];
	unsigned int i, j;
	int r;

	gpio_spi = calloc(1, sizeof(*gpio_spi));
	if (!gpio_spi) {
		msg_perr("Unable to allocate space for SPI master data\n");
		return SPI_GENERIC_ERROR;
	}

	for (i = 0; i < ARRAY_SIZE(int_params); i++) {
		const char *param_name = int_params[i].names[0];
		char *param = NULL, *endptr;

		for (j = 0; j < 2 && int_params[i].names[j]; ++j) {
			char *const p = extract_programmer_param(int_params[i].names[j]);
			if (param && p) {
				msg_perr("Parameters `%s' and `%s' are mutually exclusive.\n",
					 int_params[i].names[0], int_params[i].names[1]);
				free(param);
				free(p);
				goto err_exit;
			}
			if (p) {
				param_name = int_params[i].names[j];
				param = p;
			}
		}

		r = 1;

		if (param) {
			errno = 0;
			param_int[i] = strtoul(param, &endptr, 10);
			r = (*endptr != '\0') || (errno != 0);
			free(param);
		} else {
			param_int[i] = UINT_MAX;
		}

		if ((int_params[i].required || param) && r) {
			msg_perr("Invalid or missing required programmer parameter "
				 "%s=<n>\n", param_name);
			goto err_exit;
		}
	}

	char *const dev = extract_programmer_param("dev");
	const unsigned int gpiochip = param_int[MAX_LINES];
	if (!dev && gpiochip == UINT_MAX) {
		msg_perr("Either a `dev' or `gpiochip' parameter must be specified.\n"
			 "e.g. `-p linux_gpio2_spi:dev=/dev/gpiochip0'.\n");
		goto err_exit;
	}
	if (dev && gpiochip != UINT_MAX) {
		msg_perr("Only one of `dev' or `gpiochip' parameters can be specified.\n");
		goto free_dev_exit;
	}

	if ((param_int[IO2] == UINT_MAX) ^ (param_int[IO3] == UINT_MAX)) {
		msg_perr("Both `io2' and `io3' are required for quad i/o.\n");
		goto free_dev_exit;
	}

	const char *devpath;
	char devpath_template[] = "/dev/gpiochipX";
	if (dev) {
		devpath = dev;
	} else if (gpiochip > 9) {
		msg_perr("Maximum `gpiochip' number supported is 9.\n");
		goto err_exit;
	} else {
		devpath_template[13] = '0' + gpiochip;
		devpath = devpath_template;
	}

	gpio_spi->chip = gpiod_chip_open(devpath);
	if (!gpio_spi->chip) {
		msg_perr("Failed to open gpiochip `%s': %s\n", devpath, strerror(errno));
		goto free_dev_exit;
	}
	free(dev);

	if (param_int[IO2] != UINT_MAX) {
		bitbang_spi_master_gpiod.set_sck_set_quad_io = linux_gpio_spi_bitbang_set_sck_set_multi_io;
		bitbang_spi_master_gpiod.set_sck_get_quad_io = linux_gpio_spi_bitbang_set_sck_get_multi_io;
		gpio_spi->io_lines = 4;
	} else {
		gpio_spi->io_lines = 2;
	}

	struct gpiod_line_settings *const in = gpiod_line_settings_new();
	struct gpiod_line_settings *const out = gpiod_line_settings_new();
	gpio_spi->multi_out = gpiod_line_config_new();
	gpio_spi->multi_in = gpiod_line_config_new();
	gpio_spi->single = gpiod_line_config_new();
	if (!in || !out || !gpio_spi->multi_out || !gpio_spi->multi_in || !gpio_spi->single) {
		msg_perr("Unable to allocate space for GPIO line config\n");
		if (out)
			gpiod_line_settings_free(out);
		if (in)
			gpiod_line_settings_free(in);
		goto err_exit;
	}

	gpiod_line_settings_set_direction(in, GPIOD_LINE_DIRECTION_INPUT);
	gpiod_line_settings_set_direction(out, GPIOD_LINE_DIRECTION_OUTPUT);

	gpiod_line_config_add_line_settings(gpio_spi->single, &param_int[CS], 3, out);
	gpiod_line_config_add_line_settings(gpio_spi->single, &param_int[MISO], gpio_spi->io_lines - 1, in);

	gpiod_line_config_add_line_settings(gpio_spi->multi_in, &param_int[CS], 2, out);
	gpiod_line_config_add_line_settings(gpio_spi->multi_in, &param_int[IO0], gpio_spi->io_lines, in);

	gpiod_line_config_add_line_settings(gpio_spi->multi_out, &param_int[CS], 2 + gpio_spi->io_lines, out);

	gpiod_line_settings_free(out);
	gpiod_line_settings_free(in);

	gpio_spi->lines = gpiod_chip_request_lines(gpio_spi->chip, NULL, gpio_spi->single);
	if (!gpio_spi->lines) {
		msg_perr("Failed to acquire GPIO lines\n");
		goto err_exit;
	}
	gpio_spi->current_config = gpio_spi->single;

	memcpy(gpio_spi->offsets, param_int, sizeof(gpio_spi->offsets));

	if (register_shutdown(linux_gpio_spi_shutdown, gpio_spi))
		goto err_exit;

	/* shutdown function does the cleanup */
	return register_spi_bitbang_master(&bitbang_spi_master_gpiod, gpio_spi);

free_dev_exit:
	free(dev);
err_exit:
	linux_gpio_spi_shutdown(gpio_spi);
	return SPI_GENERIC_ERROR;
}

const struct programmer_entry programmer_linux_gpio_spi = {
	.name		= "linux_gpio_spi",
	.type		= OTHER,
	.devs.note	= "Device file /dev/gpiochip<n>\n",
	.init		= linux_gpio_spi_init,
};
