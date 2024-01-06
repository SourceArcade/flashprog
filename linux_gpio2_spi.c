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
	MAX_LINES
};

struct linux_gpio_spi {
	struct gpiod_chip *chip;
	struct gpiod_line_request *lines;
	unsigned int offsets[MAX_LINES];
};

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

	if (gpiod_line_request_set_value(gpio_spi->lines, gpio_spi->offsets[MOSI], val) < 0)
		msg_perr("Setting mosi line failed: %s\n", strerror(errno));
}

static int linux_gpio_spi_bitbang_get_miso(void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	const enum gpiod_line_value ret =
		gpiod_line_request_get_value(gpio_spi->lines, gpio_spi->offsets[MISO]);
	if (ret < 0)
		msg_perr("Getting miso line failed: %s\n", strerror(errno));
	return ret;
}

static void linux_gpio_spi_bitbang_set_sck_set_mosi(int sck, int mosi, void *data)
{
	struct linux_gpio_spi *const gpio_spi = data;

	enum gpiod_line_value vals[] = { sck, mosi };
	if (gpiod_line_request_set_values_subset(gpio_spi->lines, 2, &gpio_spi->offsets[SCK], vals) < 0)
		msg_perr("Setting sck/mosi lines failed: %s\n", strerror(errno));
}

static struct bitbang_spi_master bitbang_spi_master_gpiod = {
	.set_cs			= linux_gpio_spi_bitbang_set_cs,
	.set_sck		= linux_gpio_spi_bitbang_set_sck,
	.set_mosi		= linux_gpio_spi_bitbang_set_mosi,
	.get_miso		= linux_gpio_spi_bitbang_get_miso,
	.set_sck_set_mosi	= linux_gpio_spi_bitbang_set_sck_set_mosi,
};

static int linux_gpio_spi_shutdown(void *data)
{
	struct linux_gpio_spi *gpio_spi = data;

	if (gpio_spi->lines)
		gpiod_line_request_release(gpio_spi->lines);
	if (gpio_spi->chip)
		gpiod_chip_close(gpio_spi->chip);

	free(data);

	return 0;
}

static int linux_gpio_spi_init(struct flashprog_programmer *const prog)
{
	struct linux_gpio_spi *gpio_spi = NULL;
	const char *param_str[] = { "cs", "sck", "mosi", "miso", "gpiochip" };
	const bool param_required[] = { true, true, true, true, false };
	unsigned int param_int[ARRAY_SIZE(param_str)];
	unsigned int i;
	int r;

	gpio_spi = calloc(1, sizeof(*gpio_spi));
	if (!gpio_spi) {
		msg_perr("Unable to allocate space for SPI master data\n");
		return SPI_GENERIC_ERROR;
	}

	for (i = 0; i < ARRAY_SIZE(param_str); i++) {
		char *param = extract_programmer_param(param_str[i]);
		char *endptr;
		r = 1;

		if (param) {
			errno = 0;
			param_int[i] = strtoul(param, &endptr, 10);
			r = (*endptr != '\0') || (errno != 0);
			free(param);
		} else {
			param_int[i] = UINT_MAX;
		}

		if ((param_required[i] || param) && r) {
			msg_perr("Missing or invalid required programmer "
				 "parameter %s=<n>\n", param_str[i]);
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

	struct gpiod_line_settings *const in = gpiod_line_settings_new();
	struct gpiod_line_settings *const out = gpiod_line_settings_new();
	struct gpiod_line_config *const cfg = gpiod_line_config_new();
	if (!in || !out || !cfg) {
		msg_perr("Unable to allocate space for GPIO line config\n");
		if (cfg)
			gpiod_line_config_free(cfg);
		if (out)
			gpiod_line_settings_free(out);
		if (in)
			gpiod_line_settings_free(in);
		goto err_exit;
	}

	gpiod_line_settings_set_direction(in, GPIOD_LINE_DIRECTION_INPUT);
	gpiod_line_settings_set_direction(out, GPIOD_LINE_DIRECTION_OUTPUT);

	gpiod_line_config_add_line_settings(cfg, &param_int[CS], 3, out);
	gpiod_line_config_add_line_settings(cfg, &param_int[MISO], 1, in);

	gpiod_line_settings_free(out);
	gpiod_line_settings_free(in);

	gpio_spi->lines = gpiod_chip_request_lines(gpio_spi->chip, NULL, cfg);
	if (!gpio_spi->lines) {
		msg_perr("Failed to acquire GPIO lines\n");
		goto err_exit;
	}

	gpiod_line_config_free(cfg);

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
