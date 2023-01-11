/*
 * This file is part of the flashrom project.
 *
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
#include "spi.h"
#include "flash.h"

#define CONSUMER "flashprog"

struct linux_gpio_spi {
	struct gpiod_chip *chip;
	struct gpiod_line_bulk bulk;
	struct gpiod_line *cs_line, *sck_line, *mosi_line, *miso_line;
};

static void linux_gpio_spi_bitbang_set_cs(int val, void *spi_data)
{
	struct linux_gpio_spi *data = spi_data;
	if (gpiod_line_set_value(data->cs_line, val) < 0)
		msg_perr("Setting cs line failed\n");
}

static void linux_gpio_spi_bitbang_set_sck(int val, void *spi_data)
{
	struct linux_gpio_spi *data = spi_data;
	if (gpiod_line_set_value(data->sck_line, val) < 0)
		msg_perr("Setting sck line failed\n");
}

static void linux_gpio_spi_bitbang_set_mosi(int val, void *spi_data)
{
	struct linux_gpio_spi *data = spi_data;
	if (gpiod_line_set_value(data->mosi_line, val) < 0)
		msg_perr("Setting sck line failed\n");
}

static int linux_gpio_spi_bitbang_get_miso(void *spi_data)
{
	struct linux_gpio_spi *data = spi_data;
	int r = gpiod_line_get_value(data->miso_line);
	if (r < 0)
		msg_perr("Getting miso line failed\n");
	return r;
}

static const struct bitbang_spi_master bitbang_spi_master_gpiod = {
	.set_cs		= linux_gpio_spi_bitbang_set_cs,
	.set_sck	= linux_gpio_spi_bitbang_set_sck,
	.set_mosi	= linux_gpio_spi_bitbang_set_mosi,
	.get_miso	= linux_gpio_spi_bitbang_get_miso,
};

static int linux_gpio_spi_shutdown(void *spi_data)
{
	struct linux_gpio_spi *data = spi_data;

	if (gpiod_line_bulk_num_lines(&data->bulk) > 0)
		gpiod_line_release_bulk(&data->bulk);

	if (data->chip)
		gpiod_chip_close(data->chip);

	free(data);

	return 0;
}

static int linux_gpio_spi_init(struct flashprog_programmer *const prog)
{
	struct linux_gpio_spi *data = NULL;
	struct gpiod_chip *chip = NULL;
	const char *param_str[] = { "cs", "sck", "mosi", "miso", "gpiochip" };
	const bool param_required[] = { true, true, true, true, false };
	unsigned int param_int[ARRAY_SIZE(param_str)];
	unsigned int i;
	int r;

	data = calloc(1, sizeof(*data));
	if (!data) {
		msg_perr("Unable to allocate space for SPI master data\n");
		return 1;
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
	if (!dev && param_int[4] == UINT_MAX) {
		msg_perr("Either a 'dev' or 'gpiochip' parameter must be specified.\n");
		goto err_exit;
	}
	if (dev && param_int[4] != UINT_MAX) {
		msg_perr("Only one of 'dev' or 'gpiochip' parameters can be specified.\n");
		free(dev);
		goto err_exit;
	}

	if (dev) {
		chip = gpiod_chip_open(dev);
		free(dev);
	} else {
		chip = gpiod_chip_open_by_number(param_int[4]);
	}
	if (!chip) {
		msg_perr("Failed to open gpiochip: %s\n", strerror(errno));
		goto err_exit;
	}

	data->chip = chip;

	if (gpiod_chip_get_lines(chip, param_int, 4, &data->bulk)) {
		msg_perr("Error getting GPIO lines\n");
		goto err_exit;
	}

	data->cs_line = gpiod_line_bulk_get_line(&data->bulk, 0);
	data->sck_line = gpiod_line_bulk_get_line(&data->bulk, 1);
	data->mosi_line = gpiod_line_bulk_get_line(&data->bulk, 2);
	data->miso_line = gpiod_line_bulk_get_line(&data->bulk, 3);

	r = gpiod_line_request_output(data->cs_line, CONSUMER, 1);
	r |= gpiod_line_request_output(data->sck_line, CONSUMER, 1);
	r |= gpiod_line_request_output(data->mosi_line, CONSUMER, 1);
	r |= gpiod_line_request_input(data->miso_line, CONSUMER);

	if (r < 0) {
		msg_perr("Requesting GPIO lines failed\n");
		goto err_exit;
	}

	if (register_shutdown(linux_gpio_spi_shutdown, data))
		goto err_exit;

	/* shutdown function does the cleanup */
	return register_spi_bitbang_master(&bitbang_spi_master_gpiod, data);

err_exit:
	linux_gpio_spi_shutdown(data);
	return 1;
}

const struct programmer_entry programmer_linux_gpio_spi = {
	.name		= "linux_gpio_spi",
	.type		= OTHER,
	.devs.note	= "Device file /dev/gpiochip<n>\n",
	.init		= linux_gpio_spi_init,
};
