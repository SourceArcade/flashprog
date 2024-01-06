/*
 * This file is part of the flashrom project.
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

#ifndef __BITBANG_SPI_H__
#define __BITBANG_SPI_H__ 1

struct bitbang_spi_master {
	/* Note that CS# is active low, so val=0 means the chip is active. */
	void (*set_cs) (int val, void *data);
	void (*set_sck) (int val, void *data);
	void (*set_mosi) (int val, void *data);
	int (*get_miso) (void *data);
	void (*request_bus) (void *data);
	void (*release_bus) (void *data);
	/* optional functions to optimize xfers */
	void (*set_sck_set_mosi) (int sck, int mosi, void *data);
	int (*set_sck_get_miso) (int sck, void *data);
	/* Length of half a clock period in usecs. */
	unsigned int half_period;
};

int register_spi_bitbang_master(const struct bitbang_spi_master *, void *data);

#endif				/* !__BITBANG_SPI_H__ */
