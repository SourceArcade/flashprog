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

#ifndef __PROBING_H__
#define __PROBING_H__ 1

#include <stddef.h>
#include <stdint.h>

enum id_type {
	ID_FIXME = 0,
	ID_NONE,

	ID_82802AB,
	ID_EDI,
	ID_JEDEC,
	ID_JEDEC_29GL,
	ID_OPAQUE,
	ID_SPI_AT25F,
	ID_SPI_RDID,
	ID_SPI_REMS,
	ID_SPI_RES1,
	ID_SPI_RES2,
	ID_SPI_RES3,
	ID_SPI_SFDP,
	ID_SPI_ST95,
	ID_W29EE011,
};

/*
 * With 32bit manufacture_id and model_id we can cover IDs up to
 * (including) the 4th bank of JEDEC JEP106W Standard Manufacturer's
 * Identification code.
 */
struct id_info {
	union {
		uint32_t manufacture;
		uint32_t hwversion;
		uint32_t id1;
	};
	union {
		uint32_t model;
		uint32_t id2;
	};
	enum id_type type;
};

struct id_info_ext {
	struct id_info id;
	void *ext;
};

struct found_id {
	struct found_id *next;
	struct id_info_ext info;
};

struct master_common;
struct flashchip;

struct bus_probe {
	unsigned int priority;
	enum id_type type;
	struct found_id *(*run)(const struct bus_probe *, const struct master_common *, const struct flashchip *);
	void *arg;
};

struct bus_probing {
	unsigned int probe_count;
	const struct bus_probe *probes;
	bool (*match)(const struct flashchip *, const struct id_info_ext *);
};

struct registered_master;
void flashprog_bus_probe(struct registered_master *, const struct flashchip *);

struct flashprog_chips;
struct flashprog_flashctx;
struct flashprog_programmer;
const struct flashchip *flashprog_chip_by_name(const char *chip_name);
const struct master_common *flashprog_chip_probe(const struct flashprog_programmer *, const struct flashchip *);
int flashprog_flash_prepare_context(struct flashprog_flashctx **, const struct flashprog_programmer *, const struct master_common *, const struct flashchip *);

#endif /* !__PROBING_H__ */
