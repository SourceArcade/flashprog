/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2015 Paul Kocialkowski <contact@paulk.fr>
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

#ifndef __CHIPDRIVERS_EDI_H__
#define __CHIPDRIVERS_EDI_H__ 1

#include <stdint.h>

struct flashprog_flashctx;
struct master_common;
struct bus_probe;

struct found_id *probe_edi(const struct bus_probe *, const struct master_common *);

int edi_chip_block_erase(struct flashprog_flashctx *, unsigned int page, unsigned int size);
int edi_chip_write(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int edi_chip_read(struct flashprog_flashctx *, uint8_t *buf, unsigned int start, unsigned int len);
int edi_prepare(struct flashprog_flashctx *, enum preparation_steps);

#endif /* !__CHIPDRIVERS_EDI_H__ */
