/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Carl-Daniel Hailfinger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __CHIPDRIVERS_OPAQUE_H__
#define __CHIPDRIVERS_OPAQUE_H__ 1

#include <stdint.h>

struct flashprog_flashctx;
struct master_common;
struct bus_probe;
struct flashchip;

struct found_id *probe_opaque(const struct bus_probe *, const struct master_common *, const struct flashchip *);

int prepare_opaque(struct flashprog_flashctx *);

int read_opaque(struct flashprog_flashctx *, uint8_t *buf, unsigned int start, unsigned int len);
int write_opaque(struct flashprog_flashctx *, const uint8_t *buf, unsigned int start, unsigned int len);
int erase_opaque(struct flashprog_flashctx *, unsigned int blockaddr, unsigned int blocklen);

#endif /* !__CHIPDRIVERS_OPAQUE_H__ */
