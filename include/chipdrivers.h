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
 *
 * Header file for flash chip drivers. Included from flash.h.
 * As a general rule, every function listed here should take a pointer to
 * struct flashctx as first parameter.
 */

#ifndef __CHIPDRIVERS_H__
#define __CHIPDRIVERS_H__ 1

#include "flash.h"	/* for chipaddr and flashctx */

/* opaque.c */
int probe_opaque(struct flashctx *flash);
int read_opaque(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len);
int write_opaque(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len);
int erase_opaque(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen);

#endif /* !__CHIPDRIVERS_H__ */
