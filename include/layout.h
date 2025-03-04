/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2005-2008 coresystems GmbH
 * (Written by Stefan Reinauer <stepan@coresystems.de> for coresystems GmbH)
 * Copyright (C) 2011-2013 Stefan Tauner
 * Copyright (C) 2016 secunet Security Networks AG
 * (Written by Nico Huber <nico.huber@secunet.com> for secunet)
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

#ifndef __LAYOUT_H__
#define __LAYOUT_H__ 1

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Types and macros regarding the maximum flash space size supported by generic code. */
typedef uint32_t chipoff_t; /* Able to store any addressable offset within a supported flash memory. */
typedef uint32_t chipsize_t; /* Able to store the number of bytes of any supported flash memory. */
#define FL_MAX_CHIPOFF_BITS (24)
#define FL_MAX_CHIPOFF ((chipoff_t)(1ULL<<FL_MAX_CHIPOFF_BITS)-1)
#define PRIxCHIPOFF "06"PRIx32
#define PRIuCHIPSIZE PRIu32

#define MAX_ROMLAYOUT	128

struct romentry {
	struct romentry *next;

	chipoff_t start;
	chipoff_t end;
	bool included;
	char *name;
};

struct flashprog_layout;

struct layout_include_args;

struct flashprog_flashctx;
const struct flashprog_layout *get_default_layout(const struct flashprog_flashctx *);
const struct flashprog_layout *get_layout(const struct flashprog_flashctx *);

int layout_from_file(struct flashprog_layout **, const char *name);

int register_include_arg(struct layout_include_args **, char *arg);
int process_include_args(struct flashprog_layout *, const struct layout_include_args *);
unsigned int layout_num_regions_included(const struct flashprog_layout *);
void cleanup_include_args(struct layout_include_args **);

const struct romentry *layout_next_included_region(const struct flashprog_layout *, chipoff_t);
const struct romentry *layout_next_included(const struct flashprog_layout *, const struct romentry *);
const struct romentry *layout_next(const struct flashprog_layout *, const struct romentry *);
int layout_sanity_checks(const struct flashprog_flashctx *, bool write_it);

#endif /* !__LAYOUT_H__ */
