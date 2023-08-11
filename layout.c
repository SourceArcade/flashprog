/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2005-2008 coresystems GmbH
 * (Written by Stefan Reinauer <stepan@coresystems.de> for coresystems GmbH)
 * Copyright (C) 2011-2013 Stefan Tauner
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "flash.h"
#include "programmer.h"
#include "layout.h"

struct flashprog_layout {
	struct romentry *head;
};

struct layout_include_args {
	char *name;
	struct layout_include_args *next;
};

const struct flashprog_layout *get_default_layout(const struct flashprog_flashctx *const flashctx)
{
	return flashctx->default_layout;
}

const struct flashprog_layout *get_layout(const struct flashprog_flashctx *const flashctx)
{
	if (flashctx->layout)
		return flashctx->layout;
	else
		return get_default_layout(flashctx);
}

static struct romentry *mutable_layout_next(
		const struct flashprog_layout *const layout, struct romentry *iterator)
{
	return iterator ? iterator->next : layout->head;
}

#ifndef __LIBPAYLOAD__
int layout_from_file(struct flashprog_layout **layout, const char *name)
{
	FILE *romlayout;
	char tempstr[256], tempname[256];
	int ret = 1;

	if (flashprog_layout_new(layout))
		return 1;

	romlayout = fopen(name, "r");

	if (!romlayout) {
		msg_gerr("ERROR: Could not open ROM layout (%s).\n",
			name);
		return -1;
	}

	while (!feof(romlayout)) {
		char *tstr1, *tstr2;

		if (2 != fscanf(romlayout, "%255s %255s\n", tempstr, tempname))
			continue;
#if 0
		// fscanf does not like arbitrary comments like that :( later
		if (tempstr[0] == '#') {
			continue;
		}
#endif
		tstr1 = strtok(tempstr, ":");
		tstr2 = strtok(NULL, ":");
		if (!tstr1 || !tstr2) {
			msg_gerr("Error parsing layout file. Offending string: \"%s\"\n", tempstr);
			goto _close_ret;
		}
		if (flashprog_layout_add_region(*layout,
				strtol(tstr1, NULL, 16), strtol(tstr2, NULL, 16), tempname))
			goto _close_ret;
	}
	ret = 0;

_close_ret:
	(void)fclose(romlayout);
	return ret;
}
#endif

/* register an include argument (-i) for later processing */
int register_include_arg(struct layout_include_args **args, char *name)
{
	struct layout_include_args *tmp;
	if (name == NULL) {
		msg_gerr("<NULL> is a bad region name.\n");
		return 1;
	}

	tmp = *args;
	while (tmp) {
		if (!strcmp(tmp->name, name)) {
			msg_gerr("Duplicate region name: \"%s\".\n", name);
			return 1;
		}
		tmp = tmp->next;
	}

	tmp = malloc(sizeof(*tmp));
	if (tmp == NULL) {
		msg_gerr("Out of memory\n");
		return 1;
	}

	tmp->name = name;
	tmp->next = *args;
	*args = tmp;

	return 0;
}

/* returns -1 if an entry is not found, 0 if found. */
static int find_romentry(struct flashprog_layout *const l, char *name)
{
	if (!l->head)
		return -1;

	msg_gspew("Looking for region \"%s\"... ", name);
	if (flashprog_layout_include_region(l, name)) {
		msg_gspew("not found.\n");
		return -1;
	}
	msg_gspew("found.\n");
	return 0;
}

/* process -i arguments
 * returns 0 to indicate success, >0 to indicate failure
 */
int process_include_args(struct flashprog_layout *l, const struct layout_include_args *const args)
{
	unsigned int found = 0;
	const struct layout_include_args *tmp;

	if (args == NULL)
		return 0;

	/* User has specified an area, but no layout file is loaded. */
	if (!l || !l->head) {
		msg_gerr("Region requested (with -i \"%s\"), "
			 "but no layout data is available.\n",
			 args->name);
		return 1;
	}

	tmp = args;
	while (tmp) {
		if (find_romentry(l, tmp->name) < 0) {
			msg_gerr("Invalid region specified: \"%s\".\n",
				 tmp->name);
			return 1;
		}
		tmp = tmp->next;
		found++;
	}

	msg_ginfo("Using region%s:", found > 1 ? "s" : "");
	tmp = args;
	while (tmp) {
		msg_ginfo(" \"%s\"%s", tmp->name, found > 1 ? "," : "");
		found--;
		tmp = tmp->next;
	}
	msg_ginfo(".\n");
	return 0;
}

void cleanup_include_args(struct layout_include_args **args)
{
	struct layout_include_args *tmp;

	while (*args) {
		tmp = (*args)->next;
		free(*args);
		*args = tmp;
	}
}

int layout_sanity_checks(const struct flashprog_flashctx *const flash, const bool write_it)
{
	const struct flashprog_layout *const layout = get_layout(flash);
	const chipsize_t total_size = flash->chip->total_size * 1024;
	const size_t gran = gran_to_bytes(flash->chip->gran);
	int ret = 0;

	const struct romentry *entry = NULL;
	while ((entry = layout_next(layout, entry))) {
		if (entry->start >= total_size || entry->end >= total_size) {
			msg_gwarn("Warning: Address range of region \"%s\" "
				  "exceeds the current chip's address space.\n", entry->name);
			if (entry->included)
				ret = 1;
		}
		if (entry->start > entry->end) {
			msg_gerr("Error: Size of the address range of region \"%s\" is not positive.\n",
				  entry->name);
			ret = 1;
		}
		if (write_it && entry->included && (entry->start % gran || (entry->end + 1) % gran)) {
			msg_gerr("Error: Region \"%s\" is not aligned with write granularity (%zuB).\n",
				 entry->name, gran);
			ret = 1;
		}
	}

	return ret;
}

const struct romentry *layout_next_included_region(
		const struct flashprog_layout *const l, const chipoff_t where)
{
	const struct romentry *entry = NULL, *lowest = NULL;

	while ((entry = layout_next(l, entry))) {
		if (!entry->included)
			continue;
		if (entry->end < where)
			continue;
		if (!lowest || lowest->start > entry->start)
			lowest = entry;
	}

	return lowest;
}

const struct romentry *layout_next_included(
		const struct flashprog_layout *const layout, const struct romentry *iterator)
{
	while ((iterator = layout_next(layout, iterator))) {
		if (iterator->included)
			break;
	}
	return iterator;
}

const struct romentry *layout_next(
		const struct flashprog_layout *const layout, const struct romentry *iterator)
{
	return iterator ? iterator->next : layout->head;
}

/**
 * @addtogroup flashprog-layout
 * @{
 */

/**
 * @brief Create a new, empty layout.
 *
 * @param layout Pointer to returned layout reference.
 *
 * @return 0 on success,
 *         1 if out of memory.
 */
int flashprog_layout_new(struct flashprog_layout **const layout)
{
	*layout = malloc(sizeof(**layout));
	if (!*layout) {
		msg_gerr("Error creating layout: %s\n", strerror(errno));
		return 1;
	}

	const struct flashprog_layout tmp = { 0 };
	**layout = tmp;
	return 0;
}

/**
 * @brief Add another region to an existing layout.
 *
 * @param layout The existing layout.
 * @param start  Start address of the region.
 * @param end    End address (inclusive) of the region.
 * @param name   Name of the region.
 *
 * @return 0 on success,
 *         1 if out of memory.
 */
int flashprog_layout_add_region(
		struct flashprog_layout *const layout,
		const size_t start, const size_t end, const char *const name)
{
	struct romentry *const entry = malloc(sizeof(*entry));
	if (!entry)
		goto _err_ret;

	const struct romentry tmp = {
		.next		= layout->head,
		.start		= start,
		.end		= end,
		.included	= false,
		.name		= strdup(name),
	};
	*entry = tmp;
	if (!entry->name)
		goto _err_ret;

	msg_gdbg("Added layout entry %08zx - %08zx named %s\n", start, end, name);
	layout->head = entry;
	return 0;

_err_ret:
	msg_gerr("Error adding layout entry: %s\n", strerror(errno));
	free(entry);
	return 1;
}

/**
 * @brief Mark given region as included.
 *
 * @param layout The layout to alter.
 * @param name   The name of the region to include.
 *
 * @return 0 on success,
 *         1 if the given name can't be found.
 */
int flashprog_layout_include_region(struct flashprog_layout *const layout, const char *name)
{
	struct romentry *entry = NULL;
	while ((entry = mutable_layout_next(layout, entry))) {
		if (!strcmp(entry->name, name)) {
			entry->included = true;
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Free a layout.
 *
 * @param layout Layout to free.
 */
void flashprog_layout_release(struct flashprog_layout *const layout)
{
	if (!layout)
		return;

	while (layout->head) {
		struct romentry *const entry = layout->head;
		layout->head = entry->next;
		free(entry->name);
		free(entry);
	}
	free(layout);
}

/** @} */ /* end flashprog-layout */
