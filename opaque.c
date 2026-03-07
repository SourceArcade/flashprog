/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2011,2013,2014 Carl-Daniel Hailfinger
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

/*
 * Contains the opaque master framework.
 * An opaque master is a master which does not provide direct access
 * to the flash chip and which abstracts all flash chip properties into a
 * master specific interface.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "flash.h"
#include "flashchips.h"
#include "chipdrivers/opaque.h"
#include "chipdrivers/probing.h"
#include "programmer.h"

struct found_id *probe_opaque(const struct bus_probe *probe,
			      const struct master_common *mst,
			      const struct flashchip *chip)
{
	struct found_id *const found = calloc(1, sizeof(*found));
	if (!found) {
		msg_cerr("Out of memory!\n");
		return NULL;
	}

	found->info.id.type		= ID_OPAQUE;
	found->info.id.manufacture	= PROGMANUF_ID;
	found->info.id.model		= PROGDEV_ID;

	return found;
}

int prepare_opaque(struct flashctx *flash, enum preparation_steps step)
{
	if (step != PREPARE_POST_PROBE)
		return 0;
	return flash->mst.opaque->prepare(flash) ? 0 : -1;
}

int read_opaque(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	return flash->mst.opaque->read(flash, buf, start, len);
}

int write_opaque(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	return flash->mst.opaque->write(flash, buf, start, len);
}

int erase_opaque(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen)
{
	return flash->mst.opaque->erase(flash, blockaddr, blocklen);
}

static const struct bus_probe opaque_probes[] = {
    /* prio. type		function		function argument */
	{ 0, ID_OPAQUE,		probe_opaque,		NULL },
};

static bool opaque_probe_match(const struct flashchip *chip, const struct id_info_ext *found)
{
	return memcmp(&chip->id, &found->id, sizeof(found->id)) == 0;
}

int register_opaque_master(const struct opaque_master *mst, void *data)
{
	struct registered_master rmst = { 0 };

	if (mst->shutdown) {
		if (register_shutdown(mst->shutdown, data)) {
			mst->shutdown(data); /* cleanup */
			return 1;
		}
	}

	if (!mst->prepare || !mst->read || !mst->write || !mst->erase) {
		msg_perr("%s called with incomplete master definition.\n"
			 "Please report a bug at flashprog@flashprog.org\n",
			 __func__);
		return ERROR_FLASHPROG_BUG;
	}
	rmst.buses_supported = BUS_PROG;
	rmst.probing.probe_count = ARRAY_SIZE(opaque_probes);
	rmst.probing.probes = opaque_probes;
	rmst.probing.match = opaque_probe_match;
	rmst.opaque = *mst;
	if (data)
		rmst.opaque.data = data;

	rmst.common.max_rom_decode = MAX_ROM_DECODE_UNLIMITED;

	return register_master(&rmst);
}
