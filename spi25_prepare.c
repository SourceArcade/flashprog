/*
 * This file is part of the flashprog project.
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

#include <stdbool.h>
#include "flash.h"
#include "chipdrivers.h"
#include "programmer.h"
#include "spi_command.h"
#include "spi.h"

static int spi_enter_exit_4ba(struct flashctx *const flash, const bool enter)
{
	const unsigned char cmd = enter ? JEDEC_ENTER_4_BYTE_ADDR_MODE : JEDEC_EXIT_4_BYTE_ADDR_MODE;
	int ret = 1;

	if (flash->chip->feature_bits & FEATURE_4BA_ENTER)
		ret = spi_send_command(flash, sizeof(cmd), 0, &cmd, NULL);
	else if (flash->chip->feature_bits & FEATURE_4BA_ENTER_WREN)
		ret = spi_simple_write_cmd(flash, cmd, 0);
	else if (flash->chip->feature_bits & FEATURE_4BA_ENTER_EAR7)
		ret = spi_set_extended_address(flash, enter ? 0x80 : 0x00);

	if (!ret)
		flash->in_4ba_mode = enter;
	return ret;
}

static int spi_enter_4ba(struct flashctx *const flash)
{
	return spi_enter_exit_4ba(flash, true);
}

static int spi_exit_4ba(struct flashctx *flash)
{
	return spi_enter_exit_4ba(flash, false);
}

static int spi_prepare_4ba(struct flashctx *const flash)
{
	flash->address_high_byte = -1;
	flash->in_4ba_mode = false;

	/* Be careful about 4BA chips and broken masters */
	if (flash->chip->total_size > 16 * 1024 && spi_master_no_4ba_modes(flash)) {
		/* If we can't use native instructions, bail out */
		if ((flash->chip->feature_bits & FEATURE_4BA_NATIVE) != FEATURE_4BA_NATIVE
		    || !spi_master_4ba(flash)) {
			msg_cerr("Programmer doesn't support this chip. Aborting.\n");
			return 1;
		}
	}

	/* Enable/disable 4-byte addressing mode if flash chip supports it */
	if (flash->chip->feature_bits & (FEATURE_4BA_ENTER | FEATURE_4BA_ENTER_WREN | FEATURE_4BA_ENTER_EAR7)) {
		int ret;
		if (spi_master_4ba(flash))
			ret = spi_enter_4ba(flash);
		else
			ret = spi_exit_4ba(flash);
		if (ret) {
			msg_cerr("Failed to set correct 4BA mode! Aborting.\n");
			return 1;
		}
	}

	return 0;
}

static int spi_prepare_quad_io(struct flashctx *const flash)
{
	if (!spi_master_quad(flash))
		return 0;

	/* Check QE bit if present */
	if (flash->chip->reg_bits.qe.reg != INVALID_REG) {
		const struct reg_bit_info qe = flash->chip->reg_bits.qe;
		uint8_t reg_val;

		if (spi_read_register(flash, qe.reg, &reg_val)) {
			msg_cwarn("Failed read chip register!\n");
			reg_val = 0;
		}
		if (!(reg_val & 1 << qe.bit_index)) {
			msg_cinfo("Quad-enable (QE) bit is unknown or unset, disabling quad i/o.\n");
			flash->chip->feature_bits &= ~FEATURE_ANY_QUAD;
		} else {
			msg_cdbg("Quad-enable (QE) bit is set.\n");
		}
	}

	return 0;
}

int spi_prepare_io(struct flashctx *const flash, const enum preparation_steps prep)
{
	if (prep != PREPARE_FULL)
		return 0;

	int ret = spi_prepare_4ba(flash);
	if (ret)
		return ret;

	ret = spi_prepare_quad_io(flash);
	if (ret)
		return ret;

	return 0;
}

void spi_finish_io(struct flashctx *const flash)
{
}
