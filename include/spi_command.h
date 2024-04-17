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

#ifndef __SPI_COMMAND_H__
#define __SPI_COMMAND_H__ 1

#include <stdlib.h>
#include <stdbool.h>

/*
 * Modern SPI flashes support dual and quad i/o modes. However, there are
 * subtle differences about which parts of a transactions are transferred
 * in which mode. The transaction is generally divided into three phases:
 *   * opcode
 *   * address
 *   * data
 *
 * For each phase, the number of concurrently transferred bits is specified,
 * hence we get a triple like
 *   * 1-1-1
 * which tells us that all three phases are transferred in single i/o
 * mode. Or, for instance,
 *   * 1-4-4
 * which tells us the opcode is transferred in single i/o mode, but
 * the address and data are transferred in quad i/o mode.
 *
 * There are a few common combinations, often chips support all of them:
 *   * 1-1-1 single i/o
 *   * 1-1-2 dual output (for reads, only the flash outputs two bits at once)
 *   * 1-2-2 dual i/o (both controller and flash can transfer two bits at once)
 *   * 1-1-4 quad output (for reads, only the flash outputs four bits at once)
 *   * 1-4-4 quad i/o (both controller and flash can transfer four bits at once)
 *   * 4-4-4 QPI
 * In all modes that transfer the opcode in single i/o, the opcode tells the
 * flash what to expect, i.e. how further bytes will be transferred. This
 * achieves backwards compatibility with simple SPI controllers. The QPI
 * mode, OTOH, is not backwards compatible and usually needs to be entered
 * first with a special opcode. In QPI mode, only fast-read instructions
 * (w/ dummy cycles) are supported; the number of dummy cycles is often
 * configurable.
 *
 * For dual i/o, MOSI and MISO lines are bidirectional. So this can work
 * without any special setup, if both controller and flash are compatible.
 *
 * For quad i/o, usually the flash's /HOLD and /WP pins are re-purposed, and
 * the controller needs additional pins. The pin muxes inside the flash are
 * usually controlled by a quad-enable (QE) bit in the status register. This
 * is *not* to be confused with entering QPI mode. Quad-enable merely says
 * that the pins are available for data transfer.
 */
enum io_mode {
	SINGLE_IO_1_1_1,
	DUAL_OUT_1_1_2,
	DUAL_IO_1_2_2,
	QUAD_OUT_1_1_4,
	QUAD_IO_1_4_4,
	QPI_4_4_4,
};

enum io_mode spi_current_io_mode(const struct flashctx *);

/* describes properties of a read operation */
struct spi_read_op {
	enum io_mode io_mode;
	bool native_4ba;
	uint8_t opcode;
	uint8_t mode_byte;	/* optional byte to send after the address, if != 0 */
	uint8_t dummy_len;	/* dummy bytes (including optional mode byte) */
};

const struct spi_read_op *get_spi_read_op(const struct flashctx *);

static inline unsigned int spi_dummy_cycles(const struct spi_read_op *const op)
{
	return op->dummy_len * 8
		/ (op->io_mode == SINGLE_IO_1_1_1 ? 1
			: (op->io_mode <= DUAL_IO_1_2_2 ? 2 : 4));
}

struct spi_command {
	enum io_mode io_mode;
	size_t opcode_len;	/* bytes to write in opcode i/o phase */
	size_t address_len;	/* bytes to write in address i/o phase */
	size_t write_len;	/* bytes to write in data i/o phase */
	size_t high_z_len;	/* dummy bytes to skip in data i/o phase */
	size_t read_len;	/* bytes to read in data i/o phase */
	const unsigned char *writearr;
	unsigned char *readarr;
};
#define NULL_SPI_CMD { 0, 0, 0, 0, 0, 0, NULL, NULL, }

static inline size_t spi_write_len(const struct spi_command *const cmd)
{
	return cmd->opcode_len + cmd->address_len + cmd->write_len;
}

static inline size_t spi_read_len(const struct spi_command *const cmd)
{
	return cmd->high_z_len + cmd->read_len;
}

static inline bool spi_is_empty(const struct spi_command *const cmd)
{
	return !spi_write_len(cmd) && !spi_read_len(cmd);
}

int spi_send_command(const struct flashctx *, unsigned int writecnt, unsigned int readcnt, const unsigned char *writearr, unsigned char *readarr);
int spi_send_multicommand(const struct flashctx *, struct spi_command *cmds);

#endif				/* !__SPI_COMMAND_H__ */
