/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2024 Nico Huber <nico.h@gmx.de>
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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>

#include "platform.h"
#include "programmer.h"
#include "flash.h"
#include "spi_command.h"
#include "spi.h"

#define FT4222_RESET_REQUEST		0x00
#define  FT4222_RESET_SIO		0x0000
#define  FT4222_OUTPUT_FLUSH		0x0001
#define  FT4222_INPUT_FLUSH		0x0002

#define FT4222_INFO_REQUEST		0x20
#define  FT4222_GET_VERSION		0x00
#define  FT4222_GET_CONFIG		0x01

#define FT4222_CONFIG_REQUEST		0x21
#define  FT4222_SET_CLOCK		0x04
#define  FT4222_SET_MODE		0x05
#define   FT4222_I2C_MASTER		1
#define   FT4222_I2C_SLAVE		2
#define   FT4222_SPI_MASTER		3
#define   FT4222_SPI_SLAVE		4
#define  FT4222_SPI_SET_IO_LINES	0x42
#define  FT4222_SPI_SET_CS_ACTIVE	0x43
#define   FT4222_SPI_CS_ACTIVE_LOW	0
#define   FT4222_SPI_CS_ACTIVE_HIGH	1
#define  FT4222_SPI_SET_CLK_DIV		0x44
#define  FT4222_SPI_SET_CLK_IDLE	0x45
#define   FT4222_CLK_IDLE_LOW		0
#define   FT4222_CLK_IDLE_HIGH		1
#define  FT4222_SPI_SET_CAPTURE		0x46
#define   FT4222_LEADING_CLK		0
#define   FT4222_TRAILING_CLK		1
#define  FT4222_SPI_SET_CS_MASK		0x48
#define   FT4222_SPI_CS_MASK(cs)	(1 << (cs))
#define  FT4222_SPI_RESET_TRANSACTION	0x49
#define  FT4222_SPI_RESET		0x4a
#define   FT4222_RESET_FULL		0
#define   FT4222_RESET_LINE_NUM		1

#define READ_BUFFER_SIZE		2048	/* Any power-of-2 >= 512 seems to work. */
#define READ_MAX_XFERS			4	/* Should be >1 to avoid starvation. */

#define USB_TIMEOUT			2000	/* In milliseconds. */

#define FTDI_VID			0x0403
#define FTDI_FT4222H_PID		0x601c

static const struct dev_entry devs[] = {
	{FTDI_VID, FTDI_FT4222H_PID, OK, "FTDI", "FT4222H"},
	{0},
};

struct ft4222_clock {
	unsigned short sys_idx;
	unsigned short div_log2;
};

struct ft4222_write_info {
	bool success;
	bool done;
};

struct ft4222_read_info {
	unsigned char xfer_buf[READ_MAX_XFERS * READ_BUFFER_SIZE];
	unsigned char *target_buf;
	unsigned int active;
	size_t total;
	size_t skip;
	size_t done;
};

struct ft4222 {
	struct libusb_context *usb_context;
	struct libusb_device_handle *usb_handle;
	struct ft4222_write_info write_info;
	struct ft4222_write_info dummy_write_info;
	struct ft4222_write_info deassert_cs_info;
	struct ft4222_read_info read_info;
	unsigned char control_index;
	unsigned char in_ep, out_ep;
	unsigned char io_lines;
};

static struct ft4222_clock ft4222_find_spi_clock(const struct ft4222 *ft4222, const unsigned int target_khz)
{
	const unsigned int sys_clks[] = { 60000, 24000, 48000, 80000 };
	struct ft4222_clock found = { .sys_idx = 1, .div_log2 = 9 };
	unsigned int found_khz = sys_clks[found.sys_idx] / (1 << found.div_log2);
	unsigned int sys, div;

	if (target_khz < found_khz) {
		msg_pwarn("No compatible clock found, using minimum of %ukHz.\n", found_khz);
		return found;
	}

	/* look for the highest clock below given target */
	for (sys = 0; sys < ARRAY_SIZE(sys_clks); ++sys) {
		for (div = 9; div > 0; --div) {
			const unsigned int this_khz = sys_clks[sys] / (1 << div);
			if (this_khz > target_khz)
				break;
			if (this_khz < found_khz) /* accept equal khz for higher sys clk */
				continue;

			found_khz = this_khz;
			found.sys_idx = sys;
			found.div_log2 = div;
		}
	}

	msg_pinfo("Using %ukHz SPI clock.\n", found_khz);
	return found;
}

static int receive_control(const struct ft4222 *ft4222, unsigned char *data, size_t len,
			   uint8_t request, uint16_t value, uint16_t index)
{
	return libusb_control_transfer(
		ft4222->usb_handle, LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR,
		request, value, index, data, len, USB_TIMEOUT);
}

static int ft4222_get_version(const struct ft4222 *ft4222, uint32_t *chip_version,
			      uint32_t *version2, uint32_t *version3)
{
	unsigned char buf[12];

	int ret = receive_control(ft4222, buf, sizeof(buf), FT4222_INFO_REQUEST,
				  FT4222_GET_VERSION, ft4222->control_index);
	if (ret < 0) {
		msg_perr("Failed to query version: %s (%d)\n", libusb_strerror(ret), ret);
		return SPI_PROGRAMMER_ERROR;
	}

	if (chip_version)
		*chip_version = read_be32(buf, 0);
	if (version2)
		*version2 = read_be32(buf, 4);
	if (version3)
		*version3 = read_be32(buf, 8);

	return 0;
}

static int ft4222_get_num_channels(const struct ft4222 *ft4222, unsigned int *channels)
{
	unsigned char buf[13];

	int ret = receive_control(ft4222, buf, sizeof(buf), FT4222_INFO_REQUEST,
				  FT4222_GET_CONFIG, ft4222->control_index);
	if (ret < 0) {
		msg_perr("Failed to query config: %s (%d)\n", libusb_strerror(ret), ret);
		return SPI_PROGRAMMER_ERROR;
	}

	switch (buf[0]) {
		case 0: *channels = 1; return 0;
		case 1: *channels = 3; return 0;
		case 2: *channels = 4; return 0;
		case 3: *channels = 1; return 0;
	}

	msg_perr("Failed to determine number of channels. Mode byte: 0x%02x\n", buf[0]);
	return SPI_PROGRAMMER_ERROR;
}

static int send_control(const struct ft4222 *ft4222,
			uint8_t request, uint16_t value, uint16_t index)
{
	return libusb_control_transfer(
		ft4222->usb_handle, LIBUSB_REQUEST_TYPE_VENDOR,
		request, value, index, NULL, 0, USB_TIMEOUT);
}

static void ft4222_flush(const struct ft4222 *ft4222, const uint16_t index)
{
	int i, ret;

	for (i = 0; i < 6; ++i) {
		ret = send_control(ft4222, 0, FT4222_OUTPUT_FLUSH, index);
		if (ret < 0) {
			msg_pwarn("FT4222 output flush failed: %s (%d)\n",
				  libusb_strerror(ret), ret);
			break;
		}
	}

	ret = send_control(ft4222, 0, FT4222_INPUT_FLUSH, index);
	if (ret < 0)
		msg_pwarn("FT4222 input flush failed: %s (%d)\n", libusb_strerror(ret), ret);
}

static void ft4222_reset(const struct ft4222 *ft4222)
{
	const int ret = send_control(ft4222, 0, FT4222_RESET_SIO, 0);
	if (ret < 0)
		msg_pwarn("FT4222 device reset failed: %s (%d)\n", libusb_strerror(ret), ret);

	ft4222_flush(ft4222, ft4222->control_index);
}

static int ft4222_config_request(const struct ft4222 *ft4222, uint8_t cmd, uint8_t data)
{
	const int ret = send_control(ft4222, FT4222_CONFIG_REQUEST,
				     (data << 8) | cmd, ft4222->control_index);
	if (ret < 0) {
		msg_perr("FT4222 config command 0x%02x failed: %s (%d)\n",
			 cmd, libusb_strerror(ret), ret);
		return SPI_PROGRAMMER_ERROR;
	}

	return 0;
}

static int ft4222_set_sys_clock(const struct ft4222 *ft4222, struct ft4222_clock clock)
{
	return ft4222_config_request(ft4222, FT4222_SET_CLOCK, clock.sys_idx);
}

static int ft4222_spi_set_io_lines(struct ft4222 *ft4222, const unsigned int lines)
{
	assert(lines == 1 || lines == 2 || lines == 4);

	if (ft4222->io_lines == lines)
		return 0;

	int ret = ft4222_config_request(ft4222, FT4222_SPI_SET_IO_LINES, lines);
	if (ret)
		return ret;

	ret = ft4222_config_request(ft4222, FT4222_SPI_RESET, FT4222_RESET_LINE_NUM);
	if (!ret)
		ft4222->io_lines = lines;

	return ret;
}

static int ft4222_configure_spi_master(struct ft4222 *ft4222, struct ft4222_clock clock, unsigned int cs)
{
	assert(cs < 4);

	/* LibFT4222 always does this for spiIdx 0. Assuming that's the
	   interface channel tied to a CS pin, and given that I couldn't
	   figure out how to make it use other channels, let's do this for
	   the channel we are going to use: */
	if (ft4222_config_request(ft4222, FT4222_SPI_RESET_TRANSACTION, /* idx => */cs))
		return SPI_PROGRAMMER_ERROR;

	if (ft4222_spi_set_io_lines(ft4222, 1) ||
	    ft4222_config_request(ft4222, FT4222_SPI_SET_CLK_DIV, clock.div_log2) ||
	    ft4222_config_request(ft4222, FT4222_SPI_SET_CLK_IDLE, FT4222_CLK_IDLE_LOW) ||
	    ft4222_config_request(ft4222, FT4222_SPI_SET_CAPTURE, FT4222_LEADING_CLK) ||
	    ft4222_config_request(ft4222, FT4222_SPI_SET_CS_ACTIVE, FT4222_SPI_CS_ACTIVE_LOW) ||
	    ft4222_config_request(ft4222, FT4222_SPI_SET_CS_MASK, FT4222_SPI_CS_MASK(cs)) ||
	    ft4222_config_request(ft4222, FT4222_SET_MODE, FT4222_SPI_MASTER))
		return SPI_PROGRAMMER_ERROR;

	return 0;
}

static void ft4222_async_write_callback(struct libusb_transfer *transfer)
{
	struct ft4222_write_info *const async_info = transfer->user_data;

	async_info->success = transfer->status == LIBUSB_TRANSFER_COMPLETED;
	async_info->done = true;
}

static int ft4222_async_write(const struct ft4222 *const ft4222,
			      struct ft4222_write_info *const async_info,
			      const unsigned char *const buf, const size_t len)
{
	unsigned char *const out_buf = buf ? (unsigned char *)buf : malloc(len);
	struct libusb_transfer *const transfer = libusb_alloc_transfer(0);

	if (!out_buf || !transfer) {
		msg_perr("Out of memory!\n");
		goto err_ret;
	}

	if (out_buf != buf)
		memset(out_buf, 0xff, len);
	async_info->done = false;

	libusb_fill_bulk_transfer(
			transfer, ft4222->usb_handle, ft4222->out_ep,
			out_buf, len, ft4222_async_write_callback, async_info, 16*USB_TIMEOUT);
	transfer->flags |= LIBUSB_TRANSFER_SHORT_NOT_OK | LIBUSB_TRANSFER_FREE_TRANSFER;
	if (out_buf != buf)
		transfer->flags |= LIBUSB_TRANSFER_FREE_BUFFER;

	const int ret = libusb_submit_transfer(transfer);
	if (ret != LIBUSB_SUCCESS) {
		msg_perr("Failed to queue %zuB transfer: %s (%d)\n",
			 len, libusb_strerror(ret), ret);
		goto err_ret;
	}

	return 0;

err_ret:
	libusb_free_transfer(transfer);
	if (out_buf != buf)
		free(out_buf);

	return SPI_GENERIC_ERROR;
}

static unsigned int ft4222_num_async_reads(const struct ft4222_read_info *info)
{
	return MIN(READ_MAX_XFERS,
		(info->total - info->done + READ_BUFFER_SIZE - 1) / READ_BUFFER_SIZE);
}

static void ft4222_async_read_callback(struct libusb_transfer *const transfer)
{
	struct ft4222_read_info *const info = transfer->user_data;
	bool warned_status = false;

	if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
		msg_perr("Read failure: %s (%d)\n",
			 libusb_strerror(transfer->status), transfer->status);
		goto free_transfer;
	}

	/* A transfer contains multiple packages of up to 512B. Each one
	   starts with a 2B status (libftdi calls it modem status). */
	size_t actual_len = transfer->actual_length;
	const unsigned char *packet = transfer->buffer;
	while (actual_len > 0) {
		const size_t packet_len = MIN(actual_len, 512);
		msg_pspew("%s: packet of %zu bytes\n", __func__, packet_len);

		if (packet_len < 2) {
			msg_perr("Read failure: Broken packet\n");
			goto free_transfer;
		}

		/* So far we always received the same status bytes.
		   Libftdi ignores them, so only warn if we get some-
		   thing different. */
		if (!warned_status && (packet[0] != 0x02 || packet[1] != 0x00)) {
			msg_pwarn("Unknown status code %02x %02x\n", packet[0], packet[1]);
			warned_status = true;
		}

		if (packet_len == 2) {
			msg_pdbg2("%s: Empty packet (%u active transfers)\n", __func__, info->active);
			break;
		}

		const size_t done_here = MIN(packet_len - 2, info->total - info->done);
		if (info->done + done_here > info->skip) {
			size_t buffer_off, packet_off;
			if (info->done < info->skip) {
				buffer_off = 0;
				packet_off = info->skip - info->done;
			} else {
				buffer_off = info->done - info->skip;
				packet_off = 0;
			}
			const size_t copy = MIN(done_here - packet_off,
						info->total - info->skip - buffer_off);
			memcpy(info->target_buf + buffer_off, packet + 2 + packet_off, copy);
		}
		info->done += done_here;
		msg_pspew("%s: Processed %zuB\n", __func__, done_here);

		actual_len -= packet_len;
		packet += packet_len;
	}

	if (info->active <= ft4222_num_async_reads(info)) {
		const int ret = libusb_submit_transfer(transfer);
		if (ret != LIBUSB_SUCCESS)
			msg_perr("Failed to re-queue %dB transfer: %s (%d)\n",
				 transfer->length, libusb_strerror(ret), ret);
		else	/* do not free re-submitted transfer */
			return;
	}

free_transfer:
	libusb_free_transfer(transfer);
	--info->active;
}

static int ft4222_async_read(const struct ft4222 *const ft4222,
			     struct ft4222_read_info *const info,
			     unsigned char *const dst, const size_t len, const size_t skip)
{
	info->target_buf = dst;
	info->active = 0;
	info->total = len + skip;
	info->skip = skip;
	info->done = 0;

	unsigned int i;
	for (i = 0; i < ft4222_num_async_reads(info); ++i) {
		struct libusb_transfer *const transfer = libusb_alloc_transfer(0);
		if (!transfer) {
			msg_perr("Out of memory!\n");
			return SPI_GENERIC_ERROR;
		}

		unsigned char *const buf = info->xfer_buf + i * READ_BUFFER_SIZE;
		libusb_fill_bulk_transfer(
			transfer, ft4222->usb_handle, ft4222->in_ep,
			buf, READ_BUFFER_SIZE, ft4222_async_read_callback,
			info, USB_TIMEOUT);

		const int ret = libusb_submit_transfer(transfer);
		if (ret != LIBUSB_SUCCESS) {
			msg_perr("Failed to queue %dB transfer: %s (%d)\n",
				 transfer->length, libusb_strerror(ret), ret);
			libusb_free_transfer(transfer);
			return SPI_GENERIC_ERROR;
		}
		++info->active;
	}

	return 0;
}

static void ft4222_async_init(struct ft4222 *ft4222)
{
	/* initialize such that ft4222_async_done() thinks we're done */
	const struct ft4222_write_info success = { .success = true, .done = true };
	ft4222->write_info = success;
	ft4222->dummy_write_info = success;
	ft4222->deassert_cs_info = success;
	ft4222->read_info.active = ft4222->read_info.total = ft4222->read_info.done = 0;
}

static bool ft4222_async_done(const struct ft4222 *ft4222)
{
	return ft4222->write_info.done &&
		ft4222->dummy_write_info.done &&
		ft4222->deassert_cs_info.done &&
		ft4222->read_info.active == 0;
}

static int ft4222_async_poll(const struct ft4222 *ft4222)
{
	while (!ft4222_async_done(ft4222)) {
		struct timeval timeout = { 10, 0 };
		const int ret = libusb_handle_events_timeout(ft4222->usb_context, &timeout);
		if (ret != LIBUSB_SUCCESS) {
			msg_perr("Polling transfers failed: %s!\n", libusb_error_name(ret));
			return SPI_GENERIC_ERROR;
		}
	}

	if (!ft4222->write_info.success ||
	    !ft4222->dummy_write_info.success ||
	    !ft4222->deassert_cs_info.success ||
	    ft4222->read_info.done < ft4222->read_info.total)
		return SPI_GENERIC_ERROR;

	return 0;
}

static int ft4222_spi_send_command(
		const struct flashctx *const flash,
		const unsigned int writecnt, const unsigned int readcnt,
		const unsigned char *const writearr, unsigned char *const readarr)
{
	struct ft4222 *const ft4222 = flash->mst.spi->data;
	int ret, poll_ret;

	ret = ft4222_spi_set_io_lines(ft4222, 1);
	if (ret)
		return ret;

	/*
	 * Single-i/o mode is full-duplex. So we send
	 *   o `writecnt` real bytes,
	 *   o `readcnt` dummy bytes, and
	 *   o an empty packet to deassert CS.
	 * Then we read but discard
	 *   o `writecnt` dummy bytes, and read
	 *   o `readcnt` real bytes.
	 */

	ft4222_async_init(ft4222);

	ret = ft4222_async_write(ft4222, &ft4222->write_info, writearr, writecnt);
	if (ret)
		goto poll;

	ret = ft4222_async_write(ft4222, &ft4222->dummy_write_info, NULL, readcnt);
	if (ret)
		goto poll;

	ret = ft4222_async_write(ft4222, &ft4222->deassert_cs_info, NULL, 0);
	if (ret)
		goto poll;

	ret = ft4222_async_read(ft4222, &ft4222->read_info, readarr,
			        /* len => */readcnt, /* skip => */writecnt);

poll:	/* we should always poll, in case we partially started transfers */
	poll_ret = ft4222_async_poll(ft4222);
	return ret ? ret : poll_ret;
}

static int ft4222_spi_send_multi_io(struct ft4222 *ft4222, const struct spi_command *cmd)
{
	const size_t read_total = cmd->high_z_len + cmd->read_len;
	size_t write_single = 0, write_multi = 0;
	unsigned int io_lines = 4;
	int ret, poll_ret;

	switch (cmd->io_mode) {
	case DUAL_OUT_1_1_2:
		io_lines = 2;
		/* fall-through */
	case QUAD_OUT_1_1_4:
		write_single = cmd->opcode_len + cmd->address_len + cmd->write_len;
		break;

	case DUAL_IO_1_2_2:
		io_lines = 2;
		/* fall-through */
	case QUAD_IO_1_4_4:
		write_single = cmd->opcode_len;
		write_multi = cmd->address_len + cmd->write_len;
		break;

	case QPI_4_4_4:
		write_multi = cmd->opcode_len + cmd->address_len + cmd->write_len;
		break;

	default:
		return SPI_FLASHPROG_BUG;
	}

	ret = ft4222_spi_set_io_lines(ft4222, io_lines);
	if (ret)
		return ret;

	/*
	 * Multi-i/o mode is half-duplex. We can send up to 15B ahead
	 * as single-i/o. Then write and read up to 65535 bytes each
	 * as multi-i/o. Looks suspiciously tailored to our use case. :)
	 *
	 * The lengths are controlled by a 5B header:
	 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	 * | 4 bit |          4 bit |       2B big-endian |      2B big-endian |
	 * +-------+----------------+---------------------+--------------------+
	 * |  0x8  | single-i/o len | multi-i/o write len | multi-i/o read len |
	 * +-------+----------------+---------------------+--------------------+
	 */

	if (write_single > 15 || write_multi > UINT16_MAX || read_total > UINT16_MAX)
		return SPI_INVALID_LENGTH;

	unsigned char *const write_buf = malloc(5 + write_single + write_multi);
	if (!write_buf)
		return SPI_GENERIC_ERROR;

	write_buf[0] = 0x80 | write_single;
	write_buf[1] = write_multi >> 8 & 0xff;
	write_buf[2] = write_multi >> 0 & 0xff;
	write_buf[3] = read_total  >> 8 & 0xff;
	write_buf[4] = read_total  >> 0 & 0xff;
	memcpy(write_buf + 5, cmd->writearr, write_single + write_multi);

	ft4222_async_init(ft4222);

	ret = ft4222_async_write(ft4222, &ft4222->write_info, write_buf, 5 + write_single + write_multi);
	if (ret)
		goto poll;

	ret = ft4222_async_read(ft4222, &ft4222->read_info, cmd->readarr,
				/* len => */cmd->read_len, /* skip => */cmd->high_z_len);

poll:	/* we should always poll, in case we partially started transfers */
	poll_ret = ft4222_async_poll(ft4222);

	free(write_buf);

	return ret ? ret : poll_ret;
}

static int ft4222_spi_send_multicommand(const struct flashctx *flash, struct spi_command *cmds)
{
	struct ft4222 *const ft4222 = flash->mst.spi->data;

	for (; !spi_is_empty(cmds); ++cmds) {
		int ret;
		if (cmds->io_mode == SINGLE_IO_1_1_1) {
			ret = ft4222_spi_send_command(flash, spi_write_len(cmds),
					spi_read_len(cmds), cmds->writearr, cmds->readarr);
		} else {
			ret = ft4222_spi_send_multi_io(ft4222, cmds);
		}
		if (ret)
			return ret;
	}

	return 0;
}

static int ft4222_shutdown(void *data)
{
	struct ft4222 *const ft4222 = data;
	libusb_close(ft4222->usb_handle);
	libusb_exit(ft4222->usb_context);
	free(data);
	return 0;
}

static const struct spi_master spi_master_ft4222 = {
	.features	= SPI_MASTER_4BA | SPI_MASTER_DUAL,
	.max_data_read	= 65530,
	.max_data_write	= MAX_DATA_WRITE_UNLIMITED,
	.command	= ft4222_spi_send_command,
	.multicommand	= ft4222_spi_send_multicommand,
	.read		= default_spi_read,
	.write_256	= default_spi_write_256,
	.shutdown	= ft4222_shutdown,
	.probe_opcode	= default_spi_probe_opcode,
};

/* Returns 0 upon success, a negative number upon errors. */
static int ft4222_spi_init(struct flashprog_programmer *const prog)
{
	struct spi_master master = spi_master_ft4222;
	uint32_t chip_version, version2, version3;
	unsigned long speed_khz = 10*1000;
	unsigned long cs = 0;
	unsigned int num_cs, i;
	char *endp;

	char *const cs_arg = extract_programmer_param("cs");
	if (cs_arg) {
		cs = strtoul(cs_arg, &endp, 10);
		if (cs_arg == endp || cs > 3) {
			msg_perr("Invalid cs setting: %s\n", cs_arg);
			free(cs_arg);
			return SPI_GENERIC_ERROR;
		}
	}
	msg_pdbg("Using CS#%lu.\n", cs);
	free(cs_arg);

	char *const spispeed = extract_programmer_param("spispeed");
	if (spispeed) {
		speed_khz = strtoul(spispeed, &endp, 10);
		if (spispeed == endp || speed_khz == 0 || speed_khz > UINT_MAX) {
			msg_perr("Invalid spispeed setting: %s kHz\n", spispeed);
			free(spispeed);
			return SPI_GENERIC_ERROR;
		}
	} else {
		msg_pinfo("Using default %lukHz clock. Use 'spispeed' parameter to override.\n",
			  speed_khz);
	}
	free(spispeed);

	char *const io_mode = extract_programmer_param("iomode");
	if (io_mode) {
		if (strcmp(io_mode, "single") == 0) {
			master.features &= ~SPI_MASTER_DUAL;
		} else if (strcmp(io_mode, "dual") == 0) {
			/* dual-i/o mode is enabled by default */
		} else if (strcmp(io_mode, "quad") == 0) {
			master.features |= SPI_MASTER_QUAD | SPI_MASTER_QPI;
		} else {
			msg_perr("Invalid iomode setting: %s\n", io_mode);
			return SPI_GENERIC_ERROR;
		}
	}
	free(io_mode);

	struct ft4222 *const ft4222 = calloc(1, sizeof(*ft4222));
	if (!ft4222) {
		msg_perr("Could not allocate space for FT4222 context\n");
		return SPI_GENERIC_ERROR;
	}

	int ret = libusb_init(&ft4222->usb_context);
	if (ret != LIBUSB_SUCCESS) {
		msg_perr("Could not initialize libusb: %s\n", libusb_error_name(ret));
		free(ft4222);
		return SPI_GENERIC_ERROR;
	}

	/* Enable information, warning, and error messages (only). */
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);

	const uint16_t vid = devs[0].vendor_id;
	const uint16_t pid = devs[0].device_id;
	ft4222->usb_handle = libusb_open_device_with_vid_pid(ft4222->usb_context, vid, pid);
	if (ft4222->usb_handle == NULL) {
		msg_perr("Couldn't open device %04x:%04x.\n", vid, pid);
		libusb_exit(ft4222->usb_context);
		free(ft4222);
		return SPI_GENERIC_ERROR;
	}

	struct libusb_config_descriptor *config;
	ret = libusb_get_active_config_descriptor(libusb_get_device(ft4222->usb_handle), &config);
	if (ret != LIBUSB_SUCCESS) {
		msg_perr("Couldn't get config descriptor: %s (%d)\n", libusb_strerror(ret), ret);
		ret = SPI_GENERIC_ERROR;
		goto shutdown;
	}

	if (config->bNumInterfaces > 1) {
		/* LibFT4222 does this. So far it's
		   not known to make a difference. */
		ft4222->control_index = 1;
	}

	ret = ft4222_get_version(ft4222, &chip_version, &version2, &version3);
	if (ret)
		goto free_config_shutdown;
	msg_pinfo("Found %s, chip version %08x (%08x %08x)\n",
		  devs[0].device_name, chip_version, version2, version3);

	ret = ft4222_get_num_channels(ft4222, &num_cs);
	if (ret)
		goto free_config_shutdown;
	if (cs >= num_cs) {
		msg_perr("Invalid cs setting: %lu, maximum is %u.\n", cs, num_cs - 1);
		ret = SPI_GENERIC_ERROR;
		goto free_config_shutdown;
	}

	if (cs >= config->bNumInterfaces) {
		msg_perr("Error: Device supports less interfaces than expected.\n");
		ret = SPI_GENERIC_ERROR;
		goto free_config_shutdown;
	}

	ret = libusb_claim_interface(ft4222->usb_handle, cs);
	if (ret != LIBUSB_SUCCESS) {
		msg_perr("Couldn't claim interface %lu: %s (%d)\n", cs, libusb_strerror(ret), ret);
		ret = SPI_GENERIC_ERROR;
		goto free_config_shutdown;
	}

	const struct libusb_interface_descriptor *const interface =
					config->interface[cs].altsetting;

	/* Try first alternate setting if there are more than one. */
	if (config->interface[cs].num_altsetting > 1) {
		ret = libusb_set_interface_alt_setting(
				ft4222->usb_handle, cs, interface->bAlternateSetting);
		if (ret != LIBUSB_SUCCESS) {
			msg_perr("Failed to select alternate interface: %s (%d)\n",
				 libusb_strerror(ret), ret);
			ret = SPI_GENERIC_ERROR;
			goto free_config_shutdown;
		}
	}

	for (i = 0; i < interface->bNumEndpoints; ++i) {
		if (interface->endpoint[i].bEndpointAddress & LIBUSB_ENDPOINT_IN)
			ft4222->in_ep = interface->endpoint[i].bEndpointAddress;
		else
			ft4222->out_ep = interface->endpoint[i].bEndpointAddress;
		if (ft4222->in_ep && ft4222->out_ep)
			break;
	}
	if (!ft4222->in_ep || !ft4222->out_ep) {
		msg_perr("Error: Couldn't find compatible endpoints.\n");
		ret = SPI_GENERIC_ERROR;
		goto free_config_shutdown;
	}

	libusb_free_config_descriptor(config);

	ft4222_reset(ft4222);

	const struct ft4222_clock clock = ft4222_find_spi_clock(ft4222, speed_khz);
	ret = ft4222_set_sys_clock(ft4222, clock);
	if (ret)
		goto shutdown;

	ret = ft4222_configure_spi_master(ft4222, clock, cs);
	if (ret)
		goto shutdown;

	return register_spi_master(&master, 0, ft4222);

free_config_shutdown:
	libusb_free_config_descriptor(config);
shutdown:
	ft4222_shutdown(ft4222);
	return ret;
}

const struct programmer_entry programmer_ft4222_spi = {
	.name			= "ft4222_spi",
	.type			= USB,
	.devs.dev		= devs,
	.init			= ft4222_spi_init,
};
