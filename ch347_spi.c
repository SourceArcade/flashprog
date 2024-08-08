/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2022 Nicholas Chin <nic.c3.14@gmail.com>
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

#include <string.h>
#include <stdlib.h>
#include <libusb.h>
#include "platform.h"
#include "programmer.h"
#include "flash.h"

#define CH347_CMD_SPI_SET_CFG	0xC0
#define CH347_CMD_SPI_CS_CTRL	0xC1
#define CH347_CMD_SPI_OUT_IN	0xC2
#define CH347_CMD_SPI_IN	0xC3
#define CH347_CMD_SPI_OUT	0xC4
#define CH347_CMD_SPI_GET_CFG	0xCA

#define CH347_CS_ASSERT		0x00
#define CH347_CS_DEASSERT	0x40
#define CH347_CS_CHANGE		0x80
#define CH347_CS_IGNORE		0x00

#define WRITE_EP	0x06
#define READ_EP 	0x86

/* The USB descriptor says the max transfer size is 512 bytes, but the
 * vendor driver only seems to transfer a maximum of 510 bytes at once,
 * leaving 507 bytes for data as the command + length take up 3 bytes
 */
#define CH347_PACKET_SIZE 510
#define CH347_MAX_DATA_LEN (CH347_PACKET_SIZE - 3)

struct ch347_spi_data {
	struct libusb_device_handle *handle;
	unsigned int iface;
};

/* TODO: Add support for HID mode */
static const struct dev_entry devs_ch347_spi[] = {
	{0x1A86, 0x55DB, OK, "QinHeng Electronics", "USB To UART+SPI+I2C"},
	{0}
};

static int ch347_spi_shutdown(void *data)
{
	struct ch347_spi_data *ch347_data = data;

	libusb_release_interface(ch347_data->handle, ch347_data->iface);
	libusb_attach_kernel_driver(ch347_data->handle, ch347_data->iface);
	libusb_close(ch347_data->handle);
	libusb_exit(NULL);

	free(data);
	return 0;
}

static int ch347_cs_control(struct ch347_spi_data *ch347_data, uint8_t cs1, uint8_t cs2)
{
	uint8_t cmd[13] = {
		[0] = CH347_CMD_SPI_CS_CTRL,
		/* payload length, uint16 LSB: 10 */
		[1] = 10,
		[3] = cs1,
		[8] = cs2
	};

	int32_t ret = libusb_bulk_transfer(ch347_data->handle, WRITE_EP, cmd, sizeof(cmd), NULL, 1000);
	if (ret < 0) {
		msg_perr("Could not change CS!\n");
		return -1;
	}
	return 0;
}


static int ch347_write(struct ch347_spi_data *ch347_data, unsigned int writecnt, const uint8_t *writearr)
{
	unsigned int data_len;
	int packet_len;
	int transferred;
	int ret;
	uint8_t resp_buf[4] = {0};
	uint8_t buffer[CH347_PACKET_SIZE] = {0};
	unsigned int bytes_written = 0;

	while (bytes_written < writecnt) {
		data_len = min(CH347_MAX_DATA_LEN, writecnt - bytes_written );
		packet_len = data_len + 3;

		buffer[0] = CH347_CMD_SPI_OUT;
		buffer[1] = (data_len) & 0xFF;
		buffer[2] = ((data_len) & 0xFF00) >> 8;
		memcpy(buffer + 3, writearr + bytes_written, data_len);

		ret = libusb_bulk_transfer(ch347_data->handle, WRITE_EP, buffer, packet_len, &transferred, 1000);
		if (ret < 0 || transferred != packet_len) {
			msg_perr("Could not send write command\n");
			return -1;
		}

		ret = libusb_bulk_transfer(ch347_data->handle, READ_EP, resp_buf, sizeof(resp_buf), NULL, 1000);
		if (ret < 0) {
			msg_perr("Could not receive write command response\n");
			return -1;
		}
		bytes_written += data_len;
	}
	return 0;
}

static int ch347_read(struct ch347_spi_data *ch347_data, unsigned int readcnt, uint8_t *readarr)
{
	uint8_t *read_ptr = readarr;
	int ret;
	int transferred;
	unsigned int bytes_read = 0;
	uint8_t buffer[CH347_PACKET_SIZE] = {0};
	uint8_t command_buf[7] = {
		[0] = CH347_CMD_SPI_IN,
		[1] = 4,
		[2] = 0,
		[3] = readcnt & 0xFF,
		[4] = (readcnt & 0xFF00) >> 8,
		[5] = (readcnt & 0xFF0000) >> 16,
		[6] = (readcnt & 0xFF000000) >> 24
	};

	ret = libusb_bulk_transfer(ch347_data->handle, WRITE_EP, command_buf, sizeof(command_buf), &transferred, 1000);
	if (ret < 0 || transferred != sizeof(command_buf)) {
		msg_perr("Could not send read command\n");
		return -1;
	}

	while (bytes_read < readcnt) {
		ret = libusb_bulk_transfer(ch347_data->handle, READ_EP, buffer, CH347_PACKET_SIZE, &transferred, 1000);
		if (ret < 0) {
			msg_perr("Could not read data\n");
			return -1;
		}
		if (transferred > CH347_PACKET_SIZE) {
			msg_perr("libusb bug: bytes received overflowed buffer\n");
			return -1;
		}
		/* Response: u8 command, u16 data length, then the data that was read */
		if (transferred < 3) {
			msg_perr("CH347 returned an invalid response to read command\n");
			return -1;
		}
		int ch347_data_length = read_le16(buffer, 1);
		if (transferred - 3 < ch347_data_length) {
			msg_perr("CH347 returned less data than data length header indicates\n");
			return -1;
		}
		bytes_read += ch347_data_length;
		if (bytes_read > readcnt) {
			msg_perr("CH347 returned more bytes than requested\n");
			return -1;
		}
		memcpy(read_ptr, buffer + 3, ch347_data_length);
		read_ptr += ch347_data_length;
	}
	return 0;
}

static int ch347_spi_send_command(const struct flashctx *flash, unsigned int writecnt,
		unsigned int readcnt, const unsigned char *writearr, unsigned char *readarr)
{
	struct ch347_spi_data *ch347_data = flash->mst.spi->data;
	int ret = 0;

	ch347_cs_control(ch347_data, CH347_CS_ASSERT | CH347_CS_CHANGE, CH347_CS_IGNORE);
	if (writecnt) {
		ret = ch347_write(ch347_data, writecnt, writearr);
		if (ret < 0) {
			msg_perr("CH347 write error\n");
			return -1;
		}
	}
	if (readcnt) {
		ret = ch347_read(ch347_data, readcnt, readarr);
		if (ret < 0) {
			msg_perr("CH347 read error\n");
			return -1;
		}
	}
	ch347_cs_control(ch347_data, CH347_CS_DEASSERT | CH347_CS_CHANGE, CH347_CS_IGNORE);

	return 0;
}

static int32_t ch347_spi_config(struct ch347_spi_data *ch347_data, uint8_t divisor)
{
	int32_t ret;
	uint8_t buff[29] = {
		[0] = CH347_CMD_SPI_SET_CFG,
		[1] = (sizeof(buff) - 3) & 0xFF,
		[2] = ((sizeof(buff) - 3) & 0xFF00) >> 8,
		/* Not sure what these two bytes do, but the vendor
		 * drivers seem to unconditionally set these values
		 */
		[5] = 4,
		[6] = 1,
		/* Clock polarity: bit 1 */
		[9] = 0,
		/* Clock phase: bit 0 */
		[11] = 0,
		/* Another mystery byte */
		[14] = 2,
		/* Clock divisor: bits 5:3 */
		[15] = (divisor & 0x7) << 3,
		/* Bit order: bit 7, 0=MSB */
		[17] = 0,
		/* Yet another mystery byte */
		[19] = 7,
		/* CS polarity: bit 7 CS2, bit 6 CS1. 0 = active low */
		[24] = 0
	};

	ret = libusb_bulk_transfer(ch347_data->handle, WRITE_EP, buff, sizeof(buff), NULL, 1000);
	if (ret < 0) {
		msg_perr("Could not configure SPI interface\n");
	}

	/* FIXME: Not sure if the CH347 sends error responses for
	 * invalid config data, if so the code should check
	 */
	ret = libusb_bulk_transfer(ch347_data->handle, READ_EP, buff, sizeof(buff), NULL, 1000);
	if (ret < 0) {
		msg_perr("Could not receive configure SPI command response\n");
	}
	return ret;
}

static const struct spi_master spi_master_ch347_spi = {
	.features	= SPI_MASTER_4BA,
	.max_data_read	= MAX_DATA_READ_UNLIMITED,
	.max_data_write	= MAX_DATA_WRITE_UNLIMITED,
	.command	= ch347_spi_send_command,
	.multicommand	= default_spi_send_multicommand,
	.read		= default_spi_read,
	.write_256	= default_spi_write_256,
	.write_aai	= default_spi_write_aai,
	.shutdown	= ch347_spi_shutdown,
	.probe_opcode	= default_spi_probe_opcode,
};

static unsigned int ch347_div_to_khz(unsigned int div)
{
	/* divisor is a power of two starting from 2 for `div == 0` */
	const unsigned int clk_khz = 120*1000;
	return clk_khz / (1 << (div + 1));
}

/* Largely copied from ch341a_spi.c */
static int ch347_spi_init(struct flashprog_programmer *const prog)
{
	struct ch347_spi_data *ch347_data = calloc(1, sizeof(*ch347_data));
	if (!ch347_data) {
		msg_perr("Could not allocate space for SPI data\n");
		return 1;
	}

	unsigned int div = 3; /* Default to 7.5MHz */
	char *const spispeed = extract_programmer_param("spispeed");
	if (spispeed) {
		char *endptr;
		const unsigned long khz = strtoul(spispeed, &endptr, 10);
		if (*endptr != '\0' || endptr == spispeed) {
			msg_perr("Invalid `spispeed` argument, please provide the frequency in kHz.\n");
			free(spispeed);
			free(ch347_data);
			return 1;
		}
		free(spispeed);

		for (div = 0; div < 7; ++div) {
			if (ch347_div_to_khz(div) <= khz)
				break;
		}
		msg_pinfo("Using spispeed of %ukHz.\n", ch347_div_to_khz(div));
	} else {
		msg_pdbg("Using default spispeed of %ukHz.\n", ch347_div_to_khz(div));
	}

	int32_t ret = libusb_init(NULL);
	if (ret < 0) {
		msg_perr("Could not initialize libusb!\n");
		free(ch347_data);
		return 1;
	}

	/* Enable information, warning, and error messages (only). */
#if LIBUSB_API_VERSION < 0x01000106
	libusb_set_debug(NULL, 3);
#else
	libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);
#endif

	uint16_t vid = devs_ch347_spi[0].vendor_id;
	uint16_t pid = devs_ch347_spi[0].device_id;
	ch347_data->handle = libusb_open_device_with_vid_pid(NULL, vid, pid);
	if (ch347_data->handle == NULL) {
		msg_perr("Couldn't open device %04x:%04x.\n", vid, pid);
		free(ch347_data);
		return 1;
	}

	struct libusb_config_descriptor *config;
	ret = libusb_get_active_config_descriptor(libusb_get_device(ch347_data->handle), &config);
	if (ret != LIBUSB_SUCCESS) {
		msg_perr("Couldn't get config descriptor: %s (%d)\n", libusb_strerror(ret), ret);
		ret = 1;
		goto error_exit;
	}

	unsigned int iface;
	for (iface = 0; iface < config->bNumInterfaces; ++iface) {
		if (config->interface[iface].altsetting[0].bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC)
			break;
	}
	if (iface == config->bNumInterfaces) {
		msg_perr("Couldn't find compatible interface.\n");
		ret = 1;
		goto error_exit;
	}
	ch347_data->iface = iface;

	ret = libusb_detach_kernel_driver(ch347_data->handle, iface);
	if (ret != 0 && ret != LIBUSB_ERROR_NOT_FOUND)
		msg_pwarn("Cannot detach the existing USB driver. Claiming the interface may fail. %s\n",
			libusb_error_name(ret));

	ret = libusb_claim_interface(ch347_data->handle, iface);
	if (ret != 0) {
		msg_perr("Failed to claim interface 2: '%s'\n", libusb_error_name(ret));
		goto error_exit;
	}

	struct libusb_device *dev;
	if (!(dev = libusb_get_device(ch347_data->handle))) {
		msg_perr("Failed to get device from device handle.\n");
		goto error_exit;
	}

	struct libusb_device_descriptor desc;
	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0) {
		msg_perr("Failed to get device descriptor: '%s'\n", libusb_error_name(ret));
		goto error_exit;
	}

	msg_pdbg("Device revision is %d.%01d.%01d\n",
		(desc.bcdDevice >> 8) & 0x00FF,
		(desc.bcdDevice >> 4) & 0x000F,
		(desc.bcdDevice >> 0) & 0x000F);

	/* TODO: add programmer cfg for things like CS pin */
	if (ch347_spi_config(ch347_data, div) < 0)
		goto error_exit;

	return register_spi_master(&spi_master_ch347_spi, 0, ch347_data);

error_exit:
	ch347_spi_shutdown(ch347_data);
	return 1;
}

const struct programmer_entry programmer_ch347_spi = {
	.name		= "ch347_spi",
	.type		= USB,
	.devs.dev	= devs_ch347_spi,
	.init		= ch347_spi_init,
};
