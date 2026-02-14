/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2026 Nico Huber <nico.h@gmx.de>
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

/*
 * This file is merely mimicking the expected API, so we
 * can build test the ni845x_spi driver. Everything in
 * here is derived from the usage in `ni845x_spi.c`.
 */

#ifndef __NI845X_H__
#define __NI845X_H__ 1

#include <stdint.h>

typedef uint8_t		uInt8;
typedef uint16_t	uInt16;
typedef uint32_t	uInt32;
typedef int32_t		int32;
typedef uInt32		NiHandle;

enum {
	kNi845x12Volts,
	kNi845x15Volts,
	kNi845x18Volts,
	kNi845x25Volts,
	kNi845x33Volts,
};

void ni845xStatusToString(int32 err, uInt32 buf_size, char *buf);

int32 ni845xFindDevice(char *resource_name, NiHandle *, uInt32 *found_devices_count);
int32 ni845xFindDeviceNext(NiHandle, char *resource_name);
int32 ni845xCloseFindDeviceHandle(NiHandle);

int32 ni845xOpen(char *resource_name, uInt32 *opened_handle);
int32 ni845xSetIoVoltageLevel(uInt32 device_handle, uInt8 selected_voltage_100mV);
int32 ni845xClose(uInt32 device_handle);

int32 ni845xSpiConfigurationOpen(NiHandle *);
int32 ni845xSpiConfigurationSetClockRate(NiHandle, uInt16 SCK_freq_in_KHz);
int32 ni845xSpiConfigurationGetClockRate(NiHandle, uInt16 *clock_freq_read_KHz);
int32 ni845xSpiWriteRead(uInt32 device_handle, NiHandle, uInt32 write_size, const uInt8 *write_buf, uInt32 *read_size, uInt8 *read_buf);
int32 ni845xSpiConfigurationClose(NiHandle);

#endif				/* !__NI845X_H__ */
