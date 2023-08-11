/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2011 Carl-Daniel Hailfinger
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
 * This file determines the target os. It should only be used by the Makefile
 */

// Solaris
#if defined (__sun) && (defined(__i386) || defined(__amd64))
#define __FLASHPROG_OS__ "SunOS"
// OS X
#elif defined(__MACH__) && defined(__APPLE__)
#define __FLASHPROG_OS__ "Darwin"
// FreeBSD
#elif defined(__FreeBSD__)
#define __FLASHPROG_OS__ "FreeBSD"
// FreeBSD with glibc-based userspace (e.g. Debian/kFreeBSD)
#elif defined(__FreeBSD_kernel__) && defined(__GLIBC__)
#define __FLASHPROG_OS__ "FreeBSD-glibc"
// DragonFlyBSD
#elif defined(__DragonFly__)
#define __FLASHPROG_OS__ "DragonFlyBSD"
// NetBSD
#elif defined(__NetBSD__)
#define __FLASHPROG_OS__ "NetBSD"
// OpenBSD
#elif defined(__OpenBSD__)
#define __FLASHPROG_OS__ "OpenBSD"
// DJGPP
#elif defined(__DJGPP__)
#define __FLASHPROG_OS__ "DOS"
// MinGW (always has _WIN32 available)
#elif defined(__MINGW32__)
#define __FLASHPROG_OS__ "MinGW"
// Cygwin (usually without _WIN32)
#elif defined( __CYGWIN__)
#define __FLASHPROG_OS__ "Cygwin"
// libpayload
#elif defined(__LIBPAYLOAD__)
#define __FLASHPROG_OS__ "libpayload"
// GNU Hurd
#elif defined(__gnu_hurd__)
#define __FLASHPROG_OS__ "Hurd"
// Linux
#elif defined(__linux__)
	// There are various flags in use on Android apparently. __ANDROID__ seems to be the most trustworthy.
	#if defined(__ANDROID__)
		#define __FLASHPROG_OS__ "Android"
	#else
		#define __FLASHPROG_OS__ "Linux"
	#endif
#else
#define __FLASHPROG_OS__ "unknown"
#endif
__FLASHPROG_OS__
