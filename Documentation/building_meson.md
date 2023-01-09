# Compiling from Source with meson

## Dependencies:

  * C compiler (GCC | Clang) *
  * meson >=0.53.0 *
  * ninja *
  * pkg-config *
  * system-headers ***
  * libpci ***
  * libusb1 >=1.0.9 ***
  * libftdi1 ***
  * libjaylink ***
  * libgpiod (Linux only) ***

\*   Compile time dependency
\*** Runtime / Programmer specific

## Build Options:
  * classic_cli=auto/enabled/disabled
  * classic_cli_default_programmer=<programmer_name>:<programmer_params>
  * classic_cli_print_wiki=auto/enabled/disabled
  * ich_descriptors_tool=auto/enabled/disabled
  * use_internal_dmi=true/false
  * programmer=...

## Configure
```
meson builddir -D<your_options>
```
- __builddir__ is the directory in which flashrom will be build
- for all available options see `meson_options.txt`

## Compile
```
ninja -C builddir
```

## Install
```
ninja -C builddir install
```

## System specific information
### Ubuntu / Debian (Linux)
  * __linux-headers__ are version specific
```
apt-get install -y gcc meson ninja-build pkg-config \
	linux-headers-generic libpci-dev libusb-1.0-0-dev libftdi1-dev \
	libjaylink-dev libgpiod-dev
```

### ArchLinux / Manjaro
  * __libjaylink__ is not available through the package manager
```
pacman -S --noconfirm gcc meson ninja pkg-config \
	pciutils libusb libftdi libgpiod
```

### NixOS / Nixpkgs
```
nix-shell <flashrom_source>/util/shell.nix
```
or
```
nix-shell -p meson ninja pkg-config pciutils libusb1 libftdi1 libjaylink libgpiod
```

### OpenSUSE
```
zypper install -y gcc meson ninja pkg-config \
	pciutils-devel libusb-1_0-devel libftdi1-devel \
	libjaylink-devel libgpiod-devel
```

### Alpine
```
apk add build-base meson ninja pkgconf pciutils-dev libusb-dev \
	libftdi1-dev libjaylink-dev linux-headers libgpiod-dev
```

### Freebsd / DragonFly BSD
  * __libjaylink__ is not available through the package manager
  * __libusb1__ is part of the base system
```
pkg install pkgconf meson ninja libpci libftdi1
```

### OpenBSD
  * __libjaylink__ is not available through the package manager
```
pkg_add install meson ninja pkg-config pciutils libusb1 libftdi1
```

### NetBSD
  * __libjaylink__ is not available through the package manager
  * note: https://www.cambus.net/installing-ca-certificates-on-netbsd/
```
pkgin install meson ninja pkg-config pciutils libusb1 libftdi1
```

### OpenIndiana (Illumos, Solaris, SunOS)
  * __libpci__ missing, pciutils is build without it
  * __libftdi1__, __libjaylink__ is not available through the package manager
  * TODO: replace __build-essential__ with the default compiler
```
pkg install build-essential meson ninja libusb-1
```

### MacOS (Homebrew)
  * Internal, PCI programmer not supported
  * __libjaylink__ is not available through the package manager
```
brew install meson ninja pkg-config libusb libftdi
```
