with import <nixpkgs> {};

stdenv.mkDerivation {
	name = "flashrom";

	buildInputs = [
		gcc
		gnumake
		libftdi1
		libjaylink
		libusb1
		libgpiod
		meson
		ninja
		pciutils
		pkg-config
	];
}
