with import <nixpkgs> {};

stdenv.mkDerivation {
	name = "flashrom";

	buildInputs = [
		libftdi1
		libjaylink
		libusb1
		meson
		ninja
		pciutils
		pkg-config
	];
}
