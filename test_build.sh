#!/bin/sh
set -e

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

dd bs=$((128*1024)) count=1 </dev/urandom >"${TEMP_DIR}/rand"
dd bs=$((128*1024)) count=1 </dev/urandom >"${TEMP_DIR}/rand2"
dd bs=$((128*1024)) count=1 </dev/zero | tr '\000' '\377' >"${TEMP_DIR}/empty"

test_prog() {
	prog="$1"

	if [ "${CROSS_COMPILE}" ]; then
		return 0
	fi

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -w "${TEMP_DIR}/rand"
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -r "${TEMP_DIR}/bak"
	cmp "${TEMP_DIR}/rand" "${TEMP_DIR}/bak"

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -w "${TEMP_DIR}/rand2"
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -v "${TEMP_DIR}/rand2"

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -E
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -v "${TEMP_DIR}/empty"
}

build_and_test() {
	if [ "${MAKECMD=make}" ]; then
		${MAKECMD} clean
		eval ${MAKECMD} -j${CPUS:-$(nproc)} CC="\"${CC}\"" ${MAKEARGS-CONFIG_EVERYTHING=yes}
		test_prog ./flashprog
	fi

	if [ "${MESONCMD=meson}" ]; then
		eval CC="\"${CC}\"" ${MESONCMD} setup ${MESONARGS--D programmer=all --buildtype release} "${TEMP_DIR}/build"
		ninja ${CPUS:+-j${CPUS}} -C "${TEMP_DIR}/build"
		test_prog "${TEMP_DIR}/build/flashprog"

		if [ "${MAKECMD}" -a ! "${CROSS_COMPILE}" ]; then
			./flashprog -L >"${TEMP_DIR}/flashprog.supported"
			"${TEMP_DIR}/build/flashprog" -L >"${TEMP_DIR}/mashprog.supported"
			diff -u "${TEMP_DIR}/flashprog.supported" "${TEMP_DIR}/mashprog.supported"
		fi
	fi
}

CC="${CC:-ccache cc}"

build_and_test
if [ "${CC%%*cc}" = "" ] && \
   [ -x "$(command -v clang 2>&1)" ] && \
   ! "${CC}" --version 2>&1 | grep -iq clang 2>&1; then
	if [ "${CC% *cc}" != "${CC}" ]; then
		CC="${CC% *cc} clang"
	else
		CC="clang"
	fi
	rm -rf "${TEMP_DIR}/build"
	build_and_test
fi
