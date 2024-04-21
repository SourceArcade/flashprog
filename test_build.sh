#!/bin/sh
set -e

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

dd bs=$((128*1024)) count=1 </dev/urandom >"${TEMP_DIR}/rand"
dd bs=$((128*1024)) count=1 </dev/urandom >"${TEMP_DIR}/rand2"
dd bs=$((128*1024)) count=1 </dev/zero | tr '\000' '\377' >"${TEMP_DIR}/empty"

test_prog() {
	prog="$1"

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -w "${TEMP_DIR}/rand"
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -r "${TEMP_DIR}/bak"
	cmp "${TEMP_DIR}/rand" "${TEMP_DIR}/bak"

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -w "${TEMP_DIR}/rand2"
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -v "${TEMP_DIR}/rand2"

	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -E
	"${prog}" -p dummy:emulate=M25P10.RES,image="${TEMP_DIR}/image" -c M25P10 -v "${TEMP_DIR}/empty"
}

if [ "${MAKECMD=make}" ]; then
	${MAKECMD} clean
	eval ${MAKECMD} -j${CPUS:-$(nproc)} CC="\"${CC:-ccache cc}\"" ${MAKEARGS-CONFIG_EVERYTHING=yes}
	test_prog ./flashprog
fi

if [ "${MESONCMD=meson}" ]; then
	eval ${MESONCMD} setup ${MESONARGS--D programmer=all --buildtype release} "${TEMP_DIR}/build"
	ninja ${CPUS:+-j${CPUS}} -C "${TEMP_DIR}/build"
	test_prog "${TEMP_DIR}/build/flashprog"
fi
