#!/bin/sh
set -e

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

if command -v meson >/dev/null 2>&1; then
	meson setup --buildtype release ${TEMP_DIR}/build
	ninja ${CPUS:+-j${CPUS}} -C ${TEMP_DIR}/build
	FLASHPROG=${TEMP_DIR}/build/flashprog
else
	${MAKECMD:-make} clean
	${MAKECMD:-make} -j${CPUS:-$(nproc)} CC="${CC:-ccache cc}" CONFIG_EVERYTHING=yes
	FLASHPROG=./flashprog
fi

dd bs=128K count=1 </dev/urandom >${TEMP_DIR}/rand
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -w ${TEMP_DIR}/rand
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -r ${TEMP_DIR}/bak
cmp ${TEMP_DIR}/rand ${TEMP_DIR}/bak

dd bs=128K count=1 </dev/urandom >${TEMP_DIR}/rand
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -w ${TEMP_DIR}/rand
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -v ${TEMP_DIR}/rand

dd bs=128K count=1 </dev/zero | tr '\000' '\377' >${TEMP_DIR}/empty
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -E
${FLASHPROG} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -v ${TEMP_DIR}/empty
