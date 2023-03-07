#!/bin/sh
set -e

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

${MAKECMD:-make} clean
${MAKECMD:-make} -j${CPUS:-$(nproc)} CC="${CC:-ccache cc}" CONFIG_EVERYTHING=yes
FLASHROM=./flashrom

dd bs=128K count=1 </dev/urandom >${TEMP_DIR}/rand
${FLASHROM} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -w ${TEMP_DIR}/rand
${FLASHROM} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -r ${TEMP_DIR}/bak
cmp ${TEMP_DIR}/rand ${TEMP_DIR}/bak

dd bs=128K count=1 </dev/urandom >${TEMP_DIR}/rand
${FLASHROM} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -w ${TEMP_DIR}/rand
${FLASHROM} -p dummy:emulate=M25P10.RES,image=${TEMP_DIR}/image -c M25P10 -v ${TEMP_DIR}/rand
