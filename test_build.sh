#!/bin/sh
set -e

${MAKECMD:-make} clean
${MAKECMD:-make} -j${CPUS:-$(nproc)} CC="${CC:-ccache cc}" CONFIG_EVERYTHING=yes
