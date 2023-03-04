#!/bin/sh

cd

[ "${IDENT}" ] || IDENT=$(mktemp -u XXXXXXXX)

CCACHE=/ccache/${IDENT}.img

[ -f ${CCACHE} ] || zcat cache.img.gz >${CCACHE}

AV_ARGS="${ANITA_VMM_ARGS} -drive file=${CCACHE},index=1,media=disk,format=raw"

if [ $# -eq 0 ]; then
	exec anita --vmm-args "${AV_ARGS}" --memory-size=${MEM_SIZE} \
		interact ${INST_IMG}
else
	exec anita --vmm-args "${AV_ARGS}" --memory-size=${MEM_SIZE} \
		--persist --run ". ./init && manitest \"$*\"" \
		boot ${INST_IMG}
fi
