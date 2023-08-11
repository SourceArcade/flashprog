#!/bin/sh

cd /home/mani/flashprog/

if [ $# -eq 0 ]; then
	exec "${DEVSHELL}"
else
	exec "${DEVSHELL}" -c "$*"
fi
