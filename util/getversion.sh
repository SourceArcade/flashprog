#!/bin/sh
#
# This file is part of the flashrom project.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

GETREVISION=$(dirname ${0})/getrevision.sh

version() {
	v='unknown'
	if ${GETREVISION} -c; then
		tmp=$(${GETREVISION} --revision)
		if [ $? -eq 0 ]; then
			v="${tmp}"
		fi
	fi

	if [ "$v" = unknown -a -r versioninfo.inc ]; then
		v=$(sed -n 's/^VERSION = //p' versioninfo.inc)
	fi

	echo ${v}
}

mandate() {
	d='unknown'
	if ${GETREVISION} -c flashrom.8.tmpl; then
		tmp=$(${GETREVISION} --date flashrom.8.tmpl)
		if [ $? -eq 0 ]; then
			d="${tmp}"
		fi
	fi

	if [ "$d" = unknown -a -r versioninfo.inc ]; then
		d=$(sed -n 's/^MAN_DATE = //p' versioninfo.inc)
	fi

	echo ${d}
}

show_help() {
	echo "Usage:
	${0} <command>

Commands
    -h or --help
        this message
    -v or --version
        return current/release flashrom version
    -m or --man-date
        return current/release date of the manual page
"
}

if [ $# -ne 1 ]; then
	show_help
	echo "Error: Only exactly one command allowed.">&2
	exit 1
fi

case $1 in
	-h|--help)	show_help;;
	-m|--man-date)	mandate;;
	-v|--version)	version;;
	*)
		show_help
		echo "Error: Invalid option: $1"
		exit 1
		;;
esac
