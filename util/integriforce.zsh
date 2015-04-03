#!/usr/local/bin/zsh

# Copyright (c) 2015 Shawn Webb <shawn.webb@hardenedbsd.org>
# Author: Shawn Webb <shawn.webb@hardenedbsd.org>
# License: 2-clause BSD license

str=""

function entry_exists() {
	file=${1}
	echo ${str} | grep -qwF ${file}
	return ${?}
}

function do_executable() {
	executable=${1}

	if entry_exists ${executable}; then
		return 0
	fi

	IFS= read -r -d '' str2 <<EOF
		{
			"path": "${executable}",
			"hash": "$(sha256 -q ${executable})",
			"hash_type": "sha256",
		},
EOF

	str="${str}${str2}"

	if [ ! -x ${executable} ]; then
		echo "${executable} does not exist!" 1>2
		return 1
	fi

	for file in $(ldd ${executable} 2> /dev/null | sed -e '1d' | awk '{print $3;}'); do
		if [ ! -f ${file} ]; then
			continue
		fi

		if entry_exists ${file}; then
			continue
		fi

		IFS= read -r -d '' str2 <<EOF
		{
			"path": "${file}",
			"hash": "$(sha256 -q ${file})",
			"hash_type": "sha256",
		},
EOF
		str="${str}${str2}"
	done

	return 0
}

function do_directory() {
	dir=${1}

	for file in $(find ${dir} -type f); do
		do_executable ${file}
		if [ ! ${?} -eq 0 ]; then
			continue
		fi
	done
}

if [ ${#@} -eq 0 ]; then
	echo "USAGE: ${0} file"
	exit 1
fi

while getopts 'f:d:' o; do
	case ${o} in
		f)
			do_executable ${OPTARG}
			;;
		d)
			do_directory ${OPTARG}
			;;
		*)
			;;
	esac
done

echo "${str}"
