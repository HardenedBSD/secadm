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
	integriforce {
		path: "${executable}",
		hash: "$(sha256 -q ${executable})",
		type: "sha256",
		mode: "hard",
	},
EOF

	str="${str}${str2}"

	if [ ! -x ${executable} ]; then
		echo "${executable} does not exist!" >&2
		return 1
	fi

	for file in $(ldd -f '%p\n' ${executable} 2> /dev/null); do
		file=$(realpath ${file})
		if [ ! -f ${file} ]; then
			continue
		fi

		if entry_exists ${file}; then
			continue
		fi

		IFS= read -r -d '' str2 <<EOF
	integriforce {
		path: "${file}",
		hash: "$(sha256 -q ${file})",
		type: "sha256",
		mode: "hard",
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

function secadm_check_dups() {
	config=${1}
	res=0

	if [ ${#config} -eq 0 ]; then
		echo "USAGE: ${0} /path/to/config" >&2
		return 1
	fi

	# This assumes the path line is immediately below the
	# integriforce line
	
	tfile=$(mktemp)
	if [ -z "${tfile}" ]; then
		return 0
	fi
	
	for entry in $(grep -A 1 integriforce ${config} | grep path); do
		entry=${entry:gs/\"/}
		entry=${entry:gs/;/}
		entry=${entry:gs/,/}
		if [ -f ${entry} ]; then
			echo ${entry} >> ${tfile}
		fi
	done

	sort ${tfile} > ${tfile}.sort
	mv ${tfile}.sort ${tfile}
	uniq -c ${tfile} | while read line; do
		entries=$(echo ${line} | awk '{print $1;}')
		file=$(echo ${line} | awk '{print $2;}')
		if [ ${entries} -gt 1 ]; then
			res=$((${res} + 1))
			echo "[-] ${file} has ${entries} duplicates" >&2
		fi
	done

	rm ${tfile}

	return ${res}
}

if [ ${#@} -eq 0 ]; then
	echo "USAGE: ${0} [-c <config>] [-d <directory>] [-f <file>]"
	echo "ARGUMENTS:"
	echo "    -c <config>\tCheck the configuration file for duplicate Integriforce entries."
	echo "             \tThe Integriforce section must be the last section of the config file."
	echo "    -d <dir>\tOutput Integriforce configuration for executable files in <dir> and their dependencies."
	echo "    -f <file>\tOutput Integriforce configuration for <file> and its dependencies."
	exit 1
fi

while getopts 'c:d:f:' o; do
	case ${o} in
		c)
			secadm_check_dups ${OPTARG}
			exit ${?}
			;;
		d)
			do_directory ${OPTARG}
			;;
		f)
			do_executable ${OPTARG}
			;;
		*)
			;;
	esac
done

echo "${str}"
