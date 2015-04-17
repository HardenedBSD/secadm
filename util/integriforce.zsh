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
		echo "${executable} does not exist!" >&2
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

function secadm_check_dups() {
	config=${1}
	res=0
	tmpfile=$(mktemp)

	if [ ${#config} -eq 0 ]; then
		echo "USAGE: ${0} /path/to/config" >&2
		return 1
	fi

	# Assume the Integriforce section is the last section.
	# Trim what we look at to only the Integriforce section.
	
	line=$(grep -niF 'integriforce' ${config} | awk '{print $1;}' \
	    | sed 's/://')
	if [ ${#line} -eq 0 ]; then
		rm -f ${tmpfile}
		return 0
	fi

	foreach file in $(sed -e 1,${line}d ${config} | grep -i path \
	    | awk '{print $2;}' | sed 's/[",]//g'); do
		printout=1

		while read tfile; do
			if [ ${tfile} = ${file} ]; then
				printout=0
			fi
		done < ${tmpfile}

		if [ ${printout} -eq 1 ]; then
			count=$(sed -e 1,${line}d ${config} \
			    | grep -iw ${file} | uniq -c \
			    | awk '{print $1;}')

			if [ $((${count} + 0)) -gt 1 ]; then
				echo ${file} >> ${tmpfile}
				echo "${file} has ${count} entries"
				res=$((${res} + 1))
			fi
		fi
	done

	rm -f ${tmpfile}

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
