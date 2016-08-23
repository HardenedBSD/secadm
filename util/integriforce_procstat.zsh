#!/usr/local/bin/zsh

function check_blacklist() {
	local list
	local f

	list=(/bin /usr/bin /sbin /usr/sbin /lib /libexec /usr/lib /usr/libexec /rescue)
	f="${1}"
	for l in ${list}; do
		if echo ${f} | grep -q "^${l}"; then
			return 1
		fi
	done

	return 0
}

function do_the_procstat_thing() {
	local p
	local bin

	ps ax | awk '{print $1;}' | sed 1d > /tmp/ps.txt
	for p in $(cat /tmp/ps.txt); do
		for bin in $(procstat -v ${p} | sed 1d | awk '{print $11;}'); do
			if [ -f ${bin} ]; then
				if file ${bin} | grep -q ELF; then
					if ! check_blacklist ${bin}; then
						continue
					fi

					echo ${bin} >> /tmp/bins.txt
				fi
			fi
		done
	done
}

function sort_the_things() {
	sort /tmp/bins.txt | uniq > /tmp/sortedbins.txt
}

function hash_the_things() {
	local f

	for f in $(cat /tmp/sortedbins.txt); do
		cat <<EOF >> /tmp/integriforce.rules
integriforce {
	path: "${f}",
	hash: "$(sha256 -q ${f})",
	type: "sha256",
	mode: "hard"
},
EOF
	done
}

if [ ${UID} -ne 0 ]; then
	echo "[-] plz2run as root" >&2
	exit 1
fi

if [ -f /tmp/bins.txt ]; then
	rm -f /tmp/bins.txt
fi

if [ -f /tmp/integriforce.rules ]; then
	rm -f /tmp/integriforce.rules
fi

do_the_procstat_thing
sort_the_things
hash_the_things
