#!/bin/sh -e

case "$1" in
	start)
		cat /etc/yadecap/hugepages | tee /sys/devices/system/node/node*/hugepages/hugepages-1048576kB/nr_hugepages
		echo "off" | tee /sys/devices/system/cpu/smt/control || true

		;;
	stop)
		echo 0 | tee /sys/devices/system/node/node*/hugepages/hugepages-1048576kB/nr_hugepages

		;;
	*)
		exit 1
esac
