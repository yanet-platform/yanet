#!/bin/sh -e

case "$1" in
	start)
		for dir in $(find /sys/devices/system/node/ -maxdepth 1 -mindepth 1 -type d -name 'node*');
		do
			echo $(cat /etc/yanet/hugepages) > $dir/hugepages/hugepages-1048576kB/nr_hugepages
		done
		echo "off" | tee /sys/devices/system/cpu/smt/control || true

		modprobe rte_kni carrier=on kthread_mode=multiple
		modprobe ib_uverbs || true
		modprobe mlx5_ib || true
		modprobe igb_uio || true

		;;
	stop)
		for dir in $(find /sys/devices/system/node/ -maxdepth 1 -mindepth 1 -type d -name 'node*');
		do
			echo 0 > $dir/hugepages/hugepages-1048576kB/nr_hugepages
		done

		rmmod rte_kni
		rmmod ib_uverbs || true
		rmmod mlx5_ib || true
		rmmod igb_uio || true

		;;
	*)
		exit 1
esac
