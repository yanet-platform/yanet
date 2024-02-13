#!/bin/bash

device=$1
driver=$2

modprobe $driver

if [ "$(readlink -f /sys/bus/pci/devices/$device/driver)" != "/sys/bus/pci/drivers/$driver" ]; then
    if [ -e /sys/bus/pci/devices/$device/driver ]; then
        /bin/echo $device >/sys/bus/pci/devices/$device/driver/unbind
    fi

    /bin/echo $driver >/sys/bus/pci/devices/$device/driver_override
    /bin/echo $device >/sys/bus/pci/drivers/$driver/bind
fi
