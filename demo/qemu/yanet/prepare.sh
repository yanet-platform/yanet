#!/bin/sh -e

# setup hugepages
dpdk-hugepages.py --setup=3G

modprobe vhost_net
modprobe uio_pci_generic

# bind interfaces to uio_pci_generic module
dpdk-devbind.py --bind=uio_pci_generic 00:03.0
dpdk-devbind.py --bind=uio_pci_generic 00:04.0

mkdir /run/yanet
