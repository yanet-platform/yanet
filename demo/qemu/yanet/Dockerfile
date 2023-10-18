FROM yanetplatform/yanet

RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    openssh-server \
    openssh-client \
    bash-completion \
    pciutils \
    htop \
    curl \
    ca-certificates \
    iproute2 \
    iputils-arping \
    iputils-tracepath \
    iputils-ping \
    netbase \
    tcpdump

# this need for install linux-modules-extra
RUN apt-get update && apt-get install -y \
    linux-generic

RUN mkdir -p /etc/netplan
COPY netplan /etc/netplan/01-netcfg.yaml

RUN mkdir -p /etc/yanet
COPY *.conf /etc/yanet/

# download DPDK utils for set hugepages and bind ports
RUN curl -L https://raw.githubusercontent.com/DPDK/dpdk/v22.11/usertools/dpdk-hugepages.py -o /usr/bin/dpdk-hugepages.py && chmod +x /usr/bin/dpdk-hugepages.py
RUN curl -L https://raw.githubusercontent.com/DPDK/dpdk/v22.11/usertools/dpdk-devbind.py -o /usr/bin/dpdk-devbind.py && chmod +x /usr/bin/dpdk-devbind.py

COPY prepare.sh /usr/bin/prepare.sh

RUN ln -s /usr/bin/yanet-dataplane-corei7-low_memory /usr/bin/yanet-dataplane
RUN ln -s /usr/bin/yanet-controlplane-corei7 /usr/bin/yanet-controlplane
