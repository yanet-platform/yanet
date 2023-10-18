FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    curl \
    ca-certificates \
    iproute2 \
    iputils-arping \
    iputils-tracepath \
    iputils-ping \
    tcpdump

RUN mkdir -p /etc/netplan
COPY netplan /etc/netplan/01-netcfg.yaml
