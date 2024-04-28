FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    ninja-build \
    pkg-config \
    git \
    libnuma-dev \
    libibverbs-dev \
    libpcap-dev \
    libsystemd-dev \
    libyaml-cpp-dev \
    libgtest-dev \
    libgmock-dev \
    bison \
    flex \
    libfl-dev \
    netbase \
    gdb \
    vim \
    devscripts \
    debhelper \
    dupload \
    python3-pyelftools \
    protobuf-compiler \
    libprotobuf-dev

WORKDIR /project
