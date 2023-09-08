FROM ubuntu:22.04


RUN apt-get update && apt-get upgrade -y

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    ninja-build \
    git \
    libnuma-dev \
    libibverbs-dev \
    libpcap-dev \
    python3-pyelftools \
    pkg-config \
    autoconf \
    automake \
    libtool \
    curl \
    gdb \
    vim \
    ca-certificates

RUN mkdir -p /project
WORKDIR /project


# DPDK
ENV DPDK_VERSION 22.11.2

WORKDIR /project
RUN curl https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz -o dpdk.tar.xz
RUN mkdir dpdk && \
    tar -xf dpdk.tar.xz -C dpdk --strip-components=1

# DPDK config
COPY rte_config_append.h rte_config_append.h
RUN cat rte_config_append.h >> dpdk/config/rte_config.h

# fix multiple definition
RUN curl -L https://github.com/DPDK/dpdk/commit/cf095b1e65e63e3bbc9e285a66bc369758c39fc7.patch -o bpf_validate.patch
RUN cd dpdk && \
    patch -p1 < ../bpf_validate.patch

WORKDIR /project/dpdk
RUN mkdir build
RUN meson setup --prefix=/usr -D disable_libs=flow_classify -D enable_driver_sdk=true -D disable_drivers=net/mlx4 -D tests=false build
RUN meson compile -C build
RUN meson install -C build


# JSON
ENV NLOHMANN_JSON_VERSION 3.11.2

WORKDIR /project
RUN curl -L https://github.com/nlohmann/json/releases/download/v${NLOHMANN_JSON_VERSION}/json.hpp -o json.hpp
RUN mkdir -p /usr/include/nlohmann && \
    cp -v json.hpp /usr/include/nlohmann/


# protobuf
ENV PROTOBUF_VERSION 21.12

WORKDIR /project
RUN git clone -b v${PROTOBUF_VERSION} https://github.com/protocolbuffers/protobuf

WORKDIR /project/protobuf
RUN git submodule update --init --recursive
RUN ./autogen.sh && \
    ./configure --prefix=/usr
RUN make
RUN make install && \
    ldconfig


WORKDIR /project
RUN rm -rf *


RUN apt-get update && apt-get install -y --no-install-recommends \
    libsystemd-dev \
    libyaml-cpp-dev \
    libgtest-dev \
    libgmock-dev \
    bison \
    flex \
    libfl-dev \
    netbase
