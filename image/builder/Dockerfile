FROM ubuntu:22.04 AS base

RUN apt-get update && apt-get upgrade -y

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    autoconf \
    automake \
    libtool \
    build-essential \
    ca-certificates

RUN mkdir -p /project
WORKDIR /project


# JSON
ENV NLOHMANN_JSON_VERSION 3.11.2

WORKDIR /project
RUN curl -L https://github.com/nlohmann/json/releases/download/v${NLOHMANN_JSON_VERSION}/json.hpp -o json.hpp
RUN mkdir -p /target/include/nlohmann && \
    cp -v json.hpp /target/include/nlohmann/


# protobuf
ENV PROTOBUF_VERSION 21.12

WORKDIR /project
RUN git clone -b v${PROTOBUF_VERSION} https://github.com/protocolbuffers/protobuf

WORKDIR /project/protobuf
RUN git submodule update --init --recursive
RUN ./autogen.sh && \
    ./configure --prefix=/target
RUN make -j
RUN make install && \
    ldconfig


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
    python3-pyelftools

COPY --from=base /target/ /usr/

WORKDIR /project
