## Dependencies
Hardware:
- [DPDK compatible](https://core.dpdk.org/supported/)
- Memory: 64G

Software:
- OS: Ubuntu 18.04
- git
- gcc or clang
- DPDK v22.11.2
- nlohmann::json v3.11.2
- protobuf v21.12
- meson v0.61 or newer
- ninja
- libsystemd
- bison
- flex
- libfl

## Build DPDK and other dependencies
```
$ apt-get install -y --no-install-recommends \
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
    ca-certificates \
    python3-pip
```

Download `DPDK`:
```
$ curl https://fast.dpdk.org/rel/dpdk-22.11.2.tar.xz -o dpdk.tar.xz
$ mkdir dpdk && tar -xf dpdk.tar.xz -C dpdk --strip-components=1
```
And a fix for static linking DPDK:
```
$ curl -L https://github.com/DPDK/dpdk/commit/cf095b1e65e63e3bbc9e285a66bc369758c39fc7.patch -o bpf_validate.patch
$ cd dpdk && patch -p1 < ../bpf_validate.patch
```
Edit `dpdk/config/rte_config.h`, and set RTE_PKTMBUF_HEADROOM to 256.

Compile:
```
$ cd dpdk
$ mkdir build
$ meson setup --prefix=/usr -D platform=generic -D cpu_instruction_set=corei7 -D disable_libs=flow_classify -D enable_driver_sdk=true -D disable_drivers=net/mlx4 -D tests=false build
$ meson compile -C build
```

Install:
```
$ sudo meson install -C build
```

Download and install `nlohmann::json`:
```
$ curl -L https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp -o json.hpp
$ sudo mkdir -p /usr/include/nlohmann && sudo cp -v json.hpp /usr/include/nlohmann/
```

Download and install `protobuf`:
```
$ git clone -b v21.12 https://github.com/protocolbuffers/protobuf

$ cd protobuf
$ git submodule update --init --recursive
$ ./autogen.sh && ./configure --prefix=/usr
$ make -j
$ sudo make install && sudo ldconfig
```

## Build YANET
```
$ apt-get install -y --no-install-recommends \
    build-essential \
    meson \
    ninja-build \
    git \
    libpcap-dev \
    curl \
    ca-certificates \
    python3-pip \
    libsystemd-dev \
    bison \
    flex \
    libfl-dev
```

Install latest meson:
```
$ python3 -m pip install meson
```

Configure:
```
$ meson setup --prefix=/usr -Darch=corei7 build
```
`--prefix=/usr` - set install directory.

Available options:
- `-Darch=` - target cpu instruction set. native, corei7, broadwell, etc.
- `-Dyanet_config=` - build with config file, see `common/config.*.h`. release, low_memory, etc.
- `-Dversion_major=`, `-Dversion_minor=` - set version.

Compile:
```
$ meson compile -C build
```

Install:
```
$ sudo meson install -C build
```
