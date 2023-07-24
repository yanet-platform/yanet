YANET is an open-source extensible framework for software forwarding traffic based on DPDK.

<img alt="YANET — software forwarding traffic" src="flows.svg" />

# Quick Start
- Build docker image:
```
$ cd yanet/docker
$ make
```

- Build YANET:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanet/builder
# meson setup build
# meson compile -C build
# meson install -C build
```

- Run Unittests:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanet/builder
# meson setup -Dtarget=unittest build_unittest
# meson compile -C build_unittest
# meson test -C build_unittest
```
