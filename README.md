YANET is an open-source extensible framework for software forwarding traffic based on DPDK.

<img alt="YANET — software forwarding traffic" src="flows.svg" />

# Quick Start
- Build docker image:
```
$ cd yanet/docker
$ docker build -f builder.Dockerfile -t yanetplatform/builder .
```

- Build YANET:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder
# meson setup build
# meson compile -C build
# meson install -C build
```

- Run Unittest:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder
# meson setup -Dtarget=unittest build_unittest
# meson compile -C build_unittest
# meson test -C build_unittest
```

- Run Autotest:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder
# meson setup -Dtarget=autotest build_autotest
# meson compile -C build_autotest
# meson install -C build_autotest
# yanet-autotest-run.py autotest/units/001_one_port autotest/units/001_one_port/019_acl_decap_route
```
