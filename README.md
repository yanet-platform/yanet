<img alt="YANET — software forwarding traffic" src="flows.svg" />

# YANET
YANET is an open-source extensible framework for software forwarding traffic based on DPDK.

## Introduction
The main objective of our solution is to be fault-tolerant and high-performance traffic processor. This is achieved due to the absence of context switching, no data race, constant complexity of algorithms, lockless. And covering with autotests.

## Features
- IPv4/IPv6 routing
- Dynamic routing is based on integration with BIRD
- ECMP with weight
- MPLS encapsulation
- Dot1q ethernet encapsulation
- ACL
- Stateful firewall
- Layer-4 load balancer
- IPIP tunnel
- NAT64 stateless/stateful
- Telemetry via [telegraf](https://github.com/influxdata/telegraf)
- Over 200Gbps network bandwidth
- Advanced autotests

## Quick Start
You can build YANET in [docker](https://www.docker.com/) container and run it with virtual ports. See [DEMO](demo).

## Running Autotests
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder

# meson setup --prefix=/usr -Dtarget=autotest build_autotest
# meson compile -C build_autotest
# meson install -C build_autotest
# yanet-autotest-run.py autotest/units/001_one_port
or
# yanet-autotest-run.py autotest/units/001_one_port autotest/units/001_one_port/019_acl_decap_route
```

## Dependencies
- [DPDK](https://github.com/DPDK/dpdk)
- [JSON](https://github.com/nlohmann/json)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf)

## License
[Apache License, Version 2.0](LICENSE)

## Contributing
We are glad to welcome new contributors! See the [CONTRIBUTING](CONTRIBUTING.md) file for details.
