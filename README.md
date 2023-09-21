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

### Build YANET
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder

# meson setup -Dyanet_config=low_memory build_release
# meson compile -C build_release
```

### Start Dataplane
```
$ docker run --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/dataplane/yanet-dataplane -c demo/dataplane.conf
```

### Start Controlplane
```
$ docker run --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/controlplane/yanet-controlplane -c demo/controlplane.conf
```

### Add Static Route
```
$ docker run --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/cli/yanet-cli rib static insert default 0.0.0.0/0 200.0.0.1
# ./build_release/cli/yanet-cli rib static insert default ::/0 fe80::1
```

### Check
```
$ docker run --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/cli/yanet-cli physicalPort
moduleName  link  speed  rx_packets  rx_bytes  rx_errors  rx_drops  tx_packets  tx_bytes  tx_errors  tx_drops
----------  ----  -----  ----------  --------  ---------  --------  ----------  --------  ---------  --------
vp0         up    10G    0           0         0          0         0           0         0          0
vp1         up    10G    0           0         0          0         0           0         0          0

# ./build_release/cli/yanet-cli fw show
id  ruleno  label   counter  rule
--  ------  ------  -------  -----------------------------------------------------
1   2       :BEGIN  0        skipto :IN ip from any to any in // 6
2   4       :BEGIN  0        allow ip from any to any
3   6       :IN     0        deny udp from 1.1.1.0/24 to {2.2.2.2 or 4.4.4.4} 8000
4   8       :IN     0        deny ip from any to any frag
5   10      :IN     0        allow ip from any to any

# ./build_release/cli/yanet-cli route lookup route0 1.2.3.4
ingress_physical_ports  prefix     nexthop    egress_interface  labels
----------------------  ---------  ---------  ----------------  ------
vp0,vp1                 0.0.0.0/0  200.0.0.1  i1

# ./build_release/cli/yanet-cli route lookup route0 ::1234
ingress_physical_ports  prefix  nexthop  egress_interface  labels
----------------------  ------  -------  ----------------  ------
vp0,vp1                 ::/0    fe80::1  i0
```

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
