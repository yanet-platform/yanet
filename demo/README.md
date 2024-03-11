# Configure

## YANET in middlebox

### Build
Open new terminal:
```
$ cd yanet
$ docker run --rm -it -v $PWD:/project yanetplatform/builder

# meson setup build_release
# meson compile -C build_release
```
Uses the `low_memory` configuration with a reduced memory limit for the ACL, Firewall/NAT64/balancer states, etc.

### Start DataPlane
```
$ docker run --network=none --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/dataplane/yanet-dataplane -c demo/dataplane.conf
```
`--network=none` - network in this container is optional.

### Start ControlPlane
Open new terminal:
```
$ docker run --network=none --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/controlplane/yanet-controlplane -c demo/controlplane.conf
```

### Add Static Route
Open new terminal:
```
$ docker run --network=none --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/cli/yanet-cli rib static insert default 2000:1::/64 2000:1::1
# ./build_release/cli/yanet-cli rib static insert default 2000:2::/64 2000:2::1

# exit
```

## Host A

### Start container
Open new terminal:
```
$ docker run --network=none --sysctl net.ipv6.conf.all.disable_ipv6=0 --device=/dev/net/tun --cap-add=CAP_NET_ADMIN --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/demo
```
`--network=none` - network in this container is optional.
`--sysctl net.ipv6.conf.all.disable_ipv6=0` - allow IPv6.
`--device=/dev/net/tun --cap-add=CAP_NET_ADMIN` - need for create TAP interface.

### Create TAP interface
Forward traffic from unix socket and TAP interface:
```
# tap.py --interface vp0 &
```

### Configure network
```
# ip link set a 00:00:00:00:00:01 dev vp0
# ip a a 2000:1::1/64 dev vp0
# ip -6 neigh replace 2000:1:: lladdr 00:11:11:11:11:00 dev vp0 nud permanent
# ip -6 r add 2000:2::/64 via 2000:1::
```
Set the MAC addresses to the ssme as in `controlplane.conf`.

## Host B

### Start container
Open new terminal:
```
$ docker run --network=none --sysctl net.ipv6.conf.all.disable_ipv6=0 --device=/dev/net/tun --cap-add=CAP_NET_ADMIN --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/demo
```

### Create TAP interface
```
# tap.py --interface vp1 &
```

### Configure network
```
# ip link set a 00:00:00:00:00:02 dev vp1
# ip a a 2000:2::1/64 dev vp1
# ip -6 neigh replace 2000:2:: lladdr 00:22:22:22:22:00 dev vp1 nud permanent
# ip -6 r add 2000:1::/64 via 2000:2::
```

# Let's try to communicate
Open `Host A` terminal:
```
# ping 2000:2::1
PING 2000:2::1(2000:2::1) 56 data bytes
64 bytes from 2000:2::1: icmp_seq=1 ttl=63 time=0.319 ms
64 bytes from 2000:2::1: icmp_seq=2 ttl=63 time=0.176 ms
64 bytes from 2000:2::1: icmp_seq=3 ttl=63 time=0.177 ms
...
```
Success, `Host B` responded!

# Check YANET stats
Open new terminal:
```
$ docker run --network=none --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# # port rx/tx stats
# ./build_release/cli/yanet-cli physicalPort
moduleName  link  speed  rx_packets  rx_bytes  rx_errors  rx_drops  tx_packets  tx_bytes  tx_errors  tx_drops
----------  ----  -----  ----------  --------  ---------  --------  ----------  --------  ---------  --------
vp0         up    10G    1222        140596    0          0         1198        137764    0          0
vp1         up    10G    1137        132582    0          0         1145        133526    0          0

# # firewall stats
# ./build_release/cli/yanet-cli fw show
id  ruleno  label   counter  rule
--  ------  ------  -------  -----------------------------------------------------
1   2       :BEGIN  20       skipto :IN ip from any to any in // 6
2   4       :BEGIN  0        allow ip from any to any
3   6       :IN     0        deny udp from 1.1.1.0/24 to {2.2.2.2 or 4.4.4.4} 8000
4   8       :IN     0        deny ip from any to any frag
5   10      :IN     20       allow ip from any to any

# # lookup to fib
# ./build_release/cli/yanet-cli route lookup route0 2000:1::1
ingress_physical_ports  prefix       nexthop    egress_interface  labels
----------------------  -----------  ---------  ----------------  ------
vp0,vp1                 2000:1::/64  2000:1::1  i0

# ./build_release/cli/yanet-cli route lookup route0 2000:2::1
ingress_physical_ports  prefix       nexthop    egress_interface  labels
----------------------  -----------  ---------  ----------------  ------
vp0,vp1                 2000:2::/64  2000:2::1  i1
```

# Update configuration
For example, you can make changes to `demo/firewall.conf` and reload `controlplane`:
Open new terminal:
```
$ docker run --network=none --rm -it -v $PWD:/project -v /run/yanet:/run/yanet yanetplatform/builder

# ./build_release/cli/yanet-cli reload
```

Or upgrade hosts environment by edit yanet/demo.Dockerfile and build image:
```
$ cd yanet/demo
$ docker build -f demo.Dockerfile -t yanetplatform/demo .
```
