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
