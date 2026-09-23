# Controlplane isolation

Reserve forwarding worker cores for traffic sent to the controlplane with
`workerIsolatedCP` in the dataplane configuration:

```json
{
  "workerIsolatedCP": [4, 8],
  "ports": [
    {"interfaceName": "port0", "pci": "0000:01:00.0", "coreIds": [1, 2]},
    {"interfaceName": "port1", "pci": "0000:02:00.0", "coreIds": [5, 6]}
  ]
}
```

Other required dataplane settings are omitted from this example. Each port with
forwarding cores receives one available isolated core on the same NUMA node as
its first forwarding core. Provide a distinct isolated core for each port that
needs isolation, and keep these cores separate from `coreIds`, `workerGC`, and
`controlPlaneCoreId`.

The NIC and its DPDK driver must support ingress `rte_flow` queue and RSS rules.
ARP, LLDP, and STP traffic for `01:80:c2:00:00:00` is directed to the isolated
queue. ARP isolation covers untagged and VLAN-tagged frames. Remaining traffic
matching the port's configured `rssFlags` is distributed across forwarding queues;
traffic excluded by those flags uses the first forwarding queue. With
`rssFlags: []`, all remaining traffic uses the first forwarding queue without RSS.

The mlx5 Verbs backend uses its Ethernet ARP rule for both tagged and untagged
frames. Backends such as mlx5 DV use an additional VLAN ARP rule.

Use `rulesIsolatedCP` in the controlplane configuration to direct packets matching
a DSCP value or a destination prefix to isolated queues:

```json
{
  "rulesIsolatedCP": {
    "dscp": [48],
    "dstPrefixes": [
      "192.0.2.252/32",
      "2001:db8::1/128"
    ]
  }
}
```

The selectors are combined with **OR**: matching either list is sufficient.
DSCP values must be integers from 0 to 63. Each value matches both IPv4 and IPv6;
ECN bits and the IPv6 flow label are ignored. DSCP is read from the received IP
header, so mark incoming traffic on the upstream device. These rules do not
rewrite headers or configure DCB priorities or NIC buffers.

Both lists are optional. Reloading adds new rules and removes deleted rules;
omitting a list or providing an empty array clears that selector's rules. Omitting
`rulesIsolatedCP` or setting it to `{}` clears both lists, while static ARP, LLDP,
and STP rules remain. The old `prefixesIsolatedCP` key is rejected: move its values
to `rulesIsolatedCP.dstPrefixes`.

Prefix, DSCP, and static rules share flow priority 0 and target the same isolated
queue. Ordinary forwarding uses priority 1. DSCP isolation requires an isolated
port and support for the DSCP masks on every isolated port.

Prefix and DSCP matches can overlap at priority 0. DPDK does not guarantee behavior
for overlapping rules at the same priority, even with identical actions; verify
this combination on the target NIC and PMD.

Unchanged rules retain their handles. A failed DSCP operation rejects the reload
and can be retried on a later configuration update. New DSCP rules are created
before obsolete ones are removed. Updates are not atomic: a failed update can
leave some new rules installed or some obsolete rules removed. Failed prefix
operations retain the existing behavior of logging the error and retrying on a
later update.

The worker counters `interface_isolated_cp`, `interface_isolated_cp_miss`, and
`interface_isolated_cp_fixed_mac` show controlplane packets received by isolated
workers, unexpected controlplane packets on other workers, and packets on other
workers with recognized STP destination MAC addresses. Locally generated
firewall-sync packets are excluded. These counters are available in worker
reports and Telegraf output.
