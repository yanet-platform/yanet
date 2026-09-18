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

Use `prefixesIsolatedCP` in the controlplane configuration to direct destination
prefixes to isolated queues:

```json
{
  "prefixesIsolatedCP": ["192.0.2.0/24", "2001:db8::/32"]
}
```

Reloading the controlplane configuration adds rules for new prefixes and removes
rules for deleted prefixes. Omit the key or provide an empty array to remove all
prefix rules. Unchanged prefixes retain their rules; failed rule operations are
retried on a later configuration update.

The worker counters `interface_isolated_cp`, `interface_isolated_cp_miss`, and
`interface_isolated_cp_fixed_mac` show controlplane packets received by isolated
workers, unexpected controlplane packets on other workers, and packets on other
workers with recognized STP destination MAC addresses. Locally generated
firewall-sync packets are excluded. These counters are available in worker
reports and Telegraf output.
