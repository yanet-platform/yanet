#pragma once

#include <array>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "acl.h"
#include "balancer.h"
#include "common/actions.h"
#include "config.h"
#include "dataplane/config.h"
#include "memory_manager.h"
#include "neighbor.h"
#include "result.h"
#include "scheduler.h"
#include "type.h"

namespace common::idp
{

constexpr inline char socketPath[] = "/run/yanet/dataplane.sock";

enum class errorType : uint32_t
{
	busRead,
	busWrite,
	busParse,
	size
};

enum class requestType : uint32_t
{
	updateGlobalBase,
	updateGlobalBaseBalancer,
	getGlobalBase,
	getWorkerStats,
	getSlowWorkerStats,
	get_worker_gc_stats,
	get_dregress_counters,
	get_ports_stats,
	get_ports_stats_extended,
	getControlPlanePortStats,
	getPortStatsEx,
	getFragmentationStats,
	getFWState,
	getFWStateStats,
	clearFWState,
	getConfig,
	getErrors,
	getReport,
	lpm4LookupAddress,
	lpm6LookupAddress,
	nat64stateful_state,
	balancer_connection,
	balancer_service_connections,
	balancer_real_connections,
	limits,
	samples,
	hitcount_dump,
	debug_latch_update,
	unrdup_vip_to_balancers,
	update_vip_vport_proto,
	version,
	get_shm_info,
	get_shm_tsc_info,
	set_shm_tsc_state,
	dump_physical_port,
	balancer_state_clear,
	neighbor_show,
	neighbor_insert,
	neighbor_remove,
	neighbor_clear,
	neighbor_flush,
	neighbor_update_interfaces,
	neighbor_stats,
	memory_manager_update,
	memory_manager_stats,
	size, // size should always be at the bottom of the list, this enum allows us to find out the size of the enum list
};

using labelExp = std::tuple<uint32_t, ///< label
                            uint8_t>; ///< exp

using nexthopInterface = std::vector<std::tuple<tInterfaceId,
                                                labelExp, ///< first
                                                labelExp>>; ///< second

using value = std::tuple<globalBase::eNexthopType,
                         nexthopInterface>; ///< @todo: std::variant. @todo: rename

using port_stats_t = std::map<tPortId,
                              std::tuple<uint64_t, ///< rx_packets
                                         uint64_t, ///< rx_bytes
                                         uint64_t, ///< rx_errors
                                         uint64_t, ///< rx_drops
                                         uint64_t, ///< tx_packets
                                         uint64_t, ///< tx_bytes
                                         uint64_t, ///< tx_errors
                                         uint64_t>>; ///< tx_drops

namespace lpm
{
using insert = std::vector<std::tuple<ip_prefix_t,
                                      uint32_t>>; ///< value_id

using remove = std::vector<ip_prefix_t>;

using clear = std::tuple<>;

using request = std::vector<std::tuple<tVrfId,
                                       std::variant<insert,
                                                    remove,
                                                    clear>>>;
}

namespace updateGlobalBase
{
enum class requestType : uint32_t
{
	clear, ///< clear logicalPorts, decaps, interfaces, nat64statefuls, nat64statelesses
	updateLogicalPort,
	updateDecap,
	updateDregress, ///< @todo: slowWorker
	update_route,
	updateInterface,
	nat64stateful_update,
	nat64stateful_pool_update,
	updateNat64stateless,
	updateNat64statelessTranslation,
	update_balancer,
	update_balancer_services,
	route_lpm_update,
	route_value_update,
	route_tunnel_lpm_update,
	route_tunnel_weight_update,
	route_tunnel_value_update,
	early_decap_flags,
	acl_network_ipv4_source,
	acl_network_ipv4_destination,
	acl_network_ipv6_source,
	acl_network_ipv6_destination_ht,
	acl_network_ipv6_destination,
	acl_network_table,
	acl_network_flags,
	acl_transport_layers,
	acl_transport_table,
	acl_total_table,
	acl_values,
	dregress_prefix_update,
	dregress_prefix_remove,
	dregress_prefix_clear,
	dregress_local_prefix_update,
	dregress_neighbor_update, ///< @todo: DELETE
	dregress_value_update,
	fwstate_synchronization_update,
	sampler_update,
	tun64_update,
	tun64mappings_update,
	serial_update,
	nat46clat_update,
	dump_tags_ids,
	tsc_state_update,
	tscs_base_value_update,
	update_host_config
};

namespace updateLogicalPort
{
using request = std::tuple<tLogicalPortId, ///< @todo: DELETE
                           tPortId,
                           uint16_t, ///< vlanId
                           tVrfId, ///< vrfId
                           std::array<uint8_t, 6>, ///< etherAddress
                           uint8_t, ///< promiscuous mode
                           common::globalBase::tFlow>;
}

namespace updateDecap
{
using request = std::tuple<tDecapId,
                           eDscpMarkType,
                           uint8_t, ///< DSCP
                           uint8_t, ///< flag_ipv6_enabled
                           common::globalBase::tFlow>;
}

namespace updateDregress
{
using request = std::tuple<dregress_id_t,
                           ipv4_address_t, ///< ipv4AddressSource
                           ipv6_address_t, ///< ipv6AddressSource
                           uint16_t, ///< udpDestinationPort,
                           uint8_t, ///< onlyLongest
                           common::globalBase::tFlow>;
}

namespace update_route
{
using tunnel = std::tuple<ipv4_address_t, ///< ipv4AddressSource
                          ipv6_address_t, ///< ipv6AddressSource
                          uint16_t, ///< udpDestinationPort
                          bool>; ///< srcRndEnabled

using request = std::tuple<tRouteId,
                           std::optional<tunnel>>;
}

namespace updateInterface
{
using request = std::tuple<tInterfaceId,
                           tAclId,
                           common::globalBase::tFlow>;
}

namespace nat64stateful_update
{
using state_timeout = std::tuple<uint16_t, ///< tcp_syn
                                 uint16_t, ///< tcp_ack
                                 uint16_t, ///< tcp_fin
                                 uint16_t, ///< udp
                                 uint16_t, ///< icmp
                                 uint16_t>; ///< other

using request = std::tuple<nat64stateful_id_t,
                           eDscpMarkType,
                           uint8_t, ///< DSCP
                           tCounterId,
                           uint32_t, ///< pool_start
                           uint32_t, ///< pool_size
                           state_timeout,
                           common::globalBase::flow_t,
                           tVrfId, ///< vrf_lan
                           tVrfId>; ///< vrf_wan
}

namespace nat64stateful_pool_update
{
using request = std::vector<ipv4_prefix_t>;
}

namespace updateNat64stateless
{
using request = std::tuple<tNat64statelessId,
                           eDscpMarkType,
                           uint8_t, ///< DSCP
                           uint8_t, ///< firewall
                           common::globalBase::tFlow,
                           std::optional<ipv6_address_t>, // defrag_farm_prefix
                           std::optional<ipv6_address_t>, // defrag_source_prefix
                           uint8_t>; ///< farm
}

namespace updateNat64statelessTranslation
{
using request = std::tuple<tNat64statelessTranslationId,
                           ipv6_address_t, ///< ipv6Address
                           ipv6_address_t, ///< ipv6DestinationAddress
                           ipv4_address_t, ///< ipv4Address
                           std::optional<std::tuple<uint16_t, uint16_t>>>; ///< ingressPort, egressPort
}

namespace nat46clat_update
{
using request = std::tuple<nat46clat_id_t,
                           ipv6_address_t, ///< ipv6_source
                           ipv6_address_t, ///< ipv6_destination
                           eDscpMarkType, ///< dscp_type
                           uint8_t, ///< dscp
                           tCounterId,
                           common::globalBase::flow_t,
                           tVrfId, ///< vrf_lan
                           tVrfId>; ///< vrf_wan
}

namespace update_balancer
{
using request = std::tuple<balancer_id_t,
                           common::ipv6_address_t, ///< source ipv6
                           common::ipv4_address_t, ///< source ipv4
                           common::globalBase::tFlow>;
}

namespace update_balancer_services
{
using service = std::tuple<balancer_service_id_t, /// service id
                           uint8_t, ///< flags
                           tCounterId, ///< size 4
                           balancer::scheduler,
                           balancer::forwarding_method, // tunneling method (default ipip)
                           uint32_t, /// default_wlc_power
                           uint32_t, ///< real_start
                           uint32_t, ///< real_size
                           std::optional<common::ipv4_prefix_t>, ///< ipv4_outer_source_network
                           std::optional<common::ipv6_prefix_t>>; ///< ipv6_outer_source_network>
using real = std::tuple<balancer_real_id_t, ///< real id
                        common::ip_address_t,
                        tCounterId>;
using request = std::tuple<
        std::vector<service>, ///< services
        std::vector<real>, ///< reals
        std::vector<balancer_real_id_t>>; ///< service real binding
}

namespace update_early_decap_flags
{
using request = bool;
}

namespace acl_network_ipv4_source
{
using request = std::vector<acl::tree_chunk_8bit_t>;
}

namespace acl_network_ipv4_destination
{
using request = std::vector<acl::tree_chunk_8bit_t>;
}

namespace acl_network_ipv6_source
{
using request = std::vector<acl::tree_chunk_8bit_t>;
}

namespace acl_network_ipv6_destination_ht
{
using request = std::vector<std::tuple<ipv6_address_t, tAclGroupId>>;
}

namespace acl_network_ipv6_destination
{
using request = std::vector<acl::tree_chunk_8bit_t>;
}

namespace acl_network_table
{
using request = std::tuple<uint32_t, std::vector<tAclGroupId>>;
}

namespace acl_network_flags
{
using request = std::vector<acl::ranges_uint8_t>;
}

namespace acl_transport_layers
{
using layer = std::tuple<std::vector<acl::ranges_uint8_t>, ///< protocol
                         std::vector<acl::ranges_uint16_t>, ///< tcp.source
                         std::vector<acl::ranges_uint16_t>, ///< tcp.destination
                         std::vector<acl::ranges_uint8_t>, ///< tcp.flags
                         std::vector<acl::ranges_uint16_t>, ///< udp.source
                         std::vector<acl::ranges_uint16_t>, ///< udp.destination
                         std::vector<acl::ranges_uint16_t>, ///< icmp.type_code
                         std::vector<acl::ranges_uint16_t>>; ///< icmp.identifier

using request = std::vector<layer>;
}

namespace acl_transport_table
{
using request = std::vector<std::tuple<acl::transport_key_t, tAclGroupId>>;
}

namespace acl_total_table
{
using request = std::vector<std::tuple<acl::total_key_t, tAclGroupId>>;
}

namespace acl_values
{
using request = std::vector<common::Actions>;
}

namespace dump_tags_ids
{
using request = std::vector<std::string>;
}

namespace route_lpm_update
{
using request = lpm::request;
}

namespace route_value_update
{
using interface = std::vector<std::tuple<tInterfaceId, ///< interface_id
                                         tCounterId, ///< counter_id
                                         std::vector<uint32_t>, ///< labels
                                         ip_address_t, ///< neighbor_address
                                         uint16_t>>; ///< nexthop_flags

using request = std::tuple<uint32_t, ///< route_value_id
                           tSocketId,
                           globalBase::eNexthopType,
                           interface>;
}

namespace route_tunnel_lpm_update
{
using request = lpm::request;
}

namespace route_tunnel_weight_update
{
using request = std::vector<uint8_t>;
}

namespace route_tunnel_value_update
{
using interface = std::tuple<uint32_t, ///< weight_start
                             uint32_t, ///< weight_size
                             std::vector<std::tuple<tInterfaceId,
                                                    tCounterId,
                                                    uint32_t, ///< label
                                                    ip_address_t, ///< nexthop_address
                                                    ip_address_t, ///< neighbor_address
                                                    uint16_t>>>; ///< nexthop_flags

using request = std::tuple<uint32_t, ///< route_tunnel_value_id
                           tSocketId,
                           globalBase::eNexthopType,
                           interface>;
}

namespace dregress_prefix_update
{
using request = std::map<ip_prefix_t,
                         uint32_t>; ///< dregress_value_id
}

namespace dregress_prefix_remove
{
using request = std::set<ip_prefix_t>;
}

namespace dregress_local_prefix_update
{
using request = std::set<ip_prefix_t>;
}

namespace dregress_neighbor_update ///< @deprecated
{
using request = std::tuple<std::set<std::tuple<common::mac_address_t, common::globalBase::tFlow>>,
                           std::set<std::tuple<common::mac_address_t, common::globalBase::tFlow>>>;
}

namespace dregress_value_update
{
using request = std::map<uint32_t, ///< dregress_value_id
                         std::set<dregress::value_t>>;
}

namespace fwstate_synchronization_update
{
using request =
        std::vector<
                std::tuple<
                        tAclId, /// < aclId
                        common::ipv6_address_t, /// < ipv6SourceAddress
                        common::ipv6_address_t, /// < multicastIpv6Address
                        common::ipv6_address_t, /// < unicastIpv6SourceAddress
                        common::ipv6_address_t, /// < unicastIpv6Address
                        std::uint16_t, /// < multicastDestinationPort
                        std::uint16_t, /// < unicastDestinationPort
                        std::vector<common::globalBase::tFlow>, /// < flows
                        common::globalBase::tFlow /// < ingressFlow
                        >>;
}

namespace sampler_update
{
using request = bool; ///< enable
}

namespace tun64_update
{
using request = std::tuple<tun64_id_t,
                           eDscpMarkType,
                           uint8_t, ///< DSCP
                           uint8_t, ///< srcRndEnabled
                           ipv6_address_t, ///< ipv6SourceAddress
                           common::globalBase::tFlow>;
}

namespace tun64mappings_update
{
using request = std::vector<std::tuple<tun64_id_t,
                                       ipv4_address_t,
                                       ipv6_address_t,
                                       tCounterId>>;
}

namespace serial_update
{
using request = uint32_t; ///< serial
}

namespace tsc_state_update
{
using request = bool;
}

namespace tscs_base_value_update
{
using request = std::tuple<uint32_t, uint32_t>;
}

namespace update_host_config
{
using request = std::tuple<common::ipv4_address_t, ///< host address ipv4
                           common::ipv6_address_t, ///< host address ipv6
                           bool>; ///< hidden ip_address of host
}

using requestVariant = std::variant<std::tuple<>,
                                    updateLogicalPort::request,
                                    updateDecap::request,
                                    updateDregress::request,
                                    update_route::request,
                                    updateInterface::request,
                                    nat64stateful_update::request,
                                    nat64stateful_pool_update::request,
                                    updateNat64stateless::request,
                                    updateNat64statelessTranslation::request,
                                    tun64_update::request,
                                    tun64mappings_update::request,
                                    update_balancer::request,
                                    update_balancer_services::request,
                                    route_tunnel_weight_update::request,
                                    acl_network_ipv4_source::request, /// + acl_network_ipv4_destination, acl_network_ipv6_source, acl_network_ipv6_destination
                                    acl_network_ipv6_destination_ht::request,
                                    acl_network_table::request, /// + aclTransportDestination
                                    acl_network_flags::request,
                                    acl_transport_layers::request,
                                    acl_transport_table::request,
                                    acl_total_table::request,
                                    acl_values::request,
                                    dump_tags_ids::request,
                                    lpm::request,
                                    route_value_update::request,
                                    route_tunnel_value_update::request,
                                    dregress_prefix_update::request,
                                    dregress_prefix_remove::request, /// + dregress_local_prefix_update::request
                                    dregress_neighbor_update::request,
                                    dregress_value_update::request,
                                    fwstate_synchronization_update::request,
                                    sampler_update::request, /// + update_early_decap_flags::request, tsc_state_update::request
                                    serial_update::request,
                                    nat46clat_update::request,
                                    tscs_base_value_update::request,
                                    update_host_config::request>;

using request = std::vector<std::tuple<requestType,
                                       requestVariant>>;

using response = eResult;
}

namespace updateGlobalBaseBalancer
{
enum class requestType : uint32_t
{
	update_balancer_unordered_real,
};

namespace update_balancer_unordered_real
{
using real_state = std::tuple<balancer_real_id_t, ///< real_id
                              bool, ///< enabled
                              uint32_t>; ///< weight

using request = std::vector<real_state>;
}

using requestVariant = std::variant<std::tuple<>,
                                    update_balancer_unordered_real::request>;

using request = std::vector<std::tuple<requestType,
                                       requestVariant>>;

using response = eResult;
}

namespace getGlobalBase ///< @todo: delete
{
/// @todo: move
using logicalPort = std::tuple<tPortId,
                               uint16_t, ///< vlanId
                               std::array<uint8_t, 6>, ///< etherAddress
                               common::globalBase::tFlow>;

/// @todo: move
using decap = std::tuple<common::globalBase::tFlow>;

/// @todo: move
using interface = std::tuple<std::array<uint8_t, 6>, ///< neighborEtherAddress
                             common::globalBase::tFlow>;

/// XXX: nat64

using globalBase = std::tuple<std::map<tLogicalPortId,
                                       logicalPort>,
                              std::map<tDecapId,
                                       decap>,
                              std::map<tInterfaceId,
                                       interface>>;

using request = std::tuple<std::set<tLogicalPortId>,
                           std::set<tDecapId>,
                           std::set<tInterfaceId>>;

using response = std::map<tSocketId,
                          globalBase>;
}

namespace getWorkerStats
{
using request = std::set<tCoreId>;

using response = std::map<tCoreId,
                          std::tuple<uint64_t, ///< iterations
                                     worker::stats::common,
                                     std::map<tPortId,
                                              worker::stats::port>>>;
}

namespace getSlowWorkerStats
{
/// @todo: move to hashtable_gc_stats?
using hashtable_gc = std::tuple<tSocketId,
                                std::string, ///< name
                                uint64_t, ///< valid_keys
                                uint64_t>; ///< iterations

using response = std::tuple<common::slowworker::stats_t,
                            std::vector<hashtable_gc>>;
}

namespace get_worker_gc_stats
{
using response = std::map<tCoreId,
                          std::tuple<uint64_t, ///< iterations
                                     common::worker_gc::stats_t>>;
}

namespace get_dregress_counters
{
using response = std::vector<uint8_t>; ///< dregress_counters_v4 + dregress_counters_v6
}

namespace get_ports_stats
{
using response = port_stats_t;
}

namespace get_ports_stats_extended
{
using response = std::map<tPortId,
                          std::map<std::string, common::uint64>>; ///< all stats
}

namespace getControlPlanePortStats
{
using request = std::set<tPortId>;

using response = port_stats_t;
}

namespace getPortStatsEx
{
using response = ::common::getPortStatsEx::response;
}

namespace getFragmentationStats
{
using response = fragmentation::stats_t;
}

namespace getFWState
{
using key_t = std::tuple<
        std::uint8_t, ///< proto
        ip_address_t, ///< srcIP
        ip_address_t, ///< dstIP
        std::uint16_t, ///< srcPort
        std::uint16_t ///< dstPort
        >;

using value_t = std::tuple<
        std::uint8_t, ///< owner
        std::uint8_t, ///< flags
        std::uint32_t, ///< last_seen
        std::uint64_t, ///< packets backward
        std::uint64_t ///< packets forward
        >;

using response = std::map<
        key_t,
        value_t>;
}

namespace getFWStateStats
{
using response = fwstate::stats_t;
}

namespace getConfig
{
enum class value_type ///< @todo: delete
{
	size,
};

using values = std::vector<uint64_t>;

using response = std::tuple<std::map<uint32_t, ///< portId
                                     std::tuple<std::string, ///< interfaceName
                                                tSocketId,
                                                std::array<uint8_t, 6>, ///< etherAddress
                                                std::string>>, ///< pci
                            std::map<uint32_t, ///< coreId
                                     std::tuple<std::vector<uint32_t>, ///< inPortId
                                                tSocketId>>,
                            values>;
}

namespace getErrors
{
using response = std::map<std::string, common::uint64>;
}

namespace getReport
{
using response = std::string;
}

namespace lpm4LookupAddress
{
using request = uint32_t; ///< ipAddress

using response = std::map<tSocketId,
                          std::tuple<uint8_t, ///< found ///< @todo: std::optional
                                     uint32_t, ///< valueId
                                     value>>;
}

namespace lpm6LookupAddress
{
using request = std::array<uint8_t, 16>; ///< ipv6Address

using response = std::map<uint16_t, ///< socketId
                          std::tuple<uint8_t, ///< found ///< @todo: std::optional
                                     uint32_t, ///< valueId
                                     value>>;
}

namespace nat64stateful_state
{
using request = std::tuple<std::optional<uint32_t>>; ///< nat64stateful_id

using state = std::tuple<uint32_t, ///< nat64stateful_id
                         uint8_t, ///< proto
                         ipv6_address_t, ///< ipv6_source
                         ipv6_address_t, ///< ipv6_destination
                         uint16_t, ///< port_source
                         uint16_t, ///< port_destination
                         ipv4_address_t, ///< ipv4_source
                         uint16_t, ///< wan_port_source
                         uint32_t, ///< lan_flags
                         uint32_t, ///< wan_flags
                         std::optional<uint16_t>, ///< lan_last_seen
                         std::optional<uint16_t>>; ///< wan_last_seen

using response = std::vector<state>;
}

namespace balancer_connection
{
using connection = std::tuple<common::ip_address_t, ///< client_ip
                              std::optional<uint16_t>, ///< client_port
                              uint32_t, ///< timestamp_create
                              uint16_t, ///< timestamp_last_packet
                              uint16_t>; ///< timestamp_gc

using real_key = std::tuple<common::ip_address_t, ///< real_ip
                            std::optional<uint16_t>>; ///< real_port

using connections = std::map<std::tuple<balancer_id_t,
                                        common::ip_address_t, ///< virtual_ip
                                        uint8_t, ///< proto
                                        std::optional<uint16_t>, ///< virtual_port
                                        real_key>,
                             std::vector<connection>>;

using request = std::tuple<std::optional<balancer_id_t>,
                           std::optional<common::ip_address_t>, ///< virtual_ip
                           std::optional<uint8_t>, ///< proto
                           std::optional<uint16_t>, ///< virtual_port
                           std::optional<common::ip_address_t>, ///< real_ip
                           std::optional<uint16_t>>; ///< real_port

using response = std::map<tSocketId, connections>;
}

namespace balancer_service_connections
{
using service_key_t = std::tuple<balancer_id_t,
                                 common::ip_address_t, ///< virtual_ip
                                 uint8_t, ///< proto
                                 std::optional<uint16_t>>; ///< virtual_port

using connections = std::map<service_key_t, common::uint32>;

using response = std::map<tSocketId, connections>;
}

namespace balancer_real_connections
{
using real_key_t = std::tuple<balancer_id_t,
                              common::ip_address_t, ///< virtual_ip
                              uint8_t, ///< proto
                              uint16_t, ///< virtual_port
                              common::ip_address_t, ///< real_ip
                              uint16_t>; ///< real_port

using connections = std::map<real_key_t, common::uint32>;

using response = std::map<tSocketId, connections>;
}

namespace unrdup_vip_to_balancers
{
using request = std::tuple<balancer_id_t,
                           std::unordered_map<common::ip_address_t, std::unordered_set<common::ip_address_t>>>;

using response = eResult;
}

namespace update_vip_vport_proto
{
using request = std::tuple<uint32_t, std::unordered_set<std::tuple<common::ip_address_t, std::optional<uint16_t>, uint8_t>>>;

using response = eResult;
}

namespace version
{
using response = std::tuple<unsigned int, ///< major
                            unsigned int, ///< minor
                            std::string, ///< revision
                            std::string, ///< hash
                            std::string>; ///< custom
}

namespace get_shm_info
{
using dump_meta = std::tuple<std::string, ///< ring name
                             std::string, ///< dump tag
                             tDataPlaneConfig::DumpConfig, ///< dump config
                             tCoreId, ///< core id
                             tSocketId, ///< socket id
                             key_t, /// ipc shm key
                             uint64_t>; /// offset

using response = std::vector<dump_meta>;
}

namespace get_shm_tsc_info
{
using tsc_meta = std::tuple<tCoreId, ///< core id
                            tSocketId, ///< socket id
                            key_t, /// ipc shm key
                            uint64_t>; /// offset

using response = std::vector<tsc_meta>;
}

namespace dump_physical_port
{
using request = std::tuple<std::string, ///< interface_name
                           std::string, ///< direction (in/out/drop)
                           bool>; ///< state
}

namespace limits
{
using limit = std::tuple<std::string, ///< name
                         std::optional<tSocketId>,
                         uint64_t, ///< current
                         uint64_t>; ///< maximum

using response = std::vector<limit>;
}

namespace samples
{
using sample_t = std::tuple<uint8_t, ///< proto
                            uint32_t, ///< in_logicalport_id
                            uint32_t, ///< out_logicalport_id
                            uint16_t, ///< src_port
                            uint16_t, ///< dst_port
                            common::ip_address_t, ///< src_addr
                            common::ip_address_t>; ///< dst_addr;

using response = std::vector<sample_t>;
}

namespace hitcount_dump
{
using id = std::string;

struct Data
{
	uint64_t count; // Number of times a rule has been hit
	uint64_t bytes; // Amount of packet bytes passed through the rule
};

using response = std::unordered_map<id, Data>;
}

namespace debug_latch_update
{
enum class id : uint32_t
{
	global_base_pre_update,
	global_base_post_update,
	global_base_update_balancer,
	global_base_switch,
	balancer_update,
	size
};

using request = std::tuple<id, ///< latch id
                           uint32_t>; ///< value

using response = eResult;
}

namespace neighbor_show
{
using response = std::vector<std::tuple<std::string, ///< route_name
                                        std::string, ///< interface_name
                                        ip_address_t, ///< ip_address
                                        mac_address_t, ///< mac_address
                                        std::optional<uint32_t>>>; ///< last_update_timestamp
}

namespace neighbor_insert
{
using request = std::tuple<std::string, ///< route_name
                           std::string, ///< interface_name
                           ip_address_t, ///< ip_address
                           mac_address_t>; ///< mac_address
}

namespace neighbor_remove
{
using request = std::tuple<std::string, ///< route_name
                           std::string, ///< interface_name
                           ip_address_t>; ///< ip_address
}

namespace neighbor_update_interfaces
{
using request = std::vector<std::tuple<tInterfaceId, ///< interface_id
                                       std::string, ///< route_name
                                       std::string>>; ///< interface_name
}

namespace neighbor_stats
{
using response = common::neighbor::stats;
}

namespace memory_manager_update
{
using request = memory_manager::memory_group;
}

namespace memory_manager_stats
{
using object = std::tuple<std::string, ///< name
                          tSocketId, ///< socket_id
                          uint64_t>; ///< size

using response = std::tuple<memory_manager::memory_group,
                            std::vector<object>>;
}

//

using request = std::tuple<requestType,
                           std::variant<std::tuple<>,
                                        updateGlobalBase::request,
                                        updateGlobalBaseBalancer::request,
                                        getGlobalBase::request,
                                        getControlPlanePortStats::request,
                                        getWorkerStats::request,
                                        lpm4LookupAddress::request,
                                        lpm6LookupAddress::request,
                                        nat64stateful_state::request,
                                        balancer_connection::request,
                                        debug_latch_update::request,
                                        unrdup_vip_to_balancers::request,
                                        update_vip_vport_proto::request,
                                        dump_physical_port::request,
                                        neighbor_insert::request,
                                        neighbor_remove::request,
                                        neighbor_update_interfaces::request,
                                        memory_manager_update::request>>;

using response = std::variant<std::tuple<>,
                              updateGlobalBase::response, ///< + others which have eResult as response
                              getGlobalBase::response,
                              getWorkerStats::response,
                              getSlowWorkerStats::response,
                              get_worker_gc_stats::response,
                              get_dregress_counters::response,
                              get_ports_stats::response, ///< + getControlPlanePortStats::response
                              get_ports_stats_extended::response,
                              getPortStatsEx::response,
                              getFragmentationStats::response,
                              getFWState::response,
                              getFWStateStats::response,
                              getConfig::response,
                              getErrors::response,
                              getReport::response,
                              lpm4LookupAddress::response,
                              lpm6LookupAddress::response,
                              nat64stateful_state::response,
                              balancer_connection::response,
                              balancer_service_connections::response,
                              balancer_real_connections::response,
                              version::response,
                              limits::response,
                              samples::response,
                              hitcount_dump::response,
                              get_shm_info::response,
                              get_shm_tsc_info::response,
                              neighbor_show::response,
                              neighbor_stats::response,
                              memory_manager_stats::response>;
}
