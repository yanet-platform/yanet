#pragma once

#include <inttypes.h>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include "controlplaneconfig.h"
#include "counters.h"
#include "nat46clat.h"
#include "result.h"
#include "type.h"

namespace common
{
namespace icp
{

constexpr inline char socketPath[] = "/run/yanet/controlplane.sock";

enum class requestType : uint32_t
{
	telegraf_unsafe,
	telegraf_dregress,
	telegraf_dregress_traffic,
	telegraf_balancer_service,
	telegraf_other,
	telegraf_mappings,
	getPhysicalPorts,
	getLogicalPorts,
	getDecaps,
	getDecapPrefixes,
	nat64stateful_config,
	nat64stateful_announce,
	getNat64statelesses,
	getNat64statelessTranslations,
	getNat64statelessPrefixes,
	route_config,
	route_summary,
	route_interface,
	dregress_config,
	balancer_config,
	balancer_summary,
	balancer_service,
	balancer_real_find,
	balancer_real,
	balancer_real_flush,
	balancer_announce,
	route_lookup,
	route_get,
	route_tunnel_lookup,
	route_tunnel_get,
	getRibStats,
	checkRibPrefixes,
	getDefenders,
	getPortStatsEx,
	rib_update,
	rib_flush,
	rib_summary,
	rib_prefixes,
	rib_lookup,
	rib_get,
	rib_save,
	rib_load,
	getFwList,
	limit_summary,
	controlplane_values,
	loadConfig,
	acl_unwind,
	acl_lookup,
	clearFWState,
	getSamples,
	getAclConfig,
	tun64_tunnels,
	tun64_prefixes,
	tun64_mappings,
	resolve_ip_to_fqdn,
	resolve_fqdn_to_ip,
	controlplane_durations,
	version,
	getFwLabels,
	nat46clat_config,
	nat46clat_announce,
	nat46clat_stats,
	size
};

inline const char* requestType_toString(requestType t)
{
	switch (t)
	{
		case requestType::telegraf_unsafe:
			return "telegraf_unsafe";
		case requestType::telegraf_dregress:
			return "telegraf_dregress";
		case requestType::telegraf_dregress_traffic:
			return "telegraf_dregress_traffic";
		case requestType::telegraf_balancer_service:
			return "telegraf_balancer_service";
		case requestType::telegraf_other:
			return "telegraf_other";
		case requestType::telegraf_mappings:
			return "telegraf_mappings";
		case requestType::getPhysicalPorts:
			return "getPhysicalPorts";
		case requestType::getLogicalPorts:
			return "getLogicalPorts";
		case requestType::getDecaps:
			return "getDecaps";
		case requestType::getDecapPrefixes:
			return "getDecapPrefixes";
		case requestType::nat64stateful_config:
			return "nat64stateful_config";
		case requestType::nat64stateful_announce:
			return "nat64stateful_announce";
		case requestType::getNat64statelesses:
			return "getNat64statelesses";
		case requestType::getNat64statelessTranslations:
			return "getNat64statelessTranslations";
		case requestType::getNat64statelessPrefixes:
			return "getNat64statelessPrefixes";
		case requestType::route_config:
			return "route_config";
		case requestType::route_summary:
			return "route_summary";
		case requestType::route_interface:
			return "route_interface";
		case requestType::dregress_config:
			return "dregress_config";
		case requestType::balancer_config:
			return "balancer_config";
		case requestType::balancer_summary:
			return "balancer_summary";
		case requestType::balancer_service:
			return "balancer_service";
		case requestType::balancer_real_find:
			return "balancer_real_find";
		case requestType::balancer_real:
			return "balancer_real";
		case requestType::balancer_real_flush:
			return "balancer_real_flush";
		case requestType::balancer_announce:
			return "balancer_announce";
		case requestType::route_lookup:
			return "route_lookup";
		case requestType::route_get:
			return "route_get";
		case requestType::route_tunnel_lookup:
			return "route_tunnel_lookup";
		case requestType::route_tunnel_get:
			return "route_tunnel_get";
		case requestType::getRibStats:
			return "getRibStats";
		case requestType::checkRibPrefixes:
			return "checkRibPrefixes";
		case requestType::getDefenders:
			return "getDefenders";
		case requestType::getPortStatsEx:
			return "getPortStatsEx";
		case requestType::rib_update:
			return "rib_update";
		case requestType::rib_flush:
			return "rib_flush";
		case requestType::rib_summary:
			return "rib_summary";
		case requestType::rib_prefixes:
			return "rib_prefixes";
		case requestType::rib_lookup:
			return "rib_lookup";
		case requestType::rib_get:
			return "rib_get";
		case requestType::rib_save:
			return "rib_save";
		case requestType::rib_load:
			return "rib_load";
		case requestType::getFwList:
			return "getFwList";
		case requestType::limit_summary:
			return "limit_summary";
		case requestType::controlplane_values:
			return "controlplane_values";
		case requestType::loadConfig:
			return "loadConfig";
		case requestType::acl_unwind:
			return "acl_unwind";
		case requestType::acl_lookup:
			return "acl_lookup";
		case requestType::clearFWState:
			return "clearFWState";
		case requestType::getSamples:
			return "getSamples";
		case requestType::getAclConfig:
			return "getAclConfig";
		case requestType::tun64_tunnels:
			return "tun64_tunnels";
		case requestType::tun64_prefixes:
			return "tun64_prefixes";
		case requestType::tun64_mappings:
			return "tun64_mappings";
		case requestType::resolve_ip_to_fqdn:
			return "resolve_ip_to_fqdn";
		case requestType::resolve_fqdn_to_ip:
			return "resolve_fqdn_to_ip";
		case requestType::controlplane_durations:
			return "controlplane_durations";
		case requestType::version:
			return "version";
		case requestType::getFwLabels:
			return "getFwLabels";
		case requestType::nat46clat_config:
			return "nat46clat_config";
		case requestType::nat46clat_announce:
			return "nat46clat_announce";
		case requestType::nat46clat_stats:
			return "nat46clat_stats";
		case requestType::size:
			return "unknown";
	}

	return "unknown";
}

namespace telegraf_unsafe
{
using worker_t = std::tuple<uint64_t, ///< iterations
                            worker::stats::common,
                            std::map<std::string,
                                     worker::stats::port>>;

using worker_gc_t = std::tuple<uint64_t, ///< iterations
                               worker_gc::stats_t>;

using hashtable_gc = std::tuple<tSocketId,
                                std::string, ///< name
                                uint64_t, ///< valid_keys
                                uint64_t>; ///< iterations

using tun64_stats_t = std::map<std::string, ///< moduleName
                               common::tun64::stats_t>;

using nat64stateful_stats_t = std::map<std::string, ///< name
                                       std::array<uint64_t, (size_t)nat64stateful::module_counter::size>>;

using controlplane_stats_t = std::map<std::string, ///< name
                                      uint64_t>; ///< counter

using response = std::tuple<std::map<tCoreId,
                                     worker_t>,
                            std::map<tCoreId,
                                     worker_gc_t>,
                            std::tuple<common::slowworker::stats_t,
                                       std::vector<hashtable_gc>>,
                            common::fragmentation::stats_t,
                            common::fwstate::stats_t,
                            tun64_stats_t,
                            nat64stateful_stats_t,
                            controlplane_stats_t>;
}

namespace telegraf_dregress
{
/// @todo: common::dregress::stats_t

using response = std::tuple<std::vector<uint8_t>, ///< dregress_counters_v4 + dregress_counters_v6
                            std::map<community_t, ///< @todo: vector
                                     std::string>>;
}

namespace telegraf_dregress_traffic
{
using peer = std::tuple<bool, ///< is_ipv4
                        uint32_t, ///< link_id
                        std::string, ///< nexthop
                        uint64_t, ///< packets
                        uint64_t>;

using peer_as = std::tuple<bool, ///< is_ipv4
                           uint32_t, ///< link_id
                           std::string, ///< nexthop
                           uint32_t, ///< origin_as
                           uint64_t, ///< packets
                           uint64_t>; ///< bytes

using response = std::tuple<std::vector<peer>,
                            std::vector<peer_as>>;
}

namespace telegraf_balancer_service
{
using service = std::tuple<common::ip_address_t, ///< virtual_ip
                           uint8_t, ///< proto
                           uint16_t, ///< virtual_port
                           uint64_t, ///< connections
                           uint64_t, ///< packets
                           uint64_t, ///< bytes
                           uint64_t, ///< real_disabled_packets
                           uint64_t>; ///< real_disabled_bytes

using response = std::map<std::tuple<balancer_id_t, std::string>, ///< module_name
                          std::vector<service>>;
}

namespace telegraf_other
{
using worker = std::tuple<double>; ///< usage

using port = std::map<std::string, uint64>; ///< all stats

using response = std::tuple<uint8_t, ///< flagFirst
                            std::map<coreId,
                                     worker>,
                            std::map<std::string,
                                     port>>;
}

namespace telegraf_mappings
{
using mapping = std::tuple<std::string, ///< moduleName
                           ipv4_address_t,
                           ipv6_address_t,
                           common::tun64mapping::stats_t>;

using response = std::vector<mapping>;
}

namespace getPhysicalPorts
{
using response = std::map<std::string,
                          std::tuple<uint64_t, ///< rx_packets
                                     uint64_t, ///< rx_bytes
                                     uint64_t, ///< rx_errors
                                     uint64_t, ///< rx_drops
                                     uint64_t, ///< tx_packets
                                     uint64_t, ///< tx_bytes
                                     uint64_t, ///< tx_errors
                                     uint64_t, ///< tx_drops
                                     bool, ///< status
                                     uint32_t>>; ///< speed
}

namespace getLogicalPorts
{
using response = std::map<std::string,
                          std::tuple<std::string, ///< physicalPortName
                                     uint16_t, ///< vlanId
                                     mac_address_t, ///< macAddress
                                     uint8_t>>; ///< promiscuousMode
}

namespace tun64_tunnels
{
using response = std::map<std::string, ///< moduleName
                          std::tuple<ipv6_address_t, ///< ipv6 source
                                     uint32_t, ///< prefixes count
                                     bool, ///< source rnd flag
                                     std::string>>; ///< next_module
}

namespace getDecaps
{
using response = std::map<std::string,
                          std::tuple<uint32_t, ///< prefixes count
                                     std::optional<std::tuple<bool, uint8_t>>, ///< DSCP
                                     std::string>>; ///< next_module
}

namespace getNat64statelesses
{
using response = std::map<std::string,
                          std::tuple<uint32_t, ///< translations count
                                     std::optional<ipv6_prefix_t>, ///< wkp
                                     std::optional<ipv6_prefix_t>, ///< src
                                     uint32_t, ///< prefixes count
                                     std::string>>; ///< next_module
}

namespace route_config
{
using response = std::map<std::string, controlplane::route::config_t>;
}

namespace route_summary
{
using response = std::vector<std::tuple<std::string, ///< route_name
                                        std::string>>; ///< vrf
}

namespace route_interface
{
using response = std::map<std::tuple<std::string, ///< route_name
                                     std::string>, ///< interface_name
                          std::tuple<std::set<ip_address_t>,
                                     std::optional<ipv4_address_t>, ///< neighbor
                                     std::optional<ipv6_address_t>, ///< neighbor
                                     std::optional<mac_address_t>, ///< neighbor_mac_address_v4
                                     std::optional<mac_address_t>, ///< neighbor_mac_address_v6
                                     std::string>>; ///< next_module
}

namespace dregress_config
{
using response = std::map<std::string, controlplane::dregress::config_t>;
}

namespace nat64stateful_config
{
using response = std::map<std::string, controlplane::nat64stateful::config_t>;
}

namespace balancer_config
{
using response = std::map<std::string, controlplane::balancer::config_t>;
}

namespace balancer_summary
{
using module = std::tuple<std::string, ///< module_name
                          uint64_t, ///< services
                          uint64_t, ///< reals_enabled
                          uint64_t, ///< reals
                          uint64_t, ///< connections
                          std::string>; ///< next_module

using response = std::vector<module>;
}

namespace balancer_service
{
using service = std::tuple<std::string, ///< scheduler
                           std::optional<std::string>, ///< version
                           uint64_t, ///< connections
                           uint64_t, ///< packets
                           uint64_t>; ///< bytes

using request = std::tuple<std::optional<std::string>, ///< module
                           std::optional<common::ip_address_t>, ///< virtual_ip
                           std::optional<uint8_t>, ///< proto
                           std::optional<uint16_t>>; ///< virtual_port

using response = std::map<std::tuple<balancer_id_t,
                                     std::string>, ///< module
                          std::map<std::tuple<common::ip_address_t, ///< virtual_ip
                                              uint8_t, ///< proto
                                              uint16_t>, ///< virtual_port
                                   service>>;
}

namespace balancer_real_find
{
using real = std::tuple<common::ip_address_t, ///< real_ip
                        uint16_t, ///< real_port
                        bool, ///< enabled
                        uint32_t, ///< weight
                        uint64_t, ///< connections
                        uint64_t, ///< packets
                        uint64_t>; ///< bytes

using service = std::tuple<std::string, ///< scheduler
                           std::optional<std::string>, ///< version
                           std::vector<real>>;

using request = std::tuple<std::optional<std::string>, ///< module
                           std::optional<common::ip_address_t>, ///< virtual_ip
                           std::optional<uint8_t>, ///< proto
                           std::optional<uint16_t>, ///< virtual_port
                           std::optional<common::ip_address_t>, ///< real_ip
                           std::optional<uint16_t>>; ///< real_port

using response = std::map<std::tuple<balancer_id_t,
                                     std::string>, ///< module
                          std::map<std::tuple<common::ip_address_t, ///< virtual_ip
                                              uint8_t, ///< proto
                                              uint16_t>, ///< virtual_port
                                   service>>;
}

namespace balancer_real
{
using real = std::tuple<std::string, ///< module
                        common::ip_address_t, ///< virtual_ip
                        uint8_t, ///< proto
                        uint16_t, ///< virtual_port
                        common::ip_address_t, ///< real_ip
                        uint16_t, ///< real_port
                        bool, ///< enable
                        std::optional<uint32_t>>; ///< weight

using request = std::vector<real>;
}

namespace balancer_announce
{
using announce = std::tuple<std::string, ///< module
                            common::ip_prefix_t>;

using response = std::set<announce>;
}

namespace getRibStats
{
using response = std::tuple<uint64, ///< ipv4Prefixes ///< @todo: rename
                            uint64, ///< ipv4Labelleds
                            uint64, ///< ipv6Prefixes ///< @todo: rename
                            uint64, ///< ipv6Labelleds
                            uint64, ///< values4
                            uint64, ///< values6
                            uint8>; ///< ipv4PrefixDefault
}

namespace checkRibPrefixes
{
using response = std::map<std::string, ///< prefix
                          std::string>; ///< destination
}

namespace getDefenders
{
using response = std::map<std::string, ///< defenderName
                          defender::result>;
}

namespace getPortStatsEx
{
using response = ::common::getPortStatsEx::response;
}

namespace tun64_prefixes
{
using response = std::map<std::string, ///< moduleName
                          std::set<ip_prefix_t>>; ///< ipv4 and ipv6 prefixes
}

namespace tun64_mappings
{
using response_entry = std::tuple<std::string, ///< moduleName
                                  ipv4_address_t,
                                  ipv6_address_t,
                                  std::string>; ///< net location

using mapping = std::map<std::string, ///< moduleName
                         std::map<ipv4_address_t,
                                  std::tuple<ipv6_address_t,
                                             std::string>>>; ///< net location

using response = std::vector<response_entry>;
}

namespace resolve_ip_to_fqdn
{
using request = std::tuple<std::string, ///< vrf
                           common::ip_address_t>;

using response = std::vector<std::string>;
}

namespace resolve_fqdn_to_ip
{
using request = std::tuple<std::string, ///< vrf
                           std::string>;

using response = std::vector<common::ip_address_t>;
}

namespace tun64_config
{
using response = std::map<std::string, controlplane::tun64::config_t>;
}

namespace getDecapPrefixes
{
using response = std::map<std::string, ///< moduleName
                          std::set<ipv6_prefix_with_announces_t>>;
}

namespace nat64stateful_announce
{
using announce = std::tuple<std::string, ///< module
                            common::ip_prefix_t>;

using response = std::set<announce>;
}

namespace nat46clat_announce
{
using announce = std::tuple<std::string, ///< module_name
                            common::ip_prefix_t>;

using response = std::vector<announce>;
}

namespace nat46clat_config
{
using response = std::map<std::string, nat46clat::config>;
}

namespace nat46clat_stats
{
using response = std::map<std::string, ///< module_name
                          std::array<uint64_t, (size_t)nat46clat::module_counter::enum_size>>;
}

namespace getNat64statelessTranslations
{
using response = std::map<std::tuple<std::string, ///< moduleName
                                     ipv6_address_t, ///< ipv6Address
                                     ipv6_address_t, ///< ipv6DestinationAddress
                                     std::optional<range_t>>, ///< ingressPortRange
                          std::tuple<ipv4_address_t,
                                     std::optional<range_t>, ///< egressPortRange
                                     uint64_t, ///< @todo: NAT64COUNTER
                                     uint64_t, ///< @todo: NAT64COUNTER
                                     uint64_t, ///< @todo: NAT64COUNTER
                                     uint64_t>>; ///< @todo: NAT64COUNTER
}

namespace getNat64statelessPrefixes
{
using response = std::map<std::string, ///< moduleName
                          std::set<ip_prefix_with_announces_t>>;
}

namespace rib_update
{
using insert = std::tuple<std::string, ///< protocol
                          std::string, ///< vrf
                          uint32_t, ///< priority
                          std::map<std::tuple<ip_address_t, ///< peer
                                              std::string, ///< origin
                                              uint32_t, ///< med
                                              std::vector<uint32_t>, ///< aspath
                                              std::set<community_t>,
                                              std::set<large_community_t>,
                                              uint32_t>, ///< local_preference
                                   std::map<std::string, ///< table_name
                                            std::map<ip_address_t, ///< nexthop
                                                     std::vector<std::tuple<ip_prefix_t, ///< prefix
                                                                            std::string, ///< path_information
                                                                            std::vector<uint32_t>>>>>>>; ///< labels

using remove = std::tuple<std::string, ///< protocol
                          std::string, ///< vrf
                          uint32_t, ///< priority
                          std::map<ip_address_t, ///< peer
                                   std::map<std::string, ///< table_name
                                            std::vector<std::tuple<ip_prefix_t, ///< prefix
                                                                   std::string, ///< path_information
                                                                   std::vector<uint32_t>>>>>>; ///< labels

using clear = std::tuple<std::string, ///< protocol
                         std::optional<std::tuple<ip_address_t, ///< peer
                                                  std::tuple<std::string, ///< vrf
                                                             uint32_t>>>>; ///< priority

using eor = std::tuple<std::string, ///< protocol
                       std::string, ///< vrf
                       uint32_t, ///< priority
                       ip_address_t, ///< peer
                       std::string>; ///< table_name

using request = std::vector<std::variant<insert, remove, clear, eor>>;
}

namespace rib_summary
{
using response = std::map<std::tuple<std::string, ///< vrf
                                     uint32_t, ///< priority
                                     std::string, ///< protocol
                                     ip_address_t, ///< peer
                                     std::string>, ///< table_name
                          std::tuple<common::uint64, ///< prefixes
                                     common::uint64, ///< paths
                                     common::uint8>>; ///< eor
}

namespace rib_prefixes
{
using response = std::map<std::tuple<std::string, ///< vrf
                                     uint32_t>, ///< priority
                          std::map<ip_prefix_t,
                                   rib::nexthop_t>>;
}

namespace rib_lookup
{
using request = std::tuple<std::string, ///< vrf
                           ip_address_t>;

using response = rib_prefixes::response;
}

namespace rib_get
{
using request = std::tuple<std::string, ///< vrf
                           ip_prefix_t>;

using response = rib_prefixes::response;
}

namespace rib_save
{
using response = std::vector<uint8_t>;
}

namespace rib_load
{
using request = std::vector<uint8_t>;
}

namespace acl_unwind
{
using request = std::tuple<std::optional<std::string>, ///< module
                           std::optional<std::string>, ///< direction
                           std::optional<std::string>, ///< network_source
                           std::optional<std::string>, ///< network_destination
                           std::optional<std::string>, ///< fragment
                           std::optional<std::string>, ///< protocol
                           std::optional<std::string>, ///< transport_source
                           std::optional<std::string>, ///< transport_destination
                           std::optional<std::string>, ///< transport_flags
                           std::optional<std::string>>; ///< keepstate

using response = std::vector<std::tuple<std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>,
                                        std::optional<std::string>>>; ///< next_module
}

namespace acl_lookup
{
using request = std::tuple<std::optional<std::string>, ///< module
                           std::optional<std::string>, ///< direction
                           std::optional<std::string>, ///< network_source
                           std::optional<std::string>, ///< network_destination
                           std::optional<std::string>, ///< fragment
                           std::optional<std::string>, ///< protocol
                           std::optional<std::string>, ///< transport_source
                           std::optional<std::string>>; ///< transport_destination

using response = std::vector<std::tuple<uint32_t, ///< ruleno
                                        std::string, ///< label
                                        std::string>>; ///< rule
}

namespace route_lookup
{
using request = std::tuple<std::string, ///< module_name
                           ip_address_t>;

using response = std::set<std::tuple<std::set<std::string>, ///< ingress_physical_ports
                                     ip_prefix_t,
                                     ip_address_t, ///< nexthop
                                     std::string, ///< egress_interface
                                     std::vector<uint32_t>>>; ///< labels
}

namespace route_get
{
using request = std::tuple<std::string, ///< module_name
                           ip_prefix_t>;

using response = route_lookup::response;
}

namespace route_tunnel_lookup
{
using request = std::tuple<std::string, ///< module_name
                           ip_address_t>;

using response = std::set<std::tuple<std::set<std::string>, ///< ingress_physical_ports
                                     ip_prefix_t,
                                     ip_address_t, ///< nexthop
                                     std::optional<uint32_t>, ///< label
                                     std::string, ///< egress_interface
                                     std::optional<std::string>, ///< peer
                                     double>>; ///< weight_percent
}

namespace route_tunnel_get
{
using request = std::tuple<std::string, ///< module_name
                           ip_prefix_t>;

using response = route_tunnel_lookup::response;
}

namespace limit_summary
{
using limit = std::tuple<std::string, ///< name
                         std::optional<tSocketId>,
                         uint64_t, ///< current
                         uint64_t>; ///< maximum

using response = std::vector<limit>;
}

namespace controlplane_values
{
using response = std::vector<std::tuple<std::string, ///< name
                                        std::string>>; ///< value
}

namespace controlplane_durations
{
using response = std::map<std::string, ///< name
                          double>; ///< duration
}

namespace loadConfig
{
using request = std::tuple<std::string, ///< rootFilePath
                           std::string, ///< rootJson
                           std::map<std::string, ///< filePath
                                    std::string>>; ///< json

using response = eResult;
}

namespace getFwLabels
{
using response = std::map<uint32_t, ///< rule number
                          std::string>; ///< label
}

namespace getFwList
{
enum class requestType : uint8_t
{
	static_rules_original,
	static_rules_generated,
	dynamic_states,
	dispatcher_rules,
};

inline const char* requestType_toString(requestType t)
{
	switch (t)
	{
		case requestType::static_rules_original:
			return "static_rules_original";
		case requestType::static_rules_generated:
			return "static_rules_generated";
		case requestType::dynamic_states:
			return "dynamic_states";
		case requestType::dispatcher_rules:
			return "dispatcher_rules";
	};
}

using request = requestType;
using response = std::map<uint32_t, ///< rule number
                          std::vector<std::tuple<uint32_t, ///< rule id
                                                 uint64_t, ///< packets counter
                                                 std::string>>>; ///< rule text
}

namespace getSamples
{
using response = std::vector<std::tuple<std::string, ///< in_iface
                                        std::string, ///< out_iface
                                        uint8_t, ///< proto
                                        common::ip_address_t, ///< src_addr
                                        uint16_t, ///< src_port
                                        common::ip_address_t, ///< dst_addr
                                        uint16_t>>; ///< dst_port
}

namespace getAclConfig
{
using request = uint32_t; // serial

using response = std::tuple<
        uint32_t, ///< serial
        acl::iface_map_t, ///< acl to iface mapping
        std::vector<std::vector<uint32_t>>>; ///< rule id map
}

namespace version
{
using response = std::tuple<unsigned int, ///< major
                            unsigned int, ///< minor
                            std::string, ///< revision
                            std::string, ///< hash
                            std::string>; ///< custom
}

using request = std::tuple<requestType,
                           std::variant<std::tuple<>,
                                        acl_unwind::request,
                                        acl_lookup::request,
                                        balancer_service::request,
                                        balancer_real_find::request,
                                        balancer_real::request,
                                        rib_update::request,
                                        rib_lookup::request, /// + route_lookup::request + route_tunnel_lookup::request + resolve_ip_to_fqdn::request
                                        rib_get::request, /// + route_get::request + route_tunnel_get::request
                                        rib_load::request,
                                        resolve_fqdn_to_ip::request,
                                        getAclConfig::request,
                                        getFwList::request,
                                        loadConfig::request>>;

using response = std::variant<std::tuple<>,
                              telegraf_unsafe::response,
                              telegraf_dregress::response,
                              telegraf_dregress_traffic::response,
                              telegraf_balancer_service::response,
                              telegraf_mappings::response,
                              telegraf_other::response,
                              getPhysicalPorts::response,
                              getLogicalPorts::response,
                              tun64_tunnels::response,
                              tun64_prefixes::response,
                              tun64_mappings::response,
                              getDecaps::response,
                              getDecapPrefixes::response,
                              getNat64statelesses::response,
                              getNat64statelessTranslations::response,
                              getNat64statelessPrefixes::response,
                              route_config::response,
                              route_summary::response, ///< + controlplane_values
                              route_interface::response,
                              dregress_config::response,
                              nat64stateful_config::response,
                              balancer_config::response,
                              balancer_summary::response,
                              balancer_service::response,
                              balancer_real_find::response,
                              balancer_announce::response, ///< + nat64stateful_announce
                              acl_unwind::response,
                              acl_lookup::response,
                              route_lookup::response, ///< + route_get::response
                              route_tunnel_lookup::response, ///< + route_tunnel_get::response
                              getRibStats::response,
                              getDefenders::response,
                              checkRibPrefixes::response,
                              getPortStatsEx::response,
                              rib_summary::response,
                              rib_prefixes::response, ///< + rib_lookup::response, rib_get::response, resolve_ip_to_fqdn::response
                              rib_save::response,
                              limit_summary::response,
                              getFwList::response,
                              getFwLabels::response,
                              getSamples::response,
                              getAclConfig::response,
                              resolve_fqdn_to_ip::response,
                              controlplane_durations::response,
                              version::response,
                              loadConfig::response,
                              nat46clat_config::response,
                              nat46clat_announce::response,
                              nat46clat_stats::response>;
}

}
