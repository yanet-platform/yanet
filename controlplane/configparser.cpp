#include <fstream>
#include <sstream>

#include "errors.h"

#include "common/idataplane.h"
#include "configparser.h"

namespace
{

inline void require(const nlohmann::json& json, const char* name)
{
	if (!exist(json, name))
	{
		throw error_result_t(eResult::invalidConfigurationFile, std::string(name) + " not set");
	}
}

} // namespace

static std::string dirname(const std::string& path)
{
	auto position = path.find_last_of("/");
	if (position == std::string::npos)
	{
		return ".";
	}

	return path.substr(0, position);
}

tPortId config_parser_t::getPhysicalPortId(const std::string& name) const
{
	for (const auto& iter : std::get<0>(dataPlaneConfig))
	{
		const auto& portIdIter = iter.first;
		const auto& nameIter = std::get<0>(iter.second);

		if (nameIter == name)
		{
			return portIdIter;
		}
	}

	throw error_result_t(eResult::invalidPhysicalPortName, "unknown physicalPort: " + name);
}

controlplane::base_t config_parser_t::loadConfig(const std::string& rootFilePath,
                                                 const nlohmann::json& rootJson,
                                                 const std::map<std::string, nlohmann::json>& jsons)
{
	controlplane::base_t baseNext;
	try
	{
		if (exist(rootJson, "modules"))
		{
			for (const auto& moduleJsonIter : rootJson["modules"].items())
			{
				const auto& moduleJson = moduleJsonIter.value();

				std::string id = moduleJsonIter.key();
				std::string type = moduleJson["type"];

				/// @todo: check: 'id' not contain ':'

				baseNext.moduleTypes[id] = type;

				if (type == "logicalPort")
				{
					loadConfig_logicalPort(baseNext, id, moduleJson);
				}
				else if (type == "route")
				{
					loadConfig_route(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "decap")
				{
					loadConfig_decap(baseNext, id, moduleJson);
				}
				else if (type == "tun64")
				{
					loadConfig_tun64(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "nat64stateful")
				{
					loadConfig_nat64stateful(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "nat64stateless")
				{
					loadConfig_nat64stateless(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "acl")
				{
					loadConfig_acl(baseNext, id, moduleJson, rootFilePath);
				}
				else if (type == "dregress")
				{
					loadConfig_dregress(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "balancer")
				{
					loadConfig_balancer(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else if (type == "nat46clat")
				{
					loadConfig_nat46clat(baseNext, id, moduleJson, rootFilePath, jsons);
				}
				else
				{
					throw error_result_t(eResult::invalidType, "unknown module type: " + type);
				}
			}
		}

		if (exist(rootJson, "variables"))
		{
			loadConfig_variables(baseNext, rootJson["variables"]);
		}

		if (exist(rootJson, "fqdns"))
		{
			for (const auto& path_json : rootJson["fqdns"])
			{
				loadConfig_fqdns(baseNext, path_json, rootFilePath, jsons);
			}
		}

		if (exist(rootJson, "rib"))
		{
			loadConfig_rib(baseNext, rootJson["rib"]);
		}

		if (exist(rootJson, "memory_groups"))
		{
			loadConfig_memory_group(baseNext.root_memory_group, rootJson["memory_groups"]);
		}
	}
	catch (const error_result_t& err)
	{
		throw;
	}
	catch (const std::exception& ex)
	{
		throw error_result_t(eResult::invalidConfigurationFile, std::string("invalid configuration file: ") + ex.what());
	}
	catch (const std::string& string)
	{
		throw error_result_t(eResult::invalidConfigurationFile, "invalid configuration file: " + string);
	}
	catch (...)
	{
		throw error_result_t(eResult::invalidConfigurationFile, "invalid configuration file: ");
	}

	try
	{
		const auto& [dataplane_physicalports, dataplane_workers, dataplane_values] = dataPlaneConfig;
		(void)dataplane_workers;
		(void)dataplane_values;

		for (const auto& [core_id, worker] : dataplane_workers)
		{
			(void)core_id;
			const auto& [ports, socket_id] = worker;
			(void)ports;
			// add entry for sockets with workers, including slow worker
			baseNext.socket_interfaces[socket_id] = {};
		}
		for (const auto& [route_name, route] : baseNext.routes)
		{
			(void)route_name;

			for (const auto& [interface_name, interface] : route.interfaces)
			{
				(void)interface_name;

				if (exist(baseNext.logicalPorts, interface.nextModule))
				{
					const auto& logicalport = baseNext.logicalPorts[interface.nextModule];

					const auto& [physicalport_name, socket_id, mac_address, pci] = dataplane_physicalports.find(logicalport.physicalPortId)->second;
					(void)physicalport_name;
					(void)mac_address;
					(void)pci;

					baseNext.socket_interfaces[socket_id].emplace(interface.interfaceId);
				}
			}
		}
	}
	catch (...)
	{
		throw error_result_t(eResult::invalidConfigurationFile, "invalid configuration file: socket_interfaces");
	}

	return baseNext;
}

void config_parser_t::loadConfig_logicalPort(controlplane::base_t& baseNext,
                                             const std::string& moduleId,
                                             const nlohmann::json& moduleJson)
{
	auto& logicalPort = baseNext.logicalPorts[moduleId];

	logicalPort.physicalPort = moduleJson.value("physicalPort", std::string(""));
	logicalPort.physicalPortId = getPhysicalPortId(logicalPort.physicalPort);

	if (exist(moduleJson, "vlanId"))
	{
		logicalPort.vlanId = std::stoll(moduleJson["vlanId"].get<std::string>(), nullptr, 0);
	}

	if (exist(moduleJson, "macAddress"))
	{
		logicalPort.macAddress = moduleJson["macAddress"].get<std::string>();
	}
	else
	{
		logicalPort.macAddress = std::get<2>(std::get<0>(dataPlaneConfig)[logicalPort.physicalPortId]);
	}

	if (exist(moduleJson, "promiscuousMode"))
	{
		if (moduleJson["promiscuousMode"] == "true")
		{
			logicalPort.promiscuousMode = 1;
		}
	}

	logicalPort.nextModule = moduleJson.value("nextModule", "");

	//

	logicalPort.logicalPortId = CALCULATE_LOGICALPORT_ID(logicalPort.physicalPortId, logicalPort.vlanId);
	baseNext.logicalport_id_to_name[logicalPort.logicalPortId] = moduleId;
}

void config_parser_t::loadConfig_route(controlplane::base_t& baseNext,
                                       const std::string& moduleId,
                                       const nlohmann::json& moduleJson,
                                       const std::string& rootFilePath,
                                       const std::map<std::string, nlohmann::json>& jsons)
{
	tRouteId routeId = baseNext.routes.size();

	auto& route = baseNext.routes[moduleId];

	if (exist(moduleJson, "interfaces"))
	{
		for (const auto& interfaceJsonIter : moduleJson["interfaces"].items())
		{
			const auto& interfaceJson = interfaceJsonIter.value();

			std::string id = interfaceJsonIter.key();

			auto& interface = route.interfaces[id];

			if (exist(interfaceJson, "ipAddresses"))
			{
				for (const auto& ipAddressJson : interfaceJson["ipAddresses"])
				{
					interface.ip_prefixes.emplace(ipAddressJson.get<std::string>());
				}
			}

			if (exist(interfaceJson, "neighborIPv4Address"))
			{
				interface.neighborIPv4Address = interfaceJson["neighborIPv4Address"].get<std::string>();
			}

			if (exist(interfaceJson, "neighborIPv6Address"))
			{
				interface.neighborIPv6Address = interfaceJson["neighborIPv6Address"].get<std::string>();
			}

			if (exist(interfaceJson, "neighborMacAddress"))
			{
				/// @todo: neighborMacAddress -> neighbor_mac_address_v4 + neighbor_mac_address_v6

				interface.static_neighbor_mac_address_v4 = interfaceJson["neighborMacAddress"].get<std::string>();
				interface.static_neighbor_mac_address_v6 = interfaceJson["neighborMacAddress"].get<std::string>();
			}

			interface.nextModule = interfaceJson.value("nextModule", "");
			interface.acl = interfaceJson.value("acl", "");

			//

			interface.interfaceId = baseNext.interfacesCount;
			baseNext.interfacesCount++;

			baseNext.interfaceNames[interface.interfaceId] = id;
		}
	}

	if (exist(moduleJson, "vrf"))
	{
		route.vrf = moduleJson["vrf"].get<std::string>();
	}

	if (exist(moduleJson, "ignore_tables"))
	{
		for (const auto& ignore_table_json : moduleJson["ignore_tables"])
		{
			route.ignore_tables.emplace(ignore_table_json.get<std::string>());
		}
	}

	route.tunnel_enabled = true;

	if (exist(moduleJson, "ipv4SourceAddress"))
	{
		route.ipv4_source_address = moduleJson["ipv4SourceAddress"].get<std::string>();
	}
	else
	{
		route.tunnel_enabled = false;
	}

	if (exist(moduleJson, "ipv6SourceAddress"))
	{
		route.ipv6_source_address = moduleJson["ipv6SourceAddress"].get<std::string>();
	}
	else
	{
		route.tunnel_enabled = false;
	}

	if (exist(moduleJson, "udpDestinationPort"))
	{
		route.udp_destination_port = moduleJson["udpDestinationPort"];
	}
	else
	{
		route.tunnel_enabled = false;
	}

	if (exist(moduleJson, "localPrefixes"))
	{
		loadConfig_localPrefixes(baseNext,
		                         route.local_prefixes,
		                         moduleJson["localPrefixes"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "localPrefixes_include"))
	{
		loadConfig_localPrefixes(baseNext,
		                         route.local_prefixes,
		                         moduleJson["localPrefixes_include"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "peers"))
	{
		loadConfig_route_peers(baseNext,
		                       route,
		                       moduleJson["peers"],
		                       rootFilePath,
		                       jsons);
	}
	else
	{
		route.tunnel_enabled = false;
	}

	//

	route.routeId = routeId;
}

void config_parser_t::loadConfig_route_peers(controlplane::base_t& baseNext,
                                             controlplane::route::config_t& route,
                                             const nlohmann::json& json,
                                             const std::string& rootFilePath,
                                             const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_route_peers(baseNext,
			                       route,
			                       jsons.find(includePath)->second,
			                       rootFilePath,
			                       jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_route_peers(baseNext,
				                       route,
				                       includeJson,
				                       rootFilePath,
				                       jsons);
			}
		}

		return;
	}

	for (const auto& peerJson : json.items())
	{
		uint32_t peer_id = std::stoll(peerJson.key(), nullptr, 0);
		std::string peer_name = peerJson.value();

		route.peers[peer_id] = peer_name;
	}
}

void config_parser_t::loadConfig_decap(controlplane::base_t& baseNext,
                                       const std::string& moduleId,
                                       const nlohmann::json& moduleJson)
{
	tDecapId decapId = baseNext.decaps.size();

	auto& decap = baseNext.decaps[moduleId];

	if (exist(moduleJson, "ipv6DestinationPrefixes"))
	{
		for (const auto& ipv6DestinationPrefixJson : moduleJson["ipv6DestinationPrefixes"])
		{
			decap.ipv6DestinationPrefixes.emplace(ipv6DestinationPrefixJson);
		}
	}

	if (exist(moduleJson, "dscpMarkType"))
	{
		using common::eDscpMarkType;

		std::string dscpMarkTypeString = moduleJson["dscpMarkType"];

		if (dscpMarkTypeString == "never")
		{
			decap.dscpMarkType = eDscpMarkType::never;
		}
		else if (dscpMarkTypeString == "onlyDefault")
		{
			decap.dscpMarkType = eDscpMarkType::onlyDefault;

			if (exist(moduleJson, "dscp"))
			{
				decap.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else if (dscpMarkTypeString == "always")
		{
			decap.dscpMarkType = eDscpMarkType::always;

			if (exist(moduleJson, "dscp"))
			{
				decap.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "invalid dscpMarkType: " + dscpMarkTypeString);
		}
	}

	decap.ipv6_enabled = 0;
	if (exist(moduleJson, "ipv6_enabled"))
	{
		decap.ipv6_enabled = moduleJson["ipv6_enabled"].get<bool>();
	}

	decap.nextModule = moduleJson.value("nextModule", "");
	decap.decapId = decapId;
}

void config_parser_t::loadConfig_nat64stateful(controlplane::base_t& baseNext,
                                               const std::string& moduleId,
                                               const nlohmann::json& moduleJson,
                                               const std::string& rootFilePath,
                                               const std::map<std::string, nlohmann::json>& jsons)
{
	(void)rootFilePath;
	(void)jsons;

	auto& nat64stateful = baseNext.nat64statefuls[moduleId];
	nat64stateful_id_t nat64stateful_id = baseNext.nat64statefuls.size();

	for (const auto& prefix_json : moduleJson["ipv6_prefixes"])
	{
		common::ipv6_prefix_t ipv6_prefix(prefix_json.get<std::string>());
		nat64stateful.ipv6_prefixes.emplace_back(ipv6_prefix);
	}

	for (const auto& prefix_json : moduleJson["ipv4_prefixes"])
	{
		common::ipv4_prefix_t ipv4_prefix(prefix_json.get<std::string>());
		if (!ipv4_prefix.mask())
		{
			throw error_result_t(eResult::invalidConfigurationFile, "nat64stateful: invalid ipv4_prefix");
		}

		nat64stateful.ipv4_prefixes.emplace_back(ipv4_prefix);

		baseNext.nat64stateful_pool_size += (1u << (32 - ipv4_prefix.mask()));
	}

	if (exist(moduleJson, "announces"))
	{
		for (const auto& prefix_json : moduleJson["announces"])
		{
			nat64stateful.announces.emplace(prefix_json.get<std::string>());
		}
	}

	if (exist(moduleJson, "dscpMarkType"))
	{
		using common::eDscpMarkType;

		std::string dscpMarkTypeString = moduleJson["dscpMarkType"];

		if (dscpMarkTypeString == "never")
		{
			nat64stateful.dscp_mark_type = eDscpMarkType::never;
		}
		else if (dscpMarkTypeString == "onlyDefault")
		{
			nat64stateful.dscp_mark_type = eDscpMarkType::onlyDefault;

			if (exist(moduleJson, "dscp"))
			{
				nat64stateful.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else if (dscpMarkTypeString == "always")
		{
			nat64stateful.dscp_mark_type = eDscpMarkType::always;

			if (exist(moduleJson, "dscp"))
			{
				nat64stateful.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "invalid dscpMarkType: " + dscpMarkTypeString);
		}
	}

	if (exist(moduleJson, "state_timeout"))
	{
		nat64stateful.state_timeout = moduleJson["state_timeout"];
	}

	nat64stateful.next_module = moduleJson.value("nextModule", "");
	nat64stateful.nat64stateful_id = nat64stateful_id;

	if (baseNext.nat64stateful_pool_size > YANET_CONFIG_NAT64STATEFUL_POOL_SIZE)
	{
		throw error_result_t(eResult::invalidConfigurationFile, "nat64stateful: ipv4 pool is overflow");
	}
}

void config_parser_t::loadConfig_tun64(controlplane::base_t& baseNext,
                                       const std::string& moduleId,
                                       const nlohmann::json& moduleJson,
                                       const std::string& rootFilePath,
                                       const std::map<std::string, nlohmann::json>& jsons)
{
	auto& tunnel = baseNext.tunnels[moduleId];
	tun64_id_t tunnelId = baseNext.tunnels.size();

	if (exist(moduleJson, "random_source"))
	{
		tunnel.srcRndEnabled = (moduleJson["random_source"] != "false");
	}

	if (exist(moduleJson, "ipv6SourceAddress"))
	{
		tunnel.ipv6SourceAddress = moduleJson["ipv6SourceAddress"].get<std::string>();
	}
	else
	{
		throw error_result_t(eResult::missingRequiredOption, "ipv6SourceAddress is required for tun64 module.");
	}

	if (exist(moduleJson, "prefixes"))
	{
		loadConfig_localPrefixes(baseNext,
		                         tunnel.prefixes,
		                         moduleJson["prefixes"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "ipv6DestinationPrefixes"))
	{
		for (const auto& prefixJson : moduleJson["ipv6DestinationPrefixes"])
		{
			tunnel.prefixes.emplace(prefixJson.get<std::string>());
		}
	}
	else
	{
		tunnel.prefixes.emplace(common::ip_prefix_t(tunnel.ipv6SourceAddress, 128));
	}

	if (exist(moduleJson, "mappings"))
	{
		loadConfig_tun64mappings(baseNext,
		                         tunnel,
		                         moduleJson["mappings"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "dscpMarkType"))
	{
		using common::eDscpMarkType;

		std::string dscpMarkTypeString = moduleJson["dscpMarkType"];

		if (dscpMarkTypeString == "never")
		{
			tunnel.dscpMarkType = eDscpMarkType::never;
		}
		else if (dscpMarkTypeString == "onlyDefault")
		{
			tunnel.dscpMarkType = eDscpMarkType::onlyDefault;

			if (exist(moduleJson, "dscp"))
			{
				tunnel.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else if (dscpMarkTypeString == "always")
		{
			tunnel.dscpMarkType = eDscpMarkType::always;

			if (exist(moduleJson, "dscp"))
			{
				tunnel.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "invalid dscpMarkType: " + dscpMarkTypeString);
		}
	}

	tunnel.nextModule = moduleJson.value("nextModule", "");
	tunnel.tun64Id = tunnelId;
}

void config_parser_t::loadConfig_tun64mappings(controlplane::base_t& baseNext,
                                               controlplane::tun64::config_t& tunnel,
                                               const nlohmann::json& mappingsJson,
                                               const std::string& rootFilePath,
                                               const std::map<std::string, nlohmann::json>& jsons)
{
	for (const auto& mappingJsonIter : mappingsJson.items())
	{
		const auto& mappingJson = mappingJsonIter.value();

		if (mappingJson.is_string())
		{
			std::string includePath = mappingJson;

			if (includePath.find("/") != 0) ///< relative path
			{
				includePath = dirname(rootFilePath) + "/" + includePath;
			}

			if (exist(jsons, includePath))
			{
				loadConfig_tun64mappings(baseNext,
				                         tunnel,
				                         jsons.find(includePath)->second,
				                         rootFilePath,
				                         jsons);
			}
			else
			{
				std::ifstream includeFileStream(includePath);

				if (!includeFileStream.is_open())
				{
					throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
				}
				else
				{
					nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
					if (includeJson.is_discarded())
					{
						throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
					}

					loadConfig_tun64mappings(baseNext,
					                         tunnel,
					                         includeJson,
					                         rootFilePath,
					                         jsons);
				}
			}
			continue;
		}

		ipv4_address_t ipv4Address = ipv4_address_t(std::string(mappingJsonIter.key()));

		if (exist(mappingJson, "addr6") && exist(mappingJson, "net_loc"))
		{
			ipv6_address_t ipv6Address = mappingJson["addr6"].get<std::string>();
			tunnel.mappings[ipv4Address] = {ipv6Address,
			                                mappingJson["net_loc"].get<std::string>()};

			if (++baseNext.tun64MappingsCount >= CONFIG_YADECAP_TUN64_MAPPINGS_SIZE)
			{
				throw error_result_t(eResult::invalidTun64Id, "too many mappings");
			}
		}
	}
}

void config_parser_t::loadConfig_nat64stateless(controlplane::base_t& baseNext,
                                                const std::string& moduleId,
                                                const nlohmann::json& moduleJson,
                                                const std::string& rootFilePath,
                                                const std::map<std::string, nlohmann::json>& jsons)
{
	tNat64statelessId nat64statelessId = baseNext.nat64statelesses.size();

	auto& nat64stateless = baseNext.nat64statelesses[moduleId];

	if (exist(moduleJson, "dscpMarkType"))
	{
		using common::eDscpMarkType;

		std::string dscpMarkTypeString = moduleJson["dscpMarkType"];

		if (dscpMarkTypeString == "never")
		{
			nat64stateless.dscpMarkType = eDscpMarkType::never;
		}
		else if (dscpMarkTypeString == "onlyDefault")
		{
			nat64stateless.dscpMarkType = eDscpMarkType::onlyDefault;

			if (exist(moduleJson, "dscp"))
			{
				nat64stateless.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else if (dscpMarkTypeString == "always")
		{
			nat64stateless.dscpMarkType = eDscpMarkType::always;

			if (exist(moduleJson, "dscp"))
			{
				nat64stateless.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "invalid dscpMarkType: " + dscpMarkTypeString);
		}
	}

	if (exist(moduleJson, "firewall") &&
	    moduleJson["firewall"] == "false")
	{
		nat64stateless.firewall = 0;
	}
	else
	{
		nat64stateless.firewall = 1;
	}

	if (exist(moduleJson, "nat64_wkp_prefix"))
	{
		nat64stateless.nat64_wkp_prefix = moduleJson["nat64_wkp_prefix"].get<std::string>();
		if ((!nat64stateless.nat64_wkp_prefix->isValid()) ||
		    nat64stateless.nat64_wkp_prefix->mask() > 96)
		{
			throw error_result_t(eResult::invalidPrefix, "invalid prefix: " + nat64stateless.nat64_wkp_prefix->toString());
		}
	}

	if (exist(moduleJson, "nat64_src_prefix"))
	{
		nat64stateless.nat64_src_prefix = moduleJson["nat64_src_prefix"].get<std::string>();
		if ((!nat64stateless.nat64_src_prefix->isValid()) ||
		    nat64stateless.nat64_src_prefix->mask() > 64 ||
		    nat64stateless.nat64_src_prefix->mask() % 8 != 0)
		{
			throw error_result_t(eResult::invalidPrefix, "invalid prefix: " + nat64stateless.nat64_src_prefix->toString());
		}
	}

	if (exist(moduleJson, "nat64_prefixes"))
	{
		for (const auto& prefixJson : moduleJson["nat64_prefixes"])
		{
			nat64stateless.nat64_prefixes.emplace(prefixJson);
		}
	}

	if (exist(moduleJson, "translations"))
	{
		loadConfig_nat64stateless_translations(baseNext,
		                                       nat64stateless,
		                                       moduleJson["translations"],
		                                       rootFilePath,
		                                       jsons);
	}

	if (exist(moduleJson, "defrag_farm_prefix"))
	{
		if (!exist(moduleJson, "defrag_source_prefix"))
		{
			throw error_result_t(eResult::invalidArguments, "defrag_farm_prefix is present, but defrag_source_prefix is not");
		}
		nat64stateless.defrag_farm_prefix = moduleJson["defrag_farm_prefix"].get<std::string>();
		nat64stateless.defrag_source_prefix = moduleJson["defrag_source_prefix"].get<std::string>();
		if (exist(moduleJson, "farm") &&
		    moduleJson["farm"] == "true")
		{
			nat64stateless.farm = 1;
		}
		else
		{
			nat64stateless.farm = 0;
		}
	}

	nat64stateless.nextModule = moduleJson.value("nextModule", "");
	nat64stateless.nat64statelessId = nat64statelessId;
}

void config_parser_t::loadConfig_nat64stateless_translations(controlplane::base_t& baseNext,
                                                             controlplane::base::nat64stateless_t& nat64stateless,
                                                             const nlohmann::json& translationsJson,
                                                             const std::string& rootFilePath,
                                                             const std::map<std::string, nlohmann::json>& jsons)
{
	for (const auto& translationJson : translationsJson)
	{
		if (translationJson.is_string())
		{
			std::string includePath = translationJson;

			if (includePath.find("/") != 0) ///< relative path
			{
				includePath = dirname(rootFilePath) + "/" + includePath;
			}

			if (exist(jsons, includePath))
			{
				loadConfig_nat64stateless_translations(baseNext,
				                                       nat64stateless,
				                                       jsons.find(includePath)->second,
				                                       rootFilePath,
				                                       jsons);
			}
			else
			{
				std::ifstream includeFileStream(includePath);
				if (!includeFileStream.is_open())
				{
					throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
				}
				else
				{
					nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
					if (includeJson.is_discarded())
					{
						throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
					}

					loadConfig_nat64stateless_translations(baseNext,
					                                       nat64stateless,
					                                       includeJson,
					                                       rootFilePath,
					                                       jsons);
				}
			}

			continue;
		}

		if (!exist(translationJson, "ipv6Address"))
		{
			throw error_result_t(eResult::invalidConfigurationFile, "ipv6Address not set");
		}

		if (!exist(translationJson, "ipv4Address"))
		{
			throw error_result_t(eResult::invalidConfigurationFile, "ipv4Address not set");
		}

		std::optional<range_t> ingressPortRange;
		std::optional<range_t> egressPortRange;

		if (exist(translationJson, "ingressPortRange"))
		{
			ingressPortRange = translationJson["ingressPortRange"].get<std::string>();
		}

		if (exist(translationJson, "egressPortRange"))
		{
			egressPortRange = translationJson["egressPortRange"].get<std::string>();
		}

		/// @todo: check ingressPortRange and egressPortRange

		ipv6_address_t ipv6Address = translationJson["ipv6Address"].get<std::string>();
		ipv4_address_t ipv4Address = translationJson["ipv4Address"].get<std::string>();

		ipv6_address_t ipv6DestinationAddress;
		if (exist(translationJson, "wkp"))
		{
			if (translationJson["wkp"] == "true")
			{
				if (!nat64stateless.nat64_wkp_prefix)
				{
					throw error_result_t(eResult::invalidConfigurationFile, "nat64_wkp_prefix not set");
				}

				ipv6DestinationAddress = nat64stateless.nat64_wkp_prefix->address();
			}
			else
			{
				if (!nat64stateless.nat64_src_prefix)
				{
					throw error_result_t(eResult::invalidConfigurationFile, "nat64_src_prefix not set");
				}

				ipv6DestinationAddress = nat64stateless.nat64_src_prefix->address();
				*(uint32_t*)(ipv6DestinationAddress.data() + (nat64stateless.nat64_src_prefix->mask() / 8)) = htobe32(ipv4Address);
			}
		}
		else
		{
			if (!exist(translationJson, "ipv6DestinationAddress"))
			{
				throw error_result_t(eResult::invalidConfigurationFile, "ipv6DestinationAddress not set");
			}

			ipv6DestinationAddress = translationJson["ipv6DestinationAddress"].get<std::string>();
		}

		if (ipv6DestinationAddress.getAddress32(96) != 0)
		{
			throw error_result_t(eResult::invalidPrefix, "invalid ipv6DestinationAddress: " + ipv6DestinationAddress.toString());
		}

		nat64stateless.translations[{ipv6Address,
		                             ipv6DestinationAddress,
		                             ingressPortRange}] = {ipv4Address,
		                                                   egressPortRange,
		                                                   baseNext.nat64statelessTranslationsCount};
		baseNext.nat64statelessTranslationsCount++;
	}
}

void config_parser_t::loadConfig_nat46clat(controlplane::base_t& baseNext,
                                           const std::string& moduleId,
                                           const nlohmann::json& moduleJson,
                                           const std::string& rootFilePath,
                                           const std::map<std::string, nlohmann::json>& jsons)
{
	(void)rootFilePath;
	(void)jsons;

	auto& nat46clat = baseNext.nat46clats[moduleId];
	nat46clat_id_t nat46clat_id = baseNext.nat46clats.size();

	nat46clat.ipv6_source = moduleJson["ipv6_source"].get<std::string>();
	nat46clat.ipv6_destination = moduleJson["ipv6_destination"].get<std::string>();

	for (const auto& prefix_json : moduleJson["ipv6_prefixes"])
	{
		common::ipv6_prefix_t ipv6_prefix(prefix_json.get<std::string>());
		nat46clat.ipv6_prefixes.emplace(ipv6_prefix);
	}

	for (const auto& prefix_json : moduleJson["ipv4_prefixes"])
	{
		common::ipv4_prefix_t ipv4_prefix(prefix_json.get<std::string>());
		nat46clat.ipv4_prefixes.emplace(ipv4_prefix);
	}

	if (exist(moduleJson, "announces"))
	{
		for (const auto& prefix_json : moduleJson["announces"])
		{
			nat46clat.announces.emplace(prefix_json.get<std::string>());
		}
	}

	if (exist(moduleJson, "dscpMarkType"))
	{
		using common::eDscpMarkType;

		std::string dscpMarkTypeString = moduleJson["dscpMarkType"];

		if (dscpMarkTypeString == "never")
		{
			nat46clat.dscp_mark_type = eDscpMarkType::never;
		}
		else if (dscpMarkTypeString == "onlyDefault")
		{
			nat46clat.dscp_mark_type = eDscpMarkType::onlyDefault;

			if (exist(moduleJson, "dscp"))
			{
				nat46clat.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else if (dscpMarkTypeString == "always")
		{
			nat46clat.dscp_mark_type = eDscpMarkType::always;

			if (exist(moduleJson, "dscp"))
			{
				nat46clat.dscp = moduleJson["dscp"];
			}
			else
			{
				throw error_result_t(eResult::invalidConfigurationFile, "dscp not set");
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "invalid dscpMarkType: " + dscpMarkTypeString);
		}
	}

	nat46clat.next_module = moduleJson.value("nextModule", "");
	nat46clat.nat46clat_id = nat46clat_id;
}

void config_parser_t::loadConfig_acl(controlplane::base_t& baseNext,
                                     const std::string& moduleId,
                                     const nlohmann::json& moduleJson,
                                     const std::string& rootFilePath)
{
	tAclId aclId = baseNext.acls.size() + 1; ///< aclId 0 is YANET_ACL_ID_UNKNOWN

	auto& acl = baseNext.acls[moduleId];
	auto firewall = std::make_shared<ipfw::fw_config_t>(2);

	if (exist(moduleJson, "firewall"))
	{
		const auto& json = moduleJson["firewall"];

		if (!json.is_string())
		{
			// rules are inplaced in controlplane.conf
			std::string rules;
			for (std::string rule : json)
			{
				rules += rule + "\n";
			}
			firewall->schedule_string(rules);
		}
		else
		{
			std::string includePath = json;
			if (includePath.find("/") != 0) ///< relative path
			{
				includePath = dirname(rootFilePath) + "/" + includePath;
			}
			if (!firewall->schedule_file(includePath))
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
		}
	}
	else
	{
		// no firewall config, use empty string
		firewall->schedule_string("");
	}

	if (exist(moduleJson, "macros"))
	{
		std::string includePath = moduleJson["macros"].get<std::string>();
		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}
		if (!firewall->schedule_file(includePath))
		{
			throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
		}
	}

	if (exist(moduleJson, "dnscache"))
	{
		std::string includePath = moduleJson["dnscache"].get<std::string>();
		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}
		if (!firewall->schedule_file(includePath))
		{
			throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
		}
	}

	if (!firewall->parse())
	{
		throw error_result_t(eResult::invalidConfigurationFile, "failed to parse firewall configs");
	}
	firewall->validate();

	if (exist(moduleJson, "nextModules"))
	{
		for (const auto& nextModule : moduleJson["nextModules"])
		{
			acl.nextModules.emplace_back(nextModule);
		}
	}

	if (exist(moduleJson, "early_decap"))
	{
		const nlohmann::json& earlyDecapJson = moduleJson["early_decap"];

		if (exist(earlyDecapJson, "srcPrefixes"))
		{
			nlohmann::json srcPrefixes;

			if (earlyDecapJson["srcPrefixes"].is_string())
			{
				std::string includePath = earlyDecapJson["srcPrefixes"];
				if (includePath.find("/") != 0) ///< relative path
				{
					includePath = dirname(rootFilePath) + "/" + includePath;
				}

				std::ifstream includeFileStream(includePath);
				if (!includeFileStream.is_open())
				{
					throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
				}
				else
				{
					nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
					if (includeJson.is_discarded())
					{
						throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
					}

					srcPrefixes = includeJson["srcPrefixes"];
				}
			}
			else
			{
				srcPrefixes = earlyDecapJson["srcPrefixes"];
			}

			for (const auto& ipJson : srcPrefixes)
			{
				std::string prefix_str = ipJson.get<std::string>();
				ip_prefix_t prefix(prefix_str);

				if (prefix.is_ipv4())
				{
					acl.src4_early_decap.emplace(prefix);
				}
				else
				{
					acl.src6_early_decap.emplace(prefix);
				}
			}
		}

		if (exist(earlyDecapJson, "dstAddresses"))
		{
			for (const auto& ipJson : earlyDecapJson["dstAddresses"])
			{
				std::string addr_str = ipJson.get<std::string>();
				ip_prefix_t addr(addr_str);

				if (addr.is_ipv4())
				{
					acl.dst4_early_decap.emplace(addr);
				}
				else
				{
					acl.dst6_early_decap.emplace(addr);
				}
			}
		}
	}

	if (exist(moduleJson, "synchronization"))
	{
		// todo: consider ADL deserialization, see nlohmann::adl_serializer.
		const nlohmann::json& synchronizationJson = moduleJson["synchronization"];
		require(synchronizationJson, "ipv6SourceAddress");
		require(synchronizationJson, "multicastIpv6Address");
		require(synchronizationJson, "multicastDestinationPort");
		require(synchronizationJson, "logicalPorts");
		require(synchronizationJson, "ingressNextModule");

		acl.synchronization = controlplane::base::acl_sync_config_t{};
		acl.synchronization->ipv6SourceAddress = synchronizationJson["ipv6SourceAddress"].get<std::string>();
		acl.synchronization->multicastIpv6Address = synchronizationJson["multicastIpv6Address"].get<std::string>();
		if (exist(synchronizationJson, "unicastIpv6Address"))
		{
			require(synchronizationJson, "unicastIpv6SourceAddress");
			require(synchronizationJson, "unicastDestinationPort");
			acl.synchronization->unicastIpv6Address = synchronizationJson["unicastIpv6Address"].get<std::string>();
			acl.synchronization->unicastIpv6SourceAddress = synchronizationJson["unicastIpv6SourceAddress"].get<std::string>();
			acl.synchronization->unicastDestinationPort = synchronizationJson["unicastDestinationPort"].get<std::uint16_t>();
		}
		acl.synchronization->multicastDestinationPort = synchronizationJson["multicastDestinationPort"].get<std::uint16_t>();
		acl.synchronization->logicalPorts = synchronizationJson["logicalPorts"].get<std::vector<std::string>>();
		acl.synchronization->ingressNextModule = synchronizationJson["ingressNextModule"].get<std::string>();

		if (!acl.synchronization->multicastIpv6Address.is_multicast())
		{
			throw error_result_t(eResult::invalidConfigurationFile, "multicastIpv6Address is not a multicast address");
		}
	}

	if (exist(moduleJson, "storeSamples"))
	{
		baseNext.storeSamples |= moduleJson["storeSamples"].get<bool>();
	}

	acl.aclId = aclId;
	acl.firewall = firewall;
}

void config_parser_t::loadConfig_dregress(controlplane::base_t& baseNext,
                                          const std::string& moduleId,
                                          const nlohmann::json& moduleJson,
                                          const std::string& rootFilePath,
                                          const std::map<std::string, nlohmann::json>& jsons)
{
	dregress_id_t dregressId = baseNext.dregresses.size();

	auto& dregress = baseNext.dregresses[moduleId];

	if (!exist(moduleJson, "ipv6SourcePrefixes"))
	{
		throw error_result_t(eResult::invalidConfigurationFile, "ipv6SourcePrefixes not set");
	}
	if (!exist(moduleJson, "ipv6DestinationPrefix"))
	{
		throw error_result_t(eResult::invalidConfigurationFile, "ipv6DestinationPrefix not set");
	}
	if (!exist(moduleJson, "ipv4SourceAddress"))
	{
		throw error_result_t(eResult::invalidConfigurationFile, "ipv4SourceAddress not set");
	}
	if (!exist(moduleJson, "ipv6SourceAddress"))
	{
		throw error_result_t(eResult::invalidConfigurationFile, "ipv6SourceAddress not set");
	}
	if (!exist(moduleJson, "udpDestinationPort"))
	{
		throw error_result_t(eResult::invalidConfigurationFile, "udpDestinationPort not set");
	}

	for (std::string ipv6SourcePrefix : moduleJson["ipv6SourcePrefixes"])
	{
		dregress.ipv6SourcePrefixes.emplace(ipv6SourcePrefix);
	}

	dregress.ipv6DestinationPrefix = moduleJson["ipv6DestinationPrefix"].get<std::string>();
	dregress.ipv4SourceAddress = moduleJson["ipv4SourceAddress"].get<std::string>();
	dregress.ipv6SourceAddress = moduleJson["ipv6SourceAddress"].get<std::string>();
	dregress.udpDestinationPort = moduleJson["udpDestinationPort"];

	if (exist(moduleJson, "communities"))
	{
		loadConfig_dregress_communities(baseNext,
		                                dregress,
		                                moduleJson["communities"],
		                                rootFilePath,
		                                jsons);
	}

	if (exist(moduleJson, "localPrefixes"))
	{
		loadConfig_localPrefixes(baseNext,
		                         dregress.localPrefixes,
		                         moduleJson["localPrefixes"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "localPrefixes_include"))
	{
		loadConfig_localPrefixes(baseNext,
		                         dregress.localPrefixes,
		                         moduleJson["localPrefixes_include"],
		                         rootFilePath,
		                         jsons);
	}

	if (exist(moduleJson, "announces"))
	{
		for (std::string announce : moduleJson["announces"])
		{
			dregress.announces.emplace(announce);
		}
	}

	if (exist(moduleJson, "onlyLongest") &&
	    moduleJson["onlyLongest"] == "false")
	{
		dregress.onlyLongest = false;
	}
	else
	{
		dregress.onlyLongest = true;
	}

	if (exist(moduleJson, "ourAs"))
	{
		loadConfig_ourAs(baseNext,
		                 dregress.ourAs,
		                 moduleJson["ourAs"],
		                 rootFilePath,
		                 jsons);
	}

	dregress.nextModule = moduleJson.value("nextModule", "");

	//

	dregress.dregressId = dregressId;
}

void config_parser_t::loadConfig_dregress_communities(controlplane::base_t& baseNext,
                                                      controlplane::dregress::config_t& dregress,
                                                      const nlohmann::json& json,
                                                      const std::string& rootFilePath,
                                                      const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_dregress_communities(baseNext,
			                                dregress,
			                                jsons.find(includePath)->second,
			                                rootFilePath,
			                                jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_dregress_communities(baseNext,
				                                dregress,
				                                includeJson,
				                                rootFilePath,
				                                jsons);
			}
		}

		return;
	}

	for (const auto& communityJson : json.items())
	{
		std::string community = communityJson.key();
		std::string link = communityJson.value();

		dregress.communities[{community}] = link;
	}
}

void config_parser_t::loadConfig_localPrefixes(controlplane::base_t& baseNext,
                                               std::set<common::ip_prefix_t>& localPrefixes,
                                               const nlohmann::json& json,
                                               const std::string& rootFilePath,
                                               const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_localPrefixes(baseNext,
			                         localPrefixes,
			                         jsons.find(includePath)->second,
			                         rootFilePath,
			                         jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_localPrefixes(baseNext,
				                         localPrefixes,
				                         includeJson,
				                         rootFilePath,
				                         jsons);
			}
		}

		return;
	}

	for (std::string localPrefix : json)
	{
		localPrefixes.emplace(localPrefix);
	}
}

void config_parser_t::loadConfig_ourAs(controlplane::base_t& baseNext,
                                       std::set<uint32_t>& ourAs,
                                       const nlohmann::json& json,
                                       const std::string& rootFilePath,
                                       const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_ourAs(baseNext,
			                 ourAs,
			                 jsons.find(includePath)->second,
			                 rootFilePath,
			                 jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_ourAs(baseNext,
				                 ourAs,
				                 includeJson,
				                 rootFilePath,
				                 jsons);
			}
		}

		return;
	}

	for (uint32_t as : json)
	{
		ourAs.emplace(as);
	}
}

void config_parser_t::loadConfig_balancer(controlplane::base_t& baseNext,
                                          const std::string& moduleId,
                                          const nlohmann::json& moduleJson,
                                          const std::string& rootFilePath,
                                          const std::map<std::string, nlohmann::json>& jsons)
{
	balancer_id_t balancer_id = baseNext.balancers.size() + 1;

	auto& balancer = baseNext.balancers[moduleId];

	if (exist(moduleJson, "services"))
	{
		loadConfig_balancer_services(baseNext,
		                             balancer,
		                             moduleJson["services"],
		                             rootFilePath,
		                             jsons);
	}

	balancer.source_ipv6 = moduleJson.value("source", "::");
	balancer.source_ipv4 = moduleJson.value("source_ipv4", "0.0.0.0");

	balancer.next_module = moduleJson.value("nextModule", "");

	balancer.default_wlc_power = moduleJson.value("default_wlc_power", YANET_CONFIG_BALANCER_WLC_DEFAULT_POWER);

	//

	balancer.balancer_id = balancer_id;

	std::string unrdup_path = moduleJson.value("unrdup", "/var/db/unrdup/unrdup.cfg");
	loadConfig_balancer_unrdup(balancer, rootFilePath, unrdup_path);
}

void config_parser_t::loadConfig_balancer_services(controlplane::base_t& baseNext,
                                                   controlplane::balancer::config_t& balancer,
                                                   const nlohmann::json& json,
                                                   const std::string& rootFilePath,
                                                   const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_balancer_services(baseNext,
			                             balancer,
			                             jsons.find(includePath)->second,
			                             rootFilePath,
			                             jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_balancer_services(baseNext,
				                             balancer,
				                             includeJson,
				                             rootFilePath,
				                             jsons);
			}
		}

		return;
	}

	for (const auto& service_json : json)
	{
		if (baseNext.services_count >= YANET_CONFIG_BALANCER_SERVICES_SIZE)
		{
			throw error_result_t(eResult::invalidConfigurationFile, "too many services");
		}

		std::optional<std::string> service_version = exist(service_json, "version") ? std::make_optional(service_json["version"].get<std::string>()) : std::nullopt;

		std::optional<common::ipv4_prefix_t> ipv4_outer_source_network =
		        exist(service_json, "ipv4_outer_source_network") ? std::make_optional(service_json["ipv4_outer_source_network"].get<std::string>()) : std::nullopt;
		std::optional<common::ipv6_prefix_t> ipv6_outer_source_network =
		        exist(service_json, "ipv6_outer_source_network") ? std::make_optional(service_json["ipv6_outer_source_network"].get<std::string>()) : std::nullopt;

		std::string scheduler_string = service_json["scheduler"];

		balancer::scheduler scheduler;
		balancer::scheduler_params scheduler_params{};
		if (scheduler_string == "rr")
		{
			scheduler = balancer::scheduler::rr;
		}
		else if (scheduler_string == "wrr")
		{
			scheduler = balancer::scheduler::wrr;
		}
		else if (scheduler_string == "wlc")
		{
			scheduler = balancer::scheduler::wlc;
			if (exist(service_json, "scheduler_params") && exist(service_json["scheduler_params"], "wlc_power"))
			{
				scheduler_params.wlc_power = std::stoll(service_json["scheduler_params"]["wlc_power"].get<std::string>(), nullptr, 10);
			}
		}
		else
		{
			throw error_result_t(eResult::invalidConfigurationFile, "unknown scheduler: " + scheduler_string);
		}

		balancer::forwarding_method forwarding_method;

		if (!exist(service_json, "lvs_method"))
		{
			forwarding_method = balancer::forwarding_method::ipip;
		}
		else
		{
			std::string forwarding_method_string = service_json["lvs_method"];
			if (forwarding_method_string == "TUN")
			{
				forwarding_method = balancer::forwarding_method::ipip;
			}
			else
			{
				forwarding_method = balancer::forwarding_method::gre;
			}
		}

		std::vector<controlplane::balancer::real_t> reals;
		for (const auto& real_json : service_json["reals"])
		{
			if (baseNext.reals_count >= YANET_CONFIG_BALANCER_REALS_SIZE)
			{
				throw error_result_t(eResult::invalidConfigurationFile, "too many reals");
			}

			unsigned int weight = 1;
			if (scheduler == ::balancer::scheduler::wrr || scheduler == ::balancer::scheduler::wlc)
			{
				if (exist(real_json, "weight"))
				{
					weight = std::stoll(real_json["weight"].get<std::string>(), nullptr, 0);
				}
			}

			/// @todo: check maximum weight

			common::ip_address_t real_ip(real_json["ip"].get<std::string>());

			reals.emplace_back(real_ip,
			                   std::stoll(real_json["port"].get<std::string>(), nullptr, 0),
			                   weight);

			balancer.reals_count++;
			baseNext.reals_count++;
		}

		if (!exist(service_json, "proto"))
		{
			throw error_result_t(eResult::invalidConfigurationFile, "unknown proto");
		}

		uint8_t flags = 0;
		if (service_json.value("mss_fix", false) == true)
		{
			flags |= YANET_BALANCER_FIX_MSS_FLAG;
		}

		auto proto = controlplane::balancer::to_proto(service_json["proto"].get<std::string>());

		if (service_json.value("ops", false) && proto == IPPROTO_UDP)
		{
			flags |= YANET_BALANCER_OPS_FLAG;
		}

		balancer.services.emplace_back(baseNext.services_count + 1, ///< 0 is invalid id
		                               service_json["vip"].get<std::string>(),
		                               proto,
		                               std::stoll(service_json["vport"].get<std::string>(), nullptr, 0),
		                               service_version,
		                               scheduler,
		                               scheduler_params,
		                               forwarding_method,
		                               flags,
		                               ipv4_outer_source_network,
		                               ipv6_outer_source_network,
		                               reals);

		baseNext.services_count++;
	}
}

void config_parser_t::loadConfig_balancer_unrdup(controlplane::balancer::config_t& balancer, const std::string& rootFilePath, const std::string& unrdup_cfg_path)
{
	std::string absolute_unrdup_cfg_path;

	if (unrdup_cfg_path.find("/") != 0) ///< relative path
	{
		YANET_LOG_DEBUG("Not an absolute path, trying in current directory\n");
		absolute_unrdup_cfg_path = dirname(rootFilePath) + "/" + unrdup_cfg_path;
	}
	else
	{
		YANET_LOG_DEBUG("Provided absolute path to unrdup.cfg file %s\n", unrdup_cfg_path.data());
		absolute_unrdup_cfg_path = unrdup_cfg_path;
	}

	YANET_LOG_DEBUG("Path to unrdup.cfg file %s\n", absolute_unrdup_cfg_path.data());

	std::fstream unrdup_stream(absolute_unrdup_cfg_path, std::ios_base::in);
	decltype(balancer.vip_to_balancers) new_vip_to_balancers;

	if (!unrdup_stream.is_open())
	{
		YANET_LOG_ERROR("error: cannot open unrdup config in provided path %s\n", unrdup_cfg_path.data());
	}

	std::string another_line;
	while (getline(unrdup_stream, another_line))
	{
		std::stringstream line_stream(another_line);

		std::string vip;
		line_stream >> vip;

		while (!line_stream.eof())
		{
			std::string balancer_addr;
			line_stream >> balancer_addr;

			new_vip_to_balancers[common::ip_address_t(vip)].insert(common::ip_address_t(balancer_addr));
		}
	}

	// don't send to dataplane if unrdup.cfg was not changed since last call
	if (new_vip_to_balancers != balancer.vip_to_balancers)
	{
		balancer.vip_to_balancers = new_vip_to_balancers;
		// directly to the place where we need this table, no need to bother globalbase
		interface::dataPlane dataplane;
		dataplane.unrdup_vip_to_balancers({balancer.balancer_id, balancer.vip_to_balancers});
	}
}

void config_parser_t::loadConfig_variables(controlplane::base_t& baseNext,
                                           const nlohmann::json& json)
{
	for (const auto& json_iter : json.items())
	{
		const auto& name = json_iter.key();
		const auto& variable = json_iter.value();

		baseNext.variables[name] = variable.get<uint64_t>();
	}
}

void config_parser_t::loadConfig_fqdns(controlplane::base_t& baseNext,
                                       const nlohmann::json& json,
                                       const std::string& rootFilePath,
                                       const std::map<std::string, nlohmann::json>& jsons)
{
	if (json.is_string())
	{
		std::string includePath = json;

		if (includePath.find("/") != 0) ///< relative path
		{
			includePath = dirname(rootFilePath) + "/" + includePath;
		}

		if (exist(jsons, includePath))
		{
			loadConfig_fqdns(baseNext,
			                 jsons.find(includePath)->second,
			                 rootFilePath,
			                 jsons);
		}
		else
		{
			std::ifstream includeFileStream(includePath);
			if (!includeFileStream.is_open())
			{
				throw error_result_t(eResult::errorOpenFile, "can't open file " + includePath);
			}
			else
			{
				nlohmann::json includeJson = nlohmann::json::parse(includeFileStream, nullptr, false);
				if (includeJson.is_discarded())
				{
					throw error_result_t(eResult::invalidConfigurationFile, "invalid json format");
				}

				loadConfig_fqdns(baseNext,
				                 includeJson,
				                 rootFilePath,
				                 jsons);
			}
		}

		return;
	}

	for (const auto& json_iter : json.items())
	{
		auto& map_vrf = baseNext.vrf_fqdns[json_iter.key()];

		for (const auto& json_ip_fqdns : json.items())
		{
			auto& map_ip = map_vrf[json_ip_fqdns.key()];

			for (const auto& json_fqdn : json_ip_fqdns.value())
			{
				map_ip.emplace_back(json_fqdn);
			}
		}
	}
}

void config_parser_t::loadConfig_rib(controlplane::base_t& baseNext,
                                     const nlohmann::json& json)
{
	for (const auto& json_iter : json.items())
	{
		const auto& name = json_iter.key();
		const auto& rib_items = json_iter.value();

		auto& vrf = baseNext.rib[name];
		for (const auto& json_rib_item : rib_items)
		{
			controlplane::base_rib base_rib;
			base_rib.prefix = json_rib_item["prefix"].get<std::string>();
			base_rib.nexthop = json_rib_item["nexthop"].get<std::string>();

			vrf.emplace_back(std::move(base_rib));
		}
	}
}

void config_parser_t::loadConfig_memory_group(common::memory_manager::memory_group& memory_group,
                                              const nlohmann::json& json)
{
	for (const auto& json_iter : json)
	{
		auto memory_group_next = std::make_shared<common::memory_manager::memory_group>();

		std::string name = json_iter["name"].get<std::string>();
		std::string limit = "0";
		if (exist(json_iter, "limit"))
		{
			limit = json_iter["limit"].get<std::string>();
		}

		memory_group_next->name = name;
		memory_group_next->limit = common::memory_manager::convert_string_to_bytes(std::move(limit));

		if (exist(json_iter, "memory_groups"))
		{
			loadConfig_memory_group(*memory_group_next.get(), json_iter["memory_groups"]);
		}

		memory_group.memory_groups.emplace_back(memory_group_next);
	}
}
