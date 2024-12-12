#include <fstream>
#include <netdb.h>

#include "common/idp.h"
#include "common/version.h"

#include "acl.h"
#include "bus.h"
#include "configconverter.h"
#include "configparser.h"
#include "controlplane.h"
#include "errors.h"
#include "protobus.h"
#include "rib.h"
#include "telegraf.h"

common::log::LogPriority common::log::logPriority = common::log::TLOG_INFO;

cControlPlane::cControlPlane() :
        flagStop(false)
{
}

eResult cControlPlane::init(const std::string& jsonFilePath)
{
	eResult result = eResult::success;
	const auto start = std::chrono::steady_clock::now();

	this->jsonFilePath = jsonFilePath;

	dataPlaneConfig = dataPlane.getConfig();
	for (const auto& iter : std::get<0>(dataPlaneConfig))
	{
		sockets.emplace(std::get<1>(iter.second)); ///< @todo
	}
	for (const auto& iter : std::get<1>(dataPlaneConfig))
	{
		sockets.emplace(std::get<1>(iter.second)); ///< @todo
	}

	result = common::sdp::SdpClient::ReadSharedMemoryData(sdp_data, true);
	if (result != eResult::success)
	{
		return result;
	}
	counter_manager.init(&sdp_data);

	modules.emplace_back(new telegraf_t); ///< @todo
	modules.emplace_back(new rib_t); ///< @todo
	modules.emplace_back(new controlplane::module::bus); ///< @todo
	modules.emplace_back(new controlplane::module::protoBus); ///< @todo
	modules.emplace_back(&dregress);
	modules.emplace_back(&route);
	modules.emplace_back(&tun64);
	modules.emplace_back(&balancer);
	modules.emplace_back(&fqdn);
	modules.emplace_back(&durations);
	modules.emplace_back(&nat64stateful);
	modules.emplace_back(&nat46clat);
	modules.emplace_back(&memory_manager);

	for (auto* module : modules)
	{
		result = module->moduleInit(this);
		if (result != eResult::success)
		{
			return result;
		}
	}

	register_command(common::icp::requestType::getPhysicalPorts, [this]() {
		return getPhysicalPorts();
	});

	register_command(common::icp::requestType::getLogicalPorts, [this]() {
		return getLogicalPorts();
	});

	register_command(common::icp::requestType::getDecaps, [this]() {
		return getDecaps();
	});

	register_command(common::icp::requestType::getNat64statelesses, [this]() {
		return getNat64statelesses();
	});

	register_command(common::icp::requestType::getDefenders, [this]() {
		return getDefenders();
	});

	register_command(common::icp::requestType::limit_summary, [this]() {
		return limit_summary();
	});

	register_command(common::icp::requestType::controlplane_values, [this]() {
		return controlplane_values();
	});

	register_command(common::icp::requestType::getPortStatsEx, [this]() {
		return getPortStatsEx();
	});

	register_command(common::icp::requestType::getDecapPrefixes, [this]() {
		return command_getDecapPrefixes();
	});

	register_command(common::icp::requestType::getNat64statelessTranslations, [this]() {
		return command_getNat64statelessTranslations();
	});

	register_command(common::icp::requestType::getNat64statelessPrefixes, [this]() {
		return command_getNat64statelessPrefixes();
	});

	register_command(common::icp::requestType::getFwLabels, [this]() {
		return command_getFwLabels();
	});

	register_command(common::icp::requestType::getFwList, [this](const common::icp::request& request) {
		return command_getFwList(std::get<common::icp::getFwList::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::loadConfig, [this](const common::icp::request& request) {
		return command_loadConfig(std::get<common::icp::loadConfig::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::acl_unwind, [this](const common::icp::request& request) {
		return acl_unwind(std::get<common::icp::acl_unwind::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::acl_lookup, [this](const common::icp::request& request) {
		return acl_lookup(std::get<common::icp::acl_lookup::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::clearFWState, [this]() {
		return command_clearFWState();
	});

	register_command(common::icp::requestType::getSamples, [this]() {
		return command_getSamples();
	});

	register_command(common::icp::requestType::getAclConfig, [this](const common::icp::request& request) {
		return command_getAclConfig(std::get<common::icp::getAclConfig::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::version, [this]() {
		return command_version();
	});

	register_command(common::icp::requestType::convert, [this](const common::icp::request& request) {
		return command_convert(std::get<common::icp::convert::request>(std::get<1>(request)));
	});

	register_command(common::icp::requestType::counters_stat, [this]() {
		return command_counters_stat();
	});

	if (!jsonFilePath.empty())
	{
		std::ifstream fromFileStream(jsonFilePath);
		if (!fromFileStream.is_open())
		{
			YANET_LOG_ERROR("can't open file '%s'\n", jsonFilePath.data());
			return eResult::invalidConfigurationFile;
		}
		else
		{
			nlohmann::json rootJson = nlohmann::json::parse(fromFileStream, nullptr, false);
			if (rootJson.is_discarded())
			{
				YANET_LOG_ERROR("invalid json format\n");
				return eResult::invalidConfigurationFile;
			}

			result = loadConfig(jsonFilePath, rootJson);
			if (result != eResult::success)
			{
				YANET_LOG_ERROR("failed to load config: eResult %d\n", static_cast<std::uint32_t>(result));
				return result;
			}
			loadConfig_done++;
		}
	}
	else
	{
		common::idp::updateGlobalBase::request globalbase;
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::clear,
		                        std::tuple<>{});
		dataPlane.updateGlobalBase(globalbase);
	}
	durations.add("init", start);
	loadConfigStatus = true;

	return result;
}

void cControlPlane::start()
{
	for (auto* module : modules)
	{
		module->moduleStart();
	}

	threads.emplace_back([this] { main_thread(); });
}

void cControlPlane::stop()
{
	for (auto* module : modules)
	{
		module->moduleStop();
	}

	flagStop = true;
}

void cControlPlane::join()
{
	for (auto* module : modules)
	{
		module->moduleJoin();
	}

	for (auto& thread : threads)
	{
		if (thread.joinable())
		{
			thread.join();
		}
	}
}

eResult cControlPlane::reloadConfig()
{
	if (jsonFilePath.empty())
	{
		return eResult::invalidConfigurationFile;
	}

	std::ifstream fromFileStream(jsonFilePath);
	if (!fromFileStream.is_open())
	{
		YANET_LOG_ERROR("can't open file '%s'\n", jsonFilePath.data());
		return eResult::invalidConfigurationFile;
	}

	nlohmann::json rootJson = nlohmann::json::parse(fromFileStream, nullptr, false);
	if (rootJson.is_discarded())
	{
		YANET_LOG_ERROR("invalid json format\n");
		return eResult::invalidConfigurationFile;
	}

	return loadConfig(jsonFilePath, rootJson);
}

eResult cControlPlane::getPhysicalPortName(const tPortId& portId,
                                           std::string& name) const
{
	if (exist(std::get<0>(dataPlaneConfig), portId))
	{
		name = std::get<0>(std::get<0>(dataPlaneConfig).find(portId)->second);
		return eResult::success;
	}

	return eResult::invalidPortId;
}

const common::sdp::DataPlaneInSharedMemory* cControlPlane::getSdpData() const
{
	return &sdp_data;
}

common::icp::getPhysicalPorts::response cControlPlane::getPhysicalPorts() const
{
	common::icp::getPhysicalPorts::response response;

	auto portsStats = dataPlane.get_ports_stats();
	auto portsStatsExtended = dataPlane.get_ports_stats_extended();

	for (auto& [portId, stats] : portsStats)
	{
		const auto& [rx_packets, rx_bytes, rx_errors, rx_drops, tx_packets, tx_bytes, tx_errors, tx_drops] = stats;

		std::string physicalPortName;
		if (getPhysicalPortName(portId, physicalPortName) != eResult::success)
		{
			YANET_LOG_ERROR("unknown portId: '%u'\n", portId);
			continue;
		}

		response[physicalPortName] = {rx_packets,
		                              rx_bytes,
		                              rx_errors,
		                              rx_drops,
		                              tx_packets,
		                              tx_bytes,
		                              tx_errors,
		                              tx_drops,
		                              portsStatsExtended[portId]["link_status"],
		                              portsStatsExtended[portId]["link_speed"]};
	}

	return response;
}

common::icp::getLogicalPorts::response cControlPlane::getLogicalPorts() const
{
	common::icp::getLogicalPorts::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [logicalPortName, logicalPort] : generations.current().logicalPorts)
		{
			response[logicalPortName] = {logicalPort.physicalPort,
			                             logicalPort.vlanId,
			                             logicalPort.vrf,
			                             logicalPort.macAddress,
			                             logicalPort.promiscuousMode};
		}
	}

	return response;
}

common::icp::getDecaps::response cControlPlane::getDecaps() const
{
	common::icp::getDecaps::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [decapName, decap] : generations.current().decaps)
		{
			response[decapName] = {decap.ipv6DestinationPrefixes.size(),
			                       std::nullopt,
			                       decap.nextModule};

			if (decap.dscpMarkType != common::eDscpMarkType::never)
			{
				std::get<1>(response[decapName]) = {decap.dscpMarkType == common::eDscpMarkType::always, decap.dscp};
			}
		}
	}

	return response;
}

common::icp::getNat64statelesses::response cControlPlane::getNat64statelesses() const
{
	common::icp::getNat64statelesses::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [nat64statelessName, nat64stateless] : generations.current().nat64statelesses)
		{
			response[nat64statelessName] = {nat64stateless.translations.size(),
			                                nat64stateless.nat64_wkp_prefix,
			                                nat64stateless.nat64_src_prefix,
			                                nat64stateless.nat64_prefixes.size(),
			                                nat64stateless.nextModule};
		}
	}

	return response;
}

common::icp::getDefenders::response cControlPlane::getDefenders() const
{
	/// @todo: DELETE
	return {};
}

common::icp::getPortStatsEx::response cControlPlane::getPortStatsEx() const
{
	auto response = dataPlane.getPortStatsEx();

	for (auto& portIter : response)
	{
		std::string physicalPortName;
		if (getPhysicalPortName(portIter.first, physicalPortName) == eResult::success)
		{
			std::get<0>(portIter.second) = physicalPortName;
		}
	}

	return response;
}

common::icp::limit_summary::response cControlPlane::limit_summary() const
{
	common::icp::limit_summary::response response;

	{ /// dataplane
		interface::dataPlane dataplane;
		response = dataplane.limits();
	}

	{ /// base
		auto current_guard = generations.current_lock_guard();
		limit_insert(response,
		             "nat64stateless.translations",
		             generations.current().nat64statelessTranslationsCount,
		             CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE);
		limit_insert(response,
		             "acl.counters",
		             generations.current().ids_map.size(),
		             YANET_CONFIG_ACL_COUNTERS_SIZE);
	}

	for (auto* module : modules)
	{
		module->limit(response);
	}

	{
		limit_insert(response,
		             "counters",
		             counter_manager.stats());
	}

	return response;
}

common::icp::acl_unwind::response cControlPlane::acl_unwind(const common::icp::acl_unwind::request& request) const
{
	const auto& [module, direction, network_source, network_destination, fragment, protocol, transport_source, transport_destination, transport_flags, recordstate] = request;

	generations.current_lock();
	std::map<std::string, controlplane::base::acl_t> acls = generations.current().acls;
	acl::iface_map_t iface_map = generations.current().iface_map;
	generations.current_unlock();

	if (module)
	{
		auto it = acls.find(*module);
		if (it == acls.end())
		{
			return {};
		}

		std::map<std::string, controlplane::base::acl_t> acls_next = {{it->first, it->second}};
		acls.swap(acls_next);
	}

	return acl::unwind(acls, iface_map, module, direction, network_source, network_destination, fragment, protocol, transport_source, transport_destination, transport_flags, recordstate);
}

common::icp::acl_lookup::response cControlPlane::acl_lookup(const common::icp::acl_lookup::request& request) const
{
	const auto& [module, direction, network_source, network_destination, fragment, protocol, transport_source, transport_destination] = request;

	generations.current_lock();
	auto acls = generations.current().acls;
	auto iface_map = generations.current().iface_map;
	auto rules = generations.current().rules;
	generations.current_unlock();

	if (module)
	{
		auto it = acls.find(*module);
		if (it == acls.end())
		{
			return {};
		}

		std::map<std::string, controlplane::base::acl_t> acls_next = {{it->first, it->second}};
		acls.swap(acls_next);
	}

	auto ids = acl::lookup(acls,
	                       iface_map,
	                       module,
	                       direction,
	                       network_source,
	                       network_destination,
	                       fragment,
	                       protocol,
	                       transport_source,
	                       transport_destination);

	std::map<uint32_t, std::string> labels;
	for (const auto& [module, acl] : acls)
	{
		GCC_BUG_UNUSED(module);

		for (const auto& [label, info] : acl.firewall->labels())
		{
			auto ruleno = std::get<unsigned int>(info);
			labels[ruleno] = label;
		}
	}

	std::string label = "";

	common::icp::acl_lookup::response response;
	for (const auto& [ruleno, rules] : rules)
	{
		auto it = labels.find(ruleno);
		if (it != labels.end())
		{
			label = it->second;
		}

		for (const auto& [id, gen_text, orig_text] : rules)
		{
			GCC_BUG_UNUSED(gen_text);

			if (ids.count(id))
			{
				response.emplace_back(ruleno, label, orig_text);
				ids.erase(id);
			}

			if (ids.empty())
			{
				break;
			}
		}

		if (ids.empty())
		{
			break;
		}
	}

	return response;
}

common::icp::controlplane_values::response cControlPlane::controlplane_values() const
{
	common::icp::controlplane_values::response response;

	for (auto* module : modules)
	{
		module->controlplane_values(response);
	}

	return response;
}

common::icp::getDecapPrefixes::response cControlPlane::command_getDecapPrefixes()
{
	common::icp::getDecapPrefixes::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [moduleName, decap] : generations.current().decaps)
		{
			response[moduleName] = decap.ipv6DestinationPrefixes;
		}
	}

	return response;
}

common::icp::getNat64statelessTranslations::response cControlPlane::command_getNat64statelessTranslations()
{
	common::icp::getNat64statelessTranslations::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [moduleName, nat64stateless] : generations.current().nat64statelesses)
		{
			for (const auto& [ingress, egress] : nat64stateless.translations)
			{
				response[{moduleName,
				          std::get<0>(ingress),
				          std::get<1>(ingress),
				          std::get<2>(ingress)}] = {std::get<0>(egress),
				                                    std::get<1>(egress),
				                                    0, ///< @todo: NAT64COUNTER
				                                    0, ///< @todo: NAT64COUNTER
				                                    0, ///< @todo: NAT64COUNTER
				                                    0}; ///< @todo: NAT64COUNTER
			}
		}
	}

	return response;
}

common::icp::getNat64statelessPrefixes::response cControlPlane::command_getNat64statelessPrefixes()
{
	common::icp::getNat64statelessPrefixes::response response;

	{
		auto current_guard = generations.current_lock_guard();
		for (const auto& [moduleName, nat64stateless] : generations.current().nat64statelesses)
		{
			response[moduleName] = nat64stateless.nat64_prefixes;
		}
	}

	return response;
}

common::icp::getFwLabels::response cControlPlane::command_getFwLabels()
{
	common::icp::getFwLabels::response response;
	auto current_guard = generations.current_lock_guard();
	const auto& current = generations.current();

	for (const auto& [module, acl] : current.acls)
	{
		const auto& fw = acl.firewall;
		GCC_BUG_UNUSED(module);
		for (const auto& [label, info] : fw->labels())
		{
			auto ruleno = std::get<unsigned int>(info);
			response.insert_or_assign(ruleno, label);
		}
	}
	return response;
}

common::icp::getFwList::response cControlPlane::command_getFwList(const common::icp::getFwList::request& request)
{
	const auto rules_type = request;
	common::icp::getFwList::response response;

	if (rules_type == common::icp::getFwList::requestType::static_rules_original ||
	    rules_type == common::icp::getFwList::requestType::static_rules_generated)
	{
		auto counters = getAclCounters();
		auto current_guard = generations.current_lock_guard();
		const auto& current = generations.current();
		const auto need_orig = (rules_type == common::icp::getFwList::requestType::static_rules_original);
		std::map<uint32_t, uint64_t> counters_map; // rule id -> counter

		for (size_t i = 0; i < current.ids_map.size(); i++)
		{
			for (auto id : current.ids_map[i])
			{
				counters_map[id] += counters[i] - aclCountersDelta[i];
			}
		}

		for (const auto& [ruleno, rules] : current.rules)
		{
			auto& response_rules = response[ruleno];
			for (const auto& [id, gen_text, orig_text] : rules)
			{
				response_rules.emplace_back(id, counters_map[id], need_orig ? orig_text : gen_text);
			}
		}
	}

	if (rules_type == common::icp::getFwList::requestType::dispatcher_rules)
	{
		auto current_guard = generations.current_lock_guard();
		const auto& current = generations.current();
		auto& response_rules = response[acl::FW_DISPATCHER_START_ID];

		for (const auto& [id, gen_text, unused_text] : current.dispatcher)
		{
			GCC_BUG_UNUSED(unused_text);
			// XXX: if we need accounting for dispatcher rules
			//      we can prepare id mappings for them.
			response_rules.emplace_back(id, 0, gen_text);
		}
	}

	if (rules_type == common::icp::getFwList::requestType::dynamic_states)
	{
		// Starting offset for dynamic rules.
		auto id = acl::FW_STATES_START_ID;

		// Cache some commonly used protocols to avoid looking into /etc/protocols.
		static std::map<std::uint8_t, std::string> protocols{
		        {IPPROTO_TCP, "tcp"},
		        {IPPROTO_UDP, "udp"},
		        {IPPROTO_ESP, "esp"},
		        {IPPROTO_ICMP, "icmp"},
		        {IPPROTO_ICMPV6, "ipv6-icmp"},
		};

		for (const auto& [key, value] : dataPlane.getFWState())
		{
			const auto& [proto, src_addr, dst_addr, src_port, dst_port] = key;
			const auto& [owner, flags, last_seen, counter_backward, counter_forward] = value;
			std::ostringstream text;
			text << "allow ";

			auto it = protocols.find(proto);
			if (it == std::end(protocols))
			{
				auto proto_entry = ::getprotobynumber(proto);
				if (proto_entry != nullptr)
				{
					it = protocols.emplace_hint(it, proto, proto_entry->p_name);
				}
				else
				{
					it = protocols.emplace_hint(it, proto, std::to_string(proto));
				}
			}

			text << it->second << " from " << src_addr.toString() << " " << src_port << " to " << dst_addr.toString() << " " << dst_port;
			text << " [";
			if (owner == static_cast<std::uint8_t>(common::fwstate::owner_e::internal))
			{
				text << "own, ";
			}
			text << "last seen: " << last_seen << "s ago flags "
			     << common::fwstate::flags_to_string(flags) << ":" << common::fwstate::flags_to_string(flags >> 4) << "]"
			     << "[packets: " << counter_forward << "/" << counter_backward << "]";

			// XXX: provide correct ruleno from parent rule
			response[acl::FW_STATES_START_ID].emplace_back(id++, counter_backward + counter_forward, text.str());
		}
	}
	return response;
}

void cControlPlane::command_clearFWState()
{
	dataPlane.clearFWState();
}

common::icp::getSamples::response cControlPlane::command_getSamples()
{
	generations.current_lock();
	auto logicalport_id_to_name = generations.current().logicalport_id_to_name;
	generations.current_unlock();

	auto samples = dataPlane.samples();

	common::icp::getSamples::response response;
	response.reserve(samples.size());

	std::string unknownIface("unknown");
	for (auto& sample : samples)
	{
		auto& [proto, in_logicalport_id, out_logicalport_id, src_port, dst_port, src_addr, dst_addr] = sample;

		auto in_it = logicalport_id_to_name.find(in_logicalport_id);
		const std::string in_iface = in_it != logicalport_id_to_name.end() ? in_it->second : (unknownIface + std::to_string(in_logicalport_id));

		auto out_it = logicalport_id_to_name.find(out_logicalport_id);
		const std::string out_iface = out_it != logicalport_id_to_name.end() ? out_it->second : (unknownIface + std::to_string(out_logicalport_id));

		response.emplace_back(std::move(in_iface), std::move(out_iface), proto, src_addr, src_port, dst_addr, dst_port);
	}

	return response;
}

common::icp::getAclConfig::response cControlPlane::command_getAclConfig(common::icp::getAclConfig::request serial)
{
	std::unique_lock reload_lock(configs_mutex);
	common::icp::getAclConfig::response response;

	auto it = configs.find(serial);
	if (it != configs.end())
	{
		response = {it->first, it->second.result_iface_map, it->second.ids_map};
	}

	return response;
}

common::icp::loadConfig::response cControlPlane::command_loadConfig(const common::icp::loadConfig::request& request)
{
	eResult result = eResult::success;
	if (!jsonFilePath.empty())
	{
		result = reloadConfig();
	}
	else
	{
		std::map<std::string, nlohmann::json> jsons;
		for (const auto& iter : std::get<2>(request))
		{
			jsons[iter.first] = nlohmann::json::parse(iter.second, nullptr, false);
			if (jsons[iter.first].is_discarded())
			{
				YANET_LOG_ERROR("invalid json format\n");
				result = eResult::invalidConfigurationFile;
				break;
			}
		}

		if (result == eResult::success)
		{
			nlohmann::json rootJson = nlohmann::json::parse(std::get<1>(request), nullptr, false);
			if (rootJson.is_discarded())
			{
				YANET_LOG_ERROR("invalid json format\n");
				result = eResult::invalidConfigurationFile;
			}
			else
			{
				result = loadConfig(std::get<0>(request),
				                    rootJson,
				                    jsons);
			}
		}
	}
	if (result == eResult::success)
	{
		loadConfig_done++;
		loadConfigStatus = true;
	}
	else
	{
		loadConfig_failed++;
		loadConfigStatus = false;
	}

	return result;
}

common::icp::version::response cControlPlane::command_version()
{
	return {version_major(),
	        version_minor(),
	        version_revision(),
	        version_hash(),
	        version_custom()};
}

common::icp::convert::response cControlPlane::command_convert(const common::icp::convert::request& request)
{
	common::icp::convert::response response;
	if (request == "logical_module")
	{
		return convert_logical_module();
	}

	return response;
}

common::icp::counters_stat::response cControlPlane::command_counters_stat()
{
	return counter_manager.full_stat();
}

common::icp::convert::response cControlPlane::convert_logical_module()
{
	common::icp::convert::response response;

	generations.current_lock();
	auto logicalport_id_to_name = generations.current().logicalport_id_to_name;
	generations.current_unlock();

	for (auto [id, name] : logicalport_id_to_name)
	{
		response.emplace_back(id, name);
	}

	return response;
}

eResult cControlPlane::loadConfig(const std::string& rootFilePath,
                                  const nlohmann::json& rootJson,
                                  const std::map<std::string, nlohmann::json>& jsons)
{
	YANET_LOG_INFO("reload (stage 0)\n");
	auto start = std::chrono::steady_clock::now();

	try
	{
		std::unique_lock reload_lock(reload_mutex);

		/// read config

		YANET_LOG_INFO("parsing and converting config (stage 1)\n");

		config_parser_t parser(dataPlaneConfig);
		config_converter_t converter(this,
		                             parser.loadConfig(rootFilePath, rootJson, jsons),
		                             dataPlane.limits());
		start = durations.add("reload.parse", start);
		uint32_t serial = generations.current().serial + 1;
		auto result = converter.process(serial);
		if (result != eResult::success)
		{
			return result;
		}
		start = durations.add("reload.convert", start);

		YANET_LOG_INFO("updating dataplane (stage 2)\n");

		/// apply
		{
			{
				std::unique_lock aclCountersDelta_lock(aclCountersDelta_mutex);
				aclCountersDelta = getAclCounters();
			}

			generations.next_lock();
			for (auto* module : modules)
			{
				module->reload_before();
			}

			start = durations.add("reload.modules_before", start);

			{
				YANET_LOG_INFO("updating modules (stage 3)\n");

				common::idp::updateGlobalBase::request globalbase;

				const controlplane::base_t& base_prev = base;
				const controlplane::base_t& base_next = converter.getBaseNext();

				globalbase = std::move(converter.get_globalbase());

				generations.next() = converter.getBaseNext();
				for (auto* module : modules)
				{
					module->reload(base_prev, base_next, globalbase);
				}

				start = durations.add("reload.modules", start);
				YANET_LOG_INFO("modules updated (stage 4)\n");
				YANET_LOG_INFO("updating globalbase (stage 5)\n");

				addConfig(serial, converter.getBaseNext());
				const auto result = dataPlane.updateGlobalBase(std::move(globalbase));
				if (result != eResult::success)
				{
					// Since now the dataplane is locked for further changes
					// and considered broken.
					return result;
				}
				start = durations.add("reload.dataplane", start);

				YANET_LOG_INFO("globalbase updated (stage 6), serial %d\n", serial);
			}

			generations.switch_generation();
			generations.next_unlock();
			for (auto* module : modules)
			{
				module->reload_after();
			}

			base = converter.getBaseNext();
			durations.add("reload.modules_after", start);
		}

		YANET_LOG_INFO("dataplane has been updated (stage 7)\n");
	}
	catch (const error_result_t& error)
	{
		YANET_LOG_ERROR("%s: %s\n",
		                common::result_to_c_str(error.result()),
		                error.what());
		return error.result();
	}
	catch (const std::exception& ex)
	{
		YANET_LOG_ERROR("%s\n", ex.what());
		return eResult::invalidConfigurationFile;
	}
	catch (const std::string& string)
	{
		YANET_LOG_ERROR("%s\n", string.data());
		return eResult::invalidConfigurationFile;
	}
	catch (...)
	{
		YANET_LOG_ERROR("%s\n", "loadConfig");
		return eResult::invalidConfigurationFile;
	}

	return eResult::success;
}

void cControlPlane::addConfig(uint32_t serial, const controlplane::base_t& config)
{
	std::unique_lock reload_lock(configs_mutex);
	if (configs.size() > YANET_CONFIG_CONFIG_CACHE_SIZE)
	{
		auto it = configs.lower_bound(serial);
		if (it == configs.end())
		{
			it = configs.begin();
		}
		configs.erase(it);
	}
	configs[serial] = config;
}

void cControlPlane::main_thread()
{
	while (!flagStop)
	{
		/// XXX: GC for counters, nexthops
		std::this_thread::sleep_for(std::chrono::seconds{8});
	}
}

void cControlPlane::register_service(google::protobuf::Service* service)
{
	services[service->GetDescriptor()->name()] = service;
}

std::vector<uint64_t> cControlPlane::getAclCounters()
{
	std::vector<uint64_t> response(YANET_CONFIG_ACL_COUNTERS_SIZE);

	uint64_t start_acl_counters = sdp_data.metadata_worker.start_acl_counters;
	for (const auto& iter : sdp_data.workers)
	{
		auto* aclCounters = utils::ShiftBuffer<uint64_t*>(iter.second.buffer, start_acl_counters);
		for (size_t i = 0; i < YANET_CONFIG_ACL_COUNTERS_SIZE; i++)
		{
			response[i] += aclCounters[i];
		}
	}

	return response;
}

VrfIdStorage& cControlPlane::getVrfIdsStorage()
{
	return vrfIds;
}

std::optional<tVrfId> VrfIdStorage::Get(const std::string& vrfName) const
{
	if (vrfName.empty() || vrfName == YANET_RIB_VRF_DEFAULT)
	{
		return 0;
	}

	std::shared_lock lock(mutex);

	auto iter = vrf_ids.find(vrfName);
	if (iter != vrf_ids.end())
	{
		return iter->second;
	}

	return std::nullopt;
}

std::optional<tVrfId> VrfIdStorage::GetOrCreate(const std::string& vrfName)
{
	std::optional<tVrfId> result = Get(vrfName);
	if (result.has_value())
	{
		return result;
	}

	std::unique_lock lock(mutex);

	auto iter = vrf_ids.find(vrfName);
	if (iter != vrf_ids.end())
	{
		return iter->second;
	}

	if (vrf_ids.size() + 1 >= YANET_RIB_VRF_MAX_NUMBER)
	{
		vrf_ids[vrfName] = std::nullopt;
		YANET_LOG_ERROR("Error get id for vrf: '%s'. The number of different values has been exceeded: %d", vrfName.c_str(), YANET_RIB_VRF_MAX_NUMBER);
		return std::nullopt;
	}

	tVrfId new_id = vrf_ids.size() + 1;
	vrf_ids[vrfName] = new_id;
	return new_id;
}

tVrfId VrfIdStorage::GetOrCreateOrException(const std::string& vrfName, const std::string& message)
{
	std::optional<tVrfId> vrfId = GetOrCreate(vrfName);
	if (!vrfId.has_value())
	{
		std::ostringstream oss;
		oss << message << ": " << vrfName;
		throw error_result_t(eResult::invalidVrfId, oss.str());
	}
	return *vrfId;
}
