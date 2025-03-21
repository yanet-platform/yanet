#pragma once

#include <iostream>
#include <netdb.h>
#include <unordered_map>

#include "common/icontrolplane.h"
#include "common/idataplane.h"
#include "common/sdpclient.h"
#include "common/tsc_deltas.h"
#include "common/version.h"

#include "helper.h"
#include "table_printer.h"

namespace show
{

inline void physicalPort()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getPhysicalPorts();

	TablePrinter table;
	table.insert_row("moduleName",
	                 "link",
	                 "speed",
	                 "rx_packets",
	                 "rx_bytes",
	                 "rx_errors",
	                 "rx_drops",
	                 "tx_packets",
	                 "tx_bytes",
	                 "tx_errors",
	                 "tx_drops");

	for (const auto& [physicalPortName, physicalPort] : response)
	{
		table.insert_row(physicalPortName,
		                 std::get<8>(physicalPort) ? "up" : "down",
		                 std::to_string(std::get<9>(physicalPort) / 1000) + "G",
		                 std::get<0>(physicalPort),
		                 std::get<1>(physicalPort),
		                 std::get<2>(physicalPort),
		                 std::get<3>(physicalPort),
		                 std::get<4>(physicalPort),
		                 std::get<5>(physicalPort),
		                 std::get<6>(physicalPort),
		                 std::get<7>(physicalPort));
	}

	table.Print();
}

inline void physical_port_dump(const std::string& direction,
                               const std::string& interface_name,
                               const std::string& state)
{
	interface::dataPlane dataplane;

	bool bool_state = false;
	if (state == "enable")
	{
		bool_state = true;
	}

	const auto result = dataplane.dump_physical_port({interface_name, direction, bool_state});
	if (result != eResult::success)
	{
		throw std::string(common::result_to_c_str(result));
	}
}

inline void logicalPort()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getLogicalPorts();

	TablePrinter table;
	table.insert_row("moduleName",
	                 "physicalPortName",
	                 "vlanId",
	                 "vrf",
	                 "macAddress",
	                 "promiscuousMode");

	for (const auto& [logicalPortName, logicalPort] : response)
	{
		table.insert_row(logicalPortName,
		                 std::get<0>(logicalPort),
		                 std::get<1>(logicalPort),
		                 std::get<2>(logicalPort),
		                 std::get<3>(logicalPort),
		                 std::get<4>(logicalPort) ? "true" : "false");
	}

	table.Print();
}

static inline std::string convertToString(const common::defender::status& status)
{
	if (status == common::defender::status::success)
	{
		return "success";
	}
	else if (status == common::defender::status::fail)
	{
		return "fail";
	}
	else
	{
		return "fail (unknown status)";
	}
}

inline void defenders()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getDefenders();

	printf("defenders:\n");
	for (const auto& iter : response)
	{
		if (std::get<1>(iter.second) != "")
		{
			printf("  %s: %s (%s)\n",
			       iter.first.data(),
			       convertToString(std::get<0>(iter.second)).data(),
			       std::get<1>(iter.second).data());
		}
		else
		{
			printf("  %s: %s\n",
			       iter.first.data(),
			       convertToString(std::get<0>(iter.second)).data());
		}
	}
}

namespace tun64
{

inline void summary(std::optional<std::string> module)
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.tun64_tunnels();

	TablePrinter table;
	table.insert_row("module",
	                 "source_address",
	                 "prefixes",
	                 "randomization",
	                 "next_module");

	for (const auto& [tunnelName, tunnel] : response)
	{
		if (module.has_value() &&
		    module.value() != tunnelName)
		{
			continue;
		}

		const auto& [ipv6Src, pfxCnt, rndFlag, nxtModule] = tunnel;

		table.insert_row(tunnelName,
		                 ipv6Src,
		                 pfxCnt,
		                 rndFlag ? "true" : "false",
		                 nxtModule);
	}

	table.Print();
}

inline void announce(std::optional<std::string> module)
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.tun64_prefixes();

	TablePrinter table;
	table.insert_row("module",
	                 "prefix",
	                 "announces");

	for (const auto& [tunnelName, prefixes] : response)
	{
		if (module.has_value() &&
		    module.value() != tunnelName)
		{
			continue;
		}

		for (const auto& prefix : prefixes)
		{
			table.insert_row(tunnelName, prefix, prefix);
		}
	}

	table.Print();
}

inline void mappings(std::optional<std::string> module)
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.tun64_mappings();

	TablePrinter table;
	table.insert_row("module",
	                 "ipv4Address",
	                 "ipv6Address",
	                 "location");

	for (const auto& v : response)
	{
		const auto& [tunnelName, ipv4Address, ipv6Address, location] = v;

		if (module.has_value() &&
		    module.value() != tunnelName)
		{
			continue;
		}

		table.insert_row(tunnelName,
		                 ipv4Address,
		                 ipv6Address,
		                 location);
	}

	table.Print();
}
} /* namespace tun64 */

namespace decap
{

inline void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getDecaps();

	TablePrinter table;
	table.insert_row("module",
	                 "prefixes",
	                 "DSCP",
	                 "next_module");

	for (const auto& [decapName, decap] : response)
	{
		std::string dscpString;

		if (std::get<1>(decap))
		{
			const auto& dscp = *(std::get<1>(decap));

			dscpString = std::to_string(std::get<1>(dscp));

			if (std::get<0>(dscp))
			{
				dscpString += "!";
			}
		}
		else
		{
			dscpString = "n/s";
		}

		table.insert_row(decapName,
		                 std::get<0>(decap),
		                 dscpString,
		                 std::get<2>(decap));
	}

	table.Print();
}

inline void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getDecapPrefixes();

	TablePrinter table;
	table.insert_row("module",
	                 "prefix",
	                 "announces");

	for (const auto& [moduleName, prefixes] : response)
	{
		for (const auto& prefix : prefixes)
		{
			table.insert_row(moduleName,
			                 prefix.prefix,
			                 prefix.announces);
		}
	}

	table.Print();
}

}

namespace nat64stateless
{

inline void summary()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getNat64statelesses();

	TablePrinter table;
	table.insert_row("module",
	                 "translations",
	                 "WKP",
	                 "SRC",
	                 "prefixes",
	                 "next_module");

	for (const auto& [nat64statelessName, nat64stateless] : response)
	{
		table.insert_row(nat64statelessName,
		                 std::get<0>(nat64stateless),
		                 std::get<1>(nat64stateless),
		                 std::get<2>(nat64stateless),
		                 std::get<3>(nat64stateless),
		                 std::get<4>(nat64stateless));
	}

	table.Print();
}

inline void translation()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getNat64statelessTranslations();

	TablePrinter table;
	table.insert_row("moduleName",
	                 "ipv6Address",
	                 "ipv6DestinationAddress",
	                 "fromRange",
	                 "ipv4Address",
	                 "toRange");

	for (const auto& [key, value] : response)
	{
		const auto& moduleName = std::get<0>(key);
		const auto& ipv6Address = std::get<1>(key);
		const auto& ipv6DestinationAddress = std::get<2>(key);
		const auto& ingressPorts = std::get<3>(key);
		const auto& ipv4Address = std::get<0>(value);
		const auto& egressPorts = std::get<1>(value);

		table.insert_row(moduleName,
		                 ipv6Address,
		                 ipv6DestinationAddress,
		                 ingressPorts,
		                 ipv4Address,
		                 egressPorts);
	}

	table.Print();
}

inline void announce()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getNat64statelessPrefixes();

	TablePrinter table;
	table.insert_row("module",
	                 "prefix",
	                 "announces");

	for (const auto& [moduleName, prefixes] : response)
	{
		for (const auto& prefix : prefixes)
		{
			std::visit(
			        [&, &moduleName = moduleName](auto&& value) {
				        table.insert_row(moduleName,
				                         value.prefix,
				                         value.announces);
			        },
			        (const common::ip_prefix_with_announces_t::variant_t&)prefix);
		}
	}

	table.Print();
}

}

inline void snmp()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getPortStatsEx();

	printf("[");

	bool first = true;

	for (const auto& portIter : response)
	{
		if (!first)
		{
			printf(", ");
		}

		first = false;

		const auto& port = portIter.second;

		printf("{\n");
		printf("  \"ifIndex\" : %u,\n", portIter.first + 1);
		printf("  \"ifName\" : \"%s\",\n", std::get<0>(port).data());
		printf("  \"ifDescr\" : \"%s\",\n", std::get<0>(port).data());

		auto f = [](const char* dir, auto& data) {
			printf("  \"if%sOctets\" : %u,\n", dir, (uint32_t)std::get<0>(data));
			printf("  \"if%sUcastPkts\" : %u,\n", dir, (uint32_t)std::get<1>(data));
			printf("  \"if%sNUcastPkts\" : %u,\n", dir, (uint32_t)(std::get<2>(data) + std::get<3>(data)));
			printf("  \"if%sDiscards\" : %u,\n", dir, (uint32_t)std::get<4>(data));
			printf("  \"if%sErrors\" : %u,\n", dir, (uint32_t)std::get<5>(data));

			printf("  \"if%sMulticastPkts\" : %u,\n", dir, (uint32_t)std::get<2>(data));
			printf("  \"if%sBroadcastPkts\" : %u,\n", dir, (uint32_t)std::get<3>(data));

			printf("  \"ifHC%sOctets\" : %lu,\n", dir, std::get<0>(data));
			printf("  \"ifHC%sUcastPkts\" : %lu,\n", dir, std::get<1>(data));
			printf("  \"ifHC%sMulticastPkts\" : %lu,\n", dir, std::get<2>(data));
			printf("  \"ifHC%sBroadcastPkts\" : %lu,\n", dir, std::get<3>(data));
		};

		f("In", std::get<2>(port));
		f("Out", std::get<3>(port));

		printf("  \"ifAdminStatus\" : 1,\n"); ///< 'up'
		printf("  \"ifOperStatus\" : %u\n", std::get<1>(port) ? 1 : 2);

		/*
+        { 'name' : 'ifIndex',                 'type' : 'integer', },
+        { 'name' : 'ifDescr',                 'type' : 'string', },
-        { 'name' : 'ifType',                  'type' : 'integer', },
-        { 'name' : 'ifMtu',                   'type' : 'integer', },
-        { 'name' : 'ifSpeed',                 'type' : 'gauge', },
-        { 'name' : 'ifPhysAddress',           'type' : 'string', },
+        { 'name' : 'ifAdminStatus',           'type' : 'integer', },
+        { 'name' : 'ifOperStatus',            'type' : 'integer', },
-        { 'name' : 'ifLastChange',            'type' : 'timetick', },
+        { 'name' : 'ifInOctets',              'type' : 'counter', },
+        { 'name' : 'ifInUcastPkts',           'type' : 'counter', },
+        { 'name' : 'ifInNUcastPkts',          'type' : 'counter', },
+        { 'name' : 'ifInDiscards',            'type' : 'counter', },
+        { 'name' : 'ifInErrors',              'type' : 'counter', },
-        { 'name' : 'ifInUnknownProtos',       'type' : 'counter', },
+        { 'name' : 'ifOutOctets',             'type' : 'counter', },
+        { 'name' : 'ifOutUcastPkts',          'type' : 'counter', },
+        { 'name' : 'ifOutNUcastPkts',         'type' : 'counter', },
+        { 'name' : 'ifOutDiscards',           'type' : 'counter', },
+        { 'name' : 'ifOutErrors',             'type' : 'counter', },
-        { 'name' : 'ifOutQLen',               'type' : 'gauge', },
-        { 'name' : 'ifSpecific',              'type' : 'objectid', },

+        { 'name' : 'ifName',                  'type' : 'string', },
+        { 'name' : 'ifInMulticastPkts',       'type' : 'counter', },
+        { 'name' : 'ifInBroadcastPkts',       'type' : 'counter', },
+        { 'name' : 'ifOutMulticastPkts',      'type' : 'counter', },
+        { 'name' : 'ifOutBroadcastPkts',      'type' : 'counter', },
+        { 'name' : 'ifHCInOctets',            'type' : 'counter64', },
+        { 'name' : 'ifHCInUcastPkts',         'type' : 'counter64', },
+        { 'name' : 'ifHCInMulticastPkts',     'type' : 'counter64', },
+        { 'name' : 'ifHCInBroadcastPkts',     'type' : 'counter64', },
+        { 'name' : 'ifHCOutOctets',           'type' : 'counter64', },
+        { 'name' : 'ifHCOutUcastPkts',        'type' : 'counter64', },
+        { 'name' : 'ifHCOutMulticastPkts',    'type' : 'counter64', },
+        { 'name' : 'ifHCOutBroadcastPkts',    'type' : 'counter64', },
-        { 'name' : 'ifLinkUpDownTrapEnable',  'type' : 'integer', },
-        { 'name' : 'ifHighSpeed',             'type' : 'gauge', },
-        { 'name' : 'ifPromiscuousMode',       'type' : 'integer', },
-        { 'name' : 'ifConnectorPresent',      'type' : 'integer', },
-        { 'name' : 'ifAlias',                 'type' : 'string', },
-        { 'name' : 'ifCounterDiscontinuityTime', 'type' : 'timetick', },
*/

		printf("}");
	}

	printf("]\n");
}

static const std::map<std::string, unsigned int> rule_types = {
        {"original", 0x01}, // default for `fw show`
        {"orig", 0x01},
        {"generated", 0x02}, // default for `fw list`
        {"gen", 0x02},
        {"states", 0x04}, // dynamic states
        {"state", 0x04},
        {"all", 0x06}, // original + states
        {"dispatcher", 0x08}, // dispatcher rules
        {"disp", 0x08},
};

static void list_fw_rules(unsigned int mask, bool list)
{
	// we need labels only for orig or gen rules
	unsigned int need_labels = 0x03;
	static const common::icp::getFwList::requestType type[] = {
	        common::icp::getFwList::requestType::static_rules_original,
	        common::icp::getFwList::requestType::static_rules_generated,
	        common::icp::getFwList::requestType::dynamic_states,
	        common::icp::getFwList::requestType::dispatcher_rules,
	};
	common::icp::getFwLabels::response labels;
	interface::controlPlane controlPlane;

	TablePrinter table;
	if (list)
	{
		table.insert_row("id",
		                 "ruleno",
		                 "label",
		                 "rule");
	}
	else
	{
		table.insert_row("id",
		                 "ruleno",
		                 "label",
		                 "counter",
		                 "rule");
	}

	if (need_labels & mask)
	{
		labels = controlPlane.getFwLabels();
		if (labels.empty())
		{
			// we don't have any labels, avoid access
			need_labels = 0;
		}
	}
	for (size_t i = 0; i < sizeof(type) / sizeof(type[0]); ++i)
	{
		if ((mask & (1 << i)) == 0)
		{
			continue;
		}
		const auto response = controlPlane.getFwList(type[i]);
		uint32_t start = 0, end = 0;
		std::string label = "";
		auto it = labels.cbegin();

		for (const auto& [ruleno, rules] : response)
		{
			if (need_labels & (1 << i) && ruleno > end)
			{
				while (it != std::cend(labels))
				{
					auto next = it;
					start = it->first;
					if (++next != std::cend(labels))
					{
						end = next->first - 1;
					}
					else
					{
						end = UINT32_MAX;
					}
					if (ruleno <= end)
						break;
					it = next;
				}
			}
			if (need_labels & (1 << i))
			{
				if (ruleno >= start && ruleno < end)
				{
					label = it->second;
				}
			}
			for (const auto& [id, counter, text] : rules)
			{
				if (list)
				{
					GCC_BUG_UNUSED(counter);
					table.insert_row(id, ruleno, label, text);
				}
				else
				{
					table.insert_row(id, ruleno, label, counter, text);
				}
			}
		}
	}
	table.Print();
}

inline void fw(std::optional<std::string> str)
{
	const auto type = str.value_or("original");

	if (rule_types.count(type) != 0)
	{
		list_fw_rules(rule_types.at(type), false);
	}
	else
	{
		std::string args;
		std::for_each(rule_types.cbegin(), rule_types.cend(), [&](const auto& e) { args += " " + e.first; });
		throw std::string("invalid argument: ") + type + ", supported types:" + args;
	}
}

inline void fwlist(std::optional<std::string> str)
{
	const auto type = str.value_or("generated");

	if (rule_types.count(type) != 0)
	{
		list_fw_rules(rule_types.at(type), true);
	}
	else
	{
		std::string args;
		std::for_each(rule_types.cbegin(), rule_types.cend(), [&](const auto& e) { args += " " + e.first; });
		throw std::string("invalid argument: ") + type + ", supported types:" + args;
	}
}

inline void errors()
{
	interface::dataPlane dataPlane;
	const auto response = dataPlane.getErrors();

	FillAndPrintTable({"name", "counter"}, response);
}

inline void samples()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getSamples();

	TablePrinter table;
	table.insert_row("in_iface",
	                 "out_iface",
	                 "proto",
	                 "src_addr",
	                 "src_port",
	                 "dst_addr",
	                 "dst_port");

	// Cache the protocols we are interested in to prevent enormous number of reading of "/etc/protocols".
	std::unordered_map<std::uint8_t, std::string> proto_cache;
	for (const auto& [in_iface, out_iface, proto, src_addr, src_port, dst_addr, dst_port] : response)
	{
		auto it = proto_cache.find(proto);
		if (it == std::end(proto_cache))
		{
			if (auto* protoent = getprotobynumber(proto); protoent != nullptr)
			{
				it = proto_cache.emplace_hint(it, proto, protoent->p_name);
			}
			else
			{
				it = proto_cache.emplace_hint(it, proto, std::to_string(proto));
			}
		}
		const auto& protoName = it->second;

		table.insert_row(in_iface, out_iface, protoName, src_addr, src_port, dst_addr, dst_port);
	}

	table.Print();
}

inline void samples_dump()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.getSamples();

	std::cout << "[";

	bool first = true;
	for (const auto& [in_iface, out_iface, proto, src_addr, src_port, dst_addr, dst_port] : response)
	{
		if (!first)
		{
			std::cout << ",";
		}
		first = false;
		std::cout << "\n"
		          << R"({"in_iface":")" << in_iface << "\","
		          << R"("out_iface":")" << out_iface << "\","
		          << "\"proto\":" << (int)proto << ","
		          << R"("src_addr":")" << src_addr.toString() << "\","
		          << "\"src_port\":" << src_port << ","
		          << R"("dst_addr":")" << dst_addr.toString() << "\","
		          << "\"dst_port\":" << dst_port << "}";
	}

	std::cout << "]\n";
}

inline void hitcount_dump(const std::string& source)
{
	if (source != "acl")
	{
		YANET_THROW("Error: Need to specify source. Right now, only 'acl' is supported.\n");
	}

	interface::dataPlane dataplane;
	const auto& response = dataplane.hitcount_dump();

	std::cout << "[\n";

	bool first = true;
	for (const auto& [id, data] : response)
	{
		if (!first)
		{
			std::cout << "\n";
		}
		first = false;

		std::cout << "  " << id << ": " << data.count << ", " << data.bytes;
	}

	std::cout << "\n]\n";
}

inline void values()
{
	interface::controlPlane controlplane;
	const auto controlplane_values = controlplane.controlplane_values();

	TablePrinter table;
	table.insert_row("application",
	                 "name",
	                 "value");

	for (const auto& [name, value] : controlplane_values)
	{
		table.insert_row("controlplane",
		                 name,
		                 value);
	}

	table.Print();
}

inline void durations()
{
	interface::controlPlane controlplane;
	const auto controlplane_durations = controlplane.controlplane_durations();

	TablePrinter table;
	table.insert_row("application",
	                 "name",
	                 "duration");

	for (const auto& [name, value] : controlplane_durations)
	{
		table.insert_row("controlplane",
		                 name,
		                 value);
	}

	table.Print();
}

inline void version()
{
	TablePrinter table;
	table.insert_row("application",
	                 "version",
	                 "revision",
	                 "hash",
	                 "custom");

	/// dataplane
	try
	{
		interface::dataPlane dataplane;
		const auto [major, minor, revision, hash, custom] = dataplane.version();

		table.insert_row("dataplane",
		                 version_to_string(major, minor),
		                 version_revision_to_string(revision),
		                 version_hash_to_string(hash),
		                 version_custom_to_string(custom));
	}
	catch (...)
	{
	}

	/// controlplane
	try
	{
		interface::controlPlane controlplane;
		const auto [major, minor, revision, hash, custom] = controlplane.version();

		table.insert_row("controlplane",
		                 version_to_string(major, minor),
		                 version_revision_to_string(revision),
		                 version_hash_to_string(hash),
		                 version_custom_to_string(custom));
	}
	catch (...)
	{
	}

	/// cli
	{
		table.insert_row("cli",
		                 version_to_string(),
		                 version_revision_to_string(),
		                 version_hash_to_string(),
		                 version_custom_to_string());
	}

	table.Print();
}

inline void counter_by_name(std::string counter_name,
                            const std::optional<tCoreId>& core_id)
{
	const auto response = common::sdp::SdpClient::GetCounterByName(counter_name, core_id);

	if (response.empty())
	{
		if (core_id.has_value())
		{
			throw std::string("counter with name: '" + counter_name + "' does not exist for coreId " + std::to_string(core_id.value()));
		}
		else
		{
			throw std::string("counter with name: '" + counter_name + "' does not exist");
		}
	}

	FillAndPrintTable({"core_id", "counter_value"}, response);
}

inline void shm_info()
{
	interface::dataPlane dataplane;
	const auto response = dataplane.get_shm_info();

	// TODO: unravel inner structure somehow?
	// think about it later.
	FillAndPrintTable({"ring name",
	                   "dump tag",
	                   "dump config",
	                   "core id",
	                   "socket id",
	                   "ipc key",
	                   "offset"},
	                  response);
}

void shm_tsc_info()
{
	interface::dataPlane dataplane;
	const auto response = dataplane.get_shm_tsc_info();

	FillAndPrintTable({"core id", "socket id", "ipc key", "offset"}, response);
}

void shm_tsc_set_state(bool state)
{
	interface::dataPlane dataplane;
	common::idp::updateGlobalBase::request globalbase;
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tsc_state_update,
	                        state);
	dataplane.updateGlobalBase(globalbase);
}

using dataplane::perf::tsc_base_values;
static const std::map<std::string, uint32_t> counter_name_to_offset = {
        {"logicalPort_ingress_handle", offsetof(tsc_base_values, logicalPort_ingress_handle)},
        {"acl_ingress_handle4", offsetof(tsc_base_values, acl_ingress_handle4)},
        {"acl_ingress_handle6", offsetof(tsc_base_values, acl_ingress_handle6)},
        {"tun64_ipv4_handle", offsetof(tsc_base_values, tun64_ipv4_handle)},
        {"tun64_ipv6_handle", offsetof(tsc_base_values, tun64_ipv6_handle)},
        {"route_handle4", offsetof(tsc_base_values, route_handle4)},
        {"route_handle6", offsetof(tsc_base_values, route_handle6)},
        {"decap_handle", offsetof(tsc_base_values, decap_handle)},
        {"nat64stateful_lan_handle", offsetof(tsc_base_values, nat64stateful_lan_handle)},
        {"nat64stateful_wan_handle", offsetof(tsc_base_values, nat64stateful_wan_handle)},
        {"nat64stateless_egress_handle", offsetof(tsc_base_values, nat64stateless_egress_handle)},
        {"nat64stateless_ingress_handle", offsetof(tsc_base_values, nat64stateless_ingress_handle)},
        {"nat46clat_lan_handle", offsetof(tsc_base_values, nat46clat_lan_handle)},
        {"nat46clat_wan_handle", offsetof(tsc_base_values, nat46clat_wan_handle)},
        {"balancer_handle", offsetof(tsc_base_values, balancer_handle)},
        {"balancer_icmp_reply_handle", offsetof(tsc_base_values, balancer_icmp_reply_handle)},
        {"balancer_icmp_forward_handle", offsetof(tsc_base_values, balancer_icmp_forward_handle)},
        {"route_tunnel_handle4", offsetof(tsc_base_values, route_tunnel_handle4)},
        {"route_tunnel_handle6", offsetof(tsc_base_values, route_tunnel_handle6)},
        {"acl_egress_handle4", offsetof(tsc_base_values, acl_egress_handle4)},
        {"acl_egress_handle6", offsetof(tsc_base_values, acl_egress_handle6)},
        {"logicalPort_egress_handle", offsetof(tsc_base_values, logicalPort_egress_handle)},
        {"controlPlane_handle", offsetof(tsc_base_values, controlPlane_handle)},
};

void shm_tsc_set_base_value(std::string counter_name, uint32_t value)
{
	if (counter_name_to_offset.count(counter_name) != 0)
	{
		interface::dataPlane dataplane;
		common::idp::updateGlobalBase::request globalbase;
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tscs_base_value_update,
		                        common::idp::updateGlobalBase::tscs_base_value_update::request{counter_name_to_offset.at(counter_name), value});
		dataplane.updateGlobalBase(globalbase);
	}
	else
	{
		std::string args;
		std::for_each(counter_name_to_offset.cbegin(), counter_name_to_offset.cend(), [&](const auto& e) { args += " " + e.first; });
		throw std::string("invalid argument: ") + counter_name + ", supported types:" + args;
	}
}

void counters_stat()
{
	interface::controlPlane controlplane;
	auto [common_info, sizes_info] = controlplane.counters_stat();
	auto [free_blocks, free_cells, errors_external, errors_internal] = common_info;
	printf("Counters usage info\n");
	printf("Free blocks: %d, counters: %d\n", free_blocks, free_cells);
	printf("Errors external: %ld, internal: %ld\n", errors_external, errors_internal);

	for (auto [size, used_blocks, busy_blocks, used_segments] : sizes_info)
	{
		printf("size: %d, used blocks: %d, busy blocks: %d, used segments: %d\n", size, used_blocks, busy_blocks, used_segments);
	}
}

}
