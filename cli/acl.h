#pragma once

#include "cli/helper.h"
#include "common/icontrolplane.h"

#include "table_printer.h"

namespace acl
{

void optional_helper(std::optional<std::string>& string)
{
	if (string &&
	    *string == "any")
	{
		string = std::nullopt;
	}
}

void unwind(const std::string& in_module,
            std::optional<std::string> direction,
            std::optional<std::string> network_source,
            std::optional<std::string> network_destination,
            std::optional<std::string> fragment,
            std::optional<std::string> protocol,
            std::optional<std::string> transport_source,
            std::optional<std::string> transport_destination,
            std::optional<std::string> transport_flags,
            std::optional<std::string> recordstate)
{
	std::optional<std::string> module = in_module;

	optional_helper(module);
	optional_helper(direction);
	optional_helper(network_source);
	optional_helper(network_destination);
	optional_helper(fragment);
	optional_helper(protocol);
	optional_helper(transport_source);
	optional_helper(transport_destination);
	optional_helper(transport_flags);
	optional_helper(recordstate);

	interface::controlPlane controlplane;
	auto response = controlplane.acl_unwind({module,
	                                         direction,
	                                         network_source,
	                                         network_destination,
	                                         fragment,
	                                         protocol,
	                                         transport_source,
	                                         transport_destination,
	                                         transport_flags,
	                                         recordstate});

	FillAndPrintTable({"module",
	                   "direction",
	                   "network_source",
	                   "network_destination",
	                   "fragment",
	                   "protocol",
	                   "transport_source",
	                   "transport_destination",
	                   "transport_flags",
	                   "recordstate",
	                   "next_module",
	                   "ids",
	                   "log"},
	                  response,
	                  {.optional_null = "any"});
}

void lookup(std::optional<std::string> module,
            std::optional<std::string> direction,
            std::optional<std::string> network_source,
            std::optional<std::string> network_destination,
            std::optional<std::string> protocol,
            std::optional<std::string> transport_source,
            std::optional<std::string> transport_destination)
{
	optional_helper(module);
	optional_helper(direction);
	optional_helper(network_source);
	optional_helper(network_destination);
	optional_helper(protocol);
	optional_helper(transport_source);
	optional_helper(transport_destination);

	interface::controlPlane controlplane;
	auto response = controlplane.acl_lookup({module,
	                                         direction,
	                                         network_source,
	                                         network_destination,
	                                         std::nullopt, ///< @todo: fragment
	                                         protocol,
	                                         transport_source,
	                                         transport_destination});

	FillAndPrintTable({"ruleno", "label", "rule"}, response);
}

}
