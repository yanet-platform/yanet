#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <err.h>
#include <pthread.h>
#include <sysexits.h>
#include <unistd.h>

#include "common/type.h"
#include "controlplane/src/acl.h"
#include "controlplane/src/acl/rule.h"

auto make_default_acl(tAclId aclId = 1)
{
	controlplane::base::acl_t acl;
	common::globalBase::tFlow flow{};
	flow.type = common::globalBase::eFlowType::route;

	acl.aclId = aclId;
	acl.nextModules = {"unmatched"};
	acl.nextModuleRules.emplace_back(flow);

	return acl;
}

void dump_result(const acl::result_t& result)
{
	std::cout << "ids_map:" << std::endl;
	for (const auto& ids : result.ids_map)
	{
		std::cout << " [";
		for (const auto& id : ids)
		{
			std::cout << " " << id;
		}
		std::cout << " ]";
	}
	std::cout << std::endl
	          << "rules:" << std::endl;
	for (const auto& [ruleno, rules] : result.rules)
	{
		for (const auto& [id, gen_text, orig_text] : rules)
		{
			std::cout << ruleno << ": (" << id << ") " << orig_text << std::endl;
			std::cout << "\t" << gen_text << std::endl;
		}
	}
	std::cout << std::endl
	          << "dispatcher:" << std::endl;
	for (const auto& [id, gen_text, orig_text] : result.dispatcher)
	{
		std::cout << id << ": " << gen_text << std::endl;
	}
	std::cout << std::endl
	          << "in_iface_map:" << std::endl;
	for (const auto& [name, id] : result.in_iface_map)
	{
		std::cout << name << ": " << id << std::endl;
	}
	std::cout << std::endl
	          << "out_iface_map:" << std::endl;
	for (const auto& [name, id] : result.out_iface_map)
	{
		std::cout << name << ": " << id << std::endl;
	}
}

namespace acl
{
std::vector<rule_t> unwind_used_rules(const std::map<std::string, controlplane::base::acl_t>& acls,
                                      const iface_map_t& iface_map,
                                      ref_t<filter_t> filter,
                                      result_t& result);
};

void usage(const std::string& name)
{
	std::cerr << "Usage: " << name << " -f rules.txt [-i input_iface] [-I] [-o output_iface]" << std::endl;
	exit(EX_USAGE);
}

int main(int argc, char* argv[])
{
	common::log::logPriority = common::log::TLOG_DEBUG;
	common::acl::iface_map_t ifmap;
	std::set<std::string> oif, iif;
	std::string fname;
	char ch;

	while ((ch = getopt(argc, argv, "f:o:i:hI")) != -1)
	{
		switch (ch)
		{
			case 'f':
				fname = optarg;
				break;
			case 'i':
				iif.emplace(optarg);
				break;
			case 'I':
				// default input interface
				iif.emplace("vlan1");
				break;
			case 'o':
				oif.emplace(optarg);
				break;
			default:
				usage(argv[0]);
		}
	}

	if (fname.empty())
	{
		usage(argv[0]);
	}
	for (const auto& iface : iif)
	{
		ifmap[1].emplace(true, iface);
	}
	for (const auto& iface : oif)
	{
		ifmap[1].emplace(false, iface);
	}

	auto fw = make_default_acl();

	fw.firewall = std::make_shared<ipfw::fw_config_t>(2);
	fw.firewall->schedule_file(fname);
	fw.firewall->parse();
	fw.firewall->validate();

	std::map<std::string, controlplane::base::acl_t> acls{{"acl0", std::move(fw)}};
	acl::result_t result;
	auto rules_used = acl::unwind_used_rules(acls, ifmap, nullptr, result);

	dump_result(result);
	std::cout << std::endl
	          << "Used rules:" << std::endl;
	for (auto& rule : rules_used)
	{
		std::cout << rule.to_string() << std::endl;
	}
	return (0);
}
