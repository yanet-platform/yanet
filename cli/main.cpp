#include <functional>
#include <numeric>
#include <string>
#include <vector>

#include "acl.h"
#include "balancer.h"
#include "bus.h"
#include "config.h"
#include "convert.h"
#include "develop.h"
#include "dregress.h"
#include "helper.h"
#include "latch.h"
#include "limit.h"
#include "memory_manager.h"
#include "nat46clat.h"
#include "nat64stateful.h"
#include "neighbor.h"
#include "rib.h"
#include "route.h"
#include "show.h"
#include "telegraf.h"

std::string binPath;

common::log::LogPriority common::log::logPriority = common::log::TLOG_DEBUG;

void printUsage();

void help()
{
	printUsage();
}

std::vector<std::tuple<std::string,
                       std::string,
                       std::function<void(const std::vector<std::string>&)>>>
        commands = {{"help", "", [](const auto& args) { Call(help, args); }},
                    {},
                    {"physicalPort", "", [](const auto& args) { Call(show::physicalPort, args); }},
                    {"logicalPort", "", [](const auto& args) { Call(show::logicalPort, args); }},
                    {"acl unwind", "[module] <direction{any|in|out}> <network_source> <network_destination> <fragment{any|frag}> <protocol> <transport_source> <transport_destination> <transport_flags> <recordstate{any|true|false}>", [](const auto& args) { Call(acl::unwind, args); }},
                    {"acl lookup", "<module> <any|in|out> <network_source> <network_destination> <protocol> <transport_source> <transport_destination>", [](const auto& args) { Call(acl::lookup, args); }},
                    {"decap", "", [](const auto& args) { Call(show::decap::summary, args); }},
                    {"decap announce", "", [](const auto& args) { Call(show::decap::announce, args); }},
                    {"decap prefix allow", "[module] [ipv6_prefix] [ipv6_prefix]", [](const auto& args) { Call(config::decap::allow, args); }},
                    {"decap prefix disallow", "[module] [ipv6_prefix] [ipv6_prefix]", [](const auto& args) { Call(config::decap::disallow, args); }},
                    {"decap prefix remove", "[module] [ipv6_prefix]", [](const auto& args) { Call(config::decap::remove, args); }},
                    {"tun64", "[module]", [](const auto& args) { Call(show::tun64::summary, args); }},
                    {"tun64 announce", "[module]", [](const auto& args) { Call(show::tun64::announce, args); }},
                    {"tun64 mappings list", "[module]", [](const auto& args) { Call(show::tun64::mappings, args); }},
                    {"nat64stateful", "", [](const auto& args) { Call(nat64stateful::summary, args); }},
                    {"nat64stateful state", "<module>", [](const auto& args) { Call(nat64stateful::state, args); }},
                    {"nat64stateful announce", "", [](const auto& args) { Call(nat64stateful::announce, args); }},
                    {"nat64stateless", "", [](const auto& args) { Call(show::nat64stateless::summary, args); }},
                    {"nat64stateless translation", "", [](const auto& args) { Call(show::nat64stateless::translation, args); }},
                    {"nat64stateless announce", "", [](const auto& args) { Call(show::nat64stateless::announce, args); }},
                    {"nat64stateless prefix allow4", "[module] [ipv4_prefix] [ipv4_prefix]", [](const auto& args) { Call(config::nat64stateless::allow4, args); }},
                    {"nat64stateless prefix disallow4", "[module] [ipv4_prefix] [ipv4_prefix]", [](const auto& args) { Call(config::nat64stateless::disallow4, args); }},
                    {"nat64stateless prefix remove4", "[module] [ipv4_prefix]", [](const auto& args) { Call(config::nat64stateless::remove4, args); }},
                    {"nat64stateless prefix allow6", "[module] [ipv6_prefix] [ipv6_prefix]", [](const auto& args) { Call(config::nat64stateless::allow6, args); }},
                    {"nat64stateless prefix disallow6", "[module] [ipv6_prefix] [ipv6_prefix]", [](const auto& args) { Call(config::nat64stateless::disallow6, args); }},
                    {"nat64stateless prefix remove6", "[module] [ipv6_prefix]", [](const auto& args) { Call(config::nat64stateless::remove6, args); }},
                    {"nat46clat", "", [](const auto& args) { Call(nat46clat::summary, args); }},
                    {"nat46clat announce", "", [](const auto& args) { Call(nat46clat::announce, args); }},
                    {"balancer", "", [](const auto& args) { Call(balancer::summary, args); }},
                    {"balancer service", "[module] <virtual_ip> <proto> <virtual_port>", [](const auto& args) { Call(balancer::service, args); }},
                    {"balancer real", "[module] <virtual_ip> <proto> <virtual_port> <real_ip> <real_port>", [](const auto& args) { Call(balancer::real_find, args); }},
                    {"balancer state", "[module] <virtual_ip> <proto> <virtual_port> <real_ip> <real_port>", [](const auto& args) { Call(balancer::state, args); }},
                    {"balancer real enable", "[module] [virtual_ip] [proto] [virtual_port] [real_ip] [real_port] <real_weight>", [](const auto& args) { Call(balancer::real::enable, args); }},
                    {"balancer real disable", "[module] [virtual_ip] [proto] [virtual_port] [real_ip] [real_port]", [](const auto& args) { Call(balancer::real::disable, args); }},
                    {"balancer real flush", "", [](const auto& args) { Call(balancer::real::flush, args); }},
                    {"balancer announce", "", [](const auto& args) { Call(balancer::announce, args); }},
                    {"route", "", [](const auto& args) { Call(route::summary, args); }},
                    {"route interface", "", [](const auto& args) { Call(route::interface, args); }},
                    {"route lookup", "[module] [ip_address]", [](const auto& args) { Call(route::lookup, args); }},
                    {"route get", "[module] [ip_prefix]", [](const auto& args) { Call(route::get, args); }},
                    {"route tunnel lookup", "[module] [ip_address]", [](const auto& args) { Call(route::tunnel::lookup, args); }},
                    {"route tunnel get", "[module] [ip_prefix]", [](const auto& args) { Call(route::tunnel::get, args); }},
                    {"route counters", "", [](const auto& args) { Call(route::counters, args); }},
                    {"route tunnel counters", "", [](const auto& args) { Call(route::tunnel::counters, args); }},
                    {"neighbor show", "", [](const auto& args) { Call(neighbor::show, args); }},
                    {"neighbor insert", "[route_name] [interface_name] [ip_address] [mac_address]", [](const auto& args) { Call(neighbor::insert, args); }},
                    {"neighbor remove", "[route_name] [interface_name] [ip_address]", [](const auto& args) { Call(neighbor::remove, args); }},
                    {"neighbor flush", "", [](const auto& args) { Call(neighbor::flush, args); }},
                    {"rib", "", [](const auto& args) { Call(rib::summary, args); }},
                    {"rib prefixes", "", [](const auto& args) { Call(rib::prefixes, args); }},
                    {"rib lookup", "[vrf] [ip_address]", [](const auto& args) { Call(rib::lookup, args); }},
                    {"rib get", "[vrf] [ip_prefix]", [](const auto& args) { Call(rib::get, args); }},
                    {"rib static insert", "[vrf] [ip_prefix] [nexthop] <label> <peer_id> <origin_as> <weight>", [](const auto& args) { Call(rib::insert, args); }},
                    {"rib static remove", "[vrf] [ip_prefix] [nexthop] <label> <peer_id>", [](const auto& args) { Call(rib::remove, args); }},
                    {"dregress", "", [](const auto& args) { Call(dregress::summary, args); }},
                    {"dregress announce", "", [](const auto& args) { Call(dregress::announce, args); }},
                    {"limit", "", [](const auto& args) { Call(limit::summary, args); }},
                    {"values", "", [](const auto& args) { Call(show::values, args); }},
                    {"durations", "", [](const auto& args) { Call(show::durations, args); }},
                    {"memory show", "", [](const auto& args) { Call(memory_manager::show, args); }},
                    {"memory group", "", [](const auto& args) { Call(memory_manager::group, args); }},
                    {"dump", "[in|out|drop] [interface_name] [enable|disable]", [](const auto& args) { Call(show::physical_port_dump, args); }},
                    {},
                    {"show errors", "", [](const auto& args) { Call(show::errors, args); }},
                    {},
                    {"fw show", "<original|generated|state|all|dispatcher>", [](const auto& args) { Call(show::fw, args); }},
                    {"fw list", "<original|generated|state|all|dispatcher>", [](const auto& args) { Call(show::fwlist, args); }},
                    {},
                    {"show shm info", "", [](const auto& args) { Call(show::shm_info, args); }},
                    {},
                    {"tsc show shm info", "", [](const auto& args) { Call(show::shm_tsc_info, args); }},
                    {"tsc set state", "[true|false]", [](const auto& args) { Call(show::shm_tsc_set_state, args); }},
                    {"tsc set base", "[handle] [value]", [](const auto& args) { Call(show::shm_tsc_set_base_value, args); }},
                    {},
                    {"samples show", "", [](const auto& args) { Call(show::samples, args); }},
                    {"samples dump", "", [](const auto& args) { Call(show::samples_dump, args); }},
                    {},
                    {"dontdoit podumoi dataplane lpm4LookupAddress", "[ipv4_address]", [](const auto& args) { Call(develop::dataplane::lpm4LookupAddress, args); }},
                    {"dontdoit podumoi dataplane lpm6LookupAddress", "[ipv6_address]", [](const auto& args) { Call(develop::dataplane::lpm6LookupAddress, args); }},
                    {"dontdoit podumoi dataplane error", "", [](const auto& args) { Call(develop::dataplane::getErrors, args); }},
                    {"dontdoit podumoi dataplane report", "", [](const auto& args) { Call(develop::dataplane::getReport, args); }},
                    {"dontdoit podumoi dataplane counter", "[counter_id] <range_size>", [](const auto& args) { Call(develop::dataplane::counter, args); }},
                    {"dontdoit podumoi controlplane rib save", "", [](const auto& args) { Call(rib::save, args); }},
                    {"dontdoit podumoi controlplane rib load", "", [](const auto& args) { Call(rib::load, args); }},
                    {"dontdoit podumoi controlplane rib clear", "[protocol] <peer> <vrf> <priority>", [](const auto& args) { Call(rib::clear, args); }},
                    {"dontdoit podumoi tsc monitoring", "", [](const auto& args) { Call(develop::dataplane::tsc_monitoring, args); }},
                    {},
                    {"hitcount dump", "<acl|>", [](const auto& args) { Call(show::hitcount_dump, args); }},
                    {},
                    {"tcpdump ring", "<ring name>", [](const auto& args) { Call(show::tcpdump_ring, args); }},
                    {},
                    {"telegraf unsafe", "", [](const auto& args) { Call(telegraf::unsafe, args); }},
                    {"telegraf ports", "", [](const auto& args) { Call(telegraf::ports_stats, args); }},
                    {"telegraf dregress", "", [](const auto& args) { Call(telegraf::dregress, args); }},
                    {"telegraf peer", "", [](const auto& args) { Call(telegraf::dregress_traffic, args); }},
                    {"telegraf balancer service", "", [](const auto& args) { Call(telegraf::balancer::service, args); }},
                    {"telegraf other", "", [](const auto& args) { Call(telegraf::other, args); }},
                    {"telegraf tun64", "", [](const auto& args) { Call(telegraf::mappings, args); }},
                    {"telegraf counters", "", [](const auto& args) { Call(telegraf::main_counters, args); }},
                    {"telegraf bus", "", [](const auto& args) { Call(bus::bus_telegraf, args); }},
                    {"telegraf route", "", [](const auto& args) { Call(telegraf::route, args); }},
                    {"telegraf route tunnel", "", [](const auto& args) { Call(telegraf::route_tunnel, args); }},
                    {"telegraf acl", "", [](const auto& args) { Call(telegraf::acl, args); }},
                    {},
                    {"reload", "", [](const auto& args) { Call(config::reload, args); }},
                    {"version", "", [](const auto& args) { Call(show::version, args); }},
                    {"latch update dataplane", "<latch name> <state>", [](const auto& args) { Call(latch::dataplane_update, args); }},
                    {"counter", "[counter_name] <core_id>", [](const auto& args) { Call(show::counter_by_name, args); }},
                    {"counters stat", "", [](const auto& args) { Call(show::counters_stat, args); }},

                    {"bus requests", "", [](const auto& args) { Call(bus::bus_requests, args); }},
                    {"bus errors", "", [](const auto& args) { Call(bus::bus_errors, args); }},

                    {"latch update dataplane", "<latch name> <state>", [](const auto& args) { Call(latch::dataplane_update, args); }},
                    {},
                    {"convert logical_module", "", [](const auto& args) { Call(convert::logical_module, args); }}};

void printUsage()
{
	printf("usage:\n");
	for (const auto& [command, args, function] : commands)
	{
		GCC_BUG_UNUSED(function);

		if (command.empty())
		{
			printf("\n");
			continue;
		}

		printf("  %s %s %s\n",
		       binPath.data(),
		       command.data(),
		       args.data());
	}
}

int main(int argc,
         char** argv)
{
	binPath = argv[0];

	if (argc <= 1)
	{
		printUsage();
		return 1;
	}

	const std::vector<std::string> allArgs(argv + 1, argv + argc);
	for (int args_i = allArgs.size();
	     args_i > 0;
	     args_i--)
	{
		std::string arg_command = std::accumulate(allArgs.begin(), allArgs.begin() + args_i, std::string{}, [](const std::string& result, const std::string& string) {
			return result.empty() ? string : result + " " + string;
		});

		std::vector<std::string> arg_args(allArgs.begin() + args_i, allArgs.end());

		for (const auto& [command, args, function] : commands)
		{
			if (command == arg_command)
			{
				if (arg_args.size() == 1 &&
				    arg_args[0] == "help")
				{
					fprintf(stdout,
					        "usage: %s %s %s\n",
					        binPath.data(),
					        command.data(),
					        args.data());
					return 1;
				}

				try
				{
					function(arg_args);
					return 0;
				}
				catch (const uint32_t& rc)
				{
					return rc;
				}
				catch (const std::string& error)
				{
					fprintf(stderr, "error: %s\n", error.data());
					fprintf(stderr,
					        "usage: %s %s %s\n",
					        binPath.data(),
					        command.data(),
					        args.data());
					return 1;
				}
			}
		}
	}

	printUsage();
	return 1;
}
