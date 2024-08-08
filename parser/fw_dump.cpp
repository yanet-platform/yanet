#include "fw_dump.h"

using namespace ipfw;

void fw_dump_t::dump_dnscache()
{
	std::cerr << "# DNS Cache" << std::endl;
	std::cerr << "#----------------------------------------" << std::endl;
	for (const auto& [fqdn, values] : m_conf->m_dns_cache)
	{
		const auto& [lh, addresses, actual] = values;
		bool comma = false;

		(void)lh;
		std::cerr << fqdn << " ";
		for (const auto& addr : addresses)
		{
			if (comma)
				std::cerr << ",";
			std::cerr << addr.toString();
			comma = true;
		}
		std::cerr << " " << (actual ? "actual" : "stale") << std::endl;
	}
}

void fw_dump_t::dump_tables()
{
	static const std::vector<std::string> types{"addr", "addr", "iface"};
	std::cerr << "# Tables " << std::endl;
	std::cerr << "#----------------------------------------" << std::endl;
	for (const auto& [name, values] : m_conf->m_tables)
	{
		const auto& [lh, table] = values;

		(void)lh;
		std::cerr << "table " << name << " create type " << types[table.index()] << std::endl;
		if (std::holds_alternative<tables::prefix_skipto_t>(table))
		{
			for (const auto& [prefix, label] : std::get<tables::prefix_skipto_t>(table))
			{
				std::cerr << "table " << name << " add " << prefix.toString() << " " << label << std::endl;
			}
		}
		else if (std::holds_alternative<tables::ifname_t>(table))
		{
			for (const auto& [ifname, label] : std::get<tables::ifname_t>(table))
			{
				std::cerr << "table " << name << " add " << ifname;
				if (!label.empty())
					std::cerr << " " << label;
				std::cerr << std::endl;
			}
		}
	}
}

void fw_dump_t::dump_macros()
{
	std::cerr << "# Macros " << std::endl;
	std::cerr << "#----------------------------------------" << std::endl;
	for (const auto& [name, values] : m_conf->m_macros)
	{
		const auto& [lh, prefixes, used] = values;
		bool comma = false;

		(void)lh;
		if (!used)
		{
			// comment unused macros
			std::cerr << "# ";
		}
		std::cerr << name << ": ";
		for (const auto& prefix : prefixes)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << prefix;
			comma = true;
		}
		std::cerr << std::endl;
	}
}

void fw_dump_t::dump_labels()
{
	std::cerr << "# Labels" << std::endl;
	std::cerr << "#----------------------------------------" << std::endl;
	for (const auto& [name, info] : m_conf->m_labels)
	{
		const auto& [ruleno, location] = info;
		std::cerr << "# " << name << " defined at " << m_conf->format_location(location) << ", starts from " << ruleno << std::endl;
	}
}

void fw_dump_t::dump_rule(rule_ptr_t rulep)
{
	if (!rulep || rulep->state == rule_t::rule_state_t::UNKNOWN)
		return;

	std::cerr << rulep->text << std::endl;
	std::cerr << "# located at " << m_conf->format_location(rulep->location) << std::endl;
	std::cerr << "# ruleno = " << rulep->ruleno << ", ruleid = " << rulep->ruleid << std::endl;
	std::cerr << "# log = " << rulep->log << ", logamount = " << rulep->logamount << std::endl;
	std::cerr << "# ipver = " << rulep->ipver << std::endl;
	std::cerr << "# action = " << (int)rulep->action << std::endl;
	std::cerr << "# proto = ";
	if (rulep->proto.empty())
	{
		std::cerr << "any" << std::endl;
	}
	else
	{
		bool comma = false;
		for (auto proto : rulep->proto)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << (int)proto;
			comma = true;
		}
		std::cerr << std::endl;
	}
	std::cerr << "# src = ";
	if (rulep->src.empty())
	{
		std::cerr << "any" << std::endl;
	}
	else
	{
		bool comma = false;
		for (auto prefix : rulep->src)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << prefix;
			comma = true;
		}
		std::cerr << std::endl;
	}
	std::cerr << "# src_me = " << rulep->src_me << ", src_me6 = " << rulep->src_me6 << ", src_any = " << rulep->src_any << std::endl;
	std::cerr << "# src_ports = ";
	if (rulep->sports.empty() && rulep->sports_range.empty())
	{
		std::cerr << "any" << std::endl;
	}
	else
	{
		bool comma = false;
		for (auto port : rulep->sports)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << port;
			comma = true;
		}
		for (auto [from, to] : rulep->sports_range)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << from << "-" << to;
			comma = true;
		}
		std::cerr << std::endl;
	}
	std::cerr << "# dst = ";
	if (rulep->dst.empty())
	{
		std::cerr << "any" << std::endl;
	}
	else
	{
		bool comma = false;
		for (auto prefix : rulep->dst)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << prefix;
			comma = true;
		}
		std::cerr << std::endl;
	}
	std::cerr << "# dst_me = " << rulep->dst_me << ", dst_me6 = " << rulep->dst_me6 << ", dst_any = " << rulep->dst_any << std::endl;
	std::cerr << "# dst_ports = ";
	if (rulep->dports.empty() && rulep->dports_range.empty())
	{
		std::cerr << "any" << std::endl;
	}
	else
	{
		bool comma = false;
		for (auto port : rulep->dports)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << port;
			comma = true;
		}
		for (auto [from, to] : rulep->dports_range)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << from << "-" << to;
			comma = true;
		}
		std::cerr << std::endl;
	}
	if (rulep->tcp_established)
		std::cerr << "# established = " << rulep->tcp_established << std::endl;
	if (rulep->tcp_setflags || rulep->tcp_clearflags)
		std::cerr << "# tcpflags = set(" << std::hex << (int)rulep->tcp_setflags << "), clear(" << (int)rulep->tcp_clearflags << ")" << std::dec << std::endl;
	if (!rulep->icmp_types.empty())
	{
		bool comma = false;
		std::cerr << "# icmptypes = ";
		for (auto icmptype : rulep->icmp_types)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << icmptype;
			comma = true;
		}
		std::cerr << std::endl;
	}
	if (!rulep->icmp6_types.empty())
	{
		bool comma = false;
		std::cerr << "# icmp6types = ";
		for (auto icmptype : rulep->icmp6_types)
		{
			if (comma)
				std::cerr << ", ";
			std::cerr << icmptype;
			comma = true;
		}
		std::cerr << std::endl;
	}
	if (rulep->ipoff_setflags | rulep->ipoff_clearflags)
	{
		std::cerr << "# frag = set(" << std::hex << (int)rulep->ipoff_setflags << "), clear(" << (int)rulep->ipoff_clearflags << ")" << std::dec << std::endl;
	}
	std::cerr << "# recordstate = " << rulep->recordstate << std::endl;
	if (rulep->direction == rule_t::direction_t::IN)
		std::cerr << "# direction = IN" << std::endl;
	else if (rulep->direction == rule_t::direction_t::OUT)
		std::cerr << "# direction = OUT" << std::endl;
	if (rulep->ifaces.size())
	{
		bool many = false;
		std::cerr << "# via: ";
		for (const auto& [name, how] : rulep->ifaces)
		{
			(void)how;
			if (many)
				std::cerr << " or ";
			std::cerr << name;
			many = true;
		}
		std::cerr << std::endl;
	}
	if (rulep->iface_tables.size())
	{
		bool comma = false;
		std::cerr << "# via table: ";
		for (const auto& [how, tables] : rulep->iface_tables)
		{
			(void)how;
			for (const auto& name : tables)
			{
				if (comma)
					std::cerr << ", ";
				std::cerr << name;
				comma = true;
			}
		}
		std::cerr << std::endl;
	}
}

void fw_dump_t::dump_rules()
{
	std::cerr << "# Rules " << std::boolalpha << std::endl;
	std::cerr << "#----------------------------------------" << std::endl;
	for (auto& [ruleno, rules] : m_conf->m_rules)
	{
		(void)ruleno;
		for (auto rulep : rules)
		{
			dump_rule(rulep);
		}
	}
}

void fw_dump_t::dump_history()
{
	auto idx = 0;

	std::cerr << "# Files history" << std::endl;
	for (const auto& h : m_conf->m_history)
	{
		std::cerr << "# " << ++idx << ". " << *h.name << ": " << h.level << std::endl;
	}
}

void fw_dump_t::dump()
{
	dump_history();
	dump_dnscache();
	dump_macros();
	dump_tables();
	dump_labels();
	dump_rules();
}
