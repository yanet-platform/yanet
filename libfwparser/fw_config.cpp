#include <algorithm>
#include <limits>
#include <netdb.h>
#include <stdexcept>

#include "libfwparser/fw_parser.h"

#include "fw_config.h"

using namespace ipfw;

#define FW_CONF_DEBUG(msg)                                                              \
	do                                                                              \
	{                                                                               \
		if (m_debug > 0)                                                        \
			std::cerr << "DEBUG: " << __func__ << ": " << msg << std::endl; \
	} while (0)

fw_config_t::fw_config_t(int step) :
        m_curr_entity(entity_type::NONE), m_debug(0), m_ruleid_last(0), m_ruleno_last(0)
{
	// use limits like in FreeBSD kernel
	const auto value = std::clamp(step, 1, 1000);

	m_ruleno_step = value;
	m_curr_rule = std::make_shared<rule_t>();
	m_prev_rule = nullptr;

	// initialize protocols cache
	m_protocols.emplace("icmp6", IPPROTO_ICMPV6);
	// initialize services cache
	m_services = {
	        {"http", 80},
	        {"https", 443},
	        {"domain", 53},
	        {"bgp", 179},
	        {"ssh", 22},
	        {"snmp", 161},
	        {"syslog", 514},
	        {"ntp", 123},
	        {"bootpc", 68},
	        {"bootps", 67},
	        {"telnet", 23},
	        {"ftp", 21},
	        {"ftp-data", 20},
	        {"smtp", 25},
	        {"pop3", 110},
	        {"imap", 143},
	        {"netconf-ssh", 830},
	};
}

int fw_config_t::getservbyname(const std::string& service)
{
	auto it = m_services.find(service);
	if (it == std::end(m_services))
	{
		auto servent = ::getservbyname(service.c_str(), nullptr);
		if (servent == nullptr)
		{
			return -1;
		}
		it = m_services.emplace_hint(it, service, ntohs(servent->s_port));
	}
	return it->second;
}

int fw_config_t::getprotobyname(const std::string& proto)
{
	auto it = m_protocols.find(proto);

	if (it == std::end(m_protocols))
	{
		auto protoent = ::getprotobyname(proto.c_str());
		if (protoent == nullptr)
		{
			return -1;
		}
		it = m_protocols.emplace_hint(it, proto, protoent->p_proto);
	}
	return it->second;
}

void fw_config_t::setup_lexer(const std::string& name, istream_ptr_t istrm, bool nested)
{
	FW_CONF_DEBUG(name);
	// save fileno for current file
	m_fileno.emplace(m_history.size());
	// create new history entry: save filename and its level
	m_history.emplace_back(fw_config_history_t{
	        std::make_unique<std::string>(name), nested ? m_location.size() : 0});
	// create new lexer cursor location
	auto* file = m_history.back().name.get();
	m_location.emplace(location{file});
	// save input stream
	m_filestrm.emplace(istrm);
	// use new input stream in lexer
	m_lexer.switch_streams(istrm.get(), nullptr);
}

bool fw_config_t::open(const std::string& file, bool nested)
{
	FW_CONF_DEBUG(file);
	if (m_location.size() >= FW_CONFIG_MAX_NESTED)
	{
		throw std::runtime_error("too many nested includes: " + std::to_string(m_location.size()));
	}
	auto filename = file;
	if (nested && !filename.empty() && filename.front() != '/')
	{
		auto parent = *m_history.back().name;
		auto pos = parent.find_last_of("/");
		if (pos == std::string::npos)
		{
			parent = "./";
		}
		else
		{
			parent = parent.substr(0, pos + 1);
		}
		filename = parent + filename;
	}
	auto fstrm = std::make_shared<std::ifstream>(filename, std::ios::in);
	if (!fstrm->is_open())
	{
		throw std::runtime_error("failed to open config: " + filename);
	}

	setup_lexer(filename, fstrm, nested);
	return (true);
}

bool fw_config_t::close(void)
{
	if (m_filestrm.empty())
		return (false);

	FW_CONF_DEBUG(*m_history[m_fileno.top()].name);

	m_fileno.pop();
	m_location.pop();
	m_filestrm.pop();

	// if stack is not empty yet, switch to previously
	// opened file.
	if (!m_filestrm.empty())
	{
		auto istrm = m_filestrm.top();

		FW_CONF_DEBUG("return to " << *m_history[m_fileno.top()].name);
		m_lexer.switch_streams(istrm.get(), nullptr);
		return (true);
	}
	return (false);
}

bool fw_config_t::parse(void)
{
	fw_parser_t parser(*this);

	if (m_debug > 1)
		parser.set_debug_level(m_debug);
	if (m_debug > 2)
		m_lexer.set_debug(true);

	return parser.parse() == 0;
}

bool fw_config_t::schedule_file(const std::string& file)
{
	FW_CONF_DEBUG(file);
	return open(file, false);
}

bool fw_config_t::schedule_string(const std::string& str)
{
	auto istrm = std::make_shared<std::istringstream>(str);
	setup_lexer("<CMDLINE>", istrm, false);
	return true;
}

bool fw_config_t::schedule_stdin(void)
{
	istream_ptr_t istrm;

	istrm.reset(&std::cin, [](std::istream*) { /* custom deleter to ignore std::cin */ });
	setup_lexer("<STDIN>", istrm, false);
	return true;
}

void fw_config_t::add_label(const std::string& s)
{
	const auto& l = m_location.top();

	FW_CONF_DEBUG(s);
	if (m_labels.count(s) > 0)
	{
		const auto& location = std::get<1>(m_labels.at(s));
		throw fw_parser_t::syntax_error(l,
		                                "duplicate label " + s + ", previously was defined at " +
		                                        format_location(location));
	}
	m_last_label = s;
	m_labels.emplace(s, label_info_t{m_ruleno_last + 1, // we will jump to the next rule
	                                 location_history_t{(unsigned int)l.begin.line, m_fileno.top()}});
}

void fw_config_t::set_macro(const std::string& s)
{
	const auto& l = m_location.top();

	FW_CONF_DEBUG(s);
	if (m_macros.count(s) > 0)
	{
		const auto& location = std::get<location_history_t>(m_macros.at(s));
		throw fw_parser_t::syntax_error(l,
		                                "duplicate macro " + s + ", previously was defined at " +
		                                        format_location(location));
	}
	m_curr_name = s;
	m_curr_entity = entity_type::MACRODEF;
	m_macros.emplace(s, macro_t{location_history_t{(unsigned int)l.begin.line, m_fileno.top()}, {/* empty */}, false});
}

void fw_config_t::fill_macro(const ip_prefix_mask_t& p)
{
	const auto& l = m_location.top();

	FW_CONF_DEBUG(m_curr_name << "()");
	if (m_curr_entity != entity_type::MACRODEF || m_macros.count(m_curr_name) == 0)
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown macro");

	auto& prefixes = std::get<1>(m_macros[m_curr_name]);

	prefixes.emplace(p);
}

void fw_config_t::fill_macro_fqdn(const std::string& fqdn)
{
	const auto& l = m_location.top();

	FW_CONF_DEBUG(m_curr_name << "()");
	if (m_curr_entity != entity_type::MACRODEF || m_macros.count(m_curr_name) == 0)
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown macro");

	if (m_dns_cache.count(fqdn) == 0)
	{
		// XXX: throw warning
		return;
	}
	// mark fqdn as used
	std::get<2>(m_dns_cache[fqdn]) = true;

	auto& prefixes = std::get<1>(m_macros[m_curr_name]);
	for (const auto& addr : resolve_fqdn(fqdn))
	{
		prefixes.emplace(addr);
	}
}

void fw_config_t::set_fqdn(const std::string& s)
{
	const auto& l = m_location.top();

	FW_CONF_DEBUG(s);
	if (m_dns_cache.count(s) > 0)
	{
		auto& [location, addresses, used] = m_dns_cache[s];

		location = {(unsigned int)l.begin.line, m_fileno.top()};
		addresses.clear();
		(void)used;
	}
	else
	{
		m_dns_cache.emplace(s, dns_addresses_t{location_history_t{(unsigned int)l.begin.line, m_fileno.top()}, {/* empty */}, false});
	}
	m_curr_name = s;
	m_curr_entity = entity_type::DNSCACHE;
}

void fw_config_t::fill_fqdn(const common::ip_address_t& a)
{
	const auto& l = m_location.top();

	if (m_curr_entity != entity_type::DNSCACHE ||
	    m_dns_cache.count(m_curr_name) == 0)
	{
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown FQDN");
	}

	auto& addresses = std::get<1>(m_dns_cache[m_curr_name]);

	addresses.emplace(a);
}

void fw_config_t::set_table(const std::string& s)
{
	FW_CONF_DEBUG(s);
	m_curr_name = s;
	m_curr_entity = entity_type::TABLE;
}

void fw_config_t::check_table(void)
{
	const auto& l = m_location.top();

	if (m_curr_entity != entity_type::TABLE)
	{
		throw fw_parser_t::syntax_error(l, "attempt to create unknown TABLE");
	}
	if (m_tables.count(m_curr_name) > 0)
	{
		const auto& location = std::get<location_history_t>(m_tables.at(m_curr_name));
		throw fw_parser_t::syntax_error(l,
		                                "attempt to create table(" + m_curr_name +
		                                        "), that was already created at " +
		                                        format_location(location));
	}
}

void fw_config_t::create_iface_table(void)
{
	const auto& l = m_location.top();

	check_table();
	m_tables.emplace(m_curr_name, table_t{location_history_t{(unsigned int)l.begin.line, m_fileno.top()}, tables::ifname_t{}});
}

void fw_config_t::create_skipto_table(void)
{
	const auto& l = m_location.top();

	check_table();
	m_tables.emplace(m_curr_name, table_t{location_history_t{(unsigned int)l.begin.line, m_fileno.top()}, tables::prefix_skipto_t{}});
}

void fw_config_t::check_table_entry(const tables::entry_type_t& e)
{
	static const std::vector<std::string> types{"prefix-skipto", "ifname-skipto"};
	const auto& l = m_location.top();

	if (m_curr_entity != entity_type::TABLE ||
	    m_tables.count(m_curr_name) == 0)
	{
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown TABLE");
	}

	auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);
	if (table.index() != e.index())
	{
		throw fw_parser_t::syntax_error(l, "attempt to add value of type '" + types[e.index()] + "' to table(" + m_curr_name + "), " + "expected type is '" + types[table.index()] + "'");
	}
}

void fw_config_t::fill_skipto_table(const tables::prefix_skipto_entry_t& e)
{
	/* XXX: implicit auto creation addresses table */
	if (m_tables.count(m_curr_name) == 0)
	{
		create_skipto_table();
	}

	check_table_entry(e);

	auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);
	auto& prefixes = std::get<tables::prefix_skipto_t>(table);

	prefixes.emplace(e);
}

void fw_config_t::fill_iface_table(const tables::ifname_entry_t& e)
{
	check_table_entry(e);

	auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);
	auto& ifnames = std::get<tables::ifname_t>(table);

	ifnames.emplace(e);
}

void fw_config_t::fill_table_entry(const tables::curr_entry_t& e)
{
	const auto& l = m_location.top();

	if (m_curr_entity != entity_type::TABLE)
	{
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown TABLE");
	}
	m_curr_table_entry = e;
}

void fw_config_t::fill_table_entry_value(const tables::entry_value_t& v)
{
	const auto& l = m_location.top();

	if (m_curr_entity != entity_type::TABLE)
	{
		throw fw_parser_t::syntax_error(l, "attempt to fill unknown TABLE");
	}

	const auto eidx = m_curr_table_entry.index();
	const auto vidx = v.index();

	std::string value{/* empty */};
	// if table value is string, use it, otherwise use empty string
	if (vidx == 1)
		value = std::get<std::string>(v);

	if (eidx == 0)
	{ // prefix-skipto table: assume table value is LABEL
		fill_skipto_table(tables::prefix_skipto_entry_t{
		        std::get<common::ip_prefix_t>(m_curr_table_entry),
		        value});
	}
	else
	{ // ifname-skipto table
		auto& entry = std::get<std::string>(m_curr_table_entry);

		// check that table is already created
		if (m_tables.count(m_curr_name) != 0)
		{
			auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);

			// did table was created as ifname-skipto?
			if (table.index() == 1)
			{
				fill_iface_table(tables::ifname_entry_t{
				        entry, value});
				return;
			}
			// otherwise FALLTHROUGH
		}

		// table entry is string, or table was not created, or
		// table has prefix-skipto type.
		// Thus assume entry is FQDN, resolve it into address.
		if (m_dns_cache.count(entry) == 0)
		{
			// even if FQDN is unresolved we need to create table,
			// otherwise we can get exception later when rule
			// that uses table will try to fill addresses from table.
			if (m_tables.count(m_curr_name) == 0)
			{
				create_skipto_table();
			}
			// XXX: throw warning about unresolved hostname
			return;
		}
		// mark fqdn as used
		std::get<2>(m_dns_cache[entry]) = true;
		for (const auto& addr : resolve_fqdn(entry))
		{
			fill_skipto_table(tables::prefix_skipto_entry_t{
			        common::ip_prefix_t{addr},
			        value});
		}
	}
}

void fw_config_t::fill_rule_number(unsigned int num)
{
	// do not allow add label between rules with the same number:
	//  add 100 count ip from any to any
	//  :LABEL
	//  add 100 count tcp from any to any
	if (m_prev_rule != nullptr && m_prev_rule->ruleno == num &&
	    !m_last_label.empty())
	{
		const auto& [ruleno, location] = m_labels.at(m_last_label);
		if (num < ruleno)
		{
			throw fw_parser_t::syntax_error(m_location.top(),
			                                "attempt to add rule with the same number " +
			                                        std::to_string(num) +
			                                        ", but label " + m_last_label +
			                                        " was added at " + format_location(location) +
			                                        " and it points to rule " + std::to_string(ruleno));
		}
	}
	if (num != 0)
	{
		// lexer starts gathering rule text just after ADDRULE token
		// it is possible, that user has specified rule number, so
		// it will be gathered into rule text. We need to remove it
		// and also all white spaces that can be before rule action token.
		// We remove rule number here, and spaces will be removed in
		// set_rule_action().
		m_lexer.m_line.clear();
	}
	m_curr_rule->ruleno = num;
	m_curr_rule->state = rule_t::rule_state_t::RULENUMBER;
}

void fw_config_t::fill_rule_proto(uint8_t proto)
{
	FW_CONF_DEBUG((int)proto);
	m_curr_rule->proto.emplace(proto);
	if (m_curr_rule->state < rule_t::rule_state_t::PROTO)
		m_curr_rule->state = rule_t::rule_state_t::PROTO;
}

void fw_config_t::fill_rule_proto(const std::string& proto)
{
	auto val = getprotobyname(proto);

	if (val == -1)
	{
		throw fw_parser_t::syntax_error(m_location.top(), "unknown protocol: " + proto);
	}
	fill_rule_proto(val);
}

std::string trim_spaces(const std::string& str)
{
	const auto whitespaces = " \t";
	std::string result;

	// trim leading and trailing whitespaces
	{
		const auto start = str.find_first_not_of(whitespaces);
		if (start == std::string::npos)
		{
			return "";
		}
		const auto end = str.find_last_not_of(whitespaces);
		result = str.substr(start, end - start + 1);
	}
	// replace extra spaces
	{
		auto start = result.find_first_of(whitespaces);
		while (start != std::string::npos)
		{
			const auto end = result.find_first_not_of(whitespaces, start);
			result.replace(start, end - start, " ");
			start = result.find_first_of(whitespaces, start + 1);
		}
	}
	return result;
}

void fw_config_t::fill_rule_text(void)
{
	if (m_curr_rule->implicit_check_state)
	{
		add_implicit_check_state_rule();
	}

	m_curr_rule->text = trim_spaces(m_lexer.m_line);
	m_curr_rule->location.lineno = m_location.top().begin.line;
	m_curr_rule->location.fileno = m_fileno.top();
	// ruleid is incremened with each added rule
	m_curr_rule->ruleid = ++m_ruleid_last;

	FW_CONF_DEBUG(m_curr_rule->text);
	fill_rule_number_if_needed();
	m_rules[m_curr_rule->ruleno].emplace_back(m_curr_rule);
	m_prev_rule = m_curr_rule;
	m_curr_rule = std::make_shared<rule_t>();
}

void fw_config_t::fill_rule_ipver(rule_t::ip_version_t ver)
{
	m_curr_rule->ipver = ver;
	m_curr_rule->state = rule_t::rule_state_t::PROTO;
}

void fw_config_t::add_rule_addr(const ip_prefix_mask_t& addr)
{
	FW_CONF_DEBUG(" ");

	if (m_curr_src)
		m_curr_rule->src.emplace(addr);
	else
		m_curr_rule->dst.emplace(addr);
}

void fw_config_t::add_rule_fqdn(const std::string& fqdn)
{
	FW_CONF_DEBUG(fqdn);

	if (m_curr_src)
		m_curr_rule->src_fqdn = true;
	else
		m_curr_rule->dst_fqdn = true;

	if (m_dns_cache.count(fqdn) == 0)
	{
		// throw warning
		return;
	}

	// mark fqdn as used
	std::get<2>(m_dns_cache[fqdn]) = true;

	for (const auto& addr : resolve_fqdn(fqdn))
	{
		add_rule_addr(addr);
	}
}

void fw_config_t::add_rule_macro(const std::string& macro)
{
	FW_CONF_DEBUG(macro);

	if (m_curr_src)
		m_curr_rule->src_macros = true;
	else
		m_curr_rule->dst_macros = true;

	if (m_macros.count(macro) == 0)
	{
		// XXX: this is workaround for rules that use table name as macro
		// XXX: so, we just try find table with specified name
		add_rule_table(macro);
		// XXX: throw warning
		return;
	}

	// mark macro as used
	std::get<2>(m_macros[macro]) = true;

	for (const auto& prefix : resolve_macro(macro))
	{
		add_rule_addr(prefix);
	}
}

void fw_config_t::add_rule_table(const std::string& name)
{
	FW_CONF_DEBUG(name);
	if (m_tables.count(name) == 0)
	{
		return;
	}
	// table must have proper type
	auto& table = std::get<tables::table_type_t>(m_tables[name]);
	if (std::holds_alternative<tables::ifname_t>(table))
	{
		throw fw_parser_t::syntax_error(m_location.top(),
		                                "attempt to use wrong table type for address statement");
	}
	if (m_curr_src)
		m_curr_rule->src_tables = true;
	else
		m_curr_rule->dst_tables = true;

	for (const auto& [prefix, label] : std::get<tables::prefix_skipto_t>(table))
	{
		(void)label;
		add_rule_addr(prefix);
	}
}

void fw_config_t::add_rule_addr_any(void)
{
	FW_CONF_DEBUG(" ");
	if (m_curr_src)
		m_curr_rule->src_any = true;
	else
		m_curr_rule->dst_any = true;
}

void fw_config_t::add_rule_addr_me(void)
{
	FW_CONF_DEBUG(" ");
	if (m_curr_src)
		m_curr_rule->src_me = true;
	else
		m_curr_rule->dst_me = true;
}

void fw_config_t::add_rule_addr_me6(void)
{
	FW_CONF_DEBUG(" ");
	if (m_curr_src)
		m_curr_rule->src_me6 = true;
	else
		m_curr_rule->dst_me6 = true;
}

void fw_config_t::set_rule_action(rule_action_t a)
{
	FW_CONF_DEBUG(" ");
	m_curr_rule->action = a;
}

void fw_config_t::set_rule_action_arg(const rule_t::action_arg_t& a)
{
	FW_CONF_DEBUG("index() = " << a.index());
	m_curr_rule->action_arg = a;

	// sanity checks:
	// backward skipto isn't allowed
	if (m_curr_rule->action == rule_action_t::SKIPTO)
	{
		// skipto :LABEL
		if (std::holds_alternative<std::string>(a))
		{
			const auto& label = std::get<std::string>(a);

			// ruleno wasn't specified, it will be assigned automatically
			if (m_curr_rule->ruleno == 0)
			{
				if (m_labels.count(label) != 0)
				{
					// label was already defined.
					// This means we are trying to jump backwards.
					const auto& location = std::get<1>(m_labels.at(label));
					throw fw_parser_t::syntax_error(m_location.top(),
					                                "attempt to jump backwards using skipto " + label +
					                                        ", label was defined at " + format_location(location));
				}
			}
			else
			{
				// ruleno was specified.
				// This means that rule can be placed before, or after
				// specific label. Thus we need to check that we don't
				// jump backwards.
				if (m_labels.count(label) != 0)
				{
					const auto& [ruleno, location] = m_labels.at(label);
					if (m_curr_rule->ruleno >= ruleno)
					{
						throw fw_parser_t::syntax_error(m_location.top(),
						                                "attempt to jump backwards using skipto " + label +
						                                        ", label was defined at " + format_location(location) +
						                                        " and points to ruleno " + std::to_string(ruleno));
					}
				}
			}
			// keep track for used label, thus later we can easily check that we have
			// labels that weren't defined.
			auto& skipto_rules = m_skipto_labels[label];
			skipto_rules.emplace_back(m_curr_rule);
		}
		else if (std::holds_alternative<int64_t>(a))
		{
			// skipto RULENO
			const auto& ruleno = std::get<int64_t>(a);
			if (ruleno != 0)
			{
				if ((m_curr_rule->ruleno == 0 && ruleno < m_ruleno_last + m_ruleno_step) ||
				    (m_curr_rule->ruleno != 0 && ruleno <= m_curr_rule->ruleno))
				{
					throw fw_parser_t::syntax_error(m_location.top(),
					                                "attempt to jump backwards using skipto " +
					                                        std::to_string(ruleno));
				}
			}
			// TABLEARG
		}
	}
}

void fw_config_t::set_dump_action_arg(const rule_t::action_arg_t& a)
{
	FW_CONF_DEBUG("index() = " << a.index());
	if (std::holds_alternative<int64_t>(a))
	{
		m_curr_rule->action_arg = std::to_string(std::get<int64_t>(a));
	}
	else
	{
		m_curr_rule->action_arg = a;
	}
}

void fw_config_t::add_rule_ports(const rule_t::ports_arg_t& ports)
{
	FW_CONF_DEBUG("index() = " << ports.index());

	switch (ports.index())
	{
		case 0:
			if (m_curr_src)
				m_curr_rule->sports_range.insert(std::get<common::range_t>(ports));
			else
				m_curr_rule->dports_range.insert(std::get<common::range_t>(ports));
			break;
		case 1:
		{
			auto t = std::get<std::string>(ports);

			// remove escape symbol '\\' if any
			for (auto pos = t.find('\\');
			     pos != std::string::npos;
			     pos = t.find('\\'))
			{
				t.erase(pos, 1);
			}

			auto val = getservbyname(t);
			if (val == -1)
			{
				throw fw_parser_t::syntax_error(m_location.top(),
				                                "unknown port: " + t);
			}

			if (m_curr_src)
				m_curr_rule->sports.emplace(val);
			else
				m_curr_rule->dports.emplace(val);
		}
		break;
		case 2:
			if (m_curr_src)
				m_curr_rule->sports.emplace(std::get<uint16_t>(ports));
			else
				m_curr_rule->dports.emplace(std::get<uint16_t>(ports));
			break;
	}
}

void fw_config_t::add_rule_opcode(const rule_t::opcode_arg_t& value)
{
	FW_CONF_DEBUG("index() = " << value.index());

	switch (m_curr_opcode)
	{
		case rule_t::opcode_t::DIRECTION:
			m_curr_rule->direction |= std::get<uint32_t>(value);
			break;
		case rule_t::opcode_t::RECORDSTATE:
			m_curr_rule->recordstate = true;
			break;
		case rule_t::opcode_t::KEEPSTATE:
			m_curr_rule->implicit_check_state = true;
			m_curr_rule->recordstate = true;
			break;
		case rule_t::opcode_t::IPID:
			break;
		case rule_t::opcode_t::IPLEN:
			break;
		case rule_t::opcode_t::IPTTL:
			break;
		case rule_t::opcode_t::TCPACK:
			m_curr_rule->tcp_ack = std::get<uint32_t>(value);
			break;
		case rule_t::opcode_t::TCPDATALEN:
			break;
		case rule_t::opcode_t::TCPMSS:
			break;
		case rule_t::opcode_t::TCPSEQ:
			m_curr_rule->tcp_seq = std::get<uint32_t>(value);
			break;
		case rule_t::opcode_t::TCPWIN:
			break;
		case rule_t::opcode_t::TCPESTABLISHED:
			m_curr_rule->tcp_established = true;
			break;
		case rule_t::opcode_t::ICMPTYPE:
		{
			auto icmptype = std::get<uint32_t>(value);
			if (icmptype > 31)
			{
				const auto& l = m_location.top();
				throw fw_parser_t::syntax_error(l,
				                                "ICMP type should be < 31, was specified " +
				                                        std::to_string(icmptype));
			}
			m_curr_rule->icmp_types.emplace(icmptype);
			// add ICMP to the protocols list in case if protocol was not specified
			m_curr_rule->proto.emplace(IPPROTO_ICMP);
		}
		break;
		case rule_t::opcode_t::ICMP6TYPE:
		{
			auto icmptype = std::get<uint32_t>(value);
			if (icmptype > 201)
			{
				const auto& l = m_location.top();
				throw fw_parser_t::syntax_error(l,
				                                "ICMP6 type should be < 201, was specified " +
				                                        std::to_string(icmptype));
			}
			m_curr_rule->icmp6_types.emplace(icmptype);
			// add ICMPv6 to the protocols list in case if protocol was not specified
			m_curr_rule->proto.emplace(IPPROTO_ICMPV6);
		}
		break;
	}
}

void fw_config_t::fill_rule_number_if_needed()
{
	// user may specify rule number, if it is greather than
	// last added, use it for automatic numeration
	if (m_curr_rule->ruleno > m_ruleno_last)
	{
		m_ruleno_last = m_curr_rule->ruleno;
	}
	// if rulenumber is not specified, use automatic numeration
	if (m_curr_rule->ruleno == 0)
	{
		m_curr_rule->ruleno = m_ruleno_last + m_ruleno_step;
		m_ruleno_last = m_curr_rule->ruleno;
	}
}

void fw_config_t::add_implicit_check_state_rule()
{
	// Save the current rule
	auto current_rule = m_curr_rule;

	// Create a new check-state rule
	m_curr_rule = std::make_shared<rule_t>();
	set_rule_action(rule_action_t::CHECKSTATE);
	m_curr_rule->ruleno = current_rule->ruleno;
	m_curr_rule->location = current_rule->location;
	m_curr_rule->location.implicitly_generated_rule = true;
	m_curr_rule->ruleid = ++m_ruleid_last;
	m_curr_rule->text = "check-state";

	fill_rule_number_if_needed();

	// Add the check-state rule like fill_rule_text method does
	m_rules[m_curr_rule->ruleno].emplace_back(m_curr_rule);

	// Restore the original rule
	m_curr_rule = current_rule;

	// Reset rule number for automatic generation
	m_curr_rule->ruleno = 0;
}

void fw_config_t::set_rule_flag(uint32_t flag)
{
	FW_CONF_DEBUG("flag " << flag);

	switch (m_curr_options)
	{
		case rule_t::flags_options_t::IPOPTIONS:
			break;
		case rule_t::flags_options_t::IPOFFSETFLAGS:
			m_curr_rule->ipoff_setflags |= flag;
			break;
		case rule_t::flags_options_t::IPTOS:
			break;
		case rule_t::flags_options_t::TCPOPTIONS:
			m_curr_rule->tcp_setopts |= flag;
			break;
		case rule_t::flags_options_t::TCPFLAGS:
			m_curr_rule->tcp_setflags |= flag;
			break;
	}
}

void fw_config_t::clear_rule_flag(uint32_t flag)
{
	FW_CONF_DEBUG("flag " << flag);

	switch (m_curr_options)
	{
		case rule_t::flags_options_t::IPOPTIONS:
			break;
		case rule_t::flags_options_t::IPOFFSETFLAGS:
			m_curr_rule->ipoff_clearflags |= flag;
			break;
		case rule_t::flags_options_t::IPTOS:
			break;
		case rule_t::flags_options_t::TCPOPTIONS:
			m_curr_rule->tcp_clearopts |= flag;
			break;
		case rule_t::flags_options_t::TCPFLAGS:
			m_curr_rule->tcp_clearflags |= flag;
			break;
	}
}

void fw_config_t::add_rule_iface(const std::string& iface)
{
	static const std::map<iface_direction_t, std::string> via_token{
	        {iface_direction_t::RECV, "recv"},
	        {iface_direction_t::XMIT, "xmit"},
	        {iface_direction_t::VIA, "via"},
	};
	FW_CONF_DEBUG(via_token.at(m_curr_dir) << " " << iface);
	m_curr_rule->ifaces[iface] = m_curr_dir;
}

void fw_config_t::add_via_table(void)
{
	FW_CONF_DEBUG("add via table " << m_curr_name);

	if (m_tables.count(m_curr_name) == 0)
	{
		throw fw_parser_t::syntax_error(m_location.top(),
		                                "attempt to use unknown TABLE " + m_curr_name);
	}

	// handle "skipto tablearg"
	if (m_curr_rule->action == rule_action_t::SKIPTO &&
	    std::holds_alternative<int64_t>(m_curr_rule->action_arg) &&
	    std::get<int64_t>(m_curr_rule->action_arg) == 0)
	{
		// table must have proper type
		auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);
		if (!std::holds_alternative<tables::ifname_t>(table))
		{
			throw fw_parser_t::syntax_error(m_location.top(),
			                                "attempt to use wrong table type for skipto tablearg via table");
		}
		m_curr_rule->targ_name = m_curr_name;
		return;
	}
	m_curr_rule->iface_tables[m_curr_dir].emplace(m_curr_name);
}

void fw_config_t::add_table_addresses(void)
{
	FW_CONF_DEBUG("table(" << m_curr_name << ")");

	if (m_tables.count(m_curr_name) == 0)
	{
		throw fw_parser_t::syntax_error(m_location.top(),
		                                "attempt to use unknown TABLE " + m_curr_name);
	}

	// handle "skipto tablearg"
	if (m_curr_rule->action == rule_action_t::SKIPTO &&
	    std::holds_alternative<int64_t>(m_curr_rule->action_arg) &&
	    std::get<int64_t>(m_curr_rule->action_arg) == 0)
	{
		// table must have proper type
		auto& table = std::get<tables::table_type_t>(m_tables[m_curr_name]);
		if (!std::holds_alternative<tables::prefix_skipto_t>(table))
		{
			throw fw_parser_t::syntax_error(m_location.top(),
			                                "attempt to use wrong table type for skipto tablearg");
		}
		if (m_curr_rule->src_targ || m_curr_rule->dst_targ)
		{
			throw fw_parser_t::syntax_error(m_location.top(),
			                                "skipto tablearg table was already specified: " +
			                                        m_curr_rule->targ_name);
		}
		m_curr_rule->targ_name = m_curr_name;
		m_curr_rule->src_targ = m_curr_src;
		m_curr_rule->dst_targ = !m_curr_src;
	}
	else
	{
		add_rule_table(m_curr_name);
	}
}

std::string fw_config_t::format_location(const location_history_t& loc)
{
	std::string filename;

	if (m_history.size() > loc.fileno)
	{
		const auto& h = m_history.at(loc.fileno);
		filename = *h.name;
	}
	else
	{
		filename = "UNKNOWN";
	}

	std::string location_str = filename + ":" + std::to_string(loc.lineno);

	if (loc.implicitly_generated_rule)
	{
		return "This rule is implicit, generated by the rule at " + location_str;
	}

	return location_str;
}

bool fw_config_t::resolve_labels()
{
	auto result = true;
	if (m_rules.empty())
	{
		return result;
	}
	// check for labels that weren't defined
	for (auto& [label, skipto_rules] : m_skipto_labels)
	{
		if (m_labels.count(label) != 0)
		{
			continue;
		}
		result = false;
		for (const auto& rulep : skipto_rules)
		{
			rulep->set_vstatus(rule_t::validation_status_t::UNKNOWN_LABEL);
			std::cerr << format_location(rulep->location) << " unknown label " << label << std::endl;
		}
	}
	// resolve actual rule number that is behind the label
	for (auto& [label, info] : m_labels)
	{
		auto& ruleno = std::get<unsigned int>(info);
		auto& rules = m_rules[ruleno];

		if (rules.empty())
		{
			// we don't have rules with exact number, find next one
			const auto saved_no = ruleno;
			auto it = m_rules.find(saved_no);

			FW_CONF_DEBUG("label " << label << " points to empty rule " << saved_no);
			for (; it != m_rules.end(); ++it)
			{
				if (!it->second.empty())
				{
					ruleno = it->first;
					FW_CONF_DEBUG("update label " << label << " from " << saved_no << " to " << ruleno);
					break;
				}
			}
			if (it == m_rules.end())
			{
				// XXX: use the last rule as default rule,
				//      when ruleno points behind the end.
				ruleno = m_rules.rbegin()->first;
			}
			// erase empty ruleno
			m_rules.erase(saved_no);
		}
	}
	// XXX: update rule numbers used in skipto rules
	// XXX: update rule numbers used in skipto tables
	return result;
}

bool fw_config_t::validate_rule(rule_ptr_t rulep)
{
	if (rulep->vstatus != rule_t::validation_status_t::UNKNOWN)
	{
		// rule is already marked as failed.
		return false;
	}
	// if rule uses unsupported action, we don't need validation
	switch (rulep->action)
	{
		case rule_action_t::ALLOW:
		case rule_action_t::DENY:
		case rule_action_t::SKIPTO:
		case rule_action_t::DUMP:
		case rule_action_t::CHECKSTATE:
		case rule_action_t::STATETIMEOUT:
			break;
		default:
			return true;
	}
	FW_CONF_DEBUG("validating rule " << rulep->ruleno);
	// check for emty macro/fqdn/tables
	if (rulep->src.empty() && !rulep->src_any) // me, me6 are not yet supported
	{
		if (rulep->src_macros)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_SRC_MACRO);
		}
		else if (rulep->src_fqdn)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_SRC_FQDN);
		}
		else if (rulep->src_tables)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_SRC_TABLE);
		}
	}
	if (rulep->dst.empty() && !rulep->dst_any) // me, me6 are not yet supported
	{
		if (rulep->dst_macros)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_DST_MACRO);
		}
		else if (rulep->dst_fqdn)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_DST_FQDN);
		}
		else if (rulep->dst_tables)
		{
			rulep->set_vstatus(rule_t::validation_status_t::EMPTY_DST_TABLE);
		}
	}
	if (rulep->vstatus != rule_t::validation_status_t::UNKNOWN)
	{
		std::cerr << format_location(rulep->location) << " " << rulep->vstatus_to_string() << std::endl;
		return false;
	}
	return true;
}

bool fw_config_t::validate()
{
	auto result = true;
	if (!resolve_labels())
	{
		result = false;
	}
	for (auto& [ruleno, rules] : m_rules)
	{
		(void)ruleno;
		for (auto rulep : rules)
		{
			if (!validate_rule(rulep))
			{
				result = false;
			}
		}
	}
	return result;
}
