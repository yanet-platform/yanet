#pragma once

#include "fw_parser.h"
#include <memory>

namespace ipfw
{

// forward declaration
class fw_config_t;
class fw_dump_t
{
	std::shared_ptr<fw_config_t> m_conf;

public:
	fw_dump_t(std::shared_ptr<fw_config_t> conf)
	{
		m_conf = conf;
	}

	~fw_dump_t() = default;

	void dump_history();
	void dump_dnscache();
	void dump_macros();
	void dump_tables();
	void dump_labels();
	void dump_rules();
	void dump_rule(rule_ptr_t rulep);
	void dump();
};

} // namespace ipfw
