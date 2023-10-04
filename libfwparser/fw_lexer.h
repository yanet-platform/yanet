#pragma once

#include <algorithm>

#include "libfwparser/fw_parser.h"

/* rename yyFlexLexer generated class to fwFlexLexer */
#if !defined(yyFlexLexerOnce)
#define yyFlexLexer fwFlexLexer
#include <FlexLexer.h>
#endif

namespace ipfw
{

class fw_config_t;

class fw_lexer_t : public fwFlexLexer
{
	friend class fw_config_t;

public:
	fw_lexer_t() = default;
	~fw_lexer_t() = default;

	fw_lexer_t(const fw_lexer_t&) = delete;
	const fw_lexer_t& operator=(const fw_lexer_t&) = delete;

	fw_parser_t::symbol_type Lex(fw_config_t& cfg);

	void set_debug(bool flag)
	{
		fwFlexLexer::set_debug(flag);
	}

private:
	std::string m_line;
	bool m_save = false;

	fw_parser_t::symbol_type make_DSCPSPEC(const std::string&, fw_parser_t::location_type&);
	fw_parser_t::symbol_type make_NETWORK(const std::string&, fw_parser_t::location_type&);
	fw_parser_t::symbol_type make_IPMASK(const std::string&, fw_parser_t::location_type&);
	fw_parser_t::symbol_type make_NETWORK6(const std::string&, fw_parser_t::location_type&);
	fw_parser_t::symbol_type make_IP6MASK(const std::string&, fw_parser_t::location_type&);
	fw_parser_t::symbol_type make_IP6PRJID(const std::string&, fw_parser_t::location_type&);
};

}
