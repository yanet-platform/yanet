#include "libfwparser/fw_parser.h"

#include "fw_config.h"
#include "fw_lexer.h"

using namespace ipfw;

#define FW_LEXER_DEBUG(msg)                                                             \
	do                                                                              \
	{                                                                               \
		if (yy_flex_debug > 0)                                                  \
			std::cerr << "LEXER: " << __func__ << ": " << msg << std::endl; \
	} while (0)

fw_parser_t::symbol_type
fw_lexer_t::make_DSCPSPEC(const std::string& spec, fw_parser_t::location_type& l)
{
	static const std::map<std::string, uint8_t> dscp{
	        {"af11", 0x28 >> 2}, /* 001010 */
	        {"af12", 0x30 >> 2}, /* 001100 */
	        {"af13", 0x38 >> 2}, /* 001110 */
	        {"af21", 0x48 >> 2}, /* 010010 */
	        {"af22", 0x50 >> 2}, /* 010100 */
	        {"af23", 0x58 >> 2}, /* 010110 */
	        {"af31", 0x68 >> 2}, /* 011010 */
	        {"af32", 0x70 >> 2}, /* 011100 */
	        {"af33", 0x78 >> 2}, /* 011110 */
	        {"af41", 0x88 >> 2}, /* 100010 */
	        {"af42", 0x90 >> 2}, /* 100100 */
	        {"af43", 0x98 >> 2}, /* 100110 */
	        {"be", 0x00 >> 2}, /* 000000 */
	        {"ef", 0xb8 >> 2}, /* 101110 */
	        {"cs0", 0x00 >> 2}, /* 000000 */
	        {"cs1", 0x20 >> 2}, /* 001000 */
	        {"cs2", 0x40 >> 2}, /* 010000 */
	        {"cs3", 0x60 >> 2}, /* 011000 */
	        {"cs4", 0x80 >> 2}, /* 100000 */
	        {"cs5", 0xa0 >> 2}, /* 101000 */
	        {"cs6", 0xc0 >> 2}, /* 110000 */
	        {"cs7", 0xe0 >> 2}, /* 100000 */
	        {"va", 0xb0 >> 2}, /* 101100 */
	};

	if (dscp.count(spec) == 0)
		throw fw_parser_t::syntax_error(l, "invalid DSCP spec: " + spec);

	return fw_parser_t::make_DSCPSPEC(dscp.at(spec), l);
}

fw_parser_t::symbol_type
fw_lexer_t::make_IPMASK(const std::string& s, fw_parser_t::location_type& l)
{
	auto pos = s.find_first_of(":/");

	if (pos == std::string::npos)
		throw fw_parser_t::syntax_error(l, "invalid IPMASK: " + s);

	return fw_parser_t::make_IPMASK({common::ipv4_address_t(s.substr(0, pos)),
	                                 common::ipv4_address_t(s.substr(pos + 1))},
	                                l);
}

fw_parser_t::symbol_type
fw_lexer_t::make_NETWORK(const std::string& s, fw_parser_t::location_type& l)
{
	auto pos = s.find_first_of("/");

	if (pos == std::string::npos)
		throw fw_parser_t::syntax_error(l, "invalid NETWORK: " + s);

	auto prefixlen = std::stol(s.substr(pos + 1));
	if (prefixlen > 32)
		throw fw_parser_t::syntax_error(l, "invalid prefixlen for NETWORK: " + s);

	return fw_parser_t::make_NETWORK(common::ipv4_prefix_t(s.substr(0, pos), prefixlen), l);
}

fw_parser_t::symbol_type
fw_lexer_t::make_IP6MASK(const std::string& s, fw_parser_t::location_type& l)
{
	auto pos = s.find("/");

	if (pos == std::string::npos)
		throw fw_parser_t::syntax_error(l, "invalid IP6MASK: " + s);

	return fw_parser_t::make_IP6MASK({common::ipv6_address_t(s.substr(0, pos)),
	                                  common::ipv6_address_t(s.substr(pos + 1))},
	                                 l);
}

fw_parser_t::symbol_type
fw_lexer_t::make_NETWORK6(const std::string& s, fw_parser_t::location_type& l)
{
	auto pos = s.find("/");

	if (pos == std::string::npos)
		throw fw_parser_t::syntax_error(l, "invalid NETWORK6: " + s);

	auto prefixlen = std::stol(s.substr(pos + 1));
	if (prefixlen > 128)
		throw fw_parser_t::syntax_error(l, "invalid prefixlen for NETWORK6: " + s);

	return fw_parser_t::make_NETWORK6(common::ipv6_prefix_t(s.substr(0, pos), prefixlen), l);
}

fw_parser_t::symbol_type
fw_lexer_t::make_IP6PRJID(const std::string& s, fw_parser_t::location_type& l)
{
	std::array<uint8_t, 16> mask{};
	common::ipv6_address_t addr;
	std::string tmp = s;
	uint32_t prjid = 0;
	int prefixlen, prjid_prefixlen = 32;

	// handle addresses with holes in masks 1407@2a02:6b8:c00::/40
	auto pos = tmp.find("@");
	if (pos != std::string::npos)
	{
		auto prjrange = tmp.substr(0, pos);
		tmp.erase(0, pos + 1);

		// check for prjid range: f800/21@2a02:6b8:c00::/40
		pos = prjrange.find("/");
		if (pos != std::string::npos)
		{
			prjid = std::stoul(prjrange.substr(0, pos), nullptr, 16);
			prjid_prefixlen = std::stoul(prjrange.substr(pos + 1), nullptr, 10);
			if (prjid_prefixlen > 32 || prjid_prefixlen == 0)
			{
				throw fw_parser_t::syntax_error(l, "invalid prjid range: " + prjrange);
			}
		}
		else
		{
			prjid = std::stoul(prjrange, nullptr, 16);
		}
	}
	pos = tmp.find("/");
	if (pos == std::string::npos)
		throw fw_parser_t::syntax_error(l, "invalid IP6MASK: " + s);

	prefixlen = std::stoul(tmp.substr(pos + 1));
	if (prefixlen > 128)
		throw fw_parser_t::syntax_error(l, "invalid prefixlen: " + std::to_string(prefixlen));

	// number of bits that are set in mask, i.e. N bits -> uint8_t value mapping
	static const uint8_t bits[8] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
	// convert prefixlen into mask
	for (auto& v : mask)
	{
		if (prefixlen <= 0)
			break;
		v = (prefixlen >= 8) ? 0xff : bits[prefixlen];
		prefixlen -= 8;
	}

	addr = tmp.substr(0, pos);
	// add prjid into address and set corresponding bits in mask
	if (prjid != 0)
	{
		uint8_t* paddr = addr.data();
		for (int i = 0; i < 4; i++)
		{
			paddr[8 + i] = (prjid >> (24 - i * 8)) & 0xff;
			if (prjid_prefixlen > 0)
			{
				mask[8 + i] = (prjid_prefixlen >= 8) ? 0xff : bits[prjid_prefixlen];
				prjid_prefixlen -= 8;
			}
		}
	}
	return fw_parser_t::make_IP6MASK({common::ipv6_address_t(addr),
	                                  common::ipv6_address_t(mask)},
	                                 l);
}
