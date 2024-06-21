#pragma once

#include <arpa/inet.h>
#include <netdb.h>

#include <list>
#include <string>
#include <vector>

#include "common/actions.h"
#include "libfwparser/fw_parser.h"

#include "network.h"

#include "../acl.h"
#include "../type.h"

namespace acl
{

template<typename uint_t>
struct range_t : std::tuple<uint_t, uint_t>
{
	inline range_t(unsigned int from, unsigned int to) :
	        std::tuple<uint_t, uint_t>(from, to) {}

	inline range_t(unsigned int val) :
	        std::tuple<uint_t, uint_t>(val, val) {}

	uint_t from() const
	{
		return std::get<0>(*this);
	}

	uint_t to() const
	{
		return std::get<1>(*this);
	}
};

struct filter_base_t
{
	unsigned long ref_count;

	inline constexpr filter_base_t() :
	        ref_count(0) {}
	virtual bool is_none() const = 0;
	virtual ~filter_base_t() {}
	virtual std::string to_string() const = 0;
};

template<typename filter_t>
struct ref_t
{
	filter_t* filter;

	inline ref_t() :
	        ref_t(nullptr) {}

	inline void ref_inc()
	{
		if (filter)
		{
			++filter->ref_count;
		}
	}

	inline void ref_dec()
	{
		if (filter)
		{
			if (!--filter->ref_count)
				delete filter;
		}
	}

	inline ref_t(filter_t* _filter) :
	        filter(_filter)
	{
		ref_inc();
	}

	inline ref_t(const ref_t& _ref)
	{
		filter = _ref.filter;
		ref_inc();
	}

	/*
	inline ref_t(ref_t&& _ref)
	{
	        filter = _ref.filter;
	        _ref.filter = nullptr;
	}
*/

	inline ref_t& operator=(const ref_t& _ref)
	{
		if (_ref.filter != filter)
		{
			ref_dec();
			filter = _ref.filter;
			ref_inc();
		}
		return *this;
	}

	inline ref_t& operator=(filter_t* _filter)
	{
		if (_filter != filter)
		{
			ref_dec();
			filter = _filter;
			ref_inc();
		}
		return *this;
	}

	inline ~ref_t()
	{
		ref_dec();
	}

	operator filter_t*()
	{
		return filter;
	}

	operator const filter_t*() const
	{
		return filter;
	}

	filter_t* operator*() const
	{
		return filter;
	}

	filter_t* operator->() const
	{
		return filter;
	}

	inline operator bool() const
	{
		return filter != nullptr;
	}

	inline bool is_none() const
	{
		return filter ? filter->is_none() : false;
	}

	inline bool operator==(const ref_t& _ref) const
	{
		if (filter != nullptr && _ref)
		{
			return *filter == *_ref.filter;
		}

		return filter == _ref.filter;
	}
};

template<typename filter_t>
ref_t<filter_t> operator&(const ref_t<filter_t>& a, const ref_t<filter_t>& b)
{
	if (!a)
	{
		return b;
	}

	if (!b)
	{
		return a;
	}

	return and_op(a, b);
}

struct filter_network_t : filter_base_t
{
	std::vector<network_t> networks;

	inline filter_network_t() {}

	filter_network_t(const ipfw::rule_t::address_t& target)
	{
		for (const auto& pref : target)
		{
			std::visit([&](const auto& arg) {
				networks.emplace_back(arg);
			},
			           pref);
		}
	}

	filter_network_t(std::string string)
	{
		networks.emplace_back(std::move(string));
	}

	virtual bool is_none() const
	{
		return networks.empty();
	}

	virtual std::string to_string() const
	{
		if (networks.empty())
		{
			return "any";
		}

		std::string ret;

		for (const auto& network : networks)
		{
			if (!ret.empty())
			{
				ret += ",";
			}
			ret += network.to_string();
		}

		return ret;
	}

	bool operator==(const filter_network_t& o) const
	{
		return networks == o.networks;
	}
};

inline ref_t<filter_network_t> and_op(const ref_t<filter_network_t>& a, const ref_t<filter_network_t>& b)
{
	filter_network_t* result = new filter_network_t;

	for (const auto& a_item : a.filter->networks)
	{
		for (const auto& b_item : b.filter->networks)
		{
			if (a_item.family != b_item.family)
			{
				continue;
			}

			uint128_t a_mask = a_item.mask;
			uint128_t a_addr = a_item.addr;
			uint128_t b_mask = b_item.mask;
			uint128_t b_addr = b_item.addr;

			uint128_t f_mask = a_mask & b_mask;
			if ((a_addr & f_mask) != (b_addr & f_mask))
			{
				/// Bits fixed for both networks are not equal
				continue;
			}

			acl::network_t f_net(a_item.family, (a_addr & f_mask) | (a_addr & a_mask & ~b_mask) | (b_addr & b_mask & ~a_mask), a_mask | b_mask);
			result->networks.emplace_back(f_net);
		}
	}

	return result;
}

template<typename uint_t>
struct filter_prm_t : filter_base_t
{
	std::vector<range_t<uint_t>> ranges;

	inline filter_prm_t() {}

	filter_prm_t(const common::ranges_t& _ranges)
	{
		for (const auto& [from, to] : _ranges)
		{
			ranges.emplace_back(from, to);
		}
	}

	filter_prm_t(const std::set<uint_t>& values)
	{
		for (const auto& val : values)
		{
			ranges.emplace_back(val);
		}
	}

	filter_prm_t(const range_t<uint_t>& range)
	{
		ranges.emplace_back(range);
	}

	filter_prm_t(uint_t val)
	{
		ranges.emplace_back(val);
	}

	template<typename cont_t>
	filter_prm_t(const cont_t& cont, bool)
	{
		for (const auto& val : cont)
		{
			ranges.emplace_back(val);
		}
	}

	template<size_t size>
	filter_prm_t(const std::array<bool, size>& vals)
	{
		int start = -1;
		for (size_t i = 0; i < size; ++i)
		{
			if (vals[i])
			{
				if (start < 0)
				{
					start = i;
				}
			}
			else
			{
				if (start >= 0)
				{
					ranges.emplace_back(start, i - 1);
					start = -1;
				}
			}
		}

		if (start >= 0)
		{
			ranges.emplace_back(start, size - 1);
		}
	}

	virtual bool is_none() const
	{
		return ranges.empty();
	}

	virtual std::string to_string() const
	{
		std::string ret;

		for (const auto& range : ranges)
		{
			if (!ret.empty())
			{
				ret += ",";
			}
			if (range.from() == range.to())
			{
				ret += std::to_string(range.from());
			}
			else
			{
				ret += std::to_string(range.from()) + "-" + std::to_string(range.to());
			}
		}
		return ret;
	}

	bool operator==(const filter_prm_t& o) const
	{
		return ranges == o.ranges;
	}
};

template<typename uint_t>
ref_t<filter_prm_t<uint_t>> and_op(const ref_t<filter_prm_t<uint_t>>& a, const ref_t<filter_prm_t<uint_t>>& b)
{
	filter_prm_t<uint_t>* result = new filter_prm_t<uint_t>;

	for (const auto& a_item : a.filter->ranges)
	{
		for (const auto& b_item : b.filter->ranges)
		{
			uint_t from = std::max(a_item.from(), b_item.from());
			uint_t to = std::min(a_item.to(), b_item.to());

			if (from <= to)
			{
				result->ranges.emplace_back(from, to);
			}
		}
	}

	return result;
}

using filter_bool_t = filter_prm_t<uint8_t>;
using filter_prm8_t = filter_prm_t<uint8_t>;
using filter_prm16_t = filter_prm_t<uint16_t>;

static inline ref_t<filter_prm16_t> icmp_prm1(const common::ranges_t& types, const common::ranges_t& codes)
{
	filter_prm16_t* filter = new filter_prm16_t;

	if (types == ranges_t{common::range_t{0x00, 0xFF}} && codes == ranges_t{common::range_t{0x00, 0xFF}})
	{
		filter->ranges.emplace_back(0x0000, 0xFFFF);
	}
	else
	{
		for (const auto& [type_from, type_to] : types)
		{
			if (codes == ranges_t{common::range_t{0x00, 0xFF}})
			{
				filter->ranges.emplace_back((type_from << 8), (type_to << 8) + 0xFF);
			}
			else
			{
				for (unsigned int i = type_from; i <= type_to; ++i)
				{
					for (const auto& [code_from, code_to] : codes)
					{
						filter->ranges.emplace_back((i << 8) + code_from, (i << 8) + code_to);
					}
				}
			}
		}
	}

	return filter;
}

inline ref_t<filter_prm8_t> tcpflags(unsigned int set_mask, unsigned int clear_mask)
{
	std::array<bool, 256> vals;
	vals.fill(true);

	if ((set_mask | clear_mask) == 0)
	{
		throw std::runtime_error("tcpflags is not specified");
	}
	for (unsigned int i = 0; i < 256; ++i)
	{
		if ((i & set_mask) != set_mask || (i & clear_mask) != 0)
		{
			vals[i] = false;
		}
	}
	return new filter_prm8_t(vals);
}

static inline ref_t<filter_prm8_t> tcp_established(unsigned int mask)
{
	std::array<bool, 256> vals;
	vals.fill(true);

	for (unsigned int i = 0; i < 256; ++i)
	{
		if ((i & mask) == 0)
		{
			vals[i] = false;
		}
	}
	return new filter_prm8_t(vals);
}

static inline ref_t<filter_prm8_t> tcpflags(ipfw::rule_ptr_t rulep)
{
	if (rulep->tcp_established)
	{
		unsigned int mask = ipfw::rule_t::tcp_flags_t::RST |
		                    ipfw::rule_t::tcp_flags_t::ACK;

		return tcp_established(mask);
	}

	return tcpflags(rulep->tcp_setflags, rulep->tcp_clearflags);
}

static inline std::string tcpflags_to_string(const ref_t<filter_prm8_t> prm)
{
	static const std::map<uint8_t, std::string> flags = {
	        {ipfw::rule_t::tcp_flags_t::FIN, "fin"},
	        {ipfw::rule_t::tcp_flags_t::SYN, "syn"},
	        {ipfw::rule_t::tcp_flags_t::RST, "rst"},
	        {ipfw::rule_t::tcp_flags_t::PUSH, "psh"},
	        {ipfw::rule_t::tcp_flags_t::ACK, "ack"},
	        {ipfw::rule_t::tcp_flags_t::URG, "urg"},
	        /* NOTE: ipfw doesn't support ece/cwr tcpflags keywords */
	        {ipfw::rule_t::tcp_flags_t::ECE, "ece"},
	        {ipfw::rule_t::tcp_flags_t::CWR, "cwr"},
	};
	std::array<bool, 256> filter;
	filter.fill(false);

	// convert filter_prm8_t into array<bool, 256>
	for (const auto& range : prm->ranges)
	{
		unsigned int i = range.from();
		do
		{
			filter[i++] = true;
		} while (i <= range.to() && i < 256);
	}

	// prepare another array<bool, 256> that represents "established" opcode
	std::array<bool, 256> vals;
	vals.fill(true);
	unsigned int mask = ipfw::rule_t::tcp_flags_t::RST |
	                    ipfw::rule_t::tcp_flags_t::ACK;

	for (unsigned int i = 0; i < 256; ++i)
	{
		if ((i & mask) == 0)
		{
			vals[i] = false;
		}
	}
	// now compare given prm with established representation
	if (filter == vals)
	{
		return " etsablished";
	}

	// handle tcpflags opcode
	std::string ret;
	unsigned int set_mask = 0, clear_mask = 0;

	// restore set_mask and clear_mask from prm filter
	for (unsigned int i = 0; i < 256; ++i)
	{
		if (filter[i])
		{
			set_mask = i;
			break;
		}
	}
	for (unsigned int i = 0; i < 256; ++i)
	{
		if (filter[255 - i])
		{
			clear_mask = i;
			break;
		}
	}
	// syn,!ack has alias "setup"
	if (set_mask == ipfw::rule_t::tcp_flags_t::SYN &&
	    clear_mask == ipfw::rule_t::tcp_flags_t::ACK)
	{
		return " setup";
	}
	// convert given masks into tcpflags
	for (unsigned int i = 0; i < 8; ++i)
	{
		if (set_mask & (1 << i))
		{
			if (!ret.empty())
			{
				ret += ",";
			}
			ret += flags.at(1 << i);
		}
		if (clear_mask & (1 << i))
		{
			if (!ret.empty())
			{
				ret += ",";
			}
			ret += "!" + flags.at(1 << i);
		}
	}
	return " tcpflags " + ret;
}

static inline std::string frag_to_string(const ref_t<filter_prm8_t> prm)
{
	static const std::map<uint8_t, std::string> frags = {
	        {controlplane::base::acl_rule_t::fragState::notFragmented, "!mf,!offset"},
	        {controlplane::base::acl_rule_t::fragState::firstFragment, "!offset"},
	        {controlplane::base::acl_rule_t::fragState::notFirstFragment, "offset"},
	};
	for (const auto& range : prm->ranges)
	{
		uint8_t value = range.from();
		if (value < frags.size())
		{
			return frags.at(value);
		}
	}
	return prm->to_string();
}

struct filter_id_t : filter_base_t
{
	int val;

	inline filter_id_t(int _val) :
	        val(_val) {}

	virtual bool is_none() const
	{
		return val < 0;
	}

	virtual std::string to_string() const
	{
		return std::to_string(val);
	}

	bool operator==(const filter_id_t& o) const
	{
		return val == o.val;
	}
};

inline ref_t<filter_id_t> and_op(const ref_t<filter_id_t>& a, const ref_t<filter_id_t>& b)
{
	if (a.filter->val != b.filter->val)
	{
		return new filter_id_t(-1);
	}

	return a;
}

struct filter_proto_t : filter_base_t
{
	ref_t<filter_prm8_t> type;
	ref_t<filter_prm16_t> prm1;
	ref_t<filter_prm16_t> prm2;
	ref_t<filter_prm8_t> prm3;

	filter_proto_t(const ref_t<filter_prm8_t>& _type,
	               const ref_t<filter_prm16_t>& _prm1,
	               const ref_t<filter_prm16_t>& _prm2,
	               const ref_t<filter_prm8_t>& _prm3) :
	        type(_type),
	        prm1(_prm1),
	        prm2(_prm2),
	        prm3(_prm3) {}

	filter_proto_t(ipfw::rule_ptr_t rulep)
	{
		// If protocols list is empty we assume a rule should match any protocol.
		// Also it means we will not try to match any protocol specific attributes
		// like ports, icmp-types, tcp-flags, etc.
		//
		// If user want to match them, protocol must be specified.
		if (rulep->proto.empty())
		{
			return;
		}

		bool has_tcpproto = false, has_udpproto = false, has_icmpproto = false,
		     has_icmp6proto = false, has_otherproto = false;
		bool has_sports = false, has_dports = false, has_tcpflags = false,
		     has_icmptypes = false, has_icmp6types = false;
		for (auto proto : rulep->proto)
		{
			switch (proto)
			{
				case IPPROTO_TCP:
					has_tcpproto = true;
					has_tcpflags = rulep->tcp_established ||
					               (rulep->tcp_setflags | rulep->tcp_clearflags) != 0;
					[[fallthrough]];
				case IPPROTO_UDP:
					if (proto == IPPROTO_UDP)
					{
						has_udpproto = true;
					}
					has_sports = !(rulep->sports.empty() && rulep->sports_range.empty());
					has_dports = !(rulep->dports.empty() && rulep->dports_range.empty());
					break;
				case IPPROTO_ICMP:
					has_icmpproto = true;
					has_icmptypes = !rulep->icmp_types.empty();
					break;
				case IPPROTO_ICMPV6:
					has_icmp6proto = true;
					has_icmp6types = !rulep->icmp6_types.empty();
					break;
				default:
					has_otherproto = true;
			}
		}
		// some sanity checks
		if ((has_sports || has_dports) && (has_icmpproto || has_icmp6proto || has_otherproto))
		{
			throw std::runtime_error("wrong rule: has ports and protocols other than TCP/UDP");
		}
		if ((has_icmptypes || has_icmp6types) && (has_tcpproto || has_udpproto || has_otherproto))
		{
			throw std::runtime_error("wrong rule: has icmp types and protocols other than ICMP/ICMPv6");
		}
		if (has_icmptypes && has_icmp6types)
		{
			throw std::runtime_error("wrong rule: has icmptypes and icmp6types");
		}
		if (has_tcpflags && (has_udpproto || has_icmpproto || has_icmp6proto || has_otherproto))
		{
			throw std::runtime_error("wrong rule: has tcpflags and protocols other than TCP");
		}

		type = new filter_prm8_t(rulep->proto);

		if (has_sports)
		{
			auto prm = new filter_prm16_t(rulep->sports);
			for (const auto& [from, to] : rulep->sports_range)
			{
				prm->ranges.emplace_back(from, to);
			}
			prm1 = prm;
		}
		if (has_dports)
		{
			auto prm = new filter_prm16_t(rulep->dports);
			for (const auto& [from, to] : rulep->dports_range)
			{
				prm->ranges.emplace_back(from, to);
			}
			prm2 = prm;
		}
		if (has_tcpflags)
		{
			prm3 = tcpflags(rulep);
		}
		if (has_icmptypes)
		{
			auto prm = new filter_prm16_t;
			for (unsigned int type : rulep->icmp_types)
			{
				prm->ranges.emplace_back(type << 8, (type << 8) + 255);
			}
			prm1 = prm;
		}
		if (has_icmp6types)
		{
			auto prm = new filter_prm16_t;
			for (unsigned int type : rulep->icmp6_types)
			{
				prm->ranges.emplace_back(type << 8, (type << 8) + 255);
			}
			prm1 = prm;
		}
	}

	virtual bool is_none() const
	{
		return type.is_none() || prm1.is_none() || prm2.is_none();
	}

	virtual std::string to_string() const
	{
		bool has_ports = false, has_icmptypes = false,
		     has_icmp6types = false, has_flags = false;
		std::string ret;

		if (type)
		{
			// XXX: convert to protocol name
			ret += " proto " + type->to_string();
			for (const auto& range : type->ranges)
			{
				switch (range.from())
				{
					case IPPROTO_TCP:
						has_flags = true;
						[[fallthrough]];
					case IPPROTO_UDP:
						has_ports = true;
						break;
					case IPPROTO_ICMP:
						has_icmptypes = true;
						break;
					case IPPROTO_ICMPV6:
						has_icmp6types = true;
						break;
				}
			}
		}

		if (prm1)
		{
			if (has_ports)
			{
				ret += " src-port " + prm1->to_string();
			}
			if (has_icmptypes || has_icmp6types)
			{
				if (has_icmptypes)
				{
					ret += " icmptypes ";
				}
				else
				{
					ret += " icmp6types ";
				}

				std::string types;
				for (const auto& range : prm1->ranges)
				{
					if (!types.empty())
					{
						types += ",";
					}
					types += std::to_string(range.from() >> 8);
				}
				ret += types;
			}
		}

		if (prm2)
		{
			ret += " dst-port " + prm2->to_string();
		}

		if (prm3)
		{
			if (has_flags)
			{
				ret += tcpflags_to_string(prm3);
			}
			else
			{
				ret += " flags " + prm3->to_string();
			}
		}

		return ret;
	}

	bool operator==(const filter_proto_t& o) const
	{
		return type == o.type && prm1 == o.prm1 && prm2 == o.prm2 && prm3 == o.prm3;
	}
};

inline ref_t<filter_proto_t> and_op(const ref_t<filter_proto_t>& a, const ref_t<filter_proto_t>& b)
{
	return new filter_proto_t(a.filter->type & b.filter->type,
	                          a.filter->prm1 & b.filter->prm1,
	                          a.filter->prm2 & b.filter->prm2,
	                          a.filter->prm3 & b.filter->prm3);
}

struct filter_t : filter_base_t
{
	ref_t<filter_id_t> acl_id;
	ref_t<filter_network_t> src;
	ref_t<filter_network_t> dst;
	ref_t<filter_prm8_t> flags;
	ref_t<filter_proto_t> proto;
	ref_t<filter_id_t> dir;
	ref_t<filter_bool_t> keepstate;

	filter_t(const ref_t<filter_id_t>& _acl_id,
	         const ref_t<filter_network_t>& _src,
	         const ref_t<filter_network_t>& _dst,
	         const ref_t<filter_prm8_t>& _flags,
	         const ref_t<filter_proto_t>& _proto,
	         const ref_t<filter_id_t>& _dir,
	         const ref_t<filter_bool_t>& keepstate) :
	        acl_id(_acl_id),
	        src(_src),
	        dst(_dst),
	        flags(_flags),
	        proto(_proto),
	        dir(_dir),
	        keepstate(keepstate)
	{}

	filter_t(ipfw::rule_ptr_t rulep)
	{
		if (!rulep->src.empty())
		{
			src = new filter_network_t(rulep->src);
		}
		if (!rulep->dst.empty())
		{
			dst = new filter_network_t(rulep->dst);
		}
		if (rulep->ipoff_setflags | rulep->ipoff_clearflags)
		{
			std::list<unsigned int> list;
			const unsigned int notFragmentedBits = ipfw::rule_t::ipoff_flags_t::OFFSET |
			                                       ipfw::rule_t::ipoff_flags_t::MF;
			const unsigned int firstFragmentBits = ipfw::rule_t::ipoff_flags_t::OFFSET;

			if ((rulep->ipoff_clearflags & notFragmentedBits) == notFragmentedBits)
			{
				list.push_back(controlplane::base::acl_rule_t::fragState::notFragmented);
			}
			else if ((rulep->ipoff_clearflags & firstFragmentBits) == firstFragmentBits)
			{
				list.push_back(controlplane::base::acl_rule_t::fragState::firstFragment);
			}
			else if (rulep->ipoff_setflags & ipfw::rule_t::ipoff_flags_t::OFFSET)
			{
				list.push_back(controlplane::base::acl_rule_t::fragState::notFirstFragment);
			}
			else
			{
				YANET_LOG_WARNING("unsupported frag spec in rule '%s'\n", rulep->text.data());
			}
			if (!list.empty())
			{
				flags = new filter_prm8_t(list, true);
			}
		}
		if (!rulep->proto.empty())
		{
			proto = new filter_proto_t(rulep);
		}
		switch (rulep->direction)
		{
			case ipfw::rule_t::direction_t::IN:
				dir = new filter_id_t(0);
				break;
			case ipfw::rule_t::direction_t::OUT:
				dir = new filter_id_t(1);
				break;
		}
		if (rulep->keepstate)
		{
			keepstate = new filter_bool_t(true);
		}
	}

	virtual bool is_none() const
	{
		return acl_id.is_none() || src.is_none() || dst.is_none() || proto.is_none() || dir.is_none() || keepstate.is_none();
	}

	virtual std::string to_string() const
	{
		std::string ret;

		if (src)
		{
			ret += " src-addr " + src->to_string();
		}
		if (dst)
		{
			ret += " dst-addr " + dst->to_string();
		}
		if (proto)
		{
			ret += proto->to_string();
		}
		if (dir && dir->val != -1)
		{
			ret += dir->val == 0 ? " in" : " out";
		}
		if (flags)
		{
			ret += " frag " + frag_to_string(flags);
		}
		if (keepstate)
		{
			ret += " keepstate";
		}

		if (acl_id)
		{
			ret += " via " + acl_id->to_string();
		}

		return ret;
	}

	bool operator==(const filter_t& o) const
	{
		return src == o.src && dst == o.dst && flags == o.flags && proto == o.proto && dir == o.dir && keepstate == o.keepstate;
	}
};

inline bool compatible(const filter_network_t* a, const filter_network_t* b)
{
	for (const auto& a_item : a->networks)
	{
		for (const auto& b_item : b->networks)
		{
			if (a_item.family != b_item.family)
			{
				continue;
			}

			uint128_t a_mask = a_item.mask;
			uint128_t a_addr = a_item.addr;
			uint128_t b_mask = b_item.mask;
			uint128_t b_addr = b_item.addr;
			uint128_t f_mask = a_mask & b_mask;
			if ((a_addr & f_mask) != (b_addr & f_mask))
			{
				/// Bits fixed for both networks are not equal
				continue;
			}

			return true;
		}
	}
	return false;
}

inline bool compatible(const filter_t* a, const filter_t* b)
{
	if (a->dst && b->dst && !compatible(a->dst, b->dst))
	{
		return false;
	}

	if (a->src && b->src && !compatible(a->src, b->src))
	{
		return false;
	}

	return true;
}

inline ref_t<filter_t> and_op(const ref_t<filter_t>& a, const ref_t<filter_t>& b)
{
	return new filter_t(a.filter->acl_id & b.filter->acl_id,
	                    a.filter->src & b.filter->src,
	                    a.filter->dst & b.filter->dst,
	                    a.filter->flags & b.filter->flags,
	                    a.filter->proto & b.filter->proto,
	                    a.filter->dir & b.filter->dir,
	                    a.filter->keepstate & b.filter->keepstate);
}

const int64_t DISPATCHER = -1;

// TODO: When rewriting the current ACL library into LibFilter, we should consider not using repetitive variants
// to represent rule actions. Currently, we have this one, which is not even fully correct since it contains
// int64_t for representing a line number for the SKIPTO instruction, which is not a rule action in an unwound rule
// sense.
//
// Additionally, we might have another variant for representing rules that are suitable for execution in the dataplane.
using rule_action = std::variant<int64_t, common::globalBase::tFlow, common::acl::action_t, common::acl::check_state_t>;

struct rule_t
{
	ref_t<filter_t> filter;
	rule_action action;
	ids_t ids;
	int64_t ruleno;
	mutable std::string text;
	mutable std::string comment;
	std::set<std::string> via;
	bool log;

private:
	rule_t(const ref_t<filter_t>& _filter, rule_action _action, ids_t _ids, bool _log) :
	        filter(_filter), action(std::move(_action)), ids(std::move(_ids)), ruleno(DISPATCHER), log(_log)
	{}

public:
	rule_t(const ref_t<filter_t>& _filter, common::globalBase::tFlow flow, const ids_t& ids, bool log) :
	        rule_t(_filter, rule_action(flow), ids, log)
	{}

	rule_t(const ref_t<filter_t>& _filter, common::acl::action_t action, const ids_t& ids, bool log) :
	        rule_t(_filter, rule_action(action), ids, log)
	{}

	rule_t(const ref_t<filter_t>& _filter, common::acl::check_state_t action, const ids_t& ids, bool log) :
	        rule_t(_filter, rule_action(action), ids, log)
	{}

	rule_t(const ref_t<filter_t>& _filter, int64_t num, int64_t skipto) :
	        filter(_filter),
	        action(skipto),
	        ruleno(num),
	        log(false)
	{}

	rule_t(ipfw::rule_ptr_t rulep, ipfw::fw_config_ptr_t configp)
	{
		text = rulep->text;
		switch (rulep->action)
		{
			case ipfw::rule_action_t::SKIPTO:
				if (std::holds_alternative<std::string>(rulep->action_arg))
				{
					// skipto LABEL
					const auto& name = std::get<std::string>(rulep->action_arg);
					const auto& label_info = configp->m_labels.at(name);
					action = std::get<unsigned int>(label_info);
					// add a hint in the comment for user where are we jumping to
					// add ruleno to original text
					text += " // " + std::to_string(std::get<int64_t>(action));
					// add label to generated text
					comment = name;
				}
				else if (std::holds_alternative<int64_t>(rulep->action_arg))
				{
					// skipto tablearg || skipto RULENO
					action = std::get<int64_t>(rulep->action_arg);
				}
				else
				{
					throw std::runtime_error("unexpected skipto variant");
				}
				break;
			case ipfw::rule_action_t::DENY:
				action = common::globalBase::tFlow(common::globalBase::eFlowType::drop);
				break;
			case ipfw::rule_action_t::ALLOW:
				action = DISPATCHER;
				break;
			case ipfw::rule_action_t::CHECKSTATE:
				action = common::acl::check_state_t{};
				break;
			case ipfw::rule_action_t::DUMP:
				action = common::acl::action_t(std::get<std::string>(rulep->action_arg));
				break;
			default:
				YANET_LOG_WARNING("unexpected rule action in rule '%s'\n", rulep->text.data());
				return;
		}
		log = rulep->log;
		filter = new filter_t(rulep);
		ruleno = rulep->ruleno;
		ids.emplace_back(rulep->ruleid);
		for (const auto& [name, how] : rulep->ifaces)
		{
			(void)how; // XXX: we can use in/out filters
			via.insert(name);
		}
		for (const auto& [direction, tables] : rulep->iface_tables)
		{
			(void)direction; // XXX: we can use in/out filters
			for (const auto& tablename : tables)
			{
				if (configp->m_tables.count(tablename) == 0)
				{
					YANET_LOG_WARNING("unknown interface table %s\n", tablename.data());
					continue;
				}
				const auto& [location, table] = configp->m_tables[tablename];
				if (std::holds_alternative<ipfw::tables::ifname_t>(table))
				{
					const auto& ifnames = std::get<ipfw::tables::ifname_t>(table);
					for (const auto& [iface, label] : ifnames)
					{
						(void)label;
						via.insert(iface);
					}
				}
				else
				{
					YANET_LOG_WARNING("wrong type for interface table %s\n", tablename.data());
				}
				(void)location;
			}
		}
	}

	const std::string& to_original_string() const
	{
		if (!text.empty())
		{
			return text;
		}
		return to_string();
	}

	const std::string& to_string() const
	{
		if (std::holds_alternative<common::globalBase::tFlow>(action))
		{
			auto flow = std::get<common::globalBase::tFlow>(action);
			if (flow.type == common::globalBase::eFlowType::drop || flow.type == common::globalBase::eFlowType::controlPlane)
			{
				text = "deny";
			}
			else
			{
				text = "flow " + std::string(eFlowType_toString(flow.type)) + "(" + std::to_string(flow.data.atomic) + ")";
			}
		}
		else if (std::holds_alternative<common::acl::action_t>(action))
		{
			auto rule_action = std::get<common::acl::action_t>(action);
			if (!rule_action.dump_tag.empty())
			{
				text = "dump(" + rule_action.dump_tag + ")";
			}
		}
		else if (std::holds_alternative<common::acl::check_state_t>(action))
		{
			text = "check-state";
		}
		else
		{
			auto arg = std::get<int64_t>(action);
			switch (arg)
			{
				case DISPATCHER:
					text = "allow";
					break;
				case 0:
					text = "skipto tablearg";
					break;
				default:
					text = "skipto " + std::to_string(arg);
			}
		}

		if (log)
		{
			text += " log";
		}
		if (filter)
		{
			text += filter->to_string();
		}
		// XXX: rule filter can have via too
		if (!via.empty())
		{
			std::string ifaces;
			for (const auto& iface : via)
			{
				if (!ifaces.empty())
				{
					// XXX: not compatible with ipfw opcode format
					ifaces += ",";
				}
				ifaces += iface;
			}
			text += " via " + ifaces;
		}

		if (!comment.empty())
		{
			text += " // " + comment;
		}

		return text;
	}

	bool operator==(const rule_t& o) const
	{
		return action == o.action && filter == o.filter && log == o.log;
	}

	bool is_term() const
	{
		return std::holds_alternative<common::globalBase::tFlow>(action);
	}

	bool is_skipto() const
	{
		return std::holds_alternative<int64_t>(action);
	}
};

} // namespace acl

namespace
{
inline void hash_combine(std::size_t&) {}

template<typename T, typename... Rest>
inline void hash_combine(std::size_t& seed, const T& v, Rest... rest)
{
	std::hash<T> hasher;
	seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
	hash_combine(seed, rest...);
}
}

namespace std
{

template<>
struct hash<acl::filter_network_t>
{
	size_t operator()(const acl::filter_network_t& f) const noexcept
	{
		size_t h = 0;

		for (auto& n : f.networks)
		{
			hash_combine(h, n.family, uint64_t(n.addr), uint64_t(n.addr >> 64), uint64_t(n.mask), uint64_t(n.mask >> 64));
		}

		return h;
	}
};

template<typename T>
struct hash<acl::filter_prm_t<T>>
{
	size_t operator()(const acl::filter_prm_t<T>& f) const noexcept
	{
		size_t h = 0;

		for (auto& r : f.ranges)
		{
			hash_combine(h, r.from(), r.to());
		}

		return h;
	}
};

template<>
struct hash<acl::filter_id_t>
{
	size_t operator()(const acl::filter_id_t& f) const noexcept
	{
		return f.val;
	}
};

template<>
struct hash<acl::filter_proto_t>
{
	size_t operator()(const acl::filter_proto_t& f) const noexcept
	{
		size_t h = 0;
		hash_combine(h, f.type, f.prm1, f.prm2, f.prm3);

		return h;
	}
};

template<typename T>
struct hash<acl::ref_t<T>>
{
	size_t operator()(const acl::ref_t<T>& r) const noexcept
	{
		size_t h = 0;
		if (r)
		{
			hash_combine(h, **r);
		}
		return h;
	}
};

template<>
struct hash<acl::filter_t>
{
	size_t operator()(const acl::filter_t& f) const noexcept
	{
		size_t h = 0;
		hash_combine(h, f.src, f.dst, f.flags, f.proto, f.dir, f.keepstate);

		return h;
	}
};

template<>
struct hash<acl::rule_t>
{
	size_t operator()(const acl::rule_t& r) const noexcept
	{
		size_t h = 0;
		if (std::holds_alternative<int64_t>(r.action))
		{
			const auto& act = std::get<int64_t>(r.action);
			hash_combine(h, act);
		}
		else if (std::holds_alternative<common::globalBase::tFlow>(r.action))
		{
			auto flow = std::get<common::globalBase::tFlow>(r.action);
			hash_combine(h, 1, (uint64_t(flow.type) << 32) & flow.data.atomic);
		}
		else if (std::holds_alternative<common::acl::check_state_t>(r.action))
		{
			// Since check_state_t acts as a marker (either present or not),
			// it doesn't have specific members to hash.
			// To uniquely identify its presence in the hash, we use a
			// predefined static constant as a unique identifier.
			hash_combine(h, common::acl::check_state_t::HASH_IDENTIFIER);
		}
		else
		{
			auto action = std::get<common::acl::action_t>(r.action);
			hash_combine(h, action.dump_id);
		}
		if (r.filter)
		{
			hash_combine(h, **r.filter);
		}
		hash_combine(h, r.log);

		return h;
	}
};

template<>
struct hash<std::vector<acl::rule_t>>
{
	size_t operator()(const std::vector<acl::rule_t>& v) const noexcept
	{
		size_t h = 0;

		for (auto& r : v)
		{
			hash_combine(h, r);
		}

		return h;
	}
};

#if defined(__GNUC__) && !defined(__clang__)
template<>
struct __is_fast_hash<hash<std::vector<acl::rule_t>>> : public std::false_type
{};
#endif

} // namespace std
