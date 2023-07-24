#pragma once

#include "../acl.h"

#include "bitset.h"
#include "network.h"
#include "rule.h"

#ifdef ACL_DEBUG
#include <stdio.h>
#define debug(format...) printf(format)
#else
#define debug(format...)
#endif

namespace acl
{

namespace
{
	template<typename... Args>
	void UNUSED(Args&&...) {}
}

template<typename Addr>
class AddrTraits
{
public:
	static constexpr Addr hostMask = ~Addr(0);
	static bool is_host(Addr mask)
	{
		return mask == hostMask;
	}
};

template<typename Addr>
bool is_host(Addr mask)
{
	return AddrTraits<Addr>::is_host(mask);
}

bool is_mask_simple(uint128_t mask)
{
	bool end_found = false;
	for (unsigned int i = 1; i <= 16; ++i)
	{
		const uint8_t byte = uint8_t((mask >> (128 - i * 8)) & 0xff);
		if (end_found)
		{
			if (byte > 0)
			{
				return false;
			}
		}
		else
		{
			if (byte == 0xff)
			{
				continue;
			}
			end_found = true;
		}
	}
	return true;
}

uint8_t mask_len(common::ipv6_address_t mask)
{
	uint8_t len = 128;
	const uint8_t *data = mask.data();
	for (unsigned int i = 0; i < 16; ++i)
	{
		const uint8_t byte = data[15 - i];
		if (byte != 0x00) {
			len -= __builtin_ctz(byte);
			break;
		}
		len -= 8;
	}
	return len;
}

/*
 * Bit mask of rules
 *
 * Each bit corresponds to rule
 * Size of all rulesets is the same and equals to number of rules in current config
 */
typedef bitset_t ruleset_t;

/*
 * mapping of prefix to ruleset
 *
 * key is network prefix, value is ruleset matching this prefix
 *
 * For example, firewall rules
 *  allow ip from 10.0.0.1/32 to any
 *  allow ip from 10.0.0.0/24 to any
 *  deny ip from any to any
 * will be stored in ptree as
 *  10.0.0.1/32 -> 111 // prefix matches by rule 1, 2 and 3
 *  10.0.0.0/24 -> 011 // prefix matches by rule 2 and 3
 *  0.0.0.0/0   -> 001 // prefix matches by rule 3
 */
template<typename Addr>
class ptree_t
{
private:
	std::vector<std::tuple<Addr, Addr, ruleset_t>> storage;
	std::map<Addr, ruleset_t> host_storage;
	const size_t rules_count;

	friend class network_dict_t;

public:
	explicit ptree_t(size_t rules_count) :
	        rules_count(rules_count)
	{}

	size_t size()
	{
		return storage.size();
	}

	void insert(Addr addr, Addr mask, unsigned int idx)
	{
		if (is_host(mask))
		{
			auto it = host_storage.lower_bound(addr);
			if (it == host_storage.end() || it->first != addr)
			{
				ruleset_t ruleset(rules_count);
				ruleset.insert(idx);
				host_storage.emplace_hint(it, addr, std::move(ruleset));
			}
			else
			{
				it->second.insert(idx);
			}
			return;
		}

		ruleset_t ruleset(rules_count);
		ruleset.insert(idx);

		bool found = false;

		for (auto& [curr_addr, curr_mask, curr_ruleset] : storage)
		{
			if (curr_addr == addr && curr_mask == mask)
			{
				// such prefix was inserted already
				found = true;
			}

			// mask should be checked also to cover cases like 10.0.0.0/23 and 10.0.0.0/24
			if (!found && ((addr & mask) & curr_mask) == curr_addr && (mask & curr_mask) == curr_mask)
			{
				// new prefix is not found yet and new prefix is completely inside current
				// So new prefix is matched by all rules from curr_ruleset
				ruleset |= curr_ruleset;
			}

			if (((curr_addr & curr_mask) & mask) == addr && (curr_mask & mask) == mask)
			{
				// current prefix is inside new prefix
				// Add new rule index to current ruleset
				curr_ruleset.insert(idx);
			}
		}

		if (!found)
		{
			storage.emplace_back(addr, mask, std::move(ruleset));
		}
	}

	void calculate()
	{
		YANET_LOG_DEBUG("ptree %lu hosts, %lu nets\n", host_storage.size(), storage.size());

		for (auto& [addr, ruleset] : host_storage)
		{
			for (auto& [curr_addr, curr_mask, curr_ruleset] : storage)
			{
				if ((addr & curr_mask) == curr_addr)
				{
					ruleset |= curr_ruleset;
				}
			}
		}
		for (auto& [addr, ruleset] : host_storage)
		{
			storage.emplace_back(addr, AddrTraits<Addr>::hostMask, ruleset);
		}
	}

	void optimize()
	{
		std::unordered_map<ruleset_t, std::vector<std::tuple<Addr, Addr>>> rulesets(storage.size());
		for (auto& [addr, mask, ruleset] : storage)
		{
			auto [it, inserted] = rulesets.try_emplace(std::move(ruleset), std::vector<std::tuple<Addr, Addr>>());
			UNUSED(inserted);
			it->second.push_back({addr, mask});
		}
		auto start_size = storage.size();
		storage.clear();

		for (auto& [ruleset, v] : rulesets)
		{
			if (v.size() == 1)
			{
				auto& [addr, mask] = v[0];
				storage.emplace_back(addr, mask, ruleset);
				continue;
			}
			for (auto& [a1, m1] : v)
			{
				bool consumed = false;
				for (auto& [a2, m2] : v)
				{
					if (a1 == a2 && m1 == m2)
					{
						// skip itself
						continue;
					}
					if (((a1 & m1) & m2) == a2 && (m1 & m2) == m2)
					{
						consumed = true;
						break;
					}
				}
				if (!consumed)
				{
					storage.emplace_back(a1, m1, ruleset);
				}
			}
		}

		YANET_LOG_DEBUG("optimized ptree size from %lu to %lu\n", start_size, storage.size());
	}
};

/*
 * dictionary of unique rulesets
 * key is ruleset, value is index of ruleset
 */
struct rdict_t
{
	std::unordered_map<ruleset_t, unsigned int> map;

	rdict_t() = default;

	rdict_t(size_t n) :
	        map(n)
	{}

	unsigned int mark(ruleset_t&& ruleset)
	{
		return map.try_emplace(std::move(ruleset), map.size() + 1).first->second; // zero is reserved
	}

	std::vector<std::tuple<ruleset_t, uint32_t>> as_vector() const
	{
		std::vector<std::tuple<ruleset_t, uint32_t>> vec;
		vec.reserve(map.size());
		for (auto& v : map)
		{
			vec.push_back(v);
		}

		return vec;
	}
};

class network_dict_t
{
private:
	ptree_t<uint32_t> ptree_v4;
	ptree_t<uint128_t> ptree_v6;

public:
	rdict_t rdict_v4;
	rdict_t rdict_v6;

	inline network_dict_t(size_t rules_count) :
	        ptree_v4(rules_count), ptree_v6(rules_count),
	        rdict_v4(rules_count), rdict_v6(rules_count)
	{}

	size_t size()
	{
		return ptree_v4.size() + ptree_v6.size();
	}

	void insert(const filter_network_t* filter, unsigned int idx)
	{
		if (!filter)
		{
			ptree_v4.insert(0, 0, idx);
			ptree_v6.insert(0, 0, idx);
		}
		else
		{
			for (const auto& network : filter->networks)
			{
				if (network.family == 4)
				{
					ptree_v4.insert(network.addr, network.mask, idx);
				}
				else if (network.family == 6)
				{
					ptree_v6.insert(network.addr, network.mask, idx);
				}
				else
				{
					throw std::runtime_error("internal error");
				}
			}
		}
	}

	// compile rdicts only
	void comp()
	{
		ptree_v4.calculate();
		ptree_v6.calculate();
		// optimization does not affect rulesets, so skip it

		for (auto& [addr, mask, ruleset] : ptree_v4.storage)
		{
			UNUSED(addr, mask);
			auto ruleset_id = rdict_v4.mark(std::move(ruleset));
#ifdef ACL_DEBUG
			const auto ones = __builtin_popcount(mask);
			debug("%s/%u -> %d ", common::ipv4_address_t(addr).toString().data(), ones, ruleset_id * 2);
			ruleset.print();
			debug("\n");
#else
			UNUSED(ruleset_id);
#endif
		}
		for (auto& [addr, mask, ruleset] : ptree_v6.storage)
		{
			UNUSED(addr, mask);
			auto ruleset_id = rdict_v6.mark(std::move(ruleset));
#ifdef ACL_DEBUG
			debug("%s/%s -> %d ", common::ipv6_address_t(addr).toString().data(), common::ipv6_address_t(mask).toString().data(), ruleset_id * 2 + 1);
			ruleset.print();
			debug("\n");
#else
			UNUSED(ruleset_id);
#endif
		}
	}
};

template<typename uint_t>
struct prm_dict_t
{
	static constexpr unsigned int size = (1U << (sizeof(uint_t) * 8));

	size_t rules_count;
	std::map<std::tuple<uint_t, uint_t>, ruleset_t> dict;

	rdict_t rdict;

	inline prm_dict_t(size_t _rules_count) :
	        rules_count(_rules_count), rdict(_rules_count) {}

	void insert_item(std::tuple<uint_t, uint_t> range, unsigned int idx)
	{
		auto res = dict.try_emplace(range, ruleset_t(rules_count));
		res.first->second.insert(idx);
	}

	void insert(const filter_prm_t<uint_t>* filter, unsigned int idx)
	{
		if (filter)
		{
			for (const auto& range : filter->ranges)
			{
				insert_item(range, idx);
			}
		}
		else
		{
			insert_item(range_t<uint_t>(0, size - 1), idx);
		}
	}

	void comp(std::array<uint_t, size>& table)
	{
		std::vector<ruleset_t> rulesets;

		for (unsigned int i = 0; i < size; ++i)
		{
			rulesets.emplace_back(rules_count);
		}

		for (const auto& it : dict)
		{
			const auto& range = std::get<0>(it);
			const ruleset_t& ruleset = std::get<1>(it);
			for (unsigned int i = std::get<0>(range); i <= std::get<1>(range); ++i)
			{
				rulesets[i] |= ruleset;
			}
		}

		for (unsigned int i = 0; i < size; ++i)
		{
			table[i] = rdict.mark(std::move(rulesets[i]));
		}

#ifdef ACL_DEBUG
		debug("------------\n");

		for (const auto& [ruleset, id] : rdict.map)
		{
			int start = -1;
			for (unsigned int i = 0; i < size; ++i)
			{
				if (table[i] == id)
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
						if (start < (int)(i - 1))
						{
							debug("%u-%u,", start, i - 1);
						}
						else
						{
							debug("%u,", start);
						}
						start = -1;
					}
				}
			}

			if (start >= 0)
			{
				if (start < (int)(size - 1))
				{
					debug("%u-%u,", start, size - 1);
				}
				else
				{
					debug("%u,", start);
				}
			}

			debug(" -> %u ", id);
			ruleset.print();
			debug("\n");
		}
#endif
	}
};

struct id_dict_t
{
	std::vector<ruleset_t> table;
	size_t rules_count;

	inline id_dict_t(size_t rules_count) :
	        rules_count(rules_count)
	{
	}

	inline void insert(unsigned int id, unsigned int idx)
	{
		if (id >= table.size())
		{
			table.resize(id + 1, {rules_count});
		}
		table[id].insert(idx);
	}
};

struct dict_t
{
	id_dict_t acl_id;
	network_dict_t src;
	network_dict_t dst;
	prm_dict_t<uint8_t> flags;
	prm_dict_t<uint8_t> type;
	prm_dict_t<uint16_t> prm1;
	prm_dict_t<uint16_t> prm2;
	prm_dict_t<uint8_t> prm3;

	using key0_t = std::tuple<unsigned int,
	                          unsigned int,
	                          unsigned int,
	                          unsigned int,
	                          unsigned int>;

	using key1_t = std::tuple<uint16_t,
	                          unsigned int,
	                          unsigned int>;

	using key2_t = std::tuple<uint16_t,
	                          uint32_t>;

	dict_t(size_t rules_count) :
	        acl_id(rules_count),
	        src(rules_count),
	        dst(rules_count),
	        flags(rules_count),
	        type(rules_count),
	        prm1(rules_count),
	        prm2(rules_count),
	        prm3(rules_count) {}

	void insert(const std::vector<rule_t>& rules)
	{
		size_t idx = 0;
		YANET_LOG_DEBUG("collecting acls\n");
		for (const auto& rule : rules)
		{
			assert(rule.filter);
			assert(rule.filter->acl_id.filter);
			acl_id.insert(rule.filter->acl_id.filter->val, idx++);
		}
		idx = 0;
		YANET_LOG_DEBUG("collecting srcs\n");
		for (const auto& rule : rules)
		{
			src.insert(rule.filter->src, idx++);
		}
		idx = 0;
		YANET_LOG_DEBUG("collecting dsts\n");
		for (const auto& rule : rules)
		{
			dst.insert(rule.filter->dst, idx++);
		}
		idx = 0;
		YANET_LOG_DEBUG("collecting flags\n");
		for (const auto& rule : rules)
		{
			flags.insert(rule.filter->flags, idx++);
		}

		idx = 0;
		YANET_LOG_DEBUG("collecting proto\n");
		for (const auto& rule : rules)
		{
			if (rule.filter->proto)
			{
				const filter_proto_t* proto_filter = rule.filter->proto.filter;

				type.insert(proto_filter->type, idx);
				prm1.insert(proto_filter->prm1, idx);
				prm2.insert(proto_filter->prm2, idx);
				prm3.insert(proto_filter->prm3, idx);
			}
			else
			{
				type.insert(nullptr, idx);
				prm1.insert(nullptr, idx);
				prm2.insert(nullptr, idx);
				prm3.insert(nullptr, idx);
			}
			idx++;
		}
	}

	template<typename T, typename = void>
	struct is_iterable : std::false_type
	{};
	template<typename T>
	struct is_iterable<T, std::void_t<decltype(std::declval<T>().begin()), decltype(std::declval<T>().end())>>
	        : std::true_type
	{};

	template<typename K, typename F>
	void merge_maps_int(ruleset_t&& ruleset, K& keys, size_t, const F& store)
	{
		store(std::move(ruleset), keys);
	}

	template<typename K, typename F, typename = std::invoke_result_t<F, ruleset_t&&, K&>, typename... TMaps>
	void merge_maps_int(ruleset_t&& ruleset, K& keys, size_t i, const F& store, const TMaps&... maps)
	{
		if (store(std::move(ruleset), keys))
			return;

		merge_maps_int(ruleset, keys, i, maps...);
	}

	template<typename K, typename M, std::enable_if_t<is_iterable<M>::value, bool> = true, typename... TMaps>
	void merge_maps_int(const ruleset_t& ruleset, K& keys, size_t i, const M& map, const TMaps&... maps)
	{
		for (const auto& [cur_ruleset, id] : map)
		{
			if (ruleset.emptyAnd(cur_ruleset))
			{
				continue;
			}
			keys[i] = id;
			merge_maps_int(ruleset & cur_ruleset, keys, i + 1, maps...);
		}
	}

	template<typename F, std::enable_if_t<!is_iterable<F>::value, bool> = true, typename... TMaps>
	size_t cardinality(std::string& str, const F&, const TMaps&... maps)
	{
		if constexpr (sizeof...(maps) > 0)
		{
			return cardinality(str, maps...);
		}
		if (str.size() > 3)
		{
			str.resize(str.size() - 3); // remove " * "
		}
		return 1;
	}

	template<typename M, std::enable_if_t<is_iterable<M>::value, bool> = true, typename... TMaps>
	size_t cardinality(std::string& str, const M& map, const TMaps&... maps)
	{
		str += std::to_string(map.size());
		if constexpr (sizeof...(maps) > 0)
		{
			str += " * ";
			return map.size() * cardinality(str, maps...);
		}
		return map.size();
	}

	template<typename M, typename... TMaps>
	void merge_maps(const std::string& name, const M& map, const TMaps&... maps)
	{
		std::string log = name + " cardinality: ";
		auto size = cardinality(log, map, maps...);
		YANET_LOG_DEBUG("%s = %lu\n", log.c_str(), size);

		std::array<uint32_t, sizeof...(TMaps) + 1> keys;
		for (const auto& [cur_ruleset, id] : map)
		{
			if (cur_ruleset.empty())
			{
				continue;
			}
			keys[0] = id;
			merge_maps_int(cur_ruleset, keys, 1, maps...);
		}
	}
};

} // namespace acl
