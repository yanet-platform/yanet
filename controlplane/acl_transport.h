#pragma once

#include "acl/bitset.h"
#include "acl_base.h"
#include "acl_filter.h"
#include "acl_flat.h"

namespace acl::compiler
{

class transport_t
{
public:
	transport_t(acl::compiler_t* compiler);

public:
	using filter = filter_transport;

	void clear();
	unsigned int collect(const unsigned int rule_id, const filter& filter);
	void prepare();
	void emplace_variation(const unsigned int network_table_group_id, const std::set<unsigned int>& filter_ids);
	void distribute();
	void compile();
	void populate();
	void remap();

public:
	class layer
	{
	public:
		flat_t<uint8_t> protocol;
		flat_t<uint16_t> tcp_source;
		flat_t<uint16_t> tcp_destination;
		flat_t<uint8_t> tcp_flags;
		flat_t<uint16_t> udp_source;
		flat_t<uint16_t> udp_destination;
		flat_t<uint16_t> icmp_type_code;
		flat_t<uint16_t> icmp_identifier;

		FlatSet<unsigned int> filter_ids_set;
		FlatSet<unsigned int> network_table_group_ids_set;

		std::vector<unsigned int> filter_ids_vec;
		std::vector<unsigned int> network_table_group_ids_vec;
		std::vector<unsigned int> network_table_group_ids_vec_next;

		std::vector<unsigned int> protocol_id;
		std::vector<unsigned int> tcp_source_id;
		std::vector<unsigned int> tcp_destination_id;
		std::vector<unsigned int> tcp_flags_id;
		std::vector<unsigned int> udp_source_id;
		std::vector<unsigned int> udp_destination_id;
		std::vector<unsigned int> icmpv4_type_code_id;
		std::vector<unsigned int> icmpv4_identifier_id;
		std::vector<unsigned int> icmpv6_type_code_id;
		std::vector<unsigned int> icmpv6_identifier_id;
	};

	acl::compiler_t* compiler;

	std::vector<layer> layers;

	std::vector<tAclGroupId> remap_group_ids;
	tAclGroupId group_id;

	std::vector<filter> filters;
	std::map<filter, unsigned int> filter_ids;
	std::vector<std::vector<unsigned int>> filter_rule_ids;

	std::vector<std::vector<tAclGroupId>> filter_group_ids;

	std::vector<uint8_t> bitmask; /// @todo: bitmask_t

	std::unordered_map<bitset_t, tAclGroupId> map;
	std::map<tAclGroupId, bitset_t> reverse_map;
	std::map<tAclGroupId, bitset_t> reverse_map_next;

	std::map<std::tuple<size_t,
	                    std::set<unsigned int>>,
	         std::vector<unsigned int>>
	        variation;

protected:
	layer& get_layer(unsigned int layer_id);
};

}
