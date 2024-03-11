#pragma once

#include "acl/rule.h"

#include "acl_base.h"
#include "acl_flat.h"
#include "acl_network.h"
#include "acl_network_table.h"
#include "acl_rule.h"
#include "acl_total_table.h"
#include "acl_transport.h"
#include "acl_transport_table.h"
#include "acl_value.h"

namespace acl
{

/*
 * rule состоит из набора filter'ов, например:
 *   allow tcp    from ip1    to ip2    1024-65535    established
 *         ^      ^           ^         ^             ^
 *         ^      ^           ^         ^             transport.tcp_flags.filter
 *         ^      ^           ^         transport.tcp_destination.filter
 *         ^      ^           network_ipv4/v6_destination.filter
 *         ^      network_ipv4/v6_source.filter
 *         transport.protocol.filter
 *
 * каждый тип filter'а обрабатывает свой compiler класс: compiler::network_t, compiler::network_table_t, compiler::total_table_t, ...
 * в такой последовательности:
 *   collect(filter) - сбор всех возможный фильтров данного типа и присваивание ему filter_id
 *   prepare() - аллокация и подготовка структур
 *   compile() - заполнение структур значениями group_id (каждое уникальное пересечение filter'ов имеет свой group_id)
 *   populate() - подготовка отображения filter_id <-> [group_id1, group_id2, ...]
 *
 * lookup (acl2.0):
 *   network_ipv4/v6_source(source_address) -> source_id
 *   network_ipv4/v6_destination(destination_address) -> destination_id
 *   network_table(source_id, destination_id) -> network_table_id + transport_layer_id
 *   transport.protocol(transport_layer_id, proto) -> protocol_id
 *   transport.tcp_source(transport_layer_id, tcp_source) -> tcp_source_id
 *   transport.tcp_destination(transport_layer_id, tcp_destination) -> tcp_destination_id
 *   transport.tcp_flags(transport_layer_id, tcp_flags) -> tcp_flags_id
 *   network_flags(fragment_state) -> network_flags_id
 *   transport_table(network_table_id, protocol_id, tcp_source_id, tcp_destination_id, tcp_flags_id, network_flags_id) -> transport_table_id
 *   total_table(acl_id, transport_table_id) -> total_table_id
 *   value(total_table_id) -> action
 */

class compiler_t
{
public:
	compiler_t();

public:
	void compile(const std::vector<rule_t>& unwind_rules,
	             result_t& result,
	             const unsigned int transport_layers_size = 2048);

	void clear();
	void collect(const std::vector<rule_t>& unwind_rules);
	void network_compile();
	void network_table_compile();
	void network_flags_compile();
	void transport_compile();
	void transport_table_compile();
	void total_table_compile();
	void value_compile();

public:
	unsigned int transport_layers_size_max;
	unsigned int transport_layers_shift;

	std::vector<compiler::rule_t> rules;

	compiler::network_t<uint32_t> network_ipv4_source;
	compiler::network_t<uint32_t> network_ipv4_destination;
	compiler::network_t<uint128_t> network_ipv6_source;
	compiler::network_t<uint128_t> network_ipv6_destination;
	compiler::network_table_t network_table;
	compiler::flat_t<uint8_t> network_flags;
	compiler::transport_t transport;
	compiler::transport_table_t transport_table;
	compiler::total_table_t total_table;
	compiler::value_t value;

	std::set<uint128_t> network_ipv6_destination_hosts;

	tAclGroupId source_group_id;
	tAclGroupId destination_group_id;

	std::vector<uint32_t> used_rules;
};

}
