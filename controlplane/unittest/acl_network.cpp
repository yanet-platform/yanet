#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../src/acl_network.h"

namespace
{

using uint128_t = common::uint128_t;

uint128_t convert_to_uint128(const std::string& address)
{
	return acl::network_t(address).addr;
}

template<typename ... args_T>
void make_filter_helper(acl::compiler::network_t<uint128_t>::filter& filter,
                        const std::string& prefix,
                        const args_T& ... prefixes)
{
	filter.emplace(prefix);

	if constexpr (sizeof...(args_T) != 0)
	{
		make_filter_helper(filter, prefixes...);
	}
}

template<typename ... args_T>
acl::compiler::network_t<uint128_t>::filter make_filter(const args_T& ... prefixes)
{
	acl::compiler::network_t<uint128_t>::filter result;
	make_filter_helper(result, prefixes...);
	return result;
}

template<typename type_t>
std::vector<tAclGroupId> get_by_prefix(acl::compiler::network_t<type_t>& network,
                                       const std::string& prefix)
{
	const auto group_ids = network.get_group_ids_by_prefix({prefix});
	return group_ids;
}

template<typename type_t>
tAclGroupId get_by_address(acl::compiler::network_t<type_t>& network,
                           const std::string& address)
{
	return network.get_group_ids_by_address(convert_to_uint128(address));
}

template<typename ... args_T>
void expect_group_ids_helper(std::vector<tAclGroupId>& vector,
                             const unsigned int group_id,
                             const args_T ... group_ids)
{
	vector.emplace_back(group_id);

	if constexpr (sizeof...(args_T) != 0)
	{
		expect_group_ids_helper(vector, group_ids...);
	}
}

template<typename ... args_T>
std::vector<tAclGroupId> expect_group_ids(const args_T ... group_ids)
{
	std::vector<tAclGroupId> result;
	expect_group_ids_helper(result, group_ids...);
	return result;
}

TEST(acl_network, basic)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("1234::/ffff::"));
	acl_network.collect(make_filter("1234:1100::/ffff:ff00::", "1234:2200::/ffff:ff00::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	EXPECT_THAT(acl_network.get_group_ids_by_filter(make_filter("1234::/ffff::")), expect_group_ids(1, 2));
	EXPECT_THAT(acl_network.get_group_ids_by_filter(make_filter("1234:1100::/ffff:ff00::", "1234:2200::/ffff:ff00::")), expect_group_ids(2));
}

TEST(acl_network, get_by_prefix)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("1234::/ffff::"));
	acl_network.collect(make_filter("1234:1100::/ffff:ff00::", "1234:2200::/ffff:ff00::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	EXPECT_THAT(get_by_prefix(acl_network, "1234::/ffff::"), expect_group_ids(1, 2));
	EXPECT_THAT(get_by_prefix(acl_network, "1234:1100::/ffff:ff00::"), expect_group_ids(2));
	EXPECT_THAT(get_by_prefix(acl_network, "1234:2200::/ffff:ff00::"), expect_group_ids(2));
	EXPECT_THAT(get_by_prefix(acl_network, "1234:3300::/ffff:ff00::"), expect_group_ids(1));
	EXPECT_THAT(get_by_prefix(acl_network, "1234:ff00::/ffff:ff00::"), expect_group_ids(1));
}

TEST(acl_network, get_by_address)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("1234::/ffff::"));
	acl_network.collect(make_filter("1234:1100::/ffff:ff00::", "1234:2200::/ffff:ff00::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	EXPECT_THAT(get_by_address(acl_network, "1234:0000:1234::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "1234:1122:3333::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "1234:2222:3333::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "1234:3322:3333::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "1234:ff22:3333::"), 1);
}

TEST(acl_network, gapped_simple)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("2222:00aa::/ffff:00ff::"));
	acl_network.collect(make_filter("2222:4400::/ffff:ff00::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 21;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.size(), 1); ///< one gapped mask
	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.begin()->second.size(), 1 + 1); ///< has two last_multirefs

	/// check by filter
	EXPECT_THAT(acl_network.get_group_ids_by_filter(make_filter("::/::")), expect_group_ids(21, 22, 23, 24));
	EXPECT_THAT(acl_network.get_group_ids_by_filter(make_filter("2222:00aa::/ffff:00ff::")), expect_group_ids(23, 24));
	EXPECT_THAT(acl_network.get_group_ids_by_filter(make_filter("2222:4400::/ffff:ff00::")), expect_group_ids(22, 24));

	/// check by prefix
	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(21, 22, 23, 24));
	EXPECT_THAT(get_by_prefix(acl_network, "2222:00aa::/ffff:00ff::"), expect_group_ids(23, 24));
	EXPECT_THAT(get_by_prefix(acl_network, "2222:4400::/ffff:ff00::"), expect_group_ids(22, 24));

	/// check by address (lookup)
	EXPECT_THAT(get_by_address(acl_network, "1111::"), 21);

	EXPECT_THAT(get_by_address(acl_network, "2222:0000::"), 21);
	EXPECT_THAT(get_by_address(acl_network, "2222:00aa::"), 23);
	EXPECT_THAT(get_by_address(acl_network, "2222:00ff::"), 21);

	EXPECT_THAT(get_by_address(acl_network, "2222:4400::"), 22);
	EXPECT_THAT(get_by_address(acl_network, "2222:44aa::"), 24);
	EXPECT_THAT(get_by_address(acl_network, "2222:44ff::"), 22);

	EXPECT_THAT(get_by_address(acl_network, "2222:ff00::"), 21);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffaa::"), 23);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffff::"), 21);
}

TEST(acl_network, gapped_simple_4bit)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("2222:00aa::/ffff:00ff::"));
	acl_network.collect(make_filter("2222:4000::/ffff:f000::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 1;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.size(), 1); ///< one gapped mask

	/// @todo: optimize last_multirefs for not 8bit simple mask (must be 2)
	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.begin()->second.size(), 1 + 16);

	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(1, 2, 3, 4));

	EXPECT_THAT(get_by_address(acl_network, "1111::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:0000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:00aa::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "2222:00ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:4000::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:40aa::"), 4);
	EXPECT_THAT(get_by_address(acl_network, "2222:40ff::"), 2);

	EXPECT_THAT(get_by_address(acl_network, "2222:ff00::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffaa::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffff::"), 1);
}

TEST(acl_network, gapped_simple_4bit_6bit)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("2222:00aa::/ffff:00ff::"));
	acl_network.collect(make_filter("2222:4000::/ffff:f000::"));
	acl_network.collect(make_filter("2222:4c00::/ffff:fc00::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 1;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.size(), 1); ///< one gapped mask

	/// @todo: optimize last_multirefs for not 8bit simple mask (must be 3)
	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.begin()->second.size(), 1 + 16);

	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(1, 2, 3, 4, 5, 6));

	EXPECT_THAT(get_by_address(acl_network, "1111::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:0000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:00aa::"), 4);
	EXPECT_THAT(get_by_address(acl_network, "2222:00ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:4000::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:40aa::"), 5);
	EXPECT_THAT(get_by_address(acl_network, "2222:40ff::"), 2);

	EXPECT_THAT(get_by_address(acl_network, "2222:4c00::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "2222:4caa::"), 6);
	EXPECT_THAT(get_by_address(acl_network, "2222:4cff::"), 3);

	EXPECT_THAT(get_by_address(acl_network, "2222:ff00::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffaa::"), 4);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffff::"), 1);
}

TEST(acl_network, intersection)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("2222:00aa::/ffff:00ff::"));
	acl_network.collect(make_filter("2222:40aa::/ffff:f0ff::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 1;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.size(), 1); ///< one gapped mask

	/// @todo: optimize last_multirefs for not 8bit simple mask (must be 2)
	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.begin()->second.size(), 1 + 16);

	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(1, 2, 3));

	EXPECT_THAT(get_by_address(acl_network, "1111::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:0000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:00aa::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:00ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:4000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:40aa::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "2222:40ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:ff00::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffaa::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffff::"), 1);
}

TEST(acl_network, intersection_aa_bb)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("2222:00aa::/ffff:00ff::"));
	acl_network.collect(make_filter("2222:40bb::/ffff:f0ff::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 1;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.size(), 1); ///< one gapped mask

	/// @todo: optimize last_multirefs for not 8bit simple mask (must be 2)
	EXPECT_THAT(acl_network.tree.multirefs_chunk_ids.begin()->second.size(), 1 + 16);

	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(1, 2, 3));

	EXPECT_THAT(get_by_address(acl_network, "1111::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:0000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:00aa::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:00bb::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:00ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:4000::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:40aa::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:40bb::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "2222:40ff::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "2222:ff00::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffaa::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffbb::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "2222:ffff::"), 1);
}

TEST(acl_network, bug_find_gapped_mask)
{
	acl::compiler::network_t<uint128_t> acl_network(nullptr);

	acl_network.collect(make_filter("::/::"));
	acl_network.collect(make_filter("4adf:f9f8:0000:0000:4440::/ffff:ffff:0000:0000:fff0::"));
	acl_network.collect(make_filter("4adf:f9f8:0000:0000:4300::/ffff:ffff:ff00:0000:fff0::"));

	acl_network.prepare();
	acl_network.compile();
	acl_network.populate();

	tAclGroupId shared_group_id = 1;
	acl_network.remap(shared_group_id);

	EXPECT_THAT(get_by_prefix(acl_network, "::/::"), expect_group_ids(1, 2, 3));

	EXPECT_THAT(get_by_address(acl_network, "1111::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:0000:0000:1110::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:0000:0000:4300::"), 3);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:0000:0000:4440::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:0000:0000:fff0::"), 1);

	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:1100:0000:1110::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:1100:0000:4300::"), 1);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:1100:0000:4440::"), 2);
	EXPECT_THAT(get_by_address(acl_network, "4adf:f9f8:1100:0000:fff0::"), 1);
}

} // namespace
