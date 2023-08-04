#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../src/acl_tree.h"
#include "../src/acl/network.h"

namespace
{

using uint128_t = common::uint128_t;

template<typename type_t,
         unsigned int bits_t>
void collect(acl::compiler::tree_t<type_t, bits_t>& tree,
             const std::string& prefix)
{
	::acl::network_t network(prefix);
	tree.collect(network.addr, network.mask);
}

TEST(acl_tree, basic)
{
	acl::compiler::tree_t<uint128_t, 8> tree;

	collect(tree, "22aa:6543::/ffff:ffff::");
	collect(tree, "::/::");

	tree.prepare();

	tAclGroupId group_id = 1;
	std::vector<tAclGroupId> remap_group_ids;

	{
		remap_group_ids.resize(0);
		remap_group_ids.resize(group_id, 0);
		tree.insert(common::ipv6_address_t("22aa:6543::").getAddress128(),
		            common::ipv6_address_t("ffff:ffff::").getAddress128(),
		            group_id,
		            remap_group_ids);
	}

	{
		remap_group_ids.resize(0);
		remap_group_ids.resize(group_id, 0);
		tree.insert(common::ipv6_address_t("::").getAddress128(),
		            common::ipv6_address_t("::").getAddress128(),
		            group_id,
		            remap_group_ids);
	}

	tree.merge(group_id);

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:6543::").getAddress128(),
		         common::ipv6_address_t("ffff:ffff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {3};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:8888::").getAddress128(),
		         common::ipv6_address_t("ffff:ffff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("::").getAddress128(),
		         common::ipv6_address_t("::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2, 3};
		EXPECT_THAT(group_ids, group_ids_expect);
	}
}

TEST(acl_tree, gapped)
{
	acl::compiler::tree_t<uint128_t, 8> tree;

	collect(tree, "22aa:0043::/ffff:00ff::");
	collect(tree, "::/::");

	tree.prepare();

	tAclGroupId group_id = 1;
	std::vector<tAclGroupId> remap_group_ids;

	{
		remap_group_ids.resize(0);
		remap_group_ids.resize(group_id, 0);
		tree.insert(common::ipv6_address_t("22aa:0043::").getAddress128(),
		            common::ipv6_address_t("ffff:00ff::").getAddress128(),
		            group_id,
		            remap_group_ids);
	}

	{
		remap_group_ids.resize(0);
		remap_group_ids.resize(group_id, 0);
		tree.insert(common::ipv6_address_t("::").getAddress128(),
		            common::ipv6_address_t("::").getAddress128(),
		            group_id,
		            remap_group_ids);
	}

	tree.merge(group_id);

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:0043::").getAddress128(),
		         common::ipv6_address_t("ffff:00ff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {3};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:1243::").getAddress128(),
		         common::ipv6_address_t("ffff:ffff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {3};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:0099::").getAddress128(),
		         common::ipv6_address_t("ffff:00ff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:1299::").getAddress128(),
		         common::ipv6_address_t("ffff:ffff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("22aa:8888::").getAddress128(),
		         common::ipv6_address_t("ffff:ffff::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2};
		EXPECT_THAT(group_ids, group_ids_expect);
	}

	{
		std::vector<uint8_t> bitmask;
		std::vector<tAclGroupId> group_ids;

		bitmask.resize(0);
		bitmask.resize(group_id, 0);

		tree.get(common::ipv6_address_t("::").getAddress128(),
		         common::ipv6_address_t("::").getAddress128(),
		         bitmask);

		for (unsigned int i = 0;
		     i < group_id;
		     i++)
		{
			if (bitmask[i])
			{
				group_ids.emplace_back(i);
			}
		}

		std::vector<tAclGroupId> group_ids_expect = {2, 3};
		EXPECT_THAT(group_ids, group_ids_expect);
	}
}

TEST(acl_tree, unsupported_gapped_masks)
{
	/// double gapped
	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "::/ffff:0000:ff00:ffff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	/// last part not 8bit aligned
	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "::/ffff:003f:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	/// invalid second gapped mask
	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:0000:ff00::");
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:0000:ff00::");
		collect(tree, "2222:a000:2200::/ffff:f0ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:aa00:2200::/ffff:ff00:ff00::");
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:b000:2200::/ffff:f000:ff00::");
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:bbb0:2200::/ffff:fff0:ff00::");
		collect(tree, "2222:00b0:2200::/ffff:00ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:bbb0:2200::/ffff:fff0:ff00::");
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	/// invalid second gapped mask (reverse collect)
	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		collect(tree, "2222:0000:2200::/ffff:0000:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:a000:2200::/ffff:f0ff:ff00::");
		collect(tree, "2222:0000:2200::/ffff:0000:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		collect(tree, "2222:aa00:2200::/ffff:ff00:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		collect(tree, "2222:b000:2200::/ffff:f000:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:00b0:2200::/ffff:00ff:ff00::");
		collect(tree, "2222:bbb0:2200::/ffff:fff0:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}

	{
		acl::compiler::tree_t<uint128_t, 8> tree;
		collect(tree, "2222:0000:2200::/ffff:00ff:ff00::");
		collect(tree, "2222:bbb0:2200::/ffff:fff0:ff00::");
		EXPECT_THROW(tree.prepare(), std::runtime_error);
	}
}

} // namespace
