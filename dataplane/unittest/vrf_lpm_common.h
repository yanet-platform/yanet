#pragma once

#include <algorithm>

#include "../vrf.h"

namespace dataplane::vrflpm
{

inline uint32_t IpAddressToInternal(const ipv4_address_t& address)
{
	return rte_cpu_to_be_32(address.address);
}

inline std::array<uint8_t, 16> IpAddressToInternal(const ipv6_address_t& address)
{
	return common::ipv6_address_t(address.bytes);
}

inline std::string AddressStr(const ipv6_address_t& address)
{
	return common::ipv6_address_t(address.bytes).toString();
}

inline std::string AddressStr(const std::array<uint8_t, 16>& address)
{
	return common::ipv6_address_t(address).toString();
}

inline std::string AddressStr(const ipv4_address_t& address)
{
	return common::ipv4_address_t(address.address).toString();
}

inline std::string AddressStr(const uint32_t& address)
{
	return common::ipv4_address_t(address).toString();
}

template<typename PrefixType, typename PrefixTree>
bool FillPrefixTree(const std::vector<PrefixType>& prefixes, PrefixTree& tree, tVrfId vrf_number)
{
	uint32_t value = 0;
	stats_t stats = {0, 0};
	size_t prefix_number = prefixes.size();
	for (tVrfId vrf = 0; vrf < vrf_number; vrf++)
	{
		for (size_t index = 0; index < prefix_number; index += 1 + 5 * vrf)
		{
			auto address = prefixes[index].address;
			if (tree.Insert(stats, vrf, IpAddressToInternal(address), prefixes[index].mask, value) != eResult::success)
			{
				YANET_LOG_ERROR("Error add prefix, vrf=%d, prefix=%s/%d, value=%d\n",
				                vrf,
				                AddressStr(IpAddressToInternal(prefixes[index].address)).c_str(),
				                (uint16_t)prefixes[index].mask,
				                value);
				return false;
			}
			value++;
		}
	}

	return true;
}

template<typename PrefixTree1, typename PrefixTree2>
bool CompareTrees(const PrefixTree1& tree1, const PrefixTree2& tree2)
{
	auto list1 = tree1.GetFullList();
	auto list2 = tree2.GetFullList();
	std::sort(list1.begin(), list1.end());
	std::sort(list2.begin(), list2.end());
	auto iter1 = list1.begin();
	auto iter2 = list2.begin();

	while ((iter1 != list1.end()) && (iter2 != list2.end()))
	{
		const auto& [vrf1, address1, mask1, value1] = *iter1;
		const auto& [vrf2, address2, mask2, value2] = *iter2;
		if ((vrf1 != vrf2) || (address1 != address2) || (mask1 != mask2) || (value1 != value2))
		{
			YANET_LOG_ERROR("[vrf=%d, %s/%d, value=%d] != [vrf=%d, %s/%d, value=%d]\n",
			                vrf1,
			                AddressStr(address1).c_str(),
			                uint16_t(mask1),
			                value1,
			                vrf2,
			                AddressStr(address2).c_str(),
			                uint16_t(mask2),
			                value2);
			return false;
		}
		++iter1;
		++iter2;
	}
	if (iter1 != list1.end())
	{
		const auto& [vrf1, address1, mask1, value1] = *iter1;
		YANET_LOG_ERROR("list2 empty, in list1: vrf=%d, %s/%d, value=%d\n",
		                vrf1,
		                AddressStr(address1).c_str(),
		                uint16_t(mask1),
		                value1);
		return false;
	}
	if (iter2 != list2.end())
	{
		const auto& [vrf2, address2, mask2, value2] = *iter2;
		YANET_LOG_ERROR("list1 empty, in list2: vrf=%d, %s/%d, value=%d\n",
		                vrf2,
		                AddressStr(address2).c_str(),
		                uint16_t(mask2),
		                value2);
		return false;
	}
	return true;
}

inline ipv6_address_t LastAddress(const ipv6_prefix_t& prefix)
{
	if (prefix.mask == 64)
	{
		return prefix.address;
	}

	uint64_t hi = rte_cpu_to_be_64(*(reinterpret_cast<const uint64_t*>(prefix.address.bytes)));
	uint64_t low = rte_cpu_to_be_64(*(reinterpret_cast<const uint64_t*>(prefix.address.bytes + 8)));
	if (prefix.mask == 0)
	{
		hi = static_cast<uint64_t>(-1);
		low = static_cast<uint64_t>(-1);
	}
	else if (prefix.mask < 64)
	{
		hi += (1ull << (64 - prefix.mask)) - 1;
		low = static_cast<uint64_t>(-1);
	}
	else
	{
		low += (1ull << (128 - prefix.mask)) - 1;
	}

	ipv6_address_t result;
	*(reinterpret_cast<uint64_t*>(result.bytes)) = rte_cpu_to_be_64(hi);
	*(reinterpret_cast<uint64_t*>(result.bytes + 8)) = rte_cpu_to_be_64(low);

	return result;
}

inline uint32_t LastAddress(const ipv4_prefix_t& prefix)
{
	if (prefix.mask == 0)
	{
		return -1;
	}
	return rte_cpu_to_be_32(prefix.address.address) + ((1u << (32 - prefix.mask)) - 1);
}

inline std::vector<uint32_t> AddressesForTest(const ipv4_prefix_t& prefix)
{
	return {rte_cpu_to_be_32(prefix.address.address), rte_cpu_to_be_32(LastAddress(prefix))};
}

inline std::vector<ipv6_address_t> AddressesForTest(const ipv6_prefix_t& prefix)
{
	return {prefix.address, LastAddress(prefix)};
}

template<typename PrefixType, typename PrefixTree1, typename PrefixTree2>
bool CheckRequests(tVrfId vrf_number,
                   const std::vector<PrefixType>& prefixes,
                   const PrefixTree1& tree1,
                   const PrefixTree2& tree2)
{
	size_t size = prefixes.size();
	for (size_t index = 0; index < size; index++)
	{
		auto addresses = AddressesForTest(prefixes[index]);
		std::vector<uint32_t> values1(2), values2(2);
		for (tVrfId vrf = 0; vrf < vrf_number; vrf++)
		{
			std::vector<tVrfId> vrfs(2, vrf);
			tree1.Lookup(addresses.data(), vrfs.data(), values1.data(), 2);
			tree2.Lookup(addresses.data(), vrfs.data(), values2.data(), 2);

			for (int index_addr = 0; index_addr < 2; index_addr++)
			{
				if (values1[index_addr] != values2[index_addr])
				{
					YANET_LOG_ERROR("Different values, vrf=%d, address=%s, %d != %d\n",
					                vrf,
					                AddressStr(addresses[index_addr]).c_str(),
					                values1[index_addr],
					                values2[index_addr]);
					return false;
				}
			}
		}
	}
	return true;
}

template<typename PrefixType, typename PrefixTree1, typename PrefixTree2>
bool CompareTwoImplementations(tVrfId vrf_number,
                               const std::vector<PrefixType>& prefixes,
                               PrefixTree1& tree1,
                               PrefixTree2 tree2)
{
	if (!FillPrefixTree(prefixes, tree1, vrf_number))
	{
		YANET_LOG_ERROR("Error FillPrefixTree first tree\n");
		return false;
	}
	if (!FillPrefixTree(prefixes, tree2, vrf_number))
	{
		YANET_LOG_ERROR("Error FillPrefixTree second tree\n");
		return false;
	}

	stats_t stats = {0, 0};
	for (int step = 0; step < 2; step++)
	{
		if (step == 1)
		{
			for (size_t index = 0; index < prefixes.size(); index += 3)
			{
				for (tVrfId vrf = 0; vrf < vrf_number; vrf++)
				{
					auto addr = IpAddressToInternal(prefixes[index].address);
					if (tree1.Remove(stats, vrf, addr, prefixes[index].mask) != eResult::success)
					{
						YANET_LOG_ERROR("Error tree1.Remove. Step = %d\n", step);
						return false;
					}
					if (tree2.Remove(stats, vrf, addr, prefixes[index].mask) != eResult::success)
					{
						YANET_LOG_ERROR("Error tree2.Remove. Step = %d\n", step);
						return false;
					}
				}
			}
		}

		if (!CompareTrees(tree1, tree2))
		{
			YANET_LOG_ERROR("Trees differs. Step = %d\n", step);
			return false;
		}

		if (!CheckRequests<PrefixType, PrefixTree1, PrefixTree2>(vrf_number, prefixes, tree1, tree2))
		{
			YANET_LOG_ERROR("CheckRequests error. Step = %d\n", step);
			return false;
		}
	}

	return true;
}

static constexpr OneTestData tests_ipv4[] = {
        {1000, 20.0, 0.8, true, 42, 10}, // tree sizes: 1-4
        {1000, 15.0, 0.8, true, 42, 10}, // tree sizes: 2-7
        {1000, 10.0, 0.8, true, 42, 10}, // tree sizes: 6-15
        {1000, 5.0, 0.8, true, 42, 10}, // tree sizes: 86-271
        {10000, 3.0, 0.1, true, 42, 10}, // tree sizes: 271-992
        {10000, 3.0, 0.2, true, 42, 10} // tree sizes: 574-2053
};

static constexpr size_t number_tests_ipv4 = sizeof(tests_ipv4) / sizeof(OneTestData);

static constexpr OneTestData tests_ipv6[] = {
        {1000, 50.0, 0.8, true, 42, 10}, // tree sizes: 4-7
        {1000, 40.0, 0.8, true, 42, 10}, // tree sizes: 6-14
        {1000, 20.0, 0.8, true, 42, 10}, // tree sizes: 77-147
        {10000, 10.0, 0.03, true, 42, 10}, // tree sizes: 416-601
        {10000, 10.0, 0.1, true, 42, 10} // tree sizes: 855-1959
};

static constexpr size_t number_tests_ipv6 = sizeof(tests_ipv6) / sizeof(OneTestData);

inline std::vector<OneTestData> BuildTestData(size_t number_tests, const OneTestData* tests_ipv)
{
	std::vector<OneTestData> tests;
	for (size_t index = 0; index < number_tests; index++)
	{
		OneTestData test_data = tests_ipv[index];
		for (unsigned rand = 0; rand < 10; rand++)
		{
			test_data.rand_init_value++;
			for (int include_root = 0; include_root < 2; include_root++)
			{
				test_data.include_root = (include_root == 0);
				tests.push_back(test_data);
			}
		}
	}

	return tests;
}

inline std::vector<OneTestData> BuildTestData4()
{
	return BuildTestData(number_tests_ipv4, tests_ipv4);
}

inline std::vector<OneTestData> BuildTestData6()
{
	return BuildTestData(number_tests_ipv6, tests_ipv6);
}

template<typename VrfLpmType>
void SimpleTestVrfLpm4(VrfLpmType& vrf_lpm)
{
	std::vector<std::string> str_prefixes = {"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "0.0.0.0/0", "1.0.0.0/28", "1.0.0.0/30"};
	std::vector<std::string> str_addresses = {"1.0.0.17", "2.0.0.1", "3.0.0.1", "4.0.0.1", "1.0.0.5", "1.0.0.1"};
	std::vector<uint32_t> values = {0, 1, 2, 3, 4, 5};

	stats_t stats;
	uint32_t value = 0;
	for (const std::string& str_prefix : str_prefixes)
	{
		common::ipv4_prefix_t prefix(str_prefix);
		ASSERT_EQ(vrf_lpm.Insert(stats, 0, uint32_t(prefix.address()), prefix.mask(), value++), eResult::success);
	}

	for (size_t index = 0; index < str_addresses.size(); index++)
	{
		common::ipv4_address_t address(str_addresses[index]);
		uint32_t addr = rte_cpu_to_be_32(uint32_t(address));
		tVrfId vrfId = 0;
		uint32_t value;
		vrf_lpm.Lookup(&addr, &vrfId, &value, 1);
		ASSERT_EQ(value, values[index]) << "Error check for " << str_addresses[index];
	}
}

template<typename VrfLpmType>
void SimpleTestVrfLpm6(VrfLpmType& vrf_lpm)
{
	std::vector<std::string> str_prefixes = {"::/0", "7e01::/64", "7e02::/64", "7e03::/64", "7e01::/96", "7e01::f0/124"};
	std::vector<std::string> str_addresses = {"7e00::1", "7e01::1:0:0:f1", "7e02::1", "7e03::1", "7e01::1:f1", "7e01::f1"};
	std::vector<uint32_t> values = {0, 1, 2, 3, 4, 5};

	stats_t stats;
	uint32_t value = 0;
	for (const std::string& str_prefix : str_prefixes)
	{
		common::ipv6_prefix_t prefix(str_prefix);
		ASSERT_EQ(vrf_lpm.Insert(stats, 0, prefix.address(), prefix.mask(), value++), eResult::success);
	}

	for (size_t index = 0; index < str_addresses.size(); index++)
	{
		ipv6_address_t address = ipv6_address_t::convert(common::ipv6_address_t(str_addresses[index]));
		tVrfId vrfId = 0;
		uint32_t value;
		vrf_lpm.Lookup(&address, &vrfId, &value, 1);
		ASSERT_EQ(value, values[index]) << "Error check for " << str_addresses[index];
	}
}

} // namespace dataplane::vrflpm
