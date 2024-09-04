#include <gtest/gtest.h>

#include "../vrf.h"
#include "random_prefixes.h"
#include "vrf_lpm_common.h"
#include "vrf_lpm_map.h"

namespace dataplane::vrflpm
{

static constexpr size_t size_of_mem = 1024 * 1024 * 100;

TEST(VrfLpm4, SimpleBinaryTree)
{
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size_of_mem);
	VrfLpm4BinaryTree::BlocksAllocator allocator;
	allocator.Init(buffer.get(), size_of_mem, YANET_RIB_VRF_MAX_NUMBER);
	VrfLpm4BinaryTree vrf_linear(allocator);

	SimpleTestVrfLpm4(vrf_linear);
}

TEST(VrfLpm6, SimpleBinaryTree)
{
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size_of_mem);
	VrfLpm6BinaryTree::BlocksAllocator allocator;
	allocator.Init(buffer.get(), size_of_mem, YANET_RIB_VRF_MAX_NUMBER);
	VrfLpm6BinaryTree vrf_linear(allocator);

	SimpleTestVrfLpm6(vrf_linear);
}

TEST(VrfLpm4, CompareMapAndBinaryTree)
{
	auto all_tests = dataplane::vrflpm::BuildTestData4();
	for (const auto& test_data : all_tests)
	{
		auto prefixes = CreatePrefixesIpv4(test_data);

		VrfLpmMap<ipv4_prefix_t, uint32_t, uint32_t> vrf_map;

		std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size_of_mem);
		VrfLpm4BinaryTree::BlocksAllocator allocator;
		allocator.Init(buffer.get(), size_of_mem, YANET_RIB_VRF_MAX_NUMBER);
		VrfLpm4BinaryTree vrf_linear(allocator);

		bool result = CompareTwoImplementations(test_data.vrf_number, prefixes, vrf_map, vrf_linear);
		ASSERT_EQ(result, true) << "\nTest data:\n\t" << test_data.Description() << "\n";
	}
}

TEST(VrfLpm6, CompareMapAndBinaryTree)
{
	auto all_tests = dataplane::vrflpm::BuildTestData6();
	for (const auto& test_data : all_tests)
	{
		auto prefixes = CreatePrefixesIpv6(test_data);

		VrfLpmMap<ipv6_prefix_t, std::array<uint8_t, 16>, ipv6_address_t> vrf_map;

		std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size_of_mem);
		VrfLpm6BinaryTree::BlocksAllocator allocator;
		allocator.Init(buffer.get(), size_of_mem, YANET_RIB_VRF_MAX_NUMBER);
		VrfLpm6BinaryTree vrf_linear(allocator);

		bool result = CompareTwoImplementations(test_data.vrf_number, prefixes, vrf_map, vrf_linear);
		ASSERT_EQ(result, true) << "\nTest data:\n\t" << test_data.Description() << "\n";
	}
}

}
