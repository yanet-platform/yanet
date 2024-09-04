#pragma once

#include "../type.h"

struct OneTestData
{
	unsigned max_number_node;
	double depth_lambda;
	double probability_create_node;
	bool include_root;
	unsigned rand_init_value;
	tVrfId vrf_number;

	std::string Description() const;
};

std::vector<ipv4_prefix_t> CreatePrefixesIpv4(const OneTestData& test_data);

std::vector<ipv6_prefix_t> CreatePrefixesIpv6(const OneTestData& test_data);
