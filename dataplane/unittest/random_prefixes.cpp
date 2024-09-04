#include <algorithm>
#include <memory>
#include <queue>
#include <random>

#include "random_prefixes.h"

std::string OneTestData::Description() const
{
	return "max_number_node " + std::to_string(max_number_node) +
	       "\n\tdepth_lambda = " + std::to_string(depth_lambda) +
	       "\n\tprobability_create_node = " + std::to_string(probability_create_node) +
	       "\n\tinclude_root = " + std::to_string(include_root) +
	       "\n\trand_init_value = " + std::to_string(rand_init_value) +
	       "\n\tvrf_number = " + std::to_string(vrf_number);
}

struct Node
{
	bool has_value = false;
	unsigned depth;
	std::shared_ptr<Node> left;
	std::shared_ptr<Node> right;
};

std::shared_ptr<Node> BuildRandomTree(unsigned max_depth, const OneTestData& test_data, std::mt19937& generator)
{
	std::poisson_distribution<> poisson(test_data.depth_lambda);
	std::uniform_real_distribution<> uniform(0.0, 1.0);

	std::shared_ptr<Node> root = std::make_shared<Node>();
	root->depth = 0;

	unsigned created_nodes = 0;
	std::queue<std::shared_ptr<Node>> work;
	work.push(root);

	while (created_nodes < test_data.max_number_node && !work.empty())
	{
		std::shared_ptr<Node> node = work.front();
		work.pop();

		bool create = (node->depth == 0 ? test_data.include_root : uniform(generator) < test_data.probability_create_node);
		if (create)
		{
			node->has_value = true;
			created_nodes++;
		}

		// create left
		unsigned depth_left = node->depth + std::max(1, poisson(generator));
		if (depth_left <= max_depth)
		{
			node->left = std::make_shared<Node>();
			node->left->depth = depth_left;
			work.push(node->left);
		}

		// create right
		unsigned depth_right = node->depth + std::max(1, poisson(generator));
		if (depth_right <= max_depth)
		{
			node->right = std::make_shared<Node>();
			node->right->depth = depth_right;
			work.push(node->right);
		}
	}

	return root;
}

uint32_t CreatePartAddressIpv4(uint8_t previous_depth,
                               uint8_t depth,
                               uint32_t first_bit,
                               std::uniform_int_distribution<>& digits_distribution,
                               std::mt19937& generator)
{
	uint32_t result = first_bit;
	for (uint8_t i = previous_depth + 1; i < depth; i++)
	{
		result = (result << 1) | digits_distribution(generator);
	}

	return result << (32 - depth);
}

std::vector<ipv4_prefix_t> CreatePrefixesIpv4(const OneTestData& test_data)
{
	std::mt19937 generator(test_data.rand_init_value);
	std::uniform_int_distribution<> digits_distribution(0, 1);

	std::shared_ptr<Node> root = BuildRandomTree(32, test_data, generator);
	std::queue<std::pair<std::shared_ptr<Node>, uint32_t>> work;
	work.push({root, 0});
	std::vector<ipv4_prefix_t> prefixes;

	while (!work.empty())
	{
		auto [node, value] = work.front();
		work.pop();
		if (node->has_value)
		{
			ipv4_address_t addr = ipv4_address_t::convert(common::ipv4_address_t(value));
			prefixes.push_back({addr, static_cast<uint8_t>(node->depth)});
		}

		if (node->left != nullptr)
		{
			work.push({node->left, value | CreatePartAddressIpv4(node->depth, node->left->depth, 0, digits_distribution, generator)});
		}
		if (node->right != nullptr)
		{
			work.push({node->right, value | CreatePartAddressIpv4(node->depth, node->right->depth, 1, digits_distribution, generator)});
		}
	}

	std::shuffle(prefixes.begin(), prefixes.end(), generator);

	return prefixes;
}

std::array<uint8_t, 16> CreatePartAddressIpv6(const std::array<uint8_t, 16>& previous_address,
                                              unsigned previous_depth,
                                              unsigned depth,
                                              uint32_t first_bit,
                                              std::uniform_int_distribution<>& digits_distribution,
                                              std::mt19937& generator)
{
	std::array<uint8_t, 16> result = previous_address;
	for (uint8_t bit = previous_depth; bit < depth; bit++)
	{
		uint8_t digit = (bit == previous_depth ? first_bit : digits_distribution(generator));
		result.data()[bit / 8] |= (digit << (7 - (bit % 8)));
	}
	return result;
}

std::vector<ipv6_prefix_t> CreatePrefixesIpv6(const OneTestData& test_data)
{
	std::mt19937 generator(test_data.rand_init_value);
	std::uniform_int_distribution<> digits_distribution(0, 1);

	std::shared_ptr<Node> root = BuildRandomTree(128, test_data, generator);
	std::queue<std::pair<std::shared_ptr<Node>, std::array<uint8_t, 16>>> work;
	work.push({root, std::array<uint8_t, 16>()});
	std::vector<ipv6_prefix_t> prefixes;

	while (!work.empty())
	{
		auto [node, value] = work.front();
		work.pop();
		if (node->has_value)
		{
			ipv6_address_t addr = ipv6_address_t::convert(common::ipv6_address_t(value));
			prefixes.push_back({addr, static_cast<uint8_t>(node->depth)});
		}

		if (node->left != nullptr)
		{
			work.push({node->left, CreatePartAddressIpv6(value, node->depth, node->left->depth, 0, digits_distribution, generator)});
		}
		if (node->right != nullptr)
		{
			work.push({node->right, CreatePartAddressIpv6(value, node->depth, node->right->depth, 1, digits_distribution, generator)});
		}
	}

	std::shuffle(prefixes.begin(), prefixes.end(), generator);

	return prefixes;
}
