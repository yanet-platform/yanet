#include <gtest/gtest.h>
#include <rte_flow.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "dataplane/rteflow.h"

namespace
{
struct FlowRule
{
	uint16_t port;
	uint32_t priority;
	rte_flow_item_type type;
	rte_flow_item_eth eth_spec{};
	rte_flow_item_eth eth_mask{};
	rte_flow_item_ipv4 ipv4_spec{};
	rte_flow_item_ipv4 ipv4_mask{};
	rte_flow_item_ipv6 ipv6_spec{};
	rte_flow_item_ipv6 ipv6_mask{};
	uint16_t queue = 0;
	std::vector<uint16_t> rss_queues;
	rte_flow* handle = nullptr;
};

std::vector<FlowRule> rules;
std::vector<std::pair<uint16_t, rte_flow*>> destroyed;
std::vector<void*> allocations;
size_t allocation_calls = 0;
int failing_port = -1;
bool fail_destroy = false;
uintptr_t next_handle = 1;

class RteFlowTest : public ::testing::Test
{
	void SetUp() override
	{
		rules.clear();
		destroyed.clear();
		allocation_calls = 0;
		failing_port = -1;
		fail_destroy = false;
		next_handle = 1;
	}

	void TearDown() override
	{
		for (void* allocation : allocations)
		{
			std::free(allocation);
		}
		allocations.clear();
	}
};

template<typename T>
void ExpectItem(const T& actual, const T& expected)
{
	EXPECT_EQ(0, std::memcmp(&actual, &expected, sizeof(T)));
}
}

extern "C" rte_flow* __wrap_rte_flow_create(uint16_t port,
                                            const rte_flow_attr* attr,
                                            const rte_flow_item* pattern,
                                            const rte_flow_action* actions,
                                            rte_flow_error* error)
{
	EXPECT_EQ(1u, attr->ingress);
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_ETH, pattern[0].type);
	FlowRule rule{};
	rule.port = port;
	rule.priority = attr->priority;
	rule.type = pattern[1].type;
	if (pattern[0].spec)
	{
		rule.eth_spec = *static_cast<const rte_flow_item_eth*>(pattern[0].spec);
		rule.eth_mask = *static_cast<const rte_flow_item_eth*>(pattern[0].mask);
	}
	if (pattern[1].spec)
	{
		if (pattern[1].type == RTE_FLOW_ITEM_TYPE_IPV4)
		{
			rule.ipv4_spec = *static_cast<const rte_flow_item_ipv4*>(pattern[1].spec);
			rule.ipv4_mask = *static_cast<const rte_flow_item_ipv4*>(pattern[1].mask);
		}
		else if (pattern[1].type == RTE_FLOW_ITEM_TYPE_IPV6)
		{
			rule.ipv6_spec = *static_cast<const rte_flow_item_ipv6*>(pattern[1].spec);
			rule.ipv6_mask = *static_cast<const rte_flow_item_ipv6*>(pattern[1].mask);
		}
	}
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_END, pattern[rule.type == RTE_FLOW_ITEM_TYPE_END ? 1 : 2].type);
	EXPECT_EQ(RTE_FLOW_ACTION_TYPE_END, actions[1].type);
	if (actions[0].type == RTE_FLOW_ACTION_TYPE_QUEUE)
	{
		rule.queue = static_cast<const rte_flow_action_queue*>(actions[0].conf)->index;
	}
	else
	{
		EXPECT_EQ(RTE_FLOW_ACTION_TYPE_RSS, actions[0].type);
		const auto& rss = *static_cast<const rte_flow_action_rss*>(actions[0].conf);
		EXPECT_EQ(RTE_ETH_HASH_FUNCTION_DEFAULT, rss.func);
		EXPECT_EQ(0u, rss.level);
		EXPECT_EQ(RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP, rss.types);
		EXPECT_EQ(nullptr, pattern[1].spec);
		EXPECT_EQ(nullptr, pattern[1].mask);
		rule.rss_queues.assign(rss.queue, rss.queue + rss.queue_num);
	}
	if (port == failing_port)
	{
		error->message = "injected creation failure";
	}
	else
	{
		rule.handle = reinterpret_cast<rte_flow*>(next_handle++);
	}
	rules.push_back(rule);
	return rule.handle;
}

extern "C" int __wrap_rte_flow_destroy(uint16_t port, rte_flow* flow, rte_flow_error* error)
{
	destroyed.emplace_back(port, flow);
	if (fail_destroy)
	{
		error->message = "injected destruction failure";
		return -1;
	}
	return 0;
}

extern "C" void* __wrap_rte_malloc(const char*, size_t size, unsigned)
{
	++allocation_calls;
	void* allocation = std::malloc(std::max(size, sizeof(rte_flow_item_ipv6)));
	std::memset(allocation, 0xa5, std::max(size, sizeof(rte_flow_item_ipv6)));
	allocations.push_back(allocation);
	return allocation;
}

extern "C" void __wrap_rte_free(void* allocation)
{
	allocations.erase(std::remove(allocations.begin(), allocations.end(), allocation), allocations.end());
	std::free(allocation);
}

TEST_F(RteFlowTest, IPv6PrefixUsesCompleteZeroedItems)
{
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 7);
	storage.UpdatePrefixes({common::ip_prefix_t("2001:db8:1234:5680::/57")});
	ASSERT_EQ(1u, rules.size());
	rte_flow_item_ipv6 spec{};
	rte_flow_item_ipv6 mask{};
	const uint8_t address[] = {0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x80};
	const uint8_t prefix_mask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80};
	std::memcpy(spec.hdr.dst_addr, address, sizeof(address));
	std::memcpy(mask.hdr.dst_addr, prefix_mask, sizeof(prefix_mask));
	ExpectItem(rules[0].ipv6_spec, spec);
	ExpectItem(rules[0].ipv6_mask, mask);
	EXPECT_EQ(7u, rules[0].queue);
}

TEST_F(RteFlowTest, IPv4PrefixMatchesOnlyDestination)
{
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 7);
	storage.UpdatePrefixes({common::ip_prefix_t("192.0.2.128/25")});
	ASSERT_EQ(1u, rules.size());
	rte_flow_item_ipv4 spec{};
	rte_flow_item_ipv4 mask{};
	spec.hdr.dst_addr = rte_cpu_to_be_32(0xc0000280);
	mask.hdr.dst_addr = rte_cpu_to_be_32(0xffffff80);
	ExpectItem(rules[0].ipv4_spec, spec);
	ExpectItem(rules[0].ipv4_mask, mask);
	EXPECT_EQ(7u, rules[0].queue);
}

TEST_F(RteFlowTest, StaticRulesPreserveTrafficSelectionAndRssQueues)
{
	CreateFlowsForIsolatedPort(2, 4, 1);
	ASSERT_EQ(5u, rules.size());
	rte_flow_item_eth spec{};
	rte_flow_item_eth mask{};
	const uint8_t stp[] = {0x01, 0x80, 0xc2, 0, 0, 0};
	std::memcpy(spec.hdr.dst_addr.addr_bytes, stp, sizeof(stp));
	std::memset(mask.hdr.dst_addr.addr_bytes, 0xff, sizeof(stp));
	ExpectItem(rules[0].eth_spec, spec);
	ExpectItem(rules[0].eth_mask, mask);
	for (size_t i = 1; i < 3; ++i)
	{
		spec = {};
		mask = {};
		spec.hdr.ether_type = rte_cpu_to_be_16(i == 1 ? RTE_ETHER_TYPE_ARP : RTE_ETHER_TYPE_LLDP);
		mask.hdr.ether_type = 0xffff;
		ExpectItem(rules[i].eth_spec, spec);
		ExpectItem(rules[i].eth_mask, mask);
	}
	for (size_t i = 0; i < 3; ++i)
	{
		EXPECT_EQ(1u, rules[i].queue);
		EXPECT_EQ(0u, rules[i].priority);
	}
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_IPV4, rules[3].type);
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_IPV6, rules[4].type);
	for (size_t i = 3; i < 5; ++i)
	{
		EXPECT_EQ((std::vector<uint16_t>{0, 2, 3}), rules[i].rss_queues);
		EXPECT_EQ(1u, rules[i].priority);
	}
}

TEST_F(RteFlowTest, TemporaryPatternsDoNotAllocateDpdkMemory)
{
	CreateFlowsForIsolatedPort(2, 4, 1);
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 1);
	storage.UpdatePrefixes({common::ip_prefix_t("192.0.2.0/24"), common::ip_prefix_t("2001:db8::/32")});
	EXPECT_EQ(0u, allocation_calls);
}

TEST_F(RteFlowTest, RepeatedUpdateRetriesOnlyPortWhoseCreationFailed)
{
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 1);
	storage.AddPortAndQueue(3, 4);
	const std::set<common::ip_prefix_t> prefixes{common::ip_prefix_t("192.0.2.0/24")};
	failing_port = 3;
	storage.UpdatePrefixes(prefixes);
	ASSERT_EQ(2u, rules.size());
	failing_port = -1;
	storage.UpdatePrefixes(prefixes);
	ASSERT_EQ(3u, rules.size());
	EXPECT_EQ(3u, rules.back().port);
	EXPECT_EQ(4u, rules.back().queue);
	storage.UpdatePrefixes(prefixes);
	EXPECT_EQ(3u, rules.size());
}

TEST_F(RteFlowTest, FailedDestroyRetainsHandleForNextUpdate)
{
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 1);
	storage.UpdatePrefixes({common::ip_prefix_t("192.0.2.0/24")});
	ASSERT_EQ(1u, rules.size());
	const auto handle = rules[0].handle;
	fail_destroy = true;
	storage.UpdatePrefixes({});
	fail_destroy = false;
	storage.UpdatePrefixes({});
	EXPECT_EQ((std::vector<std::pair<uint16_t, rte_flow*>>{{2, handle}, {2, handle}}), destroyed);
	storage.UpdatePrefixes({});
	EXPECT_EQ(2u, destroyed.size());
}

TEST_F(RteFlowTest, PrefixReintroducedAfterFailedDestroyReusesExistingFlow)
{
	RteFlowStorage storage;
	storage.AddPortAndQueue(2, 1);
	const std::set<common::ip_prefix_t> prefixes{common::ip_prefix_t("192.0.2.0/24")};
	storage.UpdatePrefixes(prefixes);
	fail_destroy = true;
	storage.UpdatePrefixes({});
	storage.UpdatePrefixes(prefixes);
	EXPECT_EQ(1u, rules.size());
	EXPECT_EQ(1u, destroyed.size());
}

TEST_F(RteFlowTest, UpdateCreatesFlowForPortRegisteredAfterPreviousUpdate)
{
	RteFlowStorage storage;
	const std::set<common::ip_prefix_t> prefixes{common::ip_prefix_t("192.0.2.0/24")};
	storage.UpdatePrefixes(prefixes);
	storage.AddPortAndQueue(2, 1);
	storage.UpdatePrefixes(prefixes);
	ASSERT_EQ(1u, rules.size());
	storage.AddPortAndQueue(2, 1);
	storage.UpdatePrefixes(prefixes);
	EXPECT_EQ(1u, rules.size());
}
