#include <gtest/gtest.h>
#include <rte_flow.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <type_traits>
#include <vector>

#include "dataplane/dataplane.h"

struct rte_flow
{};

namespace
{
class IsolationDataPlane : public cDataPlane
{
public:
	IsolationDataPlane()
	{
		config.use_kernel_interface = false;
	}

	using cDataPlane::config;
	using cDataPlane::parseJsonPorts;
	using cDataPlane::ports;
};

struct FlowRule
{
	uint16_t port;
	uint32_t priority;
	rte_flow_item_type type;
	rte_flow_action_type action;
	rte_flow_item_eth eth_spec{};
	rte_flow_item_eth eth_mask{};
	rte_flow_item_vlan vlan_spec{};
	rte_flow_item_vlan vlan_mask{};
	rte_flow_item_ipv4 ipv4_spec{};
	rte_flow_item_ipv4 ipv4_mask{};
	rte_flow_item_ipv6 ipv6_spec{};
	rte_flow_item_ipv6 ipv6_mask{};
	uint16_t queue = 0;
	uint64_t rss_types = 0;
	std::vector<uint16_t> rss_queues;
	rte_flow* handle = nullptr;
};

std::vector<FlowRule> rules;
std::vector<std::pair<uint16_t, rte_flow*>> destroyed;
std::deque<rte_flow> handles;
size_t allocation_calls = 0;
int failing_port = -1;
int failing_rule = -1;
bool fail_destroy = false;
const char* driver_name = "mlx5_pci";
bool supports_eth_vlan = true;
int validation_error = ENOTSUP;
rte_flow_error_type validation_error_type = RTE_FLOW_ERROR_TYPE_ITEM;
bool validation_item_cause = true;

class RteFlowTest : public ::testing::Test
{
protected:
	RteFlowStorage storage;
	const std::set<common::ip_prefix_t> prefixes{common::ip_prefix_t("192.0.2.0/24")};

	void SetUp() override
	{
		rules.clear();
		destroyed.clear();
		handles.clear();
		allocation_calls = 0;
		failing_port = -1;
		failing_rule = -1;
		fail_destroy = false;
		driver_name = "mlx5_pci";
		supports_eth_vlan = true;
		validation_error = ENOTSUP;
		validation_error_type = RTE_FLOW_ERROR_TYPE_ITEM;
		validation_item_cause = true;
		storage.AddPortAndQueue(2, 7);
	}
};

template<typename T>
void ExpectItem(const T& actual, const T& expected)
{
	static_assert(std::has_unique_object_representations_v<T>);
	EXPECT_EQ(0, std::memcmp(&actual, &expected, sizeof(T)));
}

void ExpectItem(const rte_flow_item_eth& actual, const rte_flow_item_eth& expected)
{
	ExpectItem(actual.hdr, expected.hdr);
	EXPECT_EQ(actual.has_vlan, expected.has_vlan);
	EXPECT_EQ(actual.reserved, expected.reserved);
}
}

extern "C" int __wrap_numa_node_of_cpu(int)
{
	return 0;
}

extern "C" int __wrap_rte_eth_dev_info_get(uint16_t, rte_eth_dev_info* info)
{
	*info = {};
	info->driver_name = driver_name;
	return 0;
}

extern "C" int __wrap_rte_flow_validate(uint16_t,
                                        const rte_flow_attr*,
                                        const rte_flow_item* pattern,
                                        const rte_flow_action*,
                                        rte_flow_error* error)
{
	if (pattern[0].type == RTE_FLOW_ITEM_TYPE_ETH && pattern[0].mask &&
	    static_cast<const rte_flow_item_eth*>(pattern[0].mask)->has_vlan && !supports_eth_vlan)
	{
		error->type = validation_error_type;
		error->cause = validation_item_cause ? &pattern[0] : nullptr;
		error->message = "mask enables non supported bits";
		return -validation_error;
	}
	return 0;
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
	rule.action = actions[0].type;
	if (pattern[0].spec)
	{
		rule.eth_spec = *static_cast<const rte_flow_item_eth*>(pattern[0].spec);
		rule.eth_mask = *static_cast<const rte_flow_item_eth*>(pattern[0].mask);
	}
	if (pattern[1].spec)
	{
		if (pattern[1].type == RTE_FLOW_ITEM_TYPE_VLAN)
		{
			rule.vlan_spec = *static_cast<const rte_flow_item_vlan*>(pattern[1].spec);
			rule.vlan_mask = *static_cast<const rte_flow_item_vlan*>(pattern[1].mask);
		}
		else if (pattern[1].type == RTE_FLOW_ITEM_TYPE_IPV4)
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
		rule.rss_types = rss.types;
		EXPECT_EQ(nullptr, pattern[1].spec);
		EXPECT_EQ(nullptr, pattern[1].mask);
		rule.rss_queues.assign(rss.queue, rss.queue + rss.queue_num);
	}
	if (!supports_eth_vlan && rule.type == RTE_FLOW_ITEM_TYPE_VLAN &&
	    !(rule.vlan_spec.hdr.vlan_tci & rule.vlan_mask.hdr.vlan_tci))
	{
		error->type = RTE_FLOW_ERROR_TYPE_ITEM_SPEC;
		error->cause = pattern[1].spec;
		error->message = "VLAN cannot be empty";
	}
	else if (port == failing_port || static_cast<int>(rules.size()) == failing_rule)
	{
		error->message = "injected creation failure";
	}
	else
	{
		rule.handle = &handles.emplace_back();
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
	void* allocation = std::malloc(size);
	if (allocation)
	{
		std::memset(allocation, 0xa5, size);
	}
	return allocation;
}

extern "C" void __wrap_rte_free(void* allocation)
{
	std::free(allocation);
}

TEST_F(RteFlowTest, IPv6PrefixUsesCompleteZeroedItems)
{
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
	ASSERT_TRUE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
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
	rte_flow_item_vlan vlan_spec{};
	rte_flow_item_vlan vlan_mask{};
	vlan_spec.hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	vlan_mask.hdr.eth_proto = 0xffff;
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_VLAN, rules[3].type);
	ExpectItem(rules[3].eth_mask, rte_flow_item_eth{});
	ExpectItem(rules[3].vlan_spec, vlan_spec);
	ExpectItem(rules[3].vlan_mask, vlan_mask);
	for (size_t i = 0; i < 4; ++i)
	{
		EXPECT_EQ(RTE_FLOW_ACTION_TYPE_QUEUE, rules[i].action);
		EXPECT_EQ(1u, rules[i].queue);
		EXPECT_EQ(0u, rules[i].priority);
	}
	EXPECT_EQ(RTE_FLOW_ITEM_TYPE_END, rules[4].type);
	ExpectItem(rules[4].eth_mask, rte_flow_item_eth{});
	EXPECT_EQ(RTE_ETH_RSS_IP, rules[4].rss_types);
	EXPECT_EQ((std::vector<uint16_t>{0, 2, 3}), rules[4].rss_queues);
	EXPECT_EQ(1u, rules[4].priority);
}

TEST_F(RteFlowTest, Mlx5VerbsUsesEthernetArpRuleForTaggedTraffic)
{
	supports_eth_vlan = false;
	for (const auto* driver : {"mlx5_pci", "mlx5_auxiliary"})
	{
		SCOPED_TRACE(driver);
		driver_name = driver;
		rules.clear();
		ASSERT_TRUE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
		ASSERT_EQ(4u, rules.size());
		EXPECT_EQ(RTE_FLOW_ITEM_TYPE_END, rules[1].type);
		EXPECT_EQ(rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP), rules[1].eth_spec.hdr.ether_type);
		EXPECT_EQ(0xffffu, rules[1].eth_mask.hdr.ether_type);
		EXPECT_EQ(0u, rules[1].eth_mask.has_vlan);
		EXPECT_EQ(1u, rules[1].queue);
		EXPECT_EQ((std::vector<uint16_t>{0, 2, 3}), rules.back().rss_queues);
	}
}

TEST_F(RteFlowTest, OtherDriversStillRequireTaggedArpRule)
{
	driver_name = "net_other";
	supports_eth_vlan = false;
	EXPECT_FALSE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
}

TEST_F(RteFlowTest, UnrelatedValidationErrorsDoNotBypassTaggedArpRule)
{
	supports_eth_vlan = false;
	for (const auto& [code, type] : {std::pair<int, rte_flow_error_type>{ENOMEM, RTE_FLOW_ERROR_TYPE_ITEM},
	                                 {ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION}})
	{
		SCOPED_TRACE(code);
		validation_error = code;
		validation_error_type = type;
		rules.clear();
		EXPECT_FALSE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
	}
	validation_error = ENOTSUP;
	validation_error_type = RTE_FLOW_ERROR_TYPE_ITEM;
	validation_item_cause = false;
	rules.clear();
	EXPECT_FALSE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
}

TEST_F(RteFlowTest, Mlx5VerbsPropagatesEveryRuleCreationFailure)
{
	supports_eth_vlan = false;
	for (failing_rule = 0; failing_rule < 4; ++failing_rule)
	{
		SCOPED_TRACE(failing_rule);
		rules.clear();
		EXPECT_FALSE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
		EXPECT_EQ(static_cast<size_t>(failing_rule + 1), rules.size());
	}
}

TEST_F(RteFlowTest, TemporaryPatternsDoNotAllocateDpdkMemory)
{
	ASSERT_TRUE(CreateFlowsForIsolatedPort(2, 4, 1, RTE_ETH_RSS_IP));
	storage.UpdatePrefixes({common::ip_prefix_t("192.0.2.0/24"), common::ip_prefix_t("2001:db8::/32")});
	EXPECT_EQ(0u, allocation_calls);
}

TEST_F(RteFlowTest, RepeatedUpdateRetriesOnlyPortWhoseCreationFailed)
{
	storage.AddPortAndQueue(3, 4);
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
	storage.UpdatePrefixes(prefixes);
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
	storage.UpdatePrefixes(prefixes);
	fail_destroy = true;
	storage.UpdatePrefixes({});
	storage.UpdatePrefixes(prefixes);
	EXPECT_EQ(1u, rules.size());
	EXPECT_EQ(1u, destroyed.size());
}

TEST_F(RteFlowTest, UpdateCreatesFlowForPortRegisteredAfterPreviousUpdate)
{
	RteFlowStorage late_storage;
	late_storage.UpdatePrefixes(prefixes);
	late_storage.AddPortAndQueue(2, 1);
	late_storage.UpdatePrefixes(prefixes);
	ASSERT_EQ(1u, rules.size());
	late_storage.AddPortAndQueue(2, 1);
	late_storage.UpdatePrefixes(prefixes);
	EXPECT_EQ(1u, rules.size());
}

TEST_F(RteFlowTest, AssignsDistinctIsolatedCoresToPortsOnSameSocket)
{
	IsolationDataPlane dataplane;
	dataplane.config.workers_isolated_cp = {8, 10};
	const nlohmann::json ports = {
	        {{"interfaceName", "first"}, {"pci", "first"}, {"coreIds", {4}}, {"rssFlags", {"IPV4"}}},
	        {{"interfaceName", "second"}, {"pci", "second"}, {"coreIds", {6}}, {"rssFlags", {"IPV4"}}}};

	ASSERT_EQ(dataplane.parseJsonPorts(ports), eResult::success);
	EXPECT_EQ(dataplane.config.workers.at(8), std::vector<std::string>{"first"});
	EXPECT_EQ(dataplane.config.workers.at(10), std::vector<std::string>{"second"});
}

TEST_F(RteFlowTest, UsesActualQueueMapForIsolatedAndOrdinaryTraffic)
{
	const std::vector<std::pair<nlohmann::json, uint64_t>> policies = {
	        {nullptr, RTE_ETH_RSS_IP},
	        {nlohmann::json::array({"IPV4"}), RTE_ETH_RSS_IPV4},
	        {nlohmann::json::array({"NONFRAG_IPV4_UDP"}), RTE_ETH_RSS_NONFRAG_IPV4_UDP},
	        {nlohmann::json::array({"NONFRAG_IPV4_TCP"}), RTE_ETH_RSS_NONFRAG_IPV4_TCP},
	        {nlohmann::json::array({"NONFRAG_IPV6_UDP"}), RTE_ETH_RSS_NONFRAG_IPV6_UDP},
	        {nlohmann::json::array({"NONFRAG_IPV6_TCP"}), RTE_ETH_RSS_NONFRAG_IPV6_TCP},
	        {nlohmann::json::array({"NONFRAG_IPV4_UDP", "NONFRAG_IPV6_TCP"}), RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_TCP},
	        {nlohmann::json::array(), 0}};
	for (const auto& [flags, rss_flags] : policies)
	{
		SCOPED_TRACE(flags.dump());
		rules.clear();
		IsolationDataPlane dataplane;
		dataplane.config.workers_isolated_cp = {2};
		nlohmann::json port = {{"interfaceName", "test"}, {"pci", "test"}, {"coreIds", {4, 6}}};
		if (!flags.is_null())
		{
			port["rssFlags"] = flags;
		}
		ASSERT_EQ(dataplane.parseJsonPorts(nlohmann::json::array({port})), eResult::success);
		dataplane.ports[7] = {"test", {{2, 0}, {4, 1}, {6, 2}}, 3, {}, "test", false};

		dataplane.StartIsolatedControlPlane();

		ASSERT_EQ(rules.size(), 5u);
		EXPECT_EQ(RTE_FLOW_ITEM_TYPE_END, rules.back().type);
		ExpectItem(rules.back().eth_mask, rte_flow_item_eth{});
		for (const auto& rule : rules)
		{
			EXPECT_EQ(rule.port, 7);
			const bool uses_rss = rule.priority == 1 && rss_flags != 0;
			EXPECT_EQ(rule.action, uses_rss ? RTE_FLOW_ACTION_TYPE_RSS : RTE_FLOW_ACTION_TYPE_QUEUE);
			if (uses_rss)
			{
				EXPECT_EQ(rule.rss_types, rss_flags);
				EXPECT_EQ(rule.rss_queues, (std::vector<uint16_t>{1, 2}));
			}
			else
			{
				EXPECT_EQ(rule.queue, rule.priority == 0 ? 0 : 1);
			}
		}
	}
}

TEST_F(RteFlowTest, StartupStopsIfAnySteeringRuleFails)
{
	IsolationDataPlane dataplane;
	dataplane.config.workers_isolated_cp = {2};
	ASSERT_EQ(dataplane.parseJsonPorts({{{"interfaceName", "test"}, {"pci", "test"}, {"coreIds", {4, 6}}}}), eResult::success);
	dataplane.ports[7] = {"test", {{2, 0}, {4, 1}, {6, 2}}, 3, {}, "test", false};
	for (failing_rule = 0; failing_rule < 5; ++failing_rule)
	{
		SCOPED_TRACE(failing_rule);
		EXPECT_DEATH(dataplane.StartIsolatedControlPlane(), "");
	}
}
