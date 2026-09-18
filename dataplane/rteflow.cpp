#include <rte_flow.h>

#include "rteflow.h"

bool CreateFlowForIsolateEthernerProtocolOnQueue(uint16_t port_id, uint16_t isolated_queue, uint16_t protocol_type, const char* protocol_name)
{
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	// Prepare patterns
	struct rte_flow_item pattern[2];
	memset(&pattern[0], 0, sizeof(pattern[0]));
	memset(&pattern[1], 0, sizeof(pattern[1]));

	// Pattern 0 - Ethernet - Type
	struct rte_flow_item_eth spec;
	memset(&spec, 0, sizeof(spec));
	spec.type = rte_cpu_to_be_16(protocol_type);
	struct rte_flow_item_eth mask;
	memset(&mask, 0, sizeof(mask));
	mask.type = 0xFFFF;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &spec;
	pattern[0].mask = &mask;
	// Pattern 1 - End
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	// Prepare actions
	struct rte_flow_action_queue queue_action = {.index = isolated_queue};
	struct rte_flow_action actions[2];
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue_action;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	// Create flow
	struct rte_flow* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
	{
		YANET_LOG_ERROR("Flow creation for %s port_id=%d, queue_id=%d failed: %s\n", protocol_name, port_id, isolated_queue, error.message);
		return false;
	}
	YANET_LOG_INFO("Created flow for %s port_id=%d, queue_id=%d\n", protocol_name, port_id, isolated_queue);

	return true;
}

bool CreateFlowForIsolateEthernerDstMacOnQueue(uint16_t port_id, uint16_t isolated_queue, uint8_t* dst_mac, uint8_t* dst_mac_mask, const char* protocol_name)
{
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	// Prepare patterns
	struct rte_flow_item pattern[2];
	memset(&pattern[0], 0, sizeof(pattern[0]));
	memset(&pattern[1], 0, sizeof(pattern[1]));

	struct rte_flow_item_eth spec
	{};
	struct rte_flow_item_eth mask
	{};
	memcpy(spec.hdr.dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	memcpy(mask.hdr.dst_addr.addr_bytes, dst_mac_mask, RTE_ETHER_ADDR_LEN);
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &spec;
	pattern[0].mask = &mask;

	// Pattern 1 - End
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	// Prepare actions
	struct rte_flow_action_queue queue_action = {.index = isolated_queue};
	struct rte_flow_action actions[2];
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue_action;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	// Create flow
	struct rte_flow* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
	{
		YANET_LOG_ERROR("Flow creation for %s port_id=%d, queue_id=%d failed: %s\n", protocol_name, port_id, isolated_queue, error.message);
		return false;
	}
	YANET_LOG_INFO("Created flow for %s port_id=%d, queue_id=%d, dst=%s/%s\n", protocol_name, port_id, isolated_queue, common::mac_address_t(spec.hdr.dst_addr.addr_bytes).toString().c_str(), common::mac_address_t(mask.hdr.dst_addr.addr_bytes).toString().c_str());

	return true;
}

struct rte_flow* CreateFlowForIsolateIpPrefixOnQueue(uint16_t port_id, uint16_t isolated_queue, const common::ip_prefix_t& prefix)
{
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	// Prepare patterns
	struct rte_flow_item pattern[3];
	memset(&pattern[0], 0, sizeof(pattern[0]));
	memset(&pattern[1], 0, sizeof(pattern[1]));
	memset(&pattern[2], 0, sizeof(pattern[2]));

	// Pattern 0 - Ethernet
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	// Pattern 1 - IPv4 or IPv6 - filter on dst prefix
	struct rte_flow_item_ipv4 ipv4_spec
	{};
	struct rte_flow_item_ipv4 ipv4_mask
	{};
	struct rte_flow_item_ipv6 ipv6_spec
	{};
	struct rte_flow_item_ipv6 ipv6_mask
	{};
	if (prefix.is_ipv4())
	{
		ipv4_spec.hdr.dst_addr = rte_cpu_to_be_32(prefix.get_ipv4().address());
		uint8_t mask_len = prefix.get_ipv4().mask();
		ipv4_mask.hdr.dst_addr = rte_cpu_to_be_32(mask_len == 0 || mask_len > 32 ? 0 : 0xFFFFFFFFu << (32u - mask_len));
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
		pattern[1].spec = &ipv4_spec;
		pattern[1].mask = &ipv4_mask;
	}
	else
	{
		memcpy(ipv6_spec.hdr.dst_addr, prefix.get_ipv6().address().data(), 16);
		uint8_t mask_len = prefix.get_ipv6().mask();
		for (uint8_t i = 0; (i < mask_len) && (i < 128); i++)
		{
			ipv6_mask.hdr.dst_addr[i / 8] |= (1u << (7 - i % 8));
		}
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
		pattern[1].spec = &ipv6_spec;
		pattern[1].mask = &ipv6_mask;
	}

	// Pattern 2 - End
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	// Prepare actions
	struct rte_flow_action_queue queue_action = {.index = isolated_queue};
	struct rte_flow_action actions[2];
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue_action;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	// Create flow
	struct rte_flow* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
	{
		YANET_LOG_ERROR("Flow creation port_id=%d, queue_id=%d, prefix=%s failed: %s\n", port_id, isolated_queue, prefix.toString().c_str(), error.message);
		return nullptr;
	}

	YANET_LOG_INFO("Created flow port_id=%d, queue_id=%d, prefix=%s\n", port_id, isolated_queue, prefix.toString().c_str());
	return flow;
}

bool SetupRSSForPortWithIsolatedQueue(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue)
{
	struct rte_flow_error error;
	struct rte_flow_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	attr.priority = 1;

	// Prepare patterns
	struct rte_flow_item pattern[3];
	memset(&pattern[0], 0, sizeof(pattern[0]));
	memset(&pattern[1], 0, sizeof(pattern[1]));
	memset(&pattern[2], 0, sizeof(pattern[2]));

	// Pattern 0 - Ethernet
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = nullptr;
	// Pattern 1 - IPv4 or IPv6 without restrictions on addresses
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = nullptr;
	pattern[1].mask = nullptr;
	// Pattern 1 - End
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	// Prepare actions
	std::vector<uint16_t> queues;
	queues.reserve(queues_count);
	for (uint32_t i = 0; i < queues_count; i++)
	{
		if (i != isolated_queue)
		{
			queues.push_back(i);
		}
	}

	struct rte_flow_action_rss action_rss = {
	        .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
	        .level = 0,
	        .types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
	        .key_len = 0,
	        .queue_num = (uint32_t)queues.size(),
	        .key = nullptr,
	        .queue = queues.data(),
	};

	struct rte_flow_action actions[2];
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	actions[0].conf = &action_rss;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	// Create flows for IPv4 and IPv6
	for (int kind = 0; kind < 2; kind++)
	{
		pattern[1].type = (kind == 0 ? RTE_FLOW_ITEM_TYPE_IPV4 : RTE_FLOW_ITEM_TYPE_IPV6);
		struct rte_flow* flow_default = rte_flow_create(port_id, &attr, pattern, actions, &error);
		if (!flow_default)
		{
			YANET_LOG_ERROR("RSS flow IPv%d creation for port_id=%d and isolated queue=%d failed: %s\n", (kind == 0 ? 4 : 6), port_id, isolated_queue, error.message);
			return false;
		}

		YANET_LOG_INFO("Created RSS flow IPv%d for port_id=%d and isolated queue=%d\n", (kind == 0 ? 4 : 6), port_id, isolated_queue);
	}

	return true;
}

void CreateFlowsForIsolatedPort(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue)
{
	uint8_t stp_mac[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
	uint8_t stp_mac_mask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	CreateFlowForIsolateEthernerDstMacOnQueue(port_id, isolated_queue, stp_mac, stp_mac_mask, "STP");

	CreateFlowForIsolateEthernerProtocolOnQueue(port_id, isolated_queue, RTE_ETHER_TYPE_ARP, "ARP");
	CreateFlowForIsolateEthernerProtocolOnQueue(port_id, isolated_queue, RTE_ETHER_TYPE_LLDP, "LLDP");
	SetupRSSForPortWithIsolatedQueue(port_id, queues_count, isolated_queue);
}

void RteFlowStorage::AddPortAndQueue(tPortId port_id, tQueueId queue_id)
{
	ports_and_queues_.insert({port_id, queue_id});
}

void RteFlowStorage::UpdatePrefixes(const std::set<common::ip_prefix_t>& prefixes)
{
	for (const common::ip_prefix_t& prefix : prefixes)
	{
		for (auto [port_id, queue_id] : ports_and_queues_)
		{
			auto key = std::make_tuple(port_id, queue_id, prefix);
			if (flows_.count(key) == 0)
			{
				struct rte_flow* flow = CreateFlowForIsolateIpPrefixOnQueue(port_id, queue_id, prefix);
				if (flow != nullptr)
				{
					flows_.emplace(key, flow);
				}
			}
		}
	}

	for (auto iter = flows_.begin(); iter != flows_.end();)
	{
		const auto& [port_id, queue_id, prefix] = iter->first;
		if (prefixes.count(prefix) != 0)
		{
			++iter;
			continue;
		}

		struct rte_flow_error error
		{};
		if (rte_flow_destroy(port_id, iter->second, &error))
		{
			YANET_LOG_ERROR("error delete isolated cp flow for prefix: %s, port: %d, queue: %d, message: %s\n", prefix.toString().c_str(), port_id, queue_id, error.message);
			++iter;
		}
		else
		{
			YANET_LOG_INFO("deleted isolated cp flow for prefix: %s, port: %d, queue: %d\n", prefix.toString().c_str(), port_id, queue_id);
			iter = flows_.erase(iter);
		}
	}
}
