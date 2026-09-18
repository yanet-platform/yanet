#include <rte_flow.h>

#include "rteflow.h"

namespace
{
rte_flow* CreateQueueFlow(uint16_t port_id, uint16_t isolated_queue, const rte_flow_item* pattern, const std::string& description)
{
	rte_flow_attr attr{};
	attr.ingress = 1;
	const rte_flow_action_queue queue_action{isolated_queue};
	const rte_flow_action actions[] = {
	        {RTE_FLOW_ACTION_TYPE_QUEUE, &queue_action},
	        {RTE_FLOW_ACTION_TYPE_END, nullptr}};
	rte_flow_error error{};
	auto* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
	{
		YANET_LOG_ERROR("Flow creation for %s port_id=%d, queue_id=%d failed: %s\n", description.c_str(), port_id, isolated_queue, error.message);
	}
	else
	{
		YANET_LOG_INFO("Created flow for %s port_id=%d, queue_id=%d\n", description.c_str(), port_id, isolated_queue);
	}
	return flow;
}

rte_flow* CreateFlowForIsolateIpPrefixOnQueue(uint16_t port_id, uint16_t isolated_queue, const common::ip_prefix_t& prefix)
{
	rte_flow_item pattern[3]{};
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	rte_flow_item_ipv4 ipv4_spec{};
	rte_flow_item_ipv4 ipv4_mask{};
	rte_flow_item_ipv6 ipv6_spec{};
	rte_flow_item_ipv6 ipv6_mask{};
	if (prefix.is_ipv4())
	{
		ipv4_spec.hdr.dst_addr = rte_cpu_to_be_32(prefix.get_ipv4().address());
		uint8_t mask_len = prefix.get_ipv4().mask();
		ipv4_mask.hdr.dst_addr = rte_cpu_to_be_32(mask_len == 0 || mask_len > 32 ? 0 : 0xFFFFFFFFu << (32u - mask_len));
		pattern[1] = {RTE_FLOW_ITEM_TYPE_IPV4, &ipv4_spec, nullptr, &ipv4_mask};
	}
	else
	{
		memcpy(ipv6_spec.hdr.dst_addr, prefix.get_ipv6().address().data(), 16);
		uint8_t mask_len = prefix.get_ipv6().mask();
		for (uint8_t i = 0; (i < mask_len) && (i < 128); i++)
		{
			ipv6_mask.hdr.dst_addr[i / 8] |= (1u << (7 - i % 8));
		}
		pattern[1] = {RTE_FLOW_ITEM_TYPE_IPV6, &ipv6_spec, nullptr, &ipv6_mask};
	}
	return CreateQueueFlow(port_id, isolated_queue, pattern, prefix.toString());
}

bool SetupRSSForPortWithIsolatedQueue(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue)
{
	rte_flow_attr attr{};
	attr.ingress = 1;
	attr.priority = 1;
	rte_flow_item pattern[3]{};
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	std::vector<uint16_t> queues;
	queues.reserve(queues_count);
	for (uint32_t i = 0; i < queues_count; i++)
	{
		if (i != isolated_queue)
		{
			queues.push_back(i);
		}
	}

	rte_flow_action_rss action_rss{};
	action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss.types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
	action_rss.queue_num = queues.size();
	action_rss.queue = queues.data();
	const rte_flow_action actions[] = {
	        {RTE_FLOW_ACTION_TYPE_RSS, &action_rss},
	        {RTE_FLOW_ACTION_TYPE_END, nullptr}};

	for (const auto type : {RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_IPV6})
	{
		pattern[1].type = type;
		rte_flow_error error{};
		if (!rte_flow_create(port_id, &attr, pattern, actions, &error))
		{
			YANET_LOG_ERROR("RSS flow IPv%d creation for port_id=%d and isolated queue=%d failed: %s\n", type == RTE_FLOW_ITEM_TYPE_IPV4 ? 4 : 6, port_id, isolated_queue, error.message);
			return false;
		}
		YANET_LOG_INFO("Created RSS flow IPv%d for port_id=%d and isolated queue=%d\n", type == RTE_FLOW_ITEM_TYPE_IPV4 ? 4 : 6, port_id, isolated_queue);
	}
	return true;
}
}

void CreateFlowsForIsolatedPort(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue)
{
	rte_flow_item_eth spec{};
	rte_flow_item_eth mask{};
	const rte_flow_item pattern[] = {
	        {RTE_FLOW_ITEM_TYPE_ETH, &spec, nullptr, &mask},
	        {RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};
	spec.hdr.dst_addr = {{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}};
	memset(mask.hdr.dst_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
	CreateQueueFlow(port_id, isolated_queue, pattern, "STP");

	for (const auto& [protocol, name] : {std::pair{RTE_ETHER_TYPE_ARP, "ARP"}, std::pair{RTE_ETHER_TYPE_LLDP, "LLDP"}})
	{
		spec = {};
		mask = {};
		spec.hdr.ether_type = rte_cpu_to_be_16(protocol);
		mask.hdr.ether_type = 0xffff;
		CreateQueueFlow(port_id, isolated_queue, pattern, name);
	}
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
				auto* flow = CreateFlowForIsolateIpPrefixOnQueue(port_id, queue_id, prefix);
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

		rte_flow_error error{};
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
