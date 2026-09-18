#include <rte_ethdev.h>
#include <rte_flow.h>

#include "rteflow.h"

namespace
{
rte_flow* CreateFlow(uint16_t port_id, const rte_flow_item* pattern, const rte_flow_action& action, uint32_t priority = 0)
{
	rte_flow_attr attr{};
	attr.ingress = 1;
	attr.priority = priority;
	const rte_flow_action actions[] = {
	        action,
	        {RTE_FLOW_ACTION_TYPE_END, nullptr}};
	rte_flow_error error{};
	auto* flow = rte_flow_create(port_id, &attr, pattern, actions, &error);
	if (!flow)
	{
		YANET_LOG_ERROR("Flow creation for port_id=%u, priority=%u failed: %s\n", port_id, priority, error.message ? error.message : "unknown error");
	}
	return flow;
}

bool EthernetArpMatchesVlan(uint16_t port_id, const rte_flow_action& action)
{
	rte_eth_dev_info info{};
	if (rte_eth_dev_info_get(port_id, &info) != 0 || !info.driver_name ||
	    strncmp(info.driver_name, "mlx5", 4) != 0)
	{
		return false;
	}

	// Verbs rejects has_vlan matching; its Ethernet EtherType match includes VLANs.
	rte_flow_item_eth spec{};
	spec.has_vlan = 1;
	const rte_flow_item pattern[] = {
	        {RTE_FLOW_ITEM_TYPE_ETH, &spec, nullptr, &spec},
	        {RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};
	const rte_flow_action actions[] = {action, {RTE_FLOW_ACTION_TYPE_END, nullptr}};
	rte_flow_attr attr{};
	attr.ingress = 1;
	rte_flow_error error{};
	return rte_flow_validate(port_id, &attr, pattern, actions, &error) == -ENOTSUP &&
	       error.type == RTE_FLOW_ERROR_TYPE_ITEM && error.cause == &pattern[0];
}

rte_flow* CreatePrefixFlow(uint16_t port_id, uint16_t isolated_queue, const common::ip_prefix_t& prefix)
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
		const auto mask_len = prefix.get_ipv4().mask();
		ipv4_mask.hdr.dst_addr = rte_cpu_to_be_32(mask_len == 0 || mask_len > 32 ? 0 : 0xFFFFFFFFu << (32u - mask_len));
		pattern[1] = {RTE_FLOW_ITEM_TYPE_IPV4, &ipv4_spec, nullptr, &ipv4_mask};
	}
	else
	{
		memcpy(ipv6_spec.hdr.dst_addr, prefix.get_ipv6().address().data(), 16);
		const auto mask_len = prefix.get_ipv6().mask();
		for (uint8_t i = 0; (i < mask_len) && (i < 128); i++)
		{
			ipv6_mask.hdr.dst_addr[i / 8] |= (1u << (7 - i % 8));
		}
		pattern[1] = {RTE_FLOW_ITEM_TYPE_IPV6, &ipv6_spec, nullptr, &ipv6_mask};
	}
	const rte_flow_action_queue queue{isolated_queue};
	return CreateFlow(port_id, pattern, {RTE_FLOW_ACTION_TYPE_QUEUE, &queue});
}

bool CreateForwardingFlows(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue, uint64_t rss_flags)
{
	std::vector<uint16_t> queues;
	queues.reserve(queues_count);
	for (uint16_t queue = 0; queue < queues_count; ++queue)
	{
		if (queue != isolated_queue)
		{
			queues.push_back(queue);
		}
	}

	if (queues.empty())
	{
		YANET_LOG_ERROR("No forwarding queues for port_id=%d\n", port_id);
		return false;
	}

	rte_flow_action_rss action_rss{};
	action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss.types = rss_flags;
	action_rss.queue_num = queues.size();
	action_rss.queue = queues.data();
	const rte_flow_action_queue action_queue{queues.front()};
	const rte_flow_action action = rss_flags
	                                       ? rte_flow_action{RTE_FLOW_ACTION_TYPE_RSS, &action_rss}
	                                       : rte_flow_action{RTE_FLOW_ACTION_TYPE_QUEUE, &action_queue};

	const rte_flow_item pattern[] = {
	        {RTE_FLOW_ITEM_TYPE_ETH, nullptr, nullptr, nullptr},
	        {RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};
	return CreateFlow(port_id, pattern, action, 1) != nullptr;
}
}

bool CreateFlowsForIsolatedPort(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue, uint64_t rss_flags)
{
	const rte_flow_action_queue queue{isolated_queue};
	const rte_flow_action action{RTE_FLOW_ACTION_TYPE_QUEUE, &queue};
	rte_flow_item_eth spec{};
	rte_flow_item_eth mask{};
	const rte_flow_item pattern[] = {
	        {RTE_FLOW_ITEM_TYPE_ETH, &spec, nullptr, &mask},
	        {RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};
	spec.hdr.dst_addr = {{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}};
	memset(mask.hdr.dst_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
	if (!CreateFlow(port_id, pattern, action))
	{
		return false;
	}

	for (const auto protocol : {RTE_ETHER_TYPE_ARP, RTE_ETHER_TYPE_LLDP})
	{
		spec = {};
		mask = {};
		spec.hdr.ether_type = rte_cpu_to_be_16(protocol);
		mask.hdr.ether_type = 0xffff;
		if (!CreateFlow(port_id, pattern, action))
		{
			return false;
		}
	}
	rte_flow_item_vlan vlan_spec{};
	rte_flow_item_vlan vlan_mask{};
	vlan_spec.hdr.eth_proto = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
	vlan_mask.hdr.eth_proto = 0xffff;
	const rte_flow_item vlan_pattern[] = {
	        {RTE_FLOW_ITEM_TYPE_ETH, nullptr, nullptr, nullptr},
	        {RTE_FLOW_ITEM_TYPE_VLAN, &vlan_spec, nullptr, &vlan_mask},
	        {RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};
	return (EthernetArpMatchesVlan(port_id, action) || CreateFlow(port_id, vlan_pattern, action)) &&
	       CreateForwardingFlows(port_id, queues_count, isolated_queue, rss_flags);
}

void RteFlowStorage::AddPortAndQueue(tPortId port_id, tQueueId queue_id)
{
	ports_and_queues_.insert({port_id, queue_id});
}

void RteFlowStorage::UpdatePrefixes(const std::set<common::ip_prefix_t>& prefixes)
{
	for (const common::ip_prefix_t& prefix : prefixes)
	{
		for (const auto& [port_id, queue_id] : ports_and_queues_)
		{
			const auto key = std::make_tuple(port_id, queue_id, prefix);
			if (flows_.count(key) == 0)
			{
				if (auto* flow = CreatePrefixFlow(port_id, queue_id, prefix))
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
			YANET_LOG_ERROR("Failed to delete isolation flow: prefix=%s, port=%u, queue=%u: %s\n", prefix.toString().c_str(), port_id, queue_id, error.message ? error.message : "unknown error");
			++iter;
		}
		else
		{
			iter = flows_.erase(iter);
		}
	}
}
