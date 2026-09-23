#pragma once

#include <rte_flow.h>

#include "common.h"
#include "common/type.h"

[[nodiscard]] bool CreateFlowsForIsolatedPort(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue, uint64_t rss_flags);

class RteFlowStorage
{
public:
	void AddPortAndQueue(tPortId port_id, tQueueId queue_id);
	void UpdatePrefixes(const std::set<common::ip_prefix_t>& prefixes);
	[[nodiscard]] bool UpdateDscp(const std::set<uint8_t>& dscp);

private:
	std::set<std::pair<tPortId, tQueueId>> ports_and_queues_;
	std::map<std::tuple<tPortId, tQueueId, common::ip_prefix_t>, struct rte_flow*> flows_;
	std::map<std::tuple<tPortId, tQueueId, uint8_t, rte_flow_item_type>, rte_flow*> dscp_flows_;
};
