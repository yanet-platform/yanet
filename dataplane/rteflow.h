#pragma once

#include "common.h"
#include "common/type.h"

[[nodiscard]] bool CreateFlowsForIsolatedPort(uint16_t port_id, uint16_t queues_count, uint16_t isolated_queue, uint64_t rss_flags);

class RteFlowStorage
{
public:
	void AddPortAndQueue(tPortId port_id, tQueueId queue_id);
	void UpdatePrefixes(const std::set<common::ip_prefix_t>& prefixes);

private:
	std::set<std::pair<tPortId, tQueueId>> ports_and_queues_;
	std::map<std::tuple<tPortId, tQueueId, common::ip_prefix_t>, struct rte_flow*> flows_;
};
