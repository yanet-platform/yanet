#include <gtest/gtest.h>
#include <rte_flow.h>

#include "dataplane/dataplane.h"

namespace
{

struct FlowAction
{
	tPortId port;
	rte_flow_action_type type;
	std::vector<uint16_t> queues;
};

std::vector<FlowAction> flow_actions;

class IsolationDataPlane : public cDataPlane
{
public:
	IsolationDataPlane()
	{
		mempool_log = nullptr;
		config.use_kernel_interface = false;
	}

	using cDataPlane::parseJsonPorts;

	void Isolate(std::set<tCoreId> cores)
	{
		config.workers_isolated_cp = std::move(cores);
	}

	const auto& Workers() const
	{
		return config.workers;
	}

	void AddPort(tPortId port, const std::map<tCoreId, tQueueId>& queues)
	{
		ports[port] = {"test", queues, static_cast<unsigned int>(queues.size()), {}, "test", false};
	}
};

TEST(ControlPlaneIsolation, AssignsDistinctIsolatedCoresToPortsOnSameSocket)
{
	IsolationDataPlane dataplane;
	dataplane.Isolate({8, 10});
	const nlohmann::json ports = {
	        {{"interfaceName", "first"}, {"pci", "first"}, {"coreIds", {4}}, {"rssFlags", {"IPV4"}}},
	        {{"interfaceName", "second"}, {"pci", "second"}, {"coreIds", {6}}, {"rssFlags", {"IPV4"}}}};

	ASSERT_EQ(dataplane.parseJsonPorts(ports), eResult::success);
	EXPECT_EQ(dataplane.Workers().at(8), std::vector<std::string>{"first"});
	EXPECT_EQ(dataplane.Workers().at(10), std::vector<std::string>{"second"});
}

TEST(ControlPlaneIsolation, UsesActualQueueMapForIsolatedAndOrdinaryTraffic)
{
	IsolationDataPlane dataplane;
	dataplane.Isolate({2});
	const nlohmann::json ports = {
	        {{"interfaceName", "test"}, {"pci", "test"}, {"coreIds", {4, 6}}, {"rssFlags", {"IPV4"}}}};
	ASSERT_EQ(dataplane.parseJsonPorts(ports), eResult::success);
	dataplane.AddPort(7, {{2, 0}, {4, 1}, {6, 2}});
	flow_actions.clear();

	dataplane.StartIsolatedControlPlane();

	ASSERT_EQ(flow_actions.size(), 5u);
	for (const auto& action : flow_actions)
	{
		EXPECT_EQ(action.port, 7);
		if (action.type == RTE_FLOW_ACTION_TYPE_QUEUE)
		{
			EXPECT_EQ(action.queues, std::vector<uint16_t>{0});
		}
		else
		{
			EXPECT_EQ(action.type, RTE_FLOW_ACTION_TYPE_RSS);
			EXPECT_EQ(action.queues, (std::vector<uint16_t>{1, 2}));
		}
	}
}

} // namespace

extern "C" int __wrap_numa_node_of_cpu(int)
{
	return 0;
}

extern "C" rte_flow* __wrap_rte_flow_create(uint16_t port,
                                            const rte_flow_attr*,
                                            const rte_flow_item[],
                                            const rte_flow_action actions[],
                                            rte_flow_error*)
{
	FlowAction action{port, actions[0].type, {}};
	if (action.type == RTE_FLOW_ACTION_TYPE_QUEUE)
	{
		action.queues.push_back(static_cast<const rte_flow_action_queue*>(actions[0].conf)->index);
	}
	else if (action.type == RTE_FLOW_ACTION_TYPE_RSS)
	{
		const auto& rss = *static_cast<const rte_flow_action_rss*>(actions[0].conf);
		action.queues.assign(rss.queue, rss.queue + rss.queue_num);
	}
	flow_actions.push_back(std::move(action));
	static int flow;
	return reinterpret_cast<rte_flow*>(&flow);
}
