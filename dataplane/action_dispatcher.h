#pragma once

#include "base.h"
#include "metadata.h"
#include "worker.h"

#include <iostream>

namespace dataplane
{

struct ActionDispatcherArgs
{
	cWorker* worker;
	rte_mbuf* mbuf;
	metadata* meta;
	const base::generation* base;
};

template<FlowDirection Direction>
struct ActionDispatcher
{
	static void execute(const common::Actions& actions, const ActionDispatcherArgs& args)
	{
		for (const auto& action : actions.get_actions())
		{
			std::visit([&](const auto& act) {
				execute(act, actions.get_flow(), args);
			},
			           action.raw_action);
		}
	}

	static void execute(const common::DumpAction& action, const common::globalBase::tFlow& flow, const ActionDispatcherArgs& args)
	{
		auto ring_id = args.base->globalBase->dump_id_to_tag[action.dump_id];
		if (ring_id == -1)
		{
			return;
		}

		auto& ring = args.worker->dumpRings[ring_id];
		ring.write(args.mbuf, flow.type);
	}

	static void execute(const common::FlowAction& action, [[maybe_unused]] const common::globalBase::tFlow& flow, const ActionDispatcherArgs& args)
	{
		auto worker = args.worker;
		auto mbuf = args.mbuf;

		if (action.flow.type == common::globalBase::eFlowType::drop)
		{
			// Try to match against stateful dynamic rules. If so - a packet will be handled.
			if constexpr (Direction == FlowDirection::Egress)
			{
				if (worker->acl_egress_try_keepstate(mbuf))
				{
					return;
				}
			}
			else
			{
				if (worker->acl_try_keepstate(mbuf))
				{
					return;
				}
			}
		}

		worker->aclCounters[action.flow.counter_id]++;

		tAclId acl_id = 0;

		if constexpr (Direction == FlowDirection::Egress)
		{
			acl_id = args.meta->aclId;
		}
		else
		{
			acl_id = args.meta->flow.data.aclId;
		}

		if (action.flow.flags & (uint8_t)common::globalBase::eFlowFlags::log)
		{
			worker->acl_log(mbuf, action.flow, acl_id);
		}
		if (action.flow.flags & (uint8_t)common::globalBase::eFlowFlags::keepstate)
		{
			worker->acl_create_keepstate(mbuf, acl_id, action.flow);
		}

		if constexpr (Direction == FlowDirection::Egress)
		{
			worker->acl_egress_flow(mbuf, action.flow);
		}
		else
		{
			worker->acl_ingress_flow(mbuf, action.flow);
		}
	}

	static void execute([[maybe_unused]] const common::CheckStateAction& action, [[maybe_unused]] const common::globalBase::tFlow& flow, [[maybe_unused]] const ActionDispatcherArgs& args)
	{
		std::cout << "CheckStateAction matched" << std::endl;
		// Implementation here
	}
};

} // namespace dataplane
