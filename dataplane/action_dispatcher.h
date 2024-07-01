#pragma once

#include "base.h"
#include "metadata.h"
#include "worker.h"

#include <iostream>

namespace dataplane
{

template<FlowDirection Direction>
struct ActionDispatcher
{
	static void execute(const common::Actions& actions, cWorker* worker, rte_mbuf* mbuf, metadata* meta, const base::generation& base)
	{
		for (const auto& action : actions.get_actions())
		{
			std::visit([&](const auto& act) {
				execute(act, actions.get_flow(), worker, mbuf, meta, base);
			},
			           action.raw_action);
		}
	}

	static void execute(const common::DumpAction& action, const common::globalBase::tFlow& flow, cWorker* worker, rte_mbuf* mbuf, [[maybe_unused]] metadata* meta, const base::generation& base)
	{
		if (action.dump_id == 0)
		{
			return;
		}

		auto ring_id = base.globalBase->dump_id_to_tag[action.dump_id];
		if (ring_id == -1)
		{
			return;
		}

		auto& ring = worker->dumpRings[ring_id];
		ring.write(mbuf, flow.type);
	}

	static void execute(const common::FlowAction& action, [[maybe_unused]] const common::globalBase::tFlow& flow, cWorker* worker, rte_mbuf* mbuf, metadata* meta, [[maybe_unused]] const base::generation& base)
	{
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
			acl_id = meta->aclId;
		}
		else
		{
			acl_id = meta->flow.data.aclId;
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

	static void execute([[maybe_unused]] const common::CheckStateAction& action, [[maybe_unused]] const common::globalBase::tFlow& flow, [[maybe_unused]] cWorker* worker, [[maybe_unused]] rte_mbuf* mbuf, [[maybe_unused]] metadata* meta, [[maybe_unused]] const base::generation& base)
	{
		std::cout << "CheckStateAction matched" << std::endl;
		// Implementation here
	}
};

} // namespace dataplane
