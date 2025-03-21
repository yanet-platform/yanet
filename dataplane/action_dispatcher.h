#pragma once

#include "base.h"
#include "metadata.h"
#include "worker.h"

#include "dump_rings.h"

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
	using Flow = common::globalBase::tFlow;
	using FlowFlags = common::globalBase::eFlowFlags;

	static void execute(const common::Actions& actions, const ActionDispatcherArgs& args)
	{
		std::visit([&](const auto& specific_actions) {
			execute_impl(specific_actions, args);
		},
		           actions);
	}

	/**
	 * Determine the correct path to execute based on the presence of a check-state action.
	 *
	 * If HasCheckState is true and the state check succeeds,
	 * it executes the check_state_path_ and then returns.
	 * Otherwise, it executes the default path. The egress/ingress flow
	 * is handled by the CheckStateAction execute method.
	 */
	template<common::ActionsPath Path>
	static void execute_impl(const common::BaseActions<Path>& actions, const ActionDispatcherArgs& args)
	{
		if constexpr (Path == common::ActionsPath::WithCheckState)
		{
			auto worker = args.worker;
			auto mbuf = args.mbuf;
			cWorker::FlowFromState flow;

			if constexpr (Direction == FlowDirection::Egress)
			{
				flow = worker->acl_egress_checkstate(mbuf);
			}
			else
			{
				flow = worker->acl_checkstate(mbuf);
			}

			YANET_LOG_DEBUG("Check state was matched and state was%s found\n", flow ? "" : " not");

			if (flow)
			{
				execute_path(actions.check_state_path(), flow.value(), args);
				return;
			}
		}

		// Execute default path
		execute_path(actions.default_path(), actions.get_flow(), args);
	}

	static void execute_path(const std::vector<common::Action>& actions, const Flow& flow, const ActionDispatcherArgs& args)
	{
		for (const auto& action : actions)
		{
			std::visit([&](const auto& act) {
				YANET_LOG_DEBUG("Executing action %s\n", act.to_string().c_str());
				execute(act, flow, args);
			},
			           action.raw_action);
		}
	}

	static void execute(const common::DumpAction& action, const Flow& flow, const ActionDispatcherArgs& args)
	{
		auto ring_id = args.base->globalBase->dump_id_to_tag[action.dump_id];
		if (ring_id == -1)
		{
			return;
		}

		cWorker* worker = args.worker;

		// polymorphic, will execute either DumpRingRaw or DumpRingPcap method,
		// likely to be devirtualized
		worker->dump_rings[ring_id]->Write(args.mbuf, flow.type, worker->CurrentTime());
	}

	static void execute(const common::StateTimeoutAction& action, const Flow& flow, const ActionDispatcherArgs& args)
	{
		YANET_LOG_DEBUG("Asked to execute StateTimeoutAction, which should not occur. Check value_t::compile()\n");
	}

	static void execute(const common::FlowAction& action, [[maybe_unused]] const Flow& flow, const ActionDispatcherArgs& args)
	{
		auto worker = args.worker;
		auto mbuf = args.mbuf;

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

		if (action.flow.flags & (uint8_t)FlowFlags::log)
		{
			worker->acl_log(mbuf, action.flow, acl_id);
		}
		if (action.flow.flags & (uint8_t)FlowFlags::recordstate)
		{
			worker->acl_create_state(mbuf, acl_id, action.flow, action.timeout);
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

	static void execute([[maybe_unused]] const common::CheckStateAction& action, const Flow& flow, const ActionDispatcherArgs& args)
	{
		if constexpr (Direction == FlowDirection::Egress)
		{
			args.worker->acl_egress_flow(args.mbuf, flow);
		}
		else
		{
			args.worker->acl_ingress_flow(args.mbuf, flow);
		}
	}

	static void execute(const common::HitCountAction& action, const Flow& flow, const ActionDispatcherArgs& args)
	{
		auto worker = args.worker;
		auto mbuf = args.mbuf;

		worker->populate_hitcount_map(action.id, mbuf);
	}
};

} // namespace dataplane
