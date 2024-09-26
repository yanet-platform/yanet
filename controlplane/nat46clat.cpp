#include "nat46clat.h"
#include "controlplane.h"

using namespace nat46clat;

void generation_config::update([[maybe_unused]] const controlplane::base_t& base_prev,
                               const controlplane::base_t& base_next)
{
	config_nat46clats = base_next.nat46clats;

	for (const auto& [module_name, nat46clat] : base_next.nat46clats)
	{
		for (const auto& prefix : nat46clat.announces)
		{
			announces.emplace_back(module_name, prefix);
		}
	}
}

eResult manager::init()
{
	controlPlane->register_counter(module_counters);

	controlPlane->register_command(common::icp::requestType::nat46clat_config, [this]() {
		return nat46clat_config();
	});

	controlPlane->register_command(common::icp::requestType::nat46clat_announce, [this]() {
		return nat46clat_announce();
	});

	controlPlane->register_command(common::icp::requestType::nat46clat_stats, [this]() {
		return nat46clat_stats();
	});

	funcThreads.emplace_back([this]() {
		counters_gc_thread();
	});

	return eResult::success;
}

void manager::reload_before()
{
	generations_config.next_lock();
}

void manager::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

	for (const auto& [module_name, nat46clat] : base_next.nat46clats)
	{
		YANET_GCC_BUG_UNUSED(nat46clat);

		module_counters.insert(module_name);
	}

	for (const auto& [module_name, nat46clat] : base_prev.nat46clats)
	{
		YANET_GCC_BUG_UNUSED(nat46clat);

		module_counters.remove(module_name);
	}

	module_counters.allocate();

	compile(globalbase, generations_config.next());
}

void manager::reload_after()
{
	module_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
}

common::icp::nat46clat_config::response manager::nat46clat_config() const
{
	auto config_current_guard = generations_config.current_lock_guard();
	return generations_config.current().config_nat46clats;
}

common::icp::nat46clat_announce::response manager::nat46clat_announce() const
{
	auto current_guard = generations_config.current_lock_guard();
	return generations_config.current().announces;
}

common::icp::nat46clat_stats::response manager::nat46clat_stats() const
{
	return module_counters.get_counters();
}

void manager::compile(common::idp::updateGlobalBase::request& globalbase,
                      generation_config& generation_config)
{
	for (const auto& [module_name, nat46clat] : generation_config.config_nat46clats)
	{
		const auto counter_id = module_counters.get_id(module_name);

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::nat46clat_update,
		                        common::idp::updateGlobalBase::nat46clat_update::request(nat46clat.nat46clat_id,
		                                                                                 nat46clat.ipv6_source,
		                                                                                 nat46clat.ipv6_destination,
		                                                                                 nat46clat.dscp_mark_type,
		                                                                                 nat46clat.dscp,
		                                                                                 counter_id,
		                                                                                 nat46clat.flow));
	}
}

void manager::counters_gc_thread()
{
	while (!flagStop)
	{
		module_counters.gc();
		std::this_thread::sleep_for(std::chrono::seconds(30));
	}
}
