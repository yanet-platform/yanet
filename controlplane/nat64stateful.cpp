#include "nat64stateful.h"
#include "controlplane.h"

eResult nat64stateful_t::init()
{
	controlPlane->register_counter(module_counters);

	controlPlane->register_command(common::icp::requestType::nat64stateful_config, [this]() {
		return nat64stateful_config();
	});

	controlPlane->register_command(common::icp::requestType::nat64stateful_announce, [this]() {
		return nat64stateful_announce();
	});

	funcThreads.emplace_back([this]() {
		counters_gc_thread();
	});

	return eResult::success;
}

void nat64stateful_t::reload_before()
{
	generations_config.next_lock();
}

void nat64stateful_t::reload(const controlplane::base_t& base_prev,
                             const controlplane::base_t& base_next,
                             common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

	for (const auto& [name, nat64stateful] : base_next.nat64statefuls)
	{
		(void)nat64stateful;

		module_counters.insert(name);
	}

	for (const auto& [name, nat64stateful] : base_prev.nat64statefuls)
	{
		(void)nat64stateful;

		module_counters.remove(name);
	}

	module_counters.allocate();

	compile(globalbase, generations_config.next());
}

void nat64stateful_t::reload_after()
{
	module_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
}

common::icp::nat64stateful_config::response nat64stateful_t::nat64stateful_config() const
{
	auto config_current_guard = generations_config.current_lock_guard();
	return generations_config.current().config_nat64statefuls;
}

common::icp::nat64stateful_announce::response nat64stateful_t::nat64stateful_announce() const
{
	auto current_guard = generations_config.current_lock_guard();
	return generations_config.current().announces;
}

void nat64stateful_t::compile(common::idp::updateGlobalBase::request& globalbase,
                              nat64stateful::generation_config_t& generation_config)
{
	std::vector<ipv4_prefix_t> pool;

	uint32_t pool_start = 0;
	for (const auto& [name, nat64stateful] : generation_config.config_nat64statefuls)
	{
		const auto counter_id = module_counters.get_id(name);

		uint32_t pool_size = 0;
		for (const auto& ipv4_prefix : nat64stateful.ipv4_prefixes)
		{
			pool_size += (1u << (32 - ipv4_prefix.mask()));
			pool.emplace_back(ipv4_prefix);
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::nat64stateful_update,
		                        common::idp::updateGlobalBase::nat64stateful_update::request(nat64stateful.nat64stateful_id,
		                                                                                     nat64stateful.dscp_mark_type,
		                                                                                     nat64stateful.dscp,
		                                                                                     counter_id,
		                                                                                     pool_start,
		                                                                                     pool_size,
		                                                                                     nat64stateful.state_timeout,
		                                                                                     nat64stateful.flow));

		pool_start += pool_size;
	}

	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::nat64stateful_pool_update,
	                        std::move(pool));
}

void nat64stateful_t::counters_gc_thread()
{
	while (!flagStop)
	{
		module_counters.gc();
		std::this_thread::sleep_for(std::chrono::seconds(30));
	}
}
