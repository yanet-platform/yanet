#include "tun64.h"
#include "controlplane.h"

tun64_t::tun64_t()
{
}

tun64_t::~tun64_t()
{
}

eResult tun64_t::init()
{
	tunnel_counters.init(&controlPlane->counter_manager);
	mappings_counters.init(&controlPlane->counter_manager);

	controlPlane->register_command(common::icp::requestType::tun64_tunnels, [this]() {
		return tun64_tunnels();
	});

	controlPlane->register_command(common::icp::requestType::tun64_prefixes, [this]() {
		return tun64_prefixes();
	});

	controlPlane->register_command(common::icp::requestType::tun64_mappings, [this]() {
		return tun64_mappings();
	});

	funcThreads.emplace_back([this]() {
		counters_gc_thread();
	});

	return eResult::success;
}

void tun64_t::reload_before()
{
	generations_config.next_lock();
}

void tun64_t::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

	for (const auto& [name, tunnel] : base_next.tunnels)
	{
		tunnel_counters.insert(name);

		for (const auto& [ipv4_address, mapping] : tunnel.mappings)
		{
			(void)mapping;
			mappings_counters.insert({name, ipv4_address});
		}
	}

	for (const auto& [name, tunnel] : base_prev.tunnels)
	{
		tunnel_counters.remove(name);

		for (const auto& [ipv4_address, mapping] : tunnel.mappings)
		{
			(void)mapping;
			mappings_counters.remove({name, ipv4_address});
		}
	}

	tunnel_counters.allocate();
	mappings_counters.allocate();

	compile(globalbase, generations_config.next());
}

void tun64_t::reload_after()
{
	tunnel_counters.release();
	mappings_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
}

common::icp::tun64_config::response tun64_t::tun64_config() const
{
	auto current_guard = generations_config.current_lock_guard();
	return generations_config.current().config_tunnels;
}

common::icp::tun64_tunnels::response tun64_t::tun64_tunnels() const
{
	auto current_guard = generations_config.current_lock_guard();
	return generations_config.current().tunnels;
}

common::icp::tun64_mappings::response tun64_t::tun64_mappings() const
{
	common::icp::tun64_mappings::response response;

	{
		auto current_guard = generations_config.current_lock_guard();
		for (const auto& [module_name, mapping] : generations_config.current().mappings)
		{
			for (const auto& [ipv4_address, value] : mapping)
			{
				const auto& [ipv6_address, location] = value;

				response.emplace_back(module_name, ipv4_address, ipv6_address, location);
			}
		}
	}

	return response;
}

common::icp::tun64_prefixes::response tun64_t::tun64_prefixes() const
{
	auto current_guard = generations_config.current_lock_guard();
	return generations_config.current().prefixes;
}

void tun64_t::compile(common::idp::updateGlobalBase::request& globalbase,
                      tun64::generation_config_t& generation_config)
{
	for (auto& [name, tunnel] : generation_config.config_tunnels)
	{
		const auto counter_id = tunnel_counters.get_id(name);

		tunnel.flow.counter_id = counter_id;
		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tun64_update,
		                        common::idp::updateGlobalBase::tun64_update::request{tunnel.tun64Id,
		                                                                             tunnel.dscpMarkType,
		                                                                             tunnel.dscp,
		                                                                             tunnel.srcRndEnabled ? 1 : 0,
		                                                                             tunnel.ipv6SourceAddress,
		                                                                             tunnel.flow});

		common::idp::updateGlobalBase::tun64mappings_update::request tun64mappings_update_request;

		for (const auto& [ipv4_address, mapping] : tunnel.mappings)
		{
			const auto& [ipv6_address, location] = mapping;
			const auto counter_id = mappings_counters.get_id({name, ipv4_address});

			(void)location;
			tun64mappings_update_request.emplace_back(tunnel.tun64Id,
			                                          ipv4_address,
			                                          ipv6_address,
			                                          counter_id);
		}

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tun64mappings_update,
		                        tun64mappings_update_request);

		generation_config.tunnels[name] = {tunnel.ipv6SourceAddress,
		                                   tunnel.prefixes.size(),
		                                   tunnel.srcRndEnabled,
		                                   tunnel.nextModule};
		generation_config.prefixes[name] = tunnel.prefixes;
		generation_config.mappings[name] = tunnel.mappings;
	}
}

void tun64_t::counters_gc_thread()
{
	while (!flagStop)
	{
		tunnel_counters.gc();
		mappings_counters.gc();
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}
