#include "controlplane.h"
#include "errors.h"
#include "proxy.h"

eResult proxy_t::init()
{
    service_counters.init(&controlPlane->counter_manager);

    controlPlane->register_command(common::icp::requestType::proxy_counters, [this]() {
		return proxy_counters();
	});

    controlPlane->register_service(this);

    funcThreads.emplace_back([this]() {
		counters_gc_thread();
	});

	return eResult::success;
}

void proxy_t::reload_before()
{
	generations_config.next_lock();
}

void proxy_t::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

    std::map<controlplane::proxy::service_t::key_t, controlplane::proxy::service_t> empty;
    auto& services_prev = (base_prev.proxies.empty() ? empty : base_prev.proxies.begin()->second.services);
    auto& services_next = (base_next.proxies.empty() ? empty : base_next.proxies.begin()->second.services);

    for (const auto& iter_prev : services_prev)
    {
        if (services_next.find(iter_prev.first) == services_next.end())
        {
            // service removed
            proxy_service_id_t service_id = iter_prev.second.service_id;
            service_counters.remove(service_id);
            globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_remove,
	                    common::idp::updateGlobalBase::proxy_or_service_remove::request{service_id});
        }
    }

    for (auto& iter_next : services_next)
    {
        const controlplane::proxy::service_t& service = iter_next.second;
        const auto iter_prev = services_prev.find(iter_next.first);
        if (iter_prev == services_prev.end())
        {
            // new service
            service_counters.insert(service.service_id);
            AddRequestUpdateService(globalbase, service);
        }
        else
        {
            // check, is service changed
            if (service.as_tuple() != iter_prev->second.as_tuple())
            {
                AddRequestUpdateService(globalbase, service);
            }
        }
    }

    service_counters.allocate();
	compile(globalbase, generations_config.next());
}

void proxy_t::reload_after()
{
    service_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
}

void proxy_t::compile(common::idp::updateGlobalBase::request& globalbase,
                      proxy::generation_config_t& generation_config)
{
    for (auto& [requestType, request] : globalbase)
    {
        if (requestType == common::idp::updateGlobalBase::requestType::proxy_service_update)
        {
            auto& request_update = std::get<common::idp::updateGlobalBase::proxy_service_update::request>(request);
            proxy_service_id_t service_id = std::get<0>(request_update);
            tCounterId counter_id = service_counters.get_id(service_id);
            std::get<0>(request_update) = counter_id;
        }
    }
}

void proxy_t::AddRequestUpdateService(common::idp::updateGlobalBase::request& globalbase, const controlplane::proxy::service_t& service)
{
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_update,
	                        common::idp::updateGlobalBase::proxy_service_update::request{0, service});
}

void proxy_t::counters_gc_thread()
{
	while (!flagStop)
	{
		service_counters.gc();

		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}

common::icp::proxy_counters::response proxy_t::proxy_counters() const
{
	common::icp::proxy_counters::response response;

	generations_config.current_lock();
	std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
	generations_config.current_unlock();

	const auto counters = service_counters.get_counters();
    constexpr size_t num_counters = static_cast<size_t>(proxy::service_counter::size);

	for (auto& [module, config] : config_proxies)
	{
		for (const auto& iter_service : config.services)
		{
            const controlplane::proxy::service_t& service = iter_service.second;
            proxy_service_id_t service_id = service.service_id;
            std::string service_name = service.service;
            std::array<uint64_t, num_counters> counts;

			auto it = counters.find(service_id);
			if (it != counters.end())
			{
                for (size_t i = 0; i < num_counters; i++)
                    counts[i] = (it->second)[i];
			}

            response.emplace_back(service_id, service_name, counts);
		}
	}

	return response;
}
