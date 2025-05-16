#include "proxy.h"
#include "controlplane.h"

eResult proxy_t::init()
{
    service_counters.init(&controlPlane->counter_manager);

    controlPlane->register_command(common::icp::requestType::proxy_services, [this]() {
		return proxy_services();
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

    // remove old proxies
    for (const auto& [module_name, config] : base_prev.proxies)
    {
        if (base_next.proxies.find(module_name) == base_next.proxies.end())
        {
            std::optional<proxy_id_t> proxy_id = RemoveModule(globalbase, module_name);
            if (proxy_id.has_value())
            {
                for (const auto& service : config.services)
                {
                    RemoveService(globalbase, *proxy_id, service);
                }
            }
        }
    }

    // add new proxies and update existing
    for (const auto& [module_name, config] : base_next.proxies)
    {
        auto iter_prev = base_prev.proxies.find(module_name);
        if (iter_prev == base_prev.proxies.end())
        {
            // new
            std::optional<proxy_id_t> proxy_id = AddModule(globalbase, module_name, config);
            if (proxy_id.has_value())
            {
                for (const auto& service : config.services)
                {
                    for (const auto& prefix : config.local_pool)
                    {
                        AddPrefixToPool(globalbase, service.service_id, prefix);
                    }
                    AddService(globalbase, *proxy_id, service);
                }
            }
        }
        else
        {
            // existing
            std::optional<proxy_id_t> proxy_id = UpdateModule(globalbase, module_name, config);
            if (!proxy_id.has_value())
            {
                continue;
            }

            auto services_prev = iter_prev->second.BuildMapServices();
            auto services_next = config.BuildMapServices();

            // remove old services
            for (auto iter_serv_prev : services_prev)
            {
                if (services_next.find(iter_serv_prev.first) == services_next.end())
                {
                    RemoveService(globalbase, *proxy_id, *iter_serv_prev.second);
                }
            }

            for (auto iter_serv_next : services_next)
            {
                for (const auto& prefix : config.local_pool)
                {
                    if (iter_prev->second.local_pool.count(prefix) == 0)
                    {
                        AddPrefixToPool(globalbase, iter_serv_next.second->service_id, prefix);
                    }
                }
                auto iter_serv_prev = services_prev.find(iter_serv_next.first);
                if (iter_serv_prev == services_prev.end())
                {
                    // new
                    AddService(globalbase, *proxy_id, *iter_serv_next.second);
                }
                else
                {
                    // existing
                    UpdateService(globalbase, *proxy_id, *iter_serv_next.second);
                }
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
            std::get<1>(request_update) = counter_id;
            // YANET_LOG_WARNING("For service %d counter id: %d\n", service_id, counter_id);
        }
    }
}

std::optional<proxy_id_t> proxy_t::AddModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name, const controlplane::proxy::config_t& config)
{
    std::optional<proxy_id_t> proxy_id = proxy_assigner.Assign();
    if (!proxy_id.has_value())
    {
        YANET_LOG_ERROR("Can't assign id for proxy module: %s\n", module_name.c_str());
    }
    else
    {
        modules[module_name] = *proxy_id;
        // YANET_LOG_WARNING("MODULE add: %s, ID=%d\n", module_name.c_str(), *proxy_id);
        AddRequestUpdateProxy(globalbase, *proxy_id, config);
    }
    return proxy_id;
}

std::optional<proxy_id_t> proxy_t::UpdateModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name, const controlplane::proxy::config_t& config)
{
    auto iter = modules.find(module_name);
    if (iter == modules.end())
    {
        YANET_LOG_ERROR("not found module: %s\n", module_name.c_str());
        return std::nullopt;
    }
    proxy_id_t proxy_id = iter->second;
    // YANET_LOG_WARNING("MODULE update: %s, ID=%d\n", module_name.c_str(), proxy_id);
    AddRequestUpdateProxy(globalbase, proxy_id, config);
    return proxy_id;
}

std::optional<proxy_id_t> proxy_t::RemoveModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name)
{
    auto iter = modules.find(module_name);
    if (iter == modules.end())
    {
        YANET_LOG_ERROR("not found module: %s\n", module_name.c_str());
        return std::nullopt;
    }
    proxy_id_t proxy_id = iter->second;

    proxy_assigner.Free(proxy_id);
    modules.erase(module_name);
    // YANET_LOG_WARNING("MODULE remove: %s, ID=%d\n", module_name.c_str(), proxy_id);
    globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_remove,
                            common::idp::updateGlobalBase::proxy_or_service_remove::request{proxy_id});
    return proxy_id;
}

void proxy_t::AddPrefixToPool(common::idp::updateGlobalBase::request& globalbase, proxy_service_id_t service_id, const common::ip_prefix_t& prefix)
{
    // YANET_LOG_WARNING("LOCAL_POOL add: %s to ID=%d\n", prefix.toString().c_str(), proxy_id);
    globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_add_local_pool,
        common::idp::updateGlobalBase::proxy_add_local_pool::request{service_id, prefix});
}

void proxy_t::AddService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service)
{
    std::optional<proxy_id_t> service_id = services_assigner.Assign();
    if (!service_id.has_value())
    {
        YANET_LOG_ERROR("Can't assign id for service: %s\n", service.service.c_str());
        return;
    }
    service_counters.insert(*service_id);
    services[service.Key()] = *service_id;
    // YANET_LOG_WARNING("SERVICE add: %s:%d, IDs=%d to IDp=%d\n", service.proxy_addr.toString().c_str(), service.proxy_port, *service_id, proxy_id);
    AddRequestUpdateService(globalbase, proxy_id, *service_id, service);
}

void proxy_t::UpdateService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service)
{
    auto iter = services.find(service.Key());
    if (iter == services.end())
    {
        YANET_LOG_ERROR("not found service\n");
        return;
    }
    proxy_id_t service_id = iter->second;

    // YANET_LOG_WARNING("SERVICE update: %s:%d, ID=%d\n", service.proxy_addr.toString().c_str(), service.proxy_port, service_id);
    AddRequestUpdateService(globalbase, proxy_id, service_id, service);
}

void proxy_t::RemoveService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service)
{
    auto iter = services.find(service.Key());
    if (iter == services.end())
    {
        YANET_LOG_ERROR("not found service\n");
        return;
    }
    proxy_service_id_t service_id = iter->second;

    service_counters.remove(service_id);

    services.erase(service.Key());
    services_assigner.Free(service_id);
    // YANET_LOG_WARNING("SERVICE remove: %s:%d, ID=%d\n", service.proxy_addr.toString().c_str(), service.proxy_port, service_id);
    globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_remove,
	                    common::idp::updateGlobalBase::proxy_or_service_remove::request{service_id});
}

void proxy_t::AddRequestUpdateProxy(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::config_t& config)
{
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_update,
	                        common::idp::updateGlobalBase::proxy_update::request{proxy_id,
	                                                                             config.syn_type,
	                                                                             config.max_local_addresses,
	                                                                             config.mem_size_syn,
	                                                                             config.mem_size_connections,
	                                                                             config.timeout_syn,
	                                                                             config.timeout_connection,
	                                                                             config.timeout_fin,
	                                                                             config.flow});
}

void proxy_t::AddRequestUpdateService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, proxy_service_id_t service_id, const controlplane::proxy::service_t& config)
{
	globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_update,
	                        common::idp::updateGlobalBase::proxy_service_update::request{service_id,
	                                                                                     0,
	                                                                                     config.proxy_addr,
	                                                                                     config.proxy_port,
	                                                                                     config.service_addr,
	                                                                                     config.service_port,
                                                                                         config.proxy_header,
                                                                                         config.size_connections_table,
                                                                                         config.size_syn_table,
                                                                                         config.use_sack,
                                                                                         config.mss,
                                                                                         config.winscale});
}

void proxy_t::counters_gc_thread()
{
	while (!flagStop)
	{
		service_counters.gc();

		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}

common::icp::proxy_services::response proxy_t::proxy_services() const
{
	common::icp::proxy_services::response response;

	generations_config.current_lock();
	std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
	generations_config.current_unlock();

	const auto counters = service_counters.get_counters();

	for (auto& [module, config] : config_proxies)
	{
		for (controlplane::proxy::service_t& service : config.services)
		{
            proxy_service_id_t service_id = service.service_id;
            std::string service_name = service.service;
            uint64_t packets_in = 0;
            uint64_t bytes_in = 0;
            uint64_t packets_out = 0;
            uint64_t bytes_out = 0;
            uint64_t syn_count = 0;
            uint64_t ping_count = 0;
            uint64_t connections_count = 0;

			auto it = counters.find(service_id);
			if (it != counters.end())
			{
                packets_in = (it->second)[(tCounterId)proxy::service_counter::packets_in];
                bytes_in = (it->second)[(tCounterId)proxy::service_counter::bytes_in];
                packets_out = (it->second)[(tCounterId)proxy::service_counter::packets_out];
                bytes_out = (it->second)[(tCounterId)proxy::service_counter::bytes_out];
                syn_count = (it->second)[(tCounterId)proxy::service_counter::syn_count];
                ping_count = (it->second)[(tCounterId)proxy::service_counter::ping_count];
                connections_count = (it->second)[(tCounterId)proxy::service_counter::connections_count];
			}

            response.emplace_back(service_id, service_name, packets_in, bytes_in, packets_out, bytes_out, syn_count, ping_count, connections_count);
		}
	}

	return response;
}
