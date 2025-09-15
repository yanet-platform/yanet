#include <algorithm>

#include "controlplane.h"
#include "errors.h"
#include "proxy.h"

eResult proxy_t::init()
{
    service_counters.init(&controlPlane->counter_manager);

    controlPlane->register_command(common::icp::requestType::proxy_counters, [this]() {
		return proxy_counters();
	});
    controlPlane->register_command(common::icp::requestType::proxy_connections, [this](const common::icp::request& request) {
        return proxy_connections(std::get<common::icp::proxy_connections::request>(std::get<1>(request)));
    });
    controlPlane->register_command(common::icp::requestType::proxy_syn, [this](const common::icp::request& request) {
        return proxy_syn(std::get<common::icp::proxy_syn::request>(std::get<1>(request)));
    });
    controlPlane->register_command(common::icp::requestType::proxy_tables, [this](const common::icp::request& request) {
        return proxy_tables(std::get<common::icp::proxy_tables::request>(std::get<1>(request)));
    });
    controlPlane->register_command(common::icp::requestType::proxy_debug_counters_id, [this](const common::icp::request& request) {
        return proxy_debug_counters_id(std::get<common::icp::proxy_debug_counters_id::request>(std::get<1>(request)));
    });
    controlPlane->register_command(common::icp::requestType::proxy_blacklist, [this](const common::icp::request& request) {
        return proxy_blacklist(std::get<common::icp::proxy_blacklist::request>(std::get<1>(request)));
    });
    controlPlane->register_command(common::icp::requestType::proxy_blacklist_add, [this](const common::icp::request& request) {
        return proxy_blacklist_add(std::get<common::icp::proxy_blacklist_add::request>(std::get<1>(request)));
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

std::set<proxy_service_id_t> GetAllProxyServicesId(const controlplane::base_t& base)
{
    std::set<proxy_service_id_t> ids;
    for (const auto& iter_proxy : base.proxies)
    {
        for (const auto& iter_service : iter_proxy.second.services)
        {
            ids.insert(iter_service.second.service_id);
        }
    }
    return ids;
}

std::set<tSocketId> GetSockets(const controlplane::base_t& base)
{
    std::set<proxy_service_id_t> sockets;
    for (const auto& iter_proxy : base.proxies)
    {
        sockets.insert(iter_proxy.second.socket_id);
    }
    return sockets;
}

const controlplane::proxy::proxy_services& FindServicesOnSocket(const controlplane::base_t& base, tSocketId socket_id, const controlplane::proxy::proxy_services& default_result)
{
    for (const auto& [module, proxy] : base.proxies)
    {
        GCC_BUG_UNUSED(module);
        if (proxy.socket_id == socket_id)
        {
            return proxy.services;
        }
    }
    return default_result;
}

void proxy_t::reload(const controlplane::base_t& base_prev,
                     const controlplane::base_t& base_next,
                     common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);

	// get id's new services and removed
	std::set<proxy_service_id_t> ids_prev = GetAllProxyServicesId(base_prev);
	std::set<proxy_service_id_t> ids_next = GetAllProxyServicesId(base_next);
	std::vector<proxy_service_id_t> ids_remove, ids_insert;
	std::set_difference(ids_prev.begin(), ids_prev.end(), ids_next.begin(), ids_next.end(), std::back_inserter(ids_remove));
	std::set_difference(ids_next.begin(), ids_next.end(), ids_prev.begin(), ids_prev.end(), std::back_inserter(ids_insert));

	// update counters
	for (proxy_service_id_t service_id : ids_remove)
	{
		service_counters.remove(service_id);
	}
	for (proxy_service_id_t service_id : ids_insert)
	{
		service_counters.insert(service_id);
	}
	service_counters.allocate();

	// for each socket prepare requests
	std::set<tSocketId> sockets_all = GetSockets(base_prev);
	std::set<tSocketId> sockets_next = GetSockets(base_next);
	sockets_all.insert(sockets_next.begin(), sockets_next.end());
	controlplane::proxy::proxy_services empty;
	for (tSocketId socket_id : sockets_all)
	{
		const auto& services_prev = FindServicesOnSocket(base_prev, socket_id, empty);
		const auto& services_next = FindServicesOnSocket(base_next, socket_id, empty);

		for (const auto& iter_prev : services_prev)
		{
			if (services_next.find(iter_prev.first) == services_next.end())
			{
				// service removed
				proxy_service_id_t service_id = iter_prev.second.service_id;
				globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_remove,
				                        common::idp::updateGlobalBase::proxy_service_remove::request{socket_id, service_id});
			}
		}

		for (auto& iter_next : services_next)
		{
			const controlplane::proxy::service_t& service = iter_next.second;
			tCounterId counter_id = service_counters.get_id(service.service_id);
			globalbase.emplace_back(common::idp::updateGlobalBase::requestType::proxy_service_update,
			                        common::idp::updateGlobalBase::proxy_service_update::request{counter_id, service});
		}
	}
}

void proxy_t::reload_after()
{
    service_counters.release();
	generations_config.switch_generation();
	generations_config.next_unlock();
    controlPlane->proxy_services_ids.RemoveUnusedKeys();
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
    std::set<proxy_service_id_t> used_id;

	for (auto& [module, config] : config_proxies)
	{
		for (const auto& iter_service : config.services)
		{
            const controlplane::proxy::service_t& service = iter_service.second;
            proxy_service_id_t service_id = service.service_id;
            if (used_id.find(service_id) != used_id.end())
            {
                continue;
            }
            used_id.insert(service_id);

            std::string service_name = service.service;
            std::array<uint64_t, num_counters> counts;

			auto it = counters.find(service_id);
			if (it != counters.end())
			{
                for (size_t i = 0; i < num_counters; i++)
                    counts[i] = (it->second)[i];
			}

            response.emplace_back(service_id, service_name, service.proxy_addr.toString(), service.Protocol(), service.proxy_port, counts);
		}
	}

	return response;
}

common::icp::proxy_connections::response proxy_t::proxy_connections(const common::icp::proxy_connections::request& request) const
{
    common::icp::proxy_connections::response response;
    const std::string& service_name = request;

    generations_config.current_lock();
    std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
    generations_config.current_unlock();

    for (auto& [module, config] : config_proxies)
    {
        for (const auto& iter_service : config.services)
        {
            const controlplane::proxy::service_t& service = iter_service.second;
            if (service.service.find(service_name) != std::string::npos)
            {
                const auto& connections = dataplane.proxy_connections(service.service_id);
                for (const auto& connection : connections)
                    response.push_back(std::tuple_cat(std::make_tuple(service.service), connection));
            }
        }
    }

    return response;
}

common::icp::proxy_syn::response proxy_t::proxy_syn(const common::icp::proxy_syn::request& request) const
{
    common::icp::proxy_syn::response response;
    const std::string& service_name = request;

    generations_config.current_lock();
    std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
    generations_config.current_unlock();

    for (auto& [module, config] : config_proxies)
    {
        for (const auto& iter_service : config.services)
        {
            const controlplane::proxy::service_t& service = iter_service.second;
            if (service.service.find(service_name) != std::string::npos)
            {
                const auto& syns = dataplane.proxy_syn(service.service_id);
                for (const auto& syn : syns)
                    response.push_back(std::tuple_cat(std::make_tuple(service.service), syn));
            }
        }
    }

    return response;
}

common::icp::proxy_tables::response proxy_t::proxy_tables(const common::icp::proxy_tables::request& request) const
{
    common::icp::proxy_tables::response response;
    const std::optional<std::string>& service_name = request;

    generations_config.current_lock();
    std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
    generations_config.current_unlock();

    common::idp::proxy_tables::request services;
    for (auto& [module, config] : config_proxies)
    {
        for (const auto& iter_service : config.services)
        {
            const controlplane::proxy::service_t& service = iter_service.second;
            if (service_name.has_value())
            {
                if (service.service.find(*service_name) != std::string::npos)
                {
                    services.emplace_back(service.service_id, service.socket_id, service.service);
                }
            }
            else
            {
                services.emplace_back(service.service_id, service.socket_id, service.service);
            }
        }
    }

    return dataplane.proxy_tables(services);
}

common::icp::proxy_debug_counters_id::response proxy_t::proxy_debug_counters_id(const common::icp::proxy_debug_counters_id::request& request)
{
    proxy_service_id_t service_id = request;
    tCounterId counter_id = service_counters.get_id(service_id);
    std::vector<std::string> names;
    for (tCounterId counter = 0; counter < static_cast<tCounterId>(proxy::service_counter::size); counter++)
	{
		names.push_back(proxy::service_counter_toString(static_cast<proxy::service_counter>(counter)));
	}
    return {counter_id, names};
}

common::icp::proxy_blacklist::response proxy_t::proxy_blacklist(const common::icp::proxy_blacklist::request& request)
{
    common::icp::proxy_blacklist::response response;
    const std::string& service_name = request;

    generations_config.current_lock();
    std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
    generations_config.current_unlock();

    for (auto& [module, config] : config_proxies)
    {
        for (const auto& iter_service : config.services)
        {
            const controlplane::proxy::service_t& service = iter_service.second;
            if (service.service.find(service_name) != std::string::npos)
            {
                const auto& blacklist = dataplane.proxy_blacklist(service.service_id);
                for (const auto& entry : blacklist)
                    response.push_back(std::tuple_cat(std::make_tuple(service.service), entry));
            }
        }
    }

    return response;
}

common::icp::proxy_blacklist_add::response proxy_t::proxy_blacklist_add(const common::icp::proxy_blacklist_add::request& request)
{
    common::icp::proxy_blacklist_add::response response;
    auto [service_name, address, timeout] = request;

    generations_config.current_lock();
    std::map<std::string, controlplane::proxy::config_t> config_proxies = generations_config.current().config_proxies;
    generations_config.current_unlock();

    for (auto& [module, config] : config_proxies)
    {
        for (const auto& iter_service : config.services)
        {
            const controlplane::proxy::service_t& service = iter_service.second;
            if (service.service == service_name)
            {
                dataplane.proxy_blacklist_add({service.service_id, address, timeout});
            }
        }
    }

    return response;
}