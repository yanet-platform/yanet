#pragma once

#include "base.h"
#include "counter.h"
#include "module.h"
#include "type.h"

#include "common/controlplaneconfig.h"
#include "common/counters.h"
#include "common/generation.h"
#include "common/icp.h"
#include "common/idataplane.h"
#include "libprotobuf/controlplane.pb.h"

#include <queue>

namespace proxy
{

using service_counter_key_t = proxy_service_id_t;

class generation_config_t
{
public:
	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		config_proxies = base_next.proxies;
	}

public:
	std::map<std::string, controlplane::proxy::config_t> config_proxies;
};

}

template <typename ValueType>
class IdAssigner
{
public:
    IdAssigner(ValueType size)
    {
        for (ValueType id = 1; id < size; id++)
        {
            ids_.push(id);
        }
    }

    std::optional<ValueType> Assign()
    {
        if (ids_.empty())
        {
            return std::nullopt;
        }

        ValueType result = ids_.front();
        ids_.pop();
        return result;
    }

    void Free(ValueType id)
    {
        ids_.push(id);
    }

private:
    std::queue<ValueType> ids_;
};

class proxy_t : public module_t, common::icp_proto::BalancerService
{
public:
    proxy_t() = default;
	~proxy_t() override = default;

	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	void compile(common::idp::updateGlobalBase::request& globalbase, proxy::generation_config_t& generation_config);

protected:
	interface::dataPlane dataplane;
	generation_manager<proxy::generation_config_t> generations_config;

    std::optional<proxy_id_t> AddModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name, const controlplane::proxy::config_t& config);
    std::optional<proxy_id_t> UpdateModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name, const controlplane::proxy::config_t& config);
    std::optional<proxy_id_t> RemoveModule(common::idp::updateGlobalBase::request& globalbase, const std::string& module_name);
    void AddService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service, const common::ipv4_prefix_t& prefix);
    void UpdateService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service, const common::ipv4_prefix_t& prefix);
    void RemoveService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::service_t& service);

    void AddRequestUpdateProxy(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, const controlplane::proxy::config_t& config);
    void AddRequestUpdateService(common::idp::updateGlobalBase::request& globalbase, proxy_id_t proxy_id, proxy_service_id_t service_id, const controlplane::proxy::service_t& config, const common::ipv4_prefix_t& prefix);

    void counters_gc_thread();

    common::icp::proxy_services::response proxy_services() const;

    std::map<std::string, proxy_id_t> modules;
    std::map<std::pair<common::ip_address_t, tPortId>, proxy_service_id_t> services;
    IdAssigner<proxy_id_t> proxy_assigner{YANET_CONFIG_PROXIES_SIZE};
    IdAssigner<proxy_service_id_t> services_assigner{YANET_CONFIG_PROXY_SERVICES_SIZE};

    counter_t<proxy::service_counter_key_t, (size_t)proxy::service_counter::size> service_counters;
};
