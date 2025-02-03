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

namespace balancer
{

using real_key_t = std::tuple<common::ip_address_t,
                              std::optional<uint16_t>>; ///< port

using service_key_t = std::tuple<common::ip_address_t,
                                 uint8_t, ///< proto
                                 std::optional<uint16_t>>; ///< port

using module_name = std::string;

using service_counter_key_t = std::tuple<module_name,
                                         service_key_t>;

using real_key_global_t = std::tuple<module_name,
                                     service_key_t,
                                     real_key_t>;

using real_counter_key_t = real_key_global_t;

class generation_config_t
{
public:
	generation_config_t() = default;

	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		for (const auto& [name, balancer] : base_next.balancers)
		{
			name_id[name] = balancer.balancer_id;
		}

		config_balancers = base_next.balancers;
		services_count = base_next.services_count;
		reals_count = base_next.reals_count;
	}

public:
	std::map<std::string, balancer_id_t> name_id;
	std::map<std::string, controlplane::balancer::config_t> config_balancers;
	uint64_t services_count{};
	uint64_t reals_count{};
};

class generation_services_t
{
public:
	generation_services_t() = default;

public:
	uint64_t reals_enabled_count{};
	common::icp::balancer_summary::response summary;
	common::icp::balancer_service::response services;
	common::icp::balancer_real_find::response reals;
	common::icp::balancer_announce::response announces;
};

}

class balancer_t : public module_t, common::icp_proto::BalancerService
{
public:
	eResult init() override;
	void limit(common::icp::limit_summary::response& limits) const override;
	void controlplane_values(common::icp::controlplane_values::response& controlplane_values) const override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::balancer_config::response balancer_config() const;
	common::icp::balancer_summary::response balancer_summary() const;
	common::icp::balancer_service::response balancer_service(const common::icp::balancer_service::request& request) const;
	common::icp::balancer_real_find::response balancer_real_find(const common::icp::balancer_real_find::request& request) const;
	void balancer_real(const common::icp::balancer_real::request& request);
	void balancer_real_flush(); ///< @todo: flush_thread
	common::icp::balancer_announce::response balancer_announce() const;

	void compile(common::idp::updateGlobalBase::request& globalbase, const balancer::generation_config_t& generation_config);

	void flush_reals(common::idp::updateGlobalBaseBalancer::request& balancer,
	                 const balancer::generation_config_t& generation_config);

	void update_service(const balancer::generation_config_t& generation_config,
	                    balancer::generation_services_t& generation_services);

protected:
	void counters_gc_thread();
	void reconfigure_wlc_thread();

protected:
	interface::dataPlane dataplane;

	generation_manager<balancer::generation_config_t> generations_config;
	generation_manager<balancer::generation_services_t> generations_services;

	mutable std::mutex reals_enabled_mutex;

	std::map<balancer::real_key_global_t, std::optional<uint32_t>> reals_enabled;

	std::map<balancer::real_key_global_t, std::optional<uint32_t>> reals_wlc_weight;

	// The set contains all reals touched after the last one flush operation
	std::set<balancer::real_key_global_t> real_updates;

	// The set contains all reals touched while the last one reload was fired
	std::set<balancer::real_key_global_t> real_reload_updates;
	// The flag is true when a pending reload is there
	bool in_reload;

	mutable std::mutex reals_unordered_mutex;
	mutable std::mutex config_switch_mutex;
	std::map<std::tuple<balancer::module_name,
	                    balancer::service_key_t,
	                    balancer::real_key_t>,
	         uint32_t>
	        reals_unordered;
	std::set<id_t> reals_unordered_ids_unused;

	friend class telegraf_t;
	counter_t<balancer::service_counter_key_t, (size_t)balancer::service_counter::size> service_counters;
	counter_t<balancer::real_counter_key_t, (size_t)balancer::real_counter::size> real_counters;

	void RealFind(google::protobuf::RpcController* controller, const common::icp_proto::BalancerRealFindRequest* request, common::icp_proto::BalancerRealFindResponse* response, google::protobuf::Closure* done) override;
	void Real(google::protobuf::RpcController* controller, const ::common::icp_proto::BalancerRealRequest* request, ::common::icp_proto::Empty* response, ::google::protobuf::Closure* done) override;
	void RealFlush(google::protobuf::RpcController* controller, const ::common::icp_proto::Empty* request, ::common::icp_proto::Empty* response, ::google::protobuf::Closure* done) override;

private:
	bool reconfigure_wlc();
	uint32_t calculate_wlc_weight(uint32_t weight, uint32_t connections, uint32_t weight_sum, uint32_t connection_sum, uint32_t wlc_power);

	template<typename Map>
	std::optional<typename Map::mapped_type::value_type> get_effective_weight(const Map& map, const balancer::real_key_global_t& key) const
	{
		auto it = map.find(key);
		if (it != map.end())
		{
			return it->second;
		}
		return std::nullopt;
	}
};
