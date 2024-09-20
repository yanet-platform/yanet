#pragma once

#include <map>
#include <mutex>

#include "common/icp.h"
#include "common/idataplane.h"
#include "common/idp.h"

#include "module.h"
#include "route.h"
#include "type.h"

namespace telegraf
{

class generation_t
{
public:
	generation_t() = default;

	void update(const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		(void)base_prev;

		for (const auto& [module_name, dregress] : base_next.dregresses)
		{
			(void)module_name;

			communities.insert(dregress.communities.begin(), dregress.communities.end());
		}
		communities[{}] = "unknown";

		for (const auto& [module_name, route] : base_next.routes)
		{
			(void)module_name;

			peers.insert(route.peers.begin(), route.peers.end());
		}
		peers[0] = "unknown";
	}

	const std::map<community_t, std::string>* get_communities() const
	{
		return &communities;
	}

	const std::map<uint32_t, std::string>* get_peers() const
	{
		return &peers;
	}

public:
	std::map<community_t, std::string> communities; /// @todo: delete
	std::map<uint32_t, std::string> peers; ///< @todo: VRF
};

}

class telegraf_t : public module_t
{
public:
	telegraf_t();
	~telegraf_t() override = default;

	eResult init() override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	common::icp::telegraf_unsafe::response telegraf_unsafe();
	common::icp::telegraf_dregress::response telegraf_dregress();
	common::icp::telegraf_dregress_traffic::response telegraf_dregress_traffic();
	common::icp::telegraf_balancer_service::response telegraf_balancer_service();
	/// @todo: common::icp::telegraf_balancer_real::response telegraf_balancer_real();
	common::icp::telegraf_other::response telegraf_other();
	common::icp::telegraf_mappings::response telegraf_mappings();

protected:
	interface::dataPlane dataPlaneUnsafe;
	interface::dataPlane dataPlaneDregress;
	interface::dataPlane dataPlaneOther;

	generation_manager<telegraf::generation_t> generations;

	bool flagFirst;

	std::map<tCoreId, std::array<uint64_t, CONFIG_YADECAP_MBUFS_BURST_SIZE + 1>> prevWorkers;

	std::map<std::tuple<bool, uint32_t, common::ip_address_t>, std::array<common::uint64, 2>> route_tunnel_peer_counters; ///< @todo: gc
	std::map<route::tunnel_counter_key_t, std::array<uint64_t, 2>> dregress_traffic_counters_prev;
};
