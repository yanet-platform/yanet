#pragma once

#include "base.h"
#include "isystem.h"
#include "module.h"
#include "rib.h"
#include "type.h"

#include "common/generation.h"
#include "common/idataplane.h"
#include "common/refarray.h"

namespace dregress
{

using destination_t = std::tuple<ip_address_t, ///< nexthop
                                 uint32_t, ///< label
                                 std::set<community_t>,
                                 uint32_t, ///< peer_as
                                 uint32_t>; ///< origin_as

using value_key_t = std::tuple<std::tuple<std::string, ///< vrf
                                          uint32_t>, ///< priority
                               std::map<std::tuple<uint32_t, std::size_t, std::string, uint32_t>,
                                        std::set<dregress::destination_t>>>;

class generation_t
{
public:
	generation_t() = default;

	void update([[maybe_unused]] const controlplane::base_t& base_prev,
	            const controlplane::base_t& base_next)
	{
		routes = base_next.routes;
		dregresses = base_next.dregresses;

		/// @todo: VRF
		for (const auto& [moduleName, dregress] : dregresses)
		{
			YANET_GCC_BUG_UNUSED(moduleName);

			our_as.insert(dregress.ourAs.begin(), dregress.ourAs.end());
		}
	}

	[[nodiscard]] std::optional<community_t> get_peer_link_community(const std::set<community_t>& communities) const
	{
		/// @todo: VRF
		for (const auto& [moduleName, dregress] : dregresses)
		{
			YANET_GCC_BUG_UNUSED(moduleName);

			for (const auto& community : communities)
			{
				const auto iter = dregress.communities.find(community);
				if (iter != dregress.communities.end())
				{
					return community;
				}
			}
		}

		return std::nullopt;
	}

public:
	std::map<std::string, controlplane::route::config_t> routes;
	std::map<std::string, controlplane::dregress::config_t> dregresses;
	std::set<uint32_t> our_as; ///< @todo: VRF
};

}

class dregress_t : public module_t
{
public:
	dregress_t();

	eResult init() override;
	void limit(common::icp::limit_summary::response& limits) const override;
	void reload_before() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;
	void reload_after() override;

	void prefix_insert(const std::tuple<std::string, uint32_t>& vrf_priority, const ip_prefix_t& prefix, const rib::nexthop_map_t& nexthops);
	void prefix_remove(const std::tuple<std::string, uint32_t>& vrf_priority, const ip_prefix_t& prefix);

	void prefix_flush();

	common::icp::dregress_config::response dregress_config() const;

	void compile(common::idp::updateGlobalBase::request& globalbase, const dregress::generation_t& generation);

protected:
	std::optional<uint32_t> value_insert(const dregress::value_key_t& value_key);
	void value_remove(const dregress::value_key_t& value_key);
	void value_compile(common::idp::updateGlobalBase::request& globalbase, const dregress::generation_t& generation, const uint32_t& value_id, const dregress::value_key_t& value_key);

protected:
	interface::dataPlane dataplane;
	interface::system system;

	generation_manager<dregress::generation_t> generations;

	mutable std::mutex mutex;

	common::idp::updateGlobalBase::dregress_prefix_update::request dregress_prefix_update;
	common::idp::updateGlobalBase::dregress_prefix_remove::request dregress_prefix_remove;

	std::map<std::tuple<std::string, ///< vrf
	                    uint32_t>, ///< priority
	         std::map<ip_prefix_t,
	                  std::map<std::tuple<uint32_t, ///< local_preference
	                                      std::size_t, ///< aspath_size
	                                      std::string, ///< origin
	                                      uint32_t>, ///< med
	                           std::set<dregress::destination_t>>>>
	        prefixes;

	common::refarray_t<dregress::value_key_t, YANET_CONFIG_DREGRESS_VALUES_SIZE> values;

	std::set<ipv4_address_t> defaults_v4; ///< @todo: get from route_t
	std::set<ipv6_address_t> defaults_v6; ///< @todo: get from route_t

	std::set<uint64_t> value_ids_updated;
	bool update_neighbors;
};
