#pragma once

#include "module.h"
#include <mutex>
#include <atomic>

namespace rib
{

using vrf_priority_t = common::rib::vrf_priority_t;

using pptn_t = common::rib::pptn_t;

using nexthop_stuff_t = common::rib::nexthop_stuff_t;

using nexthop_map_t = common::rib::nexthop_map_t;

using path_info_to_nexthop_stuff_ptr_t = common::rib::path_info_to_nexthop_stuff_ptr_t;

}

class rib_t : public cModule
{
public:
	rib_t() = default;
	~rib_t() override = default;

	eResult init() override;
	void reload(const controlplane::base_t& base_prev, const controlplane::base_t& base_next, common::idp::updateGlobalBase::request& globalbase) override;

	void rib_update(const common::icp::rib_update::request& request);
	void rib_flush(bool force_flush = false);

	common::icp::rib_summary::response rib_summary();
	common::icp::rib_prefixes::response rib_prefixes();

	common::icp::rib_lookup::response rib_lookup(const common::icp::rib_lookup::request& request);
	common::icp::rib_get::response rib_get(const common::icp::rib_get::request& request);
	common::icp::rib_save::response rib_save();
	void rib_load(const common::icp::rib_load::request& request);

private:
	void rib_insert(const common::icp::rib_update::insert& request);
	void rib_remove(const common::icp::rib_update::remove& request);
	void rib_clear(const common::icp::rib_update::clear& request);
	void rib_eor(const common::icp::rib_update::eor& request);

	void rib_thread();

protected:
	mutable std::mutex rib_update_mutex;

	std::atomic<bool> need_flushing = false;

	mutable std::mutex prefixes_mutex;
	mutable std::mutex prefixes_rebuild_mutex;

	using pptn_index_t = uint32_t; // pptn index in proto_peer_table_name vector

	std::vector<rib::pptn_t> proto_peer_table_name;

	std::unordered_map<rib::vrf_priority_t,
	                   std::unordered_map<ip_prefix_t,
	                                      rib::nexthop_map_t>>
	        prefixes_to_path_info_to_nh_ptr;

	std::unordered_map<rib::nexthop_stuff_t, uint32_t> nh_to_ref_count;

	std::unordered_map<rib::vrf_priority_t,
	                   std::unordered_set<ip_prefix_t>>
	        prefixes_reb;

	mutable std::mutex summary_mutex;
	std::unordered_map<std::tuple<std::string, ///< vrf
	                              uint32_t, ///< priority
	                              std::string, ///< protocol
	                              ip_address_t, ///< peer
	                              std::string>, ///< table_name
	                   std::tuple<common::uint64, ///< prefixes
	                              common::uint64, ///< paths
	                              common::uint8>> ///< eor
	        summary;
};
