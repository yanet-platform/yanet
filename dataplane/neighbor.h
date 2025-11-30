#pragma once

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "common/generation.h"
#include "common/idp.h"
#include "common/neighbor.h"
#include "common/utils.h"

#include "hashtable.h"
#include "netlink.hpp"
#include "type.h"

namespace dataplane::neighbor
{

using namespace std::chrono_literals;

constexpr static uint16_t flag_is_ipv6 = 1 << 0;
constexpr static uint16_t flag_is_static = 1 << 1;

struct key
{
	tInterfaceId interface_id : 16;
	uint16_t flags;
	ipv6_address_t address;

	bool operator<(const key& second) const
	{
		if (interface_id != second.interface_id)
		{
			return interface_id < second.interface_id;
		}
		else if (flags != second.flags)
		{
			return flags < second.flags;
		}
		else
		{
			return address < second.address;
		}
	}
};

static_assert(CONFIG_YADECAP_INTERFACES_SIZE <= 0xFFFF, "invalid size");

struct value
{
	rte_ether_addr ether_address;
	uint16_t flags;
	uint32_t last_update_timestamp;
};

//

using hashtable = hashtable_mod_dynamic<key, value, 16>;

//

class generation_interface
{
public:
	std::unordered_map<std::string, tInterfaceId> interface_name_to_id;
	std::unordered_map<tInterfaceId,
	                   std::tuple<std::string, ///< route_name
	                              std::string>> ///< interface_name
	        interface_id_to_name;
};

class generation_hashtable
{
public:
	std::map<tSocketId, dataplane::neighbor::hashtable::updater> hashtable_updater;
};

//
class module
{
	static constexpr auto PAUSE = 10ms;
	netlink::Interface* neighbor_provider;

public:
	module();
	module(netlink::Interface* neigh_prov);
	eResult init(
	        const std::set<tSocketId>& socket_ids,
	        uint64_t ht_size,
	        std::function<dataplane::neighbor::hashtable*(tSocketId)> ht_allocator,
	        std::function<std::uint32_t()> current_time,
	        std::function<void()> on_update,
	        std::function<std::vector<dataplane::neighbor::key>()> keys_to_resolve);

	void update_worker_base(const std::vector<std::tuple<tSocketId, dataplane::base::generation*>>& base_nexts);

	common::idp::neighbor_show::response neighbor_show() const;
	eResult neighbor_insert(const common::idp::neighbor_insert::request& request);
	eResult neighbor_remove(const common::idp::neighbor_remove::request& request);
	eResult neighbor_clear();
	eResult neighbor_flush();
	eResult neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request);
	common::idp::neighbor_stats::response neighbor_stats() const;

	void report(nlohmann::json& json);

	void Upsert(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac);
	void UpdateTimestamp(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6);
	void Remove(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6);

protected:
	void StartResolveJob();
	void StartNetlinkMonitor();
	void StopNetlinkMonitor();
	eResult DumpOSNeighbors();

	void resolve(const dataplane::neighbor::key& key);

protected:
	generation_manager<dataplane::neighbor::generation_interface> generation_interface;
	generation_manager<dataplane::neighbor::generation_hashtable, eResult> generation_hashtable;

	common::neighbor::stats stats;

	std::function<std::uint32_t()> current_time_provider_;
	std::function<void()> on_neighbor_flush_handle_;
	std::function<std::vector<dataplane::neighbor::key>()> keys_to_resolve_provider_;

	template<typename UpdaterFunc>
	void TransformHashtables(UpdaterFunc&& updater);

	utils::Job resolve_;
};

template<typename UpdaterFunc>
void module::TransformHashtables(UpdaterFunc&& updater)
{
	generation_hashtable.update([&](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			(void)_;
			updater(*hashtable_updater.get_pointer());
		}
		return eResult::success;
	});
}

}
