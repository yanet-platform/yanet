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

struct key_cache
{
	std::string iface_name;
	bool is_v6;
	ipv6_address_t address;

	bool operator<(const key_cache& second) const
	{
		if (iface_name != second.iface_name)
		{
			return iface_name < second.iface_name;
		}
		else if (is_v6 != second.is_v6)
		{
			return is_v6 < second.is_v6;
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
};

struct value_cache
{
	rte_ether_addr ether_address;
	bool is_static = false;
	uint32_t last_update_timestamp = 0;
	uint32_t last_remove_timestamp = 0;
	uint32_t last_resolve_timestamp = 0;
	uint32_t number_resolve_after_remove = 0;
};

class NeighborCache
{
public:
	void Init(uint64_t checks_interval, uint64_t remove_timeout, uint64_t resolve_removed);
	void Insert(const std::string& iface_name, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac, uint32_t timestamp, bool is_static);
	bool UpdateTimestamp(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp);
	bool Remove(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp, bool is_static);
	void UpdateFromDump(const std::vector<netlink::Entry>& dump, uint32_t timestamp);
	bool NeedResolve(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp);

	common::idp::neighbor_show_cache::response NeighborShow(uint32_t timestamp) const;

	std::pair<std::vector<key_cache>, std::vector<key_cache>> GetKeysRemoveAndResolve(uint32_t timestamp);
	void SetSentResolve(const key_cache& key, uint32_t timestamp);

	std::map<key_cache, value_cache> GetData() const;
	std::lock_guard<std::mutex> LockGuard() const;

private:
	mutable std::mutex mutex_;
	std::map<key_cache, value_cache> data_;

	uint64_t checks_interval_ = YANET_CONFIG_NEIGHBOR_CHECK_INTERVAL;
	uint64_t remove_timeout_ = YANET_CONFIG_NEIGHBOR_REMOVE_TIMEOUT;
	uint64_t resolve_removed_ = YANET_CONFIG_RESOLVE_REMOVED;
};

//

using hashtable = hashtable_mod_dynamic<key, value, 16>;

//

class generation_interface
{
public:
	std::unordered_map<std::string,
	                   std::tuple<std::string, ///< route_name
	                              tInterfaceId>> ///< interface_id
	        interface_name_to_id;
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
	uint64_t rcvbuf_size_ = 0;
	uint64_t checks_interval_ = YANET_CONFIG_NEIGHBOR_CHECK_INTERVAL;
	uint64_t remove_timeout_ = YANET_CONFIG_NEIGHBOR_REMOVE_TIMEOUT;
	uint64_t resolve_removed_ = YANET_CONFIG_RESOLVE_REMOVED;
	std::mutex mutex_restart_monitor_;

public:
	module();
	module(netlink::Interface* neigh_prov);
	eResult init(
	        const std::set<tSocketId>& socket_ids,
	        uint64_t ht_size,
	        uint64_t rcvbuf_size,
	        uint64_t checks_interval,
	        uint64_t remove_timeout,
	        uint64_t resolve_removed,
	        std::function<dataplane::neighbor::hashtable*(tSocketId)> ht_allocator,
	        std::function<std::uint32_t()> current_time,
	        std::function<void()> on_update,
	        std::function<std::vector<dataplane::neighbor::key>()> keys_to_resolve);

	void update_worker_base(const std::vector<std::tuple<tSocketId, dataplane::base::generation*>>& base_nexts);

	common::idp::neighbor_show::response neighbor_show() const;
	common::idp::neighbor_show_cache::response neighbor_show_cache() const;
	eResult neighbor_insert(const common::idp::neighbor_insert::request& request);
	eResult neighbor_remove(const common::idp::neighbor_remove::request& request);
	eResult neighbor_clear();
	eResult neighbor_flush();
	eResult neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request);
	eResult neighbor_interfaces_switch();
	common::idp::neighbor_stats::response neighbor_stats() const;

	void report(nlohmann::json& json);

	void Upsert(std::string iface_name, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac);
	void UpdateTimestamp(std::string iface_name, const ipv6_address_t& dst, bool is_v6);
	void Remove(std::string iface_name, const ipv6_address_t& dst, bool is_v6);
	void NeighborThreadAction(uint32_t current_time);

protected:
	void StartResolveJob();
	void StartNetlinkMonitor();
	void StopNetlinkMonitor();
	eResult DumpOSNeighbors();

	bool resolve(const std::string& interface_name, const ipv6_address_t& ip_address, bool is_v6);
	std::optional<tInterfaceId> GetInterfaceId(const std::string& iface_name);
	std::optional<std::string> GetInterfaceName(tInterfaceId iface_id);

	void UpdateFromCache(bool remove_old);

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
	NeighborCache neighbor_cache_;
	std::atomic<uint32_t> time_del_unused_ = 0;
};

template<typename UpdaterFunc>
void module::TransformHashtables(UpdaterFunc&& updater)
{
	generation_hashtable.update([updater](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			(void)_;
			updater(*hashtable_updater.get_pointer());
		}
		return eResult::success;
	});
}

}
