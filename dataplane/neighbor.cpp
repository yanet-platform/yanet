#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netlink/netlink.h>
#include <unistd.h>

#include "base.h"
#include "neighbor.h"

#define NEIGHBOR_DEBUG_LEVEL 1
#if NEIGHBOR_DEBUG_LEVEL >= 1
#define NEIGHBOR_INFO(msg, args...) YANET_LOG_INFO(msg, ##args)
#else
#define NEIGHBOR_INFO(msg, args...)
#endif
#if NEIGHBOR_DEBUG_LEVEL >= 2
#define NEIGHBOR_DEBUG(msg, args...) YANET_LOG_INFO(msg, ##args)
#else
#define NEIGHBOR_DEBUG(msg, args...)
#endif

namespace dataplane::neighbor
{

module::module() :neighbor_provider{new netlink::Provider{}}
{
	memset(&stats, 0, sizeof(stats));
}

module::module(netlink::Interface* neigh_prov) :neighbor_provider{neigh_prov}
{
	memset(&stats, 0, sizeof(stats));
}

eResult module::init(
        const std::set<tSocketId>& socket_ids,
        uint64_t ht_size,
        uint64_t rcvbuf_size,
        uint64_t checks_interval,
        uint64_t remove_timeout,
        uint64_t resolve_removed,
        std::function<dataplane::neighbor::hashtable*(tSocketId)> ht_allocator,
        std::function<std::uint32_t()> current_time,
        std::function<void()> on_neighbor_flush,
        std::function<std::vector<dataplane::neighbor::key>()> keys_to_resolve)
{
	memset(&stats, 0, sizeof(stats));
	current_time_provider_ = std::move(current_time);
	on_neighbor_flush_handle_ = std::move(on_neighbor_flush);
	keys_to_resolve_provider_ = std::move(keys_to_resolve);
	rcvbuf_size_ = rcvbuf_size;
	checks_interval_ = checks_interval;
	remove_timeout_ = remove_timeout;
	resolve_removed_ = resolve_removed;

	neighbor_cache_.Init(checks_interval, remove_timeout, resolve_removed);

	generation_hashtable.fill([&](neighbor::generation_hashtable& hashtable) {
		for (const auto socket_id : socket_ids)
		{
			auto* pointer = ht_allocator(socket_id);
			hashtable.hashtable_updater[socket_id].update_pointer(pointer,
			                                                      socket_id,
			                                                      ht_size);
		}
	});
	DumpOSNeighbors();
	StartNetlinkMonitor();
	StartResolveJob();

	return eResult::success;
}

void module::update_worker_base(const std::vector<std::tuple<tSocketId, dataplane::base::generation*>>& base_nexts)
{
	NEIGHBOR_DEBUG("update_worker_base\n");
	auto lock = generation_hashtable.current_lock_guard();
	for (auto& [socket_id, base_next] : base_nexts)
	{
		const auto& hashtable_updater = generation_hashtable.current().hashtable_updater;
		base_next->neighbor_hashtable = hashtable_updater.find(socket_id)->second.get_pointer();
	}
}

common::idp::neighbor_show::response module::neighbor_show() const
{
	common::idp::neighbor_show::response response;

	generation_interface.current_lock();
	auto interface_id_to_name = generation_interface.current().interface_id_to_name;
	generation_interface.current_unlock();

	{
		auto lock = generation_hashtable.current_lock_guard();

		const auto& hashtable_updater = generation_hashtable.current().hashtable_updater.begin()->second;
		for (auto iter : hashtable_updater.range())
		{
			if (iter.is_valid())
			{
				auto& key = *iter.key();
				auto& value = *iter.value();

				const auto& interface_id_to_name = generation_interface.current().interface_id_to_name;
				auto it = interface_id_to_name.find(key.interface_id);
				if (it == interface_id_to_name.end())
				{
					YANET_LOG_ERROR("Interface_id_to_name not found\n");
					continue;
				}

				const auto& [route_name, interface_name] = it->second;

				response.emplace_back(route_name,
				                      interface_name,
				                      common::ip_address_t(key.flags & flag_is_ipv6 ? 6 : 4, key.address.bytes),
				                      common::mac_address_t(value.ether_address.addr_bytes));
			}
		}
	}

	return response;
}

common::idp::neighbor_show_cache::response module::neighbor_show_cache() const
{
	return neighbor_cache_.NeighborShow(current_time_provider_());
}

eResult module::neighbor_insert(const common::idp::neighbor_insert::request& request)
{
	const auto& [route_name, interface_name, ip_address, mac_address] = request;
	NEIGHBOR_INFO("neighbor_insert interface_name=%s, ip_address=%s, mac_address=%s\n", interface_name.c_str(), ip_address.toString().c_str(), mac_address.toString().c_str());
	GCC_BUG_UNUSED(route_name); ///< @todo

	dataplane::neighbor::key key;
	memset(&key, 0, sizeof(key));
	key.flags = 0;

	if (ip_address.is_ipv4())
	{
		key.address.mapped_ipv4_address = ipv4_address_t::convert(ip_address.get_ipv4());
	}
	else
	{
		key.address = ipv6_address_t::convert(ip_address.get_ipv6());
		key.flags |= flag_is_ipv6;
	}

	dataplane::neighbor::value value;
	memcpy(value.ether_address.addr_bytes, mac_address.data(), 6);

	neighbor_cache_.Insert(interface_name, key.address, ip_address.is_ipv6(), value.ether_address, current_time_provider_(), true);

	std::optional<tInterfaceId> interface_id = GetInterfaceId(interface_name);
	if (!interface_id.has_value())
	{
		return eResult::invalidInterfaceName;
	}
	key.interface_id = *interface_id;

	auto response = generation_hashtable.update([this, key, value](neighbor::generation_hashtable& hashtable) {
		eResult result = eResult::success;
		for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		{
			GCC_BUG_UNUSED(socket_id);
			if (!hashtable_updater.get_pointer()->insert_or_update(key, value))
			{
				result = eResult::isFull;
				stats.hashtable_insert_error++;
			}
			else
			{
				stats.hashtable_insert_success++;
			}
		}
		return result;
	});

	return response;
}

eResult module::neighbor_remove(const common::idp::neighbor_remove::request& request)
{
	const auto& [route_name, interface_name, ip_address] = request;
	NEIGHBOR_INFO("neighbor_remove interface_name=%s, ip_address=%s\n", interface_name.c_str(), ip_address.toString().c_str());
	GCC_BUG_UNUSED(route_name); ///< @todo

	dataplane::neighbor::key key;
	memset(&key, 0, sizeof(key));
	key.flags = 0;

	if (ip_address.is_ipv4())
	{
		key.address.mapped_ipv4_address = ipv4_address_t::convert(ip_address.get_ipv4());
	}
	else
	{
		key.address = ipv6_address_t::convert(ip_address.get_ipv6());
		key.flags |= flag_is_ipv6;
	}

	neighbor_cache_.Remove(interface_name, key.address, ip_address.is_ipv6(), current_time_provider_(), true);

	std::optional<tInterfaceId> interface_id = GetInterfaceId(interface_name);
	if (!interface_id.has_value())
	{
		return eResult::invalidInterfaceName;
	}
	key.interface_id = *interface_id;

	auto response = generation_hashtable.update([this, key](neighbor::generation_hashtable& hashtable) {
		eResult result = eResult::success;
		for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		{
			GCC_BUG_UNUSED(socket_id);
			if (!hashtable_updater.get_pointer()->remove(key))
			{
				result = eResult::invalidArguments;
				stats.hashtable_remove_error++;
			}
			else
			{
				stats.hashtable_remove_success++;
			}
		}
		return result;
	});

	return response;
}

eResult module::neighbor_clear()
{
	NEIGHBOR_INFO("neighbor_clear\n");
	eResult result = DumpOSNeighbors();
	if (result != eResult::success)
	{
		return result;
	}
	UpdateFromCache(true);

	return eResult::success;
}

eResult module::neighbor_flush()
{
	generation_hashtable.switch_generation_with_update([this]() {
		on_neighbor_flush_handle_();
	});
	return eResult::success;
}

void module::StartNetlinkMonitor()
{
	neighbor_provider->StartMonitor(
	        rcvbuf_size_,
	        [this](auto... args) { return Upsert(args...); },
	        [this](auto... args) { return Remove(args...); },
	        [this](auto... args) { return UpdateTimestamp(args...); });
	YANET_LOG_INFO("Netlink monitor started\n");
}

void module::StopNetlinkMonitor()
{
	neighbor_provider->StopMonitor();
	YANET_LOG_INFO("Netlink monitor stopped\n");
}

eResult module::DumpOSNeighbors()
{
	NEIGHBOR_INFO("DumpOSNeighbors\n");
	std::vector<netlink::Entry> dump = neighbor_provider->GetHostDump(rcvbuf_size_);
	neighbor_cache_.UpdateFromDump(dump, current_time_provider_());

	auto interfaces_guard = generation_interface.current_lock_guard();
	const auto& interface_name_to_id = generation_interface.current().interface_name_to_id;
	eResult res = generation_hashtable.update(
	        [&dump,
	         now = current_time_provider_(),
	         interface_name_to_id,
	         this](
	                neighbor::generation_hashtable& hashtable) {
		        for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		        {
			        for (const auto& entry : dump)
			        {
				        const auto& [iface_name, dst, mac, is_v6] = entry;
				        if (!mac)
				        {
					        NEIGHBOR_INFO("No MAC address for neighbor in dump\n");
					        continue;
				        }

				        auto iter = interface_name_to_id.find(iface_name);
				        if (iter == interface_name_to_id.end())
				        {
					        continue;
				        }
				        tInterfaceId iface = std::get<1>(iter->second);
				        NEIGHBOR_INFO("DumpOSNeighbors add iface=%d %s\n", iface, entry.toString().c_str());

				        hashtable_updater.get_pointer()
				                ->insert_or_update(
				                        dataplane::neighbor::key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
				                        dataplane::neighbor::value{mac.value()});
				        stats.netlink_neighbor_update++;
			        }
		        }
		        return eResult::success;
	        });
	if (res != eResult::success)
	{
		YANET_LOG_ERROR("Failed to load OS neighbors dump\n");
		return res;
	}

	return neighbor_flush();
}

template<typename K, typename V>
bool HasNewKeys(const std::unordered_map<K, V>& current, const std::unordered_map<K, V>& update)
{
	for (const auto& iter : update)
	{
		if (current.find(iter.first) == current.end())
		{
			return true;
		}
	}
	return false;
}

template<typename K, typename V>
void CopyNewKeys(std::unordered_map<K, V>& current, const std::unordered_map<K, V>& update)
{
	for (const auto& iter : update)
	{
		if (current.find(iter.first) == current.end())
		{
			current.insert(iter);
		}
	}
}

template<typename K, typename V>
bool MapsEqual(const std::unordered_map<K, V>& first, const std::unordered_map<K, V>& second)
{
	if (first.size() != second.size())
	{
		return false;
	}
	for (const auto& iter_first : first)
	{
		const auto iter_second = second.find(iter_first.first);
		if (iter_second == second.end() || iter_first.second != iter_second->second)
		{
			return false;
		}
	}
	return true;
}

eResult module::neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request)
{
	YANET_LOG_INFO("neighbor_update_interfaces\n");

	// build new maps for next generation
	decltype(generation_interface.next().interface_name_to_id) interface_name_to_id;
	decltype(generation_interface.next().interface_id_to_name) interface_id_to_name;
	for (const auto& [interface_id, route_name, interface_name] : request)
	{
		NEIGHBOR_INFO("neighbor_update_interfaces %d %s\n", interface_id, interface_name.c_str());
		interface_name_to_id[interface_name] = {route_name, interface_id};
		interface_id_to_name[interface_id] = {route_name, interface_name};
	}

	{
		// check if there are any new keys
		auto lock = generation_interface.current_lock_guard();
		if (HasNewKeys(generation_interface.current().interface_name_to_id, interface_name_to_id) ||
		    HasNewKeys(generation_interface.current().interface_id_to_name, interface_id_to_name))
		{
			// prepare new tmp maps
			auto tmp_interface_name_to_id = generation_interface.current().interface_name_to_id;
			CopyNewKeys(tmp_interface_name_to_id, interface_name_to_id);
			auto tmp_interface_id_to_name = generation_interface.current().interface_id_to_name;
			CopyNewKeys(tmp_interface_id_to_name, interface_id_to_name);
			lock.unlock();

			// update by new tmp maps and switch generation
			generation_interface.next_lock();
			generation_interface.next().interface_name_to_id = tmp_interface_name_to_id;
			generation_interface.next().interface_id_to_name = tmp_interface_id_to_name;
			generation_interface.next_unlock();
			generation_interface.switch_generation();
		}
	}

	// update next generations
	generation_interface.next_lock();
	auto& generation = generation_interface.next();
	generation.interface_name_to_id = interface_name_to_id;
	generation.interface_id_to_name = interface_id_to_name;
	generation_interface.next_unlock();

	return eResult::success;
}

eResult module::neighbor_interfaces_switch()
{
	YANET_LOG_INFO("neighbor_interfaces_switch\n");

	// check if there have been any changes
	generation_interface.current_lock();
	generation_interface.next_lock();
	bool changed = !MapsEqual(generation_interface.current().interface_id_to_name, generation_interface.next().interface_id_to_name) ||
	               !MapsEqual(generation_interface.current().interface_name_to_id, generation_interface.next().interface_name_to_id);
	generation_interface.next_unlock();
	generation_interface.current_unlock();

	// switch generation
	generation_interface.switch_generation();

	if (changed)
	{
		NEIGHBOR_INFO("neighbor_interfaces_switch changed");
#ifdef CONFIG_YADECAP_AUTOTEST
		UpdateFromCache(true);
#else // CONFIG_YADECAP_AUTOTEST
		time_del_unused_ = current_time_provider_() + 30;
		UpdateFromCache(false);
#endif // CONFIG_YADECAP_AUTOTEST
	}

	return eResult::success;
}

common::idp::neighbor_stats::response module::neighbor_stats() const
{
	return stats;
}

void module::report(nlohmann::json& json)
{
	json["neighbor"]["hashtable_insert_success"] = stats.hashtable_insert_success;
	json["neighbor"]["hashtable_insert_error"] = stats.hashtable_insert_error;
	json["neighbor"]["hashtable_remove_success"] = stats.hashtable_remove_success;
	json["neighbor"]["hashtable_remove_error"] = stats.hashtable_remove_error;
	json["neighbor"]["netlink_neighbor_update"] = stats.netlink_neighbor_update;
	json["neighbor"]["resolve"] = stats.resolve;
	json["neighbor"]["resolve_removed"] = stats.resolve_removed;
	json["neighbor"]["remove_final"] = stats.remove_final;
}

void module::StartResolveJob()
{
	resolve_.Run([this]() mutable {
		std::vector<dataplane::neighbor::key> keys = keys_to_resolve_provider_();
		uint32_t timestamp = current_time_provider_();
		for (const auto& key : keys)
		{
			std::optional<std::string> interface_name = GetInterfaceName(key.interface_id);
			if (interface_name.has_value() && neighbor_cache_.NeedResolve(*interface_name, key.address, key.flags & flag_is_ipv6, timestamp))
			{
				common::ip_address_t ip_address(key.flags & flag_is_ipv6 ? 6 : 4, key.address.bytes);
				resolve(*interface_name, ip_address);
			}
		}

		neighbor_flush();

		std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE));
		return true;
	});
	YANET_LOG_INFO("Neighbor resolve job started\n");
}

void module::Upsert(std::string iface_name, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac)
{
	NEIGHBOR_INFO("Upsert %s\n", netlink::Entry{iface_name, dst, mac, is_v6}.toString().c_str());
	bool is_static = false;
#ifdef CONFIG_YADECAP_UNITTEST
	is_static = true;
#endif
	neighbor_cache_.Insert(iface_name, dst, is_v6, mac, current_time_provider_(), is_static);

	std::optional<tInterfaceId> iface = GetInterfaceId(iface_name);
	if (!iface.has_value())
	{
		stats.hashtable_insert_error++;
		return;
	}

	TransformHashtables([k = key{*iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
	                     v = value{mac},
	                     this](dataplane::neighbor::hashtable& hashtable) {
		if (!hashtable.insert_or_update(k, v))
		{
			stats.hashtable_insert_error++;
		}
		else
		{
			stats.hashtable_insert_success++;
		}
	});
}

void module::UpdateTimestamp(std::string iface_name, const ipv6_address_t& dst, bool is_v6)
{
	NEIGHBOR_INFO("UpdateTimestamp %s\n", netlink::Entry{iface_name, dst, std::nullopt, is_v6}.toString().c_str());
	if (neighbor_cache_.UpdateTimestamp(iface_name, dst, is_v6, current_time_provider_()))
	{
		stats.hashtable_insert_success++;
	}
	else
	{
		stats.hashtable_insert_error++;
	}
}

void module::Remove(std::string iface_name, const ipv6_address_t& dst, bool is_v6)
{
	NEIGHBOR_INFO("Remove %s\n", netlink::Entry{iface_name, dst, std::nullopt, is_v6}.toString().c_str());
	bool is_static = false;
#ifdef CONFIG_YADECAP_UNITTEST
	is_static = true;
	time_del_unused_ = 1;
#endif
	if (neighbor_cache_.Remove(iface_name, dst, is_v6, current_time_provider_(), is_static))
	{
		stats.hashtable_remove_success++;
	}
	else
	{
		stats.hashtable_remove_error++;
	}
}

bool module::resolve(const std::string& interface_name, const common::ip_address_t& ip_address)
{
	stats.resolve++;

	NEIGHBOR_DEBUG("neighbor resolve: %s, %s\n", interface_name.c_str(), ip_address.toString().c_str());
	YANET_LOG_DEBUG("resolve: %s, %s\n",
	                interface_name.data(),
	                ip_address.toString().data());

	bool result = true;
#ifdef CONFIG_YADECAP_AUTOTEST
	NEIGHBOR_INFO("Mocking resolve: %s, %s\n",
	              interface_name.data(),
	              ip_address.toString().data());
	value value;
	value.ether_address.addr_bytes[0] = 44;
	value.ether_address.addr_bytes[1] = 44;
	if (ip_address.is_ipv6())
	{
		value.ether_address.addr_bytes[0] = 66;
		value.ether_address.addr_bytes[1] = 66;
	}

	dataplane::neighbor::key key;
	memset(&key, 0, sizeof(key));
	if (ip_address.is_ipv4())
	{
		key.address.mapped_ipv4_address = ipv4_address_t::convert(ip_address.get_ipv4());
	}
	else
	{
		key.address = ipv6_address_t::convert(ip_address.get_ipv6());
		key.flags |= flag_is_ipv6;
	}
	*((uint32_t*)&value.ether_address.addr_bytes[2]) = rte_hash_crc(key.address.bytes, 16, 0);

	neighbor_cache_.Insert(interface_name, key.address, ip_address.is_ipv6(), value.ether_address, current_time_provider_(), false);

	std::optional<tInterfaceId> interface_id = GetInterfaceId(interface_name);
	if (interface_id.has_value())
	{
		key.interface_id = *interface_id;
		generation_hashtable.update([this, key, value](neighbor::generation_hashtable& hashtable) {
			for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
			{
				GCC_BUG_UNUSED(socket_id);
				if (!hashtable_updater.get_pointer()->insert_or_update(key, value))
				{
					stats.hashtable_insert_error++;
				}
				else
				{
					stats.hashtable_insert_success++;
				}
			}
			return eResult::success;
		});
	}

	neighbor_flush();
#else // CONFIG_YADECAP_AUTOTEST

	/// @todo: in first, try resolve like 'ip neig show 10.0.0.1 dev eth0'

	int family = AF_INET;
	int protocol = IPPROTO_ICMP;
	if (ip_address.is_ipv6())
	{
		family = AF_INET6;
		protocol = IPPROTO_ICMPV6;
	}

	int icmp_socket = socket(family, SOCK_RAW, protocol);
	if (icmp_socket == -1)
	{
		YANET_LOG_WARNING("neighbor_resolve: socket(): %s\n",
		                  strerror(errno));
		return false;
	}

	int rc = setsockopt(icmp_socket,
	                    SOL_SOCKET,
	                    SO_BINDTODEVICE,
	                    interface_name.data(),
	                    strlen(interface_name.data()) + 1);
	if (rc == -1)
	{
		YANET_LOG_WARNING("neighbor_resolve: setsockopt(%s): %s\n",
		                  interface_name.data(),
		                  strerror(errno));
		close(icmp_socket);
		return false;
	}

	union
	{
		sockaddr address;
		sockaddr_in address_v4;
		sockaddr_in6 address_v6;
	};

	socklen_t address_length = sizeof(address_v4);

	if (ip_address.is_ipv6())
	{
		address_v6.sin6_family = AF_INET6;
		address_v6.sin6_port = 0;
		memcpy(address_v6.sin6_addr.__in6_u.__u6_addr8, ip_address.get_ipv6().data(), 16);

		address_length = sizeof(address_v6);
	}
	else
	{
		address_v4.sin_family = AF_INET;
		address_v4.sin_port = 0;
		address_v4.sin_addr.s_addr = ip_address.get_ipv6().get_mapped_ipv4_address();
	}

	icmphdr header;
	memset(&header, 0, sizeof(header));
	if (sendto(icmp_socket,
	           &header,
	           sizeof(header),
	           0,
	           &address,
	           address_length) == -1)
	{
		YANET_LOG_WARNING("neighbor_resolve: sendto(): %s\n",
		                  strerror(errno));
		result = false;
	}

	close(icmp_socket);
#endif // CONFIG_YADECAP_AUTOTEST
	return result;
}

void module::NeighborThreadAction(uint32_t current_time)
{
	// Check monitor status
	if (neighbor_provider->IsFailedWorkMonitor())
	{
		std::lock_guard<std::mutex> guard(mutex_restart_monitor_);
		StopNetlinkMonitor();
		DumpOSNeighbors();
		StartNetlinkMonitor();
	}

	// find records to remove or resolve
	auto [keys_to_remove, keys_to_resolve] = neighbor_cache_.GetKeysRemoveAndResolve(current_time_provider_());

	// remove records
	for (const key_cache& cur_key : keys_to_remove)
	{
		std::optional<tInterfaceId> interface_id = GetInterfaceId(cur_key.iface_name);
		if (!interface_id.has_value())
		{
			stats.hashtable_remove_error++;
			continue;
		}

		dataplane::neighbor::key key_main;
		memset(&key_main, 0, sizeof(key_main));
		key_main.interface_id = *interface_id;
		key_main.address = cur_key.address;
		if (cur_key.is_v6)
		{
			key_main.flags |= flag_is_ipv6;
		}

		TransformHashtables([key_main, this](dataplane::neighbor::hashtable& hashtable) {
			if (hashtable.remove(key_main))
			{
				stats.remove_final++;
			}
			else
			{
				stats.hashtable_remove_error++;
			}
		});
	}

	// resolve
	for (const key_cache& cur_key : keys_to_resolve)
	{
		common::ip_address_t ip_address(cur_key.is_v6 ? 6 : 4, cur_key.address.bytes);
		if (resolve(cur_key.iface_name, ip_address))
		{
			neighbor_cache_.SetSentResolve(cur_key, current_time_provider_());
		}
	}

	// delete unused records
	if (time_del_unused_ != 0 && current_time >= time_del_unused_)
	{
		time_del_unused_ = 0;
		UpdateFromCache(true);
	}
}

std::optional<tInterfaceId> module::GetInterfaceId(const std::string& iface_name)
{
	auto lock = generation_interface.current_lock_guard();
	const auto& interface_name_to_id = generation_interface.current().interface_name_to_id;
	auto it = interface_name_to_id.find(iface_name);
	if (it == interface_name_to_id.end())
	{
		return std::nullopt;
	}

	return std::get<1>(it->second);
}

std::optional<std::string> module::GetInterfaceName(tInterfaceId iface_id)
{
	auto lock = generation_interface.current_lock_guard();
	const auto& interface_id_to_name = generation_interface.current().interface_id_to_name;
	auto it = interface_id_to_name.find(iface_id);
	if (it == interface_id_to_name.end())
	{
		return std::nullopt;
	}

	const auto& [it_route_name, it_interface_name] = it->second;
	GCC_BUG_UNUSED(it_route_name);

	return it_interface_name;
}

void module::UpdateFromCache(bool remove_old)
{
	std::lock_guard<std::mutex> lock_cache = neighbor_cache_.LockGuard();
	std::map<key_cache, value_cache> data = neighbor_cache_.GetData();

	// insert or update all values
	for (const auto& [cur_key, cur_value] : data)
	{
		std::optional<tInterfaceId> iface_id = GetInterfaceId(cur_key.iface_name);
		if (iface_id.has_value())
		{
			NEIGHBOR_DEBUG("UpdateFromCache %s iface_id=%d\n", netlink::Entry{cur_key.iface_name, cur_key.address, cur_value.ether_address, cur_key.is_v6}.toString().c_str(), *iface_id);
			TransformHashtables([k = key{*iface_id, cur_key.is_v6 ? flag_is_ipv6 : uint16_t{}, cur_key.address},
			                     v = value{cur_value.ether_address},
			                     this](dataplane::neighbor::hashtable& hashtable) {
				if (!hashtable.insert_or_update(k, v))
				{
					stats.hashtable_insert_error++;
				}
				else
				{
					stats.hashtable_insert_success++;
				}
			});
		}
		else
		{
			NEIGHBOR_DEBUG("UpdateFromCache %s iface_id=null\n", netlink::Entry{cur_key.iface_name, cur_key.address, cur_value.ether_address, cur_key.is_v6}.toString().c_str());
			stats.hashtable_insert_error++;
		}
	}

	// remove unused
	if (remove_old)
	{
		std::set<key> keys_del;
		{
			auto lock = generation_hashtable.current_lock_guard();
			for (auto it : generation_hashtable.current().hashtable_updater.begin()->second.range())
			{
				if (it.is_valid())
				{
					const key& cur_key = *it.key();
					bool exists = false;
					std::optional<std::string> iface_name = GetInterfaceName(cur_key.interface_id);
					if (iface_name.has_value())
					{
						key_cache check_key{*iface_name, (cur_key.flags & flag_is_ipv6) != 0, cur_key.address};
						if (data.find(check_key) != data.end())
						{
							exists = true;
						}
					}
					NEIGHBOR_DEBUG("UpdateFromCache key_exists=%d %s iface_id=%d\n", exists, netlink::Entry{"", cur_key.address, std::nullopt, true}.toString().c_str(), cur_key.interface_id);

					if (!exists)
					{
						keys_del.insert(cur_key);
					}
				}
			}
		}

		for (const key& key_main : keys_del)
		{
			NEIGHBOR_DEBUG("UpdateFromCache %s iface_id=%d\n", netlink::Entry{"", key_main.address, std::nullopt, true}.toString().c_str(), key_main.interface_id);
			TransformHashtables([key_main, this](dataplane::neighbor::hashtable& hashtable) {
				if (hashtable.remove(key_main))
				{
					stats.remove_final++;
				}
				else
				{
					stats.hashtable_remove_error++;
				}
			});
		}
	}

	// flush
	neighbor_flush();
}

void NeighborCache::Init(uint64_t checks_interval, uint64_t remove_timeout, uint64_t resolve_removed)
{
	checks_interval_ = checks_interval;
	remove_timeout_ = remove_timeout;
	resolve_removed_ = resolve_removed;
}

bool NeighborCache::UpdateTimestamp(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp)
{
	key_cache key;
	key.iface_name = iface_name;
	key.is_v6 = is_v6;
	key.address = dst;

	std::lock_guard<std::mutex> guard(mutex_);
	auto iter = data_.find(key);
	if (iter == data_.end())
	{
		return false;
	}

	dataplane::neighbor::value_cache& value = iter->second;
	value.last_update_timestamp = timestamp;
	value.last_remove_timestamp = 0;
	value.last_resolve_timestamp = 0;
	value.number_resolve_after_remove = 0;

	return true;
}

void NeighborCache::Insert(const std::string& iface_name, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac, uint32_t timestamp, bool is_static)
{
	key_cache key;
	key.iface_name = iface_name;
	key.is_v6 = is_v6;
	key.address = dst;

	std::lock_guard<std::mutex> guard(mutex_);
	if (!is_static)
	{
		auto iter = data_.find(key);
		if (iter != data_.end() && iter->second.is_static)
		{
			return;
		}
	}

	dataplane::neighbor::value_cache value;
	memcpy(value.ether_address.addr_bytes, mac.addr_bytes, 6);
	value.is_static = is_static;
	value.last_update_timestamp = timestamp;
	value.last_remove_timestamp = 0;
	value.last_resolve_timestamp = 0;
	value.number_resolve_after_remove = 0;

	data_[key] = value;
}

bool NeighborCache::Remove(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp, bool is_static)
{
	key_cache key;
	key.iface_name = iface_name;
	key.is_v6 = is_v6;
	key.address = dst;

	std::lock_guard<std::mutex> guard(mutex_);
	auto iter = data_.find(key);
	if (iter == data_.end())
	{
		return false;
	}

#ifdef CONFIG_YADECAP_AUTOTEST
	data_.erase(key);
#else // CONFIG_YADECAP_AUTOTEST
	if (is_static)
	{
		data_.erase(key);
	}
	else
	{
		dataplane::neighbor::value_cache& value = iter->second;
		if (value.last_remove_timestamp == 0)
		{
			value.last_remove_timestamp = timestamp;
			value.number_resolve_after_remove = 0;
		}
	}
#endif // CONFIG_YADECAP_AUTOTEST

	return true;
}

common::idp::neighbor_show_cache::response NeighborCache::NeighborShow(uint32_t timestamp) const
{
	std::lock_guard<std::mutex> guard(mutex_);
	common::idp::neighbor_show_cache::response response;
	for (const auto& [key, value] : data_)
	{
		std::optional<uint32_t> last_update_timestamp;
		if (!value.is_static)
		{
			last_update_timestamp = timestamp - value.last_update_timestamp;
		}

		std::string last_remove_timestamp;
		if (value.last_remove_timestamp != 0)
		{
			last_remove_timestamp = std::to_string(timestamp - value.last_remove_timestamp);
		}

		response.emplace_back(key.iface_name,
		                      common::ip_address_t(key.is_v6 ? 6 : 4, key.address.bytes),
		                      common::mac_address_t(value.ether_address.addr_bytes),
		                      last_update_timestamp,
		                      last_remove_timestamp);
	}

	return response;
}

void NeighborCache::UpdateFromDump(const std::vector<netlink::Entry>& dump, uint32_t timestamp)
{
	std::set<key_cache> all_keys;
	for (const netlink::Entry& entry : dump)
	{
		if (entry.mac.has_value())
		{
			Insert(entry.ifname, entry.dst, entry.v6, *entry.mac, timestamp, false);
			all_keys.insert({entry.ifname, entry.v6, entry.dst});
		}
	}

	std::set<key_cache> keys_del;
	{
		std::lock_guard<std::mutex> guard(mutex_);
		for (const auto& iter : data_)
		{
			if (all_keys.find(iter.first) == all_keys.end())
			{
				keys_del.insert(iter.first);
			}
		}
	}

	for (const key_cache& key : keys_del)
	{
		bool is_static = false;
#ifdef CONFIG_YADECAP_UNITTEST
		is_static = true;
#endif
		Remove(key.iface_name, key.address, key.is_v6, timestamp, is_static);
	}
}

bool NeighborCache::NeedResolve(std::string iface_name, const ipv6_address_t& dst, bool is_v6, uint32_t timestamp)
{
	key_cache key;
	key.iface_name = iface_name;
	key.is_v6 = is_v6;
	key.address = dst;

	std::lock_guard<std::mutex> guard(mutex_);
	auto iter = data_.find(key);
	if (iter == data_.end())
	{
		return true;
	}

	dataplane::neighbor::value_cache& value = iter->second;
	return value.last_resolve_timestamp != timestamp;
}

std::pair<std::vector<key_cache>, std::vector<key_cache>> NeighborCache::GetKeysRemoveAndResolve(uint32_t timestamp)
{
	std::vector<key_cache> keys_to_remove;
	std::vector<key_cache> keys_to_resolve;

	std::lock_guard<std::mutex> guard(mutex_);
	for (const auto& [key, value] : data_)
	{
		NEIGHBOR_DEBUG("NeighborCache::GetKeysRemoveAndResolve check %s, timestamp=%d, last_remove_timestamp=%d, is_static=%d\n",
		               netlink::Entry{key.iface_name, key.address, std::nullopt, key.is_v6}.toString().c_str(),
		               timestamp,
		               value.last_remove_timestamp,
		               value.is_static);
		if ((value.last_remove_timestamp == 0) || value.is_static)
		{
			continue;
		}
		else if (value.last_remove_timestamp + remove_timeout_ < timestamp)
		{
			keys_to_remove.push_back(key);
		}
		else if (value.last_resolve_timestamp + checks_interval_ <= timestamp && value.number_resolve_after_remove < resolve_removed_)
		{
			keys_to_resolve.push_back(key);
		}
	}

	for (const key_cache& key : keys_to_remove)
	{
		data_.erase(key);
	}

	return {keys_to_remove, keys_to_resolve};
}

void NeighborCache::SetSentResolve(const key_cache& key, uint32_t timestamp)
{
	std::lock_guard<std::mutex> guard(mutex_);
	auto iter = data_.find(key);
	if (iter == data_.end())
	{
		return;
	}

	dataplane::neighbor::value_cache& value = iter->second;
	value.last_resolve_timestamp = timestamp;
	value.number_resolve_after_remove++;
}

std::map<key_cache, value_cache> NeighborCache::GetData() const
{
	return data_;
}

std::lock_guard<std::mutex> NeighborCache::LockGuard() const
{
	return std::lock_guard(mutex_);
}

} // namespace dataplane::neighbor
