#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netlink/netlink.h>
#include <unistd.h>

#include "base.h"
#include "neighbor.h"

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
        std::function<dataplane::neighbor::hashtable*(tSocketId)> ht_allocator,
        std::function<std::uint32_t()> current_time,
        std::function<void()> on_neighbor_flush,
        std::function<std::vector<dataplane::neighbor::key>()> keys_to_resolve)
{
	memset(&stats, 0, sizeof(stats));
	current_time_provider_ = std::move(current_time);
	on_neighbor_flush_handle_ = std::move(on_neighbor_flush);
	keys_to_resolve_provider_ = std::move(keys_to_resolve);

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

				std::optional<uint32_t> last_update_timestamp;
				if (!(value.flags & flag_is_static))
				{
					last_update_timestamp = current_time_provider_() - value.last_update_timestamp;
				}

				response.emplace_back(route_name,
				                      interface_name,
				                      common::ip_address_t(key.flags & flag_is_ipv6 ? 6 : 4, key.address.bytes),
				                      common::mac_address_t(value.ether_address.addr_bytes),
				                      last_update_timestamp);
			}
		}
	}

	return response;
}

eResult module::neighbor_insert(const common::idp::neighbor_insert::request& request)
{
	const auto& [route_name, interface_name, ip_address, mac_address] = request;
	GCC_BUG_UNUSED(route_name); ///< @todo

	tInterfaceId interface_id = 0;
	{
		auto lock = generation_interface.current_lock_guard();

		const auto& interface_name_to_id = generation_interface.current().interface_name_to_id;
		auto it = interface_name_to_id.find(interface_name);
		if (it == interface_name_to_id.end())
		{
			return eResult::invalidInterfaceName;
		}

		interface_id = it->second;
	}

	dataplane::neighbor::key key;
	memset(&key, 0, sizeof(key));
	key.interface_id = interface_id;
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
	value.flags = 0;
	value.flags |= flag_is_static;
	value.last_update_timestamp = current_time_provider_();

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

	if (response != eResult::success)
	{
		return response;
	}

	return neighbor_flush();
}

eResult module::neighbor_remove(const common::idp::neighbor_remove::request& request)
{
	const auto& [route_name, interface_name, ip_address] = request;
	GCC_BUG_UNUSED(route_name); ///< @todo

	tInterfaceId interface_id = 0;
	{
		auto lock = generation_interface.current_lock_guard();

		const auto& interface_name_to_id = generation_interface.current().interface_name_to_id;
		auto it = interface_name_to_id.find(interface_name);
		if (it == interface_name_to_id.end())
		{
			return eResult::invalidInterfaceName;
		}

		interface_id = it->second;
	}

	dataplane::neighbor::key key;
	memset(&key, 0, sizeof(key));
	key.interface_id = interface_id;
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

	if (response != eResult::success)
	{
		return response;
	}

	return neighbor_flush();
}

eResult module::neighbor_clear()
{
	return DumpOSNeighbors();
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
	        [this](const char* ifname) -> std::optional<tInterfaceId> {
		        auto interfaces_guard = generation_interface.current_lock_guard();
		        auto& ids = generation_interface.current().interface_name_to_id;
		        if (auto it = ids.find(ifname); it != ids.end())
		        {
			        return it->second;
		        }
		        else
		        {
			        return std::nullopt;
		        }
	        },
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
	std::vector<netlink::Entry> dump;
	std::vector<std::pair<dataplane::neighbor::key, dataplane::neighbor::value>> static_entries;
	{
		auto interfaces_guard = generation_interface.current_lock_guard();
		auto& new_interfaces = generation_interface.current();
		auto& old_interfaces = generation_interface.next();
		dump = neighbor_provider->GetHostDump(new_interfaces.interface_name_to_id);

		{
			auto lock = generation_hashtable.current_lock_guard();
			for (auto it : generation_hashtable.current().hashtable_updater.begin()->second.range())
			{
				if (!it.is_valid())
				{
					continue;
				}

				if (it.value()->flags & flag_is_static)
				{
					auto key = *it.key();
					auto to_name = old_interfaces.interface_id_to_name.find(key.interface_id);
					if (to_name == old_interfaces.interface_id_to_name.cend())
					{
						continue;
					}

					auto to_id = new_interfaces.interface_name_to_id.find(std::get<1>(to_name->second));
					if (to_id == new_interfaces.interface_name_to_id.cend())
					{
						continue;
					}

					key.interface_id = to_id->second;
					static_entries.emplace_back(key, *it.value());
				}
			}
		}
	}

	eResult res = generation_hashtable.update(
	        [&dump,
	         now = current_time_provider_(),
	         &static_entries,
	         this](
	                neighbor::generation_hashtable& hashtable) {
		        for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		        {
			        GCC_BUG_UNUSED(socket_id);
			        hashtable_updater.get_pointer()->clear();

			        for (const auto& [key, value] : static_entries)
			        {
				        hashtable_updater.get_pointer()->insert_or_update(key, value);
			        }

			        for (const auto& [iface, dst, mac, is_v6] : dump)
			        {
				        if (!mac)
				        {
					        YANET_LOG_INFO("No MAC address for neighbor in dump\n");
					        continue;
				        }

				        hashtable_updater.get_pointer()
				                ->insert_or_update(
				                        dataplane::neighbor::key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
				                        dataplane::neighbor::value{mac.value(), 0, now});
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

eResult module::neighbor_update_interfaces(const common::idp::neighbor_update_interfaces::request& request)
{
	generation_interface.next_lock();
	auto& generation = generation_interface.next();
	for (const auto& [interface_id,
	                  route_name,
	                  interface_name] : request)
	{
		generation.interface_name_to_id[interface_name] = interface_id;
		generation.interface_id_to_name[interface_id] = {route_name, interface_name};
	}

	generation_interface.switch_generation();
	generation_interface.next_unlock();
	StopNetlinkMonitor();
	DumpOSNeighbors();
	StartNetlinkMonitor();
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
}

void module::StartResolveJob()
{
	resolve_.Run([this]() mutable {
		std::vector<dataplane::neighbor::key> keys = keys_to_resolve_provider_();
		for (const auto& key : keys)
		{
			resolve(key);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE));
		return true;
	});
	YANET_LOG_INFO("Neighbor resolve job started\n");
}

void module::Upsert(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6, const rte_ether_addr& mac)
{
	TransformHashtables([k = key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
	                     v = value{mac, 0, current_time_provider_()},
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

void module::UpdateTimestamp(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6)
{
	TransformHashtables([k = key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
	                     this](dataplane::neighbor::hashtable& hashtable) {
		dataplane::neighbor::value* value;
		hashtable.lookup(k, value);
		if (value)
		{
			value->last_update_timestamp = current_time_provider_();
			stats.hashtable_insert_success++;
		}
		else
		{
			stats.hashtable_insert_error++;
		}
	});
}

void module::Remove(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6)
{
	TransformHashtables([k = key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
	                     this](dataplane::neighbor::hashtable& hashtable) {
		if (hashtable.remove(k))
		{
			stats.hashtable_remove_success++;
		}
	});
}

void module::resolve(const dataplane::neighbor::key& key)
{
	stats.resolve++;

	common::ip_address_t ip_address(key.flags & flag_is_ipv6 ? 6 : 4, key.address.bytes);
	std::string interface_name;
	{
		auto lock = generation_interface.current_lock_guard();
		const auto& interface_id_to_name = generation_interface.current().interface_id_to_name;
		auto it = interface_id_to_name.find(key.interface_id);
		if (it == interface_id_to_name.end())
		{
			YANET_LOG_ERROR("unknown interface_id: %u [ipv4_address: %s]\n",
			                key.interface_id,
			                ip_address.toString().data());
			return;
		}

		const auto& [it_route_name, it_interface_name] = it->second;
		GCC_BUG_UNUSED(it_route_name);

		interface_name = it_interface_name;
	}

	YANET_LOG_DEBUG("resolve: %s, %s\n",
	                interface_name.data(),
	                ip_address.toString().data());

#ifdef CONFIG_YADECAP_AUTOTEST
	YANET_LOG_INFO("Mocking resolve: %s, %s\n",
	               interface_name.data(),
	               ip_address.toString().data());
	value value;
	value.ether_address.addr_bytes[0] = 44;
	value.ether_address.addr_bytes[1] = 44;
	if (key.flags & flag_is_ipv6)
	{
		value.ether_address.addr_bytes[0] = 66;
		value.ether_address.addr_bytes[1] = 66;
	}
	*((uint32_t*)&value.ether_address.addr_bytes[2]) = rte_hash_crc(key.address.bytes, 16, 0);
	value.flags = 0 | flag_is_static;
	value.last_update_timestamp = current_time_provider_();

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
	neighbor_flush();
#else // CONFIG_YADECAP_AUTOTEST

	/// @todo: in first, try resolve like 'ip neig show 10.0.0.1 dev eth0'

	int family = AF_INET;
	int protocol = IPPROTO_ICMP;
	if (key.flags & flag_is_ipv6)
	{
		family = AF_INET6;
		protocol = IPPROTO_ICMPV6;
	}

	int icmp_socket = socket(family, SOCK_RAW, protocol);
	if (icmp_socket == -1)
	{
		YANET_LOG_WARNING("neighbor_resolve: socket(): %s\n",
		                  strerror(errno));
		return;
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
		return;
	}

	union
	{
		sockaddr address;
		sockaddr_in address_v4;
		sockaddr_in6 address_v6;
	};

	socklen_t address_length = sizeof(address_v4);

	if (key.flags & flag_is_ipv6)
	{
		address_v6.sin6_family = AF_INET6;
		address_v6.sin6_port = 0;
		memcpy(address_v6.sin6_addr.__in6_u.__u6_addr8, key.address.bytes, 16);

		address_length = sizeof(address_v6);
	}
	else
	{
		address_v4.sin_family = AF_INET;
		address_v4.sin_port = 0;
		address_v4.sin_addr.s_addr = key.address.mapped_ipv4_address.address;
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
	}

	close(icmp_socket);
#endif // CONFIG_YADECAP_AUTOTEST
}

} // namespace dataplane::neighbor
