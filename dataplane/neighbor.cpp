#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>
#include <unistd.h>

#include "dataplane.h"
#include "neighbor.h"
#include "worker.h"

using namespace dataplane::neighbor;

module::module() :dataplane(nullptr)
{
	memset(&stats, 0, sizeof(stats));
}

eResult module::init(cDataPlane* dataplane)
{
	this->dataplane = dataplane;

	auto ht_size = dataplane->getConfigValues().neighbor_ht_size;
	generation_hashtable.fill([&](neighbor::generation_hashtable& hashtable) {
		for (const auto socket_id : dataplane->get_socket_ids())
		{
			auto* pointer = dataplane->memory_manager.create<dataplane::neighbor::hashtable>("neighbor.ht",
			                                                                                 socket_id,
			                                                                                 dataplane::neighbor::hashtable::calculate_sizeof(ht_size));
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
					last_update_timestamp = dataplane->get_current_time() - value.last_update_timestamp;
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
	value.last_update_timestamp = dataplane->get_current_time();

	YANET_LOG_ERROR("Neighbor insert (controlplane): %s, %s, %s\n",
	                interface_name.data(),
	                ip_address.toString().data(),
	                mac_address.toString().data());

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

	return response;
}

eResult module::neighbor_clear()
{
	auto response = generation_hashtable.update([](neighbor::generation_hashtable& hashtable) {
		for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		{
			GCC_BUG_UNUSED(socket_id);
			hashtable_updater.get_pointer()->clear();
		}
		return eResult::success;
	});

	return response;
}

eResult module::neighbor_flush()
{
	generation_hashtable.switch_generation_with_update([this]() {
		dataplane->switch_worker_base();
	});
	return eResult::success;
}

namespace
{

struct Entry
{
	tInterfaceId iface;
	ipv6_address_t dst;
	std::optional<rte_ether_addr> mac;
	bool is_v6;
};

struct ValidDumpMsgArg
{
	std::vector<Entry> dump;
	const std::unordered_map<std::string, tInterfaceId>& ids;
};

std::variant<Entry, int> ParseNeighbor(rtnl_neigh* neigh, const std::unordered_map<std::string, tInterfaceId>& ids)
{
	int sysifid = rtnl_neigh_get_ifindex(neigh);
	Entry entry;
	char ifname[IFNAMSIZ];
	if (if_indextoname(sysifid, ifname) == nullptr)
	{
		YANET_LOG_INFO("Skipping message for unknown OS interface '%i'\n", sysifid);
		return NL_OK;
	}
	if (auto it = ids.find(ifname); it == ids.end())
	{
		YANET_LOG_INFO("Skipping message for unconfigured interface '%s'\n", ifname);
		return NL_OK;
	}
	else
	{
		entry.iface = it->second;
	}

	nl_addr* oaddr = rtnl_neigh_get_dst(neigh);
	if (!oaddr)
	{
		YANET_LOG_INFO("Skipping message with no destination address\n");
		return NL_OK;
	}
	char buf[256];
	char* dst = nl_addr2str(oaddr, buf, sizeof(buf));
	if (!dst)
	{
		YANET_LOG_INFO("Failed to parse destination address\n");
		return NL_OK;
	}
	switch (nl_addr_get_family(oaddr))
	{
		case AF_INET:
		{
			auto& ip = entry.dst;
			std::fill(std::begin(ip.nap), std::end(ip.nap), 0);
			ip.mapped_ipv4_address =
			        ipv4_address_t{*static_cast<uint32_t*>(nl_addr_get_binary_addr(oaddr))};
			entry.is_v6 = false;
			break;
		}
		case AF_INET6:
			entry.dst.SetBinary(static_cast<uint8_t*>(nl_addr_get_binary_addr(oaddr)));
			entry.is_v6 = true;
			break;
		default:
			YANET_LOG_INFO("Skipping message with unsupported address family\n");
			return NL_OK;
	}

	nl_addr* omac = rtnl_neigh_get_lladdr(neigh);
	if (omac)
	{
		char* cmac = nl_addr2str(omac, buf, sizeof(buf));
		if (cmac)
		{
			auto mac = static_cast<uint8_t*>(nl_addr_get_binary_addr(omac));
			entry.mac.emplace();
			std::copy(mac, mac + RTE_ETHER_ADDR_LEN, entry.mac.value().addr_bytes);
		}
		else
		{
			YANET_LOG_INFO("Failed to parse MAC address from\n");
		}
	}

	return entry;
}

int OnValidDumpMsg(nl_msg* msg, void* arg)
{
	auto& [dump, ids] = *static_cast<ValidDumpMsgArg*>(arg);

	nlmsghdr* msghdr = nlmsg_hdr(msg);
	if (msghdr->nlmsg_type != RTM_NEWNEIGH && msghdr->nlmsg_type != RTM_DELNEIGH)
	{
		YANET_LOG_INFO("Skipping message of type '%d'\n", msghdr->nlmsg_type);
		return NL_OK;
	}

	rtnl_neigh* neigh;
	if (rtnl_neigh_parse(nlmsg_hdr(msg), &neigh))
	{
		YANET_LOG_INFO("Failed to parse neighbor message\n");
		return NL_OK;
	}

	const int state = rtnl_neigh_get_state(neigh);
	if (state == NUD_NOARP)
	{
		return NL_OK;
	}

	auto var = ParseNeighbor(neigh, ids);
	if (!std::holds_alternative<Entry>(var))
	{
		return std::get<int>(var);
	}
	auto& entry = std::get<Entry>(var);
	if (!entry.mac)
	{
		YANET_LOG_INFO("Skipping message with no MAC address\n");
		return NL_OK;
	}
	dump.emplace_back(std::move(entry));

	return NL_OK;
}

struct ValidUpdateMsgArg
{
	module& mod;
	generation_manager<dataplane::neighbor::generation_interface>& generation_interface;
};

int OnValidUpdateMsg(nl_msg* msg, void* arg)
{
	auto& [mod, generation_interface] = *static_cast<ValidUpdateMsgArg*>(arg);
	nlmsghdr* msghdr = nlmsg_hdr(msg);
	if (msghdr->nlmsg_type != RTM_NEWNEIGH && msghdr->nlmsg_type != RTM_DELNEIGH)
	{
		YANET_LOG_INFO("Skipping message of type '%d'\n", msghdr->nlmsg_type);
		return NL_OK;
	}
	rtnl_neigh* neigh;
	if (rtnl_neigh_parse(msghdr, &neigh))
	{
		YANET_LOG_INFO("Failed to parse neighbor message\n");
		return NL_OK;
	}
	const int state = rtnl_neigh_get_state(neigh);
	if (state == NUD_NOARP)
	{
		YANET_LOG_INFO("Skipping message with state NUD_NOARP\n");
		return NL_OK;
	}

	std::variant<Entry, int> var;
	{
		auto guard = generation_interface.current_lock_guard();
		auto ids = generation_interface.current().interface_name_to_id;
		var = ParseNeighbor(neigh, ids);
	}
	if (!std::holds_alternative<Entry>(var))
	{
		return std::get<int>(var);
	}
	auto& entry = std::get<Entry>(var);

	switch (msghdr->nlmsg_type)
	{
		case RTM_NEWNEIGH:
			if (entry.mac)
			{
				mod.Upsert(entry.iface, entry.dst, entry.is_v6, entry.mac.value());
			}
			else
			{
				mod.UpdateTimestamp(entry.iface, entry.dst, entry.is_v6);
			}
			break;
		case RTM_DELNEIGH:
			mod.Remove(entry.iface, entry.dst, entry.is_v6);
			break;
	}
	return NL_OK;
}

std::vector<Entry> GetHostDump(
        const std::unordered_map<std::string, tInterfaceId>& ids)
{
	ValidDumpMsgArg arg{{}, ids};
	rtgenmsg rt_hdr = {.rtgen_family = AF_UNSPEC};
	nl_sock* sk = nl_socket_alloc();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return {};
	}
#if AUTOTEST
	set fd
	set proto
#else
	if (auto err = nl_connect(sk, NETLINK_ROUTE); err < 0)
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket '%s'\n", nl_geterror(err));
		goto cleanup;
	}
#endif
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &OnValidDumpMsg, &arg))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		goto cleanup;
	}
	// if (nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM, &OnDone, nullptr))
	// {
	// 	YANET_LOG_ERROR("Failed to set netlink callback\n");
	// 	goto cleanup;
	// }
	if (nl_send_simple(sk, RTM_GETNEIGH, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr)) < 0)
	{
		YANET_LOG_ERROR("Failed to send netlink request\n");
		goto cleanup;
	}
	if (int err = nl_recvmsgs_default(sk); err < 0)
	{
		YANET_LOG_ERROR("Failed to receive netlink messages %s\n", nl_geterror(err));
	}
cleanup:
	nl_socket_free(sk);
	return arg.dump;
}

} // namespace

void module::StartNetlinkMonitor()
{
	ValidUpdateMsgArg* arg;
	{
		auto interfaces_guard = generation_interface.current_lock_guard();
		arg = new ValidUpdateMsgArg{*this, generation_interface};
	}
	nl_sock* sk = nl_socket_alloc();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return;
	}
	if (auto err = nl_connect(sk, NETLINK_ROUTE); err < 0)
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket '%s'\n", nl_geterror(err));
		nl_socket_free(sk);
		return;
	}
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &OnValidUpdateMsg, arg))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		nl_socket_free(sk);
		return;
	}
	nl_socket_disable_seq_check(sk);
	if (nl_socket_add_membership(sk, RTNLGRP_NEIGH))
	{
		YANET_LOG_ERROR("Failed to subscribe to neighbor updates\n");
		nl_socket_free(sk);
		return;
	}
	int fd = nl_socket_get_fd(sk);
	timeval tv = {.tv_sec = 0, .tv_usec = 100000};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	{
		YANET_LOG_ERROR("Failed to set socket timeout (%s)\n", strerror(errno));
	}
	monitor_.Run([this, sk]() {
		int err;
		if ((err = nl_recvmsgs_default(sk)) < 0)
		{
			switch (errno)
			{
				case ENOBUFS:
					YANET_LOG_ERROR("Lost events because of ENOBUFS\n");
					break;
				case EAGAIN:
				case EINTR:
					break;
				default:
					YANET_LOG_ERROR("Failed to receive: %s", nl_geterror(err));
					return false;
			}
		}
		return true;
	});
	YANET_LOG_ERROR("Netlink monitor started\n");
	return;
}

eResult module::DumpOSNeighbors()
{
	std::vector<Entry> dump;
	{
		auto interfaces_guard = generation_interface.current_lock_guard();
		dump = GetHostDump(generation_interface.current().interface_name_to_id);
	}

	eResult res = generation_hashtable.update(
	        [dump,
	         now = dataplane->get_current_time(),
	         this](
	                neighbor::generation_hashtable& hashtable) {
		        for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		        {
			        hashtable_updater.get_pointer()->clear();

			        for (const auto& [iface, dst, mac, is_v6] : dump)
			        {
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
	monitor_.Stop();
	YANET_LOG_INFO("Netlink monitor stopped\n");
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
	std::vector<dataplane::neighbor::key> keys;

	resolve_.Run([this, keys]() mutable {
		keys.clear();

		for (auto* worker : dataplane->get_workers())
		{
			dataplane->run_on_worker_gc(worker->socketId, [&]() {
				for (auto iter : worker->neighbor_resolve.range())
				{
					iter.lock();
					if (!iter.is_valid())
					{
						iter.unlock();
						continue;
					}

					auto key = *iter.key();

					iter.unset_valid();
					iter.unlock();

					keys.emplace_back(key);
				}

				return true;
			});
		}

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
	generation_hashtable.update([this, iface, &dst, is_v6, &mac](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			if (!hashtable_updater.get_pointer()->insert_or_update(
			            key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst},
			            value{mac, 0, dataplane->get_current_time()}))
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
}

void module::UpdateTimestamp(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6)
{
	generation_hashtable.update([this, iface, &dst, is_v6](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			dataplane::neighbor::value* value;
			hashtable_updater.get_pointer()
			        ->lookup(key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst}, value);
			if (value)
			{
				value->last_update_timestamp = dataplane->get_current_time();
				stats.hashtable_insert_success++;
			}
			else
			{
				stats.hashtable_insert_error++;
			}
		}
		return eResult::success;
	});
	neighbor_flush();
}

void module::Remove(tInterfaceId iface, const ipv6_address_t& dst, bool is_v6)
{
	generation_hashtable.update([this, iface, &dst, is_v6](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			hashtable_updater.get_pointer()->remove(key{iface, is_v6 ? flag_is_ipv6 : uint16_t{}, dst});
			stats.hashtable_remove_success++;
		}
		return eResult::success;
	});
	neighbor_flush();
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
	value value;
	value.ether_address.addr_bytes[0] = 44;
	value.ether_address.addr_bytes[1] = 44;
	if (key.flags & flag_is_ipv6)
	{
		value.ether_address.addr_bytes[0] = 66;
		value.ether_address.addr_bytes[1] = 66;
	}
	*((uint32_t*)&value.ether_address.addr_bytes[2]) = rte_hash_crc(key.address.bytes, 16, 0);
	value.flags = 0;
	value.last_update_timestamp = dataplane->get_current_time();

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
