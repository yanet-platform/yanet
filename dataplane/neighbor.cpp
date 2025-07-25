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

#if 0
static void parse_rt_attributes(rtattr* rt_attributes[],
                                unsigned int rt_attributes_size,
                                rtattr* rta,
                                int length)
{
	memset(rt_attributes, 0, sizeof(rtattr*) * (rt_attributes_size + 1));
	while (RTA_OK(rta, length))
	{
		if ((rta->rta_type <= rt_attributes_size) &&
		    (!rt_attributes[rta->rta_type]))
		{
			rt_attributes[rta->rta_type] = rta;
		}

		rta = RTA_NEXT(rta, length);
	}

	if (length)
	{
		YANET_LOG_WARNING("invalid length: %d of %u\n", length, rta->rta_len);
	}
}

static std::string iface_id_to_name(int32_t iface_id)
{
	char buffer[IFNAMSIZ];
	if (if_indextoname(iface_id, buffer) == nullptr)
	{
		snprintf(buffer, IFNAMSIZ, "unknown_%i", iface_id);
	}
	return buffer;
}

static void netlink_parse(const std::function<void(const std::string&, const common::ip_address_t&, const common::mac_address_t&)>& callback,
                          const std::function<void(const std::string&, const std::optional<common::mac_address_t>&)>& cb_remove,
                          const char* buffer,
                          const unsigned int buffer_length)
{
	rtattr* rt_attributes[NDA_MAX + 1];

	unsigned int offset = 0;
	while (offset + sizeof(nlmsghdr) <= buffer_length)
	{
		auto* nl_message_header = (nlmsghdr*)(buffer + offset);
		uint32_t length = nl_message_header->nlmsg_len;

		if (nl_message_header->nlmsg_type == NLMSG_DONE)
		{
			YANET_LOG_ERROR("Netlink done\n");
			return;
		}

		if (nl_message_header->nlmsg_type == NLMSG_ERROR)
		{
			YANET_LOG_ERROR("Netlink error\n");
			return;
		}

		YANET_LOG_ERROR("Netlink message %d\n", nl_message_header->nlmsg_type);

		if (nl_message_header->nlmsg_type == RTM_NEWNEIGH ||
		    nl_message_header->nlmsg_type == RTM_GETNEIGH)
		{
			auto* nl_message = (ndmsg*)NLMSG_DATA(nl_message_header);
			parse_rt_attributes(rt_attributes,
			                    NDA_MAX,
			                    (rtattr*)(((char*)(nl_message)) + NLMSG_ALIGN(sizeof(ndmsg))),
			                    nl_message_header->nlmsg_len - NLMSG_LENGTH(sizeof(*nl_message)));
			if (nl_message->ndm_state != NUD_REACHABLE)
			{
				YANET_LOG_ERROR("Netlink adding neighbor with state %d != NUD_REACHABLE\n", nl_message->ndm_state);
			}
			if (rt_attributes[NDA_DST] &&
			    rt_attributes[NDA_LLADDR] &&
			    nl_message->ndm_ifindex)
			{
				std::string interface_name = iface_id_to_name(nl_message->ndm_ifindex);

				unsigned int family = nl_message->ndm_family;
				if (family == AF_BRIDGE)
				{
					if (RTA_PAYLOAD(rt_attributes[NDA_DST]) == sizeof(in6_addr))
					{
						family = AF_INET6;
					}
					else
					{
						family = AF_INET;
					}
				}

				common::mac_address_t mac_address((const uint8_t*)RTA_DATA(rt_attributes[NDA_LLADDR]));

				if (family == AF_INET)
				{
					common::ipv4_address_t ip_address(rte_be_to_cpu_32(*(const uint32_t*)RTA_DATA(rt_attributes[NDA_DST])));
					callback(interface_name, ip_address, mac_address);
				}
				else if (family == AF_INET6)
				{
					common::ipv6_address_t ip_address((const uint8_t*)RTA_DATA(rt_attributes[NDA_DST]));
					callback(interface_name, ip_address, mac_address);
				}
				return;
			}
			if (!rt_attributes[NDA_DST])
			{
				YANET_LOG_ERROR("Netlink DST missing\n");
			}
			if (!rt_attributes[NDA_LLADDR])
			{
				YANET_LOG_ERROR("Netlink LLADDR missing\n");
			}
			if (!nl_message->ndm_ifindex)
			{
				YANET_LOG_ERROR("Netlink ifindex missing\n");
			}
			if (rt_attributes[NDA_VLAN])
			{
				YANET_LOG_ERROR("Netlink VLAN is %s\n", (const uint8_t*)RTA_DATA(rt_attributes[NDA_VLAN]));
			}
		}

		if (nl_message_header->nlmsg_type == RTM_DELNEIGH ||
		    nl_message_header->nlmsg_type == RTM_DELLINK)
		{
			auto* nl_message = (ndmsg*)NLMSG_DATA(nl_message_header);
			parse_rt_attributes(rt_attributes,
			                    NDA_MAX,
			                    (rtattr*)(((char*)(nl_message)) + NLMSG_ALIGN(sizeof(ndmsg))),
			                    nl_message_header->nlmsg_len - NLMSG_LENGTH(sizeof(*nl_message)));

			if (nl_message->ndm_ifindex)
			{
				std::optional<common::mac_address_t> mac;

				if (rt_attributes[NDA_LLADDR])
				{
					mac = (const uint8_t*)RTA_DATA(rt_attributes[NDA_LLADDR]);
				}

				std::optional<common::mac_address_t> ip;

				std::string interface_name = iface_id_to_name(nl_message->ndm_ifindex);
				cb_remove(interface_name, mac);
			}
		}

		offset += NLMSG_ALIGN(length);
	}

	if (buffer_length - offset)
	{
		YANET_LOG_WARNING("extra buffer_length: %u of %u\n", offset, buffer_length);
	}
}

static void netlink_neighbor_monitor(const std::function<void(const std::string&, const common::ip_address_t&, const common::mac_address_t&)>& cb_update,
                                     const std::function<void(const std::string&, const std::optional<common::mac_address_t>&)>& cb_remove)
{
	int nl_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_socket < 0)
	{
		YANET_LOG_ERROR("socket(): %s\n", strerror(errno));
		return;
	}

	sockaddr_nl nl_sockaddr;
	memset(&nl_sockaddr, 0, sizeof(nl_sockaddr));
	nl_sockaddr.nl_family = AF_NETLINK;
	nl_sockaddr.nl_groups = 1u << (RTNLGRP_NEIGH - 1);

	if (bind(nl_socket, (sockaddr*)&nl_sockaddr, sizeof(nl_sockaddr)) < 0)
	{
		YANET_LOG_ERROR("bind(): %s\n", strerror(errno));
		return;
	}

	char buffer[4096];
	for (;;)
	{
		int buffer_length = recv(nl_socket, buffer, sizeof(buffer), 0);
		if (buffer_length > 0)
		{
			netlink_parse(cb_update, cb_remove, buffer, buffer_length);
		}
		else
		{
			break;
		}
	}

	close(nl_socket);
}

static void netlink_neighbor_dump(const std::function<void(const std::string&, const common::ip_address_t&, const common::mac_address_t&)>& cb_update,
                                  const std::function<void(const std::string&, const std::optional<common::mac_address_t>&)>& cb_remove)
{
	int nl_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl_socket < 0)
	{
		YANET_LOG_ERROR("socket(): %s\n", strerror(errno));
		return;
	}

	struct
	{
		nlmsghdr nl_msg;
		ndmsg nd_msg;
		char buf[256];
	} request;

	memset(&request, 0, sizeof(request));
	request.nl_msg.nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
	request.nl_msg.nlmsg_type = RTM_GETNEIGH;
	request.nl_msg.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;

	static std::atomic<uint32_t> sequence = time(nullptr);
	request.nl_msg.nlmsg_seq = sequence++;

	request.nd_msg.ndm_family = AF_UNSPEC;

	if (send(nl_socket, &request, sizeof(request), 0) == -1)
	{
		YANET_LOG_WARNING("neighbor_dump: send(): %s\n",
		                  strerror(errno));
		close(nl_socket);
		return;
	}

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	char buffer[81920];
	int buffer_length = recv(nl_socket, buffer, sizeof(buffer), 0);
	if (buffer_length > 0)
	{
		netlink_parse(cb_update, cb_remove, buffer, buffer_length);
	}
	if (buffer_length == sizeof(buffer))
	{
		YANET_LOG_ERROR("Buffer to small for neighbor_dump\n");
	}

	close(nl_socket);
}
#endif

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

#if 0
	std::stringstream ss;
	ss << "Interface ID to name:\n";
	for (auto& [id, name] : interface_id_to_name)
	{
		ss << id << " " << std::get<0>(name) << " " << std::get<1>(name) << "\n";
	}
	ss << "Interface name to ID:\n";
	for (auto& [name, id] : interface_name_to_id)
	{
		ss << name << " " << id << "\n";
	}
	YANET_LOG_ERROR("PDR:\n %s", ss.str().c_str());
#endif

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
		return NL_SKIP;
	}
	if (ids.find(ifname) == ids.end())
	{
		YANET_LOG_INFO("Skipping message for unconfigured interface '%s'\n", ifname);
		return NL_SKIP;
	}
	entry.iface = ids.at(ifname);

	nl_addr* oaddr = rtnl_neigh_get_dst(neigh);
	if (!oaddr)
	{
		YANET_LOG_INFO("Skipping message with no destination address\n");
		return NL_SKIP;
	}
	char buf[256];
	char* dst = nl_addr2str(oaddr, buf, sizeof(buf));
	if (!dst)
	{
		YANET_LOG_INFO("Failed to parse destination address\n");
		return NL_SKIP;
	}
	switch (nl_addr_get_family(oaddr))
	{
		case AF_INET:
		{
			auto& ip = entry.dst;
			std::fill(std::begin(ip.nap), std::end(ip.nap), 0);
			ip.mapped_ipv4_address =
			        ipv4_address_t{*static_cast<uint32_t*>(nl_addr_get_binary_addr(oaddr))};
			break;
		}
		case AF_INET6:
			entry.dst.SetBinary(static_cast<uint8_t*>(nl_addr_get_binary_addr(oaddr)));
			break;
		default:
			YANET_LOG_INFO("Skipping message with unsupported address family\n");
			return NL_SKIP;
	}

	nl_addr* omac = rtnl_neigh_get_lladdr(neigh);
	if (omac)
	{
		char* cmac = nl_addr2str(omac, buf, sizeof(buf));
		if (cmac)
		{
			auto mac = static_cast<uint8_t*>(nl_addr_get_binary_addr(omac));
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

	rtnl_neigh* neigh;
	if (rtnl_neigh_parse(nlmsg_hdr(msg), &neigh))
	{
		YANET_LOG_INFO("Failed to parse neighbor message\n");
		return NL_SKIP;
	}

	const int type = rtnl_neigh_get_type(neigh);
	if (type != RTM_NEWNEIGH)
	{
		YANET_LOG_INFO("Skipping message of type '%d'\n", type);
		return NL_SKIP;
	}
	const int state = rtnl_neigh_get_state(neigh);
	if (state == NUD_NOARP)
	{
		return NL_SKIP;
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
		return NL_SKIP;
	}
	dump.emplace_back(std::move(entry));

	return NL_OK;
}

struct ValidUpdateMsgArg
{
	module& mod;
	const std::unordered_map<std::string, tInterfaceId>& ids;
};

int OnValidUpdateMsg(nl_msg* msg, void* arg)
{
	auto& [mod, ids] = *static_cast<ValidUpdateMsgArg*>(arg);
	rtnl_neigh* neigh;
	if (rtnl_neigh_parse(nlmsg_hdr(msg), &neigh))
	{
		YANET_LOG_INFO("Failed to parse neighbor message\n");
		return NL_SKIP;
	}
	const int state = rtnl_neigh_get_state(neigh);
	if (state == NUD_NOARP)
	{
		return NL_SKIP;
	}

	auto var = ParseNeighbor(neigh, ids);
	if (!std::holds_alternative<Entry>(var))
	{
		return std::get<int>(var);
	}
	auto& entry = std::get<Entry>(var);

	switch (rtnl_neigh_get_type(neigh))
	{
		case RTM_NEWNEIGH:
			if (entry.mac)
			{
				mod.Upsert(entry.iface, entry.dst, entry.mac.value());
			}
			else
			{
				mod.UpdateTimestamp(entry.iface, entry.dst);
			}
			break;
		case RTM_DELNEIGH:
			mod.Remove(entry.iface, entry.dst);
			break;
		default:
			YANET_LOG_INFO("Skipping message of type '%d'\n", rtnl_neigh_get_type(neigh));
			return NL_SKIP;
	}
	return NL_OK;
}

std::vector<Entry> GetHostDump(
        const std::unordered_map<std::string, tInterfaceId>& ids)
{
	ValidDumpMsgArg arg{{}, ids};
	nl_sock* sk = nl_socket_alloc();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return {};
	}
	if (nl_connect(sk, NETLINK_ROUTE))
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket\n");
		return {};
	}
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &OnValidDumpMsg, &arg))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		return {};
	}
	rtgenmsg rt_hdr = {.rtgen_family = AF_UNSPEC};
	if (nl_send_simple(sk, RTM_GETNEIGH, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr)) < 0)
	{
		YANET_LOG_ERROR("Failed to send netlink request\n");
	}
	if (nl_recvmsgs_default(sk))
	{
		YANET_LOG_ERROR("Failed to receive netlink messages\n");
	}
	nl_socket_free(sk);
	return arg.dump;
}

} // namespace

void module::StartNetlinkMonitor()
{
	ValidUpdateMsgArg arg{*this, generation_interface.current().interface_name_to_id};
	nl_sock* sk = nl_socket_alloc();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return;
	}
	if (nl_connect(sk, NETLINK_ROUTE))
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket\n");
		return;
	}
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &OnValidUpdateMsg, &arg))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		return;
	}
	nl_socket_disable_seq_check(sk);
	if (nl_socket_add_membership(sk, RTNLGRP_NEIGH))
	{
		YANET_LOG_ERROR("Failed to subscribe to neighbor updates\n");
		return;
	}
	if (nl_socket_set_nonblocking(sk))
	{
		YANET_LOG_ERROR("Failed to set netlink socket to non-blocking mode\n");
	}
	monitor_.Run([this, sk]() {
		nl_recvmsgs_default(sk);
		using namespace std::chrono_literals;
		std::this_thread::sleep_for(PAUSE);
	});
	nl_socket_free(sk);
}

eResult module::DumpOSNeighbors()
{
	auto interfaces_guard = generation_interface.current_lock_guard();
	std::vector<Entry> dump = GetHostDump(generation_interface.current().interface_name_to_id);

	eResult res = generation_hashtable.update(
	        [dump,
	         now = dataplane->get_current_time(),
	         this](
	                neighbor::generation_hashtable& hashtable) {
		        for (auto& [socket_id, hashtable_updater] : hashtable.hashtable_updater)
		        {
			        GCC_BUG_UNUSED(socket_id);
			        hashtable_updater.get_pointer()->clear();
			        for (const auto& [iface, dst, mac] : dump)
			        {
				        hashtable_updater.get_pointer()
				                ->insert_or_update(
				                        dataplane::neighbor::key{iface, 0, dst},
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

		if (!keys.empty())
		{
			neighbor_flush();
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE));
	});
}

void module::Upsert(tInterfaceId iface, const ipv6_address_t& dst, const rte_ether_addr& mac)
{
	generation_hashtable.update([this, iface, &dst, &mac](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			if (!hashtable_updater.get_pointer()->insert_or_update(
			            key{iface, 0, dst},
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

void module::UpdateTimestamp(tInterfaceId iface, const ipv6_address_t& dst)
{
	generation_hashtable.update([this, iface, &dst](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			dataplane::neighbor::value* value;
			hashtable_updater.get_pointer()->lookup(key{iface, 0, dst}, value);
		}
		return eResult::success;
	});
	neighbor_flush();
}

void module::Remove(tInterfaceId iface, const ipv6_address_t& dst)
{
	generation_hashtable.update([this, iface, &dst](neighbor::generation_hashtable& hashtable) {
		for (auto& [_, hashtable_updater] : hashtable.hashtable_updater)
		{
			hashtable_updater.get_pointer()->remove(key{iface, 0, dst});
		}
		return eResult::success;
	});
	neighbor_flush();
}

void module::neighbor_upsert(const std::string& interface_name,
                             const common::ip_address_t& ip_address,
                             const common::mac_address_t& mac_address)
{
	tInterfaceId interface_id = 0;
	{
		auto lock = generation_interface.current_lock_guard();

		const auto& interface_name_to_id = generation_interface.current().interface_name_to_id;
		auto it = interface_name_to_id.find(interface_name);
		if (it == interface_name_to_id.end())
		{
			return;
		}
		interface_id = it->second;
	}

	stats.netlink_neighbor_update++;

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

	value value;
	memcpy(value.ether_address.addr_bytes, mac_address.data(), RTE_ETHER_ADDR_LEN);
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
