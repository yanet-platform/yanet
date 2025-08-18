#include "netlink.hpp"

#include <variant>

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>

namespace netlink
{

std::variant<Entry, int> ParseNeighbor(
        rtnl_neigh* neigh,
        std::function<std::optional<tInterfaceId>(const char*)> get_id)
{
	int sysifid = rtnl_neigh_get_ifindex(neigh);
	Entry entry;
	char ifname[IFNAMSIZ];
	if (if_indextoname(sysifid, ifname) == nullptr)
	{
		YANET_LOG_INFO("Skipping message for unknown OS interface '%i'\n", sysifid);
		return NL_OK;
	}
	if (auto id = get_id(ifname); id.has_value())
	{
		std::get<tInterfaceId>(entry) = id.value();
	}
	else
	{
		YANET_LOG_INFO("Skipping message for unconfigured interface '%s'\n", ifname);
		return NL_OK;
	}

	nl_addr* oaddr = rtnl_neigh_get_dst(neigh);
	if (!oaddr)
	{
		YANET_LOG_INFO("Skipping message with no destination address\n");
		return NL_OK;
	}
	switch (nl_addr_get_family(oaddr))
	{
		case AF_INET:
		{
			auto& ip = std::get<ipv6_address_t>(entry);
			std::fill(std::begin(ip.nap), std::end(ip.nap), 0);
			ip.mapped_ipv4_address =
			        ipv4_address_t{*static_cast<uint32_t*>(nl_addr_get_binary_addr(oaddr))};
			std::get<bool>(entry) = false;
			break;
		}
		case AF_INET6:
			std::get<ipv6_address_t>(entry).SetBinary(static_cast<uint8_t*>(nl_addr_get_binary_addr(oaddr)));
			std::get<bool>(entry) = true;
			break;
		default:
			YANET_LOG_INFO("Skipping message with unsupported address family\n");
			return NL_OK;
	}

	nl_addr* omac = rtnl_neigh_get_lladdr(neigh);
	if (omac)
	{
		auto mac = static_cast<uint8_t*>(nl_addr_get_binary_addr(omac));
		std::get<std::optional<rte_ether_addr>>(entry).emplace();
		std::copy(mac, mac + RTE_ETHER_ADDR_LEN, std::get<std::optional<rte_ether_addr>>(entry).value().addr_bytes);
	}

	return entry;
}

std::vector<Entry> Provider::GetHostDump(
        const std::unordered_map<std::string, tInterfaceId>& ids)
{
	rtgenmsg rt_hdr = {.rtgen_family = AF_UNSPEC};
	nl_sock* sk = nl_socket_alloc();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return {};
	}
	std::vector<Entry> dump;
	auto cb = [&](nl_msg* msg) -> int {
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

		auto var = ParseNeighbor(neigh, [&](const char* name) -> std::optional<tInterfaceId> {
			if (auto it = ids.find(name); it != ids.end())
			{
				return it->second;
			}
			return std::nullopt;
		});

		if (!std::holds_alternative<Entry>(var))
		{
			return std::get<int>(var);
		}
		auto& entry = std::get<Entry>(var);
		if (!std::get<std::optional<rte_ether_addr>>(entry).has_value())
		{
			YANET_LOG_INFO("Skipping message with no MAC address\n");
			return NL_OK;
		}
		dump.emplace_back(std::move(entry));
		return NL_OK;
	};
	if (auto err = nl_connect(sk, NETLINK_ROUTE); err < 0)
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket '%s'\n", nl_geterror(err));
		goto cleanup;
	}
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &WrapAsCallback<decltype(cb)>, &cb))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		goto cleanup;
	}
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
	return dump;
}

void Provider::StartMonitor(std::function<std::optional<tInterfaceId>(const char*)> get_id,
                            std::function<void(tInterfaceId, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
                            std::function<void(tInterfaceId, const ipv6_address_t&, bool)> remove,
                            std::function<void(tInterfaceId, const ipv6_address_t&, bool)> timestamp)
{
	sk_ = nl_socket_alloc();
	if (!sk_)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return;
	}
	if (auto err = nl_connect(sk_, NETLINK_ROUTE); err < 0)
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket '%s'\n", nl_geterror(err));
		nl_socket_free(sk_);
		return;
	}
	monitor_callback_ = [get_id, upsert, remove, timestamp](nl_msg* msg) -> int {
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

		auto parsed = ParseNeighbor(neigh, get_id);

		if (!std::holds_alternative<Entry>(parsed))
		{
			return std::get<int>(parsed);
		}
		auto& [iface, dst, mac, is_v6] = std::get<Entry>(parsed);
		switch (msghdr->nlmsg_type)
		{
			case RTM_NEWNEIGH:
				if (mac.has_value())
				{
					upsert(iface, dst, is_v6, mac.value());
				}
				else
				{
					timestamp(iface, dst, is_v6);
				}
				break;
			case RTM_DELNEIGH:
				remove(iface, dst, is_v6);
				break;
		}
		return NL_OK;
	};
	if (nl_socket_modify_cb(sk_, NL_CB_VALID, NL_CB_CUSTOM, &WrapAsCallback<decltype(monitor_callback_)>, &monitor_callback_))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		nl_socket_free(sk_);
		return;
	}
	nl_socket_disable_seq_check(sk_);
	if (nl_socket_add_membership(sk_, RTNLGRP_NEIGH))
	{
		YANET_LOG_ERROR("Failed to subscribe to neighbor updates\n");
		nl_socket_free(sk_);
		return;
	}
	int fd = nl_socket_get_fd(sk_);
	timeval tv = {.tv_sec = 0, .tv_usec = 100000};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	{
		YANET_LOG_ERROR("Failed to set socket timeout (%s)\n", strerror(errno));
	}
	monitor_.Run([this]() {
		int err;
		if ((err = nl_recvmsgs_default(sk_)) < 0)
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
}

void Provider::StopMonitor()
{
	monitor_.Stop();
	nl_socket_free(sk_);
}

Provider::~Provider()
{
	StopMonitor();
}

} // namespace netlink