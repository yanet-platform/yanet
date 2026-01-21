#include "netlink.hpp"

#include <variant>

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/route/neighbour.h>

namespace netlink
{

std::string Entry::toString() const
{
	std::stringstream ss;
	ss << "ifname=" << ifname;
	if (v6)
	{
		ss << ", addr=" << common::ipv6_address_t(dst.bytes).toString();
	}
	else
	{
		ss << ", addr=" << common::ipv4_address_t(rte_cpu_to_be_32(dst.mapped_ipv4_address.address)).toString();
	}
	if (mac.has_value())
	{
		ss << ", mac=" << common::mac_address_t(mac->addr_bytes).toString();
	}
	return ss.str();
}

std::variant<Entry, int> ParseNeighbor(rtnl_neigh* neigh)
{
	int sysifid = rtnl_neigh_get_ifindex(neigh);
	Entry entry;
	char ifname[IFNAMSIZ];
	if (if_indextoname(sysifid, ifname) == nullptr)
	{
		YANET_LOG_INFO("Skipping message for unknown OS interface '%i'\n", sysifid);
		return NL_OK;
	}
	entry.ifname = ifname;

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
			auto& ip = entry.dst;
			std::fill(std::begin(ip.nap), std::end(ip.nap), 0);
			ip.mapped_ipv4_address =
			        ipv4_address_t{*static_cast<uint32_t*>(nl_addr_get_binary_addr(oaddr))};
			entry.v6 = false;
			break;
		}
		case AF_INET6:
			entry.dst.SetBinary(static_cast<uint8_t*>(nl_addr_get_binary_addr(oaddr)));
			entry.v6 = true;
			break;
		default:
			YANET_LOG_INFO("Skipping message with unsupported address family\n");
			return NL_OK;
	}

	nl_addr* omac = rtnl_neigh_get_lladdr(neigh);
	if (omac)
	{
		auto mac = static_cast<uint8_t*>(nl_addr_get_binary_addr(omac));
		entry.mac.emplace();
		std::copy(mac, mac + RTE_ETHER_ADDR_LEN, entry.mac.value().addr_bytes);
	}

	return entry;
}

std::vector<Entry> Provider::GetHostDump(unsigned rcvbuf_size)
{
	auto deleter = [](nl_sock* sk) { nl_socket_free(sk); };
	std::unique_ptr<nl_sock, decltype(deleter)> usk{nl_socket_alloc(), deleter};
	nl_sock* sk = usk.get();
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

		auto var = ParseNeighbor(neigh);

		if (!std::holds_alternative<Entry>(var))
		{
			return std::get<int>(var);
		}
		auto& entry = std::get<Entry>(var);
		if (!entry.mac.has_value())
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
		return dump;
	}
	if (rcvbuf_size != 0)
	{
		YANET_LOG_INFO("Netlink set recieve buffer size: %d\n", rcvbuf_size);
		if (auto err = nl_socket_set_buffer_size(sk, rcvbuf_size, 0); err < 0)
		{
			YANET_LOG_ERROR("Failed set size in nl_socket_set_buffer_size '%s'\n", nl_geterror(err));
		}
	}
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &WrapAsCallback<decltype(cb)>, &cb))
	{
		YANET_LOG_ERROR("Failed to set netlink callback\n");
		return dump;
	}
	rtgenmsg rt_hdr = {.rtgen_family = AF_UNSPEC};
	if (nl_send_simple(sk, RTM_GETNEIGH, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr)) < 0)
	{
		YANET_LOG_ERROR("Failed to send netlink request\n");
		return dump;
	}
	if (int err = nl_recvmsgs_default(sk); err < 0)
	{
		YANET_LOG_ERROR("Failed to receive netlink messages %s\n", nl_geterror(err));
	}
	return dump;
}

void Provider::StartMonitor(unsigned rcvbuf_size,
                            std::function<void(std::string, const ipv6_address_t&, bool, const rte_ether_addr&)> upsert,
                            std::function<void(std::string, const ipv6_address_t&, bool)> remove,
                            std::function<void(std::string, const ipv6_address_t&, bool)> timestamp)
{
	auto deleter = [](nl_sock* sk) { nl_socket_free(sk); };
	std::unique_ptr<nl_sock, decltype(deleter)> usk{nl_socket_alloc(), deleter};
	nl_sock* sk = usk.get();
	if (!sk)
	{
		YANET_LOG_ERROR("Failed to allocate netlink socket\n");
		return;
	}
	if (auto err = nl_connect(sk, NETLINK_ROUTE); err < 0)
	{
		YANET_LOG_ERROR("Failed to connect to netlink socket '%s'\n", nl_geterror(err));
		return;
	}
	if (rcvbuf_size != 0)
	{
		YANET_LOG_INFO("Netlink set recieve buffer size: %d\n", rcvbuf_size);
		if (auto err = nl_socket_set_buffer_size(sk, rcvbuf_size, 0); err < 0)
		{
			YANET_LOG_ERROR("Failed set size in nl_socket_set_buffer_size '%s'\n", nl_geterror(err));
		}
	}

	monitor_callback_ = [upsert, remove, timestamp](nl_msg* msg) -> int {
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

		auto parsed = ParseNeighbor(neigh);

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
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, &WrapAsCallback<decltype(monitor_callback_)>, &monitor_callback_))
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
	int fd = nl_socket_get_fd(sk);
	timeval tv = {.tv_sec = 0, .tv_usec = SOCKET_TIMEOUT};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	{
		YANET_LOG_ERROR("Failed to set socket timeout (%s)\n", strerror(errno));
	}
	sk_ = usk.release();
	monitor_.Run([this]() {
		failed_work_monitor_.store(false);
		int err;
		if ((err = nl_recvmsgs_default(sk_)) < 0)
		{
			switch (errno)
			{
				case ENOBUFS:
					YANET_LOG_ERROR("Lost events because of ENOBUFS\n");
					failed_work_monitor_.store(true);
					return false;
				case EAGAIN:
				case EINTR:
					break;
				default:
					YANET_LOG_ERROR("Failed to receive: %s", nl_geterror(err));
					failed_work_monitor_.store(true);
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
	sk_ = nullptr;
}

Provider::~Provider()
{
	StopMonitor();
}

bool Provider::IsFailedWorkMonitor()
{
	return failed_work_monitor_;
}

} // namespace netlink