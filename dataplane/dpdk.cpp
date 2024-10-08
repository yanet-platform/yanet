#include <dpdk.h>

namespace dpdk
{

std::optional<std::string> GetNameByPort(tPortId pid)
{
	char cname[256];
	if (int res = rte_eth_dev_get_name_by_port(pid, cname); res)
	{
		YANET_LOG_ERROR("Failed to get name for port %d (%s)", pid, strerror(res));
		return std::nullopt;
	}
	return std::optional<std::string>{cname};
}

std::optional<common::mac_address_t> GetMacAddress(tPortId pid)
{
	rte_ether_addr ether_addr;
	if (int res = rte_eth_macaddr_get(pid, &ether_addr))
	{
		YANET_LOG_ERROR("Failed to get MAC for port %d (%s)", pid, strerror(res));
		return std::nullopt;
	}
	return std::optional<common::mac_address_t>{ether_addr.addr_bytes};
}

}