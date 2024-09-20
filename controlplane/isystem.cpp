#include <ifaddrs.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "isystem.h"

using interface::system;

static std::string exec(const char* cmd)
{
	std::string result;

	FILE* pipe = popen(cmd, "r");
	if (!pipe)
	{
		return "";
	}

	std::array<char, 128> buffer;
	while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
	{
		result += buffer.data();
	}

	pclose(pipe);
	return result;
}

bool system::getEtherAddress(const uint32_t& ipAddress,
                             std::array<uint8_t, 6>* etherAddress)
{
	/// @todo: try to connect

	int arpSocket = 0;
	struct arpreq request;
	struct sockaddr_in* sin = nullptr;
	struct ifaddrs* interfaces = nullptr;
	struct ifaddrs* interfaceNext = nullptr;

	arpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (arpSocket == -1)
	{
		return false;
	}

	memset(&request, 0, sizeof(request));

	sin = (sockaddr_in*)&request.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(ipAddress);

	sin = (sockaddr_in*)&request.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	if (getifaddrs(&interfaces))
	{
		close(arpSocket);
		return false;
	}

	interfaceNext = interfaces;
	while (interfaceNext)
	{
		struct ifaddrs* networkInterface = interfaceNext;
		interfaceNext = interfaceNext->ifa_next;

		if (networkInterface->ifa_flags & IFF_LOOPBACK)
		{
			continue;
		}

		if (networkInterface->ifa_addr == nullptr || networkInterface->ifa_addr->sa_family != AF_PACKET)
		{
			continue;
		}

		snprintf(request.arp_dev, sizeof(request.arp_dev), "%s", networkInterface->ifa_name);

		if (ioctl(arpSocket, SIOCGARP, (caddr_t)&request) != -1 &&
		    request.arp_flags & ATF_COM)
		{
			if (etherAddress)
			{
				memcpy(etherAddress->data(), request.arp_ha.sa_data, etherAddress->size());
			}

			freeifaddrs(interfaces);
			close(arpSocket);
			return true;
		}
	}

	freeifaddrs(interfaces);
	close(arpSocket);
	return false;
}

bool system::getEtherAddress(const std::string& interfaceName,
                             const ipv6_address_t& ipv6Address,
                             mac_address_t& etherAddress)
{
	/// @todo: netlink

	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "ip -6 neighbour show to %s dev %s | cut -d' ' -f3", ipv6Address.toString().data(), interfaceName.data());

	etherAddress = exec(buffer);
	if (etherAddress.is_default())
	{
		return false;
	}

	return true;
}

bool system::getEtherAddress(const ipv6_address_t& ipv6Address,
                             mac_address_t& etherAddress)
{
	/// @todo: netlink

	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "ip -6 neighbour show to %s | cut -d' ' -f5", ipv6Address.toString().data());

	etherAddress = exec(buffer);
	if (etherAddress.is_default())
	{
		return false;
	}

	return true;
}

std::optional<mac_address_t> system::getMacAddress(const std::string& interfaceName,
                                                   const ip_address_t& address)
{
	if (address.is_ipv4())
	{
		std::array<uint8_t, 6> neighborMacAddress;
		if (getEtherAddress(address.get_ipv4(), &neighborMacAddress))
		{
			return neighborMacAddress;
		}
	}
	else
	{
		mac_address_t neighborMacAddress;
		if (getEtherAddress(interfaceName, address.get_ipv6(), neighborMacAddress))
		{
			return neighborMacAddress;
		}
	}

	return std::nullopt;
}

void system::updateRoute(const uint32_t& network,
                         const uint8_t& mask,
                         const std::set<uint32_t>& nexthops)
{
	/// @todo: netlink

	ipv4_prefix_t prefix = {network, mask};

	char buffer[1024];
	snprintf(buffer, sizeof(buffer), "ip route replace %s", prefix.toString().data());

	for (const auto& nexthop : nexthops)
	{
		snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), " nexthop via %s", ipv4_address_t(nexthop).toString().data());
	}

	int ret = ::system(buffer);
	(void)ret;
}

void system::updateRoute(const ip_prefix_t& prefix,
                         const std::set<ip_address_t>& nexthops)
{
	if (prefix.is_ipv4())
	{
		std::set<uint32_t> l_nexthops;
		for (const auto& nexthop : nexthops)
		{
			if (nexthop.is_ipv4())
			{
				l_nexthops.emplace(nexthop.get_ipv4());
			}
			else
			{
				/// @todo
			}
		}

		updateRoute(prefix.get_ipv4().address(),
		            prefix.get_ipv4().mask(),
		            l_nexthops);
	}
	else
	{
		/// @todo
	}
}

void system::removeRoute(const uint32_t& network,
                         const uint8_t& mask)
{
	/// @todo: netlink

	ipv4_prefix_t prefix = {network, mask};

	char buffer[512];
	snprintf(buffer, sizeof(buffer), "ip route del %s", prefix.toString().data());

	int ret = ::system(buffer);
	(void)ret;
}

void system::removeRoute(const ip_prefix_t& prefix)
{
	if (prefix.is_ipv4())
	{
		removeRoute(prefix.get_ipv4().address(),
		            prefix.get_ipv4().mask());
	}
	else
	{
		/// @todo
	}
}

std::set<uint32_t> system::getLocalIpAddresses()
{
	std::set<uint32_t> result;

	struct ifaddrs* ifaddr = nullptr;
	struct ifaddrs* ifa = nullptr;
	int n = 0;

	if (getifaddrs(&ifaddr) == -1)
	{
		YANET_LOG_ERROR("getifaddrs()\n");
		return result;
	}

	for (ifa = ifaddr, n = 0;
	     ifa != nullptr;
	     ifa = ifa->ifa_next, n++)
	{
		if (ifa->ifa_addr == nullptr)
		{
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			result.emplace(ntohl(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr));
		}
	}

	freeifaddrs(ifaddr);

	return result;
}

std::set<std::array<uint8_t, 16>> system::getLocalIPv6Addresses()
{
	std::set<std::array<uint8_t, 16>> result;

	struct ifaddrs* ifaddr = nullptr;
	struct ifaddrs* ifa = nullptr;
	int n = 0;

	if (getifaddrs(&ifaddr) == -1)
	{
		YANET_LOG_ERROR("getifaddrs()\n");
		return result;
	}

	for (ifa = ifaddr, n = 0;
	     ifa != nullptr;
	     ifa = ifa->ifa_next, n++)
	{
		if (ifa->ifa_addr == nullptr)
		{
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6)
		{
			std::array<uint8_t, 16> ipv6Address;
			memcpy(ipv6Address.data(), ((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr.__in6_u.__u6_addr8, 16);
			result.emplace(ipv6Address);
		}
	}

	freeifaddrs(ifaddr);

	return result;
}

std::optional<mac_address_t> system::get_mac_address(const std::string& vrf,
                                                     const ip_address_t& address)
{
	(void)vrf; ///< @todo: VRF

	if (address.is_ipv4())
	{
		std::array<uint8_t, 6> neighborMacAddress;
		if (getEtherAddress(address.get_ipv4(), &neighborMacAddress))
		{
			return neighborMacAddress;
		}
	}
	else
	{
		mac_address_t neighborMacAddress;
		if (getEtherAddress(address.get_ipv6(), neighborMacAddress))
		{
			return neighborMacAddress;
		}
	}

	return std::nullopt;
}
