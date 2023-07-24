#pragma once

#include <array>
#include <set>
#include <string>

#include "type.h"

namespace interface
{

class system
{
public:
	static bool getEtherAddress(const uint32_t& ipAddress, std::array<uint8_t, 6>* etherAddress = nullptr);
	static bool getEtherAddress(const std::string& interfaceName, const ipv6_address_t& ipv6Address, mac_address_t& etherAddress);
	static bool getEtherAddress(const ipv6_address_t& ipv6Address, mac_address_t& etherAddress);
	static std::optional<mac_address_t> getMacAddress(const std::string& interfaceName, const ip_address_t& address);
	static void updateRoute(const uint32_t& network, const uint8_t& mask, const std::set<uint32_t>& nexthops);
	static void updateRoute(const ip_prefix_t& prefix, const std::set<ip_address_t>& nexthops);
	static void removeRoute(const uint32_t& network, const uint8_t& mask);
	static void removeRoute(const ip_prefix_t& prefix);
	static std::set<uint32_t> getLocalIpAddresses();
	static std::set<std::array<uint8_t, 16>> getLocalIPv6Addresses();
	static std::optional<mac_address_t> get_mac_address(const std::string& vrf, const ip_address_t& address);
};

}
