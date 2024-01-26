#pragma once

#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <inttypes.h>
#include <memory.h>
#include <nlohmann/json.hpp>

#include "config.h"
#include "ctree.h"
#include "define.h"
#include "stream.h"
#include "uint128.h"

using tCoreId = uint32_t;
using tSocketId = uint32_t;
using tPortId = uint16_t;
using tQueueId = uint8_t;
using tCounterId = uint32_t;
using tLogicalPortId = uint32_t;
using tDecapId = uint32_t;
using tInterfaceId = uint32_t;
using tRouteId = uint32_t;
using nat64stateful_id_t = uint32_t;
using tNat64statelessId = uint32_t;
using tNat64statelessTranslationId = uint32_t;
using nat46clat_id_t = uint32_t;
using tAclId = uint32_t;
using tAclRuleId = uint32_t;
using tAclGroupId = uint32_t;
using dregress_id_t = uint32_t;
using balancer_id_t = uint32_t;
using balancer_service_id_t = uint32_t;
using balancer_real_id_t = uint32_t;
using tun64_id_t = uint32_t;
using coreId = uint32_t;
using socketId = uint32_t;
using counterId = uint32_t;

namespace common
{

enum class eDscpMarkType : uint8_t
{
	never,
	onlyDefault,
	always,
};

template<typename type_t,
         type_t default_value = 0>
class default_value_t
{
public:
	using this_type = default_value_t<type_t, default_value>;

public:
	inline default_value_t() :
	        value(default_value)
	{
	}

	inline default_value_t(const type_t& value) :
	        value(value)
	{
	}

	inline operator const type_t&() const
	{
		return value;
	}

	inline this_type& operator+=(const this_type& second)
	{
		this->value += second.value;
		return *this;
	}

	inline this_type& operator-=(const this_type& second)
	{
		this->value -= second.value;
		return *this;
	}

	inline this_type& operator++()
	{
		this->value++;
		return *this;
	}

	inline this_type& operator--()
	{
		this->value--;
		return *this;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(value);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(value);
	}

public:
	type_t value;
};

using int8 = default_value_t<int8_t>;
using int16 = default_value_t<int16_t>;
using int32 = default_value_t<int32_t>;
using int64 = default_value_t<int64_t>;
using uint8 = default_value_t<uint8_t>;
using uint16 = default_value_t<uint16_t>;
using uint32 = default_value_t<uint32_t>;
using uint64 = default_value_t<uint64_t>;

constexpr inline uint32_t unlabelled = 3;

//

class uint
{
public:
	uint(const std::string& string)
	{
		value = std::stoull(string, nullptr, 0);
	}

	constexpr operator const uint64_t&() const
	{
		return value;
	}

public:
	std::string toString()
	{
		return std::to_string(value);
	}

	uint64_t value;
};

class mac_address_t
{
public:
	constexpr mac_address_t() :
	        address{0, 0, 0, 0, 0, 0}
	{
	}

	constexpr mac_address_t(const std::array<uint8_t, 6>& address) :
	        address(address)
	{
	}

	mac_address_t(const uint8_t* address)
	{
		memcpy(this->address.data(), address, this->address.size());
	}

	mac_address_t(const std::string& string)
	{
		unsigned int bytes[6];
		auto rc = std::sscanf(string.data(),
		                      "%02x:%02x:%02x:%02x:%02x:%02x",
		                      &bytes[0],
		                      &bytes[1],
		                      &bytes[2],
		                      &bytes[3],
		                      &bytes[4],
		                      &bytes[5]);
		if (rc == 6)
		{
			address = {(uint8_t)bytes[0], (uint8_t)bytes[1], (uint8_t)bytes[2], (uint8_t)bytes[3], (uint8_t)bytes[4], (uint8_t)bytes[5]};
		}
		else
		{
			address = {0, 0, 0, 0, 0, 0};
		}
	}

	bool operator==(const mac_address_t& second) const
	{
		return !memcmp(address.data(), second.address.data(), address.size());
	}

	bool operator==(const uint8_t* second) const
	{
		return !memcmp(address.data(), second, address.size());
	}

	bool operator!=(const mac_address_t& second) const
	{
		return memcmp(address.data(), second.address.data(), address.size());
	}

	bool operator<(const mac_address_t& second) const
	{
		return address < second.address;
	}

	constexpr operator const std::array<uint8_t, 6> &() const
	{
		return address;
	}

	constexpr operator std::array<uint8_t, 6> &()
	{
		return address;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	bool is_default() const
	{
		return *this == mac_address_t();
	}

	std::string toString() const
	{
		char buffer[64];
		snprintf(buffer, 64, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X", address[0], address[1], address[2], address[3], address[4], address[5]);
		return buffer;
	}

	uint8_t* data()
	{
		return address.data();
	}

	const uint8_t* data() const
	{
		return address.data();
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(address);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(address);
	}

protected:
	std::array<uint8_t, 6> address;
};

class ipv4_address_t
{
public:
	constexpr ipv4_address_t() :
	        address(0)
	{
	}

	constexpr ipv4_address_t(const uint32_t& address) :
	        address(address)
	{
	}

	ipv4_address_t(const std::string& string)
	{
		// inet_aton() is able to handle octal numbers in IPv4 octets
		// i.e. 192.168.0.010
		if (inet_aton(string.data(), (struct in_addr*)&address) != 1)
		{
			std::ostringstream error;
			error << "'" << string << "' is not a valid IPv4 address";
			YANET_THROW(error.str());
		}
		address = ntohl(address);
	}

	constexpr bool operator<(const ipv4_address_t& second) const
	{
		return address < second.address;
	}

	constexpr bool operator>(const ipv4_address_t& second) const
	{
		return address > second.address;
	}

	constexpr operator const uint32_t&() const
	{
		return address;
	}

	constexpr operator uint32_t&()
	{
		return address;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		char buffer[64];
		snprintf(buffer, 64, "%u.%u.%u.%u", (address >> 24) & 0xFF, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF);
		return buffer;
	}

	constexpr ipv4_address_t applyMask(const uint8_t& mask) const
	{
		if (mask == 0 ||
		    mask > 32)
		{
			return {0};
		}

		return {address & (0xFFFFFFFFu << (32u - mask))};
	}

	constexpr std::tuple<ipv4_address_t, ipv4_address_t> splitNetwork(const uint8_t& mask) const
	{
		if (mask >= 32)
		{
			return {address,
			        address};
		}

		return {address,
		        address | (1u << (32u - mask - 1u))};
	}

	void set_bit(const uint32_t& index, const uint8_t& bit)
	{
		address |= bit << (31 - index);
		address &= ~((!bit) << (31 - index));
	}

	uint8_t get_bit(const uint32_t& index) const
	{
		return (address >> (31 - index)) & 1;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(address);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(address);
	}

protected:
	uint32_t address;
};

class ipv6_address_t
{
public:
	constexpr ipv6_address_t() :
	        address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	{
	}

	constexpr ipv6_address_t(const std::array<uint8_t, 16>& address) :
	        address{address}
	{
	}

	ipv6_address_t(const uint8_t* address)
	{
		memcpy(this->address.data(), address, 16);
	}

	ipv6_address_t(const uint64_t& address0,
	               const uint64_t& address64)
	{
		*(uint64_t*)&address[0] = htobe64(address0);
		*(uint64_t*)&address[8] = htobe64(address64);
	}

	explicit ipv6_address_t(uint128_t address) :
	        ipv6_address_t(uint64_t(address >> 64), uint64_t(address))
	{
	}

	ipv6_address_t(const std::string& string)
	{
		if (inet_pton(AF_INET6, string.data(), address.data()) != 1)
		{
			std::ostringstream error;
			error << "'" << string << "' is not a valid IPv6 address";
			YANET_THROW(error.str());
		}
	}

	bool operator<(const ipv6_address_t& second) const
	{
		return address < second.address;
	}

	bool operator>(const ipv6_address_t& second) const
	{
		return address > second.address;
	}

	ipv6_address_t operator+(const uint32_t& value) const
	{
		ipv6_address_t result(*this);

		*(uint32_t*)&result.address[12] = htobe32(be32toh(*(uint32_t*)&result.address[12]) + value);

		return result;
	}

	bool operator==(const ipv6_address_t& second) const
	{
		return !memcmp(address.data(), second.address.data(), address.size());
	}

	constexpr operator const std::array<uint8_t, 16> &() const
	{
		return address;
	}

	constexpr operator std::array<uint8_t, 16> &()
	{
		return address;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		char buffer[256];
		inet_ntop(AF_INET6, address.data(), buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = 0;
		return buffer;
	}

	ipv6_address_t applyMask(const uint8_t& mask) const
	{
		if (mask == 0 ||
		    mask > 128)
		{
			return {};
		}

		uint64_t address0 = getAddress64(0);
		uint64_t address64 = getAddress64(64);

		if (mask > 64)
		{
			address64 = address64 & (0xFFFFFFFFFFFFFFFFull << (128u - mask));
		}
		else
		{
			address0 = address0 & (0xFFFFFFFFFFFFFFFFull << (64u - mask));
			address64 = 0ull;
		}

		return {address0, address64};
	}

	uint128_t getAddress128() const
	{
		return ((uint128_t)(getAddress64(0)) << 64) + ((uint128_t)(getAddress64(64)));
	}

	uint64_t getAddress64(const uint8_t& offset) const
	{
		if (offset % 8 ||
		    offset > 128 - 64)
		{
			return 0;
		}

		return be64toh(*(uint64_t*)&address[offset / 8]);
	}

	uint32_t getAddress32(const uint8_t& offset) const
	{
		if (offset % 8 ||
		    offset > 128 - 32)
		{
			return 0;
		}

		return be32toh(*(uint32_t*)&address[offset / 8]);
	}

	ipv4_address_t get_mapped_ipv4_address() const
	{
		return ipv4_address_t(getAddress32(96));
	}

	constexpr const uint8_t* data() const
	{
		return address.data();
	}

	constexpr uint8_t* data()
	{
		return address.data();
	}

	void set_bit(const uint32_t& index, const uint8_t& bit)
	{
		auto& byte = address[index / 8];
		byte |= bit << (7 - (index % 8));
		byte &= ~((!bit) << (7 - (index % 8)));
	}

	uint8_t get_bit(const uint32_t& index) const
	{
		uint32_t address = getAddress32((index / 32) * 32);
		return (address >> (31 - (index % 32))) & 1;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(address);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(address);
	}

	/// Returns true if this is a multicast address (ff00::/8).
	///
	/// This property is defined by IETF RFC 4291.
	constexpr bool is_multicast() const
	{
		return (address[0] & 0xff) == 0xff;
	}

protected:
	std::array<uint8_t, 16> address;
};

class ip_address_t
{
public:
	constexpr ip_address_t()
	{
	}

	constexpr ip_address_t(const uint8_t ip_version, const uint8_t* bytes)
	{
		if (ip_version == 4)
		{
			address = ipv4_address_t(ntohl(*reinterpret_cast<const uint32_t*>(&bytes[12])));
		}
		else
		{
			address = ipv6_address_t(bytes);
		}
	}

	constexpr ip_address_t(const ipv4_address_t& address) :
	        address(address)
	{
	}

	constexpr ip_address_t(const ipv6_address_t& address) :
	        address(address)
	{
	}

	ip_address_t(const std::string& string)
	{
		if (string.find("::ffff:") == 0)
		{
			address = ipv4_address_t(string.substr(7));
		}
		else if (string.find(':') == std::string::npos)
		{
			address = ipv4_address_t(string);
		}
		else
		{
			address = ipv6_address_t(string);
		}
	}

	constexpr bool operator<(const ip_address_t& second) const
	{
		return address < second.address;
	}

	constexpr bool operator>(const ip_address_t& second) const
	{
		return address > second.address;
	}

	constexpr bool operator==(const ip_address_t& second) const
	{
		return address == second.address;
	}

	constexpr bool operator!=(const ip_address_t& second) const
	{
		return !(address == second.address);
	}

	constexpr operator const std::variant<ipv4_address_t, ipv6_address_t> &() const
	{
		return address;
	}

	constexpr operator std::variant<ipv4_address_t, ipv6_address_t> &()
	{
		return address;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		std::string string;

		std::visit([&string](const auto& address) {
			string = address.toString();
		},
		           address);

		return string;
	}

	constexpr bool is_ipv4() const
	{
		return std::holds_alternative<ipv4_address_t>(address);
	}

	constexpr bool is_ipv6() const
	{
		return std::holds_alternative<ipv6_address_t>(address);
	}

	ipv4_address_t& get_ipv4()
	{
		return std::get<ipv4_address_t>(address);
	}

	const ipv4_address_t& get_ipv4() const
	{
		return std::get<ipv4_address_t>(address);
	}

	ipv6_address_t& get_ipv6()
	{
		return std::get<ipv6_address_t>(address);
	}

	const ipv6_address_t& get_ipv6() const
	{
		return std::get<ipv6_address_t>(address);
	}

	bool is_default() const
	{
		if (is_ipv4() &&
		    get_ipv4() == ipv4_address_t())
		{
			return true;
		}
		else if (is_ipv6() &&
		         get_ipv6() == ipv6_address_t())
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	ip_address_t applyMask(const uint8_t& mask) const
	{
		if (is_ipv4())
		{
			return std::get<ipv4_address_t>(address).applyMask(mask);
		}
		else
		{
			return std::get<ipv6_address_t>(address).applyMask(mask);
		}
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(address);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(address);
	}

protected:
	std::variant<ipv4_address_t, ipv6_address_t> address;
};

class ipv4_prefix_t
{
public:
	constexpr ipv4_prefix_t() :
	        prefix(ipv4_address_t(), 0)
	{
	}

	constexpr ipv4_prefix_t(const ipv4_address_t& address,
	                        const uint8_t& mask) :
	        prefix(address, mask)
	{
	}

	ipv4_prefix_t(const std::string& string)
	{
		if (string.find('/') == std::string::npos)
		{
			std::get<0>(prefix) = string;
			std::get<1>(prefix) = 32;
		}
		else
		{
			std::get<0>(prefix) = string.substr(0, string.find('/'));
			std::get<1>(prefix) = std::stoll(string.substr(string.find('/') + 1), nullptr, 0);
		}
	}

	constexpr bool operator==(const ipv4_prefix_t& second) const
	{
		return prefix == second.prefix;
	}

	constexpr bool operator<(const ipv4_prefix_t& second) const
	{
		return prefix < second.prefix;
	}

	constexpr bool operator>(const ipv4_prefix_t& second) const
	{
		return prefix > second.prefix;
	}

	constexpr operator const std::tuple<ipv4_address_t, uint8_t> &() const
	{
		return prefix;
	}

	constexpr operator std::tuple<ipv4_address_t, uint8_t> &()
	{
		return prefix;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	constexpr const ipv4_address_t& address() const
	{
		return std::get<0>(prefix);
	}

	constexpr ipv4_address_t& address()
	{
		return std::get<0>(prefix);
	}

	constexpr const uint8_t& mask() const
	{
		return std::get<1>(prefix);
	}

	constexpr uint8_t& mask()
	{
		return std::get<1>(prefix);
	}

	std::string toString() const
	{
		return address().toString() + "/" + std::to_string(mask());
	}

	constexpr bool isValid() const
	{
		return mask() <= 32 &&
		       address().applyMask(mask()) == address();
	}

	constexpr ipv4_prefix_t applyMask(const uint8_t& mask) const
	{
		return {address().applyMask(mask), mask};
	}

	constexpr std::tuple<ipv4_prefix_t, ipv4_prefix_t> splitNetwork() const
	{
		if (mask() >= 32)
		{
			return {*this,
			        *this};
		}

		return {{address(), (uint8_t)(mask() + 1)},
		        {address() | (1u << (32u - mask() - 1u)), (uint8_t)(mask() + 1)}};
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
	}

	bool subnetOf(const ipv4_prefix_t& other) const
	{
		if (mask() < other.mask())
		{
			return false;
		}

		return address().applyMask(other.mask()) == other.address();
	}

	bool subnetFor(const ipv4_address_t& other) const
	{
		return other.applyMask(mask()) == address().applyMask(mask());
	}

protected:
	std::tuple<ipv4_address_t, uint8_t> prefix;
};

class ipv4_prefix_with_announces_t
{
public:
	ipv4_prefix_with_announces_t()
	{
	}

	ipv4_prefix_with_announces_t(const nlohmann::json& prefixJson)
	{
		// prefix could be either a string (for old configs support) or an object
		if (prefixJson.is_string())
		{
			prefix = ipv4_prefix_t{prefixJson.get_ref<const std::string&>()};
			announces.emplace_back(prefix);
		}
		else if (prefixJson.is_object())
		{
			prefix = ipv4_prefix_t{prefixJson["prefix"].get_ref<const std::string&>()};

			const auto& announcesRaw = prefixJson["announces"];
			announces.reserve(announcesRaw.size());
			for (const auto& announceRaw : announcesRaw)
			{
				ipv4_prefix_t announce{announceRaw.get<std::string>()};
				if (!announce.isValid())
				{
					std::ostringstream error;
					error << "prefix has invalid announce: '" << announce.toString()
					      << "' that isn' t a subnet of prefix ";
					YANET_THROW(error.str());
				}
				if (!announce.subnetOf(prefix))
				{
					std::ostringstream error;
					error << "prefix: '" << prefix.toString() << "' has announce: '"
					      << announce.toString() << "' that isn' t a subnet of prefix ";
					YANET_THROW(error.str());
				}
				announces.emplace_back(std::move(announce));
			}
		}
		else
		{
			YANET_THROW(std::string("prefix has invalid type"));
		}
	}

	ipv4_prefix_with_announces_t(ipv4_prefix_t prefix) :
	        prefix(std::move(prefix))
	{
	}

	ipv4_prefix_with_announces_t(ipv4_prefix_t prefix, std::vector<ipv4_prefix_t> announces) :
	        prefix(std::move(prefix)), announces(std::move(announces))
	{
	}

	constexpr bool operator<(const ipv4_prefix_with_announces_t& second) const
	{
		return prefix < second.prefix;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
		stream.pop(announces);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
		stream.push(announces);
	}

public:
	ipv4_prefix_t prefix;
	std::vector<ipv4_prefix_t> announces;
};

class ipv6_prefix_t
{
public:
	constexpr ipv6_prefix_t() :
	        prefix(ipv6_address_t(), 0)
	{
	}

	constexpr ipv6_prefix_t(const ipv6_address_t& address,
	                        const uint8_t& mask) :
	        prefix(address, mask)
	{
	}

	ipv6_prefix_t(const std::string& string)
	{
		if (string.find('/') == std::string::npos)
		{
			std::get<0>(prefix) = string;
			std::get<1>(prefix) = 128;
		}
		else
		{
			std::get<0>(prefix) = string.substr(0, string.find('/'));
			std::get<1>(prefix) = std::stoll(string.substr(string.find('/') + 1), nullptr, 0);
		}
	}

	constexpr bool operator==(const ipv6_prefix_t& second) const
	{
		return prefix == second.prefix;
	}

	constexpr bool operator<(const ipv6_prefix_t& second) const
	{
		return prefix < second.prefix;
	}

	constexpr bool operator>(const ipv6_prefix_t& second) const
	{
		return prefix > second.prefix;
	}

	constexpr operator const std::tuple<ipv6_address_t, uint8_t> &() const
	{
		return prefix;
	}

	constexpr operator std::tuple<ipv6_address_t, uint8_t> &()
	{
		return prefix;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	constexpr const ipv6_address_t& address() const
	{
		return std::get<0>(prefix);
	}

	constexpr ipv6_address_t& address()
	{
		return std::get<0>(prefix);
	}

	constexpr const uint8_t& mask() const
	{
		return std::get<1>(prefix);
	}

	constexpr uint8_t& mask()
	{
		return std::get<1>(prefix);
	}

	std::string toString() const
	{
		return address().toString() + "/" + std::to_string(mask());
	}

	bool isValid() const
	{
		if (mask() > 128)
		{
			return false;
		}

		if ((address().getAddress64(0) & getAddressMask64(0)) != address().getAddress64(0))
		{
			return false;
		}

		if ((address().getAddress64(64) & getAddressMask64(64)) != address().getAddress64(64))
		{
			return false;
		}

		return true;
	}

	ipv6_prefix_t applyMask(const uint8_t& mask) const
	{
		return {address().applyMask(mask), mask};
	}

	uint64_t getAddress64(const uint8_t& offset) const
	{
		return address().getAddress64(offset) & getAddressMask64(offset);
	}

	uint32_t getAddress32(const uint8_t& offset) const
	{
		return address().getAddress32(offset) & getAddressMask32(offset);
	}

	uint64_t getAddressMask64(const uint8_t& offset) const
	{
		if (offset > 128 - 64)
		{
			return 0;
		}

		if (mask() >= 64 + offset)
		{
			return 0xFFFFFFFFFFFFFFFFull;
		}

		if (mask() == offset)
		{
			return 0;
		}

		return 0xFFFFFFFFFFFFFFFFull << (64ull + offset - mask());
	}

	uint32_t getAddressMask32(const uint8_t& offset) const
	{
		if (offset > 128 - 32)
		{
			return 0;
		}

		if (mask() >= 32 + offset)
		{
			return 0xFFFFFFFFu;
		}

		if (mask() == offset)
		{
			return 0;
		}

		return 0xFFFFFFFFu << (32u + offset - mask());
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
	}

	bool subnetFor(const ipv6_address_t& other) const
	{
		return other.applyMask(mask()) == address().applyMask(mask());
	}

	bool subnetOf(const ipv6_prefix_t& other) const
	{
		if (mask() < other.mask())
		{
			return false;
		}

		return address().applyMask(other.mask()) == other.address();
	}

protected:
	std::tuple<ipv6_address_t, uint8_t> prefix;
};

class ipv6_prefix_with_announces_t
{
public:
	ipv6_prefix_with_announces_t() :
	        prefix{}, announces{}
	{
	}

	ipv6_prefix_with_announces_t(const nlohmann::json& prefixJson)
	{
		// prefix could be either a string (for old configs support) or an object
		if (prefixJson.is_string())
		{
			prefix = ipv6_prefix_t{prefixJson.get_ref<const std::string&>()};
			announces.emplace_back(prefix);
		}
		else if (prefixJson.is_object())
		{
			prefix = ipv6_prefix_t{prefixJson["prefix"].get_ref<const std::string&>()};

			const auto& announcesRaw = prefixJson["announces"];
			announces.reserve(announcesRaw.size());
			for (const auto& announceRaw : announcesRaw)
			{
				ipv6_prefix_t announce{announceRaw.get<std::string>()};
				if (!announce.isValid())
				{
					std::ostringstream error;
					error << "prefix has invalid announce: '" << announce.toString()
					      << "' that isn' t a subnet of prefix ";
					YANET_THROW(error.str());
				}
				if (!announce.subnetOf(prefix))
				{
					std::ostringstream error;
					error << "prefix: '" << prefix.toString() << "' has announce: '"
					      << announce.toString() << "' that isn' t a subnet of prefix ";
					YANET_THROW(error.str());
				}
				announces.emplace_back(std::move(announce));
			}
		}
		else
		{
			YANET_THROW(std::string("prefix has invalid type"));
		}
	}

	ipv6_prefix_with_announces_t(ipv6_prefix_t prefix) :
	        prefix(std::move(prefix))
	{
	}

	ipv6_prefix_with_announces_t(ipv6_prefix_t prefix, std::vector<ipv6_prefix_t> announces) :
	        prefix(std::move(prefix)), announces(std::move(announces))
	{
	}

	constexpr bool operator<(const ipv6_prefix_with_announces_t& second) const
	{
		return prefix < second.prefix;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
		stream.pop(announces);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
		stream.push(announces);
	}

public:
	ipv6_prefix_t prefix;
	std::vector<ipv6_prefix_t> announces;
};

class ip_prefix_t
{
public:
	constexpr ip_prefix_t()
	{
	}

	constexpr ip_prefix_t(const ipv4_prefix_t& prefix) :
	        prefix(prefix)
	{
	}

	constexpr ip_prefix_t(const ipv6_prefix_t& prefix) :
	        prefix(prefix)
	{
	}

	constexpr ip_prefix_t(const ip_address_t& address, const uint8_t& mask)
	{
		if (address.is_ipv4())
		{
			prefix = ipv4_prefix_t(address.get_ipv4(), mask);
		}
		else
		{
			prefix = ipv6_prefix_t(address.get_ipv6(), mask);
		}
	}

	ip_prefix_t(const std::string& string)
	{
		if (string.find(':') == std::string::npos)
		{
			prefix = ipv4_prefix_t(string);
		}
		else
		{
			prefix = ipv6_prefix_t(string);
		}
	}

	constexpr bool operator<(const ip_prefix_t& second) const
	{
		return prefix < second.prefix;
	}

	constexpr bool operator>(const ip_prefix_t& second) const
	{
		return prefix > second.prefix;
	}

	bool operator==(const ip_prefix_t& second) const
	{
		return prefix == second.prefix;
	}

	constexpr operator const std::variant<ipv4_prefix_t, ipv6_prefix_t> &() const
	{
		return prefix;
	}

	constexpr operator std::variant<ipv4_prefix_t, ipv6_prefix_t> &()
	{
		return prefix;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		std::string string;

		std::visit([&string](const auto& prefix) {
			string = prefix.toString();
		},
		           prefix);

		return string;
	}

	bool is_ipv4() const
	{
		return std::holds_alternative<ipv4_prefix_t>(prefix);
	}

	bool is_ipv6() const
	{
		return std::holds_alternative<ipv6_prefix_t>(prefix);
	}

	ipv4_prefix_t& get_ipv4()
	{
		return std::get<ipv4_prefix_t>(prefix);
	}

	const ipv4_prefix_t& get_ipv4() const
	{
		return std::get<ipv4_prefix_t>(prefix);
	}

	ipv6_prefix_t& get_ipv6()
	{
		return std::get<ipv6_prefix_t>(prefix);
	}

	const ipv6_prefix_t& get_ipv6() const
	{
		return std::get<ipv6_prefix_t>(prefix);
	}

	uint8_t& mask()
	{
		if (is_ipv4())
		{
			return std::get<ipv4_prefix_t>(prefix).mask();
		}
		else
		{
			return std::get<ipv6_prefix_t>(prefix).mask();
		}
	}

	const uint8_t& mask() const
	{
		if (is_ipv4())
		{
			return std::get<ipv4_prefix_t>(prefix).mask();
		}
		else
		{
			return std::get<ipv6_prefix_t>(prefix).mask();
		}
	}

	bool is_default() const
	{
		if (is_ipv4() &&
		    get_ipv4() == ipv4_prefix_t())
		{
			return true;
		}
		else if (is_ipv6() &&
		         get_ipv6() == ipv6_prefix_t())
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	bool is_host() const
	{
		if (is_ipv4())
		{
			return std::get<ipv4_prefix_t>(prefix).mask() == 32;
		}
		else
		{
			return std::get<ipv6_prefix_t>(prefix).mask() == 128;
		}
	}

	ip_prefix_t get_default() const
	{
		if (is_ipv4())
		{
			return ipv4_prefix_t();
		}
		else
		{
			return ipv6_prefix_t();
		}
	}

	ip_address_t address() const
	{
		if (is_ipv4())
		{
			return get_ipv4().address();
		}
		else
		{
			return get_ipv6().address();
		}
	}

	ip_prefix_t applyMask(const uint8_t& mask) const
	{
		if (is_ipv4())
		{
			return std::get<ipv4_prefix_t>(prefix).applyMask(mask);
		}
		else
		{
			return std::get<ipv6_prefix_t>(prefix).applyMask(mask);
		}
	}

	bool subnetFor(const ip_address_t& other) const
	{
		if (is_ipv4() && other.is_ipv4())
		{
			return get_ipv4().subnetFor(other.get_ipv4());
		}
		else if (is_ipv6() && other.is_ipv6())
		{
			return get_ipv6().subnetFor(other.get_ipv6());
		}
		return false;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
	}

protected:
	std::variant<ipv4_prefix_t, ipv6_prefix_t> prefix;
};

class ip_prefix_with_announces_t
{
public:
	using variant_t = std::variant<ipv4_prefix_with_announces_t, ipv6_prefix_with_announces_t>;

	ip_prefix_with_announces_t()
	{
	}

	ip_prefix_with_announces_t(const nlohmann::json& prefixJson)
	{
		auto prefixString = [&]() -> std::string {
			// prefix could be either a string (for old configs support) or an object
			if (prefixJson.is_string())
			{
				return prefixJson;
			}
			else
			{
				return prefixJson["prefix"];
			}
		}();

		// only IPv4 has ':'
		if (prefixString.find(':') == std::string::npos)
		{
			prefix = ipv4_prefix_with_announces_t{prefixJson};
		}
		else
		{
			prefix = ipv6_prefix_with_announces_t{prefixJson};
		}
	}

	ip_prefix_with_announces_t(const ipv4_prefix_with_announces_t& prefix) :
	        prefix(prefix)
	{
	}

	ip_prefix_with_announces_t(const ipv6_prefix_with_announces_t& prefix) :
	        prefix(prefix)
	{
	}

	constexpr bool operator<(const ip_prefix_with_announces_t& second) const
	{
		return prefix < second.prefix;
	}

	constexpr operator const variant_t&() const
	{
		return prefix;
	}

	constexpr operator variant_t&()
	{
		return prefix;
	}

public:
	ip_prefix_t get_prefix() const
	{
		if (std::holds_alternative<ipv4_prefix_with_announces_t>(prefix))
		{
			return std::get<ipv4_prefix_with_announces_t>(prefix).prefix;
		}
		else
		{
			return std::get<ipv6_prefix_with_announces_t>(prefix).prefix;
		}
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(prefix);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(prefix);
	}

protected:
	variant_t prefix;
};

class community_t
{
public:
	constexpr community_t() :
	        value(0)
	{
	}

	constexpr community_t(const uint32_t& value) :
	        value(value)
	{
	}

	constexpr community_t(const uint16_t& value1,
	                      const uint16_t& value2) :
	        value(value1 << 16 | value2)
	{
	}

	community_t(const std::string& string)
	{
		if (string.find(':') == std::string::npos)
		{
			value = 0;
		}
		else
		{
			value = std::stoll(string.substr(0, string.find(':')), nullptr, 0) << 16;
			value |= std::stoll(string.substr(string.find(':') + 1), nullptr, 0) & 0xFFFF;
		}
	}

	constexpr bool operator<(const community_t& second) const
	{
		return value < second.value;
	}

	bool operator==(const community_t& second) const
	{
		return value == second.value;
	}

	constexpr operator const uint32_t&() const
	{
		return value;
	}

	constexpr operator uint32_t&()
	{
		return value;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		return std::to_string(value >> 16) + ":" + std::to_string(value & 0xFFFF);
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(value);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(value);
	}

protected:
	uint32_t value;
};

class large_community_t
{
public:
	constexpr large_community_t() :
	        value{0, 0, 0}
	{
	}

	constexpr large_community_t(const uint32_t& ga,
	                            const uint32_t& data1,
	                            const uint32_t& data2) :
	        value{ga, data1, data2}
	{
	}

	large_community_t(std::string string)
	{
		value[0] = 0;
		value[1] = 0;
		value[2] = 0;

		if (string.find(':') == std::string::npos)
		{
			value[0] = std::stoll(string, nullptr, 0);
			return;
		}

		value[0] = std::stoll(string.substr(0, string.find(':')), nullptr, 0);
		string = string.substr(string.find(':') + 1);

		if (string.find(':') == std::string::npos)
		{
			value[1] = std::stoll(string, nullptr, 0);
			return;
		}

		value[1] = std::stoll(string.substr(0, string.find(':')), nullptr, 0);
		value[2] = std::stoll(string.substr(string.find(':') + 1), nullptr, 0);
	}

	bool operator<(const large_community_t& second) const
	{
		return value < second.value;
	}

	bool operator==(const large_community_t& second) const
	{
		return value == second.value;
	}

	constexpr operator const std::array<uint32_t, 3> &() const
	{
		return value;
	}

	constexpr operator std::array<uint32_t, 3> &()
	{
		return value;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		return std::to_string(value[0]) + ":" + std::to_string(value[1]) + ":" + std::to_string(value[2]);
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(value);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(value);
	}

public:
	std::array<uint32_t, 3> value;
};

class values_t
{
public:
	values_t()
	{
	}

	template<typename... args_T>
	values_t(const args_T&... args)
	{
		insertHelper(args...);
	}

	operator const std::set<uint64_t> &() const
	{
		return values;
	}

	operator std::set<uint64_t> &()
	{
		return values;
	}

	auto begin() const
	{
		return values.begin();
	}

	auto end() const
	{
		return values.end();
	}

protected:
	template<typename arg0_T, typename... args_T>
	void insertHelper(const arg0_T& arg0,
	                  const args_T&... args)
	{
		values.emplace(arg0);

		if constexpr (sizeof...(args_T))
		{
			insertHelper(args...);
		}
	}

protected:
	std::set<uint64_t> values;
};

class range_t
{
public:
	constexpr range_t()
	{
	}

	constexpr range_t(const uint64_t& value) :
	        range(value, value)
	{
	}

	constexpr range_t(const uint64_t& from,
	                  const uint64_t& to) :
	        range(from, to)
	{
	}

	range_t(const std::string& string)
	{
		if (string.find('-') == std::string::npos)
		{
			range = {std::stoull(string, nullptr, 0),
			         std::stoull(string, nullptr, 0)};
		}
		else
		{
			range = {std::stoull(string.substr(0, string.find('-')), nullptr, 0),
			         std::stoull(string.substr(string.find('-') + 1), nullptr, 0)};
		}
	}

	constexpr bool operator==(const range_t& second) const
	{
		return range == second.range;
	}

	constexpr bool operator!=(const range_t& second) const
	{
		return range != second.range;
	}

	constexpr bool operator<(const range_t& second) const
	{
		return range < second.range;
	}

	constexpr operator const std::tuple<uint64_t, uint64_t> &() const
	{
		return range;
	}

	constexpr operator std::tuple<uint64_t, uint64_t> &()
	{
		return range;
	}

	operator std::string() const
	{
		return toString();
	}

public:
	std::string toString() const
	{
		return std::to_string(from()) + (from() == to() ? "" : "-" + std::to_string(to()));
	}

	uint64_t& from()
	{
		return std::get<0>(range);
	}

	const uint64_t& from() const
	{
		return std::get<0>(range);
	}

	uint64_t& to()
	{
		return std::get<1>(range);
	}

	const uint64_t& to() const
	{
		return std::get<1>(range);
	}

	void pop(stream_in_t& stream)
	{
		stream.pop(range);
	}

	void push(stream_out_t& stream) const
	{
		stream.push(range);
	}

protected:
	std::tuple<uint64_t, uint64_t> range;
};

class flags_t
{
public:
	constexpr flags_t() :
	        flags{0, 0}
	{
	}

	constexpr flags_t(const uint64_t& mask,
	                  const uint64_t& value) :
	        flags{mask, value}
	{
	}

protected:
	std::tuple<uint64_t, uint64_t> flags;
};

class ranges_t ///< @todo: rename filter_t
{
public:
	ranges_t()
	{
	}

	ranges_t(const uint64_t& value)
	{
		ranges.emplace(value, value);
	}

	ranges_t(const values_t& values)
	{
		for (const auto& value : values)
		{
			ranges.emplace(value, value);
		}
	}

	ranges_t(const range_t& range)
	{
		ranges.emplace(range);
	}

	ranges_t(const std::string& string)
	{
		/// @todo: list of ranges

		if (string.find('-') == std::string::npos)
		{
			ranges.emplace(std::stoull(string, nullptr, 0),
			               std::stoull(string, nullptr, 0));
		}
		else
		{
			ranges.emplace(std::stoull(string.substr(0, string.find('-')), nullptr, 0),
			               std::stoull(string.substr(string.find('-') + 1), nullptr, 0));
		}
	}

	bool operator==(const ranges_t& second) const
	{
		return ranges == second.ranges;
	}

	bool operator<(const ranges_t& second) const
	{
		return ranges < second.ranges;
	}

	auto begin() const
	{
		return ranges.begin();
	}

	auto end() const
	{
		return ranges.end();
	}

	bool empty() const
	{
		return ranges.empty();
	}

public:
	void insert(const uint64_t& value)
	{
		ranges.emplace(value, value);
	}

	void insert(const range_t& range)
	{
		ranges.emplace(range);
	}

	void remove(const uint64_t& value)
	{
		std::set<std::tuple<uint64_t, uint64_t>> newRanges;

		for (const auto& [from, to] : ranges)
		{
			if (value < from ||
			    value > to)
			{
				newRanges.emplace(from, to);
				continue;
			}

			if (from == value && to == value)
			{
				continue;
			}

			if (from == value)
			{
				newRanges.emplace(from + 1, to);
			}
			else if (to == value)
			{
				newRanges.emplace(from, to - 1);
			}
			else
			{
				newRanges.emplace(from, value - 1);
				newRanges.emplace(value + 1, to);
			}
		}

		ranges = newRanges;
	}

	bool isIntersect(const ranges_t& second) const
	{
		for (const auto& range : ranges)
		{
			const auto& [from, to] = range;

			for (const auto& secondRange : second.ranges)
			{
				const auto& [secondFrom, secondTo] = secondRange;

				if (from < secondFrom && to < secondFrom)
				{
					continue;
				}
				else if (secondFrom < from && secondTo < from)
				{
					continue;
				}

				return true;
			}
		}

		return false;
	}

protected:
	std::set<std::tuple<uint64_t, uint64_t>> ranges;
};

//

constexpr ipv4_address_t ipv4_address_default = {0};
constexpr ipv6_address_t ipv6_address_default = {std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
constexpr ipv4_prefix_t ipv4_prefix_default = {ipv4_address_default, 0};
constexpr ipv6_prefix_t ipv6_prefix_default = {ipv6_address_default, 0};

//

namespace worker
{
namespace stats
{
struct common
{
	uint64_t brokenPackets;
	uint64_t dropPackets;
	uint64_t ring_highPriority_drops;
	uint64_t ring_normalPriority_drops;
	uint64_t ring_lowPriority_drops;
	uint64_t ring_highPriority_packets;
	uint64_t ring_normalPriority_packets;
	uint64_t ring_lowPriority_packets;

	/// @todo: use counters
	uint64_t decap_packets;
	uint64_t decap_fragments;
	uint64_t decap_unknownExtensions;
	uint64_t interface_lookupMisses;
	uint64_t interface_hopLimits;
	uint64_t interface_neighbor_invalid;
	uint64_t nat64stateless_ingressPackets;
	uint64_t nat64stateless_ingressFragments;
	uint64_t nat64stateless_ingressUnknownICMP;
	uint64_t nat64stateless_egressPackets;
	uint64_t nat64stateless_egressFragments;
	uint64_t nat64stateless_egressUnknownICMP;
	uint64_t balancer_invalid_reals_count;
	uint64_t fwsync_multicast_egress_drops;
	uint64_t fwsync_multicast_egress_packets;
	uint64_t fwsync_multicast_egress_imm_packets;
	uint64_t fwsync_no_config_drops;
	uint64_t fwsync_unicast_egress_drops;
	uint64_t fwsync_unicast_egress_packets;
	uint64_t acl_ingress_dropPackets;
	uint64_t acl_egress_dropPackets;
	uint64_t repeat_ttl;
	uint64_t leakedMbufs;
	uint64_t logs_packets;
	uint64_t logs_drops;
};

struct port
{
	port()
	{
		memset(this, 0, sizeof(*this));
	}

	void pop(stream_in_t& stream)
	{
		stream.pop((char*)this, sizeof(*this));
	}

	void push(stream_out_t& stream) const
	{
		stream.push((char*)this, sizeof(*this));
	}

	uint64_t physicalPort_egress_drops;
	uint64_t controlPlane_drops; ///< @todo: DELETE
};
}
}

namespace worker_gc
{
struct stats_t
{
	/// @todo
	uint64_t broken_packets;
	uint64_t drop_packets;
	uint64_t ring_to_slowworker_packets;
	uint64_t ring_to_slowworker_drops;
	uint64_t fwsync_multicast_egress_packets;
	uint64_t fwsync_multicast_egress_drops;
	uint64_t fwsync_unicast_egress_packets;
	uint64_t fwsync_unicast_egress_drops;
	uint64_t drop_samples;
	uint64_t balancer_state_insert_failed;
	uint64_t balancer_state_insert_done;
};
}

namespace globalBase ///< @todo: remove
{
enum class static_counter_type : uint32_t
{
	start = YANET_CONFIG_COUNTER_FALLBACK_SIZE - 1,
	balancer_state,
	balancer_state_insert_failed = balancer_state,
	balancer_state_insert_done,
	balancer_icmp_generated_echo_reply_ipv4,
	balancer_icmp_generated_echo_reply_ipv6,
	balancer_icmp_sent_to_real,
	balancer_icmp_drop_icmpv4_payload_too_short_ip,
	balancer_icmp_drop_icmpv4_payload_too_short_port,
	balancer_icmp_drop_icmpv6_payload_too_short_ip,
	balancer_icmp_drop_icmpv6_payload_too_short_port,
	balancer_icmp_unmatching_src_from_original_ipv4,
	balancer_icmp_unmatching_src_from_original_ipv6,
	balancer_icmp_drop_real_disabled,
	balancer_icmp_no_balancer_src_ipv4,
	balancer_icmp_no_balancer_src_ipv6,
	balancer_icmp_drop_already_cloned,
	balancer_icmp_out_rate_limit_reached,
	balancer_icmp_drop_no_unrdup_table_for_balancer_id,
	balancer_icmp_drop_unrdup_vip_not_found,
	balancer_icmp_drop_no_vip_vport_proto_table_for_balancer_id,
	balancer_icmp_drop_unexpected_transport_protocol,
	balancer_icmp_drop_unknown_service,
	balancer_icmp_failed_to_clone,
	balancer_icmp_clone_forwarded,
	balancer_fragment_drops,
	acl_ingress_v4_broken_packet,
	acl_ingress_v6_broken_packet,
	acl_egress_v4_broken_packet,
	acl_egress_v6_broken_packet,
	slow_worker_normal_priority_rate_limit_exceeded,
	size
};

enum class eNexthopType : unsigned int
{
	drop,
	interface,
	controlPlane,
	repeat,
};

enum class eFlowType : uint8_t
{
	drop,
	acl_ingress,
	tun64_ipv4_checked,
	tun64_ipv6_checked,
	decap_checked, ///< @todo: decap
	nat64stateful_lan,
	nat64stateful_wan,
	nat64stateless_ingress_checked, ///< @todo: nat64stateless_ingress
	nat64stateless_ingress_icmp,
	nat64stateless_ingress_fragmentation,
	nat64stateless_egress_checked, ///< @todo: nat64stateless_egress
	nat64stateless_egress_icmp,
	nat64stateless_egress_fragmentation,
	nat64stateless_egress_farm,
	balancer,
	balancer_icmp_reply,
	balancer_icmp_forward,
	route,
	route_local,
	route_tunnel,
	acl_egress,
	dregress,
	controlPlane,
	logicalPort_egress,
	slowWorker_nat64stateless_ingress_icmp,
	slowWorker_nat64stateless_ingress_fragmentation,
	slowWorker_nat64stateless_egress_icmp,
	slowWorker_nat64stateless_egress_fragmentation,
	slowWorker_nat64stateless_egress_farm,
	slowWorker_dregress,
	slowWorker_kni,
	slowWorker_dump,
	slowWorker_repeat,
	slowWorker_kni_local,
	slowWorker_fw_sync,
	after_early_decap,
	slowWorker_balancer_icmp_forward,
	balancer_fragment,
	nat46clat_lan,
	nat46clat_wan,
};

inline const char* eFlowType_toString(eFlowType t)
{
	switch (t)
	{
		case eFlowType::drop:
			return "drop";
		case eFlowType::acl_ingress:
			return "acl_ingress";
		case eFlowType::tun64_ipv4_checked:
			return "tun64_ipv4_checked";
		case eFlowType::tun64_ipv6_checked:
			return "tun64_ipv6_checked";
		case eFlowType::decap_checked:
			return "decap_checked";
		case eFlowType::nat64stateful_lan:
			return "nat64stateful_lan";
		case eFlowType::nat64stateful_wan:
			return "nat64stateful_wan";
		case eFlowType::nat64stateless_ingress_checked:
			return "nat64stateless_ingress_checked";
		case eFlowType::nat64stateless_ingress_icmp:
			return "nat64stateless_ingress_icmp";
		case eFlowType::nat64stateless_ingress_fragmentation:
			return "nat64stateless_ingress_fragmentation";
		case eFlowType::nat64stateless_egress_checked:
			return "nat64stateless_egress_checked";
		case eFlowType::nat64stateless_egress_icmp:
			return "nat64stateless_egress_icmp";
		case eFlowType::nat64stateless_egress_fragmentation:
			return "nat64stateless_egress_fragmentation";
		case eFlowType::nat64stateless_egress_farm:
			return "nat64stateless_egress_farm";
		case eFlowType::balancer:
			return "balancer";
		case eFlowType::balancer_icmp_reply:
			return "balancer_icmp_reply";
		case eFlowType::balancer_icmp_forward:
			return "balancer_icmp_forward";
		case eFlowType::route:
			return "route";
		case eFlowType::route_local:
			return "route_local";
		case eFlowType::route_tunnel:
			return "route_tunnel";
		case eFlowType::acl_egress:
			return "acl_egress";
		case eFlowType::dregress:
			return "dregress";
		case eFlowType::controlPlane:
			return "controlPlane";
		case eFlowType::logicalPort_egress:
			return "logicalPort_egress";
		case eFlowType::slowWorker_nat64stateless_ingress_icmp:
			return "slowWorker_nat64stateless_ingress_icmp";
		case eFlowType::slowWorker_nat64stateless_ingress_fragmentation:
			return "slowWorker_nat64stateless_ingress_fragmentation";
		case eFlowType::slowWorker_nat64stateless_egress_icmp:
			return "slowWorker_nat64stateless_egress_icmp";
		case eFlowType::slowWorker_nat64stateless_egress_fragmentation:
			return "slowWorker_nat64stateless_egress_fragmentation";
		case eFlowType::slowWorker_nat64stateless_egress_farm:
			return "slowWorker_nat64stateless_egress_farm";
		case eFlowType::slowWorker_dregress:
			return "slowWorker_dregress";
		case eFlowType::slowWorker_kni:
			return "slowWorker_kni";
		case eFlowType::slowWorker_dump:
			return "slowWorker_dump";
		case eFlowType::slowWorker_repeat:
			return "slowWorker_repeat";
		case eFlowType::slowWorker_kni_local:
			return "slowWorker_kni_local";
		case eFlowType::slowWorker_fw_sync:
			return "slowWorker_fw_sync";
		case eFlowType::after_early_decap:
			return "after_early_decap";
		case eFlowType::slowWorker_balancer_icmp_forward:
			return "slowWorker_balancer_icmp_forward";
		case eFlowType::balancer_fragment:
			return "balancer_fragment";
		case eFlowType::nat46clat_lan:
			return "nat46clat_lan";
		case eFlowType::nat46clat_wan:
			return "nat46clat_wan";
	}

	return "unknown";
}

enum class eFlowFlags : uint8_t
{
	keepstate = 1,
	log = 2,
};

enum class dump_type_e : uint8_t
{
	physicalPort_ingress,
	physicalPort_egress,
	physicalPort_drop,
	acl,
};

union tFlowData
{
	tLogicalPortId logicalPortId;
	tAclId aclId;
	tDecapId decapId;
	tRouteId routeId;
	nat64stateful_id_t nat64stateful_id;
	nat46clat_id_t nat46clat_id;
	dregress_id_t dregressId;
	tun64_id_t tun64Id;

	struct
	{
		tNat64statelessId id : 8;
		tNat64statelessTranslationId translationId : 24;
	} nat64stateless;

	struct
	{
		balancer_id_t id : 8;
		balancer_service_id_t service_id : 24;
	} balancer;

	struct
	{
		dump_type_e type : 8;
		uint32_t id : 24;
	} dump;

	uint32_t atomic;
};

static_assert(CONFIG_YADECAP_NAT64STATELESSES_SIZE <= 0xFF);
static_assert(CONFIG_YADECAP_NAT64STATELESS_TRANSLATIONS_SIZE <= 0xFFFFFF);

using flow_data_t = tFlowData;

class tFlow
{
public:
	tFlow() :
	        type(eFlowType::controlPlane), ///< @todo: drop
	        flags(0),
	        counter_id(0)
	{
		data.atomic = 0;
	}

	tFlow(eFlowType t) :
	        type(t),
	        flags(0),
	        counter_id(0)
	{
		data.atomic = 0;
	}

	inline bool operator==(const tFlow& second) const
	{
		return std::tie(type_params_atomic, data.atomic) == std::tie(second.type_params_atomic, second.data.atomic);
	}

	inline bool operator!=(const tFlow& second) const
	{
		return !operator==(second);
	}

	constexpr bool operator<(const tFlow& second) const
	{
		return std::tie(type_params_atomic, data.atomic) < std::tie(second.type_params_atomic, second.data.atomic);
	}

public:
	uint64_t getId() ///< @todo
	{
		if (type == eFlowType::nat64stateless_ingress_checked ||
		    type == eFlowType::nat64stateless_ingress_icmp ||
		    type == eFlowType::nat64stateless_ingress_fragmentation ||
		    type == eFlowType::slowWorker_nat64stateless_ingress_icmp ||
		    type == eFlowType::slowWorker_nat64stateless_ingress_fragmentation)
		{
			return data.nat64stateless.id;
		}

		if (type == eFlowType::nat64stateless_egress_checked ||
		    type == eFlowType::nat64stateless_egress_icmp ||
		    type == eFlowType::nat64stateless_egress_fragmentation ||
		    type == eFlowType::slowWorker_nat64stateless_egress_icmp ||
		    type == eFlowType::slowWorker_nat64stateless_egress_fragmentation)
		{
			return data.nat64stateless.id;
		}

		return data.atomic;
	}

	void pop(stream_in_t& stream)
	{
		stream.pop((char*)this, sizeof(*this));
	}

	void push(stream_out_t& stream) const
	{
		stream.push((char*)this, sizeof(*this));
	}

public:
	union
	{
		uint32_t type_params_atomic;
		struct
		{
			eFlowType type;
			uint8_t flags : 2;
			uint32_t counter_id : 22;
		};
	};

	flow_data_t data;
};

static_assert(YANET_CONFIG_ACL_COUNTERS_SIZE < (1 << 22));

using flow_t = tFlow;
}

namespace defender
{

enum class status
{
	success,
	fail
};

using result = std::tuple<status, std::string>;

}

namespace getPortStatsEx
{
using portCounters = std::tuple<uint64_t, //< bytes
                                uint64_t, //< unicast_pkts
                                uint64_t, //< multicast_pkts
                                uint64_t, //< broadcast_pkts
                                uint64_t, //< drops
                                uint64_t>; //< errors

using port = std::tuple<std::string, //< name
                        uint8_t, //< link_state
                        portCounters, ///< in
                        portCounters>; ///< out

using response = std::map<tPortId, port>;
}

namespace fragmentation
{

struct stats_t
{
	uint64_t current_count_packets;
	uint64_t total_overflow_packets;
	uint64_t not_fragment_packets;
	uint64_t empty_packets;
	uint64_t flow_overflow_packets;
	uint64_t intersect_packets;
	uint64_t unknown_network_type_packets;
	uint64_t timeout_packets;
};

}

namespace tun64
{

struct stats_t
{
	uint64_t encap_packets;
	uint64_t encap_bytes;
	uint64_t encap_dropped;
	uint64_t decap_packets;
	uint64_t decap_bytes;
	uint64_t decap_unknown;
};

}

namespace tun64mapping
{

struct stats_t
{
	uint64_t encap_packets;
	uint64_t encap_bytes;
	uint64_t decap_packets;
	uint64_t decap_bytes;
};

}

namespace dregress
{

struct stats_t
{
	uint64_t bad_decap_transport;
	uint64_t fragment;
	uint64_t bad_transport;
	uint64_t lookup_miss;
	uint64_t local;
	uint64_t tcp_syn;
	uint64_t tcp_unknown_option;
	uint64_t tcp_no_option;
	uint64_t tcp_insert_sessions;
	uint64_t tcp_close_sessions;
	uint64_t tcp_retransmission;
	uint64_t tcp_ok;
	uint64_t tcp_timeout_sessions;
	uint64_t tcp_unknown_sessions;
};

using value_t = std::tuple<common::ip_address_t, ///< nexthop
                           uint32_t, ///< label
                           common::community_t,
                           uint32_t, ///< peer_as
                           uint32_t, ///< origin_as
                           bool>; ///< is_best

using counters_t = common::ctree<4, ///< ack, loss, rtt_sum, rtt_count
                                 common::community_t,
                                 common::ip_address_t, ///< nexthop
                                 bool, ///< is_best
                                 uint32_t, ///< label
                                 uint32_t, ///< peer_as
                                 uint32_t, ///< origin_as
                                 common::ip_prefix_t>;

}

namespace slowworker
{

struct stats_t
{
	uint64_t repeat_packets;
	uint64_t tofarm_packets;
	uint64_t farm_packets;
	uint64_t fwsync_multicast_ingress_packets;
	uint64_t slowworker_packets;
	uint64_t slowworker_drops;
	uint64_t mempool_is_empty;
	uint64_t unknown_dump_interface;
};

}

namespace fwstate
{

struct stats_t
{
	uint64_t fwstate4_size;
	uint64_t fwstate6_size;
};

enum class owner_e : uint8_t
{
	internal = 0x01,
	external = 0x02,
};

enum class tcp_flags_e : uint8_t
{
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	ACK = 0x08,
};

inline uint8_t from_tcp_flags(uint8_t tcp_flags)
{
	/*
	 * RTE_TCP_ACK_FLAG 0x10
	 * RTE_TCP_PSH_FLAG 0x08
	 * RTE_TCP_RST_FLAG 0x04
	 * RTE_TCP_SYN_FLAG 0x02
	 * RTE_TCP_FIN_FLAG 0x01
	 */
	return (tcp_flags & 7) | (tcp_flags & 0X10 ? uint8_t(tcp_flags_e::ACK) : 0);
}
inline std::string flags_to_string(uint8_t flags)
{
	std::string ret;
	if (flags & uint8_t(tcp_flags_e::SYN))
	{
		ret += "S";
	}
	if (flags & uint8_t(tcp_flags_e::RST))
	{
		ret += "R";
	}
	if (flags & uint8_t(tcp_flags_e::ACK))
	{
		ret += "A";
	}
	if (flags & uint8_t(tcp_flags_e::FIN))
	{
		ret += "F";
	}
	return ret;
}

} // namespace fwstate

template<class T>
inline void hash_combine(std::size_t& s, const T& v)
{
	std::hash<T> h;
	s ^= h(v) + 0x9e3779b9 + (s << 6) + (s >> 2);
}

}

// specialization of std::hash
namespace std
{

template<>
struct hash<common::ipv4_address_t>
{
	std::size_t operator()(const common::ipv4_address_t& ip_addr) const
	{
		const uint32_t ipv4 = static_cast<uint32_t>(ip_addr);
		return std::hash<uint32_t>()(ipv4);
	}
};

template<>
struct hash<common::ipv6_address_t>
{
	std::size_t operator()(const common::ipv6_address_t& ip_addr) const
	{
		uint64_t ipv6_low = ip_addr.getAddress64(0);
		uint64_t ipv6_high = ip_addr.getAddress64(64);

		std::size_t res = 0;
		common::hash_combine(res, ipv6_low);
		common::hash_combine(res, ipv6_high);

		return res;
	}
};

template<>
struct hash<common::ip_address_t>
{
	std::size_t operator()(const common::ip_address_t& ip_addr) const
	{
		if (ip_addr.is_ipv4())
		{
			return std::hash<common::ipv4_address_t>()(ip_addr.get_ipv4());
		}

		return std::hash<common::ipv6_address_t>()(ip_addr.get_ipv6());
	}
};

template<>
struct hash<std::tuple<common::ip_address_t, uint16_t, uint8_t>>
{
	std::size_t operator()(const std::tuple<common::ip_address_t, uint16_t, uint8_t> vip_vport_proto) const
	{
		common::ip_address_t vip = std::get<0>(vip_vport_proto);
		uint16_t vport = std::get<1>(vip_vport_proto);
		uint8_t proto = std::get<2>(vip_vport_proto);

		std::size_t res = 0;
		common::hash_combine(res, vip);
		common::hash_combine(res, vport);
		common::hash_combine(res, proto);

		return res;
	}
};

template<>
struct hash<common::ip_prefix_t>
{
	std::size_t operator()(const common::ip_prefix_t& prefix) const
	{
		if (prefix.is_ipv4())
		{
			uint64_t ipv4 = static_cast<uint32_t>(prefix.get_ipv4().address()) + (prefix.get_ipv4().mask() << 4);
			return std::hash<uint64_t>()(ipv4);
		}

		uint64_t ipv6_low = prefix.get_ipv6().address().getAddress64(0);
		uint64_t ipv6_high = prefix.get_ipv6().address().getAddress64(64);
		uint64_t ipv6_mask = prefix.get_ipv6().getAddressMask64(0);

		std::size_t res = 0;
		common::hash_combine(res, ipv6_low);
		common::hash_combine(res, ipv6_high);
		common::hash_combine(res, ipv6_mask);

		return res;
	}
};

template<>
struct hash<std::tuple<std::string, common::ip_address_t, std::string>>
{
	std::size_t operator()(const std::tuple<std::string, common::ip_address_t, std::string>& protocol_peer_table_name) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(protocol_peer_table_name));
		common::hash_combine(res, std::get<1>(protocol_peer_table_name));
		common::hash_combine(res, std::get<2>(protocol_peer_table_name));

		return res;
	}
};

template<>
struct hash<std::tuple<std::string, common::ip_address_t, std::string, std::string>>
{
	std::size_t operator()(const std::tuple<std::string, common::ip_address_t, std::string, std::string>& nexthop_key) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(nexthop_key));
		common::hash_combine(res, std::get<1>(nexthop_key));
		common::hash_combine(res, std::get<2>(nexthop_key));
		common::hash_combine(res, std::get<3>(nexthop_key));

		return res;
	}
};

template<>
struct hash<std::tuple<std::string, uint32_t>>
{
	std::size_t operator()(const std::tuple<std::string, uint32_t>& vrf_priority) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(vrf_priority));
		common::hash_combine(res, std::get<1>(vrf_priority));

		return res;
	}
};

template<>
struct hash<std::tuple<common::ip_prefix_t, std::string, common::ip_address_t, std::string, uint32_t, std::string>>
{
	std::size_t operator()(const std::tuple<common::ip_prefix_t, std::string, common::ip_address_t, std::string, uint32_t, std::string>& stats_helper_key) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(stats_helper_key));
		common::hash_combine(res, std::get<1>(stats_helper_key));
		common::hash_combine(res, std::get<2>(stats_helper_key));
		common::hash_combine(res, std::get<3>(stats_helper_key));
		common::hash_combine(res, std::get<4>(stats_helper_key));
		common::hash_combine(res, std::get<5>(stats_helper_key));

		return res;
	}
};

template<>
struct hash<std::tuple<std::string, uint32_t, std::string, common::ip_address_t, std::string>>
{
	std::size_t operator()(const std::tuple<std::string, uint32_t, std::string, common::ip_address_t, std::string>& summary_key) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(summary_key));
		common::hash_combine(res, std::get<1>(summary_key));
		common::hash_combine(res, std::get<2>(summary_key));
		common::hash_combine(res, std::get<3>(summary_key));
		common::hash_combine(res, std::get<4>(summary_key));

		return res;
	}
};

}

namespace common
{

namespace rib
{
using nexthop_t = std::map<std::tuple<std::string, ///< protocol
                                      ip_address_t, ///< peer
                                      std::string, ///< table_name
                                      std::string>, ///< path_information
                           std::tuple<ip_address_t, ///< nexthop
                                      std::vector<uint32_t>, ///< labels
                                      std::string, ///< origin
                                      uint32_t, ///< med
                                      std::vector<uint32_t>, ///< aspath
                                      std::set<community_t>, ///< communities
                                      std::set<large_community_t>, ///< large_communities
                                      uint32_t>>; ///< local_preference

using vrf_priority_t = std::tuple<std::string, uint32_t>;

using pptn_t = std::tuple<std::string, ///< protocol
                          ip_address_t, ///< peer
                          std::string ///< table_name
                          >;

using vppptn_t = std::tuple<std::string, ///< vrf
                            uint32_t, ///< priority
                            std::string, ///< protocol
                            ip_address_t, ///< peer
                            std::string ///< table_name
                            >;

using nexthop_stuff_t = std::tuple<ip_address_t, ///< nexthop
                                   std::vector<uint32_t>, ///< labels
                                   std::string, ///< origin
                                   uint32_t, ///< med
                                   std::vector<uint32_t>, ///< aspath
                                   std::set<common::community_t>, ///< communities
                                   std::set<common::large_community_t>, ///< large_communities
                                   uint32_t ///< local_preference
                                   >;

using nexthop_map_t = std::unordered_map<uint32_t,
                                         std::unordered_map<std::string, ///< path_info
                                                            const rib::nexthop_stuff_t*>>;

using path_info_to_nexthop_stuff_ptr_t = std::unordered_map<std::string, ///< path_info
                                                            const nexthop_stuff_t*>;
}

namespace acl
{
typedef std::map<tAclId, std::set<std::tuple<bool, std::string>>> iface_map_t; // true -> ingress
}

}

// specialization of std::hash for nexthop_stuff_t
namespace std
{

template<>
struct hash<common::community_t>
{
	std::size_t operator()(const common::community_t& community) const
	{
		std::size_t res = 0;

		common::hash_combine(res, static_cast<uint32_t>(community));

		return res;
	}
};

template<>
struct hash<common::large_community_t>
{
	std::size_t operator()(const common::large_community_t& large_community) const
	{
		std::size_t res = 0;

		common::hash_combine(res, large_community.value[0]);
		common::hash_combine(res, large_community.value[1]);
		common::hash_combine(res, large_community.value[2]);

		return res;
	}
};

template<>
struct hash<std::vector<uint32_t>>
{
	std::size_t operator()(const std::vector<uint32_t>& labels) const
	{
		std::size_t res = 0;

		for (const auto& label : labels)
		{
			common::hash_combine(res, label);
		}

		return res;
	}
};

template<>
struct hash<std::set<common::community_t>>
{
	std::size_t operator()(const std::set<common::community_t>& communities) const
	{
		std::size_t res = 0;

		for (const auto& community : communities)
		{
			common::hash_combine(res, community);
		}

		return res;
	}
};

template<>
struct hash<std::set<common::large_community_t>>
{
	std::size_t operator()(const std::set<common::large_community_t>& large_communities) const
	{
		std::size_t res = 0;

		for (const auto& large_community : large_communities)
		{
			common::hash_combine(res, large_community);
		}

		return res;
	}
};

template<>
struct hash<common::rib::nexthop_stuff_t>
{
	std::size_t operator()(const common::rib::nexthop_stuff_t& nxthp_stff) const
	{
		std::size_t res = 0;
		common::hash_combine(res, std::get<0>(nxthp_stff));
		common::hash_combine(res, std::get<1>(nxthp_stff));
		common::hash_combine(res, std::get<2>(nxthp_stff));
		common::hash_combine(res, std::get<3>(nxthp_stff));
		common::hash_combine(res, std::get<4>(nxthp_stff));
		common::hash_combine(res, std::get<5>(nxthp_stff));
		common::hash_combine(res, std::get<6>(nxthp_stff));
		common::hash_combine(res, std::get<7>(nxthp_stff));

		return res;
	}
};

}
