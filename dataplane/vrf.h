#pragma once

#include <array>
#include <set>
#include <tuple>
#include <vector>

#include "common/result.h"
#include "common/type.h"

class VrfIpv4
{
public:
	eResult Insert(tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId);
    eResult Remove(tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask);
    void Clear();
    void Lookup(tVrfId vrfId, const uint32_t& ipAddress, uint32_t* valueId) const;

private:
	std::map<tVrfId, std::map<std::tuple<uint32_t, uint8_t>, uint32_t>> vrf_tables; // vrfId -> vector<ipAddress, mask, valueId>;
};

class VrfIpv6
{
public:
	eResult Insert(tVrfId vrfId, const std::array<uint8_t, 16>& ipv6Address, const uint8_t& mask, const uint32_t& valueId);
    eResult Remove(tVrfId vrfId, const std::array<uint8_t, 16>& ipv6Address, const uint8_t& mask);
    void Clear();
    void Lookup(tVrfId vrfId, const uint8_t* ipv6Address, uint32_t* valueId) const;

private:
	std::map<uint16_t, std::map<std::tuple<std::array<uint8_t, 16>, uint8_t>, uint32_t>> vrf_tables; // vrfId -> vector<ipAddress, mask, valueId>;
};
