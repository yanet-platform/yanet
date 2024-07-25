#include "vrf.h"

#include <rte_errno.h>
#include <rte_ethdev.h>


eResult VrfIpv4::Insert(tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId)
{
	vrf_tables[vrfId][{ipAddress, mask}] = valueId;
	// YANET_LOG_WARNING("insert vrf=%d, %s/%d, size vrf=%ld\n", vrfId, common::ipv4_address_t(ipAddress).toString().c_str(), mask, vrf_tables[vrfId].size());
	return eResult::success;
}

eResult VrfIpv4::Remove(tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask)
{
    vrf_tables[vrfId].erase({ipAddress, mask});
    return eResult::success;
}

void VrfIpv4::Clear()
{
    vrf_tables.clear();
}

void VrfIpv4::Lookup(tVrfId vrfId, const uint32_t& address, uint32_t* value_id) const
{
	uint32_t address_be = rte_cpu_to_be_32(address);
	// YANET_LOG_WARNING("lookup_vrf %d, ip=%s\n", vrfId, common::ipv4_address_t(address_be).toString().c_str());
	const auto iter = vrf_tables.find(vrfId);
	if (iter != vrf_tables.end())
	{
		// YANET_LOG_WARNING("size table: %ld\n", iter->second.size());
		uint8_t best_mask = 0;
		for (auto [key, valueId] : iter->second)
		{
            auto [ipAddress, mask] = key;
			if (mask >= best_mask)
			{
				// YANET_LOG_WARNING("Check %s/%d, valueId=%d\n", common::ipv4_address_t(ipAddress).toString().c_str(), uint16_t(mask), valueId);
				if (common::ipv4_address_t(address_be).applyMask(mask) == ipAddress)
				{
					*value_id = valueId;
					best_mask = mask;
					// YANET_LOG_WARNING("OK\n");
				}
			}
		}
	}
}

eResult VrfIpv6::Insert(tVrfId vrfId, const std::array<uint8_t, 16>& ipv6Address, const uint8_t& mask, const uint32_t& valueId)
{
	vrf_tables[vrfId][{ipv6Address, mask}] = valueId;
	// YANET_LOG_WARNING("insert vrf=%d, %s/%d, size vrf=%ld\n", vrfId, common::ipv6_address_t(ipv6Address).toString().c_str(), mask, vrf_tables[vrfId].size());
	return eResult::success;
}

eResult VrfIpv6::Remove(tVrfId vrfId, const std::array<uint8_t, 16>& ipv6Address, const uint8_t& mask)
{
    vrf_tables[vrfId].erase({ipv6Address, mask});
    return eResult::success;
}

void VrfIpv6::Clear()
{
    vrf_tables.clear();
}

void VrfIpv6::Lookup(tVrfId vrfId, const uint8_t* ipv6Address, uint32_t* value_id) const
{
    // YANET_LOG_WARNING("lookup_vrf %d, ip=%s\n", vrfId, common::ip_address_t(ipv6Address).toString().c_str());
    const auto iter = vrf_tables.find(vrfId);
    if (iter != vrf_tables.end())
    {
        uint8_t best_mask = 0;
        for (const auto& [key, valueId] : iter->second)
        {
            const auto& [ipAddress, mask] = key;
            if (mask >= best_mask)
            {
                // YANET_LOG_WARNING("Check %s/%d\n", common::ipv6_address_t(ipAddress).toString().c_str(), uint16_t(mask));
                if (common::ipv6_address_t(ipv6Address).applyMask(mask) == ipAddress)
                {
                    best_mask = mask;
                    *value_id = valueId;
                    // YANET_LOG_WARNING("OK\n");
                }
            }
        }
    }
}
