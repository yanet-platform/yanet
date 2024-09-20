#include <map>

#include "../../common/result.h"
#include "../type.h"
#include "../vrf.h"

template<typename PrefixType, typename AddressType, typename LookupAddressType>
class VrfLpmMap
{
public:
	eResult Insert(dataplane::vrflpm::stats_t& stats,
	               tVrfId vrfId,
	               const AddressType& ipAddress,
	               const uint8_t& mask,
	               const uint32_t& valueId)
	{
		values_[vrfId][BuildPrefix(ipAddress, mask)] = valueId;
		return eResult::success;
	}

	eResult Remove(dataplane::vrflpm::stats_t& stats,
	               tVrfId vrfId,
	               const AddressType& ipAddress,
	               const uint8_t& mask)
	{
		auto iter = values_.find(vrfId);
		if (iter != values_.end())
		{
			iter->second.erase(BuildPrefix(ipAddress, mask));
		}
		return eResult::success;
	}

	void Lookup(const LookupAddressType* ipAddresses,
	            const tVrfId* vrfIds,
	            uint32_t* valueIds,
	            const unsigned int& count) const
	{
		for (unsigned int index = 0; index < count; index++)
		{
			valueIds[index] = dataplane::vrflpm::lpmValueIdInvalid;

			const auto iter = values_.find(vrfIds[index]);
			if (iter == values_.end())
			{
				continue;
			}

			uint8_t max_length = 0;
			for (const auto& [prefix, value] : iter->second)
			{
				if ((max_length == 0 || prefix.mask > max_length) && PrefixContains(prefix, ipAddresses[index]))
				{
					max_length = prefix.mask;
					valueIds[index] = value;
				}
			}
		}
	}

	std::vector<std::tuple<tVrfId, AddressType, uint8_t, uint32_t>> GetFullList() const
	{
		std::vector<std::tuple<tVrfId, AddressType, uint8_t, uint32_t>> result;
		for (const auto& [vrf, iter] : values_)
		{
			for (const auto& [prefix, value] : iter)
			{
				result.emplace_back(vrf, AddressForUpload(prefix.address), prefix.mask, value);
			}
		}
		return result;
	}

private:
	struct PrefixesComparator
	{
		bool operator()(const ipv6_prefix_t& left, const ipv6_prefix_t& right) const
		{
			return common::ipv6_prefix_t(left.address.bytes, left.mask) < common::ipv6_prefix_t(right.address.bytes, right.mask);
		}

		bool operator()(const ipv4_prefix_t& left, const ipv4_prefix_t& right) const
		{
			return common::ipv4_prefix_t(left.address.address, left.mask) < common::ipv4_prefix_t(right.address.address, right.mask);
		}
	};

	std::map<tVrfId, std::map<PrefixType, uint32_t, PrefixesComparator>> values_;

	ipv6_prefix_t BuildPrefix(const std::array<uint8_t, 16>& address, uint8_t mask) const
	{
		return {ipv6_address_t::convert(common::ipv6_address_t{address.data()}), mask};
	}

	ipv4_prefix_t BuildPrefix(const uint32_t& address, uint8_t mask) const
	{
		return {common::ipv4_address_t(address), mask};
	}

	uint32_t AddressForUpload(const ipv4_address_t& address) const
	{
		return address.address;
	}

	std::array<uint8_t, 16> AddressForUpload(const ipv6_address_t& address) const
	{
		return common::ipv6_address_t(address.bytes);
	}

	bool PrefixContains(const ipv6_prefix_t& prefix, const ipv6_address_t& address) const
	{
		return (common::ipv6_address_t(address.bytes).applyMask(prefix.mask) == common::ipv6_address_t(prefix.address.bytes));
	}

	bool PrefixContains(const ipv4_prefix_t& prefix, const uint32_t& address) const
	{
		return (common::ipv4_address_t(rte_cpu_to_be_32(address)).applyMask(prefix.mask) == common::ipv4_address_t(prefix.address.address));
	}
};
