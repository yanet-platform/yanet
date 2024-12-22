#pragma once

#include <array>

#include "lpm.h"
#include "type.h"

namespace dataplane::vrflpm
{

template<typename Address, typename InnerLpmType>
class VrfLookuper
{
public:
	void Update(std::array<InnerLpmType*, YANET_RIB_VRF_MAX_NUMBER> lpms)
	{
		for (size_t index = 0; index < lpms_.size(); index++)
		{
			lpms_[index] = lpms[index];
		}
	}

	void Lookup(const Address* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const
	{
		for (unsigned int index = 0; index < count; index++)
		{
			valueIds[index] = lpmValueIdInvalid;
			tVrfId vrf = vrfIds[index];
			if ((vrf < YANET_RIB_VRF_MAX_NUMBER) && (lpms_[vrf] != nullptr))
			{
				lpms_[vrf]->lookup(ipAddresses + index, valueIds + index, 1);
			}
		}
	}

private:
	std::array<InnerLpmType*, YANET_RIB_VRF_MAX_NUMBER> lpms_;
};

} // namespace dataplane
