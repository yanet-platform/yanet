#include <queue>

#include "vrf.h"

std::string ip4str(uint32_t ipAddress)
{
	return common::ipv4_address_t(ipAddress).toString();
}

std::string ip6str(const uint8_t* ipAddress)
{
	return common::ipv6_address_t(ipAddress).toString();
}

namespace dataplane::vrflpm
{

template<typename Allocator>
void UpdateStats(Allocator& allocator, stats_t& stats)
{
	auto [blocks_total, blocks_used] = allocator.Stat();
	stats.extended_chunks_size = blocks_total;
	stats.extended_chunks_count = blocks_used;
}

/*
 * Implementation VrfLpm4Linear
 */

VrfLpm4Linear::VrfLpm4Linear(BlocksAllocator& allocator) :
        allocator_(allocator)
{
	Clear();
}

eResult VrfLpm4Linear::Insert(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId)
{
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		return eResult::invalidId;
	}

	BlocksAllocator::Index index = vrfId;
	OneBlock* block = Block(index);
	OneBlock* first_unused = nullptr;
	OneBlock* last_block = block;

	while (block != nullptr)
	{
		if (block->ipAddress == ipAddress && block->mask == mask)
		{
			block->used = 1;
			block->valueId = valueId;
			UpdateStats(allocator_, stats);
			return eResult::success;
		}
		last_block = block;
		if ((block->used == 0) && (first_unused == nullptr))
		{
			first_unused = block;
		}
		index = block->next_block;
		block = Block(block->next_block);
	}

	if (first_unused != nullptr)
	{
		block = first_unused;
	}
	else
	{
		index = allocator_.Allocate();
		if (index == BlocksAllocator::null_block)
		{
			UpdateStats(allocator_, stats);
			return eResult::errorAllocatingMemory;
		}
		block = Block(index);
		last_block->next_block = index;
		block->next_block = BlocksAllocator::null_block;
	}

	block->ipAddress = ipAddress;
	block->mask = mask;
	block->valueId = valueId;
	block->used = 1;
	UpdateStats(allocator_, stats);

	return eResult::success;
}

eResult VrfLpm4Linear::Remove(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask)
{
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		return eResult::invalidId;
	}

	OneBlock* block = Block(vrfId);
	while (block != nullptr)
	{
		if (block->ipAddress == ipAddress && block->mask == mask)
		{
			block->used = 0;
			UpdateStats(allocator_, stats);
			return eResult::success;
		}
		block = Block(block->next_block);
	}
	UpdateStats(allocator_, stats);

	return eResult::success;
}

eResult VrfLpm4Linear::Clear()
{
	if (allocator_.Empty())
	{
		return eResult::isEmpty;
	}

	for (unsigned index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
	{
		OneBlock* block = Block(index);
		block->next_block = BlocksAllocator::null_block;
		block->used = 0;
	}

	return eResult::success;
}

eResult VrfLpm4Linear::CopyFrom(const VrfLpm4Linear& other, stats_t& stats)
{
	eResult result = Clear();
	if (result != eResult::success)
	{
		UpdateStats(allocator_, stats);
		return result;
	}

	for (tVrfId vrf = 0; vrf < YANET_RIB_VRF_MAX_NUMBER; vrf++)
	{
		OneBlock* block = other.Block(vrf);
		while (block != nullptr)
		{
			if (block->used == 1)
			{
				result = Insert(stats, vrf, block->ipAddress, block->mask, block->valueId);
			}
			block = other.Block(block->next_block);
		}
	}
	UpdateStats(allocator_, stats);

	return eResult::success;
}

void VrfLpm4Linear::Swap(VrfLpm4Linear& other)
{
	allocator_.Swap(other.allocator_);
}

void VrfLpm4Linear::Lookup(const uint32_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const
{
	for (unsigned int index = 0; index < count; index++)
	{
		valueIds[index] = lpmValueIdInvalid;
		common::ipv4_address_t address(rte_cpu_to_be_32(ipAddresses[index]));
		uint8_t best_mask = 0;
		if (vrfIds[index] < YANET_RIB_VRF_MAX_NUMBER)
		{
			OneBlock* block = Block(vrfIds[index]);
			while (block != nullptr)
			{
				if (block->mask >= best_mask && block->used == 1)
				{
					if (address.applyMask(block->mask) == block->ipAddress)
					{
						valueIds[index] = block->valueId;
						best_mask = block->mask;
					}
				}
				block = Block(block->next_block);
			}
		}
	}
}

std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> VrfLpm4Linear::GetFullList() const
{
	std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> result;
	for (tVrfId vrfId = 0; vrfId < YANET_RIB_VRF_MAX_NUMBER; vrfId++)
	{
		OneBlock* block = Block(vrfId);
		while (block != nullptr)
		{
			if (block->used == 1)
			{
				result.emplace_back(vrfId, block->ipAddress, block->mask, block->valueId);
			}
			block = Block(block->next_block);
		}
	}

	return result;
}

VrfLpm4Linear::OneBlock* VrfLpm4Linear::Block(BlocksAllocator::Index index) const
{
	return reinterpret_cast<VrfLpm4Linear::OneBlock*>((index == BlocksAllocator::null_block ? nullptr : allocator_[index]));
}

/*
 * Implementation VrfLpm6Linear
 */

VrfLpm6Linear::VrfLpm6Linear(BlocksAllocator& allocator) :
        allocator_(allocator)
{
	Clear();
}

eResult VrfLpm6Linear::Insert(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask, const uint32_t& valueId)
{
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		return eResult::invalidId;
	}

	BlocksAllocator::Index index = vrfId;
	OneBlock* block = Block(index);
	OneBlock* first_unused = nullptr;
	OneBlock* last_block = block;

	while (block != nullptr)
	{
		if (block->ipAddress == ipAddress && block->mask == mask)
		{
			block->used = 1;
			block->valueId = valueId;
			UpdateStats(allocator_, stats);
			return eResult::success;
		}
		last_block = block;
		if ((block->used == 0) && (first_unused == nullptr))
		{
			first_unused = block;
		}
		index = block->next_block;
		block = Block(block->next_block);
	}

	if (first_unused != nullptr)
	{
		block = first_unused;
	}
	else
	{
		index = allocator_.Allocate();
		if (index == BlocksAllocator::null_block)
		{
			UpdateStats(allocator_, stats);
			return eResult::errorAllocatingMemory;
		}
		block = Block(index);
		last_block->next_block = index;
		block->next_block = BlocksAllocator::null_block;
	}

	block->ipAddress = ipAddress;
	block->mask = mask;
	block->valueId = valueId;
	block->used = 1;
	UpdateStats(allocator_, stats);

	return eResult::success;
}

eResult VrfLpm6Linear::Remove(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask)
{
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		return eResult::invalidId;
	}

	OneBlock* block = Block(vrfId);
	while (block != nullptr)
	{
		if (block->ipAddress == ipAddress && block->mask == mask)
		{
			block->used = 0;
			UpdateStats(allocator_, stats);
			return eResult::success;
		}
		block = Block(block->next_block);
	}
	UpdateStats(allocator_, stats);

	return eResult::success;
}

eResult VrfLpm6Linear::Clear()
{
	if (allocator_.Empty())
	{
		return eResult::isEmpty;
	}

	for (unsigned index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
	{
		OneBlock* block = Block(index);
		block->next_block = BlocksAllocator::null_block;
		block->used = 0;
	}

	return eResult::success;
}

eResult VrfLpm6Linear::CopyFrom(const VrfLpm6Linear& other, stats_t& stats)
{
	eResult result = Clear();
	if (result != eResult::success)
	{
		UpdateStats(allocator_, stats);
		return result;
	}

	for (tVrfId vrf = 0; vrf < YANET_RIB_VRF_MAX_NUMBER; vrf++)
	{
		OneBlock* block = other.Block(vrf);
		while (block != nullptr)
		{
			if (block->used == 1)
			{
				result = Insert(stats, vrf, block->ipAddress, block->mask, block->valueId);
			}
			block = other.Block(block->next_block);
		}
	}
	UpdateStats(allocator_, stats);

	return eResult::success;
}

void VrfLpm6Linear::Swap(VrfLpm6Linear& other)
{
	allocator_.Swap(other.allocator_);
}

void VrfLpm6Linear::Lookup(const ipv6_address_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const
{
	for (unsigned int index = 0; index < count; index++)
	{
		valueIds[index] = lpmValueIdInvalid;
		uint8_t best_mask = 0;
		if (vrfIds[index] < YANET_RIB_VRF_MAX_NUMBER)
		{
			OneBlock* block = Block(vrfIds[index]);
			while (block != nullptr)
			{
				if (block->mask >= best_mask && block->used == 1)
				{
					if (common::ipv6_address_t(ipAddresses[index].bytes).applyMask(block->mask) == common::ipv6_address_t(block->ipAddress))
					{
						valueIds[index] = block->valueId;
						best_mask = block->mask;
					}
				}
				block = Block(block->next_block);
			}
		}
	}
}

std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> VrfLpm6Linear::GetFullList() const
{
	std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> result;
	for (tVrfId vrfId = 0; vrfId < YANET_RIB_VRF_MAX_NUMBER; vrfId++)
	{
		OneBlock* block = Block(vrfId);
		while (block != nullptr)
		{
			if (block->used == 1)
			{
				result.emplace_back(vrfId, block->ipAddress, block->mask, block->valueId);
			}
			block = Block(block->next_block);
		}
	}

	return result;
}

VrfLpm6Linear::OneBlock* VrfLpm6Linear::Block(BlocksAllocator::Index index) const
{
	return reinterpret_cast<VrfLpm6Linear::OneBlock*>((index == BlocksAllocator::null_block ? nullptr : allocator_[index]));
}

} // namespace dataplane
