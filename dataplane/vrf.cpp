#include "vrf.h"

#include <queue>

namespace dataplane::vrflpm
{

template<typename Allocator>
void UpdateStats(Allocator& allocator, stats_t& stats)
{
	auto [blocks_total, blocks_used] = allocator.Stat();
	stats.extended_chunks_size = blocks_total;
	stats.extended_chunks_count = blocks_used;
}

std::array<uint8_t, 16> ConcatenateTwoUint64(uint64_t hi, uint64_t low)
{
	std::array<uint8_t, 16> result;
	*(uint64_t*)result.data() = hi;
	*(uint64_t*)(result.data() + 8) = low;
	return result;
}

std::string ValueStr(uint32_t valueId)
{
	constexpr static uint32_t flagValue = (1u << 31);

	if (valueId == dataplane::vrflpm::lpmValueIdInvalid)
	{
		return "<null>";
	}
	else if (valueId & flagValue)
	{
		return "v:" + std::to_string(valueId ^ flagValue);
	}
	else
	{
		return "b:" + std::to_string(valueId);
	}
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
 * Implementation VrfLpm4BinaryTree
 */

VrfLpm4BinaryTree::VrfLpm4BinaryTree(BlocksAllocator& allocator) :
        allocator_(allocator)
{
	Init();
}

eResult VrfLpm4BinaryTree::Insert(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId)
{
	if (mask > 32 || valueId & 0xFF000000)
	{
		YANET_LOG_DEBUG("invalid prefix or value\n");
		return eResult::invalidArguments;
	}
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		YANET_LOG_DEBUG("invalid vrf id\n");
		return eResult::invalidArguments;
	}

	OneBlock* block = Block(vrfId);
	auto [next_block, block_type] = FindBlock(block, BlockType::Block, ipAddress, mask, true);
	UpdateStats(allocator_, stats);
	if (next_block == nullptr)
	{
		return eResult::errorAllocatingMemory;
	}
	if (block_type == BlockType::Block)
	{
		next_block->value = valueId;
	}
	else
	{
		next_block->GetPart(block_type)->value = valueId | flagValue;
	}

	return eResult::success;
}

eResult VrfLpm4BinaryTree::Remove(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask)
{
	if (mask > 32)
	{
		YANET_LOG_DEBUG("invalid prefix\n");
		return eResult::invalidArguments;
	}
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		YANET_LOG_DEBUG("invalid vrf id\n");
		return eResult::invalidArguments;
	}

	OneBlock* block = Block(vrfId);
	auto [next_block, block_type] = FindBlock(block, BlockType::Block, ipAddress, mask, false);
	UpdateStats(allocator_, stats);
	if (next_block == nullptr)
	{
		return eResult::success;
	}
	if (block_type == BlockType::Block)
	{
		next_block->value = lpmValueIdInvalid;
	}
	else
	{
		next_block->GetPart(block_type)->value = lpmValueIdInvalid;
	}

	return eResult::success;
}

eResult VrfLpm4BinaryTree::Clear()
{
	return Init();
}

eResult VrfLpm4BinaryTree::CopyFrom(const VrfLpm4BinaryTree& other, stats_t& stats)
{
	std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> full_list = other.GetFullList();
	for (const auto& [vrfId, address, mask, value] : full_list)
	{
		eResult result = Insert(stats, vrfId, address, mask, value);
		if (result != eResult::success)
		{
			return result;
		}
	}

	return eResult::success;
}

void VrfLpm4BinaryTree::Swap(VrfLpm4BinaryTree& other)
{
	allocator_.Swap(other.allocator_);
}

void VrfLpm4BinaryTree::Lookup(const uint32_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const
{
	for (unsigned int index = 0; index < count; index++)
	{
		valueIds[index] = lpmValueIdInvalid;
		LookupOne(vrfIds[index], ipAddresses[index], &valueIds[index]);
	}
}

std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> VrfLpm4BinaryTree::GetFullList() const
{
	std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> result;

	for (tVrfId vrfId = 0; vrfId < YANET_RIB_VRF_MAX_NUMBER; vrfId++)
	{
		OneBlock* block = Block(vrfId);
		if (block->Empty())
		{
			continue;
		}

		// queue - (block, address, mask, is_low)
		using QueueELementType = std::tuple<OneBlock*, BlockType, uint32_t, uint8_t>;
		std::queue<QueueELementType> work;
		work.push({block, BlockType::Block, 0, 0});
		while (!work.empty())
		{
			auto [block, block_type, address, mask] = work.front();
			work.pop();

			if (block_type != BlockType::Block)
			{
				OneBlock::Part* part = block->GetPart(block_type);
				if (part->value & flagValue)
				{
					address = part->address;
					mask = common::bits::count_ones_32(part->mask);
					result.emplace_back(vrfId, rte_cpu_to_be_32(address), mask, part->value ^ flagValue);
					continue;
				}
				block = Block(part->value);
			}

			if (block->value != lpmValueIdInvalid)
			{
				result.emplace_back(vrfId, rte_cpu_to_be_32(address), mask, block->value);
			}

			if (!block->left.Empty())
			{
				mask = common::bits::count_ones_32(block->left.mask);
				address = block->left.address;
				work.push({block, BlockType::Left, address, mask});
			}
			if (!block->right.Empty())
			{
				mask = common::bits::count_ones_32(block->right.mask);
				address = block->right.address;
				work.push({block, BlockType::Right, address, mask});
			}
		}
	}

	return result;
}

void VrfLpm4BinaryTree::PrintDebug(int vrf_blocks, int data_blocks) const
{
	for (int index = 0; index <= vrf_blocks; index++)
	{
		YANET_LOG_DEBUG("[%d]: %s\n", index, Block(index)->toString().c_str());
	}

	for (int index = YANET_RIB_VRF_MAX_NUMBER; index < YANET_RIB_VRF_MAX_NUMBER + data_blocks; index++)
	{
		YANET_LOG_DEBUG("[%d]: %s\n", index, Block(index)->toString().c_str());
	}
}

eResult VrfLpm4BinaryTree::Init()
{
	if (allocator_.Empty())
	{
		return eResult::isEmpty;
	}

	for (unsigned index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
	{
		OneBlock* block = Block(index);
		block->Init();
	}

	return eResult::success;
}

VrfLpm4BinaryTree::OneBlock* VrfLpm4BinaryTree::Block(BlocksAllocator::Index index) const
{
	return reinterpret_cast<VrfLpm4BinaryTree::OneBlock*>((index == BlocksAllocator::null_block ? nullptr : allocator_[index]));
}

std::pair<VrfLpm4BinaryTree::OneBlock*, BlockType> VrfLpm4BinaryTree::FindBlock(OneBlock* block,
                                                                                BlockType block_type,
                                                                                uint32_t path,
                                                                                uint8_t depth,
                                                                                bool create)
{
	uint32_t mask = common::bits::build_mask_32(depth);

	uint8_t cur_depth = 0;
	while (cur_depth < depth)
	{
		if (block_type == BlockType::Block)
		{
			block_type = (common::bits::get_bit_32(path, 31 - cur_depth) == 0 ? BlockType::Left : BlockType::Right);
			OneBlock::Part* part = block->GetPart(block_type);

			if (part->value == lpmValueIdInvalid)
			{
				if (!create)
				{
					return {nullptr, block_type};
				}
				// empty part
				part->mask = rte_cpu_to_be_32(mask);
				part->address = rte_cpu_to_be_32(path & mask);
				return {block, block_type};
			}

			uint8_t depth_part = common::bits::count_ones_32(part->mask);
			uint8_t common_depth = common::bits::get_first_enabled_bit_32(path ^ rte_cpu_to_be_32(part->address));
			common_depth = std::min(common_depth, std::min(depth_part, depth));

			cur_depth = common_depth;
			if (common_depth == depth_part)
			{
				if ((part->value & flagValue) == 0)
				{
					block_type = BlockType::Block;
					block = Block(part->value);
				}
				continue;
			}

			if (!create)
			{
				return {nullptr, block_type};
			}

			block_type = BlockType::Block;
			BlocksAllocator::Index index_middle = allocator_.Allocate();
			if (index_middle == BlocksAllocator::null_block)
			{
				return {nullptr, block_type};
			}
			block = Block(index_middle);
			block->Init();
			OneBlock::Part* new_part = (common::bits::get_bit_32(rte_cpu_to_be_32(part->address), 31 - cur_depth) == 0 ? &block->left : &block->right);
			*new_part = *part;
			uint32_t mask_middle = common::bits::build_mask_32(cur_depth);
			part->mask = rte_cpu_to_be_32(mask_middle);
			part->address = rte_cpu_to_be_32(mask_middle & path);
			part->value = index_middle;
		}
		else
		{
			if (!create)
			{
				return {nullptr, block_type};
			}

			OneBlock::Part* part = block->GetPart(block_type);
			block_type = BlockType::Block;
			BlocksAllocator::Index index_new = allocator_.Allocate();
			if (index_new == BlocksAllocator::null_block)
			{
				return {nullptr, block_type};
			}
			block = Block(index_new);
			block->Init();
			block->value = part->value ^ flagValue;
			part->value = index_new;
		}
	}

	return {block, block_type};
}

void VrfLpm4BinaryTree::LookupOne(tVrfId vrfId, const uint32_t& ipAddress, uint32_t* valueId) const
{
	OneBlock* block = (vrfId >= YANET_RIB_VRF_MAX_NUMBER ? nullptr : Block(vrfId));
	while (block != nullptr)
	{
		if (block->value != lpmValueIdInvalid)
		{
			*valueId = block->value;
		}

		uint32_t next_value;
		if ((block->left.mask & ipAddress) == block->left.address)
		{
			next_value = block->left.value;
		}
		else if ((block->right.mask & ipAddress) == block->right.address)
		{
			next_value = block->right.value;
		}
		else
		{
			return;
		}

		if ((next_value & flagValue) == 0)
		{
			block = Block(next_value);
		}
		else
		{
			if (next_value != lpmValueIdInvalid)
			{
				*valueId = next_value ^ flagValue;
			}
			return;
		}
	}
}

void VrfLpm4BinaryTree::OneBlock::Init()
{
	value = lpmValueIdInvalid;
	left.Init();
	right.Init();
}

bool VrfLpm4BinaryTree::OneBlock::Empty() const
{
	return value == lpmValueIdInvalid && left.Empty() && right.Empty();
}

VrfLpm4BinaryTree::OneBlock::Part* VrfLpm4BinaryTree::OneBlock::GetPart(BlockType block_type)
{
	return (block_type == BlockType::Left ? &left : &right);
}

std::string VrfLpm4BinaryTree::OneBlock::toString()
{
	return (value == lpmValueIdInvalid ? "<null>" : std::to_string(value)) + " [" + left.toString() + "] [" + right.toString() + "]";
}

void VrfLpm4BinaryTree::OneBlock::Part::Init()
{
	address = lpmValueIdInvalid;
	mask = 0;
	value = lpmValueIdInvalid;
}

bool VrfLpm4BinaryTree::OneBlock::Part::Empty() const
{
	return value == lpmValueIdInvalid;
}

std::string VrfLpm4BinaryTree::OneBlock::Part::toString()
{
	char buffer[256];
	snprintf(buffer, sizeof(buffer), "%08x/%08x %s", address, (uint32_t)mask, ValueStr(value).c_str());
	return std::string(buffer);
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

/*
 * Implementation VrfLpm6BinaryTree
 */

VrfLpm6BinaryTree::VrfLpm6BinaryTree(BlocksAllocator& allocator) :
        allocator_(allocator)
{
	Init();
}

eResult VrfLpm6BinaryTree::Insert(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask, const uint32_t& valueId)
{
	if (mask > 128 || valueId & 0xFF000000)
	{
		YANET_LOG_DEBUG("invalid prefix or value\n");
		return eResult::invalidArguments;
	}
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		YANET_LOG_DEBUG("invalid vrf id\n");
		return eResult::invalidArguments;
	}

	OneBlock* block = Block(vrfId);
	uint64_t hi = *(uint64_t*)ipAddress.data();
	if (mask <= 64)
	{
		auto [next_block, block_type] = FindBlock(block, BlockType::Block, hi, mask, true);
		UpdateStats(allocator_, stats);
		if (next_block == nullptr)
		{
			return eResult::errorAllocatingMemory;
		}
		if (block_type == BlockType::Block)
		{
			next_block->value = valueId;
		}
		else
		{
			next_block->GetPart(block_type)->value = valueId | flagValue;
		}
	}
	else
	{
		auto [next_block, block_type] = FindBlock(block, BlockType::Block, hi, 64, true);
		UpdateStats(allocator_, stats);
		if (next_block == nullptr)
		{
			return eResult::errorAllocatingMemory;
		}

		uint64_t low = *(uint64_t*)(ipAddress.data() + 8);
		auto [low_block, low_type] = FindBlock(next_block, block_type, low, mask - 64, true);
		UpdateStats(allocator_, stats);

		if (low_block == nullptr)
		{
			return eResult::errorAllocatingMemory;
		}
		if (low_type == BlockType::Block)
		{
			low_block->value = valueId;
		}
		else
		{
			low_block->GetPart(low_type)->value = valueId | flagValue;
		}
	}

	return eResult::success;
}

eResult VrfLpm6BinaryTree::Remove(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask)
{
	if (mask > 128)
	{
		YANET_LOG_DEBUG("invalid prefix\n");
		return eResult::invalidArguments;
	}
	if (vrfId >= YANET_RIB_VRF_MAX_NUMBER)
	{
		YANET_LOG_DEBUG("invalid vrf id\n");
		return eResult::invalidArguments;
	}

	OneBlock* block = Block(vrfId);
	uint64_t hi = *(uint64_t*)ipAddress.data();
	if (mask <= 64)
	{
		auto [next_block, block_type] = FindBlock(block, BlockType::Block, hi, mask, false);
		UpdateStats(allocator_, stats);
		if (next_block == nullptr)
		{
			return eResult::success;
		}
		if (block_type == BlockType::Block)
		{
			next_block->value = lpmValueIdInvalid;
		}
		else
		{
			next_block->GetPart(block_type)->value = lpmValueIdInvalid;
		}
	}
	else
	{
		auto [next_block, block_type] = FindBlock(block, BlockType::Block, hi, 64, false);
		UpdateStats(allocator_, stats);
		if (next_block == nullptr)
		{
			return eResult::success;
		}

		uint64_t low = *(uint64_t*)(ipAddress.data() + 8);
		auto [low_block, low_type] = FindBlock(next_block, block_type, low, mask - 64, false);
		UpdateStats(allocator_, stats);

		if (low_block == nullptr)
		{
			return eResult::success;
		}
		if (low_type == BlockType::Block)
		{
			low_block->value = lpmValueIdInvalid;
		}
		else
		{
			low_block->GetPart(low_type)->value = lpmValueIdInvalid;
		}
	}

	return eResult::success;
}

eResult VrfLpm6BinaryTree::Clear()
{
	return Init();
}

eResult VrfLpm6BinaryTree::CopyFrom(const VrfLpm6BinaryTree& other, stats_t& stats)
{
	std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> full_list = other.GetFullList();
	for (const auto& [vrfId, address, mask, value] : full_list)
	{
		eResult result = Insert(stats, vrfId, address, mask, value);
		if (result != eResult::success)
		{
			return result;
		}
	}

	return eResult::success;
}

void VrfLpm6BinaryTree::Swap(VrfLpm6BinaryTree& other)
{
	allocator_.Swap(other.allocator_);
}

void VrfLpm6BinaryTree::Lookup(const ipv6_address_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const
{
	for (unsigned int index = 0; index < count; index++)
	{
		valueIds[index] = lpmValueIdInvalid;
		LookupOne(vrfIds[index], ipAddresses[index].bytes, &valueIds[index]);
	}
}

std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> VrfLpm6BinaryTree::GetFullList() const
{
	std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> result;
	for (tVrfId vrfId = 0; vrfId < YANET_RIB_VRF_MAX_NUMBER; vrfId++)
	{
		OneBlock* block = Block(vrfId);
		if (block->Empty())
		{
			continue;
		}

		// queue - (block, hi, low, mask, is_low)
		using QueueELementType = std::tuple<OneBlock*, BlockType, uint64_t, uint64_t, uint8_t, bool>;
		std::queue<QueueELementType> work;
		work.push({block, BlockType::Block, 0, 0, 0, false});
		while (!work.empty())
		{
			auto [block, block_type, hi, low, mask, is_low] = work.front();
			work.pop();

			if (block_type != BlockType::Block)
			{
				OneBlock::Part* part = block->GetPart(block_type);
				if (part->value & flagValue)
				{
					if (is_low)
					{
						low = part->address;
						mask = common::bits::count_ones_64(part->mask) + 64;
					}
					else
					{
						hi = part->address;
						mask = common::bits::count_ones_64(part->mask);
					}
					std::array<uint8_t, 16> address = ConcatenateTwoUint64(hi, low);
					result.emplace_back(vrfId, address, mask, part->value ^ flagValue);
					continue;
				}
				block = Block(part->value);
			}

			if (block->value != lpmValueIdInvalid)
			{
				if (is_low)
				{
					mask += 64;
				}
				std::array<uint8_t, 16> address = ConcatenateTwoUint64(hi, low);
				result.emplace_back(vrfId, address, mask, block->value);
			}

			if (!is_low && mask == 64)
			{
				is_low = true;
			}

			if (!block->left.Empty())
			{
				mask = common::bits::count_ones_64(block->left.mask);
				if (is_low)
				{
					low = block->left.address;
				}
				else
				{
					hi = block->left.address;
				}
				work.push({block, BlockType::Left, hi, low, mask, is_low});
			}
			if (!block->right.Empty())
			{
				mask = common::bits::count_ones_64(block->right.mask);
				if (is_low)
				{
					low = block->right.address;
				}
				else
				{
					hi = block->right.address;
				}
				work.push({block, BlockType::Right, hi, low, mask, is_low});
			}
		}
	}

	return result;
}

void VrfLpm6BinaryTree::PrintDebug(int vrf_blocks, int data_blocks) const
{
	for (int index = 0; index <= vrf_blocks; index++)
	{
		YANET_LOG_DEBUG("[%d]: %s\n", index, Block(index)->toString().c_str());
	}

	for (int index = YANET_RIB_VRF_MAX_NUMBER; index < YANET_RIB_VRF_MAX_NUMBER + data_blocks; index++)
	{
		YANET_LOG_DEBUG("[%d]: %s\n", index, Block(index)->toString().c_str());
	}
}

eResult VrfLpm6BinaryTree::Init()
{
	if (allocator_.Empty())
	{
		return eResult::isEmpty;
	}

	for (unsigned index = 0; index < YANET_RIB_VRF_MAX_NUMBER; index++)
	{
		OneBlock* block = Block(index);
		block->Init();
	}

	return eResult::success;
}

VrfLpm6BinaryTree::OneBlock* VrfLpm6BinaryTree::Block(BlocksAllocator::Index index) const
{
	return reinterpret_cast<OneBlock*>((index == BlocksAllocator::null_block ? nullptr : allocator_[index]));
}

std::pair<VrfLpm6BinaryTree::OneBlock*, BlockType> VrfLpm6BinaryTree::FindBlock(OneBlock* block,
                                                                                BlockType block_type,
                                                                                uint64_t path,
                                                                                uint8_t depth,
                                                                                bool create)
{
	path = rte_cpu_to_be_64(path);
	uint64_t mask = common::bits::build_mask_64(depth);

	uint8_t cur_depth = 0;
	while (cur_depth < depth)
	{
		if (block_type == BlockType::Block)
		{
			block_type = (common::bits::get_bit_64(path, 63 - cur_depth) == 0 ? BlockType::Left : BlockType::Right);
			OneBlock::Part* part = block->GetPart(block_type);

			if (part->value == lpmValueIdInvalid)
			{
				if (!create)
				{
					return {nullptr, block_type};
				}
				// empty part
				part->mask = rte_cpu_to_be_64(mask);
				part->address = rte_cpu_to_be_64(path & mask);
				return {block, block_type};
			}

			uint8_t depth_part = common::bits::count_ones_64(part->mask);
			uint8_t common_depth = common::bits::get_first_enabled_bit_64(path ^ rte_cpu_to_be_64(part->address));
			common_depth = std::min(common_depth, std::min(depth_part, depth));

			cur_depth = common_depth;
			if (common_depth == depth_part)
			{
				if ((part->value & flagValue) == 0)
				{
					block_type = BlockType::Block;
					block = Block(part->value);
				}
				continue;
			}

			if (!create)
			{
				return {nullptr, block_type};
			}

			block_type = BlockType::Block;
			BlocksAllocator::Index index_middle = allocator_.Allocate();
			if (index_middle == BlocksAllocator::null_block)
			{
				return {nullptr, block_type};
			}
			block = Block(index_middle);
			block->Init();
			OneBlock::Part* new_part = (common::bits::get_bit_64(rte_cpu_to_be_64(part->address), 63 - cur_depth) == 0 ? &block->left : &block->right);
			*new_part = *part;
			uint64_t mask_middle = common::bits::build_mask_64(cur_depth);
			part->mask = rte_cpu_to_be_64(mask_middle);
			part->address = rte_cpu_to_be_64(mask_middle & path);
			part->value = index_middle;
		}
		else
		{
			if (!create)
			{
				return {nullptr, block_type};
			}

			OneBlock::Part* part = block->GetPart(block_type);
			block_type = BlockType::Block;
			BlocksAllocator::Index index_new = allocator_.Allocate();
			if (index_new == BlocksAllocator::null_block)
			{
				return {nullptr, block_type};
			}
			block = Block(index_new);
			block->Init();
			block->value = (part->value == lpmValueIdInvalid ? -1 : part->value ^ flagValue);
			part->value = index_new;
		}
	}

	return {block, block_type};
}

void VrfLpm6BinaryTree::LookupOne(tVrfId vrfId, const uint8_t* bytes, uint32_t* valueId) const
{
	uint64_t address = *(uint64_t*)bytes;
	OneBlock* block = (vrfId >= YANET_RIB_VRF_MAX_NUMBER ? nullptr : Block(vrfId));
	bool work = true;
	while ((block != nullptr) && work)
	{
		if (block->value != lpmValueIdInvalid)
		{
			*valueId = block->value;
		}

		uint32_t next_value;
		if ((block->left.mask & address) == block->left.address)
		{
			next_value = block->left.value;
			work = (block->left.mask != static_cast<uint64_t>(-1));
		}
		else if ((block->right.mask & address) == block->right.address)
		{
			next_value = block->right.value;
			work = (block->right.mask != static_cast<uint64_t>(-1));
		}
		else
		{
			return;
		}

		if ((next_value & flagValue) == 0)
		{
			block = Block(next_value);
		}
		else
		{
			if (next_value != lpmValueIdInvalid)
			{
				*valueId = next_value ^ flagValue;
			}
			return;
		}
	}

	address = *(uint64_t*)(bytes + 8);
	while (block != nullptr)
	{
		if (block->value != lpmValueIdInvalid)
		{
			*valueId = block->value;
		}

		uint32_t next_value;
		if ((block->left.mask & address) == block->left.address)
		{
			next_value = block->left.value;
		}
		else if ((block->right.mask & address) == block->right.address)
		{
			next_value = block->right.value;
		}
		else
		{
			return;
		}

		if ((next_value & flagValue) == 0)
		{
			block = Block(next_value);
		}
		else
		{
			if (next_value != lpmValueIdInvalid)
			{
				*valueId = next_value ^ flagValue;
			}
			return;
		}
	}
}

void VrfLpm6BinaryTree::OneBlock::Init()
{
	value = lpmValueIdInvalid;
	left.Init();
	right.Init();
}

bool VrfLpm6BinaryTree::OneBlock::Empty() const
{
	return value == lpmValueIdInvalid && left.Empty() && right.Empty();
}

VrfLpm6BinaryTree::OneBlock::Part* VrfLpm6BinaryTree::OneBlock::GetPart(BlockType block_type)
{
	return (block_type == BlockType::Left ? &left : &right);
}

std::string VrfLpm6BinaryTree::OneBlock::toString()
{
	return (value == lpmValueIdInvalid ? "<null>" : std::to_string(value)) + " [" + left.toString() + "] [" + right.toString() + "]";
}

void VrfLpm6BinaryTree::OneBlock::Part::Init()
{
	address = lpmValueIdInvalid;
	mask = 0;
	value = lpmValueIdInvalid;
}

bool VrfLpm6BinaryTree::OneBlock::Part::Empty() const
{
	return value == lpmValueIdInvalid;
}

std::string VrfLpm6BinaryTree::OneBlock::Part::toString()
{
	char buffer[256];
	snprintf(buffer, sizeof(buffer), "%016lx/%016lx %s", address, mask, ValueStr(value).c_str());
	return std::string(buffer);
}

} // namespace dataplane
