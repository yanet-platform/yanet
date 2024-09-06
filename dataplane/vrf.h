#pragma once

#include <array>
#include <tuple>
#include <vector>

#include "common/blocks_allocator.h"
#include "common/result.h"
#include "lpm.h"
#include "type.h"

namespace dataplane::vrflpm
{

constexpr inline uint32_t lpmValueIdInvalid = dataplane::lpmValueIdInvalid;

struct stats_t
{
	uint64_t extended_chunks_count;
	uint64_t extended_chunks_size;
};

enum BlockType
{
	Block,
	Left,
	Right
};

class VrfLpm4Linear
{
public:
	constexpr static size_t size_of_chunk = 16;
	constexpr static uint64_t extended_chunks_size_min = YANET_RIB_VRF_MAX_NUMBER;

	using BlocksAllocator = common::allocator::BlocksAllocator<size_of_chunk>;

	VrfLpm4Linear(BlocksAllocator& allocator);

	eResult Insert(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId);
	eResult Remove(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask);
	eResult Clear();
	eResult CopyFrom(const VrfLpm4Linear& other, stats_t& stats);
	void Swap(VrfLpm4Linear& other);
	void Lookup(const uint32_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const;
	std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> GetFullList() const;

private:
	struct OneBlock
	{
		VrfLpm4Linear::BlocksAllocator::Index next_block;
		uint32_t ipAddress;
		uint32_t valueId;
		uint8_t mask;
		uint8_t used;
	};
	static_assert(sizeof(OneBlock) <= size_of_chunk, "invalid size of OneBlock");

	BlocksAllocator& allocator_;

	OneBlock* Block(BlocksAllocator::Index index) const;
};

class VrfLpm4BinaryTree
{
public:
	constexpr static size_t size_of_chunk = 32;
	constexpr static uint64_t extended_chunks_size_min = YANET_RIB_VRF_MAX_NUMBER;

	using BlocksAllocator = common::allocator::BlocksAllocator<size_of_chunk>;

	VrfLpm4BinaryTree(BlocksAllocator& allocator);

	eResult Insert(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask, const uint32_t& valueId);
	eResult Remove(stats_t& stats, tVrfId vrfId, const uint32_t& ipAddress, const uint8_t& mask);
	eResult Clear();
	eResult CopyFrom(const VrfLpm4BinaryTree& other, stats_t& stats);
	void Swap(VrfLpm4BinaryTree& other);
	void Lookup(const uint32_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const;
	std::vector<std::tuple<tVrfId, uint32_t, uint8_t, uint32_t>> GetFullList() const;

	void PrintDebug(int vrf_blocks, int data_blocks) const;

private:
	constexpr static uint32_t flagValue = (1u << 31);

	struct OneBlock
	{
		struct Part
		{
			uint32_t address;
			uint32_t mask;
			uint32_t value;

			void Init();
			bool Empty() const;
			std::string toString();
		};

		uint32_t value;
		Part left;
		Part right;

		void Init();
		bool Empty() const;
		Part* GetPart(BlockType block_type);
		std::string toString();
	};

	static_assert(sizeof(OneBlock) <= size_of_chunk, "invalid size of VrfLpm4BinaryTree::OneBlock");

	BlocksAllocator& allocator_;

	eResult Init();
	OneBlock* Block(BlocksAllocator::Index index) const;
	std::pair<OneBlock*, BlockType> FindBlock(OneBlock* block,
	                                          BlockType block_type,
	                                          uint32_t path,
	                                          uint8_t depth,
	                                          bool create);
	void LookupOne(tVrfId vrfId, const uint32_t& ipAddress, uint32_t* valueId) const;
};

class VrfLpm6Linear
{
public:
	constexpr static size_t size_of_chunk = 32;
	constexpr static uint64_t extended_chunks_size_min = YANET_RIB_VRF_MAX_NUMBER;

	using BlocksAllocator = common::allocator::BlocksAllocator<size_of_chunk>;

	VrfLpm6Linear(BlocksAllocator& allocator);

	eResult Insert(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask, const uint32_t& valueId);
	eResult Remove(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask);
	eResult Clear();
	eResult CopyFrom(const VrfLpm6Linear& other, stats_t& stats);
	void Swap(VrfLpm6Linear& other);
	void Lookup(const ipv6_address_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const;
	std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> GetFullList() const;

private:
	struct OneBlock
	{
		VrfLpm4Linear::BlocksAllocator::Index next_block;
		std::array<uint8_t, 16> ipAddress;
		uint32_t valueId;
		uint8_t mask;
		uint8_t used;
	};
	static_assert(sizeof(OneBlock) <= size_of_chunk, "invalid size of OneBlock");

	BlocksAllocator& allocator_;

	OneBlock* Block(BlocksAllocator::Index index) const;
};

class VrfLpm6BinaryTree
{
public:
	constexpr static size_t size_of_chunk = 64;
	constexpr static uint64_t extended_chunks_size_min = YANET_RIB_VRF_MAX_NUMBER;

	using BlocksAllocator = common::allocator::BlocksAllocator<size_of_chunk>;

	VrfLpm6BinaryTree(BlocksAllocator& allocator);

	eResult Insert(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask, const uint32_t& valueId);
	eResult Remove(stats_t& stats, tVrfId vrfId, const std::array<uint8_t, 16>& ipAddress, const uint8_t& mask);
	eResult Clear();
	eResult CopyFrom(const VrfLpm6BinaryTree& other, stats_t& stats);
	void Swap(VrfLpm6BinaryTree& other);
	void Lookup(const ipv6_address_t* ipAddresses, const tVrfId* vrfIds, uint32_t* valueIds, const unsigned int& count) const;
	std::vector<std::tuple<tVrfId, std::array<uint8_t, 16>, uint8_t, uint32_t>> GetFullList() const;

	void PrintDebug(int vrf_blocks, int data_blocks) const;

private:
	constexpr static uint32_t flagValue = (1u << 31);

	struct OneBlock
	{
		struct Part
		{
			uint64_t address;
			uint64_t mask;
			uint32_t value;

			void Init();
			bool Empty() const;
			std::string toString();
		};

		uint32_t value;
		Part left;
		Part right;

		void Init();
		bool Empty() const;
		Part* GetPart(BlockType block_type);
		std::string toString();
	};

	static_assert(sizeof(OneBlock) <= size_of_chunk, "invalid size of VrfLpm6BinaryTree::OneBlock");

	BlocksAllocator& allocator_;

	eResult Init();
	OneBlock* Block(BlocksAllocator::Index index) const;
	std::pair<OneBlock*, BlockType> FindBlock(OneBlock* block,
	                                          BlockType block_type,
	                                          uint64_t path,
	                                          uint8_t depth,
	                                          bool create);
	void LookupOne(tVrfId vrfId, const uint8_t* bytes, uint32_t* valueId) const;
};

} // namespace dataplane
