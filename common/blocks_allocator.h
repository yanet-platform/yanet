#pragma once

#include "bits_ops.h"

namespace common::allocator
{

template<size_t BlockSize>
class BlocksAllocator
{
public:
	using Index = uint32_t;
	static constexpr Index null_block = static_cast<Index>(-1);

	static size_t GetBufferSize(Index blocks_number)
	{
		size_t groups_number = (blocks_number + 63) / 64;
		return groups_number * (sizeof(Group) + 64 * BlockSize);
	}

	void Init(void* pointer, size_t size, Index number_first_reserved)
	{
		// size >= groups_number_ * (sizeof(Group) + 64 * BlockSize)
		groups_number_ = size / (sizeof(Group) + 64 * BlockSize);
		pointer_ = pointer;
		blocks_ = pointer;
		groups_ = reinterpret_cast<Group*>(reinterpret_cast<uint8_t*>(pointer) + groups_number_ * BlockSize * 64);

		for (Index index = 0; index < groups_number_; index++)
		{
			groups_[index].Init(index + 1 == groups_number_ ? null_block : index + 1);
		}
		first_available_group_ = (groups_number_ == 0 ? null_block : 0);

		blocks_total_ = groups_number_ * 64;
		blocks_used_ = 0;
		if ((number_first_reserved != 0) && (number_first_reserved <= 64 * groups_number_))
		{
			first_available_group_ = number_first_reserved / 64;
			for (Index index = 0; index < first_available_group_; index++)
			{
				groups_[index].Occupy();
			}
			for (Index index = 0; index < number_first_reserved % 64; index++)
			{
				Allocate();
			}
			blocks_used_ = number_first_reserved;
		}
	}

	void* GetPointer() const
	{
		return pointer_;
	}

	Index Allocate()
	{
		if (first_available_group_ == null_block)
		{
			return null_block;
		}

		Group& group = groups_[first_available_group_];
		Index result = first_available_group_ * static_cast<Index>(64) + group.Allocate();
		if (group.Busy())
		{
			first_available_group_ = group.next;
		}
		blocks_used_++;
		return result;
	}

	void Free(Index block_index)
	{
		Index group_index = block_index / 64;
		Group& group = groups_[group_index];
		if (group.Busy())
		{
			group.next = first_available_group_;
			first_available_group_ = group_index;
		}
		blocks_used_--;
		group.Free(block_index % 64);
	}

	void* operator[](Index block_index) const
	{
		return reinterpret_cast<uint8_t*>(blocks_) + block_index * BlockSize;
	}

	void Swap(BlocksAllocator<BlockSize>& other)
	{
		std::swap(pointer_, other.pointer_);
		std::swap(blocks_, other.blocks_);
		std::swap(groups_, other.groups_);
		std::swap(first_available_group_, other.first_available_group_);
		std::swap(groups_number_, other.groups_number_);
		std::swap(blocks_total_, other.blocks_total_);
		std::swap(blocks_used_, other.blocks_used_);
	}

	bool Empty() const
	{
		return pointer_ == nullptr;
	}

	std::pair<size_t, size_t> Stat() const
	{
		return {blocks_total_, blocks_used_};
	}

private:
	struct Group
	{
		void Init(Index next)
		{
			available = static_cast<uint64_t>(-1);
			this->next = next;
		}

		bool Busy()
		{
			return available == 0;
		}

		void Occupy()
		{
			available = 0;
		}

		uint8_t Allocate()
		{
			uint8_t result = common::bits::get_last_enabled_bit_64(available);
			common::bits::disable_bit_64(available, result);
			return result;
		}

		void Free(uint8_t bit)
		{
			common::bits::enable_bit_64(available, bit);
		}

		uint64_t available;
		Index next;
	};

	void* pointer_ = nullptr;
	void* blocks_ = nullptr;
	Group* groups_ = nullptr;
	Index first_available_group_ = null_block;
	Index groups_number_ = 0;
	size_t blocks_total_ = 0;
	size_t blocks_used_ = 0;
};

} // namespace common::allocacator
