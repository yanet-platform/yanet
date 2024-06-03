#pragma once

#include <cstdint>
#include <cstring>

#include <iostream>

#define ENABLE_BIT(v, b) (v) |= ((uint64_t)1) << (b)
#define GET_BIT(v, b) (((v) >> (b)) & 1)
#define DISABLE_BIT(v, b) (v) &= ~(((uint64_t)1) << (b))

template<uint32_t IndexBegin, uint32_t IndexEnd, uint32_t BlockSize, uint32_t MaxBufferSize, uint32_t ErrorResult>
class SegmentAllocator
{
public:
	static_assert((BlockSize % 64) == 0);
	static_assert((BlockSize <= 64 * 64) && (BlockSize >= 64));
	static_assert((MaxBufferSize <= 64) && (MaxBufferSize >= 1));
	// Last block can't be less than MaxBufferSize
	static_assert(((IndexEnd - IndexBegin) % BlockSize == 0) || ((IndexEnd - IndexBegin) % BlockSize >= MaxBufferSize));

	struct OneSizeBlockInfo
	{
		uint32_t head_block = 0;
		uint32_t used_blocks = 0;
		uint32_t busy_blocks = 0;
		uint32_t used_segments = 0;
	};

	SegmentAllocator()
	{
		free_cells_ = IndexEnd - IndexBegin;

		// Initialize blocks in main list of free blocks and set size of each block
		for (uint32_t index = 0; index < total_blocks_; ++index)
		{
			all_blocks_[index].Initialize(index - 1, index + 1);
		}
		all_blocks_[0].previous = null_block_;
		all_blocks_[total_blocks_ - 1].next = null_block_;
		// the size of the last block may vary
		all_blocks_[total_blocks_ - 1].block_size = IndexEnd - IndexBegin - (total_blocks_ - 1) * BlockSize;

		// Initialize data for each size of segments
		for (uint32_t index = 1; index <= MaxBufferSize; ++index)
		{
			sizes_info_[index].head_block = null_block_;
		}
		// size = 0 - free blocks, at start head_block = 0
		sizes_info_[0].used_blocks = total_blocks_;
	}

	uint32_t Allocate(uint16_t size)
	{
		if ((size == 0) || (size > MaxBufferSize))
		{
			// bad size
			errors_external_++;
			return ErrorResult;
		}

		// try find block
		OneSizeBlockInfo& size_info = sizes_info_[size];
		if (size_info.head_block == null_block_)
		{
			uint32_t block_index = sizes_info_[0].head_block;
			// no free blocks this size
			if (block_index == null_block_)
			{
				// no free blocks
				return ErrorResult;
			}
			else
			{
				// move block from list of free to blocks of this size
				RemoveFromList(block_index, 0);
				all_blocks_[block_index].SetSize(size);
				InsertToList(block_index, size);
			}
		}

		OneBlock& block = all_blocks_[size_info.head_block];
		uint16_t index_in_block = block.Allocate();
		if (index_in_block == error_in_block_)
		{
			errors_internal_++;
			return ErrorResult;
		}
		uint32_t result = size_info.head_block * BlockSize + index_in_block * size + IndexBegin;
		if (block.free_segments == 0)
		{
			// block is busy
			RemoveFromList(size_info.head_block, size);
			size_info.busy_blocks++;
		}
		size_info.used_segments++;

		free_cells_ -= size;
		return result;
	}

	uint32_t Free(uint32_t start, uint16_t size)
	{
		if ((size == 0) || (size > MaxBufferSize) || (start >= IndexEnd) || (start < IndexBegin))
		{
			errors_external_++;
			return false;
		}

		uint32_t block_index = (start - IndexBegin) / BlockSize;
		OneBlock& block = all_blocks_[block_index];
		if (block.one_segment_size != size)
		{
			errors_external_++;
			return false;
		}
		else if ((start - block_index * BlockSize - IndexBegin) % size != 0)
		{
			errors_external_++;
			return false;
		}

		bool block_was_busy = (block.free_segments == 0);
		uint16_t index = (start - block_index * BlockSize - IndexBegin) / size;
		if (block.Free(index) == error_in_block_)
		{
			errors_external_++;
			return false;
		}

		OneSizeBlockInfo& size_info = sizes_info_[size];
		if (block_was_busy)
		{
			if ((block.previous != null_block_) || (block.next != null_block_))
			{
				errors_internal_++;
			}
			InsertToList(block_index, size);
			size_info.busy_blocks--;
		}
		if (block.free_segments == block.total_segments)
		{
			RemoveFromList(block_index, size);
			InsertToList(block_index, 0);
		}

		size_info.used_segments--;
		free_cells_ += size;
		return true;
	}

	uint32_t Size() const
	{
		return free_cells_;
	}

	const OneSizeBlockInfo* GetBlocksStat() const
	{
		return sizes_info_;
	}

	std::pair<uint64_t, uint64_t> GetErrors() const
	{
		return {errors_external_, errors_internal_};
	}

private:
	struct OneBlock
	{
		// indexes of previous and next blocks in list
		uint32_t previous;
		uint32_t next;

		// block structure
		uint16_t block_size;
		uint16_t one_segment_size;
		uint16_t total_segments;
		uint16_t free_segments;

		// bit masks of segments usage
		uint64_t group_mask;
		uint64_t masks[BlockSize / 64];

		void Initialize(uint32_t previous, uint32_t next)
		{
			this->previous = previous;
			this->next = next;
			block_size = BlockSize;
			group_mask = 0;
			memset(masks, 0, sizeof(masks));
		}

		void SetSize(uint16_t segment_size)
		{
			one_segment_size = segment_size;
			total_segments = block_size / segment_size;
			free_segments = total_segments;
		}

		uint16_t Allocate()
		{
			// calling the function implies that we are sure that there are free segments
			if ((~group_mask) == 0)
			{
				return error_in_block_;
			}

			uint16_t group = __builtin_ctzll(~group_mask);
			if ((group >= sizeof(masks) / sizeof(masks[0])) || ((~masks[group]) == 0))
			{
				return error_in_block_;
			}
			uint16_t index_in_group = __builtin_ctzll(~masks[group]);
			uint16_t index = group * 64 + index_in_group;

			if (index >= total_segments)
			{
				return error_in_block_;
			}

			// set bits usage
			ENABLE_BIT(masks[group], index_in_group);
			if ((~masks[group]) == 0)
			{
				ENABLE_BIT(group_mask, group);
			}

			// change number of free segments
			free_segments--;

			return index;
		}

		uint16_t Free(uint16_t index)
		{
			if (index >= total_segments)
			{
				return error_in_block_;
			}

			uint16_t group = index >> 6; // divide by 64
			index &= 0x003f; // % 64

			if (GET_BIT(masks[group], index) == 0)
			{
				return error_in_block_;
			}

			// set bits usage
			DISABLE_BIT(masks[group], index);
			if (masks[group] == 0)
			{
				DISABLE_BIT(group_mask, group);
			}

			// change number of free segments
			free_segments++;

			return 0;
		}
	};

	static constexpr uint32_t total_blocks_ = (IndexEnd - IndexBegin + BlockSize - 1) / BlockSize;
	static constexpr uint32_t null_block_ = static_cast<uint32_t>(-1);
	static constexpr uint16_t error_in_block_ = static_cast<uint16_t>(-1);

	OneBlock all_blocks_[total_blocks_];
	OneSizeBlockInfo sizes_info_[MaxBufferSize + 1];

	uint32_t free_cells_;
	uint64_t errors_external_ = 0;
	uint64_t errors_internal_ = 0;

	void RemoveFromList(uint32_t block_index, uint16_t size)
	{
		OneBlock& block = all_blocks_[block_index];
		sizes_info_[size].used_blocks--;

		// change links in previous and next block
		if (block.previous != null_block_)
		{
			all_blocks_[block.previous].next = block.next;
		}
		if (block.next != null_block_)
		{
			all_blocks_[block.next].previous = block.previous;
		}

		// if it was head
		if (sizes_info_[size].head_block == block_index)
		{
			sizes_info_[size].head_block = block.next;
		}

		// we don't have to delete links to the previous and next one, but we do it only
		// for internal verification when we add it to the list
		block.previous = null_block_;
		block.next = null_block_;
	}

	void InsertToList(uint32_t block_index, uint16_t size)
	{
		all_blocks_[block_index].next = sizes_info_[size].head_block;
		all_blocks_[block_index].previous = null_block_;
		sizes_info_[size].head_block = block_index;
		sizes_info_[size].used_blocks++;
	}
};
