#pragma once

#include <memory.h>
#include <unordered_map>
#include <unordered_set>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ip.h>

#include "common/acl.h"
#include "common/result.h"

#include "common.h"
#include "metadata.h"
#include "type.h"

namespace dataplane
{

constexpr inline uint32_t lpmValueIdInvalid = (0xFFFFFFFF);

template<uint32_t TExtendedSize>
class lpm4_24bit_8bit_atomic
{
public:
	lpm4_24bit_8bit_atomic()
	{
		extendedChunksCount = 0;
		maxUsedChunkId = 0;
		freeChunkCache.flags = 0;
	}

	eResult insert(const uint32_t& ipAddress,
	               const uint8_t& mask,
	               const uint32_t& valueId,
	               bool* needWait = nullptr)
	{
		if (mask > 32 ||
		    valueId & 0xFF000000)
		{
			YADECAP_LOG_DEBUG("invalid prefix or value\n");
			return eResult::invalidArguments;
		}

		if (needWait)
		{
			*needWait = false;
		}

		return insertStep1(ipAddress,
		                   mask,
		                   valueId,
		                   needWait,
		                   0,
		                   rootChunk);
	}

	eResult remove(const uint32_t& ipAddress,
	               const uint8_t& mask,
	               bool* needWait = nullptr)
	{
		if (mask > 32)
		{
			YADECAP_LOG_DEBUG("invalid prefix\n");
			return eResult::invalidArguments;
		}

		if (needWait)
		{
			*needWait = false;
		}

		return removeStep1(ipAddress,
		                   mask,
		                   needWait,
		                   0,
		                   rootChunk);
	}

	void clear()
	{
		memset(&rootChunk.entries[0], 0, sizeof(rootChunk.entries));
		extendedChunksCount = 0;
		maxUsedChunkId = 0;
		freeChunkCache.flags = 0;
	}

	inline void lookup(const uint32_t* ipAddresses,
	                   uint32_t* valueIds,
	                   const unsigned int& count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int ipAddress_i = 0;
		     ipAddress_i < count;
		     ipAddress_i++)
		{
			const uint32_t& ipAddress = ipAddresses[ipAddress_i];

			valueIds[ipAddress_i] = lpmValueIdInvalid;

			tEntry entry;
			entry.atomic = rootChunk.entries[rte_be_to_cpu_32(ipAddress) >> 8].atomic;

			if (entry.flags & flagValid)
			{
				///                   = entry.valueId;
				valueIds[ipAddress_i] = entry.atomic >> 8;
			}
			else if (entry.flags & flagExtended)
			{
				///          = extendedChunks[entry.extendedChunkId].entries[ipAddress >> 24].atomic;
				entry.atomic = extendedChunks[entry.atomic >> 8].entries[ipAddress >> 24].atomic;

				if (entry.flags & flagValid)
				{
					///                   = entry.valueId;
					valueIds[ipAddress_i] = entry.atomic >> 8;
				}
			}
		}
	}

	template<unsigned int TOffset>
	inline void lookup(rte_mbuf** mbufs,
	                   uint32_t* valueIds,
	                   const unsigned int& count) const
	{
		uint32_t ipAddresses[CONFIG_YADECAP_MBUFS_BURST_SIZE];

		for (unsigned int mbuf_i = 0;
		     mbuf_i < count;
		     mbuf_i++)
		{
			const rte_mbuf* mbuf = mbufs[mbuf_i];
			dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

			ipAddresses[mbuf_i] = *(rte_pktmbuf_mtod_offset(mbuf, const uint32_t*, metadata->network_headerOffset + TOffset));
		}

		lookup(ipAddresses, valueIds, count);
	}

	inline bool lookup(const uint32_t& ipAddress,
	                   uint32_t* valueId = nullptr) const
	{
		uint32_t lvalueId;

		lookup(&ipAddress, &lvalueId, 1);

		if (valueId)
		{
			*valueId = lvalueId;
		}

		if (lvalueId != lpmValueIdInvalid)
		{
			return true;
		}

		return false;
	}

	struct tStats
	{
		uint64_t extendedChunksCount;
	};

	tStats getStats() const
	{
		tStats result;
		memset(&result, 0, sizeof(result));
		result.extendedChunksCount = extendedChunksCount;

		return result;
	}

protected:
	constexpr static uint8_t flagExtended = 1 << 0;
	constexpr static uint8_t flagValid = 1 << 1;
	constexpr static uint8_t flagExtendedChunkOccupied = 1 << 7;

	union tEntry
	{
		struct
		{
			uint8_t flags : 8;
			union
			{
				uint32_t valueId : 24;
				uint32_t extendedChunkId : 24;
			} __attribute__((__packed__));
		} __attribute__((__packed__));

		uint32_t atomic;
	} __attribute__((__packed__));

	static_assert(sizeof(tEntry) == 4, "invalid size of tEntry");

	struct tChunk8
	{
		tChunk8()
		{
			memset(&entries[0], 0, sizeof(entries));
		}

		tEntry entries[256];
	} __attribute__((__packed__));

	struct tChunk24
	{
		tChunk24()
		{
			memset(this, 0, sizeof(*this));
		}

		tEntry entries[256 * 256 * 256];
	} __attribute__((__packed__));

protected:
	uint32_t extendedChunksCount;
	uint32_t maxUsedChunkId;
	tEntry freeChunkCache;

	bool newExtendedChunk(uint32_t& extendedChunkId)
	{
		if (freeChunkCache.flags & flagExtended)
		{
			extendedChunkId = freeChunkCache.extendedChunkId;
			tChunk8& extendedChunk = extendedChunks[extendedChunkId];
			freeChunkCache.flags = extendedChunk.entries[0].flags;
			freeChunkCache.extendedChunkId = extendedChunk.entries[0].extendedChunkId;
			memset(&extendedChunk.entries[0], 0, sizeof(extendedChunk.entries));
			extendedChunk.entries[0].flags |= flagExtendedChunkOccupied;
			++extendedChunksCount;
			return true;
		}
		else if (maxUsedChunkId < TExtendedSize)
		{
			extendedChunkId = maxUsedChunkId++;

			tChunk8& extendedChunk = extendedChunks[extendedChunkId];
			memset(&extendedChunk.entries[0], 0, sizeof(extendedChunk.entries));
			extendedChunk.entries[0].flags |= flagExtendedChunkOccupied;
			++extendedChunksCount;
			return true;
		}

		return false;
	}

	void freeExtendedChunk(const uint32_t& extendedChunkId)
	{
		tChunk8& extendedChunk = extendedChunks[extendedChunkId];

		extendedChunk.entries[0].flags = freeChunkCache.flags;
		extendedChunk.entries[0].extendedChunkId = freeChunkCache.extendedChunkId;

		freeChunkCache.flags = flagExtended;
		freeChunkCache.extendedChunkId = extendedChunkId;
		--extendedChunksCount;
	}

	static void updateEntry(tEntry& entry,
	                        const uint8_t& flags,
	                        const uint32_t& value)
	{
		tEntry newEntry;
		newEntry.flags = flags & ~flagExtendedChunkOccupied;
		newEntry.flags |= entry.flags & flagExtendedChunkOccupied;
		newEntry.valueId = value;

		YADECAP_MEMORY_BARRIER_COMPILE;

		entry.atomic = newEntry.atomic;
	}

	static void updateAllEntries(tChunk8& chunk,
	                             const tEntry& entry)
	{
		YADECAP_MEMORY_BARRIER_COMPILE;

		uint8_t flag = chunk.entries[0].flags & flagExtendedChunkOccupied;

		tEntry newEntry;
		newEntry.atomic = entry.atomic;
		newEntry.flags &= ~flagExtendedChunkOccupied;

		YADECAP_MEMORY_BARRIER_COMPILE;

		for (unsigned int entry_i = 0;
		     entry_i < 256;
		     entry_i++)
		{
			chunk.entries[entry_i].atomic = newEntry.atomic;
		}

		chunk.entries[0].flags |= flag;

		YADECAP_MEMORY_BARRIER_COMPILE;
	}

	eResult insertStep1(const uint32_t& ipAddress,
	                    const uint8_t& mask,
	                    const uint32_t& valueId,
	                    bool* needWait,
	                    const unsigned int& step,
	                    tChunk24& chunk)
	{
		if (mask > 24)
		{
			uint32_t entry_i = ipAddress >> 8;

			if (chunk.entries[entry_i].flags & flagExtended)
			{
				/// already extended

				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

				eResult result = insertStep2(ipAddress,
				                             mask - 24,
				                             valueId,
				                             needWait,
				                             step + 1,
				                             extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					return result;
				}

				bool merge = true;
				for (unsigned int next_entry_i = 0;
				     next_entry_i < 256;
				     next_entry_i++)
				{
					if (!(extendedChunks[extendedChunkId].entries[next_entry_i].flags & flagValid &&
					      extendedChunks[extendedChunkId].entries[next_entry_i].valueId == valueId))
					{
						merge = false;
						break;
					}
				}
				if (merge)
				{
					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}

				return eResult::success;
			}
			else
			{
				/// valid or empty

				if (chunk.entries[entry_i].flags & flagValid &&
				    chunk.entries[entry_i].valueId == valueId)
				{
					return eResult::success;
				}

				uint32_t extendedChunkId;
				if (!newExtendedChunk(extendedChunkId))
				{
					YADECAP_LOG_WARNING("lpm4 is full\n");
					return eResult::isFull;
				}

				updateAllEntries(extendedChunks[extendedChunkId],
				                 chunk.entries[entry_i]);

				eResult result = insertStep2(ipAddress,
				                             mask - 24,
				                             valueId,
				                             needWait,
				                             step + 1,
				                             extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					freeExtendedChunk(extendedChunkId);
					return result;
				}

				updateEntry(chunk.entries[entry_i],
				            flagExtended,
				            extendedChunkId);

				return eResult::success;
			}
		}
		else
		{
			for (unsigned int mask_i = 0;
			     mask_i < (((unsigned int)1) << (24 - mask));
			     mask_i++)
			{
				uint32_t entry_i = (ipAddress >> 8) + mask_i;

				if (chunk.entries[entry_i].flags & flagExtended)
				{
					/// extended

					uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}
				else
				{
					/// valid or empty

					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);
				}
			}

			return eResult::success;
		}
	}

	eResult insertStep2(const uint32_t& ipAddress,
	                    const uint8_t& mask,
	                    const uint32_t& valueId,
	                    bool* needWait,
	                    const unsigned int& step,
	                    tChunk8& chunk)
	{
		(void)needWait;
		(void)step;

		for (unsigned int mask_i = 0;
		     mask_i < (((unsigned int)1) << (8 - mask));
		     mask_i++)
		{
			uint8_t entry_i = (ipAddress & 0xFF) + mask_i;

			updateEntry(chunk.entries[entry_i],
			            flagValid,
			            valueId);
		}

		return eResult::success;
	}

	eResult removeStep1(const uint32_t& ipAddress,
	                    const uint8_t& mask,
	                    bool* needWait,
	                    const unsigned int& step,
	                    tChunk24& chunk)
	{
		if (mask > 24)
		{
			uint32_t entry_i = ipAddress >> 8;

			if (chunk.entries[entry_i].flags & flagExtended)
			{
				/// extended

				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

				eResult result = removeStep2(ipAddress,
				                             mask - 24,
				                             needWait,
				                             step + 1,
				                             extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					return result;
				}

				bool isEmpty = true;
				for (unsigned int next_entry_i = 0;
				     next_entry_i < 256;
				     next_entry_i++)
				{
					if (extendedChunks[extendedChunkId].entries[next_entry_i].flags & (flagExtended | flagValid))
					{
						isEmpty = false;
						break;
					}
				}
				if (isEmpty)
				{
					updateEntry(chunk.entries[entry_i],
					            0,
					            0);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}

				return eResult::success;
			}
			else if (chunk.entries[entry_i].flags & flagValid)
			{
				/// valid

				uint32_t extendedChunkId;
				if (!newExtendedChunk(extendedChunkId))
				{
					YADECAP_LOG_WARNING("lpm4 is full\n");
					return eResult::isFull;
				}

				updateAllEntries(extendedChunks[extendedChunkId],
				                 chunk.entries[entry_i]);

				eResult result = removeStep2(ipAddress,
				                             mask - 24,
				                             needWait,
				                             step + 1,
				                             extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					freeExtendedChunk(extendedChunkId);
					return result;
				}

				updateEntry(chunk.entries[entry_i],
				            flagExtended,
				            extendedChunkId);

				return eResult::success;
			}
			else
			{
				/// empty

				/** @todo: only for debug
				YADECAP_LOG_DEBUG("chunk is invalid\n");
				return eResult::invalidArguments;
				*/

				return eResult::success;
			}
		}
		else
		{
			for (unsigned int mask_i = 0;
			     mask_i < (((unsigned int)1) << (24 - mask));
			     mask_i++)
			{
				uint32_t entry_i = (ipAddress >> 8) + mask_i;

				if (chunk.entries[entry_i].flags & flagExtended)
				{
					uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

					updateEntry(chunk.entries[entry_i],
					            0,
					            0);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}
				else
				{
					updateEntry(chunk.entries[entry_i],
					            0,
					            0);
				}
			}

			return eResult::success;
		}
	}

	eResult removeStep2(const uint32_t& ipAddress,
	                    const uint8_t& mask,
	                    bool* needWait,
	                    const unsigned int& step,
	                    tChunk8& chunk)
	{
		(void)needWait;
		(void)step;

		for (unsigned int mask_i = 0;
		     mask_i < (((unsigned int)1) << (8 - mask));
		     mask_i++)
		{
			uint8_t entry_i = (ipAddress & 0xFF) + mask_i;

			updateEntry(chunk.entries[entry_i],
			            0,
			            0);
		}

		return eResult::success;
	}

protected:
	tChunk24 rootChunk;
	tChunk8 extendedChunks[TExtendedSize];
} __rte_aligned(RTE_CACHE_LINE_SIZE);

//

template<uint32_t TExtendedSize>
class lpm6_8x16bit_atomic
{
public:
	lpm6_8x16bit_atomic()
	{
		extendedChunksCount = 0;
		maxUsedChunkId = 0;
		freeChunkCache.flags = 0;
	}

	static std::array<uint8_t, 16> createMask(uint8_t ones)
	{
		std::array<uint8_t, 16> maskBuf;
		for (int i = 0; i < 16; i++)
		{
			if (ones >= 8)
			{
				maskBuf[i] = 0xFF;
				ones -= 8;
				continue;
			}

			maskBuf[i] = ~(0xFF >> ones);
			ones = 0;
		}

		return maskBuf;
	}

	/// Insertion order matters!
	eResult insert(const std::array<uint8_t, 16>& ipv6Address,
	               const uint8_t& mask,
	               const uint32_t& valueId,
	               bool* needWait = nullptr)
	{
		if (mask > 128 ||
		    valueId & 0xFF000000)
		{
			YADECAP_LOG_DEBUG("invalid prefix or value\n");
			return eResult::invalidArguments;
		}

		if (needWait)
		{
			*needWait = false;
		}

		return insertStep(ipv6Address,
		                  mask,
		                  valueId,
		                  needWait,
		                  0,
		                  rootChunk);
	}

	eResult insert(const std::array<uint8_t, 16>& ipv6Address,
	               const std::array<uint8_t, 16>& mask,
	               const uint32_t& valueId)
	{
		if (valueId & 0xFF000000)
		{
			YADECAP_LOG_DEBUG("invalid value\n");
			return eResult::invalidArguments;
		}

		return insertStep(ipv6Address,
		                  mask,
		                  valueId,
		                  0,
		                  false,
		                  rootChunk);
	}

	eResult remove(const std::array<uint8_t, 16>& ipv6Address,
	               const uint8_t& mask,
	               bool* needWait = nullptr)
	{
		if (mask > 128)
		{
			YADECAP_LOG_DEBUG("invalid prefix\n");
			return eResult::invalidArguments;
		}

		if (needWait)
		{
			*needWait = false;
		}

		return removeStep(ipv6Address,
		                  mask,
		                  needWait,
		                  0,
		                  rootChunk);
	}

	eResult remove(const std::array<uint8_t, 16>& ipv6Address,
	               const std::array<uint8_t, 16>& mask)
	{
		return removeStep(ipv6Address, mask, 0, false, rootChunk);
	}

	void clear()
	{
		this->rootChunk = {};
		extendedChunksCount = 0;
		maxUsedChunkId = 0;
		freeChunkCache.flags = 0;
	}

	inline void lookup(const ipv6_address_t* ipv6Addresses,
	                   uint32_t* valueIds,
	                   const unsigned int& count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int ipv6Address_i = 0;
		     ipv6Address_i < count;
		     ipv6Address_i++)
		{
			const ipv6_address_t& ipv6Address = ipv6Addresses[ipv6Address_i];
			const tChunk* currentChunk = &rootChunk;

			valueIds[ipv6Address_i] = lpmValueIdInvalid;

			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.bytes) + step));

				tEntry entry;
				entry.atomic = currentChunk->entries[entry_i].atomic;

				if (entry.flags & flagValid)
				{
					///                     = entry.valueId;
					valueIds[ipv6Address_i] = entry.atomic >> 8;
					break;
				}
				else if (entry.flags & flagExtended)
				{
					///          = &extendedChunks[entry.extendedChunkId];
					currentChunk = &extendedChunks[entry.atomic >> 8];
				}
				else
				{
					break;
				}
			}
		}
	}

	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	inline void lookup(const uint32_t mask,
	                   const ipv6_address_t* ipv6Addresses,
	                   uint32_t* valueIds,
	                   const unsigned int& count) const
	{
		/// @todo: OPT: le -> be

		if (mask == mask_full)
		{
			return;
		}

		for (unsigned int ipv6Address_i = 0;
		     ipv6Address_i < count;
		     ipv6Address_i++)
		{
			if (mask & (1u << ipv6Address_i))
			{
				continue;
			}

			const ipv6_address_t& ipv6Address = ipv6Addresses[ipv6Address_i];
			const tChunk* currentChunk = &rootChunk;

			valueIds[ipv6Address_i] = lpmValueIdInvalid;

			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.bytes) + step));

				tEntry entry;
				entry.atomic = currentChunk->entries[entry_i].atomic;

				if (entry.flags & flagValid)
				{
					///                     = entry.valueId;
					valueIds[ipv6Address_i] = entry.atomic >> 8;
					break;
				}
				else if (entry.flags & flagExtended)
				{
					///          = &extendedChunks[entry.extendedChunkId];
					currentChunk = &extendedChunks[entry.atomic >> 8];
				}
				else
				{
					break;
				}
			}
		}
	}

	template<unsigned int TOffset>
	inline void lookup(rte_mbuf** mbufs,
	                   uint32_t* valueIds,
	                   const unsigned int& count) const
	{
		ipv6_address_t ipv6Addresses[CONFIG_YADECAP_MBUFS_BURST_SIZE];

		for (unsigned int mbuf_i = 0;
		     mbuf_i < count;
		     mbuf_i++)
		{
			const rte_mbuf* mbuf = mbufs[mbuf_i];
			dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

			memcpy(ipv6Addresses[mbuf_i].bytes,
			       rte_pktmbuf_mtod_offset(mbuf, const void*, metadata->network_headerOffset + TOffset),
			       16);
		}

		lookup(ipv6Addresses, valueIds, count);
	}

	inline bool lookup(const std::array<uint8_t, 16>& ipv6Address,
	                   uint32_t* valueId = nullptr) const
	{
		ipv6_address_t lipv6Address;
		uint32_t lvalueId;

		memcpy(lipv6Address.bytes, ipv6Address.data(), 16);
		lookup(&lipv6Address, &lvalueId, 1);

		if (valueId)
		{
			*valueId = lvalueId;
		}

		if (lvalueId != lpmValueIdInvalid)
		{
			return true;
		}

		return false;
	}

	inline bool lookup(const uint8_t* ipv6_address,
	                   uint32_t* value_id = nullptr) const
	{
		ipv6_address_t lipv6Address;
		uint32_t lvalueId;

		memcpy(lipv6Address.bytes, ipv6_address, 16);
		lookup(&lipv6Address, &lvalueId, 1);

		if (value_id)
		{
			*value_id = lvalueId;
		}

		if (lvalueId != lpmValueIdInvalid)
		{
			return true;
		}

		return false;
	}

	struct tStats
	{
		uint64_t extendedChunksCount;
	};

	tStats getStats() const
	{
		tStats result;
		memset(&result, 0, sizeof(result));

		result.extendedChunksCount = extendedChunksCount;

		return result;
	}

protected:
	constexpr static uint8_t flagExtended = 1 << 0;
	constexpr static uint8_t flagValid = 1 << 1;
	constexpr static uint8_t flagExtendedChunkOccupied = 1 << 7;

	union tEntry
	{
		struct
		{
			uint8_t flags : 8;
			union
			{
				uint32_t valueId : 24;
				uint32_t extendedChunkId : 24;
			} __attribute__((__packed__));
		} __attribute__((__packed__));

		uint32_t atomic;
	} __attribute__((__packed__));

	static_assert(sizeof(tEntry) == 4, "invalid size of tEntry");

	struct tChunk
	{
		tChunk()
		{
			memset(&entries[0], 0, sizeof(entries));
		}

		tEntry entries[256 * 256];

		uint16_t ownerMaskHextet;
	} __attribute__((__packed__));

protected:
	uint32_t extendedChunksCount;
	tEntry freeChunkCache;

	bool newExtendedChunk(uint32_t& extendedChunkId, uint16_t ownerMaskHextet)
	{
		if (freeChunkCache.flags & flagExtended)
		{
			extendedChunkId = freeChunkCache.extendedChunkId;
			tChunk& extendedChunk = extendedChunks[extendedChunkId];
			freeChunkCache.flags = extendedChunk.entries[0].flags;
			freeChunkCache.extendedChunkId = extendedChunk.entries[0].extendedChunkId;
			memset(&extendedChunk.entries[0], 0, sizeof(extendedChunk.entries));
			extendedChunk.entries[0].flags |= flagExtendedChunkOccupied;
			extendedChunk.ownerMaskHextet = ownerMaskHextet;
			++extendedChunksCount;
			return true;
		}
		else if (maxUsedChunkId < TExtendedSize)
		{
			extendedChunkId = maxUsedChunkId++;

			tChunk& extendedChunk = extendedChunks[extendedChunkId];
			memset(&extendedChunk.entries[0], 0, sizeof(extendedChunk.entries));
			extendedChunk.entries[0].flags |= flagExtendedChunkOccupied;
			extendedChunk.ownerMaskHextet = ownerMaskHextet;
			++extendedChunksCount;
			return true;
		}

		return false;
	}

	void freeExtendedChunk(const uint32_t extendedChunkId)
	{
		tChunk& extendedChunk = extendedChunks[extendedChunkId];
		if (!(extendedChunk.entries[0].flags & flagExtendedChunkOccupied))
		{
			return;
		}

		for (unsigned int entry_i = 0;
		     entry_i < 256 * 256;
		     entry_i++)
		{
			if (extendedChunk.entries[entry_i].flags & flagExtended)
			{
				freeExtendedChunk(extendedChunk.entries[entry_i].extendedChunkId);
			}
		}

		extendedChunk.entries[0].flags = freeChunkCache.flags;
		extendedChunk.entries[0].extendedChunkId = freeChunkCache.extendedChunkId;

		freeChunkCache.flags = flagExtended;
		freeChunkCache.extendedChunkId = extendedChunkId;
		--extendedChunksCount;
	}

	static void updateEntry(tEntry& entry,
	                        const uint8_t& flags,
	                        const uint32_t& value)
	{
		tEntry newEntry;
		newEntry.flags = flags & ~flagExtendedChunkOccupied;
		newEntry.flags |= entry.flags & flagExtendedChunkOccupied;
		newEntry.valueId = value;

		YADECAP_MEMORY_BARRIER_COMPILE;

		entry.atomic = newEntry.atomic;
	}

	static void updateAllEntries(tChunk& chunk,
	                             const tEntry& entry)
	{
		YADECAP_MEMORY_BARRIER_COMPILE;

		uint8_t flag = chunk.entries[0].flags & flagExtendedChunkOccupied;

		tEntry newEntry;
		newEntry.atomic = entry.atomic;
		newEntry.flags &= ~flagExtendedChunkOccupied;

		YADECAP_MEMORY_BARRIER_COMPILE;

		for (unsigned int entry_i = 0;
		     entry_i < 256 * 256;
		     entry_i++)
		{
			chunk.entries[entry_i].atomic = newEntry.atomic;
		}

		chunk.entries[0].flags |= flag;

		YADECAP_MEMORY_BARRIER_COMPILE;
	}

	static uint16_t hextetOf(const std::array<uint8_t, 16>& addr, const unsigned int& step)
	{
		assert(step < 8);
		return (addr[2 * step] << 8) + addr[2 * step + 1];
	}

	static bool hasMoreMaskFurtherFrom(const std::array<uint8_t, 16>& mask, const unsigned int& step)
	{
		assert(step < 8);

		for (auto s = step + 1; s < 8; s++)
		{
			if (hextetOf(mask, s) > 0)
			{
				return true;
			}
		}

		return false;
	}

	// todo: reuse common::ipv6_network
	eResult insertStep(const std::array<uint8_t, 16>& ipv6Address,
	                   const std::array<uint8_t, 16>& mask,
	                   const uint32_t& valueId,
	                   const unsigned int& step,
	                   const bool& copyChunk,
	                   tChunk& chunk)
	{
		const auto maskHextet = hextetOf(mask, step);
		const auto hasMoreMaskFurther = hasMoreMaskFurtherFrom(mask, step);
		const auto hextet = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step));

		if (!hasMoreMaskFurther)
		{
			// This hextet is the latest, we should fill the chunk with the given value and return.
			for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
			{
				// todo: free chunk if it is extended? test.
				uint16_t entry_i = hextet + mask_i;
				updateEntry(chunk.entries[entry_i], flagValid, valueId);
			}
			return eResult::success;
		}

		uint32_t extChunkId = lpmValueIdInvalid;
		std::unordered_map<uint32_t, uint32_t> nextExtendedChunkIds;
		std::unordered_map<uint32_t, uint32_t> nextValuedChunkIds;
		auto freeAllocatedExtendedChunks = [&]() {
			if (extChunkId != lpmValueIdInvalid)
			{
				freeExtendedChunk(extChunkId);
			}

			for (auto it : nextValuedChunkIds)
			{
				freeExtendedChunk(it.second);
			}
		};

		uint32_t lastExtendedChunkId = lpmValueIdInvalid;
		std::pair<uint32_t, uint32_t> lastValuedChunkId = {lpmValueIdInvalid, lpmValueIdInvalid};
		for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
		{
			uint16_t entry_i = hextet + mask_i;
			if (chunk.entries[entry_i].flags & flagExtended)
			{
				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;
				if (lastExtendedChunkId != extendedChunkId)
				{
					const auto& it = nextExtendedChunkIds.find(extendedChunkId);
					if (it == nextExtendedChunkIds.end())
					{
						auto& nextChunk = extendedChunks[extendedChunkId];
						if (copyChunk || (~nextChunk.ownerMaskHextet & maskHextet))
						{
							uint32_t newExtendedChunkId;
							if (!newExtendedChunk(newExtendedChunkId, maskHextet))
							{
								freeAllocatedExtendedChunks();
								return eResult::isFull;
							}
							auto& newChunk = extendedChunks[newExtendedChunkId];
							memcpy(newChunk.entries, nextChunk.entries, sizeof(chunk.entries));
							nextExtendedChunkIds.emplace(extendedChunkId, newExtendedChunkId);
							updateEntry(chunk.entries[entry_i], flagExtended, newExtendedChunkId);
						}
						else
						{
							nextExtendedChunkIds.emplace(extendedChunkId, extendedChunkId);
						}
					}
					else
					{
						updateEntry(chunk.entries[entry_i], flagExtended, it->second);
					}
					lastExtendedChunkId = extendedChunkId;
				}
			}
			else if (chunk.entries[entry_i].flags & flagValid)
			{
				uint32_t valueId = chunk.entries[entry_i].valueId;
				uint32_t nextValuedChunkId = lastValuedChunkId.second;
				if (lastValuedChunkId.first != valueId)
				{
					auto it = nextValuedChunkIds.find(valueId);
					if (it == nextValuedChunkIds.end())
					{
						if (!newExtendedChunk(nextValuedChunkId, maskHextet))
						{
							freeAllocatedExtendedChunks();
							return eResult::isFull;
						}

						nextValuedChunkIds.emplace(valueId, nextValuedChunkId);

						updateAllEntries(extendedChunks[nextValuedChunkId], chunk.entries[entry_i]);
					}
					else
					{
						nextValuedChunkId = it->second;
					}
					lastValuedChunkId = {valueId, nextValuedChunkId};
				}
				updateEntry(chunk.entries[entry_i], flagExtended, nextValuedChunkId);
			}
			else
			{
				// This entry is empty. Allocate new chunk if required, copy this chunk's content to it and
				// point entry to the new chunk.

				if (extChunkId == lpmValueIdInvalid)
				{
					// No chunk was allocated before, so allocate it.
					if (!newExtendedChunk(extChunkId, maskHextet))
					{
						freeAllocatedExtendedChunks();
						return eResult::isFull;
					}

					updateAllEntries(extendedChunks[extChunkId], chunk.entries[entry_i]);
					nextExtendedChunkIds.emplace(extChunkId, extChunkId);
				}

				updateEntry(chunk.entries[entry_i], flagExtended, extChunkId);
			}
		}

		for (const auto& it : nextValuedChunkIds)
		{
			auto chunkId = it.second;
			eResult result = insertStep(ipv6Address, mask, valueId, step + 1, copyChunk, extendedChunks[chunkId]);
			if (result != eResult::success)
			{
				freeAllocatedExtendedChunks();
				return result;
			}
		}
		for (const auto& it : nextExtendedChunkIds)
		{
			auto chunkId = it.second;
			eResult result = insertStep(ipv6Address, mask, valueId, step + 1, copyChunk || (it.first != chunkId), extendedChunks[chunkId]);
			if (result != eResult::success)
			{
				freeAllocatedExtendedChunks();
				return result;
			}

			bool merge = true;
			for (unsigned int next_entry_i = 0; next_entry_i < 256 * 256; next_entry_i++)
			{
				if (!(extendedChunks[chunkId].entries[next_entry_i].flags & flagValid &&
				      extendedChunks[chunkId].entries[next_entry_i].valueId == valueId))
				{
					merge = false;
					break;
				}
			}
			if (merge)
			{
				for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
				{
					uint16_t entry_i = hextet + mask_i;
					if (chunk.entries[entry_i].extendedChunkId == chunkId && chunk.entries[entry_i].flags & flagExtended)
					{
						updateEntry(chunk.entries[entry_i], flagValid, valueId);
					}
				}
				freeExtendedChunk(chunkId);
			}
		}

		return eResult::success;
	}

	eResult
	insertStep(const std::array<uint8_t, 16>& ipv6Address,
	           const uint8_t& mask,
	           const uint32_t& valueId,
	           bool* needWait,
	           const unsigned int& step,
	           tChunk& chunk)
	{
		if (mask > 16)
		{
			uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step));

			if (chunk.entries[entry_i].flags & flagExtended)
			{
				/// already extended

				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

				eResult result = insertStep(ipv6Address,
				                            mask - 16,
				                            valueId,
				                            needWait,
				                            step + 1,
				                            extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					return result;
				}

				bool merge = true;
				for (unsigned int next_entry_i = 0;
				     next_entry_i < 256 * 256;
				     next_entry_i++)
				{
					if (!(extendedChunks[extendedChunkId].entries[next_entry_i].flags & flagValid &&
					      extendedChunks[extendedChunkId].entries[next_entry_i].valueId == valueId))
					{
						merge = false;
						break;
					}
				}
				if (merge)
				{
					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}

				return eResult::success;
			}
			else
			{
				/// valid or empty

				if (chunk.entries[entry_i].flags & flagValid &&
				    chunk.entries[entry_i].valueId == valueId)
				{
					return eResult::success;
				}

				uint32_t extendedChunkId;
				if (!newExtendedChunk(extendedChunkId, 0xffff))
				{
					YADECAP_LOG_WARNING("lpm6 is full\n");
					return eResult::isFull;
				}

				updateAllEntries(extendedChunks[extendedChunkId],
				                 chunk.entries[entry_i]);

				eResult result = insertStep(ipv6Address,
				                            mask - 16,
				                            valueId,
				                            needWait,
				                            step + 1,
				                            extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					freeExtendedChunk(extendedChunkId);
					return result;
				}

				updateEntry(chunk.entries[entry_i],
				            flagExtended,
				            extendedChunkId);

				return eResult::success;
			}
		}
		else
		{
			for (unsigned int mask_i = 0;
			     mask_i < (((unsigned int)1) << (16 - mask));
			     mask_i++)
			{
				uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step)) + mask_i;

				if (chunk.entries[entry_i].flags & flagExtended)
				{
					/// extended

					uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}
				else
				{
					/// valid or empty

					updateEntry(chunk.entries[entry_i],
					            flagValid,
					            valueId);
				}
			}

			return eResult::success;
		}
	}

	eResult removeStep(const std::array<uint8_t, 16>& ipv6Address,
	                   const std::array<uint8_t, 16>& mask,
	                   const unsigned int& step,
	                   const bool& copyChunk,
	                   tChunk& chunk)
	{
		const auto maskHextet = hextetOf(mask, step);
		const auto hasMoreMaskFurther = hasMoreMaskFurtherFrom(mask, step);

		if (!hasMoreMaskFurther)
		{
			// This hextet is the latest, we should fill the chunk with 0 and return.
			for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
			{
				uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step)) + mask_i;
				if (chunk.entries[entry_i].flags & flagExtended)
				{
					uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;
					freeExtendedChunk(extendedChunkId);
				}
				updateEntry(chunk.entries[entry_i], 0, 0);
			}
			return eResult::success;
		}

		uint32_t extChunkId = lpmValueIdInvalid;
		std::unordered_map<uint32_t, uint32_t> nextExtendedChunkIds;
		std::unordered_map<uint32_t, uint32_t> nextValuedChunkIds;
		auto freeAllocatedExtendedChunks = [&]() {
			if (extChunkId != lpmValueIdInvalid)
			{
				freeExtendedChunk(extChunkId);
			}

			for (auto it : nextValuedChunkIds)
			{
				freeExtendedChunk(it.second);
			}
		};

		for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
		{
			uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step)) + mask_i;
			if (chunk.entries[entry_i].flags & flagExtended)
			{
				// Entry is extended. Go deeper.

				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;
				const auto& it = nextExtendedChunkIds.find(extendedChunkId);
				if (it == nextExtendedChunkIds.end())
				{
					auto& nextChunk = extendedChunks[extendedChunkId];
					if (copyChunk || (~nextChunk.ownerMaskHextet & maskHextet))
					{
						uint32_t newExtendedChunkId;
						if (!newExtendedChunk(newExtendedChunkId, maskHextet))
						{
							freeAllocatedExtendedChunks();
							return eResult::isFull;
						}
						auto& newChunk = extendedChunks[newExtendedChunkId];
						memcpy(newChunk.entries, nextChunk.entries, sizeof(chunk.entries));
						nextExtendedChunkIds.emplace(extendedChunkId, newExtendedChunkId);
						updateEntry(chunk.entries[entry_i], flagExtended, newExtendedChunkId);
					}
					else
					{
						nextExtendedChunkIds.emplace(extendedChunkId, extendedChunkId);
					}
				}
				else
				{
					updateEntry(chunk.entries[entry_i], flagExtended, it->second);
				}
			}
			else if (chunk.entries[entry_i].flags & flagValid)
			{
				// Entry is valid. Split.

				uint32_t valueId = chunk.entries[entry_i].valueId;
				if (nextValuedChunkIds.count(valueId) == 0)
				{
					uint32_t nextExtendedChunkId;
					if (!newExtendedChunk(nextExtendedChunkId, maskHextet))
					{
						freeAllocatedExtendedChunks();
						return eResult::isFull;
					}

					nextValuedChunkIds.emplace(valueId, nextExtendedChunkId);

					updateAllEntries(extendedChunks[nextExtendedChunkId], chunk.entries[entry_i]);
				}
				updateEntry(chunk.entries[entry_i], flagExtended, nextValuedChunkIds[valueId]);
			}
			else
			{
				YADECAP_LOG_DEBUG("chunk is invalid\n");
				return eResult::invalidArguments;
			}
		}

		for (const auto& it : nextValuedChunkIds)
		{
			auto chunkId = it.second;
			eResult result = removeStep(ipv6Address, mask, step + 1, copyChunk, extendedChunks[chunkId]);
			if (result != eResult::success)
			{
				freeAllocatedExtendedChunks();
				return result;
			}
		}
		for (const auto& it : nextExtendedChunkIds)
		{
			auto chunkId = it.second;
			eResult result = removeStep(ipv6Address, mask, step + 1, copyChunk || (it.first != it.second), extendedChunks[chunkId]);
			if (result != eResult::success)
			{
				freeAllocatedExtendedChunks();
				return result;
			}

			bool isEmpty = true;
			for (unsigned int next_entry_i = 0; next_entry_i < 256 * 256; next_entry_i++)
			{
				if (extendedChunks[chunkId].entries[next_entry_i].flags & (flagExtended | flagValid))
				{
					isEmpty = false;
					break;
				}
			}
			if (isEmpty)
			{
				for (unsigned int mask_i = 0; mask_i < static_cast<unsigned int>(0xffff - maskHextet + 1); mask_i++)
				{
					uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step)) + mask_i;
					if (chunk.entries[entry_i].extendedChunkId == chunkId && chunk.entries[entry_i].flags & flagExtended)
					{
						updateEntry(chunk.entries[entry_i], 0, 0);
					}
				}
				freeExtendedChunk(chunkId);
			}
		}

		return eResult::success;
	}

	eResult removeStep(const std::array<uint8_t, 16>& ipv6Address,
	                   const uint8_t& mask,
	                   bool* needWait,
	                   const unsigned int& step,
	                   tChunk& chunk)
	{
		if (mask > 16)
		{
			uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step));

			if (chunk.entries[entry_i].flags & flagExtended)
			{
				/// extended

				uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

				eResult result = removeStep(ipv6Address,
				                            mask - 16,
				                            needWait,
				                            step + 1,
				                            extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					return result;
				}

				bool isEmpty = true;
				for (unsigned int next_entry_i = 0;
				     next_entry_i < 256 * 256;
				     next_entry_i++)
				{
					if (extendedChunks[extendedChunkId].entries[next_entry_i].flags & (flagExtended | flagValid))
					{
						isEmpty = false;
						break;
					}
				}
				if (isEmpty)
				{
					updateEntry(chunk.entries[entry_i],
					            0,
					            0);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}

				return eResult::success;
			}
			else if (chunk.entries[entry_i].flags & flagValid)
			{
				/// valid

				uint32_t extendedChunkId;
				if (!newExtendedChunk(extendedChunkId, 0xffff))
				{
					YADECAP_LOG_WARNING("lpm6 is full\n");
					return eResult::isFull;
				}

				updateAllEntries(extendedChunks[extendedChunkId],
				                 chunk.entries[entry_i]);

				eResult result = removeStep(ipv6Address,
				                            mask - 16,
				                            needWait,
				                            step + 1,
				                            extendedChunks[extendedChunkId]);
				if (result != eResult::success)
				{
					freeExtendedChunk(extendedChunkId);
					return result;
				}

				updateEntry(chunk.entries[entry_i],
				            flagExtended,
				            extendedChunkId);

				return eResult::success;
			}
			else
			{
				/// empty

				/** @todo: only for debug
				YADECAP_LOG_DEBUG("chunk is invalid\n");
				return eResult::invalidArguments;
				*/

				return eResult::success;
			}
		}
		else
		{
			for (unsigned int mask_i = 0;
			     mask_i < (((unsigned int)1) << (16 - mask));
			     mask_i++)
			{
				uint16_t entry_i = rte_be_to_cpu_16(*(((uint16_t*)ipv6Address.data()) + step)) + mask_i;

				if (chunk.entries[entry_i].flags & flagExtended)
				{
					uint32_t extendedChunkId = chunk.entries[entry_i].extendedChunkId;

					updateEntry(chunk.entries[entry_i],
					            0,
					            0);

					freeExtendedChunk(extendedChunkId);

					if (needWait)
					{
						*needWait = true;
					}
				}
				else
				{
					updateEntry(chunk.entries[entry_i],
					            0,
					            0);
				}
			}

			return eResult::success;
		}
	}

public:
	uint32_t maxUsedChunkId;
	tChunk rootChunk;
	tChunk extendedChunks[TExtendedSize];
} __rte_aligned(RTE_CACHE_LINE_SIZE);

//

template<uint32_t extended_chunks_size>
class lpm4_24bit_8bit_id32
{
public:
	class updater
	{
	public:
		updater() :
		        extended_chunks_count(1)
		{
		}

		void clear(const unsigned int tree_size)
		{
			extended_chunks_count = 1;
			remap_chunks.resize(0);
			remap_chunks.resize(tree_size, 0);
		}

		inline unsigned int allocate_extended_chunk()
		{
			if (extended_chunks_count >= extended_chunks_size)
			{
				return 0;
			}

			unsigned int new_chunk_id = extended_chunks_count;
			extended_chunks_count++;

			return new_chunk_id;
		}

		inline unsigned int& remap(const unsigned int from_chunk_id)
		{
			return remap_chunks[from_chunk_id];
		}

		unsigned int get_extended_chunks_count() const
		{
			return extended_chunks_count;
		}

		unsigned int get_extended_chunks_size() const
		{
			return extended_chunks_size;
		}

	public:
		unsigned int extended_chunks_count;
		std::vector<unsigned int> remap_chunks;
	};

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const std::optional<unsigned int>& socket_id,
	            const updater& updater) const
	{
		list.emplace_back(name + ".extended_chunks",
		                  socket_id,
		                  updater.extended_chunks_count,
		                  extended_chunks_size);
	}

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const updater& updater) const
	{
		limits(list, name, std::nullopt, updater);
	}

	template<typename json_t> ///< @todo: nlohmann::json
	void report(json_t& json,
	            const updater& updater) const
	{
		json["extended_chunks_count"] = updater.extended_chunks_count;
	}

public:
	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const ipv4_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			const auto& address = addresses[address_i].address;
			auto& group_id = group_ids[address_i];

			const auto& root_chunk_value = root_chunk.values[rte_be_to_cpu_32(address) >> 8];
			if (root_chunk_value.id & 0x80000000u)
			{
				const auto& extended_chunk = extended_chunks[root_chunk_value.id ^ 0x80000000u];
				group_id = extended_chunk.values[address >> 24].id;
			}
			else
			{
				group_id = root_chunk_value.id;
			}
		}
	}

	eResult update(updater& updater,
	               const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks)
	{
		updater.clear(from_chunks.size());
		return update_root_chunk<0>(updater, from_chunks, 0, 0);
	}

protected:
	constexpr static unsigned int bits_step1 = 24;
	constexpr static unsigned int bits_step2 = 8;
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	struct value_t
	{
		value_t() :
		        id(0)
		{
		}

		uint32_t id;
	};

	struct chunk_step1_t
	{
		value_t values[1u << bits_step1];
	};

	struct chunk_step2_t
	{
		value_t values[1u << bits_step2];
	};

	chunk_step1_t root_chunk;
	chunk_step2_t extended_chunks[extended_chunks_size];

protected:
	template<unsigned int bits_offset>
	eResult update_root_chunk(updater& updater,
	                          const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                          const unsigned int from_chunk_id,
	                          const unsigned int root_chunk_values_offset)
	{
		eResult result = eResult::success;

		const auto& from_chunk = from_chunks[from_chunk_id];
		for (uint32_t i = 0;
		     i < (1u << 8);
		     i++)
		{
			const unsigned int root_chunk_values_i = root_chunk_values_offset + (i << (bits_step1 - bits_offset - 8));
			const auto& from_chunk_value = from_chunk.values[i];

			if (from_chunk_value.is_chunk_id())
			{
				if constexpr (bits_offset < bits_step1 - bits_step2)
				{
					result = update_root_chunk<bits_offset + 8>(updater,
					                                            from_chunks,
					                                            from_chunk_value.get_chunk_id(),
					                                            root_chunk_values_i);
					if (result != eResult::success)
					{
						return result;
					}
				}
				else if constexpr (bits_offset < bits_step1)
				{
					auto& root_chunk_value = root_chunk.values[root_chunk_values_i];

					auto& extended_chunk_id = updater.remap(from_chunk_value.get_chunk_id());
					if (!extended_chunk_id)
					{
						extended_chunk_id = updater.allocate_extended_chunk();
						if (!extended_chunk_id)
						{
							YANET_LOG_ERROR("lpm is full\n");
							return eResult::isFull;
						}

						result = update_extended_chunk(updater,
						                               from_chunks,
						                               from_chunk_value.get_chunk_id(),
						                               extended_chunk_id);
						if (result != eResult::success)
						{
							return result;
						}
					}

					root_chunk_value.id = extended_chunk_id ^ 0x80000000u;
				}
				else
				{
					YANET_LOG_ERROR("tree broken\n");
					return eResult::invalidArguments;
				}
			}
			else
			{
				if constexpr (bits_offset < bits_step1)
				{
					for (uint32_t j = 0;
					     j < (1u << (bits_step1 - bits_offset - 8));
					     j++)
					{
						root_chunk.values[root_chunk_values_i + j].id = from_chunk_value.get_group_id();
					}
				}
				else
				{
					YANET_LOG_ERROR("tree broken\n");
					return eResult::invalidArguments;
				}
			}
		}

		return result;
	}

	eResult update_extended_chunk(updater& updater,
	                              const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                              const unsigned int from_chunk_id,
	                              const unsigned int extended_chunk_id)
	{
		(void)updater;

		const auto& from_chunk = from_chunks[from_chunk_id];
		auto& extended_chunk = extended_chunks[extended_chunk_id];

		for (uint32_t i = 0;
		     i < (1u << 8);
		     i++)
		{
			const auto& from_chunk_value = from_chunk.values[i];
			auto& extended_chunk_value = extended_chunk.values[i];

			if (from_chunk_value.is_chunk_id())
			{
				YANET_LOG_ERROR("is_chunk_id\n");
				return eResult::invalidArguments;
			}
			else
			{
				extended_chunk_value.id = from_chunk_value.get_group_id();
			}
		}

		return eResult::success;
	}
};

//

class lpm4_24bit_8bit_id32_dynamic
{
public:
	constexpr static uint64_t extended_chunks_size_min = 8;

	struct stats_t
	{
		uint32_t extended_chunks_size;
		unsigned int extended_chunks_count;
		std::vector<unsigned int> remap_chunks;
	};

	static uint64_t calculate_sizeof(const uint64_t extended_chunks_size)
	{
		if (!extended_chunks_size)
		{
			YANET_LOG_ERROR("wrong extended_chunks_size: %lu\n", extended_chunks_size);
			return 0;
		}

		return sizeof(lpm4_24bit_8bit_id32_dynamic) + extended_chunks_size * sizeof(chunk_step2_t);
	}

public:
	lpm4_24bit_8bit_id32_dynamic()
	{
		for (auto& value : root_chunk.values)
		{
			value.id = 0;
		}
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const ipv4_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			const auto& address = addresses[address_i].address;
			auto& group_id = group_ids[address_i];

			const auto& root_chunk_value = root_chunk.values[rte_be_to_cpu_32(address) >> 8];
			if (root_chunk_value.id & 0x80000000u)
			{
				const auto& extended_chunk = extended_chunks[root_chunk_value.id ^ 0x80000000u];
				group_id = extended_chunk.values[address >> 24].id;
			}
			else
			{
				group_id = root_chunk_value.id;
			}
		}
	}

	eResult fill(stats_t& stats, const std::vector<common::acl::tree_chunk_8bit_t>& values)
	{
		stats.extended_chunks_count = 1;
		stats.remap_chunks.resize(0);
		stats.remap_chunks.resize(values.size(), 0);

		if (values.empty())
		{
			return eResult::success;
		}

		return update_root_chunk<0>(stats, values, 0, 0);
	}

protected:
	constexpr static unsigned int bits_step1 = 24;
	constexpr static unsigned int bits_step2 = 8;
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	unsigned int allocate_extended_chunk(stats_t& stats)
	{
		if (stats.extended_chunks_count >= stats.extended_chunks_size)
		{
			return 0;
		}

		unsigned int new_chunk_id = stats.extended_chunks_count;
		stats.extended_chunks_count++;

		return new_chunk_id;
	}

	template<unsigned int bits_offset>
	eResult update_root_chunk(stats_t& stats,
	                          const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                          const unsigned int from_chunk_id,
	                          const unsigned int root_chunk_values_offset)
	{
		eResult result = eResult::success;

		const auto& from_chunk = from_chunks[from_chunk_id];
		for (uint32_t i = 0;
		     i < (1u << 8);
		     i++)
		{
			const unsigned int root_chunk_values_i = root_chunk_values_offset + (i << (bits_step1 - bits_offset - 8));
			const auto& from_chunk_value = from_chunk.values[i];

			if (from_chunk_value.is_chunk_id())
			{
				if constexpr (bits_offset < bits_step1 - bits_step2)
				{
					result = update_root_chunk<bits_offset + 8>(stats,
					                                            from_chunks,
					                                            from_chunk_value.get_chunk_id(),
					                                            root_chunk_values_i);
					if (result != eResult::success)
					{
						return result;
					}
				}
				else if constexpr (bits_offset < bits_step1)
				{
					auto& root_chunk_value = root_chunk.values[root_chunk_values_i];

					auto& extended_chunk_id = stats.remap_chunks[from_chunk_value.get_chunk_id()];
					if (!extended_chunk_id)
					{
						extended_chunk_id = allocate_extended_chunk(stats);
						if (!extended_chunk_id)
						{
							YANET_LOG_ERROR("lpm is full\n");
							return eResult::isFull;
						}

						result = update_extended_chunk(from_chunks,
						                               from_chunk_value.get_chunk_id(),
						                               extended_chunk_id);
						if (result != eResult::success)
						{
							return result;
						}
					}

					root_chunk_value.id = extended_chunk_id ^ 0x80000000u;
				}
				else
				{
					YANET_LOG_ERROR("tree broken\n");
					return eResult::invalidArguments;
				}
			}
			else
			{
				if constexpr (bits_offset < bits_step1)
				{
					for (uint32_t j = 0;
					     j < (1u << (bits_step1 - bits_offset - 8));
					     j++)
					{
						root_chunk.values[root_chunk_values_i + j].id = from_chunk_value.get_group_id();
					}
				}
				else
				{
					YANET_LOG_ERROR("tree broken\n");
					return eResult::invalidArguments;
				}
			}
		}

		return result;
	}

	eResult update_extended_chunk(const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                              const unsigned int from_chunk_id,
	                              const unsigned int extended_chunk_id)
	{
		const auto& from_chunk = from_chunks[from_chunk_id];
		auto& extended_chunk = extended_chunks[extended_chunk_id];

		for (uint32_t i = 0;
		     i < (1u << 8);
		     i++)
		{
			const auto& from_chunk_value = from_chunk.values[i];
			auto& extended_chunk_value = extended_chunk.values[i];

			if (from_chunk_value.is_chunk_id())
			{
				YANET_LOG_ERROR("is_chunk_id\n");
				return eResult::invalidArguments;
			}
			else
			{
				extended_chunk_value.id = from_chunk_value.get_group_id();
			}
		}

		return eResult::success;
	}

protected:
	struct value_t
	{
		uint32_t id;
	};

	struct chunk_step1_t
	{
		value_t values[1u << bits_step1];
	};

	struct chunk_step2_t
	{
		value_t values[1u << bits_step2];
	};

	chunk_step1_t root_chunk;
	chunk_step2_t extended_chunks[];
};

//

template<uint32_t chunks_size>
class lpm6_8x16bit_id32
{
public:
	class updater
	{
	public:
		updater() :
		        chunks_count(1) ///< 0 is root chunk
		{
		}

		void clear(const unsigned int tree_size)
		{
			chunks_count = 1; ///< 0 is root chunk
			remap_chunks.resize(0);
			remap_chunks.resize(tree_size, 0);
		}

		inline unsigned int allocate_chunk()
		{
			if (chunks_count >= chunks_size)
			{
				return 0;
			}

			unsigned int new_chunk_id = chunks_count;
			chunks_count++;

			return new_chunk_id;
		}

		inline unsigned int& remap(const unsigned int from_chunk_id)
		{
			return remap_chunks[from_chunk_id];
		}

	public:
		unsigned int chunks_count;
		std::vector<unsigned int> remap_chunks;
	};

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const std::optional<unsigned int>& socket_id,
	            const updater& updater) const
	{
		list.emplace_back(name + ".chunks",
		                  socket_id,
		                  updater.chunks_count,
		                  chunks_size);
	}

	template<typename list_T> ///< @todo: common::idp::limits::response
	void limits(list_T& list,
	            const std::string& name,
	            const updater& updater) const
	{
		limits(list, name, std::nullopt, updater);
	}

	template<typename json_t> ///< @todo: nlohmann::json
	void report(json_t& json,
	            const updater& updater) const
	{
		json["chunks_count"] = updater.chunks_count;
	}

public:
	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				const uint16_t step_address = rte_be_to_cpu_16(*(((uint16_t*)address.bytes) + step));
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const uint32_t mask,
	                   const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		if (mask == mask_full)
		{
			return;
		}

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			if (mask & (1u << address_i))
			{
				continue;
			}

			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				const uint16_t step_address = rte_be_to_cpu_16(*(((uint16_t*)address.bytes) + step));
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

	eResult update(updater& updater,
	               const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks)
	{
		updater.clear(from_chunks.size());
		return update_chunk(updater, from_chunks, root_chunk_id, root_chunk_id);
	}

protected:
	constexpr static unsigned int bits = 16;
	constexpr static unsigned int root_chunk_id = 0;
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	struct value_t
	{
		value_t() :
		        id(0)
		{
		}

		uint32_t id;
	};

	struct chunk_t
	{
		value_t values[1u << bits];
	};

	chunk_t chunks[chunks_size];

protected:
	eResult update_chunk(updater& updater,
	                     const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                     const unsigned int from_chunk_id,
	                     const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];
		chunk = {}; ///< @todo: delete?

		const auto& from_chunk = from_chunks[from_chunk_id];
		for (uint32_t i = 0;
		     i < (1u << 8);
		     i++)
		{
			const auto& from_chunk_value = from_chunk.values[i];

			if (from_chunk_value.is_chunk_id())
			{
				const auto& from_chunk_next = from_chunks[from_chunk_value.get_chunk_id()];

				memcpy(chunk.values + (i << 8), from_chunk_next.values, (1u << 8) * sizeof(common::acl::tree_value_t));
			}
			else
			{
				for (uint32_t j = 0;
				     j < (1u << 8);
				     j++)
				{
					chunk.values[(i << 8) + j].id = from_chunk_value.get_group_id();
				}
			}
		}

		std::vector<std::tuple<unsigned int, unsigned int>> nexts;

		for (uint32_t i = 0;
		     i < (1u << bits);
		     i++)
		{
			auto& chunk_value = chunk.values[i];

			if (chunk_value.id & 0x80000000u) ///< is_chunk_id
			{
				auto& chunk_id = updater.remap(chunk_value.id ^ 0x80000000u);
				if (!chunk_id)
				{
					chunk_id = updater.allocate_chunk();
					if (!chunk_id)
					{
						return eResult::isFull;
					}

					nexts.emplace_back(chunk_value.id ^ 0x80000000u, chunk_id);
				}

				chunk_value.id = chunk_id ^ 0x80000000u;
			}
		}

		for (const auto& [next_from_chunk_id, next_chunk_id] : nexts)
		{
			auto result = update_chunk(updater, from_chunks, next_from_chunk_id, next_chunk_id);
			if (result != eResult::success)
			{
				return result;
			}
		}

		return eResult::success;
	}
};

//

class lpm6_8x16bit_id32_dynamic
{
public:
	class updater
	{
	public:
		updater() :
		        lpm(nullptr),
		        chunks_size(0)
		{
		}

		void update_pointer(lpm6_8x16bit_id32_dynamic* lpm,
		                    const tSocketId socket_id,
		                    const unsigned int chunks_size)
		{
			this->lpm = lpm;
			this->socket_id = socket_id;
			this->chunks_size = chunks_size;
		}

		eResult update(const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks)
		{
			chunks_count = 1; ///< 0 is root chunk
			remap_chunks.resize(0);
			remap_chunks.resize(from_chunks.size(), 0);
			return update_chunk(from_chunks, root_chunk_id, root_chunk_id);
		}

	public:
		template<typename list_T> ///< @todo: common::idp::limits::response
		void limits(list_T& list,
		            const std::string& name) const
		{
			list.emplace_back(name + ".chunks",
			                  socket_id,
			                  chunks_count,
			                  chunks_size);
		}

		template<typename json_t> ///< @todo: nlohmann::json
		void report(json_t& json) const
		{
			json["chunks_count"] = chunks_count;
		}

	protected:
		inline unsigned int allocate_chunk()
		{
			if (chunks_count >= chunks_size)
			{
				return 0;
			}

			unsigned int new_chunk_id = chunks_count;
			chunks_count++;

			return new_chunk_id;
		}

		eResult update_chunk(const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
		                     const unsigned int from_chunk_id,
		                     const unsigned int chunk_id)
		{
			auto& chunk = lpm->chunks[chunk_id];
			chunk = {}; ///< @todo: delete?

			const auto& from_chunk = from_chunks[from_chunk_id];
			for (uint32_t i = 0;
			     i < (1u << 8);
			     i++)
			{
				const auto& from_chunk_value = from_chunk.values[i];

				if (from_chunk_value.is_chunk_id())
				{
					const auto& from_chunk_next = from_chunks[from_chunk_value.get_chunk_id()];

					memcpy(chunk.values + (i << 8), from_chunk_next.values, (1u << 8) * sizeof(common::acl::tree_value_t));
				}
				else
				{
					for (uint32_t j = 0;
					     j < (1u << 8);
					     j++)
					{
						chunk.values[(i << 8) + j].id = from_chunk_value.get_group_id();
					}
				}
			}

			std::vector<std::tuple<unsigned int, unsigned int>> nexts;

			for (uint32_t i = 0;
			     i < (1u << bits);
			     i++)
			{
				auto& chunk_value = chunk.values[i];

				if (chunk_value.id & 0x80000000u) ///< is_chunk_id
				{
					auto& chunk_id = remap_chunks[chunk_value.id ^ 0x80000000u];
					if (!chunk_id)
					{
						chunk_id = allocate_chunk();
						if (!chunk_id)
						{
							return eResult::isFull;
						}

						nexts.emplace_back(chunk_value.id ^ 0x80000000u, chunk_id);
					}

					chunk_value.id = chunk_id ^ 0x80000000u;
				}
			}

			for (const auto& [next_from_chunk_id, next_chunk_id] : nexts)
			{
				auto result = update_chunk(from_chunks, next_from_chunk_id, next_chunk_id);
				if (result != eResult::success)
				{
					return result;
				}
			}

			return eResult::success;
		}

	public:
		lpm6_8x16bit_id32_dynamic* lpm;
		tSocketId socket_id;
		unsigned int chunks_size;
		unsigned int chunks_count;
		std::vector<unsigned int> remap_chunks;
	};

public:
	static size_t calculate_sizeof(const unsigned int chunks_size)
	{
		if (!chunks_size)
		{
			YANET_LOG_ERROR("wrong chunks_size: %u\n", chunks_size);
			return 0;
		}

		return (size_t)chunks_size * sizeof(chunk_t);
	}

public:
	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				const uint16_t step_address = rte_be_to_cpu_16(*(((uint16_t*)address.bytes) + step));
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const uint32_t mask,
	                   const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		if (mask == mask_full)
		{
			return;
		}

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			if (mask & (1u << address_i))
			{
				continue;
			}

			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 8;
			     step++)
			{
				const uint16_t step_address = rte_be_to_cpu_16(*(((uint16_t*)address.bytes) + step));
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

protected:
	constexpr static unsigned int bits = 16;
	constexpr static unsigned int root_chunk_id = 0;
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	struct value_t
	{
		value_t() :
		        id(0)
		{
		}

		uint32_t id;
	};

	struct chunk_t
	{
		value_t values[1u << bits];
	};

	chunk_t chunks[1];
};

class lpm6_16x8bit_id32_dynamic
{
public:
	constexpr static uint64_t extended_chunks_size_min = 8;

	struct stats_t
	{
		uint32_t extended_chunks_size;
		unsigned int extended_chunks_count;
		std::vector<unsigned int> remap_chunks;
	};

	static uint64_t calculate_sizeof(const uint64_t extended_chunks_size)
	{
		if (!extended_chunks_size)
		{
			YANET_LOG_ERROR("wrong extended_chunks_size: %lu\n", extended_chunks_size);
			return 0;
		}

		return sizeof(lpm6_16x8bit_id32_dynamic) + extended_chunks_size * sizeof(chunk_t);
	}

public:
	lpm6_16x8bit_id32_dynamic()
	{
		for (auto& value : chunks[0].values)
		{
			value.id = 0;
		}
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 16;
			     step++)
			{
				const uint8_t step_address = *(((uint8_t*)address.bytes) + step);
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

	template<unsigned int burst_size = YANET_CONFIG_BURST_SIZE>
	inline void lookup(const uint32_t mask,
	                   const ipv6_address_t (&addresses)[burst_size],
	                   uint32_t (&group_ids)[burst_size],
	                   const unsigned int count) const
	{
		/// @todo: OPT: le -> be

		if (mask == mask_full)
		{
			return;
		}

		for (unsigned int address_i = 0;
		     address_i < count;
		     address_i++)
		{
			if (mask & (1u << address_i))
			{
				continue;
			}

			const auto& address = addresses[address_i];
			auto& group_id = group_ids[address_i];

			unsigned int chunk_id = root_chunk_id;
			for (unsigned int step = 0;
			     step < 16;
			     step++)
			{
				const uint8_t step_address = *(((uint8_t*)address.bytes) + step);
				const auto& chunk_value = chunks[chunk_id].values[step_address];

				if (chunk_value.id & 0x80000000u)
				{
					chunk_id = chunk_value.id ^ 0x80000000u;
				}
				else
				{
					group_id = chunk_value.id;
					break;
				}
			}
		}
	}

	eResult fill(stats_t& stats, const std::vector<common::acl::tree_chunk_8bit_t>& values)
	{
		stats.extended_chunks_count = 1; ///< 0 is root chunk
		stats.remap_chunks.resize(0);
		stats.remap_chunks.resize(values.size(), 0);

		if (values.empty())
		{
			return eResult::success;
		}

		return update_chunk(stats, values, root_chunk_id, root_chunk_id);
	}

protected:
	constexpr static unsigned int bits = 8;
	constexpr static unsigned int root_chunk_id = 0;
	constexpr static uint32_t mask_full = 0xFFFFFFFFu;

	inline unsigned int allocate_extended_chunk(stats_t& stats)
	{
		if (stats.extended_chunks_count >= stats.extended_chunks_size)
		{
			return 0;
		}

		unsigned int new_chunk_id = stats.extended_chunks_count;
		stats.extended_chunks_count++;

		return new_chunk_id;
	}

	eResult update_chunk(stats_t& stats,
	                     const std::vector<common::acl::tree_chunk_8bit_t>& from_chunks,
	                     const unsigned int from_chunk_id,
	                     const unsigned int chunk_id)
	{
		auto& chunk = chunks[chunk_id];
		chunk = {}; ///< @todo: delete?

		const auto& from_chunk = from_chunks[from_chunk_id];

		memcpy(chunk.values, from_chunk.values, (1u << 8) * sizeof(common::acl::tree_value_t));

		std::vector<std::tuple<unsigned int, unsigned int>> nexts;

		for (uint32_t i = 0;
		     i < (1u << bits);
		     i++)
		{
			auto& chunk_value = chunk.values[i];

			if (chunk_value.id & 0x80000000u) ///< is_chunk_id
			{
				auto& chunk_id = stats.remap_chunks[chunk_value.id ^ 0x80000000u];
				if (!chunk_id)
				{
					chunk_id = allocate_extended_chunk(stats);
					if (!chunk_id)
					{
						return eResult::isFull;
					}

					nexts.emplace_back(chunk_value.id ^ 0x80000000u, chunk_id);
				}

				chunk_value.id = chunk_id ^ 0x80000000u;
			}
		}

		for (const auto& [next_from_chunk_id, next_chunk_id] : nexts)
		{
			auto result = update_chunk(stats, from_chunks, next_from_chunk_id, next_chunk_id);
			if (result != eResult::success)
			{
				return result;
			}
		}

		return eResult::success;
	}

protected:
	struct value_t
	{
		value_t() :
		        id(0)
		{
		}

		uint32_t id;
	};

	struct chunk_t
	{
		value_t values[1u << bits];
	};

	chunk_t chunks[1];
};

}
