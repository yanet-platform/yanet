#pragma once

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/type.h"

#include "config.h"
#include "globalbase.h"
#include "pcap_shm_device.h"

using WallclockAnchor = dataplane::globalBase::atomic::WallclockAnchor;

namespace dumprings
{
using Format = tDataPlaneConfig::DumpFormat;
using Config = tDataPlaneConfig::DumpConfig;
using RawPacket = pcpp::RawPacket;

class RingBase
{
	// Current packet number that we will read next. It's used only by autotests
	unsigned read_pkt_number = 0;

	[[nodiscard]] virtual bool GetPacket(RawPacket& raw_packet, unsigned pkt_number) const = 0;

public:
	virtual ~RingBase() = default;

	virtual void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) = 0;

	virtual void ResetState() = 0;

	bool GetNextPacket(RawPacket& raw_packet)
	{
		raw_packet.clear();

		bool result = GetPacket(raw_packet, read_pkt_number);

		if (result)
		{
			read_pkt_number++;
		}

		return result;
	}

	// Number of packets we read so far
	[[nodiscard]] unsigned PacketsRead() const
	{
		return read_pkt_number;
	}

	void Clear()
	{
		read_pkt_number = 0;
		ResetState();
	}
};

size_t GetCapacity(const Config& config);

std::unique_ptr<RingBase> CreateSharedMemoryDumpRing(const Config& config, void* memory);

class RingRaw final : public RingBase
{
	using PacketBufferRing = common::PacketBufferRing;
	using ring_t = PacketBufferRing::ring_t;
	using item_t = PacketBufferRing::item_t;

	PacketBufferRing buffer_;
	ring_t* ring_;

public:
	RingRaw(void* memory, size_t max_pkt_size, size_t pkt_count);

	~RingRaw() override = default;

	virtual void ResetState() override;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) override;

	[[nodiscard]] bool GetPacket(RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

/**
 * A class for writing packets to a shared memory region in pcap format,
 * using a slot-based ring-buffer.
 *
 * The shared memory is structured as follows:
 * 1. A `dumprings::RingMeta` header containing the global PCAP file header
 *    and the atomic `after` slot index.
 * 2. An array of `N` fixed-size slots.
 *
 * Each slot contains:
 * 1. A pcap packet header -- packet's timestamp and length.
 * 2. The raw packet data, truncated to fit the slot size.
 *
 * The writer increments the `after` counter only after a slot is completely
 * filled, making the entire slot atomically available to the reader.
 */
class RingPcap final : public RingBase
{
	PcapShmWriterDevice dev_;

public:
	RingPcap(void* memory, size_t max_pkt_size, size_t pkt_count);

	~RingPcap() override = default;

	virtual void ResetState() override;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) override;

	[[nodiscard]] bool GetPacket(RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

} // namespace dumprings
