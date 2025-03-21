#pragma once

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/type.h"

#include "config.h"
#include "pcap_shm_device.h"

namespace dumprings
{
using Format = tDataPlaneConfig::DumpFormat;
using Config = tDataPlaneConfig::DumpConfig;

class RingBase
{
	// Current packet number that we will read next
	unsigned read_pkt_number = 0;

public:
	virtual ~RingBase() = default;

	virtual void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) = 0;

	[[nodiscard]] virtual bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const = 0;

	bool GetNextPacket(pcpp::RawPacket& raw_packet)
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

	void Clean()
	{
		read_pkt_number = 0;
	}
};

class RingRaw : public RingBase
{
	using PacketBufferRing = common::PacketBufferRing;
	using ring_t = PacketBufferRing::ring_t;
	using item_t = PacketBufferRing::item_t;

	PacketBufferRing buffer_;
	ring_t* ring_;

public:
	RingRaw(void* memory, size_t max_pkt_size, size_t pkt_count);

	~RingRaw() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) override;

	[[nodiscard]] bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

class RingPcap : public RingBase
{
	pcpp::PcapShmWriterDevice dev_;

public:
	RingPcap(void* memory, size_t max_pkt_size, size_t pkt_count);

	~RingPcap() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) override;

	[[nodiscard]] bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

size_t GetCapacity(const Config& config);

std::unique_ptr<RingBase> CreateSharedMemoryDumpRing(const Config& config, void* memory);

} // namespace dumprings
