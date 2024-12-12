#pragma once
//TODO: RENAME TO dump_rings.h

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/type.h"

#include "config.h"
#include "pcap_shm_device.h"

namespace sharedmemory
{
using DumpFormat = tDataPlaneConfig::DumpFormat;
using DumpConfig = tDataPlaneConfig::DumpConfig;

struct DumpRingBase
{
	virtual ~DumpRingBase();

	virtual void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) = 0;
};

class DumpRingRaw : public DumpRingBase
{
	using PacketBufferRing = common::PacketBufferRing;
	using ring_t = PacketBufferRing::ring_t;
	using item_t = PacketBufferRing::item_t;
	using ring_header_t = PacketBufferRing::ring_header_t;

	PacketBufferRing buffer_;
	ring_t* ring_;

public:
	DumpRingRaw(void* memory, size_t max_pkt_size, size_t pkt_count);

	~DumpRingRaw() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

class DumpRingPcap : public DumpRingBase
{
	pcpp::PcapShmWriterDevice dev_;

public:
	DumpRingPcap(void* memory, size_t max_pkt_size, size_t pkt_count);

	~DumpRingPcap() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, uint32_t time) override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);
};

inline size_t GetCapacity(const DumpConfig& config)
{
	auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case DumpFormat::kRaw:
			return DumpRingRaw::GetCapacity(max_pkt_size, pkt_count);
		case DumpFormat::kPcap:
			return DumpRingPcap::GetCapacity(max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

inline std::unique_ptr<DumpRingBase> CreateSharedMemoryDumpRing(const DumpConfig& config, void* memory)
{
	auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case DumpFormat::kRaw:
			return std::make_unique<DumpRingRaw>(memory, max_pkt_size, pkt_count);
		case DumpFormat::kPcap:
			return std::make_unique<DumpRingPcap>(memory, max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

} // namespace sharedmemory
