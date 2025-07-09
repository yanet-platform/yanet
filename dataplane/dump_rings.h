#pragma once

#include <rte_mbuf.h>

#include "common/bufferring.h"
#include "common/type.h"

#include "config.h"
#include "pcap_shm_device.h"
#include "globalbase.h"

namespace dumprings
{
using Format = tDataPlaneConfig::DumpFormat;
using Config = tDataPlaneConfig::DumpConfig;
using Filenames = std::vector<std::string>;
using WallclockAnchor = dataplane::globalBase::atomic::WallclockAnchor;

class RingBase
{
	// Current packet number that we will read next. It's used only by autotests
	unsigned read_pkt_number = 0;

	virtual void Clean() = 0;

public:
	virtual ~RingBase() = default;

	virtual void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) = 0;

	[[nodiscard]] virtual bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const = 0;

	virtual void Flush() = 0;
	virtual Filenames DumpPcapFilesToDisk(std::string_view prefix, std::string_view path) = 0;

	virtual void SwitchToFollow() = 0;
	virtual void FollowDone() = 0;

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

	void Clear()
	{
		read_pkt_number = 0;
		Clean();
	}
};

class RingRaw final : public RingBase
{
	using PacketBufferRing = common::PacketBufferRing;
	using ring_t = PacketBufferRing::ring_t;
	using item_t = PacketBufferRing::item_t;

	PacketBufferRing buffer_;
	ring_t* ring_;

	void Clean() override
	{
		YANET_LOG_DEBUG("No need to clean raw dump ring, all of it's state "
		                "is in shared memory which gets cleaned by default.");
	}

public:
	RingRaw(void* memory, size_t max_pkt_size, size_t pkt_count);

	~RingRaw() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) override;

	[[nodiscard]] bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);

	void Flush() override
	{
		YANET_LOG_DEBUG("No need to flush raw dump ring, "
		                "it does not use any buffers.");
	}

	Filenames DumpPcapFilesToDisk([[maybe_unused]] std::string_view prefix,
	                              [[maybe_unused]] std::string_view path) override
	{
		YANET_LOG_DEBUG("Cannot dump packets written in raw format in this ring "
		                "on disk as pcap files. You should use this function only with "
		                "RingPcap ring.");
		return {};
	}

	void SwitchToFollow() override
	{
		YANET_LOG_DEBUG("Cannot switch mode to 'follow' in raw dump ring. "
		                "You should use this function only with RingPcap ring.");
	}

	void FollowDone() override
	{
		YANET_LOG_DEBUG("Cannot end 'follow' mode in raw dump ring. "
		                "You should use this function only with RingPcap ring.");
	}
};

class RingPcap final : public RingBase
{
	pcpp::PcapShmWriterDevice dev_;

	void Clean() override;

public:
	RingPcap(void* memory, size_t max_pkt_size, size_t pkt_count, size_t file_count);

	~RingPcap() override = default;

	void Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, const WallclockAnchor& anchor) override;

	[[nodiscard]] bool GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const override;

	static size_t GetCapacity(size_t max_pkt_size, size_t pkt_count);

	void Flush() override;

	Filenames DumpPcapFilesToDisk(std::string_view prefix, std::string_view path) override;

	void SwitchToFollow() override;

	void FollowDone() override;
};

size_t GetCapacity(const Config& config);

std::unique_ptr<RingBase> CreateSharedMemoryDumpRing(const Config& config, void* memory);

} // namespace dumprings
