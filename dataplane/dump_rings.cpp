#include "dump_rings.h"
#include "RawPacket.h"
#include "common/type.h"
#include "common/utils.h"
#include "metadata.h"

#include "MBufRawPacket.h"
#include <iostream>

namespace dumprings
{

RingRaw::RingRaw(void* memory, size_t max_pkt_size, size_t pkt_count) :
        buffer_(memory, max_pkt_size, pkt_count), ring_(buffer_.ring)
{
	ring_->header.before = 0;
	ring_->header.after = 0;
}

void RingRaw::Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, [[maybe_unused]] uint32_t time)
{
	// Each ring has its own header, the header contains absolute position
	// to which next packet should be written. Position has two state:
	// -- "before" increments immediately before of copying data to memory;
	// -- "after" increments after copying data.
	using ring_header_t = PacketBufferRing::ring_header_t;

	uint64_t wpos = (ring_->header.before) % buffer_.units_number;
	ring_->header.before++;
	auto* item = utils::ShiftBuffer<item_t*>(ring_->memory, wpos * buffer_.unit_size);

	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	uint64_t memory_size = buffer_.unit_size - sizeof(ring_header_t);
	uint64_t copy_size = RTE_MIN(memory_size, mbuf->data_len);

	item->header.size = copy_size;
	item->header.tag = metadata->hash;
	item->header.in_logicalport_id = metadata->in_logicalport_id;
	item->header.out_logicalport_id = metadata->out_logicalport_id;
	item->header.flow_type = static_cast<uint8_t>(flow_type);

	memcpy(item->memory, rte_pktmbuf_mtod(mbuf, void*), copy_size);

	YANET_MEMORY_BARRIER_COMPILE;

	ring_->header.after++;
}

bool RingRaw::GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const
{
	timespec empty_timespec{}; // RingRaw does not support timestamps

	if (pkt_number >= ring_->header.after)
	{
		return false;
	}

	auto* item = utils::ShiftBuffer<item_t*>(ring_->memory, pkt_number * buffer_.unit_size);
	int raw_data_len = static_cast<int>(item->header.size);

	raw_packet.initWithRawData(item->memory, raw_data_len, empty_timespec);

	return true;
}

size_t RingRaw::GetCapacity(size_t max_pkt_size, size_t pkt_count)
{
	return PacketBufferRing::GetCapacity(max_pkt_size, pkt_count);
}

// TODO: use max_pkt_size as snaplen in pcap?
// TODO: Don't know how yet, but we need to pass files amount. Let's do three by now.
RingPcap::RingPcap(void* memory, size_t max_pkt_size, size_t pkt_count) :
        dev_(memory, GetCapacity(max_pkt_size, pkt_count), 3)
{
	dev_.open();
}

void RingPcap::Clean()
{
	dev_.Clean();
}

/**
 * @brief A complete copy of the PcapPlusPlus wrapper of the RawPacket class.
 *
 * This class allows initialization with an already-created mbuf, making it
 * possible to safely pass the object to a Writer instance as the base class
 * RawPacket. In the original `MBufRawPacket` class, the `setMBuf` method
 * was protected, plus is requires to build PcapPlusPlus with DPDK support,
 * which is unnecessary for such a small change.
 */
class MBufRawPacketCopy : public pcpp::RawPacket
{
	void SetMBuf(rte_mbuf* mbuf, timespec timestamp)
	{
		if (mbuf == nullptr)
		{
			std::cerr << "mbuf to set is nullptr" << std::endl;
			return;
		}

		initWithRawData(rte_pktmbuf_mtod(mbuf, const uint8_t*), rte_pktmbuf_pkt_len(mbuf), timestamp, pcpp::LINKTYPE_ETHERNET);
	}

public:
	MBufRawPacketCopy(rte_mbuf* mbuf, const timespec& timestamp) :
	        RawPacket()
	{
		SetMBuf(mbuf, timestamp);
	}
};

void RingPcap::Write(rte_mbuf* mbuf, [[maybe_unused]] common::globalBase::eFlowType flow_type, uint32_t time)
{
	timespec ts = {.tv_sec = time, .tv_nsec = 0};
	MBufRawPacketCopy raw_packet(mbuf, ts);

	// TODO: can I do this, or should I use time obtained from basePermanently.globalBaseAtomic->currentTime like I do now?
	/* timespec_get(&ts, TIME_UTC); */

	dev_.WritePacket(raw_packet);
}

bool RingPcap::GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const
{
	return dev_.GetPacket(raw_packet, pkt_number);
}

size_t RingPcap::GetCapacity(size_t max_pkt_size, size_t pkt_count)
{
	auto& file_hdr_size = pcpp::PcapShmWriterDevice::kPcapFileHeaderSize;
	auto& pkt_hdr_size = pcpp::PcapShmWriterDevice::kPcapPacketHeaderSizeOnDisk;

	size_t capacity = file_hdr_size + (pkt_hdr_size + max_pkt_size) * pkt_count;

	if (capacity % RTE_CACHE_LINE_SIZE != 0)
	{
		capacity += RTE_CACHE_LINE_SIZE - capacity % RTE_CACHE_LINE_SIZE; /// round up
	}

	return capacity;
}

size_t GetCapacity(const Config& config)
{
	const auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case Format::kRaw:
			return RingRaw::GetCapacity(max_pkt_size, pkt_count);
		case Format::kPcap:
			return RingPcap::GetCapacity(max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

std::unique_ptr<RingBase> CreateSharedMemoryDumpRing(const Config& config, void* memory)
{
	const auto& [format, max_pkt_size, pkt_count] = config;

	switch (format)
	{
		case Format::kRaw:
			return std::make_unique<RingRaw>(memory, max_pkt_size, pkt_count);
		case Format::kPcap:
			return std::make_unique<RingPcap>(memory, max_pkt_size, pkt_count);
		default:
			YANET_THROW("Invalid dump format");
			std::abort();
	}
}

} // namespace sharedmemory
