#include "sharedmemory.h"
#include "common/type.h"
#include "common/utils.h"
#include "metadata.h"

#include "MBufRawPacket.h"

namespace sharedmemory
{

DumpRingRaw::DumpRingRaw(void* memory, size_t max_pkt_size, size_t pkt_count) :
        buffer_(memory, max_pkt_size, pkt_count), ring_(buffer_.ring)
{
	ring_->header.before = 0;
	ring_->header.after = 0;
}

void DumpRingRaw::Write(rte_mbuf* mbuf, common::globalBase::eFlowType flow_type, [[maybe_unused]] uint32_t time)
{
	// Each ring has its own header, the header contains absolute position
	// to which next packet should be written. Position has two state:
	// -- "before" increments immediately before of copying data to memory;
	// -- "after" increments after copying data.

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

size_t DumpRingRaw::GetCapacity(size_t max_pkt_size, size_t pkt_count)
{
	return PacketBufferRing::GetCapacity(max_pkt_size, pkt_count);
}

// TODO: use max_pkt_size as snaplen in pcap?
DumpRingPcap::DumpRingPcap(void* memory, size_t max_pkt_size, size_t pkt_count) :
        dev_(memory, GetCapacity(max_pkt_size, pkt_count), 3)
{
	// TODO: Don't know how yet, but we need to pass files amount. Let's do three by now.
}

/**
 * @brief A complete copy of the PcapPlusPlus wrapper of the RawPacket class.
 *
 * This class allows initialization with an already-created mbuf, making it
 * possible to safely pass the object to a Writer instance as the base class
 * RawPacket. In the original `MBufRawPacket` class, the `setMBuf` method
 * was protected, but it has been incorporated into a new constructor.
 */
struct MBufRawPacketCopy : public pcpp::MBufRawPacket
{
	using MBufRawPacket::MBufRawPacket;

	MBufRawPacketCopy(rte_mbuf* mBuf, const timespec& timestamp) :
	        MBufRawPacket()
	{
		setMBuf(mBuf, timestamp);
	}
};

void DumpRingPcap::Write(rte_mbuf* mbuf, [[maybe_unused]] common::globalBase::eFlowType flow_type, uint32_t time)
{
	timespec ts = {.tv_sec = time, .tv_nsec = 0};
	MBufRawPacketCopy raw_packet(mbuf, ts);

	// TODO: can I do this, or should I use time obtained from basePermanently.globalBaseAtomic->currentTime?
	/* timespec_get(&ts, TIME_UTC); */

	dev_.WritePacket(raw_packet);
}

size_t DumpRingPcap::GetCapacity(size_t max_pkt_size, size_t pkt_count)
{
	auto& file_hdr_size = pcpp::PcapShmWriterDevice::kPcapFileHeaderSize;
	auto& pkt_hdr_size = pcpp::PcapShmWriterDevice::kPcapPacketHeaderSizeOnDisk;

	return file_hdr_size + (pkt_hdr_size + max_pkt_size) * pkt_count;
}

} // namespace sharedmemory
