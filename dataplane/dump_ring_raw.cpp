#include "dump_rings.h"
#include "common/type.h"
#include "common/utils.h"
#include "metadata.h"

namespace dumprings
{

RingRaw::RingRaw(void* memory, size_t max_pkt_size, size_t pkt_count) :
        buffer_(memory, max_pkt_size, pkt_count), ring_(buffer_.ring)
{
	ring_->header.before = 0;
	ring_->header.after = 0;
}

void RingRaw::Write(rte_mbuf* mbuf,
                    common::globalBase::eFlowType flow_type,
                    [[maybe_unused]] const WallclockAnchor& anchor)
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

bool RingRaw::GetPacket(RawPacket& raw_packet, unsigned pkt_number) const
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

} // namespace sharedmemory
