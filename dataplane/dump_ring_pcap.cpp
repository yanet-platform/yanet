#include "RawPacket.h"
#include "common/type.h"
#include "dump_rings.h"

#include "MBufRawPacket.h"

/**
 * @brief A complete copy of the PcapPlusPlus wrapper of the RawPacket class.
 *
 * This class allows initialization with an already-created mbuf, making it
 * possible to safely pass the object to a Writer instance as the base class
 * RawPacket. In the original `MBufRawPacket` class, the `setMBuf` method
 * was protected, plus is requires to build PcapPlusPlus with DPDK support,
 * which is unnecessary for such a small change.
 */
class MBufRawPacketCopy final : public pcpp::RawPacket
{
	void SetMBuf(rte_mbuf* mbuf, timespec timestamp)
	{
		if (mbuf == nullptr)
		{
			YANET_LOG_ERROR("Cannot initialize MBufRawPacketCopy with null mbuf\n");
			return;
		}

		initWithRawData(rte_pktmbuf_mtod(mbuf, const uint8_t*),
		                rte_pktmbuf_pkt_len(mbuf),
		                timestamp,
		                pcpp::LINKTYPE_ETHERNET);
	}

public:
	MBufRawPacketCopy(rte_mbuf* mbuf, const timespec& timestamp) :
	        RawPacket()
	{
		SetMBuf(mbuf, timestamp);
	}
};

static timespec fast_wall_timestamp(const WallclockAnchor& anchor)
{
	constexpr uint64_t NSEC_PER_SEC = 1'000'000'000ULL;

	uint64_t current_tsc = rte_get_tsc_cycles();
	uint64_t delta_cycles = (current_tsc > anchor.tsc0) ? (current_tsc - anchor.tsc0) : 0;

	// Use a 128-bit intermediate to prevent overflow when multiplying by a billion.
	auto delta_ns_128 = static_cast<unsigned __int128>(delta_cycles * NSEC_PER_SEC);
	uint64_t delta_ns = delta_ns_128 / anchor.hz;

	timespec ts = anchor.wall0;

	ts.tv_sec += static_cast<__time_t>(delta_ns / NSEC_PER_SEC);
	ts.tv_nsec += static_cast<long>(delta_ns % NSEC_PER_SEC);

	// Normalize tv_nsec to be within the valid [0, 999999999] range.
	if (unlikely(static_cast<uint64_t>(ts.tv_nsec) >= NSEC_PER_SEC))
	{
		ts.tv_sec++;
		ts.tv_nsec -= NSEC_PER_SEC;
	}

	return ts;
}

namespace dumprings
{

RingPcap::RingPcap(void* memory, size_t max_pkt_size, size_t pkt_count) :
        dev_(static_cast<std::byte*>(memory), max_pkt_size, pkt_count)
{}

void RingPcap::ResetState()
{
	dev_.InitMeta();
}

void RingPcap::Write(rte_mbuf* mbuf,
                     [[maybe_unused]] common::globalBase::eFlowType flow_type,
                     const WallclockAnchor& anchor)
{
	MBufRawPacketCopy raw_packet(mbuf, fast_wall_timestamp(anchor));
	dev_.WritePacket(raw_packet);
}

bool RingPcap::GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const
{
	return dev_.GetPacket(raw_packet, pkt_number);
}

size_t RingPcap::GetCapacity(size_t max_pkt_size, size_t pkt_count)
{
	return PcapShmWriterDevice::GetRequiredShmSize(max_pkt_size, pkt_count);
}

} // namespace dumprings
