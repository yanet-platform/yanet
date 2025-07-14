#include <cstdint>
#include <cstdio>
#include <pcap/pcap.h>

#include "common/define.h"
#include "common/utils.h"
#include "pcap_shm_device.h"
#include "rte_branch_prediction.h"

namespace dumprings
{

using utils::ShiftBuffer;

bool PcapShmWriterDevice::InitMeta()
{
	meta_->after.store(0, std::memory_order_relaxed);

	// create a “dead” pcap_t* that describes the capture format
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	pcpp::internal::PcapHandle dead(pcap_open_dead_with_tstamp_precision(
	        static_cast<int>(link_layer_type_),
	        static_cast<int>(max_packet_size_),
	        static_cast<unsigned int>(precision_)));
#else
	pcpp::internal::PcapHandle dead(pcap_open_dead(
	        static_cast<int>(linkLayerType),
	        static_cast<int>(max_pkt_size)));
#endif
	if (!dead)
	{
		YANET_LOG_ERROR("pcap_open_dead[_with_tstamp_precision] returned nullptr\n");
		return false;
	}

	// have libpcap generate the 24-byte global header in-place
	FILE* mem_file = fmemopen(&meta_->pcap_header, sizeof(meta_->pcap_header), "wb");
	if (!mem_file)
	{
		YANET_LOG_ERROR("fmemopen() failed while initialising ring header\n");
		return false;
	}

	pcap_dumper_t* dumper = pcap_dump_fopen(dead.get(), mem_file);
	if (!dumper)
	{
		YANET_LOG_ERROR("pcap_dump_fopen() failed: %s\n", dead.getLastError());
		fclose(mem_file);
		return false;
	}

	pcap_dump_flush(dumper); // force-write the header bytes
	pcap_dump_close(dumper); // Also closes the file

	return true;
}

PcapShmWriterDevice::PcapShmWriterDevice(std::byte* shm_ptr,
                                         size_t max_pkt_size,
                                         size_t pkt_count,
                                         pcpp::LinkLayerType link_layer_type,
                                         bool nanoseconds_precision) :
        meta_(new(shm_ptr) Meta()),
        slots_ptr_(ShiftBuffer(shm_ptr, sizeof(Meta))),
        max_packet_size_(max_pkt_size),
        packet_slot_size_(GetSlotSize(max_pkt_size)),
        packet_count_(pkt_count),
        link_layer_type_(link_layer_type)
{
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	precision_ = nanoseconds_precision ? pcpp::FileTimestampPrecision::Nanoseconds
	                                   : pcpp::FileTimestampPrecision::Microseconds;
#else
	if (nanoseconds_precision)
	{
		YANET_LOG_WARNING("PcapPlusPlus was compiled without nano precision "
		                  "support which requires libpcap > 1.5.1. Please, "
		                  "recompile PcapPlusPlus with nano precision support "
		                  "to use this feature. Using default microsecond precision.\n");
	}
	precision_ = FileTimestampPrecision::Microseconds;
#endif

	switch (link_layer_type_)
	{
		case pcpp::LINKTYPE_RAW:
		case pcpp::LINKTYPE_DLT_RAW2:
			YANET_LOG_ERROR("The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
			                "LINKTYPE_DLT_RAW1, please use that instead\n");
		default:
			break;
	}

	if (!InitMeta())
	{
		throw std::runtime_error("Failed to initialise PCAP ring header");
	}
}

size_t PcapShmWriterDevice::GetRequiredShmSize(size_t max_pkt_size, size_t pkt_count)
{
	return sizeof(Meta) + (GetSlotSize(max_pkt_size) * pkt_count);
}

std::byte* PcapShmWriterDevice::GetSlotPtr(uint64_t packet_number) const
{
	size_t slot_idx = packet_number % packet_count_;
	return ShiftBuffer(slots_ptr_, slot_idx * packet_slot_size_);
}

void PcapShmWriterDevice::FillPacketHeader(PcapHeader* header, const pcpp::RawPacket& packet)
{
	pcap_pkthdr intermediate_hdr;
	timespec packet_timestamp = packet.getPacketTimeStamp();

#if defined(PCAP_TSTAMP_PRECISION_NANO)
	if (precision_ != pcpp::FileTimestampPrecision::Nanoseconds)
	{
		TIMESPEC_TO_TIMEVAL(&intermediate_hdr.ts, &packet_timestamp);
		header->ts_sec = intermediate_hdr.ts.tv_sec;
		header->ts_usec = intermediate_hdr.ts.tv_usec;
	}
	else
	{
		header->ts_sec = packet_timestamp.tv_sec;
		header->ts_usec = packet_timestamp.tv_nsec;
	}
#else
	TIMESPEC_TO_TIMEVAL(&intermediate_hdr.ts, &packet_timestamp);
	header->ts_sec = intermediate_hdr.ts.tv_sec;
	header->ts_usec = intermediate_hdr.ts.tv_usec;
#endif

	header->orig_len = packet.getFrameLength();
	header->incl_len = packet.getRawDataLen();
}

bool PcapShmWriterDevice::WritePacket(const pcpp::RawPacket& packet)
{
	const size_t raw_data_len = packet.getRawDataLen();
	if (unlikely(raw_data_len > max_packet_size_))
	{
		YANET_LOG_WARNING("Packet size %zu exceeds max slot data size %zu. Skipping.\n",
		                  raw_data_len,
		                  max_packet_size_);
		return false;
	}

	const uint64_t wpos = meta_->after.load(std::memory_order_relaxed);

	std::byte* slot_ptr = GetSlotPtr(wpos);
	auto* hdr = reinterpret_cast<PcapHeader*>(slot_ptr);
	FillPacketHeader(hdr, packet);

	std::byte* data_ptr = ShiftBuffer(slot_ptr, sizeof(PcapHeader));
	memcpy(data_ptr, packet.getRawData(), hdr->incl_len);

	meta_->after.store(wpos + 1, std::memory_order_release);

	return true;
}

bool PcapShmWriterDevice::GetPacket(pcpp::RawPacket& raw_packet, unsigned pkt_number) const
{
	uint64_t last_packet_idx = meta_->after.load(std::memory_order_acquire);
	if (last_packet_idx == 0 || pkt_number >= last_packet_idx)
	{
		return false;
	}

	const std::byte* slot_ptr = GetSlotPtr(pkt_number);

	auto* data = ShiftBuffer<const uint8_t*, const std::byte*>(slot_ptr, sizeof(PcapHeader));
	uint32_t size = reinterpret_cast<const PcapHeader*>(slot_ptr)->incl_len;
	// We don't care about timestamp
	timespec ts{};

	raw_packet.initWithRawData(data, static_cast<int>(size), ts, link_layer_type_);
	return true;
}

} // namespace dumprings
