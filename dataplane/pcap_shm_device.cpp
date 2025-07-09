#include <cstdio>
#include <pcap/pcap.h>

#include "common/define.h"
#include "common/utils.h"
#include "rte_branch_prediction.h"
#include "pcap_shm_device.h"

namespace pcpp
{

using utils::ShiftBuffer;

IShmWriterDevice::~IShmWriterDevice() noexcept = default;

PcapShmWriterDevice::PcapShmWriterDevice(void* shm_ptr,
                                         size_t shm_size,
                                         LinkLayerType link_layer_type,
                                         bool nanoseconds_precision) :
        // Usable buffer starts after the meta
        IShmWriterDevice(ShiftBuffer(shm_ptr, sizeof(Meta)), shm_size - sizeof(Meta)),
        link_layer_type_(link_layer_type), meta(new (shm_ptr) Meta())
{
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	precision_ = nanoseconds_precision ? FileTimestampPrecision::Nanoseconds
	                                   : FileTimestampPrecision::Microseconds;
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
}

PcapShmWriterDevice::~PcapShmWriterDevice()
{
	Close();
}

void PcapShmWriterDevice::ResetMeta()
{
	meta->before.store(0, std::memory_order_relaxed);
	meta->after.store(0, std::memory_order_relaxed);
}

bool PcapShmWriterDevice::Open()
{
	if (device_opened_)
	{
		return true;
	}

	switch (link_layer_type_)
	{
		case LINKTYPE_RAW:
		case LINKTYPE_DLT_RAW2:
			YANET_LOG_ERROR("The only Raw IP link type supported in libpcap/WinPcap/Npcap is "
			                "LINKTYPE_DLT_RAW1, please use that instead\n");
			return false;
		default:
			break;
	}

	ResetMeta();

	device_opened_ = true;

	return device_opened_;
}

// TODO: Utilize this funciton... We set precision_ for a reason.
pcap_pkthdr PcapShmWriterDevice::CreatePacketHeader(const RawPacket& packet)
{
	pcap_pkthdr pkt_hdr;
	pkt_hdr.caplen = packet.getRawDataLen();
	pkt_hdr.len = packet.getFrameLength();

	timespec packet_timestamp = packet.getPacketTimeStamp();
#if defined(PCAP_TSTAMP_PRECISION_NANO)
	if (precision_ != FileTimestampPrecision::Nanoseconds)
	{
		TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
	}
	else
	{
		pkt_hdr.ts.tv_sec = packet_timestamp.tv_sec;
		pkt_hdr.ts.tv_usec = packet_timestamp.tv_nsec;
	}
#else
	TIMESPEC_TO_TIMEVAL(&pkt_hdr.ts, &packet_timestamp);
#endif

	return pkt_hdr;
}

// bool PcapShmWriterDevice::WritePacketForRead(RawPacket const& packet)
// {
// 	const pcap_pkthdr pkt_hdr = CreatePacketHeader(packet);

// 	// sizeof(PcapOnDiskRecordHeader) is different from sizeof(pcap_pkthdr)
// 	size_t needed = sizeof(PcapOnDiskRecordHeader) + pkt_hdr.caplen;
// 	if (!EnsureSegmentCapacity(needed))
// 	{
// 		return false;
// 	}

// 	pcap_dump(reinterpret_cast<uint8_t*>(segments_[current_segment_index_].dumper), &pkt_hdr, packet.getRawData());
// 	return true;
// }

bool PcapShmWriterDevice::WritePacket(RawPacket const& packet)
{
	if (unlikely(!device_opened_))
	{
		YANET_LOG_ERROR("Device not opened\n");
		return false;
	}

	if (unlikely(packet.getLinkLayerType() != link_layer_type_))
	{
		YANET_LOG_ERROR("Cannot write a packet with a different link layer type\n");
		return false;
	}

	PcapOnDiskRecordHeader disk_hdr;
	timespec packet_timestamp = packet.getPacketTimeStamp();

	//TODO: use libpcap for this???
	disk_hdr.ts_sec = static_cast<uint32_t>(packet_timestamp.tv_sec);
	disk_hdr.ts_usec = static_cast<uint32_t>(packet_timestamp.tv_nsec / 1000);
	disk_hdr.incl_len = packet.getRawDataLen();
	disk_hdr.orig_len = packet.getFrameLength();

	constexpr size_t on_disk_hdr_len = sizeof(PcapOnDiskRecordHeader);
	const size_t payload_len = disk_hdr.incl_len;
	const size_t total_record_size = on_disk_hdr_len + payload_len;

	// shm_size_ is the usable data area size (already excludes Meta).
	// A single record cannot be larger than the entire usable ring buffer.
	if (unlikely(total_record_size > shm_size_))
	{
		YANET_LOG_WARNING("Packet record size %zu (header %zu + payload %zu) "
		                  "exceeds SHM Follow buffer capacity %zu. Skipping packet.\n",
		                  total_record_size,
		                  on_disk_hdr_len,
		                  payload_len,
		                  shm_size_);
		return false;
	}

	uint64_t record_abs_start_offset = meta->before.fetch_add(total_record_size,
	                                                          std::memory_order_relaxed);

	auto* start = static_cast<uint8_t*>(shm_ptr_); // Base of SHM data area
	size_t capacity = shm_size_; // Capacity of SHM data area

	size_t hdr_offset = record_abs_start_offset % capacity;
	size_t hdr_available = capacity - hdr_offset;

	// Copy header
	if (on_disk_hdr_len <= hdr_available)
	{
		memcpy(ShiftBuffer(start, hdr_offset), &disk_hdr, on_disk_hdr_len);
	}
	else
	{
		// Header wraps
		memcpy(ShiftBuffer(start, hdr_offset), &disk_hdr, hdr_available);
		memcpy(start, ShiftBuffer(&disk_hdr, hdr_available), on_disk_hdr_len - hdr_available);
	}

	// Copy payload
	uint64_t payload_abs_start_offset = record_abs_start_offset + on_disk_hdr_len;
	size_t payload_offset = payload_abs_start_offset % capacity;
	size_t payload_available = capacity - payload_offset;
	const uint8_t* data = packet.getRawData();

	if (payload_len > 0) // Only copy if there's payload
	{
		if (payload_len <= payload_available)
		{
			memcpy(ShiftBuffer(start, payload_offset), data, payload_len);
		}
		else
		{
			// Payload wraps
			memcpy(ShiftBuffer(start, payload_offset), data, payload_available);
			memcpy(start, ShiftBuffer(data, payload_available), payload_len - payload_available);
		}
	}

	meta->after.store(record_abs_start_offset + total_record_size, std::memory_order_release);
	return true;
}

void PcapShmWriterDevice::Close()
{
	if (!device_opened_)
		return;

	ResetMeta();

	device_opened_ = false;
}

void PcapShmWriterDevice::Clean()
{
	Close();
	Open();
}

bool PcapShmWriterDevice::GetPacket(RawPacket& raw_packet, unsigned pkt_number) const
{
	if (!device_opened_)
	{
		return false;
	}

	// TODO: implement
	return true;
}

} // namespace pcpp
